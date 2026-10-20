-- =====================================================================
--  004: 단체 담당자 정보 비공개 저장소 (orgprivate)
--   담당자 이름·연락처, 종교 기관 확인 정보 등은 관리자와 해당 단체 관리자만 볼 수 있음
-- =====================================================================
create or replace function public.doc_can_read(c text, i text, d jsonb) returns boolean
language plpgsql stable security definer set search_path = public as $$
begin
  if c = 'reports' then return public.is_admin() or i = auth.uid()::text; end if;
  if c = 'orgprivate' then return public.is_admin() or public.owns_org(i); end if;
  if c = 'dms' or c like 'dms/%/msgs' then return public.dm_party_ok(c,d); end if;
  return true;
end $$;

create or replace function public.doc_can_modify(c text, i text, d jsonb) returns boolean
language plpgsql stable security definer set search_path = public as $$
declare uid text := auth.uid()::text;
begin
  if uid is null then return false; end if;
  if c = 'dms' or c like 'dms/%/msgs' then return public.dm_party_ok(c,d); end if;
  if public.is_admin() then return true; end if;
  if c = 'orgprivate' then return public.owns_org(i); end if;
  if c in ('people','reports') then return i = uid; end if;
  if c in ('mod','notices') then return false; end if;
  if c = 'orgs' then return (d->'ownerIds') ? uid; end if;
  if c = 'posts' then return d->>'authorId' = uid or public.owns_org(d->>'orgId'); end if;
  if c = 'comments' then return d->>'authorId' = uid; end if;
  if c = 'stories' then return d->>'authorId' = uid or public.owns_org(d->>'orgId'); end if;
  return false;
end $$;

create or replace function public.doc_can_write(c text, i text, d jsonb) returns boolean
language plpgsql stable security definer set search_path = public as $$
declare uid text := auth.uid()::text; cid text;
begin
  if uid is null then return false; end if;
  if public.is_admin() then return true; end if;
  if public.is_blocked() then return false; end if;
  if c = 'orgprivate' then return public.owns_org(i); end if;
  if c in ('people','reports') then return i = uid; end if;
  if c in ('mod','notices') then return false; end if;
  if c = 'orgs' then return (d->'ownerIds') ? uid; end if;
  if c = 'posts' then return d->>'authorId' = uid and (d->>'orgId' is null or public.owns_org(d->>'orgId')); end if;
  if c = 'comments' then return d->>'authorId' = uid; end if;
  if c = 'stories' then return d->>'authorId' = uid and public.owns_org(d->>'orgId'); end if;
  if c = 'dms' then return exists (select 1 from jsonb_array_elements_text(coalesce(d->'parties','[]'::jsonb)) p where public.owns_party(p)); end if;
  if c like 'dms/%/msgs' then
    cid := split_part(c,'/',2);
    return public.owns_party(d->>'from') and d->>'by' = uid
       and exists (select 1 from public.docs x, jsonb_array_elements_text(coalesce(x.data->'parties','[]'::jsonb)) p
                   where x.collection='dms' and x.id=cid and p = d->>'from');
  end if;
  return false;
end $$;

-- 기존 단체 문서에 공개돼 있던 담당자 이름을 비공개 저장소로 옮김
insert into public.docs(collection,id,data)
  select 'orgprivate', id, jsonb_build_object('manager', data->>'manager', 'managerRole', data->>'managerRole')
  from public.docs where collection='orgs' and data ? 'manager'
on conflict (collection,id) do nothing;
update public.docs set data = data - 'manager' - 'managerRole' where collection='orgs' and data ? 'manager';
