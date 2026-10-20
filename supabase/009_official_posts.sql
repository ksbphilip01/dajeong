-- 009: 운영자 공식 소식(official) 표시는 관리자만 쓸 수 있음
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
  if c = 'posts' then return coalesce(d->>'official','false') <> 'true' and d->>'authorId' = uid and (d->>'orgId' is null or public.owns_org(d->>'orgId')); end if;
  if c = 'comments' then return d->>'authorId' = uid; end if;
  if c = 'praise' then return public.is_member() and d->>'authorId' = uid and (d->>'byOrg' is null or public.owns_org(d->>'byOrg')); end if;
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
