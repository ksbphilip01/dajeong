-- 008: 칭찬합니다 글쓰기·'저도 칭찬해요'는 가입을 마친 회원(개인 프로필 또는 단체 관리자)만
create or replace function public.is_member() returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_admin()
      or exists (select 1 from public.docs where collection='people' and id=auth.uid()::text and data ? 'profile' and data->'profile' <> 'null'::jsonb)
      or exists (select 1 from public.docs where collection='orgs' and (data->'ownerIds') ? auth.uid()::text);
$$;
grant execute on function public.is_member() to authenticated;

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

create or replace function public.praise_cheer(p_id text) returns void
language plpgsql security definer set search_path = public as $$
declare uid text := auth.uid()::text;
begin
  if uid is null or public.is_blocked() or not public.is_member() then raise exception 'not allowed'; end if;
  update public.docs set data = case when (data->'cheers') ? uid
      then data #- array['cheers', uid]
      else jsonb_set(coalesce(data,'{}'::jsonb), '{cheers}', coalesce(data->'cheers','{}'::jsonb) || jsonb_build_object(uid, (extract(epoch from now())*1000)::bigint), true) end
   where collection='praise' and id=p_id;
end $$;
