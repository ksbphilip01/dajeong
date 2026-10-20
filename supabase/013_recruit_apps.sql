-- 013: 함께해요 단체 봉사 모집 신청서 (collection: apps)
--  신청서(이름·소속·전화번호)는 모집한 단체의 관리자와 신청자 본인만 볼 수 있음. 운영자(관리자)도 열람 불가.
create or replace function public.doc_can_read(c text, i text, d jsonb) returns boolean
language plpgsql stable security definer set search_path = public as $$
begin
  if c = 'reports' then return public.is_admin() or i = auth.uid()::text; end if;
  if c = 'apps' then return public.owns_org(d->>'orgId') or d->>'uid' = auth.uid()::text; end if;
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
  if c = 'apps' then return public.owns_org(d->>'orgId') or d->>'uid' = uid; end if;
  if public.is_admin() then return true; end if;
  if c = 'orgprivate' then return public.owns_org(i); end if;
  if c in ('people','reports') then return i = uid; end if;
  if c in ('mod','notices') then return false; end if;
  if c = 'orgs' then return (d->'ownerIds') ? uid; end if;
  if c = 'posts' then return d->>'authorId' = uid or public.owns_org(d->>'orgId'); end if;
  if c = 'comments' then return d->>'authorId' = uid; end if;
  if c in ('praise','together') then return d->>'authorId' = uid; end if;
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
  if c = 'posts' then return coalesce(d->>'official','false') <> 'true' and d->>'authorId' = uid and (d->>'orgId' is null or public.owns_org(d->>'orgId')); end if;
  if c = 'comments' then return d->>'authorId' = uid; end if;
  if c = 'praise' then return public.is_member() and d->>'authorId' = uid and (d->>'byOrg' is null or public.owns_org(d->>'byOrg')); end if;
  if c = 'apps' then return false; end if;
  if c = 'together' then return (coalesce(d->>'recruit','false') <> 'true' or d->>'byOrg' is not null) and public.is_member() and d->>'authorId' = uid and (d->>'byOrg' is null or public.owns_org(d->>'byOrg')); end if;
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

create or replace function public.together_app_recount(p_id text) returns int
language plpgsql security definer set search_path = public as $$
declare n int;
begin
  select count(*) into n from public.docs where collection='apps' and data->>'tid' = p_id;
  update public.docs set data = jsonb_set(data,'{appCount}',to_jsonb(n),true) where collection='together' and id=p_id;
  return n;
end $$;

create or replace function public.together_apply(p_id text, p_name text, p_aff text, p_phone text, p_consent boolean) returns int
language plpgsql security definer set search_path = public as $$
declare uid text := auth.uid()::text; t jsonb; n int;
begin
  if uid is null or public.is_blocked() or not public.is_member() then raise exception 'not allowed'; end if;
  if not coalesce(p_consent,false) then raise exception 'consent required'; end if;
  if length(trim(coalesce(p_name,''))) < 1 or length(trim(coalesce(p_aff,''))) < 1 or length(regexp_replace(coalesce(p_phone,''),'\D','','g')) < 9 then raise exception 'missing fields'; end if;
  select data into t from public.docs where collection='together' and id=p_id;
  if t is null or coalesce(t->>'recruit','false') <> 'true' then raise exception 'not a recruit'; end if;
  if coalesce(t->>'closed','false') = 'true' then raise exception 'closed'; end if;
  if (t->>'slots') is not null and (t->>'slots') <> 'null' and not exists (select 1 from public.docs where collection='apps' and id = p_id||'_'||uid)
     and (select count(*) from public.docs where collection='apps' and data->>'tid'=p_id) >= (t->>'slots')::int then raise exception 'full'; end if;
  insert into public.docs(collection,id,data) values ('apps', p_id||'_'||uid, jsonb_build_object(
      'tid',p_id,'orgId',t->>'byOrg','uid',uid,'name',left(trim(p_name),30),'aff',left(trim(p_aff),40),'phone',left(trim(p_phone),20),
      'consentAt',(extract(epoch from now())*1000)::bigint,'createdAt',(extract(epoch from now())*1000)::bigint))
  on conflict (collection,id) do update set data = excluded.data;
  return public.together_app_recount(p_id);
end $$;

-- 신청 취소(본인) 또는 신청서 삭제(모집 단체 관리자)
create or replace function public.together_app_delete(p_app text) returns int
language plpgsql security definer set search_path = public as $$
declare a jsonb; uid text := auth.uid()::text;
begin
  select data into a from public.docs where collection='apps' and id=p_app;
  if a is null then return 0; end if;
  if not (a->>'uid' = uid or public.owns_org(a->>'orgId')) then raise exception 'not allowed'; end if;
  delete from public.docs where collection='apps' and id=p_app;
  return public.together_app_recount(a->>'tid');
end $$;

-- 모집 글의 신청서 전체 삭제(모집 단체 관리자)
create or replace function public.together_apps_clear(p_id text) returns void
language plpgsql security definer set search_path = public as $$
declare t jsonb;
begin
  select data into t from public.docs where collection='together' and id=p_id;
  if t is null or not public.owns_org(t->>'byOrg') then raise exception 'not allowed'; end if;
  delete from public.docs where collection='apps' and data->>'tid'=p_id;
  perform public.together_app_recount(p_id);
end $$;

grant execute on function public.together_apply(text,text,text,text,boolean), public.together_app_delete(text), public.together_apps_clear(text) to authenticated;
