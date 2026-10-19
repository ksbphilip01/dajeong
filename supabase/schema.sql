-- =====================================================================
--  다정 (지역 선한 소식 플랫폼) — Supabase 스키마 v1
--  SQL Editor 에 통째로 붙여 넣고 Run 하면 됩니다. (여러 번 실행해도 안전)
-- =====================================================================

-- 0) 확장
create extension if not exists pgcrypto;

-- 1) 관리자 / 프로필 -------------------------------------------------
create table if not exists public.admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default '',
  avatar_url text,
  created_at timestamptz not null default now()
);

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.admins where user_id = auth.uid());
$$;

-- 가입 시 프로필 생성 + 첫 가입자는 자동으로 관리자
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, display_name)
  values (new.id, coalesce(new.raw_user_meta_data->>'display_name', split_part(new.email,'@',1)))
  on conflict (id) do nothing;
  if not exists (select 1 from public.admins) then
    insert into public.admins (user_id) values (new.id);
  end if;
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- 2) 문서 저장소 (컬렉션/문서/JSON) -----------------------------------
--  앱은 Firestore 비슷한 문서 모델을 씁니다. 컬렉션별 권한은 아래 함수로 판정.
create table if not exists public.docs (
  collection text not null,
  id text not null,
  data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (collection, id)
);
create index if not exists docs_collection_idx on public.docs (collection);
create index if not exists docs_data_gin on public.docs using gin (data);

create or replace function public.touch_updated_at() returns trigger
language plpgsql as $$ begin new.updated_at = now(); return new; end $$;
drop trigger if exists docs_touch on public.docs;
create trigger docs_touch before update on public.docs for each row execute procedure public.touch_updated_at();

-- jsonb 깊은 병합 (update = merge)
create or replace function public.jsonb_deep_merge(a jsonb, b jsonb) returns jsonb
language sql immutable as $$
  select case
    when jsonb_typeof(a) = 'object' and jsonb_typeof(b) = 'object' then
      (select coalesce(jsonb_object_agg(k, case
          when a ? k and b ? k then public.jsonb_deep_merge(a->k, b->k)
          when b ? k then b->k else a->k end), '{}'::jsonb)
       from (select jsonb_object_keys(a) k union select jsonb_object_keys(b)) ks)
    else b end;
$$;

-- 당사자(party) 소유 판정: 'me:<uid>' 또는 'org:<orgId>'
create or replace function public.owns_party(p text) returns boolean
language plpgsql stable security definer set search_path = public as $$
declare uid text := auth.uid()::text;
begin
  if uid is null or p is null then return false; end if;
  if p = 'me:' || uid then return true; end if;
  if left(p,4) = 'org:' then
    return exists (select 1 from public.docs d where d.collection='orgs' and d.id = substr(p,5) and (d.data->'ownerIds') ? uid);
  end if;
  return false;
end $$;

create or replace function public.owns_org(org_id text) returns boolean
language sql stable security definer set search_path = public as $$
  select org_id is not null and exists (select 1 from public.docs d where d.collection='orgs' and d.id=org_id and (d.data->'ownerIds') ? auth.uid()::text);
$$;

-- 기존 행에 대한 권한 (update/delete의 USING)
create or replace function public.doc_can_modify(c text, i text, d jsonb) returns boolean
language plpgsql stable security definer set search_path = public as $$
declare uid text := auth.uid()::text; cid text;
begin
  if uid is null then return false; end if;
  if public.is_admin() then return true; end if;
  if c in ('people','reports') then return i = uid; end if;
  if c in ('mod','notices') then return false; end if;
  if c = 'orgs' then return (d->'ownerIds') ? uid; end if;
  if c = 'posts' then return d->>'authorId' = uid or public.owns_org(d->>'orgId'); end if;
  if c = 'comments' then return d->>'authorId' = uid; end if;
  if c = 'stories' then return d->>'authorId' = uid or public.owns_org(d->>'orgId'); end if;
  if c = 'dms' then return exists (select 1 from jsonb_array_elements_text(coalesce(d->'parties','[]'::jsonb)) p where public.owns_party(p)); end if;
  if c like 'dms/%/msgs' then
    cid := split_part(c,'/',2);
    return exists (select 1 from public.docs x, jsonb_array_elements_text(coalesce(x.data->'parties','[]'::jsonb)) p
                   where x.collection='dms' and x.id=cid and public.owns_party(p));
  end if;
  return false;
end $$;

-- 새 행에 대한 권한 (insert / update의 WITH CHECK)
create or replace function public.doc_can_write(c text, i text, d jsonb) returns boolean
language plpgsql stable security definer set search_path = public as $$
declare uid text := auth.uid()::text; cid text;
begin
  if uid is null then return false; end if;
  if public.is_admin() then return true; end if;
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

-- 읽기 권한: 대부분 공개, 메시지는 당사자만, 신고는 본인/관리자만
create or replace function public.doc_can_read(c text, i text, d jsonb) returns boolean
language plpgsql stable security definer set search_path = public as $$
begin
  if c = 'reports' then return public.is_admin() or i = auth.uid()::text; end if;
  if c = 'dms' or c like 'dms/%/msgs' then return public.doc_can_modify(c,i,d); end if;
  return true;
end $$;

alter table public.docs enable row level security;
drop policy if exists docs_select on public.docs;
drop policy if exists docs_insert on public.docs;
drop policy if exists docs_update on public.docs;
drop policy if exists docs_delete on public.docs;
create policy docs_select on public.docs for select using (public.doc_can_read(collection,id,data));
create policy docs_insert on public.docs for insert with check (public.doc_can_write(collection,id,data));
create policy docs_update on public.docs for update using (public.doc_can_modify(collection,id,data)) with check (public.doc_can_write(collection,id,data));
create policy docs_delete on public.docs for delete using (public.doc_can_modify(collection,id,data));

alter table public.profiles enable row level security;
drop policy if exists profiles_select on public.profiles;
drop policy if exists profiles_update on public.profiles;
create policy profiles_select on public.profiles for select using (true);
create policy profiles_update on public.profiles for update using (id = auth.uid()) with check (id = auth.uid());
alter table public.admins enable row level security;
drop policy if exists admins_select on public.admins;
create policy admins_select on public.admins for select using (true);

-- 3) 앱이 쓰는 RPC --------------------------------------------------------
-- 3-1) 문서 병합 업데이트 (존재해야 함; 권한은 RLS와 동일 판정)
create or replace function public.doc_update(p_collection text, p_id text, p_patch jsonb) returns void
language plpgsql security definer set search_path = public as $$
declare cur jsonb;
begin
  select data into cur from public.docs where collection=p_collection and id=p_id;
  if cur is null then raise exception 'invalid_argument: document does not exist'; end if;
  if not public.doc_can_modify(p_collection,p_id,cur) then raise exception 'invalid_argument: not allowed'; end if;
  update public.docs set data = public.jsonb_deep_merge(cur, p_patch) where collection=p_collection and id=p_id;
end $$;

-- 3-2) 초대 코드로 단체 관리자 합류
create or replace function public.join_org(p_code text) returns text
language plpgsql security definer set search_path = public as $$
declare uid text := auth.uid()::text; r record;
begin
  if uid is null then raise exception 'login required'; end if;
  select id, data into r from public.docs
   where collection='orgs' and data->'invite'->>'code' = upper(p_code)
     and (data->'invite'->>'at')::numeric > (extract(epoch from now())*1000 - 7*86400000) limit 1;
  if r.id is null then raise exception 'invalid_code'; end if;
  if (r.data->'ownerIds') ? uid then return r.id; end if;
  update public.docs set data = jsonb_set(data, '{ownerIds}', coalesce(data->'ownerIds','[]'::jsonb) || to_jsonb(uid)) where collection='orgs' and id=r.id;
  return r.id;
end $$;

-- 3-3) 콜라보 수락/거절 (초대받은 단체의 관리자만)
create or replace function public.collab_answer(p_post text, p_org text, p_accept boolean) returns void
language plpgsql security definer set search_path = public as $$
declare cur jsonb; k text; ts text := (extract(epoch from now())*1000)::bigint::text;
begin
  if not public.owns_org(p_org) then raise exception 'not allowed'; end if;
  select data into cur from public.docs where collection='posts' and id=p_post;
  if cur is null or not (coalesce(cur->'collabs','[]'::jsonb) ? p_org) then raise exception 'not invited'; end if;
  k := case when p_accept then 'collabAccepted' else 'collabDeclined' end;
  update public.docs set data = jsonb_set(data, array[k, p_org], to_jsonb(ts::numeric), true) where collection='posts' and id=p_post;
end $$;

-- 3-4) 신고 카운트 (익명 키로 기록)
create or replace function public.report_target(p_collection text, p_id text, p_key text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'login required'; end if;
  if p_collection not in ('posts','comments') then raise exception 'bad target'; end if;
  update public.docs set data = jsonb_set(data, array['reportedBy', p_key], to_jsonb((extract(epoch from now())*1000)::bigint), true)
   where collection=p_collection and id=p_id;
end $$;

-- 3-5) 스토리 조회 기록
create or replace function public.story_seen(p_id text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return; end if;
  update public.docs set data = jsonb_set(data, array['seen', auth.uid()::text], to_jsonb((extract(epoch from now())*1000)::bigint), true)
   where collection='stories' and id=p_id;
end $$;

-- 3-6) 회원 탈퇴 (본인 데이터 정리 후 계정 삭제)
create or replace function public.delete_me() returns void
language plpgsql security definer set search_path = public as $$
declare uid uuid := auth.uid();
begin
  if uid is null then raise exception 'login required'; end if;
  delete from public.docs where collection in ('people','reports') and id = uid::text;
  delete from public.profiles where id = uid;
  delete from auth.users where id = uid;
end $$;

grant execute on function public.doc_update(text,text,jsonb), public.join_org(text), public.collab_answer(text,text,boolean),
  public.report_target(text,text,text), public.story_seen(text), public.delete_me(), public.is_admin() to authenticated;
grant execute on function public.is_admin() to anon;

-- 4) 실시간 ------------------------------------------------------------------
do $$ begin
  if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and tablename='docs') then
    alter publication supabase_realtime add table public.docs;
  end if;
end $$;

-- 5) 스토리지 (버킷 media: 공개 읽기, 본인 폴더에만 쓰기) -------------------------
insert into storage.buckets (id, name, public) values ('media','media', true) on conflict (id) do update set public = true;
drop policy if exists media_read on storage.objects;
drop policy if exists media_insert on storage.objects;
drop policy if exists media_delete on storage.objects;
create policy media_read on storage.objects for select using (bucket_id = 'media');
create policy media_insert on storage.objects for insert to authenticated with check (bucket_id = 'media' and (storage.foldername(name))[1] = auth.uid()::text);
create policy media_delete on storage.objects for delete to authenticated using (bucket_id = 'media' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_admin()));
