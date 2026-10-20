-- =====================================================================
--  002: 계정 관리 (관리자: 가입 계정 목록, 정지, 반려)
--  SQL Editor 에 붙여 넣고 Run. 여러 번 실행해도 안전합니다.
-- =====================================================================

create table if not exists public.account_status (
  user_id uuid primary key references auth.users(id) on delete cascade,
  status text not null check (status in ('suspended','rejected')),
  reason text not null default '',
  until timestamptz,                 -- null = 기한 없음
  hide_content boolean not null default false,
  at timestamptz not null default now(),
  by uuid
);
alter table public.account_status enable row level security;
drop policy if exists account_status_select on public.account_status;
create policy account_status_select on public.account_status for select using (public.is_admin() or user_id = auth.uid());

-- 현재 사용자가 정지/반려 상태인지
create or replace function public.is_blocked() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.account_status s where s.user_id = auth.uid() and (s.until is null or s.until > now()));
$$;

-- 쓰기 권한에 정지/반려 반영 (기존 함수 덮어쓰기: 맨 앞에 차단 검사만 추가)
create or replace function public.doc_can_write(c text, i text, d jsonb) returns boolean
language plpgsql stable security definer set search_path = public as $$
declare uid text := auth.uid()::text; cid text;
begin
  if uid is null then return false; end if;
  if public.is_admin() then return true; end if;
  if public.is_blocked() then return false; end if;
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

drop policy if exists media_insert on storage.objects;
create policy media_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'media' and (storage.foldername(name))[1] = auth.uid()::text and not public.is_blocked());

-- 관리자: 가입 계정 목록
create or replace function public.admin_list_users()
returns table(id uuid, email text, display_name text, created_at timestamptz, last_sign_in_at timestamptz,
              is_admin boolean, status text, reason text, until timestamptz, hide_content boolean)
language plpgsql stable security definer set search_path = public, auth as $$
begin
  if not public.is_admin() then raise exception 'not allowed'; end if;
  return query
    select u.id, u.email::text, coalesce(p.display_name,''), u.created_at, u.last_sign_in_at,
           exists(select 1 from public.admins a where a.user_id=u.id),
           case when s.user_id is null or (s.until is not null and s.until <= now()) then 'active' else s.status end,
           coalesce(s.reason,''), s.until, coalesce(s.hide_content,false)
    from auth.users u left join public.profiles p on p.id=u.id left join public.account_status s on s.user_id=u.id
    order by u.created_at desc;
end $$;

-- 관리자: 상태 변경 (active / suspended / rejected)
create or replace function public.admin_set_status(p_user uuid, p_status text, p_reason text, p_days int, p_hide boolean)
returns void language plpgsql security definer set search_path = public as $$
declare v_until timestamptz := case when p_days is null or p_days <= 0 then null else now() + make_interval(days => p_days) end;
begin
  if not public.is_admin() then raise exception 'not allowed'; end if;
  if p_user = auth.uid() then raise exception 'cannot change your own account'; end if;
  if exists (select 1 from public.admins where user_id = p_user) then raise exception 'cannot change an admin account'; end if;
  if p_status = 'active' then
    delete from public.account_status where user_id = p_user;
    delete from public.docs where collection='mod' and id = 'acct_' || p_user::text;
    return;
  end if;
  if p_status not in ('suspended','rejected') then raise exception 'bad status'; end if;
  insert into public.account_status(user_id,status,reason,until,hide_content,at,by)
    values (p_user,p_status,coalesce(p_reason,''),v_until,coalesce(p_hide,false),now(),auth.uid())
  on conflict (user_id) do update set status=excluded.status, reason=excluded.reason, until=excluded.until,
    hide_content=excluded.hide_content, at=now(), by=auth.uid();
  -- 공개 표시용(사유 제외): 앱이 이 문서를 보고 콘텐츠를 숨김
  insert into public.docs(collection,id,data) values ('mod','acct_'||p_user::text,
    jsonb_build_object('status',p_status,'hide',coalesce(p_hide,false),
      'until', case when v_until is null then null else (extract(epoch from v_until)*1000)::bigint end))
  on conflict (collection,id) do update set data = excluded.data;
end $$;

grant execute on function public.is_blocked(), public.admin_list_users(), public.admin_set_status(uuid,text,text,int,boolean) to authenticated;
