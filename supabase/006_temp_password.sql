-- =====================================================================
--  006: 관리자 임시 비밀번호 발급
--   비밀번호는 해시로만 저장되어 누구도 열람할 수 없음. 대신 관리자가 임시 비밀번호를 발급하고,
--   사용자는 임시 비밀번호로 로그인한 뒤 바로 새 비밀번호를 정함.
-- =====================================================================
create table if not exists public.pw_temp (
  user_id uuid primary key references auth.users(id) on delete cascade,
  issued_at timestamptz not null default now(),
  issued_by uuid
);
alter table public.pw_temp enable row level security;   -- 정책 없음: 함수로만 접근

create or replace function public.admin_temp_password(p_user uuid) returns text
language plpgsql security definer set search_path = public, extensions, auth as $$
declare pw text;
begin
  if not public.is_admin() then raise exception 'not allowed'; end if;
  if exists (select 1 from public.admins where user_id = p_user) then raise exception 'cannot reset an admin account'; end if;
  pw := substr(translate(encode(gen_random_bytes(18),'base64'),'+/=0OoIl1',''),1,10);
  update auth.users set encrypted_password = crypt(pw, gen_salt('bf')), updated_at = now() where id = p_user;
  if not found then raise exception 'no such user'; end if;
  insert into public.pw_temp(user_id,issued_at,issued_by) values (p_user, now(), auth.uid())
    on conflict (user_id) do update set issued_at = now(), issued_by = auth.uid();
  update public.recovery set fails = 0, locked_until = null where user_id = p_user;
  begin delete from auth.refresh_tokens where user_id = p_user::text; exception when others then null; end;
  begin delete from auth.sessions where user_id = p_user; exception when others then null; end;
  return pw;
end $$;

create or replace function public.pw_temp_pending() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.pw_temp where user_id = auth.uid());
$$;

create or replace function public.pw_temp_clear() returns void
language sql security definer set search_path = public as $$
  delete from public.pw_temp where user_id = auth.uid();
$$;

grant execute on function public.admin_temp_password(uuid), public.pw_temp_pending(), public.pw_temp_clear() to authenticated;
