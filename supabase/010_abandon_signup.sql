-- 010: 가입을 끝까지 마치지 않은 계정 정리 (개인 프로필도, 단체도 없는 계정만. 관리자 제외)
create or replace function public.abandon_signup() returns boolean
language plpgsql security definer set search_path = public, auth as $$
declare uid uuid := auth.uid();
begin
  if uid is null then return false; end if;
  if public.is_admin() or public.is_member() then return false; end if;
  delete from public.docs where collection in ('people','reports') and id = uid::text;
  delete from public.profiles where id = uid;
  delete from auth.users where id = uid;
  return true;
end $$;
grant execute on function public.abandon_signup() to authenticated;
