-- =====================================================================
--  006: 비밀번호 찾기 질문으로 임시 비밀번호 발급
--   질문에 맞게 답하면 임시 비밀번호(10자리)를 발급하고, 그 비밀번호로 로그인하면
--   바로 새 비밀번호를 정하도록 함. 비밀번호 원문은 어디에도 저장하지 않음.
-- =====================================================================
create table if not exists public.pw_temp (
  user_id uuid primary key references auth.users(id) on delete cascade,
  issued_at timestamptz not null default now()
);
alter table public.pw_temp enable row level security;   -- 정책 없음: 함수로만 접근

-- 결과: {"status":"ok","pw":"..."} / {"status":"wrong"} / {"status":"locked"}
create or replace function public.recovery_temp(p_email text, p_answer text) returns jsonb
language plpgsql security definer set search_path = public, extensions, auth as $$
declare u uuid; r public.recovery%rowtype; pw text;
begin
  select id into u from auth.users where lower(email)=lower(trim(p_email));
  if u is null or exists (select 1 from public.admins a where a.user_id=u) then perform pg_sleep(0.4); return '{"status":"wrong"}'; end if;
  select * into r from public.recovery where user_id=u for update;
  if not found then perform pg_sleep(0.4); return '{"status":"wrong"}'; end if;
  if r.locked_until is not null and r.locked_until > now() then return '{"status":"locked"}'; end if;
  if r.answer_hash <> crypt(public.recovery_norm(p_answer), r.answer_hash) then
    update public.recovery set fails = case when r.fails+1 >= 5 then 0 else r.fails+1 end,
      locked_until = case when r.fails+1 >= 5 then now() + interval '1 hour' else null end where user_id=u;
    return case when r.fails+1 >= 5 then '{"status":"locked"}'::jsonb else '{"status":"wrong"}'::jsonb end;
  end if;
  pw := substr(translate(encode(gen_random_bytes(18),'base64'),'+/=0OoIl1',''),1,10);
  update auth.users set encrypted_password = crypt(pw, gen_salt('bf')), updated_at = now() where id=u;
  update public.recovery set fails=0, locked_until=null where user_id=u;
  insert into public.pw_temp(user_id,issued_at) values (u, now()) on conflict (user_id) do update set issued_at = now();
  begin delete from auth.refresh_tokens where user_id = u::text; exception when others then null; end;
  begin delete from auth.sessions where user_id = u; exception when others then null; end;
  return jsonb_build_object('status','ok','pw',pw);
end $$;

create or replace function public.pw_temp_pending() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.pw_temp where user_id = auth.uid());
$$;

create or replace function public.pw_temp_clear() returns void
language sql security definer set search_path = public as $$
  delete from public.pw_temp where user_id = auth.uid();
$$;

-- 질문 답변으로 바로 비밀번호를 바꾸던 이전 방식은 사용하지 않음
revoke execute on function public.recovery_reset(text,text,text) from anon, authenticated;
drop function if exists public.admin_temp_password(uuid);

revoke all on function public.recovery_temp(text,text) from public;
grant execute on function public.recovery_temp(text,text) to anon, authenticated;
grant execute on function public.pw_temp_pending(), public.pw_temp_clear() to authenticated;
