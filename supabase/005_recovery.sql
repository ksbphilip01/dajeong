-- =====================================================================
--  005: 비밀번호 찾기 질문·답변
--   답변은 원문을 저장하지 않고 bcrypt 해시로만 저장. 5번 틀리면 1시간 잠금.
--   관리자 계정은 질문·답변으로 재설정할 수 없음(이메일 재설정만).
-- =====================================================================
create extension if not exists pgcrypto with schema extensions;

create table if not exists public.recovery (
  user_id uuid primary key references auth.users(id) on delete cascade,
  question text not null,
  answer_hash text not null,
  fails int not null default 0,
  locked_until timestamptz,
  updated_at timestamptz not null default now()
);
alter table public.recovery enable row level security;   -- 정책 없음: 함수로만 접근

create or replace function public.recovery_norm(a text) returns text
language sql immutable as $$ select regexp_replace(lower(coalesce(a,'')), '\s+', '', 'g') $$;

-- 내 질문·답변 설정(변경)
create or replace function public.set_recovery(p_question text, p_answer text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  if length(trim(coalesce(p_question,''))) < 4 then raise exception 'question too short'; end if;
  if length(public.recovery_norm(p_answer)) < 2 then raise exception 'answer too short'; end if;
  insert into public.recovery(user_id,question,answer_hash,fails,locked_until,updated_at)
    values (auth.uid(), left(trim(p_question),80), crypt(public.recovery_norm(p_answer), gen_salt('bf')), 0, null, now())
  on conflict (user_id) do update set question=excluded.question, answer_hash=excluded.answer_hash, fails=0, locked_until=null, updated_at=now();
end $$;

-- 내 질문 (설정 여부 확인용)
create or replace function public.my_recovery_question() returns text
language sql stable security definer set search_path = public as $$
  select question from public.recovery where user_id = auth.uid();
$$;

-- 이메일로 질문 조회 (가입 여부가 드러나지 않도록 없는 이메일에도 그럴듯한 질문을 돌려줌)
create or replace function public.recovery_question(p_email text) returns text
language plpgsql stable security definer set search_path = public, auth as $$
declare q text; fakes text[] := array['처음 다닌 초등학교 이름은?','가장 좋아하는 여수의 장소는?','어릴 적 별명은?','처음 키운 반려동물 이름은?','가장 기억에 남는 선생님 성함은?'];
begin
  select r.question into q from auth.users u join public.recovery r on r.user_id=u.id
    where lower(u.email)=lower(trim(p_email)) and not exists (select 1 from public.admins a where a.user_id=u.id);
  if q is not null then return q; end if;
  return fakes[1 + (abs(hashtext(lower(trim(coalesce(p_email,''))))) % array_length(fakes,1))];
end $$;

-- 답변 확인 후 새 비밀번호로 변경. 결과: ok / wrong / locked / weak
create or replace function public.recovery_reset(p_email text, p_answer text, p_new_password text) returns text
language plpgsql security definer set search_path = public, extensions, auth as $$
declare u uuid; r public.recovery%rowtype;
begin
  if length(coalesce(p_new_password,'')) < 6 then return 'weak'; end if;
  select id into u from auth.users where lower(email)=lower(trim(p_email));
  if u is null or exists (select 1 from public.admins a where a.user_id=u) then perform pg_sleep(0.4); return 'wrong'; end if;
  select * into r from public.recovery where user_id=u for update;
  if not found then perform pg_sleep(0.4); return 'wrong'; end if;
  if r.locked_until is not null and r.locked_until > now() then return 'locked'; end if;
  if r.answer_hash <> crypt(public.recovery_norm(p_answer), r.answer_hash) then
    update public.recovery set fails = case when r.fails+1 >= 5 then 0 else r.fails+1 end,
      locked_until = case when r.fails+1 >= 5 then now() + interval '1 hour' else null end where user_id=u;
    return case when r.fails+1 >= 5 then 'locked' else 'wrong' end;
  end if;
  update auth.users set encrypted_password = crypt(p_new_password, gen_salt('bf')), updated_at = now() where id=u;
  update public.recovery set fails=0, locked_until=null where user_id=u;
  begin delete from auth.refresh_tokens where user_id = u::text; exception when others then null; end;
  begin delete from auth.sessions where user_id = u; exception when others then null; end;
  return 'ok';
end $$;

revoke all on function public.recovery_reset(text,text,text), public.recovery_question(text) from public;
grant execute on function public.recovery_question(text), public.recovery_reset(text,text,text) to anon, authenticated;
grant execute on function public.set_recovery(text,text), public.my_recovery_question() to authenticated;
