-- =====================================================================
--  003: 운영 원칙 반영
--   1) 1:1 메시지는 당사자만 읽기·수정 (관리자도 열람 불가)
--   2) 금지어(정치 직함, 지역 전·현직 정치인 이름) 서버 차단
--  SQL Editor 에 붙여 넣고 Run. 여러 번 실행해도 안전합니다.
-- =====================================================================

-- 1) 메시지: 관리자 예외 없이 당사자만
create or replace function public.dm_party_ok(c text, d jsonb) returns boolean
language plpgsql stable security definer set search_path = public as $$
declare cid text;
begin
  if auth.uid() is null then return false; end if;
  if c = 'dms' then
    return exists (select 1 from jsonb_array_elements_text(coalesce(d->'parties','[]'::jsonb)) p where public.owns_party(p));
  end if;
  cid := split_part(c,'/',2);
  return exists (select 1 from public.docs x, jsonb_array_elements_text(coalesce(x.data->'parties','[]'::jsonb)) p
                 where x.collection='dms' and x.id=cid and public.owns_party(p));
end $$;

create or replace function public.doc_can_read(c text, i text, d jsonb) returns boolean
language plpgsql stable security definer set search_path = public as $$
begin
  if c = 'reports' then return public.is_admin() or i = auth.uid()::text; end if;
  if c = 'dms' or c like 'dms/%/msgs' then return public.dm_party_ok(c,d); end if;
  return true;
end $$;

create or replace function public.doc_can_modify(c text, i text, d jsonb) returns boolean
language plpgsql stable security definer set search_path = public as $$
declare uid text := auth.uid()::text;
begin
  if uid is null then return false; end if;
  if c = 'dms' or c like 'dms/%/msgs' then return public.dm_party_ok(c,d); end if;   -- 관리자 예외 없음
  if public.is_admin() then return true; end if;
  if c in ('people','reports') then return i = uid; end if;
  if c in ('mod','notices') then return false; end if;
  if c = 'orgs' then return (d->'ownerIds') ? uid; end if;
  if c = 'posts' then return d->>'authorId' = uid or public.owns_org(d->>'orgId'); end if;
  if c = 'comments' then return d->>'authorId' = uid; end if;
  if c = 'stories' then return d->>'authorId' = uid or public.owns_org(d->>'orgId'); end if;
  return false;
end $$;

-- 2) 금지어
create or replace function public.banned_hit(txt text) returns text
language plpgsql stable security definer set search_path = public as $$
declare t text := regexp_replace(coalesce(txt,''), '\s+', '', 'g'); w text; extra jsonb;
  base text[] := array['시의원','도의원','구의원','군의원','국회의원','대통령','국무총리','도지사','구청장','군수',
                       '시장님','시장후보','여수시장','여수시시장','지역위원장','당협위원장','공천','선거운동'];
begin
  if t = '' then return null; end if;
  foreach w in array base loop if position(w in t) > 0 then return w; end if; end loop;
  -- '시장' 이 직함으로 쓰인 경우 (수산시장·전통시장 등 장터는 허용)
  if t ~ '(^|[^가-힣])시장(님|후보|선거|당선|출마|께서|실)' then return '시장'; end if;
  select data->'words' into extra from public.docs where collection='mod' and id='banned';
  if extra is not null then
    for w in select regexp_replace(jsonb_array_elements_text(extra),'\s+','','g') loop
      if length(w) >= 2 and position(w in t) > 0 then return w; end if;
    end loop;
  end if;
  return null;
end $$;

create or replace function public.check_banned() returns trigger
language plpgsql security definer set search_path = public as $$
declare hit text;
begin
  if new.collection in ('posts','comments','stories','orgs') or new.collection like 'dms/%/msgs' then
    hit := public.banned_hit(concat_ws(' ', new.data->>'caption', new.data->>'text', new.data->>'location',
                                        new.data->>'name', new.data->>'bio'));
    if hit is not null then raise exception 'banned_word:%', hit using errcode = 'P0001'; end if;
  end if;
  return new;
end $$;
drop trigger if exists docs_banned on public.docs;
create trigger docs_banned before insert or update on public.docs for each row execute procedure public.check_banned();

grant execute on function public.banned_hit(text) to anon, authenticated;
