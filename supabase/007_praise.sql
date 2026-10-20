-- =====================================================================
--  007: 칭찬합니다 게시판 (collection: praise)
--   가입한 사람은 누구나 칭찬 글을 쓸 수 있고, 본인 글만 수정·삭제. 금지어·신고 적용.
--   '저도 칭찬해요'는 praise_cheer 함수로만 기록.
-- =====================================================================
create or replace function public.doc_can_modify(c text, i text, d jsonb) returns boolean
language plpgsql stable security definer set search_path = public as $$
declare uid text := auth.uid()::text;
begin
  if uid is null then return false; end if;
  if c = 'dms' or c like 'dms/%/msgs' then return public.dm_party_ok(c,d); end if;
  if public.is_admin() then return true; end if;
  if c = 'orgprivate' then return public.owns_org(i); end if;
  if c in ('people','reports') then return i = uid; end if;
  if c in ('mod','notices') then return false; end if;
  if c = 'orgs' then return (d->'ownerIds') ? uid; end if;
  if c = 'posts' then return d->>'authorId' = uid or public.owns_org(d->>'orgId'); end if;
  if c = 'comments' then return d->>'authorId' = uid; end if;
  if c = 'praise' then return d->>'authorId' = uid; end if;
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
  if c = 'posts' then return d->>'authorId' = uid and (d->>'orgId' is null or public.owns_org(d->>'orgId')); end if;
  if c = 'comments' then return d->>'authorId' = uid; end if;
  if c = 'praise' then return d->>'authorId' = uid and (d->>'byOrg' is null or public.owns_org(d->>'byOrg')); end if;
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

create or replace function public.check_banned() returns trigger
language plpgsql security definer set search_path = public as $$
declare hit text;
begin
  if new.collection in ('posts','comments','stories','orgs','praise') or new.collection like 'dms/%/msgs' then
    hit := public.banned_hit(concat_ws(' ', new.data->>'caption', new.data->>'text', new.data->>'location',
                                        new.data->>'name', new.data->>'bio', new.data->>'target'));
    if hit is not null then raise exception 'banned_word:%', hit using errcode = 'P0001'; end if;
  end if;
  return new;
end $$;

create or replace function public.report_target(p_collection text, p_id text, p_key text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'login required'; end if;
  if p_collection not in ('posts','comments','praise') then raise exception 'bad target'; end if;
  update public.docs set data = jsonb_set(data, array['reportedBy', p_key], to_jsonb((extract(epoch from now())*1000)::bigint), true)
   where collection=p_collection and id=p_id;
end $$;

-- '저도 칭찬해요' 토글
create or replace function public.praise_cheer(p_id text) returns void
language plpgsql security definer set search_path = public as $$
declare uid text := auth.uid()::text;
begin
  if uid is null or public.is_blocked() then raise exception 'not allowed'; end if;
  update public.docs set data = case when (data->'cheers') ? uid
      then data #- array['cheers', uid]
      else jsonb_set(coalesce(data,'{}'::jsonb), '{cheers}', coalesce(data->'cheers','{}'::jsonb) || jsonb_build_object(uid, (extract(epoch from now())*1000)::bigint), true) end
   where collection='praise' and id=p_id;
end $$;
grant execute on function public.praise_cheer(text) to authenticated;
