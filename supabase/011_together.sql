-- 011: 함께해요 게시판 (collection: together) — 칭찬합니다와 같은 규칙
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
  if c = 'together' then return public.is_member() and d->>'authorId' = uid and (d->>'byOrg' is null or public.owns_org(d->>'byOrg')); end if;
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
  if new.collection in ('posts','comments','stories','orgs','praise','together') or new.collection like 'dms/%/msgs' then
    hit := public.banned_hit(concat_ws(' ', new.data->>'caption', new.data->>'text', new.data->>'location',
                                        new.data->>'name', new.data->>'bio', new.data->>'target', new.data->>'title',
                                        new.data->>'place', new.data->>'when'));
    if hit is not null then raise exception 'banned_word:%', hit using errcode = 'P0001'; end if;
  end if;
  return new;
end $$;

create or replace function public.report_target(p_collection text, p_id text, p_key text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'login required'; end if;
  if p_collection not in ('posts','comments','praise','together') then raise exception 'bad target'; end if;
  update public.docs set data = jsonb_set(data, array['reportedBy', p_key], to_jsonb((extract(epoch from now())*1000)::bigint), true)
   where collection=p_collection and id=p_id;
end $$;

-- '저도 함께할게요' 토글
create or replace function public.together_join(p_id text) returns void
language plpgsql security definer set search_path = public as $$
declare uid text := auth.uid()::text;
begin
  if uid is null or public.is_blocked() or not public.is_member() then raise exception 'not allowed'; end if;
  update public.docs set data = case when (data->'joins') ? uid
      then data #- array['joins', uid]
      else jsonb_set(coalesce(data,'{}'::jsonb), '{joins}', coalesce(data->'joins','{}'::jsonb) || jsonb_build_object(uid, (extract(epoch from now())*1000)::bigint), true) end
   where collection='together' and id=p_id;
end $$;
grant execute on function public.together_join(text) to authenticated;
