-- 015: 채널(단체 대화방). 1:1 메시지는 종료. 채널 생성: 승인된 단체 관리자·운영자, 참여·대화: 가입 회원
create or replace function public.doc_can_read(c text, i text, d jsonb) returns boolean
language plpgsql stable security definer set search_path = public as $$
begin
  if c = 'reports' then return public.is_admin() or i = auth.uid()::text; end if;
  if c like 'channels/%/msgs' then return auth.uid() is not null and public.is_member(); end if;
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
  if c = 'channels' then return d->>'ownerUid' = uid; end if;
  if c like 'channels/%/msgs' then return d->>'by' = uid; end if;
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
  if c = 'dms' or c like 'dms/%/msgs' then return false; end if;   -- 1:1 메시지 종료
  if c like 'channels/%/msgs' then return false; end if;           -- channel_post 함수로만
  if c = 'channels' then return public.is_member() and d->>'ownerUid' = uid and ((d->>'orgId') is null or public.owns_org(d->>'orgId')) and ((d->>'orgId') is not null or public.is_admin()); end if;
  if c = 'together' then return d->>'authorId' = uid and d->>'byOrg' is not null and public.owns_org(d->>'byOrg')
     and exists (select 1 from public.docs m where m.collection='mod' and m.id='org_'||(d->>'byOrg') and m.data ? 'verified' and m.data->'verified' <> 'null'::jsonb); end if;
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
  if new.collection in ('posts','comments','stories','orgs','praise','together','channels') or new.collection like 'dms/%/msgs' or new.collection like 'channels/%/msgs' then
    hit := public.banned_hit(concat_ws(' ', new.data->>'caption', new.data->>'text', new.data->>'location',
                                        new.data->>'name', new.data->>'bio', new.data->>'target', new.data->>'title',
                                        new.data->>'place', new.data->>'when', new.data->>'desc'));
    if hit is not null then raise exception 'banned_word:%', hit using errcode = 'P0001'; end if;
  end if;
  return new;
end $$;

-- 채널 참여/나가기
create or replace function public.channel_join(p_id text, p_join boolean) returns int
language plpgsql security definer set search_path = public as $$
declare uid text := auth.uid()::text; n int;
begin
  if uid is null or public.is_blocked() or not public.is_member() then raise exception 'not allowed'; end if;
  if p_join then
    update public.docs set data = jsonb_set(coalesce(data,'{}'::jsonb),'{members}', coalesce(data->'members','{}'::jsonb) || jsonb_build_object(uid,(extract(epoch from now())*1000)::bigint), true)
     where collection='channels' and id=p_id;
  else
    update public.docs set data = data #- array['members',uid] where collection='channels' and id=p_id;
  end if;
  select count(*) into n from public.docs d, jsonb_object_keys(coalesce(d.data->'members','{}'::jsonb)) k where d.collection='channels' and d.id=p_id;
  update public.docs set data = jsonb_set(data,'{memberCount}',to_jsonb(n),true) where collection='channels' and id=p_id;
  return n;
end $$;

-- 채널 메시지 보내기 (참여자만)
create or replace function public.channel_post(p_id text, p_text text, p_as_org text) returns text
language plpgsql security definer set search_path = public as $$
declare uid text := auth.uid()::text; ch jsonb; mid text; t text := left(trim(coalesce(p_text,'')),1000);
begin
  if uid is null or public.is_blocked() or not public.is_member() then raise exception 'not allowed'; end if;
  if length(t) < 1 then raise exception 'empty'; end if;
  select data into ch from public.docs where collection='channels' and id=p_id;
  if ch is null then raise exception 'no channel'; end if;
  if not ((ch->'members') ? uid) and not public.is_admin() then raise exception 'join first'; end if;
  if p_as_org is not null and not public.owns_org(p_as_org) then p_as_org := null; end if;
  mid := to_char(clock_timestamp(),'YYYYMMDDHH24MISSMS') || substr(md5(random()::text),1,6);
  insert into public.docs(collection,id,data) values ('channels/'||p_id||'/msgs', mid,
    jsonb_build_object('by',uid,'asOrg',p_as_org,'text',t,'at',(extract(epoch from now())*1000)::bigint));
  update public.docs set data = data || jsonb_build_object('lastText',left(t,80),'lastAt',(extract(epoch from now())*1000)::bigint,'lastBy',uid)
   where collection='channels' and id=p_id;
  return mid;
end $$;

-- 채널 삭제 시 메시지도 함께 (소유자·운영자)
create or replace function public.channel_delete(p_id text) returns void
language plpgsql security definer set search_path = public as $$
declare ch jsonb;
begin
  select data into ch from public.docs where collection='channels' and id=p_id;
  if ch is null then return; end if;
  if not (ch->>'ownerUid' = auth.uid()::text or public.is_admin()) then raise exception 'not allowed'; end if;
  delete from public.docs where collection = 'channels/'||p_id||'/msgs';
  delete from public.docs where collection='channels' and id=p_id;
end $$;

grant execute on function public.channel_join(text,boolean), public.channel_post(text,text,text), public.channel_delete(text) to authenticated;
