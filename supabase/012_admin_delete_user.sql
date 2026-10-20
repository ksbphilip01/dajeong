-- 012: 관리자 계정 강제 삭제 (관리자 계정·본인은 삭제 불가)
--  삭제 대상: 계정, 개인 프로필, 신고 기록, 이 계정이 쓴 소식·댓글·스토리·칭찬·함께해요 글,
--            이 계정 혼자 관리하던 단체(와 그 단체 소식), 공동 관리 단체에서는 관리자 명단에서만 제외
create or replace function public.admin_delete_user(p_user uuid) returns jsonb
language plpgsql security definer set search_path = public, auth as $$
declare u text := p_user::text; solo text[]; n_posts int; n_orgs int;
begin
  if not public.is_admin() then raise exception 'not allowed'; end if;
  if p_user = auth.uid() then raise exception 'cannot delete yourself'; end if;
  if exists (select 1 from public.admins where user_id = p_user) then raise exception 'cannot delete an admin account'; end if;

  select coalesce(array_agg(id), '{}') into solo from public.docs
   where collection='orgs' and (data->'ownerIds') ? u and jsonb_array_length(coalesce(data->'ownerIds','[]'::jsonb)) = 1;
  n_orgs := coalesce(array_length(solo,1),0);

  -- 공동 관리 단체: 명단에서 제외
  update public.docs set data = jsonb_set(data,'{ownerIds}', (select coalesce(jsonb_agg(x),'[]'::jsonb) from jsonb_array_elements_text(data->'ownerIds') x where x <> u))
   where collection='orgs' and (data->'ownerIds') ? u and not (id = any(solo));

  select count(*) into n_posts from public.docs where collection='posts' and (data->>'authorId' = u or data->>'orgId' = any(solo));
  delete from public.docs where collection='comments' and data->>'postId' in (select id from public.docs where collection='posts' and (data->>'authorId' = u or data->>'orgId' = any(solo)));
  delete from public.docs where collection in ('posts','stories') and (data->>'authorId' = u or data->>'orgId' = any(solo));
  delete from public.docs where collection in ('comments','praise','together') and data->>'authorId' = u;
  delete from public.docs where collection in ('orgs','orgprivate') and id = any(solo);
  delete from public.docs where collection='mod' and id = any(select 'org_'||x from unnest(solo) x);
  delete from public.docs where collection in ('people','reports') and id = u;
  delete from public.docs where collection='mod' and id = 'acct_'||u;
  delete from public.profiles where id = p_user;
  delete from auth.users where id = p_user;
  return jsonb_build_object('posts', n_posts, 'orgs', n_orgs);
end $$;
grant execute on function public.admin_delete_user(uuid) to authenticated;
