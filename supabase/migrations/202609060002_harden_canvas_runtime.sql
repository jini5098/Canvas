-- Follow-up hardening discovered by the post-migration security/performance audit.

begin;

create index if not exists artworks_owner_id_idx on public.artworks(owner_id);
create index if not exists artworks_room_id_idx on public.artworks(room_id);
create index if not exists community_comments_author_id_idx on public.community_comments(author_id);
create index if not exists community_posts_author_id_idx on public.community_posts(author_id);
create index if not exists reports_reporter_id_idx on public.reports(reporter_id);
create index if not exists reports_target_user_id_idx on public.reports(target_user_id);
create index if not exists workspace_rooms_created_by_idx on public.workspace_rooms(created_by);

create or replace function public.delete_workspace_room(p_room_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    if not private.is_active_user() then raise exception 'account is not active'; end if;
    if not exists (
        select 1 from public.workspace_rooms
        where id = p_room_id
          and (created_by = (select auth.uid()) or private.is_admin())
    ) then raise exception 'room owner permission required'; end if;
    delete from public.workspace_rooms where id = p_room_id;
end;
$$;

create or replace function public.set_workspace_room_privacy(p_room_id uuid, p_password text default null)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    if not private.is_active_user() then raise exception 'account is not active'; end if;
    if not exists (
        select 1 from public.workspace_rooms
        where id = p_room_id
          and (created_by = (select auth.uid()) or private.is_admin())
    ) then raise exception 'room owner permission required'; end if;
    if p_password is not null and char_length(p_password) not between 4 and 128 then
        raise exception 'room password must have 4 to 128 characters';
    end if;
    update public.workspace_rooms
    set is_private = p_password is not null,
        password_hash = case
            when p_password is null then null
            else extensions.crypt(p_password, extensions.gen_salt('bf'))
        end
    where id = p_room_id;
end;
$$;

create or replace function public.kick_workspace_member(p_room_id uuid, p_target_user uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    if not private.is_active_user() then raise exception 'account is not active'; end if;
    if not exists (
        select 1 from public.workspace_rooms
        where id = p_room_id
          and (created_by = (select auth.uid()) or private.is_admin())
    ) then raise exception 'room owner permission required'; end if;
    if exists (
        select 1 from public.workspace_rooms
        where id = p_room_id and created_by = p_target_user
    ) then raise exception 'room owner cannot be kicked'; end if;
    delete from public.workspace_room_members
    where room_id = p_room_id and user_id = p_target_user;
    perform realtime.send(
        jsonb_build_object('targetUserId', p_target_user),
        'kick_user',
        'room-server:' || p_room_id::text,
        true
    );
end;
$$;

create or replace function public.broadcast_workspace_timer(p_room_id uuid, p_action text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    if not private.is_active_user() then raise exception 'account is not active'; end if;
    if p_action not in ('start', 'stop') then raise exception 'invalid timer action'; end if;
    if not exists (
        select 1 from public.workspace_rooms
        where id = p_room_id
          and (created_by = (select auth.uid()) or private.is_admin())
    ) then raise exception 'room owner permission required'; end if;
    perform realtime.send(
        jsonb_build_object(
            'action', p_action,
            'seconds', 300,
            'senderId', (select auth.uid())
        ),
        'timer',
        'room-server:' || p_room_id::text,
        true
    );
end;
$$;

revoke all on function public.delete_workspace_room(uuid) from public, anon;
revoke all on function public.set_workspace_room_privacy(uuid, text) from public, anon;
revoke all on function public.kick_workspace_member(uuid, uuid) from public, anon;
revoke all on function public.broadcast_workspace_timer(uuid, text) from public, anon;
grant execute on function public.delete_workspace_room(uuid) to authenticated;
grant execute on function public.set_workspace_room_privacy(uuid, text) to authenticated;
grant execute on function public.kick_workspace_member(uuid, uuid) to authenticated;
grant execute on function public.broadcast_workspace_timer(uuid, text) to authenticated;

commit;
