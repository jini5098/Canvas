-- Anonymous visitors can collaborate in public rooms. Account-owned writes
-- remain available only to registered members.
begin;

create or replace function private.is_registered_user()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select private.is_active_user() and exists (
        select 1 from auth.users
        where id = (select auth.uid()) and is_anonymous is false
    );
$$;
revoke all on function private.is_registered_user() from public, anon;
grant execute on function private.is_registered_user() to authenticated;

create or replace function private.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select private.is_registered_user() and exists (
        select 1 from public.profiles
        where id = (select auth.uid()) and role = 'admin'
    );
$$;

create or replace function private.handle_new_canvas_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
    candidate text;
begin
    if new.is_anonymous is true then
        candidate := 'Guest_' || substr(replace(new.id::text, '-', ''), 1, 12);
    else
        candidate := private.normalize_nickname(new.raw_user_meta_data ->> 'nickname', new.id);
    end if;
    if exists (select 1 from public.profiles where lower(nickname) = lower(candidate)) then
        candidate := left(candidate, 13) || '_' || substr(new.id::text, 1, 6);
    end if;
    insert into public.profiles (id, email, nickname)
    values (new.id, new.email, candidate)
    on conflict (id) do update set email = excluded.email;
    return new;
end;
$$;

create or replace function private.is_room_member(room uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select private.is_active_user() and exists (
        select 1
        from public.workspace_room_members as member
        join public.workspace_rooms as workspace on workspace.id = member.room_id
        where member.room_id = room and member.user_id = (select auth.uid())
          and workspace.active
          and (not workspace.is_private or private.is_registered_user())
    );
$$;

create or replace function public.list_workspace_rooms()
returns table (id uuid, name text, created_by uuid, creator_nickname text, is_private boolean, created_at timestamptz)
language sql
stable
security definer
set search_path = ''
as $$
    select room.id, room.name, room.created_by, room.creator_nickname, room.is_private, room.created_at
    from public.workspace_rooms as room
    where room.active and private.is_active_user()
      and (not room.is_private or private.is_registered_user())
    order by room.created_at desc
    limit 100;
$$;

create or replace function public.create_workspace_room(p_name text, p_password text default null)
returns table (id uuid, name text, created_by uuid, creator_nickname text, is_private boolean, created_at timestamptz)
language plpgsql
security definer
set search_path = ''
as $$
declare
    new_room public.workspace_rooms%rowtype;
    nickname_value text;
begin
    if not private.is_registered_user() then raise exception 'member account required to create rooms'; end if;
    if char_length(btrim(coalesce(p_name, ''))) not between 1 and 60 then raise exception 'invalid room name'; end if;
    if p_password is not null and char_length(p_password) not between 4 and 128 then raise exception 'room password must have 4 to 128 characters'; end if;
    select profile.nickname into nickname_value from public.profiles as profile where profile.id = (select auth.uid());
    insert into public.workspace_rooms (name, created_by, creator_nickname, is_private, password_hash)
    values (btrim(p_name), (select auth.uid()), nickname_value, p_password is not null, case when p_password is null then null else extensions.crypt(p_password, extensions.gen_salt('bf')) end)
    returning * into new_room;
    insert into public.workspace_room_members (room_id, user_id, nickname)
    values (new_room.id, (select auth.uid()), nickname_value);
    return query select new_room.id, new_room.name, new_room.created_by, new_room.creator_nickname, new_room.is_private, new_room.created_at;
end;
$$;

create or replace function public.join_workspace_room(p_room_id uuid, p_password text default null)
returns table (id uuid, name text, created_by uuid, creator_nickname text, is_private boolean, created_at timestamptz)
language plpgsql
security definer
set search_path = ''
as $$
declare
    selected_room public.workspace_rooms%rowtype;
    nickname_value text;
begin
    if not private.is_active_user() then raise exception 'account is not active'; end if;
    select * into selected_room from public.workspace_rooms where workspace_rooms.id = p_room_id and active;
    if not found then raise exception 'room not found'; end if;
    if selected_room.is_private and not private.is_registered_user() then raise exception 'member account required for private rooms'; end if;
    if p_password is not null and char_length(p_password) > 128 then raise exception 'invalid room password'; end if;
    if selected_room.is_private and selected_room.created_by <> (select auth.uid()) and not private.is_admin()
       and (p_password is null or selected_room.password_hash <> extensions.crypt(p_password, selected_room.password_hash)) then
        raise exception 'invalid room password';
    end if;
    select profile.nickname into nickname_value from public.profiles as profile where profile.id = (select auth.uid());
    insert into public.workspace_room_members (room_id, user_id, nickname)
    values (selected_room.id, (select auth.uid()), nickname_value)
    on conflict (room_id, user_id) do update set nickname = excluded.nickname, joined_at = now();
    return query select selected_room.id, selected_room.name, selected_room.created_by, selected_room.creator_nickname, selected_room.is_private, selected_room.created_at;
end;
$$;

create or replace function public.set_workspace_room_privacy(p_room_id uuid, p_password text default null)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
    removed_user uuid;
begin
    if not private.is_registered_user() then raise exception 'member account required'; end if;
    if not exists (
        select 1 from public.workspace_rooms
        where id = p_room_id and (created_by = (select auth.uid()) or private.is_admin())
    ) then raise exception 'room owner permission required'; end if;
    if p_password is not null and char_length(p_password) not between 4 and 128 then
        raise exception 'room password must have 4 to 128 characters';
    end if;
    -- Notify existing guests while the room is still public, then remove their
    -- membership before making it private. New joins are checked above.
    if p_password is not null then
        for removed_user in
            delete from public.workspace_room_members as member
            using auth.users as account
            where member.room_id = p_room_id and member.user_id = account.id
              and account.is_anonymous is true
            returning member.user_id
        loop
            perform realtime.send(
                jsonb_build_object('targetUserId', removed_user, 'reason', '방이 비공개로 바뀌어 로비로 이동합니다. 회원 로그인 후 다시 입장해주세요.'),
                'kick_user', 'room-server:' || p_room_id::text, true
            );
        end loop;
    end if;
    update public.workspace_rooms
    set is_private = p_password is not null,
        password_hash = case when p_password is null then null else extensions.crypt(p_password, extensions.gen_salt('bf')) end
    where id = p_room_id;
end;
$$;

-- Restrictive policies are ANDed with the existing ownership/validation rules.
-- Reads, reports and public-room messages remain available to guests.
create policy profiles_registered_update on public.profiles as restrictive
for update to authenticated
using (private.is_registered_user()) with check (private.is_registered_user());

do $$
declare
    target_table text;
begin
    foreach target_table in array array['community_posts', 'community_comments', 'artworks'] loop
        execute format('create policy %I on public.%I as restrictive for insert to authenticated with check (private.is_registered_user())', target_table || '_registered_insert', target_table);
        execute format('create policy %I on public.%I as restrictive for update to authenticated using (private.is_registered_user()) with check (private.is_registered_user())', target_table || '_registered_update', target_table);
        execute format('create policy %I on public.%I as restrictive for delete to authenticated using (private.is_registered_user())', target_table || '_registered_delete', target_table);
    end loop;
end;
$$;

create policy canvas_storage_registered_insert on storage.objects as restrictive
for insert to authenticated
with check (bucket_id <> 'canvas-artworks' or private.is_registered_user());
create policy canvas_storage_registered_delete on storage.objects as restrictive
for delete to authenticated
using (bucket_id <> 'canvas-artworks' or private.is_registered_user());

commit;
