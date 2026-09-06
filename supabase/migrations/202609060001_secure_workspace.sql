-- Canvas secure workspace migration
-- Run once in the Supabase SQL editor before deploying the matching frontend.

create extension if not exists pgcrypto;
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

create table if not exists public.profiles (
    id uuid primary key references auth.users(id) on delete cascade,
    email text,
    nickname text,
    is_banned boolean not null default false,
    created_at timestamptz not null default now()
);
alter table public.profiles add column if not exists email text;
alter table public.profiles add column if not exists nickname text;
alter table public.profiles add column if not exists is_banned boolean not null default false;
alter table public.profiles add column if not exists created_at timestamptz not null default now();
alter table public.profiles add column if not exists role text not null default 'member';
alter table public.profiles add column if not exists banned_until timestamptz;
alter table public.profiles add column if not exists updated_at timestamptz not null default now();
alter table public.profiles drop constraint if exists profiles_role_check;
alter table public.profiles add constraint profiles_role_check check (role in ('member', 'admin'));

update public.profiles set nickname = 'user_' || substr(id::text, 1, 12) where nickname is null or btrim(nickname) = '';
with duplicate_names as (
    select id, row_number() over (partition by lower(nickname) order by created_at nulls last, id) as position
    from public.profiles
)
update public.profiles as profile
set nickname = left(profile.nickname, 13) || '_' || substr(profile.id::text, 1, 6)
from duplicate_names
where duplicate_names.id = profile.id and duplicate_names.position > 1;
create unique index if not exists profiles_nickname_lower_key on public.profiles (lower(nickname));

insert into public.profiles (id, email, nickname)
select users.id, users.email, 'user_' || substr(users.id::text, 1, 12)
from auth.users as users
where not exists (select 1 from public.profiles where profiles.id = users.id)
on conflict (id) do nothing;

create or replace function private.is_active_user()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1 from public.profiles
        where id = (select auth.uid())
          and not coalesce(is_banned, false)
          and (banned_until is null or banned_until <= now())
    );
$$;

create or replace function private.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1 from public.profiles
        where id = (select auth.uid())
          and role = 'admin'
          and not coalesce(is_banned, false)
          and (banned_until is null or banned_until <= now())
    );
$$;

create or replace function private.profile_nickname(user_id uuid)
returns text
language sql
stable
security definer
set search_path = ''
as $$
    select nickname from public.profiles where id = user_id;
$$;

revoke all on function private.is_active_user() from public, anon, authenticated;
revoke all on function private.is_admin() from public, anon, authenticated;
revoke all on function private.profile_nickname(uuid) from public, anon, authenticated;

create or replace function private.normalize_nickname(candidate text, user_id uuid)
returns text
language plpgsql
immutable
set search_path = ''
as $$
declare
    normalized text := btrim(coalesce(candidate, ''));
begin
    if normalized !~ '^[가-힣A-Za-z0-9_.-]{2,20}$' then
        normalized := 'user_' || substr(user_id::text, 1, 12);
    end if;
    return normalized;
end;
$$;
revoke all on function private.normalize_nickname(text, uuid) from public, anon, authenticated;

create or replace function public.handle_new_canvas_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
    candidate text := private.normalize_nickname(new.raw_user_meta_data ->> 'nickname', new.id);
begin
    if exists (select 1 from public.profiles where lower(nickname) = lower(candidate)) then
        candidate := left(candidate, 13) || '_' || substr(new.id::text, 1, 6);
    end if;
    insert into public.profiles (id, email, nickname)
    values (new.id, new.email, candidate)
    on conflict (id) do update set email = excluded.email;
    return new;
end;
$$;

drop trigger if exists on_canvas_auth_user_created on auth.users;
create trigger on_canvas_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_canvas_user();

create or replace function public.touch_canvas_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
    new.updated_at := now();
    return new;
end;
$$;

drop trigger if exists touch_canvas_profiles_updated_at on public.profiles;
create trigger touch_canvas_profiles_updated_at before update on public.profiles
for each row execute function public.touch_canvas_updated_at();

create table if not exists public.workspace_rooms (
    id uuid primary key default gen_random_uuid(),
    name text not null check (char_length(name) between 1 and 60),
    created_by uuid not null references auth.users(id) on delete cascade,
    creator_nickname text not null,
    is_private boolean not null default false,
    password_hash text,
    active boolean not null default true,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    check ((is_private and password_hash is not null) or (not is_private and password_hash is null))
);

create table if not exists public.workspace_room_members (
    room_id uuid not null references public.workspace_rooms(id) on delete cascade,
    user_id uuid not null references auth.users(id) on delete cascade,
    nickname text not null,
    joined_at timestamptz not null default now(),
    primary key (room_id, user_id)
);
create index if not exists workspace_room_members_user_idx on public.workspace_room_members(user_id);

drop trigger if exists touch_canvas_rooms_updated_at on public.workspace_rooms;
create trigger touch_canvas_rooms_updated_at before update on public.workspace_rooms
for each row execute function public.touch_canvas_updated_at();

create or replace function private.is_room_member(room uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select private.is_active_user() and exists (
        select 1 from public.workspace_room_members
        where room_id = room and user_id = (select auth.uid())
    );
$$;

create or replace function private.topic_room_id(topic_name text)
returns uuid
language plpgsql
immutable
set search_path = ''
as $$
begin
    if topic_name !~ '^room(?:-server)?:[0-9a-fA-F-]{36}$' then return null; end if;
    return split_part(topic_name, ':', 2)::uuid;
exception when others then
    return null;
end;
$$;

revoke all on function private.is_room_member(uuid) from public, anon, authenticated;
revoke all on function private.topic_room_id(text) from public, anon, authenticated;
grant usage on schema private to authenticated;
grant execute on function private.is_active_user() to authenticated;
grant execute on function private.is_admin() to authenticated;
grant execute on function private.profile_nickname(uuid) to authenticated;
grant execute on function private.is_room_member(uuid) to authenticated;
grant execute on function private.topic_room_id(text) to authenticated;

create table if not exists public.system_settings (
    key text primary key,
    value text not null default '',
    updated_at timestamptz not null default now()
);
insert into public.system_settings (key, value) values
    ('notice', 'Canvas에 오신 것을 환영합니다.'),
    ('guide', '방을 만들거나 공개방에 입장해 함께 그려보세요.'),
    ('summer_event', 'false')
on conflict (key) do nothing;

create table if not exists public.community_posts (
    id bigint generated by default as identity primary key,
    category text not null default 'free',
    title text not null,
    content text not null,
    author text not null,
    created_at timestamptz not null default now()
);
alter table public.community_posts add column if not exists author_id uuid references auth.users(id) on delete set null;

create table if not exists public.community_comments (
    id bigint generated by default as identity primary key,
    post_id bigint not null references public.community_posts(id) on delete cascade,
    content text not null,
    author text not null,
    created_at timestamptz not null default now()
);
alter table public.community_comments add column if not exists author_id uuid references auth.users(id) on delete set null;

create table if not exists public.reports (
    id bigint generated by default as identity primary key,
    reporter text,
    target_user text,
    reason text not null,
    content text,
    created_at timestamptz not null default now()
);
alter table public.reports add column if not exists reporter_id uuid references auth.users(id) on delete set null;
alter table public.reports add column if not exists target_user_id uuid references auth.users(id) on delete set null;

create table if not exists public.artworks (
    id bigint generated by default as identity primary key,
    room_name text,
    image_url text not null,
    creator text,
    collaborators text,
    is_featured boolean not null default false,
    created_at timestamptz not null default now()
);
alter table public.artworks add column if not exists owner_id uuid references auth.users(id) on delete set null;
alter table public.artworks add column if not exists room_id uuid references public.workspace_rooms(id) on delete set null;
alter table public.artworks add column if not exists storage_path text;
alter table public.artworks add column if not exists is_hidden boolean not null default false;

update public.artworks as artwork set owner_id = profile.id
from public.profiles as profile
where artwork.owner_id is null and lower(artwork.creator) = lower(profile.nickname);
update public.community_posts as post set author_id = profile.id
from public.profiles as profile
where post.author_id is null and lower(post.author) = lower(profile.nickname);
update public.community_comments as comment set author_id = profile.id
from public.profiles as profile
where comment.author_id is null and lower(comment.author) = lower(profile.nickname);
update public.reports as report set reporter_id = profile.id
from public.profiles as profile
where report.reporter_id is null and lower(report.reporter) = lower(profile.nickname);
update public.reports as report set target_user_id = profile.id
from public.profiles as profile
where report.target_user_id is null and lower(report.target_user) = lower(profile.nickname);

drop view if exists public.public_profiles;
create view public.public_profiles with (security_barrier = true) as
select id, nickname from public.profiles
where not coalesce(is_banned, false) and (banned_until is null or banned_until <= now());
revoke all on public.public_profiles from public, anon;
grant select on public.public_profiles to authenticated;

do $$
declare policy_record record;
begin
    for policy_record in
        select tablename, policyname from pg_policies
        where schemaname = 'public'
          and tablename = any (array['profiles','system_settings','community_posts','community_comments','reports','artworks','workspace_rooms','workspace_room_members'])
    loop
        execute format('drop policy if exists %I on public.%I', policy_record.policyname, policy_record.tablename);
    end loop;
end $$;

alter table public.profiles enable row level security;
alter table public.system_settings enable row level security;
alter table public.community_posts enable row level security;
alter table public.community_comments enable row level security;
alter table public.reports enable row level security;
alter table public.artworks enable row level security;
alter table public.workspace_rooms enable row level security;
alter table public.workspace_room_members enable row level security;

create policy profiles_read_self_or_admin on public.profiles for select to authenticated
using (id = (select auth.uid()) or private.is_admin());
create policy profiles_update_self on public.profiles for update to authenticated
using (id = (select auth.uid()) and private.is_active_user())
with check (id = (select auth.uid()) and private.is_active_user());

create policy settings_read_safe on public.system_settings for select to authenticated
using (private.is_active_user() and key in ('notice', 'guide', 'summer_event'));
create policy settings_admin_insert on public.system_settings for insert to authenticated
with check (private.is_admin() and key in ('notice', 'guide', 'summer_event'));
create policy settings_admin_update on public.system_settings for update to authenticated
using (private.is_admin() and key in ('notice', 'guide', 'summer_event'))
with check (private.is_admin() and key in ('notice', 'guide', 'summer_event'));

create policy posts_read_active on public.community_posts for select to authenticated using (private.is_active_user());
create policy posts_insert_own on public.community_posts for insert to authenticated
with check (private.is_active_user() and author_id = (select auth.uid()) and author = private.profile_nickname((select auth.uid())) and char_length(title) between 1 and 100 and char_length(content) between 1 and 5000 and category in ('feedback','idea','free'));
create policy posts_change_own on public.community_posts for update to authenticated
using (author_id = (select auth.uid()) or private.is_admin())
with check (
    private.is_admin()
    or (author_id = (select auth.uid()) and author = private.profile_nickname((select auth.uid())) and char_length(title) between 1 and 100 and char_length(content) between 1 and 5000 and category in ('feedback','idea','free'))
);
create policy posts_delete_own on public.community_posts for delete to authenticated using (author_id = (select auth.uid()) or private.is_admin());

create policy comments_read_active on public.community_comments for select to authenticated using (private.is_active_user());
create policy comments_insert_own on public.community_comments for insert to authenticated
with check (private.is_active_user() and author_id = (select auth.uid()) and author = private.profile_nickname((select auth.uid())) and char_length(content) between 1 and 1000);
create policy comments_change_own on public.community_comments for update to authenticated
using (author_id = (select auth.uid()) or private.is_admin())
with check (private.is_admin() or (author_id = (select auth.uid()) and author = private.profile_nickname((select auth.uid())) and char_length(content) between 1 and 1000));
create policy comments_delete_own on public.community_comments for delete to authenticated using (author_id = (select auth.uid()) or private.is_admin());

create policy reports_insert_own on public.reports for insert to authenticated
with check (private.is_active_user() and reporter_id = (select auth.uid()) and target_user_id <> (select auth.uid()) and reporter = private.profile_nickname((select auth.uid())) and target_user = private.profile_nickname(target_user_id) and char_length(reason) between 1 and 2000);
create policy reports_read_admin on public.reports for select to authenticated using (private.is_admin());
create policy reports_delete_admin on public.reports for delete to authenticated using (private.is_admin());

create policy artworks_read_visible on public.artworks for select to authenticated
using (private.is_active_user() and (not is_hidden or owner_id = (select auth.uid()) or private.is_admin()));
create policy artworks_insert_own on public.artworks for insert to authenticated
with check (private.is_active_user() and owner_id = (select auth.uid()) and creator = private.profile_nickname((select auth.uid())) and private.is_room_member(room_id) and storage_path like (select auth.uid())::text || '/%' and not is_featured and not is_hidden);
create policy artworks_update_admin on public.artworks for update to authenticated
using (private.is_admin()) with check (private.is_admin());
create policy artworks_delete_own on public.artworks for delete to authenticated
using (owner_id = (select auth.uid()) or private.is_admin());

revoke all on public.profiles, public.system_settings, public.community_posts, public.community_comments, public.reports, public.artworks, public.workspace_rooms, public.workspace_room_members from public, anon, authenticated;
grant select (id, nickname, role, is_banned, banned_until, created_at) on public.profiles to authenticated;
grant update (nickname) on public.profiles to authenticated;
grant select, insert, update on public.system_settings to authenticated;
grant select, insert, update, delete on public.community_posts, public.community_comments to authenticated;
grant select, insert, update, delete on public.reports, public.artworks to authenticated;
do $$
declare
    table_name text;
    sequence_name text;
begin
    foreach table_name in array array['community_posts', 'community_comments', 'reports', 'artworks']
    loop
        sequence_name := pg_get_serial_sequence('public.' || table_name, 'id');
        if sequence_name is not null then execute format('grant usage, select on sequence %s to authenticated', sequence_name); end if;
    end loop;
end $$;

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
    order by room.created_at desc
    limit 100;
$$;

create or replace function public.list_workspace_room_members(p_room_id uuid)
returns table (user_id uuid, nickname text)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
    if not private.is_room_member(p_room_id) then raise exception 'room membership required'; end if;
    return query
    select member.user_id, member.nickname
    from public.workspace_room_members as member
    where member.room_id = p_room_id
    order by member.joined_at;
end;
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
    if not private.is_active_user() then raise exception 'account is not active'; end if;
    if char_length(btrim(coalesce(p_name, ''))) not between 1 and 60 then raise exception 'invalid room name'; end if;
    if p_password is not null and char_length(p_password) < 4 then raise exception 'room password must have at least 4 characters'; end if;
    select profile.nickname into nickname_value from public.profiles as profile where profile.id = (select auth.uid());
    insert into public.workspace_rooms (name, created_by, creator_nickname, is_private, password_hash)
    values (btrim(p_name), (select auth.uid()), nickname_value, p_password is not null, case when p_password is null then null else crypt(p_password, gen_salt('bf')) end)
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
    if selected_room.is_private and selected_room.created_by <> (select auth.uid()) and not private.is_admin()
       and (p_password is null or selected_room.password_hash <> crypt(p_password, selected_room.password_hash)) then
        raise exception 'invalid room password';
    end if;
    select profile.nickname into nickname_value from public.profiles as profile where profile.id = (select auth.uid());
    insert into public.workspace_room_members (room_id, user_id, nickname)
    values (selected_room.id, (select auth.uid()), nickname_value)
    on conflict (room_id, user_id) do update set nickname = excluded.nickname, joined_at = now();
    return query select selected_room.id, selected_room.name, selected_room.created_by, selected_room.creator_nickname, selected_room.is_private, selected_room.created_at;
end;
$$;

create or replace function public.leave_workspace_room(p_room_id uuid)
returns void
language sql
security definer
set search_path = ''
as $$
    delete from public.workspace_room_members where room_id = p_room_id and user_id = (select auth.uid());
$$;

create or replace function public.delete_workspace_room(p_room_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    if not exists (select 1 from public.workspace_rooms where id = p_room_id and (created_by = (select auth.uid()) or private.is_admin())) then raise exception 'room owner permission required'; end if;
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
    if not exists (select 1 from public.workspace_rooms where id = p_room_id and (created_by = (select auth.uid()) or private.is_admin())) then raise exception 'room owner permission required'; end if;
    if p_password is not null and char_length(p_password) < 4 then raise exception 'room password must have at least 4 characters'; end if;
    update public.workspace_rooms set is_private = p_password is not null, password_hash = case when p_password is null then null else crypt(p_password, gen_salt('bf')) end where id = p_room_id;
end;
$$;

create or replace function public.kick_workspace_member(p_room_id uuid, p_target_user uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    if not exists (select 1 from public.workspace_rooms where id = p_room_id and (created_by = (select auth.uid()) or private.is_admin())) then raise exception 'room owner permission required'; end if;
    if exists (select 1 from public.workspace_rooms where id = p_room_id and created_by = p_target_user) then raise exception 'room owner cannot be kicked'; end if;
    delete from public.workspace_room_members where room_id = p_room_id and user_id = p_target_user;
    perform realtime.send(jsonb_build_object('targetUserId', p_target_user), 'kick_user', 'room-server:' || p_room_id::text, true);
end;
$$;

create or replace function public.broadcast_workspace_timer(p_room_id uuid, p_action text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    if p_action not in ('start', 'stop') then raise exception 'invalid timer action'; end if;
    if not exists (select 1 from public.workspace_rooms where id = p_room_id and (created_by = (select auth.uid()) or private.is_admin())) then raise exception 'room owner permission required'; end if;
    perform realtime.send(jsonb_build_object('action', p_action, 'seconds', 300, 'senderId', (select auth.uid())), 'timer', 'room-server:' || p_room_id::text, true);
end;
$$;

create or replace function public.broadcast_workspace_chat(p_room_id uuid, p_message text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
    nickname_value text;
begin
    if not private.is_room_member(p_room_id) then raise exception 'room membership required'; end if;
    if char_length(btrim(coalesce(p_message, ''))) not between 1 and 500 then raise exception 'chat message must be between 1 and 500 characters'; end if;
    select nickname into nickname_value from public.profiles where id = (select auth.uid());
    perform realtime.send(
        jsonb_build_object('senderId', (select auth.uid()), 'senderNickname', nickname_value, 'message', btrim(p_message)),
        'chat', 'room-server:' || p_room_id::text, true
    );
end;
$$;

create or replace function public.set_workspace_user_ban(p_user_id uuid, p_is_banned boolean, p_banned_until timestamptz default null)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    if not private.is_admin() then raise exception 'admin permission required'; end if;
    if p_user_id = (select auth.uid()) then raise exception 'you cannot ban yourself'; end if;
    if p_is_banned and p_banned_until is not null then raise exception 'permanent ban cannot have an end date'; end if;
    update public.profiles set is_banned = p_is_banned, banned_until = case when p_is_banned then null else p_banned_until end where id = p_user_id;
    if not found then raise exception 'user not found'; end if;
    if p_is_banned or p_banned_until > now() then
        perform realtime.send(jsonb_build_object('action', 'ban_user', 'targetUserId', p_user_id), 'system_update', 'system:global', true);
    end if;
end;
$$;

revoke all on function public.list_workspace_rooms() from public, anon;
revoke all on function public.list_workspace_room_members(uuid) from public, anon;
revoke all on function public.create_workspace_room(text, text) from public, anon;
revoke all on function public.join_workspace_room(uuid, text) from public, anon;
revoke all on function public.leave_workspace_room(uuid) from public, anon;
revoke all on function public.delete_workspace_room(uuid) from public, anon;
revoke all on function public.set_workspace_room_privacy(uuid, text) from public, anon;
revoke all on function public.kick_workspace_member(uuid, uuid) from public, anon;
revoke all on function public.broadcast_workspace_timer(uuid, text) from public, anon;
revoke all on function public.broadcast_workspace_chat(uuid, text) from public, anon;
revoke all on function public.set_workspace_user_ban(uuid, boolean, timestamptz) from public, anon;
grant execute on function public.list_workspace_rooms() to authenticated;
grant execute on function public.list_workspace_room_members(uuid) to authenticated;
grant execute on function public.create_workspace_room(text, text) to authenticated;
grant execute on function public.join_workspace_room(uuid, text) to authenticated;
grant execute on function public.leave_workspace_room(uuid) to authenticated;
grant execute on function public.delete_workspace_room(uuid) to authenticated;
grant execute on function public.set_workspace_room_privacy(uuid, text) to authenticated;
grant execute on function public.kick_workspace_member(uuid, uuid) to authenticated;
grant execute on function public.broadcast_workspace_timer(uuid, text) to authenticated;
grant execute on function public.broadcast_workspace_chat(uuid, text) to authenticated;
grant execute on function public.set_workspace_user_ban(uuid, boolean, timestamptz) to authenticated;

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('canvas-artworks', 'canvas-artworks', true, 10485760, array['image/png'])
on conflict (id) do update set public = excluded.public, file_size_limit = excluded.file_size_limit, allowed_mime_types = excluded.allowed_mime_types;

do $$
declare policy_record record;
begin
    for policy_record in
        select policyname from pg_policies
        where schemaname = 'storage' and tablename = 'objects'
          and (coalesce(qual, '') ilike '%canvas-artworks%' or coalesce(with_check, '') ilike '%canvas-artworks%')
    loop
        execute format('drop policy if exists %I on storage.objects', policy_record.policyname);
    end loop;
end $$;

create policy canvas_artworks_public_read on storage.objects for select to public using (bucket_id = 'canvas-artworks');
create policy canvas_artworks_owner_insert on storage.objects for insert to authenticated
with check (bucket_id = 'canvas-artworks' and (storage.foldername(name))[1] = (select auth.uid())::text and private.is_active_user());
create policy canvas_artworks_owner_delete on storage.objects for delete to authenticated
using (bucket_id = 'canvas-artworks' and ((storage.foldername(name))[1] = (select auth.uid())::text or private.is_admin()));

drop policy if exists canvas_realtime_read on realtime.messages;
drop policy if exists canvas_realtime_send on realtime.messages;
create policy canvas_realtime_read on realtime.messages for select to authenticated
using (
    (select realtime.topic()) = 'system:global'
    or private.is_room_member(private.topic_room_id((select realtime.topic())))
);
create policy canvas_realtime_send on realtime.messages for insert to authenticated
with check (
    ((select realtime.topic()) = 'system:global' and private.is_admin())
    or (
        (select realtime.topic()) ~ '^room:[0-9a-fA-F-]{36}$'
        and private.is_room_member(private.topic_room_id((select realtime.topic())))
        and extension in ('presence', 'broadcast')
    )
);

-- After this migration:
-- 1. Set the owner's role once: update public.profiles set role = 'admin' where id = '<OWNER USER UUID>';
-- 2. In Realtime Settings, turn off "Allow public access" so private-channel policies are enforced.
