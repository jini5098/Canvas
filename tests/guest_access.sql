-- Integration check for the deployed schema. Run as postgres. All fixture
-- users, rooms, reports and messages are rolled back, including on failure.
begin;
do $$
declare
    guest_id uuid := gen_random_uuid();
    owner_id uuid;
    owner_nick text;
    guest_nick text;
    public_room uuid;
    private_room uuid;
    denied boolean;
    changed_count integer;
begin
    select profile.id, profile.nickname into strict owner_id, owner_nick
    from public.profiles as profile join auth.users as account on account.id = profile.id
    where profile.role = 'admin' and account.is_anonymous is false limit 1;
    insert into auth.users (id, aud, role, is_anonymous, raw_user_meta_data)
    values (guest_id, 'authenticated', 'authenticated', true, '{"nickname":"admin","role":"admin","is_anonymous":false}');
    select nickname into strict guest_nick from public.profiles where id = guest_id;
    if guest_nick not like 'Guest_%' then raise exception 'anonymous metadata must not control the guest label'; end if;

    perform set_config('request.jwt.claim.sub', owner_id::text, true);
    perform set_config('request.jwt.claims', jsonb_build_object('sub', owner_id, 'role', 'authenticated', 'is_anonymous', false)::text, true);
    execute 'set local role authenticated';
    if not private.is_admin() then raise exception 'registered admin access regressed'; end if;
    select id into public_room from public.create_workspace_room('Guest integration check', null);
    select id into private_room from public.create_workspace_room('Guest private check', 'temporary-test-password');

    perform set_config('request.jwt.claim.sub', guest_id::text, true);
    -- Even a fabricated claim cannot promote an anonymous Auth row.
    perform set_config('request.jwt.claims', jsonb_build_object('sub', guest_id, 'role', 'authenticated', 'is_anonymous', false)::text, true);
    if private.is_registered_user() or private.is_admin() then raise exception 'guest gained member privileges'; end if;
    if not exists (select 1 from public.list_workspace_rooms() where id = public_room) then raise exception 'guest cannot list a public room'; end if;
    if exists (select 1 from public.list_workspace_rooms() where id = private_room) then raise exception 'guest can list a private room'; end if;
    perform public.join_workspace_room(public_room, null);
    if not private.is_room_member(public_room) then raise exception 'guest cannot join a public room'; end if;
    if not exists (select 1 from public.list_workspace_room_members(public_room) where user_id = guest_id) then raise exception 'guest missing from participants'; end if;
    perform public.broadcast_workspace_chat(public_room, 'transactional guest check');

    denied := false;
    begin
        perform public.create_workspace_room('Must not be created', null);
    exception when raise_exception then
        denied := sqlerrm = 'member account required to create rooms';
    end;
    if not denied then raise exception 'guest room creation was not rejected'; end if;
    denied := false;
    begin
        perform public.join_workspace_room(private_room, 'temporary-test-password');
    exception when raise_exception then
        denied := sqlerrm = 'member account required for private rooms';
    end;
    if not denied then raise exception 'guest private join was not rejected'; end if;

    denied := false;
    begin
        insert into public.community_posts (category, title, content, author, author_id)
        values ('free', 'Must not be stored', 'guest write check', guest_nick, guest_id);
    exception when insufficient_privilege then denied := true;
    end;
    if not denied then raise exception 'guest post write bypassed RLS'; end if;
    denied := false;
    begin
        insert into storage.objects (bucket_id, name)
        values ('canvas-artworks', guest_id::text || '/guest-check.png');
    exception when insufficient_privilege then denied := true;
    end;
    if not denied then raise exception 'guest upload bypassed RLS'; end if;
    update public.profiles set nickname = 'GuestRenamed' where id = guest_id;
    get diagnostics changed_count = row_count;
    if changed_count <> 0 then raise exception 'guest changed an account profile'; end if;
    insert into public.reports (reporter_id, reporter, target_user_id, target_user, reason)
    values (guest_id, guest_nick, owner_id, owner_nick, 'transactional guest reporting check');
    perform public.leave_workspace_room(public_room);
    if private.is_room_member(public_room) then raise exception 'guest membership was not released'; end if;

    perform public.join_workspace_room(public_room, null);
    perform set_config('request.jwt.claim.sub', owner_id::text, true);
    perform set_config('request.jwt.claims', jsonb_build_object('sub', owner_id, 'role', 'authenticated', 'is_anonymous', false)::text, true);
    perform public.set_workspace_room_privacy(public_room, 'temporary-test-password');
    execute 'reset role';
    if exists (select 1 from public.workspace_room_members where room_id = public_room and user_id = guest_id) then raise exception 'private conversion retained a guest'; end if;
    if not exists (select 1 from realtime.messages where topic = 'room-server:' || public_room::text and event = 'chat') then raise exception 'guest chat was not produced'; end if;
    if not exists (select 1 from realtime.messages where topic = 'room-server:' || public_room::text and event = 'kick_user' and payload->>'targetUserId' = guest_id::text) then raise exception 'guest removal notification was not produced'; end if;
end;
$$;
select 'guest access integration checks passed' as result;
rollback;
