const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const migration = fs.readFileSync(path.join(root, 'supabase/migrations/202609060001_secure_workspace.sql'), 'utf8');
const hardeningMigration = fs.readFileSync(path.join(root, 'supabase/migrations/202609060002_harden_canvas_runtime.sql'), 'utf8');

function inlineProgram() {
  const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)].map((match) => match[1]);
  const source = scripts.find((script) => script.includes('const WorkspaceSyncEngine'));
  assert.ok(source, 'main inline program should exist');
  return source;
}

function canvasRuntime({ client = {}, hash = '', ImageClass = class {}, elements = {} } = {}) {
  const alerts = [];
  const element = () => ({ style: {}, value: '', classList: { add() {}, remove() {}, toggle() {} }, append() {}, addEventListener() {} });
  const context = {
    window: { location: { hash }, supabase: { createClient: () => client } },
    document: { getElementById: (id) => elements[id] ||= element(), createElement: element, createTextNode: (text) => ({ textContent: text }), querySelectorAll: () => [] },
    console: { ...console, error() {} }, URL, crypto: crypto.webcrypto, Image: ImageClass,
    setTimeout, clearTimeout, setInterval, clearInterval, alert: (message) => alerts.push(message),
  };
  vm.createContext(context);
  new vm.Script(`${inlineProgram()}\n;globalThis.__canvasTest = { AuthController, ViewToggle, WorkspaceSyncEngine, GlobalState, RoomController, SystemConfigController, CommunityController };`).runInContext(context);
  return { ...context.__canvasTest, window: context.window, alerts, elements };
}

test('main JavaScript parses', () => {
  assert.doesNotThrow(() => new vm.Script(inlineProgram(), { filename: 'index-inline.js' }));
});

test('every statically referenced element ID exists', () => {
  const defined = new Set([...html.matchAll(/\bid=["']([^"']+)["']/g)].map((match) => match[1]));
  const referenced = new Set([...inlineProgram().matchAll(/getElementById\(["']([^"']+)["']\)/g)].map((match) => match[1]));
  const missing = [...referenced].filter((id) => !defined.has(id));
  assert.deepEqual(missing, []);
});

test('security-sensitive legacy patterns stay removed', () => {
  assert.doesNotMatch(html, /\.select\(\s*['"]\*['"]\s*\)/);
  assert.doesNotMatch(html, /from\(\s*['"]rooms['"]\s*\)/);
  assert.doesNotMatch(html, /room_pipe_|sync_data_all|user_present|user_join|user_leave/);
  assert.doesNotMatch(html, /sb_secret_|service_role/i);
  assert.match(html, /config:\s*\{\s*private:\s*true/);
  assert.match(html, /AuthController\.restoreSession\(\)/);
  assert.match(html, /navigator\.serviceWorker\.register\('\.\/sw\.js'\)/);
  assert.match(html, /client\.rpc\('broadcast_workspace_chat'/);
});

test('legacy HTML entry redirects to the fixed app', () => {
  const legacy = fs.readFileSync(path.join(root, 'Canvas.html'), 'utf8');
  assert.match(legacy, /window\.location\.replace\('\.\/'\)/);
  assert.doesNotMatch(legacy, /SUPABASE|password_hash|from\(/);
});

test('manifest and service worker are scoped to the project folder', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8'));
  assert.equal(manifest.id, './');
  assert.equal(manifest.start_url, './');
  assert.equal(manifest.scope, './');
  const worker = fs.readFileSync(path.join(root, 'sw.js'), 'utf8');
  assert.match(worker, /canvas-shell-v5/);
  assert.match(worker, /url\.origin !== self\.location\.origin/);
});

test('service worker removes only obsolete Canvas caches', async () => {
  const handlers = {}; const removed = []; const pending = [];
  const context = {
    URL,
    self: { location: { href: 'https://jini5098.github.io/Canvas/sw.js', origin: 'https://jini5098.github.io' }, clients: { claim() {} }, addEventListener: (type, handler) => { handlers[type] = handler; } },
    caches: { keys: async () => ['canvas-shell-v4', 'canvas-shell-v5', 'ted-cache-v1', 'other-site'], delete: async (key) => { removed.push(key); } },
  };
  vm.runInNewContext(fs.readFileSync(path.join(root, 'sw.js'), 'utf8'), context);
  handlers.activate({ waitUntil: (promise) => pending.push(promise) });
  await Promise.all(pending);
  assert.deepEqual(removed, ['canvas-shell-v4']);
});

test('service worker does not intercept another app on the same origin', () => {
  const handlers = {};
  const context = { URL, self: { location: { href: 'https://jini5098.github.io/Canvas/sw.js', origin: 'https://jini5098.github.io' }, addEventListener: (type, handler) => { handlers[type] = handler; } } };
  vm.runInNewContext(fs.readFileSync(path.join(root, 'sw.js'), 'utf8'), context);
  handlers.fetch({ request: { method: 'GET', url: 'https://jini5098.github.io/TED/index.html' }, respondWith: () => assert.fail('TED must remain outside the Canvas cache') });
});

test('database migration hashes passwords and enforces private channels', () => {
  assert.match(migration, /\nbegin;\s*\n/i);
  assert.match(migration, /commit;\s*$/i);
  assert.match(migration, /extensions\.crypt\(p_password, extensions\.gen_salt\('bf'\)\)/);
  assert.doesNotMatch(migration, /workspace_rooms[\s\S]{0,500}\bpassword\s+text/i);
  assert.match(migration, /alter table public\.profiles enable row level security/i);
  assert.match(migration, /private\.is_room_member/i);
  assert.match(migration, /\(select realtime\.topic\(\)\)/i);
  assert.match(migration, /room-server:/);
  assert.match(migration, /canvas-artworks/);
  assert.match(migration, /nickname ~ '\^\[가-힣A-Za-z0-9_.-\]\{2,20\}\$'/);
  assert.match(migration, /create schema if not exists canvas_backup_20260906/i);
  assert.match(migration, /update public\.rooms set password = null/i);
  assert.match(migration, /tablename = any \(array\[[^\]]*'rooms'/i);
  assert.match(migration, /revoke all on public\.rooms from public, anon, authenticated/i);
  assert.match(migration, /public_upload_artworks/);
  assert.match(migration, /extensions\.crypt\(/);
  assert.match(migration, /find_canvas_profile_by_nickname/);
  assert.match(migration, /function private\.sync_canvas_nickname/);
  assert.doesNotMatch(migration, /create view public\.public_profiles/i);
  assert.doesNotMatch(migration, /function public\.handle_new_canvas_user/i);
  assert.doesNotMatch(html, /from\(\s*['"]public_profiles['"]\s*\)/);
  assert.match(html, /rpc\('find_canvas_profile_by_nickname'/);
  assert.match(hardeningMigration, /workspace_rooms_created_by_idx/);
  assert.equal((hardeningMigration.match(/private\.is_active_user\(\)/g) || []).length, 4);
  assert.match(hardeningMigration, /extensions\.crypt\(p_password, extensions\.gen_salt\('bf'\)\)/);
  assert.match(hardeningMigration, /commit;\s*$/i);
});

test('canvas helpers clamp input and wait for every sync chunk', () => {
  let cleared = 0;
  let drawn = 0;
  class ImageStub {
    set src(value) {
      this.value = value;
      if (this.onload) this.onload();
    }
  }
  const context = {
    window: { supabase: { createClient: () => ({}) } },
    console,
    URL,
    CSS: { supports: (_property, value) => /^#[0-9a-f]{6}$/i.test(value) },
    Image: ImageStub,
    crypto: crypto.webcrypto,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    alert: () => {},
  };
  context.globalThis = context;
  vm.createContext(context);
  const source = `${inlineProgram()}\n;globalThis.__canvasTest = { WorkspaceSyncEngine, GlobalState, safeImageUrl };`;
  new vm.Script(source, { filename: 'index-inline.js' }).runInContext(context);
  const { WorkspaceSyncEngine: engine, GlobalState: state } = context.__canvasTest;
  engine.canvas = { width: 1100, height: 700 };
  engine.ctx = { clearRect: () => { cleared += 1; }, drawImage: () => { drawn += 1; } };
  engine.applyCanvasBackground = () => {};
  state.user = { id: '11111111-1111-4111-8111-111111111111' };
  state.currentRoom = { id: 'test-room' };

  assert.deepEqual({ ...engine.clampPoint(-20, 900) }, { x: 0, y: 700 });
  assert.equal(engine.safeColor('#aabbcc'), '#aabbcc');
  assert.equal(engine.safeColor('url(javascript:bad)'), '#0f172a');
  assert.match(context.__canvasTest.safeImageUrl('https://uxaqxpzmmbjsxfrlvbtg.supabase.co/storage/v1/object/public/canvas-artworks/test.png'), /^https:\/\//);
  assert.equal(context.__canvasTest.safeImageUrl('https://example.com/tracker.png'), '');

  const base = { transferId: '22222222-2222-4222-8222-222222222222', senderId: '33333333-3333-4333-8333-333333333333', targetUserId: state.user.id, total: 2 };
  engine.receiveCanvasChunk({ ...base, index: 0, chunk: 'data:image/png;base64,' });
  assert.equal(drawn, 0, 'a partial transfer must not render');
  engine.receiveCanvasChunk({ ...base, index: 1, chunk: 'AA==' });
  assert.equal(cleared, 1);
  assert.equal(drawn, 1);
  assert.equal(state.syncChunks.size, 0);
});

test('sign in and sign up preserve every password character', async () => {
  const received = [];
  const client = { auth: {
    signInWithPassword: async (args) => { received.push(args); return { data: { session: {} }, error: null }; },
    signUp: async (args) => { received.push(args); return { data: { session: {} }, error: null }; },
  } };
  const password = '  sample password  ';
  const elements = Object.fromEntries(Object.entries({ loginEmail: ' test@example.com ', loginPw: password, signupEmail: ' test@example.com ', signupPw: password, signupNick: '테스트' }).map(([id, value]) => [id, { value }]));
  const { AuthController: auth, window } = canvasRuntime({ client, elements });
  window.location.href = 'https://jini5098.github.io/Canvas/';
  auth.enterAuthenticatedSession = async () => {};
  await auth.handleSignIn();
  await auth.handleSignUp();
  assert.equal(received.length, 2);
  for (const args of received) { assert.equal(args.password, password); assert.equal(args.email, 'test@example.com'); }
});

test('guest entry creates one anonymous session and reuses it on the next visit', async () => {
  let session = null; let created = 0; const entered = [];
  const client = { auth: {
    getSession: async () => ({ data: { session }, error: null }),
    signInAnonymously: async () => {
      created += 1; session = { user: { id: 'guest-uuid', is_anonymous: true } };
      return { data: { session }, error: null };
    },
  } };
  const { AuthController: auth, elements } = canvasRuntime({ client });
  auth.enterAuthenticatedSession = async (value) => entered.push(value);
  await auth.handleGuestLogin();
  await auth.handleGuestLogin();
  assert.equal(created, 1);
  assert.deepEqual(entered, [session, session]);
  assert.equal(elements.doGuestLoginBtn.disabled, false);
});

test('guest connection failures remain visible and do not silently open a local canvas', async () => {
  const client = { auth: {
    getSession: async () => ({ data: { session: null }, error: null }),
    signInAnonymously: async () => ({ data: { session: null }, error: new Error('connection unavailable') }),
  } };
  const { AuthController: auth, RoomController: rooms, GlobalState: state, alerts, elements } = canvasRuntime({ client });
  rooms.startLocalCanvas = () => assert.fail('online guest must not silently fall back to offline');
  await auth.handleGuestLogin();
  assert.equal(state.user, null);
  assert.match(alerts[0], /게스트 연결 실패/);
  assert.equal(elements.doGuestLoginBtn.disabled, false);
});

test('an anonymous session enters the online lobby with guest privileges even if a profile claims admin', async () => {
  const profile = { id: 'guest-uuid', nickname: 'Guest_123', role: 'admin', is_banned: false };
  const selection = { select() { return this; }, eq() { return this; }, async single() { return { data: profile, error: null }; } };
  const runtime = canvasRuntime({ client: { from: () => selection } });
  const calls = [];
  runtime.ViewToggle.showScreen = (screen) => calls.push(screen);
  runtime.RoomController.loadActiveRooms = async () => calls.push('rooms');
  runtime.SystemConfigController.initGlobalChannel = () => calls.push('realtime');
  runtime.SystemConfigController.loadFeaturedArtwork = () => {};
  runtime.CommunityController.loadPosts = () => calls.push('posts');
  await runtime.AuthController.enterAuthenticatedSession({ user: { id: profile.id, is_anonymous: true } });
  assert.equal(runtime.GlobalState.user.isGuest, true);
  assert.equal(runtime.GlobalState.user.isLocalOnly, false);
  assert.equal(runtime.GlobalState.isAdmin, false);
  assert.deepEqual(calls, ['lobby', 'rooms', 'realtime', 'posts']);
});

test('guests can quick-join a public room and subscribe to drawing and chat', async () => {
  const subscriptions = []; const channels = [];
  const client = {
    rpc: async () => ({ data: [{ id: 'private-room', is_private: true }, { id: 'public-room', is_private: false }], error: null }),
    realtime: { setAuth: async () => {} },
    channel: (name, options) => {
      channels.push({ name, private: options.config.private });
      return { on() { return this; }, subscribe() { subscriptions.push(name); return this; } };
    },
  };
  const { RoomController: rooms, WorkspaceSyncEngine: engine, GlobalState: state } = canvasRuntime({ client });
  state.user = { id: 'guest-uuid', isGuest: true, isLocalOnly: false };
  let joined;
  rooms.validateAndJoin = async (room) => { joined = room.id; };
  await rooms.handleQuickJoin();
  assert.equal(joined, 'public-room');
  state.currentRoom = { id: joined, isLocal: false };
  await engine.connectRealtimePipeline();
  assert.deepEqual(subscriptions, ['room:public-room', 'room-server:public-room']);
  assert.ok(channels.every((channel) => channel.private));
});

test('member-only actions reject a guest before making account-owned writes', async () => {
  const client = { rpc: () => assert.fail('restricted RPC must not be called'), from: () => assert.fail('restricted write must not be sent') };
  const { RoomController: rooms, CommunityController: community, GlobalState: state, alerts } = canvasRuntime({ client });
  state.user = { id: 'guest-uuid', isGuest: true, isLocalOnly: false };
  await rooms.handleCreateRoom();
  await rooms.validateAndJoin({ id: 'private-room', is_private: true });
  await community.handleWritePost();
  await community.handleAddComment();
  assert.equal(alerts.length, 4);
});

test('leaving an online guest room releases membership, returns to lobby, and sign-out revokes the session', async () => {
  const calls = [];
  const client = { rpc: async (name) => { calls.push(name); return { error: null }; }, auth: { signOut: async () => { calls.push('signOut'); return { error: null }; } } };
  const runtime = canvasRuntime({ client });
  runtime.GlobalState.user = { id: 'guest-uuid', isGuest: true, isLocalOnly: false };
  runtime.GlobalState.currentRoom = { id: 'public-room', isLocal: false };
  runtime.ViewToggle.showScreen = (screen) => calls.push(screen);
  runtime.RoomController.loadActiveRooms = () => {};
  runtime.SystemConfigController.loadFeaturedArtwork = () => {};
  runtime.WorkspaceSyncEngine.clearCanvasLocal = () => {};
  await runtime.RoomController.handleExitRoom();
  assert.deepEqual(calls, ['leave_workspace_room', 'lobby']);
  await runtime.AuthController.handleSignOut();
  assert.deepEqual(calls, ['leave_workspace_room', 'lobby', 'signOut', 'auth']);
  assert.equal(runtime.GlobalState.user, null);
});

test('password recovery survives the Auth SDK clearing the URL fragment', async () => {
  const client = { auth: { getSession: async () => ({ data: { session: { user: { id: 'test-user' } } }, error: null }) } };
  const { AuthController: auth, ViewToggle: view, window } = canvasRuntime({ client, hash: '#access_token=test&type=recovery' });
  window.location.hash = '';
  const screens = [];
  view.showScreen = (name) => screens.push(name);
  view.switchAuthForm = (name) => screens.push(name);
  auth.enterAuthenticatedSession = async () => assert.fail('recovery must not enter the lobby');
  await auth.restoreSession();
  assert.deepEqual(screens, ['auth', 'updatePw']);
});

test('queued canvas images cannot be sent into a different room', async () => {
  const { WorkspaceSyncEngine: engine, GlobalState: state } = canvasRuntime({ elements: { bgTemplate: { value: 'none' } } });
  const first = []; const second = [];
  const roomA = { id: 'room-a' };
  state.user = { id: '11111111-1111-4111-8111-111111111111' };
  state.currentRoom = roomA;
  state.roomChannel = { send: async (message) => { first.push(message); return 'ok'; } };
  engine.canvas = { toDataURL: () => 'data:image/png;base64,AA==' };
  let release;
  engine.syncQueue = new Promise((resolve) => { release = resolve; });
  const queued = engine.broadcastCanvasState();
  state.currentRoom = { id: 'room-b' };
  state.roomChannel = { send: async (message) => { second.push(message); return 'ok'; } };
  release(); await queued;
  assert.equal(first.length, 0); assert.equal(second.length, 0);
});

test('an image decoded after leaving a room cannot overwrite the next canvas', () => {
  const images = [];
  class DelayedImage { constructor() { images.push(this); } set src(value) { this.value = value; } }
  const { WorkspaceSyncEngine: engine, GlobalState: state } = canvasRuntime({ ImageClass: DelayedImage });
  state.user = { id: '11111111-1111-4111-8111-111111111111' };
  state.currentRoom = { id: 'room-a' };
  engine.canvas = { width: 1100, height: 700 };
  let draws = 0;
  engine.clearCanvasLocal = () => { draws += 1; };
  engine.ctx = { drawImage: () => { draws += 1; } };
  engine.applyCanvasBackground = () => {};
  engine.receiveCanvasChunk({ transferId: '22222222-2222-4222-8222-222222222222', senderId: '33333333-3333-4333-8333-333333333333', total: 1, index: 0, chunk: 'data:image/png;base64,AA==' });
  assert.equal(images.length, 1);
  state.currentRoom = { id: 'room-b' };
  images[0].onload();
  assert.equal(draws, 0);
});

test('sync chunks from different senders are never combined', () => {
  const { WorkspaceSyncEngine: engine, GlobalState: state } = canvasRuntime();
  state.user = { id: '11111111-1111-4111-8111-111111111111' };
  state.currentRoom = { id: 'room-a' };
  const base = { transferId: '22222222-2222-4222-8222-222222222222', senderId: '33333333-3333-4333-8333-333333333333', total: 2 };
  engine.receiveCanvasChunk({ ...base, index: 0, chunk: 'data:image/png;base64,' });
  engine.receiveCanvasChunk({ ...base, senderId: '44444444-4444-4444-8444-444444444444', index: 1, chunk: 'AA==' });
  const transfer = state.syncChunks.get(base.transferId);
  assert.equal(transfer.received, 1);
  clearTimeout(transfer.timer);
});
