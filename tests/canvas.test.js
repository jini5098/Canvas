const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const migration = fs.readFileSync(path.join(root, 'supabase/migrations/202609060001_secure_workspace.sql'), 'utf8');

function inlineProgram() {
  const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)].map((match) => match[1]);
  const source = scripts.find((script) => script.includes('const WorkspaceSyncEngine'));
  assert.ok(source, 'main inline program should exist');
  return source;
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
  assert.match(worker, /canvas-shell-v3/);
  assert.match(worker, /url\.origin !== self\.location\.origin/);
});

test('database migration hashes passwords and enforces private channels', () => {
  assert.match(migration, /crypt\(p_password, gen_salt\('bf'\)\)/);
  assert.doesNotMatch(migration, /workspace_rooms[\s\S]{0,500}\bpassword\s+text/i);
  assert.match(migration, /alter table public\.profiles enable row level security/i);
  assert.match(migration, /private\.is_room_member/i);
  assert.match(migration, /\(select realtime\.topic\(\)\)/i);
  assert.match(migration, /room-server:/);
  assert.match(migration, /canvas-artworks/);
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
