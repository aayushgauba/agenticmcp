const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { ProposalStore, snapshot, safePath, MAX_BYTES } = require('../dist/core');

function fixture() {
  let time = 1000;
  const files = new Map([['py/aiwaf/processor.py', 'original\r\n']]);
  const root = { id: 'root', name: 'test', path: '/test' };
  const adapter = {
    async read(_root, relative) { return snapshot(files.has(relative) ? Buffer.from(files.get(relative)) : undefined); },
    async write(_root, relative, _before, replacement) { files.set(relative, replacement); }
  };
  return { store: new ProposalStore([root], adapter, () => time), files, adapter, advance: n => { time += n; } };
}

test('nested replacement requires approval, applies exact bytes once, and returns immutable proposals', async () => {
  const { store, files } = fixture();
  const original = await store.inspect('py/aiwaf/processor.py');
  const p = await store.propose(original.path, original.sha256, 'new\r\n');
  p.replacement = 'tampered';
  await assert.rejects(store.apply(p.id), /pending_approval/);
  store.decide(p.id, true);
  assert.equal((await store.apply(p.id)).status, 'applied');
  assert.equal(files.get(original.path), 'new\r\n');
  await assert.rejects(store.apply(p.id), /applied/);
});

test('new-file creation uses null, and a concurrently created file is preserved', async () => {
  const { store, files } = fixture();
  assert.deepEqual(await store.inspect('notes.txt'), { workspace: 'root', path: 'notes.txt', exists: false, content: '', sha256: null });
  const p = await store.propose('notes.txt', null, 'Hello!\n');
  store.decide(p.id, true);
  files.set('notes.txt', 'someone else');
  await assert.rejects(store.apply(p.id), /changed/);
  assert.equal(files.get('notes.txt'), 'someone else');
  assert.equal(store.get(p.id).status, 'failed');
  const second = await store.propose('new.txt', null, 'Hello!\n');
  store.decide(second.id, true);
  await store.apply(second.id);
  assert.equal(files.get('new.txt'), 'Hello!\n');
});

test('changed, rejected, and expired proposals never write', async () => {
  const { store, files, advance } = fixture();
  await assert.rejects(store.propose('py/aiwaf/processor.py', null, 'wrong'), /changed/);
  const p = await store.propose('a.txt', null, 'a');
  store.decide(p.id, false);
  await assert.rejects(store.apply(p.id), /rejected/);
  const q = await store.propose('b.txt', null, 'b');
  store.decide(q.id, true);
  advance(600_000);
  await assert.rejects(store.apply(q.id), /expired/);
  assert.equal(files.has('a.txt'), false);
  assert.equal(files.has('b.txt'), false);
});

test('simultaneous apply cannot execute twice; failed writes cannot be retried', async () => {
  const { store, adapter } = fixture();
  let writes = 0;
  adapter.write = async () => { writes++; throw new Error('disk unavailable'); };
  const p = await store.propose('new.txt', null, 'value');
  store.decide(p.id, true);
  const results = await Promise.allSettled([store.apply(p.id), store.apply(p.id)]);
  assert.equal(writes, 1);
  assert.ok(results.every(r => r.status === 'rejected'));
  assert.equal(store.get(p.id).status, 'failed');
});

test('bounds and encoding preserve BOM and reject malformed/binary input', async () => {
  assert.equal(snapshot(Buffer.from('\ufeffhello')).content, '\ufeffhello');
  assert.throws(() => snapshot(Buffer.from([0xff])), /encoded data/);
  assert.throws(() => snapshot(Buffer.from('x\0')), /Binary/);
  assert.throws(() => snapshot(Buffer.alloc(MAX_BYTES + 1)), /limit/);
  const { store } = fixture();
  await assert.rejects(store.propose('x', null, '\ud800'), /UTF-8/);
  await assert.rejects(store.propose('x', null, 'x'.repeat(MAX_BYTES + 1)), /1 MiB/);
  for (let i = 0; i < 50; i++) await store.propose(`file${i}`, null, 'x');
  await assert.rejects(store.propose('full', null, 'x'), /Too many/);
});

test('multi-workspace calls require explicit selection', () => {
  const store = new ProposalStore([{ id: 'a' }, { id: 'b' }], {});
  assert.throws(() => store.root(), /Choose a workspace/);
  assert.throws(() => store.root('unknown'), /Choose a workspace/);
  assert.equal(store.root('b').id, 'b');
});

test('path checks reject traversal, junctions, hard links, devices and missing parents', async t => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'agentic-path-'));
  t.after(() => fs.rm(temp, { recursive: true, force: true }));
  const root = await fs.realpath(temp);
  await fs.mkdir(path.join(root, 'nested'));
  await fs.writeFile(path.join(root, 'nested', 'ok.txt'), 'ok');
  assert.equal(await safePath(root, 'nested/new.txt'), path.join(root, 'nested/new.txt'));
  for (const invalid of ['../escape', '/absolute', 'C:/escape', 'a\\b', '.git/config', 'nested/../ok', 'a//b', 'CON.txt', 'x:stream', 'name.', 'name ', 'x\0']) {
    await assert.rejects(safePath(root, invalid), undefined, invalid);
  }
  await assert.rejects(safePath(root, 'missing/new.txt'), /ENOENT/);
  await fs.link(path.join(root, 'nested', 'ok.txt'), path.join(root, 'hard.txt'));
  await assert.rejects(safePath(root, 'hard.txt'), /hard links/);
  await fs.symlink(path.join(root, 'nested'), path.join(root, 'alias'), process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(safePath(root, 'alias/new.txt'), /Symlinks/);
});
