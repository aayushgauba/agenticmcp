const { test } = require('node:test');
const assert = require('node:assert/strict');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StreamableHTTPClientTransport } = require('@modelcontextprotocol/sdk/client/streamableHttp.js');
const { ProposalStore, snapshot } = require('../dist/core');
const { startServer } = require('../dist/server');

test('official MCP SDK client: list, inspect, propose, reject unapproved write, approve, create, reject replay', async t => {
  const files = new Map();
  const store = new ProposalStore([{ id: 'root', name: 'workspace', path: '/workspace' }], {
    async read(root, relative) { return snapshot(files.has(relative) ? Buffer.from(files.get(relative)) : undefined); },
    async write(root, relative, before, replacement) { files.set(relative, replacement); }
  });
  let notified = 0;
  const endpoint = await startServer(store, () => notified++);
  t.after(() => endpoint.dispose());
  const client = new Client({ name: 'test', version: '1.0.0' });
  t.after(() => client.close());
  await client.connect(new StreamableHTTPClientTransport(new URL(endpoint.url), {
    requestInit: { headers: { Authorization: `Bearer ${endpoint.token}` } }
  }));
  const tools = await client.listTools();
  assert.deepEqual(tools.tools.map(t => t.name), ['list_workspaces', 'inspect_file', 'propose_patch', 'proposal_status', 'apply_approved_patch']);
  const call = async (name, args) => client.callTool({ name, arguments: args });
  const read = await call('inspect_file', { path: 'notes.txt' });
  assert.equal(JSON.parse(read.content[0].text).exists, false);
  const proposal = await call('propose_patch', { path: 'notes.txt', before_sha256: null, replacement: 'Hello!\n' });
  const { proposal_id } = JSON.parse(proposal.content[0].text);
  assert.equal(notified, 1);
  assert.equal((await call('apply_approved_patch', { proposal_id })).isError, true);
  assert.equal(files.size, 0);
  store.decide(proposal_id, true);
  const status = await call('proposal_status', { proposal_id });
  assert.equal(JSON.parse(status.content[0].text).status, 'approved');
  const applied = await call('apply_approved_patch', { proposal_id });
  assert.equal(JSON.parse(applied.content[0].text).status, 'applied');
  assert.equal(files.get('notes.txt'), 'Hello!\n');
  assert.equal((await call('apply_approved_patch', { proposal_id })).isError, true);
});

test('loopback transport denies unauthenticated, browser-origin and invalid requests', async t => {
  const endpoint = await startServer(new ProposalStore([], {}), () => {});
  t.after(() => endpoint.dispose());
  const headers = { Authorization: `Bearer ${endpoint.token}`, 'Content-Type': 'application/json' };
  assert.equal((await fetch(endpoint.url)).status, 403);
  assert.equal((await fetch(endpoint.url, { headers: { ...headers, Origin: 'https://example.com' } })).status, 403);
  assert.equal((await fetch(endpoint.url, { headers })).status, 405);
  assert.equal((await fetch(endpoint.url + '/other', { headers })).status, 404);
  assert.equal((await fetch(endpoint.url, { method: 'POST', headers, body: 'not json' })).status, 400);
  assert.equal((await fetch(endpoint.url, { method: 'POST', headers, body: 'x'.repeat(8 * 1024 * 1024 + 1) })).status, 413);
});
