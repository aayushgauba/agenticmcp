const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { mergeCodexConfig, installCodexConnection } = require('../dist/codex-install');
const endpoint = { url: 'http://127.0.0.1:12345/mcp', token: 'a'.repeat(64) };

test('config update preserves other tables, comments and multiline strings; replaces quoted and nested own tables', async () => {
  const prefix = '# My settings\nmodel = "test"\ninstructions = """\n[mcp_servers.agentic_workspace]\nfake text\n"""\n';
  const other = '[mcp_servers.other]\ncommand = "other" # Keep this comment\n';
  const text = prefix + '[mcp_servers."agentic_workspace"]\nurl = "old"\n[mcp_servers.agentic_workspace.http_headers]\nAuthorization = "old-secret"\n' + other;
  const updated = await mergeCodexConfig(text, endpoint);
  assert.ok(updated.startsWith(prefix));
  assert.ok(updated.includes(other));
  assert.ok(!updated.includes('old-secret'));
  const parser = await import('toml-eslint-parser');
  const data = parser.getStaticTOMLValue(parser.parseTOML(updated));
  assert.equal(data.model, 'test');
  assert.equal(data.mcp_servers.other.command, 'other');
  assert.equal(data.mcp_servers.agentic_workspace.url, endpoint.url);
  assert.equal(data.mcp_servers.agentic_workspace.required, false);
  assert.equal(await mergeCodexConfig(updated, endpoint), updated, 'Updates must not accumulate comments or tables');
});

test('supports dotted entries and preserves CRLF; refuses invalid or unsupported inline configs', async () => {
  const result = await mergeCodexConfig('model = "x"\r\n[mcp_servers]\r\nagentic_workspace.url = "old"\r\nother.command = "safe"\r\n', endpoint);
  assert.ok(result.includes('other.command = "safe"'));
  assert.ok(!result.includes('"old"'));
  assert.ok(!/(?<!\r)\n/.test(result));
  await assert.rejects(mergeCodexConfig('invalid = [', endpoint));
  await assert.rejects(mergeCodexConfig('mcp_servers = { other = { command = "safe" } }', endpoint), /Cannot safely update/);
});

test('installation backs up existing settings, refreshes owned entry, and refuses to overwrite a different connection', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'agentic-config-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const config = path.join(dir, 'config.toml');
  const original = '# Preserve this\nmodel = "original"\n';
  await fs.writeFile(config, original);
  const first = await installCodexConnection(config, endpoint);
  assert.equal(await fs.readFile(first.backupPath, 'utf8'), original);
  const next = { ...endpoint, url: 'http://127.0.0.1:23456/mcp' };
  const second = await installCodexConnection(config, next, first.fingerprint);
  assert.equal(second.backupPath, undefined);
  assert.notEqual(first.fingerprint, second.fingerprint);
  const saved = await fs.readFile(config, 'utf8');
  await assert.rejects(installCodexConnection(config, endpoint, first.fingerprint), /changed outside/);
  assert.equal(await fs.readFile(config, 'utf8'), saved);
  assert.ok(!(await fs.readdir(dir)).some(name => name.endsWith('.lock') || name.endsWith('.tmp')));
  await fs.writeFile(config, 'invalid = [');
  await assert.rejects(installCodexConnection(config, endpoint));
  assert.equal(await fs.readFile(config, 'utf8'), 'invalid = [');
});
