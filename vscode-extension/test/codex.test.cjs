const { test } = require('node:test');
const assert = require('node:assert/strict');
const { codexConfig } = require('../dist/codex');

test('Codex export contains only the intended server connection, not host policy', () => {
  const text = codexConfig({ url: 'http://127.0.0.1:12345/mcp', token: 'a'.repeat(64) });
  assert.equal((text.match(/^\[/gm) || []).length, 1);
  assert.match(text, /^\[mcp_servers\.agentic_workspace\]$/m);
  assert.match(text, /^required = true$/m);
  assert.ok(!/sandbox_mode|approval_policy|model_provider|shell_tool/.test(text));
  assert.match(text, /Replace this table after reloading VS Code/);
});

test('Codex export rejects remote endpoints and TOML injection', () => {
  const token = 'a'.repeat(64);
  for (const url of ['https://example.com/mcp', 'http://0.0.0.0:123/mcp', 'http://127.0.0.1:123/mcp?x=1', 'http://127.0.0.1:123/mcp"\nmodel="other']) {
    assert.throws(() => codexConfig({ url, token }), /Invalid local MCP endpoint/);
  }
  assert.throws(() => codexConfig({ url: 'http://127.0.0.1:123/mcp', token: 'a"\n' }), /Invalid local MCP endpoint/);
});
