const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const Module = require('node:module');
const { pathToFileURL, fileURLToPath } = require('node:url');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StreamableHTTPClientTransport } = require('@modelcontextprotocol/sdk/client/streamableHttp.js');

// Exercise activation, the UI-only approval path, and workspace filesystem writes
// with an API double. Real MCP SDK client and real disposable filesystem are used.
test('extension provider and review command connect MCP to saved workspace files', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'agentic-extension-'));
  const originalCodexHome = process.env.CODEX_HOME;
  process.env.CODEX_HOME = path.join(dir, 'codex-home');
  t.after(() => { if (originalCodexHome === undefined) delete process.env.CODEX_HOME; else process.env.CODEX_HOME = originalCodexHome; });
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  await fs.mkdir(path.join(dir, 'py'));
  const commands = new Map();
  let provider;
  let diffCalls = 0;
  let modalCalls = 0;
  let fileWrites = 0;
  let reject = false;
  let folderChange;
  let clipboard = '';
  let clipboardWrites = 0;
  const errors = [];
  const log = [];
  const disposable = () => ({ dispose() {} });
  class Uri {
    constructor(value) { this.value = value; this.scheme = new URL(value).protocol.slice(0, -1); }
    get fsPath() { return fileURLToPath(this.value); }
    toString() { return this.value; }
    static file(value) { return new Uri(pathToFileURL(value).href); }
    static parse(value) { return new Uri(value); }
  }
  class FileSystemError extends Error { constructor(code) { super(code); this.code = code; } }
  const vscode = {
    Uri, FileSystemError,
    env: { clipboard: { async writeText(text) { clipboard = text; clipboardWrites++; } } },
    EventEmitter: class { event = () => disposable(); fire() {} dispose() {} },
    workspace: {
      isTrusted: true, workspaceFolders: [{ uri: Uri.file(dir), name: 'test' }], textDocuments: [],
      registerTextDocumentContentProvider: () => disposable(),
      onDidChangeWorkspaceFolders(fn) { folderChange = fn; return disposable(); },
      fs: {
        async stat(uri) { try { return await fs.stat(uri.fsPath); } catch (e) { if (e.code === 'ENOENT') throw new FileSystemError('FileNotFound'); throw e; } },
        readFile: uri => fs.readFile(uri.fsPath),
        writeFile: async (uri, bytes) => { fileWrites++; await fs.writeFile(uri.fsPath, bytes); }
      }
    },
    commands: {
      registerCommand(id, fn) { commands.set(id, fn); return disposable(); },
      async executeCommand(id, ...args) {
        if (id === 'vscode.diff') { diffCalls++; return; }
        return commands.get(id)?.(...args);
      }
    },
    window: {
      createOutputChannel: () => ({ ...disposable(), appendLine(message) { log.push(message); }, show() {} }),
      showQuickPick: async items => items[0],
      async showInformationMessage(message, ...args) {
        if (args[0]?.modal) { modalCalls++; return reject ? 'Reject' : 'Approve'; }
        if (args.includes('Continue Review')) return 'Continue Review';
        return undefined;
      },
      showErrorMessage: async error => { errors.push(error); }
    },
    lm: { registerMcpServerDefinitionProvider(id, p) { provider = p; return disposable(); } },
    McpHttpServerDefinition: class { constructor(label, uri, headers, version) { Object.assign(this, { label, uri, headers, version }); } }
  };
  const originalLoad = Module._load;
  Module._load = function(request, ...args) { return request === 'vscode' ? vscode : originalLoad.call(this, request, ...args); };
  let extension;
  try { extension = require('../dist/extension'); } finally { Module._load = originalLoad; }
  const state = new Map();
  const context = { subscriptions: [], workspaceState: { get: key => state.get(key), update: async (key, value) => state.set(key, value) } };
  t.after(() => context.subscriptions.forEach(d => d.dispose()));
  await extension.activate(context);
  const definition = provider.provideMcpServerDefinitions()[0];
  await assert.rejects(fs.readFile(path.join(process.env.CODEX_HOME, 'config.toml')), /ENOENT/);
  await commands.get('agenticWorkspace.connectCodex')();
  const installed = await fs.readFile(path.join(process.env.CODEX_HOME, 'config.toml'), 'utf8');
  assert.match(installed, /\[mcp_servers\.agentic_workspace\]/);
  assert.ok(installed.includes(definition.uri.toString()));
  assert.ok(state.has('codexConnection'), 'Remember that this workspace opted into automatic refresh');
  assert.match(installed, /required = false/);
  assert.equal(clipboardWrites, 0, 'Activation must not export credentials automatically');
  await commands.get('agenticWorkspace.copyCodexConfig')();
  assert.equal(clipboardWrites, 1);
  assert.match(clipboard, /\[mcp_servers\.agentic_workspace\]/);
  assert.match(clipboard, /required = true/);
  const url = JSON.parse(clipboard.match(/^url = (.+)$/m)[1]);
  const authorization = JSON.parse(clipboard.match(/^http_headers = \{ Authorization = (.+) \}$/m)[1]);
  assert.equal(url, definition.uri.toString());
  assert.equal(authorization, definition.headers.Authorization);
  assert.ok(!log.join('\n').includes(authorization), 'Never log the exported credential');
  const client = new Client({ name: 'codex-config-test', version: '1.0' });
  t.after(() => client.close());
  await client.connect(new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers: { Authorization: authorization } } }));
  const selectedTools = JSON.parse(clipboard.match(/^enabled_tools = (.+)$/m)[1]);
  assert.deepEqual((await client.listTools()).tools.map(tool => tool.name), selectedTools);
  assert.ok(!selectedTools.includes('approve'));
  const call = (name, args) => client.callTool({ name, arguments: args });
  const value = result => JSON.parse(result.content[0].text);
  let p = value(await call('propose_patch', { path: 'py/new.py', before_sha256: null, replacement: 'print("Hello!")\r\n' }));
  assert.equal(fileWrites, 0);
  assert.equal((await call('apply_approved_patch', { proposal_id: p.proposal_id })).isError, true);
  await commands.get('agenticWorkspace.review')();
  assert.equal(diffCalls, 1);
  assert.equal(modalCalls, 1);
  assert.equal(fileWrites, 0, 'Approval must not write the file');
  await call('apply_approved_patch', { proposal_id: p.proposal_id });
  assert.equal(await fs.readFile(path.join(dir, 'py/new.py'), 'utf8'), 'print("Hello!")\r\n');
  // Copilot and Codex share one proposal store: a second client cannot reuse approval.
  const otherClient = new Client({ name: 'copilot-test', version: '1.0' });
  t.after(() => otherClient.close());
  await otherClient.connect(new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers: definition.headers } }));
  assert.equal((await otherClient.callTool({ name: 'apply_approved_patch', arguments: { proposal_id: p.proposal_id } })).isError, true);
  const current = value(await call('inspect_file', { path: 'py/new.py' }));
  p = value(await call('propose_patch', { path: 'py/new.py', before_sha256: current.sha256, replacement: 'rejected' }));
  reject = true;
  await commands.get('agenticWorkspace.review')();
  assert.equal((await call('apply_approved_patch', { proposal_id: p.proposal_id })).isError, true);
  assert.equal(fileWrites, 1);
  vscode.workspace.textDocuments.push({ uri: Uri.file(path.join(dir, 'py/new.py')), isDirty: true });
  assert.equal((await call('inspect_file', { path: 'py/new.py' })).isError, true);
  assert.deepEqual(errors, []);
  folderChange();
  assert.deepEqual(provider.provideMcpServerDefinitions(), []);
  await commands.get('agenticWorkspace.copyCodexConfig')();
  assert.equal(clipboardWrites, 1, 'Do not export a stopped endpoint');
  assert.match(errors.at(-1), /Codex connection is unavailable/);
  assert.ok(log.some(line => line.includes('MCP adapter ready')));
  // Regression: opening only a file must give a useful status, not silently disappear.
  vscode.workspace.workspaceFolders = [];
  provider = undefined;
  const emptyContext = { subscriptions: [], workspaceState: context.workspaceState };
  t.after(() => emptyContext.subscriptions.forEach(d => d.dispose()));
  await extension.activate(emptyContext);
  await commands.get('agenticWorkspace.status')();
  assert.match(log.at(-1), /No accessible local workspace folder/);
  assert.equal(provider, undefined);
  assert.ok(commands.has('agenticWorkspace.servers'));
  await commands.get('agenticWorkspace.copyCodexConfig')();
  assert.equal(clipboardWrites, 1);
  assert.match(errors.at(-1), /No accessible local workspace folder/);
});
