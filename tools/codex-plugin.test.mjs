import test from 'node:test';
import assert from 'node:assert/strict';
import { serviceCommand, configPath, resolveConnection } from '../plugins/agentic-jwt/server/launch.mjs';
import { LazyService, serve, lines } from '../plugins/agentic-jwt/server/proxy.mjs';
import { spawn } from 'node:child_process';
import { PassThrough, Readable } from 'node:stream';

const config = { mode: 'linux', binary: '/opt/agentic/agentic-mcp', root: '/srv/files', stateDir: '/srv/state', approver: '/etc/agentic/public.json', owner: 'alice' };

test('Linux and WSL always launch serve with the configured boundaries', () => {
  const linux = serviceCommand(config, 'linux');
  assert.deepEqual(linux, { command: config.binary, args: ['serve', '--root', config.root, '--state-dir', config.stateDir, '--approver', config.approver, '--owner', 'alice'] });
  assert.deepEqual(serviceCommand({ ...config, mode: 'wsl', distribution: 'Ubuntu-22.04' }, 'win32'), { command: 'wsl.exe', args: ['--distribution', 'Ubuntu-22.04', '--exec', linux.command, ...linux.args] });
  assert.throws(() => serviceCommand(config, 'win32'), /requires Linux/);
  assert.throws(() => serviceCommand({ ...config, mode: 'wsl', distribution: 'Ubuntu' }, 'linux'), /requires Windows/);
});

test('SSH uses a host alias and never injects a remote command or host-key bypass', () => {
  const ssh = serviceCommand({ mode: 'ssh', host: 'agentic-files' });
  assert.equal(ssh.command, 'ssh');
  assert.deepEqual(ssh.args, ['-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ClearAllForwardings=yes', '-o', 'ConnectTimeout=10', 'agentic-files']);
  for (const host of ['-oProxyCommand=evil', 'host;command', 'host\ncommand', 'user@host', '']) assert.throws(() => serviceCommand({ mode: 'ssh', host }));
});

test('configuration rejects approval keys, arbitrary commands, and invalid paths', () => {
  for (const key of ['privateKey', 'command', 'args', 'approval']) assert.throws(() => serviceCommand({ ...config, [key]: 'unsafe' }, 'linux'));
  for (const field of ['binary', 'root', 'stateDir', 'approver']) assert.throws(() => serviceCommand({ ...config, [field]: 'relative' }, 'linux'), /absolute Linux path/);
  assert.throws(() => serviceCommand({ ...config, owner: 'a\nb' }, 'linux'));
  for (const invalid of [null, [], {}, { mode: 'approve' }]) assert.throws(() => serviceCommand(invalid));
  assert.equal(configPath({ AGENTIC_JWT_CONFIG: '/selected/connection.json' }), '/selected/connection.json');
  assert.match(configPath({ CODEX_HOME: '/custom-codex' }).replaceAll('\\', '/'), /^\/custom-codex\/agentic-jwt\/connection.json$/);
});

test('installed plugin root resolves using the real location and WSL translation', async () => {
  assert.equal((await resolveConnection({ ...config, root: '@plugin' }, { platform: 'linux', pluginRoot: '/cache/agentic-jwt/0.1.1' })).root, '/cache/agentic-jwt/0.1.1');
  const resolved = await resolveConnection({ ...config, mode: 'wsl', distribution: 'Ubuntu', root: '@plugin' }, { platform: 'win32', pluginRoot: 'C:\\cache\\plugin', translate: async (distribution, directory) => {
    assert.equal(distribution, 'Ubuntu');
    assert.equal(directory, 'C:\\cache\\plugin');
    return '/mnt/c/cache/plugin';
  } });
  assert.equal(resolved.root, '/mnt/c/cache/plugin');
  await assert.rejects(resolveConnection({ mode: 'ssh', root: '@plugin', host: 'files' }), /cannot manage/);
});

const fixture = `
const readline = require('node:readline');
let initialized = false;
readline.createInterface({input: process.stdin}).on('line', line => {
  const m = JSON.parse(line);
  if (m.method === 'notifications/initialized') { initialized = true; return; }
  let result;
  if (m.method === 'initialize') result = {protocolVersion: m.params.protocolVersion, capabilities: {tools:{}}, serverInfo:{name:'test',version:'1'}};
  else if (initialized && m.method === 'tools/call') {
    if (m.params.name === 'apply_approved_patch') { process.exit(7); return; }
    result = {content:[{type:'text',text:JSON.stringify(m.params.arguments)}],isError:false};
  } else { process.exit(8); return; }
  process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:m.id,result})+'\\n');
});
`;

test('tool discovery never provisions or starts the Rust service', async () => {
  let starts = 0;
  const service = new LazyService({ load: async () => { starts++; throw new Error('setup required'); } });
  const messages = [
    {jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'test',version:'1'}}},
    {jsonrpc:'2.0',method:'notifications/initialized'},
    {jsonrpc:'2.0',id:2,method:'tools/list'}
  ];
  const output = new PassThrough();
  let bytes = '';
  output.on('data', chunk => { bytes += chunk; });
  await serve({ input: Readable.from(messages.map(m => JSON.stringify(m)+'\n')), output, service });
  const responses = bytes.trim().split('\n').map(JSON.parse);
  assert.equal(starts, 0);
  assert.equal(responses[1].result.tools.length, 6);
  assert.equal(responses[1].result.tools.some(t => /approve$|keygen|resolve/.test(t.name)), false);
});

test('first use starts one process, handshakes, and reuses it without replaying failed writes', async () => {
  let starts = 0;
  const service = new LazyService({ load: async () => config, platform: 'linux', timeout: 3000,
    start: () => { starts++; return spawn(process.execPath, ['-e', fixture], {stdio:['pipe','pipe','pipe'],windowsHide:true}); } });
  try {
    const calls = await Promise.all([service.call({name:'inspect_file',arguments:{path:'first.txt'}}, '2025-11-25'), service.call({name:'inspect_file',arguments:{path:'second.txt'}}, '2025-11-25')]);
    assert.equal(starts, 1);
    assert.deepEqual(calls.map(c => JSON.parse(c.content[0].text).path), ['first.txt','second.txt']);
    await assert.rejects(service.call({name:'apply_approved_patch',arguments:{proposal_id:'id',approval:'signed-receipt'}}, '2025-11-25'), /in-flight write/);
    assert.equal(starts, 1);
  } finally { service.close(); }
});

test('missing configuration returns a tool error, then retries setup on a later call', async () => {
  let attempts = 0;
  const service = new LazyService({ load: async () => { attempts++; throw new Error('Missing test connection'); } });
  const messages = [
    {jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'test',version:'1'}}},
    {jsonrpc:'2.0',method:'notifications/initialized'},
    ...[2,3].map(id => ({jsonrpc:'2.0',id,method:'tools/call',params:{name:'inspect_file',arguments:{path:'file.txt'}}}))
  ];
  const output = new PassThrough();
  let bytes = '';
  output.on('data', chunk => { bytes += chunk; });
  await serve({ input: Readable.from(messages.map(m => JSON.stringify(m)+'\n')), output, service });
  const responses = bytes.trim().split('\n').map(JSON.parse);
  assert.equal(attempts, 2);
  assert.equal(responses[1].result.isError, true);
  assert.equal(responses[2].result.isError, true);
  assert.match(responses[2].result.content[0].text, /Missing test connection/);
});

test('framing handles split UTF-8 and rejects excessive or incomplete input', async () => {
  const chunks = Buffer.from('"é"\n');
  const results = [];
  for await (const line of lines(Readable.from([chunks.subarray(0,2),chunks.subarray(2)]))) results.push(line);
  assert.deepEqual(results, ['"é"']);
  await assert.rejects(async () => { for await (const line of lines(Readable.from([Buffer.alloc(131072, 65)]))) void line; }, /too large/);
  await assert.rejects(async () => { for await (const line of lines(Readable.from(['partial']))) void line; }, /Incomplete/);
});
