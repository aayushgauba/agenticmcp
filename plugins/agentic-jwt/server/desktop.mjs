import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import { mkdir, readFile, writeFile, realpath, stat, lstat, open, rename, unlink } from 'node:fs/promises';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { configPath, installedPluginRoot } from './launch.mjs';

const run = promisify(execFile);
export const bundledBinary = path.join(installedPluginRoot, 'bin', process.platform === 'win32' ? 'agentic-mcp.exe' : 'agentic-mcp');
const page = await readFile(new URL('./desktop.html', import.meta.url), 'utf8');

export class DesktopReview {
  constructor({ configuration = configPath(), binary = bundledBinary, defaultRoot = installedPluginRoot, setupOnly = false } = {}) {
    this.configuration = configuration;
    this.binary = binary;
    this.defaultRoot = defaultRoot;
    this.setupOnly = setupOnly;
    this.entries = new Map();
    this.snapshots = new Map();
    this.token = randomBytes(32).toString('hex');
    this.http = null;
    this.starting = null;
    this.base = null;
    this.serial = Promise.resolve();
  }

  async config() {
    try { return JSON.parse(await readFile(this.configuration, 'utf8')); }
    catch (error) { if (error.code === 'ENOENT') return null; throw new Error('Existing connection settings are invalid; restore them before setup.'); }
  }

  async status() {
    const config = await this.config();
    return { configured: !!config, mode: config?.mode ?? null, root: config?.root ?? this.defaultRoot,
      bundled_service: await stat(this.binary).then(s => s.isFile()).catch(() => false),
      local_review: config?.mode === 'workspace', setup_url: await this.url(),
      message: config ? 'The service starts automatically when its first file tool is called.' : 'Open setup once, select the directory to manage, and click Enable local review. No connection JSON or WSL is required.' };
  }

  async url() {
    if (!this.starting) this.starting = this.start();
    await this.starting;
    return `${this.base}/#${this.token}`;
  }

  async start() {
    this.http = createServer((req, res) => { void this.handle(req, res); });
    await new Promise((resolve, reject) => { this.http.once('error', reject); this.http.listen(0, '127.0.0.1', resolve); });
    this.base = `http://127.0.0.1:${this.http.address().port}`;
    this.http.requestTimeout = 10000;
    this.http.headersTimeout = 5000;
    this.http.maxConnections = 8;
  }

  async setup(root, changing = false) {
    await mkdir(path.dirname(this.configuration), { recursive: true, mode: 0o700 });
    const lock = this.configuration + '.lock';
    const handle = await open(lock, 'wx', 0o600).catch(error => {
      if (error.code === 'EEXIST') throw new Error('Another folder setup is in progress. Try again shortly.');
      throw error;
    });
    try { return await this.configure(root, changing); }
    finally { await handle.close(); await unlink(lock); }
  }

  async configure(root, changing) {
    if (typeof root !== 'string' || !path.isAbsolute(root)) throw new Error('Choose an absolute folder path.');
    const previous = await this.config();
    if (changing && previous?.mode !== 'workspace') throw new Error('Folder changes are available only for configured local workspaces. External connections are preserved.');
    if (!changing && previous) throw new Error('A connection is already configured. Use Change folder instead.');
    root = await realpath(root);
    if (changing && root === previous.root) return { configured: true, root, changed: false };
    if (!(await stat(root)).isDirectory()) throw new Error('Choose an existing directory.');
    if (!(await stat(this.binary)).isFile()) throw new Error('The native service is missing from this plugin package.');
    const home = path.dirname(this.configuration);
    if (root === home || home.startsWith(root + path.sep)) throw new Error('Choose a folder that does not contain the plugin configuration or review keys.');
    const review = path.join(home, 'local-review');
    const stateDir = path.join(home, 'workspaces', createHash('sha256').update(root).digest('hex'));
    const privateKey = path.join(review, 'approver.key');
    const approver = path.join(review, 'approver.json');
    if (changing && (previous.approver !== approver || previous.owner !== 'local-user')) throw new Error('This workspace uses custom signing settings. Its connection settings were preserved.');
    await mkdir(review, { recursive: true, mode: 0o700 });
    await mkdir(stateDir, { recursive: true, mode: 0o700 });
    const privateExists = await stat(privateKey).then(() => true).catch(() => false);
    const publicExists = await stat(approver).then(() => true).catch(() => false);
    if (privateExists !== publicExists) throw new Error('Local review key setup is incomplete. Restore the key pair before continuing.');
    if (changing && !privateExists) throw new Error('Restore the existing review key pair before changing folders.');
    if (!privateExists) {
      // Called only by a human's authenticated setup-page submission, never MCP.
      await run(this.binary, ['keygen', '--private', privateKey, '--public', approver], { windowsHide: true });
    }
    for (const key of [privateKey, approver]) {
      const metadata = await lstat(key);
      if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) throw new Error('Local review keys must be regular files without links.');
    }
    await run(this.binary, ['check-workspace', '--root', root, '--state-dir', stateDir, '--approver', approver, '--owner', 'local-user'], { windowsHide: true, timeout: 10000 });
    const contents = JSON.stringify({ mode: 'workspace', root, stateDir, approver, owner: 'local-user' }, null, 2) + '\n';
    if (JSON.stringify(await this.config()) !== JSON.stringify(previous)) throw new Error('Connection settings changed during setup. Refresh and try again.');
    if (changing) {
      const temporary = this.configuration + '.' + randomBytes(12).toString('hex') + '.tmp';
      try {
        await writeFile(temporary, contents, { flag: 'wx', mode: 0o600 });
        await rename(temporary, this.configuration);
      } finally { await unlink(temporary).catch(() => {}); }
      this.entries.clear();
      this.snapshots.clear();
    } else await writeFile(this.configuration, contents, { flag: 'wx', mode: 0o600 });
    return { configured: true, root, changed: changing };
  }

  record(name, result) {
    const value = result.structuredContent;
    if (name === 'inspect_file' && value?.path && !result.isError) this.snapshots.set(value.path, value);
    if ((name === 'propose_patch' || name === 'proposal_status') && value?.proposal && !result.isError) {
      const proposal = structuredClone(value.proposal);
      const old = this.entries.get(proposal.id);
      const snapshot = this.snapshots.get(proposal.path);
      this.entries.set(proposal.id, { proposal, digest: value.proposal_sha256 ?? old?.digest, status: value.status === 'pending_approval' && ['approved','rejected'].includes(old?.status) ? old.status : value.status,
        before: snapshot && (snapshot.sha256 ?? '') === proposal.before_sha256 ? snapshot.content : old?.before,
        receipt: old?.receipt });
    }
    if (name === 'apply_approved_patch' && value?.proposal_id && !result.isError) {
      const entry = this.entries.get(value.proposal_id);
      if (entry) { entry.status = 'applied'; entry.receipt = undefined; }
    }
  }

  receipt(id) {
    const entry = this.entries.get(id);
    if (!entry?.receipt || entry.proposal.expires_at * 1000 <= Date.now()) throw new Error('Open the review link and approve this exact change first.');
    return entry.receipt;
  }

  async approve(id) {
    const config = await this.config();
    if (config?.mode !== 'workspace') throw new Error('This connection uses externally signed approvals.');
    const entry = this.entries.get(id);
    if (!entry || !['pending_approval', 'approved'].includes(entry.status) || entry.proposal.expires_at * 1000 <= Date.now()) throw new Error('The proposal is no longer pending or has expired.');
    const root = await realpath(config.root);
    const proposalRoot = entry.proposal.root.replace(/^\\\\\?\\/, '');
    if (root !== proposalRoot || entry.proposal.owner !== config.owner) throw new Error('Proposal is for a different workspace.');
    const review = path.join(path.dirname(this.configuration), 'local-review');
    const proposalFile = path.join(review, `${randomBytes(12).toString('hex')}.proposal.json`);
    const receiptFile = proposalFile + '.receipt';
    await writeFile(proposalFile, JSON.stringify(entry.proposal), { flag: 'wx', mode: 0o600 });
    try {
      const { stdout } = await run(this.binary, ['review-workspace', '--proposal', proposalFile], { windowsHide: true });
      const digest = /Proposal SHA-256: ([a-f0-9]{64})/.exec(stdout)?.[1];
      if (!digest || (entry.digest && digest !== entry.digest)) throw new Error('The proposal digest changed.');
      // Only this page's authenticated human button can request a signature.
      await run(this.binary, ['approve-workspace', '--proposal', proposalFile, '--private', path.join(review, 'approver.key'), '--digest', digest, '--output', receiptFile], { windowsHide: true });
      entry.receipt = await readFile(receiptFile, 'utf8');
      entry.status = 'approved';
      return { approved: true, proposal_id: id };
    } finally {
      const { unlink } = await import('node:fs/promises');
      await unlink(proposalFile).catch(() => {});
      await unlink(receiptFile).catch(() => {});
    }
  }

  async handle(req, res) {
    const send = (code, value) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(value)); };
    try {
      if (!this.base || req.headers.host !== new URL(this.base).host) return send(403, { error: 'Invalid host' });
      if (req.method === 'GET' && req.url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store',
          'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'", 'Referrer-Policy': 'no-referrer' });
        return res.end(page);
      }
      const supplied = Buffer.from(req.headers['x-review-token'] ?? '');
      const expected = Buffer.from(this.token);
      if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected) || (req.headers.origin && req.headers.origin !== this.base)) return send(403, { error: 'Open the original review link.' });
      if (req.method === 'GET' && req.url === '/state') {
        const config = await this.config();
        const root = config?.root;
        return send(200, { configured: !!config, mode: config?.mode, root: root ?? this.defaultRoot, setup_only: this.setupOnly, proposals: [...this.entries.values()].filter(e => e.proposal.root.replace(/^\\\\\?\\/, '') === root).map(({ proposal, before, status }) => ({ proposal, before, status })) });
      }
      if (req.method !== 'POST' || req.headers.origin !== this.base || !req.headers['content-type']?.startsWith('application/json')) return send(405, { error: 'Use the setup and review buttons.' });
      let body = Buffer.alloc(0);
      for await (const chunk of req) { body = Buffer.concat([body, chunk]); if (body.length > 8192) return send(413, { error: 'Request too large' }); }
      const args = JSON.parse(body.toString('utf8'));
      const operation = this.serial.then(async () => {
        if (req.url === '/setup') return this.setup(args.root);
        if (req.url === '/change-folder') return this.setup(args.root, true);
        if (req.url === '/approve') return this.approve(args.id);
        if (req.url === '/reject') { const entry = this.entries.get(args.id); if (!entry) throw new Error('Unknown proposal'); entry.status = 'rejected'; entry.receipt = undefined; return { rejected: true }; }
        throw new Error('Unknown review action');
      });
      this.serial = operation.catch(() => {});
      return send(200, await operation);
    } catch (error) { return send(400, { error: error.message }); }
  }

  close() { this.http?.closeAllConnections(); this.http?.close(); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const review = new DesktopReview({setupOnly: process.argv.includes('--setup-only')});
  console.log(await review.url());
  const timer = setTimeout(() => { review.close(); }, 30 * 60 * 1000);
  process.on('SIGINT', () => { clearTimeout(timer); review.close(); });
}
