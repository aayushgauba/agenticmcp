import { spawn } from 'node:child_process';
import { serviceCommand, readConnection, resolveConnection } from './launch.mjs';
import { DesktopReview } from './desktop.mjs';

const MAX_MESSAGE = 131072;
const versions = ['2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25'];
export const tools = [
  ['inspect_file', 'Read a UTF-8 file and its SHA-256. Local workspace mode supports nested paths and reports missing files.', ['path'], true],
  ['propose_patch', 'Propose an exact full-file replacement. Requires separate signed approval before execution.', ['path', 'before_sha256', 'replacement'], false],
  ['proposal_status', 'Read the proposal and session status. Approval receipts are checked only when executing.', ['proposal_id'], true],
  ['apply_approved_patch', 'Verify an independently signed approval and apply the stored replacement once. No approval can be created through MCP.', ['proposal_id', 'approval'], false]
].map(([name, description, fields, readOnly]) => ({ name, description,
  inputSchema: { type: 'object', properties: Object.fromEntries(fields.map(f => [f, { type: 'string' }])), required: fields, additionalProperties: false },
  annotations: { readOnlyHint: readOnly, destructiveHint: name === 'apply_approved_patch', idempotentHint: readOnly, openWorldHint: false }
}));
tools.find(t => t.name === 'propose_patch').inputSchema.properties.before_sha256.type = ['string', 'null'];
tools.find(t => t.name === 'apply_approved_patch').inputSchema.required = ['proposal_id'];
tools.find(t => t.name === 'apply_approved_patch').description += ' In local review mode, omit approval to use the receipt from the human review page.';
tools.push(
  { name: 'setup_workspace', description: 'Check configuration and open the human setup and folder-change page. Returns a setup URL; does not configure a folder, generate keys, or approve changes through MCP.', inputSchema: { type: 'object', properties: {}, additionalProperties: false }, annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } },
  { name: 'review_change', description: 'Open the local human review page for a proposal. This tool cannot approve or sign it.', inputSchema: { type: 'object', properties: { proposal_id: { type: 'string' } }, required: ['proposal_id'], additionalProperties: false }, annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } }
);

// Bounded newline framing, matching the Rust transport's limit.
export async function* lines(input) {
  let pending = Buffer.alloc(0);
  for await (const chunk of input) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    let start = 0;
    for (let i = 0; i < bytes.length; i++) {
      if (bytes[i] !== 10) continue;
      if (pending.length + i - start + 1 > MAX_MESSAGE) throw new Error('MCP message too large.');
      yield Buffer.concat([pending, bytes.subarray(start, i)]).toString('utf8');
      pending = Buffer.alloc(0);
      start = i + 1;
    }
    pending = Buffer.concat([pending, bytes.subarray(start)]);
    if (pending.length >= MAX_MESSAGE) throw new Error('MCP message too large.');
  }
  if (pending.length) throw new Error('Incomplete MCP message.');
}

export class LazyService {
  constructor({ load = readConnection, start = options => spawn(options.command, options.args, { stdio: ['pipe', 'pipe', 'inherit'], shell: false, windowsHide: true }), timeout = 30000, platform = process.platform, review = new DesktopReview() } = {}) {
    this.load = load;
    this.start = start;
    this.timeout = timeout;
    this.platform = platform;
    this.review = review;
    this.config = null;
    this.pending = new Map();
    this.sequence = 0;
    this.child = null;
    this.ready = null;
    this.queue = Promise.resolve();
  }

  fail(message) {
    for (const request of this.pending.values()) request.reject(new Error(message));
    this.pending.clear();
    this.ready = null;
    this.child?.stdin.destroy();
    this.child?.kill();
    this.child = null;
  }

  request(method, params) {
    const id = ++this.sequence;
    const body = JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n';
    if (Buffer.byteLength(body) > MAX_MESSAGE) return Promise.reject(new Error('MCP message too large.'));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.fail('Rust service timed out. If applying a patch, the outcome may be uncertain: inspect proposal status and contact the operator; do not blindly retry.'), this.timeout);
      const finish = fn => value => { clearTimeout(timer); this.pending.delete(id); fn(value); };
      this.pending.set(id, { resolve: finish(resolve), reject: finish(reject) });
      this.child.stdin.write(body, error => { if (error) this.fail('Rust service input closed. An in-flight write may require operator recovery.'); });
    });
  }

  async disconnect() {
    const child = this.child;
    this.child = null;
    this.ready = null;
    if (!child || child.exitCode !== null || child.signalCode !== null) return;
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { child.kill(); reject(new Error('The previous service is still stopping. Retry after it exits.')); }, 5000);
      child.once('exit', () => { clearTimeout(timer); resolve(); });
      child.stdin.end();
    });
  }

  async connect(protocolVersion, config) {
    this.config = config;
    this.child = this.start(serviceCommand(config, this.platform));
    const child = this.child;
    child.on('error', () => { if (this.child === child) this.fail('Cannot start the configured service. Check WSL/SSH, the binary, and connection settings.'); });
    child.stdin.on('error', () => { if (this.child === child) this.fail('Rust service connection closed. An in-flight write may require operator recovery.'); });
    child.on('exit', () => { if (this.child === child) this.fail('Rust service exited. Check its stderr and provisioning. An in-flight write may require operator recovery.'); });
    void (async () => {
      try {
        for await (const line of lines(child.stdout)) {
          const response = JSON.parse(line);
          if (response.jsonrpc !== '2.0') throw new Error('Invalid service response.');
          const waiting = this.pending.get(response.id);
          if (!waiting) continue;
          if (response.error) waiting.reject(new Error(response.error.message || 'Rust service protocol error.'));
          else if ('result' in response) waiting.resolve(response.result);
          else throw new Error('Missing service result.');
        }
      } catch { if (this.child === child) this.fail('Invalid Rust service transport. An in-flight write may require operator recovery.'); }
    })();
    await this.request('initialize', { protocolVersion, capabilities: {}, clientInfo: { name: 'agentic-jwt-plugin', version: '0.2.2' } });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  }

  call(params, protocolVersion) {
    // A single Rust process/session handles calls in order. Never replay a failed call.
    const operation = this.queue.then(async () => {
      const result = value => ({ content: [{ type: 'text', text: JSON.stringify(value) }], structuredContent: value, isError: false });
      if (params.name === 'setup_workspace') return result(await this.review.status());
      // Recheck settings between serialized calls; an active write always finishes first.
      let config;
      try { config = await resolveConnection(await this.load(), { platform: this.platform }); }
      catch (error) {
        if (error.message.startsWith('Service setup required')) return { ...result(await this.review.status()), isError: true };
        throw error;
      }
      if (this.config && JSON.stringify(config) !== JSON.stringify(this.config)) {
        await this.disconnect();
        this.review.entries?.clear();
        this.review.snapshots?.clear();
      }
      if (!this.ready) {
        this.ready = this.connect(protocolVersion, config);
        try { await this.ready; } catch (error) {
          this.fail(error.message);
          if (error.message.startsWith('Service setup required')) return { ...result(await this.review.status()), isError: true };
          throw error;
        }
      } else await this.ready;
      if (params.name === 'review_change') {
        if (this.config.mode !== 'workspace') return result({ message: 'This connection uses external signed receipts. Review and sign the returned proposal using the independent approver.' });
        const status = await this.request('tools/call', { name: 'proposal_status', arguments: params.arguments });
        this.review.record('proposal_status', status);
        if (status.isError) return status;
        return result({ proposal_id: params.arguments.proposal_id, review_url: await this.review.url(), message: 'The human must inspect the exact change and click Approve. This tool does not sign it.' });
      }
      if (params.name === 'apply_approved_patch' && !params.arguments?.approval) {
        if (this.config.mode !== 'workspace') throw new Error('An external approval JWT is required for this service.');
        params = { ...params, arguments: { ...params.arguments, approval: this.review.receipt(params.arguments.proposal_id) } };
      }
      const response = await this.request('tools/call', params);
      if (this.config.mode === 'workspace') {
        this.review.record(params.name, response);
        if (params.name === 'propose_patch' && !response.isError) {
          const value = { ...response.structuredContent, review_url: await this.review.url(), next_step: 'Human: inspect and approve this exact change on the review page. Then ask Codex to apply the proposal.' };
          return result(value);
        }
      }
      return response;
    });
    this.queue = operation.catch(() => {});
    return operation;
  }

  close() { this.fail('Plugin disconnected.'); this.review.close(); }
}

const rpcError = (id, code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });

export async function serve({ input = process.stdin, output = process.stdout, service = new LazyService() } = {}) {
  let state = 0;
  let protocolVersion = versions.at(-1);
  const stop = () => service.close();
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  try {
    for await (const line of lines(input)) {
      let message;
      try { message = JSON.parse(line); }
      catch { output.write(JSON.stringify(rpcError(null, -32700, 'Parse error')) + '\n'); continue; }
      const id = message?.id ?? null;
      let response;
      if (!message || Array.isArray(message) || message.jsonrpc !== '2.0' || typeof message.method !== 'string'
        || ('id' in message && typeof id !== 'string' && !Number.isSafeInteger(id))) response = rpcError(null, -32600, 'Invalid Request');
      else if (!('id' in message)) {
        if (message.method === 'notifications/initialized' && state === 1) state = 2;
        continue;
      } else {
        const params = message.params ?? {};
        let result;
        if (message.method === 'initialize') {
          if (state !== 0) response = rpcError(id, -32600, 'Session already initialized');
          else if (typeof params?.protocolVersion !== 'string' || !params.capabilities || typeof params.capabilities !== 'object'
            || typeof params.clientInfo?.name !== 'string' || typeof params.clientInfo?.version !== 'string') response = rpcError(id, -32602, 'Invalid initialize parameters');
          else {
            protocolVersion = versions.includes(params.protocolVersion) ? params.protocolVersion : versions.at(-1);
            state = 1;
            result = { protocolVersion, capabilities: { tools: {} }, serverInfo: { name: 'agentic-jwt-files', version: '0.2.2' }, instructions: 'Call setup_workspace on first use and give the human its setup URL. Local mode bundles a native Rust service supporting nested files and creation. The human enables setup and signs exact changes on the review page; never operate the approve/setup buttons yourself. External signed connections retain their own restrictions. No approval or recovery MCP tool is exposed.' };
          }
        } else if (message.method === 'ping') result = {};
        else if (state !== 2) response = rpcError(id, -32600, 'Initialize the session first');
        else if (message.method === 'tools/list') {
          if (!params || Array.isArray(params) || typeof params !== 'object' || 'cursor' in params) response = rpcError(id, -32602, 'Invalid list parameters');
          else result = { tools };
        } else if (message.method === 'tools/call') {
          if (!tools.some(t => t.name === params?.name)) response = rpcError(id, -32602, 'Unknown tool');
          else {
            try { result = await service.call(params, protocolVersion); }
            catch (error) { result = { content: [{ type: 'text', text: error.message }], isError: true }; }
          }
        } else response = rpcError(id, -32601, 'Method not found');
        response ??= { jsonrpc: '2.0', id, result };
      }
      output.write(JSON.stringify(response) + '\n');
    }
  } finally {
    service.close();
    process.removeListener('SIGINT', stop);
    process.removeListener('SIGTERM', stop);
  }
}
