import { createServer, Server as HttpServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import { MAX_BYTES, Proposal, ProposalStore } from './core';

export function publicProposal(p: Proposal) {
  return { proposal_id: p.id, workspace: p.workspace, path: p.path, before_sha256: p.before.sha256,
    replacement: p.replacement, expires_at: p.expires_at, status: p.status };
}

export function createMcpServer(store: ProposalStore, onProposal: (p: Proposal) => void) {
  const server = new McpServer({ name: 'agentic-workspace', version: '0.1.3' }, {
    instructions: 'Paths are relative to the open VS Code workspace. Inspect first, then propose the complete replacement. '
      + 'For new files use before_sha256: null. The user must run Agentic Workspace: Review Pending Change and approve in VS Code. '
      + 'There is no MCP approval tool. After approval, call apply_approved_patch. Do not use other editing tools to bypass review.'
  });
  const annotations = (readOnlyHint: boolean) => ({ readOnlyHint, destructiveHint: !readOnlyHint, openWorldHint: false });
  const result = (value: unknown) => ({ content: [{ type: 'text' as const, text: JSON.stringify(value) }] });
  const invoke = async (fn: () => unknown | Promise<unknown>) => {
    try { return result(await fn()); }
    catch (error) { return { ...result({ error: error instanceof Error ? error.message : String(error) }), isError: true }; }
  };
  const workspace = z.string().optional().describe('Workspace id from list_workspaces; optional for a single folder.');
  const relative = z.string().min(1).max(2048).describe('Workspace-relative path, e.g. py/aiwaf/processor.py.');
  server.registerTool('list_workspaces', { description: 'List the open workspace folders and their ids.', annotations: annotations(true) },
    async () => result(store.roots.map(({ id, name }) => ({ id, name }))));
  server.registerTool('inspect_file', { description: 'Read a UTF-8 workspace file (up to 1 MiB), or report exists:false and sha256:null for a new file. Parent folders must exist.',
    inputSchema: { path: relative, workspace }, annotations: annotations(true) },
    async args => invoke(() => store.inspect(args.path, args.workspace)));
  server.registerTool('propose_patch', { description: 'Propose an exact full-file replacement or new file. Does not edit. Requires separate human approval in the VS Code review UI; expires in ten minutes.',
    inputSchema: { path: relative, workspace, before_sha256: z.string().regex(/^[a-f0-9]{64}$/).nullable(), replacement: z.string().max(MAX_BYTES) },
    annotations: annotations(false) }, async args => invoke(async () => {
      const p = await store.propose(args.path, args.before_sha256, args.replacement, args.workspace);
      onProposal(p);
      return { ...publicProposal(p), next_step: 'User: run Agentic Workspace: Review Pending Change, inspect the diff, and approve. Then call apply_approved_patch.' };
    }));
  server.registerTool('proposal_status', { description: 'Get the proposal and its approval/application status.',
    inputSchema: { proposal_id: z.string() }, annotations: annotations(true) },
    async args => invoke(() => publicProposal(store.get(args.proposal_id))));
  server.registerTool('apply_approved_patch', { description: 'Apply an exact proposal once, only after the user has approved it in VS Code. Rejects changed files and expired approvals.',
    inputSchema: { proposal_id: z.string() }, annotations: annotations(false) },
    async args => invoke(() => store.apply(args.proposal_id)));
  return server;
}

export async function startServer(store: ProposalStore, onProposal: (p: Proposal) => void) {
  const token = randomBytes(32).toString('hex');
  let port = 0;
  const http: HttpServer = createServer(async (req, res) => {
    // No browser origins; strict host and a per-window secret protect the loopback endpoint.
    const expected = Buffer.from(`Bearer ${token}`);
    const actual = Buffer.from(req.headers.authorization ?? '');
    if (req.headers.origin || req.headers.host !== `127.0.0.1:${port}`
      || actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
      res.writeHead(403).end(); return;
    }
    if (req.url !== '/mcp') { res.writeHead(404).end(); return; }
    if (req.method !== 'POST') { res.writeHead(405, { Allow: 'POST' }).end(); return; }
    if (!req.headers['content-type']?.startsWith('application/json')) { res.writeHead(415).end(); return; }
    let mcp: McpServer | undefined;
    let transport: StreamableHTTPServerTransport | undefined;
    try {
      const chunks: Buffer[] = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 8 * MAX_BYTES) { res.writeHead(413).end(); return; }
        chunks.push(Buffer.from(chunk));
      }
      let body: unknown;
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
      catch { res.writeHead(400, { 'Content-Type': 'application/json' }).end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } })); return; }
      mcp = createMcpServer(store, onProposal);
      transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      res.on('close', () => { void transport?.close(); void mcp?.close(); });
      await mcp.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch {
      if (!res.headersSent) res.writeHead(500).end();
      else res.end();
      await transport?.close();
      await mcp?.close();
    }
  });
  http.requestTimeout = 30_000;
  http.headersTimeout = 10_000;
  http.maxConnections = 16;
  await new Promise<void>((resolve, reject) => {
    http.once('error', reject);
    http.listen(0, '127.0.0.1', () => { port = (http.address() as { port: number }).port; resolve(); });
  });
  return { url: `http://127.0.0.1:${port}/mcp`, token,
    dispose: () => { http.closeAllConnections(); http.close(); } };
}
