import * as vscode from 'vscode';
import * as fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { Adapter, MAX_BYTES, ProposalStore, Root, safePath, snapshot } from './core';
import { startServer } from './server';

export async function activate(context: vscode.ExtensionContext) {
  const output = vscode.window.createOutputChannel('Agentic Workspace');
  context.subscriptions.push(output);
  let status = 'Starting workspace adapter.';
  let proposalStatus = () => '';
  const report = (message: string) => { status = message; output.appendLine(message); };
  context.subscriptions.push(vscode.commands.registerCommand('agenticWorkspace.status', () => {
    output.appendLine(status);
    const details = proposalStatus();
    if (details) output.appendLine(details);
    output.show();
  }));
  context.subscriptions.push(vscode.commands.registerCommand('agenticWorkspace.servers', async () => {
    output.appendLine(status);
    try { await vscode.commands.executeCommand('workbench.mcp.listServer'); }
    catch (error) { output.appendLine(String(error)); output.show(); }
  }));
  report('Activating Agentic Workspace.');
  if (!vscode.workspace.isTrusted) { report('Workspace is not trusted. Trust it and reload the window to enable MCP.'); return; }
  const roots: Root[] = [];
  for (const folder of vscode.workspace.workspaceFolders ?? []) {
    if (folder.uri.scheme !== 'file') { output.appendLine(`Unsupported workspace scheme: ${folder.uri.scheme}`); continue; }
    try {
      const canonical = await fs.realpath(folder.uri.fsPath);
      roots.push({ id: createHash('sha256').update(canonical).digest('hex').slice(0, 16), name: folder.name, path: canonical });
    } catch (error) { output.appendLine(`Cannot open workspace folder ${folder.name}: ${String(error)}`); }
  }
  if (!roots.length) {
    report('No accessible local workspace folder. Use File > Open Folder, then Developer: Reload Window. Opening a file alone is not enough.');
    context.subscriptions.push(vscode.workspace.onDidChangeWorkspaceFolders(() => {
      void vscode.window.showInformationMessage('A workspace folder was opened. Reload the window to enable Agentic Workspace.', 'Reload Window')
        .then(choice => { if (choice) void vscode.commands.executeCommand('workbench.action.reloadWindow'); });
    }));
    return;
  }
  let workspaceChanged = false;
  const assertWorkspace = (root: Root) => {
    if (!vscode.workspace.isTrusted || workspaceChanged || !roots.includes(root)) throw new Error('Workspace changed. Reload the window before using Agentic Workspace.');
  };
  const dirty = (uri: vscode.Uri) => vscode.workspace.textDocuments.some(doc => doc.uri.toString() === uri.toString() && doc.isDirty);
  const adapter: Adapter = {
    async read(root, relative) {
      assertWorkspace(root);
      const target = await safePath(root.path, relative);
      const uri = vscode.Uri.file(target);
      if (dirty(uri)) throw new Error('Save or revert unsaved editor changes first.');
      try {
        const stat = await vscode.workspace.fs.stat(uri);
        if (stat.size > MAX_BYTES) throw new Error('File exceeds the 1 MiB limit.');
        return snapshot(await vscode.workspace.fs.readFile(uri));
      } catch (error) {
        if (error instanceof vscode.FileSystemError && error.code === 'FileNotFound') return snapshot();
        throw error;
      }
    },
    async write(root, relative, before, replacement) {
      assertWorkspace(root);
      const target = await safePath(root.path, relative);
      const uri = vscode.Uri.file(target);
      const current = await adapter.read(root, relative);
      if (current.sha256 !== before.sha256) throw new Error('File changed before writing.');
      // Use the workspace filesystem provider to save exact approved UTF-8 bytes.
      // No editor save participants can silently rewrite the approved replacement.
      if (dirty(uri)) throw new Error('File has unsaved editor changes.');
      await vscode.workspace.fs.writeFile(uri, Buffer.from(replacement, 'utf8'));
    }
  };
  const store = new ProposalStore(roots, adapter);
  proposalStatus = () => `Proposals: ${store.list().map(p => `${p.id}: ${p.status}`).join(', ') || 'none'}`;
  const documents = new Map<string, string>();
  context.subscriptions.push(vscode.workspace.registerTextDocumentContentProvider('agentic-review', {
    provideTextDocumentContent: uri => documents.get(uri.toString()) ?? ''
  }));
  let reviewing = false;
  context.subscriptions.push(vscode.commands.registerCommand('agenticWorkspace.review', async () => {
    if (reviewing) { void vscode.window.showInformationMessage('A proposal review is already open.'); return; }
    reviewing = true;
    try {
      const pending = store.list().filter(p => p.status === 'pending_approval');
      if (!pending.length) { void vscode.window.showInformationMessage('No pending Agentic Workspace changes.'); return; }
      const selection = await vscode.window.showQuickPick(pending.map(p => ({ label: p.path,
        description: `${store.root(p.workspace).name} · ${p.before.exists ? 'replace' : 'create'} · ${p.id.slice(0, 8)}`, id: p.id })),
      { title: 'Choose a proposed change to review' });
      if (!selection) return;
      const p = store.get(selection.id);
      const before = vscode.Uri.parse(`agentic-review:/${p.id}/before/${p.path}`);
      const after = vscode.Uri.parse(`agentic-review:/${p.id}/after/${p.path}`);
      documents.set(before.toString(), p.before.content);
      documents.set(after.toString(), p.replacement);
      // Bound virtual snapshots separately from the proposal store.
      while (documents.size > 100) documents.delete(documents.keys().next().value!);
      await vscode.commands.executeCommand('vscode.diff', before, after, `${p.path} — Proposed ${p.before.exists ? 'replacement' : 'new file'}`, { preview: true });
      const ready = await vscode.window.showInformationMessage('Inspect the proposed diff, then continue to the approval decision.', 'Continue Review');
      if (!ready) return;
      const choice = await vscode.window.showInformationMessage(
        `Approve the exact proposed ${p.before.exists ? 'replacement' : 'creation'} of ${p.path}?`,
        { modal: true, detail: 'Review the before/after diff. Approval permits one application by the MCP tool, expires ten minutes after proposal creation, and is invalidated if the file changes. This button does not write the file.' },
        'Approve', 'Reject');
      if (choice === 'Approve' || choice === 'Reject') {
        store.decide(p.id, choice === 'Approve');
        output.appendLine(`${choice === 'Approve' ? 'Approved' : 'Rejected'} proposal ${p.id}`);
        void vscode.window.showInformationMessage(choice === 'Approve'
          ? 'Approved. Copilot can now call apply_approved_patch for this proposal.' : 'Proposal rejected.');
      }
    } catch (error) { void vscode.window.showErrorMessage(String(error)); }
    finally { reviewing = false; }
  }));
  let endpoint: Awaited<ReturnType<typeof startServer>>;
  try { endpoint = await startServer(store, p => {
    output.appendLine(`Pending proposal ${p.id}`);
    // Deliberately do not invoke the approval UI from a model-controlled command argument.
    void vscode.window.showInformationMessage('A workspace change is ready for review.', 'Review Changes').then(choice => {
      if (choice) void vscode.commands.executeCommand('agenticWorkspace.review');
    });
  }); } catch (error) {
    report(`MCP startup failed: ${String(error)}`);
    void vscode.window.showErrorMessage('Agentic Workspace could not start. Run Agentic Workspace: Show Status for details.');
    return;
  }
  context.subscriptions.push(endpoint);
  const changed = new vscode.EventEmitter<void>();
  context.subscriptions.push(changed);
  context.subscriptions.push(vscode.workspace.onDidChangeWorkspaceFolders(() => {
    workspaceChanged = true;
    report('Workspace folders changed. Reload the window to reconnect Agentic Workspace.');
    endpoint.dispose();
    changed.fire();
    void vscode.window.showInformationMessage('Workspace folders changed. Reload the window to reconnect Agentic Workspace.');
  }));
  try { context.subscriptions.push(vscode.lm.registerMcpServerDefinitionProvider('agentic-workspace.server', {
    onDidChangeMcpServerDefinitions: changed.event,
    provideMcpServerDefinitions: () => {
      output.appendLine(workspaceChanged ? 'MCP discovery: reload required.' : 'MCP discovery: returning Agentic Workspace.');
      return workspaceChanged ? [] : [new vscode.McpHttpServerDefinition(
        'Agentic Workspace', vscode.Uri.parse(endpoint.url), { Authorization: `Bearer ${endpoint.token}` }, '0.1.1')];
    }
  })); } catch (error) {
    endpoint.dispose();
    report(`MCP registration failed: ${String(error)}`);
    void vscode.window.showErrorMessage('Agentic Workspace could not register its MCP server. Run Agentic Workspace: Show Status.');
    return;
  }
  report(`MCP adapter ready. Workspaces: ${roots.map(root => root.name).join(', ')}. Run Agentic Workspace: Open MCP Servers and select Agentic Workspace.`);
}
