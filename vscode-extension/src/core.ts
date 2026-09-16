import { createHash, randomUUID } from 'node:crypto';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

export const MAX_BYTES = 1024 * 1024;
export const hash = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
export type Root = { id: string; name: string; path: string };
export type Snapshot = { exists: boolean; content: string; sha256: string | null };
export type Proposal = {
  id: string; workspace: string; path: string; before: Snapshot; replacement: string;
  expires_at: number; status: 'pending_approval' | 'approved' | 'applying' | 'applied' | 'rejected' | 'expired' | 'failed';
};
export interface Adapter {
  read(root: Root, relative: string): Promise<Snapshot>;
  write(root: Root, relative: string, before: Snapshot, replacement: string): Promise<void>;
}

// Deny aliases, traversal, alternate data streams, and platform-specific device names.
// Parent directories must exist. Symlinks/junctions and multiply-linked files are refused.
export async function safePath(root: string, relative: string): Promise<string> {
  if (typeof relative !== 'string' || !relative || relative.length > 2048 || relative.includes('\\')) {
    throw new Error('Use a workspace-relative path with forward slashes.');
  }
  const parts = relative.split('/');
  for (const part of parts) {
    if (!part || part === '.' || part === '..' || /[\x00-\x1f\x7f<>:"|?*]/.test(part)
      || /[. ]$/.test(part) || part.toLowerCase() === '.git'
      || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part)) {
      throw new Error('Invalid workspace path (traversal, .git, and device paths are forbidden).');
    }
  }
  // The workspace root itself may be an OS alias; pin its resolved identity at activation.
  if (await fs.realpath(root) !== root) throw new Error('Workspace root identity changed. Reload the window.');
  let current = root;
  for (let i = 0; i < parts.length; i++) {
    current = path.join(current, parts[i]);
    try {
      const stat = await fs.lstat(current);
      if (stat.isSymbolicLink()) throw new Error('Symlinks and junctions are not supported.');
      if (i < parts.length - 1 && !stat.isDirectory()) throw new Error('Parent is not a directory.');
      if (i === parts.length - 1 && (!stat.isFile() || stat.nlink !== 1)) {
        throw new Error('Target must be a regular file without hard links.');
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT' && i === parts.length - 1) return current;
      throw error;
    }
  }
  return current;
}

export function snapshot(bytes?: Uint8Array): Snapshot {
  if (bytes === undefined) return { exists: false, content: '', sha256: null };
  if (bytes.byteLength > MAX_BYTES) throw new Error('File exceeds the 1 MiB limit.');
  const content = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  if (content.includes('\0')) throw new Error('Binary files are not supported.');
  return { exists: true, content, sha256: hash(bytes) };
}

export class ProposalStore {
  private entries = new Map<string, Proposal>();
  private serial: Promise<unknown> = Promise.resolve();
  constructor(readonly roots: Root[], private adapter: Adapter, private now = Date.now) {}

  root(id?: string): Root {
    const root = id ? this.roots.find(root => root.id === id) : this.roots.length === 1 ? this.roots[0] : undefined;
    if (!root) throw new Error('Choose a workspace id from list_workspaces.');
    return root;
  }
  async inspect(relative: string, workspace?: string) {
    const root = this.root(workspace);
    return { workspace: root.id, path: relative, ...await this.adapter.read(root, relative) };
  }
  private prune() {
    for (const entry of this.entries.values()) {
      if (['pending_approval', 'approved'].includes(entry.status) && this.now() >= entry.expires_at) entry.status = 'expired';
    }
  }
  list(): Proposal[] { this.prune(); return [...this.entries.values()].map(p => structuredClone(p)); }
  get(id: string): Proposal {
    this.prune();
    const entry = this.entries.get(id);
    if (!entry) throw new Error('Unknown proposal. Reloading the window clears proposals.');
    return structuredClone(entry);
  }
  private async locked<T>(fn: () => Promise<T>): Promise<T> {
    const task = this.serial.then(fn);
    this.serial = task.catch(() => {});
    return task;
  }
  async propose(relative: string, beforeSha256: string | null, replacement: string, workspace?: string) {
    return this.locked(async () => {
      if (Buffer.byteLength(replacement, 'utf8') > MAX_BYTES || replacement.includes('\0')
        || Buffer.from(replacement).toString('utf8') !== replacement) throw new Error('Replacement must be valid UTF-8 text up to 1 MiB.');
      const root = this.root(workspace);
      const before = await this.adapter.read(root, relative);
      if (before.sha256 !== beforeSha256) throw new Error('File changed; inspect it again. Use null only for a missing file.');
      this.prune();
      if (this.entries.size >= 50) {
        for (const [id, p] of this.entries) if (['applied', 'rejected', 'expired', 'failed'].includes(p.status)) this.entries.delete(id);
      }
      if (this.entries.size >= 50) throw new Error('Too many proposals. Review pending changes first.');
      const proposal: Proposal = { id: randomUUID(), workspace: root.id, path: relative, before,
        replacement, expires_at: this.now() + 600_000, status: 'pending_approval' };
      this.entries.set(proposal.id, proposal);
      return this.get(proposal.id);
    });
  }
  // This method is only called by the extension's user confirmation UI, never an MCP tool.
  decide(id: string, approved: boolean) {
    const proposal = this.get(id);
    if (proposal.status !== 'pending_approval') throw new Error('Proposal is no longer pending approval.');
    this.entries.get(id)!.status = approved ? 'approved' : 'rejected';
  }
  async apply(id: string) {
    return this.locked(async () => {
      const proposal = this.get(id);
      if (proposal.status !== 'approved') throw new Error(`Proposal is ${proposal.status}. Use the VS Code review command to approve first.`);
      const entry = this.entries.get(id)!;
      entry.status = 'applying';
      try {
        const root = this.root(proposal.workspace);
        const current = await this.adapter.read(root, proposal.path);
        if (current.sha256 !== proposal.before.sha256) throw new Error('File changed since proposal; inspect and propose again.');
        if (this.now() >= proposal.expires_at) throw new Error('Approval expired.');
        await this.adapter.write(root, proposal.path, proposal.before, proposal.replacement);
        const written = await this.adapter.read(root, proposal.path);
        if (written.sha256 !== hash(Buffer.from(proposal.replacement))) throw new Error('Saved contents differ from the approved replacement.');
        entry.status = 'applied';
        return { proposal_id: id, status: entry.status, path: proposal.path, sha256: written.sha256 };
      } catch (error) {
        entry.status = 'failed';
        throw new Error(`Apply failed; inspect the file before retrying with a new proposal. ${String(error)}`);
      }
    });
  }
}
