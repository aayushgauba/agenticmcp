import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { createHash, randomUUID } from 'node:crypto';
import { codexConfig } from './codex';

const serverKey = ['mcp_servers', 'agentic_workspace'];
export type Connection = { configPath: string; fingerprint: string };
const isServer = (key: (string | number)[]) => serverKey.every((part, i) => key[i] === part);
export function codexConfigPath() {
  return path.join(process.env.CODEX_HOME || path.join(os.homedir(), '.codex'), 'config.toml');
}

export async function configFingerprint(text: string): Promise<string> {
  const { parseTOML, getStaticTOMLValue } = await import('toml-eslint-parser');
  const data = getStaticTOMLValue(parseTOML(text)) as { mcp_servers?: Record<string, unknown> };
  return createHash('sha256').update(JSON.stringify(data.mcp_servers?.agentic_workspace ?? null)).digest('hex');
}

/** Edit only the named server's AST ranges, preserving unrelated comments and formatting. */
export async function mergeCodexConfig(text: string, endpoint: { url: string; token: string }): Promise<string> {
  const { parseTOML } = await import('toml-eslint-parser');
  const ast = parseTOML(text);
  const ranges: [number, number][] = [];
  const keys = (key: typeof ast.body[0]['body'][0]['key']) => key.keys.map(part => part.type === 'TOMLBare' ? part.name : part.value);
  for (const node of ast.body[0].body) {
    if (node.type === 'TOMLTable') {
      if (isServer(node.resolvedKey)) ranges.push(node.range);
      else for (const property of node.body) {
        if (isServer([...node.resolvedKey, ...keys(property.key)])) ranges.push(property.range);
      }
    } else if (isServer(keys(node.key))) ranges.push(node.range);
  }
  let updated = text;
  for (const [start, end] of ranges.sort((a, b) => b[0] - a[0])) updated = updated.slice(0, start) + updated.slice(end);
  // Missing local UI must not prevent unrelated Codex sessions from starting.
  const snippet = codexConfig(endpoint).split('\n').filter(line => !line.startsWith('#')).join('\n')
    .replace('required = true', 'required = false');
  updated = `${updated.trimEnd()}\n\n${snippet}`;
  if (text.includes('\r\n')) updated = updated.replace(/\r?\n/g, '\r\n');
  try { parseTOML(updated); }
  catch { throw new Error('Cannot safely update this TOML layout. Expand inline mcp_servers into standard [mcp_servers.NAME] tables and try again. No configuration was changed.'); }
  return updated;
}

export async function installCodexConnection(configPath: string, endpoint: { url: string; token: string }, expectedFingerprint?: string): Promise<Connection & { backupPath?: string }> {
  if (!path.isAbsolute(configPath)) throw new Error('Codex configuration path must be absolute.');
  await fs.mkdir(path.dirname(configPath), { recursive: true, mode: 0o700 });
  const lockPath = `${configPath}.agentic-workspace.lock`;
  const lock = await fs.open(lockPath, 'wx', 0o600).catch(() => { throw new Error('Another connection update may be running. Retry when it finishes.'); });
  const temp = `${configPath}.agentic-${randomUUID()}.tmp`;
  try {
    let original = '';
    let existed = false;
    try {
      const stat = await fs.lstat(configPath);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error('Codex config must be a regular file without links.');
      original = await fs.readFile(configPath, 'utf8');
      existed = true;
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    if (expectedFingerprint !== undefined && await configFingerprint(original) !== expectedFingerprint) {
      throw new Error('The Codex server entry changed outside this window. Run Connect Codex explicitly to select this workspace again.');
    }
    const updated = await mergeCodexConfig(original, endpoint);
    // One backup for each explicit setup; background endpoint refresh does not accumulate secrets.
    const backupPath = existed && expectedFingerprint === undefined ? `${configPath}.agentic-backup-${randomUUID()}` : undefined;
    if (backupPath) await fs.writeFile(backupPath, original, { flag: 'wx', mode: 0o600 });
    const file = await fs.open(temp, 'wx', 0o600);
    try { await file.writeFile(updated, 'utf8'); await file.sync(); } finally { await file.close(); }
    let latest: string | undefined;
    try { latest = await fs.readFile(configPath, 'utf8'); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    if (latest !== (existed ? original : undefined)) throw new Error('Codex config changed during setup. Retry Connect Codex.');
    await fs.rename(temp, configPath);
    return { configPath, fingerprint: await configFingerprint(updated), backupPath };
  } finally {
    await fs.rm(temp, { force: true });
    await lock.close();
    await fs.rm(lockPath, { force: true });
  }
}
