import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
export const installedPluginRoot = fileURLToPath(new URL('../', import.meta.url));

export async function resolveConnection(config, { platform = process.platform, pluginRoot = installedPluginRoot,
  translate = async (distribution, directory) => {
    const { stdout } = await execFileAsync('wsl.exe', ['--distribution', text(distribution, 'distribution'), '--exec', 'wslpath', '-a', '-u', directory], { timeout: 10000, windowsHide: true });
    return stdout.trim();
  }
} = {}) {
  if (config?.root !== '@plugin') return config;
  if (config.mode === 'workspace') return { ...config, root: pluginRoot };
  if (config.mode === 'ssh') throw new Error('An SSH service cannot manage this computer\'s installed plugin folder.');
  const root = config.mode === 'wsl' && platform === 'win32'
    ? await translate(config.distribution, pluginRoot) : pluginRoot;
  return { ...config, root: linuxPath(root, 'installed plugin root') };
}

export function configPath(env = process.env) {
  return env.AGENTIC_JWT_CONFIG || path.join(env.CODEX_HOME || path.join(homedir(), '.codex'), 'agentic-jwt', 'connection.json');
}

function text(value, label) {
  if (typeof value !== 'string' || !value.length || /[\x00-\x1f\x7f]/.test(value)) throw new Error(`Invalid ${label}.`);
  return value;
}

function linuxPath(value, label) {
  if (!text(value, label).startsWith('/')) throw new Error(`${label} must be an absolute Linux path.`);
  return value;
}

export function serviceCommand(config, platform = process.platform) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('Connection must be a JSON object.');
  const modes = {
    linux: ['mode', 'binary', 'root', 'stateDir', 'approver', 'owner'],
    wsl: ['mode', 'distribution', 'binary', 'root', 'stateDir', 'approver', 'owner'],
    ssh: ['mode', 'host'],
    workspace: ['mode', 'root', 'stateDir', 'approver', 'owner']
  };
  const fields = modes[config.mode];
  if (!fields || Object.keys(config).some(key => !fields.includes(key))) throw new Error('Unknown connection mode or field. See README.md.');
  if (config.mode === 'workspace') {
    if (!['win32', 'linux'].includes(platform)) throw new Error('Local workspace mode supports Windows and Linux.');
    for (const field of ['root', 'stateDir', 'approver']) if (!path.isAbsolute(text(config[field], field))) throw new Error(`${field} must be absolute.`);
    return { command: path.join(installedPluginRoot, 'bin', platform === 'win32' ? 'agentic-mcp.exe' : 'agentic-mcp'),
      args: ['serve-workspace', '--root', config.root, '--state-dir', config.stateDir, '--approver', config.approver, '--owner', text(config.owner, 'owner')] };
  }
  if (config.mode === 'ssh') {
    // Only an SSH config alias; no model-provided remote shell command.
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(text(config.host, 'SSH host alias'))) throw new Error('Use a simple SSH config host alias.');
    return { command: 'ssh', args: ['-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ClearAllForwardings=yes', '-o', 'ConnectTimeout=10', config.host] };
  }
  const binary = linuxPath(config.binary, 'binary');
  const args = ['serve', '--root', linuxPath(config.root, 'root'), '--state-dir', linuxPath(config.stateDir, 'stateDir'), '--approver', linuxPath(config.approver, 'approver'), '--owner', text(config.owner, 'owner')];
  if (config.mode === 'wsl') {
    if (platform !== 'win32') throw new Error('WSL mode requires Windows.');
    return { command: 'wsl.exe', args: ['--distribution', text(config.distribution, 'distribution'), '--exec', binary, ...args] };
  }
  if (platform !== 'linux') throw new Error('The Rust service requires Linux. Choose WSL or SSH on this platform.');
  return { command: binary, args };
}

export async function launch() {
  const { serve } = await import('./proxy.mjs');
  await serve();
}

export async function readConnection() {
  const file = configPath();
  try { return JSON.parse(await readFile(file, 'utf8')); }
  catch { throw new Error(`Service setup required: cannot read connection JSON at ${file}. Follow the plugin README to provision the Linux binary, managed directory, and independent approver's public JSON key. Then retry the tool; the service starts automatically. No private signing key is needed by this plugin.`); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  launch().catch(error => { console.error(`agentic-jwt: ${error.message}`); process.exitCode = 1; });
}
