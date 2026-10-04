import { mkdir, readFile, writeFile, readdir, copyFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const root = fileURLToPath(new URL('../', import.meta.url));
const plugin = path.join(root, 'plugins', 'agentic-jwt');
await mkdir(path.join(plugin, 'bin'), { recursive: true });
const binaryName = process.platform === 'win32' ? 'agentic-mcp.exe' : 'agentic-mcp';
await copyFile(path.join(root, 'target', 'release', binaryName), path.join(plugin, 'bin', binaryName));
const manifest = JSON.parse(await readFile(path.join(plugin, 'plugin.json'), 'utf8'));
const mcp = JSON.parse(await readFile(path.join(plugin, 'mcp.json'), 'utf8'));
const presentation = manifest.extensions['com.openai'].interface;
if (presentation.shortDescription.length > 30) throw new Error('Plugin subtitle exceeds 30 characters.');
await mkdir(path.join(plugin, '.codex-plugin'), { recursive: true });
const compatibility = { name: manifest.name, version: manifest.version, description: manifest.description, author: manifest.author, skills: './skills/', mcpServers: './.mcp.json', interface: presentation };
await writeFile(path.join(plugin, '.codex-plugin', 'plugin.json'), JSON.stringify(compatibility, null, 2) + '\n');
await writeFile(path.join(plugin, '.mcp.json'), JSON.stringify(mcp.mcpServers, null, 2) + '\n');
await mkdir(path.join(root, '.agents', 'plugins'), { recursive: true });
const marketplaceFile = path.join(root, '.agents', 'plugins', 'marketplace.json');
let marketplace = { name: 'agentic-local', interface: { displayName: 'Agentic Local' }, plugins: [] };
try { marketplace = JSON.parse(await readFile(marketplaceFile, 'utf8')); }
catch (error) { if (error.code !== 'ENOENT') throw error; }
if (marketplace.name !== 'agentic-local') throw new Error('Existing marketplace has another identity; refusing to replace it.');
const entry = { name: manifest.name, source: { source: 'local', path: './plugins/agentic-jwt' }, policy: { installation: 'AVAILABLE', authentication: 'ON_INSTALL' }, category: 'Developer Tools' };
marketplace.plugins = [...marketplace.plugins.filter(p => p.name !== manifest.name), entry];
const catalog = JSON.stringify(marketplace, null, 2) + '\n';
if (await readFile(marketplaceFile, 'utf8').catch(error => { if (error.code === 'ENOENT') return ''; throw error; }) !== catalog) {
  await writeFile(marketplaceFile, catalog);
}
// All package files are explicitly enumerated, including hidden files. No dependencies or links.
async function files(directory, prefix = '') {
  const entries = await readdir(directory, { withFileTypes: true });
  const output = [];
  for (const entry of entries) {
    if (entry.isSymbolicLink()) throw new Error('Plugin packages cannot contain links.');
    const relative = path.join(prefix, entry.name);
    if (entry.isDirectory()) output.push(...await files(path.join(directory, entry.name), relative));
    else output.push(relative);
  }
  return output;
}
const entries = await files(plugin);
await mkdir(path.join(root, 'artifacts'), { recursive: true });
const archive = path.join(root, 'artifacts', `${manifest.name}-${manifest.version}.zip`);
// Python's standard library produces a cross-platform ZIP with forward-slash paths.
const script = 'import json,sys,zipfile,pathlib; root=pathlib.Path(sys.argv[1]); z=zipfile.ZipFile(sys.argv[2],"w",zipfile.ZIP_DEFLATED); [z.write(root/p,"agentic-jwt/"+pathlib.PurePath(p).as_posix()) for p in json.loads(sys.argv[3])]; z.close()';
execFileSync('python', ['-c', script, plugin, archive, JSON.stringify(entries)], { stdio: 'inherit', windowsHide: true });
console.log(`Packaged ${entries.length} files: ${archive}`);
