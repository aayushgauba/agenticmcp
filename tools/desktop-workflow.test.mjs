import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { DesktopReview } from '../plugins/agentic-jwt/server/desktop.mjs';
import { LazyService } from '../plugins/agentic-jwt/server/proxy.mjs';

const binary = fileURLToPath(new URL(`../target/debug/agentic-mcp${process.platform === 'win32' ? '.exe' : ''}`, import.meta.url));

test('native desktop setup and signed nested-file workflow, with rejection and replay protection', {skip: !['win32','linux'].includes(process.platform)}, async () => {
  // Disposable test keys and files only: no user approval key or project is used.
  const temporary = await mkdtemp(path.join(tmpdir(), 'agentic-desktop-test-'));
  assert.ok(path.resolve(temporary).startsWith(path.resolve(tmpdir()) + path.sep));
  const root = path.join(temporary, 'project');
  const configuration = path.join(temporary, 'profile', 'connection.json');
  await mkdir(path.join(root, 'templates'), {recursive:true,mode:0o700});
  await writeFile(path.join(root, 'templates', 'existing.html'), 'Before\n');
  const review = new DesktopReview({configuration,binary,defaultRoot:root});
  const makeService = () => new LazyService({load:()=>review.config(),review,start:options=>spawn(binary,options.args,{stdio:['pipe','pipe','pipe'],windowsHide:true})});
  let service = makeService();
  const call = (name,args) => service.call({name,arguments:args}, '2025-11-25');
  const good = result => { assert.equal(result.isError,false,JSON.stringify(result)); return result.structuredContent; };
  try {
    const status = good(await call('setup_workspace',{}));
    assert.equal(status.configured,false);
    const url = new URL(status.setup_url), headers = {'x-review-token':url.hash.slice(1)};
    assert.equal((await fetch(url.origin+'/state')).status,403);
    assert.equal((await fetch(url.origin+'/setup',{method:'POST',headers:{...headers,'Content-Type':'application/json'},body:JSON.stringify({root})})).status,405);
    // Simulated human setup/review submissions for this disposable fixture.
    const post = (route,args) => fetch(url.origin+route,{method:'POST',headers:{...headers,'Content-Type':'application/json',Origin:url.origin},body:JSON.stringify(args)});
    assert.equal((await post('/setup',{root})).status,200);
    const config = await review.config();
    assert.equal(config.mode,'workspace');
    const missing = good(await call('inspect_file',{path:'templates/new-section/new.html'}));
    assert.equal(missing.sha256,null);
    const proposed = good(await call('propose_patch',{path:'templates/new-section/new.html',before_sha256:null,replacement:'<h1>Home</h1>\n'}));
    assert.ok(proposed.review_url);
    await assert.rejects(call('apply_approved_patch',{proposal_id:proposed.proposal.id}),/approve this exact/);
    await assert.rejects(readFile(path.join(root,'templates','new-section','new.html')),/ENOENT/);
    assert.equal((await post('/approve',{id:proposed.proposal.id})).status,200);
    good(await call('apply_approved_patch',{proposal_id:proposed.proposal.id}));
    assert.equal(await readFile(path.join(root,'templates','new-section','new.html'),'utf8'),'<h1>Home</h1>\n');
    await assert.rejects(call('apply_approved_patch',{proposal_id:proposed.proposal.id}),/approve this exact/);
    const rejected = good(await call('propose_patch',{path:'templates/rejected.html',before_sha256:null,replacement:'Rejected\n'}));
    assert.equal((await post('/reject',{id:rejected.proposal.id})).status,200);
    await assert.rejects(call('apply_approved_patch',{proposal_id:rejected.proposal.id}),/approve this exact/);
    const previous = good(await call('inspect_file',{path:'templates/existing.html'}));
    const stale = good(await call('propose_patch',{path:'templates/existing.html',before_sha256:previous.sha256,replacement:'After\n'}));
    assert.equal((await post('/approve',{id:stale.proposal.id})).status,200);
    await writeFile(path.join(root,'templates','existing.html'),'Changed externally\n');
    assert.equal((await call('apply_approved_patch',{proposal_id:stale.proposal.id})).isError,true);
    assert.equal(await readFile(path.join(root,'templates','existing.html'),'utf8'),'Changed externally\n');
    for (const bad of ['../outside.txt','.git/config','templates/../../escape','C:/Windows/file']) assert.equal((await call('inspect_file',{path:bad})).isError,true);
    const outside = path.join(temporary,'outside');
    await mkdir(outside);
    await writeFile(path.join(outside,'secret.txt'),'outside');
    await symlink(outside,path.join(root,'templates','escape'),process.platform==='win32'?'junction':'dir');
    assert.equal((await call('inspect_file',{path:'templates/escape/secret.txt'})).isError,true);
    const approvedOld = good(await call('propose_patch',{path:'old-only.txt',before_sha256:null,replacement:'old workspace'}));
    assert.equal((await post('/approve',{id:approvedOld.proposal.id})).status,200);
    const secondRoot = path.join(temporary,'second-project');
    await mkdir(secondRoot);
    await writeFile(path.join(secondRoot,'identity.txt'),'second workspace');
    assert.equal((await post('/change-folder',{root:path.join(temporary,'missing')})).status,400);
    assert.equal((await review.config()).root,root);
    assert.equal((await post('/change-folder',{root:secondRoot})).status,200);
    const secondConfig = await review.config();
    assert.notEqual(secondConfig.stateDir,config.stateDir);
    assert.equal(secondConfig.approver,config.approver);
    const pageState = await (await fetch(url.origin+'/state',{headers})).json();
    assert.equal(pageState.proposals.length,0);
    assert.equal((await post('/approve',{id:approvedOld.proposal.id})).status,400);
    assert.equal(good(await call('inspect_file',{path:'identity.txt'})).content,'second workspace');
    await assert.rejects(call('apply_approved_patch',{proposal_id:approvedOld.proposal.id}),/approve this exact/);
    assert.equal((await post('/change-folder',{root:secondRoot})).status,200); // Same folder, live state lock.
    assert.equal((await post('/change-folder',{root})).status,200);
    assert.equal(good(await call('proposal_status',{proposal_id:proposed.proposal.id})).status,'applied');
    await assert.rejects(call('apply_approved_patch',{proposal_id:approvedOld.proposal.id}),/approve this exact/);
    await assert.rejects(readFile(path.join(root,'old-only.txt')),/ENOENT/);
    await assert.rejects(readFile(path.join(secondRoot,'old-only.txt')),/ENOENT/);
    const child = service.child;
    const stopped = new Promise(resolve=>child.once('exit',resolve));
    service.close();
    await stopped;
    service = makeService();
    const durable = good(await call('proposal_status',{proposal_id:proposed.proposal.id}));
    assert.equal(durable.status,'applied');
  } finally {
    service.close();
    review.close();
    // Windows process/SQLite handles finish closing asynchronously.
    await rm(temporary,{recursive:true,force:true,maxRetries:10,retryDelay:50});
  }
});
