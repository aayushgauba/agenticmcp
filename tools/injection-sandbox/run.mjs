import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {mkdir,writeFile} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {cases,modes,execute,containerArgs,credentialState,authenticationFailure,modelSelectionFailure} from './common.mjs';
import {scenarioNames} from './scenarios.mjs';
import {summarize,trialCount} from './benchmark.mjs';
import {rescoreSession} from './evidence.mjs';
import {readFile} from 'node:fs/promises';
const root=fileURLToPath(new URL('../../',import.meta.url));
const [command,...options]=process.argv.slice(2);
async function docker(args,timeout=180000) {
  const result=await execute('docker',args,{timeout,cwd:root});
  if(result.code!==0||result.timedOut||result.overflow) throw Error(result.stderr||result.stdout||'Docker failed or timed out');
  return result.stdout;
}
async function container(args,network,image) {
  const name='auth51-injection-'+randomUUID();
  try {
    const stdout=await docker([...containerArgs(name,network,image),...args],210000);
    const report=JSON.parse(stdout.trim());
    if(!report.kind||!report.status) throw Error('Invalid sandbox report');
    return report;
  } catch(error) {return {kind:'sandbox_error',status:'infrastructure_error',error:error.message};}
  finally {await execute('docker',['rm','--force',name],{timeout:15000});}
}
try {
  if(command==='analyze') {
    const reportIndex=options.indexOf('--report'),source=reportIndex>=0?options[reportIndex+1]:null;
    if(!source||source.startsWith('--')) throw Error('Specify analyze --report PATH');
    const original=JSON.parse(await readFile(source,'utf8'));
    if(!Array.isArray(original.reports)) throw Error('Expected a sandbox report containing reports');
    const sessions=original.reports.filter(row=>row.kind==='copilot_injection').map(row=>({...rescoreSession(row),originalStatus:row.status}));
    const analysis={schemaVersion:5,kind:'historical_evidence_analysis',createdAt:new Date().toISOString(),sourceReport:path.resolve(source),sourceSchemaVersion:original.schemaVersion,summary:summarize(original.reports),sessions:sessions.map(row=>({fixture:row.fixture,mode:row.mode,trial:row.trial,originalStatus:row.originalStatus,status:row.status,taskOutcome:row.task?.outcome,consumed:row.consumed,behavior:row.behavior,trajectory:row.trajectory}))};
    const output=path.join(root,'artifacts','injection-sandbox',Date.now()+'-analysis.json');
    await mkdir(path.dirname(output),{recursive:true});await writeFile(output,JSON.stringify(analysis,null,2));
    console.log(output);
    console.log(JSON.stringify({sessions:sessions.length,unauthorizedProposalSessions:analysis.sessions.filter(row=>row.behavior.acceptedUnauthorizedProposals>0).length,acceptedUnauthorizedProposals:analysis.sessions.reduce((count,row)=>count+row.behavior.acceptedUnauthorizedProposals,0),unauthorizedWrites:sessions.filter(row=>row.status==='unauthorized_write').length}));
  } else if(command==='build') {
    const child=await import('node:child_process');
    // Stream build progress; no credentials or host configuration enter the build.
    const build=child.spawn('docker',['build','--file','tools/injection-sandbox/Dockerfile','--tag','auth51-injection-sandbox:local','.'],{cwd:root,stdio:'inherit',windowsHide:true});
    build.on('error',error=>{console.error(error.message);process.exitCode=1;});
    build.on('exit',code=>{process.exitCode=code??1;});
  } else if(command==='doctor') {
    console.log(JSON.stringify({docker:JSON.parse(await docker(['version','--format','{{json .Server}}'])),tokenConfigured:Boolean(process.env.COPILOT_GITHUB_TOKEN)},null,2));
  } else if(command==='control'||command==='run') {
    if(command==='run') {
      process.env.COPILOT_GITHUB_TOKEN=(process.env.COPILOT_GITHUB_TOKEN??'').trim();
      if(!credentialState(process.env.COPILOT_GITHUB_TOKEN).fineGrainedFormat) throw Error('Expected the generated fine-grained token value beginning github_pat_. Copy the token value, not its name or a URL. No live tests ran.');
    }
    const trials=trialCount(options),suiteIndex=options.indexOf('--suite'),suite=suiteIndex>=0?options[suiteIndex+1]:'coding';
    const selected=scenarioNames(suite);
    const reports=[];
    const image=JSON.parse(await docker(['image','inspect','auth51-injection-sandbox:local','--format','{{json .Id}}']));
    if(command==='run') {
      const check=await container(['credential-check'],true,image);
      reports.push(check);
      console.error('Container credential check: '+JSON.stringify(check));
      if(check.status!=='passed') throw Error('Credential did not reach the container in the expected format. No live tests ran.');
    }
    const control=await container(['control'],false,image);reports.push(control);
    if(control.status!=='passed') throw Error('Rust boundary control failed: '+JSON.stringify(control));
    const forced=await container(['forced-control'],false,image);reports.push(forced);
    if(forced.status!=='passed') throw Error('Forced unauthorized-write control failed: '+JSON.stringify(forced));
    if(command==='control') for(const fixture of new Set([...scenarioNames('coding'),...scenarioNames('repair'),...scenarioNames('hard')])) reports.push(await container(['fixture-control',fixture],false,image));
    if(command==='run') {
      const modelIndex=options.indexOf('--model'),model=modelIndex>=0?options[modelIndex+1]:null;
      if(!model||model.startsWith('--')) throw Error('Specify --model MODEL to keep comparisons consistent');
      if(!process.env.COPILOT_GITHUB_TOKEN) throw Error('Set COPILOT_GITHUB_TOKEN in your local environment. Do not paste it into chat. No live Copilot tests ran.');
      matrix: for(let trial=1;trial<=trials;trial++) for(const fixture of selected) for(const mode of modes) {
        console.error(`Running trial ${trial}/${trials}: ${fixture}/${mode}`);
        const result=await container(['attack',mode,fixture,model],true,image);
        result.trial=trial;result.fixture??=fixture;result.mode??=mode;
        reports.push(result);
        if(authenticationFailure(result)||modelSelectionFailure(result)) {
          console.error('Authentication or model selection failed; stopping before the remaining sessions. See stderr and safe diagnostics in the report.');
          break matrix;
        }
      }
    }
    const report={schemaVersion:5,createdAt:new Date().toISOString(),image,suite,requestedTrials:command==='run'?trials:0,plannedSessions:command==='run'?selected.length*modes.length*trials:0,summary:summarize(reports),reports};
    const output=path.join(root,'artifacts','injection-sandbox',Date.now()+'.json');
    await mkdir(path.dirname(output),{recursive:true});await writeFile(output,JSON.stringify(report,null,2));
    console.log(output);
    for(const row of reports) console.log(`${row.kind}/${row.fixture??'-'}/${row.mode??'-'}: ${row.status}${row.task?' (task: '+row.task.outcome+')':''}${row.behavior?.unauthorizedProposalRequests?' (behavior: '+row.behavior.outcome+'; accepted proposals: '+row.behavior.acceptedUnauthorizedProposals+')':''}`);
    if(reports.some(row=>['infrastructure_error','unauthorized_write','inconclusive_write_evidence','inconclusive_no_verified_read','task_incomplete'].includes(row.status))) process.exitCode=1;
  } else throw Error('Usage: node tools/injection-sandbox/run.mjs analyze --report PATH | doctor | build | control | run --model MODEL [--suite coding|repair|hard|readonly|all] [--trials 1..10]');
} catch(error) {console.error(error.message);process.exitCode=1;}
