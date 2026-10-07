// Stdout is reserved for MCP. Audit only request metadata and success/error flags.
import {spawn} from 'node:child_process';
import {appendFileSync} from 'node:fs';
import {createInterface} from 'node:readline';
const pending=new Map();
const proposalPaths=new Map();
const child=spawn('agentic-mcp',['serve','--root','/tmp/work','--state-dir','/tmp/state','--approver','/tmp/public.json','--owner','sandbox'],{stdio:['pipe','pipe','pipe'],env:{PATH:process.env.PATH}});
const audit=value=>appendFileSync('/tmp/audit.jsonl',JSON.stringify(value)+'\n');
createInterface({input:process.stdin}).on('line',line=>{
  const msg=JSON.parse(line);
  if(msg.id!==undefined) pending.set(msg.id,{method:msg.method,...msg.params});
  if(msg.method==='tools/call') audit({direction:'request',id:msg.id,...msg.params,targetPath:msg.params.name==='apply_approved_patch'?proposalPaths.get(msg.params.arguments?.proposal_id):msg.params.arguments?.path});
  child.stdin.write(line+'\n');
});
createInterface({input:child.stdout}).on('line',line=>{
  const msg=JSON.parse(line),request=pending.get(msg.id);
  if(request?.name==='propose_patch'&&msg.result?.isError===false) proposalPaths.set(msg.result.structuredContent.proposal.id,request.arguments.path);
  if(request?.method==='tools/list') audit({direction:'capabilities',tools:msg.result?.tools?.map(tool=>tool.name)??[]});
  if(request?.method==='tools/call') audit({direction:'response',id:msg.id,name:request.name,targetPath:request.name==='apply_approved_patch'?proposalPaths.get(request.arguments?.proposal_id):request.arguments?.path,proposalId:msg.result?.structuredContent?.proposal?.id,isError:msg.result?.isError,error:msg.result?.isError?msg.result.content:undefined});
  pending.delete(msg.id);
  process.stdout.write(line+'\n');
});
child.stderr.on('data',()=>{});
child.on('exit',code=>process.exit(code??1));
process.stdin.on('end',()=>child.stdin.end());
process.on('SIGTERM',()=>{child.kill();process.exit(0);});
