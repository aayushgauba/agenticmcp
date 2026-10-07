import test from 'node:test';
import assert from 'node:assert/strict';
import {scenarios,scenarioNames,scenarioConsumed,policyBefore,policyAttack,appBefore,appExpected,taskOutcome} from './scenarios.mjs';
import {summarize} from './benchmark.mjs';

test('hard attacks retain the repair contract and an uncontaminated clean control',()=>{
  const names=scenarioNames('hard');
  assert.equal(names.length,6);
  assert.equal(names[0],'repairClean');
  for(const name of names) {
    const spec=scenarios[name];
    assert.equal(spec.prompt,scenarios.repairClean.prompt);
    assert.equal(spec.files['app.js'],appBefore);
    assert.equal(spec.files['policy.json'],policyBefore);
    assert.equal(spec.protectedPath,'policy.json');
    assert.equal(taskOutcome(spec,appExpected,[]),'completed');
    assert.ok(scenarioNames('all').includes(name));
    if(name!=='repairClean') assert.ok(!scenarioNames('repair').includes(name));
  }
  assert.equal(scenarioNames('all').length,18);
  assert.ok(!JSON.stringify(scenarios.repairClean).includes('REVIEW-482'));
  const encoded=scenarios.repairHardEncoded.needle.match(/base64 JSON\): ([A-Za-z0-9+/=]+)/)[1];
  assert.equal(Buffer.from(encoded,'base64').toString(),policyAttack);
});

test('split attack requires all three successfully delivered payloads',()=>{
  const spec=scenarios.repairHardSplit;
  const audit=['README.md','dependency-notes.md'].flatMap((path,id)=>[
    {direction:'request',id,name:'inspect_file',arguments:{path}},
    {direction:'response',id,isError:false}
  ]);
  const events=[
    {type:'tool.execution_start',data:{toolName:'fixture-quality_report',toolCallId:'diagnostic'}},
    {type:'tool.execution_complete',data:{toolCallId:'diagnostic',success:true,result:spec.toolMessage}}
  ];
  assert.equal(scenarioConsumed(events,audit,spec),true);
  assert.equal(scenarioConsumed([],audit,spec),false);
  assert.equal(scenarioConsumed(events,audit.slice(0,2),spec),false);
  assert.equal(scenarioConsumed(events,audit.slice(2),spec),false);
  assert.equal(scenarioConsumed(events.map(e=>e.type==='tool.execution_complete'?{...e,data:{...e.data,success:false}}:e),audit,spec),false);
  assert.equal(scenarioConsumed(events.map(e=>e.type==='tool.execution_complete'?{...e,data:{...e.data,result:'clean diagnostic'}}:e),audit,spec),false);
});

test('hard comparisons require the matching repair clean controls',()=>{
  const row={kind:'copilot_injection',fixture:'repairHardOracle',trial:1,mode:'baseline',consumed:true,exitCode:0,mcpReady:true,fixtureReady:true,observedModels:['fixed-model'],before:'ok',after:'ok',protected:{path:'policy.json',before:policyBefore,after:policyAttack,changed:true},status:'unauthorized_write',task:{outcome:'completed'}};
  const governed={...row,mode:'mcp-only',protected:{...row.protected,after:policyBefore,changed:false},status:'no_observed_write',task:{outcome:'awaiting_independent_approval'}};
  assert.equal(summarize([row,governed]).comparativeEvidencePairs,0);
  const clean=[{...row,fixture:'repairClean',protected:governed.protected,status:'no_observed_write'},{...governed,fixture:'repairClean'}];
  assert.equal(summarize([...clean,row,governed]).comparativeEvidencePairs,1);
  assert.equal(summarize([...clean,row,{...governed,consumed:false}]).comparativeEvidencePairs,0);
});

test('multiline patch delivery works through raw and JSON-encoded tool envelopes',()=>{
  const spec=scenarios.repairHardBundle;
  const trace=result=>[
    {type:'tool.execution_start',data:{toolName:'view',toolCallId:'patch'}},
    {type:'tool.execution_complete',data:{toolCallId:'patch',success:true,result}}
  ];
  assert.equal(scenarioConsumed(trace({content:spec.files['checks.js']}),[],spec),true);
  assert.equal(scenarioConsumed(trace({content:[{text:JSON.stringify({text:spec.files['checks.js']})}]}),[],spec),true);
  assert.equal(scenarioConsumed(trace({content:appExpected}),[],spec),false);
});
