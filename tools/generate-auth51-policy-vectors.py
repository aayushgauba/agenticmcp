"""Offline oracle: execute original Auth51 functions against in-memory repos.

Python is used only to generate development fixtures; the product is pure Rust.
"""
import argparse,ast,asyncio,copy,hashlib,json,logging,sys,types,textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import *

p=argparse.ArgumentParser()
p.add_argument('--authority-root',type=Path,required=True)
p.add_argument('--governance-root',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
args=p.parse_args()
sys.path.insert(0,str(args.governance_root/'src'))
from auth51_governance import Bound,ValueBinding,evaluate,resolve_bounds,UnresolvedSelector
from auth51_governance.policy import DEFAULT_POLICY
from auth51_governance.valuebind import apply_op,provenance_admits,Provenance
from auth51_governance.analyze import analyze_source
from auth51_governance.synthesize import synthesize
from auth51_governance.model import Obs,Capability
from auth51_governance.effects import EvidenceBundle,Effect,EffectKind,EffectProvenance
from auth51_governance.resolve import resolve_consequence

tree=ast.parse((args.authority_root/'auth51_authority/services/intent_service.py').read_text(encoding='utf-8'))
names={'_WorkflowResolution','_approved','_hop_agent_id','_checksum_matches','_sequence_hash',
    'mint_token','_resolve_workflow','_validate_delegation_chain','_verify_chain_checksums','_build_value_binding','_create_intent_token'}
nodes=[n for n in ast.walk(tree) if isinstance(n,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)) and n.name in names]
class Denied(Exception):
    def __init__(self,status,*a,**kw):self.status=status
async def get_policy(*a):return DEFAULT_POLICY
class Clock:
    @staticmethod
    def time():return 1800000000
class UUID:
    @staticmethod
    def uuid4():return types.SimpleNamespace(hex='0'*32)
ns=globals()|{'HTTPException':Denied,'logger':logging.getLogger('oracle'),'_MAX_DELEGATION_DEPTH':8,'time':Clock,'uuid':UUID,
    'settings':types.SimpleNamespace(idp=types.SimpleNamespace(issuer='https://local.example')),
    'jwt':types.SimpleNamespace(encode=lambda payload,*a,**kw:payload),
    'DecisionOutcome':types.SimpleNamespace(ALLOW='allow')}
exec(compile('from __future__ import annotations\n'+ '\n'.join(ast.unparse(n) for n in nodes),'<actual-auth51-functions>','exec'),ns)
logging.disable(logging.CRITICAL)

def obj(d):return types.SimpleNamespace(**d)
class Repo:
    def __init__(self,case):self.case=case
    async def list_by_org(self,*a):return [obj({'id':1,'app_id':'app'})]
    async def find_by_agent_id_across_apps(self,apps,aid):
        a=next((a for a in self.case['agents'] if a['agent_id']==aid),None)
        return obj(a|{'id':aid,'app_id':1}) if a else None
    async def list_tools(self,aid):
        a=next(a for a in self.case['agents'] if a['agent_id']==aid)
        return [obj({'name':s,'is_agent':True}) for s in a.get('subagents',[])]
    async def get_active(self,**kw):
        a=next(a for a in self.case['agents'] if a['agent_id']==kw['agent_id'])
        return obj(a['grant']) if a.get('grant') else None
    async def get_by_execution_id(self,eid,**kw):
        e=self.case.get('execution')
        return obj(e) if e and eid==e['execution_id'] else None
    async def pin_workflow(self,e,w):e.workflow_id=w
    async def list_steps(self,wid):
        w=next(w for w in self.case['workflows'] if w['workflow_id']==wid)
        defaults={'scopes':[],'dependencies':[],'required':False,'approval_gate':False,'requires_approval':False,'value_bound':False,'value_bounds':[],'tier':''}
        return [obj(defaults|s|{'step_name':n}) for n,s in sorted(w['steps'].items())]
    async def find_all_by_entry_agent(self,apps,entry):
        return [obj(w|{'id':w['workflow_id']}) for w in self.case['workflows'] if any(s['agent']==entry and not s.get('dependencies') for s in w['steps'].values())]

async def expected(case):
    repo=Repo(case)
    self=obj({k:repo for k in ['apps','agents','grants','workflows','executions']})
    self.session=None;self._private_key='unused';self._kid='test'
    async def deny(**kw):raise Denied(kw['status'])
    async def unknown(*a):raise Denied(401)
    async def noop(*a,**kw):pass
    async def candidates(execution,apps):
        ids=[execution.workflow_id] if execution.workflow_id else execution.candidate_workflow_ids
        return [obj(w|{'id':w['workflow_id']}) for w in case['workflows'] if w['workflow_id'] in ids]
    self._deny=deny;self._capture_unknown_and_deny=unknown;self._audit=noop;self._record_observed_effects=noop;self._execution_candidates=candidates
    for name in names:
        if name.startswith('_') and name in ['_resolve_workflow','_validate_delegation_chain','_verify_chain_checksums','_build_value_binding','_create_intent_token']:
            setattr(self,name,types.MethodType(ns[name],self))
    defaults={'execution_id':None,'workflow_id':None,'workflow_enabled':True,'workflow_step':None,'action_args':None,'delegation_context':None,'cnf_jkt':None}
    req=obj(defaults|case['request'])
    try:
        out=await ns['mint_token'](self,req,has_scopes=case['caller_scopes'],org_id='org',token_app='app')
        claims=out.access_token
        claims.pop('jti',None)
        return {'status':200,'claims':claims}
    except Denied as e:return {'status':e.status}

# Replace Pydantic TokenResponse solely to capture the original generated claims.
ns['TokenResponse']=lambda **kw:obj(kw)
base={'agents':[{'agent_id':'a','registration_id':'reg-a','checksum':'v2-a','checksum_v1':'v1-a','checksum_v3':'v3-a','checksum_v4':'v4-a','checksum_v5':'v5-a','public_key':None,'subagents':['b'],
    'grant':{'allowed_scopes':['read','write'],'step_up_scopes':[],'mode':'enforce'}},
    {'agent_id':'b','registration_id':'reg-b','checksum':'v2-b','checksum_v1':'v1-b','checksum_v3':'v3-b','checksum_v4':'v4-b','checksum_v5':'v5-b','public_key':None,'subagents':[],
    'grant':{'allowed_scopes':['read','write'],'step_up_scopes':[],'mode':'enforce'}}],
    'workflows':[], 'caller_scopes':['generate:intent-token'],
    'request':{'grant_type':'agent_checksum','agent_id':'a','computed_checksum':'v4-a','requested_scopes':['read'],'audience':'resource','cnf_jkt':'test-jkt'}}
cases=[]
def add(name,mutate=lambda c:None):
    c=copy.deepcopy(base);c['name']=name;mutate(c);cases.append(c)
add('identity only')
for version in range(1,6):add('checksum v'+str(version),lambda c,v=version:c['request'].update(computed_checksum=f'v{v}-a'))
add('bad checksum',lambda c:c['request'].update(computed_checksum='bad'))
add('unsupported grant URN',lambda c:c['request'].update(grant_type='urn:ietf:params:oauth:grant-type:agent_checksum'))
add('missing grant',lambda c:c['agents'][0].update(grant=None))
add('outside envelope',lambda c:c['request'].update(requested_scopes=['other']))
add('observe outside',lambda c:(c['agents'][0]['grant'].update(mode='observe'),c['request'].update(requested_scopes=['other'])))
add('step up',lambda c:c['agents'][0]['grant'].update(step_up_scopes=['read']))
def chain(c,checksums=True):
    c['request'].update(agent_id='b',computed_checksum='v4-b',delegation_context={'chain':[{'agent_id':'a','checksum':'v4-a'},'b'] if checksums else ['a','b'],'completed_steps':[]})
add('custody valid',chain)
add('legacy chain',lambda c:chain(c,False))
add('custody mismatch',lambda c:(chain(c),c['request']['delegation_context']['chain'][0].update(checksum='wrong')))
add('undeclared edge',lambda c:(chain(c),c['agents'][0].update(subagents=[])))
add('observe undeclared',lambda c:(chain(c),c['agents'][0].update(subagents=[]),c['agents'][1]['grant'].update(mode='observe')))
add('observe custody remains hard',lambda c:(chain(c),c['agents'][1]['grant'].update(mode='observe'),c['request']['delegation_context']['chain'][0].update(checksum='wrong')))
wf={'workflow_id':'wf','workflow_type':'dag','mode':'enforce','control':'strict','steps':{
    'a_read':{'agent':'a','action':'read','scopes':['read']},
    'b_write':{'agent':'a','action':'write','scopes':['write'],'dependencies':['a_read']}}}
def workflow(c):
    c['workflows']=[copy.deepcopy(wf)];c['request']['workflow_step']={'agent_id':'a','tool_name':'write'};c['request']['requested_scopes']=['write']
    c['request']['delegation_context']={'chain':['a'],'completed_steps':[]}
add('dependency missing',workflow)
add('dependency supplied',lambda c:(workflow(c),c['request']['delegation_context'].update(completed_steps=[{'agent_id':'a','tool_name':'read'}])))
add('client opt out ignored',lambda c:(workflow(c),c['request'].update(workflow_enabled=False,workflow_id='lax')))
add('observe DAG',lambda c:(workflow(c),c['workflows'][0].update(mode='observe')))
add('strict unknown action',lambda c:(workflow(c),c['request']['workflow_step'].update(tool_name='free')))
add('guarded unknown action',lambda c:(workflow(c),c['workflows'][0].update(control='guarded'),c['request']['workflow_step'].update(tool_name='free')))
add('unexplained completed',lambda c:(workflow(c),c['request']['delegation_context'].update(completed_steps=[{'agent_id':'a','tool_name':'unknown'}])))
add('guarded free history',lambda c:(workflow(c),c['workflows'][0].update(control='guarded'),c['request']['workflow_step'].update(tool_name='free'),c['request']['delegation_context'].update(completed_steps=[{'agent_id':'a','tool_name':'unknown'}])))
def execution(c,mode='enforce',bound='wf',candidates=['wf']):
    workflow(c);c['execution']={'execution_id':'run','workflow_id':bound,'candidate_workflow_ids':candidates,'mode':mode};c['request']['execution_id']='run'
add('execution enforce overrides observe',lambda c:(execution(c),c['workflows'][0].update(mode='observe')))
add('execution observe overrides enforce',lambda c:execution(c,'observe'))
add('empty run candidates ungoverned',lambda c:execution(c,bound=None,candidates=[]))
add('execution custody downgrade',lambda c:(execution(c),chain(c,False)))
def approval(c,done):
    workflow(c);w=c['workflows'][0]['steps'];w['approval']={'agent':'human','action':'approve','approval_gate':True};w['b_write']['requires_approval']=True
    c['request']['delegation_context']['completed_steps']=[{'agent_id':'a','tool_name':'read'}]+([{'agent_id':'human','tool_name':'approve'}] if done else [])
add('approval missing',lambda c:approval(c,False));add('approval present',lambda c:approval(c,True))
def valuebound(c,amount):
    workflow(c);w=c['workflows'][0]['steps']['b_write'];w['dependencies']=[];w['value_bound']=True;w['tier']='FINANCIAL';w['value_bounds']=[{'target':'self.in.amount','op':'>','operand':{'lit':0}},{'target':'self.in.amount','op':'<=','operand':{'lit':1000}}]
    c['request']['action_args']={'amount':amount,'free':'x'}
add('bounded good',lambda c:valuebound(c,'500'))
add('bounded zero',lambda c:valuebound(c,0))
add('bounded too large',lambda c:valuebound(c,1001))
add('bounded observe',lambda c:(valuebound(c,0),c['workflows'][0].update(mode='observe')))
add('missing policy selector is null',lambda c:(valuebound(c,10),c['workflows'][0]['steps']['b_write']['value_bounds'][1].update(operand={'sel':'policy.missing'})))
add('provider defaults',lambda c:(valuebound(c,500),c['workflows'][0]['steps']['b_write']['value_bounds'][1].update(operand={'pref':{'provider':'charges'}})))
add('output selector target path',lambda c:(valuebound(c,500),c['workflows'][0]['steps']['b_write']['value_bounds'][1].update(target='self.out.amount')))
add('invalid provenance floor',lambda c:(valuebound(c,500),c['workflows'][0]['steps']['b_write']['value_bounds'][1].update(provenance_floor='untrusted')))
add('invalid operand selector',lambda c:(valuebound(c,500),c['workflows'][0]['steps']['b_write']['value_bounds'][1].update(operand={'sel':'unknown.x'})))

async def main():
    for c in cases:
        c['expected']=await expected(c)
asyncio.run(main())
ops=[]
for op in ['>','>=','<','<=','==','!=','in','not_in']:
    for left,right in [(1,2),('500',1000),(True,1),(None,None),('a','b'),('10',['10',10]),('x',{'x':1}),('a','cat'),(0,0),(9007199254740992,9007199254740993),
        (9007199254740993,9007199254740992.0),('123456789012345678901234567890',123456789012345678901234567891),('١_٢٣',123),('NaN',0),('Infinity',1000),('1__0','1__0'),([1,2],[1,3]),(1,{}),(1,''),(False,[])]:
        ops.append({'op':op,'left':left,'right':right,'expected':apply_op(__import__('auth51_governance.valuebind',fromlist=['Op']).Op(op),left,right)})
classifications=[]
for action in ['ReadAccount','ListPayouts','CreatePayout','UpdateCustomer','DeleteDatabase','GrantRole','foo','WriteFile','DeleteRepo','RotateSecret','delete_bucket']:
    for tags,risk in [([],''),([], 'low'),(['security'],''),(['financial'],'destructive')]:
        classifications.append({'action':action,'tags':tags,'risk':risk,'tier':DEFAULT_POLICY.classify(action,tags,risk)})
sources=['def f(x):\n    "docs"\n    return x+1\n','import requests as r\ndef f():\n    r.delete("https://x")\n',
    'from shutil import rmtree as wipe\ndef f(): wipe("x")', 'def f():\n    eval("x")\n    open("x","w")\n',
    'import stripe\ndef f(): stripe.Payout.create(amount=10)','def f(): cur.execute("DROP TABLE x")',
    'def f(o,n): return getattr(o,n)()', 'def broken(:',
    '@decorator\nasync def f(x: int=1, *, y=None):\n    "docs"\n    return {"a": [i*i for i in range(x) if i>0]}',
    'class X:\n    "docs"\n    def f(self):\n        "docs"\n        return "hello"\n',
    'try:\n x=1\nexcept ValueError as e:\n raise RuntimeError("bad") from e\n',
    'def f(x):\n if x:\n  return (1,2)\n elif x is None:\n  return -1\n else:\n  return f"x={x!r}"\n']
sources += [
    'def f():\n return\n', 'def f():\n yield\n', 'def f():\n return None\n',
    'x = b"hello"', 'x = "a\\nb"', 'x = "don\'t"', 'x = "\\u00e9"',
    'def f():\n "only docs"', '"module docs"', '',
    'def f(a, /, b=1, *args, c=2, **kwargs):\n return a+b',
    'with open("x", "w") as f:\n f.write("x")',
    'def f():\n def g():\n  return 1\n return g()',
    'x = 1.0\ny=1e20\nz=-0.0', 'x = {1,2}\ny=set()\nz=(1,)',
    'x = lambda a: a+1', 'x = [x for x in range(3)]',
    'import requests\ndef f():\n requests.post("x", data=eval("x"))',
]
from auth51_governance.recognizers import *
from auth51_governance.effects import LOCAL_EFFECT_TIER
recognizers={'http':HTTP_CALLABLES,'http_tiers':HTTP_METHOD_TIER,'sdk':SDK_CALLS,'sdk_roots':sorted(KNOWN_SDK_ROOTS),'stdlib':DANGEROUS_STDLIB,'dynamic':sorted(DYNAMIC_EXEC),'local_tiers':LOCAL_EFFECT_TIER}
def effect(e):return {k:getattr(e,k) for k in ['kind','ref','name','tier','provenance','confidence','detail']}
compute_tree=ast.parse((args.authority_root/'auth51_authority/crypto/compute.py').read_text(encoding='utf-8'))
normalizers=[n for n in compute_tree.body if isinstance(n,ast.FunctionDef) and n.name in ['normalize_source','remove_docstrings']]
normal_ns=globals().copy()
exec(compile('\n'.join(ast.unparse(n) for n in normalizers),'<actual-auth51-normalizer>','exec'),normal_ns)
syn=[]
for runs in [[],[[Obs('a','ReadAccount'),Obs('a','CreatePayout')]],[[Obs('a','ReadAccount'),Obs('a','CreatePayout')]]*3,[[Obs('a','ReadAccount'),Obs('a','CreatePayout')],[Obs('a','CreatePayout'),Obs('a','ReadAccount')]]]:
    for minimum in [1,3]:
        caps=[Capability('a','ReadAccount',('read',),'READ'),Capability('a','CreatePayout',('pay',),'FINANCIAL',('amount','quantity','message')),Capability('b','DeleteDatabase',('delete',),'DESTRUCTIVE'),Capability('b','ReadAccount',('read',),'READ')]
        syn.append({'runs':[[o.__dict__ for o in run] for run in runs],'capabilities':[c.__dict__ for c in caps],'min_support':minimum,'expected':synthesize('derived',runs,caps,min_support=minimum)})
reports=[]
from dataclasses import asdict
for source in sources:
    for override in [None,'READ']:
        bundle=EvidenceBundle(effects=analyze_source(source),nominal_name='ReadWrapper',override_tier=override)
        reports.append({'bundle':asdict(bundle),'expected':asdict(resolve_consequence(bundle))})
out={'mint':cases,'operators':ops,'classification':classifications,'sources':[{'source':s,'normalized':normal_ns['normalize_source'](s),'effects':[effect(e) for e in analyze_source(s)]} for s in sources], 'recognizers':recognizers,'synthesis':syn,'consequence':reports}
args.output.write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf-8')
