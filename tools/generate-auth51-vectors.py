"""Generate offline cross-language fixtures from the actual Auth51 algorithms."""
import importlib.util
import json
import sys
import argparse
import base64
import hashlib
import random
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--authority-root", type=Path, required=True)
parser.add_argument("--governance-root", type=Path, required=True)
parser.add_argument("--output", type=Path, default=Path("tests/fixtures/auth51.json"))
args = parser.parse_args()
# Install auth51-checksum into this interpreter before regenerating fixtures.
from auth51_checksum.agent import compute_all_v5
from auth51_checksum._source import normalize_source
sys.path.insert(0, str(args.governance_root / "src"))
from auth51_governance.valuebind import compute_action_hash
spec = importlib.util.spec_from_file_location("scopes", args.authority_root / "auth51_authority/vendor/auth51_scopes/__init__.py")
scopes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scopes)

components = [
    {"agent_id":"planner", "prompt_template":"You are planner.", "tools":[], "configuration":{"temperature":0}},
    {"agent_id":"unicode", "prompt_template":"  Cafe\u0301 😀\r\n\n next \n", "configuration":{"z":" x \n y ","a":True}, "tools":[
        {"name":"z", "signature":"(x: int)", "description":" desc ", "parameters":{"type":"object","properties":{"x":{"type":"integer"}}}, "source_code":"def z(x):\n    \"\"\"docs\"\"\"\n    # ignored\n    return x+1\n"},
        {"name":"remote", "signature":"()", "description":"MCP", "source":"mcp"},
        {"name":"child", "signature":"()", "description":"delegate", "is_agent":True},
    ]},
    {"agent_id":"floats", "prompt_template":"p", "tools":[], "configuration":{"numbers":[0.0,-0.0,1e-5,1e-4,1e15,1e16,1e20,1e-7,1.2345678901234567,0.7]}},
    {"agent_id":"source", "prompt_template":"p", "configuration":{}, "tools":[
        {"name":"f", "signature":"()", "description":"", "source_code":"  def f():\n      \"\"\"only docs\"\"\"\n"},
        {"name":"bad", "signature":"()", "description":"", "source_code":" def broken(:\n"}]},
]
rng = random.Random(51)
components.append({"agent_id":"numeric", "prompt_template":"p", "tools":[],
    "configuration":{"values":[rng.uniform(-1,1)*10.0**rng.randrange(-300,300) for _ in range(100)]}})
vectors=[]
for c in components:
    v2,v1,v3,v4,v5=compute_all_v5(c)
    normalized={t["source_code"]:normalize_source(t["source_code"]) for t in c["tools"] if t.get("source_code")}
    vectors.append({"components":c,"v1":v1,"v2":v2,"v3":v3,"v4":v4,"v5":v5,"normalized_sources":normalized})
routes = [("example.com","GET","//files/:id/"),("example.com","POST","/x/<int:item>"),("rs","PUT","/café/a:b/%/😀")]
actions = [("transfer",{"amount":"500","account":"A"}),("sell",{"price":0}),("unicode",{"é":"😀","nested":{"x":"10"}}),
           ("float",{"small":"1e-5","large":"1e20","negative":"-0.0"})]
out={"checksums":vectors,"scopes":[{"rs":r,"method":m,"path":p,"scope":scopes.derive_scope(r,m,p)} for r,m,p in routes],
     "actions":[{"operation":op,"params":p,"hash":compute_action_hash(op,p)} for op,p in actions]}
b64=lambda b:base64.urlsafe_b64encode(b).decode().rstrip("=")
jwk={"crv":"P-256","kty":"EC","x":b64(bytes(range(32))),"y":b64(bytes(reversed(range(32))))}
out["jwk"] = jwk
out["jkt"] = b64(hashlib.sha256(json.dumps(jwk,sort_keys=True,separators=(",",":")).encode()).digest())
out["ath"] = b64(hashlib.sha256(b"test.access.token").digest())
out["sequence"] = ["a", "{'agent_id': 'b', 'tool_name': 'read'}"]
out["current_repr"] = "{'agent_id': 'c', 'tool_name': 'write'}"
out["sequence_hash"] = hashlib.sha256("|".join(out["sequence"]+[out["current_repr"]]).encode()).hexdigest()[:16]
args.output.write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding="utf-8")
