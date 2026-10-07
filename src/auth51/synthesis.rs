use super::*;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    pub agent: String,
    pub action: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capability {
    pub agent: String,
    pub action: String,
    pub tier: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub params: Vec<String>,
}
type Key = (String, String);
fn slug(s: &str) -> String {
    let s: String = s
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect();
    let s = s.trim_matches('_');
    if s.is_empty() {
        "step".into()
    } else {
        s.into()
    }
}
fn step_name(k: &Key, used: &mut BTreeSet<String>) -> String {
    let base = slug(&k.1);
    let mut name = if used.contains(&base) {
        format!("{base}__{}", slug(&k.0))
    } else {
        base
    };
    while used.contains(&name) {
        name.push_str("_x");
    }
    used.insert(name.clone());
    name
}
pub fn derive_static_bounds(tier: &str, params: &[String], caps: &Value) -> Vec<Value> {
    let pattern = regex::Regex::new(
        r"(?i)(amount|price|total|subtotal|cost|fee|charge|payment|qty|quantity|units?)$",
    )
    .expect("constant regex");
    let mut bounds = vec![];
    for p in params.iter().filter(|p| pattern.is_match(p)) {
        bounds.push(
            json!({"target":format!("self.in.{p}"),"op":">","operand":{"lit":0},"tier":tier}),
        );
        if let Some(cap) = caps.get(tier).filter(|c| !c.is_null()) {
            bounds.push(json!({"target":format!("self.in.{p}"),"op":"<=","operand":{"lit":cap},"tier":tier}));
        }
    }
    bounds
}
/// Mine first occurrences and cross-run ordering, then compile the policy's
/// evidence-dependent guard strengths into Auth51's DAG primitives.
pub fn synthesize(
    workflow_id: &str,
    runs: &[Vec<Observation>],
    capabilities: &[Capability],
    policy: &TierPolicy,
    min_support: Option<u64>,
) -> Value {
    let mut observed: Vec<(Key, &Observation)> = vec![];
    let mut run_first = vec![];
    let mut support: BTreeMap<Key, u64> = BTreeMap::new();
    for run in runs {
        let mut first = BTreeMap::new();
        for (i, o) in run.iter().enumerate() {
            let k = (o.agent.clone(), o.action.clone());
            if !observed.iter().any(|(key, _)| key == &k) {
                observed.push((k.clone(), o));
            }
            first.entry(k).or_insert(i);
        }
        for k in first.keys() {
            *support.entry(k.clone()).or_default() += 1;
        }
        run_first.push(first);
    }
    let mut names = BTreeMap::new();
    let mut used = BTreeSet::new();
    for (k, _) in &observed {
        names.insert(k.clone(), step_name(k, &mut used));
    }
    let mut capmap = BTreeMap::new();
    for c in capabilities {
        capmap.insert((c.agent.clone(), c.action.clone()), c);
    }
    let floor = min_support.unwrap_or(policy.min_support);
    let mut steps = serde_json::Map::new();
    let mut need_approval = false;
    let mut emit = |k: &Key,
                    tier: &str,
                    strength: GuardStrength,
                    scopes: &[String],
                    required: bool,
                    names: &BTreeMap<Key, String>| {
        let mut deps = vec![];
        if strength != GuardStrength::Free {
            for (a, _) in &observed {
                if a == k {
                    continue;
                }
                let together: Vec<_> = run_first
                    .iter()
                    .filter(|f| f.contains_key(a) && f.contains_key(k))
                    .collect();
                if !together.is_empty() && together.iter().all(|f| f[a] < f[k]) {
                    deps.push(names[a].clone());
                }
            }
        }
        if strength == GuardStrength::Approval {
            deps.push("approval".into());
            need_approval = true;
        }
        deps.sort();
        deps.dedup();
        let mut step = json!({"agent":k.0,"action":k.1,"scopes":scopes,"dependencies":deps,"required":required,"approval_gate":false,"requires_approval":false,"tier":tier});
        if strength == GuardStrength::ValueBound {
            step["value_bound"] = json!(true);
            let bounds = capmap
                .get(k)
                .map(|c| derive_static_bounds(tier, &c.params, &policy.value_caps))
                .unwrap_or_default();
            if !bounds.is_empty() {
                step["value_bounds"] = json!(bounds);
            }
        }
        steps.insert(names[k].clone(), step);
    };
    for (k, o) in &observed {
        let cap = capmap.get(k);
        let tier = cap.map_or(policy.default_tier.as_str(), |c| c.tier.as_str());
        let scopes = if o.scopes.is_empty() {
            cap.map_or(&[][..], |c| c.scopes.as_slice())
        } else {
            &o.scopes
        };
        let evidence = if support[k] >= floor {
            "observed_trusted"
        } else {
            "observed_untrusted"
        };
        emit(
            k,
            tier,
            policy.guard_for(tier, evidence),
            scopes,
            !runs.is_empty() && run_first.iter().all(|f| f.contains_key(k)),
            &names,
        );
    }
    for c in capabilities {
        let k = (c.agent.clone(), c.action.clone());
        if observed.iter().any(|(key, _)| key == &k) {
            continue;
        }
        let strength = policy.guard_for(&c.tier, "unobserved");
        if strength == GuardStrength::Free {
            continue;
        }
        // Python eagerly allocates a name even when setdefault retains an old one.
        let name = step_name(&k, &mut used);
        names.entry(k.clone()).or_insert(name);
        emit(&k, &c.tier, strength, &c.scopes, false, &names);
    }
    if need_approval {
        steps.insert("approval".into(),json!({"agent":"human-approver","action":"ApproveHighConsequence","scopes":[],"dependencies":[],"required":false,"approval_gate":true,"requires_approval":false}));
    }
    json!({"workflow_id":workflow_id,"workflow_type":"dag","mode":"enforce","control":"guarded","steps":steps})
}
