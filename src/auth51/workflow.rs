use super::*;
use std::collections::{BTreeMap, BTreeSet};

/// The candidates must already belong to the authenticated app/run. Matching
/// follows Auth51's stored alphabetical step order, not declaration order.
pub fn resolve_workflow(
    candidates: &[Dag],
    completed: &[Value],
    current: &Value,
    scopes: &[String],
) -> WorkflowResolution {
    if candidates.is_empty() {
        return WorkflowResolution::default();
    }
    let mode = |items: &[&Dag]| {
        if items.iter().any(|w| w.mode == Mode::Enforce) {
            Mode::Enforce
        } else {
            Mode::Observe
        }
    };
    let consistent: Vec<_> = candidates
        .iter()
        .filter(|w| {
            w.control == Control::Guarded
                || completed.iter().all(|c| name_for(&w.steps, c).is_some())
        })
        .collect();
    if consistent.is_empty() {
        return WorkflowResolution {
            governed: true,
            authorised: false,
            mode: mode(&candidates.iter().collect::<Vec<_>>()),
            ..Default::default()
        };
    }
    let governing_mode = mode(&consistent);
    let authorizing: Vec<_> = consistent
        .iter()
        .filter_map(|w| {
            let name = name_for(&w.steps, current);
            match name {
                None if w.control == Control::Guarded => Some((*w, None)),
                None => None,
                Some(name) => {
                    let step = &w.steps[name];
                    let done: BTreeSet<_> = completed
                        .iter()
                        .filter_map(|c| name_for(&w.steps, c))
                        .collect();
                    if step.scopes.iter().any(|s| !scopes.contains(s))
                        || step.dependencies.iter().any(|d| !done.contains(d.as_str()))
                    {
                        return None;
                    }
                    if step.requires_approval {
                        let gate = w
                            .steps
                            .iter()
                            .take_while(|(n, _)| n.as_str() != name)
                            .filter(|(_, s)| s.approval_gate)
                            .map(|(n, _)| n.as_str())
                            .last();
                        if gate.is_none_or(|g| !done.contains(g)) {
                            return None;
                        }
                    }
                    Some((*w, Some(name.to_string())))
                }
            }
        })
        .collect();
    let mut result = WorkflowResolution {
        governed: true,
        mode: governing_mode,
        authorised: !authorizing.is_empty(),
        ..Default::default()
    };
    if authorizing.is_empty() {
        if consistent.len() == 1 {
            result.workflow_id = Some(consistent[0].workflow_id.clone());
            result.mode = consistent[0].mode;
        }
    } else {
        result.step_name = authorizing[0].1.clone();
        if authorizing.len() == 1 {
            let (w, name) = &authorizing[0];
            result.workflow_id = Some(w.workflow_id.clone());
            result.mode = w.mode;
            if let Some(step) = name.as_ref().and_then(|n| w.steps.get(n)) {
                result.value_bound = step.value_bound;
                result.value_bounds = step.value_bounds.clone();
                result.tier = step.tier.clone().unwrap_or_default();
                result.action = step.action.clone();
            }
        }
    }
    result
}

fn name_for<'a>(steps: &'a BTreeMap<String, WorkflowStep>, current: &Value) -> Option<&'a str> {
    steps
        .iter()
        .find(|(_, s)| current["agent_id"] == s.agent && current["tool_name"] == s.action)
        .map(|(n, _)| n.as_str())
}

pub fn provenance_admits(floor: &str, actual: &str) -> Result<bool> {
    let rank = |p| match p {
        "llm" | "external" => Ok(0),
        "observed" => Ok(1),
        "app" | "human" => Ok(2),
        _ => Err(Error::Invalid("provenance")),
    };
    Ok(rank(actual)? >= rank(floor)?)
}

/// Auth51 fingerprints do not include advisory tier/value-binding metadata.
/// Keep this explicit for versioning parity; registration floor checks use
/// authority-owned tiers and are performed separately.
pub fn workflow_fingerprint(w: &Dag) -> Result<String> {
    let steps: Vec<_> = w
        .steps
        .iter()
        .map(|(name, s)| {
            let mut scopes = s.scopes.clone();
            scopes.sort();
            let mut deps = s.dependencies.clone();
            deps.sort();
            serde_json::json!([
                name,
                s.agent,
                s.action,
                scopes,
                deps,
                s.required,
                s.approval_gate,
                s.requires_approval
            ])
        })
        .collect();
    Ok(serde_json::to_string(&serde_json::json!([
        w.workflow_type,
        w.mode,
        w.control,
        steps
    ]))?)
}
