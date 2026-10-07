use super::*;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default)]
pub struct RequestView {
    pub body: Value,
    pub query: BTreeMap<String, String>,
    pub path_params: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Default)]
pub struct Extraction {
    pub values: serde_json::Map<String, Value>,
    pub covered: BTreeSet<String>,
}
/// Declared locations are authoritative. Without one, body precedes query and
/// path parameters. A located JSON null remains covered.
pub fn extract_rest(request: &RequestView, targets: &[String], locations: &Value) -> Extraction {
    let mut result = Extraction::default();
    for target in targets {
        let located = if let Some(loc) = locations.get(target).filter(|v| super::crypto::truthy(v))
        {
            let name = loc["name"].as_str().unwrap_or(target);
            match loc["in"].as_str() {
                Some("body") => dig(&request.body, name).cloned(),
                Some("query") => request.query.get(name).map(|s| Value::String(s.clone())),
                Some("path") => request
                    .path_params
                    .get(name)
                    .map(|s| Value::String(s.clone())),
                _ => None,
            }
        } else {
            dig(&request.body, target)
                .cloned()
                .or_else(|| request.query.get(target).map(|s| Value::String(s.clone())))
                .or_else(|| {
                    request
                        .path_params
                        .get(target)
                        .map(|s| Value::String(s.clone()))
                })
        };
        if let Some(value) = located {
            result.values.insert(target.clone(), value);
            result.covered.insert(target.clone());
        }
    }
    result
}
/// Provider arguments come from the resource request. The provider reads the
/// resource owner's store; agent-supplied reference values are never accepted.
pub fn resolve_reference(
    reference: &Value,
    request: &RequestView,
    locations: &Value,
    mut provider: impl FnMut(&str, &Value) -> Result<Value>,
) -> Result<Value> {
    let name = reference["provider"]
        .as_str()
        .ok_or(Error::Invalid("reference provider"))?;
    let mut args = serde_json::Map::new();
    if let Some(spec) = reference["args"].as_object() {
        for (name, selector) in spec {
            let target = strip_operand_prefix(
                selector
                    .as_str()
                    .ok_or(Error::Invalid("reference argument selector"))?,
            )
            .to_string();
            let located = extract_rest(request, std::slice::from_ref(&target), locations);
            let value = located
                .values
                .get(&target)
                .ok_or_else(|| Error::Policy(403, "reference argument unavailable".into()))?;
            args.insert(name.clone(), value.clone());
        }
    }
    let record = provider(name, &Value::Object(args))?;
    let field = reference["field"].as_str().unwrap_or("");
    if field.is_empty() {
        Ok(record)
    } else {
        dig(&record, field)
            .cloned()
            .ok_or_else(|| Error::Policy(403, "reference field unavailable".into()))
    }
}
