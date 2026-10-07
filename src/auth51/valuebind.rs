use super::*;
use serde_json::json;

pub fn dig<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(v, |v, k| v.as_object()?.get(k))
}

use super::algorithms::{PythonNumber, parse_python_number};
use num_bigint::BigInt;
use std::cmp::Ordering;
fn number(v: &Value, coerce: bool) -> Option<PythonNumber> {
    match v {
        Value::Bool(b) => Some(PythonNumber::Integer(BigInt::from(u8::from(*b)))),
        Value::Number(n) => {
            if n.is_f64() {
                n.as_f64().map(PythonNumber::Float)
            } else {
                n.to_string().parse().ok().map(PythonNumber::Integer)
            }
        }
        Value::String(s) if coerce => parse_python_number(s),
        _ => None,
    }
}
fn int_float_cmp(integer: &BigInt, float: f64) -> Option<Ordering> {
    if float.is_nan() {
        return None;
    }
    if float.is_infinite() {
        return Some(if float.is_sign_positive() {
            Ordering::Less
        } else {
            Ordering::Greater
        });
    }
    let bits = float.to_bits();
    let exp = ((bits >> 52) & 0x7ff) as i32;
    let mut mantissa = BigInt::from(if exp == 0 {
        bits & ((1 << 52) - 1)
    } else {
        (bits & ((1 << 52) - 1)) | (1 << 52)
    });
    if float.is_sign_negative() {
        mantissa = -mantissa;
    }
    let shift = if exp == 0 { -1074 } else { exp - 1023 - 52 };
    Some(if shift >= 0 {
        integer.cmp(&(mantissa << shift as usize))
    } else {
        (integer << (-shift) as usize).cmp(&mantissa)
    })
}
fn numeric_cmp(a: PythonNumber, b: PythonNumber) -> Option<Ordering> {
    match (a, b) {
        (PythonNumber::Integer(a), PythonNumber::Integer(b)) => Some(a.cmp(&b)),
        (PythonNumber::Float(a), PythonNumber::Float(b)) => a.partial_cmp(&b),
        (PythonNumber::Integer(a), PythonNumber::Float(b)) => int_float_cmp(&a, b),
        (PythonNumber::Float(a), PythonNumber::Integer(b)) => {
            int_float_cmp(&b, a).map(Ordering::reverse)
        }
    }
}
fn py_equal(a: &Value, b: &Value) -> bool {
    if let (Some(a), Some(b)) = (number(a, false), number(b, false)) {
        return numeric_cmp(a, b) == Some(Ordering::Equal);
    }
    match (a, b) {
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| py_equal(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(k, v)| b.get(k).is_some_and(|b| py_equal(v, b)))
        }
        _ => a == b,
    }
}
fn py_cmp(a: &Value, b: &Value, coerce: bool) -> Option<Ordering> {
    match (number(a, coerce), number(b, coerce)) {
        (Some(a), Some(b)) => return numeric_cmp(a, b),
        (Some(_), None) | (None, Some(_)) => return None,
        _ => {}
    }
    match (a, b) {
        (Value::String(a), Value::String(b)) => Some(a.cmp(b)),
        (Value::Array(a), Value::Array(b)) => {
            for (a, b) in a.iter().zip(b) {
                if !py_equal(a, b) {
                    return py_cmp(a, b, false);
                }
            }
            Some(a.len().cmp(&b.len()))
        }
        _ => None,
    }
}

/// Closed native operator set. Numeric coercion applies to comparisons, but
/// membership follows Python's original container semantics without coercion.
pub fn apply_op(op: &str, left: &Value, right: &Value) -> bool {
    if ["in", "not_in"].contains(&op) {
        if !super::crypto::truthy(right) {
            return op == "not_in";
        }
        let contains = match right {
            Value::Array(a) => Some(a.iter().any(|v| py_equal(left, v))),
            Value::Object(m) => left.as_str().map(|s| m.contains_key(s)),
            Value::String(s) => left.as_str().map(|l| s.contains(l)),
            v if !super::crypto::truthy(v) => Some(false),
            _ => None,
        };
        return contains.is_some_and(|c| if op == "in" { c } else { !c });
    }
    match op {
        "==" | "!=" => {
            let eq = match (number(left, true), number(right, true)) {
                (Some(a), Some(b)) => numeric_cmp(a, b) == Some(Ordering::Equal),
                (Some(_), None) | (None, Some(_)) => false,
                _ => py_equal(left, right),
            };
            if op == "==" { eq } else { !eq }
        }
        ">" | ">=" | "<" | "<=" => {
            let cmp = py_cmp(left, right, true);
            cmp.is_some_and(|c| match op {
                ">" => c.is_gt(),
                ">=" => c.is_ge(),
                "<" => c.is_lt(),
                _ => c.is_le(),
            })
        }
        _ => false,
    }
}

pub fn valid_bound(raw: &Value) -> bool {
    let target = raw["target"].as_str().unwrap_or("");
    let target_ok = selector_path(target).is_some();
    let op = raw["op"].as_str().unwrap_or("");
    let operand = &raw["operand"];
    target_ok
        && [">", ">=", "<", "<=", "==", "!=", "in", "not_in"].contains(&op)
        && valid_operand(operand)
        && raw.get("provenance_floor").is_none_or(|f| {
            !super::crypto::truthy(f)
                || f.as_str()
                    .is_some_and(|s| ["llm", "external", "observed", "app", "human"].contains(&s))
        })
}
fn selector_path(text: &str) -> Option<(&str, String)> {
    let s = text.trim();
    let (root, rest) = if s.starts_with("tool(") {
        let pattern = regex::Regex::new(
            r#"^tool\(\s*"([^"]+)"\s*\)(\[[^\]]*\])?(@last|@first|@all|@\[\d+\])?(.*)$"#,
        )
        .expect("selector regex");
        let matched = pattern.captures(s)?;
        (
            "tool",
            matched
                .get(4)
                .map_or("", |m| m.as_str())
                .trim_start_matches('.'),
        )
    } else {
        s.split_once('.').unwrap_or((s, ""))
    };
    if !["self", "action", "tool", "policy", "spec", "task"].contains(&root) {
        return None;
    }
    let mut parts: Vec<_> = rest.split('.').filter(|s| !s.is_empty()).collect();
    if ["self", "action", "tool"].contains(&root)
        && parts.first().is_some_and(|p| ["in", "out"].contains(p))
    {
        parts.remove(0);
    }
    Some((root, parts.join(".")))
}
fn valid_operand(operand: &Value) -> bool {
    if operand.get("lit").is_some() {
        return true;
    }
    if let Some(sel) = operand.get("sel") {
        return sel.as_str().is_some_and(|s| selector_path(s).is_some());
    }
    if operand.get("ref").is_some() {
        return true;
    }
    if operand.get("fn").is_some() {
        return operand.get("args").is_none_or(|a| {
            !super::crypto::truthy(a) || a.as_array().is_some_and(|a| a.iter().all(valid_operand))
        });
    }
    if let Some(pref) = operand.get("pref") {
        return pref.is_object()
            && pref.get("provider").is_some()
            && pref
                .get("args")
                .is_none_or(|a| !super::crypto::truthy(a) || a.is_object());
    }
    false
}

/// Static mint-time resolution. Provider references stay unresolved until the
/// resource reads its own system of record. Dynamic untrusted selectors fail.
pub fn freeze_bounds(
    raw: &[Value],
    operation: &str,
    params: &Value,
    policy: &Value,
    spec: &Value,
    tier: &str,
) -> Result<ValueBinding> {
    let mut bounds = Vec::new();
    let mut constrained = serde_json::Map::new();
    for b in raw {
        if !valid_bound(b) {
            return Err(Error::Policy(403, "malformed value bound".into()));
        }
        let target = b["target"].as_str().ok_or(Error::Invalid("target"))?;
        let (_, target) = selector_path(target).ok_or(Error::Invalid("target selector"))?;
        let operand = &b["operand"];
        let (value, reference) = if let Some(lit) = operand.get("lit") {
            (Some(lit.clone()), None)
        } else if let Some(sel) = operand["sel"].as_str() {
            let (root, path) = selector_path(sel).ok_or(Error::Invalid("operand selector"))?;
            let value = match root {
                "policy" => dig(policy, &path).cloned().unwrap_or(Value::Null),
                "spec" => dig(spec, &path).cloned().unwrap_or(Value::Null),
                _ => return Err(Error::Policy(403, "unresolved value selector".into())),
            };
            (Some(value), None)
        } else if operand.get("ref").is_none()
            && operand.get("fn").is_none()
            && operand.get("pref").is_some()
        {
            let pref = &operand["pref"];
            let args = pref
                .get("args")
                .filter(|a| super::crypto::truthy(a))
                .cloned()
                .unwrap_or_else(|| json!({}));
            let field = pref
                .get("field")
                .map(python_str)
                .transpose()?
                .unwrap_or_default();
            (
                None,
                Some(json!({"provider":python_str(&pref["provider"])? ,"args":args,"field":field})),
            )
        } else {
            return Err(Error::Policy(403, "unresolved value selector".into()));
        };
        bounds.push(FrozenBound {
            target: target.clone(),
            op: b["op"].as_str().unwrap_or("").into(),
            value,
            r#ref: reference,
            source_provenance: None,
        });
        let actual = dig(params, &target).cloned().unwrap_or(Value::Null);
        constrained.insert(target, actual);
    }
    Ok(ValueBinding {
        action_hash: action_hash(operation, &Value::Object(constrained))?,
        bounds,
        tier: tier.into(),
        operation: operation.into(),
        pin: None,
    })
}

pub fn strip_operand_prefix(s: &str) -> &str {
    for prefix in ["self.in.", "action.in.", "self.", "action."] {
        if let Some(s) = s.strip_prefix(prefix) {
            return s;
        }
    }
    s
}

pub fn evaluate_binding(binding: &ValueBinding, params: &Value) -> bool {
    binding
        .bounds
        .iter()
        .filter(|b| b.r#ref.is_none())
        .all(|b| {
            apply_op(
                &b.op,
                dig(params, &b.target).unwrap_or(&Value::Null),
                b.value.as_ref().unwrap_or(&Value::Null),
            )
        })
}

/// Resource-side extraction is passed separately from raw request data: bound
/// targets must be located, including dotted names, rather than assumed absent.
pub fn verify_binding(
    binding: &ValueBinding,
    values: &Value,
    mut provider: impl FnMut(&Value) -> Result<Value>,
) -> Result<()> {
    let mut constrained = serde_json::Map::new();
    for b in &binding.bounds {
        let actual = values
            .get(&b.target)
            .ok_or(Error::Policy(403, "value binding unverifiable".into()))?;
        let rhs = match &b.r#ref {
            Some(r) => provider(r)?,
            None => b.value.clone().unwrap_or(Value::Null),
        };
        if !apply_op(&b.op, actual, &rhs) {
            return Err(Error::Policy(403, "value bound violated".into()));
        }
        // Python verify() digs dotted targets through a nested mapping; retain
        // that behavior even when the extractor returns a literal dotted key.
        constrained.insert(
            b.target.clone(),
            dig(values, &b.target).cloned().unwrap_or(Value::Null),
        );
    }
    if !binding.operation.is_empty()
        && action_hash(&binding.operation, &json!(constrained))? != binding.action_hash
    {
        return Err(Error::Policy(403, "action_hash mismatch".into()));
    }
    Ok(())
}
