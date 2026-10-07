use super::*;
use num_bigint::BigInt;
use serde_json::json;
use sha3::{Digest, Sha3_512};

pub(crate) enum PythonNumber {
    Integer(BigInt),
    Float(f64),
}
/// Python int/float accept decimal Unicode digits and digit-separated
/// underscores. Retain arbitrary integer precision before considering float.
pub(crate) fn parse_python_number(s: &str) -> Option<PythonNumber> {
    use unicode_general_category::{GeneralCategory, get_general_category};
    let mut digits = String::new();
    for c in s
        .trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
        .chars()
    {
        if get_general_category(c) == GeneralCategory::DecimalNumber {
            let mut start = c as u32;
            while start > 0
                && char::from_u32(start - 1)
                    .is_some_and(|p| get_general_category(p) == GeneralCategory::DecimalNumber)
            {
                start -= 1;
            }
            digits.push(char::from(b'0' + ((c as u32 - start) % 10) as u8));
        } else {
            digits.push(c);
        }
    }
    let chars: Vec<_> = digits.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if *c == '_'
            && (i == 0
                || i + 1 == chars.len()
                || !chars[i - 1].is_ascii_digit()
                || !chars[i + 1].is_ascii_digit())
        {
            return None;
        }
    }
    let digits = digits.replace('_', "");
    if let Ok(n) = digits.parse::<BigInt>() {
        return Some(PythonNumber::Integer(n));
    }
    digits.parse::<f64>().ok().map(PythonNumber::Float)
}

/// Auth51 normalizes numeric-looking strings before hashing constrained values.
pub fn canonical_values(v: &Value) -> Value {
    match v {
        Value::String(s) => {
            match parse_python_number(s) {
                Some(PythonNumber::Integer(n)) => {
                    return serde_json::from_str(&n.to_string())
                        .expect("arbitrary precision JSON integer");
                }
                Some(PythonNumber::Float(n)) if n.is_finite() => return json!(n),
                _ => {}
            }
            v.clone()
        }
        Value::Array(a) => Value::Array(a.iter().map(canonical_values).collect()),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, v)| (k.clone(), canonical_values(v)))
                .collect(),
        ),
        v => v.clone(),
    }
}

/// SHA3-512 over compact, UTF-8 Python JSON: {operation, params}. Only values
/// named by frozen bounds belong in constrained_params; do not hash all args.
pub fn action_hash(operation: &str, constrained_params: &Value) -> Result<String> {
    if !constrained_params.is_object() {
        return Err(Error::Invalid("constrained params must be an object"));
    }
    let bytes = format!(
        "{{\"operation\":{},\"params\":{}}}",
        serde_json::to_string(operation)?,
        compact_python_json(&canonical_values(constrained_params))?
    );
    Ok(format!("{:x}", Sha3_512::digest(bytes.as_bytes())))
}

fn compact_python_json(v: &Value) -> Result<String> {
    match v {
        Value::Array(a) => Ok(format!(
            "[{}]",
            a.iter()
                .map(compact_python_json)
                .collect::<Result<Vec<_>>>()?
                .join(",")
        )),
        Value::Object(m) => {
            let sorted: std::collections::BTreeMap<_, _> = m.iter().collect();
            Ok(format!(
                "{{{}}}",
                sorted
                    .into_iter()
                    .map(|(k, v)| Ok(format!(
                        "{}:{}",
                        serde_json::to_string(k)?,
                        compact_python_json(v)?
                    )))
                    .collect::<Result<Vec<_>>>()?
                    .join(",")
            ))
        }
        Value::String(s) => match parse_python_number(s) {
            Some(PythonNumber::Float(f)) if f.is_nan() => Ok("NaN".into()),
            Some(PythonNumber::Float(f)) if f.is_infinite() => Ok(if f.is_sign_negative() {
                "-Infinity"
            } else {
                "Infinity"
            }
            .into()),
            _ => Ok(serde_json::to_string(s)?),
        },
        v => super::identity::python_json(v),
    }
}

/// RFC 7638 thumbprint matching Auth51's P-256 ephemeral holder key.
pub fn jwk_thumbprint(jwk: &Value) -> Result<String> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::Sha256;
    if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
        return Err(Error::Invalid("P-256 public JWK required"));
    }
    let x = jwk["x"].as_str().ok_or(Error::Invalid("JWK x"))?;
    let y = jwk["y"].as_str().ok_or(Error::Invalid("JWK y"))?;
    for coord in [x, y] {
        if URL_SAFE_NO_PAD
            .decode(coord)
            .map_err(|_| Error::Invalid("JWK coordinate"))?
            .len()
            != 32
        {
            return Err(Error::Invalid("JWK coordinate length"));
        }
    }
    let core = json!({"crv":"P-256","kty":"EC","x":x,"y":y});
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(compact_python_json(&core)?.as_bytes())))
}

pub fn access_token_hash(token: &str) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::Sha256;
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

/// The Auth51 sequence algorithm hashes Python str/repr, not canonical JSON.
/// Accept already-rendered items so nested dict insertion order is preserved.
pub fn sequence_hash(sequence: &[String], current_python_repr: Option<&str>) -> String {
    use sha2::Sha256;
    let mut seq: Vec<&str> = sequence.iter().map(String::as_str).collect();
    if let Some(current) = current_python_repr.filter(|s| !s.is_empty()) {
        seq.push(current);
    }
    format!("{:x}", Sha256::digest(seq.join("|").as_bytes()))[..16].into()
}
