use super::*;
use serde_json::json;
use sha2::Sha256;
use sha3::{Digest, Sha3_512};
use unicode_normalization::UnicodeNormalization;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Components {
    pub agent_id: String,
    pub prompt_template: String,
    #[serde(default)]
    pub tools: Vec<Value>,
    #[serde(default = "empty_object")]
    pub configuration: Value,
}
fn empty_object() -> Value {
    json!({})
}

fn normalize_v1(s: &str) -> String {
    s.trim()
        .replace("\r\n", "\n")
        .split('\n')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}
fn normalize(s: &str) -> String {
    normalize_v1(s).nfc().collect()
}
fn canonical(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(normalize(s)),
        Value::Array(a) => Value::Array(a.iter().map(canonical).collect()),
        Value::Object(m) => {
            Value::Object(m.iter().map(|(k, v)| (k.clone(), canonical(v))).collect())
        }
        v => v.clone(),
    }
}

/// Python json.dumps(sort_keys=True, ensure_ascii=True), including spaces and
/// UTF-16 surrogate escapes and Python's floating-point exponent style.
pub(crate) fn python_json(v: &Value) -> Result<String> {
    match v {
        Value::String(s) => {
            let encoded = serde_json::to_string(s)?;
            let mut out = String::new();
            for c in encoded.chars() {
                if (c as u32) < 127 {
                    out.push(c);
                } else {
                    for u in c.encode_utf16(&mut [0; 2]).iter() {
                        out.push_str(&format!("\\u{u:04x}"));
                    }
                }
            }
            Ok(out)
        }
        Value::Array(a) => Ok(format!(
            "[{}]",
            a.iter()
                .map(python_json)
                .collect::<Result<Vec<_>>>()?
                .join(", ")
        )),
        Value::Object(m) => {
            let sorted: std::collections::BTreeMap<_, _> = m.iter().collect();
            Ok(format!(
                "{{{}}}",
                sorted
                    .into_iter()
                    .map(|(k, v)| Ok(format!(
                        "{}: {}",
                        python_json(&Value::String(k.clone()))?,
                        python_json(v)?
                    )))
                    .collect::<Result<Vec<_>>>()?
                    .join(", ")
            ))
        }
        Value::Number(n) if n.is_f64() => {
            let f = n
                .as_f64()
                .ok_or(Error::Invalid("finite JSON number required"))?;
            let s = if f != 0.0 && (f.abs() < 1e-4 || f.abs() >= 1e16) {
                let raw = format!("{f:e}");
                let (mantissa, exponent) = raw.split_once('e').expect("scientific float");
                let exp: i32 = exponent.parse().expect("float exponent");
                format!(
                    "{mantissa}e{}{:02}",
                    if exp < 0 { "-" } else { "+" },
                    exp.abs()
                )
            } else {
                let raw = f.to_string();
                if raw.contains('.') {
                    raw
                } else {
                    format!("{raw}.0")
                }
            };
            Ok(s)
        }
        v => Ok(v.to_string()),
    }
}

impl Components {
    fn legacy(&self) -> Result<Value> {
        let mut tools = Vec::new();
        for t in &self.tools {
            if t.get("is_agent").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            tools.push(
                json!({"name":t.get("name").ok_or(Error::Invalid("tool name"))?,
                "signature":t.get("signature").cloned().unwrap_or(json!("")),
                "description":t.get("description").cloned().unwrap_or(json!("")),
                "source_code":t.get("source_code").cloned().unwrap_or(Value::Null),
                "is_agent":false}),
            );
        }
        Ok(
            json!({"agent_id":self.agent_id, "prompt_template":self.prompt_template,
            "tools":tools, "configuration":self.configuration}),
        )
    }
    pub fn checksum_v1(&self) -> Result<String> {
        let legacy = self.legacy()?;
        let mut tools = Vec::new();
        for t in legacy["tools"].as_array().expect("legacy tools") {
            let mut tool = json!({"name":t["name"], "signature":t["signature"], "description":t["description"]});
            if t["source_code"].as_str().is_some_and(|s| !s.is_empty()) {
                tool["source_code"] = t["source_code"].clone();
            }
            tools.push(tool);
        }
        tools.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        let payload = json!({"id":self.agent_id, "prompt":normalize_v1(&self.prompt_template),
            "tools":tools, "config":self.configuration});
        Ok(format!(
            "{:x}",
            Sha256::digest(python_json(&payload)?.as_bytes())
        ))
    }
    pub fn checksum_v2(&self) -> Result<String> {
        Ok(format!(
            "sha3-512:v1:{:x}",
            Sha3_512::digest(python_json(&canonical(&self.legacy()?))?.as_bytes())
        ))
    }
    pub fn checksum_v3(&self) -> Result<String> {
        self.identity_checksum(false)
    }
    pub fn checksum_v4(&self) -> Result<String> {
        self.identity_checksum(true)
    }
    pub fn checksum_v5_with(
        &self,
        mut normalize_source: impl FnMut(&str) -> Result<String>,
    ) -> Result<String> {
        let mut core = self.identity_core(true)?;
        let tools = core["tools"].as_array_mut().expect("identity tools");
        let mut source_tools: Vec<_> = self
            .tools
            .iter()
            .filter(|t| t["source"] != "mcp" && t["is_agent"] != true)
            .collect();
        source_tools.sort_by_key(|t| t["name"].as_str().unwrap_or("").trim());
        for (entry, raw) in tools.iter_mut().zip(source_tools) {
            if let Some(src) = raw["source_code"].as_str().filter(|s| !s.is_empty()) {
                entry["source"] = Value::String(normalize_source(src)?);
            }
        }
        Ok(format!(
            "sha3-512:id3:{:x}",
            Sha3_512::digest(python_json(&canonical(&core))?.as_bytes())
        ))
    }
    /// Pure Rust normalization of Python tool source.
    pub fn checksum_v5(&self) -> Result<String> {
        self.checksum_v5_with(normalize_python_source)
    }
    fn identity_checksum(&self, include_tools: bool) -> Result<String> {
        let core = self.identity_core(include_tools)?;
        let bytes = python_json(&canonical(&core))?;
        Ok(format!(
            "sha3-512:{}:{:x}",
            if include_tools { "id2" } else { "id1" },
            Sha3_512::digest(bytes.as_bytes())
        ))
    }
    fn identity_core(&self, include_tools: bool) -> Result<Value> {
        if !self.configuration.is_object() {
            return Err(Error::Invalid("configuration must be an object"));
        }
        let mut core = json!({"agent_id":self.agent_id, "prompt_template":self.prompt_template,
            "configuration":self.configuration});
        if include_tools {
            let mut tools = Vec::new();
            for t in &self.tools {
                if t.get("source").and_then(Value::as_str) == Some("mcp")
                    || t.get("is_agent").and_then(Value::as_bool) == Some(true)
                {
                    continue;
                }
                let name = t
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or(Error::Invalid("tool name"))?;
                let description = t.get("description").and_then(Value::as_str).unwrap_or("");
                let parameters = t
                    .get("parameters")
                    .filter(|v| !v.is_null())
                    .or_else(|| t.get("signature").filter(|v| !v.is_null()))
                    .cloned()
                    .unwrap_or(json!({}));
                tools.push(json!({"name":name.trim(), "description":normalize(description), "parameters":parameters}));
            }
            tools.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
            core["tools"] = Value::Array(tools);
        }
        Ok(core)
    }
}

/// Same endpoint identity as auth51-scopes. The path is a route template.
pub fn derive_scope(rs: &str, method: &str, path: &str) -> Result<String> {
    if rs.is_empty() || rs.contains(':') {
        return Err(Error::Invalid("resource id"));
    }
    let method = method.trim().to_lowercase();
    if !["get", "post", "put", "patch", "delete", "head", "options"].contains(&method.as_str()) {
        return Err(Error::Invalid("HTTP method"));
    }
    let colon = regex::Regex::new(r"/:([A-Za-z_][A-Za-z0-9_]*)").expect("static regex");
    let angle = regex::Regex::new(r"<[^>]*?([A-Za-z_][A-Za-z0-9_]*)>").expect("static regex");
    let p = colon.replace_all(path.trim(), "/{$1}");
    let p = angle.replace_all(&p, "{$1}");
    let p = format!("/{}", p.trim_matches('/'));
    let p = regex::Regex::new(r"/{2,}")
        .expect("static regex")
        .replace_all(&p, "/");
    let mut encoded = String::new();
    for b in p.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/{}".contains(&b) {
            encoded.push(b as char);
        } else {
            encoded.push_str(&format!("%{b:02X}"));
        }
    }
    Ok(format!("a51:rs:{rs}:{method}:{encoded}"))
}
