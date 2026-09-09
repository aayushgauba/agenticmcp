use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

use crate::{Error, Result, crypto};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub name: String,
    pub description: String,
    /// An explicit, framework-independent JSON schema, not reflected Rust source.
    pub parameters: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSpec {
    pub agent_id: String,
    pub prompt_template: String,
    pub tools: Vec<Tool>,
    pub configuration: Value,
}

impl AgentSpec {
    /// JCS / SHA-256 profile of draft §5.3.1. Prompts are preserved byte-for-byte.
    /// Tool names are unique and tools are sorted by name before serialization.
    pub fn checksum(&self) -> Result<String> {
        identifier(&self.agent_id)?;
        if self.prompt_template.is_empty() || !self.configuration.is_object() {
            return Err(Error::Invalid("prompt and configuration"));
        }
        let mut spec = self.clone();
        let mut names = HashSet::new();
        for tool in &spec.tools {
            identifier(&tool.name)?;
            if !tool.parameters.is_object() || !names.insert(&tool.name) {
                return Err(Error::Invalid("tool schema or duplicate name"));
            }
        }
        spec.tools.sort_by(|a, b| a.name.cmp(&b.name));
        let bytes = crypto::canonical(&spec)?;
        if bytes.len() > 262_144 {
            return Err(Error::Invalid("agent specification too large"));
        }
        Ok(format!("sha256:{}", crypto::hash(&bytes)))
    }
}

pub(crate) fn identifier(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Error::Invalid("identifier"));
    }
    Ok(())
}
