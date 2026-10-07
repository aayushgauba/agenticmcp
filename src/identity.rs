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
    /// Auth51 runtime identity: v3 without tools, v4 with process tools.
    /// Cosmetic prompt whitespace and NFC-equivalent strings hash identically.
    pub fn checksum(&self) -> Result<String> {
        identifier(&self.agent_id)?;
        if self.prompt_template.is_empty() || !self.configuration.is_object() {
            return Err(Error::Invalid("prompt and configuration"));
        }
        let mut names = HashSet::new();
        for tool in &self.tools {
            identifier(&tool.name)?;
            if !tool.parameters.is_object() || !names.insert(&tool.name) {
                return Err(Error::Invalid("tool schema or duplicate name"));
            }
        }
        if serde_json::to_vec(self)?.len() > 262_144 {
            return Err(Error::Invalid("agent specification too large"));
        }
        let components = crate::auth51::Components {
            agent_id: self.agent_id.clone(),
            prompt_template: self.prompt_template.clone(),
            tools: self
                .tools
                .iter()
                .map(serde_json::to_value)
                .collect::<std::result::Result<_, _>>()?,
            configuration: self.configuration.clone(),
        };
        let result = if self.tools.is_empty() {
            components.checksum_v3()
        } else {
            components.checksum_v4()
        };
        result.map_err(|_| Error::Invalid("Auth51 identity components"))
    }

    /// Original JCS / SHA-256 checksum for explicit migrations.
    pub fn checksum_legacy_jcs(&self) -> Result<String> {
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
