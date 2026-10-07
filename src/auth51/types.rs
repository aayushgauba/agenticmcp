use super::*;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Observe,
    #[default]
    Enforce,
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Control {
    #[default]
    Strict,
    Guarded,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    pub allowed_scopes: Vec<String>,
    #[serde(default)]
    pub step_up_scopes: Vec<String>,
    pub mode: Mode,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub agent: String,
    pub action: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub approval_gate: bool,
    #[serde(default)]
    pub requires_approval: bool,
    #[serde(default)]
    pub tier: Option<String>,
    #[serde(default)]
    pub value_bound: bool,
    #[serde(default)]
    pub value_bounds: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Dag {
    pub workflow_id: String,
    #[serde(default = "dag_type")]
    pub workflow_type: String,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub control: Control,
    pub steps: BTreeMap<String, WorkflowStep>,
}
fn dag_type() -> String {
    "dag".into()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Delegation {
    #[serde(default)]
    pub chain: Vec<Value>,
    #[serde(default)]
    pub completed_steps: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MintRequest {
    pub grant_type: String,
    pub agent_id: String,
    pub computed_checksum: String,
    pub requested_scopes: Vec<String>,
    pub audience: String,
    #[serde(default)]
    pub execution_id: Option<String>,
    /// Accepted for compatibility; never used to select or disable governance.
    #[serde(default)]
    pub workflow_id: Option<String>,
    #[serde(default = "enabled")]
    pub workflow_enabled: bool,
    #[serde(default)]
    pub workflow_step: Option<Value>,
    #[serde(default)]
    pub action_args: Option<Value>,
    #[serde(default)]
    pub delegation_context: Option<Delegation>,
    #[serde(default)]
    pub cnf_jkt: Option<String>,
}
fn enabled() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Execution {
    pub execution_id: String,
    pub app_id: String,
    pub workflow_id: Option<String>,
    pub candidate_workflow_ids: Vec<String>,
    pub mode: Mode,
}

#[derive(Clone, Debug)]
pub struct RegisteredAgent {
    pub agent_id: String,
    pub registration_id: String,
    pub checksums: Vec<String>,
    pub subagents: Vec<String>,
    pub public_jwk: Option<Value>,
    pub grant: Option<Grant>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkflowResolution {
    pub governed: bool,
    pub mode: Mode,
    pub workflow_id: Option<String>,
    pub step_name: Option<String>,
    pub authorised: bool,
    pub value_bound: bool,
    pub value_bounds: Vec<Value>,
    pub tier: String,
    pub action: String,
}
impl Default for WorkflowResolution {
    fn default() -> Self {
        Self {
            governed: false,
            mode: Mode::Observe,
            workflow_id: None,
            step_name: None,
            authorised: true,
            value_bound: false,
            value_bounds: vec![],
            tier: String::new(),
            action: String::new(),
        }
    }
}

/// No Debug: token strings are credentials.
#[derive(Serialize, Deserialize)]
pub struct IntentToken {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrozenBound {
    pub target: String,
    pub op: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_provenance: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValueBinding {
    pub action_hash: String,
    pub bounds: Vec<FrozenBound>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tier: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<Value>,
}
