use crate::{Error, KeyPair, PublicKey, Result, crypto};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:agent_checksum";
pub(crate) const TOKEN_TYPE: &str = "ajwt-intent+jwt";
pub(crate) const PROOF_TYPE: &str = "ajwt-pop+jwt";
pub(crate) const TOKEN_LIFETIME: u64 = 300;
pub(crate) const PROOF_LIFETIME: u64 = 60;

/// Immutable approved operation. Body hashes cover exact bytes, not parsed JSON.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub method: String,
    pub uri: String,
    pub body_sha256: String,
    pub scope: String,
}

impl Action {
    pub fn new(method: &str, uri: &str, body: &[u8], scope: &str) -> Result<Self> {
        let action = Self {
            method: method.into(),
            uri: uri.into(),
            body_sha256: crypto::hash(body),
            scope: scope.into(),
        };
        action.validate()?;
        Ok(action)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let url = url::Url::parse(&self.uri).map_err(|_| Error::Invalid("URI"))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.as_str() != self.uri
        {
            return Err(Error::Invalid("canonical HTTPS URI required"));
        }
        if !matches!(
            self.method.as_str(),
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
        ) || self.scope.is_empty()
            || self.scope.len() > 128
            || !self
                .scope
                .bytes()
                .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
            || self.body_sha256.len() != 64
            || !self
                .body_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Invalid("action"));
        }
        Ok(())
    }
}

/// Administrative policy for a single agent registration.
#[derive(Clone, Debug)]
pub struct AgentPolicy {
    pub scopes: BTreeSet<String>,
    /// Exact URI origins such as `https://api.example.com`.
    pub audiences: BTreeSet<String>,
}

#[derive(Clone, Debug)]
pub struct Step {
    pub id: String,
    pub agent_id: String,
    pub audience: String,
    pub action: Action,
    pub requires_approval: bool,
}

/// A trusted, ordered plan. Adjacent steps explicitly authorize delegation.
#[derive(Clone, Debug)]
pub struct Workflow {
    pub id: String,
    pub steps: Vec<Step>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationContext {
    /// Includes the current agent exactly once at the tail of the path.
    pub chain: Vec<String>,
    pub completed_steps: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRequest {
    pub grant_type: String,
    pub agent_id: String,
    pub computed_checksum: String,
    pub workflow_id: String,
    pub workflow_step: String,
    pub workflow_enabled: bool,
    pub requested_scopes: Vec<String>,
    pub audience: String,
    pub delegation_context: DelegationContext,
    /// Profile extension: isolate concurrent executions of the same workflow.
    pub run_id: String,
}

/// Both the registered client and executing agent sign the entire grant request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedGrant {
    pub client_id: String,
    pub issuer: String,
    pub iat: u64,
    pub jti: String,
    pub request: TokenRequest,
    pub client_signature: String,
    pub agent_signature: String,
}

impl SignedGrant {
    pub fn sign(
        client_id: &str,
        issuer: &str,
        request: TokenRequest,
        client: &KeyPair,
        agent: &KeyPair,
        now: u64,
    ) -> Result<Self> {
        let mut grant = Self {
            client_id: client_id.into(),
            issuer: issuer.into(),
            iat: now,
            jti: crypto::id(),
            request,
            client_signature: String::new(),
            agent_signature: String::new(),
        };
        grant.client_signature = client.sign(&grant.signing_input("client")?);
        grant.agent_signature = agent.sign(&grant.signing_input("agent")?);
        Ok(grant)
    }

    pub(crate) fn signing_input(&self, role: &str) -> Result<Vec<u8>> {
        // Role and protocol labels prevent cross-protocol / cross-role signature reuse.
        crypto::canonical(&(
            "agentic-jwt-grant-v1",
            role,
            &self.client_id,
            &self.issuer,
            self.iat,
            &self.jti,
            &self.request,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub workflow_id: String,
    pub workflow_step: String,
    pub executed_by: String,
    pub delegation_chain: String,
    pub step_sequence_hash: String,
    pub run_id: String,
    pub resource_owner: String,
    pub action: Action,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProof {
    pub agent_checksum: String,
    pub registration_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confirmation {
    pub jwk: PublicKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub exp: u64,
    pub iat: u64,
    pub jti: String,
    pub scope: String,
    pub cnf: Confirmation,
    pub intent: Intent,
    pub agent_proof: AgentProof,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestProof {
    pub iat: u64,
    pub jti: String,
    pub token_sha256: String,
    pub action: Action,
}

/// Profile-specific request proof. This is deliberately not labeled RFC 9449 DPoP.
pub fn prove_request(
    token: &str,
    action: &Action,
    agent_id: &str,
    key: &KeyPair,
    now: u64,
) -> Result<String> {
    action.validate()?;
    let proof = RequestProof {
        iat: now,
        jti: crypto::id(),
        token_sha256: crypto::hash(token.as_bytes()),
        action: action.clone(),
    };
    crypto::encode(&proof, key, PROOF_TYPE, agent_id)
}

pub(crate) fn fresh(iat: u64, now: u64) -> Result<()> {
    if iat > now || now - iat >= PROOF_LIFETIME {
        return Err(Error::Time);
    }
    Ok(())
}

pub(crate) fn sequence_hash(sequence: &[String]) -> String {
    // IDs cannot contain '|', so the draft's delimiter is unambiguous in this profile.
    crypto::hash(sequence.join("|").as_bytes())[..16].into()
}
