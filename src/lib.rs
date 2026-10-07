//! Experimental Agentic JWT: configuration identity, signed intent, and trusted workflows.
//!
//! This experimental profile has not been independently reviewed for production use.
//! Administrative methods on [`Authority`] are trusted, in-process operations, not
//! unauthenticated network endpoints. No LLM or network service is required by the demo.

pub mod auth51;
mod authority;
mod crypto;
mod identity;
pub mod mcp;
mod protocol;

pub use authority::{Authority, Permit};
pub use crypto::{KeyPair, PublicKey};
pub use identity::{AgentSpec, Tool};
pub use protocol::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid input: {0}")]
    Invalid(&'static str),
    #[error("invalid signature or signing key")]
    Signature,
    #[error("unknown or revoked identity")]
    Identity,
    #[error("agent_checksum_mismatch")]
    Checksum,
    #[error("unsupported_grant_type")]
    GrantType,
    #[error("requested authority exceeds registered policy")]
    Policy,
    #[error("workflow state or delegation does not match")]
    Workflow,
    #[error("approval required")]
    Approval,
    #[error("expired or future-dated credential")]
    Time,
    #[error("replayed proof")]
    Replay,
    #[error("request does not match authorized action")]
    Action,
    #[error("JSON encoding error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
