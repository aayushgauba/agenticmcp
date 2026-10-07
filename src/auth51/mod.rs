//! Local Auth51 algorithms. No HTTP client, service connection or credentials.
mod algorithms;
mod crypto;
mod effects;
mod engine;
mod extraction;
mod identity;
mod policy;
mod source;
mod synthesis;
mod types;
mod valuebind;
mod workflow;
pub use algorithms::*;
pub use crypto::*;
pub use effects::*;
pub use engine::*;
pub use extraction::*;
pub use identity::*;
pub use policy::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
pub use source::*;
pub use synthesis::*;
pub use types::*;
pub use valuebind::*;
pub use workflow::*;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("authorization denied ({0}): {1}")]
    Policy(u16, String),
    #[error("invalid credential or proof")]
    Credential,
    #[error("invalid Auth51 input: {0}")]
    Invalid(&'static str),
    #[error("JSON encoding error")]
    Json(#[from] serde_json::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
