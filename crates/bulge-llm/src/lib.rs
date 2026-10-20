//! bulge-llm: pluggable model core.

pub mod assemble;
pub mod backend;
pub mod error;
pub mod http;
pub mod protocol;
pub mod repair;
pub mod retry;
pub mod sse;
pub mod types;

pub use backend::LlmBackend;
pub use error::{ErrorCode, LlmError};
pub use types::*;
