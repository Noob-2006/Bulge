//! ark-core: the interface layer. Provider-neutral types and the traits every
//! implementation (providers, tools, stores, gates) plugs into. Deliberately
//! dependency-light and stable: the kernel (`ark-kernel`) and the adapters
//! (`ark-model`, `ark-tools`) all build on this crate only.

pub mod cancel;
pub mod exec;
pub mod imageevict;
pub mod proc;
pub mod provider;
pub mod registry;
pub mod share;
pub mod team;
pub mod tmp;
pub mod tool;
pub mod types;

pub use cancel::Cancel;
pub use provider::{ModelCaps, Provider, ProviderError, ProviderErrorKind};
pub use tool::{expand_home, Effect, Tool, ToolCtx, ToolHost, ToolOutput, ToolSpec};
pub use types::*;
