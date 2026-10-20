//! bulge-core: the agent loop.

pub mod budget;
pub mod dispatch;
pub mod driver;
pub mod schedule;
pub mod vm_dispatch;

pub use budget::{BudgetState, BudgetTracker};
pub use dispatch::{ToolCall, ToolDispatcher, builtin_concurrency_safe, builtin_tools};
pub use driver::{Driver, LoopOutcome};
pub use vm_dispatch::VmDispatcher;
