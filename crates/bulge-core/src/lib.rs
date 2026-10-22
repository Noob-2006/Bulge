//! bulge-core: the agent loop.

pub mod budget;
pub mod complete;
pub mod context;
pub mod cron;
pub mod dispatch;
pub mod cache_watch;
pub mod driver;
pub mod hooks;
pub mod mcp;
pub mod schedule;
pub mod vm_dispatch;

pub use budget::{BudgetState, BudgetTracker};
pub use cron::{Schedule, ScheduledJob, ScheduleStore, Weekday, next_occurrence};
pub use dispatch::{PLAN_TOOL, ToolCall, ToolDispatcher, builtin_concurrency_safe, builtin_tools, plan_tool};
pub use driver::{Driver, LoopOutcome};
pub use hooks::{HookConfig, HookEvent, HookRunner, HookedDispatcher};
pub use vm_dispatch::VmDispatcher;
