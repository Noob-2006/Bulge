//! bulge-core: the agent loop.

pub mod budget;
pub mod complete;
pub mod context;
pub mod cron;
pub mod dispatch;
pub mod cache_watch;
pub mod driver;
pub mod hooks;
pub mod ledger;
pub mod mcp;
pub mod schedule;
pub mod vm_dispatch;

pub use budget::{BudgetState, BudgetTracker};
pub use cron::{Schedule, Weekday, next_occurrence};
pub use dispatch::{
    BROWSER_TOOL, ORG_STATUS_TOOL, PLAN_TOOL, PROPOSE_ROLE_TOOL, ToolCall, ToolDispatcher, VIEW_IMAGE_TOOL, view_image_tool,
    browser_tool, builtin_concurrency_safe, builtin_tools, org_status_tool, plan_tool, propose_role_tool,
};
pub use driver::{DelegateRequest, Driver, HostTool, LoopOutcome, ProposeRoleHandler};
pub use hooks::{HookConfig, HookEvent, HookRunner, HookedDispatcher};
pub use vm_dispatch::VmDispatcher;
