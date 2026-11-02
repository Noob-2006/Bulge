//! ark-kernel: the runtime. Event-sourced sessions, the step runner, context
//! assembly, budgets, the two gates, scheduling and the daemon protocol.

pub mod approver;
pub mod automation;
pub mod checkpoint;
pub mod commands;
pub mod coderun;
pub mod compaction;
pub mod config;
pub mod context;
pub mod cron;
pub mod daemon;
pub mod engine;
pub mod event;
pub mod gate;
pub mod hooks;
pub mod kernel;
pub mod ledger;
pub mod normalize;
pub mod projection;
pub mod shell;
pub mod store;
pub mod util;
pub mod vault;
