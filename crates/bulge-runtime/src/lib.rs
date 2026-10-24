//! The bulge runtime: a job end to end — launch the sandbox VM, assemble the
//! agents ([`recipe`]), drive the loop with delegation to sub-agents
//! ([`delegate`]), stream the log, collect and write back changes
//! ([`writeback`]), and learn afterwards. Every front end (the CLI, the
//! desktop app, chat channels, schedules, ACP) runs jobs through
//! [`run::run_streaming`] or a [`run::Session`], so there is one code path
//! for a job, not one per front end.

pub mod backend;
pub mod cron;
pub mod delegate;
pub mod recall;
pub mod recipe;
pub mod run;
pub mod skills;
pub mod writeback;
