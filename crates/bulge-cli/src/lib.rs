//! bulge-cli as a library: the front ends (chat channels, schedules, ACP,
//! eval, remote pairing) over [`bulge_runtime`], whose modules are
//! re-exported here under their old paths.

pub mod acp;
pub mod channels;
pub mod remote;
pub mod eval;

pub use bulge_runtime::{backend, cron, delegate, recall, recipe, run, skills, writeback};
