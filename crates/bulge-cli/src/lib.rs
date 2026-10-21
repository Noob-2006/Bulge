//! bulge-cli as a library.
//!
//! The CLI binary (`src/main.rs`) parses flags and calls into these modules; the
//! desktop app (`bulge-app`) reuses the exact same orchestration through
//! [`run::run_streaming`] so there is one code path for a job, not two.

pub mod acp;
pub mod backend;
pub mod cron;
pub mod eval;
pub mod run;
