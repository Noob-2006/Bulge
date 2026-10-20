//! sandboxd: the bulge guest daemon.

pub mod bridge;
pub mod commands;
pub mod runtime;
pub mod setup;
pub mod tools;

/// The egress proxy URL to export to executed commands, set once the egress
/// bridge is running. `None`/unset means the guest has no outbound access.
pub static EGRESS_PROXY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
