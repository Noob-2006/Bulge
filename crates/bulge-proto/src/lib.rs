//! bulge-proto: authenticated, sequenced framing between the bulge host app
//! and the guest daemon (`sandboxd`), carried over vsock.
//!
//! The host creates a fresh 32-byte session key, session id, and nonzero
//! generation per VM boot and delivers them to the guest out of band (never on
//! argv/env). Everything after that handoff is this crate.

pub mod frame;
pub mod handshake;
pub mod msg;
pub mod session;
