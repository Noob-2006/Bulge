//! Egress filtering between the VMM and passt.

pub mod frame;
pub mod policy;
pub mod relay;

pub use frame::{Verdict, inspect_guest_frame};
pub use policy::{EgressPolicy, is_forbidden_destination};
pub use relay::{RelayHandle, RelayStats, spawn_relay};
