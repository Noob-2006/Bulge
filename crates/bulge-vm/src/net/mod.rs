//! Egress filtering between the VMM and passt, and the two-key egress gateway.

pub mod frame;
pub mod gateway;
pub mod policy;
pub mod relay;

pub use frame::{Verdict, inspect_guest_frame};
pub use gateway::{GATEWAY_VSOCK_PORT, GatewayConfig, GatewayStats};
pub use policy::{EgressPolicy, is_forbidden_destination};
pub use relay::{RelayHandle, RelayStats, spawn_relay};
