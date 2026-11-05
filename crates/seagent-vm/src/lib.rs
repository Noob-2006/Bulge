//! seagent-vm: the microVM execution environment (GAPS B1–B7, plus the H items that
//! live in B).
//!
//! Layers, bottom-up:
//! * [`isolation`] — what wall each backend gives you, and the warning when it is
//!   weaker than a microVM. Nothing here silently downgrades.
//! * [`provider`] — boot one VM (Firecracker / QEMU-KVM) and hand back a
//!   [`channel::Channel`].
//! * [`proto`] / [`channel`] — the single guest channel: tool I/O, plus *requests*
//!   from the guest to the daemon (privileged commands, egress); the guest never
//!   gets a host socket or a key.
//! * [`pool`] — VM lifecycle per session and per trust tier, snapshots/undo,
//!   idle reaping, resource ceilings ([`limits`]).
//! * [`image`] — guest image manifest (kernel + initramfs, sha256, version).
//!
//! The `seagent-tools` `vm` exec backend is the thin adapter from this crate to the
//! `ExecBackend` trait; it deliberately contains no VM logic.

pub mod cgroup;
pub mod channel;
pub mod config;
pub mod desktop;
pub mod hostcaps;
pub mod image;
pub mod isolation;
pub mod limits;
pub mod policy;
pub mod pool;
pub mod proto;
pub mod provider;
pub mod secrets;
pub mod snapshot;
pub mod trust;
pub mod unify;

pub use config::VmConfig;
pub use isolation::{Capabilities, IsolationLevel, ProviderKind};
pub use pool::{Broker, BrokerFrom, VmManager};

/// Version of the guest image layout this crate understands; the manifest and
/// the agent's `Hello` must agree (a mismatch rebuilds the image instead of
/// booting a guest that speaks an old protocol).
pub const IMAGE_VERSION: u32 = 1;

/// Wire name of the exec backend (`exec.backend = "vm"`).
pub const BACKEND_NAME: &str = "vm";
