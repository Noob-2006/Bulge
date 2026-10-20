//! Typed messages carried inside authenticated frames after the handshake.
//!
//! The host invokes named guest commands; the guest answers each invocation
//! exactly once. Payloads are JSON values so command schemas can evolve
//! without changing the framing.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// vsock port the guest daemon listens on for the control channel.
pub const CONTROL_VSOCK_PORT: u32 = 1024;

/// Path (inside the guest) of the one-shot virtual file that carries the
/// session bootstrap. The guest reads it once at startup; it can never be read
/// again and never appears on argv or in the environment.
pub const BOOTSTRAP_PATH: &str = "/.bulge-bootstrap";

/// Secret bootstrap material delivered through [`BOOTSTRAP_PATH`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bootstrap {
    /// Hex-encoded 32-byte session key.
    pub session_key_hex: String,
    pub session_id: String,
    pub generation: u64,
    /// Host uid/gid that owns the shared workspace. The guest drops its own
    /// privileges to this id (or to `nobody` when the host runs as root) so the
    /// sandbox never executes anything with CAP_SYS_ADMIN. Older hosts that did
    /// not send these default to 0, which the guest maps to `nobody`.
    #[serde(default)]
    pub host_uid: u32,
    #[serde(default)]
    pub host_gid: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostMessage {
    Invoke {
        id: u64,
        command: String,
        #[serde(default)]
        params: Value,
        /// Requested handler timeout; the guest clamps it to its own maximum.
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    Cancel {
        id: u64,
    },
    /// Orderly shutdown: cancel everything, sync, power off.
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GuestMessage {
    /// Sent once after the handshake; lists the commands the guest serves.
    Ready {
        commands: Vec<String>,
    },
    Result {
        id: u64,
        outcome: Outcome,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome {
    Ok { value: Value },
    Err { code: String, message: String },
}
