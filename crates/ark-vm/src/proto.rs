//! Wire protocol of the single guest↔host channel (B3).
//!
//! One connection, length-prefixed JSON frames (`u32` big endian + UTF-8 JSON),
//! binary payloads base64. Exactly two kinds of traffic travel over it:
//!
//! 1. tool execution (the host pushes a script, the guest streams output back) —
//!    nothing in the VM ever touches the host file system or a host socket;
//! 2. requests that need the daemon (privileged commands, egress) — the guest
//!    can only *ask*; the allow-list, the keys and the decision stay on the host
//!    (A2/A3/A4). See `docs`/`AB-interface.md` for the broker payloads.
//!
//! The same types are compiled into the host and into the guest agent
//! (`ark-vm-guest`), so a protocol change breaks both sides at once.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Bumped whenever a frame's shape changes; the agent and the host refuse to
/// talk across a mismatch instead of mis-parsing.
pub const VERSION: u32 = 1;

/// vsock port the guest agent listens on (Firecracker: the host connects to the
/// Firecracker unix socket and writes `CONNECT 5000\n`).
pub const VSOCK_PORT: u32 = 5000;
/// virtio-serial port the guest agent uses under QEMU (`/dev/vport0p1`).
pub const SERIAL_DEVICE: &str = "/dev/vport0p1";
/// Where the guest agent lets in-VM programs ask the daemon for things
/// (privileged command, egress). Inside the VM only; never a host socket.
pub const BROKER_SOCKET: &str = "/run/ark/broker.sock";

/// Non-privileged account the agent drops to. Nothing in the guest runs as root
/// after init, so a compromised tool cannot even reconfigure the VM.
pub const AGENT_USER: &str = "agent";
pub const AGENT_UID: u32 = 1000;
pub const AGENT_HOME: &str = "/home/agent";
/// Where the workspace is mounted inside the guest.
pub const GUEST_WORKSPACE: &str = "/workspace";

/// Maximum frame size; a larger frame is a protocol error (a guest cannot make
/// the host allocate without bound).
pub const MAX_FRAME: usize = 32 * 1024 * 1024;

/// host → guest
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum HostMsg {
    /// Start `script` with `bash -c` as the agent user.
    Exec {
        id: u64,
        script: String,
        #[serde(default)]
        cwd: Option<String>,
        #[serde(default)]
        env: Vec<(String, String)>,
        #[serde(default)]
        login: bool,
        /// Keep stdin open (the host will send `Stdin`/`Eof`).
        #[serde(default)]
        stdin: bool,
        /// (rows, cols) — allocate a pty of that size.
        #[serde(default)]
        pty: Option<(u16, u16)>,
        /// Guest-side wall clock limit in seconds (0 = none).
        #[serde(default)]
        timeout_secs: u64,
    },
    /// base64 bytes for the running command's stdin.
    Stdin { id: u64, data: String },
    Eof { id: u64 },
    /// SIGTERM, then SIGKILL when `force`.
    Signal { id: u64, force: bool },
    Resize { id: u64, rows: u16, cols: u16 },
    /// Answer to a `GuestMsg::Broker` request.
    BrokerReply { id: u64, ok: bool, payload: Value },
    /// Read files (relative to the guest workspace) back to the host.
    Pull { id: u64, paths: Vec<String> },
    /// Write files (relative to the guest workspace) into the VM.
    Push { id: u64, files: Vec<FileBlob> },
    /// Resource limits applied to every later command.
    Limits { #[serde(default)] nproc: Option<u64>, #[serde(default)] nofile: Option<u64>, #[serde(default)] cpu_seconds: Option<u64> },
    Ping { id: u64 },
    /// Guest agent exits (VM shutdown).
    Shutdown,
}

/// guest → host
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum GuestMsg {
    /// First frame after connect. `uid` proves the agent dropped privileges.
    Hello { version: u32, agent: String, kernel: String, #[serde(default)] cid: Option<u32>, transport: String, uid: u32 },
    /// base64 output chunk (stdout+stderr merged, or the pty).
    Out { id: u64, data: String },
    Exit { id: u64, #[serde(default)] code: Option<i32>, #[serde(default)] signal: Option<i32> },
    /// The VM asks the daemon for something. `kind` is one of `priv.exec`,
    /// `egress.http`, `secret.sign`; the host decides (never the guest).
    Broker { id: u64, kind: String, payload: Value },
    /// `Pull` answer.
    Files { id: u64, files: Vec<FileBlob> },
    /// Generic ack (`Push`, `Limits`).
    Ok { id: u64, #[serde(default)] detail: Value },
    Err { id: u64, message: String },
    Pong { id: u64 },
}

/// One file crossing the channel. `path` is relative to the guest workspace and
/// must not escape it (`..`, absolute, symlink) — both sides check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileBlob {
    pub path: String,
    pub data: String,
    /// Unix mode (0o644 when the guest does not care).
    #[serde(default = "default_mode")]
    pub mode: u32,
}

fn default_mode() -> u32 {
    0o644
}

/// Reject a workspace-relative path that would escape the workspace.
pub fn check_rel_path(p: &str) -> Result<(), String> {
    if p.is_empty() || p.starts_with('/') || p.split('/').any(|c| c == ".." || c.is_empty() || c == ".") {
        return Err(format!("path `{p}` must be a plain relative path inside the workspace"));
    }
    Ok(())
}

impl HostMsg {
    pub fn id(&self) -> Option<u64> {
        Some(match self {
            HostMsg::Exec { id, .. }
            | HostMsg::Stdin { id, .. }
            | HostMsg::Eof { id }
            | HostMsg::Signal { id, .. }
            | HostMsg::Resize { id, .. }
            | HostMsg::BrokerReply { id, .. }
            | HostMsg::Pull { id, .. }
            | HostMsg::Push { id, .. }
            | HostMsg::Ping { id } => *id,
            HostMsg::Limits { .. } | HostMsg::Shutdown => return None,
        })
    }
}

impl GuestMsg {
    pub fn id(&self) -> Option<u64> {
        Some(match self {
            GuestMsg::Hello { .. } => return None,
            GuestMsg::Out { id, .. }
            | GuestMsg::Exit { id, .. }
            | GuestMsg::Broker { id, .. }
            | GuestMsg::Files { id, .. }
            | GuestMsg::Ok { id, .. }
            | GuestMsg::Err { id, .. }
            | GuestMsg::Pong { id } => *id,
        })
    }
}

// ── framing ─────────────────────────────────────────────────────────────────

pub fn encode<T: Serialize>(m: &T) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(m).map_err(|e| format!("encode frame: {e}"))?;
    if body.len() > MAX_FRAME {
        return Err(format!("frame too large ({} bytes, max {MAX_FRAME})", body.len()));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Split `buf` into complete frames; returns (frames, consumed bytes).
pub fn decode<T: for<'de> Deserialize<'de>>(buf: &[u8]) -> Result<(Vec<T>, usize), String> {
    let mut out = Vec::new();
    let mut off = 0;
    while buf.len() >= off + 4 {
        let len = u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as usize;
        if len > MAX_FRAME {
            return Err(format!("frame too large ({len} bytes, max {MAX_FRAME})"));
        }
        if buf.len() < off + 4 + len {
            break;
        }
        let m = serde_json::from_slice(&buf[off + 4..off + 4 + len]).map_err(|e| format!("decode frame: {e}"))?;
        out.push(m);
        off += 4 + len;
    }
    Ok((out, off))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_split() {
        let a = HostMsg::Exec { id: 7, script: "echo hi".into(), cwd: None, env: vec![], login: false, stdin: false, pty: None, timeout_secs: 0 };
        let b = HostMsg::Ping { id: 8 };
        let mut buf = encode(&a).unwrap();
        buf.extend(encode(&b).unwrap());
        // A partial tail is not a frame yet.
        let (partial, used) = decode::<HostMsg>(&buf[..buf.len() - 1]).unwrap();
        assert_eq!(partial.len(), 1);
        assert!(used > 0);
        let (all, used) = decode::<HostMsg>(&buf).unwrap();
        assert_eq!(all, vec![a, b]);
        assert_eq!(used, buf.len());
    }

    #[test]
    fn oversized_and_malformed_frames_are_refused() {
        let mut big = (MAX_FRAME as u32 + 1).to_be_bytes().to_vec();
        big.extend_from_slice(b"{}");
        assert!(decode::<HostMsg>(&big).unwrap_err().contains("too large"));
        let mut bad = 2u32.to_be_bytes().to_vec();
        bad.extend_from_slice(b"[[");
        assert!(decode::<HostMsg>(&bad).is_err());
        let huge = HostMsg::Exec { id: 1, script: "x".repeat(MAX_FRAME + 16), cwd: None, env: vec![], login: false, stdin: false, pty: None, timeout_secs: 0 };
        assert!(encode(&huge).unwrap_err().contains("too large"));
    }

    #[test]
    fn workspace_paths_cannot_escape() {
        assert!(check_rel_path("src/main.rs").is_ok());
        for bad in ["/etc/passwd", "../x", "a/../../b", "", "./a"] {
            assert!(check_rel_path(bad).is_err(), "{bad}");
        }
    }
}
