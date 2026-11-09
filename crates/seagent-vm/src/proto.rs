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
//! (`seagent-vm-guest`), so a protocol change breaks both sides at once.

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
/// Second 16550 UART, the channel under VirtualBox and Hyper-V (`seagent.channel=uart`):
/// neither offers virtio-serial or a host-reachable vsock, both serve a COM port to the host
/// as a socket / named pipe. `ttyS0` stays the boot console.
pub const UART_DEVICE: &str = "/dev/ttyS1";
/// The same second UART on arm64 VirtualBox / Hyper-V, which emulate PL011s (`ttyAMA*`)
/// instead of 16550s. The aarch64 guest agent opens it when it exists and falls back to
/// [`UART_DEVICE`] (a 16550 on an arm64 machine model); x86_64 only ever uses [`UART_DEVICE`].
pub const UART_DEVICE_PL011: &str = "/dev/ttyAMA1";
/// Where the guest agent lets in-VM programs ask the daemon for things
/// (privileged command, egress). Inside the VM only; never a host socket.
pub const BROKER_SOCKET: &str = "/run/seagent/broker.sock";

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
    /// Channel authentication (only where the host issued a per-boot key, i.e. a TCP channel
    /// other local processes could reach): the host proves it knows the key —
    /// `mac` = [`auth_mac`]`(key, "host", hello nonce, nonce)` — and challenges the guest with
    /// its own `nonce`. The guest answers [`GuestMsg::Auth`] and refuses every other frame
    /// until this one verified.
    Auth { nonce: String, mac: String },
}

/// guest → host
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum GuestMsg {
    /// First frame after connect. `uid` proves the agent dropped privileges.
    Hello {
        version: u32,
        agent: String,
        kernel: String,
        #[serde(default)]
        cid: Option<u32>,
        transport: String,
        uid: u32,
        /// Present iff the guest was given a channel key (fw_cfg `opt/seagent/key`): the
        /// challenge for [`HostMsg::Auth`]. Absent on Linux / vsock / unix socket channels,
        /// whose frames are byte-for-byte what they always were.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nonce: Option<String>,
    },
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
    /// The guest's half of the channel authentication: `mac` = [`auth_mac`]`(key, "guest",
    /// host nonce, hello nonce)`.
    Auth { mac: String },
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
            HostMsg::Limits { .. } | HostMsg::Shutdown | HostMsg::Auth { .. } => return None,
        })
    }
}

impl GuestMsg {
    pub fn id(&self) -> Option<u64> {
        Some(match self {
            GuestMsg::Hello { .. } | GuestMsg::Auth { .. } => return None,
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

// ── channel authentication ──────────────────────────────────────────────────

/// Where QEMU hands the guest its per-boot channel key (`-fw_cfg name=opt/seagent/key,file=…`);
/// the agent reads it as root before dropping privileges (mode 0400), so no command in the
/// guest ever sees it, and it never appears on a command line on the host.
pub const FW_CFG_KEY: &str = "/sys/firmware/qemu_fw_cfg/by_name/opt/seagent/key/raw";
/// The fw_cfg item name for [`FW_CFG_KEY`].
pub const FW_CFG_KEY_NAME: &str = "opt/seagent/key";

/// HMAC-SHA256 (hex) proving knowledge of `key` for `role` (`host` / `guest`) over the
/// peer's challenge and the sender's own nonce. Distinct roles make a reflected answer
/// useless; fresh nonces on both sides make a replayed one useless.
pub fn auth_mac(key: &[u8], role: &str, challenge: &str, nonce: &str) -> String {
    let msg = format!("seagent-vm-channel-v1\0{role}\0{challenge}\0{nonce}");
    seagent_net::crypto::hmac_sha256(key, msg.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// Constant-time check of an [`auth_mac`] answer.
pub fn auth_ok(key: &[u8], role: &str, challenge: &str, nonce: &str, mac: &str) -> bool {
    let want = auth_mac(key, role, challenge, nonce);
    want.len() == mac.len() && want.bytes().zip(mac.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// The guest's side of [`HostMsg::Auth`]: the [`GuestMsg::Auth`] answer when the host's
/// proof over our Hello `challenge` checks, else why the frame is refused.
pub fn guest_auth_answer(key: &[u8], challenge: &str, host_nonce: &str, host_mac: &str) -> Result<GuestMsg, String> {
    if !auth_ok(key, "host", challenge, host_nonce, host_mac) {
        return Err("channel authentication failed: the peer does not hold this VM's key".into());
    }
    Ok(GuestMsg::Auth { mac: auth_mac(key, "guest", host_nonce, challenge) })
}

/// A fresh random nonce / key (hex).
pub fn random_hex(bytes: usize) -> String {
    seagent_net::crypto::random_bytes(bytes).iter().map(|b| format!("{b:02x}")).collect()
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
    fn channel_auth_binds_key_role_and_both_nonces() {
        let key = b"k3y";
        let m = auth_mac(key, "host", "gnonce", "hnonce");
        assert_eq!(m.len(), 64);
        assert!(auth_ok(key, "host", "gnonce", "hnonce", &m));
        assert!(!auth_ok(b"other", "host", "gnonce", "hnonce", &m), "wrong key");
        assert!(!auth_ok(key, "guest", "gnonce", "hnonce", &m), "a host proof is not a guest proof (no reflection)");
        assert!(!auth_ok(key, "host", "gnonce2", "hnonce", &m), "bound to the challenge (no replay)");
        assert!(!auth_ok(key, "host", "gnonce", "hnonce", &m[..63]));
        assert_ne!(random_hex(16), random_hex(16));
        // Without a key nothing changes on the wire: no `nonce` key in Hello.
        let h = GuestMsg::Hello { version: 1, agent: "a".into(), kernel: "k".into(), cid: None, transport: "vsock".into(), uid: 1000, nonce: None };
        let bytes = String::from_utf8(encode(&h).unwrap()[4..].to_vec()).unwrap();
        assert!(!bytes.contains("nonce"), "{bytes}");
        let (back, _) = decode::<GuestMsg>(&encode(&h).unwrap()).unwrap();
        assert_eq!(back[0], h);
    }

    #[test]
    fn workspace_paths_cannot_escape() {
        assert!(check_rel_path("src/main.rs").is_ok());
        for bad in ["/etc/passwd", "../x", "a/../../b", "", "./a"] {
            assert!(check_rel_path(bad).is_err(), "{bad}");
        }
    }
}
