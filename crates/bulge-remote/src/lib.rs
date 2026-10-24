//! Reach bulge from your other devices, across networks and operating
//! systems, the way RustDesk does — rebuilt for bulge's two-key rule.
//!
//! ```text
//!   device ──dial──▶ ┌────────────┐ ◀──control── bulge host
//!                    │ bulge-relay│ ◀──accept───
//!   device ◀═══════ blind byte pipe ═══════════▶ bulge host
//!            Noise_IKpsk2 end to end (relay sees only ciphertext)
//! ```
//!
//! * Both ends dial OUT to a small relay ([`relay`]), so neither needs an
//!   open port or a public address. Every connection to the relay is itself
//!   encrypted and pinned to the relay's key ([`tunnel`]), so the network
//!   sees neither ids nor content; the relay passes the device↔host frames
//!   along without being able to read them.
//! * The host proves to the relay that it owns its id (an ed25519 key) before
//!   it is reachable, so nobody can squat on it.
//! * Device and host then run `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` through
//!   the pipe ([`noise`]). The device knows the host's static key from the
//!   pairing link, so a relay in the middle cannot impersonate the host. The
//!   host admits a device only when BOTH keys match: its static key is in the
//!   paired-device list and it proves the per-device pre-shared key.
//! * There is exactly one protocol and no fallback: any failure closes the
//!   connection. (RustDesk falls back to plaintext when key exchange fails;
//!   bulge never does.)
//! * Pairing: `bulge remote pair` prints a one-time link (and QR code) holding
//!   the relay, the host's keys and a 256-bit pairing secret valid for ten
//!   minutes. The device uses it once as the PSK; the host then issues the
//!   device its own long-term PSK.

pub mod cli;
#[cfg(feature = "channel")]
pub mod channel;
#[cfg(feature = "direct")]
pub mod conversation;
#[cfg(feature = "direct")]
pub mod direct;
pub mod device;
pub mod frame;
pub mod host;
pub mod link;
pub mod noise;
pub mod relay;
pub mod store;
pub mod tunnel;
pub mod wire;

pub use bulge_util::{hex, now_secs, random, unhex};

/// Why reaching a host failed — decides whether a device keeps retrying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// Definitely refused: the relay is not the pinned one, the host's
    /// answer did not verify, or the host said no. Retrying will not help.
    Rejected(String),
    /// The host closed the connection without answering. That is how it
    /// treats a device it does not know (no oracle), but a network hiccup
    /// looks the same, so only repeated silence counts.
    Silent(String),
    /// Anything else (network, relay restarting, host offline): retry.
    Transient(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Rejected(m) | Failure::Silent(m) | Failure::Transient(m) => f.write_str(m),
        }
    }
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Failure::Transient(message)
    }
}

impl From<&str> for Failure {
    fn from(message: &str) -> Self {
        Failure::Transient(message.to_owned())
    }
}

impl From<Failure> for String {
    fn from(failure: Failure) -> Self {
        failure.to_string()
    }
}

/// The directory holding remote keys and lists: `~/.bulge/remote`.
pub fn default_dir() -> Result<std::path::PathBuf, String> {
    Ok(bulge_util::home_dir()?.join(".bulge").join("remote"))
}

