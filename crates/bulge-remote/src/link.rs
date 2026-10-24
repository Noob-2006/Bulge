//! The one-time pairing link: everything a device needs to find the host and
//! prove it was invited. Shown as text and as a QR code; it holds a secret, so
//! it is meant to go from screen to device directly (scan or copy), not
//! through a chat or email.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::unhex;

const PREFIX: &str = "bulge-pair:";
pub const VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairLink {
    pub v: u32,
    /// `host:port` of the relay.
    pub relay: String,
    /// The relay's static key (hex), pinned by the relay tunnel.
    pub relay_key: String,
    /// The host's relay id (hex ed25519 public key).
    pub host: String,
    /// The host's Noise static key (hex X25519 public key).
    pub key: String,
    /// The pairing token id.
    pub token: String,
    /// The pairing secret (hex, 32 bytes), used once as the PSK.
    pub secret: String,
}

impl PairLink {
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).unwrap_or_default();
        format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(json))
    }

    pub fn decode(text: &str) -> Result<Self, String> {
        let body = text.trim().strip_prefix(PREFIX).ok_or("not a bulge pairing link (it starts with bulge-pair:)")?;
        let json = URL_SAFE_NO_PAD.decode(body).map_err(|_| "the pairing link is damaged (bad base64)")?;
        let link: Self = serde_json::from_slice(&json).map_err(|e| format!("the pairing link is damaged: {e}"))?;
        if link.v != VERSION {
            return Err(format!("pairing link version {} is not supported (this program speaks {VERSION})", link.v));
        }
        unhex::<32>(&link.relay_key).map_err(|e| format!("pairing link relay key: {e}"))?;
        unhex::<32>(&link.host).map_err(|e| format!("pairing link host id: {e}"))?;
        unhex::<32>(&link.key).map_err(|e| format!("pairing link host key: {e}"))?;
        unhex::<32>(&link.secret).map_err(|e| format!("pairing link secret: {e}"))?;
        if link.relay.is_empty() || link.token.is_empty() {
            return Err("the pairing link is missing the relay or token".into());
        }
        Ok(link)
    }
}

/// Render `text` as a QR code with Unicode half blocks (light modules drawn,
/// so it scans on a dark terminal background).
pub fn qr(text: &str) -> Result<String, String> {
    use qrcode::render::unicode::Dense1x2;
    let code = qrcode::QrCode::new(text.as_bytes()).map_err(|e| format!("qr: {e}"))?;
    Ok(code.render::<Dense1x2>().dark_color(Dense1x2::Light).light_color(Dense1x2::Dark).quiet_zone(true).build())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PairLink {
        PairLink { v: 2, relay: "relay.example:21117".into(), relay_key: "aa".repeat(32), host: "ab".repeat(32), key: "cd".repeat(32), token: "t1".into(), secret: "ef".repeat(32) }
    }

    #[test]
    fn links_round_trip_and_damage_is_reported() {
        let link = sample();
        let text = link.encode();
        assert!(text.starts_with("bulge-pair:"));
        assert_eq!(PairLink::decode(&format!("  {text}\n")).unwrap(), link);
        assert!(PairLink::decode("https://x").is_err());
        assert!(PairLink::decode(&text[..text.len() - 4]).is_err());
        let old = PairLink { v: 1, ..sample() };
        assert!(PairLink::decode(&old.encode()).unwrap_err().contains("version"));
        let bad = PairLink { secret: "00".into(), ..sample() };
        assert!(PairLink::decode(&bad.encode()).is_err());
        assert!(qr(&text).unwrap().lines().count() > 10);
    }
}
