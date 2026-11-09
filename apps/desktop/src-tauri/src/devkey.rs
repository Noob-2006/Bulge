//! This install's device key (docs/SECURITY.md §8; host side `crates/seagent-app/src/device_auth.rs`).
//!
//! An ECDSA P-256 key made on first use and kept in `<app data>/device-key.p8` (PKCS#8,
//! owner-only), apart from `hosts.json`: the console token stored there is only good together
//! with a fresh signature by this key, so a copied `hosts.json` (backup, sync folder, another
//! app reading it) does not open the host. The public half goes to the host when pairing
//! (`device.publicKey`); hosts paired by an older version get it on the next `host_open`
//! (the host binds it once: automatic migration). Same code on Windows, macOS, Linux, Android
//! and iOS (ring). No Tauri types here (unit-testable).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::{json, Value};
use std::path::Path;

pub const FILE: &str = "device-key.p8";

pub struct DeviceKey {
    pair: EcdsaKeyPair,
}

/// What the device signs (must match the host's `refresh_message`).
pub fn refresh_message(host_id: &str, device_id: &str, ts: u64, nonce: &str) -> String {
    format!("seagent-device-refresh|v1|{host_id}|{device_id}|{ts}|{nonce}")
}

fn write_private(p: &Path, data: &[u8]) -> Result<(), String> {
    let tmp = p.with_extension("tmp");
    std::fs::write(&tmp, data).map_err(|e| format!("{}: {e}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, p).map_err(|e| format!("{}: {e}", p.display()))
}

impl DeviceKey {
    /// The key in `dir`, created on first use.
    pub fn load_or_create(dir: &Path) -> Result<DeviceKey, String> {
        let rng = SystemRandom::new();
        let p = dir.join(FILE);
        if let Ok(der) = std::fs::read(&p) {
            if let Ok(pair) = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &rng) {
                return Ok(DeviceKey { pair });
            }
        }
        let der = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).map_err(|_| "cannot create a device key".to_string())?;
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        write_private(&p, der.as_ref())?;
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der.as_ref(), &rng).map_err(|_| "bad device key".to_string())?;
        Ok(DeviceKey { pair })
    }

    /// base64url of the 65-byte uncompressed public point (`device.publicKey`).
    pub fn public_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.pair.public_key().as_ref())
    }

    fn sign(&self, msg: &[u8]) -> Result<String, String> {
        let sig = self.pair.sign(&SystemRandom::new(), msg).map_err(|_| "signing failed".to_string())?;
        Ok(URL_SAFE_NO_PAD.encode(sig.as_ref()))
    }

    /// The `POST /pair/refresh` body. `ts` comes from the host's clock (`GET /pair/info`), so a
    /// phone with a wrong clock still lands inside the replay window.
    pub fn refresh_body(&self, host_id: &str, device_id: &str, ts: u64) -> Result<Value, String> {
        let mut n = [0u8; 18];
        ring::rand::SecureRandom::fill(&SystemRandom::new(), &mut n).map_err(|_| "no randomness".to_string())?;
        let nonce = URL_SAFE_NO_PAD.encode(n);
        let sig = self.sign(refresh_message(host_id, device_id, ts, &nonce).as_bytes())?;
        Ok(json!({"deviceId": device_id, "ts": ts, "nonce": nonce, "sig": sig, "publicKey": self.public_b64()}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};

    #[test]
    fn the_key_is_made_once_kept_and_signs_what_the_host_verifies() {
        let dir = std::env::temp_dir().join(format!("seagent-devkey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let k = DeviceKey::load_or_create(&dir).unwrap();
        let again = DeviceKey::load_or_create(&dir).unwrap();
        assert_eq!(k.public_b64(), again.public_b64(), "kept across starts");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(dir.join(FILE)).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let pk = URL_SAFE_NO_PAD.decode(k.public_b64()).unwrap();
        assert_eq!((pk.len(), pk[0]), (65, 4));
        let b = k.refresh_body("0123456789abcdef", "dev1", 1_700_000_000_000).unwrap();
        let msg = refresh_message("0123456789abcdef", "dev1", 1_700_000_000_000, b["nonce"].as_str().unwrap());
        assert_eq!(msg, format!("seagent-device-refresh|v1|0123456789abcdef|dev1|1700000000000|{}", b["nonce"].as_str().unwrap()), "the host's format");
        let sig = URL_SAFE_NO_PAD.decode(b["sig"].as_str().unwrap()).unwrap();
        assert!(UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &pk).verify(msg.as_bytes(), &sig).is_ok());
        assert!(UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &pk).verify(b"something else", &sig).is_err());
        assert_ne!(b["nonce"], k.refresh_body("h", "d", 1).unwrap()["nonce"], "fresh nonce per refresh");
        let _ = std::fs::remove_dir_all(dir);
    }
}
