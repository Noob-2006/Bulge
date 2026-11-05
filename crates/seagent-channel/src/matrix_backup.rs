//! Matrix key backup and secret storage primitives (client-server spec
//! §"Server-side key backups", §"Secret storage", appendix "Cryptographic key
//! representation"), all pure:
//!
//! - Recovery keys: base58 (Bitcoin alphabet) of `0x8B 0x01 ‖ key ‖ parity`,
//!   shown in groups of four; passphrase keys are PBKDF2-HMAC-SHA-512.
//! - `m.secret_storage.v1.aes-hmac-sha2`: `HKDF(0³², key, name)` → AES-256-CTR
//!   key + HMAC-SHA-256 key; IV with bit 63 cleared; the key check is the
//!   encryption of 32 zero bytes under the empty name.
//! - `m.megolm_backup.v1.curve25519-aes-sha2`: ephemeral X25519 against the
//!   backup public key, `HKDF(0³², S, "")` → AES-256-CBC key, MAC key, IV. The
//!   MAC is HMAC-SHA-256 over the empty string (libolm's historical behaviour,
//!   which every client reproduces); a MAC over the ciphertext is accepted too.

use crate::olm::{b64, hkdf, unb64, Curve};
use seagent_net::crypto::{ct_eq, hmac_sha256, random_bytes, Aes};
use base64::Engine;
use serde_json::{json, Value};

pub const BACKUP_ALGORITHM: &str = "m.megolm_backup.v1.curve25519-aes-sha2";
pub const SSSS_ALGORITHM: &str = "m.secret_storage.v1.aes-hmac-sha2";
const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const PREFIX: [u8; 2] = [0x8b, 0x01];

pub fn base58_encode(b: &[u8]) -> String {
    let zeros = b.iter().take_while(|&&x| x == 0).count();
    let mut digits: Vec<u8> = vec![];
    for &byte in b {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    std::iter::repeat_n('1', zeros).chain(digits.iter().rev().map(|&d| B58[d as usize] as char)).collect()
}

pub fn base58_decode(s: &str) -> Option<Vec<u8>> {
    let zeros = s.bytes().take_while(|&c| c == b'1').count();
    let mut bytes: Vec<u8> = vec![];
    for c in s.bytes() {
        let mut carry = B58.iter().position(|&x| x == c)? as u32;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push(carry as u8);
            carry >>= 8;
        }
    }
    Some(std::iter::repeat_n(0, zeros).chain(bytes.into_iter().rev()).collect())
}

pub fn encode_recovery_key(key: &[u8; 32]) -> String {
    let mut b = PREFIX.to_vec();
    b.extend_from_slice(key);
    b.push(b.iter().fold(0, |a, x| a ^ x));
    let s = base58_encode(&b);
    s.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(" ")
}

pub fn decode_recovery_key(s: &str) -> Option<[u8; 32]> {
    let b = base58_decode(&s.chars().filter(|c| !c.is_whitespace()).collect::<String>())?;
    if b.len() != 35 || b[..2] != PREFIX || b.iter().fold(0, |a, x| a ^ x) != 0 {
        return None;
    }
    b[2..34].try_into().ok()
}

/// Secret-storage key from a passphrase (`m.pbkdf2`, SHA-512).
pub fn passphrase_key(pass: &str, salt: &str, iterations: u32) -> [u8; 32] {
    let mut k = [0u8; 32];
    ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA512, std::num::NonZeroU32::new(iterations.max(1)).unwrap(), salt.as_bytes(), pass.as_bytes(), &mut k);
    k
}

fn padded(d: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(d)
}

fn ssss_keys(key: &[u8; 32], name: &str) -> ([u8; 32], [u8; 32]) {
    let k = hkdf(&[0; 32], key, name.as_bytes(), 64);
    (k[..32].try_into().unwrap(), k[32..].try_into().unwrap())
}

fn ssss_with_iv(key: &[u8; 32], name: &str, plain: &[u8], iv: [u8; 16]) -> Value {
    let (ak, mk) = ssss_keys(key, name);
    let mut ct = plain.to_vec();
    Aes::new(&ak).unwrap().ctr_apply(&iv, &mut ct);
    json!({"iv": padded(&iv), "ciphertext": padded(&ct), "mac": padded(&hmac_sha256(&mk, &ct))})
}

/// `{iv, ciphertext, mac}` for secret `name` (padded base64, as Element writes it).
pub fn ssss_encrypt(key: &[u8; 32], name: &str, plain: &[u8]) -> Value {
    let mut iv: [u8; 16] = random_bytes(16).try_into().unwrap();
    iv[8] &= 0x7f;
    ssss_with_iv(key, name, plain, iv)
}

pub fn ssss_decrypt(key: &[u8; 32], name: &str, v: &Value) -> Option<Vec<u8>> {
    let (ak, mk) = ssss_keys(key, name);
    let iv: [u8; 16] = unb64(v["iv"].as_str()?)?.try_into().ok()?;
    let mut ct = unb64(v["ciphertext"].as_str()?)?;
    if !ct_eq(&hmac_sha256(&mk, &ct), &unb64(v["mac"].as_str()?)?) {
        return None;
    }
    Aes::new(&ak).unwrap().ctr_apply(&iv, &mut ct);
    Some(ct)
}

/// `m.secret_storage.key.*` content for a new key (with its key check).
pub fn ssss_key_description(key: &[u8; 32]) -> Value {
    let mut v = ssss_encrypt(key, "", &[0; 32]);
    v.as_object_mut().unwrap().remove("ciphertext");
    v["algorithm"] = json!(SSSS_ALGORITHM);
    v
}

/// Does `key` match a key description's check (`iv` + `mac`)?
pub fn ssss_check(key: &[u8; 32], desc: &Value) -> bool {
    let Some(iv) = desc["iv"].as_str().and_then(unb64).and_then(|i| <[u8; 16]>::try_from(i).ok()) else { return false };
    let want = desc["mac"].as_str().and_then(unb64).unwrap_or_default();
    desc["algorithm"] == SSSS_ALGORITHM && ct_eq(&unb64(ssss_with_iv(key, "", &[0; 32], iv)["mac"].as_str().unwrap()).unwrap(), &want)
}

/// Encrypt one backed-up session for the backup public key.
pub fn backup_encrypt(public: &[u8; 32], plain: &[u8]) -> Value {
    let eph = Curve::generate();
    let k = hkdf(&[0; 32], &eph.dh(public), b"", 80);
    let ct = Aes::new(&k[..32]).unwrap().cbc_encrypt(&k[64..80].try_into().unwrap(), plain);
    let mac = hmac_sha256(&k[32..64], b"");
    json!({"ephemeral": b64(&eph.public), "ciphertext": b64(&ct), "mac": b64(&mac[..8])})
}

pub fn backup_decrypt(secret: &[u8; 32], v: &Value) -> Option<Vec<u8>> {
    let eph: [u8; 32] = unb64(v["ephemeral"].as_str()?)?.try_into().ok()?;
    let ct = unb64(v["ciphertext"].as_str()?)?;
    let mac = unb64(v["mac"].as_str()?)?;
    let k = hkdf(&[0; 32], &Curve::from_secret(*secret).dh(&eph), b"", 80);
    if !ct_eq(&hmac_sha256(&k[32..64], b"")[..8], &mac) && !ct_eq(&hmac_sha256(&k[32..64], &ct)[..8], &mac) {
        return None;
    }
    Aes::new(&k[..32]).unwrap().cbc_decrypt(&k[64..80].try_into().unwrap(), &ct)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58_and_recovery_keys() {
        // Bitcoin base58 vectors.
        for (raw, enc) in [(&b""[..], ""), (b"\0", "1"), (b"\0\0\x01", "112"), (b"hello world", "StV1DL6CwTryKyV"), (&[0xff; 4], "7YXq9G")] {
            assert_eq!(base58_encode(raw), enc);
            assert_eq!(base58_decode(enc).unwrap(), raw);
        }
        assert!(base58_decode("0OIl").is_none());
        let key: [u8; 32] = std::array::from_fn(|i| i as u8 * 7);
        let rk = encode_recovery_key(&key);
        assert!(rk.starts_with("Es") && rk.split(' ').all(|g| g.len() <= 4) && rk.split(' ').count() == 12, "{rk}");
        assert_eq!(decode_recovery_key(&rk), Some(key));
        assert_eq!(decode_recovery_key(&rk.replace(' ', "")), Some(key));
        let mut bad = rk.into_bytes();
        bad[5] = if bad[5] == b'a' { b'b' } else { b'a' };
        assert_eq!(decode_recovery_key(std::str::from_utf8(&bad).unwrap()), None, "parity");
    }

    #[test]
    fn secret_storage_round_trip_and_key_check() {
        let key = [9u8; 32];
        let desc = ssss_key_description(&key);
        assert!(ssss_check(&key, &desc) && !ssss_check(&[8; 32], &desc));
        assert_eq!(unb64(desc["iv"].as_str().unwrap()).unwrap()[8] & 0x80, 0, "bit 63 clear");
        let e = ssss_encrypt(&key, "m.megolm_backup.v1", b"c2VjcmV0");
        assert_eq!(ssss_decrypt(&key, "m.megolm_backup.v1", &e).unwrap(), b"c2VjcmV0");
        assert!(ssss_decrypt(&key, "m.cross_signing.master", &e).is_none(), "name is bound in");
        assert!(ssss_decrypt(&[1; 32], "m.megolm_backup.v1", &e).is_none());
        // PBKDF2-HMAC-SHA512 (RFC 6070-style vector for SHA-512: "password"/"salt", 1 iteration).
        assert_eq!(seagent_net::crypto::hex(&passphrase_key("password", "salt", 1)), "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252");
    }

    #[test]
    fn backup_round_trip() {
        let secret = [5u8; 32];
        let public = Curve::from_secret(secret).public;
        let v = backup_encrypt(&public, br#"{"session_key":"x"}"#);
        assert_eq!(backup_decrypt(&secret, &v).unwrap(), br#"{"session_key":"x"}"#);
        assert!(backup_decrypt(&[6; 32], &v).is_none());
        let mut t = v.clone();
        t["mac"] = json!("AAAAAAAAAAA");
        assert!(backup_decrypt(&secret, &t).is_none());
    }
}
