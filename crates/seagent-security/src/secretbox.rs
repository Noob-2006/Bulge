//! Authenticated encryption primitives for data that must be stored at rest (A4: the
//! secret store, A13/A18: nothing here — signatures live in [`crate::signing`]).
//!
//! Everything is `ring`, which is already in the tree through rustls, so the crypto has no
//! new dependency and no hand-rolled primitives:
//!
//! * **AEAD**: ChaCha20-Poly1305, 96-bit random nonce, caller-supplied associated data. The
//!   AAD is what binds the ciphertext to its metadata (a store file's `backend`/`kdf`/
//!   `iterations`/`salt` header): flipping an iteration count to 1 or a salt to a different
//!   value makes the tag check fail instead of silently weakening the key.
//! * **Password KDF**: PBKDF2-HMAC-SHA256 with a per-file random salt, and a floor on the
//!   iteration count so a config edit can never turn a passphrase into a fast hash.
//! * **Randomness**: `ring::rand::SystemRandom` (getrandom) — never `rand`, never time.
//!
//! The module deliberately does not know about files, keyrings or TPMs: it turns keys and
//! bytes into ciphertext and back. [`crate::secretbox`] is used by `seagent_kernel::secretstore`.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use std::num::NonZeroU32;

/// Key length of every key this module accepts (ChaCha20-Poly1305 = 256 bit).
pub const KEY_LEN: usize = 32;
/// 96-bit nonce: unique per (key, message); generated fresh for every seal.
pub const NONCE_LEN: usize = 12;
/// Salt length for the password KDF.
pub const SALT_LEN: usize = 16;
/// Default PBKDF2-HMAC-SHA256 iteration count (OWASP 2023 guidance for SHA-256 is 600k).
pub const DEFAULT_ITERATIONS: u32 = 600_000;
/// Refuse to derive a key with fewer iterations than this: a store file that asks for 100
/// iterations is either corrupt or someone trying to make an offline attack cheap.
pub const MIN_ITERATIONS: u32 = 100_000;

fn rand_bytes(n: usize) -> Result<Vec<u8>, String> {
    let mut b = vec![0u8; n];
    SystemRandom::new().fill(&mut b).map_err(|_| "the OS random source failed".to_string())?;
    Ok(b)
}

/// A fresh 32-byte key (used for keyring/TPM-held keys and for tests).
pub fn random_key() -> Result<[u8; KEY_LEN], String> {
    let v = rand_bytes(KEY_LEN)?;
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(&v);
    Ok(k)
}

/// A fresh salt for the password KDF.
pub fn random_salt() -> Result<[u8; SALT_LEN], String> {
    let v = rand_bytes(SALT_LEN)?;
    let mut s = [0u8; SALT_LEN];
    s.copy_from_slice(&v);
    Ok(s)
}

/// PBKDF2-HMAC-SHA256. `iterations` below [`MIN_ITERATIONS`] is an error, not a warning.
pub fn derive_key(passphrase: &str, salt: &[u8], iterations: u32) -> Result<[u8; KEY_LEN], String> {
    if iterations < MIN_ITERATIONS {
        return Err(format!("key derivation needs at least {MIN_ITERATIONS} iterations (got {iterations})"));
    }
    let rounds = NonZeroU32::new(iterations).ok_or("iteration count must be positive")?;
    let mut key = [0u8; KEY_LEN];
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, rounds, salt, passphrase.as_bytes(), &mut key);
    Ok(key)
}

fn aead_key(key: &[u8]) -> Result<LessSafeKey, String> {
    if key.len() != KEY_LEN {
        return Err(format!("a store key must be {KEY_LEN} bytes (got {})", key.len()));
    }
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| "unusable AEAD key".to_string())?;
    Ok(LessSafeKey::new(unbound))
}

/// Encrypt `plaintext` under `key`. Returns `(nonce, ciphertext+tag)`; `aad` is authenticated
/// but not stored, so the caller must reproduce it exactly on [`open`].
pub fn seal(key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let k = aead_key(key)?;
    let nonce_bytes = rand_bytes(NONCE_LEN)?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&nonce_bytes);
    let mut buf = plaintext.to_vec();
    k.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), &mut buf).map_err(|_| "encryption failed".to_string())?;
    Ok((nonce.to_vec(), buf))
}

/// Decrypt what [`seal`] produced. A wrong key, a changed `aad`, a flipped byte anywhere in
/// the nonce or ciphertext, or a truncated input all fail with the same message on purpose:
/// the caller learns "this is not my file", not which part matched.
pub fn open(key: &[u8], aad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let k = aead_key(key)?;
    if nonce.len() != NONCE_LEN {
        return Err("cannot decrypt: wrong key, wrong passphrase, or the file is damaged".to_string());
    }
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(nonce);
    let mut buf = ciphertext.to_vec();
    let plain = k.open_in_place(Nonce::assume_unique_for_key(n), Aad::from(aad), &mut buf).map_err(|_| "cannot decrypt: wrong key, wrong passphrase, or the file is damaged".to_string())?;
    Ok(plain.to_vec())
}

/// Lower-case hex, the form keys are printed in (`seagent secrets backend`).
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a 32-byte key written as 64 hex characters or as base64. Both spellings appear in
/// practice (systemd `LoadCredential` gives bytes, `openssl rand -hex` gives hex).
pub fn parse_key(s: &str) -> Result<[u8; KEY_LEN], String> {
    use base64::Engine as _;
    let t = s.trim();
    let raw = if t.len() == KEY_LEN * 2 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        (0..KEY_LEN).map(|i| u8::from_str_radix(&t[i * 2..i * 2 + 2], 16)).collect::<Result<Vec<u8>, _>>().map_err(|_| "key is not valid hex".to_string())?
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(t)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(t))
            .map_err(|_| format!("a store key must be {} hex characters or base64", KEY_LEN * 2))?
    };
    if raw.len() != KEY_LEN {
        return Err(format!("a store key must be {KEY_LEN} bytes (got {})", raw.len()));
    }
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(&raw);
    Ok(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    const AAD: &[u8] = b"seagent-secret-store-v1|tpm|raw|0|";
    /// Fast iteration count for tests: the floor is a constant, the value runs once here.
    const FAST: u32 = MIN_ITERATIONS;

    #[test]
    fn seal_open_roundtrip_uses_a_fresh_nonce() {
        let k = random_key().unwrap();
        let (n1, c1) = seal(&k, AAD, b"GITHUB_TOKEN = \"x\"\n").unwrap();
        let (n2, c2) = seal(&k, AAD, b"GITHUB_TOKEN = \"x\"\n").unwrap();
        assert_ne!(n1, n2, "every seal draws a new nonce");
        assert_ne!(c1, c2);
        assert_eq!(open(&k, AAD, &n1, &c1).unwrap(), b"GITHUB_TOKEN = \"x\"\n");
        assert!(!c1.windows(6).any(|w| w == b"GITHUB"), "ciphertext leaks no plaintext");
    }

    #[test]
    fn every_tamper_is_refused_with_the_same_answer() {
        let k = random_key().unwrap();
        let (nonce, ct) = seal(&k, AAD, b"secret-value").unwrap();
        let wrong = random_key().unwrap();
        let mut flipped = ct.clone();
        flipped[0] ^= 1;
        let mut bad_nonce = nonce.clone();
        bad_nonce[3] ^= 1;
        type Case<'a> = (&'a str, Vec<u8>, Vec<u8>, &'a [u8]);
        let cases: Vec<Case> = vec![
            ("wrong key", wrong.to_vec(), ct.clone(), AAD),
            ("flipped ciphertext", k.to_vec(), flipped, AAD),
            ("flipped nonce", k.to_vec(), ct.clone(), AAD),
            ("different aad", k.to_vec(), ct.clone(), b"seagent-secret-store-v1|passphrase|pbkdf2-hmac-sha256|100000|"),
            ("truncated", k.to_vec(), ct[4..].to_vec(), AAD),
        ];
        for (what, key, ct, aad) in cases {
            let n = if what == "flipped nonce" { bad_nonce.as_slice() } else { nonce.as_slice() };
            let err = open(&key, aad, n, &ct).unwrap_err();
            assert!(err.contains("wrong key, wrong passphrase, or the file is damaged"), "{what}: {err}");
        }
        assert_eq!(open(&k, AAD, &nonce, &ct).unwrap(), b"secret-value", "the original still opens");
    }

    #[test]
    fn password_kdf_is_deterministic_salted_and_floor_limited() {
        let salt = random_salt().unwrap();
        let a = derive_key("correct horse", &salt, FAST).unwrap();
        assert_eq!(a, derive_key("correct horse", &salt, FAST).unwrap());
        assert_ne!(a, derive_key("correct horsE", &salt, FAST).unwrap());
        let other = random_salt().unwrap();
        assert_ne!(a, derive_key("correct horse", &other, FAST).unwrap(), "salt changes the key");
        let e = derive_key("x", &salt, MIN_ITERATIONS - 1).unwrap_err();
        assert!(e.contains("at least 100000 iterations"), "{e}");
        // A passphrase-derived key really is a store key.
        let (n, c) = seal(&a, AAD, b"v").unwrap();
        assert_eq!(open(&derive_key("correct horse", &salt, FAST).unwrap(), AAD, &n, &c).unwrap(), b"v");
    }

    #[test]
    fn keys_parse_from_hex_and_base64_and_nothing_else() {
        use base64::Engine as _;
        let k = random_key().unwrap();
        assert_eq!(parse_key(&hex(&k)).unwrap(), k);
        assert_eq!(parse_key(&base64::engine::general_purpose::STANDARD.encode(k)).unwrap(), k);
        assert_eq!(parse_key(&format!("  {}  ", hex(&k))).unwrap(), k, "whitespace is trimmed");
        assert!(parse_key("short").is_err());
        assert!(parse_key(&hex(&[7u8; 31])).is_err());
        assert!(parse_key("not base64 !!!").is_err());
        assert_ne!(hex(&k), hex(&random_key().unwrap()));
    }

    #[test]
    fn wrong_key_length_is_named() {
        assert!(seal(&[0u8; 16], AAD, b"x").unwrap_err().contains("must be 32 bytes"));
        assert!(open(&[0u8; 5], AAD, &[0u8; NONCE_LEN], b"xx").is_err());
    }
}
