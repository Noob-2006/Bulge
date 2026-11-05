//! Ed25519 signing core for the supply chain (A13): package digests, publisher keys and the
//! trust store that decides which keys a hub/skill/plugin install may trust.
//!
//! Why this exists: a lock file's `content_hash` only proves that the bytes on disk are the bytes
//! that were installed — it says nothing about *who* produced them, and anyone who can rewrite
//! `lock.json` can rewrite the hash with it. A detached Ed25519 signature over a canonical digest
//! moves that decision to a key the user (or their distro) pinned out of band. Everything here is
//! deliberately dependency-free apart from `ring` (already in the tree via rustls) so this module
//! can be the single place the kernel, the skills hub, the plugin installer and the release
//! tooling agree on what "the package" is.
//!
//! ## Canonical manifest digest
//!
//! [`manifest_digest`] is a digest over the *file map*, not over an archive: archive bytes depend
//! on the compressor, the mtime and the entry order, so two byte-identical trees could still hash
//! differently and a re-zipped package would stop verifying. The encoding is a tiny RFC-8785-like
//! subset — one LF-terminated line per file, sorted by path bytes (which for UTF-8 equals code
//! point order):
//!
//! ```text
//! <posix path> NUL <lowercase hex sha256 of the file content> LF
//! ```
//!
//! UTF-8, no BOM, no trailing blank line, no file count and no separators other than the ones
//! above; the result is `"sha256:" + hex(sha256(that byte string))`. Paths are POSIX-normalized
//! (`/` separators, no leading `./`) and must not contain NUL or LF — the path validators that
//! guard every bundle (`validate_rel`, `skip_bundle_file`) already reject those, and the digest is
//! only ever computed after them.
//!
//! ## Keys
//!
//! A public key travels as text: `ed25519:<base64 of the 32 raw key bytes>` (a bare base64 string
//! of 32 bytes is accepted too, because that is what `ring` prints). [`PublicKey::id`] is the
//! first 16 hex characters of `sha256(key material)` — a short, stable handle for log lines and
//! consent records; it is a *name*, not an authentication primitive.
//!
//! Production code only verifies. [`sign`] exists for tests and for release tooling run by the
//! person holding the seed; nothing in seagent's runtime paths ever sees a secret key.

use ring::signature::KeyPair;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Prefix that marks a textual Ed25519 public key.
pub const KEY_PREFIX: &str = "ed25519:";

/// Raw digest of `bytes`.
pub fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Lowercase hex SHA-256 of `bytes` (no prefix); the building block of every digest here.
pub fn sha256_hex(bytes: &[u8]) -> String {
    sha256_bytes(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let s = s.trim();
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(s))
        .map_err(|e| format!("invalid base64: {e}"))
}

fn b64_encode(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn key_bytes(raw: &str) -> Result<Vec<u8>, String> {
    let b = b64_decode(raw)?;
    if b.len() != 32 {
        return Err(format!("an Ed25519 public key is 32 bytes, got {}", b.len()));
    }
    Ok(b)
}

/// An Ed25519 public key parsed from its textual form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    raw: [u8; 32],
}

impl PublicKey {
    /// `ed25519:<base64 32 bytes>` or a bare base64 of 32 bytes.
    pub fn parse(text: &str) -> Result<PublicKey, String> {
        let t = text.trim();
        let bare = t.strip_prefix(KEY_PREFIX).unwrap_or(t);
        if bare.is_empty() {
            return Err("empty public key".into());
        }
        let b = key_bytes(bare).map_err(|e| format!("invalid public key `{}`: {e}", short(text)))?;
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&b);
        Ok(PublicKey { raw })
    }

    /// First 16 hex characters of `sha256(key material)`: the id used in logs and consent records.
    pub fn id(&self) -> String {
        sha256_hex(&self.raw)[..16].to_string()
    }

    /// Canonical textual form (`ed25519:<base64>`), as written into a trust store.
    pub fn text(&self) -> String {
        format!("{KEY_PREFIX}{}", b64_encode(&self.raw))
    }

    /// Raw 32 key bytes (what `ring` verifies against).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.raw
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text())
    }
}

fn short(s: &str) -> String {
    if s.chars().count() <= 24 {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(24).collect::<String>())
    }
}

/// Verify a base64 (standard, optionally unpadded) signature over `msg`.
pub fn verify(public: &PublicKey, msg: &[u8], sig_b64: &str) -> Result<(), String> {
    let sig = b64_decode(sig_b64).map_err(|e| format!("invalid signature encoding: {e}"))?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public.as_bytes())
        .verify(msg, &sig)
        .map_err(|_| format!("bad signature for key {}: the message or the signature was tampered with", public.id()))
}

/// Sign `msg` with the 32-byte seed in `secret_seed_b64`, returning base64.
///
/// Only tests and maintainer-side release tooling call this; the runtime never holds a secret key.
pub fn sign(secret_seed_b64: &str, msg: &[u8]) -> Result<String, String> {
    let seed = b64_decode(secret_seed_b64).map_err(|e| format!("invalid base64: {e}"))?;
    let kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| format!("an Ed25519 secret seed is 32 bytes, got {}", seed.len()))?;
    Ok(b64_encode(kp.sign(msg).as_ref()))
}

/// The public key (`ed25519:<base64>`) belonging to a seed: what a publisher hands out.
pub fn public_of(secret_seed_b64: &str) -> Result<String, String> {
    let seed = b64_decode(secret_seed_b64).map_err(|e| format!("invalid base64: {e}"))?;
    let kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| format!("an Ed25519 secret seed is 32 bytes, got {}", seed.len()))?;
    Ok(format!("{KEY_PREFIX}{}", b64_encode(kp.public_key().as_ref())))
}

/// The exact bytes [`manifest_digest`] hashes: `path NUL hex sha256 LF` per file, sorted.
pub fn manifest_bytes(files: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    for (path, data) in files {
        // BTreeMap iterates by `String` order == UTF-8 byte order, which is what the doc promises.
        out.extend_from_slice(path.as_bytes());
        out.push(0);
        out.extend_from_slice(sha256_hex(data).as_bytes());
        out.push(b'\n');
    }
    out
}

/// Canonical content digest of a file map (`"sha256:<hex>"`), see the module docs.
pub fn manifest_digest(files: &BTreeMap<String, Vec<u8>>) -> String {
    format!("sha256:{}", sha256_hex(&manifest_bytes(files)))
}

/// One key a caller has decided to trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedKey {
    /// Human label (`acme-release`), matched case-insensitively by [`TrustStore::verify`].
    pub id: String,
    pub key: PublicKey,
    /// Why this key is trusted (shown in refusal messages), e.g. "vendored in the distro image".
    pub note: String,
}

/// The keys an install may trust plus the signature policy.
#[derive(Debug, Clone, Default)]
pub struct TrustStore {
    pub keys: Vec<TrustedKey>,
    /// `[policy] require_signature`: refuse an unsigned bundle. Defaults to false so existing
    /// installs and hubs keep working (see `hub::verify`'s module docs).
    pub require_signature: bool,
}

impl TrustStore {
    /// Parse the tiny trust-store TOML:
    ///
    /// ```toml
    /// [policy]
    /// require_signature = true
    ///
    /// [[key]]
    /// id = "acme-release"
    /// key = "ed25519:…"
    /// note = "acme skills hub, pinned 2026-01"
    /// ```
    ///
    /// Hand-parsed instead of via the `toml` crate: that crate is a dev-dependency of
    /// `seagent-security` (it only exists to test `[security.egress_proxy]`), and this file must not
    /// grow the production dependency set. The subset is small and fixed — sections, `[[key]]`
    /// tables, `k = "v"` / `k = true` — so a line scanner is less code than a dependency argument.
    pub fn from_toml(src: &str) -> Result<TrustStore, String> {
        #[derive(Clone, Copy, PartialEq)]
        enum Sec {
            Root,
            Policy,
            Key,
            Other,
        }
        let mut ts = TrustStore::default();
        let mut sec = Sec::Root;
        let mut cur: Option<(String, String, String)> = None; // id, key, note
        let flush = |cur: &mut Option<(String, String, String)>, ts: &mut TrustStore| -> Result<(), String> {
            if let Some((id, key, note)) = cur.take() {
                if key.is_empty() {
                    return Err(format!("trust store: [[key]] `{}` has no `key`", if id.is_empty() { "?" } else { &id }));
                }
                let key = PublicKey::parse(&key)?;
                let id = if id.is_empty() { key.id() } else { id };
                if ts.keys.iter().any(|k| k.key == key) {
                    return Err(format!("trust store: key {} listed twice", key.id()));
                }
                ts.keys.push(TrustedKey { id, key, note });
            }
            Ok(())
        };
        for (n, raw) in src.lines().enumerate() {
            let line = match raw.find('#') {
                // A `#` inside a value is legal, but no key id/base64 we accept contains one.
                Some(i) => &raw[..i],
                None => raw,
            }
            .trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') {
                flush(&mut cur, &mut ts)?;
                sec = if line == "[[key]]" {
                    cur = Some((String::new(), String::new(), String::new()));
                    Sec::Key
                } else if line == "[policy]" {
                    Sec::Policy
                } else if line.starts_with("[[") || line.starts_with('[') {
                    Sec::Other
                } else {
                    return Err(format!("trust store line {}: malformed section `{line}`", n + 1));
                };
                continue;
            }
            let (k, v) = line.split_once('=').ok_or_else(|| format!("trust store line {}: expected `key = value`", n + 1))?;
            let (k, v) = (k.trim(), unquote(v.trim()));
            match sec {
                Sec::Policy => {
                    if k == "require_signature" {
                        ts.require_signature = match v.to_ascii_lowercase().as_str() {
                            "true" => true,
                            "false" => false,
                            other => return Err(format!("trust store: require_signature must be true or false, got `{other}`")),
                        };
                    }
                }
                Sec::Key => {
                    let Some((id, key, note)) = cur.as_mut() else { continue };
                    match k {
                        "id" => *id = v,
                        "key" => *key = v,
                        "note" => *note = v,
                        other => return Err(format!("trust store: unknown key field `{other}`")),
                    }
                }
                Sec::Root | Sec::Other => {}
            }
        }
        flush(&mut cur, &mut ts)?;
        Ok(ts)
    }

    /// Load a trust store from an explicit path. Callers choose the path: there is no implicit
    /// "trust whatever is next to the package" lookup, so a compromised hub cannot ship its own
    /// keyring and bless itself.
    pub fn load(path: &Path) -> Result<TrustStore, String> {
        let src = std::fs::read_to_string(path).map_err(|e| format!("cannot read trust store {}: {e}", path.display()))?;
        TrustStore::from_toml(&src).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// The path `seagent` conventionally uses for the user's trust store under a data dir.
    pub fn default_path(data: &Path) -> PathBuf {
        data.join("trust").join("ed25519.toml")
    }

    /// Find a key by label, textual form, fingerprint or bare base64 material.
    pub fn find(&self, key_id_or_key: &str) -> Option<&TrustedKey> {
        let want = key_id_or_key.trim();
        self.keys.iter().find(|k| k.id.eq_ignore_ascii_case(want) || k.key.text() == want || k.key.id() == want || b64_encode(k.key.as_bytes()) == want)
    }

    /// Verify a signature against the named key. An unknown key is an error that names it: an
    /// unsigned-but-claimed identity must never degrade into "trusted".
    pub fn verify(&self, key_id_or_key: &str, msg: &[u8], sig: &str) -> Result<&TrustedKey, String> {
        let k = self.find(key_id_or_key).ok_or_else(|| format!("unknown signing key `{}`: not in the trust store", short(key_id_or_key.trim())))?;
        verify(&k.key, msg, sig)?;
        Ok(k)
    }
}

fn unquote(v: &str) -> String {
    let v = v.trim();
    let v = v.strip_prefix('"').and_then(|x| x.strip_suffix('"')).or_else(|| v.strip_prefix('\'').and_then(|x| x.strip_suffix('\''))).unwrap_or(v);
    v.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed seed: no key files in the repo, and every run derives the same identity.
    const SEED: &str = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusN26XHso=";
    const OTHER_SEED: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    fn files(pairs: &[(&str, &[u8])]) -> BTreeMap<String, Vec<u8>> {
        pairs.iter().map(|(p, c)| (p.to_string(), c.to_vec())).collect()
    }

    #[test]
    fn key_ids_and_text_forms_roundtrip() {
        let pubt = public_of(SEED).unwrap();
        let k = PublicKey::parse(&pubt).unwrap();
        assert!(pubt.starts_with(KEY_PREFIX));
        assert_eq!(k.text(), pubt);
        assert_eq!(k.id().len(), 16);
        assert_eq!(k.id(), sha256_hex(k.as_bytes())[..16], "id is a sha256 prefix");
        // Raw base64 of the same key parses to the same key; garbage and wrong lengths do not.
        assert_eq!(PublicKey::parse(pubt.trim_start_matches(KEY_PREFIX)).unwrap(), k);
        assert!(PublicKey::parse("ed25519:not base64!!").is_err());
        assert!(PublicKey::parse(&format!("{KEY_PREFIX}{}", b64_encode(&[7u8; 31]))).unwrap_err().contains("32 bytes"));
        assert!(PublicKey::parse("").is_err());
        assert_ne!(PublicKey::parse(&public_of(OTHER_SEED).unwrap()).unwrap().id(), k.id());
    }

    #[test]
    fn sign_verify_roundtrip_and_failures() {
        let k = PublicKey::parse(&public_of(SEED).unwrap()).unwrap();
        let sig = sign(SEED, b"the package").unwrap();
        assert!(verify(&k, b"the package", &sig).is_ok());
        // Tampered message.
        let e = verify(&k, b"the package!", &sig).unwrap_err();
        assert!(e.contains("bad signature") && e.contains(&k.id()), "{e}");
        // Wrong key: same seed family, different identity.
        let other = PublicKey::parse(&public_of(OTHER_SEED).unwrap()).unwrap();
        assert!(verify(&other, b"the package", &sig).is_err());
        // Malformed signature encodings.
        assert!(verify(&k, b"the package", "!!not base64!!").unwrap_err().contains("invalid signature"));
        assert!(verify(&k, b"the package", &b64_encode(&[0u8; 16])).is_err());
        assert!(sign("AAAA", b"x").unwrap_err().contains("32 bytes"));
    }

    #[test]
    fn manifest_digest_is_order_independent_and_content_sensitive() {
        let a = files(&[("SKILL.md", b"hello"), ("references/guide.md", b"world")]);
        let b: BTreeMap<String, Vec<u8>> = [("references/guide.md".to_string(), b"world".to_vec()), ("SKILL.md".to_string(), b"hello".to_vec())].into_iter().collect();
        assert_eq!(manifest_digest(&a), manifest_digest(&b), "insertion order is not content");
        assert!(manifest_digest(&a).starts_with("sha256:"));
        // Sensitivity to content …
        let c = files(&[("SKILL.md", b"hello!"), ("references/guide.md", b"world")]);
        assert_ne!(manifest_digest(&a), manifest_digest(&c));
        // … to a rename (same bytes, different paths) …
        let d = files(&[("SKILL.md", b"hello"), ("references/other.md", b"world")]);
        assert_ne!(manifest_digest(&a), manifest_digest(&d));
        // … and to a missing file.
        let e = files(&[("SKILL.md", b"hello")]);
        assert_ne!(manifest_digest(&a), manifest_digest(&e));
        // The documented encoding: `path NUL hex LF` per file, sorted, LF-terminated.
        assert_eq!(manifest_bytes(&e), format!("SKILL.md\0{}\n", sha256_hex(b"hello")).into_bytes());
        assert!(manifest_digest(&BTreeMap::new()).starts_with("sha256:"));
    }

    #[test]
    fn trust_store_parses_policy_and_refuses_unknown_keys() {
        let pubt = public_of(SEED).unwrap();
        let ts = TrustStore::from_toml(&format!("# acme\n[policy]\nrequire_signature = true\n\n[[key]]\nid = \"acme-release\"\nkey = \"{pubt}\"  # release key\nnote = \"acme hub\"\n")).unwrap();
        assert!(ts.require_signature);
        assert_eq!(ts.keys.len(), 1);
        assert_eq!(ts.keys[0].note, "acme hub");
        let sig = sign(SEED, b"payload").unwrap();
        assert_eq!(ts.verify("acme-release", b"payload", &sig).unwrap().id, "acme-release");
        // Fingerprint and textual form address the same key.
        assert!(ts.verify(&ts.keys[0].key.id(), b"payload", &sig).is_ok());
        assert!(ts.verify(&pubt, b"payload", &sig).is_ok());
        // Unknown key: named in the error, never silently trusted.
        let e = ts.verify("someone-else", b"payload", &sig).unwrap_err();
        assert!(e.contains("someone-else") && e.contains("unknown signing key"), "{e}");
        // Signature that does not match the trusted key.
        let other = sign(OTHER_SEED, b"payload").unwrap();
        assert!(ts.verify("acme-release", b"payload", &other).unwrap_err().contains("bad signature"));
        // Default policy is "signatures welcome, not required" (compatibility).
        assert!(!TrustStore::default().require_signature);
        let plain = TrustStore::from_toml(&format!("[[key]]\nkey = \"{pubt}\"\n")).unwrap();
        assert!(!plain.require_signature);
        assert_eq!(plain.keys[0].id, PublicKey::parse(&pubt).unwrap().id(), "missing id defaults to the fingerprint");
        // Malformed stores fail closed instead of loading an empty keyring.
        assert!(TrustStore::from_toml("[policy]\nrequire_signature = maybe\n").is_err());
        assert!(TrustStore::from_toml("[[key]]\nid = \"x\"\n").unwrap_err().contains("no `key`"));
        assert!(TrustStore::from_toml(&format!("[[key]]\nkey = \"{pubt}\"\n[[key]]\nkey = \"{pubt}\"\n")).unwrap_err().contains("twice"));
    }

    #[test]
    fn load_uses_the_given_path_only() {
        // Self-removing guard (`seagent_core::tmp`): the test never leaves a tree in TMPDIR.
        let d = seagent_core::tmp::TempDir::new("seagent-security-signing");
        let p = TrustStore::default_path(d.path());
        assert!(TrustStore::load(&p).unwrap_err().contains("cannot read trust store"), "no implicit keyring");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, format!("[[key]]\nid = \"acme\"\nkey = \"{}\"\n", public_of(SEED).unwrap())).unwrap();
        assert_eq!(TrustStore::load(&p).unwrap().keys[0].id, "acme");
    }
}
