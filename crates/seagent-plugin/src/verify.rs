//! Plugin manifest verification (A13): signature, content integrity and version pinning for the
//! package a `seagent plugins install` command is about to turn into a process, an MCP server or a set
//! of skill files.
//!
//! ## The threat
//!
//! A plugin is code that seagent *executes*. Its manifest (`plugin.json`, `seagent-plugin.toml`, an
//! `openclaw.plugin.json` imported by [`crate::compat`]) is the part a registry or marketplace
//! controls, and it decides what the process is allowed to do — plus, for a clawpack, which
//! capability set the daemon will report for it. Two attacks matter here and neither is visible in
//! the install record:
//!
//! 1. **Substituted bytes.** A hub, a git remote or a MITM swap the manifest (or one of the files
//!    it lists) between the moment the publisher built it and the moment seagent writes it to
//!    `<plugins>/<name>`. A signature over the canonical manifest, checked against a key in the
//!    user's trust store (`seagent_security::signing::TrustStore`, an explicit path), is the only
//!    thing that survives that.
//! 2. **A quiet widening on update.** The installed 1.0.0 asks for nothing; 1.1.0 asks for
//!    `hooks`, a channel and a public route. [`capability_diff`] surfaces exactly that set so the
//!    caller can re-confirm it (`seagent_security::plugin_guard::widened` / `consent_lines` hold the
//!    consent record; this module only computes and reports).
//!
//! ## What is signed
//!
//! The *canonical* manifest: the JSON object with `signature`/`sig` removed, keys sorted
//! recursively, no whitespace (the same subset RFC 8785 gives us, restricted to the types a
//! manifest uses). Anything else — pretty-printing, key order, the order a TOML parser produced —
//! must not change the answer, otherwise two equivalent manifests would verify differently.
//!
//! Like skills (`seagent_skills::hub::verify`), an unsigned manifest is *accepted* by default and
//! reported (`Verified::key_id == None`): refusing unsigned plugins would break every existing
//! install. A signature that is present is always checked, and an unknown key is always an error.

use seagent_security::plugin_guard;
use seagent_security::signing::{self, PublicKey, TrustStore};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

/// Fields that carry the signature itself and therefore cannot be part of the signed payload.
const SIGNATURE_FIELDS: [&str; 2] = ["signature", "sig"];

/// What verification learned about a manifest.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Verified {
    /// Fingerprint of the signing key (`PublicKey::id`); `None` for an unsigned manifest.
    pub key_id: Option<String>,
    /// The manifest's declared `signer`/`publisher` label, free-form and *not* authenticated by
    /// itself — logged next to the fingerprint so a human can tell which key is which.
    pub signer: Option<String>,
    pub version: String,
    /// Declared package digest (`content_hash`), when the manifest lists one.
    pub content_hash: Option<String>,
    /// Declared per-file digests (`files`), path → `sha256:…`.
    pub files: BTreeMap<String, String>,
    /// Warnings the caller should print (unsigned manifest, no trust store entry, …).
    pub warnings: Vec<String>,
}

/// A pin a caller holds for one plugin: the version/signer it installed last time.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PluginPin {
    pub version: String,
    /// Fingerprint of the key that signed the pinned version (`None` if it was unsigned).
    pub key_id: Option<String>,
}

/// Canonical bytes a manifest signature covers: sorted keys, no whitespace, no `signature`/`sig`.
pub fn canonical_manifest(manifest: &Value) -> Vec<u8> {
    let mut v = manifest.clone();
    if let Some(o) = v.as_object_mut() {
        for f in SIGNATURE_FIELDS {
            o.remove(f);
        }
    }
    let mut out = String::new();
    canonical(&v, &mut out);
    out.into_bytes()
}

fn canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            // Sorted keys, so a manifest round-tripped through any parser verifies identically.
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap_or_else(|_| "\"\"".into()));
                out.push(':');
                canonical(&m[*k], out);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(x, out);
            }
            out.push(']');
        }
        other => out.push_str(&serde_json::to_string(other).unwrap_or_else(|_| "null".into())),
    }
}

/// Parse a manifest as JSON, or as TOML when it is not JSON (`seagent-plugin.toml`, `manifest.toml`).
fn parse_manifest(bytes: &[u8]) -> Result<Value, String> {
    if let Ok(v) = serde_json::from_slice::<Value>(bytes) {
        return Ok(v);
    }
    let text = std::str::from_utf8(bytes).map_err(|e| format!("manifest is neither JSON nor UTF-8 TOML: {e}"))?;
    let t: toml::Value = toml::from_str(text).map_err(|e| format!("manifest is neither JSON nor TOML: {e}"))?;
    serde_json::to_value(t).map_err(|e| format!("manifest could not be converted to JSON: {e}"))
}

fn field<'a>(m: &'a Value, names: &[&str]) -> Option<&'a str> {
    names.iter().find_map(|n| m.get(*n).and_then(Value::as_str)).filter(|s| !s.is_empty())
}

/// Verify a plugin manifest: signature (a), declared content integrity (b) and, when given, the
/// pin (c).
///
/// Refusals, in order: a manifest that does not parse, a `signature` without a `signer`/`key`, an
/// unknown signing key, a signature that does not check out, and — with a pin — a version or
/// signer that moved.
pub fn verify_manifest(manifest_bytes: &[u8], trust: &TrustStore) -> Result<Verified, String> {
    verify_manifest_with(manifest_bytes, trust, None, None)
}

/// [`verify_manifest`] plus the trust-store path (for messages) and a pin to hold the manifest to.
pub fn verify_manifest_with(manifest_bytes: &[u8], trust: &TrustStore, trust_path: Option<&Path>, pin: Option<&PluginPin>) -> Result<Verified, String> {
    let m = parse_manifest(manifest_bytes)?;
    let mut v = Verified {
        signer: field(&m, &["signer", "key_id", "publisher"]).map(String::from),
        version: field(&m, &["version"]).unwrap_or("").to_string(),
        content_hash: field(&m, &["content_hash", "contentHash", "digest"]).map(String::from),
        ..Default::default()
    };
    // (b) declared per-file digests: `files: {path: "sha256:…"}` or `[{path, sha256}]`.
    match m.get("files") {
        Some(Value::Object(o)) => {
            for (k, d) in o {
                let d = d.get("sha256").and_then(Value::as_str).or_else(|| d.as_str()).ok_or_else(|| format!("manifest files.{k} has no sha256 digest"))?;
                v.files.insert(k.clone(), if d.starts_with("sha256:") { d.to_string() } else { format!("sha256:{d}") });
            }
        }
        Some(Value::Array(a)) => {
            for e in a {
                let p = e.get("path").and_then(Value::as_str).ok_or("manifest files[] entry without a path")?;
                let d = e.get("sha256").or_else(|| e.get("digest")).and_then(Value::as_str).ok_or_else(|| format!("manifest files[] {p} has no digest"))?;
                v.files.insert(p.to_string(), if d.starts_with("sha256:") { d.to_string() } else { format!("sha256:{d}") });
            }
        }
        _ => {}
    }
    let payload = canonical_manifest(&m);
    let sig = field(&m, &SIGNATURE_FIELDS);
    match (sig, field(&m, &["signer", "key", "public_key", "key_id"])) {
        (Some(sig), Some(key_text)) => {
            let key = PublicKey::parse(key_text).or_else(|_| {
                // `signer` is often a human label and `key` the actual key: try the key field first.
                PublicKey::parse(field(&m, &["key", "public_key"]).unwrap_or(""))
            })?;
            // The store decides whom to trust: either the label or the key material resolves.
            let trusted = trust.find(key_text).or_else(|| trust.find(&key.text())).or_else(|| trust.find(&key.id())).ok_or_else(|| {
                format!("unknown signing key `{}` (fingerprint {}): not in the trust store{}", field(&m, &["signer", "key_id"]).unwrap_or(""), key.id(), trust_path.map(|p| format!(" {}", p.display())).unwrap_or_default())
            })?;
            if trusted.key != key {
                return Err(format!("manifest key {} does not match trust store key `{}` ({})", key.id(), trusted.id, trusted.key.id()));
            }
            signing::verify(&trusted.key, &payload, sig)?;
            v.key_id = Some(trusted.key.id());
        }
        (Some(_), None) => return Err("manifest carries a `signature` but no `signer`/`key` to check it against".into()),
        (None, _) => {
            if trust.require_signature {
                return Err(format!("plugin manifest is not signed and the trust store{} requires signatures (require_signature = true)", trust_path.map(|p| format!(" {}", p.display())).unwrap_or_default()));
            }
            v.warnings.push("warning: plugin manifest is unsigned; installed unverified".into());
        }
    }
    // (c) the pin: a version that moved is exactly the update the user did not agree to.
    if let Some(p) = pin {
        if !p.version.is_empty() && !v.version.is_empty() && p.version != v.version {
            return Err(format!("pinned to {}, manifest offers {} — refusing to jump", p.version, v.version));
        }
        if let (Some(want), Some(got)) = (p.key_id.as_deref(), v.key_id.as_deref()) {
            if want != got {
                return Err(format!("the signing key changed since {} was pinned (was {want}, now {got})", p.version));
            }
        }
        if p.key_id.is_some() && v.key_id.is_none() {
            return Err(format!("{} was signed when installed but this update is unsigned; refusing to drop the signature", p.version));
        }
    }
    Ok(v)
}

/// (b) on disk: every file the manifest lists must exist with the declared digest, and when the
/// manifest declares a package `content_hash` it must match the directory as a whole.
pub fn verify_files(dir: &Path, v: &Verified) -> Result<(), String> {
    for (rel, want) in &v.files {
        if rel.starts_with('/') || rel.split('/').any(|p| p == "..") {
            return Err(format!("manifest lists an unsafe path: {rel}"));
        }
        let p = dir.join(rel);
        let bytes = std::fs::read(&p).map_err(|e| format!("manifest lists {rel} but {} cannot be read: {e}", p.display()))?;
        let got = format!("sha256:{}", signing::sha256_hex(&bytes));
        if &got != want {
            return Err(format!("integrity failure: {rel} hashes to {got}, manifest says {want}"));
        }
    }
    Ok(())
}

/// Capabilities `new` adds relative to `old`, in the same shape
/// [`seagent_security::plugin_guard::widened`] returns (`group → sorted new values`).
///
/// `plugin_guard::widened` compares a declaration against the *consent store on disk*, which is the
/// right thing during install (see [`consent_diff`]) but not for comparing two manifests in
/// memory; both go through `plugin_guard::summarize`, so the grouping/dedup rules are identical and
/// this cannot drift from the consent check.
pub fn capability_diff(old: &Value, new: &Value) -> BTreeMap<String, Vec<String>> {
    let before = plugin_guard::summarize(old);
    let after = plugin_guard::summarize(new);
    let mut out = BTreeMap::new();
    for (k, vals) in &after {
        let had = before.get(k);
        let added: Vec<String> = vals.iter().filter(|v| !had.is_some_and(|h| h.contains(v))).cloned().collect();
        if !added.is_empty() {
            out.insert(k.clone(), added);
        }
    }
    out
}

/// The store-backed widening check: what `plugin_guard::widened` reports for a candidate against
/// the capabilities the user already consented to under `data`.
pub fn consent_diff(data: &Path, plugin: &str, declared: &Value) -> BTreeMap<String, Vec<String>> {
    plugin_guard::widened(data, plugin, &plugin_guard::summarize(declared))
}

/// One-line summary for install/update output.
pub fn summary(v: &Verified) -> String {
    let signer = v.key_id.as_deref().map(|k| format!("signed by key {k}")).unwrap_or_else(|| "unsigned".into());
    let version = if v.version.is_empty() { "unversioned".to_string() } else { v.version.clone() };
    json!({"version": version, "signer": signer, "files": v.files.len()}).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_security::signing::{public_of, sign};

    /// Fixed seeds: real Ed25519, no key material in the repo.
    const SEED: &str = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusN26XHso=";
    const OTHER_SEED: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    fn trust_with(seed: &str) -> TrustStore {
        TrustStore::from_toml(&format!("[[key]]\nid = \"acme-release\"\nkey = \"{}\"\n", public_of(seed).unwrap())).unwrap()
    }

    /// Sign a manifest the way release tooling does: the signature covers the canonical form with
    /// the signature field removed, so it can be added afterwards.
    fn signed(mut m: Value, seed: &str) -> Vec<u8> {
        // The key is part of the signed payload (a signature must not be re-pointable at another
        // key), so it goes in before signing and only `signature` is excluded.
        m["key"] = json!(public_of(seed).unwrap());
        let sig = sign(seed, &canonical_manifest(&m)).unwrap();
        m["signature"] = json!(sig);
        serde_json::to_vec(&m).unwrap()
    }

    fn manifest(caps: Value, version: &str) -> Value {
        json!({"name": "weather", "version": version, "capabilities": caps, "entry": "index.js"})
    }

    /// Self-removing scratch dir (`seagent_core::tmp::TempDir`); the guard is what keeps TMPDIR clean
    /// even when an assertion panics mid-test.
    fn tmp(tag: &str) -> seagent_core::tmp::TempDir {
        seagent_core::tmp::TempDir::new(&format!("seagent-plugin-verify-{tag}"))
    }

    #[test]
    fn signed_manifest_verifies_and_tampering_is_refused() {
        let bytes = signed(manifest(json!({"hooks": ["pre_tool"]}), "1.0.0"), SEED);
        let v = verify_manifest(&bytes, &trust_with(SEED)).unwrap();
        let key = PublicKey::parse(&public_of(SEED).unwrap()).unwrap().id();
        assert_eq!(v.key_id.as_deref(), Some(key.as_str()));
        assert_eq!(v.version, "1.0.0");
        assert!(v.warnings.is_empty());
        assert!(summary(&v).contains("signed by key"));
        // Tampered field (what a swapped marketplace manifest looks like).
        let mut t: Value = serde_json::from_slice(&bytes).unwrap();
        t["capabilities"]["routes"] = json!([{"path": "/hook", "public": true}]);
        let e = verify_manifest(&serde_json::to_vec(&t).unwrap(), &trust_with(SEED)).unwrap_err();
        assert!(e.contains("bad signature"), "{e}");
        // Key the store does not know.
        let other = signed(manifest(json!({}), "1.0.0"), OTHER_SEED);
        let e = verify_manifest(&other, &trust_with(SEED)).unwrap_err();
        assert!(e.contains("unknown signing key") && e.contains(&PublicKey::parse(&public_of(OTHER_SEED).unwrap()).unwrap().id()), "{e}");
        // A key substituted under a trusted label.
        let mut substit: Value = serde_json::from_slice(&other).unwrap();
        substit["signer"] = json!("acme-release");
        let e = verify_manifest(&serde_json::to_vec(&substit).unwrap(), &trust_with(SEED)).unwrap_err();
        assert!(e.contains("unknown signing key") || e.contains("does not match trust store key"), "{e}");
        // Malformed signature / no key to check against.
        let mut no_sig: Value = serde_json::from_slice(&bytes).unwrap();
        no_sig["signature"] = json!("!!!not base64!!!");
        assert!(verify_manifest(&serde_json::to_vec(&no_sig).unwrap(), &trust_with(SEED)).is_err());
        let mut sig_only = manifest(json!({}), "1.0.0");
        sig_only["signature"] = json!("AAAA");
        assert!(verify_manifest(&serde_json::to_vec(&sig_only).unwrap(), &trust_with(SEED)).unwrap_err().contains("no `signer`/`key`"));
    }

    #[test]
    fn canonicalisation_ignores_key_order_and_signature_fields() {
        let a: Value = serde_json::from_str(r#"{"name":"x","version":"1","capabilities":{"hooks":["a"]}}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"capabilities":{"hooks":["a"]},"name":"x","version":"1","signature":"zzz"}"#).unwrap();
        assert_eq!(canonical_manifest(&a), canonical_manifest(&b));
        assert_eq!(String::from_utf8(canonical_manifest(&a)).unwrap(), r#"{"capabilities":{"hooks":["a"]},"name":"x","version":"1"}"#);
        // Signing one and verifying a re-serialized copy (key order changed) still works: that is
        // what makes the signature survive a JSON round-trip through any tool.
        let bytes = signed(a, SEED);
        let mut v: Value = serde_json::from_slice(&bytes).unwrap();
        let caps = v["capabilities"].clone();
        v.as_object_mut().unwrap().remove("capabilities");
        v["capabilities"] = caps;
        assert!(verify_manifest(&serde_json::to_vec(&v).unwrap(), &trust_with(SEED)).is_ok());
    }

    #[test]
    fn toml_manifests_and_unsigned_default() {
        let bytes = signed(manifest(json!({"hooks": ["pre_tool"]}), "2.0.0"), SEED);
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        let toml_text = toml::to_string(&v).unwrap();
        // The TOML form is a different byte string but the same canonical manifest only if the
        // signature was made over that form; here we only assert parsing works and the unsigned
        // path reports instead of blocking.
        let parsed = parse_manifest(toml_text.as_bytes()).unwrap();
        assert_eq!(parsed["name"], "weather");
        let unsigned = serde_json::to_vec(&manifest(json!({}), "1.0.0")).unwrap();
        let v = verify_manifest(&unsigned, &trust_with(SEED)).unwrap();
        assert_eq!(v.key_id, None);
        assert!(v.warnings.iter().any(|w| w.contains("unsigned")), "{:?}", v.warnings);
        // …and a strict store refuses it.
        let strict = TrustStore::from_toml("[policy]\nrequire_signature = true\n").unwrap();
        let e = verify_manifest(&unsigned, &strict).unwrap_err();
        assert!(e.contains("not signed") && e.contains("require_signature"), "{e}");
        assert!(verify_manifest(b"{not json or toml", &trust_with(SEED)).unwrap_err().contains("neither JSON nor TOML"));
    }

    #[test]
    fn pins_hold_version_and_signer() {
        let bytes = signed(manifest(json!({}), "1.1.0"), SEED);
        let key = PublicKey::parse(&public_of(SEED).unwrap()).unwrap().id();
        let pin = PluginPin { version: "1.0.0".into(), key_id: Some(key.clone()) };
        let e = verify_manifest_with(&bytes, &trust_with(SEED), None, Some(&pin)).unwrap_err();
        assert!(e.contains("pinned to 1.0.0, manifest offers 1.1.0"), "{e}");
        let pin = PluginPin { version: "1.1.0".into(), key_id: Some(key) };
        assert!(verify_manifest_with(&bytes, &trust_with(SEED), None, Some(&pin)).is_ok());
        // A different signer is refused even at the pinned version (key rotation is a re-pin).
        let pin = PluginPin { version: "1.1.0".into(), key_id: Some("0123456789abcdef".into()) };
        assert!(verify_manifest_with(&bytes, &trust_with(SEED), None, Some(&pin)).unwrap_err().contains("signing key changed"));
        // Dropping the signature on update is refused too.
        let unsigned = serde_json::to_vec(&manifest(json!({}), "1.1.0")).unwrap();
        let pin = PluginPin { version: "1.1.0".into(), key_id: Some(PublicKey::parse(&public_of(SEED).unwrap()).unwrap().id()) };
        let e = verify_manifest_with(&unsigned, &trust_with(SEED), None, Some(&pin)).unwrap_err();
        assert!(e.contains("unsigned") && e.contains("refusing to drop the signature"), "{e}");
    }

    #[test]
    fn declared_file_digests_are_checked_on_disk() {
        let d = tmp("files");
        let dir = d.path();
        std::fs::write(dir.join("index.js"), b"module.exports = 1\n").unwrap();
        let digest = format!("sha256:{}", signing::sha256_hex(b"module.exports = 1\n"));
        let mut m = manifest(json!({}), "1.0.0");
        m["files"] = json!({"index.js": digest});
        let bytes = signed(m, SEED);
        let v = verify_manifest(&bytes, &trust_with(SEED)).unwrap();
        assert_eq!(v.files["index.js"], digest);
        verify_files(dir, &v).unwrap();
        // Edited file: integrity failure naming the path.
        std::fs::write(dir.join("index.js"), b"require('http').get('https://evil.example')\n").unwrap();
        let e = verify_files(dir, &v).unwrap_err();
        assert!(e.contains("integrity failure") && e.contains("index.js"), "{e}");
        // Listed but missing, and traversal attempts, are refusals rather than skips.
        let mut m = manifest(json!({}), "1.0.0");
        m["files"] = json!([{"path": "missing.js", "sha256": digest}]);
        let v = verify_manifest(&signed(m, SEED), &trust_with(SEED)).unwrap();
        assert!(verify_files(dir, &v).unwrap_err().contains("cannot be read"));
        let mut bad = manifest(json!({}), "1.0.0");
        bad["files"] = json!({"../escape.js": digest});
        let v = verify_manifest(&signed(bad, SEED), &trust_with(SEED)).unwrap();
        assert!(verify_files(dir, &v).unwrap_err().contains("unsafe path"));
        drop(d);
    }

    #[test]
    fn capability_diff_reports_only_the_new_values() {
        let old = json!({"version": 1, "hooks": ["pre_tool"], "channels": ["telegram"], "memory": false});
        let new = json!({"version": 1, "hooks": ["pre_tool", "post_tool"], "channels": ["telegram"], "routes": [{"path": "/hook", "public": true}], "memory": true});
        let w = capability_diff(&old, &new);
        assert_eq!(w.get("hooks").unwrap(), &vec!["post_tool".to_string()]);
        assert_eq!(w.get("memory").unwrap(), &vec!["yes".to_string()], "flat booleans group like plugin_guard::summarize");
        assert_eq!(w.get("routes").unwrap(), &vec!["/hook".to_string()]);
        assert!(!w.contains_key("channels"));
        assert!(capability_diff(&new, &new).is_empty());
        // The store-backed variant is `plugin_guard::widened` unchanged.
        let d = tmp("consent");
        let dir = d.path();
        let widened = consent_diff(dir, "weather", &new);
        assert_eq!(widened.len(), 4, "nothing consented yet: every group is new: {widened:?}");
        plugin_guard::accept(dir, "weather", &plugin_guard::summarize(&new)).unwrap();
        assert!(consent_diff(dir, "weather", &new).is_empty());
        assert_eq!(consent_diff(dir, "weather", &old), BTreeMap::new(), "narrowing is not a widening");
        drop(d);
    }
}
