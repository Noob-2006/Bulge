//! Secret vault. Secrets never enter the model context: the model writes
//! `{{secret:NAME}}`, tools substitute at execution time, and any secret value
//! that comes back in tool output is redacted to the placeholder before logging.
//!
//! Storage is [`crate::secretstore`]'s job (A4): the vault is the in-process face of it —
//! the daemon owns one, the VM and the broker never see a plaintext value, and the bytes on
//! disk are ciphertext whenever a key source exists.

use crate::secretstore::{Backend, Options, Status, Store};
use std::path::Path;
use std::sync::RwLock;

pub struct Vault {
    store: RwLock<Store>,
}

impl std::fmt::Debug for Vault {
    // Never print values.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault").field("names", &self.names()).field("storage", &self.store.read().map(|s| s.backend().as_str()).unwrap_or("?")).finish()
    }
}

/// Values shorter than this are not redacted (too many false positives).
const MIN_REDACT_LEN: usize = 6;

impl Vault {
    pub fn empty() -> Self {
        Vault { store: RwLock::new(Store::in_memory()) }
    }

    /// Load the store that belongs to `secrets.toml`. An encrypted `secrets.enc` next to it is
    /// opened with the backend recorded in its header; a plaintext file is migrated when a key
    /// source is available (see [`secretstore`]).
    pub fn load(path: &Path) -> Result<Self, String> {
        Self::load_with(path, &Options::from_env())
    }

    /// Same, with explicit key material: tests and daemons that pass a credential in memory.
    pub fn load_with(path: &Path, opts: &Options) -> Result<Self, String> {
        Ok(Vault { store: RwLock::new(Store::open(path, opts)?) })
    }

    pub fn names(&self) -> Vec<String> {
        self.store.read().map(|s| s.names()).unwrap_or_default()
    }

    /// Which backend holds the secrets, and any note worth telling the operator (a migration,
    /// a plaintext fallback, a keyring entry that could not be written).
    pub fn status(&self) -> Status {
        self.store.read().map(|s| s.status()).unwrap_or_else(|_| Status { path: std::path::PathBuf::new(), backend: Backend::Plaintext, legacy_present: false, secrets: 0, notes: vec![] })
    }

    pub fn backend(&self) -> Backend {
        self.store.read().map(|s| s.backend()).unwrap_or(Backend::Plaintext)
    }

    pub fn set(&self, name: &str, value: &str) -> Result<(), String> {
        self.store.write().map_err(|_| "the vault lock is poisoned".to_string())?.set(name, value)
    }

    pub fn remove(&self, name: &str) -> Result<bool, String> {
        self.store.write().map_err(|_| "the vault lock is poisoned".to_string())?.remove(name)
    }

    /// Replace `{{secret:NAME}}` with values. Unknown names are left as-is.
    pub fn substitute(&self, s: &str) -> String {
        if !s.contains("{{secret:") {
            return s.to_string();
        }
        let guard = match self.store.read() {
            Ok(g) => g,
            Err(_) => return s.to_string(),
        };
        let map = guard.map();
        let mut out = String::with_capacity(s.len());
        let mut rest = s;
        while let Some(i) = rest.find("{{secret:") {
            out.push_str(&rest[..i]);
            let after = &rest[i + 9..];
            match after.find("}}") {
                Some(j) if map.contains_key(&after[..j]) => {
                    out.push_str(&map[&after[..j]]);
                    rest = &after[j + 2..];
                }
                _ => {
                    out.push_str("{{secret:");
                    rest = after;
                }
            }
        }
        out.push_str(rest);
        out
    }

    /// Replace any secret value with its placeholder.
    pub fn redact(&self, s: &str) -> String {
        let guard = match self.store.read() {
            Ok(g) => g,
            Err(_) => return s.to_string(),
        };
        let map = guard.map();
        let mut out = s.to_string();
        // Longest first so a secret containing another is redacted whole.
        let mut pairs: Vec<_> = map.iter().filter(|(_, v)| v.len() >= MIN_REDACT_LEN).collect();
        pairs.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));
        for (k, v) in pairs {
            if out.contains(v.as_str()) {
                out = out.replace(v.as_str(), &format!("{{{{secret:{k}}}}}"));
            }
        }
        out
    }

    /// Does `s` contain a secret value (for the egress gate)?
    pub fn leaks(&self, s: &str) -> Option<String> {
        let guard = self.store.read().ok()?;
        guard.map().iter().find(|(_, v)| v.len() >= MIN_REDACT_LEN && s.contains(v.as_str())).map(|(k, _)| k.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    /// Self-removing scratch dir (`ark-vault-*` used to be left behind on every run). Callers keep
    /// the returned guard in scope; it derefs to `Path`, so `d.join(..)` keeps working.
    fn tmpdir() -> ark_core::tmp::TempDir {
        ark_core::tmp::TempDir::new("ark-vault")
    }

    /// The pre-A4 behaviour, pinned explicitly: no key source, plaintext 0600.
    fn plaintext_opts() -> Options {
        Options { backend: Some(Backend::Plaintext), ..Default::default() }
    }

    fn env_opts() -> Options {
        Options { backend: Some(Backend::Env), key: Some([7u8; 32]), ..Default::default() }
    }

    #[test]
    fn substitute_redact_roundtrip() {
        let v = Vault::empty();
        v.set("GH", "ghp_abcdef123456").unwrap();
        v.set("SHORT", "abc").unwrap();
        let cmd = "curl -H 'Authorization: {{secret:GH}}' {{secret:NOPE}} {{secret:GH";
        let run = v.substitute(cmd);
        assert!(run.contains("ghp_abcdef123456"));
        assert!(run.contains("{{secret:NOPE}}"), "unknown names untouched");
        assert!(run.ends_with("{{secret:GH"), "unterminated placeholder untouched");
        assert_eq!(v.redact("token=ghp_abcdef123456 abc"), "token={{secret:GH}} abc");
        assert_eq!(v.leaks("x ghp_abcdef123456"), Some("GH".into()));
        assert_eq!(v.leaks("abc"), None, "short values never match");
    }

    #[test]
    fn overlapping_secrets_redact_longest_first() {
        let v = Vault::empty();
        v.set("A", "secret12").unwrap();
        v.set("B", "secret12345").unwrap();
        assert_eq!(v.redact("secret12345"), "{{secret:B}}");
    }

    #[test]
    fn persists_with_0600_and_rejects_world_readable() {
        let d = tmpdir();
        let p = d.join("secrets.toml");
        let v = Vault::load_with(&p, &plaintext_opts()).unwrap();
        v.set("K", "value123").unwrap();
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(Vault::load_with(&p, &plaintext_opts()).unwrap().substitute("{{secret:K}}"), "value123");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Vault::load_with(&p, &plaintext_opts()).unwrap_err().contains("chmod 600"));
    }

    #[test]
    fn encrypted_store_keeps_no_plaintext_value_on_disk() {
        let d = tmpdir();
        let p = d.join("secrets.toml");
        let v = Vault::load_with(&p, &env_opts()).unwrap();
        v.set("GITHUB_TOKEN", "ghp_plain_value_123").unwrap();
        let enc = d.join("secrets.enc");
        let body = fs::read(&enc).unwrap();
        assert!(!body.windows(6).any(|w| w == b"GITHUB"), "the name is ciphertext too");
        assert!(!body.windows(6).any(|w| w == b"ghp_pl"));
        assert!(!p.exists(), "no plaintext file is created");
        assert_eq!(fs::metadata(&enc).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(v.backend(), Backend::Env);
        // A second process with the same key reads it back.
        let again = Vault::load_with(&p, &env_opts()).unwrap();
        assert_eq!(again.substitute("{{secret:GITHUB_TOKEN}}"), "ghp_plain_value_123");
        assert_eq!(again.status().backend, Backend::Env);
    }

    #[test]
    fn a_plaintext_file_is_migrated_and_removed() {
        let d = tmpdir();
        let p = d.join("secrets.toml");
        fs::write(&p, "A = \"value-a\"\nB = \"value-b\"\n").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        let v = Vault::load_with(&p, &env_opts()).unwrap();
        assert_eq!(v.names(), vec!["A".to_string(), "B".to_string()]);
        assert!(!p.exists(), "the plaintext file is shredded and removed");
        assert!(v.status().notes.iter().any(|n| n.contains("migrated")), "{:?}", v.status().notes);
        assert!(fs::read(d.join("secrets.enc")).is_ok());
        assert_eq!(Vault::load_with(&p, &env_opts()).unwrap().substitute("{{secret:B}}"), "value-b");
    }

    #[test]
    fn a_wrong_key_is_refused_and_says_so() {
        let d = tmpdir();
        let p = d.join("secrets.toml");
        Vault::load_with(&p, &env_opts()).unwrap().set("K", "value123").unwrap();
        let other = Options { backend: Some(Backend::Env), key: Some([9u8; 32]), ..Default::default() };
        let e = Vault::load_with(&p, &other).unwrap_err();
        assert!(e.contains("wrong key"), "{e}");
        // A missing key names the variable instead of failing cryptically.
        let none = Vault::load_with(&p, &Options { backend: Some(Backend::Env), ..Default::default() }).unwrap_err();
        assert!(none.contains("ARK_VAULT_KEY"), "{none}");
    }

    #[test]
    fn rejects_bad_names_and_non_string_values() {
        let v = Vault::empty();
        assert!(v.set("bad name", "x").is_err());
        let d = tmpdir();
        let p = d.join("s.toml");
        fs::write(&p, "N = 5\n").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Vault::load_with(&p, &plaintext_opts()).unwrap_err().contains("must be a string"));
        fs::write(&p, "this is = = not toml").unwrap();
        assert!(Vault::load_with(&p, &plaintext_opts()).is_err());
    }

    #[test]
    fn empty_vault_never_touches_disk() {
        let v = Vault::empty();
        v.set("K", "value123").unwrap();
        assert_eq!(v.names(), vec!["K"]);
        assert_eq!(v.status().path.as_os_str().len(), 0);
    }
}
