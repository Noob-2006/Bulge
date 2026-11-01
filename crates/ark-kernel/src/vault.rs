//! Secret vault. Secrets never enter the model context: the model writes
//! `{{secret:NAME}}`, tools substitute at execution time, and any secret value
//! that comes back in tool output is redacted to the placeholder before logging.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

pub struct Vault {
    path: PathBuf,
    secrets: RwLock<BTreeMap<String, String>>,
}

impl std::fmt::Debug for Vault {
    // Never print values.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault").field("names", &self.names()).finish()
    }
}

/// Values shorter than this are not redacted (too many false positives).
const MIN_REDACT_LEN: usize = 6;

impl Vault {
    pub fn empty() -> Self {
        Vault { path: PathBuf::new(), secrets: RwLock::new(BTreeMap::new()) }
    }

    /// Load `secrets.toml` (`NAME = "value"`). Refuses a file readable by others.
    pub fn load(path: &Path) -> Result<Self, String> {
        let mut map = BTreeMap::new();
        if path.exists() {
            let meta = fs::metadata(path).map_err(|e| e.to_string())?;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(format!("{} must not be readable by group/others (chmod 600)", path.display()));
            }
            let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
            let table: toml::Table = text.parse().map_err(|e| format!("{}: {e}", path.display()))?;
            for (k, v) in table {
                match v.as_str() {
                    Some(s) => {
                        map.insert(k, s.to_string());
                    }
                    None => return Err(format!("secret `{k}` must be a string")),
                }
            }
        }
        Ok(Vault { path: path.to_path_buf(), secrets: RwLock::new(map) })
    }

    pub fn names(&self) -> Vec<String> {
        self.secrets.read().unwrap().keys().cloned().collect()
    }

    pub fn set(&self, name: &str, value: &str) -> Result<(), String> {
        if !valid_name(name) {
            return Err("secret names are [A-Za-z0-9_] only".into());
        }
        self.secrets.write().unwrap().insert(name.to_string(), value.to_string());
        self.save()
    }

    pub fn remove(&self, name: &str) -> Result<bool, String> {
        let had = self.secrets.write().unwrap().remove(name).is_some();
        self.save()?;
        Ok(had)
    }

    fn save(&self) -> Result<(), String> {
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }
        let map = self.secrets.read().unwrap();
        let table: toml::Table = map.iter().map(|(k, v)| (k.clone(), toml::Value::String(v.clone()))).collect();
        let text = toml::to_string(&table).map_err(|e| e.to_string())?;
        crate::util::atomic_write(&self.path, text.as_bytes()).map_err(|e| e.to_string())?;
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())
    }

    /// Replace `{{secret:NAME}}` with values. Unknown names are left as-is.
    pub fn substitute(&self, s: &str) -> String {
        if !s.contains("{{secret:") {
            return s.to_string();
        }
        let map = self.secrets.read().unwrap();
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
        let map = self.secrets.read().unwrap();
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
        let map = self.secrets.read().unwrap();
        map.iter().find(|(_, v)| v.len() >= MIN_REDACT_LEN && s.contains(v.as_str())).map(|(k, _)| k.clone())
    }
}

fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("ark-vault-{}", crate::util::random_hex(8)));
        fs::create_dir_all(&d).unwrap();
        d
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
        let v = Vault::load(&p).unwrap();
        v.set("K", "value123").unwrap();
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(Vault::load(&p).unwrap().substitute("{{secret:K}}"), "value123");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Vault::load(&p).unwrap_err().contains("chmod 600"));
    }

    #[test]
    fn rejects_bad_names_and_non_string_values() {
        let v = Vault::empty();
        assert!(v.set("bad name", "x").is_err());
        let d = tmpdir();
        let p = d.join("s.toml");
        fs::write(&p, "N = 5\n").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Vault::load(&p).unwrap_err().contains("must be a string"));
        fs::write(&p, "this is = = not toml").unwrap();
        assert!(Vault::load(&p).is_err());
    }
}
