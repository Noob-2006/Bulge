//! System-managed configuration (ent-063, with ent-064…068 and ent-089 as its payload).
//!
//! An administrator puts organisation policy in `/etc/ark/managed.toml` (and/or drop-ins in
//! `/etc/ark/managed.d/*.toml`, applied in name order). Everything in those files is a
//! **default** underneath the user and project layers, except the keys listed in
//! `[managed] locked`: those are forced back to the system value after every other layer
//! (user file, project file, `--set`) has been merged, so nobody below can change them.
//!
//! ```toml
//! # /etc/ark/managed.toml  (root-owned, 0644)
//! [managed]
//! locked = [
//!   "approvals.preset", "approvals.mode",          # risk levels         (ent-064)
//!   "envelopes",                                    # task-envelope limits (ent-065)
//!   "model.allow",                                  # approved models     (ent-066 / ent-089)
//!   "tools.deny", "tools.disabled",                 # tool policy         (ent-067)
//!   "gate.egress_allow", "gate.egress_deny",        # egress hosts        (ent-068)
//!   "audit", "compliance",
//! ]
//! [model]
//! allow = ["anthropic/*", "local/*"]
//! [gate]
//! egress_allow = ["api.anthropic.com", "*.corp.example"]
//! ```
//!
//! A locked key that the system file does not set is locked to the built-in default (the
//! lower layers' value is removed). The system files must be owned by root and not writable
//! by group/other; anything else is refused (a policy file the user can edit is no policy).
//! `/etc/ark` always wins; `ARK_SYSTEM_CONFIG` is consulted only when `/etc/ark` holds no
//! policy at all (tests, packaging checks), so setting it can never weaken a real install.

use std::path::{Path, PathBuf};

pub const SYSTEM_DIR: &str = "/etc/ark";

/// What the system layer contributed, for `ark config managed` / `config.managed`.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct Managed {
    /// Files read, in order.
    pub files: Vec<String>,
    /// `[managed] locked` keys.
    pub locked: Vec<String>,
    /// Locked keys a lower layer tried to change (and lost).
    pub overridden: Vec<String>,
}

impl Managed {
    pub fn active(&self) -> bool {
        !self.files.is_empty()
    }
    /// Is `key` (dotted) locked, either itself or through a locked parent table?
    pub fn is_locked(&self, key: &str) -> bool {
        self.locked.iter().any(|l| key == l || key.starts_with(&format!("{l}.")) || l.starts_with(&format!("{key}.")))
    }
}

/// The system policy files, in application order.
pub fn system_files() -> Vec<PathBuf> {
    let from_dir = files_in(Path::new(SYSTEM_DIR));
    if !from_dir.is_empty() {
        return from_dir;
    }
    match std::env::var_os("ARK_SYSTEM_CONFIG").map(PathBuf::from) {
        Some(p) if p.is_dir() => files_in(&p),
        Some(p) if p.is_file() => vec![p],
        _ => vec![],
    }
}

fn files_in(dir: &Path) -> Vec<PathBuf> {
    let mut v = vec![];
    let main = dir.join("managed.toml");
    if main.is_file() {
        v.push(main);
    }
    if let Ok(rd) = std::fs::read_dir(dir.join("managed.d")) {
        let mut d: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "toml")).collect();
        d.sort();
        v.extend(d);
    }
    v
}

/// Refuse a policy file a non-root user could have written. Only enforced for `/etc/ark`.
fn check_owner(p: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if !p.starts_with(SYSTEM_DIR) {
        return Ok(());
    }
    let m = std::fs::metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
    if m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err(format!("{}: managed policy must be owned by root and not group/world-writable", p.display()));
    }
    Ok(())
}

/// Read and merge the system files: `(defaults table, locked keys, files)`.
pub fn load_system(files: &[PathBuf]) -> Result<(toml::Table, Vec<String>, Vec<String>), String> {
    let mut merged = toml::Table::new();
    let mut locked: Vec<String> = vec![];
    let mut names = vec![];
    for p in files {
        check_owner(p)?;
        let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
        let mut t: toml::Table = text.parse().map_err(|e| format!("{}: {e}", p.display()))?;
        if let Some(m) = t.remove("managed") {
            let m = m.as_table().cloned().unwrap_or_default();
            for k in m.keys() {
                if k != "locked" {
                    return Err(format!("{}: unknown key `managed.{k}` (expected `locked`)", p.display()));
                }
            }
            for v in m.get("locked").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
                let k = v.as_str().ok_or_else(|| format!("{}: managed.locked holds strings", p.display()))?.trim().to_string();
                if k.is_empty() || k.split('.').any(str::is_empty) {
                    return Err(format!("{}: bad locked key `{k}`", p.display()));
                }
                if !locked.contains(&k) {
                    locked.push(k);
                }
            }
        }
        crate::config::merge_tables(&mut merged, t);
        names.push(p.display().to_string());
    }
    Ok((merged, locked, names))
}

fn get<'a>(t: &'a toml::Table, path: &str) -> Option<&'a toml::Value> {
    let mut parts = path.split('.');
    let mut cur = t.get(parts.next()?)?;
    for p in parts {
        cur = cur.as_table()?.get(p)?;
    }
    Some(cur)
}

fn set_at(t: &mut toml::Table, parts: &[&str], v: Option<toml::Value>) {
    let (first, rest) = (parts[0], &parts[1..]);
    if rest.is_empty() {
        match v {
            Some(v) => {
                t.insert(first.to_string(), v);
            }
            None => {
                t.remove(first);
            }
        }
        return;
    }
    if !t.get(first).is_some_and(|x| x.is_table()) {
        if v.is_none() {
            return;
        }
        t.insert(first.to_string(), toml::Value::Table(toml::Table::new()));
    }
    if let Some(sub) = t.get_mut(first).and_then(|x| x.as_table_mut()) {
        set_at(sub, rest, v);
    }
}

/// Force every locked key in `merged` back to the system value (or remove it). Returns the
/// keys whose value a lower layer had changed.
pub fn enforce(merged: &mut toml::Table, system: &toml::Table, locked: &[String]) -> Vec<String> {
    let mut overridden = vec![];
    for key in locked {
        let want = get(system, key).cloned();
        let have = get(merged, key).cloned();
        if want == have {
            continue;
        }
        overridden.push(key.clone());
        let parts: Vec<&str> = key.split('.').collect();
        set_at(merged, &parts, want);
    }
    overridden
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> toml::Table {
        s.parse().unwrap()
    }

    #[test]
    fn locks_force_system_values_and_remove_unset_ones() {
        let sys = t("[model]\nallow = [\"anthropic/*\"]\n[gate]\negress_allow = [\"api.anthropic.com\"]\n");
        let mut merged = t("[model]\nallow = [\"*\"]\ndefault = \"x/y\"\n[gate]\negress_allow = [\"evil.example\"]\n[tools]\ndeny = []\n");
        let over = enforce(&mut merged, &sys, &["model.allow".into(), "gate.egress_allow".into(), "tools.deny".into(), "approvals.preset".into()]);
        assert_eq!(over, vec!["model.allow", "gate.egress_allow", "tools.deny"]);
        assert_eq!(get(&merged, "model.allow"), get(&sys, "model.allow"));
        assert_eq!(get(&merged, "model.default").unwrap().as_str(), Some("x/y"), "unlocked keys stay the user's");
        assert!(get(&merged, "tools.deny").is_none(), "locked but unset in system → built-in default");
        let m = Managed { files: vec!["x".into()], locked: vec!["gate".into(), "model.allow".into()], overridden: vec![] };
        assert!(m.is_locked("gate.egress_allow") && m.is_locked("model.allow") && m.is_locked("model") && !m.is_locked("model.default"));
    }

    #[test]
    fn system_layer_defaults_and_locks_through_config_load() {
        let d = ark_core::tmp::TempDir::new("ark-managed");
        let sys = d.path().join("managed.toml");
        std::fs::write(&sys, "[managed]\nlocked = [\"model.allow\", \"gate.egress_allow\", \"approvals.preset\", \"tools.deny\"]\n[model]\nallow = [\"anthropic/*\"]\ndefault = \"anthropic/claude-sonnet-5-5\"\n[gate]\negress_allow = [\"api.anthropic.com\"]\n[tools]\ndeny = [\"browser\"]\n").unwrap();
        let drop_in = d.path().join("managed.d");
        std::fs::create_dir_all(&drop_in).unwrap();
        std::fs::write(drop_in.join("10-audit.toml"), "[managed]\nlocked = [\"audit.log_reads\"]\n[audit]\nlog_reads = true\n").unwrap();
        let user = d.path().join("user.toml");
        std::fs::write(&user, "[model]\nallow = [\"*\"]\ndefault = \"anthropic/claude-opus-5\"\n[gate]\negress_allow = [\"evil.example\"]\n[tools]\ndeny = []\n[audit]\nlog_reads = false\n").unwrap();
        let files = files_in(d.path());
        assert_eq!(files.len(), 2);
        let c = crate::config::Config::load_with_system(&files, Some(&user), None, &["model.allow=[\"x/*\"]".into()]).unwrap();
        assert_eq!(c.model.allow, vec!["anthropic/*"], "neither the user file nor --set can widen a locked list");
        assert_eq!(c.gate.egress_allow, vec!["api.anthropic.com"]);
        assert_eq!(c.tools.deny, vec!["browser"]);
        assert!(c.audit.log_reads, "a drop-in locks its own keys");
        assert_eq!(c.model.default, "anthropic/claude-opus-5", "unlocked keys stay with the user");
        assert!(c.managed.active() && c.managed.is_locked("gate.egress_allow"));
        assert!(c.managed.overridden.contains(&"model.allow".to_string()));
        // Without a system layer nothing is locked.
        let c = crate::config::Config::load_with_system(&[], Some(&user), None, &[]).unwrap();
        assert!(!c.managed.active() && c.model.allow == vec!["*"]);
        // A malformed [managed] table is an error, not a silent no-op.
        std::fs::write(&sys, "[managed]\nlock = [\"x\"]\n").unwrap();
        assert!(crate::config::Config::load_with_system(&[sys], None, None, &[]).unwrap_err().contains("managed.lock"));
    }
}
