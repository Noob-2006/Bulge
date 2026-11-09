//! Memory provider migration (Hermes hermes_cli/memory_provider_migration.py,
//! profile_memory_config.py, profiles_honcho.py, MIT):
//! - check the configured `[memory] provider`: builtin, bundled (byterover / retaindb), an
//!   installed plugin, or missing → install hint with exponential retry backoff stamps;
//! - copy a provider's own config (`<home>/<provider>/`, `<home>/<provider>.json`) between
//!   profiles, owner-only;
//! - rename Honcho host blocks (`hermes_<old>` → `hermes_<new>`) in honcho.json files;
//! - import a Hermes home's MEMORY.md / USER.md into seagent's store.

use crate::util;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

/// Owner-only copy: mode 0600 on unix, an owner-only DACL on Windows.
fn private(t: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(t, fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    {
        seagent_core::platform::fs_private::set_private(t)
    }
}

pub const BUNDLED: &[&str] = &["byterover", "retaindb"];
/// Providers that live outside the core (Hermes `_LEFT_CORE` minus the two seagent bundles).
pub const CATALOG: &[&str] = &["hindsight", "honcho", "mem0", "supermemory", "openviking", "holographic"];
pub const RETRY_SECS: u64 = 3600;
pub const RETRY_MAX_SECS: u64 = 7 * 24 * 3600;

#[derive(Debug, Clone, PartialEq)]
pub enum ProviderState {
    Builtin,
    Bundled(String),
    Plugin(String),
    /// Missing: message for the user, and whether a retry is allowed now (backoff).
    Missing { name: String, message: String, retry_now: bool },
}

fn stamp(data: &Path, name: &str) -> PathBuf {
    data.join("cache").join(format!("left-core-{name}.failed"))
}

fn failures(p: &Path) -> u32 {
    fs::read_to_string(p).ok().map(|t| t.trim().parse().unwrap_or(1)).unwrap_or(0)
}

pub fn note_failure(data: &Path, name: &str) {
    let p = stamp(data, name);
    let _ = util::write_atomic(&p, (failures(&p) + 1).to_string().as_bytes());
}

pub fn note_success(data: &Path, name: &str) {
    let _ = fs::remove_file(stamp(data, name));
}

/// Backoff: 1 h doubling per failure up to 7 days.
pub fn failed_recently(data: &Path, name: &str, now_secs: u64) -> bool {
    let p = stamp(data, name);
    let Ok(m) = fs::metadata(&p) else { return false };
    let mtime = m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
    let n = failures(&p).clamp(1, 32);
    now_secs.saturating_sub(mtime) < (RETRY_SECS.saturating_mul(1u64 << (n - 1).min(20))).min(RETRY_MAX_SECS)
}

pub fn check_provider(data: &Path, provider: &str, plugins: &[String]) -> ProviderState {
    let p = provider.trim();
    if p.is_empty() || p == "builtin" || p == "none" {
        return ProviderState::Builtin;
    }
    if BUNDLED.contains(&p) {
        return ProviderState::Bundled(p.into());
    }
    if plugins.iter().any(|x| x == p) {
        note_success(data, p);
        return ProviderState::Plugin(p.into());
    }
    let retry_now = !failed_recently(data, p, util::now_ms() / 1000);
    let message = if CATALOG.contains(&p) {
        format!("Memory provider '{p}' is configured but not installed. Install its plugin with `seagent plugin install {p}` (memory.provider and your stored memories are unchanged), or change [memory] provider.")
    } else {
        format!("Memory provider '{p}' is configured but not installed and not a known provider. Install a plugin named `{p}` with `\"memory\": true`, or change [memory] provider.")
    };
    ProviderState::Missing { name: p.into(), message, retry_now }
}

fn valid_name(p: &str) -> bool {
    !p.is_empty() && p != "." && p != ".." && p.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
}

fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for e in fs::read_dir(src)? {
        let e = e?;
        let t = dst.join(e.file_name());
        if e.file_type()?.is_dir() {
            copy_dir(&e.path(), &t)?;
        } else if e.file_type()?.is_file() {
            fs::copy(e.path(), &t)?;
            private(&t)?;
        }
    }
    Ok(())
}

/// Copy `<provider>/` and/or `<provider>.json` from one profile home to another.
pub fn clone_provider_config(src: &Path, dst: &Path, provider: &str) -> Result<bool, String> {
    if !valid_name(provider) || provider == "builtin" {
        return Ok(false);
    }
    let mut copied = false;
    if src.join(provider).is_dir() {
        copy_dir(&src.join(provider), &dst.join(provider)).map_err(|e| e.to_string())?;
        copied = true;
    }
    let f = src.join(format!("{provider}.json"));
    if f.is_file() {
        fs::create_dir_all(dst).map_err(|e| e.to_string())?;
        let t = dst.join(format!("{provider}.json"));
        fs::copy(&f, &t).map_err(|e| e.to_string())?;
        private(&t).map_err(|e| e.to_string())?;
        copied = true;
    }
    Ok(copied)
}

/// Rename Honcho host blocks for a renamed profile without changing peers.
pub fn migrate_honcho_profile_host(old: &str, new: &str, candidates: &[PathBuf]) -> Vec<String> {
    let (old_host, legacy, new_host) = (format!("hermes_{old}"), format!("hermes.{old}"), format!("hermes_{new}"));
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for p in candidates {
        let r = fs::canonicalize(p).unwrap_or_else(|_| p.clone());
        if !p.is_file() || !seen.insert(r) {
            continue;
        }
        let Some(mut raw) = util::read_json(p) else { continue };
        let Some(hosts) = raw.get_mut("hosts").and_then(Value::as_object_mut) else { continue };
        let src = if hosts.contains_key(&old_host) { old_host.clone() } else { legacy.clone() };
        if !hosts.contains_key(&src) {
            continue;
        }
        if hosts.contains_key(&new_host) {
            out.push(format!("⚠ Honcho host block not migrated: {new_host} already exists in {}", p.display()));
            continue;
        }
        let mut block = hosts.remove(&src).unwrap_or(json!({}));
        if block.is_object() && block.get("aiPeer").is_none() {
            block["aiPeer"] = json!(old);
        }
        hosts.insert(new_host.clone(), block);
        if util::write_json(p, &raw).is_ok() {
            out.push(format!("✓ Honcho host updated: {src} → {new_host} in {}", p.display()));
        }
    }
    out
}

/// Honcho config files to consider for a profile home. `default_home` is the home the caller
/// resolved (`$HOME` for the CLI): the legacy `~/.honcho/config.json` is looked up *there*,
/// never through a fresh `$HOME` read, so a test or an alternate profile can point the
/// migration at its own home instead of the developer's real one.
pub fn honcho_candidates(profile_dir: &Path, default_home: &Path) -> Vec<PathBuf> {
    let mut out = vec![profile_dir.join("honcho.json"), default_home.join("honcho.json")];
    if !default_home.as_os_str().is_empty() {
        out.push(default_home.join(".honcho").join("config.json"));
    }
    out
}

/// Merge a Hermes home's `memories/MEMORY.md` and `USER.md` into seagent's store (dedupe, budget-checked).
pub fn import_hermes(hermes_home: &Path, data: &Path) -> Result<String, String> {
    let mut out = Vec::new();
    for (f, target) in [("MEMORY.md", "memory"), ("USER.md", "user")] {
        let p = hermes_home.join("memories").join(f);
        let entries = seagent_tools::memory_store::load(&p)?;
        if entries.is_empty() {
            continue;
        }
        let ops: Vec<Value> = entries.iter().map(|e| json!({"action": "add", "text": e.replace('§', "")})).collect();
        out.push(format!("{f}: {}", seagent_tools::memory_store::apply_batch(data, target, &ops)?));
    }
    Ok(if out.is_empty() { format!("no Hermes memories found under {}", hermes_home.join("memories").display()) } else { out.join("\n") })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_check_and_backoff() {
        let d = crate::tmp("mig");
        assert_eq!(check_provider(&d, "", &[]), ProviderState::Builtin);
        assert_eq!(check_provider(&d, "retaindb", &[]), ProviderState::Bundled("retaindb".into()));
        assert_eq!(check_provider(&d, "kb", &["kb".into()]), ProviderState::Plugin("kb".into()));
        match check_provider(&d, "honcho", &[]) {
            ProviderState::Missing { message, retry_now, .. } => assert!(message.contains("seagent plugin install honcho") && retry_now),
            s => panic!("{s:?}"),
        }
        note_failure(&d, "honcho");
        note_failure(&d, "honcho");
        assert!(failed_recently(&d, "honcho", util::now_ms() / 1000));
        assert!(!failed_recently(&d, "honcho", util::now_ms() / 1000 + 2 * 3600 + 5), "2 failures → 2 h");
        note_success(&d, "honcho");
        assert!(!failed_recently(&d, "honcho", util::now_ms() / 1000));
    }

    #[test]
    fn clone_and_honcho_host_and_import() {
        let d = crate::tmp("mig2");
        let (a, b) = (d.join("a"), d.join("b"));
        fs::create_dir_all(a.join("hindsight")).unwrap();
        fs::write(a.join("hindsight/cfg.json"), "{}").unwrap();
        fs::write(a.join("mem0.json"), "{\"k\":1}").unwrap();
        assert!(clone_provider_config(&a, &b, "hindsight").unwrap());
        assert!(clone_provider_config(&a, &b, "mem0").unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(b.join("mem0.json")).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert!(!clone_provider_config(&a, &b, "../x").unwrap());
        let hj = a.join("honcho.json");
        fs::write(&hj, r#"{"hosts":{"hermes.work":{"workspace":"w"}}}"#).unwrap();
        let msgs = migrate_honcho_profile_host("work", "job", &[hj.clone(), hj.clone()]);
        assert_eq!(msgs, vec![format!("✓ Honcho host updated: hermes.work → hermes_job in {}", hj.display())]);
        let v = util::read_json(&hj).unwrap();
        assert_eq!(v["hosts"]["hermes_job"]["aiPeer"], "work");
        fs::write(&hj, r#"{"hosts":{"hermes_work":{},"hermes_job":{}}}"#).unwrap();
        assert!(migrate_honcho_profile_host("work", "job", &[hj])[0].contains("already exists"));
        let hh = d.join("hermes");
        fs::create_dir_all(hh.join("memories")).unwrap();
        fs::write(hh.join("memories/USER.md"), "name: Wu\n§\nprefers zh-TW").unwrap();
        assert!(import_hermes(&hh, &d).unwrap().contains("USER.md"));
        assert_eq!(fs::read_to_string(d.join("memory/USER.md")).unwrap(), "name: Wu\n§\nprefers zh-TW");
    }

    /// The legacy `~/.honcho/config.json` lives under the *passed* home; a developer's real
    /// `$HOME` is never consulted (a migration must not rewrite it from a test or a profile).
    #[test]
    fn honcho_candidates_use_the_passed_home() {
        let d = crate::tmp("mig-home");
        let home = d.join("home");
        fs::create_dir_all(home.join(".honcho")).unwrap();
        // Joined per component, as the product does (`\.honcho\config.json` on Windows).
        let legacy = home.join(".honcho").join("config.json");
        fs::write(&legacy, r#"{"hosts":{"hermes.work":{"workspace":"w"}}}"#).unwrap();
        let real_home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
        let real_legacy = real_home.join(".honcho/config.json");
        let before = fs::read(&real_legacy).ok();

        let profile = d.join("profile");
        let candidates = honcho_candidates(&profile, &home);
        assert_eq!(candidates, vec![profile.join("honcho.json"), home.join("honcho.json"), legacy.clone()]);
        assert!(!candidates.contains(&real_legacy), "$HOME must not be consulted: {candidates:?}");

        let msgs = migrate_honcho_profile_host("work", "job", &candidates);
        assert_eq!(msgs, vec![format!("✓ Honcho host updated: hermes.work → hermes_job in {}", legacy.display())]);
        assert_eq!(fs::read(&real_legacy).ok(), before, "the real ~/.honcho/config.json is untouched");
        // An empty home (no `$HOME` in the environment) adds no legacy candidate.
        assert_eq!(honcho_candidates(&profile, Path::new("")).len(), 2);
    }
}
