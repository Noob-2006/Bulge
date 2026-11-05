//! Self-update, uninstall and reset (Hermes `update`/`uninstall`, OpenClaw `update`
//! with stable/beta/dev channels, `uninstall`, `reset`).
//!
//! Releases come from a GitHub-compatible API (`[update] url`): stable = newest
//! non-prerelease, beta = newest prerelease or stable, dev = newest of all. The asset
//! for this platform (`ark-<arch>-<os>[.tar.gz]`) must match the release's `SHA256SUMS`
//! (or `<asset>.sha256`). The binary is replaced atomically next to itself, the old one
//! kept as `ark.prev` (`ark update --rollback`), and a running daemon is stopped before
//! and restarted after the swap.

use crate::args::Args;
use crate::ops::{archive, net};
use crate::{usage, R};
use ark_kernel::config::{Config, Paths};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const COMMANDS: &[&str] = &["update", "upgrade", "uninstall", "reset"];
pub const VALUE_FLAGS: &[&str] = &["channel", "version", "scope"];
pub const BOOL_FLAGS: &[&str] = &["check", "rollback", "purge", "all-profiles", "remove-binary", "no-restart"];

pub fn target() -> String {
    format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
}

/// `v1.2.3-beta.1` → (1,2,3, pre?) ordering key.
pub fn parse_version(v: &str) -> Option<(u64, u64, u64, Option<String>)> {
    let v = v.trim().trim_start_matches('v');
    let (core, pre) = v.split_once('-').map(|(c, p)| (c, Some(p.to_string()))).unwrap_or((v, None));
    let mut it = core.split('.').map(|x| x.parse::<u64>());
    Some((it.next()?.ok()?, it.next().unwrap_or(Ok(0)).ok()?, it.next().unwrap_or(Ok(0)).ok()?, pre))
}

/// True when `a` is newer than `b` (a release outranks its own prereleases).
pub fn newer(a: &str, b: &str) -> bool {
    match (parse_version(a), parse_version(b)) {
        (Some(x), Some(y)) => match (x.0, x.1, x.2).cmp(&(y.0, y.1, y.2)) {
            std::cmp::Ordering::Equal => match (&x.3, &y.3) {
                (None, Some(_)) => true,
                (Some(p), Some(q)) => p > q,
                _ => false,
            },
            o => o == std::cmp::Ordering::Greater,
        },
        _ => false,
    }
}

#[derive(Debug, Clone)]
pub struct Release {
    pub tag: String,
    pub prerelease: bool,
    pub notes: String,
    pub asset: Option<(String, String)>,
    pub sums: Option<String>,
}

pub fn releases(base: &str) -> Result<Vec<Release>, String> {
    let v = net::get_json(&format!("{}/releases?per_page=30", base.trim_end_matches('/')), &[("accept", "application/vnd.github+json".into()), ("user-agent", format!("ark/{}", env!("CARGO_PKG_VERSION")))])?;
    let t = target();
    Ok(v.as_array().ok_or("release index is not a list")?.iter().filter(|r| r["draft"] != true).map(|r| {
        let assets = r["assets"].as_array().cloned().unwrap_or_default();
        let url = |a: &Value| (a["name"].as_str().unwrap_or("").to_string(), a["browser_download_url"].as_str().unwrap_or("").to_string());
        let asset = assets.iter().find(|a| a["name"].as_str().is_some_and(|n| n == format!("ark-{t}") || n == format!("ark-{t}.tar.gz"))).map(url);
        let sums = assets.iter().find(|a| a["name"] == "SHA256SUMS").map(|a| url(a).1).or_else(|| asset.as_ref().and_then(|(n, _)| assets.iter().find(|a| a["name"].as_str() == Some(&format!("{n}.sha256"))).map(|a| url(a).1)));
        Release { tag: r["tag_name"].as_str().unwrap_or("").to_string(), prerelease: r["prerelease"] == true, notes: r["body"].as_str().unwrap_or("").to_string(), asset, sums }
    }).collect())
}

pub fn pick(rs: &[Release], channel: &str, version: Option<&str>) -> Result<Option<Release>, String> {
    if let Some(v) = version {
        return rs.iter().find(|r| r.tag.trim_start_matches('v') == v.trim_start_matches('v')).cloned().map(Some).ok_or_else(|| format!("no release {v}"));
    }
    let ok = |r: &&Release| match channel {
        "stable" => !r.prerelease,
        "beta" => !r.prerelease || r.tag.contains("beta") || r.tag.contains("rc"),
        "dev" => true,
        _ => false,
    };
    if !["stable", "beta", "dev"].contains(&channel) {
        return Err(format!("unknown channel `{channel}` (stable, beta, dev)"));
    }
    let mut best: Option<&Release> = None;
    for r in rs.iter().filter(ok) {
        if best.is_none_or(|b| newer(&r.tag, &b.tag)) {
            best = Some(r);
        }
    }
    Ok(best.cloned())
}

/// `None` when up to date.
pub fn check(cfg: &Config, channel: Option<&str>) -> Result<Option<Release>, String> {
    let rs = releases(&cfg.update.url)?;
    let r = pick(&rs, channel.unwrap_or(&cfg.update.channel), None)?;
    Ok(r.filter(|r| newer(&r.tag, env!("CARGO_PKG_VERSION"))))
}

/// One-line answer for `/update` and the daemon's start-up check.
pub fn check_text(cfg: &Config) -> String {
    match check(cfg, None) {
        Ok(Some(r)) => format!("ark {} is available (you have {}); run `ark update` on the host", r.tag, env!("CARGO_PKG_VERSION")),
        Ok(None) => format!("ark {} is up to date ({} channel)", env!("CARGO_PKG_VERSION"), cfg.update.channel),
        Err(e) => format!("update check failed: {e}"),
    }
}

fn download(url: &str) -> Result<Vec<u8>, String> {
    let (s, b) = net::request("GET", url, &[("user-agent", format!("ark/{}", env!("CARGO_PKG_VERSION")))], None, 512 << 20, Duration::from_secs(600))?;
    if s != 200 {
        return Err(format!("{url}: HTTP {s}"));
    }
    Ok(b)
}

/// The verified new binary bytes for `r`.
pub fn fetch(r: &Release) -> Result<Vec<u8>, String> {
    let (name, url) = r.asset.clone().ok_or_else(|| format!("release {} has no build for {}", r.tag, target()))?;
    let sums_url = r.sums.clone().ok_or_else(|| format!("release {} publishes no SHA256SUMS; refusing an unverifiable binary", r.tag))?;
    let bytes = download(&url)?;
    let sums = String::from_utf8_lossy(&download(&sums_url)?).to_string();
    let want = sums.lines().find_map(|l| {
        let mut p = l.split_whitespace();
        let (h, n) = (p.next()?, p.next().unwrap_or(&name).trim_start_matches('*'));
        (n == name || sums.lines().count() == 1).then(|| h.to_lowercase())
    }).ok_or_else(|| format!("{name} is not listed in the checksum file"))?;
    let got = ark_net::crypto::hex(&ark_net::crypto::sha256(&bytes));
    if got != want {
        return Err(format!("checksum mismatch for {name}: expected {want}, got {got}"));
    }
    if name.ends_with(".tar.gz") {
        let entries = archive::untar(&archive::gunzip(&bytes)?)?;
        return entries.into_iter().find(|e| !e.dir && (e.path == "ark" || e.path.ends_with("/ark"))).map(|e| e.data).ok_or_else(|| "archive has no `ark` binary".into());
    }
    Ok(bytes)
}

/// Package-managed installs update through their manager.
pub fn managed(exe: &Path) -> Option<&'static str> {
    let s = exe.to_string_lossy();
    if s.starts_with("/nix/store/") {
        Some("installed by Nix: update your flake / profile instead")
    } else if s.starts_with("/usr/bin/") || s.starts_with("/bin/") {
        Some("installed by the system package manager: update it there")
    } else {
        None
    }
}

/// Put `bytes` in place of `exe` (old kept as `<exe>.prev`) after a `--version` smoke test.
pub fn install_binary(exe: &Path, bytes: &[u8]) -> Result<PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;
    let dir = exe.parent().ok_or("no install directory")?;
    let tmp = dir.join(format!(".ark-new-{}", std::process::id()));
    std::fs::write(&tmp, bytes).map_err(|e| format!("{}: {e} (no write access? reinstall with the installer)", tmp.display()))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    let ok = std::process::Command::new(&tmp).arg("version").output().map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).starts_with("ark ")).unwrap_or(false);
    if !ok {
        let _ = std::fs::remove_file(&tmp);
        return Err("the downloaded binary does not run on this machine; nothing changed".into());
    }
    let prev = exe.with_extension("prev");
    std::fs::copy(exe, &prev).map_err(|e| format!("backup {}: {e}", prev.display()))?;
    std::fs::rename(&tmp, exe).map_err(|e| e.to_string())?;
    Ok(prev)
}

pub fn rollback(exe: &Path) -> Result<(), String> {
    let prev = exe.with_extension("prev");
    if !prev.exists() {
        return Err(format!("no previous version saved ({})", prev.display()));
    }
    let tmp = exe.with_extension("rollback");
    std::fs::copy(&prev, &tmp).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, exe).map_err(|e| e.to_string())
}

fn daemon_running(paths: &Paths) -> bool {
    ark_kernel::daemon::call(&paths.socket(), "ping", json!({})).is_ok()
}

fn run_self(args: &[&str]) -> bool {
    std::env::current_exe().ok().and_then(|e| std::process::Command::new(e).args(args).status().ok()).is_some_and(|s| s.success())
}

fn cmd_update(a: &Args) -> R {
    let paths = Paths::from_env();
    let cfg = Config::load(Some(&paths.user_config()), None, &[]).unwrap_or_default();
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    if a.flag("rollback") {
        rollback(&exe)?;
        println!("rolled back to the previous binary");
        return Ok(0);
    }
    let channel = a.val("channel").unwrap_or(&cfg.update.channel).to_string();
    let rs = releases(&cfg.update.url)?;
    let Some(r) = pick(&rs, &channel, a.val("version"))? else {
        println!("no release on the {channel} channel");
        return Ok(0);
    };
    let up = newer(&r.tag, env!("CARGO_PKG_VERSION"));
    if a.flag("check") || a.flag("dry-run") || (!up && a.val("version").is_none()) {
        println!("current {} · {channel} channel latest {}{}", env!("CARGO_PKG_VERSION"), r.tag, if up { " — update available" } else { " — up to date" });
        if up && !r.notes.is_empty() {
            println!("\n{}", r.notes.lines().take(20).collect::<Vec<_>>().join("\n"));
        }
        return Ok(if up && a.flag("check") { 10 } else { 0 });
    }
    if let Some(why) = managed(&exe) {
        return Err(why.into());
    }
    let bytes = fetch(&r)?;
    let restart = daemon_running(&paths) && !a.flag("no-restart");
    if restart {
        run_self(&["daemon", "stop"]);
    }
    let prev = install_binary(&exe, &bytes)?;
    println!("updated ark {} → {} (previous binary: {}; `ark update --rollback` restores it)", env!("CARGO_PKG_VERSION"), r.tag, prev.display());
    if restart {
        let unit = std::process::Command::new("systemctl").args(["--user", "is-active", "--quiet", "arkd.service"]).status().is_ok_and(|s| s.success());
        if unit {
            let _ = std::process::Command::new("systemctl").args(["--user", "restart", "arkd.service"]).status();
        } else {
            run_self(&["daemon", "start"]);
        }
        println!("daemon restarted on the new version");
    }
    Ok(0)
}

/// What `ark reset --scope` clears (OpenClaw `reset`): config | sessions | memory | state | all.
pub fn reset(paths: &Paths, scope: &str) -> Result<Vec<PathBuf>, String> {
    let d = &paths.data;
    let targets: Vec<PathBuf> = match scope {
        "config" => vec![paths.user_config()],
        "sessions" => vec![d.join("sessions"), d.join("display.json"), d.join("channels/routes.json")],
        "memory" => vec![d.join("memory")],
        "state" => std::fs::read_dir(d).map(|r| r.flatten().map(|e| e.path()).filter(|p| !p.ends_with("backups")).collect()).unwrap_or_default(),
        "all" => {
            let mut v = vec![paths.user_config(), paths.config_dir.join(".env"), paths.secrets()];
            v.extend(std::fs::read_dir(d).map(|r| r.flatten().map(|e| e.path()).filter(|p| !p.ends_with("backups")).collect::<Vec<_>>()).unwrap_or_default());
            v
        }
        other => return Err(format!("unknown scope `{other}` (config, sessions, memory, state, all)")),
    };
    let mut gone = vec![];
    for t in targets.into_iter().filter(|t| t.exists()) {
        if t.is_dir() { std::fs::remove_dir_all(&t) } else { std::fs::remove_file(&t) }.map_err(|e| format!("{}: {e}", t.display()))?;
        gone.push(t);
    }
    Ok(gone)
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    match cmd {
        "update" | "upgrade" => Some(cmd_update(a)),
        "reset" => Some((|| -> R {
            let paths = Paths::from_env();
            let scope = a.val("scope").or(a.pos(0)).unwrap_or("");
            if scope.is_empty() {
                return usage("usage: ark reset --scope config|sessions|memory|state|all --yes");
            }
            if daemon_running(&paths) {
                return Err("arkd is running; stop it first (ark daemon stop)".into());
            }
            if !a.flag("yes") {
                return Err(format!("this deletes the {scope} of profile {}; re-run with --yes (a backup is written first)", crate::ops::profile::current()).into());
            }
            let (pre, _) = crate::ops::backup::create(&paths, &paths.data.join("backups"), &crate::ops::backup::Opts { sessions: true, label: format!("before reset {scope}"), ..Default::default() })?;
            let gone = reset(&paths, scope)?;
            println!("reset {scope}: removed {} item(s) · backup {}", gone.len(), pre.display());
            Ok(0)
        })()),
        "uninstall" => Some((|| -> R {
            let paths = Paths::from_env();
            if !a.flag("yes") {
                return Err(format!("this stops and removes the ark service{}; re-run with --yes", if a.flag("purge") { format!(" and DELETES {} and {}", paths.config_dir.display(), paths.data.display()) } else { String::new() }).into());
            }
            if a.flag("purge") {
                // Refuse a suicidal target before the daemon is stopped: a bad ARK_HOME must not
                // take the service down on its way to being rejected. `plan` checks again.
                purge_target_ok(&paths.config_dir)?;
                purge_target_ok(&paths.data)?;
            }
            if daemon_running(&paths) {
                run_self(&["daemon", "stop"]);
            }
            run_self(&["service", "uninstall"]);
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            // What an uninstall removes is decided (and tested) in [`plan`]; the dispatch only
            // carries it out.
            let p = plan(&paths, a.flag("purge"), a.flag("all-profiles"), a.flag("remove-binary"), &exe)?;
            if let Some(why) = &p.binary_kept {
                println!("binary left in place: {why}");
            }
            let removed = apply(&p)?;
            for n in crate::ops::profile::list() {
                let _ = crate::ops::profile::remove_alias(&n);
            }
            for r in &removed {
                println!("removed {}", r.display());
            }
            println!("ark uninstalled{}", if a.flag("remove-binary") { "" } else { " (binary kept; --remove-binary deletes it)" });
            Ok(0)
        })()),
        _ => None,
    }
}

// ───────────────────────── uninstall plan (Hermes `uninstall.py`) ─────────────────────────

/// What `ark uninstall` would remove. `config`/`data` need `--purge`; every profile's directory
/// needs `--all-profiles` on top; the binary needs `--remove-binary` and is kept when the install
/// is managed by someone else (nix/store, a distro package).
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    pub dirs: Vec<PathBuf>,
    pub binary: Option<PathBuf>,
    pub binary_kept: Option<&'static str>,
}

pub fn plan(paths: &Paths, purge: bool, all_profiles: bool, remove_binary: bool, exe: &Path) -> Result<Plan, String> {
    let mut dirs = vec![];
    if purge {
        // `--purge` deletes these recursively, so every target goes through the guard first: an
        // `ARK_HOME` of `/`, `$HOME` or `/etc` must fail loudly here, not erase the box.
        for d in [&paths.data, &paths.config_dir] {
            purge_target_ok(d)?;
        }
        dirs.push(paths.config_dir.clone());
        dirs.push(paths.data.clone());
        if all_profiles {
            dirs.push(crate::ops::profile::profiles_root());
        }
    }
    let mut dedup: Vec<PathBuf> = Vec::new();
    for d in dirs {
        if !dedup.contains(&d) {
            dedup.push(d);
        }
    }
    let mut binary = None;
    let mut binary_kept: Option<&'static str> = None;
    if remove_binary {
        match managed(exe) {
            Some(why) => binary_kept = Some(why),
            None => binary = Some(exe.to_path_buf()),
        }
    }
    Ok(Plan { dirs: dedup, binary, binary_kept })
}

/// Refuse a `--purge` target that is not a plausible per-user ark directory.
///
/// The uninstall path deletes `<target>` with a recursive `remove_dir_all`. `ARK_HOME` comes from
/// the environment, so a typo or an inherited value (`ARK_HOME=/`, `ARK_HOME=$HOME`, a symlink to
/// either) would take the user's home or the whole filesystem with it. The checks are deliberately
/// about the *canonical* target: a symlink is only as safe as what it points at.
pub fn purge_target_ok(p: &Path) -> Result<(), String> {
    purge_target_ok_in(p, std::env::var_os("HOME").map(PathBuf::from).filter(|h| !h.as_os_str().is_empty()))
}

/// [`purge_target_ok`] with the home directory passed in: tests must never read or change the
/// real `$HOME`.
fn purge_target_ok_in(p: &Path, home: Option<PathBuf>) -> Result<(), String> {
    use std::path::Component;
    let refuse = |why: String| {
        Err(format!(
            "refusing to purge {}: {why}. `ark uninstall --purge` deletes ARK_HOME/config and ARK_HOME/data \
             recursively; set a proper ARK_HOME (e.g. `ARK_HOME=\"$HOME/.ark\"`) and re-run, or remove that \
             directory by hand",
            p.display()
        ))
    };
    if p.as_os_str().is_empty() {
        return refuse("the path is empty".into());
    }
    // `.`/`..` can point the deletion at a directory the caller did not name; canonicalisation
    // would hide that, so look at the components as given.
    if p.components().any(|c| matches!(c, Component::CurDir | Component::ParentDir)) {
        return refuse("the path contains a `.` or `..` component".into());
    }
    let target = match std::fs::canonicalize(p) {
        Ok(t) => t,
        // A missing directory is fine (nothing to delete) as long as its parent is a real place.
        Err(_) => match (p.parent(), p.file_name()) {
            (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => match std::fs::canonicalize(parent) {
                Ok(q) => q.join(name),
                Err(_) => return refuse("the path does not exist and neither does its parent".into()),
            },
            _ => return refuse("the path cannot be resolved".into()),
        },
    };
    let mut blocked: Vec<PathBuf> =
        ["/", "/home", "/root", "/usr", "/usr/local", "/etc", "/var", "/bin", "/sbin", "/lib", "/lib64", "/boot"]
            .iter()
            .map(PathBuf::from)
            .collect();
    if let Some(home) = home {
        blocked.push(std::fs::canonicalize(&home).unwrap_or(home));
    }
    if blocked.iter().any(|b| b == &target) {
        return refuse(format!("{} is a system directory or the user's home", target.display()));
    }
    if target.components().count() < 3 {
        return refuse(format!("{} is too close to the filesystem root", target.display()));
    }
    Ok(())
}

/// Carry out a [`Plan`]; returns what was actually removed (missing paths are skipped, so a
/// second run is a no-op). The `ark.prev` rollback copy goes with the binary.
pub fn apply(p: &Plan) -> Result<Vec<PathBuf>, String> {
    let mut removed = vec![];
    for d in p.dirs.iter().filter(|d| d.exists()) {
        std::fs::remove_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        removed.push(d.clone());
    }
    if let Some(exe) = p.binary.as_ref().filter(|e| e.exists()) {
        let _ = std::fs::remove_file(exe.with_extension("prev"));
        std::fs::remove_file(exe).map_err(|e| format!("{}: {e}", exe.display()))?;
        removed.push(exe.clone());
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::net::fake;
    use std::sync::Arc;

    #[test]
    fn versions_and_channels() {
        assert!(newer("v1.2.0", "1.1.9") && !newer("1.0.0", "1.0.0") && newer("1.0.0", "1.0.0-rc.1") && newer("1.0.0-rc.2", "1.0.0-rc.1") && !newer("0.9", "0.10.0"));
        let rel = |t: &str, p: bool| Release { tag: t.into(), prerelease: p, notes: String::new(), asset: None, sums: None };
        let rs = vec![rel("v0.3.0-beta.1", true), rel("v0.2.0", false), rel("v0.3.0-dev.5", true)];
        assert_eq!(pick(&rs, "stable", None).unwrap().unwrap().tag, "v0.2.0");
        assert_eq!(pick(&rs, "beta", None).unwrap().unwrap().tag, "v0.3.0-beta.1");
        assert_eq!(pick(&rs, "dev", None).unwrap().unwrap().tag, "v0.3.0-dev.5");
        assert_eq!(pick(&rs, "stable", Some("0.3.0-beta.1")).unwrap().unwrap().tag, "v0.3.0-beta.1");
        assert!(pick(&rs, "nightly", None).is_err());
        assert!(managed(Path::new("/nix/store/abc/bin/ark")).is_some() && managed(Path::new("/home/u/.local/bin/ark")).is_none());
    }

    #[test]
    fn uninstall_plan_purges_profiles_and_keeps_a_managed_binary() {
        let t = ark_core::tmp::TempDir::new("ark-uninst");
        let root = t.path();
        let paths = Paths { data: root.join("data"), config_dir: root.join("config"), runtime: root.join("run") };
        for d in [&paths.data, &paths.config_dir] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(paths.data.join("session.jsonl"), "{}").unwrap();
        let exe = root.join("bin/ark");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, "bin").unwrap();
        std::fs::write(exe.with_extension("prev"), "old").unwrap();

        // Plain uninstall (no --purge): nothing on disk is touched, the config/data survive.
        let p = plan(&paths, false, false, false, &exe).unwrap();
        assert!(p.dirs.is_empty() && p.binary.is_none());
        assert!(apply(&p).unwrap().is_empty());
        assert!(paths.config_dir.exists() && paths.data.exists() && exe.exists());

        // --purge: config + data; --all-profiles adds the profiles root; --remove-binary the exe.
        let p = plan(&paths, true, true, true, &exe).unwrap();
        assert!(p.dirs.contains(&paths.config_dir) && p.dirs.contains(&paths.data));
        assert_eq!(p.binary.as_deref(), Some(exe.as_path()));
        let removed = apply(&p).unwrap();
        assert!(removed.contains(&paths.config_dir) && removed.contains(&paths.data) && removed.contains(&exe));
        assert!(!paths.config_dir.exists() && !paths.data.exists() && !exe.exists());
        assert!(!exe.with_extension("prev").exists(), "the rollback copy goes too");
        // Idempotent: a second uninstall finds nothing to remove and does not fail.
        assert!(apply(&p).unwrap().is_empty());

        // A managed install keeps its binary even with --remove-binary.
        let managed_exe = Path::new("/nix/store/abc-ark-1.0/bin/ark");
        let p = plan(&paths, false, false, true, managed_exe).unwrap();
        assert!(p.binary.is_none() && p.binary_kept.is_some_and(|w| w.contains("Nix")), "{p:?}");
    }

    /// A `--purge` target of `/`, `$HOME` or a system directory would take the machine (or the
    /// user's home) with it: the guard has to refuse those before anything is deleted.
    #[test]
    fn purge_refuses_the_home_or_a_system_directory() {
        let t = ark_core::tmp::TempDir::new("ark-uninst");
        let fake_home = t.path().join("home");
        std::fs::create_dir_all(&fake_home).unwrap();
        let ok = |p: &Path| purge_target_ok_in(p, Some(fake_home.clone()));
        for bad in ["/", "/home", "/root", "/usr", "/usr/local", "/etc", "/var"] {
            let e = ok(Path::new(bad)).unwrap_err();
            assert!(e.contains("refusing to purge") && e.contains("ARK_HOME="), "{bad}: {e}");
        }
        assert!(ok(Path::new("")).unwrap_err().contains("empty"));
        assert!(ok(&fake_home).unwrap_err().contains("home"), "the home directory itself is refused");
        // Deep, per-user directories are fine (that is where a real ARK_HOME lives).
        let deep = fake_home.join(".ark");
        std::fs::create_dir_all(deep.join("data")).unwrap();
        assert!(ok(&deep).is_ok(), "{}", deep.display());
        // A symlink is judged by what it points at.
        let link = t.path().join("to-root");
        std::os::unix::fs::symlink("/", &link).unwrap();
        assert!(ok(&link).unwrap_err().contains("refusing to purge"));
        // `.`/`..` are refused before canonicalisation can hide where they point.
        assert!(ok(&t.path().join("home/../home")).unwrap_err().contains(".."));
        // `plan` runs the same guard, so the CLI cannot skip it.
        let bad = Paths { data: PathBuf::from("/usr"), config_dir: PathBuf::from("/etc"), runtime: PathBuf::from("/run") };
        let e = plan(&bad, true, false, false, Path::new("/opt/ark")).unwrap_err();
        assert!(e.contains("refusing to purge /usr") && e.contains("system directory"), "{e}");
        let good = Paths { data: deep.join("data"), config_dir: deep.join("config"), runtime: deep.join("run") };
        assert!(plan(&good, true, false, false, Path::new("/opt/ark")).is_ok());
    }

    #[test]
    fn fetch_verifies_checksums_against_a_fake_release_server() {
        let t = target();
        let bin = b"#!/bin/sh\necho ark 9.9.9\n".to_vec();
        let tgz = archive::gzip(&archive::tar(&[archive::Entry { path: "ark".into(), data: bin.clone(), mode: 0o755, dir: false }]));
        let sum = ark_net::crypto::hex(&ark_net::crypto::sha256(&tgz));
        let (tgz2, sum2) = (tgz.clone(), sum.clone());
        let tt = t.clone();
        let (base, _log) = fake::serve(Arc::new(move |r: &fake::Req| {
            let me = "http://HOST";
            match r.path.as_str() {
                p if p.starts_with("/repos/o/r/releases") => (200, "application/json".into(), json!([
                    {"tag_name": "v9.9.9", "prerelease": false, "body": "notes", "assets": [{"name": format!("ark-{tt}.tar.gz"), "browser_download_url": format!("{me}/dl/ark.tgz")}, {"name": "SHA256SUMS", "browser_download_url": format!("{me}/dl/sums")}]},
                    {"tag_name": "v9.9.8", "prerelease": false, "assets": [{"name": format!("ark-{tt}.tar.gz"), "browser_download_url": format!("{me}/dl/ark.tgz")}, {"name": "SHA256SUMS", "browser_download_url": format!("{me}/dl/badsums")}]}
                ]).to_string().into_bytes()),
                "/dl/ark.tgz" => (200, "application/octet-stream".into(), tgz2.clone()),
                "/dl/sums" => (200, "text/plain".into(), format!("{sum2}  ark-{tt}.tar.gz\n").into_bytes()),
                "/dl/badsums" => (200, "text/plain".into(), format!("{}  ark-{tt}.tar.gz\n", "0".repeat(64)).into_bytes()),
                _ => (404, "text/plain".into(), vec![]),
            }
        }));
        let fix = |r: Release| Release { asset: r.asset.map(|(n, u)| (n, u.replace("http://HOST", &base))), sums: r.sums.map(|u| u.replace("http://HOST", &base)), ..r };
        let rs: Vec<Release> = releases(&format!("{base}/repos/o/r")).unwrap().into_iter().map(fix).collect();
        assert_eq!(rs.len(), 2);
        assert_eq!(fetch(&rs[0]).unwrap(), bin);
        assert!(fetch(&rs[1]).unwrap_err().contains("checksum mismatch"));
        // Install over a fake "current" binary, then roll back.
        let t = ark_core::tmp::TempDir::new("ark-upd");
        let d = t.path().to_path_buf();
        std::fs::create_dir_all(&d).unwrap();
        let exe = d.join("ark");
        std::fs::write(&exe, "#!/bin/sh\necho ark 0.0.1\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        install_binary(&exe, &bin).unwrap();
        assert!(std::fs::read_to_string(&exe).unwrap().contains("9.9.9"));
        assert!(install_binary(&exe, b"not a program").is_err(), "smoke test guards the swap");
        rollback(&exe).unwrap();
        assert!(std::fs::read_to_string(&exe).unwrap().contains("0.0.1"));
    }

    #[test]
    fn reset_scopes() {
        let t = ark_core::tmp::TempDir::new("ark-reset");
        let root = t.path();
        let p = Paths { data: root.join("data"), config_dir: root.join("config"), runtime: root.join("run") };
        std::fs::create_dir_all(p.data.join("sessions")).unwrap();
        std::fs::create_dir_all(p.data.join("memory")).unwrap();
        std::fs::create_dir_all(p.data.join("backups")).unwrap();
        std::fs::create_dir_all(&p.config_dir).unwrap();
        std::fs::write(p.user_config(), "").unwrap();
        assert_eq!(reset(&p, "memory").unwrap().len(), 1);
        assert!(p.data.join("sessions").exists());
        reset(&p, "all").unwrap();
        assert!(!p.user_config().exists() && !p.data.join("sessions").exists() && p.data.join("backups").exists());
        assert!(reset(&p, "everything").is_err());
    }
}
