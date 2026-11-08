//! Self-update, uninstall and reset (Hermes `update`/`uninstall`, OpenClaw `update`
//! with stable/beta/dev channels, `uninstall`, `reset`).
//!
//! Releases come from a GitHub-compatible API (`[update] url`): stable = newest
//! non-prerelease, lts = newest stable of the maintained line (`[update] lts_series`, or releases
//! marked `LTS` in their notes), beta = newest prerelease or stable, dev = newest of all.
//!
//! The asset is the one `.github/workflows/release.yml` publishes, `seagent-<triple>.tar.gz` with
//! `<triple>` = `<arch>-unknown-linux-musl` (static, preferred) or `-gnu`; the archive holds
//! `bin/seagent` and `share/seagent/…`. It must match the release's `SHA256SUMS`, and when
//! `[update] verify_key` is set, `SHA256SUMS.sig` must verify (Ed25519) against that key.
//! The binary is replaced atomically next to itself, the old one kept as `seagent.prev`
//! (`seagent update --rollback`); the bundled `share/seagent` next to it is refreshed the same way. A
//! config+data backup is written first, so `seagent update --rollback --restore-data` can undo
//! settings and state too. A running daemon is stopped before and restarted after the swap.

use crate::args::Args;
use crate::ops::{archive, net};
use crate::{usage, R};
use seagent_kernel::config::{Config, Paths};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const COMMANDS: &[&str] = &["update", "upgrade", "uninstall", "reset"];
pub const VALUE_FLAGS: &[&str] = &["channel", "version", "scope"];
pub const BOOL_FLAGS: &[&str] = &["check", "rollback", "purge", "all-profiles", "remove-binary", "no-restart", "restore-data"];

/// The release triple this machine downloads: the static musl build of its CPU.
pub fn target() -> String {
    format!("{}-unknown-linux-musl", std::env::consts::ARCH)
}

/// Asset names of `arch`, best first: exactly what release.yml publishes (musl is static and
/// runs everywhere; gnu is the fallback). Kept in one place so the release workflow and the
/// updater cannot drift apart again (see the `asset_names_match_release_workflow` test).
pub fn asset_names(arch: &str) -> Vec<String> {
    ["musl", "gnu"].iter().map(|libc| format!("seagent-{arch}-unknown-linux-{libc}.tar.gz")).collect()
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
    /// URL of `SHA256SUMS.sig` (detached base64 Ed25519 signature over `SHA256SUMS`).
    pub sig: Option<String>,
}

pub fn releases(base: &str) -> Result<Vec<Release>, String> {
    seagent_net::http::ensure_online("the update check")?;
    let v = net::get_json(&format!("{}/releases?per_page=30", base.trim_end_matches('/')), &[("accept", "application/vnd.github+json".into()), ("user-agent", format!("seagent/{}", env!("CARGO_PKG_VERSION")))])?;
    let wanted = asset_names(std::env::consts::ARCH);
    Ok(v.as_array().ok_or("release index is not a list")?.iter().filter(|r| r["draft"] != true).map(|r| {
        let assets = r["assets"].as_array().cloned().unwrap_or_default();
        let url = |a: &Value| (a["name"].as_str().unwrap_or("").to_string(), a["browser_download_url"].as_str().unwrap_or("").to_string());
        let asset = wanted.iter().find_map(|w| assets.iter().find(|a| a["name"].as_str() == Some(w.as_str()))).map(url);
        let sums = assets.iter().find(|a| a["name"] == "SHA256SUMS").map(|a| url(a).1).or_else(|| asset.as_ref().and_then(|(n, _)| assets.iter().find(|a| a["name"].as_str() == Some(&format!("{n}.sha256"))).map(|a| url(a).1)));
        let sig = assets.iter().find(|a| a["name"] == "SHA256SUMS.sig").map(|a| url(a).1);
        Release { tag: r["tag_name"].as_str().unwrap_or("").to_string(), prerelease: r["prerelease"] == true, notes: r["body"].as_str().unwrap_or("").to_string(), asset, sums, sig }
    }).collect())
}

/// `MAJOR.MINOR` of a tag.
fn series(tag: &str) -> Option<String> {
    parse_version(tag).map(|(a, b, ..)| format!("{a}.{b}"))
}

/// A release the maintainers marked as long-term support: an `LTS` line in the notes.
fn marked_lts(notes: &str) -> bool {
    notes.lines().any(|l| matches!(l.trim().trim_start_matches(['#', '*', '-', ' ']).to_ascii_lowercase().trim_end_matches([':', '.']), "lts" | "channel: lts" | "lts release"))
}

/// The release `channel` (or an exact `version`) resolves to; `lts_series` is `[update] lts_series`.
pub fn pick_in(rs: &[Release], channel: &str, version: Option<&str>, lts_series: &str) -> Result<Option<Release>, String> {
    if let Some(v) = version {
        return rs.iter().find(|r| r.tag.trim_start_matches('v') == v.trim_start_matches('v')).cloned().map(Some).ok_or_else(|| format!("no release {v}"));
    }
    let lts_series = lts_series.trim().trim_start_matches('v');
    let ok = |r: &&Release| match channel {
        "stable" => !r.prerelease,
        "lts" => !r.prerelease && if lts_series.is_empty() { marked_lts(&r.notes) } else { series(&r.tag).as_deref() == Some(lts_series) },
        "beta" => !r.prerelease || r.tag.contains("beta") || r.tag.contains("rc"),
        "dev" => true,
        _ => false,
    };
    if !["stable", "lts", "beta", "dev"].contains(&channel) {
        return Err(format!("unknown channel `{channel}` (stable, lts, beta, dev)"));
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
    let r = pick_in(&rs, channel.unwrap_or(&cfg.update.channel), None, &cfg.update.lts_series)?;
    Ok(r.filter(|r| newer(&r.tag, env!("CARGO_PKG_VERSION"))))
}

/// One-line answer for `/update` and the daemon's start-up check.
pub fn check_text(cfg: &Config) -> String {
    if let Some(src) = seagent_net::http::offline_source() {
        return format!("update check skipped: offline mode ({src})");
    }
    match check(cfg, None) {
        Ok(Some(r)) => format!("seagent {} is available (you have {}); run `seagent update` on the host", r.tag, env!("CARGO_PKG_VERSION")),
        Ok(None) => format!("seagent {} is up to date ({} channel)", env!("CARGO_PKG_VERSION"), cfg.update.channel),
        Err(e) => format!("update check failed: {e}"),
    }
}

fn download(url: &str) -> Result<Vec<u8>, String> {
    let (s, b) = net::request("GET", url, &[("user-agent", format!("seagent/{}", env!("CARGO_PKG_VERSION")))], None, 512 << 20, Duration::from_secs(600))?;
    if s != 200 {
        return Err(format!("{url}: HTTP {s}"));
    }
    Ok(b)
}

/// What a release tarball carries: the binary and the bundled `share/seagent/…` entries
/// (paths relative to the share dir).
#[derive(Debug)]
pub struct Bundle {
    pub bin: Vec<u8>,
    pub share: Vec<archive::Entry>,
}

/// Ed25519 public key from `release-key.pub.pem` text or base64 (raw 32 bytes, or an SPKI DER).
pub fn parse_verify_key(text: &str) -> Result<Vec<u8>, String> {
    let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect::<Vec<_>>().concat();
    let der = seagent_net::crypto::b64_decode(body.trim()).ok_or("[update] verify_key is not base64 / PEM")?;
    match der.len() {
        32 => Ok(der),
        44 if der.starts_with(&[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]) => Ok(der[12..].to_vec()),
        n => Err(format!("[update] verify_key is {n} bytes; expected an Ed25519 public key (32 raw bytes or SPKI)")),
    }
}

/// `SHA256SUMS.sig` (base64 of 64 raw bytes, from `packaging/release/sign.sh`) over `sums`.
pub fn verify_signature(sums: &[u8], sig_b64: &str, key: &str) -> Result<(), String> {
    let key = parse_verify_key(key)?;
    let sig = seagent_net::crypto::b64_decode(sig_b64.trim()).ok_or("SHA256SUMS.sig is not base64")?;
    if sig.len() != 64 || !seagent_net::crypto::ed25519_verify(&key, sums, &sig) {
        return Err("the signature of SHA256SUMS does not verify against [update] verify_key; refusing this release".into());
    }
    Ok(())
}

fn unpack(name: &str, bytes: Vec<u8>) -> Result<Bundle, String> {
    if !name.ends_with(".tar.gz") {
        return Ok(Bundle { bin: bytes, share: vec![] });
    }
    let entries = archive::untar(&archive::gunzip(&bytes)?)?;
    let clean = |p: &str| p.trim_start_matches("./").to_string();
    let bin = entries.iter().find(|e| !e.dir && matches!(clean(&e.path).as_str(), "seagent" | "bin/seagent")).map(|e| e.data.clone()).ok_or("archive has no `bin/seagent` binary")?;
    let share = entries.into_iter().filter_map(|e| clean(&e.path).strip_prefix("share/seagent/").filter(|r| !r.is_empty()).map(|r| archive::Entry { path: r.to_string(), ..e })).collect();
    Ok(Bundle { bin, share })
}

/// The verified release contents for `r`. `verify_key` (may be empty) is `[update] verify_key`.
pub fn fetch_bundle(r: &Release, verify_key: &str) -> Result<Bundle, String> {
    let (name, url) = r.asset.clone().ok_or_else(|| format!("release {} has no build for {} (looked for {})", r.tag, target(), asset_names(std::env::consts::ARCH).join(" / ")))?;
    let sums_url = r.sums.clone().ok_or_else(|| format!("release {} publishes no SHA256SUMS; refusing an unverifiable binary", r.tag))?;
    let bytes = download(&url)?;
    let sums_raw = download(&sums_url)?;
    if !verify_key.trim().is_empty() {
        let sig_url = r.sig.clone().ok_or_else(|| format!("release {} has no SHA256SUMS.sig but [update] verify_key is set; refusing an unsigned release", r.tag))?;
        verify_signature(&sums_raw, &String::from_utf8_lossy(&download(&sig_url)?), verify_key)?;
    }
    let sums = String::from_utf8_lossy(&sums_raw).to_string();
    let want = sums.lines().find_map(|l| {
        let mut p = l.split_whitespace();
        let (h, n) = (p.next()?, p.next().unwrap_or(&name).trim_start_matches('*'));
        (n == name || sums.lines().count() == 1).then(|| h.to_lowercase())
    }).ok_or_else(|| format!("{name} is not listed in the checksum file"))?;
    let got = seagent_net::crypto::hex(&seagent_net::crypto::sha256(&bytes));
    if got != want {
        return Err(format!("checksum mismatch for {name}: expected {want}, got {got}"));
    }
    unpack(&name, bytes)
}

/// Where the bundled data of the binary at `exe` lives, if it was installed with one:
/// `<bin>/../lib/seagent/share` (install.sh) or `<bin>/../share/seagent` (tarball under a prefix).
pub fn installed_share(exe: &Path) -> Option<PathBuf> {
    let bin = exe.parent()?;
    ["../lib/seagent/share", "../share/seagent"].iter().map(|r| bin.join(r)).find(|p| p.join("skills").is_dir())
}

/// Replace the share dir with the release's (stage next to it, swap, drop the old one).
pub fn install_share(dest: &Path, entries: &[archive::Entry]) -> Result<usize, String> {
    if entries.is_empty() {
        return Ok(0);
    }
    let stage = dest.with_extension("new");
    let old = dest.with_extension("old");
    let _ = std::fs::remove_dir_all(&stage);
    let _ = std::fs::remove_dir_all(&old);
    std::fs::create_dir_all(&stage).map_err(|e| format!("{}: {e}", stage.display()))?;
    let n = archive::extract(entries, &stage).inspect_err(|_| {
        let _ = std::fs::remove_dir_all(&stage);
    })?;
    if dest.exists() {
        std::fs::rename(dest, &old).map_err(|e| format!("{}: {e}", dest.display()))?;
    }
    std::fs::rename(&stage, dest).map_err(|e| format!("{}: {e}", dest.display()))?;
    let _ = std::fs::remove_dir_all(&old);
    Ok(n)
}

/// Package-managed installs update through their manager.
pub fn managed(exe: &Path) -> Option<&'static str> {
    let s = exe.to_string_lossy();
    if s.starts_with("/nix/store/") {
        Some("installed by Nix: update your flake / profile instead")
    } else if s.starts_with("/usr/bin/") || s.starts_with("/bin/") || s.starts_with("/usr/sbin/") || s.starts_with("/usr/lib/") {
        Some("installed by the system package manager: update it there")
    } else if exe.parent().is_some_and(|b| b.join("../share/seagent/managed-by-package").exists() || b.join("seagent.managed").exists()) {
        Some("installed by a package (managed-by-package marker): update it with the package manager")
    } else {
        None
    }
}

/// Put `bytes` in place of `exe` (old kept as `<exe>.prev`) after a `--version` smoke test.
pub fn install_binary(exe: &Path, bytes: &[u8]) -> Result<PathBuf, String> {
    let dir = exe.parent().ok_or("no install directory")?;
    // Windows only runs `.exe` files.
    let tmp = dir.join(format!(".seagent-new-{}{}", std::process::id(), std::env::consts::EXE_SUFFIX));
    std::fs::write(&tmp, bytes).map_err(|e| format!("{}: {e} (no write access? reinstall with the installer)", tmp.display()))?;
    crate::ops::hostos::set_mode(&tmp, 0o755).map_err(|e| e.to_string())?;
    let ok = std::process::Command::new(&tmp).arg("version").output().map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).starts_with("seagent ")).unwrap_or(false);
    if !ok {
        let _ = std::fs::remove_file(&tmp);
        return Err("the downloaded binary does not run on this machine; nothing changed".into());
    }
    let prev = exe.with_extension("prev");
    std::fs::copy(exe, &prev).map_err(|e| format!("backup {}: {e}", prev.display()))?;
    replace_exe(&tmp, exe)?;
    Ok(prev)
}

/// Move `new` over `exe`. Unix: one atomic rename (a running binary keeps its inode).
/// Windows cannot overwrite a running `.exe` but can rename it: the current one moves aside to
/// `<exe>.old` (removed on the next update once nothing runs it), then `new` takes its name.
fn replace_exe(new: &Path, exe: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        let old = exe.with_extension("old");
        let _ = std::fs::remove_file(&old);
        let old = if old.exists() { exe.with_extension(format!("old-{}", std::process::id())) } else { old };
        std::fs::rename(exe, &old).map_err(|e| format!("move {} aside: {e}", exe.display()))?;
        if let Err(e) = std::fs::rename(new, exe) {
            let _ = std::fs::rename(&old, exe);
            return Err(e.to_string());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(new, exe).map_err(|e| e.to_string())
    }
}

pub fn rollback(exe: &Path) -> Result<(), String> {
    let prev = exe.with_extension("prev");
    if !prev.exists() {
        return Err(format!("no previous version saved ({})", prev.display()));
    }
    let tmp = exe.with_extension("rollback");
    std::fs::copy(&prev, &tmp).map_err(|e| e.to_string())?;
    replace_exe(&tmp, exe)
}

fn daemon_running(paths: &Paths) -> bool {
    seagent_kernel::daemon::call(&paths.socket(), "ping", json!({})).is_ok()
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
        let rec = rollback_record(&paths);
        if a.flag("restore-data") {
            let rec = rec.ok_or("no pre-update backup recorded; nothing to restore")?;
            let file = PathBuf::from(rec["backup"].as_str().unwrap_or(""));
            let (n, pre) = crate::ops::backup::restore(&paths, &file, false)?;
            println!("restored {n} file(s) of config and data from {} (state before the restore: {})", file.display(), pre.display());
        } else if let Some(rec) = rec {
            println!("settings and data were not rolled back; the state before the update to {} is in {} (add --restore-data, seagentd must be stopped)", rec["to"].as_str().unwrap_or("?"), rec["backup"].as_str().unwrap_or("?"));
        }
        return Ok(0);
    }
    let channel = a.val("channel").unwrap_or(&cfg.update.channel).to_string();
    let rs = releases(&cfg.update.url)?;
    let Some(r) = pick_in(&rs, &channel, a.val("version"), &cfg.update.lts_series)? else {
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
    if cfg.update.verify_key.trim().is_empty() {
        eprintln!("note: [update] verify_key is not set; this update is checked against SHA256SUMS only (set it to require a release signature)");
    }
    let bundle = fetch_bundle(&r, &cfg.update.verify_key)?;
    match pre_update_backup(&paths, &r.tag) {
        Ok(b) => println!("backed up settings and data to {} (`seagent update --rollback --restore-data` restores them)", b.display()),
        Err(e) => eprintln!("warning: could not back up settings and data before updating ({e}); `--rollback` will only restore the binary"),
    }
    let restart = daemon_running(&paths) && !a.flag("no-restart");
    if restart {
        run_self(&["daemon", "stop"]);
    }
    let prev = install_binary(&exe, &bundle.bin)?;
    if let Some(share) = installed_share(&exe) {
        match install_share(&share, &bundle.share) {
            Ok(0) => {}
            Ok(n) => println!("refreshed {n} bundled file(s) in {}", share.display()),
            Err(e) => eprintln!("warning: the new binary is in place but the bundled data in {} was not refreshed: {e}", share.display()),
        }
    }
    println!("updated seagent {} → {} (previous binary: {}; `seagent update --rollback` restores it)", env!("CARGO_PKG_VERSION"), r.tag, prev.display());
    if restart {
        #[cfg(not(any(target_os = "macos", windows, target_os = "android", target_os = "ios")))]
        let unit = std::process::Command::new("systemctl").args(["--user", "is-active", "--quiet", "seagentd.service"]).status().is_ok_and(|s| s.success());
        #[cfg(any(target_os = "macos", windows, target_os = "android", target_os = "ios"))]
        let unit = crate::ops::service_os::managed();
        if unit {
            #[cfg(not(any(target_os = "macos", windows, target_os = "android", target_os = "ios")))]
            let _ = std::process::Command::new("systemctl").args(["--user", "restart", "seagentd.service"]).status();
            #[cfg(any(target_os = "macos", windows, target_os = "android", target_os = "ios"))]
            let _ = crate::ops::service_os::restart_managed();
        } else {
            run_self(&["daemon", "start"]);
        }
        println!("daemon restarted on the new version");
    }
    Ok(0)
}

const ROLLBACK_FILE: &str = "update-rollback.json";

/// Config + data (no sessions: they only grow) archived before an update replaces the binary.
pub fn pre_update_backup(paths: &Paths, to: &str) -> Result<PathBuf, String> {
    let from = env!("CARGO_PKG_VERSION");
    let file = paths.data.join("backups").join(format!("pre-update-{from}-to-{}.tar.gz", to.trim_start_matches('v')));
    let (file, _) = crate::ops::backup::create(paths, &file, &crate::ops::backup::Opts { label: format!("before update {from} -> {to}"), ..Default::default() })?;
    std::fs::create_dir_all(&paths.data).map_err(|e| e.to_string())?;
    let rec = json!({"from": from, "to": to, "backup": file.display().to_string(), "at": seagent_kernel::util::unix_now()});
    std::fs::write(paths.data.join(ROLLBACK_FILE), rec.to_string()).map_err(|e| e.to_string())?;
    Ok(file)
}

/// The last update's `{from, to, backup}` record.
pub fn rollback_record(paths: &Paths) -> Option<Value> {
    serde_json::from_str(&std::fs::read_to_string(paths.data.join(ROLLBACK_FILE)).ok()?).ok()
}

/// What `seagent reset --scope` clears (OpenClaw `reset`): config | sessions | memory | state | all.
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
                return usage("usage: seagent reset --scope config|sessions|memory|state|all --yes");
            }
            if daemon_running(&paths) {
                return Err("seagentd is running; stop it first (seagent daemon stop)".into());
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
                return Err(format!("this stops and removes the seagent service{}; re-run with --yes", if a.flag("purge") { format!(" and DELETES {} and {}", paths.config_dir.display(), paths.data.display()) } else { String::new() }).into());
            }
            if a.flag("purge") {
                // Refuse a suicidal target before the daemon is stopped: a bad SEAGENT_HOME must not
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
            println!("seagent uninstalled{}", if a.flag("remove-binary") { "" } else { " (binary kept; --remove-binary deletes it)" });
            Ok(0)
        })()),
        _ => None,
    }
}

// ───────────────────────── uninstall plan (Hermes `uninstall.py`) ─────────────────────────

/// What `seagent uninstall` would remove. `config`/`data` need `--purge`; every profile's directory
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
        // `SEAGENT_HOME` of `/`, `$HOME` or `/etc` must fail loudly here, not erase the box.
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

/// Refuse a `--purge` target that is not a plausible per-user seagent directory.
///
/// The uninstall path deletes `<target>` with a recursive `remove_dir_all`. `SEAGENT_HOME` comes from
/// the environment, so a typo or an inherited value (`SEAGENT_HOME=/`, `SEAGENT_HOME=$HOME`, a symlink to
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
            "refusing to purge {}: {why}. `seagent uninstall --purge` deletes SEAGENT_HOME/config and SEAGENT_HOME/data \
             recursively; set a proper SEAGENT_HOME (e.g. `SEAGENT_HOME=\"$HOME/.seagent\"`) and re-run, or remove that \
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
/// second run is a no-op). The `seagent.prev` rollback copy goes with the binary.
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
    fn offline_mode_skips_the_update_check_ent039() {
        let offline = seagent_net::http::NetConfig { offline: true, ..Default::default() };
        seagent_net::http::with_config(offline, || {
            assert!(releases("http://127.0.0.1:9/never").unwrap_err().contains("offline mode"));
            assert!(check_text(&Config::default()).contains("skipped: offline mode"));
        });
    }

    #[test]
    fn versions_and_channels() {
        assert!(newer("v1.2.0", "1.1.9") && !newer("1.0.0", "1.0.0") && newer("1.0.0", "1.0.0-rc.1") && newer("1.0.0-rc.2", "1.0.0-rc.1") && !newer("0.9", "0.10.0"));
        let rel = |t: &str, p: bool| Release { tag: t.into(), prerelease: p, notes: String::new(), asset: None, sums: None, sig: None };
        let rs = vec![rel("v0.3.0-beta.1", true), rel("v0.2.0", false), rel("v0.3.0-dev.5", true)];
        assert_eq!(pick_in(&rs, "stable", None, "").unwrap().unwrap().tag, "v0.2.0");
        assert_eq!(pick_in(&rs, "beta", None, "").unwrap().unwrap().tag, "v0.3.0-beta.1");
        assert_eq!(pick_in(&rs, "dev", None, "").unwrap().unwrap().tag, "v0.3.0-dev.5");
        assert_eq!(pick_in(&rs, "stable", Some("0.3.0-beta.1"), "").unwrap().unwrap().tag, "v0.3.0-beta.1");
        assert!(pick_in(&rs, "nightly", None, "").is_err());
        assert!(managed(Path::new("/nix/store/abc/bin/seagent")).is_some() && managed(Path::new("/home/u/.local/bin/seagent")).is_none());
    }

    #[test]
    fn uninstall_plan_purges_profiles_and_keeps_a_managed_binary() {
        let t = seagent_core::tmp::TempDir::new("seagent-uninst");
        let root = t.path();
        let paths = Paths { data: root.join("data"), config_dir: root.join("config"), runtime: root.join("run"), ..Default::default() };
        for d in [&paths.data, &paths.config_dir] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(paths.data.join("session.jsonl"), "{}").unwrap();
        let exe = root.join("bin/seagent");
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
        let managed_exe = Path::new("/nix/store/abc-seagent-1.0/bin/seagent");
        let p = plan(&paths, false, false, true, managed_exe).unwrap();
        assert!(p.binary.is_none() && p.binary_kept.is_some_and(|w| w.contains("Nix")), "{p:?}");
    }

    /// A `--purge` target of `/`, `$HOME` or a system directory would take the machine (or the
    /// user's home) with it: the guard has to refuse those before anything is deleted.
    #[test]
    fn purge_refuses_the_home_or_a_system_directory() {
        let t = seagent_core::tmp::TempDir::new("seagent-uninst");
        let fake_home = t.path().join("home");
        std::fs::create_dir_all(&fake_home).unwrap();
        let ok = |p: &Path| purge_target_ok_in(p, Some(fake_home.clone()));
        for bad in ["/", "/home", "/root", "/usr", "/usr/local", "/etc", "/var"] {
            let e = ok(Path::new(bad)).unwrap_err();
            assert!(e.contains("refusing to purge") && e.contains("SEAGENT_HOME="), "{bad}: {e}");
        }
        assert!(ok(Path::new("")).unwrap_err().contains("empty"));
        assert!(ok(&fake_home).unwrap_err().contains("home"), "the home directory itself is refused");
        // Deep, per-user directories are fine (that is where a real SEAGENT_HOME lives).
        let deep = fake_home.join(".seagent");
        std::fs::create_dir_all(deep.join("data")).unwrap();
        assert!(ok(&deep).is_ok(), "{}", deep.display());
        // A symlink is judged by what it points at.
        let link = t.path().join("to-root");
        std::os::unix::fs::symlink("/", &link).unwrap();
        assert!(ok(&link).unwrap_err().contains("refusing to purge"));
        // `.`/`..` are refused before canonicalisation can hide where they point.
        assert!(ok(&t.path().join("home/../home")).unwrap_err().contains(".."));
        // `plan` runs the same guard, so the CLI cannot skip it.
        let bad = Paths { data: PathBuf::from("/usr"), config_dir: PathBuf::from("/etc"), runtime: PathBuf::from("/run"), ..Default::default() };
        let e = plan(&bad, true, false, false, Path::new("/opt/seagent")).unwrap_err();
        assert!(e.contains("refusing to purge /usr") && e.contains("system directory"), "{e}");
        let good = Paths { data: deep.join("data"), config_dir: deep.join("config"), runtime: deep.join("run"), ..Default::default() };
        assert!(plan(&good, true, false, false, Path::new("/opt/seagent")).is_ok());
    }

    #[test]
    fn fetch_verifies_checksums_against_a_fake_release_server() {
        // The asset name is the one release.yml publishes (not a name made up here), and the
        // archive has the layout make-tarball.sh produces: bin/seagent + share/seagent/….
        let t = asset_names(std::env::consts::ARCH)[0].trim_end_matches(".tar.gz").trim_start_matches("seagent-").to_string();
        assert_eq!(t, target());
        let bin = b"#!/bin/sh\necho seagent 9.9.9\n".to_vec();
        let tgz = archive::gzip(&archive::tar(&[
            archive::Entry { path: "./bin/seagent".into(), data: bin.clone(), mode: 0o755, dir: false },
            archive::Entry { path: "./share/seagent/skills/x/SKILL.md".into(), data: b"---\nname: x\n---\n".to_vec(), mode: 0o644, dir: false },
        ]));
        let sum = seagent_net::crypto::hex(&seagent_net::crypto::sha256(&tgz));
        let (tgz2, sum2) = (tgz.clone(), sum.clone());
        let tt = t.clone();
        // Release signing: sign.sh signs the SHA256SUMS text with Ed25519 and publishes base64.
        let seed = [7u8; 32];
        let sums_text = format!("{sum}  seagent-{t}.tar.gz\n");
        let sig2 = seagent_net::crypto::b64(&seagent_net::crypto::ed25519_sign(&seed, sums_text.as_bytes()));
        let pubkey = seagent_net::crypto::b64(&seagent_net::crypto::ed25519_public(&seed));
        let (base, _log) = fake::serve(Arc::new(move |r: &fake::Req| {
            let me = "http://HOST";
            match r.path.as_str() {
                p if p.starts_with("/repos/o/r/releases") => (200, "application/json".into(), json!([
                    {"tag_name": "v9.9.9", "prerelease": false, "body": "notes", "assets": [{"name": format!("seagent-{tt}.tar.gz"), "browser_download_url": format!("{me}/dl/seagent.tgz")}, {"name": "SHA256SUMS", "browser_download_url": format!("{me}/dl/sums")}, {"name": "SHA256SUMS.sig", "browser_download_url": format!("{me}/dl/sig")}]},
                    {"tag_name": "v9.9.8", "prerelease": false, "assets": [{"name": format!("seagent-{tt}.tar.gz"), "browser_download_url": format!("{me}/dl/seagent.tgz")}, {"name": "SHA256SUMS", "browser_download_url": format!("{me}/dl/badsums")}]}
                ]).to_string().into_bytes()),
                "/dl/seagent.tgz" => (200, "application/octet-stream".into(), tgz2.clone()),
                "/dl/sums" => (200, "text/plain".into(), format!("{sum2}  seagent-{tt}.tar.gz\n").into_bytes()),
                "/dl/sig" => (200, "text/plain".into(), sig2.clone().into_bytes()),
                "/dl/badsums" => (200, "text/plain".into(), format!("{}  seagent-{tt}.tar.gz\n", "0".repeat(64)).into_bytes()),
                _ => (404, "text/plain".into(), vec![]),
            }
        }));
        let fix = |r: Release| Release { asset: r.asset.map(|(n, u)| (n, u.replace("http://HOST", &base))), sums: r.sums.map(|u| u.replace("http://HOST", &base)), sig: r.sig.map(|u| u.replace("http://HOST", &base)), ..r };
        let rs: Vec<Release> = releases(&format!("{base}/repos/o/r")).unwrap().into_iter().map(fix).collect();
        assert_eq!(rs.len(), 2);
        assert_eq!(fetch_bundle(&rs[0], "").unwrap().bin, bin);
        let b = fetch_bundle(&rs[0], &pubkey).unwrap();
        assert_eq!(b.bin, bin);
        assert_eq!(b.share.len(), 1, "{:?}", b.share.iter().map(|e| &e.path).collect::<Vec<_>>());
        assert_eq!(b.share[0].path, "skills/x/SKILL.md");
        // A key that did not sign this release, or a release without a signature, is refused.
        let other = seagent_net::crypto::b64(&seagent_net::crypto::ed25519_public(&[9u8; 32]));
        assert!(fetch_bundle(&rs[0], &other).unwrap_err().contains("does not verify"));
        assert!(fetch_bundle(&rs[1], &pubkey).unwrap_err().contains("no SHA256SUMS.sig"));
        assert!(fetch_bundle(&rs[1], "").unwrap_err().contains("checksum mismatch"));
        // Install over a fake "current" binary, then roll back.
        let t = seagent_core::tmp::TempDir::new("seagent-upd");
        let d = t.path().to_path_buf();
        std::fs::create_dir_all(&d).unwrap();
        let exe = d.join("seagent");
        std::fs::write(&exe, "#!/bin/sh\necho seagent 0.0.1\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        install_binary(&exe, &bin).unwrap();
        assert!(std::fs::read_to_string(&exe).unwrap().contains("9.9.9"));
        assert!(install_binary(&exe, b"not a program").is_err(), "smoke test guards the swap");
        rollback(&exe).unwrap();
        assert!(std::fs::read_to_string(&exe).unwrap().contains("0.0.1"));
    }

    #[test]
    fn asset_names_match_release_workflow() {
        let yml = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/release.yml")).expect("release.yml");
        let line = yml.lines().find(|l| l.trim_start().starts_with("target: [")).expect("build matrix");
        let triples: Vec<&str> = line.split('[').nth(1).unwrap().split(']').next().unwrap().split(',').map(str::trim).collect();
        assert_eq!(triples.len(), 4);
        // The workflow names the file `seagent-$t.tar.gz`, `t` being a matrix triple.
        assert!(yml.contains("\"seagent-$t.tar.gz\""), "tarball naming in release.yml changed");
        for arch in ["x86_64", "aarch64"] {
            let names = asset_names(arch);
            for libc in ["gnu", "musl"] {
                let published = format!("seagent-{arch}-unknown-linux-{libc}.tar.gz");
                assert!(triples.contains(&format!("{arch}-unknown-linux-{libc}").as_str()), "{published} is not built by release.yml");
                assert!(names.contains(&published), "seagent update does not look for {published}");
            }
            assert!(names[0].contains("musl"), "static build preferred");
        }
        // install.sh downloads the same musl names.
        let sh = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/install.sh")).unwrap();
        assert!(sh.contains("seagent-$target.tar.gz") && sh.contains("$arch-unknown-linux-musl"));
    }

    #[test]
    fn release_index_picks_the_published_asset_name() {
        let arch = std::env::consts::ARCH;
        let (base, _log) = fake::serve(Arc::new(move |_r: &fake::Req| {
            let a = |n: String| json!({"name": n, "browser_download_url": "http://h/x"});
            (200, "application/json".into(), json!([{"tag_name": "v1.0.0", "assets": [a(format!("seagent-{arch}-unknown-linux-gnu.tar.gz")), a(format!("seagent-{arch}-unknown-linux-musl.tar.gz")), a("seagent-other-unknown-linux-musl.tar.gz".into()), a("SHA256SUMS".into())]}]).to_string().into_bytes())
        }));
        let rs = releases(&format!("{base}/repos/o/r")).unwrap();
        assert_eq!(rs[0].asset.as_ref().unwrap().0, format!("seagent-{arch}-unknown-linux-musl.tar.gz"));
        assert!(rs[0].sums.is_some() && rs[0].sig.is_none());
    }

    #[test]
    fn lts_follows_its_line_or_the_notes_marker() {
        let rel = |t: &str, notes: &str| Release { tag: t.into(), prerelease: false, notes: notes.into(), asset: None, sums: None, sig: None };
        let rs = vec![rel("v1.4.1", ""), rel("v1.4.3", ""), rel("v1.5.0", ""), rel("v2.0.0", "Big release")];
        // Configured line: newest patch of 1.4, never the newer minors.
        assert_eq!(pick_in(&rs, "lts", None, "1.4").unwrap().unwrap().tag, "v1.4.3");
        assert_eq!(pick_in(&rs, "stable", None, "1.4").unwrap().unwrap().tag, "v2.0.0");
        // No line configured: only releases whose notes say LTS.
        let rs = vec![rel("v1.4.3", "## v1.4.3\nLTS\n- fixes"), rel("v1.5.0", ""), rel("v1.4.2", "LTS")];
        assert_eq!(pick_in(&rs, "lts", None, "").unwrap().unwrap().tag, "v1.4.3");
        assert!(pick_in(&[rel("v1.0.0", "")], "lts", None, "").unwrap().is_none());
        assert!(pick_in(&rs, "bogus", None, "").unwrap_err().contains("lts"));
    }

    #[test]
    fn verify_key_accepts_pem_and_raw() {
        let seed = [3u8; 32];
        let raw = seagent_net::crypto::ed25519_public(&seed);
        let mut der = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
        der.extend(raw);
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", seagent_net::crypto::b64(&der));
        assert_eq!(parse_verify_key(&pem).unwrap(), raw);
        assert_eq!(parse_verify_key(&seagent_net::crypto::b64(&raw)).unwrap(), raw);
        assert!(parse_verify_key("AAAA").is_err());
        let sig = seagent_net::crypto::b64(&seagent_net::crypto::ed25519_sign(&seed, b"sums"));
        assert!(verify_signature(b"sums", &sig, &pem).is_ok());
        assert!(verify_signature(b"tampered", &sig, &pem).is_err());
    }

    #[test]
    fn share_dir_is_swapped_in_and_package_installs_are_managed() {
        let t = seagent_core::tmp::TempDir::new("seagent-upd-share");
        let r = t.path();
        let share = r.join("prefix/lib/seagent/share");
        std::fs::create_dir_all(share.join("skills/old")).unwrap();
        std::fs::write(share.join("skills/old/SKILL.md"), "old").unwrap();
        std::fs::create_dir_all(r.join("prefix/bin")).unwrap();
        let exe = r.join("prefix/bin/seagent");
        assert_eq!(installed_share(&exe).unwrap().canonicalize().unwrap(), share.canonicalize().unwrap());
        let n = install_share(&installed_share(&exe).unwrap(), &[archive::Entry::file("skills/new/SKILL.md", b"new".to_vec())]).unwrap();
        assert_eq!(n, 1);
        assert!(share.join("skills/new/SKILL.md").is_file() && !share.join("skills/old").exists());
        assert!(!share.with_extension("old").exists() && !share.with_extension("new").exists());
        assert!(install_share(&share, &[archive::Entry::file("../evil", b"x".to_vec())]).is_err(), "no path escapes");
        assert!(share.join("skills/new").is_dir(), "a rejected archive leaves the install intact");
        assert!(managed(Path::new("/usr/bin/seagent")).is_some() && managed(Path::new("/usr/lib/seagent/seagent")).is_some());
        assert!(managed(&exe).is_none());
        std::fs::write(r.join("prefix/bin/seagent.managed"), "").unwrap();
        assert!(managed(&exe).is_some());
    }

    #[test]
    fn rollback_can_restore_settings_and_data() {
        let t = seagent_core::tmp::TempDir::new("seagent-upd-data");
        let root = t.path();
        let p = Paths { data: root.join("data"), config_dir: root.join("config"), runtime: root.join("run"), ..Default::default() };
        std::fs::create_dir_all(p.data.join("memory")).unwrap();
        std::fs::create_dir_all(&p.config_dir).unwrap();
        std::fs::write(p.user_config(), "identity = \"v1\"\n").unwrap();
        std::fs::write(p.data.join("memory/MEMORY.md"), "before").unwrap();
        let file = pre_update_backup(&p, "v9.9.9").unwrap();
        assert!(file.is_file());
        let rec = rollback_record(&p).unwrap();
        assert_eq!(rec["to"], "v9.9.9");
        // The new version migrates things...
        std::fs::write(p.user_config(), "identity = \"v2\"\n").unwrap();
        std::fs::write(p.data.join("memory/MEMORY.md"), "after").unwrap();
        // ...and --rollback --restore-data puts them back.
        let (n, _pre) = crate::ops::backup::restore(&p, Path::new(rec["backup"].as_str().unwrap()), false).unwrap();
        assert!(n >= 2);
        assert_eq!(std::fs::read_to_string(p.user_config()).unwrap(), "identity = \"v1\"\n");
        assert_eq!(std::fs::read_to_string(p.data.join("memory/MEMORY.md")).unwrap(), "before");
    }

    #[test]
    fn reset_scopes() {
        let t = seagent_core::tmp::TempDir::new("seagent-reset");
        let root = t.path();
        let p = Paths { data: root.join("data"), config_dir: root.join("config"), runtime: root.join("run"), ..Default::default() };
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
