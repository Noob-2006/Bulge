//! Backups (OpenClaw `backup create|verify|restore|list` + retention, Hermes `backup` /
//! `import` and `/snapshot`). An archive is a `.tar.gz` with `MANIFEST.json` (sha-256 of
//! every file) plus `config/…` and `data/…` mirroring the profile's directories.
//! Restore verifies first, refuses while the daemon runs, and keeps a pre-restore
//! archive of the current state. Retention keeps the newest archive in each of the last
//! N daily / weekly / monthly UTC buckets. `[backup] enabled` makes the daemon back up
//! every `every_hours`.

use crate::args::Args;
use crate::ops::archive::{self, Entry};
use crate::{usage, R};
use seagent_kernel::config::{BackupConfig, Config, Paths};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const COMMANDS: &[&str] = &["backup", "backups", "snapshot"];
pub const VALUE_FLAGS: &[&str] = &["to", "every", "keep-daily", "keep-weekly", "keep-monthly", "include-dir"];
pub const BOOL_FLAGS: &[&str] = &["dry-run", "verify", "only-config", "exclude-secrets", "no-sessions", "clean"];

#[derive(Debug, Clone, Default)]
pub struct Opts {
    pub only_config: bool,
    pub exclude_secrets: bool,
    pub sessions: bool,
    /// Extra directories (e.g. workspaces) stored under `extra/<n>/`.
    pub include: Vec<PathBuf>,
    pub label: String,
}

/// Never archived: runtime state, our own backups, sockets, logs of logs.
fn skip(p: &Path, o: &Opts) -> bool {
    let n = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    if n.ends_with(".sock") || ["run", "backups", "snapshots", "profiles", "profile-exports", ".git", "target", "node_modules"].contains(&n.as_str()) {
        return true;
    }
    // A4: the encrypted store and its sealed key are secrets too.
    if o.exclude_secrets && ["secrets.toml", "secrets.enc", "secrets.key", ".env"].contains(&n.as_str()) {
        return true;
    }
    !o.sessions && n == "sessions"
}

pub fn default_dir(paths: &Paths, cfg: &BackupConfig) -> PathBuf {
    if cfg.dir.is_empty() {
        paths.data.join("backups")
    } else {
        PathBuf::from(&cfg.dir)
    }
}

fn host() -> String {
    std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()).ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "host".into())
}

pub fn plan(paths: &Paths, o: &Opts) -> Result<Vec<Entry>, String> {
    let mut entries = vec![];
    if o.only_config {
        for f in ["config.toml", ".env", "secrets.toml", "secrets.enc", "secrets.key"] {
            let p = paths.config_dir.join(f);
            if p.exists() && !skip(&p, o) {
                entries.push(Entry { path: format!("config/{f}"), data: std::fs::read(&p).map_err(|e| e.to_string())?, mode: 0o600, dir: false });
            }
        }
    } else {
        archive::collect(&paths.config_dir, "config/", &|p| skip(p, o), &mut entries)?;
        archive::collect(&paths.data, "data/", &|p| skip(p, o), &mut entries)?;
    }
    for (i, d) in o.include.iter().enumerate() {
        archive::collect(d, &format!("extra/{i}/"), &|p| skip(p, o), &mut entries)?;
    }
    Ok(entries)
}

/// Build the archive bytes (manifest first).
pub fn build(paths: &Paths, o: &Opts) -> Result<(Vec<u8>, Value), String> {
    let mut entries = plan(paths, o)?;
    let files: Vec<Value> = entries.iter().filter(|e| !e.dir).map(|e| json!({"path": e.path, "size": e.data.len(), "sha256": seagent_net::crypto::hex(&seagent_net::crypto::sha256(&e.data))})).collect();
    let manifest = json!({
        "format": 1, "created": seagent_kernel::util::unix_now(), "host": host(), "seagent": env!("CARGO_PKG_VERSION"),
        "profile": crate::ops::profile::current(), "label": o.label, "only_config": o.only_config, "secrets": !o.exclude_secrets,
        "extra": o.include.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(), "files": files,
    });
    entries.insert(0, Entry::file("MANIFEST.json", serde_json::to_vec_pretty(&manifest).unwrap_or_default()));
    Ok((archive::gzip(&archive::tar(&entries)), manifest))
}

pub fn create(paths: &Paths, out: &Path, o: &Opts) -> Result<(PathBuf, Value), String> {
    let (bytes, manifest) = build(paths, o)?;
    let file = if out.extension().is_some_and(|e| e == "gz") { out.to_path_buf() } else { out.join(format!("seagent-{}-{}.tar.gz", host(), stamp())) };
    if let Some(d) = file.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700));
    }
    let tmp = file.with_extension("partial");
    std::fs::write(&tmp, &bytes).map_err(|e| format!("{}: {e}", tmp.display()))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    std::fs::rename(&tmp, &file).map_err(|e| e.to_string())?;
    Ok((file, manifest))
}

fn stamp() -> String {
    seagent_kernel::util::fmt_time(seagent_kernel::util::unix_now(), 0).replace([' ', ':'], "").replace('-', "") + &format!("-{}", seagent_kernel::util::random_hex(2))
}

/// Check every file against the manifest. Returns the manifest and entries.
pub fn verify(file: &Path) -> Result<(Value, Vec<Entry>), String> {
    let bytes = std::fs::read(file).map_err(|e| format!("{}: {e}", file.display()))?;
    let entries = archive::untar(&archive::gunzip(&bytes)?)?;
    let m: Value = entries.iter().find(|e| e.path == "MANIFEST.json").and_then(|e| serde_json::from_slice(&e.data).ok()).ok_or("not an seagent backup (no MANIFEST.json)")?;
    let files = m["files"].as_array().ok_or("manifest has no file list")?;
    for f in files {
        let path = f["path"].as_str().unwrap_or("");
        archive::safe_join(Path::new("/"), path)?;
        let e = entries.iter().find(|e| e.path == path).ok_or_else(|| format!("missing from archive: {path}"))?;
        if seagent_net::crypto::hex(&seagent_net::crypto::sha256(&e.data)) != f["sha256"].as_str().unwrap_or("") {
            return Err(format!("checksum mismatch: {path}"));
        }
    }
    let listed = files.len();
    let actual = entries.iter().filter(|e| !e.dir && e.path != "MANIFEST.json").count();
    if listed != actual {
        return Err(format!("archive holds {actual} files but the manifest lists {listed}"));
    }
    Ok((m, entries))
}

/// Restore into `paths` (only files in the manifest). With `clean`, config/ and data/
/// are emptied first (the pre-restore archive still holds them).
pub fn restore(paths: &Paths, file: &Path, clean: bool) -> Result<(usize, PathBuf), String> {
    let (_, entries) = verify(file)?;
    if seagent_kernel::daemon::call(&paths.socket(), "ping", json!({})).is_ok() {
        return Err("seagentd is running; stop it first (seagent daemon stop)".into());
    }
    let (pre, _) = create(paths, &paths.data.join("backups").join(format!("pre-restore-{}.tar.gz", stamp())), &Opts { sessions: true, label: "pre-restore".into(), ..Default::default() })?;
    if clean {
        for d in [&paths.config_dir, &paths.data] {
            for e in std::fs::read_dir(d).map(|r| r.flatten().collect::<Vec<_>>()).unwrap_or_default() {
                if e.file_name() == "backups" {
                    continue;
                }
                let _ = if e.path().is_dir() { std::fs::remove_dir_all(e.path()) } else { std::fs::remove_file(e.path()) };
            }
        }
    }
    let mut n = 0;
    for (prefix, root) in [("config/", &paths.config_dir), ("data/", &paths.data)] {
        let mine: Vec<Entry> = entries.iter().filter_map(|e| e.path.strip_prefix(prefix).map(|r| Entry { path: r.to_string(), ..e.clone() })).filter(|e| !e.path.is_empty()).collect();
        n += archive::extract(&mine, root)?;
    }
    Ok((n, pre))
}

/// Archives in `dir`, newest first, with their creation time (from the file name's mtime).
pub fn list(dir: &Path) -> Vec<(PathBuf, i64, u64)> {
    let mut v: Vec<(PathBuf, i64, u64)> = std::fs::read_dir(dir)
        .map(|r| {
            r.flatten()
                .filter(|e| e.file_name().to_string_lossy().ends_with(".tar.gz"))
                .filter_map(|e| {
                    let m = e.metadata().ok()?;
                    let t = m.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as i64;
                    Some((e.path(), t, m.len()))
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort_by_key(|x| std::cmp::Reverse(x.1));
    v
}

/// Which archives to keep: newest per day/week/month bucket for the newest N buckets of each.
pub fn retained(items: &[(PathBuf, i64, u64)], daily: u32, weekly: u32, monthly: u32) -> Vec<PathBuf> {
    let mut keep: Vec<PathBuf> = vec![];
    let mut pick = |key: &dyn Fn(i64) -> i64, n: u32| {
        let mut seen = vec![];
        for (p, t, _) in items {
            let k = key(*t);
            if seen.contains(&k) {
                continue;
            }
            if seen.len() as u32 >= n {
                break;
            }
            seen.push(k);
            if !keep.contains(p) {
                keep.push(p.clone());
            }
        }
    };
    pick(&|t| t.div_euclid(86_400), daily);
    pick(&|t| (t.div_euclid(86_400) + 3).div_euclid(7), weekly); // weeks start Monday (1970-01-01 was a Thursday)
    pick(&|t| {
        let (y, m, _) = seagent_kernel::util::civil_from_days(t.div_euclid(86_400));
        y * 12 + m as i64
    }, monthly);
    keep
}

pub fn prune(dir: &Path, daily: u32, weekly: u32, monthly: u32, dry: bool) -> Result<Vec<PathBuf>, String> {
    let items: Vec<_> = list(dir).into_iter().filter(|(p, _, _)| !p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("pre-restore-"))).collect();
    let keep = retained(&items, daily, weekly, monthly);
    let gone: Vec<PathBuf> = items.into_iter().map(|i| i.0).filter(|p| !keep.contains(p)).collect();
    if !dry {
        for p in &gone {
            std::fs::remove_file(p).map_err(|e| format!("{}: {e}", p.display()))?;
        }
    }
    Ok(gone)
}

/// One scheduled run: back up, then apply retention. Records the result in `<data>/backups/last.json`.
pub fn scheduled(paths: &Paths, cfg: &BackupConfig) -> Result<PathBuf, String> {
    let dir = default_dir(paths, cfg);
    let r = create(paths, &dir, &Opts { exclude_secrets: cfg.exclude_secrets, sessions: cfg.include_sessions, label: "scheduled".into(), ..Default::default() });
    let rec = match &r {
        Ok((p, _)) => json!({"ok": true, "at": seagent_kernel::util::unix_now(), "file": p}),
        Err(e) => json!({"ok": false, "at": seagent_kernel::util::unix_now(), "error": e}),
    };
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(dir.join("last.json"), rec.to_string());
    let (p, _) = r?;
    prune(&dir, cfg.keep_daily, cfg.keep_weekly, cfg.keep_monthly, false)?;
    Ok(p)
}

/// Daemon timer for `[backup] enabled = true`.
pub fn spawn_scheduler(paths: Paths, cfg: BackupConfig, stop: seagent_core::Cancel) -> Option<std::thread::JoinHandle<()>> {
    if !cfg.enabled {
        return None;
    }
    Some(std::thread::spawn(move || {
        let every = cfg.every_hours.max(1) as i64 * 3600;
        while !stop.is_cancelled() {
            let last = list(&default_dir(&paths, &cfg)).into_iter().find(|(p, _, _)| !p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("pre-restore-"))).map(|i| i.1).unwrap_or(0);
            if seagent_kernel::util::unix_now() - last >= every {
                match scheduled(&paths, &cfg) {
                    Ok(p) => eprintln!("seagentd: backup written to {}", p.display()),
                    Err(e) => eprintln!("seagentd: scheduled backup failed: {e}"),
                }
            }
            for _ in 0..600 {
                if stop.is_cancelled() {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }))
}

// ───────────── snapshots (Hermes /snapshot) ─────────────

fn snap_dir(paths: &Paths) -> PathBuf {
    paths.data.join("snapshots")
}

/// Config + state without session history: config, secrets, memory, skills, commands, schedules.
pub fn snapshot_create(paths: &Paths, label: &str) -> Result<String, String> {
    let (p, _) = create(paths, &snap_dir(paths).join(format!("snap-{}.tar.gz", stamp())), &Opts { sessions: false, label: label.into(), ..Default::default() })?;
    Ok(p.file_name().unwrap().to_string_lossy().trim_end_matches(".tar.gz").to_string())
}

pub fn snapshot_list(paths: &Paths) -> Vec<(String, i64, String)> {
    list(&snap_dir(paths)).into_iter().map(|(p, t, _)| {
        let label = verify(&p).ok().and_then(|(m, _)| m["label"].as_str().map(String::from)).unwrap_or_default();
        (p.file_name().unwrap().to_string_lossy().trim_end_matches(".tar.gz").to_string(), t, label)
    }).collect()
}

/// Restore a snapshot's files over the current ones (sessions untouched). Works while the
/// daemon runs: config changes apply on the next restart.
pub fn snapshot_restore(paths: &Paths, id: &str) -> Result<usize, String> {
    let m: Vec<_> = snapshot_list(paths).into_iter().filter(|s| s.0 == id || s.0.ends_with(id)).collect();
    let id = match m.len() {
        1 => m[0].0.clone(),
        0 => return Err(format!("no snapshot `{id}`")),
        _ => return Err(format!("`{id}` matches {} snapshots", m.len())),
    };
    let (_, entries) = verify(&snap_dir(paths).join(format!("{id}.tar.gz")))?;
    snapshot_create(paths, &format!("before restoring {id}"))?;
    let mut n = 0;
    for (prefix, root) in [("config/", &paths.config_dir), ("data/", &paths.data)] {
        let mine: Vec<Entry> = entries.iter().filter_map(|e| e.path.strip_prefix(prefix).map(|r| Entry { path: r.to_string(), ..e.clone() })).filter(|e| !e.path.is_empty()).collect();
        n += archive::extract(&mine, root)?;
    }
    Ok(n)
}

/// `/snapshot [create [label]|list|restore <id>]`.
pub fn snapshot_command(paths: &Paths, args: &str) -> Result<String, String> {
    let mut w = args.split_whitespace();
    match w.next().unwrap_or("list") {
        "create" | "new" | "save" => Ok(format!("snapshot {}", snapshot_create(paths, &w.collect::<Vec<_>>().join(" "))?)),
        "list" | "ls" => {
            let l = snapshot_list(paths);
            Ok(if l.is_empty() { "no snapshots (/snapshot create)".into() } else { l.iter().map(|(id, t, label)| format!("{id}  {}  {label}", seagent_kernel::util::fmt_time(*t, 480))).collect::<Vec<_>>().join("\n") })
        }
        "restore" => {
            let id = w.next().ok_or("usage: /snapshot restore <id>")?;
            Ok(format!("restored {} file(s) from {id}; the previous state was snapshotted. Restart the daemon (/restart) for config changes.", snapshot_restore(paths, id)?))
        }
        other => Err(format!("unknown `{other}` (create, list, restore)")),
    }
}

fn opts(a: &Args, _cfg: &Config) -> Result<Opts, String> {
    Ok(Opts {
        only_config: a.flag("only-config"),
        exclude_secrets: a.flag("exclude-secrets"),
        sessions: !a.flag("no-sessions"),
        include: a.vals("include-dir").iter().map(|d| PathBuf::from(d).canonicalize().map_err(|e| format!("{d}: {e}"))).collect::<Result<_, _>>()?,
        label: a.val("name").unwrap_or("").to_string(),
    })
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if !COMMANDS.contains(&cmd) {
        return None;
    }
    Some((|| -> R {
        let paths = Paths::from_env();
        let cfg = Config::load(Some(&paths.user_config()), None, &[]).unwrap_or_default();
        if cmd == "snapshot" {
            println!("{}", snapshot_command(&paths, &a.rest(0))?);
            return Ok(0);
        }
        let dir = a.val("to").map(PathBuf::from).unwrap_or_else(|| default_dir(&paths, &cfg.backup));
        let keep = |k: &str, d: u32| a.num::<u32>(k).map(|v| v.unwrap_or(d));
        match a.pos(0).unwrap_or("list") {
            "create" => {
                let o = opts(a, &cfg)?;
                if a.flag("dry-run") {
                    let entries = plan(&paths, &o)?;
                    let bytes: usize = entries.iter().map(|e| e.data.len()).sum();
                    if a.flag("json") {
                        println!("{}", json!({"files": entries.iter().filter(|e| !e.dir).map(|e| &e.path).collect::<Vec<_>>(), "bytes": bytes}));
                    } else {
                        println!("would archive {} files ({:.1} MB) to {}", entries.iter().filter(|e| !e.dir).count(), bytes as f64 / 1e6, dir.display());
                    }
                    return Ok(0);
                }
                let out = a.val("output").map(PathBuf::from).unwrap_or(dir.clone());
                let (file, m) = create(&paths, &out, &o)?;
                if a.flag("verify") {
                    verify(&file)?;
                }
                let pruned = if a.val("keep-daily").is_some() || a.val("keep-weekly").is_some() || a.val("keep-monthly").is_some() {
                    prune(file.parent().unwrap(), keep("keep-daily", cfg.backup.keep_daily)?, keep("keep-weekly", cfg.backup.keep_weekly)?, keep("keep-monthly", cfg.backup.keep_monthly)?, false)?.len()
                } else {
                    0
                };
                if a.flag("json") {
                    println!("{}", json!({"file": file, "files": m["files"].as_array().map(|f| f.len()), "pruned": pruned}));
                } else {
                    println!("backup {} ({} files{}){}", file.display(), m["files"].as_array().map(|f| f.len()).unwrap_or(0), if a.flag("verify") { ", verified" } else { "" }, if pruned > 0 { format!(" · pruned {pruned} old") } else { String::new() });
                }
                Ok(0)
            }
            "verify" => {
                let f = a.need(1, "archive")?;
                let (m, _) = verify(Path::new(f))?;
                println!("ok · {} files · created {} on {} · seagent {}", m["files"].as_array().map(|f| f.len()).unwrap_or(0), seagent_kernel::util::fmt_time(m["created"].as_i64().unwrap_or(0), 480), m["host"].as_str().unwrap_or("?"), m["seagent"].as_str().unwrap_or("?"));
                Ok(0)
            }
            "restore" | "import" => {
                let f = PathBuf::from(a.need(1, "archive")?);
                if a.flag("dry-run") {
                    let (m, _) = verify(&f)?;
                    println!("would restore {} files into {} and {}", m["files"].as_array().map(|f| f.len()).unwrap_or(0), paths.config_dir.display(), paths.data.display());
                    return Ok(0);
                }
                if !a.flag("yes") {
                    return Err(format!("this overwrites {} and {} with the archive's files; re-run with --yes (a pre-restore backup is kept)", paths.config_dir.display(), paths.data.display()).into());
                }
                let (n, pre) = restore(&paths, &f, a.flag("clean"))?;
                println!("restored {n} files · previous state saved as {}", pre.display());
                Ok(0)
            }
            "list" | "ls" => {
                let l = list(&dir);
                if a.flag("json") {
                    println!("{}", json!(l.iter().map(|(p, t, s)| json!({"file": p, "time": t, "bytes": s})).collect::<Vec<_>>()));
                    return Ok(0);
                }
                if l.is_empty() {
                    println!("no backups in {}", dir.display());
                }
                for (p, t, s) in l {
                    println!("{}  {:>8.1} MB  {}", seagent_kernel::util::fmt_time(t, 480), s as f64 / 1e6, p.display());
                }
                if let Ok(last) = std::fs::read_to_string(dir.join("last.json")) {
                    println!("last scheduled run: {last}");
                }
                Ok(0)
            }
            "prune" => {
                let gone = prune(&dir, keep("keep-daily", cfg.backup.keep_daily)?, keep("keep-weekly", cfg.backup.keep_weekly)?, keep("keep-monthly", cfg.backup.keep_monthly)?, a.flag("dry-run"))?;
                for p in &gone {
                    println!("{} {}", if a.flag("dry-run") { "would remove" } else { "removed" }, p.display());
                }
                println!("{} archive(s) {}", gone.len(), if a.flag("dry-run") { "would be pruned" } else { "pruned" });
                Ok(0)
            }
            "schedule" => {
                match a.pos(1).unwrap_or("status") {
                    "enable" | "on" => {
                        crate::ops::confcli::set(&paths, "backup.enabled", "true")?;
                        if let Some(h) = a.val("every") {
                            let hours: u64 = h.trim_end_matches('h').parse().map_err(|_| "--every takes hours, e.g. 24h")?;
                            crate::ops::confcli::set(&paths, "backup.every_hours", &hours.to_string())?;
                        }
                        for k in ["keep-daily", "keep-weekly", "keep-monthly"] {
                            if let Some(v) = a.val(k) {
                                crate::ops::confcli::set(&paths, &format!("backup.{}", k.replace('-', "_")), v)?;
                            }
                        }
                        println!("scheduled backups on (seagentd backs up while it runs; restart it to apply)");
                    }
                    "disable" | "off" => {
                        crate::ops::confcli::set(&paths, "backup.enabled", "false")?;
                        println!("scheduled backups off");
                    }
                    _ => println!("scheduled backups {} · every {}h · keep {}d/{}w/{}m · to {}", if cfg.backup.enabled { "on" } else { "off" }, cfg.backup.every_hours, cfg.backup.keep_daily, cfg.backup.keep_weekly, cfg.backup.keep_monthly, dir.display()),
                }
                Ok(0)
            }
            other => usage(format!("unknown `backup {other}` (create, verify, restore, list, prune, schedule)")),
        }
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> Paths {
        let root = seagent_core::tmp::scratch_path(format!("seagent-bk-{}", seagent_kernel::util::random_hex(6)));
        let p = Paths { data: root.join("data"), config_dir: root.join("config"), runtime: root.join("run"), ..Default::default() };
        std::fs::create_dir_all(p.data.join("sessions")).unwrap();
        std::fs::create_dir_all(p.data.join("memory")).unwrap();
        std::fs::create_dir_all(&p.config_dir).unwrap();
        std::fs::write(p.user_config(), "identity = \"v1\"\n").unwrap();
        std::fs::write(p.secrets(), "K = \"s\"\n").unwrap();
        std::fs::write(p.data.join("sessions/a.jsonl"), "{}\n").unwrap();
        std::fs::write(p.data.join("memory/MEMORY.md"), "fact").unwrap();
        p
    }

    #[test]
    fn create_verify_restore() {
        let p = paths();
        let (f, m) = create(&p, &p.data.join("backups"), &Opts { sessions: true, ..Default::default() }).unwrap();
        assert_eq!(m["files"].as_array().unwrap().len(), 4);
        verify(&f).unwrap();
        std::fs::write(p.user_config(), "identity = \"v2\"\n").unwrap();
        std::fs::remove_file(p.data.join("memory/MEMORY.md")).unwrap();
        let (n, pre) = restore(&p, &f, false).unwrap();
        assert_eq!(n, 4);
        assert!(std::fs::read_to_string(p.user_config()).unwrap().contains("v1"));
        assert_eq!(std::fs::read_to_string(p.data.join("memory/MEMORY.md")).unwrap(), "fact");
        assert!(verify(&pre).unwrap().1.iter().any(|e| e.path == "config/config.toml" && e.data == b"identity = \"v2\"\n"));
        // Excluding secrets/sessions; tampering is caught.
        let (f2, m2) = create(&p, &p.data.join("x.tar.gz"), &Opts { exclude_secrets: true, sessions: false, ..Default::default() }).unwrap();
        let names: Vec<&str> = m2["files"].as_array().unwrap().iter().filter_map(|f| f["path"].as_str()).collect();
        assert!(!names.contains(&"config/secrets.toml") && !names.iter().any(|n| n.contains("sessions")), "{names:?}");
        let entries = archive::untar(&archive::gunzip(&std::fs::read(&f2).unwrap()).unwrap()).unwrap();
        let tampered: Vec<Entry> = entries.into_iter().map(|mut e| {
            if e.path == "config/config.toml" {
                e.data = b"evil".to_vec();
            }
            e
        }).collect();
        std::fs::write(&f2, archive::gzip(&archive::tar(&tampered))).unwrap();
        assert!(verify(&f2).unwrap_err().contains("checksum"));
        let only = plan(&p, &Opts { only_config: true, ..Default::default() }).unwrap();
        assert!(only.iter().all(|e| e.path.starts_with("config/")));
    }

    #[test]
    fn retention_buckets() {
        let day = 86_400;
        let base = 20_000 * day; // a Monday-aligned-ish epoch day
        let items: Vec<(PathBuf, i64, u64)> = (0..40).map(|i| (PathBuf::from(format!("b{i}")), base - i * day / 2, 1)).collect();
        let keep = retained(&items, 3, 2, 1);
        // b0 is day D; b1 (-12h) and b2 (-24h) share day D-1; b3/b4 share D-2.
        assert!(keep.contains(&PathBuf::from("b0")) && keep.contains(&PathBuf::from("b1")) && keep.contains(&PathBuf::from("b3")));
        assert!(!keep.contains(&PathBuf::from("b2")), "only the newest of each day");
        assert!(keep.len() <= 3 + 2 + 1);
        assert!(retained(&items, 0, 0, 0).is_empty());
    }

    #[test]
    fn snapshots() {
        let p = paths();
        let id = snapshot_create(&p, "before experiment").unwrap();
        std::fs::write(p.user_config(), "identity = \"changed\"\n").unwrap();
        assert!(snapshot_command(&p, "list").unwrap().contains("before experiment"));
        assert!(snapshot_command(&p, &format!("restore {id}")).unwrap().contains("restored"));
        assert!(std::fs::read_to_string(p.user_config()).unwrap().contains("v1"));
        assert!(!verify(&snap_dir(&p).join(format!("{id}.tar.gz"))).unwrap().1.iter().any(|e| e.path.contains("sessions")));
        assert_eq!(snapshot_list(&p).len(), 2, "restore snapshots the current state first");
    }
}
