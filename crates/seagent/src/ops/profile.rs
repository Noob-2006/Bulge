//! Profiles: several isolated seagent instances on one machine (Hermes `hermes -p NAME`,
//! `hermes profile …`). A profile is an `SEAGENT_HOME` tree (`config/`, `data/`, `run/`)
//! under `$XDG_DATA_HOME/seagent/profiles/<name>` with its own config, secrets, memory,
//! skills, sessions and daemon socket, so profiles run side by side (each `seagent -p NAME
//! daemon start` is its own gateway; `seagent -p NAME service install` installs
//! `seagentd-NAME.service`).
//!
//! Selection, first match wins: `-p NAME` / `--profile NAME` on the command line, an
//! explicit `SEAGENT_HOME`, `SEAGENT_PROFILE`, then the sticky choice from `seagent profile use`.

use crate::args::Args;
use crate::ops::archive;
use crate::{usage, R};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const COMMANDS: &[&str] = &["profile", "profiles"];
pub const VALUE_FLAGS: &[&str] = &["clone-from", "text", "output", "alias-name"];
pub const BOOL_FLAGS: &[&str] = &["clone", "clone-all", "clone-channels", "no-alias", "remove", "force", "auto", "force-config"];

/// Names that collide with seagent itself or common binaries.
const RESERVED: &[&str] = &["seagent", "seagentd", "default", "test", "tmp", "root", "sudo", "seagent-call"];

/// Profiles hang off the default per-user layout (`seagent_core::layout::user`, ignoring `SEAGENT_HOME`).
pub fn profiles_root() -> PathBuf {
    seagent_core::layout::user().data.join("profiles")
}

fn sticky_file() -> PathBuf {
    seagent_core::layout::user().config.join("active_profile")
}

pub fn dir_of(name: &str) -> PathBuf {
    profiles_root().join(name)
}

pub fn valid_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty() && name.len() <= 64 && name.as_bytes()[0].is_ascii_alphanumeric() && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if !ok {
        return Err(format!("invalid profile name `{name}`: use 1-64 lowercase letters, digits, - or _, starting with a letter or digit"));
    }
    if RESERVED.contains(&name) || crate::BUILTINS.contains(&name) || crate::ops::owns(name) {
        return Err(format!("profile name `{name}` is reserved (it collides with seagent itself, an seagent command or a system binary)"));
    }
    Ok(())
}

/// Strip `-p NAME` / `--profile NAME` / `--profile=NAME` (before `--`) and point
/// `SEAGENT_HOME` at the chosen profile.
pub fn early(raw: &mut Vec<String>) {
    let mut chosen: Option<String> = None;
    let mut i = 1;
    while i < raw.len() {
        if raw[i] == "--" {
            break;
        }
        if raw[i] == "-p" || raw[i] == "--profile" {
            if i + 1 < raw.len() {
                chosen = Some(raw[i + 1].clone());
                raw.drain(i..i + 2);
                continue;
            }
        } else if let Some(v) = raw[i].strip_prefix("--profile=") {
            chosen = Some(v.to_string());
            raw.remove(i);
            continue;
        }
        i += 1;
    }
    let name = match chosen {
        Some(n) => Some(n),
        None if std::env::var_os("SEAGENT_HOME").is_some() => return,
        None => std::env::var("SEAGENT_PROFILE").ok().filter(|s| !s.is_empty()).or_else(|| std::fs::read_to_string(sticky_file()).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())),
    };
    match name.as_deref() {
        None | Some("default") => {
            std::env::remove_var("SEAGENT_PROFILE");
            if raw.iter().any(|a| a == "-p" || a.starts_with("--profile")) {
                std::env::remove_var("SEAGENT_HOME");
            }
        }
        Some(n) => {
            // SAFETY of set_var: called first thing in main, before any thread exists.
            std::env::set_var("SEAGENT_HOME", dir_of(n));
            std::env::set_var("SEAGENT_PROFILE", n);
        }
    }
}

/// Active profile name ("default" when none).
pub fn current() -> String {
    std::env::var("SEAGENT_PROFILE").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| if std::env::var_os("SEAGENT_HOME").is_some() { "custom SEAGENT_HOME".into() } else { "default".into() })
}

/// Root (`SEAGENT_HOME`-style or the default XDG dirs) of a profile.
pub fn home_of(name: &str) -> (PathBuf, PathBuf) {
    if name == "default" {
        let u = seagent_core::layout::user();
        (u.config, u.data)
    } else {
        let d = dir_of(name);
        (d.join("config"), d.join("data"))
    }
}

fn meta_path(name: &str) -> PathBuf {
    home_of(name).0.join("profile.json")
}

pub fn meta(name: &str) -> Value {
    std::fs::read_to_string(meta_path(name)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(json!({}))
}

fn save_meta(name: &str, v: &Value) -> Result<(), String> {
    let p = meta_path(name);
    std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
    seagent_kernel::util::atomic_write(&p, serde_json::to_string_pretty(v).unwrap_or_default().as_bytes()).map_err(|e| e.to_string())
}

pub fn list() -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(profiles_root()).map(|r| r.flatten().filter(|e| e.path().is_dir()).map(|e| e.file_name().to_string_lossy().to_string()).collect()).unwrap_or_default();
    v.sort();
    v.insert(0, "default".into());
    v
}

fn exists(name: &str) -> bool {
    name == "default" || dir_of(name).is_dir()
}

fn copy_tree(from: &Path, to: &Path) -> Result<(), String> {
    let mut entries = vec![];
    archive::collect(from, "", &|p| p.file_name().is_some_and(|n| n.to_string_lossy().ends_with(".sock")), &mut entries)?;
    archive::extract(&entries, to).map(|_| ())
}

/// Drop `[channels]` from a config text (bot tokens and allow lists stay with their profile).
fn without_channels(text: &str) -> String {
    match text.parse::<toml::Table>() {
        Ok(mut t) if t.contains_key("channels") => {
            t.remove("channels");
            toml::to_string_pretty(&t).unwrap_or_default()
        }
        _ => text.to_string(),
    }
}

pub struct CreateOpts {
    pub clone_from: Option<String>,
    pub clone_all: bool,
    pub clone_channels: bool,
    pub description: Option<String>,
}

pub fn create(name: &str, o: &CreateOpts) -> Result<PathBuf, String> {
    valid_name(name)?;
    let dir = dir_of(name);
    if dir.exists() {
        return Err(format!("profile `{name}` already exists ({})", dir.display()));
    }
    for d in ["config", "data", "run"] {
        std::fs::create_dir_all(dir.join(d)).map_err(|e| e.to_string())?;
    }
    let _ = crate::ops::hostos::set_mode(&dir, 0o700);
    if let Some(src) = &o.clone_from {
        if !exists(src) {
            return Err(format!("no profile `{src}`"));
        }
        let (scfg, sdata) = home_of(src);
        if o.clone_all {
            copy_tree(&scfg, &dir.join("config"))?;
            // Everything but history and per-profile runtime state.
            for sub in std::fs::read_dir(&sdata).map(|r| r.flatten().collect::<Vec<_>>()).unwrap_or_default() {
                let n = sub.file_name().to_string_lossy().to_string();
                if ["sessions", "run", "channels", "seagentd.log", "profiles", "checkpoints"].contains(&n.as_str()) {
                    continue;
                }
                if sub.path().is_dir() {
                    copy_tree(&sub.path(), &dir.join("data").join(&n))?;
                } else {
                    let _ = std::fs::copy(sub.path(), dir.join("data").join(&n));
                }
            }
        } else {
            for f in ["config.toml", "secrets.toml", "secrets.enc", "secrets.key", ".env"] {
                if scfg.join(f).exists() {
                    std::fs::copy(scfg.join(f), dir.join("config").join(f)).map_err(|e| e.to_string())?;
                }
            }
            for d in ["skills", "commands"] {
                if sdata.join(d).is_dir() {
                    copy_tree(&sdata.join(d), &dir.join("data").join(d))?;
                }
            }
        }
        let cfgp = dir.join("config/config.toml");
        if !o.clone_channels {
            if let Ok(t) = std::fs::read_to_string(&cfgp) {
                std::fs::write(&cfgp, without_channels(&t)).map_err(|e| e.to_string())?;
            }
        }
        let _ = std::fs::remove_file(dir.join("config/profile.json"));
    }
    let mut m = json!({"name": name, "created": seagent_kernel::util::unix_now()});
    if let Some(d) = &o.description {
        m["description"] = json!(d);
        m["description_source"] = json!("user");
    }
    if let Some(s) = &o.clone_from {
        m["cloned_from"] = json!(s);
    }
    save_meta(name, &m)?;
    Ok(dir)
}

pub fn delete(name: &str) -> Result<(), String> {
    if name == "default" {
        return Err("the default profile cannot be deleted".into());
    }
    valid_name(name).or_else(|e| if dir_of(name).is_dir() { Ok(()) } else { Err(e) })?;
    let d = dir_of(name);
    if !d.is_dir() {
        return Err(format!("no profile `{name}`"));
    }
    let sock = d.join("run/seagentd.sock");
    if seagent_kernel::daemon::call(&sock, "ping", json!({})).is_ok() {
        return Err(format!("profile `{name}` has a running daemon; stop it first: seagent -p {name} daemon stop"));
    }
    std::fs::remove_dir_all(&d).map_err(|e| e.to_string())?;
    let _ = remove_alias(name);
    if std::fs::read_to_string(sticky_file()).is_ok_and(|s| s.trim() == name) {
        let _ = std::fs::remove_file(sticky_file());
    }
    Ok(())
}

pub fn rename(old: &str, new: &str) -> Result<(), String> {
    if old == "default" {
        return Err("the default profile cannot be renamed".into());
    }
    valid_name(new)?;
    if !dir_of(old).is_dir() {
        return Err(format!("no profile `{old}`"));
    }
    if dir_of(new).exists() {
        return Err(format!("profile `{new}` already exists"));
    }
    if seagent_kernel::daemon::call(&dir_of(old).join("run/seagentd.sock"), "ping", json!({})).is_ok() {
        return Err(format!("stop the daemon first: seagent -p {old} daemon stop"));
    }
    std::fs::rename(dir_of(old), dir_of(new)).map_err(|e| e.to_string())?;
    let mut m = meta(new);
    m["name"] = json!(new);
    save_meta(new, &m)?;
    if alias_path(old).is_some_and(|p| p.exists()) {
        let _ = remove_alias(old);
        let _ = make_alias(new, new);
    }
    if std::fs::read_to_string(sticky_file()).is_ok_and(|s| s.trim() == old) {
        let _ = std::fs::write(sticky_file(), new);
    }
    Ok(())
}

pub fn use_profile(name: &str) -> Result<(), String> {
    if !exists(name) {
        return Err(format!("no profile `{name}` (seagent profile create {name})"));
    }
    let f = sticky_file();
    if name == "default" {
        let _ = std::fs::remove_file(&f);
        return Ok(());
    }
    std::fs::create_dir_all(f.parent().unwrap()).map_err(|e| e.to_string())?;
    std::fs::write(&f, name).map_err(|e| e.to_string())
}

/// `$HOME`, or empty when unset. The alias helpers take a home directory as a parameter so tests
/// can point them at a throwaway directory instead of the real `$HOME`.
fn home_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
}

fn bin_dir_in(home: &Path) -> PathBuf {
    home.join(".local/bin")
}

fn alias_path(alias: &str) -> Option<PathBuf> {
    alias_path_in(&home_dir(), alias)
}

fn alias_path_in(home: &Path, alias: &str) -> Option<PathBuf> {
    valid_name(alias).ok().map(|_| bin_dir_in(home).join(if cfg!(windows) { format!("{alias}.cmd") } else { alias.to_string() }))
}

const ALIAS_MARK: &str = "# seagent profile wrapper";

/// `~/.local/bin/<alias>` running `seagent -p <profile> "$@"`. Refuses to replace a file that
/// is not one of ours.
pub fn make_alias(alias: &str, profile: &str) -> Result<PathBuf, String> {
    make_alias_in(&home_dir(), alias, profile)
}

fn make_alias_in(home: &Path, alias: &str, profile: &str) -> Result<PathBuf, String> {
    let p = alias_path_in(home, alias).ok_or_else(|| format!("invalid alias `{alias}`"))?;
    if p.exists() && !std::fs::read_to_string(&p).unwrap_or_default().contains(ALIAS_MARK) {
        return Err(format!("{} exists and is not an seagent wrapper", p.display()));
    }
    std::fs::create_dir_all(bin_dir_in(home)).map_err(|e| e.to_string())?;
    let exe = std::env::current_exe().map(|e| e.display().to_string()).unwrap_or_else(|_| "seagent".into());
    #[cfg(unix)]
    std::fs::write(&p, format!("#!/bin/sh\n{ALIAS_MARK}\nexec '{}' -p {profile} \"$@\"\n", exe.replace('\'', "'\\''"))).map_err(|e| e.to_string())?;
    // Windows: a batch file (`<alias>.cmd`, found through PATHEXT) instead of a shell script.
    #[cfg(not(unix))]
    std::fs::write(&p, format!("@echo off\r\nrem {ALIAS_MARK}\r\n\"{exe}\" -p {profile} %*\r\n")).map_err(|e| e.to_string())?;
    crate::ops::hostos::set_mode(&p, 0o755).map_err(|e| e.to_string())?;
    Ok(p)
}

pub fn remove_alias(alias: &str) -> Result<bool, String> {
    remove_alias_in(&home_dir(), alias)
}

fn remove_alias_in(home: &Path, alias: &str) -> Result<bool, String> {
    let Some(p) = alias_path_in(home, alias) else { return Ok(false) };
    if p.exists() && std::fs::read_to_string(&p).unwrap_or_default().contains(ALIAS_MARK) {
        std::fs::remove_file(&p).map_err(|e| e.to_string())?;
        return Ok(true);
    }
    Ok(false)
}

/// Files never put in a shared profile archive: credentials, history, runtime state.
fn export_skip(p: &Path) -> bool {
    let n = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    ["secrets.toml", "secrets.enc", "secrets.key", ".env", "run", "sessions", "channels", "seagentd.log", "checkpoints", "logs", "backups"].contains(&n.as_str()) || n.ends_with(".sock")
}

/// Shareable `.tar.gz` of a profile: config (channels removed), skills, commands, memory
/// files, metadata — never secrets or history.
pub fn export(name: &str, out: Option<&Path>) -> Result<PathBuf, String> {
    if !exists(name) {
        return Err(format!("no profile `{name}`"));
    }
    let (cfg, data) = home_of(name);
    let mut entries = vec![];
    archive::collect(&cfg, "config/", &|p| export_skip(p) || p.file_name().is_some_and(|n| n == "config.toml"), &mut entries)?;
    if let Ok(t) = std::fs::read_to_string(cfg.join("config.toml")) {
        entries.push(archive::Entry::file("config/config.toml", without_channels(&t).into_bytes()));
    }
    archive::collect(&data, "data/", &|p| export_skip(p) || p.file_name().is_some_and(|n| n == "profiles"), &mut entries)?;
    entries.insert(0, archive::Entry::file("seagent-profile.json", serde_json::to_vec_pretty(&json!({"format": 1, "name": name, "exported": seagent_kernel::util::unix_now(), "version": env!("CARGO_PKG_VERSION")})).unwrap_or_default()));
    let out = match out {
        Some(p) => p.to_path_buf(),
        None => home_of("default").1.join("profile-exports").join(format!("{name}-{}.tar.gz", seagent_kernel::util::unix_now())),
    };
    if let Some(d) = out.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    std::fs::write(&out, archive::gzip(&archive::tar(&entries))).map_err(|e| format!("{}: {e}", out.display()))?;
    Ok(out)
}

pub fn import(archive_path: &Path, name: Option<&str>) -> Result<String, String> {
    let bytes = std::fs::read(archive_path).map_err(|e| format!("{}: {e}", archive_path.display()))?;
    let entries = archive::untar(&archive::gunzip(&bytes)?)?;
    let manifest: Value = entries.iter().find(|e| e.path == "seagent-profile.json").and_then(|e| serde_json::from_slice(&e.data).ok()).ok_or("not an seagent profile archive (no seagent-profile.json)")?;
    let name = name.map(String::from).or_else(|| manifest["name"].as_str().map(String::from)).ok_or("archive has no profile name; pass --name")?;
    valid_name(&name)?;
    let dir = dir_of(&name);
    if dir.exists() {
        return Err(format!("profile `{name}` already exists; pass --name to import under another name"));
    }
    let keep: Vec<archive::Entry> = entries.into_iter().filter(|e| (e.path.starts_with("config/") || e.path.starts_with("data/")) && !export_skip(Path::new(&e.path))).collect();
    archive::extract(&keep, &dir)?;
    std::fs::create_dir_all(dir.join("run")).map_err(|e| e.to_string())?;
    let mut m = meta(&name);
    m["name"] = json!(name);
    m["imported_from"] = json!(archive_path.display().to_string());
    save_meta(&name, &m)?;
    Ok(name)
}

fn size_of(p: &Path) -> u64 {
    std::fs::read_dir(p).map(|r| r.flatten().map(|e| if e.path().is_dir() { size_of(&e.path()) } else { e.metadata().map(|m| m.len()).unwrap_or(0) }).sum()).unwrap_or(0)
}

pub fn show(name: &str) -> Result<String, String> {
    if !exists(name) {
        return Err(format!("no profile `{name}`"));
    }
    let (cfg, data) = home_of(name);
    let m = meta(name);
    let sessions = std::fs::read_dir(data.join("sessions")).map(|r| r.count()).unwrap_or(0);
    let model = std::fs::read_to_string(cfg.join("config.toml")).ok().and_then(|t| t.parse::<toml::Table>().ok()).and_then(|t| t.get("model")?.get("default")?.as_str().map(String::from)).unwrap_or_else(|| "(default)".into());
    let sock = if name == "default" { seagent_kernel::config::Paths::from_env().socket() } else { dir_of(name).join("run/seagentd.sock") };
    let running = seagent_kernel::daemon::call(&sock, "ping", json!({})).is_ok();
    Ok(format!(
        "profile {name}{}\nconfig   {}\ndata     {}\nmodel    {model}\nsessions {sessions} · {:.1} MB · daemon {}\n{}",
        if current() == name { " (active)" } else { "" },
        cfg.display(),
        data.display(),
        size_of(&data) as f64 / 1e6,
        if running { "running" } else { "stopped" },
        m["description"].as_str().map(|d| format!("about    {d}")).unwrap_or_default()
    )
    .trim_end()
    .to_string())
}

/// `distribution.toml` in a git repo or directory: a shareable profile template.
/// `[profile] name, description, version` plus `config.toml`, `skills/`, `commands/`,
/// `AGENTS.md` (becomes the profile's identity) at its root.
///
/// A git source is cloned into a scratch directory that removes itself once the install is done:
/// the copied profile is complete at that point, so the clone must not outlive it (that is how
/// `/tmp` filled up before). The guard travels with the `Source`, so it outlives `install`.
struct Source {
    dir: PathBuf,
    _scratch: Option<seagent_core::tmp::TempDir>,
}

fn fetch_distribution(source: &str) -> Result<Source, String> {
    let p = Path::new(source);
    if p.is_dir() {
        return Ok(Source { dir: p.canonicalize().map_err(|e| e.to_string())?, _scratch: None });
    }
    let looks_git = source.starts_with("https://") || source.starts_with("git@") || source.starts_with("github.com/");
    if !looks_git {
        return Err(format!("`{source}` is neither a directory nor a git URL"));
    }
    let url = if source.starts_with("github.com/") { format!("https://{source}") } else { source.to_string() };
    let scratch = seagent_core::tmp::TempDir::new("seagent-tmp");
    let dir = scratch.path().join("src");
    let st = std::process::Command::new("git").args(["clone", "--depth", "1", "--quiet", &url]).arg(&dir).status().map_err(|e| format!("git: {e}"))?;
    if !st.success() {
        return Err(format!("git clone {url} failed"));
    }
    Ok(Source { dir, _scratch: Some(scratch) })
}

pub fn install(source: &str, name: Option<&str>, force: bool, force_config: bool) -> Result<String, String> {
    let fetched = fetch_distribution(source)?;
    let src = fetched.dir.as_path();
    let manifest: toml::Table = std::fs::read_to_string(src.join("distribution.toml")).map_err(|_| format!("{} has no distribution.toml", src.display()))?.parse().map_err(|e| format!("distribution.toml: {e}"))?;
    let prof = manifest.get("profile").and_then(|v| v.as_table()).cloned().unwrap_or_default();
    let name = name.map(String::from).or_else(|| prof.get("name").and_then(|v| v.as_str()).map(String::from)).ok_or("distribution.toml has no [profile] name; pass --name")?;
    valid_name(&name)?;
    let fresh = !dir_of(&name).exists();
    if !fresh && !force && meta(&name).get("distribution").is_none() {
        return Err(format!("profile `{name}` exists; pass --force to install over it (your data is kept)"));
    }
    if fresh {
        create(&name, &CreateOpts { clone_from: None, clone_all: false, clone_channels: false, description: prof.get("description").and_then(|v| v.as_str()).map(String::from) })?;
    }
    let (cfg, data) = home_of(&name);
    if src.join("config.toml").exists() && (fresh || force_config) {
        std::fs::copy(src.join("config.toml"), cfg.join("config.toml")).map_err(|e| e.to_string())?;
    }
    for d in ["skills", "commands"] {
        if src.join(d).is_dir() {
            copy_tree(&src.join(d), &data.join(d))?;
        }
    }
    if let Ok(a) = std::fs::read_to_string(src.join("AGENTS.md")) {
        crate::ops::confcli::set(&seagent_kernel::config::Paths { data: data.clone(), config_dir: cfg.clone(), runtime: dir_of(&name).join("run"), ..Default::default() }, "identity", &toml::Value::String(a).to_string())?;
    }
    let mut m = meta(&name);
    m["distribution"] = json!({"source": source, "version": prof.get("version").and_then(|v| v.as_str()), "installed": seagent_kernel::util::unix_now()});
    save_meta(&name, &m)?;
    Ok(name)
}

fn describe_auto(name: &str) -> Result<String, String> {
    let (cfg, data) = home_of(name);
    let paths = seagent_kernel::config::Paths { data: data.clone(), config_dir: cfg.clone(), runtime: dir_of(name).join("run"), ..Default::default() };
    let conf = seagent_kernel::config::Config::load(Some(&paths.user_config()), None, &[])?;
    let vault = crate::load_vault(&paths).map_err(|e| e.to_string())?;
    let providers = crate::providers::Providers::new(&conf.providers, vault.clone())?;
    let skills: Vec<String> = std::fs::read_dir(data.join("skills")).map(|r| r.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect()).unwrap_or_default();
    let facts = format!("profile `{name}`\nidentity: {}\nmodel: {}\nskills: {}\nmcp servers: {}\nchannels: {}", conf.identity.chars().take(1500).collect::<String>(), conf.model.default, skills.join(", "), conf.mcp.keys().cloned().collect::<Vec<_>>().join(", "), conf.channels.keys().cloned().collect::<Vec<_>>().join(", "));
    let (pid, m) = seagent_kernel::context::split_model(conf.aux_model());
    let p = seagent_kernel::kernel::Resolver::provider(&providers, pid)?;
    let req = seagent_core::ModelRequest { model: m.into(), system: vec![], messages: vec![seagent_core::Message::user(format!("Write ONE or two sentences (max 200 characters) describing what this agent profile is good at, for routing tasks to it. No preamble.\n\n{facts}"))], tools: vec![], max_tokens: 200, temperature: None, cache_after_message: None, reasoning: None, options: Default::default() };
    let r = p.complete(&req, &mut |_| {}, &seagent_core::Cancel::new()).map_err(|e| e.to_string())?;
    Ok(r.message.text().trim().chars().take(300).collect())
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if !COMMANDS.contains(&cmd) {
        return None;
    }
    Some((|| -> R {
        let name_at = |i: usize| a.need(i, "profile").map(String::from);
        match a.pos(0).unwrap_or("list") {
            "list" | "ls" => {
                let cur = current();
                for n in list() {
                    let m = meta(&n);
                    println!("{} {n:<20} {}", if n == cur { "*" } else { " " }, m["description"].as_str().unwrap_or(""));
                }
                Ok(0)
            }
            "current" | "whoami" => {
                println!("{}", current());
                Ok(0)
            }
            "use" => {
                let n = name_at(1)?;
                use_profile(&n)?;
                println!("default profile → {n} (override per command with -p NAME)");
                Ok(0)
            }
            "create" | "new" => {
                let n = name_at(1)?;
                let clone_from = a.val("clone-from").map(String::from).or_else(|| (a.flag("clone") || a.flag("clone-all")).then(current).map(|c| if c == "custom SEAGENT_HOME" { "default".into() } else { c }));
                let d = create(&n, &CreateOpts { clone_from: clone_from.clone(), clone_all: a.flag("clone-all"), clone_channels: a.flag("clone-channels"), description: a.val("description").map(String::from) })?;
                println!("created profile {n} at {}{}", d.display(), clone_from.map(|c| format!(" (cloned from {c})")).unwrap_or_default());
                if !a.flag("no-alias") {
                    match make_alias(&n, &n) {
                        Ok(p) => println!("wrapper: {} (runs `seagent -p {n} …`)", p.display()),
                        Err(e) => eprintln!("note: no wrapper script: {e}"),
                    }
                }
                println!("use it: seagent -p {n} setup   ·   make it the default: seagent profile use {n}");
                Ok(0)
            }
            "delete" | "rm" => {
                let n = name_at(1)?;
                if !a.flag("yes") {
                    return Err(format!("this permanently deletes profile `{n}` ({}) with its sessions, memory and secrets; re-run with --yes", dir_of(&n).display()).into());
                }
                delete(&n)?;
                println!("deleted profile {n}");
                Ok(0)
            }
            "describe" => {
                let n = a.pos(1).map(String::from).unwrap_or_else(current);
                let mut m = meta(&n);
                if let Some(t) = a.val("text") {
                    m["description"] = json!(t);
                    m["description_source"] = json!("user");
                    save_meta(&n, &m)?;
                } else if a.flag("auto") {
                    if m["description_source"] == "user" && !a.flag("force") {
                        println!("{n} has a user-written description; --force to replace it");
                        return Ok(0);
                    }
                    m["description"] = json!(describe_auto(&n)?);
                    m["description_source"] = json!("auto");
                    save_meta(&n, &m)?;
                }
                println!("{}", m["description"].as_str().unwrap_or("(no description; set one with --text or --auto)"));
                Ok(0)
            }
            "show" | "info" => {
                let n = a.pos(1).map(String::from).unwrap_or_else(current);
                println!("{}", show(&n)?);
                if let Some(d) = meta(&n).get("distribution") {
                    println!("distribution {}", d);
                }
                Ok(0)
            }
            "alias" => {
                let n = name_at(1)?;
                let alias = a.val("alias-name").unwrap_or(&n).to_string();
                if a.flag("remove") {
                    println!("{}", if remove_alias(&alias)? { "removed wrapper" } else { "no seagent wrapper to remove" });
                } else {
                    if !exists(&n) {
                        return Err(format!("no profile `{n}`").into());
                    }
                    println!("{}", make_alias(&alias, &n)?.display());
                }
                Ok(0)
            }
            "rename" | "mv" => {
                let (o, n) = (name_at(1)?, a.need(2, "new name")?.to_string());
                rename(&o, &n)?;
                println!("renamed {o} → {n}");
                Ok(0)
            }
            "export" => {
                let n = a.pos(1).map(String::from).unwrap_or_else(current);
                let p = export(&n, a.val("output").map(Path::new))?;
                println!("exported {n} → {} (secrets, sessions and channels are not included)", p.display());
                Ok(0)
            }
            "import" => {
                let p = a.need(1, "archive")?;
                let n = import(Path::new(p), a.val("name"))?;
                println!("imported profile {n} · add its keys with: seagent -p {n} secrets set NAME");
                Ok(0)
            }
            "install" => {
                let n = install(a.need(1, "source")?, a.val("name"), a.flag("force"), true)?;
                if !a.flag("no-alias") {
                    let _ = make_alias(&n, &n);
                }
                println!("installed profile {n}");
                Ok(0)
            }
            "update" => {
                let n = name_at(1)?;
                let src = meta(&n)["distribution"]["source"].as_str().map(String::from).ok_or_else(|| format!("profile `{n}` was not installed from a distribution"))?;
                install(&src, Some(&n), true, a.flag("force-config"))?;
                println!("updated {n} from {src}{}", if a.flag("force-config") { "" } else { " (config.toml kept; --force-config to replace it)" });
                Ok(0)
            }
            other => usage(format!("unknown `profile {other}` (list, current, use, create, delete, describe, show, alias, rename, export, import, install, update)")),
        }
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Profiles live under $XDG_DATA_HOME; tests serialize on the shared env lock.
    fn sandbox() -> (std::sync::MutexGuard<'static, ()>, seagent_core::tmp::TempDir) {
        let g = crate::testkit::env_lock();
        let root = seagent_core::tmp::TempDir::new("seagent-tmp");
        std::env::set_var("XDG_DATA_HOME", root.path().join("share"));
        std::env::set_var("XDG_CONFIG_HOME", root.path().join("cfg"));
        (g, root)
    }

    #[test]
    fn lifecycle_clone_export_import() {
        let (_g, _root) = sandbox();
        assert!(valid_name("Work").is_err() && valid_name("seagent").is_err() && valid_name("-x").is_err() && valid_name("chat").is_err());
        let (dcfg, ddata) = home_of("default");
        std::fs::create_dir_all(&dcfg).unwrap();
        std::fs::create_dir_all(ddata.join("skills/s1")).unwrap();
        std::fs::write(ddata.join("skills/s1/SKILL.md"), "skill").unwrap();
        std::fs::write(dcfg.join("config.toml"), "identity = \"hi\"\n[channels.tg]\nkind = \"telegram\"\n").unwrap();
        std::fs::write(dcfg.join("secrets.toml"), "X = \"y\"\n").unwrap();
        create("work", &CreateOpts { clone_from: Some("default".into()), clone_all: false, clone_channels: false, description: Some("coding".into()) }).unwrap();
        let wc = std::fs::read_to_string(dir_of("work").join("config/config.toml")).unwrap();
        assert!(wc.contains("identity") && !wc.contains("telegram"), "channels left behind: {wc}");
        assert!(dir_of("work").join("data/skills/s1/SKILL.md").exists());
        assert!(create("work", &CreateOpts { clone_from: None, clone_all: false, clone_channels: false, description: None }).is_err());
        assert_eq!(list(), ["default", "work"]);
        assert_eq!(meta("work")["description"], "coding");
        use_profile("work").unwrap();
        std::env::remove_var("SEAGENT_HOME");
        std::env::remove_var("SEAGENT_PROFILE");
        let mut raw = vec!["seagent".to_string(), "status".into()];
        early(&mut raw);
        assert_eq!(std::env::var("SEAGENT_PROFILE").unwrap(), "work");
        assert_eq!(PathBuf::from(std::env::var("SEAGENT_HOME").unwrap()), dir_of("work"));
        let mut raw = vec!["seagent".to_string(), "-p".into(), "default".into(), "run".into(), "--".into(), "-p".into()];
        early(&mut raw);
        assert_eq!(raw, ["seagent", "run", "--", "-p"]);
        assert!(std::env::var_os("SEAGENT_HOME").is_none());
        let out = export("work", None).unwrap();
        let names: Vec<String> = archive::untar(&archive::gunzip(&std::fs::read(&out).unwrap()).unwrap()).unwrap().into_iter().map(|e| e.path).collect();
        assert!(names.contains(&"data/skills/s1/SKILL.md".to_string()) && !names.iter().any(|n| n.contains("secrets")), "{names:?}");
        assert_eq!(import(&out, Some("copy")).unwrap(), "copy");
        assert!(dir_of("copy").join("data/skills/s1/SKILL.md").exists() && !dir_of("copy").join("config/secrets.toml").exists());
        rename("copy", "copy2").unwrap();
        assert_eq!(meta("copy2")["name"], "copy2");
        assert!(show("copy2").unwrap().contains("profile copy2"));
        delete("copy2").unwrap();
        assert!(delete("default").is_err());
        std::env::remove_var("SEAGENT_HOME");
        std::env::remove_var("SEAGENT_PROFILE");
    }

    #[test]
    fn distribution_install_and_alias() {
        let (_g, root) = sandbox();
        let dist = root.path().join("dist");
        std::fs::create_dir_all(dist.join("skills/review")).unwrap();
        std::fs::write(dist.join("distribution.toml"), "[profile]\nname = \"reviewer\"\ndescription = \"Reviews PRs\"\nversion = \"1.2\"\n").unwrap();
        std::fs::write(dist.join("skills/review/SKILL.md"), "v1").unwrap();
        std::fs::write(dist.join("AGENTS.md"), "You review code.").unwrap();
        assert_eq!(install(dist.to_str().unwrap(), None, false, false).unwrap(), "reviewer");
        let (cfg, data) = home_of("reviewer");
        assert!(std::fs::read_to_string(cfg.join("config.toml")).unwrap().contains("You review code."));
        std::fs::write(dist.join("skills/review/SKILL.md"), "v2").unwrap();
        install(dist.to_str().unwrap(), Some("reviewer"), true, false).unwrap();
        assert_eq!(std::fs::read_to_string(data.join("skills/review/SKILL.md")).unwrap(), "v2");
        assert_eq!(meta("reviewer")["distribution"]["version"], "1.2");
        // Aliases are written under the home directory passed in, never the real $HOME.
        let p = make_alias_in(root.path(), "reviewer", "reviewer").unwrap();
        assert!(std::fs::read_to_string(&p).unwrap().contains("-p reviewer"));
        std::fs::write(bin_dir_in(root.path()).join("other"), "#!/bin/sh\n").unwrap();
        assert!(make_alias_in(root.path(), "other", "reviewer").is_err(), "foreign files are not replaced");
        assert!(remove_alias_in(root.path(), "reviewer").unwrap());
    }
}
