//! Chat-side helpers shared by Telegram and Discord (and every other channel with
//! `caps().media`): sending files the agent produced, "reply to the chat this session came
//! from", and the `/sethome` registry.
//!
//! ## File sending
//! The model passes `media` (paths) to the `message` / `channel_send` tools; both end up in
//! [`media_from_input`]. Every local path goes through [`authorize`], the **single entry point**
//! for "may this file leave the machine for a chat". The rules themselves belong to the safety
//! layer: it installs its checker with [`set_path_guard`]. Until it does, the built-in fallback
//! is deliberately small and fail-closed: the file must resolve (symlinks followed) inside one
//! of the allowed roots (the session workspace and artifacts dir the tool call carries, plus
//! anything registered with [`add_root`]).

use crate::{Media, MediaKind};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

/// Biggest file we try to upload (Discord's default limit; Telegram bots allow 50 MB).
pub const MAX_SEND_BYTES: u64 = 25 * 1024 * 1024;

/// Checker installed by the safety layer: `Ok(canonical path)` to allow.
pub type PathGuard = Arc<dyn Fn(&Path) -> Result<PathBuf, String> + Send + Sync>;

static GUARD: RwLock<Option<PathGuard>> = RwLock::new(None);
static ROOTS: RwLock<Vec<PathBuf>> = RwLock::new(Vec::new());

/// Install the safety layer's outbound path check (replaces the fallback root check).
pub fn set_path_guard(g: Option<PathGuard>) {
    *GUARD.write().unwrap_or_else(|p| p.into_inner()) = g;
}

/// Allow files under `root` (fallback check only).
pub fn add_root(root: &Path) {
    let mut r = ROOTS.write().unwrap_or_else(|p| p.into_inner());
    if !r.iter().any(|x| x == root) {
        r.push(root.to_path_buf());
    }
}

/// The one gate every outbound local file passes. `extra_roots` are the caller's own allowed
/// directories (workspace, artifacts) for the fallback check.
pub fn authorize(path: &Path, extra_roots: &[PathBuf]) -> Result<PathBuf, String> {
    let guard = GUARD.read().unwrap_or_else(|p| p.into_inner()).clone();
    if let Some(g) = guard {
        return g(path);
    }
    let mut roots = ROOTS.read().unwrap_or_else(|p| p.into_inner()).clone();
    roots.extend(extra_roots.iter().cloned());
    roots.extend(crate::media_guard::extra_roots());
    // Same rule as the per-channel guard: inside an allowed root and never key material.
    crate::media_guard::check(path, Path::new("/"), &roots)
}

fn kind_of(name: &str) -> (MediaKind, &'static str) {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "png" => (MediaKind::Image, "image/png"),
        "jpg" | "jpeg" => (MediaKind::Image, "image/jpeg"),
        "gif" => (MediaKind::Image, "image/gif"),
        "webp" => (MediaKind::Image, "image/webp"),
        "mp4" | "mov" | "webm" | "mkv" => (MediaKind::Video, "video/mp4"),
        "mp3" => (MediaKind::Audio, "audio/mpeg"),
        "wav" => (MediaKind::Audio, "audio/wav"),
        "m4a" => (MediaKind::Audio, "audio/mp4"),
        "ogg" | "oga" | "opus" => (MediaKind::Audio, "audio/ogg"),
        "pdf" => (MediaKind::Document, "application/pdf"),
        "txt" | "md" | "log" => (MediaKind::Document, "text/plain"),
        "csv" => (MediaKind::Document, "text/csv"),
        "json" => (MediaKind::Document, "application/json"),
        "zip" => (MediaKind::Document, "application/zip"),
        _ => (MediaKind::Document, "application/octet-stream"),
    }
}

/// Build the outbound [`Media`] for one local file, after [`authorize`] and a size check.
pub fn media_for_path(src: &str, base: &Path, roots: &[PathBuf], caption: Option<&str>) -> Result<Media, String> {
    let raw = src.trim().strip_prefix("file://").unwrap_or(src.trim());
    if raw.is_empty() {
        return Err("empty file path".into());
    }
    let p = ark_core::tool::expand_home(raw);
    let p = if p.is_absolute() { p } else { base.join(p) };
    let canon = authorize(&p, roots)?;
    let meta = std::fs::metadata(&canon).map_err(|e| format!("cannot read {}: {e}", canon.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", canon.display()));
    }
    if meta.len() > MAX_SEND_BYTES {
        return Err(format!("{} is {} MB; chats accept at most {} MB per file", canon.display(), meta.len() >> 20, MAX_SEND_BYTES >> 20));
    }
    let name = canon.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
    let (kind, mime) = kind_of(&name);
    Ok(Media { kind, path: Some(canon.display().to_string()), mime: mime.into(), name, size: meta.len(), caption: caption.map(str::to_string), ..Default::default() })
}

/// The files a tool call asks to send: `media` / `files` (array or string) or `path` / `file`.
/// Public http(s) URLs pass through as URL media. Relative paths resolve against `base`.
pub fn media_from_input(input: &Value, base: &Path, roots: &[PathBuf]) -> Result<Vec<Media>, String> {
    let mut srcs: Vec<String> = vec![];
    for k in ["media", "files", "attachments", "path", "file", "filePath"] {
        match input.get(k) {
            Some(Value::String(s)) if !s.trim().is_empty() => srcs.push(s.clone()),
            Some(Value::Array(a)) => srcs.extend(a.iter().filter_map(|v| v.as_str().map(str::to_string)).filter(|s| !s.trim().is_empty())),
            _ => {}
        }
    }
    if srcs.len() > 10 {
        return Err("at most 10 files per message".into());
    }
    let mut out = vec![];
    for s in srcs {
        let s = s.trim();
        if s.starts_with("http://") || s.starts_with("https://") {
            let name = s.split(['?', '#']).next().unwrap_or(s).rsplit('/').next().unwrap_or("file").to_string();
            let (kind, mime) = kind_of(&name);
            out.push(Media { kind, url: Some(s.to_string()), mime: mime.into(), name, ..Default::default() });
        } else {
            out.push(media_for_path(s, base, roots, None)?);
        }
    }
    Ok(out)
}

// ───────────────────────── /sethome registry ─────────────────────────

static HOMES: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);
static HOME_FILE: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Load the persisted homes from `file` and keep writing there on [`set_home`].
pub fn load_homes(file: &Path) {
    let map: HashMap<String, String> = std::fs::read_to_string(file).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    *HOMES.lock().unwrap_or_else(|p| p.into_inner()) = Some(map);
    *HOME_FILE.lock().unwrap_or_else(|p| p.into_inner()) = Some(file.to_path_buf());
}

/// The chat `/sethome` chose for `channel`, if any (wins over the configured `default_chat`).
pub fn home(channel: &str) -> Option<String> {
    HOMES.lock().unwrap_or_else(|p| p.into_inner()).as_ref().and_then(|m| m.get(channel).cloned())
}

/// `chat` if given, else the home, else the configured default.
pub fn effective_default(channel: &str, configured: Option<&String>) -> Option<String> {
    home(channel).or_else(|| configured.cloned())
}

/// Make `chat` the home of `channel` (persisted when [`load_homes`] ran).
pub fn set_home(channel: &str, chat: &str) -> Result<(), String> {
    let mut g = HOMES.lock().unwrap_or_else(|p| p.into_inner());
    let m = g.get_or_insert_with(HashMap::new);
    m.insert(channel.to_string(), chat.to_string());
    if let Some(f) = HOME_FILE.lock().unwrap_or_else(|p| p.into_inner()).clone() {
        if let Some(d) = f.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let tmp = f.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(m).unwrap_or_default()).and_then(|_| std::fs::rename(&tmp, &f)).map_err(|e| format!("saving {}: {e}", f.display()))?;
    }
    Ok(())
}

// ───────────────────────── "the chat this session came from" ─────────────────────────

/// session id → (channel, chat)
pub type OriginFn = Arc<dyn Fn(&str) -> Option<(String, String)> + Send + Sync>;
static ORIGIN: RwLock<Option<OriginFn>> = RwLock::new(None);

pub fn set_origin(f: Option<OriginFn>) {
    *ORIGIN.write().unwrap_or_else(|p| p.into_inner()) = f;
}

/// The channel and chat a session's conversation lives in (set by the daemon from its routes).
pub fn origin_of(session: &str) -> Option<(String, String)> {
    let f = ORIGIN.read().unwrap_or_else(|p| p.into_inner()).clone()?;
    f(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> ark_core::tmp::TempDir {
        ark_core::tmp::TempDir::new(&format!("ark-outfile-{tag}"))
    }

    #[test]
    fn fallback_guard_confines_files_to_roots_and_follows_symlinks() {
        let ws = dir("ws");
        let out = dir("outside");
        std::fs::write(ws.join("report.pdf"), b"%PDF-1").unwrap();
        std::fs::write(out.join("secret.txt"), b"x").unwrap();
        std::os::unix::fs::symlink(out.join("secret.txt"), ws.join("link.txt")).unwrap();
        let roots = vec![ws.to_path_buf()];
        let m = media_for_path("report.pdf", &ws, &roots, None).unwrap();
        assert_eq!((m.kind, m.mime.as_str(), m.name.as_str()), (MediaKind::Document, "application/pdf", "report.pdf"));
        assert!(media_for_path(&out.join("secret.txt").display().to_string(), &ws, &roots, None).unwrap_err().contains("outside"));
        assert!(media_for_path("link.txt", &ws, &roots, None).unwrap_err().contains("outside"), "symlink escape");
        assert!(media_for_path("../nope", &ws, &roots, None).is_err());
    }

    #[test]
    fn input_forms_and_limits() {
        let ws = dir("in");
        std::fs::write(ws.join("a.png"), b"\x89PNG").unwrap();
        let roots = vec![ws.to_path_buf()];
        let v = serde_json::json!({"media": ["a.png", "https://e.com/x.mp4"], "text": "here"});
        let m = media_from_input(&v, &ws, &roots).unwrap();
        assert_eq!((m[0].kind, m[1].kind, m[1].url.as_deref()), (MediaKind::Image, MediaKind::Video, Some("https://e.com/x.mp4")));
        assert_eq!(media_from_input(&serde_json::json!({"path": "a.png"}), &ws, &roots).unwrap().len(), 1);
        assert!(media_from_input(&serde_json::json!({"text": "plain"}), &ws, &roots).unwrap().is_empty());
        let many: Vec<String> = (0..11).map(|_| "a.png".into()).collect();
        assert!(media_from_input(&serde_json::json!({"media": many}), &ws, &roots).is_err());
    }

    #[test]
    fn homes_persist_and_win_over_configured() {
        let d = dir("home");
        let f = d.join("home.json");
        load_homes(&f);
        assert_eq!(effective_default("tgx", Some(&"cfg".to_string())).as_deref(), Some("cfg"));
        set_home("tgx", "42").unwrap();
        assert_eq!(effective_default("tgx", Some(&"cfg".to_string())).as_deref(), Some("42"));
        load_homes(&f);
        assert_eq!(home("tgx").as_deref(), Some("42"), "reloaded from disk");
    }
}
