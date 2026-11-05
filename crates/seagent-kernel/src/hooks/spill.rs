//! Spill oversized hook-injected context to disk (Hermes `tools/hook_output_spill.py`).
//!
//! Hook context rides every later model request, so a large blob inflates each turn and breaks
//! the prompt-cache prefix. Above `max_chars` (default 10 000) the text is written to
//! `<dir>/<session>/<random>.txt` (private 0700 dir, 0600 file, exclusive create that refuses
//! symlinks) and replaced by a head/tail preview plus the path. `enabled = false` disables it.
//! Never fails: an I/O error still yields a preview (without a path).
//!
//! Config: `[hooks_extra.output_spill] enabled, max_chars, preview_head, preview_tail, directory`.

use serde::Deserialize;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default)]
pub struct SpillConfig {
    pub enabled: bool,
    pub max_chars: usize,
    pub preview_head: usize,
    pub preview_tail: usize,
    /// Default `<seagent data>/hook_outputs`.
    pub directory: String,
}

impl Default for SpillConfig {
    fn default() -> Self {
        SpillConfig { enabled: true, max_chars: 10_000, preview_head: 500, preview_tail: 500, directory: String::new() }
    }
}

impl SpillConfig {
    /// From `[hooks_extra.output_spill]` (absent or malformed = defaults; `max_chars` must be > 0).
    pub fn from_table(t: Option<&toml::Value>) -> SpillConfig {
        let mut c: SpillConfig = t.and_then(|v| v.clone().try_into().ok()).unwrap_or_default();
        if c.max_chars == 0 {
            c.max_chars = 10_000;
        }
        c
    }
}

static CONFIG: RwLock<Option<SpillConfig>> = RwLock::new(None);

pub fn configure(c: SpillConfig) {
    *CONFIG.write().unwrap() = Some(c);
}

pub fn config() -> SpillConfig {
    CONFIG.read().unwrap().clone().unwrap_or_default()
}

fn base_dir(c: &SpillConfig) -> PathBuf {
    if c.directory.trim().is_empty() {
        crate::config::Paths::from_env().data.join("hook_outputs")
    } else {
        seagent_core::tool::expand_home(c.directory.trim())
    }
}

fn ensure_private_dir(p: &Path) -> std::io::Result<()> {
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(p)?;
    let md = std::fs::symlink_metadata(p)?;
    if !md.file_type().is_dir() {
        return Err(std::io::Error::other(format!("spill dir is not a directory (symlink?): {}", p.display())));
    }
    if md.permissions().mode() & 0o777 != 0o700 {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_exclusive(p: &Path, text: &str) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(p)?;
    f.write_all(text.as_bytes())?;
    if !text.ends_with('\n') {
        f.write_all(b"\n")?;
    }
    Ok(())
}

/// `text` unchanged when small (or disabled), else a preview pointing at the saved file.
pub fn spill_if_oversized(text: &str, session: &str, source: &str, c: &SpillConfig) -> String {
    let total = text.chars().count();
    if !c.enabled || total <= c.max_chars {
        return text.to_string();
    }
    let seg: String = if session.is_empty() { "no-session".into() } else { session.replace(['/', '\\'], "_").replace("..", "_") };
    let dir = base_dir(c).join(seg);
    let saved = ensure_private_dir(&dir).and_then(|_| {
        let p = dir.join(format!("{}.txt", crate::util::random_hex(32)));
        write_exclusive(&p, text).map(|_| p)
    });
    let mut parts = vec![match &saved {
        Ok(p) => format!("[{source} output truncated — {total} chars; full content saved to {}]", p.display()),
        Err(_) => format!("[{source} output truncated — {total} chars; full content unavailable — spill write failed]"),
    }];
    if c.preview_head > 0 {
        parts.push("--- head ---".into());
        parts.push(text.chars().take(c.preview_head).collect());
    }
    if c.preview_tail > 0 && total > c.preview_head {
        parts.push("--- tail ---".into());
        parts.push(text.chars().skip(total - c.preview_tail.min(total)).collect());
    }
    parts.join("\n")
}

/// With the installed config.
pub fn spill(text: &str, session: &str, source: &str) -> String {
    spill_if_oversized(text, session, source, &config())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_passes_large_spills_privately() {
        let d = seagent_core::tmp::scratch_path(format!("seagent-spill-{}", crate::util::random_hex(6)));
        let c = SpillConfig { max_chars: 100, preview_head: 5, preview_tail: 4, directory: d.display().to_string(), ..Default::default() };
        assert_eq!(spill_if_oversized("short", "s", "hook", &c), "short");
        let big = format!("HEAD-{}-TAIL", "x".repeat(200));
        let out = spill_if_oversized(&big, "../evil/s1", "hook", &c);
        assert!(out.starts_with("[hook output truncated — 210 chars; full content saved to "), "{out}");
        assert!(out.contains("--- head ---\nHEAD-") && out.ends_with("--- tail ---\nTAIL"), "{out}");
        let path = out.split("saved to ").nth(1).unwrap().split(']').next().unwrap();
        assert!(Path::new(path).starts_with(&d), "session segment cannot escape the base: {path}");
        assert_eq!(std::fs::read_to_string(path).unwrap(), format!("{big}\n"));
        assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(Path::new(path).parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        let off = SpillConfig { enabled: false, ..c.clone() };
        assert_eq!(spill_if_oversized(&big, "s", "hook", &off), big);
        let bad = SpillConfig { directory: "/proc/nope".into(), ..c };
        assert!(spill_if_oversized(&big, "s", "hook", &bad).contains("spill write failed"));
        let t: toml::Value = toml::from_str("max_chars = 0\npreview_head = 7").unwrap();
        let c = SpillConfig::from_table(Some(&t));
        assert_eq!((c.max_chars, c.preview_head, c.enabled), (10_000, 7, true));
    }
}
