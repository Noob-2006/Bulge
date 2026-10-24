//! Files received from chats: safe names, no symlinks, never overwritten;
//! files sent without a request wait for the sender's next message.

use std::path::Path;
use bulge_channels::{Attachment, Channel, Inbound};
use super::Hub;

/// Create `dir` (and its parents inside `root`) as real directories; refuse
/// if any of them is a symlink.
pub(crate) fn ensure_real_dir(root: &Path, dir: &Path) -> Result<(), String> {
    let relative = dir.strip_prefix(root).map_err(|_| format!("{} is outside the workspace", dir.display()))?;
    // The workspace itself is the configured (trusted) path.
    std::fs::create_dir_all(root).map_err(|e| format!("create {}: {e}", root.display()))?;
    let mut current = root.to_path_buf();
    for part in relative.components() {
        current.push(part);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => return Err(format!("{} is a symlink; files are not written through it", current.display())),
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => return Err(format!("{} is not a directory", current.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir(&current).map_err(|e| format!("create {}: {e}", current.display()))?,
            Err(e) => return Err(format!("{}: {e}", current.display())),
        }
    }
    Ok(())
}

/// Write a new file, never following a symlink at `path` and never
/// replacing an existing file: with `create_new` (O_CREAT|O_EXCL) the open
/// fails on any existing name, a symlink included, even a dangling one.
pub(crate) fn create_new_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    std::fs::OpenOptions::new().write(true).create_new(true).open(path)?.write_all(bytes)
}

/// Lowercase ASCII letters, digits and dashes only.
pub(crate) fn slug(text: &str) -> String {
    text.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' }).take(48).collect()
}

/// A file name safe to create (no paths, no hidden or odd characters).
pub(crate) fn safe_file_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = base.chars().filter(|c| !c.is_control() && !matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')).collect();
    let cleaned = cleaned.trim().trim_start_matches('.').to_owned();
    let cleaned: String = cleaned.chars().rev().take(80).collect::<Vec<_>>().into_iter().rev().collect();
    cleaned
}

/// A file extension from the first bytes, for files sent without a name.
pub(crate) fn sniff_extension(bytes: &[u8]) -> &'static str {
    match bytes {
        [0x89, b'P', b'N', b'G', ..] => "png",
        [0xFF, 0xD8, 0xFF, ..] => "jpg",
        [b'G', b'I', b'F', b'8', ..] => "gif",
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => "webp",
        [b'%', b'P', b'D', b'F', ..] => "pdf",
        [_, _, _, _, b'f', b't', b'y', b'p', ..] => "mp4",
        [b'P', b'K', 3, 4, ..] => "zip",
        [b'O', b'g', b'g', b'S', ..] => "ogg",
        _ => "bin",
    }
}

pub(crate) fn kind_label(kind: &str) -> &'static str {
    match kind {
        "image" => "圖片",
        "video" => "影片",
        "audio" => "語音",
        _ => "檔案",
    }
}

/// Largest file taken from a chat app.
pub(crate) const MAX_FILE: u64 = 25 * 1024 * 1024;
/// Files sent without a request wait this long for the sender's next message.
pub(crate) const STASH_SECS: u64 = 30 * 60;
pub(crate) const STASH_MAX: usize = 10;

/// Files a message brings: kept aside until the request comes, or saved
/// into the workspace.
impl Hub {
    pub(crate) fn stash_key(message: &Inbound) -> String {
        format!("{}\0{}", message.chat_key(), message.sender_id)
    }

    pub(crate) fn put_aside(&self, key: &str, files: Vec<Attachment>, now: u64) {
        if let Ok(mut stash) = self.stash.lock() {
            stash.retain(|_, v| {
                v.retain(|(_, at)| now.saturating_sub(*at) <= STASH_SECS);
                !v.is_empty()
            });
            let waiting = stash.entry(key.to_owned()).or_default();
            waiting.extend(files.into_iter().map(|f| (f, now)));
            if waiting.len() > STASH_MAX {
                let extra = waiting.len() - STASH_MAX;
                waiting.drain(..extra);
            }
        }
    }

    pub(crate) fn take_aside(&self, key: &str, now: u64) -> Vec<Attachment> {
        self.stash.lock().ok().and_then(|mut s| s.remove(key)).unwrap_or_default().into_iter().filter(|(_, at)| now.saturating_sub(*at) <= STASH_SECS).map(|(f, _)| f).collect()
    }

    /// Download `files` into `<workspace>/inbox/`. Returns the lines for the
    /// prompt (workspace-relative paths) and the failures for the reply.
    pub(crate) async fn receive(&self, channel: &dyn Channel, files: &[Attachment], workspace: &Path) -> (Vec<String>, Vec<String>) {
        let inbox = workspace.join("inbox");
        let (mut saved, mut failed) = (Vec::new(), Vec::new());
        if files.is_empty() {
            return (saved, failed);
        }
        // inbox/ must be a real directory in the workspace: a symlink there
        // (written back earlier, or left by the owner) would send these
        // files anywhere on the host.
        if let Err(error) = ensure_real_dir(workspace, &inbox) {
            failed.push(error);
            return (saved, failed);
        }
        let stamp = bulge_util::now_secs();
        for (index, file) in files.iter().enumerate() {
            let label = kind_label(&file.kind);
            if file.size.is_some_and(|size| size > MAX_FILE) {
                failed.push(format!("{label} {} 超過 {} MB", file.name.as_deref().unwrap_or(""), MAX_FILE / (1024 * 1024)));
                continue;
            }
            let bytes = match channel.fetch(file, MAX_FILE).await {
                Ok(bytes) => bytes,
                Err(error) => {
                    eprintln!("{}: could not fetch a file: {error}", channel.name());
                    failed.push(format!("{label}：{error}"));
                    continue;
                }
            };
            let named = file.name.as_deref().map(safe_file_name).filter(|n| !n.is_empty());
            let name = named.unwrap_or_else(|| format!("{}-{stamp}-{}.{}", file.kind, index + 1, sniff_extension(&bytes)));
            let mut written = Err(String::new());
            let mut path = inbox.join(&name);
            for n in 1..=100 {
                if n > 1 {
                    path = inbox.join(format!("{n}-{name}"));
                }
                match create_new_file(&path, &bytes) {
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    other => {
                        written = other.map_err(|e| e.to_string());
                        break;
                    }
                }
            }
            match written {
                Ok(()) => {
                    let relative = path.strip_prefix(workspace).map(|p| p.display().to_string()).unwrap_or(name);
                    saved.push(format!("- {relative}（{label}，{} KB）", bytes.len().div_ceil(1024)));
                }
                Err(error) => failed.push(format!("{label}：寫入失敗 {error}")),
            }
        }
        (saved, failed)
    }
}
