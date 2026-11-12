//! Terminal input helpers shared by `seagent chat` and the TUI: clipboard copy (OSC 52
//! plus wl-copy / xclip / xsel / pbcopy; Windows `clip.exe`), clipboard image paste, local image
//! attachments and composing a message in `$EDITOR` (Hermes `/copy`, `/paste`,
//! `/image`, `/prompt`).

use seagent_core::Block;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;

/// Largest image attached from disk or the clipboard.
pub const MAX_IMAGE_BYTES: usize = 20 * 1024 * 1024;

/// First of `names` found on `$PATH`.
pub fn which(names: &[&str]) -> Option<PathBuf> {
    which_in(&std::env::var_os("PATH")?, names)
}

fn which_in(path: &std::ffi::OsStr, names: &[&str]) -> Option<PathBuf> {
    for n in names {
        for d in std::env::split_paths(path) {
            let p = d.join(n);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

/// OSC 52 "set clipboard" — works over SSH and inside tmux (with `set-clipboard on`).
pub fn osc52(text: &str) -> String {
    format!("\x1b]52;c;{}\x07", seagent_net::crypto::b64(text.as_bytes()))
}

/// Copy `text`: a native clipboard tool when present, and OSC 52 for remote terminals.
/// Returns how it was copied.
pub fn copy(text: &str) -> Result<String, String> {
    copy_in(text, &std::env::var_os("PATH").unwrap_or_default(), std::env::var_os("WAYLAND_DISPLAY").is_some())
}

fn copy_in(text: &str, path: &std::ffi::OsStr, wayland: bool) -> Result<String, String> {
    // Windows: clip.exe reads UTF-16LE with a BOM as Unicode (anything else as the OEM codepage).
    #[cfg(windows)]
    if let Some(p) = seagent_core::platform::layout::which("clip") {
        if let Ok(mut child) = seagent_core::platform::proc::command(p).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn() {
            if let Some(mut i) = child.stdin.take() {
                let mut b = vec![0xff, 0xfe];
                b.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
                let _ = i.write_all(&b);
            }
            if child.wait().is_ok_and(|s| s.success()) {
                return Ok("clip".into());
            }
        }
    }
    let tools: &[(&str, &[&str])] = if wayland {
        &[("wl-copy", &[]), ("xclip", &["-selection", "clipboard"]), ("xsel", &["--clipboard", "--input"]), ("pbcopy", &[])]
    } else {
        &[("xclip", &["-selection", "clipboard"]), ("xsel", &["--clipboard", "--input"]), ("wl-copy", &[]), ("pbcopy", &[])]
    };
    for (bin, args) in tools {
        let Some(p) = which_in(path, &[bin]) else { continue };
        let Ok(mut child) = seagent_core::platform::proc::command(p).args(*args).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn() else { continue };
        if let Some(mut i) = child.stdin.take() {
            let _ = i.write_all(text.as_bytes());
        }
        if child.wait().is_ok_and(|s| s.success()) {
            return Ok(bin.to_string());
        }
    }
    if text.len() > 100_000 {
        return Err("no clipboard tool found (install wl-clipboard or xclip) and the text is too long for OSC 52".into());
    }
    let mut out = std::io::stdout();
    out.write_all(osc52(text).as_bytes()).map_err(|e| e.to_string())?;
    let _ = out.flush();
    Ok("OSC 52".into())
}

/// Media type from magic bytes.
pub fn sniff(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if b.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if b.len() > 12 && &b[..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

pub fn image_block(bytes: &[u8]) -> Result<Block, String> {
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err(format!("image is {} MB; the limit is {} MB", bytes.len() / 1_048_576, MAX_IMAGE_BYTES / 1_048_576));
    }
    let mt = sniff(bytes).ok_or("not a PNG, JPEG, GIF or WebP image")?;
    Ok(Block::Image { media_type: mt.into(), data: seagent_net::crypto::b64(bytes) })
}

/// Split a leading path token (quoted, or with `\ ` escapes) from trailing free-form text
/// (Hermes `cli_terminal_input._split_path_input`): `/image shot.png what is this` attaches
/// `shot.png` and leaves `what is this` as the prompt.
pub fn split_path_input(raw: &str) -> (String, String) {
    let raw = raw.trim();
    if raw.is_empty() {
        return (String::new(), String::new());
    }
    let mut chars = raw.char_indices();
    if let Some((_, q @ ('"' | '\''))) = chars.next() {
        let mut pos = q.len_utf8();
        while pos < raw.len() {
            let ch = raw[pos..].chars().next().unwrap_or_default();
            if ch == '\\' && pos + 1 < raw.len() {
                pos += 1 + raw[pos + 1..].chars().next().map(|c| c.len_utf8()).unwrap_or(0);
                continue;
            }
            if ch == q {
                let path = raw[q.len_utf8()..pos].to_string();
                return (path, raw[pos + ch.len_utf8()..].trim().to_string());
            }
            pos += ch.len_utf8();
        }
        return (raw[q.len_utf8()..].to_string(), String::new());
    }
    // Unquoted: a `\ ` escape keeps the space inside the path.
    let b = raw.as_bytes();
    let mut pos = 0;
    while pos < b.len() {
        if b[pos] == b'\\' && pos + 1 < b.len() && b[pos + 1] == b' ' {
            pos += 2;
            continue;
        }
        if b[pos] == b' ' || b[pos] == b'\t' {
            let path = raw[..pos].replace("\\ ", " ");
            return (path, raw[pos..].trim().to_string());
        }
        pos += 1;
    }
    (raw.replace("\\ ", " "), String::new())
}

/// `/image <path>` (relative to `cwd`; `~` expands).
pub fn image_file(path: &str, cwd: &Path) -> Result<Block, String> {
    let p = path.trim().trim_matches(['"', '\'']);
    if p.is_empty() {
        return Err("usage: /image <path>".into());
    }
    let pb = match p.strip_prefix("~/") {
        Some(rest) => PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(rest),
        None => cwd.join(p),
    };
    let meta = std::fs::metadata(&pb).map_err(|e| format!("{}: {e}", pb.display()))?;
    if meta.len() as usize > MAX_IMAGE_BYTES {
        return Err(format!("{} is larger than {} MB", pb.display(), MAX_IMAGE_BYTES / 1_048_576));
    }
    image_block(&std::fs::read(&pb).map_err(|e| format!("{}: {e}", pb.display()))?)
}

/// Clipboard image (`/paste`): wl-paste, xclip or pngpaste (macOS: else AppleScript's
/// `«class PNGf»`; Windows: `System.Windows.Forms.Clipboard` through PowerShell).
pub fn paste_image() -> Result<Block, String> {
    #[cfg(windows)]
    return paste_windows();
    #[cfg(not(windows))]
    {
        let r = paste_in(&std::env::var_os("PATH").unwrap_or_default());
        #[cfg(target_os = "macos")]
        if r.is_err() {
            return paste_macos().or(r);
        }
        r
    }
}

#[cfg(windows)]
fn paste_windows() -> Result<Block, String> {
    const PS: &str = "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; $i=[System.Windows.Forms.Clipboard]::GetImage(); if ($i) { $m=New-Object System.IO.MemoryStream; $i.Save($m,[System.Drawing.Imaging.ImageFormat]::Png); $o=[Console]::OpenStandardOutput(); $o.Write($m.ToArray(),0,[int]$m.Length); $o.Flush() }";
    let o = seagent_core::platform::proc::command("powershell").args(["-NoProfile", "-NonInteractive", "-STA", "-Command", PS]).stderr(Stdio::null()).output().map_err(|e| format!("powershell: {e}"))?;
    if o.status.success() && !o.stdout.is_empty() {
        return image_block(&o.stdout);
    }
    Err("no image on the clipboard (powershell)".into())
}

#[cfg(target_os = "macos")]
fn paste_macos() -> Result<Block, String> {
    let guard = seagent_core::tmp::TempDir::new("seagent-paste");
    let f = guard.path().join("clip.png");
    let script = format!("set f to (open for access POSIX file \"{}\" with write permission)\ntry\nwrite (the clipboard as «class PNGf») to f\nend try\nclose access f", f.display());
    let ok = seagent_core::platform::proc::command("osascript").args(["-e", &script]).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
    match std::fs::read(&f) {
        Ok(b) if ok && !b.is_empty() => image_block(&b),
        _ => Err("no image on the clipboard (pngpaste, osascript)".into()),
    }
}

#[cfg_attr(windows, allow(dead_code))]
fn paste_in(path: &std::ffi::OsStr) -> Result<Block, String> {
    let attempts: &[(&str, &[&str])] = &[("wl-paste", &["--no-newline", "--type", "image/png"]), ("xclip", &["-selection", "clipboard", "-t", "image/png", "-o"]), ("pngpaste", &["-"])];
    let mut tried = vec![];
    for (bin, args) in attempts {
        let Some(p) = which_in(path, &[bin]) else { continue };
        tried.push(*bin);
        if let Ok(o) = seagent_core::platform::proc::command(p).args(*args).stderr(Stdio::null()).output() {
            if o.status.success() && !o.stdout.is_empty() {
                return image_block(&o.stdout);
            }
        }
    }
    Err(if tried.is_empty() { "no clipboard tool found (install wl-clipboard or xclip)".into() } else { format!("no image on the clipboard ({})", tried.join(", ")) })
}

/// Create the `/prompt` draft with mode 0600 from the first byte.
///
/// The draft holds the user's next message, which may contain secrets, and it lives in a shared
/// temp directory: `create_new` + `mode(0o600)` means the file is never briefly world-readable
/// between `open` and `chmod`. A file already at that path is not reused — another local user
/// could have planted a symlink or a file we do not own — it is unlinked and recreated, so the
/// draft the editor opens is always ours and always private.
fn private_draft(path: &Path, text: &str) -> Result<(), String> {
    if std::fs::symlink_metadata(path).is_ok() {
        std::fs::remove_file(path).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    #[cfg(unix)]
    let opened = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            // A planted dangling symlink would otherwise be followed by a plain `create`.
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
    };
    // Windows: CREATE_NEW (an existing name or link fails) with an owner-only DACL from creation.
    #[cfg(not(unix))]
    let opened = seagent_core::platform::fs_private::open_private(path, seagent_core::platform::fs_private::OpenMode::CreateNew);
    let mut f = opened.map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())
}

/// Open `$VISUAL`/`$EDITOR` on a temporary Markdown file and return what was written
/// (`#`-comment lines from the template removed).
pub fn compose(initial: &str) -> Result<String, String> {
    // Windows has no vi; Notepad blocks until its window closes, like a terminal editor.
    let editor = std::env::var("VISUAL").or_else(|_| std::env::var("EDITOR")).unwrap_or_else(|_| if cfg!(windows) { "notepad" } else { "vi" }.into());
    // Guard: the draft's directory is removed on every exit path (the 0600 file lives inside it).
    let guard = seagent_core::tmp::TempDir::new("seagent-prompt");
    let tmp = guard.path().join("prompt.md");
    let template = format!("{initial}\n<!-- Write your message above. Save and quit to send; leave it empty to cancel. -->\n");
    private_draft(&tmp, &template)?;
    let mut parts = editor.split_whitespace();
    let bin = parts.next().unwrap_or("vi");
    let st = seagent_core::platform::proc::command(bin).args(parts).arg(&tmp).status().map_err(|e| format!("{bin}: {e}"));
    let text = std::fs::read_to_string(&tmp).unwrap_or_default();
    // Best effort and always: the draft must not outlive the editor, not even when it failed.
    let _ = std::fs::remove_file(&tmp);
    let st = st?;
    if !st.success() {
        return Err(format!("{bin} exited with {st}"));
    }
    let body: String = text.lines().filter(|l| !l.trim_start().starts_with("<!-- Write your message above")).collect::<Vec<_>>().join("\n");
    Ok(body.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osc_sniff_and_files() {
        assert_eq!(osc52("hi"), "\x1b]52;c;aGk=\x07");
        assert_eq!(sniff(b"\x89PNG\r\n\x1a\nrest"), Some("image/png"));
        assert_eq!(sniff(&[0xff, 0xd8, 0xff, 0xe0]), Some("image/jpeg"));
        assert_eq!(sniff(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
        assert!(sniff(b"hello").is_none());
        let t = seagent_core::tmp::TempDir::new("seagent-clip");
        let d = t.path();
        std::fs::write(d.join("a.png"), b"\x89PNG\r\n\x1a\n0000").unwrap();
        std::fs::write(d.join("b.txt"), b"text").unwrap();
        assert!(matches!(image_file("a.png", d).unwrap(), Block::Image { media_type, .. } if media_type == "image/png"));
        assert!(image_file("b.txt", d).unwrap_err().contains("not a PNG"));
        assert!(image_file("missing.png", d).is_err());
    }

    #[cfg(unix)]
    /// `/prompt` (`/compose`): `$EDITOR` opens on the seeded draft and what it writes
    /// comes back as the message — the same `seagent_app::clip::compose` path `seagent chat` and
    /// the TUI use. The editor here is a shell script, so no terminal is needed.
    #[test]
    fn compose_opens_editor_with_the_draft() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        let d = seagent_core::tmp::TempDir::new("seagent-compose");
        let editor = d.path().join("editor.sh");
        let seen = d.path().join("seen");
        let mode = d.path().join("mode");
        let draft = d.path().join("draft-path");
        // argv[1] is the temporary Markdown file: keep a copy, record its mode and path (the
        // draft must be 0600 while the editor runs), then write the answer.
        std::fs::write(
            &editor,
            format!(
                "#!/bin/sh\ncp \"$1\" {seen}\nstat -c %a \"$1\" > {mode}\nprintf '%s' \"$1\" > {draft}\nprintf 'edited message\\n\\nsecond line\\n' > \"$1\"\n",
                seen = seen.display(),
                mode = mode.display(),
                draft = draft.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&editor, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::env::set_var("EDITOR", &editor);
        std::env::remove_var("VISUAL");
        let out = compose("draft text").unwrap();
        assert_eq!(out, "edited message\n\nsecond line", "the editor's body minus the template comment");
        // The draft may contain the user's next message (possibly secrets): private from the
        // start, and gone once the editor exits.
        assert_eq!(std::fs::read_to_string(&mode).unwrap().trim(), "600", "the draft is 0600 while the editor runs");
        let draft = std::fs::read_to_string(&draft).unwrap();
        assert!(!std::path::Path::new(&draft).exists(), "the draft is deleted after the editor: {draft}");
        let seeded = std::fs::read_to_string(&seen).unwrap();
        assert!(seeded.contains("draft text"), "the current composer draft seeds the editor: {seeded}");
        assert!(seeded.contains("<!-- Write your message above"), "the template comment is there: {seeded}");
        // A failing editor is reported, and its draft is cleaned up too.
        let bad = d.path().join("bad.sh");
        std::fs::write(&bad, format!("#!/bin/sh\nprintf '%s' \"$1\" > {}\nexit 3\n", d.path().join("bad-path").display())).unwrap();
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::env::set_var("EDITOR", &bad);
        let err = compose("x").unwrap_err();
        assert!(err.contains("exited with"), "{err}");
        let draft = std::fs::read_to_string(d.path().join("bad-path")).unwrap();
        assert!(!std::path::Path::new(&draft).exists(), "no draft survives a failing editor: {draft}");
    }

    #[cfg(unix)]
    /// The draft writer itself: a pre-existing file at the path (e.g. a 0644 leftover from an
    /// older seagent, or something another local user put there) is never reused.
    #[test]
    fn prompt_draft_is_private_and_replaces_a_world_readable_file() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        let d = seagent_core::tmp::TempDir::new("seagent-prompt");
        let p = d.path().join("draft.md");
        std::fs::write(&p, "stale draft").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        private_draft(&p, "new draft").unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "new draft");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn split_path_input_splits_quoted_and_escaped_paths() {
        assert_eq!(split_path_input("a.png"), ("a.png".into(), "".into()));
        assert_eq!(split_path_input("  a.png  "), ("a.png".into(), "".into()));
        assert_eq!(split_path_input("a.png what is this"), ("a.png".into(), "what is this".into()));
        assert_eq!(split_path_input("my\\ shot.png describe"), ("my shot.png".into(), "describe".into()));
        assert_eq!(split_path_input("\"my shot.png\" describe this"), ("my shot.png".into(), "describe this".into()));
        assert_eq!(split_path_input("'shot.png'"), ("shot.png".into(), "".into()));
        assert_eq!(split_path_input("\"unterminated shot.png"), ("unterminated shot.png".into(), "".into()));
        assert_eq!(split_path_input(""), ("".into(), "".into()));
        // The image path really resolves with the split.
        let t = seagent_core::tmp::TempDir::new("seagent-clip-split");
        let d = t.path().to_path_buf();
        std::fs::write(d.join("my shot.png"), b"\x89PNG\r\n\x1a\n0000").unwrap();
        let (path, rest) = split_path_input("my\\ shot.png look");
        assert!(matches!(image_file(&path, &d).unwrap(), Block::Image { .. }) && rest == "look");
    }

    #[cfg(unix)]
    #[test]
    fn clipboard_tools_from_path() {
        // A fake xclip on PATH receives the text; paste returns its PNG bytes.
        let t = seagent_core::tmp::TempDir::new("seagent-clipbin");
        let d = t.path().to_path_buf();
        let log = d.join("got");
        let script = format!("#!/bin/sh\nif [ \"$5\" = \"-o\" ]; then printf '\\211PNG\\r\\n\\032\\nxx'; else cat > {}; fi\n", log.display());
        let bin = d.join("xclip");
        std::fs::write(&bin, script).unwrap();
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let r = copy_in("copied text", d.as_os_str(), false);
        let p = paste_in(d.as_os_str());
        assert!(paste_in(std::ffi::OsStr::new("/nonexistent")).unwrap_err().contains("no clipboard tool"));
        assert_eq!(r.unwrap(), "xclip");
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "copied text");
        assert!(matches!(p.unwrap(), Block::Image { media_type, .. } if media_type == "image/png"));
    }
}
