use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Write `data` to `path` atomically: temp file in the same dir, fsync, rename.
/// Keeps the permissions of an existing file.
pub fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = path.file_name().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp: PathBuf = dir.join(format!(
        ".{}.ark-tmp-{}-{}",
        name.to_string_lossy(),
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let res = (|| {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        if let Ok(meta) = fs::metadata(path) {
            fs::set_permissions(&tmp, meta.permissions())?;
        }
        fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

pub fn io_err(action: &str, path: &Path, e: &io::Error) -> String {
    let hint = match e.kind() {
        io::ErrorKind::NotFound => " (path does not exist; check spelling or use glob to locate it)",
        io::ErrorKind::PermissionDenied => " (permission denied; this file is not accessible to the agent user)",
        io::ErrorKind::IsADirectory => " (it is a directory)",
        _ => "",
    };
    format!("cannot {action} {}: {e}{hint}", path.display())
}

/// Heuristic: NUL byte in the first 8 KiB.
pub fn is_binary(data: &[u8]) -> bool {
    data[..data.len().min(8192)].contains(&0)
}

/// Cut a string to at most `max` bytes on a char boundary.
pub fn truncate_str(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Path shown to the model: relative to the workspace when inside it.
pub fn display_path(workspace: &Path, p: &Path) -> String {
    p.strip_prefix(workspace).map(|r| r.display().to_string()).unwrap_or_else(|_| p.display().to_string())
}

/// Accept a common alternative name for an argument (models guess `content`
/// for `text`, `old` for `old_string`…). The canonical key always wins.
/// Arrays of strings become newline-joined text.
pub fn alias(input: &mut serde_json::Value, canonical: &str, alts: &[&str]) {
    let Some(o) = input.as_object_mut() else { return };
    if !o.contains_key(canonical) {
        if let Some(v) = alts.iter().find_map(|a| o.remove(*a)) {
            let v = match v {
                serde_json::Value::Array(a) if a.iter().all(|x| x.is_string()) => serde_json::Value::String(a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join("\n")),
                other => other,
            };
            o.insert(canonical.to_string(), v);
        }
    }
}

/// Like `alias` but keeps the value as-is (for array/object arguments); a
/// JSON string holding an array/object is parsed.
pub fn rename(input: &mut serde_json::Value, canonical: &str, alts: &[&str]) {
    let Some(o) = input.as_object_mut() else { return };
    if !o.contains_key(canonical) {
        if let Some(v) = alts.iter().find_map(|a| o.remove(*a)) {
            o.insert(canonical.to_string(), v);
        }
    }
    if let Some(serde_json::Value::String(s)) = o.get(canonical) {
        let t = s.trim();
        if t.starts_with('[') || t.starts_with('{') {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
                o.insert(canonical.to_string(), v);
            }
        }
    }
}

/// Models sometimes name the `action` key differently.
fn action_key(input: &mut serde_json::Value) {
    rename(input, "action", &["operation", "op", "mode"]);
}

/// Map synonyms of an `action` value onto the real one.
pub fn action_synonyms(input: &mut serde_json::Value, map: &[(&str, &str)]) {
    action_key(input);
    if let Some(a) = input.get("action").and_then(|a| a.as_str()).map(|a| a.to_ascii_lowercase()) {
        if let Some((_, to)) = map.iter().find(|(from, _)| *from == a) {
            input["action"] = serde_json::Value::String(to.to_string());
        }
    }
}

/// Fill in `action` when the model left it out but the other arguments make it unambiguous.
pub fn infer_action(input: &mut serde_json::Value, rules: &[(&str, &str)]) {
    action_key(input);
    let Some(o) = input.as_object_mut() else { return };
    if o.get("action").and_then(|a| a.as_str()).is_none() {
        if let Some((_, act)) = rules.iter().find(|(key, _)| o.contains_key(*key)) {
            o.insert("action".into(), serde_json::Value::String(act.to_string()));
        }
    }
}
