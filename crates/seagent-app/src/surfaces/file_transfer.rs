//! File transfer with paired nodes: `file_fetch`, `dir_list`, `dir_fetch`, `file_write`
//! (OpenClaw extensions/file-transfer, MIT), plus the node side (`file.fetch`, `dir.list`,
//! `dir.fetch`, `file.write`).
//!
//! The node decides what is reachable: reads stay inside `read_roots`, writes inside
//! `write_roots` (node.toml; empty = denied). Fetched bytes land in
//! `<surfaces>/file-transfer/` with a media id a later `file_write` can reuse.

use super::{canvas, now_ms, write_atomic, Env};
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub const DEFAULT_MAX_BYTES: u64 = 8 * 1024 * 1024;
pub const HARD_MAX_BYTES: u64 = 16 * 1024 * 1024;
pub const DIR_LIST_DEFAULT: u64 = 200;
pub const DIR_LIST_MAX: u64 = 5000;
const TEXT_LIMIT: usize = 8192;
const INLINE_TEXT: usize = 8 * 1024;

fn d_timeout() -> u64 {
    60_000
}

/// `[surfaces.file_transfer]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileTransferConfig {
    /// Node invoke timeout. Default 60000 ms.
    #[serde(default = "d_timeout")]
    pub timeout_ms: u64,
}

impl Default for FileTransferConfig {
    fn default() -> Self {
        FileTransferConfig { timeout_ms: d_timeout() }
    }
}

pub fn tools(env: Arc<Env>) -> Vec<Arc<dyn Tool>> {
    let inv = canvas::default_invoker();
    let list = canvas::default_lister();
    ["file_fetch", "dir_list", "dir_fetch", "file_write"].iter().map(|k| Arc::new(Transfer { env: env.clone(), kind: k, invoke: inv.clone(), list: list.clone() }) as Arc<dyn Tool>).collect()
}

pub struct Transfer {
    env: Arc<Env>,
    kind: &'static str,
    invoke: canvas::Invoker,
    list: canvas::Lister,
}

const NODE_DESC: &str = "Existing paired node id or display name (see node_invoke action=list). Do not use local, host or auto; use local file tools for the workspace.";

fn media_dir(env: &Env) -> PathBuf {
    env.dir.join("file-transfer")
}

fn mime(name: &str) -> &'static str {
    match name.rsplit('.').next().unwrap_or("").to_ascii_lowercase().as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "json" => "application/json",
        "txt" | "log" | "md" | "csv" | "toml" | "yaml" | "yml" | "rs" | "py" | "js" | "ts" | "sh" | "conf" | "ini" | "xml" | "html" | "css" => "text/plain",
        "gz" | "tgz" => "application/gzip",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

fn human(n: u64) -> String {
    match n {
        n if n >= 1 << 20 => format!("{:.1} MB", n as f64 / (1 << 20) as f64),
        n if n >= 1 << 10 => format!("{:.1} KB", n as f64 / 1024.0),
        n => format!("{n} B"),
    }
}

fn sha256_hex(b: &[u8]) -> String {
    seagent_net::crypto::hex(&seagent_net::crypto::sha256(b))
}

/// Strict base64 (standard alphabet, canonical padding).
fn decode_strict(s: &str) -> Result<Vec<u8>, String> {
    let b = seagent_net::crypto::b64_decode(s.trim()).ok_or("contentBase64 is not valid base64")?;
    if seagent_net::crypto::b64(&b).trim_end_matches('=') != s.trim().trim_end_matches('=') {
        return Err("contentBase64 is not valid base64".into());
    }
    if b.len() as u64 > HARD_MAX_BYTES {
        return Err(format!("decoded content is {} bytes; maximum is {HARD_MAX_BYTES} bytes ({})", b.len(), human(HARD_MAX_BYTES)));
    }
    Ok(b)
}

fn save_media(env: &Env, name: &str, bytes: &[u8]) -> Result<(String, PathBuf), String> {
    let safe: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || "._-".contains(c) { c } else { '_' }).collect::<String>().trim_start_matches('.').chars().take(80).collect();
    let id = format!("{}-{}", seagent_net::crypto::hex(&seagent_net::crypto::random_bytes(8)), if safe.is_empty() { "file".into() } else { safe });
    let p = media_dir(env).join(&id);
    write_atomic(&p, bytes)?;
    Ok((id, p))
}

fn valid_media_id(id: &str) -> bool {
    !id.is_empty() && !id.starts_with('.') && id.len() <= 120 && id.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

impl Transfer {
    fn node(&self, p: &Value, command: &str) -> Result<String, String> {
        let q = p["node"].as_str().map(str::trim).filter(|s| !s.is_empty()).ok_or("node required")?;
        if matches!(q, "local" | "host" | "gateway" | "auto") {
            return Err(format!("`{q}` is not a paired node; use local file tools for local paths"));
        }
        canvas::resolve_node(&(self.list)(), Some(q), command).map(|(id, _)| id).map_err(|e| e.replace("canvas", "node"))
    }

    fn path(p: &Value) -> Result<String, String> {
        let s = p["path"].as_str().map(str::trim).filter(|s| !s.is_empty()).ok_or("path required")?;
        if !s.starts_with('/') {
            return Err("path must be absolute on the node".into());
        }
        Ok(s.to_string())
    }

    fn timeout(&self, p: &Value) -> Duration {
        Duration::from_millis(p["timeoutMs"].as_u64().unwrap_or(self.env.cfg.file_transfer.timeout_ms).clamp(1000, 600_000))
    }

    fn run(&self, p: &Value) -> Result<String, String> {
        match self.kind {
            "file_fetch" => {
                let (node, path) = (self.node(p, "file.fetch")?, Self::path(p)?);
                let max = p["maxBytes"].as_u64().unwrap_or(DEFAULT_MAX_BYTES).clamp(1, HARD_MAX_BYTES);
                let r = (self.invoke)(&node, "file.fetch", json!({"path": path, "maxBytes": max}), self.timeout(p))?;
                let bytes = seagent_net::crypto::b64_decode(r["base64"].as_str().ok_or("unexpected file.fetch response from node")?).ok_or("node returned invalid base64")?;
                if let Some(h) = r["sha256"].as_str() {
                    if h != sha256_hex(&bytes) {
                        return Err("file.fetch integrity check failed (sha256 mismatch)".into());
                    }
                }
                let canonical = r["path"].as_str().unwrap_or(&path).to_string();
                let name = Path::new(&canonical).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
                let (id, local) = save_media(&self.env, &name, &bytes)?;
                let m = r["mimeType"].as_str().unwrap_or(mime(&name)).to_string();
                let mut text = format!("Fetched {canonical} ({}, {m}) from {node}\nlocalPath: {}\nmediaId: {id}", human(bytes.len() as u64), local.display());
                if (m.starts_with("text/") || m == "application/json") && bytes.len() <= INLINE_TEXT {
                    if let Ok(s) = std::str::from_utf8(&bytes) {
                        text.push_str(&format!("\n--- content ---\n{s}"));
                    }
                }
                Ok(format!("{text}\n{}", json!({"path": canonical, "localPath": local, "mediaId": id, "size": bytes.len(), "mimeType": m, "sha256": sha256_hex(&bytes)})))
            }
            "dir_list" => {
                let (node, path) = (self.node(p, "dir.list")?, Self::path(p)?);
                let max = p["maxEntries"].as_u64().unwrap_or(DIR_LIST_DEFAULT).clamp(1, DIR_LIST_MAX);
                let mut params = json!({"path": path, "maxEntries": max});
                if let Some(t) = p["pageToken"].as_str() {
                    params["pageToken"] = t.into();
                }
                let r = (self.invoke)(&node, "dir.list", params, self.timeout(p))?;
                let entries = r["entries"].as_array().cloned().ok_or("unexpected dir.list response from node")?;
                let offset: u64 = p["pageToken"].as_str().and_then(|t| t.parse().ok()).unwrap_or(0);
                let head = format!("{} ({} entries{})\n", r["path"].as_str().unwrap_or(&path), entries.len(), if r["truncated"] == true { ", more available" } else { "" });
                let mut text = head;
                let mut shown = 0usize;
                for e in &entries {
                    let line = format!("{}{}\t{}\n", e["name"].as_str().unwrap_or(""), if e["isDir"] == true { "/" } else { "" }, if e["isDir"] == true { "-".into() } else { human(e["size"].as_u64().unwrap_or(0)) });
                    if text.len() + line.len() + 80 > TEXT_LIMIT {
                        break;
                    }
                    text.push_str(&line);
                    shown += 1;
                }
                if shown == 0 && !entries.is_empty() {
                    text.push_str("(first entry cannot be shown within the text limit; pagination cannot advance)\n");
                } else if shown < entries.len() || r["truncated"] == true {
                    text.push_str(&format!("nextPageToken: {}\n", offset + shown as u64));
                }
                Ok(format!("{text}{}", json!({"path": r["path"], "entries": entries, "nextPageToken": r["nextPageToken"], "truncated": r["truncated"]})))
            }
            "dir_fetch" => {
                let (node, path) = (self.node(p, "dir.fetch")?, Self::path(p)?);
                let max = p["maxBytes"].as_u64().unwrap_or(DEFAULT_MAX_BYTES).clamp(1, HARD_MAX_BYTES);
                let r = (self.invoke)(&node, "dir.fetch", json!({"path": path, "maxBytes": max}), self.timeout(p))?;
                let tar = seagent_net::crypto::b64_decode(r["base64"].as_str().ok_or("unexpected dir.fetch response from node")?).ok_or("node returned invalid base64")?;
                if r["sha256"].as_str().is_some_and(|h| h != sha256_hex(&tar)) {
                    return Err("dir.fetch integrity check failed (sha256 mismatch)".into());
                }
                let (id, tar_path) = save_media(&self.env, "dir.tar.gz", &tar)?;
                let root = media_dir(&self.env).join(format!("dir-fetch-{id}"));
                if let Err(e) = unpack(&tar_path, &root) {
                    let _ = std::fs::remove_dir_all(&root);
                    let _ = std::fs::remove_file(&tar_path);
                    return Err(e);
                }
                let mut files = Vec::new();
                walk(&root, &root, &mut files);
                files.sort();
                let mut shown = Vec::new();
                let mut size = 0;
                for (rel, n) in &files {
                    let rec = json!({"relPath": rel, "size": n}).to_string();
                    if size + rec.len() + 400 > TEXT_LIMIT {
                        break;
                    }
                    size += rec.len() + 1;
                    shown.push(rec);
                }
                let omitted = files.len() - shown.len();
                Ok(format!("Fetched {} files.\n{{\"rootDir\":{},\"fileCount\":{},\"displayedCount\":{},\"files\":[{}]}}\n{omitted} saved files omitted from this text. All remain under rootDir.", files.len(), json!(root), files.len(), shown.len(), shown.join(",")))
            }
            "file_write" => {
                let (node, path) = (self.node(p, "file.write")?, Self::path(p)?);
                let (bytes, source) = match (p["sourceMediaId"].as_str().map(str::trim).filter(|s| !s.is_empty()), p["contentBase64"].as_str()) {
                    (Some(id), _) => {
                        if !valid_media_id(id) {
                            return Err("sourceMediaId is not a file-transfer media id".into());
                        }
                        let b = std::fs::read(media_dir(&self.env).join(id)).map_err(|_| format!("no file-transfer media `{id}`"))?;
                        if b.len() as u64 > HARD_MAX_BYTES {
                            return Err("source media exceeds 16 MB".into());
                        }
                        (b, "media")
                    }
                    (None, Some(b64)) => (decode_strict(b64)?, "inline"),
                    _ => return Err("contentBase64 or sourceMediaId required".into()),
                };
                let sha = sha256_hex(&bytes);
                let r = (self.invoke)(&node, "file.write", json!({"path": path, "contentBase64": seagent_net::crypto::b64(&bytes), "overwrite": p["overwrite"] == true, "createParents": p["createParents"] == true, "expectedSha256": sha}), self.timeout(p))?;
                if r["ok"] != true {
                    return Err(r["message"].as_str().unwrap_or("unexpected file.write response from node").to_string());
                }
                Ok(format!("Wrote {} ({}, sha256:{}){}\n{}", r["path"].as_str().unwrap_or(&path), human(r["size"].as_u64().unwrap_or(bytes.len() as u64)), &sha[..12], if r["overwritten"] == true { " (overwrote existing file)" } else { "" }, json!({"path": r["path"], "size": r["size"], "sha256": sha, "overwritten": r["overwritten"], "source": source})))
            }
            _ => Err("unknown transfer".into()),
        }
    }
}

/// Unpack a node's tarball after checking every member: regular files and directories
/// only, relative paths without `..`, bounded count and size.
fn unpack(tar: &Path, root: &Path) -> Result<(), String> {
    let list = std::process::Command::new("tar").arg("-tvzf").arg(tar).output().map_err(|e| format!("tar: {e}"))?;
    if !list.status.success() {
        return Err("UNSAFE_ARCHIVE: archive could not be read".into());
    }
    let names = std::process::Command::new("tar").arg("-tzf").arg(tar).output().map_err(|e| format!("tar: {e}"))?;
    let listing = String::from_utf8_lossy(&list.stdout);
    let mut total: u64 = 0;
    let mut count = 0;
    for (line, name) in listing.lines().zip(String::from_utf8_lossy(&names.stdout).lines()) {
        count += 1;
        let kind = line.chars().next().unwrap_or('?');
        if kind != '-' && kind != 'd' {
            return Err(format!("UNSAFE_ARCHIVE: `{name}` is not a regular file or directory"));
        }
        if name.starts_with('/') || name.split('/').any(|c| c == "..") {
            return Err(format!("UNSAFE_ARCHIVE: unsafe path `{name}`"));
        }
        total += line.split_whitespace().nth(2).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    }
    if count > 10_000 {
        return Err("UNSAFE_ARCHIVE: too many entries".into());
    }
    if total > 64 * HARD_MAX_BYTES {
        return Err("UNCOMPRESSED_TOO_LARGE: tree expands beyond 1 GB".into());
    }
    std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let st = std::process::Command::new("tar").args(["--no-same-owner", "--no-same-permissions", "-xzf"]).arg(tar).arg("-C").arg(root).status().map_err(|e| format!("tar: {e}"))?;
    if !st.success() {
        return Err("UNSAFE_ARCHIVE: extraction failed".into());
    }
    Ok(())
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, u64)>) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        match e.file_type() {
            Ok(t) if t.is_dir() => walk(root, &p, out),
            Ok(t) if t.is_file() => out.push((p.strip_prefix(root).unwrap_or(&p).display().to_string(), e.metadata().map(|m| m.len()).unwrap_or(0))),
            _ => {}
        }
    }
}

impl Tool for Transfer {
    fn spec(&self) -> ToolSpec {
        let (desc, props, req): (&str, Value, Vec<&str>) = match self.kind {
            "file_fetch" => ("Retrieve a file from a paired node by absolute path. Saves the bytes in seagent's file-transfer store and returns localPath and mediaId (reusable as sourceMediaId for file_write); inlines small text files (≤8 KB). The node only serves paths inside its read_roots.", json!({"maxBytes": {"type": "integer", "minimum": 1, "description": "Max bytes. Default 8 MB, hard ceiling 16 MB."}}), vec![]),
            "dir_list" => ("List a directory on a paired node (not the local workspace): names, isDir and sizes; text is limited to 8192 bytes. For more, pass the returned nextPageToken as pageToken with the same node and path.", json!({"pageToken": {"type": "string"}, "maxEntries": {"type": "integer", "minimum": 1, "description": "Default 200, hard ceiling 5000."}}), vec![]),
            "dir_fetch" => ("Retrieve a whole directory tree (including dotfiles) from a paired node as a gzipped tarball and unpack it locally; returns rootDir and relPath/size records. Rejects trees larger than 16 MB compressed and archives with links or unsafe paths.", json!({"maxBytes": {"type": "integer", "minimum": 1, "description": "Max tarball bytes. Default 8 MB, hard ceiling 16 MB."}}), vec![]),
            _ => ("Write a file to a paired node by absolute path (atomic temp + rename). Refuses to overwrite unless overwrite=true, and refuses symlink targets. Pass contentBase64, or sourceMediaId from file_fetch. The node only writes inside its write_roots.", json!({"contentBase64": {"type": "string", "description": "Bytes to write (max 16 MB decoded)."}, "sourceMediaId": {"type": "string"}, "mimeType": {"type": "string"}, "overwrite": {"type": "boolean"}, "createParents": {"type": "boolean"}}), vec![]),
        };
        let mut schema = json!({"type": "object", "properties": {"node": {"type": "string", "description": NODE_DESC}, "path": {"type": "string", "description": "Absolute path on the node."}, "timeoutMs": {"type": "integer", "minimum": 1}}, "required": ["node", "path"]});
        for (k, v) in props.as_object().unwrap() {
            schema["properties"][k] = v.clone();
        }
        let _ = req;
        ToolSpec { name: self.kind.into(), description: desc.into(), input_schema: schema, parallel_safe: self.kind != "file_write", idempotent: self.kind != "file_write", pinned: false }
    }
    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let node = input["node"].as_str().unwrap_or("");
        let path = input["path"].as_str().unwrap_or("");
        match self.kind {
            // Writing on someone's device needs the operator's say-so.
            "file_write" => vec![Effect::Remote { dest: format!("node:{node}"), reason: format!("file_write changes {path} on node {node}") }, Effect::Net { dest: format!("node:{node}"), payload: format!("{path} ({} bytes base64)", input["contentBase64"].as_str().map(str::len).unwrap_or(0)) }],
            _ => vec![Effect::Net { dest: format!("node:{node}"), payload: path.to_string() }],
        }
    }
    fn call(&self, _ctx: &ToolCtx, input: Value) -> ToolOutput {
        match self.run(&input) {
            Ok(t) => ToolOutput::ok(t),
            Err(e) => ToolOutput::err(e),
        }
    }
}

// ───────────────────────── node side ─────────────────────────

pub const NODE_COMMANDS: &[&str] = &["file.fetch", "dir.list", "dir.fetch", "file.write"];

fn err(code: &str, msg: &str) -> String {
    format!("{code}: {msg}")
}

/// Canonical path inside one of `roots`, else an error naming why.
fn inside(roots: &[PathBuf], p: &Path, code_missing: &str) -> Result<PathBuf, String> {
    if !p.is_absolute() {
        return Err(err("INVALID_PARAMS", "path must be absolute"));
    }
    if roots.is_empty() {
        return Err(err("POLICY_DENIED", "no roots are configured on this node"));
    }
    let c = p.canonicalize().map_err(|e| if e.kind() == std::io::ErrorKind::NotFound { err(code_missing, "path not found") } else { err("PERMISSION_DENIED", &e.to_string()) })?;
    if roots.iter().filter_map(|r| r.canonicalize().ok()).any(|r| c.starts_with(&r)) {
        Ok(c)
    } else {
        Err(err("POLICY_DENIED", "path is outside the node's allowed roots"))
    }
}

pub fn node_run(read_roots: &[PathBuf], write_roots: &[PathBuf], command: &str, p: &Value) -> Result<Value, String> {
    let path = PathBuf::from(p["path"].as_str().unwrap_or(""));
    match command {
        "file.fetch" => {
            let c = inside(read_roots, &path, "NOT_FOUND")?;
            let md = std::fs::metadata(&c).map_err(|e| e.to_string())?;
            if !md.is_file() {
                return Err(err("IS_DIRECTORY", "path is not a regular file"));
            }
            let max = p["maxBytes"].as_u64().unwrap_or(DEFAULT_MAX_BYTES).min(HARD_MAX_BYTES);
            if md.len() > max {
                return Err(err("FILE_TOO_LARGE", &format!("file is {} bytes; maxBytes is {max}", md.len())));
            }
            let b = std::fs::read(&c).map_err(|e| err("READ_ERROR", &e.to_string()))?;
            let name = c.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            Ok(json!({"ok": true, "path": c, "name": name, "size": b.len(), "mimeType": mime(&name), "sha256": sha256_hex(&b), "base64": seagent_net::crypto::b64(&b)}))
        }
        "dir.list" => {
            let c = inside(read_roots, &path, "NOT_FOUND")?;
            if !c.is_dir() {
                return Err(err("NOT_DIRECTORY", "path is not a directory"));
            }
            let max = p["maxEntries"].as_u64().unwrap_or(DIR_LIST_DEFAULT).clamp(1, DIR_LIST_MAX) as usize;
            let offset: usize = p["pageToken"].as_str().and_then(|t| t.parse().ok()).unwrap_or(0);
            let mut all: Vec<(String, bool, bool, u64, u64)> = std::fs::read_dir(&c)
                .map_err(|e| err("READ_ERROR", &e.to_string()))?
                .flatten()
                .map(|e| {
                    let md = e.metadata().ok();
                    let ft = e.file_type().ok();
                    let mtime = md.as_ref().and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as u64).unwrap_or(0);
                    (e.file_name().to_string_lossy().into_owned(), ft.is_some_and(|t| t.is_dir()), ft.is_some_and(|t| t.is_file()), md.map(|m| m.len()).unwrap_or(0), mtime)
                })
                .collect();
            all.sort();
            let total = all.len();
            let entries: Vec<Value> = all.into_iter().skip(offset).take(max).map(|(n, d, f, s, m)| json!({"name": n, "path": c.join(&n), "size": if d { 0 } else { s }, "mimeType": if d { "inode/directory" } else { mime(&n) }, "isDir": d, "isFile": f, "mtime": m})).collect();
            let truncated = offset + max < total;
            Ok(json!({"ok": true, "path": c, "entries": entries, "nextPageToken": truncated.then(|| (offset + max).to_string()), "truncated": truncated}))
        }
        "dir.fetch" => {
            let c = inside(read_roots, &path, "NOT_FOUND")?;
            if !c.is_dir() {
                return Err(err("NOT_DIRECTORY", "path is not a directory"));
            }
            // A denied descendant (a symlink leaving the roots) rejects the whole transfer.
            let mut stack = vec![c.clone()];
            while let Some(d) = stack.pop() {
                for e in std::fs::read_dir(&d).map_err(|e| err("READ_ERROR", &e.to_string()))?.flatten() {
                    let t = e.file_type().map_err(|e| e.to_string())?;
                    if t.is_symlink() {
                        return Err(err("POLICY_DENIED", &format!("{} is a symlink; dir.fetch only sends regular files", e.path().display())));
                    }
                    if t.is_dir() {
                        stack.push(e.path());
                    }
                }
            }
            let max = p["maxBytes"].as_u64().unwrap_or(DEFAULT_MAX_BYTES).min(HARD_MAX_BYTES);
            let out = std::process::Command::new("tar").arg("-czf").arg("-").arg("-C").arg(&c).arg(".").stdin(std::process::Stdio::null()).output().map_err(|e| err("READ_ERROR", &format!("tar: {e}")))?;
            if !out.status.success() {
                return Err(err("READ_ERROR", &String::from_utf8_lossy(&out.stderr)));
            }
            if out.stdout.len() as u64 > max {
                return Err(err("TREE_TOO_LARGE", &format!("compressed tree is {} bytes; maxBytes is {max}", out.stdout.len())));
            }
            Ok(json!({"ok": true, "path": c, "size": out.stdout.len(), "sha256": sha256_hex(&out.stdout), "base64": seagent_net::crypto::b64(&out.stdout)}))
        }
        "file.write" => {
            if !path.is_absolute() {
                return Err(err("INVALID_PARAMS", "path must be absolute"));
            }
            let bytes = seagent_net::crypto::b64_decode(p["contentBase64"].as_str().unwrap_or("")).ok_or_else(|| err("INVALID_PARAMS", "contentBase64 is not valid base64"))?;
            if bytes.len() as u64 > HARD_MAX_BYTES {
                return Err(err("FILE_TOO_LARGE", "content exceeds 16 MB"));
            }
            if p["expectedSha256"].as_str().is_some_and(|h| h != sha256_hex(&bytes)) {
                return Err(err("INTEGRITY", "content does not match expectedSha256"));
            }
            let name = path.file_name().ok_or_else(|| err("INVALID_PARAMS", "path has no file name"))?.to_owned();
            if name == ".." || name == "." {
                return Err(err("INVALID_PARAMS", "invalid file name"));
            }
            let parent = path.parent().ok_or_else(|| err("INVALID_PARAMS", "path has no parent"))?;
            if !parent.exists() {
                if p["createParents"] != true {
                    return Err(err("PARENT_NOT_FOUND", "parent directory does not exist (pass createParents)"));
                }
                // Check the nearest existing ancestor is inside the roots before creating anything.
                let mut a = parent;
                while !a.exists() {
                    a = a.parent().ok_or_else(|| err("INVALID_PARAMS", "no existing ancestor"))?;
                }
                inside(write_roots, a, "PARENT_NOT_FOUND")?;
                if parent.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
                    return Err(err("INVALID_PARAMS", "path must not contain .."));
                }
                std::fs::create_dir_all(parent).map_err(|e| err("WRITE_ERROR", &e.to_string()))?;
            }
            let cparent = inside(write_roots, parent, "PARENT_NOT_FOUND")?;
            let target = cparent.join(&name);
            let existing = std::fs::symlink_metadata(&target).ok();
            if existing.as_ref().is_some_and(|m| m.file_type().is_symlink()) {
                return Err(err("SYMLINK_TARGET", "refusing to write through a symlink"));
            }
            if existing.as_ref().is_some_and(|m| m.is_dir()) {
                return Err(err("IS_DIRECTORY", "path is a directory"));
            }
            let overwritten = existing.is_some();
            if overwritten && p["overwrite"] != true {
                return Err(err("EXISTS", "file exists (pass overwrite=true to replace it)"));
            }
            let tmp = cparent.join(format!(".{}.seagent-{}.tmp", name.to_string_lossy(), now_ms()));
            std::fs::write(&tmp, &bytes).map_err(|e| err("WRITE_ERROR", &e.to_string()))?;
            std::fs::rename(&tmp, &target).map_err(|e| {
                let _ = std::fs::remove_file(&tmp);
                err("WRITE_ERROR", &e.to_string())
            })?;
            Ok(json!({"ok": true, "path": target, "size": bytes.len(), "sha256": sha256_hex(&bytes), "overwritten": overwritten}))
        }
        other => Err(format!("unknown command `{other}`")),
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit;
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn node_side_enforces_roots_and_writes_atomically() {
        let d = testkit::temp("ft-node");
        let (r, w) = (d.join("read"), d.join("write"));
        std::fs::create_dir_all(r.join("sub/.hidden")).unwrap();
        std::fs::create_dir_all(&w).unwrap();
        std::fs::write(r.join("a.txt"), "hello").unwrap();
        std::fs::write(r.join("sub/.hidden/b.log"), "x").unwrap();
        let rr = vec![r.clone()];
        let wr = vec![w.clone()];
        let f = node_run(&rr, &wr, "file.fetch", &json!({"path": r.join("a.txt")})).unwrap();
        assert_eq!((f["size"].as_u64(), f["mimeType"].as_str()), (Some(5), Some("text/plain")));
        assert!(node_run(&rr, &wr, "file.fetch", &json!({"path": "/etc/hostname"})).unwrap_err().starts_with("POLICY_DENIED"));
        assert!(node_run(&rr, &wr, "file.fetch", &json!({"path": r.join("a.txt"), "maxBytes": 2})).unwrap_err().starts_with("FILE_TOO_LARGE"));
        assert!(node_run(&rr, &wr, "file.fetch", &json!({"path": r.join("../read/a.txt")})).is_ok(), "canonicalized");
        let l = node_run(&rr, &wr, "dir.list", &json!({"path": r, "maxEntries": 1})).unwrap();
        assert_eq!((l["entries"][0]["name"].as_str(), l["nextPageToken"].as_str()), (Some("a.txt"), Some("1")));
        let l2 = node_run(&rr, &wr, "dir.list", &json!({"path": r, "pageToken": "1"})).unwrap();
        assert_eq!(l2["entries"][0]["isDir"], true);
        let t = node_run(&rr, &wr, "dir.fetch", &json!({"path": r})).unwrap();
        assert!(t["size"].as_u64().unwrap() > 0);
        std::os::unix::fs::symlink("/etc", r.join("sub/escape")).unwrap();
        assert!(node_run(&rr, &wr, "dir.fetch", &json!({"path": r})).unwrap_err().contains("symlink"));
        std::fs::remove_file(r.join("sub/escape")).unwrap();
        // Writes.
        let b64 = seagent_net::crypto::b64(b"data");
        assert!(node_run(&rr, &[], "file.write", &json!({"path": w.join("x"), "contentBase64": b64})).unwrap_err().starts_with("POLICY_DENIED"));
        let ok = node_run(&rr, &wr, "file.write", &json!({"path": w.join("x"), "contentBase64": b64, "expectedSha256": sha256_hex(b"data")})).unwrap();
        assert_eq!(ok["overwritten"], false);
        assert!(node_run(&rr, &wr, "file.write", &json!({"path": w.join("x"), "contentBase64": b64})).unwrap_err().starts_with("EXISTS"));
        assert_eq!(node_run(&rr, &wr, "file.write", &json!({"path": w.join("x"), "contentBase64": b64, "overwrite": true})).unwrap()["overwritten"], true);
        assert!(node_run(&rr, &wr, "file.write", &json!({"path": w.join("n/m/y"), "contentBase64": b64})).unwrap_err().starts_with("PARENT_NOT_FOUND"));
        assert!(node_run(&rr, &wr, "file.write", &json!({"path": w.join("n/m/y"), "contentBase64": b64, "createParents": true})).is_ok());
        std::os::unix::fs::symlink(r.join("a.txt"), w.join("link")).unwrap();
        assert!(node_run(&rr, &wr, "file.write", &json!({"path": w.join("link"), "contentBase64": b64, "overwrite": true})).unwrap_err().starts_with("SYMLINK_TARGET"));
        assert!(node_run(&rr, &wr, "file.write", &json!({"path": w.join("z"), "contentBase64": b64, "expectedSha256": "00"})).unwrap_err().starts_with("INTEGRITY"));
        assert!(node_run(&rr, &wr, "file.write", &json!({"path": "/tmp/../etc/x", "contentBase64": b64})).is_err());
    }

    #[test]
    fn tools_round_trip_through_a_node() {
        let (env, _) = testkit::env("ft", &[], "");
        let d = testkit::temp("ft-roots");
        std::fs::create_dir_all(d.join("r/docs")).unwrap();
        std::fs::create_dir_all(d.join("w")).unwrap();
        std::fs::write(d.join("r/notes.md"), "# hi").unwrap();
        std::fs::write(d.join("r/docs/x.bin"), [0u8, 1, 2]).unwrap();
        let (rr, wr) = (vec![d.join("r")], vec![d.join("w")]);
        let calls: Arc<Mutex<Vec<String>>> = Arc::default();
        let c2 = calls.clone();
        let inv: canvas::Invoker = Arc::new(move |_n: &str, c: &str, p: Value, _| {
            c2.lock().unwrap().push(c.to_string());
            node_run(&rr, &wr, c, &p)
        });
        let list: canvas::Lister = Arc::new(|| vec![json!({"id": "n1", "name": "Laptop", "commands": NODE_COMMANDS})]);
        let mk = |k: &'static str| Transfer { env: env.clone(), kind: k, invoke: inv.clone(), list: list.clone() };
        let ws = testkit::temp("ft-ws");
        let ctx = testkit::ctx(&env, &ws);
        let o = mk("file_fetch").call(&ctx, json!({"node": "Laptop", "path": d.join("r/notes.md")}));
        assert!(!o.is_error && o.content.contains("--- content ---\n# hi"), "{}", o.content);
        let v: Value = serde_json::from_str(o.content.lines().last().unwrap()).unwrap();
        let media = v["mediaId"].as_str().unwrap().to_string();
        let o = mk("file_write").call(&ctx, json!({"node": "n1", "path": d.join("w/copy.md"), "sourceMediaId": media}));
        assert!(!o.is_error, "{}", o.content);
        assert_eq!(std::fs::read_to_string(d.join("w/copy.md")).unwrap(), "# hi");
        assert!(mk("file_write").call(&ctx, json!({"node": "n1", "path": d.join("w/q"), "contentBase64": "@@@"})).content.contains("not valid base64"));
        assert!(mk("file_write").call(&ctx, json!({"node": "n1", "path": d.join("w/q"), "sourceMediaId": "../../etc/passwd"})).content.contains("not a file-transfer media id"));
        let o = mk("dir_list").call(&ctx, json!({"node": "n1", "path": d.join("r")}));
        assert!(o.content.contains("docs/\t-") && o.content.contains("notes.md\t4 B"), "{}", o.content);
        let o = mk("dir_fetch").call(&ctx, json!({"node": "n1", "path": d.join("r")}));
        assert!(o.content.starts_with("Fetched 2 files."), "{}", o.content);
        assert!(o.content.contains("docs/x.bin"));
        assert!(mk("file_fetch").call(&ctx, json!({"node": "local", "path": "/x"})).is_error);
        assert!(mk("file_fetch").call(&ctx, json!({"node": "n1", "path": "rel"})).content.contains("absolute"));
        assert!(matches!(mk("file_write").effects(&ctx, &json!({"node": "n1", "path": "/x"}))[0], Effect::Remote { .. }));
    }

    #[test]
    fn unpack_rejects_links() {
        let d = testkit::temp("ft-tar");
        std::fs::create_dir_all(d.join("src")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", d.join("src/p")).unwrap();
        let st = std::process::Command::new("tar").arg("-czf").arg(d.join("a.tgz")).arg("-C").arg(d.join("src")).arg(".").status().unwrap();
        assert!(st.success());
        assert!(unpack(&d.join("a.tgz"), &d.join("out")).unwrap_err().contains("UNSAFE_ARCHIVE"));
    }
}
