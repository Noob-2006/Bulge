//! Board export / import (move a whole board between machines). Archive: a POSIX
//! ustar file with one top-level directory named for the source slug holding
//! `manifest.json`, `board.json`, `kanban.json`, `attachments/<task>/…` and
//! optionally `logs/<task>.log`. Machine-local state (claims, worker sessions,
//! owner pids, chat subscriptions, origin session ids) is scrubbed on export and
//! again on import (an archive is untrusted). Imports always land as a NEW board.

use super::boards::{self, MetaPatch};
use super::store::{self, BoardData};
use super::{attachments_dir, board_dir, now, DEFAULT_BOARD};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

pub const FORMAT: &str = "seagent-kanban-board";
pub const FORMAT_VERSION: u64 = 1;
const MAX_ENTRY: u64 = 512 * 1024 * 1024;

pub fn scrub(b: &mut BoardData) {
    b.subscriptions.clear();
    b.placements.clear();
    let n = now();
    for t in b.tasks.iter_mut() {
        t.claim_lock = None;
        t.claim_expires = None;
        t.claim_owner = None;
        t.claim_token = None;
        t.current_run_id = None;
        t.last_heartbeat_at = None;
        t.session_id = None;
        t.session_key = None;
        t.consecutive_failures = 0;
        t.last_failure_error = None;
        if t.status == "running" {
            t.status = "ready".into();
        }
    }
    for r in b.runs.iter_mut() {
        if r.status == "running" || r.ended_at.is_none() {
            r.status = "released".into();
            r.outcome.get_or_insert_with(|| "reclaimed".into());
            r.ended_at.get_or_insert(n);
        }
        r.claim_lock = None;
        r.worker_session = None;
        r.owner_pid = None;
        r.owner_birth = None;
        r.last_heartbeat_at = None;
    }
}

fn header(name: &str, size: u64, dir: bool) -> Result<[u8; 512], String> {
    let mut h = [0u8; 512];
    let (prefix, base) = if name.len() > 100 {
        let cut = name[..name.len().min(155)].rfind('/').ok_or_else(|| format!("path too long for tar: {name}"))?;
        (&name[..cut], &name[cut + 1..])
    } else {
        ("", name)
    };
    if base.len() > 100 || prefix.len() > 155 {
        return Err(format!("path too long for tar: {name}"));
    }
    h[..base.len()].copy_from_slice(base.as_bytes());
    let oct = |v: u64, w: usize| format!("{v:0>width$o}\0", width = w - 1);
    h[100..108].copy_from_slice(oct(if dir { 0o755 } else { 0o644 }, 8).as_bytes());
    h[108..116].copy_from_slice(oct(0, 8).as_bytes());
    h[116..124].copy_from_slice(oct(0, 8).as_bytes());
    h[124..136].copy_from_slice(oct(size, 12).as_bytes());
    h[136..148].copy_from_slice(oct(now() as u64, 12).as_bytes());
    h[148..156].copy_from_slice(b"        ");
    h[156] = if dir { b'5' } else { b'0' };
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    let sum: u32 = h.iter().map(|b| *b as u32).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    Ok(h)
}

struct Tar<W: Write>(W);
impl<W: Write> Tar<W> {
    fn file(&mut self, name: &str, data: &[u8]) -> Result<(), String> {
        self.0.write_all(&header(name, data.len() as u64, false)?).map_err(|e| e.to_string())?;
        self.0.write_all(data).map_err(|e| e.to_string())?;
        let pad = (512 - data.len() % 512) % 512;
        self.0.write_all(&vec![0u8; pad]).map_err(|e| e.to_string())
    }
    fn finish(mut self) -> Result<(), String> {
        self.0.write_all(&[0u8; 1024]).map_err(|e| e.to_string())?;
        self.0.flush().map_err(|e| e.to_string())
    }
}

/// Every regular file entry: (path, bytes). Rejects traversal, absolute paths and links.
pub fn read_tar(path: &Path) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = vec![];
    loop {
        let mut h = [0u8; 512];
        if f.read_exact(&mut h).is_err() || h.iter().all(|b| *b == 0) {
            return Ok(out);
        }
        let field = |a: usize, b: usize| String::from_utf8_lossy(&h[a..b]).trim_end_matches('\0').to_string();
        let name = field(0, 100);
        let prefix = field(345, 500);
        let name = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
        let size = u64::from_str_radix(field(124, 136).trim(), 8).map_err(|_| "corrupt tar header".to_string())?;
        if size > MAX_ENTRY {
            return Err(format!("tar entry {name} is too large"));
        }
        let kind = h[156];
        let mut data = vec![0u8; size as usize];
        f.read_exact(&mut data).map_err(|e| e.to_string())?;
        let pad = (512 - size % 512) % 512;
        std::io::copy(&mut (&mut f).take(pad), &mut std::io::sink()).map_err(|e| e.to_string())?;
        if kind == b'5' {
            continue;
        }
        if kind != b'0' && kind != 0 {
            return Err(format!("unsupported tar entry type for {name} (links are refused)"));
        }
        let p = Path::new(&name);
        if p.is_absolute() || p.components().any(|c| matches!(c, Component::ParentDir | Component::RootDir | Component::Prefix(_))) {
            return Err(format!("unsafe path in archive: {name}"));
        }
        out.push((name, data));
    }
}

fn walk(dir: &Path, base: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_dir() {
            walk(&p, base, out);
        } else if ft.is_file() {
            // Archive member names use `/` on every OS (`attachments/x` on Windows too).
            out.push((seagent_core::platform::layout::model_path(p.strip_prefix(base).unwrap()), p));
        }
    }
}

pub fn export_board(data: &Path, slug: &str, output: &Path, include_attachments: bool, include_logs: bool) -> Result<Value, String> {
    if !boards::board_exists(data, slug) {
        return Err(format!("board {slug:?} does not exist"));
    }
    let mut b = store::read_board(data, slug)?;
    scrub(&mut b);
    // Attachment paths are machine-local: ship them board-relative (import re-anchors by leaf).
    for a in b.attachments.iter_mut() {
        let leaf = Path::new(&a.stored_path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
        a.stored_path = format!("attachments/{}/{leaf}", a.task_id);
    }
    let mut meta = boards::read_meta(data, slug);
    meta.default_workdir = None;
    meta.default_workspace = None;
    let dir = board_dir(data, slug);
    let mut files: Vec<(String, PathBuf)> = vec![];
    if include_attachments {
        walk(&dir.join("attachments"), &dir, &mut files);
    }
    if include_logs {
        walk(&dir.join("logs"), &dir, &mut files);
    }
    let counts = json!({"tasks": b.tasks.len(), "task_links": b.links.len(), "task_comments": b.comments.len(), "task_events": b.events.len(), "task_runs": b.runs.len(), "task_attachments": b.attachments.len(), "attachment_files": files.iter().filter(|f| f.0.starts_with("attachments/")).count()});
    let manifest = json!({"format": FORMAT, "format_version": FORMAT_VERSION, "board": slug, "name": meta.name, "exported_at": now(), "seagent_version": env!("CARGO_PKG_VERSION"), "includes": {"attachments": include_attachments, "logs": include_logs}, "counts": counts});
    if let Some(p) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let tmp = output.with_extension("partial");
    let mut tar = Tar(std::io::BufWriter::new(std::fs::File::create(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?));
    tar.file(&format!("{slug}/manifest.json"), serde_json::to_string_pretty(&manifest).unwrap().as_bytes())?;
    tar.file(&format!("{slug}/board.json"), serde_json::to_string_pretty(&meta).unwrap().as_bytes())?;
    tar.file(&format!("{slug}/kanban.json"), serde_json::to_string(&b).unwrap().as_bytes())?;
    for (rel, p) in &files {
        let data = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
        tar.file(&format!("{slug}/{rel}"), &data)?;
    }
    tar.finish()?;
    std::fs::rename(&tmp, output).map_err(|e| e.to_string())?;
    let size = std::fs::metadata(output).map(|m| m.len()).unwrap_or(0);
    Ok(json!({"board": slug, "archive": output.display().to_string(), "size": size, "counts": counts}))
}

pub fn import_board(data: &Path, archive: &Path, as_slug: Option<&str>, activate: bool) -> Result<Value, String> {
    let entries = read_tar(archive)?;
    let roots: std::collections::BTreeSet<String> = entries.iter().map(|(n, _)| n.split('/').next().unwrap_or("").to_string()).collect();
    if roots.len() != 1 {
        return Err("archive must contain exactly one top-level board directory".into());
    }
    let root = roots.into_iter().next().unwrap();
    let get = |n: &str| entries.iter().find(|(p, _)| p == &format!("{root}/{n}")).map(|(_, d)| d.clone());
    let manifest: Value = serde_json::from_slice(&get("manifest.json").ok_or("archive has no manifest.json")?).map_err(|e| format!("manifest.json: {e}"))?;
    if manifest["format"] != FORMAT {
        return Err(format!("not an seagent kanban board archive (format {:?})", manifest["format"]));
    }
    if manifest["format_version"].as_u64().unwrap_or(0) > FORMAT_VERSION {
        return Err(format!("archive format version {} is newer than this seagent supports ({FORMAT_VERSION})", manifest["format_version"]));
    }
    let mut b: BoardData = serde_json::from_slice(&get("kanban.json").ok_or("archive has no kanban.json")?).map_err(|e| format!("kanban.json: {e}"))?;
    let meta: boards::BoardMeta = get("board.json").and_then(|d| serde_json::from_slice(&d).ok()).unwrap_or_default();
    let requested = super::normalize_slug(Some(as_slug.unwrap_or(manifest["board"].as_str().unwrap_or(&root))))?.ok_or("archive names no board")?;
    let mut slug = if requested == DEFAULT_BOARD { "default-imported".to_string() } else { requested.clone() };
    let mut n = 2;
    while boards::board_exists(data, &slug) || board_dir(data, &slug).exists() {
        slug = format!("{requested}-{n}");
        n += 1;
    }
    scrub(&mut b);
    let mut warnings = vec![];
    // Re-anchor attachments and refuse any stored path that is not ours.
    let mut written = 0;
    for (name, bytes) in &entries {
        let Some(rel) = name.strip_prefix(&format!("{root}/")) else { continue };
        if rel.starts_with("attachments/") || rel.starts_with("logs/") {
            let dest = board_dir(data, &slug).join(rel);
            std::fs::create_dir_all(dest.parent().unwrap()).map_err(|e| e.to_string())?;
            std::fs::write(&dest, bytes).map_err(|e| e.to_string())?;
            if rel.starts_with("attachments/") {
                written += 1;
            }
        }
    }
    for a in b.attachments.iter_mut() {
        let leaf = Path::new(&a.stored_path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
        let p = attachments_dir(data, &slug, &a.task_id).join(&leaf);
        if !p.exists() {
            warnings.push(format!("attachment {} ({}) was not included in the archive", a.id, a.filename));
        }
        a.stored_path = p.display().to_string();
    }
    // A task whose workspace cannot be rebuilt here is parked in triage (only if dispatchable).
    let mut parked = 0;
    for t in b.tasks.iter_mut() {
        if t.workspace_kind == "scratch" {
            t.workspace_path = None;
            continue;
        }
        let missing = t.workspace_path.as_deref().is_none_or(|p| !Path::new(p).exists());
        if missing && matches!(t.status.as_str(), "ready" | "todo" | "scheduled") {
            t.status = "triage".into();
            parked += 1;
        }
    }
    if parked > 0 {
        warnings.push(format!("{parked} task(s) reference a dir/worktree workspace that does not exist on this machine; moved to triage"));
    }
    boards::create_board(data, &slug, MetaPatch { name: Some(meta.name.clone()), description: Some(meta.description.clone()), icon: Some(meta.icon.clone()), color: Some(meta.color.clone()), kind: Some(if meta.kind.is_empty() { "cards".into() } else { meta.kind.clone() }), sessions: meta.sessions.clone(), ..Default::default() })?;
    let counts = json!({"tasks": b.tasks.len(), "task_comments": b.comments.len(), "attachment_files": written});
    store::with_board(data, &slug, |cur| {
        *cur = b;
        Ok(())
    })?;
    if activate {
        super::set_current_board(data, &slug)?;
    }
    Ok(json!({"board": slug, "requested_board": requested, "renamed": slug != requested, "name": boards::read_meta(data, &slug).name, "path": board_dir(data, &slug).display().to_string(), "counts": counts, "warnings": warnings, "activated": activate}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kanban::ops::{self, NewTask};

    #[test]
    fn export_import_roundtrip_scrubs_and_renames() {
        let d = crate::kanban::testutil::data();
        boards::create_board(&d, "proj", MetaPatch { name: Some("Project".into()), default_workdir: Some("/secret/home".into()), ..Default::default() }).unwrap();
        let id = store::with_board(&d, "proj", |b| {
            let id = ops::create_task(b, NewTask { title: "a".into(), session_id: Some("chat-123".into()), ..Default::default() })?;
            ops::claim(b, &id, ops::ClaimOpts { lock: "host:1", ttl: 60, lane: "ready", owner: None, token: Some("tok") });
            ops::store_attachment(b, &d, "proj", &id, "notes.txt", b"hello", None, None, None)?;
            ops::create_task(b, NewTask { title: "dir".into(), workspace_kind: Some("dir".into()), workspace_path: Some("/no/such/dir".into()), ..Default::default() })?;
            notify_sub(b, &id);
            Ok(id)
        })
        .unwrap();
        let out = d.join("out/proj.tar");
        let r = export_board(&d, "proj", &out, true, false).unwrap();
        assert_eq!(r["counts"]["attachment_files"], 1);
        let ents = read_tar(&out).unwrap();
        assert!(ents.iter().any(|(n, _)| n == "proj/manifest.json"));
        let r = import_board(&d, &out, None, true).unwrap();
        assert_eq!(r["board"], "proj-2");
        assert_eq!(r["renamed"], true);
        assert_eq!(crate::kanban::current_board(&d), "proj-2");
        let b = store::read_board(&d, "proj-2").unwrap();
        let t = b.task(&id).unwrap();
        assert_eq!(t.status, "ready", "a phantom claim never imports");
        assert!(t.claim_lock.is_none() && t.session_id.is_none() && t.claim_token.is_none());
        assert!(b.subscriptions.is_empty(), "chat subscriptions stripped");
        assert_eq!(std::fs::read(&b.attachments[0].stored_path).unwrap(), b"hello");
        assert!(b.attachments[0].stored_path.contains("proj-2"));
        assert!(b.tasks.iter().any(|t| t.title == "dir" && t.status == "triage"));
        assert!(boards::read_meta(&d, "proj-2").default_workdir.is_none(), "machine-local paths stripped");
        // Traversal is refused.
        let evil = d.join("evil.tar");
        let mut w = Tar(std::fs::File::create(&evil).unwrap());
        w.file("x/../../etc/passwd", b"x").unwrap();
        w.finish().unwrap();
        assert!(read_tar(&evil).unwrap_err().contains("unsafe path"));
    }

    fn notify_sub(b: &mut BoardData, id: &str) {
        crate::kanban::notify::subscribe(b, store::Subscription { task_id: Some(id.into()), platform: Some("telegram".into()), chat_id: Some("42".into()), ..Default::default() }).unwrap();
    }

    /// The ARP surface the dashboard and `seagent kanban export|import` both call.
    fn arp(k: &crate::kernel::Kernel, method: &str, p: Value) -> Result<Value, String> {
        crate::kanban::methods::call(k, method, &p).unwrap_or_else(|| Err((-32601, format!("unknown method {method}")))).map_err(|(_, e)| e)
    }

    #[test]
    fn arp_export_import_moves_a_board_and_strips_machine_state() {
        use crate::kanban::methods;
        let (k, _p, _ws) = crate::kanban::testutil::kernel(|c| c.kanban.enabled = true);
        let d = k.paths.data.clone();
        boards::create_board(&d, "proj", MetaPatch { name: Some("Project".into()), default_workdir: Some("/secret/home".into()), ..Default::default() }).unwrap();
        let id = store::with_board(&d, "proj", |b| {
            let id = ops::create_task(b, NewTask { title: "carry me over".into(), session_id: Some("chat-123".into()), ..Default::default() })?;
            ops::claim(b, &id, ops::ClaimOpts { lock: "host:1", ttl: 60, lane: "ready", owner: None, token: Some("tok") });
            ops::store_attachment(b, &d, "proj", &id, "notes.txt", b"hello", None, None, None)?;
            notify_sub(b, &id);
            Ok(id)
        })
        .unwrap();
        assert!(methods::NAMES.contains(&"kanban.export") && methods::NAMES.contains(&"kanban.import"));

        // Missing arguments are parameter errors, not silent defaults.
        let (code, msg) = methods::call(&k, "kanban.export", &json!({"board": "proj"})).unwrap().unwrap_err();
        assert_eq!(code, -32602);
        assert!(msg.contains("missing `output`"), "{msg}");
        let (code, msg) = methods::call(&k, "kanban.import", &json!({})).unwrap().unwrap_err();
        assert_eq!(code, -32602);
        assert!(msg.contains("missing `archive`"), "{msg}");

        let out = d.join("out/proj.tar");
        let v = arp(&k, "kanban.export", json!({"board": "proj", "output": out.display().to_string()})).unwrap();
        assert_eq!(v["board"], "proj");
        assert_eq!(v["counts"]["tasks"], 1);
        assert_eq!(v["counts"]["attachment_files"], 1);
        assert!(v["size"].as_u64().unwrap() > 0 && out.is_file());
        // Attachments ship by default; `attachments: false` drops them.
        let plain = d.join("out/plain.tar");
        let v = arp(&k, "kanban.export", json!({"board": "proj", "output": plain.display().to_string(), "attachments": false})).unwrap();
        assert_eq!(v["counts"]["attachment_files"], 0);

        // The archive itself is scrubbed: no claim, token, owner session or chat subscription.
        let ents = read_tar(&out).unwrap();
        let board_json = ents.iter().find(|(n, _)| n == "proj/kanban.json").map(|(_, d)| d.clone()).unwrap();
        let archived: BoardData = serde_json::from_slice(&board_json).unwrap();
        let at = archived.task(&id).unwrap();
        assert!(at.claim_lock.is_none() && at.claim_token.is_none() && at.session_id.is_none() && at.current_run_id.is_none());
        assert!(archived.subscriptions.is_empty());
        assert!(archived.runs.iter().all(|r| r.claim_lock.is_none() && r.worker_session.is_none() && r.owner_pid.is_none()), "runs carry no owner pid / session");
        assert!(archived.attachments.iter().all(|a| a.stored_path.is_empty() || !a.stored_path.contains(&d.display().to_string())), "attachment paths are made board-relative");

        // Import lands as a NEW board and activates it on request.
        let v = arp(&k, "kanban.import", json!({"archive": out.display().to_string(), "as_slug": "copy", "switch": true})).unwrap();
        assert_eq!(v["board"], "copy");
        assert_eq!(v["renamed"], false);
        assert_eq!(v["activated"], true);
        assert_eq!(crate::kanban::current_board(&d), "copy");
        let b = store::read_board(&d, "copy").unwrap();
        assert_eq!(b.tasks.len(), 1);
        assert_eq!(b.status_of(&id), Some("ready"), "a phantom claim never survives the trip");
        assert_eq!(std::fs::read(&b.attachments[0].stored_path).unwrap(), b"hello");
        assert!(b.attachments[0].stored_path.contains("copy"), "attachments are re-anchored to the new board");

        // Without `as_slug` the source name is kept unless it is taken (then suffixed).
        let v = arp(&k, "kanban.import", json!({"archive": out.display().to_string()})).unwrap();
        assert_eq!(v["board"], "proj-2");
        assert_eq!(v["renamed"], true);
        assert_eq!(v["requested_board"], "proj");
        assert_eq!(v["activated"], false, "import never switches boards unless asked");

        // `default` is never imported over the live default board.
        boards::create_board(&d, "default", Default::default()).unwrap();
        store::with_board(&d, "default", |b| ops::create_task(b, NewTask { title: "home".into(), ..Default::default() })).unwrap();
        let dflt = d.join("out/default.tar");
        arp(&k, "kanban.export", json!({"board": "default", "output": dflt.display().to_string()})).unwrap();
        let v = arp(&k, "kanban.import", json!({"archive": dflt.display().to_string()})).unwrap();
        assert_eq!(v["board"], "default-imported");
    }

    #[test]
    fn arp_transfer_errors_are_actionable() {
        let (k, _p, _ws) = crate::kanban::testutil::kernel(|c| c.kanban.enabled = true);
        let d = k.paths.data.clone();
        boards::create_board(&d, "proj", Default::default()).unwrap();

        let e = arp(&k, "kanban.export", json!({"board": "ghost", "output": d.join("x.tar").display().to_string()})).unwrap_err();
        assert!(e.contains("board \"ghost\" does not exist"), "{e}");

        let e = arp(&k, "kanban.import", json!({"archive": d.join("nope.tar").display().to_string()})).unwrap_err();
        assert!(e.contains("nope.tar"), "the error names the file it could not read: {e}");

        // A file that is not one of our archives is refused by format, not by luck.
        let junk = d.join("junk.tar");
        let mut t = Tar(std::fs::File::create(&junk).unwrap());
        t.file("x/manifest.json", br#"{"format":"something-else","format_version":1}"#).unwrap();
        t.file("x/kanban.json", b"{}").unwrap();
        t.finish().unwrap();
        let e = arp(&k, "kanban.import", json!({"archive": junk.display().to_string()})).unwrap_err();
        assert!(e.contains("not an seagent kanban board archive"), "{e}");

        // Two top-level directories: ambiguous, refused.
        let two = d.join("two.tar");
        let mut t = Tar(std::fs::File::create(&two).unwrap());
        t.file("a/manifest.json", b"{}").unwrap();
        t.file("b/manifest.json", b"{}").unwrap();
        t.finish().unwrap();
        let e = arp(&k, "kanban.import", json!({"archive": two.display().to_string()})).unwrap_err();
        assert!(e.contains("exactly one top-level board directory"), "{e}");

        // Nothing was created by the failures.
        let slugs: Vec<String> = boards::list_boards(&d, true).into_iter().map(|m| m.slug).collect();
        assert!(slugs.iter().all(|s| s == "default" || s == "proj"), "a failed import leaves no half-board: {slugs:?}");
    }
}
