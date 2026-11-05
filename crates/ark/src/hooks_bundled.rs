//! Bundled hooks (OpenClaw src/hooks/bundled/*), native Rust, enabled with
//! `[hooks_extra] bundled = [...]` or `ark hooks enable <name>`:
//!
//! - `boot-md` (daemon_start): run `<workspace>/BOOT.md` once in a throwaway session.
//! - `bootstrap-extra-files` (session_start): add AGENTS.md-class files matched by
//!   `[hooks_extra.bootstrap_extra_files] paths` (inside the workspace only).
//! - `command-logger` (command): JSON lines in `<data>/logs/commands.log`.
//! - `compaction-notifier` (pre/post_compact): tell the session's chat about compaction.
//! - `session-memory` (session_end on new/reset/idle/daily): recent conversation →
//!   `<workspace>/memory/YYYY-MM-DD-<slug>.md`.

use crate::hooks_ext::{HooksExtra, KernelSlot, SessionMemoryCfg};
use ark_core::{Cancel, Message, ModelRequest, Role};
use ark_kernel::config::Paths;
use ark_kernel::event::EventKind;
use ark_kernel::hooks::{Hook, HookDecision, HookEvent};
use ark_kernel::kernel::{Kernel, RunOpts};
use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub fn make(name: &str, x: &HooksExtra, paths: &Paths, kernel: KernelSlot) -> Arc<dyn Hook> {
    match name {
        "boot-md" => Arc::new(BootMd { kernel }),
        "bootstrap-extra-files" => {
            let b = &x.bootstrap_extra_files;
            Arc::new(BootstrapExtraFiles { patterns: b.paths.iter().chain(&b.patterns).chain(&b.files).cloned().collect() })
        }
        "command-logger" => Arc::new(CommandLogger { path: paths.log_dir().join("commands.log") }),
        "compaction-notifier" => Arc::new(CompactionNotifier),
        _ => Arc::new(SessionMemory { cfg: x.session_memory.clone(), kernel }),
    }
}

// ───────────────────────── boot-md ─────────────────────────

const BOOT_FILENAME: &str = "BOOT.md";
const MAX_BOOT_FILE_BYTES: u64 = 16 * 1024 * 1024;
pub const SILENT_REPLY_TOKEN: &str = "NO_REPLY";

struct BootMd {
    kernel: KernelSlot,
}

/// BOOT.md content: Ok(None) when missing or empty.
pub fn load_boot_file(ws: &Path) -> Result<Option<String>, String> {
    let p = ws.join(BOOT_FILENAME);
    let real = match std::fs::canonicalize(&p) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", p.display())),
    };
    let md = std::fs::metadata(&real).map_err(|e| format!("{}: {e}", real.display()))?;
    if !md.is_file() {
        return Err(format!("{} is not a regular file", real.display()));
    }
    if md.len() > MAX_BOOT_FILE_BYTES {
        return Err(format!("{} is larger than {MAX_BOOT_FILE_BYTES} bytes", real.display()));
    }
    let c = std::fs::read_to_string(&real).map_err(|e| format!("{}: {e}", real.display()))?;
    Ok(Some(c.trim().to_string()).filter(|c| !c.is_empty()))
}

/// OpenClaw `buildBootPrompt`, as one message.
pub fn boot_prompt(content: &str) -> String {
    format!(
        "You are running a boot check. Follow BOOT.md instructions exactly.\n\nBOOT.md:\n{}\n\nIf BOOT.md asks you to send a message, use the channel_send tool (channel + chat).\nAfter sending, reply with exactly {SILENT_REPLY_TOKEN} as the entire final answer.\nIf nothing needs attention, reply with exactly {SILENT_REPLY_TOKEN} as the entire final answer.\n{SILENT_REPLY_TOKEN} discards anything written this turn that was not sent, so send confirmations before ending silently.\n\nRun the workspace boot check now.",
        content.replace("<<<", "‹‹‹").replace(">>>", "›››")
    )
}

/// Run BOOT.md in a run-owned session that is removed afterwards. Returns "ran" / "skipped: …".
pub fn run_boot_once(k: &Kernel, ws: &Path) -> Result<String, String> {
    let Some(content) = load_boot_file(ws)? else { return Ok("skipped: missing or empty".into()) };
    let id = k.create_session(ws, None, None, Some("boot")).map_err(|e| e.to_string())?;
    let r = k.submit(&id, &boot_prompt(&content), "boot").map_err(|e| e.to_string()).and_then(|_| k.run(&id, RunOpts::default()).map_err(|e| e.to_string()));
    let _ = k.store.remove(&id);
    let o = r?;
    if o.reason.ok() {
        Ok("ran".into())
    } else {
        Err(format!("boot run ended: {}", o.reason.label()))
    }
}

impl Hook for BootMd {
    fn name(&self) -> String {
        "bundled:boot-md".into()
    }
    fn wants(&self, e: HookEvent, _: Option<&str>) -> bool {
        e == HookEvent::DaemonStart
    }
    fn run(&self, _: HookEvent, p: &Value) -> Result<HookDecision, String> {
        let Some(k) = self.kernel.get().cloned() else { return Ok(HookDecision::Allow) };
        let ws = PathBuf::from(p["cwd"].as_str().unwrap_or("."));
        std::thread::spawn(move || match run_boot_once(&k, &ws) {
            Ok(s) => eprintln!("arkd: boot-md: {s}"),
            Err(e) => eprintln!("arkd: boot-md: {e}"),
        });
        Ok(HookDecision::Allow)
    }
}

// ───────────────────────── bootstrap-extra-files ─────────────────────────

/// OpenClaw `WORKSPACE_BOOTSTRAP_FILENAMES`.
pub const BOOTSTRAP_NAMES: &[&str] = &["AGENTS.md", "SOUL.md", "IDENTITY.md", "USER.md", "BOOTSTRAP.md", "MEMORY.md"];
/// OpenClaw `DEFAULT_BOOTSTRAP_MAX_CHARS`.
const BOOTSTRAP_MAX_CHARS: usize = 20_000;

struct BootstrapExtraFiles {
    patterns: Vec<String>,
}

/// Glob → anchored regex: `**` any depth, `*` / `?` within a segment, `{a,b}`, `[..]`.
pub fn glob_regex(pat: &str) -> Option<regex::Regex> {
    let mut re = String::from("^");
    let cs: Vec<char> = pat.chars().collect();
    let mut i = 0;
    let mut brace = 0;
    while i < cs.len() {
        let c = cs[i];
        match c {
            '*' if cs.get(i + 1) == Some(&'*') => {
                i += 1;
                if cs.get(i + 1) == Some(&'/') {
                    i += 1;
                    re.push_str("(?:.*/)?");
                } else {
                    re.push_str(".*");
                }
            }
            '*' => re.push_str("[^/]*"),
            '?' => re.push_str("[^/]"),
            '{' => {
                brace += 1;
                re.push_str("(?:");
            }
            '}' if brace > 0 => {
                brace -= 1;
                re.push(')');
            }
            ',' if brace > 0 => re.push('|'),
            '[' => {
                let end = cs[i..].iter().position(|c| *c == ']')? + i;
                let body: String = cs[i + 1..end].iter().collect();
                re.push('[');
                re.push_str(&body.replace('!', "^").replace('\\', "\\\\"));
                re.push(']');
                i = end;
            }
            c => re.push_str(&regex::escape(&c.to_string())),
        }
        i += 1;
    }
    re.push('$');
    regex::Regex::new(&re).ok()
}

fn has_glob(p: &str) -> bool {
    p.chars().any(|c| matches!(c, '*' | '?' | '[' | '{'))
}

fn walk_rel(root: &Path, dir: &Path, depth: usize, out: &mut Vec<String>) {
    if depth > 8 || out.len() > 5000 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let n = e.file_name().to_string_lossy().to_string();
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_dir() {
            if !matches!(n.as_str(), ".git" | "node_modules" | "target" | ".venv") {
                walk_rel(root, &e.path(), depth + 1, out);
            }
        } else if let Ok(rel) = e.path().strip_prefix(root) {
            out.push(rel.to_string_lossy().to_string());
        }
    }
}

/// OpenClaw `loadExtraBootstrapFilesWithDiagnostics`: (relative path, content) of the files the
/// patterns name, plus skip reasons. Paths must stay inside the workspace (realpath checked).
pub fn extra_bootstrap_files(ws: &Path, patterns: &[String]) -> (Vec<(String, String)>, Vec<String>) {
    let mut diag = Vec::new();
    let Ok(root) = ws.canonicalize() else { return (vec![], vec![format!("workspace {} missing", ws.display())]) };
    let mut rels: Vec<String> = Vec::new();
    let mut all: Option<Vec<String>> = None;
    for pat in patterns.iter().map(|p| p.trim().trim_start_matches("./").to_string()).filter(|p| !p.is_empty()) {
        if pat.starts_with('/') || pat.split('/').any(|s| s == "..") {
            diag.push(format!("{pat}: pattern resolves outside the workspace"));
            continue;
        }
        if has_glob(&pat) {
            let Some(re) = glob_regex(&pat) else {
                diag.push(format!("{pat}: invalid pattern"));
                continue;
            };
            let files = all.get_or_insert_with(|| {
                let mut v = Vec::new();
                walk_rel(&root, &root, 0, &mut v);
                v.sort();
                v
            });
            rels.extend(files.iter().filter(|f| re.is_match(f)).cloned());
        } else {
            rels.push(pat);
        }
    }
    rels.dedup();
    let mut out = Vec::new();
    for rel in rels {
        let base = rel.rsplit('/').next().unwrap_or(&rel).to_string();
        if !BOOTSTRAP_NAMES.contains(&base.as_str()) {
            diag.push(format!("{rel}: unsupported bootstrap basename: {base}"));
            continue;
        }
        let real = match root.join(&rel).canonicalize() {
            Ok(r) => r,
            Err(_) => {
                diag.push(format!("{rel}: missing"));
                continue;
            }
        };
        if !real.starts_with(&root) || !real.is_file() {
            diag.push(format!("{rel}: resolves outside the workspace"));
            continue;
        }
        match std::fs::read_to_string(&real) {
            Ok(t) => out.push((rel, t.chars().take(BOOTSTRAP_MAX_CHARS).collect())),
            Err(e) => diag.push(format!("{rel}: {e}")),
        }
    }
    (out, diag)
}

impl Hook for BootstrapExtraFiles {
    fn name(&self) -> String {
        "bundled:bootstrap-extra-files".into()
    }
    fn wants(&self, e: HookEvent, _: Option<&str>) -> bool {
        e == HookEvent::SessionStart && !self.patterns.is_empty()
    }
    fn run(&self, _: HookEvent, p: &Value) -> Result<HookDecision, String> {
        let ws = PathBuf::from(p["cwd"].as_str().unwrap_or("."));
        let (files, _diag) = extra_bootstrap_files(&ws, &self.patterns);
        if files.is_empty() {
            return Ok(HookDecision::Allow);
        }
        let text = files.iter().map(|(rel, t)| format!("## {rel}\n\n{}", t.trim_end())).collect::<Vec<_>>().join("\n\n");
        Ok(HookDecision::Context(format!("# Project Context (extra bootstrap files)\n\n{text}")))
    }
}

// ───────────────────────── command-logger ─────────────────────────

struct CommandLogger {
    path: PathBuf,
}

impl Hook for CommandLogger {
    fn name(&self) -> String {
        "bundled:command-logger".into()
    }
    fn wants(&self, e: HookEvent, _: Option<&str>) -> bool {
        e == HookEvent::Command
    }
    fn run(&self, _: HookEvent, p: &Value) -> Result<HookDecision, String> {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = self.path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        if std::fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(format!("{} is a symlink; not logging", dir.display()));
        }
        let line = json!({
            "timestamp": p["timestamp"].as_str().map(String::from).unwrap_or_else(crate::hooks_ext::now_iso),
            "action": p["action"], "sessionKey": p["session_id"],
            "senderId": p["sender_id"].as_str().filter(|s| !s.is_empty()).unwrap_or("unknown"),
            "source": p["source"].as_str().filter(|s| !s.is_empty()).unwrap_or("unknown"),
        });
        let mut f = std::fs::OpenOptions::new().create(true).append(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&self.path).map_err(|e| format!("{}: {e}", self.path.display()))?;
        writeln!(f, "{line}").map_err(|e| e.to_string())?;
        Ok(HookDecision::Allow)
    }
}

// ───────────────────────── compaction-notifier ─────────────────────────

struct CompactionNotifier;

/// The notice OpenClaw's compaction-notifier pushes for a compaction event.
pub fn compaction_notice(event: HookEvent, p: &Value) -> Option<String> {
    match event {
        HookEvent::PreCompact => Some(format!("🧹 Compacting context{} so I can continue without losing history…", p["messages"].as_u64().map(|n| format!(" ({n} messages)")).unwrap_or_default())),
        HookEvent::PostCompact if p["outcome"] == "skipped" => Some("✅ Nothing to compact. Continuing from where I left off.".into()),
        HookEvent::PostCompact => {
            let delta = match (p["tokens_before"].as_u64(), p["tokens_after"].as_u64()) {
                (Some(b), Some(a)) => format!(" ({b} → {a} tokens)"),
                _ => String::new(),
            };
            Some(format!("✅ Context compacted{delta}. Continuing from where I left off."))
        }
        _ => None,
    }
}

impl Hook for CompactionNotifier {
    fn name(&self) -> String {
        "bundled:compaction-notifier".into()
    }
    fn wants(&self, e: HookEvent, _: Option<&str>) -> bool {
        matches!(e, HookEvent::PreCompact | HookEvent::PostCompact)
    }
    fn run(&self, e: HookEvent, p: &Value) -> Result<HookDecision, String> {
        let (Some(text), Some(routes)) = (compaction_notice(e, p), ark_kernel::kernel::host_routes()) else { return Ok(HookDecision::Allow) };
        let Some(origin) = routes.origin(p["session_id"].as_str().unwrap_or("")) else { return Ok(HookDecision::Allow) };
        // Never hold up the compaction on a slow chat API.
        std::thread::spawn(move || {
            if let Err(e) = routes.deliver(&origin, &text) {
                eprintln!("ark: compaction-notifier: {e}");
            }
        });
        Ok(HookDecision::Allow)
    }
}

// ───────────────────────── session-memory ─────────────────────────

struct SessionMemory {
    cfg: SessionMemoryCfg,
    kernel: KernelSlot,
}

/// OpenClaw transcript rendering: `role: "<json-quoted text>"`, slash commands skipped, last `n`.
pub fn memory_transcript(messages: &[Message], n: usize) -> String {
    let lines: Vec<String> = messages
        .iter()
        .filter_map(|m| {
            let t = m.text();
            let t = t.trim();
            if t.is_empty() || t.starts_with('/') || m.content.iter().any(|b| matches!(b, ark_core::Block::ToolResult { .. })) {
                return None;
            }
            let role = if m.role == Role::User { "user" } else { "assistant" };
            Some(format!("{role}: {}", serde_json::to_string(t).unwrap_or_default().replace(['\u{85}', '\u{2028}', '\u{2029}'], " ")))
        })
        .collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

/// OpenClaw llm-slug-generator normalisation.
pub fn normalize_slug(text: &str) -> Option<String> {
    let s: String = text.trim().to_lowercase().chars().map(|c| if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' { c } else { '-' }).collect();
    let mut out = String::new();
    for c in s.chars() {
        if !(c == '-' && out.ends_with('-')) {
            out.push(c);
        }
    }
    let out: String = out.trim_matches('-').chars().take(30).collect();
    Some(out.trim_matches('-').to_string()).filter(|s| !s.is_empty())
}

fn llm_slug(k: &Kernel, model: &str, transcript: &str) -> Option<String> {
    let model = if model.contains('/') { model.to_string() } else { k.cfg.aux_model().to_string() };
    let (pid, m) = model.split_once('/')?;
    let p = k.resolver.provider(pid).ok()?;
    let prompt = format!("Based on this conversation, generate a short 1-2 word filename slug (lowercase, hyphen-separated, no file extension).\n\nConversation summary:\n{}\n\nReply with ONLY the slug, nothing else. Examples: \"vendor-pitch\", \"api-design\", \"bug-fix\"", transcript.chars().take(2000).collect::<String>());
    let req = ModelRequest { model: m.to_string(), system: vec![], messages: vec![Message::user(prompt)], tools: vec![], max_tokens: 32, temperature: None, cache_after_message: None, reasoning: None, options: Default::default() };
    let r = p.complete(&req, &mut |_| {}, &Cancel::new()).ok()?;
    normalize_slug(&r.message.text())
}

fn offset_label(min: i32) -> String {
    if min == 0 {
        return "UTC".into();
    }
    let sign = if min < 0 { '-' } else { '+' };
    format!("UTC{sign}{:02}:{:02}", min.abs() / 60, min.abs() % 60)
}

/// Write the memory file for a session ending with `reason`; returns its path.
pub fn save_session_memory(k: &Kernel, cfg: &SessionMemoryCfg, session: &str, reason: &str, now_secs: i64) -> Result<Option<PathBuf>, String> {
    let events = k.store.read(session).map_err(|e| e.to_string())?;
    let view = ark_kernel::projection::project(&events);
    if view.workspace.is_empty() {
        return Ok(None);
    }
    let title = events.iter().find_map(|e| match &e.kind {
        EventKind::Header { title, .. } => title.clone(),
        _ => None,
    });
    let transcript = memory_transcript(&view.messages, cfg.messages.max(1));
    let off = k.cfg.schedule.utc_offset_minutes;
    let stamp = ark_kernel::util::fmt_time(now_secs, off); // YYYY-MM-DD HH:MM
    let (date, hm) = stamp.split_once(' ').unwrap_or((&stamp, "00:00"));
    let secs = (now_secs + off as i64 * 60).rem_euclid(60);
    let slug = (cfg.llm_slug && !transcript.is_empty()).then(|| llm_slug(k, &cfg.model, &transcript)).flatten().unwrap_or_else(|| hm.replace(':', ""));
    let dir = PathBuf::from(&view.workspace).join("memory");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut n = 1;
    let path = loop {
        let f = if n == 1 { format!("{date}-{slug}.md") } else { format!("{date}-{slug}-{n}.md") };
        if !dir.join(&f).exists() {
            break dir.join(f);
        }
        n += 1;
    };
    let detail = if matches!(reason, "idle" | "daily") { format!("- **Reason**: {reason}") } else { format!("- **Source**: /{reason}") };
    let mut body = format!("# Session: {date} {hm}:{secs:02} {}\n\n- **Session Key**: {}\n- **Session ID**: {session}\n{detail}\n\n", offset_label(off), title.unwrap_or_else(|| session.to_string()));
    if !transcript.is_empty() {
        body.push_str(&format!("## Conversation Summary\n\n{transcript}\n"));
    }
    std::fs::write(&path, body).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Some(path))
}

impl Hook for SessionMemory {
    fn name(&self) -> String {
        "bundled:session-memory".into()
    }
    fn wants(&self, e: HookEvent, _: Option<&str>) -> bool {
        e == HookEvent::SessionEnd
    }
    fn run(&self, _: HookEvent, p: &Value) -> Result<HookDecision, String> {
        let reason = p["reason"].as_str().unwrap_or("");
        if !matches!(reason, "new" | "reset" | "idle" | "daily") {
            return Ok(HookDecision::Allow);
        }
        let Some(k) = self.kernel.get() else { return Ok(HookDecision::Allow) };
        // Capture now (the session may be replaced right after); slugging can be slow.
        let (k, cfg, sid, reason) = (k.clone(), self.cfg.clone(), p["session_id"].as_str().unwrap_or("").to_string(), reason.to_string());
        let job = move || match save_session_memory(&k, &cfg, &sid, &reason, ark_kernel::util::unix_now()) {
            Ok(Some(path)) => eprintln!("ark: session-memory: saved {}", path.display()),
            Ok(None) => {}
            Err(e) => eprintln!("ark: session-memory: {e}"),
        };
        if self.cfg.llm_slug {
            std::thread::spawn(job);
        } else {
            job();
        }
        Ok(HookDecision::Allow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = ark_core::tmp::scratch_path(format!("ark-hb-{tag}-{}", ark_kernel::util::random_hex(8)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn globs_match_like_openclaw_patterns() {
        let r = glob_regex("packages/*/AGENTS.md").unwrap();
        assert!(r.is_match("packages/api/AGENTS.md") && !r.is_match("packages/a/b/AGENTS.md"));
        let r = glob_regex("team/{core,api}/**/AGENTS.md").unwrap();
        assert!(r.is_match("team/core/AGENTS.md") && r.is_match("team/api/x/y/AGENTS.md") && !r.is_match("team/web/AGENTS.md"));
        assert!(glob_regex("team[1]/SOUL.md").unwrap().is_match("team1/SOUL.md"));
    }

    #[test]
    fn extra_bootstrap_files_stay_inside_and_use_known_names() {
        let ws = tmp("boot");
        std::fs::create_dir_all(ws.join("packages/api")).unwrap();
        std::fs::create_dir_all(ws.join("packages/web")).unwrap();
        std::fs::write(ws.join("packages/api/AGENTS.md"), "api rules").unwrap();
        std::fs::write(ws.join("packages/web/AGENTS.md"), "web rules").unwrap();
        std::fs::write(ws.join("packages/web/README.md"), "no").unwrap();
        let outside = tmp("outside");
        std::fs::write(outside.join("AGENTS.md"), "secret").unwrap();
        std::os::unix::fs::symlink(outside.join("AGENTS.md"), ws.join("packages/link-AGENTS.md")).unwrap();
        std::fs::create_dir_all(ws.join("evil")).unwrap();
        std::os::unix::fs::symlink(outside.join("AGENTS.md"), ws.join("evil/AGENTS.md")).unwrap();
        let pats = vec!["packages/*/AGENTS.md".into(), "packages/web/README.md".into(), "../x/AGENTS.md".into(), "evil/AGENTS.md".into()];
        let (files, diag) = extra_bootstrap_files(&ws, &pats);
        assert_eq!(files.iter().map(|f| f.0.as_str()).collect::<Vec<_>>(), ["packages/api/AGENTS.md", "packages/web/AGENTS.md"]);
        assert!(diag.iter().any(|d| d.contains("unsupported bootstrap basename")));
        assert!(diag.iter().any(|d| d.starts_with("../x") && d.contains("outside")));
        assert!(diag.iter().any(|d| d.starts_with("evil/") && d.contains("outside")), "{diag:?}");
        let h = BootstrapExtraFiles { patterns: pats };
        let HookDecision::Context(c) = h.run(HookEvent::SessionStart, &json!({"cwd": ws})).unwrap() else { panic!() };
        assert!(c.contains("## packages/api/AGENTS.md\n\napi rules") && !c.contains("secret"));
    }

    #[test]
    fn command_logger_appends_json_lines() {
        let d = tmp("cmdlog");
        let h = CommandLogger { path: d.join("logs/commands.log") };
        h.run(HookEvent::Command, &json!({"action": "new", "session_id": "s1", "sender_id": "+886", "source": "telegram", "timestamp": "2026-01-16T14:30:00Z"})).unwrap();
        h.run(HookEvent::Command, &json!({"action": "stop", "session_id": ""})).unwrap();
        let lines: Vec<Value> = std::fs::read_to_string(d.join("logs/commands.log")).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines[0], json!({"timestamp": "2026-01-16T14:30:00Z", "action": "new", "sessionKey": "s1", "senderId": "+886", "source": "telegram"}));
        assert_eq!((lines[1]["senderId"].as_str(), lines[1]["source"].as_str()), (Some("unknown"), Some("unknown")));
    }

    #[test]
    fn compaction_notices_and_boot_prompt() {
        assert_eq!(compaction_notice(HookEvent::PreCompact, &json!({"messages": 42})).unwrap(), "🧹 Compacting context (42 messages) so I can continue without losing history…");
        assert_eq!(compaction_notice(HookEvent::PostCompact, &json!({"tokens_before": 9000, "tokens_after": 1200})).unwrap(), "✅ Context compacted (9000 → 1200 tokens). Continuing from where I left off.");
        assert_eq!(compaction_notice(HookEvent::PostCompact, &json!({})).unwrap(), "✅ Context compacted. Continuing from where I left off.");
        let ws = tmp("bootmd");
        assert_eq!(load_boot_file(&ws).unwrap(), None);
        std::fs::write(ws.join("BOOT.md"), "  \n").unwrap();
        assert_eq!(load_boot_file(&ws).unwrap(), None, "empty");
        std::fs::write(ws.join("BOOT.md"), "Check the disk.\n").unwrap();
        let c = load_boot_file(&ws).unwrap().unwrap();
        let p = boot_prompt(&c);
        assert!(p.starts_with("You are running a boot check.") && p.contains("BOOT.md:\nCheck the disk.") && p.ends_with("Run the workspace boot check now."));
    }

    #[test]
    fn transcript_and_slug_normalisation() {
        let msgs = vec![Message::user("/new"), Message::user("deploy \"api\"\nplease"), Message::assistant("done"), Message::user("thanks")];
        assert_eq!(memory_transcript(&msgs, 15), "user: \"deploy \\\"api\\\"\\nplease\"\nassistant: \"done\"\nuser: \"thanks\"");
        assert_eq!(memory_transcript(&msgs, 1), "user: \"thanks\"");
        assert_eq!(normalize_slug(" \"Vendor Pitch!\" ").as_deref(), Some("vendor-pitch"));
        assert_eq!(normalize_slug("---").as_deref(), None);
        assert_eq!(offset_label(480), "UTC+08:00");
        assert_eq!(offset_label(-330), "UTC-05:30");
    }
}
