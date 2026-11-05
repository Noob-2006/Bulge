//! memory_search / memory_get (OpenClaw memory-core tools, MIT) and personal_instructions
//! (OpenClaw personal-instructions-tool.ts): per-sender USER.md for multi-user channels.

use crate::index::SKIP_DIRS;
use crate::util::{self, sha256_hex};
use crate::{events, recall, Host};
use seagent_core::tool::{arg_opt_str, arg_opt_u64};
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

pub const DEFAULT_READ_LINES: usize = 120;
pub const DEFAULT_READ_MAX_CHARS: usize = 12_000;

fn out(v: Value, is_error: bool) -> ToolOutput {
    let s = serde_json::to_string_pretty(&v).unwrap_or_default();
    if is_error {
        ToolOutput::err(s)
    } else {
        ToolOutput::ok(s)
    }
}

fn num(input: &Value, keys: &[&str]) -> Option<f64> {
    keys.iter().find_map(|k| input.get(*k).and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))))
}

pub struct MemorySearch(pub Arc<Host>);

impl Tool for MemorySearch {
    fn spec(&self) -> ToolSpec {
        let sessions = self.0.settings.search.sources.iter().any(|s| s == "sessions");
        let files = "MEMORY.md, USER.md, DREAMS.md and Markdown notes under the memory directory";
        ToolSpec {
            name: "memory_search".into(),
            description: format!("Semantically search {files}{} when an answer depends on prior work, decisions, dates, people, preferences, or todos not already present in the current turn. Do not repeat memory retrieval when supplied context fully answers the question. Results carry `citation` (path#Lstart-Lend); use memory_get to pull only the needed lines. corpus=memory restricts to memory files, corpus=sessions to session transcripts, corpus=wiki/all adds the compiled wiki. If low confidence after search, say you checked.", if sessions { " and indexed session transcripts" } else { "" }),
            input_schema: json!({"type":"object","properties":{
                "query":{"type":"string"},
                "maxResults":{"type":"integer","minimum":1},
                "minScore":{"type":"number"},
                "corpus":{"type":"string","enum":["memory","wiki","all","sessions"]}},"required":["query"]}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![Effect::Read { path: self.0.memory_dir() }]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let h = &self.0;
        let Some(query) = arg_opt_str(&input, "query").or(arg_opt_str(&input, "q")).map(str::trim).filter(|q| !q.is_empty()) else {
            return ToolOutput::err("memory_search needs `query`");
        };
        let max = num(&input, &["maxResults", "max_results", "limit"]).map(|n| n.max(1.0) as usize).unwrap_or(h.settings.search.max_results);
        let min = num(&input, &["minScore", "min_score"]).map(|n| n.clamp(0.0, 1.0)).unwrap_or(h.settings.search.min_score);
        let corpus = arg_opt_str(&input, "corpus").unwrap_or("");
        if !["", "memory", "wiki", "all", "sessions"].contains(&corpus) {
            return ToolOutput::err("corpus must be one of: memory, wiki, all, sessions");
        }
        if corpus == "sessions" && !h.settings.search.sources.iter().any(|s| s == "sessions") {
            return out(json!({"results": [], "disabled": true, "error": "Session transcript search is not enabled.", "warning": "Session transcript search is unavailable for this agent.", "action": "Ask the operator to add \"sessions\" to [memory.search] sources."}), false);
        }
        let citations = h.settings.search.citations != "off";
        let mut results = Vec::new();
        let mut meta = json!({});
        if corpus != "wiki" {
            let sources: Vec<&str> = match corpus {
                "memory" => vec!["memory"],
                "sessions" => vec!["sessions"],
                _ => vec![],
            };
            // srv-037: a session only retrieves its own tenant's knowledge.
            let viewer = h.session_viewer(&ctx.session_id);
            match h.search_as(query, max, min, &sources, viewer.as_ref()) {
                Ok(o) => {
                    let mut st = recall::Store::load(&h.data);
                    let (rec, skip) = st.record_hits(query, &o.hits, util::now_ms(), h.utc_offset_minutes);
                    if rec > 0 {
                        let _ = st.save(&h.data);
                    }
                    let _ = events::record(&h.data, "memory.recall.recorded", json!({"query": query, "resultCount": o.hits.len(), "skippedResultCount": skip, "results": o.hits.iter().map(|x| json!({"path": x.path, "startLine": x.start_line, "endLine": x.end_line, "score": x.score})).collect::<Vec<_>>()}));
                    for x in &o.hits {
                        let mut r = json!({"path": x.path, "startLine": x.start_line, "endLine": x.end_line, "score": (x.score * 1000.0).round() / 1000.0, "snippet": x.snippet, "source": x.source});
                        if citations {
                            r["citation"] = json!(x.citation());
                        }
                        results.push(r);
                    }
                    meta = json!({"provider": o.provider, "mode": o.mode});
                    if !o.warnings.is_empty() {
                        meta["warning"] = json!(o.warnings.join(" "));
                    }
                }
                Err(e) => return out(json!({"results": [], "disabled": true, "error": e, "warning": "Memory search is unavailable; tell the user recall may be incomplete."}), false),
            }
        }
        if corpus == "wiki" || corpus == "all" {
            for w in crate::wiki::search(h, query, max) {
                results.push(json!({"path": w.path, "title": w.title, "score": w.score, "snippet": w.snippet, "source": "wiki", "citation": format!("wiki:{}", w.path)}));
            }
            results.sort_by(|a, b| b["score"].as_f64().partial_cmp(&a["score"].as_f64()).unwrap());
            results.truncate(max);
        }
        meta["results"] = Value::Array(results);
        out(meta, false)
    }
}

/// Resolve a memory-file path: relative to the memory dir, `.md` only, never into
/// staging/index/… or outside; absolute paths only inside configured extra paths.
pub fn resolve_memory_path(h: &Host, raw: &str) -> Result<(String, PathBuf), String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("path required".into());
    }
    if raw.starts_with("sessions/") {
        return Err("session transcript paths are unsupported; use session_search for session hits".into());
    }
    let rel = raw.trim_start_matches("./").trim_start_matches("memory/");
    let p = Path::new(rel);
    if p.is_absolute() {
        let abs = PathBuf::from(rel);
        let allowed = h.settings.search.extra_paths.iter().map(|e| seagent_core::tool::expand_home(e)).any(|e| abs == e || (abs.starts_with(&e) && e.is_dir()));
        if allowed && rel.ends_with(".md") && !abs.components().any(|c| c == Component::ParentDir) {
            return Ok((rel.to_string(), abs));
        }
        return Err("path is not an allowed Markdown memory file".into());
    }
    if p.components().any(|c| !matches!(c, Component::Normal(_))) || !rel.ends_with(".md") {
        return Err("path is not an allowed Markdown memory file".into());
    }
    if let Some(Component::Normal(first)) = p.components().next() {
        if p.components().count() > 1 && SKIP_DIRS.contains(&first.to_string_lossy().as_ref()) {
            return Err("path is not an allowed Markdown memory file".into());
        }
    }
    let abs = h.memory_dir().join(rel);
    if let Ok(meta) = fs::symlink_metadata(&abs) {
        if meta.file_type().is_symlink() {
            return Err("path is not an allowed Markdown memory file (symlink)".into());
        }
    }
    Ok((rel.to_string(), abs))
}

/// Bounded excerpt (OpenClaw read-file-shared.ts): 120 lines / 12 000 chars by default, with a
/// continuation notice carrying `nextFrom`.
pub fn excerpt(content: &str, path: &str, from: Option<usize>, lines: Option<usize>) -> Value {
    let mut all: Vec<&str> = content.split('\n').collect();
    if all.last() == Some(&"") {
        all.pop();
    }
    let start = from.unwrap_or(1).max(1);
    let count = lines.unwrap_or(DEFAULT_READ_LINES).max(1);
    let sel: Vec<&str> = all.iter().skip(start - 1).take(count).copied().collect();
    let more = start - 1 + sel.len() < all.len();
    let (mut chars, mut inc) = (0usize, 0usize);
    for l in &sel {
        let next = chars + l.chars().count() + usize::from(inc > 0);
        if inc > 0 && next > DEFAULT_READ_MAX_CHARS {
            break;
        }
        inc += 1;
        chars = next;
    }
    let hard = chars > DEFAULT_READ_MAX_CHARS;
    let mut text = util::clip(&sel[..inc].join("\n"), DEFAULT_READ_MAX_CHARS);
    let next_from = (!hard && (more || inc < sel.len())).then_some(start + inc);
    let truncated = hard || inc < sel.len() || more;
    if truncated {
        text.push_str(&match next_from {
            Some(n) => format!("\n\n[More content available. Use from={n} to continue.]"),
            None => "\n\n[More content available. Requested excerpt exceeded the default maxChars budget. If you need the full raw line, use read on the source file.]".into(),
        });
    }
    let mut v = json!({"status": "ok", "path": path, "text": text, "from": start, "lines": inc});
    if truncated {
        v["truncated"] = json!(true);
    }
    if let Some(n) = next_from {
        v["nextFrom"] = json!(n);
    }
    v
}

pub fn read_memory_file(h: &Host, path: &str, from: Option<usize>, lines: Option<usize>) -> Value {
    // `memories/<id>`: a long-term memory row (memory_search cites them like files).
    if let Some(id) = path.strip_prefix("memories/") {
        return match crate::memstore::get(&h.data, id).filter(|r| r.trust != crate::trust::QUARANTINED) {
            Some(r) => {
                let mut v = excerpt(&r.text, path, from, lines);
                v["source"] = json!(r.source);
                v["trust"] = json!(r.trust);
                v
            }
            None => json!({"status": "not_found", "path": path, "text": ""}),
        };
    }
    match resolve_memory_path(h, path) {
        Err(e) => json!({"status": "error", "path": path, "text": "", "code": "MEMORY_PATH_NOT_ALLOWED", "error": e}),
        Ok((rel, abs)) => match fs::read(&abs) {
            Ok(b) => match String::from_utf8(b) {
                Ok(t) => excerpt(&t, &rel, from, lines),
                Err(_) => json!({"status": "error", "path": rel, "text": "", "code": "MEMORY_READ_FAILED", "error": "file is not valid UTF-8"}),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => json!({"status": "not_found", "path": rel, "text": ""}),
            Err(e) if e.kind() == std::io::ErrorKind::IsADirectory => json!({"status": "error", "path": rel, "text": "", "code": "MEMORY_READ_FAILED", "error": "path must be a regular file"}),
            Err(e) => json!({"status": "error", "path": rel, "text": "", "code": "MEMORY_READ_FAILED", "error": e.to_string()}),
        },
    }
}

pub struct MemoryGet(pub Arc<Host>);

impl Tool for MemoryGet {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "memory_get".into(),
            description: "Safe exact excerpt read from MEMORY.md, USER.md, DREAMS.md and Markdown notes under the memory directory (paths as memory_search returns them). Session transcript paths are unsupported. Defaults to a bounded excerpt (120 lines) and includes truncation/continuation info (`nextFrom`) when more content exists. corpus=wiki reads compiled-wiki pages. status=ok means the excerpt was read; not_found means the file is missing; error means the read failed.".into(),
            input_schema: json!({"type":"object","properties":{
                "path":{"type":"string"},
                "from":{"type":"integer","minimum":1},
                "lines":{"type":"integer","minimum":1},
                "corpus":{"type":"string","enum":["memory","wiki","all"]}},"required":["path"]}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, _: &ToolCtx, input: &Value) -> Vec<Effect> {
        let p = arg_opt_str(input, "path").and_then(|p| resolve_memory_path(&self.0, p).ok()).map(|(_, a)| a).unwrap_or_else(|| self.0.memory_dir());
        vec![Effect::Read { path: p }]
    }
    fn call(&self, _: &ToolCtx, input: Value) -> ToolOutput {
        let path = arg_opt_str(&input, "path").unwrap_or("");
        let from = arg_opt_u64(&input, "from").map(|n| n as usize);
        let lines = arg_opt_u64(&input, "lines").map(|n| n as usize);
        let corpus = arg_opt_str(&input, "corpus").unwrap_or("memory");
        if corpus == "wiki" || (corpus == "all" && path.starts_with("wiki:")) {
            return match crate::wiki::get(&self.0, path.trim_start_matches("wiki:"), from, lines) {
                Some(v) => out(v, false),
                None => out(json!({"status": "not_found", "path": path, "text": ""}), false),
            };
        }
        let v = read_memory_file(&self.0, path, from, lines);
        if corpus == "all" && v["status"] == "not_found" {
            if let Some(w) = crate::wiki::get(&self.0, path, from, lines) {
                return out(w, false);
            }
        }
        let err = v["status"] == "error";
        out(v, err)
    }
}

/// Who sent the current turn of `session` (a stable per-user identity), or None for local
/// / unauthenticated turns.
pub type SenderFn = Arc<dyn Fn(&ToolCtx) -> Option<String> + Send + Sync>;

/// Default sender: the latest inbox `source` of the session when it came from a channel
/// (`channel:<name>`), qualified by the session title's sender (`<channel> · <sender>`).
pub fn default_sender(data: PathBuf) -> SenderFn {
    Arc::new(move |ctx: &ToolCtx| {
        let log = fs::read_to_string(data.join("sessions").join(&ctx.session_id).join("events.jsonl")).ok()?;
        let mut source = None;
        let mut title = None;
        for l in log.lines() {
            let Ok(v) = serde_json::from_str::<Value>(l) else { continue };
            match v["type"].as_str() {
                Some("inbox") => source = v["source"].as_str().map(str::to_string),
                Some("header") => title = v["title"].as_str().map(str::to_string),
                Some("title") => title = v["title"].as_str().map(str::to_string).or(title),
                _ => {}
            }
        }
        let source = source?;
        if !(source.starts_with("channel:") || source.starts_with("a2a:")) {
            return None;
        }
        let who = title.as_deref().and_then(|t| t.split_once(" · ")).map(|(_, s)| s.trim().to_string()).filter(|s| !s.is_empty());
        Some(match who {
            Some(w) => format!("{source}:{w}"),
            None => format!("{source}:{}", ctx.session_id),
        })
    })
}

pub struct PersonalInstructions {
    host: Arc<Host>,
    sender: SenderFn,
}

impl PersonalInstructions {
    pub fn new(host: Arc<Host>) -> Self {
        let sender = default_sender(host.data.clone());
        PersonalInstructions { host, sender }
    }
    pub fn with_sender(host: Arc<Host>, sender: SenderFn) -> Self {
        PersonalInstructions { host, sender }
    }
    pub fn file_for(&self, sender: &str) -> PathBuf {
        let safe: String = sender.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' }).collect();
        self.host.memory_dir().join("users").join(format!("{}-{}", util::clip(&safe, 60), &sha256_hex(sender.as_bytes())[..8])).join("USER.md")
    }
}

impl Tool for PersonalInstructions {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "personal_instructions".into(),
            description: "On a multi-user channel, read or update the requesting user's personal USER.md (not the shared one). Use get first, preserve unrelated preferences, then set the complete content with expectedHash set to the returned hash (null only when missing). Limit 4,000 characters. Only update when the user asks. Requires a live user turn from a channel.".into(),
            input_schema: json!({"type":"object","properties":{
                "action":{"type":"string","enum":["get","set"]},
                "content":{"type":"string","maxLength":4000},
                "expectedHash":{"type":["string","null"],"pattern":"^[a-f0-9]{64}$"}},"required":["action"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let Some(s) = (self.sender)(ctx) else { return vec![] };
        let path = self.file_for(&s);
        if arg_opt_str(input, "action") == Some("set") {
            vec![Effect::Write { path }]
        } else {
            vec![Effect::Read { path }]
        }
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let Some(sender) = (self.sender)(ctx) else {
            return ToolOutput::err("Personal instructions require a live authenticated user turn (a channel message); the session owner's shared USER.md is the `memory` tool's file=user.");
        };
        let p = self.file_for(&sender);
        let cur = fs::read_to_string(&p).ok();
        let hash = cur.as_ref().map(|c| sha256_hex(c.as_bytes()));
        match arg_opt_str(&input, "action") {
            Some("get") => out(json!({"status": if cur.is_some() { "ok" } else { "missing" }, "content": cur.clone().unwrap_or_default(), "hash": hash}), false),
            Some("set") => {
                let Some(content) = arg_opt_str(&input, "content") else { return ToolOutput::err("Use get, or set with content and the hash returned by get.") };
                if content.chars().count() > 4000 {
                    return ToolOutput::err("personal instructions are limited to 4,000 characters");
                }
                let expected = input.get("expectedHash").and_then(Value::as_str).map(str::to_string);
                if input.get("expectedHash").is_none() || expected != hash {
                    return out(json!({"status": "conflict", "error": "Personal instructions changed since get (or expectedHash missing); call get again and merge.", "hash": hash}), true);
                }
                if let Err(e) = crate::util::write_atomic(&p, content.as_bytes()) {
                    return ToolOutput::err(e);
                }
                let _ = events::record(&self.host.data, "memory.write", json!({"action": "personal_instructions.set", "target": "personal", "chars": content.chars().count()}));
                out(json!({"status": "ok", "hash": sha256_hex(content.as_bytes())}), false)
            }
            _ => ToolOutput::err("Use get, or set with content and the hash returned by get."),
        }
    }
}

#[cfg(test)]
pub fn tests_ctx(home: &Path) -> ToolCtx {
    tests::ctx(home, "s")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use seagent_core::Cancel;

    pub fn ctx(home: &Path, session: &str) -> ToolCtx {
        struct H;
        impl seagent_core::ToolHost for H {
            fn spawn_agent(&self, _: seagent_core::tool::SpawnRequest, _: &Cancel) -> Result<String, String> {
                Err("no".into())
            }
            fn ask_user(&self, _: &str) -> Result<String, String> {
                Err("no".into())
            }
        }
        ToolCtx { workspace: home.to_path_buf(), session_id: session.into(), artifacts: home.join("a"), home: home.to_path_buf(), cancel: Cancel::new(), host: Arc::new(H), secrets: Arc::new(|s: &str| s.to_string()) }
    }

    #[test]
    fn search_records_recall_and_get_reads_bounded() {
        // Sessions are a default corpus now (srv-059); this test covers the opt-out.
        let h = crate::test_host("tools", |s| s.search.sources = vec!["memory".into()]);
        fs::create_dir_all(h.memory_dir().join("daily")).unwrap();
        let note: String = (1..=200).map(|i| format!("line {i}: the deploy key rotates monthly")).collect::<Vec<_>>().join("\n");
        fs::write(h.memory_dir().join("daily/2026-11-01.md"), &note).unwrap();
        let c = ctx(&h.data, "s");
        let o = MemorySearch(h.clone()).call(&c, json!({"query":"deploy key rotation","limit":2}));
        assert!(!o.is_error, "{}", o.content);
        let v: Value = serde_json::from_str(&o.content).unwrap();
        assert_eq!(v["mode"], "fts-only");
        assert!(v["results"].as_array().unwrap().len() <= 2);
        assert!(v["results"][0]["citation"].as_str().unwrap().starts_with("daily/2026-11-01.md#L"));
        assert!(!recall::Store::load(&h.data).entries.is_empty(), "short-term recall recorded");
        assert_eq!(events::list(&h.data, &["memory.recall.recorded"], None, 9).len(), 1);
        assert!(MemorySearch(h.clone()).call(&c, json!({"query":"x","corpus":"bogus"})).is_error);
        let v: Value = serde_json::from_str(&MemorySearch(h.clone()).call(&c, json!({"query":"x","corpus":"sessions"})).content).unwrap();
        assert_eq!(v["disabled"], true);
        let g = MemoryGet(h.clone());
        let v: Value = serde_json::from_str(&g.call(&c, json!({"path":"daily/2026-11-01.md"})).content).unwrap();
        assert_eq!((v["lines"].as_u64(), v["nextFrom"].as_u64()), (Some(120), Some(121)));
        assert!(v["text"].as_str().unwrap().ends_with("[More content available. Use from=121 to continue.]"));
        let v: Value = serde_json::from_str(&g.call(&c, json!({"path":"memory/daily/2026-11-01.md","from":199,"lines":5})).content).unwrap();
        assert_eq!(v["lines"], 2);
        assert!(v.get("truncated").is_none());
        for bad in ["../secrets.md", "staging/x.md", "/etc/passwd", "MEMORY.txt", "sessions/abc"] {
            assert!(g.call(&c, json!({"path": bad})).is_error, "{bad}");
        }
        let v: Value = serde_json::from_str(&g.call(&c, json!({"path":"nope.md"})).content).unwrap();
        assert_eq!(v["status"], "not_found");
    }

    #[test]
    fn personal_instructions_per_sender_with_hash() {
        let h = crate::test_host("pi", |_| {});
        let who = Arc::new(std::sync::Mutex::new(Some("telegram:alice".to_string())));
        let w2 = who.clone();
        let t = PersonalInstructions::with_sender(h.clone(), Arc::new(move |_| w2.lock().unwrap().clone()));
        let c = ctx(&h.data, "s");
        let v: Value = serde_json::from_str(&t.call(&c, json!({"action":"get"})).content).unwrap();
        assert_eq!((v["status"].as_str(), v["hash"].is_null()), (Some("missing"), true));
        assert!(t.call(&c, json!({"action":"set","content":"x"})).is_error, "expectedHash required");
        let o = t.call(&c, json!({"action":"set","content":"call me Al","expectedHash":null}));
        assert!(!o.is_error, "{}", o.content);
        let v: Value = serde_json::from_str(&t.call(&c, json!({"action":"get"})).content).unwrap();
        assert_eq!(v["content"], "call me Al");
        assert!(t.call(&c, json!({"action":"set","content":"y","expectedHash":"0".repeat(64)})).is_error);
        *who.lock().unwrap() = Some("telegram:bob".into());
        let v: Value = serde_json::from_str(&t.call(&c, json!({"action":"get"})).content).unwrap();
        assert_eq!(v["status"], "missing", "bob does not see alice's file");
        *who.lock().unwrap() = None;
        assert!(t.call(&c, json!({"action":"get"})).content.contains("live authenticated"));
        // Default sender reads the session log.
        let sd = h.data.join("sessions/s1");
        fs::create_dir_all(&sd).unwrap();
        fs::write(sd.join("events.jsonl"), "{\"type\":\"header\",\"title\":\"telegram · Carol\"}\n{\"type\":\"inbox\",\"source\":\"channel:telegram\",\"id\":\"1\",\"text\":\"hi\"}\n").unwrap();
        assert_eq!(default_sender(h.data.clone())(&ctx(&h.data, "s1")), Some("channel:telegram:Carol".into()));
        fs::write(sd.join("events.jsonl"), "{\"type\":\"inbox\",\"source\":\"cli\"}\n").unwrap();
        assert_eq!(default_sender(h.data.clone())(&ctx(&h.data, "s1")), None);
    }
}
