//! RetainDB memory provider (Hermes plugins/memory/retaindb, MIT): REST client, durable
//! write-behind queue (JSONL instead of SQLite, replayed on the next sync), context overlay
//! + dialectic + agent self-model prefetch, and the 10 retaindb_* tools.

use crate::manager::Provider;
use crate::util::{self, clip, resolve_value, Resp};
use crate::Host;
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const DEFAULT_BASE_URL: &str = "https://api.retaindb.com";
const TEXT_EXTS: &[&str] = &[".txt", ".md", ".json", ".csv", ".yaml", ".yml", ".xml", ".html"];

fn q(s: &str) -> String {
    crate::sigv4::uri_encode(s, false)
}

pub struct RetainDb {
    pub base_url: String,
    pub api_key: String,
    pub project: String,
    pub user_id: String,
    pub agent_id: String,
    queue: PathBuf,
    qlock: Mutex<()>,
}

impl RetainDb {
    pub fn new(h: &Host) -> Result<RetainDb, String> {
        let s = &h.settings.retaindb;
        let api_key = resolve_value(&h.subst, &s.api_key, &["RETAINDB_API_KEY"]);
        if api_key.is_empty() {
            return Err("RETAINDB_API_KEY is not set ([memory.retaindb] api_key)".into());
        }
        let base = resolve_value(&h.subst, &s.base_url, &["RETAINDB_BASE_URL"]);
        let project = resolve_value(&h.subst, &s.project, &["RETAINDB_PROJECT"]);
        Ok(RetainDb {
            base_url: if base.is_empty() { DEFAULT_BASE_URL.into() } else { base.trim_end_matches('/').to_string() },
            api_key,
            project: if project.is_empty() { "default".into() } else { project },
            user_id: s.user_id.clone(),
            agent_id: s.agent_id.clone(),
            queue: h.memory_dir().join("retaindb/queue.jsonl"),
            qlock: Mutex::new(()),
        })
    }

    fn headers(&self, path: &str, json_body: bool) -> Vec<(String, String)> {
        let tok = self.api_key.trim_start_matches("Bearer ").trim().to_string();
        let mut h = vec![("Authorization".to_string(), format!("Bearer {tok}")), ("x-sdk-runtime".to_string(), "seagent-plugin".to_string())];
        if json_body {
            h.push(("Content-Type".into(), "application/json".into()));
        }
        if path.starts_with("/v1/memory") || path.starts_with("/v1/context") {
            h.push(("X-API-Key".into(), tok));
        }
        h
    }

    fn raw(&self, method: &str, path: &str, body: Option<Vec<u8>>, extra: Vec<(String, String)>, timeout: f64) -> Result<Resp, String> {
        let mut h = self.headers(path, false);
        h.extend(extra);
        util::http(method, &format!("{}{path}", self.base_url), &h, body.as_deref(), Duration::from_secs_f64(timeout))
    }

    /// JSON request; non-2xx → `RetainDB <METHOD> <path> failed (<status>): <message>`.
    pub fn request(&self, method: &str, path: &str, params: &[(&str, String)], body: Option<Value>, timeout: f64) -> Result<Value, String> {
        let qs = params.iter().map(|(k, v)| format!("{k}={}", q(v))).collect::<Vec<_>>().join("&");
        let full = if qs.is_empty() { path.to_string() } else { format!("{path}?{qs}") };
        let send = !matches!(method, "GET" | "DELETE");
        let data = if send { Some(serde_json::to_vec(&body.unwrap_or(json!({}))).unwrap_or_default()) } else { None };
        let r = util::http(method, &format!("{}{full}", self.base_url), &self.headers(path, send), data.as_deref(), Duration::from_secs_f64(timeout))?;
        let payload = r.json().unwrap_or_else(|_| Value::String(r.text()));
        if !r.ok() {
            let msg = payload.get("message").or(payload.get("error")).and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| payload.to_string());
            return Err(format!("RetainDB {method} {path} failed ({}): {msg}", r.status));
        }
        Ok(payload)
    }

    fn fallback(&self, a: Result<Value, String>, b: impl FnOnce() -> Result<Value, String>) -> Result<Value, String> {
        a.or_else(|_| b())
    }
    fn scoped(&self, session: &str, extra: Value) -> Value {
        let mut v = json!({"project": self.project, "user_id": self.user_id, "session_id": session});
        if let (Some(o), Some(e)) = (v.as_object_mut(), extra.as_object()) {
            o.extend(e.clone());
        }
        v
    }

    pub fn query_context(&self, session: &str, query: &str) -> Result<Value, String> {
        self.request("POST", "/v1/context/query", &[], Some(self.scoped(session, json!({"query": query, "include_memories": true, "max_tokens": 1200}))), 8.0)
    }
    pub fn search(&self, session: &str, query: &str, top_k: u64) -> Result<Value, String> {
        self.request("POST", "/v1/memory/search", &[], Some(self.scoped(session, json!({"query": query, "top_k": top_k, "include_pending": true}))), 8.0)
    }
    pub fn profile(&self) -> Result<Value, String> {
        let a = self.request("GET", &format!("/v1/memory/profile/{}", q(&self.user_id)), &[("project", self.project.clone()), ("include_pending", "true".into())], None, 8.0);
        self.fallback(a, || self.request("GET", "/v1/memories", &[("project", self.project.clone()), ("user_id", self.user_id.clone()), ("limit", "200".into())], None, 8.0))
    }
    pub fn add_memory(&self, session: &str, content: &str, kind: &str, importance: f64) -> Result<Value, String> {
        let body = self.scoped(session, json!({"content": content, "memory_type": kind, "importance": importance}));
        let mut sync = body.clone();
        sync["write_mode"] = json!("sync");
        let a = self.request("POST", "/v1/memory", &[], Some(sync), 5.0);
        self.fallback(a, || self.request("POST", "/v1/memories", &[], Some(body), 5.0))
    }
    pub fn delete_memory(&self, id: &str) -> Result<Value, String> {
        let a = self.request("DELETE", &format!("/v1/memory/{}", q(id)), &[], None, 5.0);
        self.fallback(a, || self.request("DELETE", &format!("/v1/memories/{}", q(id)), &[], None, 5.0))
    }
    pub fn ingest_session(&self, session: &str, messages: &Value) -> Result<Value, String> {
        self.request("POST", "/v1/memory/ingest/session", &[], Some(self.scoped(session, json!({"messages": messages, "write_mode": "sync"}))), 15.0)
    }
    pub fn ask_user(&self, query: &str) -> Result<Value, String> {
        let level = if query.len() < 120 { "low" } else if query.len() < 400 { "medium" } else { "high" };
        self.request("POST", &format!("/v1/memory/profile/{}/ask", q(&self.user_id)), &[], Some(json!({"project": self.project, "query": query, "reasoning_level": level})), 8.0)
    }
    pub fn agent_model(&self) -> Result<Value, String> {
        self.request("GET", &format!("/v1/memory/agent/{}/model", q(&self.agent_id)), &[("project", self.project.clone())], None, 4.0)
    }

    pub fn upload_file(&self, data: &[u8], filename: &str, remote: &str, mime: &str, scope: &str) -> Result<Value, String> {
        let boundary = format!("seagent{}", &util::sha256_hex(data)[..16]);
        let mut body = Vec::new();
        for (k, v) in [("path", remote), ("scope", &scope.to_uppercase())] {
            body.extend(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n").as_bytes());
        }
        body.extend(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\nContent-Type: {mime}\r\n\r\n", filename.replace('"', "")).as_bytes());
        body.extend(data);
        body.extend(format!("\r\n--{boundary}--\r\n").as_bytes());
        let r = self.raw("POST", "/v1/files", Some(body), vec![("Content-Type".into(), format!("multipart/form-data; boundary={boundary}"))], 30.0)?;
        if !r.ok() {
            return Err(format!("RetainDB POST /v1/files failed ({}): {}", r.status, clip(&r.text(), 300)));
        }
        r.json()
    }

    /// Queue a turn for ingest, then replay every pending row (failed rows stay queued).
    pub fn enqueue_and_flush(&self, session: &str, messages: Value) {
        let _g = self.qlock.lock().unwrap();
        let _ = util::append_line(&self.queue, &json!({"session": session, "messages": messages, "created": util::iso(util::now_ms())}).to_string());
        let pending = std::fs::read_to_string(&self.queue).unwrap_or_default();
        let mut keep = Vec::new();
        for l in pending.lines().filter(|l| !l.trim().is_empty()) {
            let Ok(v) = serde_json::from_str::<Value>(l) else { continue };
            if let Err(e) = self.ingest_session(v["session"].as_str().unwrap_or(""), &v["messages"]) {
                eprintln!("seagent: RetainDB ingest failed (will retry): {e}");
                keep.push(l.to_string());
            }
        }
        let _ = util::write_atomic(&self.queue, if keep.is_empty() { String::new() } else { format!("{}\n", keep.join("\n")) }.as_bytes());
    }

    pub fn pending(&self) -> usize {
        std::fs::read_to_string(&self.queue).map(|t| t.lines().filter(|l| !l.trim().is_empty()).count()).unwrap_or(0)
    }

    fn overlay(&self, session: &str, query: &str) -> Result<Value, String> {
        let qr = self.query_context(session, query)?;
        let prof = self.profile().unwrap_or(json!({}));
        Ok(json!({"context": build_overlay(&prof, &qr), "raw": qr}))
    }

    fn dispatch(&self, session: &str, tool: &str, a: &Value) -> Result<Value, String> {
        let req = |k: &str| a[k].as_str().filter(|s| !s.is_empty()).map(str::to_string).ok_or_else(|| format!("{k} is required"));
        match tool {
            "retaindb_profile" => self.profile(),
            "retaindb_search" => self.search(session, &req("query")?, a["top_k"].as_u64().unwrap_or(8).min(20)),
            "retaindb_context" => self.overlay(session, &req("query")?),
            "retaindb_remember" => self.add_memory(session, &req("content")?, a["memory_type"].as_str().unwrap_or("factual"), a["importance"].as_f64().unwrap_or(0.7)),
            "retaindb_forget" => self.delete_memory(&req("memory_id")?),
            "retaindb_upload_file" => {
                let lp = PathBuf::from(req("local_path")?);
                let data = std::fs::read(&lp).map_err(|_| format!("File not found: {}", lp.display()))?;
                let name = lp.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                let mime = if TEXT_EXTS.iter().any(|e| name.ends_with(e)) { "text/plain" } else { "application/octet-stream" };
                let mut r = self.upload_file(&data, &name, a["remote_path"].as_str().unwrap_or(&format!("/{name}")), mime, a["scope"].as_str().unwrap_or("PROJECT"))?;
                if a["ingest"].as_bool() == Some(true) {
                    if let Some(id) = r["file"]["id"].as_str().map(str::to_string) {
                        r["ingest"] = self.ingest_file(&id)?;
                    }
                }
                Ok(r)
            }
            "retaindb_list_files" => {
                let mut p = vec![("limit", a["limit"].as_u64().unwrap_or(50).to_string())];
                if let Some(pre) = a["prefix"].as_str() {
                    p.push(("prefix", pre.to_string()));
                }
                self.request("GET", "/v1/files", &p, None, 8.0)
            }
            "retaindb_read_file" => {
                let id = req("file_id")?;
                let info = self.request("GET", &format!("/v1/files/{}", q(&id)), &[], None, 8.0)?["file"].clone();
                let out = json!({"file_id": id, "rdb_uri": info["rdb_uri"], "name": info["name"]});
                let name = info["name"].as_str().unwrap_or("");
                if !(info["mime_type"].as_str().unwrap_or("").to_lowercase().starts_with("text/") || TEXT_EXTS.iter().any(|e| name.ends_with(e))) {
                    let mut o = out;
                    o["content"] = Value::Null;
                    o["note"] = json!("Binary file — use retaindb_ingest_file to extract text into memory.");
                    return Ok(o);
                }
                let r = self.raw("GET", &format!("/v1/files/{}/content", q(&id)), None, vec![], 30.0)?;
                if !r.ok() {
                    return Err(format!("RetainDB GET /v1/files/{id}/content failed ({})", r.status));
                }
                let text = r.text();
                let mut o = out;
                o["content"] = json!(clip(&text, 32_000));
                o["truncated"] = json!(text.chars().count() > 32_000);
                Ok(o)
            }
            "retaindb_ingest_file" => self.ingest_file(&req("file_id")?),
            "retaindb_delete_file" => self.request("DELETE", &format!("/v1/files/{}", q(&req("file_id")?)), &[], None, 5.0),
            other => Err(format!("Unknown tool: {other}")),
        }
    }
    fn ingest_file(&self, id: &str) -> Result<Value, String> {
        self.request("POST", &format!("/v1/files/{}/ingest", q(id)), &[], Some(json!({"user_id": self.user_id, "agent_id": self.agent_id})), 60.0)
    }
}

fn compact(s: &str) -> String {
    clip(&util::compact_ws(s), 320)
}

/// `[RetainDB Context]` overlay: 5 profile + 5 query memories, deduped.
pub fn build_overlay(profile: &Value, query: &Value) -> String {
    let norm = |s: &str| compact(s).to_lowercase().chars().filter(|c| c.is_ascii_alphanumeric() || *c == ' ').collect::<String>();
    let mut seen = std::collections::HashSet::new();
    let mut take = |items: &Value| -> Vec<String> {
        items.as_array().map(|a| a.iter().take(5).filter_map(|m| m["content"].as_str().map(compact)).filter(|c| !c.is_empty() && seen.insert(norm(c))).collect()).unwrap_or_default()
    };
    let p = take(&profile["memories"]);
    let r = take(&query["results"]);
    if p.is_empty() && r.is_empty() {
        return String::new();
    }
    let list = |v: &[String]| if v.is_empty() { vec!["- None".to_string()] } else { v.iter().map(|i| format!("- {i}")).collect() };
    [vec!["[RetainDB Context]".to_string(), "Profile:".into()], list(&p), vec!["Relevant memories:".into()], list(&r)].concat().join("\n")
}

impl Provider for RetainDb {
    fn name(&self) -> String {
        "retaindb".into()
    }
    fn prefetch(&self, session: &str, query: &str) -> Option<String> {
        let ctx = self.overlay(session, query).ok().and_then(|v| v["context"].as_str().map(str::to_string)).unwrap_or_default();
        let dia = self.ask_user(query).ok().and_then(|v| v["answer"].as_str().map(str::to_string)).filter(|s| !s.is_empty()).map(|a| format!("[RetainDB User Synthesis]\n{a}"));
        let model = self.agent_model().ok().filter(|m| m["memory_count"].as_u64().unwrap_or(0) > 0).map(|m| {
            let mut lines = Vec::new();
            if let Some(p) = m["persona"].as_str() {
                lines.push(format!("Persona: {p}"));
            }
            if let Some(i) = m["persistent_instructions"].as_array() {
                lines.push(format!("Instructions:\n{}", i.iter().filter_map(Value::as_str).map(|s| format!("- {s}")).collect::<Vec<_>>().join("\n")));
            }
            if let Some(w) = m["working_style"].as_str() {
                lines.push(format!("Working style: {w}"));
            }
            format!("[RetainDB Agent Self-Model]\n{}", lines.join("\n"))
        });
        let parts: Vec<String> = [Some(ctx).filter(|s| !s.is_empty()), dia, model].into_iter().flatten().collect();
        (!parts.is_empty()).then(|| parts.join("\n\n"))
    }
    fn sync_turn(&self, session: &str, user: &str, assistant: &str) {
        if user.is_empty() {
            return;
        }
        let now = util::iso(util::now_ms());
        self.enqueue_and_flush(session, json!([{"role": "user", "content": user, "timestamp": now}, {"role": "assistant", "content": assistant, "timestamp": now}]));
    }
    fn on_memory_write(&self, action: &str, target: &str, content: &str) {
        if action == "add" && !content.is_empty() {
            let _ = self.add_memory("", content, if target == "user" { "preference" } else { "factual" }, 0.7);
        }
    }
}

const TOOLS: &[(&str, &str)] = &[
    ("retaindb_profile", "Get the user's stable profile — preferences, facts, and patterns recalled from long-term memory."),
    ("retaindb_search", "Semantic search across stored memories. Returns ranked results with relevance scores."),
    ("retaindb_context", "Synthesized context block — what matters most for the current task, pulled from long-term memory."),
    ("retaindb_remember", "Persist an explicit fact, preference, or decision to long-term memory."),
    ("retaindb_forget", "Delete a specific memory by ID."),
    ("retaindb_upload_file", "Upload a file to the shared RetainDB file store. Returns an rdb:// URI any agent can reference."),
    ("retaindb_list_files", "List files in the shared file store."),
    ("retaindb_read_file", "Read the text content of a stored file by its file ID."),
    ("retaindb_ingest_file", "Chunk, embed, and extract memories from a stored file. Makes its contents searchable."),
    ("retaindb_delete_file", "Delete a stored file."),
];

fn schema(name: &str) -> Value {
    let s = |d: &str| json!({"type":"string","description":d});
    let (props, req): (Value, Vec<&str>) = match name {
        "retaindb_search" => (json!({"query": s("What to search for."), "top_k": {"type":"integer","description":"Max results (default: 8, max: 20)."}}), vec!["query"]),
        "retaindb_context" => (json!({"query": s("Current task or question.")}), vec!["query"]),
        "retaindb_remember" => (json!({"content": s("The fact to remember."), "memory_type": {"type":"string","enum":["factual","preference","goal","instruction","event","opinion"],"description":"Category (default: factual)."}, "importance": {"type":"number","description":"Importance 0-1 (default: 0.7)."}}), vec!["content"]),
        "retaindb_forget" => (json!({"memory_id": s("Memory ID to delete.")}), vec!["memory_id"]),
        "retaindb_upload_file" => (json!({"local_path": s("Local file path to upload."), "remote_path": s("Destination path, e.g. /reports/q1.pdf"), "scope": {"type":"string","enum":["USER","PROJECT","ORG"],"description":"Access scope (default: PROJECT)."}, "ingest": {"type":"boolean","description":"Also extract memories from file after upload (default: false)."}}), vec!["local_path"]),
        "retaindb_list_files" => (json!({"prefix": s("Path prefix to filter by, e.g. /reports/"), "limit": {"type":"integer","description":"Max results (default: 50)."}}), vec![]),
        "retaindb_read_file" | "retaindb_ingest_file" => (json!({"file_id": s("File ID returned from upload or list.")}), vec!["file_id"]),
        "retaindb_delete_file" => (json!({"file_id": s("File ID to delete.")}), vec!["file_id"]),
        _ => (json!({}), vec![]),
    };
    json!({"type":"object","properties":props,"required":req})
}

pub fn tools(r: &Arc<RetainDb>) -> Vec<Arc<dyn Tool>> {
    TOOLS.iter().map(|(n, d)| Arc::new(RetainTool(r.clone(), n, d)) as Arc<dyn Tool>).collect()
}

pub struct RetainTool(pub Arc<RetainDb>, pub &'static str, pub &'static str);

impl Tool for RetainTool {
    fn spec(&self) -> ToolSpec {
        let ro = matches!(self.1, "retaindb_profile" | "retaindb_search" | "retaindb_context" | "retaindb_list_files" | "retaindb_read_file");
        ToolSpec { name: self.1.into(), description: self.2.into(), input_schema: schema(self.1), parallel_safe: ro, idempotent: ro, pinned: false }
    }
    fn effects(&self, _: &ToolCtx, input: &Value) -> Vec<Effect> {
        let mut v = vec![Effect::Net { dest: self.0.base_url.clone(), payload: input.to_string() }];
        if let Some(p) = input["local_path"].as_str() {
            v.push(Effect::Read { path: PathBuf::from(p) });
        }
        v
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        match self.0.dispatch(&ctx.session_id, self.1, &input) {
            Ok(v) => ToolOutput::ok(v.to_string()),
            Err(e) => ToolOutput::err(json!({"error": e}).to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::testutil::fake;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn client_tools_queue_and_prefetch() {
        let down = Arc::new(AtomicBool::new(true));
        let d2 = down.clone();
        let f = fake(move |r, _| {
            let p = r.path.split('?').next().unwrap_or("");
            match (r.method.as_str(), p) {
                ("POST", "/v1/memory/ingest/session") if d2.load(Ordering::SeqCst) => (503, r#"{"message":"down"}"#.into()),
                ("POST", "/v1/context/query") => (200, json!({"results": [{"content": "Prefers dark mode"}, {"content": "prefers   dark mode"}]}).to_string()),
                ("GET", "/v1/memory/profile/default") => (404, r#"{"error":"gone"}"#.into()),
                ("GET", "/v1/memories") => (200, json!({"memories": [{"content": "Lives in Taipei"}]}).to_string()),
                ("POST", "/v1/memory/profile/default/ask") => (200, json!({"answer": "A night owl."}).to_string()),
                ("GET", "/v1/memory/agent/seagent/model") => (200, json!({"memory_count": 1, "persona": "Calm", "persistent_instructions": ["be brief"]}).to_string()),
                ("POST", "/v1/files") => (200, json!({"file": {"id": "f1"}}).to_string()),
                ("GET", "/v1/files/f1") => (200, json!({"file": {"name": "a.md", "rdb_uri": "rdb://a"}}).to_string()),
                ("GET", "/v1/files/f1/content") => (200, "hello file".into()),
                ("DELETE", "/v1/memory/m1") => (500, "{}".into()),
                _ => (200, json!({"ok": true, "path": p}).to_string()),
            }
        });
        let h = crate::test_host("rdb", |s| { s.retaindb.api_key = "rk-test".into(); s.retaindb.base_url = f.url.clone(); });
        let r = Arc::new(RetainDb::new(&h).unwrap());
        assert_eq!(r.project, "default");
        let pf = r.prefetch("s", "what theme do I like").unwrap();
        assert!(pf.contains("[RetainDB Context]\nProfile:\n- Lives in Taipei\nRelevant memories:\n- Prefers dark mode") && !pf.contains("prefers   dark"), "{pf}");
        assert!(pf.contains("[RetainDB User Synthesis]\nA night owl.") && pf.contains("Instructions:\n- be brief"));
        r.sync_turn("s", "hi there", "hello");
        assert_eq!(r.pending(), 1, "failed ingest stays queued");
        down.store(false, Ordering::SeqCst);
        r.sync_turn("s", "second", "ok");
        assert_eq!(r.pending(), 0, "queue replayed");
        let c = crate::tools::tests_ctx(&h.data);
        let t = tools(&r);
        assert_eq!(t.len(), 10);
        let by = |n: &str| t.iter().find(|x| x.spec().name == n).unwrap().clone();
        assert!(by("retaindb_remember").call(&c, json!({"content":"x"})).content.contains("/v1/memory"));
        assert!(by("retaindb_forget").call(&c, json!({"memory_id":"m1"})).content.contains("/v1/memories/m1"), "legacy fallback route");
        assert!(by("retaindb_search").call(&c, json!({})).is_error);
        let lp = h.data.join("a.md");
        std::fs::write(&lp, "hello").unwrap();
        assert!(by("retaindb_upload_file").call(&c, json!({"local_path": lp, "ingest": true})).content.contains("f1"));
        assert!(by("retaindb_read_file").call(&c, json!({"file_id":"f1"})).content.contains("hello file"));
        let reqs = f.reqs.lock().unwrap().clone();
        let up = reqs.iter().find(|x| x.path == "/v1/files" && x.method == "POST").unwrap();
        assert!(up.header("content-type").unwrap().starts_with("multipart/form-data; boundary="));
        assert!(String::from_utf8_lossy(&up.body).contains("filename=\"a.md\""));
        let ctxq = reqs.iter().find(|x| x.path == "/v1/context/query").unwrap();
        assert_eq!(ctxq.header("x-api-key").unwrap(), "rk-test");
        assert_eq!(ctxq.header("authorization").unwrap(), "Bearer rk-test");
        assert_eq!(ctxq.json()["project"], "default");
        assert!(reqs.iter().any(|x| x.path.starts_with("/v1/files/f1/ingest")));
    }
}
