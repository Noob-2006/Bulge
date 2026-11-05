//! Session Share (OpenClaw `extensions/session-share`, MIT): teammates read selected ark
//! conversations on another host through a paired node. Read-only by construction.
//!
//! ```toml
//! [integrations.session_share]
//! enabled = true            # receiver: offer the `session_share` tool
//! groups = ["team"]         # source: share sessions whose group (session meta) is listed
//! ```
//!
//! Source side: a node running on the sharing host offers two node commands,
//! `ark.sessions.list.v1` `{cursor?, limit?, searchTerm?}` and `ark.sessions.read.v1`
//! `{threadId, cursor?, limit?}`, served from the local session store. Only sessions whose
//! group is listed in `groups` and that are not sub-agent / spawned / archived are visible,
//! and transcripts carry user and assistant text only (≤ 6000 chars per item, `truncated`
//! flag) — no tool calls or results, no local identities. Receiver side: the
//! `session_share` tool (action `list` | `read`) invokes those commands on a paired node and
//! validates every page against the wire vocabulary before returning it.

use ark_core::{Block, Effect, Role, Tool, ToolCtx, ToolOutput, ToolSpec};
use ark_kernel::config::{project_config, Config, Paths};
use ark_kernel::event::EventKind;
use ark_kernel::projection::project;
use ark_kernel::store::Store;
use serde_json::{json, Map, Value};
use std::time::Duration;

pub const LIST: &str = "ark.sessions.list.v1";
pub const READ: &str = "ark.sessions.read.v1";
pub const COMMANDS: &[&str] = &[LIST, READ];
const TEXT_MAX: usize = 6000;
const PAGE_MAX: usize = 100;
const PAGE_DEFAULT: usize = 50;
const RESPONSE_MAX: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ShareConfig {
    pub enabled: bool,
    pub groups: Vec<String>,
}

impl ShareConfig {
    pub fn parse(cfg: &Config) -> ShareConfig {
        let t = cfg.integrations.get("session_share").and_then(|v| v.as_table());
        let Some(t) = t else { return ShareConfig::default() };
        ShareConfig {
            enabled: t.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false),
            groups: t.get("groups").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|g| g.as_str()).filter(|g| !g.is_empty()).map(String::from).collect()).unwrap_or_default(),
        }
    }
}

/// The local host's sharing config (the node process reads the user's config).
fn local_groups() -> Vec<String> {
    let paths = Paths::from_env();
    let ws = std::env::current_dir().unwrap_or_default();
    Config::load(Some(&paths.user_config()), Some(&project_config(&ws)), &[]).map(|c| ShareConfig::parse(&c).groups).unwrap_or_default()
}

/// Node commands this host offers (none unless groups are configured).
pub fn node_commands() -> Vec<&'static str> {
    if local_groups().is_empty() { vec![] } else { COMMANDS.to_vec() }
}

pub fn handles(command: &str) -> bool {
    COMMANDS.contains(&command)
}

/// Node-host entry: serve `command` from the local store.
pub fn node_run(command: &str, p: &Value) -> Result<Value, String> {
    let paths = Paths::from_env();
    serve(&Store::new(paths.sessions()), &local_groups(), command, p)
}

fn cursor_decode(c: Option<&Value>) -> Result<usize, String> {
    match c {
        None | Some(Value::Null) => Ok(0),
        Some(Value::String(s)) if !s.is_empty() && s.len() <= 2048 && s.starts_with('o') && s[1..].chars().all(|c| c.is_ascii_digit()) => s[1..].parse().map_err(|_| "invalid cursor".into()),
        _ => Err("invalid cursor".into()),
    }
}
fn cursor_encode(off: usize) -> String {
    format!("o{off}")
}
fn is_cursor(s: &str) -> bool {
    !s.is_empty() && s.len() <= 2048 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn params(p: &Value, allowed: &[&str], not_object: &str, unknown: &str) -> Result<Map<String, Value>, String> {
    let m = match p {
        Value::Null => Map::new(),
        Value::Object(m) => m.clone(),
        _ => return Err(not_object.into()),
    };
    if let Some(k) = m.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(format!("{unknown}: {k}"));
    }
    Ok(m)
}

fn limit(m: &Map<String, Value>) -> Result<usize, String> {
    match m.get("limit") {
        None | Some(Value::Null) => Ok(PAGE_DEFAULT),
        Some(v) => v.as_u64().filter(|n| (1..=PAGE_MAX as u64).contains(n)).map(|n| n as usize).ok_or_else(|| format!("limit must be an integer between 1 and {PAGE_MAX}")),
    }
}

struct Shared {
    id: String,
    name: Option<String>,
    cwd: String,
    created: u64,
    updated: u64,
}

fn shared(store: &Store, groups: &[String]) -> Vec<Shared> {
    if groups.is_empty() {
        return vec![];
    }
    store.list().into_iter().filter(|s| s.parent.is_none()).filter_map(|s| {
        let v = project(&store.read(&s.id).ok()?);
        let ok = v.group.as_ref().is_some_and(|g| groups.contains(g)) && !v.archived && v.parent.is_none();
        ok.then(|| Shared { id: s.id, name: v.title.or(s.title), cwd: s.workspace, created: s.created_ms, updated: s.updated_ms })
    }).collect()
}

fn clip(s: &str) -> (String, bool) {
    if s.chars().count() > TEXT_MAX {
        (s.chars().take(TEXT_MAX).collect(), true)
    } else {
        (s.to_string(), false)
    }
}

/// Serve one page (testable without a node).
pub fn serve(store: &Store, groups: &[String], command: &str, p: &Value) -> Result<Value, String> {
    match command {
        LIST => {
            let m = params(p, &["cursor", "limit", "searchTerm"], "Session list parameters must be an object", "Unknown session list parameter")?;
            let off = cursor_decode(m.get("cursor"))?;
            let lim = limit(&m)?;
            let search = match m.get("searchTerm") {
                None | Some(Value::Null) => None,
                Some(Value::String(s)) if !s.trim().is_empty() && s.chars().count() <= 500 => Some(s.to_lowercase()),
                _ => return Err("searchTerm must be a non-empty string of at most 500 characters".into()),
            };
            let mut all: Vec<Shared> = shared(store, groups).into_iter().filter(|s| search.as_ref().is_none_or(|q| s.id.to_lowercase().contains(q) || s.name.as_deref().is_some_and(|n| n.to_lowercase().contains(q)))).collect();
            all.sort_by(|a, b| b.updated.cmp(&a.updated).then(a.id.cmp(&b.id)));
            let page: Vec<Value> = all.iter().skip(off).take(lim).map(|s| {
                let mut o = json!({"threadId": s.id, "cwd": clip(&s.cwd).0, "status": "idle", "createdAt": s.created, "updatedAt": s.updated, "recencyAt": s.updated, "archived": false, "canContinue": false, "canArchive": false, "canOpenTerminal": false});
                if let Some(n) = &s.name {
                    o["name"] = json!(clip(n).0);
                }
                o
            }).collect();
            let mut out = json!({"sessions": page});
            if off + lim < all.len() {
                out["nextCursor"] = json!(cursor_encode(off + lim));
            }
            Ok(out)
        }
        READ => {
            let m = params(p, &["threadId", "cursor", "limit"], "Session read parameters must be an object", "Unknown session read parameter")?;
            let tid = m.get("threadId").and_then(Value::as_str).filter(|t| !t.is_empty() && t.len() <= 512).ok_or("threadId must be a non-empty session key of at most 512 characters")?;
            // Not shared and not existing look the same: nothing leaks about private sessions.
            if !shared(store, groups).iter().any(|s| s.id == tid) {
                return Err(format!("Unknown shared session: {tid}"));
            }
            let off = cursor_decode(m.get("cursor"))?;
            let lim = limit(&m)?;
            let events = store.read(tid).map_err(|e| e.to_string())?;
            let mut items = vec![];
            let mut model = String::new();
            for e in &events {
                match &e.kind {
                    EventKind::Model { model: m } => model = m.clone(),
                    EventKind::Header { .. } if model.is_empty() => model = project(std::slice::from_ref(e)).model,
                    EventKind::Message { message, model: mm, .. } => {
                        let t: String = message.content.iter().filter_map(|b| if let Block::Text { text } = b { Some(text.as_str()) } else { None }).collect::<Vec<_>>().join("\n");
                        if t.trim().is_empty() {
                            continue;
                        }
                        let (text, truncated) = clip(&t);
                        let mut it = json!({"type": if message.role == Role::User { "userMessage" } else { "agentMessage" }, "id": format!("{}", e.seq), "text": text, "timestamp": ark_kernel::util::fmt_time((e.ts / 1000) as i64, 0)});
                        if truncated {
                            it["truncated"] = json!(true);
                        }
                        if message.role == Role::Assistant {
                            let md = mm.clone().filter(|m| !m.is_empty()).unwrap_or_else(|| model.clone());
                            if !md.is_empty() {
                                it["model"] = json!(md);
                            }
                        }
                        items.push(it);
                    }
                    _ => {}
                }
            }
            let total = items.len();
            let page: Vec<Value> = items.into_iter().skip(off).take(lim).collect();
            let mut out = json!({"threadId": tid, "items": page});
            if off + lim < total {
                out["nextCursor"] = json!(cursor_encode(off + lim));
            }
            Ok(out)
        }
        _ => Err(format!("unknown session-share command {command}")),
    }
}

fn unwrap_payload(v: Value) -> Result<Value, String> {
    if let Some(s) = v.get("payloadJSON").and_then(Value::as_str) {
        if s.len() > RESPONSE_MAX {
            return Err("Session catalog response exceeded the page limit".into());
        }
        return serde_json::from_str(s).map_err(|e| e.to_string());
    }
    Ok(v)
}

const ITEM_TYPES: &[&str] = &["userMessage", "agentMessage", "reasoning", "toolCall", "toolResult", "other"];

/// Receiver validation (upstream `parseSessionSharePage`): reject anything off-vocabulary.
pub fn parse_session_page(raw: Value) -> Result<Value, String> {
    let v = unwrap_payload(raw)?;
    let bad = || "Invalid ark session page from paired node".to_string();
    let o = v.as_object().ok_or_else(bad)?;
    if o.keys().any(|k| k != "sessions" && k != "nextCursor") || o.get("nextCursor").is_some_and(|c| !c.as_str().is_some_and(is_cursor)) {
        return Err(bad());
    }
    let ss = o.get("sessions").and_then(Value::as_array).filter(|a| a.len() <= PAGE_MAX).ok_or_else(bad)?;
    const KEYS: &[&str] = &["threadId", "name", "color", "cwd", "status", "createdAt", "updatedAt", "recencyAt", "gitBranch", "archived", "createdActor", "canContinue", "canArchive", "canOpenTerminal"];
    for s in ss {
        let so = s.as_object().ok_or_else(bad)?;
        let tid_ok = so.get("threadId").and_then(Value::as_str).is_some_and(|t| !t.is_empty() && t.len() <= 512);
        let status_ok = so.get("status").and_then(Value::as_str).is_some_and(|s| matches!(s, "live" | "idle" | "archived"));
        let ro = so.get("canContinue") == Some(&json!(false)) && so.get("canArchive") == Some(&json!(false)) && so.get("canOpenTerminal").is_none_or(|v| v == &json!(false));
        if !tid_ok || !status_ok || !ro || !so.get("archived").is_some_and(Value::is_boolean) || so.keys().any(|k| !KEYS.contains(&k.as_str())) {
            return Err(bad());
        }
    }
    Ok(v)
}

/// Receiver validation (upstream `parseSessionShareTranscriptPage`).
pub fn parse_transcript_page(raw: Value, thread: &str) -> Result<Value, String> {
    let v = unwrap_payload(raw)?;
    let bad = || "Invalid ark transcript page from paired node".to_string();
    let o = v.as_object().ok_or_else(bad)?;
    if o.get("threadId").and_then(Value::as_str) != Some(thread) || o.keys().any(|k| !matches!(k.as_str(), "threadId" | "items" | "nextCursor")) || o.get("nextCursor").is_some_and(|c| !c.as_str().is_some_and(is_cursor)) {
        return Err(bad());
    }
    let items = o.get("items").and_then(Value::as_array).filter(|a| a.len() <= PAGE_MAX).ok_or_else(bad)?;
    for it in items {
        let io = it.as_object().ok_or_else(bad)?;
        let ty_ok = io.get("type").and_then(Value::as_str).is_some_and(|t| ITEM_TYPES.contains(&t));
        let text_ok = io.get("text").is_none_or(|t| t.as_str().is_some_and(|s| s.chars().count() <= TEXT_MAX));
        if !ty_ok || !text_ok || io.keys().any(|k| !matches!(k.as_str(), "type" | "id" | "text" | "timestamp" | "model" | "sender" | "truncated")) {
            return Err(bad());
        }
    }
    Ok(v)
}

/// The receiver tool.
pub struct SessionShareTool;

impl Tool for SessionShareTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "session_share".into(),
            description: "Browse read-only ark sessions shared by a paired host (Session Share). action=list {node, searchTerm?, cursor?, limit?} lists shared sessions; action=read {node, threadId, cursor?, limit?} returns user/assistant text of one session. Shared sessions cannot be continued or changed.".into(),
            input_schema: json!({"type": "object", "properties": {"action": {"type": "string", "enum": ["list", "read"]}, "node": {"type": "string", "description": "Paired node id serving the shared sessions."}, "threadId": {"type": "string"}, "searchTerm": {"type": "string"}, "cursor": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}, "required": ["action", "node"]}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, _: &ToolCtx, input: Value) -> ToolOutput {
        let node = input["node"].as_str().unwrap_or("");
        let mut p = Map::new();
        for k in ["cursor", "limit", "searchTerm", "threadId"] {
            if let Some(v) = input.get(k).filter(|v| !v.is_null()) {
                p.insert(k.into(), v.clone());
            }
        }
        let r = match input["action"].as_str() {
            Some("list") => {
                p.remove("threadId");
                crate::node::invoke(node, LIST, Value::Object(p), Duration::from_secs(30), None).and_then(parse_session_page)
            }
            Some("read") => {
                p.remove("searchTerm");
                let t = input["threadId"].as_str().unwrap_or("").to_string();
                crate::node::invoke(node, READ, Value::Object(p), Duration::from_secs(30), None).and_then(|v| parse_transcript_page(v, &t))
            }
            _ => Err("action must be list or read".into()),
        };
        match r {
            Ok(v) => ToolOutput::ok(serde_json::to_string_pretty(&v).unwrap_or_default()),
            Err(e) => ToolOutput::err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_core::Message;
    use ark_kernel::event::EventKind;

    fn session(store: &Store, title: &str, group: Option<&str>, parent: Option<&str>) -> String {
        let mut log = store.create(EventKind::Header { version: 1, session_id: format!("s{}", ark_kernel::util::random_hex(8)), workspace: "/w".into(), model: "p/m".into(), parent: parent.map(String::from), title: None }).unwrap();
        log.append(EventKind::Title { title: title.into() }).unwrap();
        if let Some(g) = group {
            log.append(EventKind::Meta { pinned: None, archived: None, group: Some(g.into()), status: None }).unwrap();
        }
        log.append(EventKind::Message { message: Message::user("question"), usage: None, model: None, inbox: None }).unwrap();
        log.append(EventKind::Message { message: Message::assistant("x".repeat(7000)), usage: None, model: Some("p/m".into()), inbox: None }).unwrap();
        log.id.clone()
    }

    #[test]
    fn only_shared_groups_text_only_paging_and_validation() {
        let root = std::env::temp_dir().join(format!("ark-share-{}", ark_kernel::util::random_hex(6)));
        let store = Store::new(root.join("sessions"));
        let a = session(&store, "team plan", Some("team"), None);
        let _private = session(&store, "secret", None, None);
        let _other = session(&store, "other group", Some("solo"), None);
        let _kid = session(&store, "kid", Some("team"), Some(&a));
        let g = vec!["team".to_string()];
        let l = serve(&store, &g, LIST, &json!({})).unwrap();
        let ss = l["sessions"].as_array().unwrap();
        assert_eq!(ss.len(), 1, "{l}");
        assert_eq!(ss[0]["threadId"], a.as_str());
        assert_eq!(ss[0]["canContinue"], false);
        assert!(parse_session_page(l.clone()).is_ok());
        assert!(serve(&store, &[], LIST, &json!({})).unwrap()["sessions"].as_array().unwrap().is_empty(), "nothing shared without groups");
        assert!(serve(&store, &g, LIST, &json!({"bogus": 1})).unwrap_err().contains("Unknown session list parameter: bogus"));
        assert_eq!(serve(&store, &g, LIST, &json!({"searchTerm": "nomatch"})).unwrap()["sessions"], json!([]));
        let r = serve(&store, &g, READ, &json!({"threadId": a, "limit": 1})).unwrap();
        assert_eq!(r["items"][0]["type"], "userMessage");
        assert_eq!(r["nextCursor"], "o1");
        let r2 = serve(&store, &g, READ, &json!({"threadId": a, "cursor": "o1"})).unwrap();
        assert_eq!(r2["items"][0]["type"], "agentMessage");
        assert_eq!(r2["items"][0]["truncated"], true);
        assert_eq!(r2["items"][0]["text"].as_str().unwrap().len(), 6000);
        assert!(parse_transcript_page(r2.clone(), &a).is_ok());
        assert!(parse_transcript_page(r2, "someone-else").is_err(), "thread id must match");
        assert!(serve(&store, &g, READ, &json!({"threadId": _private})).unwrap_err().contains("Unknown shared session"));
        assert!(parse_session_page(json!({"sessions": [{"threadId": "x", "status": "idle", "archived": false, "canContinue": true, "canArchive": false}]})).is_err(), "writable sessions rejected");
        assert!(parse_session_page(json!({"payloadJSON": serde_json::to_string(&l).unwrap()})).is_ok());
        let cfg: Config = toml::from_str("[integrations.session_share]\nenabled = true\ngroups = [\"team\"]\n").unwrap();
        assert_eq!(ShareConfig::parse(&cfg), ShareConfig { enabled: true, groups: g });
        let _ = std::fs::remove_dir_all(&root);
    }
}
