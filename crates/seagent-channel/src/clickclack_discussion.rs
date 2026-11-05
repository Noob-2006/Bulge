//! ClickClack session discussions (OpenClaw `extensions/clickclack/src/discussions`, MIT).
//!
//! A discussion is a managed public ClickClack channel bound to one seagent session, where
//! people talk about the work while the agent runs. The `discussion` tool (named
//! `discussion_<channel>` for a channel not called `clickclack`):
//! - `read` (default, upstream's only action): the latest `limit` messages (1–200, default
//!   30) of the bound channel, roots and thread replies merged by time, as one
//!   `timestamp=… [Author "…" id="…"] text="…"` record per line. The scan is bounded like
//!   upstream (8 root pages of 200, 24 thread fetches); hitting a bound appends a note.
//! - `open`: create (or adopt, by `external_ref`) the managed channel for this session —
//!   upstream's session-discussion provider "open" — and bind it.
//! - `close`: archive the channel and drop the binding (upstream retention/revocation).
//!
//! Bindings live next to the channel's cursor file (`<state>.discussions.json`), keyed by
//! session id; a binding whose channel was archived or deleted reads as unbound.

use super::{enc, s, Core};
use crate::http::Payload;
use crate::ChannelError;
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;

const DEFAULT_LIMIT: u64 = 30;
const MAX_LIMIT: u64 = 200;
const PAGE_LIMIT: usize = 200;
const ROOT_PAGE_LIMIT: usize = 8;
const THREAD_REQUEST_LIMIT: usize = 24;
const SECTION: &str = "Agent discussions";
const NOT_BOUND: &str = "No discussion is bound to this session.";

pub(super) struct DiscussionTool {
    name: String,
    core: Arc<Core>,
}

pub(super) fn tool(core: &Arc<Core>) -> Arc<dyn Tool> {
    let safe: String = core.id.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' }).collect();
    let name = if safe == "clickclack" { "discussion".to_string() } else { format!("discussion_{safe}") };
    Arc::new(DiscussionTool { name, core: core.clone() })
}

fn bindings_path(core: &Core) -> PathBuf {
    let mut p = core.state.clone().into_os_string();
    p.push(".discussions.json");
    PathBuf::from(p)
}

fn load(core: &Core) -> Value {
    std::fs::read_to_string(bindings_path(core)).ok().and_then(|t| serde_json::from_str(&t).ok()).filter(Value::is_object).unwrap_or_else(|| json!({}))
}

fn save(core: &Core, v: &Value) -> Result<(), String> {
    let p = bindings_path(core);
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    crate::write_atomic(&p, serde_json::to_string_pretty(v).unwrap_or_default().as_bytes()).map_err(|e| format!("cannot save discussion bindings: {e}"))
}

/// Same digest as upstream's naming helpers (sha256 of the session key, hex).
fn session_hash(session: &str) -> String {
    seagent_net::crypto::sha256(session.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

fn external_ref(session: &str) -> String {
    format!("seagent-discussion:{}", &session_hash(session)[..32])
}

/// Upstream `slugifyLabel`: lowercase ASCII words joined by `-`, at most 80 chars.
fn slugify(label: &str) -> String {
    let mut out = String::new();
    for c in label.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let t: String = out.trim_matches('-').chars().take(80).collect();
    t.trim_end_matches('-').to_string()
}

fn channel_name(label: &str, session: &str) -> String {
    let slug = slugify(label);
    if slug.is_empty() {
        format!("s-{}", &session_hash(session)[..8])
    } else {
        slug
    }
}

/// JSON-escape plus Unicode line separators so one record stays one line.
fn record_json(v: &str) -> String {
    Value::String(v.to_string()).to_string().replace('\u{0085}', "\\u0085").replace('\u{2028}', "\\u2028").replace('\u{2029}', "\\u2029")
}

fn order(a: &Value, b: &Value) -> std::cmp::Ordering {
    (s(&a["created_at"]), s(&a["id"])).cmp(&(s(&b["created_at"]), s(&b["id"])))
}

fn keep_latest(mut v: Vec<Value>, limit: usize) -> Vec<Value> {
    v.sort_by(order);
    v.dedup_by(|a, b| a["id"] == b["id"] && !s(&a["id"]).is_empty());
    let n = v.len();
    v.split_off(n.saturating_sub(limit))
}

/// Upstream `latestChannelMessages`: root pages newest-first, threads of roots whose last
/// reply may fall inside the window; incomplete threads and exhausted budgets set `truncated`.
fn latest_messages(core: &Core, channel: &str, limit: usize) -> Result<(Vec<Value>, bool), ChannelError> {
    let limit = limit.clamp(1, PAGE_LIMIT);
    let mut before: Option<i64> = None;
    let mut latest: Vec<Value> = Vec::new();
    let (mut pages, mut threads, mut truncated) = (0, 0, false);
    loop {
        pages += 1;
        let mut q = format!("limit={PAGE_LIMIT}");
        if let Some(b) = before {
            q.push_str(&format!("&before_seq={b}"));
        }
        let page = core.api("GET", &format!("/api/channels/{}/messages?{q}", enc(channel)), Payload::None)?;
        let roots = page["messages"].as_array().cloned().unwrap_or_default();
        for root in &roots {
            latest = keep_latest([latest, vec![root.clone()]].concat(), limit);
            let replies = root["thread_state"]["reply_count"].as_u64().unwrap_or(0);
            let last = s(&root["thread_state"]["last_reply_at"]);
            let cutoff = (latest.len() == limit).then(|| s(&latest[0]["created_at"]));
            if replies == 0 || (!last.is_empty() && cutoff.as_ref().is_some_and(|c| last < *c)) {
                continue;
            }
            if threads >= THREAD_REQUEST_LIMIT {
                truncated = true;
                continue;
            }
            threads += 1;
            let t = core.api("GET", &format!("/api/messages/{}/thread?limit={PAGE_LIMIT}", enc(&s(&root["id"]))), Payload::None)?;
            let rs = t["replies"].as_array().cloned().unwrap_or_default();
            if (rs.len() as u64) < replies {
                truncated = true;
                continue;
            }
            latest = keep_latest([latest, rs].concat(), limit);
        }
        if !page["has_older"].as_bool().unwrap_or(false) {
            return Ok((latest, truncated));
        }
        if pages >= ROOT_PAGE_LIMIT {
            return Ok((latest, true));
        }
        let oldest = page["oldest_seq"].as_i64();
        match oldest {
            Some(o) if !roots.is_empty() && o >= 0 && Some(o) != before => before = Some(o),
            _ => return Err(ChannelError::new(crate::ChannelErrorKind::Protocol, "ClickClack message pagination did not advance")),
        }
    }
}

fn format_history(msgs: &[Value], truncated: bool) -> String {
    let text: Vec<String> = msgs
        .iter()
        .map(|m| {
            let a = &m["author"];
            let author = [s(&a["display_name"]), s(&a["handle"]), s(&m["author_id"])].into_iter().find(|x| !x.is_empty()).unwrap_or_else(|| "Unknown".into());
            format!("timestamp={} [Author {} id={}] text={}", record_json(&s(&m["created_at"])), record_json(&author), record_json(&s(&m["author_id"])), record_json(&s(&m["body"])))
        })
        .collect();
    let text = text.join("\n");
    if text.is_empty() {
        return text;
    }
    if truncated {
        format!("{text}\n[History scan reached its safety bound; older active threads may be omitted.]")
    } else {
        text
    }
}

/// The bound channel when it still exists and is not archived.
fn active_binding(core: &Core, session: &str) -> Result<Option<Value>, ChannelError> {
    let all = load(core);
    let Some(b) = all.get(session).cloned() else { return Ok(None) };
    match core.api("GET", &format!("/api/channels/{}", enc(&s(&b["channel_id"]))), Payload::None) {
        Ok(v) => {
            let ch = if v["channel"].is_object() { &v["channel"] } else { &v };
            let ours = s(&ch["external_ref"]) == s(&b["external_ref"]);
            Ok((ours && !ch["archived"].as_bool().unwrap_or(false) && ch["archived_at"].is_null()).then_some(b))
        }
        Err(e) if e.kind == crate::ChannelErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// The `limit` input: any integer clamps to 1..=200 (negative included), else the default
/// (upstream `register.ts` 159-165: `Math.max(1, Math.min(MAX, requested))` when integer).
fn limit_arg(input: &Value) -> u64 {
    match input.get("limit") {
        Some(Value::Number(n)) => match n.as_i64() {
            Some(l) => l.clamp(1, MAX_LIMIT as i64) as u64,
            None => n.as_u64().map(|l| l.clamp(1, MAX_LIMIT)).unwrap_or(DEFAULT_LIMIT),
        },
        _ => DEFAULT_LIMIT,
    }
}

fn read(core: &Core, session: &str, input: &Value) -> Result<(String, Value), String> {
    let limit = limit_arg(input);
    let Some(b) = active_binding(core, session).map_err(|e| e.to_string())? else {
        return Ok((NOT_BOUND.into(), json!({"bound": false, "limit": limit})));
    };
    let ch = s(&b["channel_id"]);
    let (msgs, truncated) = latest_messages(core, &ch, limit as usize).map_err(|e| e.to_string())?;
    let text = format_history(&msgs, truncated);
    Ok((if text.is_empty() { "The bound discussion has no messages yet.".into() } else { text }, json!({"bound": true, "limit": limit, "channelId": ch})))
}

fn open(core: &Core, session: &str, input: &Value) -> Result<(String, Value), String> {
    if let Some(b) = active_binding(core, session).map_err(|e| e.to_string())? {
        return Ok((format!("This session's discussion is #{} ({}).", s(&b["name"]), s(&b["channel_id"])), json!({"bound": true, "channelId": b["channel_id"], "created": false})));
    }
    let ident = core.ident().map_err(|e| e.to_string())?;
    let ws = ident.workspace;
    let label = input.get("title").and_then(Value::as_str).map(str::trim).filter(|t| !t.is_empty()).unwrap_or("");
    let display: String = (if label.is_empty() { format!("seagent session {session}") } else { label.to_string() }).chars().take(200).collect::<String>().trim().to_string();
    let xref = external_ref(session);
    let list = core.api("GET", &format!("/api/workspaces/{}/channels", enc(&ws)), Payload::None).map_err(|e| e.to_string())?;
    let channels = list["channels"].as_array().cloned().unwrap_or_default();
    let adopted = channels.iter().find(|c| c["external_managed"].as_bool() == Some(true) && s(&c["external_ref"]) == xref).cloned();
    let base = channel_name(if label.is_empty() { "" } else { label }, session);
    // Upstream `resolveAvailableChannelName`: suffix collisions with -2, -3…
    let taken = |n: &str| channels.iter().any(|c| s(&c["name"]) == n && adopted.as_ref().map(|a| a["id"] != c["id"]).unwrap_or(true));
    let mut name = base.clone();
    let mut i = 2;
    while taken(&name) {
        name = format!("{base}-{i}");
        i += 1;
    }
    let fields = json!({"name": name, "external_managed": true, "external_ref": xref, "external_url": "", "sidebar_section": SECTION, "display_title": display});
    let ch = match &adopted {
        Some(a) => {
            let mut patch = fields.clone();
            patch["archived"] = json!(false);
            core.api("PATCH", &format!("/api/channels/{}", enc(&s(&a["id"]))), Payload::Json(&patch))
        }
        None => {
            let mut body = fields.clone();
            body["kind"] = json!("public");
            core.api("POST", &format!("/api/workspaces/{}/channels", enc(&ws)), Payload::Json(&body))
        }
    }
    .map_err(|e| e.to_string())?;
    let ch = if ch["channel"].is_object() { ch["channel"].clone() } else { ch };
    let id = s(&ch["id"]);
    if id.is_empty() || s(&ch["external_ref"]) != xref {
        return Err("ClickClack returned an incompatible discussion channel (missing id or external_ref)".into());
    }
    let mut all = load(core);
    all[session] = json!({"channel_id": id, "name": s(&ch["name"]), "external_ref": xref, "workspace_id": ws, "server": core.base});
    save(core, &all)?;
    Ok((format!("Opened discussion #{} ({id}) for this session. People can post there; read it with action \"read\".", s(&ch["name"])), json!({"bound": true, "channelId": id, "created": adopted.is_none()})))
}

fn close(core: &Core, session: &str) -> Result<(String, Value), String> {
    let mut all = load(core);
    let Some(b) = all.as_object_mut().and_then(|o| o.remove(session)) else {
        return Ok((NOT_BOUND.into(), json!({"bound": false})));
    };
    match core.api("PATCH", &format!("/api/channels/{}", enc(&s(&b["channel_id"]))), Payload::Json(&json!({"archived": true}))) {
        Ok(_) => {}
        Err(e) if e.kind == crate::ChannelErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    save(core, &all)?;
    Ok((format!("Archived discussion {}.", s(&b["channel_id"])), json!({"bound": false, "channelId": b["channel_id"]})))
}

impl Tool for DiscussionTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: self.name.clone(),
            description: format!("Read the latest messages from the ClickClack discussion bound to this session (channel `{}`). `open` creates the discussion channel for this session first; `close` archives it.", self.core.id),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["read", "open", "close"], "description": "read (default), open or close"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT, "description": format!("Maximum messages to return (default {DEFAULT_LIMIT}).")},
                    "title": {"type": "string", "description": "Channel display title for open (default: the session id)"}
                },
                "additionalProperties": false
            }),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }

    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        match input.get("action").and_then(Value::as_str).unwrap_or("read") {
            "open" | "close" => vec![Effect::Send { channel: self.core.id.clone(), payload: format!("{} discussion channel", input["action"].as_str().unwrap_or("")) }],
            _ => vec![],
        }
    }

    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        if ctx.session_id.is_empty() {
            return ToolOutput::ok(NOT_BOUND);
        }
        let r = match input.get("action").and_then(Value::as_str).unwrap_or("read") {
            "read" => read(&self.core, &ctx.session_id, &input),
            "open" => open(&self.core, &ctx.session_id, &input),
            "close" => close(&self.core, &ctx.session_id),
            other => Err(format!("unknown action `{other}`; use read, open or close")),
        };
        match r {
            Ok((text, details)) => ToolOutput::ok(format!("{text}\n\n{details}")),
            Err(e) => ToolOutput::err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn naming_and_record_escaping() {
        assert_eq!(slugify("Fix the Parser — v2!"), "fix-the-parser-v2");
        assert!(channel_name("", "sess").starts_with("s-") && channel_name("", "sess").len() == 10);
        assert_eq!(record_json("a\u{2028}b\"c"), "\"a\\u2028b\\\"c\"");
        let m = vec![json!({"id": "b", "created_at": "2024-01-02"}), json!({"id": "a", "created_at": "2024-01-01"}), json!({"id": "c", "created_at": "2024-01-03"})];
        let k = keep_latest(m, 2);
        assert_eq!(k.iter().map(|x| s(&x["id"])).collect::<Vec<_>>(), ["b", "c"]);
        assert_eq!(format_history(&[], true), "");
    }
}

/// Hermetic `discussion` tool tests: a fake ClickClack on 127.0.0.1 plus a temp state dir,
/// so every assertion is about the tool's HTTP shape, its bindings file and its text.
#[cfg(test)]
mod tool_tests {
    use super::*;
    use crate::http::Http;
    use crate::testutil::{temp_dir, tool_ctx, FakeServer, Req};
    use seagent_core::Cancel;
    use std::sync::Mutex;
    use std::time::Duration;

    type Reply = (u16, Vec<(String, String)>, String);

    /// sha256("sess-1") = abe633f3a47a2758… — `XREF` is its 32-hex slice, `SNAME` its 8.
    const SESSION: &str = "sess-1";
    const XREF: &str = "seagent-discussion:abe633f3a47a2758174eabe9160daf36";
    const SNAME: &str = "s-abe633f3";
    const NOTE: &str = "[History scan reached its safety bound; older active threads may be omitted.]";

    fn ok(v: Value) -> Reply {
        (200, vec![], v.to_string())
    }
    fn nf() -> Reply {
        (404, vec![], "{\"error\":\"not found\"}".into())
    }
    fn me() -> Reply {
        ok(json!({"user": {"id": "usr_bot", "handle": "seagentbot", "display_name": "Seagent"}}))
    }

    fn core_with(id: &str, srv: &FakeServer, dir: &std::path::Path) -> Arc<Core> {
        Arc::new(Core {
            id: id.into(),
            base: srv.url.clone(),
            http: Http::new(Duration::from_secs(5)),
            workspace_sel: "wsp_1".into(),
            bot_id_cfg: None,
            state: dir.join("clickclack.json"),
            ident: Mutex::new(None),
            stop: Cancel::new(),
            reconnect: Duration::from_millis(50),
            idle: Duration::from_secs(90),
            ping_every: Duration::from_secs(30),
            ws_base: String::new(),
        })
    }
    fn core_for(srv: &FakeServer, dir: &std::path::Path) -> Arc<Core> {
        core_with("clickclack", srv, dir)
    }
    fn ctx_for(session: &str) -> ToolCtx {
        let mut c = tool_ctx();
        c.session_id = session.into();
        c
    }

    /// `call` → (text, details) for a successful result (`text\n\n{json}`).
    fn ok_call(t: &Arc<dyn Tool>, ctx: &ToolCtx, input: Value) -> (String, Value) {
        let out = t.call(ctx, input);
        assert!(!out.is_error, "unexpected error: {}", out.content);
        let (text, details) = out.content.rsplit_once("\n\n").expect("tool text + details JSON");
        (text.to_string(), serde_json::from_str(details).unwrap())
    }
    fn err_call(t: &Arc<dyn Tool>, ctx: &ToolCtx, input: Value) -> String {
        let out = t.call(ctx, input);
        assert!(out.is_error, "expected an error, got: {}", out.content);
        out.content
    }

    fn bindings(core: &Core) -> Value {
        load(core)
    }
    /// Persist a binding the way `open` would.
    fn bind(core: &Core, session: &str, channel_id: &str, xref: &str) {
        let mut all = load(core);
        all[session] = json!({"channel_id": channel_id, "name": SNAME, "external_ref": xref, "workspace_id": "wsp_1", "server": core.base});
        save(core, &all).unwrap();
    }

    fn chan(id: &str, name: &str, xref: &str) -> Value {
        json!({"id": id, "name": name, "kind": "public", "external_managed": true, "external_ref": xref, "sidebar_section": SECTION, "display_title": name, "archived": false, "archived_at": null})
    }
    fn m(id: &str, created_at: &str, body: &str, extra: Value) -> Value {
        let mut v = json!({"id": id, "channel_id": "chn_1", "author_id": "usr_amy", "body": body, "created_at": created_at, "author": {"id": "usr_amy", "display_name": "Amy", "handle": "amy"}});
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        v
    }
    fn record(created_at: &str, author: &str, author_id: &str, body: &str) -> String {
        format!(r#"timestamp="{created_at}" [Author "{author}" id="{author_id}"] text="{body}""#)
    }
    fn post_body(reqs: &[Req]) -> Value {
        reqs.iter().find(|r| r.method == "POST").expect("a POST request").json()
    }

    /// Runs `open` against a fresh server whose channel list holds `taken`; a POST echoes
    /// the created channel back.
    fn open_case(taken: Vec<Value>, input: Value) -> (Arc<Core>, String, Value, Vec<Req>) {
        let srv = FakeServer::start(move |req, _| match (req.method.as_str(), req.path.as_str()) {
            (_, "/api/me") => me(),
            ("GET", "/api/workspaces/wsp_1/channels") => ok(json!({ "channels": taken })),
            ("POST", "/api/workspaces/wsp_1/channels") => {
                let b = req.json();
                ok(json!({ "channel": { "id": "chn_new", "name": b["name"], "kind": "public", "external_managed": true, "external_ref": b["external_ref"], "sidebar_section": b["sidebar_section"], "display_title": b["display_title"], "archived_at": null } }))
            }
            _ => (500, vec![], "unexpected request".into()),
        });
        let core = core_for(&srv, &temp_dir("disc-open"));
        let (text, details) = ok_call(&tool(&core), &ctx_for(SESSION), input);
        let reqs = srv.requests();
        (core, text, details, reqs)
    }

    #[test]
    fn read_unbound_reports_no_binding_without_any_request() {
        let srv = FakeServer::start(|_, _| (500, vec![], "unused".into()));
        let core = core_for(&srv, &temp_dir("disc-unbound"));
        let (text, details) = ok_call(&tool(&core), &ctx_for(SESSION), json!({}));
        assert_eq!(text, NOT_BOUND);
        assert_eq!(details, json!({"bound": false, "limit": 30}));
        assert!(srv.requests().is_empty(), "an unbound read must not touch the network");
    }

    #[test]
    fn read_reports_an_empty_discussion() {
        let srv = FakeServer::start(|req, _| {
            if req.path == "/api/channels/chn_1" {
                return ok(json!({"channel": chan("chn_1", SNAME, XREF)}));
            }
            ok(json!({"messages": [], "has_older": false, "oldest_seq": 0}))
        });
        let core = core_for(&srv, &temp_dir("disc-empty"));
        bind(&core, SESSION, "chn_1", XREF);
        let (text, details) = ok_call(&tool(&core), &ctx_for(SESSION), json!({}));
        assert_eq!(text, "The bound discussion has no messages yet.");
        assert_eq!(details["bound"], true);
    }

    #[test]
    fn empty_session_id_is_unbound_for_every_action() {
        let srv = FakeServer::start(|_, _| (500, vec![], "unused".into()));
        let core = core_for(&srv, &temp_dir("disc-nosession"));
        let t = tool(&core);
        for input in [json!({}), json!({"action": "read"}), json!({"action": "open"}), json!({"action": "close"})] {
            let out = t.call(&ctx_for(""), input.clone());
            assert_eq!(out.content, NOT_BOUND, "{input}");
            assert!(!out.is_error);
        }
        assert!(srv.requests().is_empty());
    }

    #[test]
    fn open_creates_a_public_managed_channel_and_persists_the_binding() {
        let (core, text, details, reqs) = open_case(vec![json!({"id": "chn_gen", "name": "general", "external_managed": false})], json!({"action": "open"}));
        assert!(text.starts_with("Opened discussion #s-abe633f3 (chn_new) for this session."), "{text}");
        assert_eq!(details, json!({"bound": true, "channelId": "chn_new", "created": true}));
        let body = post_body(&reqs);
        assert_eq!(body["name"], SNAME);
        assert_eq!(body["kind"], "public");
        assert_eq!(body["external_managed"], true);
        assert_eq!(body["external_ref"], XREF);
        assert_eq!(body["sidebar_section"], SECTION);
        assert_eq!(body["display_title"], "seagent session sess-1");
        assert_eq!(reqs.iter().find(|r| r.method == "POST").unwrap().path, "/api/workspaces/wsp_1/channels");
        let saved = bindings(&core);
        assert_eq!(saved[SESSION], json!({"channel_id": "chn_new", "name": SNAME, "external_ref": XREF, "workspace_id": "wsp_1", "server": core.base}));
        assert!(bindings_path(&core).exists());
    }

    #[test]
    fn open_twice_returns_the_existing_binding_and_creates_nothing() {
        let srv = FakeServer::start(|req, _| match (req.method.as_str(), req.path.as_str()) {
            (_, "/api/me") => me(),
            ("GET", "/api/workspaces/wsp_1/channels") => ok(json!({"channels": [chan("chn_new", SNAME, XREF)]})),
            ("GET", "/api/channels/chn_new") => ok(json!({"channel": chan("chn_new", SNAME, XREF)})),
            ("POST", _) => (500, vec![], "must not create".into()),
            _ => (500, vec![], "unexpected request".into()),
        });
        let core = core_for(&srv, &temp_dir("disc-twice"));
        bind(&core, SESSION, "chn_new", XREF);
        let (text, details) = ok_call(&tool(&core), &ctx_for(SESSION), json!({"action": "open"}));
        assert_eq!(text, format!("This session's discussion is #{SNAME} (chn_new)."));
        assert_eq!(details, json!({"bound": true, "channelId": "chn_new", "created": false}));
        let reqs = srv.requests();
        assert!(reqs.iter().all(|r| r.method != "POST"), "no channel is created");
        assert_eq!(reqs.len(), 1, "only the live channel check");
    }

    #[test]
    fn open_adopts_a_channel_carrying_the_same_external_ref() {
        let srv = FakeServer::start(|req, _| match (req.method.as_str(), req.path.as_str()) {
            (_, "/api/me") => me(),
            ("GET", "/api/workspaces/wsp_1/channels") => ok(json!({"channels": [chan("chn_old", SNAME, XREF)]})),
            ("PATCH", "/api/channels/chn_old") => ok(json!({"channel": chan("chn_old", SNAME, XREF)})),
            ("POST", _) => (500, vec![], "must adopt, not create".into()),
            _ => (500, vec![], "unexpected request".into()),
        });
        let core = core_for(&srv, &temp_dir("disc-adopt"));
        let (text, details) = ok_call(&tool(&core), &ctx_for(SESSION), json!({"action": "open"}));
        assert!(text.contains("#s-abe633f3 (chn_old)"), "{text}");
        assert_eq!(details, json!({"bound": true, "channelId": "chn_old", "created": false}));
        let reqs = srv.requests();
        let patch = reqs.iter().find(|r| r.method == "PATCH").expect("PATCH the adopted channel");
        assert_eq!(patch.path, "/api/channels/chn_old");
        let body = patch.json();
        assert_eq!(body["archived"], false, "adoption unarchives");
        assert_eq!(body["external_managed"], true);
        assert_eq!(body["external_ref"], XREF);
        assert_eq!(body["sidebar_section"], SECTION);
        assert_eq!(body["display_title"], "seagent session sess-1");
        assert_eq!(body["name"], SNAME, "an adopted channel keeps its name");
        assert!(reqs.iter().all(|r| r.method != "POST"));
        assert_eq!(bindings(&core)[SESSION]["channel_id"], "chn_old");
    }

    #[test]
    fn open_suffixes_colliding_channel_names_with_two_and_three() {
        let (_, _, _, reqs) = open_case(vec![json!({"id": "chn_other", "name": SNAME, "external_managed": false})], json!({"action": "open"}));
        assert_eq!(post_body(&reqs)["name"], "s-abe633f3-2");
        let taken = vec![json!({"id": "chn_a", "name": SNAME, "external_managed": false}), json!({"id": "chn_b", "name": "s-abe633f3-2", "external_managed": false})];
        let (_, _, _, reqs) = open_case(taken, json!({"action": "open"}));
        assert_eq!(post_body(&reqs)["name"], "s-abe633f3-3");
    }

    #[test]
    fn open_slugifies_the_title_and_cuts_name_and_display_title() {
        let (_, _, _, reqs) = open_case(vec![], json!({"action": "open", "title": "  Fix_the  Parser!! v2 "}));
        let body = post_body(&reqs);
        assert_eq!(body["name"], "fix-the-parser-v2");
        assert_eq!(body["display_title"], "Fix_the  Parser!! v2", "trimmed, not slugified");

        let (_, _, _, reqs) = open_case(vec![], json!({"action": "open", "title": "a".repeat(120)}));
        assert_eq!(post_body(&reqs)["name"].as_str().unwrap(), "a".repeat(80));

        let (_, _, _, reqs) = open_case(vec![], json!({"action": "open", "title": "é".repeat(201)}));
        assert_eq!(post_body(&reqs)["display_title"].as_str().unwrap().chars().count(), 200, "cut at 200 codepoints, not bytes");
        assert_eq!(post_body(&reqs)["name"], SNAME, "a title that slugifies to nothing falls back to the session hash");
    }

    #[test]
    fn open_rejects_a_channel_without_the_external_ref() {
        let srv = FakeServer::start(|req, _| match (req.method.as_str(), req.path.as_str()) {
            (_, "/api/me") => me(),
            ("GET", "/api/workspaces/wsp_1/channels") => ok(json!({"channels": []})),
            ("POST", "/api/workspaces/wsp_1/channels") => ok(json!({"channel": {"id": "chn_new", "name": SNAME}})),
            _ => (500, vec![], "unexpected request".into()),
        });
        let core = core_for(&srv, &temp_dir("disc-incompat"));
        let err = err_call(&tool(&core), &ctx_for(SESSION), json!({"action": "open"}));
        assert!(err.contains("incompatible discussion channel"), "{err}");
        assert_eq!(bindings(&core), json!({}), "an incompatible channel is never bound");
    }

    #[test]
    fn read_merges_sorts_dedupes_limits_and_formats_records() {
        let r1 = m("r1", "2024-01-02T10:00:00Z", "hello", json!({"thread_state": {"reply_count": 1, "last_reply_at": "2024-01-02T12:00:00Z"}}));
        let r2 = m("r2", "2024-01-02T10:30:00Z", "second", json!({}));
        let t1 = json!({"id": "t1", "author_id": "usr_bob", "author": {"handle": "bob"}, "body": "in \"thread\"\u{2028}x", "created_at": "2024-01-02T12:00:00Z"});
        let page = json!({"messages": [r1, r2], "has_older": false, "oldest_seq": 5});
        let thread = json!({"replies": [t1, t1]});
        let srv = FakeServer::start(move |req, _| {
            let p = req.path.as_str();
            if p == "/api/channels/chn_1" {
                return ok(json!({"channel": chan("chn_1", SNAME, XREF)}));
            }
            if p.starts_with("/api/channels/chn_1/messages") {
                return ok(page.clone());
            }
            if p.starts_with("/api/messages/r1/thread") {
                return ok(thread.clone());
            }
            (500, vec![], "unexpected request".into())
        });
        let core = core_for(&srv, &temp_dir("disc-read"));
        bind(&core, SESSION, "chn_1", XREF);
        let t = tool(&core);
        let ctx = ctx_for(SESSION);

        let lines = [
            record("2024-01-02T10:00:00Z", "Amy", "usr_amy", "hello"),
            record("2024-01-02T10:30:00Z", "Amy", "usr_amy", "second"),
            r#"timestamp="2024-01-02T12:00:00Z" [Author "bob" id="usr_bob"] text="in \"thread\"\u2028x""#.to_string(),
        ];
        let (text, details) = ok_call(&t, &ctx, json!({}));
        assert_eq!(text, lines.join("\n"), "sorted by (created_at, id) and deduped by id");
        assert_eq!(details, json!({"bound": true, "limit": 30, "channelId": "chn_1"}));

        let (text, details) = ok_call(&t, &ctx, json!({"limit": 2}));
        assert_eq!(text, lines[1..].join("\n"));
        assert_eq!(details["limit"], 2);

        let (text, details) = ok_call(&t, &ctx, json!({"limit": 500}));
        assert_eq!(details["limit"], 200, "clamped to the page cap");
        assert_eq!(text.lines().count(), 3);

        let (text, details) = ok_call(&t, &ctx, json!({"limit": 0}));
        assert_eq!(details["limit"], 1);
        assert_eq!(text, lines[2]);

        let (_, details) = ok_call(&t, &ctx, json!({"limit": -5}));
        assert_eq!(details["limit"], 1, "negative limits clamp like upstream");

        let reqs = srv.requests();
        assert!(reqs.iter().any(|r| r.path == "/api/channels/chn_1/messages?limit=200"), "{reqs:?}");
        assert!(reqs.iter().any(|r| r.path == "/api/messages/r1/thread?limit=200"), "threads are fetched at the page cap");
    }

    #[test]
    fn read_notes_truncation_when_a_thread_is_incomplete() {
        let root = m("r1", "2024-01-02T10:00:00Z", "hello", json!({"thread_state": {"reply_count": 3}}));
        let srv = FakeServer::start(move |req, _| {
            let p = req.path.as_str();
            if p == "/api/channels/chn_1" {
                return ok(json!({"channel": chan("chn_1", SNAME, XREF)}));
            }
            if p.starts_with("/api/channels/chn_1/messages") {
                return ok(json!({"messages": [root], "has_older": false, "oldest_seq": 1}));
            }
            ok(json!({"replies": [m("t1", "2024-01-02T11:00:00Z", "only one", json!({}))]}))
        });
        let core = core_for(&srv, &temp_dir("disc-short-thread"));
        bind(&core, SESSION, "chn_1", XREF);
        let (text, _) = ok_call(&tool(&core), &ctx_for(SESSION), json!({}));
        assert_eq!(text, format!("{}\n{NOTE}", record("2024-01-02T10:00:00Z", "Amy", "usr_amy", "hello")));
    }

    #[test]
    fn read_notes_truncation_when_the_thread_budget_runs_out() {
        let roots: Vec<Value> = (0..26).map(|i| m(&format!("r{i:02}"), "2024-01-02T10:00:00Z", "root", json!({"thread_state": {"reply_count": 1}}))).collect();
        let srv = FakeServer::start(move |req, n| {
            let p = req.path.as_str();
            if p == "/api/channels/chn_1" {
                return ok(json!({"channel": chan("chn_1", SNAME, XREF)}));
            }
            if p.starts_with("/api/channels/chn_1/messages") {
                return ok(json!({"messages": roots, "has_older": false, "oldest_seq": 1}));
            }
            ok(json!({"replies": [m(&format!("t{n}"), "2024-01-02T11:00:00Z", "reply", json!({}))]}))
        });
        let core = core_for(&srv, &temp_dir("disc-thread-budget"));
        bind(&core, SESSION, "chn_1", XREF);
        let (text, _) = ok_call(&tool(&core), &ctx_for(SESSION), json!({}));
        assert!(text.ends_with(NOTE), "{text}");
        assert_eq!(text.lines().count(), 31, "30 records plus the note");
        assert_eq!(srv.requests().iter().filter(|r| r.path.contains("/thread?limit=")).count(), 24, "the thread budget");
    }

    #[test]
    fn read_notes_truncation_after_eight_root_pages() {
        let srv = FakeServer::start(|req, _| {
            let p = req.path.as_str();
            if p == "/api/channels/chn_1" {
                return ok(json!({"channel": chan("chn_1", SNAME, XREF)}));
            }
            if p.starts_with("/api/channels/chn_1/messages") {
                let seq = p.split("before_seq=").nth(1).and_then(|v| v.parse::<i64>().ok()).unwrap_or(5000);
                return ok(json!({"messages": [m("r1", "2024-01-02T10:00:00Z", "root", json!({}))], "has_older": true, "oldest_seq": seq - 1}));
            }
            (500, vec![], "unexpected request".into())
        });
        let core = core_for(&srv, &temp_dir("disc-page-budget"));
        bind(&core, SESSION, "chn_1", XREF);
        let (text, _) = ok_call(&tool(&core), &ctx_for(SESSION), json!({}));
        assert!(text.ends_with(NOTE), "{text}");
        assert_eq!(srv.requests().iter().filter(|r| r.path.starts_with("/api/channels/chn_1/messages")).count(), 8, "the root-page budget");
    }

    #[test]
    fn read_treats_archived_revoked_and_missing_channels_as_unbound() {
        let revoked = [
            json!({"channel": {"id": "chn_1", "external_ref": XREF, "archived": true}}),
            json!({"channel": {"id": "chn_1", "external_ref": XREF, "archived_at": "2024-02-01T00:00:00Z"}}),
            json!({"channel": {"id": "chn_1", "external_ref": "seagent-discussion:somebody-else"}}),
        ];
        for body in revoked {
            let srv = FakeServer::start(move |req, _| if req.path == "/api/channels/chn_1" { ok(body.clone()) } else { (500, vec![], "must not read messages".into()) });
            let core = core_for(&srv, &temp_dir("disc-revoked"));
            bind(&core, SESSION, "chn_1", XREF);
            let (text, details) = ok_call(&tool(&core), &ctx_for(SESSION), json!({}));
            assert_eq!(text, NOT_BOUND);
            assert_eq!(details["bound"], false);
            assert_eq!(srv.requests().len(), 1, "only the live channel check");
        }
        let srv = FakeServer::start(|req, _| if req.path == "/api/channels/chn_1" { nf() } else { (500, vec![], "must not read messages".into()) });
        let core = core_for(&srv, &temp_dir("disc-gone"));
        bind(&core, SESSION, "chn_1", XREF);
        let (text, details) = ok_call(&tool(&core), &ctx_for(SESSION), json!({}));
        assert_eq!(text, NOT_BOUND, "a deleted channel is a revoked discussion");
        assert_eq!(details["bound"], false);
    }

    #[test]
    fn read_rejects_pagination_that_does_not_advance() {
        let variants = [
            json!({"messages": [m("r1", "2024-01-02T10:00:00Z", "root", json!({}))], "has_older": true}),
            json!({"messages": [m("r1", "2024-01-02T10:00:00Z", "root", json!({}))], "has_older": true, "oldest_seq": -1}),
            json!({"messages": [m("r1", "2024-01-02T10:00:00Z", "root", json!({}))], "has_older": true, "oldest_seq": 5}),
            json!({"messages": [], "has_older": true, "oldest_seq": 4}),
        ];
        for page in variants {
            let srv = FakeServer::start(move |req, _| {
                let p = req.path.as_str();
                if p == "/api/channels/chn_1" {
                    return ok(json!({"channel": chan("chn_1", SNAME, XREF)}));
                }
                if p.contains("before_seq=") {
                    return ok(page.clone());
                }
                ok(json!({"messages": [m("r0", "2024-01-02T09:00:00Z", "root", json!({}))], "has_older": true, "oldest_seq": 5}))
            });
            let core = core_for(&srv, &temp_dir("disc-paging"));
            bind(&core, SESSION, "chn_1", XREF);
            let err = err_call(&tool(&core), &ctx_for(SESSION), json!({}));
            assert!(err.contains("ClickClack message pagination did not advance"), "{err}");
        }
    }

    #[test]
    fn close_archives_the_channel_and_removes_the_binding() {
        let srv = FakeServer::start(|req, _| match (req.method.as_str(), req.path.as_str()) {
            ("PATCH", "/api/channels/chn_1") => ok(json!({"channel": {"id": "chn_1", "archived": true}})),
            _ => (500, vec![], "unexpected request".into()),
        });
        let core = core_for(&srv, &temp_dir("disc-close"));
        bind(&core, SESSION, "chn_1", XREF);
        let (text, details) = ok_call(&tool(&core), &ctx_for(SESSION), json!({"action": "close"}));
        assert_eq!(text, "Archived discussion chn_1.");
        assert_eq!(details, json!({"bound": false, "channelId": "chn_1"}));
        let reqs = srv.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "PATCH");
        assert_eq!(reqs[0].json(), json!({"archived": true}));
        assert!(bindings(&core).get(SESSION).is_none(), "binding removed: {}", bindings(&core));
    }

    #[test]
    fn close_without_a_binding_is_unbound_and_sends_nothing() {
        let srv = FakeServer::start(|_, _| (500, vec![], "unused".into()));
        let core = core_for(&srv, &temp_dir("disc-close-none"));
        let (text, details) = ok_call(&tool(&core), &ctx_for(SESSION), json!({"action": "close"}));
        assert_eq!(text, NOT_BOUND);
        assert_eq!(details, json!({"bound": false}));
        assert!(srv.requests().is_empty());
    }

    #[test]
    fn close_tolerates_a_channel_that_is_already_gone() {
        let srv = FakeServer::start(|_, _| nf());
        let core = core_for(&srv, &temp_dir("disc-close-404"));
        bind(&core, SESSION, "chn_1", XREF);
        let (text, details) = ok_call(&tool(&core), &ctx_for(SESSION), json!({"action": "close"}));
        assert_eq!(text, "Archived discussion chn_1.");
        assert_eq!(details["bound"], false);
        assert!(bindings(&core).get(SESSION).is_none(), "a 404 still clears the binding");
    }

    #[test]
    fn effects_send_only_on_open_and_close_and_unknown_actions_error() {
        let srv = FakeServer::start(|_, _| (500, vec![], "unused".into()));
        let core = core_for(&srv, &temp_dir("disc-effects"));
        let t = tool(&core);
        let ctx = ctx_for(SESSION);
        assert!(t.effects(&ctx, &json!({})).is_empty(), "read is the default and sends nothing");
        assert!(t.effects(&ctx, &json!({"action": "read"})).is_empty());
        for action in ["open", "close"] {
            assert_eq!(t.effects(&ctx, &json!({"action": action})), vec![Effect::Send { channel: "clickclack".into(), payload: format!("{action} discussion channel") }]);
        }
        let err = err_call(&t, &ctx, json!({"action": "nuke"}));
        assert!(err.contains("unknown action `nuke`"), "{err}");
        assert!(srv.requests().is_empty());
    }

    #[test]
    fn tool_name_is_discussion_only_for_a_clickclack_channel() {
        let srv = FakeServer::start(|_, _| (500, vec![], "unused".into()));
        let dir = temp_dir("disc-name");
        let plain = tool(&core_with("clickclack", &srv, &dir));
        assert_eq!(plain.spec().name, "discussion");
        let other = tool(&core_with("Slack Team", &srv, &dir));
        assert_eq!(other.spec().name, "discussion_Slack_Team");
        assert_eq!(other.spec().schema().name, "discussion_Slack_Team");
        let schema = plain.spec().input_schema;
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["limit"]["minimum"], 1);
        assert_eq!(schema["properties"]["limit"]["maximum"], 200);
    }
}
