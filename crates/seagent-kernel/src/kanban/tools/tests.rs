//! Tool-layer tests: every advertised `kanban_*` name is driven through
//! `KanbanTool::call` (schema validation → dispatch → board effect) on a temp data
//! dir. Network paths (URL attachments, GitHub acceptance) use a local fake server.

use super::*;
use crate::kanban::testutil::{self, ctx};
use seagent_core::ToolCtx;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, Mutex};

fn cfg() -> KanbanConfig {
    KanbanConfig { enabled: true, ..Default::default() }
}
fn tool(name: &'static str) -> KanbanTool {
    KanbanTool { name, cfg: cfg() }
}
fn with_cfg(name: &'static str, cfg: KanbanConfig) -> KanbanTool {
    KanbanTool { name, cfg }
}
fn sid(tag: &str) -> String {
    format!("{tag}-{}", crate::util::random_hex(8))
}

fn call_ok(t: &KanbanTool, c: &ToolCtx, args: Value) -> Value {
    let out = t.call(c, args);
    assert!(!out.is_error, "{} returned an error: {}", t.name, out.content);
    serde_json::from_str(&out.content).unwrap_or_else(|e| panic!("{} returned non-JSON ({e}): {}", t.name, out.content))
}
fn call_err(t: &KanbanTool, c: &ToolCtx, args: Value) -> String {
    let out = t.call(c, args);
    assert!(out.is_error, "{} was expected to fail but returned: {}", t.name, out.content);
    out.content
}
fn board(data: &Path, slug: &str) -> BoardData {
    store::read_board(data, slug).unwrap()
}

fn create_card(t: &KanbanTool, c: &ToolCtx, title: &str, extra: Value) -> String {
    let mut args = json!({"title": title, "assignee": "dev"});
    if let Some(o) = extra.as_object() {
        args.as_object_mut().unwrap().extend(o.clone());
    }
    call_ok(t, c, args)["task_id"].as_str().expect("task_id in kanban_create output").to_string()
}

/// Register a dispatcher-style worker scope: claim `tid` in `lane` and bind `session`
/// to that run (the in-process registry `scope_for_session` reads).
fn claim_for(data: &Path, slug: &str, tid: &str, session: &str, profile: &str, lane: &str) -> u64 {
    let lock = format!("test:{}", session);
    let rid = store::with_board(data, slug, |b| {
        ops::claim(b, tid, ops::ClaimOpts { lock: &lock, ttl: 900, lane, owner: Some(profile), token: None }).ok_or_else(|| format!("claim of {tid} in {lane} failed"))
    })
    .unwrap_or_else(|e| panic!("{e}"));
    dispatch::register_live(session, dispatch::Live { slug: slug.into(), task: tid.into(), run: rid, profile: Some(profile.into()), lock });
    rid
}

// ───────────────────────── fake HTTP server ─────────────────────────

#[derive(Clone)]
struct Route {
    status: u16,
    body: Vec<u8>,
    ctype: String,
    location: Option<String>,
    link: Option<String>,
}

impl Route {
    fn ok(ctype: &str, body: &[u8]) -> Route {
        Route { status: 200, body: body.to_vec(), ctype: ctype.into(), location: None, link: None }
    }
    fn json(body: &str) -> Route {
        Route::ok("application/json", body.as_bytes())
    }
    fn status(code: u16) -> Route {
        Route { status: code, body: b"{}".to_vec(), ctype: "application/json".into(), location: None, link: None }
    }
    fn redirect(to: &str) -> Route {
        Route { status: 302, body: vec![], ctype: "text/plain".into(), location: Some(to.into()), link: None }
    }
}

/// Serve `router(path)` on a loopback port; returns the base URL and every path seen.
fn serve(router: impl Fn(&str) -> Route + Send + 'static) -> (String, Arc<Mutex<Vec<String>>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = format!("http://{}", l.local_addr().unwrap());
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let s2 = seen.clone();
    let base = addr.clone();
    std::thread::spawn(move || {
        for conn in l.incoming().flatten() {
            let mut r = BufReader::new(conn.try_clone().unwrap());
            let mut line = String::new();
            if r.read_line(&mut line).is_err() {
                continue;
            }
            let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
            let mut len = 0usize;
            loop {
                let mut h = String::new();
                if r.read_line(&mut h).is_err() || h.trim().is_empty() {
                    break;
                }
                let low = h.to_lowercase();
                if let Some(v) = low.strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
            }
            if len > 0 {
                let mut body = vec![0u8; len];
                let _ = r.read_exact(&mut body);
            }
            s2.lock().unwrap().push(path.clone());
            let rt = router(&path);
            let mut head = format!("HTTP/1.1 {} X\r\ncontent-type: {}\r\ncontent-length: {}\r\n", rt.status, rt.ctype, rt.body.len());
            if let Some(l) = &rt.location {
                head.push_str(&format!("location: {l}\r\n"));
            }
            if let Some(l) = &rt.link {
                head.push_str(&format!("link: <{base}{l}>; rel=\"next\"\r\n"));
            }
            head.push_str("connection: close\r\n\r\n");
            let mut w = conn;
            let _ = w.write_all(head.as_bytes());
            let _ = w.write_all(&rt.body);
        }
    });
    (addr, seen)
}

// ───────────────────────── schema surface ─────────────────────────

/// `required` for every name, in `NAMES` order (`task_id` defaults to the worker's
/// task, so it is optional everywhere it appears).
const REQUIRED: &[(&str, &[&str])] = &[
    ("kanban_show", &[]),
    ("kanban_list", &[]),
    ("kanban_complete", &[]),
    ("kanban_block", &["reason"]),
    ("kanban_schedule", &[]),
    ("kanban_request_review", &["summary"]),
    ("kanban_request_changes", &["reason"]),
    ("kanban_heartbeat", &[]),
    ("kanban_comment", &["task_id", "body"]),
    ("kanban_attach", &["filename", "content_base64"]),
    ("kanban_attach_url", &["url"]),
    ("kanban_attachments", &[]),
    ("kanban_create", &["title", "assignee"]),
    ("kanban_unblock", &["task_id"]),
    ("kanban_link", &["parent_id", "child_id"]),
];

#[test]
fn every_name_has_a_schema_and_the_right_tool_set() {
    assert_eq!(NAMES.len(), 15, "15 Hermes kanban tools");
    assert_eq!(REQUIRED.iter().map(|(n, _)| *n).collect::<Vec<_>>(), NAMES.to_vec(), "required table covers NAMES in order");
    for name in NAMES {
        let (desc, props, req) = schema(name);
        assert!(!desc.trim().is_empty(), "{name} has no description");
        let props = props.as_object().unwrap_or_else(|| panic!("{name} schema properties are not an object"));
        assert!(props.contains_key("board"), "{name} must accept a board override");
        for r in &req {
            assert!(props.contains_key(*r), "{name}: required field {r} is not in properties");
        }
        let spec = tool(name).spec();
        assert_eq!(spec.name, *name);
        assert_eq!(spec.input_schema["type"], "object");
        assert_eq!(spec.input_schema["properties"].as_object().map(|o| o.len()), Some(props.len()));
        assert_eq!(spec.input_schema["required"].as_array().map(|a| a.len()), Some(req.len()));
        assert_eq!(spec.parallel_safe, matches!(*name, "kanban_show" | "kanban_list" | "kanban_attachments"), "{name} parallel_safe");
        assert!(spec.idempotent == matches!(*name, "kanban_show" | "kanban_list" | "kanban_attachments" | "kanban_heartbeat"), "{name} idempotent");
    }
    for (name, want) in REQUIRED {
        let (_, _, req) = schema(name);
        assert_eq!(&req[..], *want, "{name} required fields");
    }
    // The status filter enum lists every Hermes column plus `archived`.
    let cols = schema("kanban_list").1["status"]["enum"].as_array().unwrap().clone();
    for c in crate::kanban::workflow::HERMES_STATUSES.iter().chain(["archived"].iter()) {
        assert!(cols.iter().any(|v| v == c), "kanban_list status enum is missing {c}");
    }
}

#[test]
fn session_tools_follow_the_enabled_flag() {
    assert!(session_tools(&KanbanConfig::default()).is_empty(), "kanban is off by default: no tools for the model");
    let mut off = KanbanConfig { enabled: true, ..Default::default() };
    off.enabled = false;
    assert!(session_tools(&off).is_empty());

    let on = session_tools(&cfg());
    let names: Vec<String> = on.iter().map(|t| t.spec().name).collect();
    assert_eq!(names.len(), NAMES.len() + crate::kanban::workboard::NAMES.len(), "both vocabularies reach a session");
    for n in NAMES.iter().chain(crate::kanban::workboard::NAMES.iter()) {
        assert!(names.iter().any(|x| x == n), "{n} is not offered by session_tools");
    }
    let mut seen = std::collections::BTreeSet::new();
    for n in &names {
        assert!(seen.insert(n.clone()), "duplicate tool name {n}");
    }

    // A dispatched worker gets the mutating subset of both vocabularies, never routing.
    let w: Vec<String> = worker_tools(&cfg()).iter().map(|t| t.spec().name).collect();
    for n in ["kanban_list", "kanban_unblock"] {
        assert!(!w.iter().any(|x| x == n), "{n} must stay orchestrator-only");
    }
    for n in ["kanban_show", "kanban_complete", "kanban_block", "kanban_heartbeat"] {
        assert!(w.iter().any(|x| x == n), "{n} is missing from worker_tools");
    }
}

#[test]
fn every_name_is_dispatchable_and_rejects_unknown_parameters() {
    let d = testutil::data();
    let c = ctx(&d, "orch");
    for name in NAMES {
        let out = tool(name).call(&c, json!({}));
        assert!(!out.content.contains("unknown kanban tool"), "{name} fell through the dispatcher: {}", out.content);
    }
    // Typos are refused before anything is written.
    let msg = call_err(&tool("kanban_create"), &c, json!({"title": "x", "assignee": "dev", "asignee": "dev"}));
    assert!(msg.contains("unknown parameter(s): asignee"), "{msg}");
    assert!(msg.contains("Nothing changed"), "{msg}");
    assert!(board(&d, "default").tasks.is_empty(), "a rejected call writes nothing");
}

// ───────────────────────── create / list / show / comment / link ─────────────────────────

#[test]
fn create_list_show_comment_and_link() {
    let d = testutil::data();
    let c = ctx(&d, "orch");
    let create = tool("kanban_create");
    let out = call_ok(&create, &c, json!({"title": "Write the report", "assignee": "Dev", "body": "Spec v1", "priority": 2, "tenant": "acme", "skills": ["docs", "docs", " "] }));
    let a = out["task_id"].as_str().unwrap().to_string();
    assert!(a.starts_with("t_"), "{a}");
    assert_eq!(out["status"], "ready");
    assert_eq!(out["gated"], false);
    assert_eq!(out["subscribed"], true, "the creating session subscribes by default");
    let t = board(&d, "default");
    let card = t.task(&a).unwrap();
    assert_eq!(card.assignee.as_deref(), Some("dev"), "assignees are canonicalised");
    assert_eq!(card.created_by.as_deref(), Some("default"), "identity comes from the config, never from tool args");
    assert_eq!(card.skills.as_deref(), Some(&["docs".to_string()][..]), "skills are de-duplicated");

    // list: filters, row shape, limit validation
    let list = tool("kanban_list");
    let v = call_ok(&list, &c, json!({}));
    assert_eq!(v["count"].as_u64(), Some(1));
    assert_eq!(v["tasks"][0]["id"], a.as_str());
    assert_eq!(v["tasks"][0]["tenant"], "acme");
    assert_eq!(v["truncated"], false);
    assert_eq!(call_ok(&list, &c, json!({"assignee": "dev"}))["count"].as_u64(), Some(1));
    assert_eq!(call_ok(&list, &c, json!({"assignee": "nobody"}))["count"].as_u64(), Some(0));
    assert_eq!(call_ok(&list, &c, json!({"status": "done"}))["count"].as_u64(), Some(0));
    assert_eq!(call_ok(&list, &c, json!({"tenant": "acme"}))["count"].as_u64(), Some(1));
    assert!(call_err(&list, &c, json!({"limit": 0})).contains("limit must be >= 1"));
    assert!(call_err(&list, &c, json!({"limit": 201})).contains("limit must be <= 200"));
    assert!(call_err(&tool("kanban_create"), &c, json!({"assignee": "dev"})).contains("title is required"));
    assert!(call_err(&create, &c, json!({"title": "no assignee"})).contains("assignee is required"));

    // show: full state, parents/children, the pre-formatted worker context
    let show = tool("kanban_show");
    let s = call_ok(&show, &c, json!({"task_id": &a}));
    assert_eq!(s["task"]["title"], "Write the report");
    assert_eq!(s["task"]["body"], "Spec v1");
    assert!(s["worker_context"].as_str().unwrap().contains("Write the report"));
    assert!(call_err(&show, &c, json!({"task_id": "t_missing"})).contains("not found"));
    // Outside a worker there is no default task: the bare call points at kanban_list.
    let hint = call_ok(&show, &c, json!({}));
    assert!(hint["hint"].as_str().unwrap().contains("kanban_list"), "{hint}");
    assert_eq!(hint["current_task"], Value::Null);

    // comment: thread + secret redaction (author = config identity)
    let comment = tool("kanban_comment");
    let secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    let cid = call_ok(&comment, &c, json!({"task_id": &a, "body": format!("leaked key {secret}")}))["comment_id"].clone();
    assert!(cid.is_u64(), "{cid}");
    let s = call_ok(&show, &c, json!({"task_id": &a}));
    assert_eq!(s["comments"][0]["author"], "default");
    let body = s["comments"][0]["body"].as_str().unwrap();
    assert!(body.contains("[REDACTED]") && !body.contains(secret), "comment body not redacted: {body}");
    assert!(call_err(&comment, &c, json!({"body": "orphan"})).contains("task_id is required"));

    // link: the child waits for its parent and shows unsatisfied parents
    let b = create_card(&create, &c, "Review it", json!({"assignee": "rev"}));
    let link = tool("kanban_link");
    let l = call_ok(&link, &c, json!({"parent_id": &a, "child_id": &b}));
    assert_eq!(l["gated"], true);
    assert_eq!(l["gated_by"], a.as_str());
    assert_eq!(board(&d, "default").status_of(&b), Some("todo"));
    let s = call_ok(&show, &c, json!({"task_id": &b}));
    assert_eq!(s["parents"], json!([a]));
    assert_eq!(s["unsatisfied_parents"][0]["id"], a.as_str());
    assert!(call_err(&link, &c, json!({"parent_id": &b, "child_id": &a})).contains("cycle"));
    assert!(call_err(&link, &c, json!({"parent_id": &a})).contains("both parent_id and child_id are required"));

    // the child stays gated until the parent is done, then promotes
    assert!(call_err(&tool("kanban_complete"), &c, json!({"task_id": &b, "summary": "done"})).contains("unsatisfied parent"));
    call_ok(&tool("kanban_complete"), &c, json!({"task_id": &a, "summary": "report shipped"}));
    assert_eq!(board(&d, "default").status_of(&b), Some("ready"), "finishing the parent promotes the child");
}

// ───────────────────────── worker lifecycle ─────────────────────────

#[test]
fn worker_heartbeat_block_unblock_and_schedule() {
    let d = testutil::data();
    let orch = ctx(&d, "orch");
    let create = tool("kanban_create");
    let a = create_card(&create, &orch, "Train the model", json!({}));
    let other = create_card(&create, &orch, "Other card", json!({}));

    // Drive everything through a worker session bound to `a`.
    let wname = sid("w");
    claim_for(&d, "default", &a, &wname, "dev", "ready");
    let w = ctx(&d, &wname);

    // show/heartbeat default to the worker's own task
    let show = tool("kanban_show");
    assert_eq!(call_ok(&show, &w, json!({}))["task"]["id"], a.as_str());
    let hb = tool("kanban_heartbeat");
    call_ok(&hb, &w, json!({"note": "epoch 3/10"}));
    let t = board(&d, "default");
    assert!(t.task(&a).unwrap().last_heartbeat_at.is_some());
    assert!(t.events_for(&a).iter().any(|e| e.kind == "heartbeat" && e.payload.as_ref().unwrap()["note"] == "epoch 3/10"), "heartbeat note reaches the event log");
    assert!(call_err(&hb, &w, json!({"task_id": &other})).contains("scoped to task"), "a worker cannot touch another card");

    // block: redacted reason, typed kind, and the claim is released
    let block = tool("kanban_block");
    let secret = "sk-ant-abcdefghijklmnopqrstuvwx";
    let v = call_ok(&block, &w, json!({"kind": "needs_input", "reason": format!("need the {secret} key")}));
    assert_eq!(v["status"], "blocked");
    assert_eq!(v["block_kind"], "needs_input");
    let t = board(&d, "default");
    assert_eq!(t.task(&a).unwrap().claim_lock, None, "blocking releases the claim");
    let reason = t.events_for(&a).into_iter().rev().find(|e| e.kind == "blocked").and_then(|e| e.payload.as_ref()).and_then(|p| p["reason"].as_str()).unwrap().to_string();
    assert!(reason.contains("[REDACTED]") && !reason.contains(secret), "block reason not redacted: {reason}");
    assert!(call_err(&block, &w, json!({"reason": "again"})).contains("could not block"));
    assert!(call_err(&block, &w, json!({"reason": "x", "kind": "because"})).contains("kind must be one of"));

    // unblock is orchestrator-only
    assert!(call_err(&tool("kanban_unblock"), &w, json!({"task_id": &a})).contains("orchestrator-only"));
    let v = call_ok(&tool("kanban_unblock"), &orch, json!({"task_id": &a}));
    assert_eq!(v["status"], "ready");

    // schedule parks the card and ends the run
    let run2 = claim_for(&d, "default", &a, &wname, "dev", "ready");
    let v = call_ok(&tool("kanban_schedule"), &w, json!({"reason": "SCHEDULED_UNTIL=2026-01-01T00:00:00Z"}));
    assert_eq!(v["status"], "scheduled");
    assert_eq!(v["run_id"].as_u64(), Some(run2));
    let t = board(&d, "default");
    assert_eq!(t.task(&a).unwrap().claim_lock, None);
    assert!(call_err(&hb, &w, json!({})).contains("could not heartbeat"), "a scheduled card is not running");
    // unblock resumes it and the schedule marker is gone
    let v = call_ok(&tool("kanban_unblock"), &orch, json!({"task_id": &a}));
    assert!(v["status"].is_string());
    assert_eq!(board(&d, "default").task(&a).unwrap().scheduled_at, None);
}

#[test]
fn worker_hands_off_for_review_and_the_reviewer_returns_changes() {
    let d = testutil::data();
    let orch = ctx(&d, "orch");
    let a = create_card(&tool("kanban_create"), &orch, "Ship the feature", json!({}));
    let impl_s = sid("impl");
    claim_for(&d, "default", &a, &impl_s, "dev", "ready");
    let w = ctx(&d, &impl_s);

    let review = tool("kanban_request_review");
    assert!(call_err(&review, &w, json!({})).contains("summary is required"));
    let v = call_ok(&review, &w, json!({"summary": "Implemented X; cargo test green", "reviewer": "rev"}));
    assert_eq!(v["status"], "review");
    assert_eq!(board(&d, "default").task(&a).unwrap().assignee.as_deref(), Some("rev"), "the named reviewer takes the card");
    let t = board(&d, "default");
    assert!(t.events_for(&a).iter().any(|e| e.kind == "review_requested"), "review handoff is on the event log");
    assert_eq!(t.task(&a).unwrap().claim_lock, None, "review releases the implementer's claim");

    // The reviewer claims the card from the review lane, then asks for changes.
    let run2 = claim_for(&d, "default", &a, "rev-session", "rev", "review");
    let r = ctx(&d, "rev-session");
    let changes = tool("kanban_request_changes");
    assert!(call_err(&changes, &r, json!({})).contains("reason is required"));
    let v = call_ok(&changes, &r, json!({"reason": "handle the empty case"}));
    assert_eq!(v["implementer"], "dev");
    assert_eq!(v["status"], "ready");
    assert_eq!(board(&d, "default").task(&a).unwrap().assignee.as_deref(), Some("dev"), "the card returns to its implementer");
    assert_eq!(v["run_id"].as_u64(), Some(run2), "the verdict closes the review run");

    // Re-review reuses the durable reviewer, then approval completes from `review`.
    claim_for(&d, "default", &a, &impl_s, "dev", "ready");
    call_ok(&review, &w, json!({"summary": "Empty case handled; tests green"}));
    assert_eq!(board(&d, "default").task(&a).unwrap().assignee.as_deref(), Some("rev"));
    claim_for(&d, "default", &a, "rev-2", "rev", "review");
    let v = call_ok(&tool("kanban_complete"), &ctx(&d, "rev-2"), json!({"summary": "Reviewed and merged"}));
    assert_eq!(v["task_id"], a.as_str());
    let t = board(&d, "default");
    assert_eq!(t.status_of(&a), Some("done"));
    assert!(t.events_for(&a).iter().any(|e| e.kind == "completed"));
    assert!(t.events_for(&a).iter().any(|e| e.kind == "changes_requested"));

    // Completing an unknown/terminal card fails with the board's own reason.
    assert!(call_err(&tool("kanban_complete"), &orch, json!({"task_id": "t_nope", "summary": "s"})).contains("could not complete"));
}

// ───────────────────────── attachments ─────────────────────────

#[test]
fn attachments_inline_url_and_listing() {
    let d = testutil::data();
    let c = ctx(&d, "orch");
    let a = create_card(&tool("kanban_create"), &c, "Report", json!({}));
    let attach = tool("kanban_attach");
    use base64::Engine;
    let bytes = b"col1,col2\n1,2\n";
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    let v = call_ok(&attach, &c, json!({"task_id": &a, "filename": "../../etc/report.csv", "content_base64": b64}));
    assert_eq!(v["size"].as_u64(), Some(bytes.len() as u64));
    assert!(call_err(&attach, &c, json!({"task_id": &a, "filename": "x.txt", "content_base64": "not base64!"})).contains("not valid base64"));

    let list = tool("kanban_attachments");
    let v = call_ok(&list, &c, json!({"task_id": &a}));
    let att = &v["attachments"][0];
    assert_eq!(att["filename"], "report.csv", "only the leaf name is kept");
    assert_eq!(att["content_type"], "text/csv", "MIME is guessed from the name");
    assert_eq!(att["uploaded_by"], "agent");
    assert_eq!(att["size"].as_u64(), Some(bytes.len() as u64));
    let root = std::fs::canonicalize(crate::kanban::attachments_dir(&d, "default", &a)).unwrap();
    let p = std::path::PathBuf::from(att["stored_path"].as_str().unwrap());
    assert!(p.starts_with(&root), "{} is not under {}", p.display(), root.display());
    assert_eq!(std::fs::read(&p).unwrap(), bytes);
    assert!(call_err(&list, &c, json!({"task_id": "t_nope"})).contains("not found"));

    // URL attach: fetched server-side, named from the URL leaf, Content-Type kept.
    let (url, seen) = serve(|path: &str| match path {
        "/files/chart.png?x=1" => Route::ok("image/png", b"PNG"),
        _ => Route::status(404),
    });
    let at = with_cfg("kanban_attach_url", KanbanConfig { attach_url_allow_private: true, ..cfg() });
    let v = call_ok(&at, &c, json!({"task_id": &a, "url": format!("{url}/files/chart.png?x=1")}));
    assert_eq!(v["size"].as_u64(), Some(3));
    let v = call_ok(&list, &c, json!({"task_id": &a}));
    assert_eq!(v["attachments"].as_array().unwrap().len(), 2);
    let url_att = &v["attachments"][1];
    assert_eq!(url_att["filename"], "chart.png");
    assert_eq!(url_att["content_type"], "image/png");
    assert_eq!(seen.lock().unwrap().as_slice(), &["/files/chart.png?x=1".to_string()]);
    // `title` is accepted as a filename alias, and an explicit type wins.
    let v = call_ok(&at, &c, json!({"task_id": &a, "url": format!("{url}/files/chart.png?x=1"), "title": "renamed.bin", "content_type": "application/x-thing"}));
    assert_eq!(v["size"].as_u64(), Some(3));
    let v = call_ok(&list, &c, json!({"task_id": &a}));
    assert_eq!(v["attachments"][2]["filename"], "renamed.bin");
    assert_eq!(v["attachments"][2]["content_type"], "application/x-thing");

    // Loopback is refused by default (SSRF guard) — no request is made.
    let before = seen.lock().unwrap().len();
    let msg = call_err(&tool("kanban_attach_url"), &c, json!({"task_id": &a, "url": format!("{url}/files/chart.png?x=1")}));
    assert!(msg.contains("SSRF"), "{msg}");
    assert_eq!(seen.lock().unwrap().len(), before, "the blocked URL never reached the server");
}

/// The production policy shape, built without the process-wide global so a test asserts
/// exactly the rules it set (`[kanban] attach_url_allow_private` is the `allow` bit).
fn fetch_policy(allow: bool) -> FetchPolicy {
    FetchPolicy { url: seagent_security::url_safety::UrlPolicy { allow_private_urls: allow, fake_ip_ranges: vec![] }, ..Default::default() }
}

#[test]
fn download_capped_caps_follows_redirects_and_rejects_bad_targets() {
    let (url, seen) = serve(|path: &str| match path {
        "/small" => Route::ok("text/plain", b"hello"),
        "/big" => Route::ok("application/octet-stream", &[b'x'; 200]),
        "/go" => Route::redirect("/small"),
        "/loop" => Route::redirect("/loop"),
        _ => Route::status(404),
    });
    let open = fetch_policy(true);
    let (body, ct) = download_capped(&format!("{url}/small"), 10, &open).unwrap();
    assert_eq!(body, b"hello");
    assert_eq!(ct.as_deref(), Some("text/plain"));
    // Exactly at the cap is allowed; one byte over is not.
    assert!(download_capped(&format!("{url}/big"), 200, &open).is_ok());
    let e = download_capped(&format!("{url}/big"), 199, &open).unwrap_err();
    assert!(e.contains("attachment exceeds") && e.contains("MB limit"), "{e}");
    // A redirect is followed and the cap still applies.
    assert_eq!(download_capped(&format!("{url}/go"), 10, &open).unwrap().0, b"hello");
    assert!(download_capped(&format!("{url}/loop"), 10, &open).unwrap_err().contains("too many redirects"));
    // Only http(s), never a private/loopback target unless explicitly allowed.
    assert!(download_capped("file:///etc/passwd", 10, &open).unwrap_err().contains("unsupported URL scheme"));
    assert!(download_capped("ftp://example.com/x", 10, &open).unwrap_err().contains("unsupported URL scheme"));
    assert!(download_capped(&format!("{url}/small"), 10, &fetch_policy(false)).unwrap_err().contains("SSRF protection"));
    assert!(download_capped(&format!("{url}/nope"), 10, &open).unwrap_err().contains("HTTP 404"));
    assert!(seen.lock().unwrap().iter().any(|p| p == "/go"), "the redirect was requested");
}

/// A redirect out of an allowed host into a blocklisted / metadata target is refused at the
/// hop check, before any connection: the target listener never sees a connection. An allowed
/// URL keeps working. This is the regression the private `public_url` re-implementation left
/// open (it only looked at the *first* hop and never re-applied the website blocklist).
#[test]
fn download_capped_refuses_blocked_redirect_hops_without_connecting() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = target.local_addr().unwrap().port();
    let hits = Arc::new(Mutex::new(0usize));
    let h2 = hits.clone();
    std::thread::spawn(move || {
        for conn in target.incoming().flatten() {
            *h2.lock().unwrap() += 1;
            drop(conn);
        }
    });
    let (url, seen) = serve(move |path: &str| match path {
        "/to-blocked" => Route::redirect(&format!("http://localhost:{port}/secret")),
        "/to-metadata" => Route::redirect("http://169.254.169.254/latest/meta-data/"),
        "/small" => Route::ok("text/plain", b"hello"),
        _ => Route::status(404),
    });
    // Private targets allowed (the LAN/test escape hatch), so only the hop rules can refuse.
    let mut p = fetch_policy(true);
    p.blocklist = seagent_security::url_safety::WebsiteBlocklist { enabled: true, domains: vec!["localhost".into()], shared_files: vec![] };
    let e = download_capped(&format!("{url}/to-blocked"), 10, &p).unwrap_err();
    assert!(e.contains("website policy") && e.contains("localhost"), "{e}");
    assert_eq!(*hits.lock().unwrap(), 0, "the blocklisted redirect target was never dialled");
    // The cloud-metadata floor still applies with private targets allowed.
    let e = download_capped(&format!("{url}/to-metadata"), 10, &p).unwrap_err();
    assert!(e.contains("metadata") && e.contains("SSRF protection"), "{e}");
    // An allowed URL still fetches.
    assert_eq!(download_capped(&format!("{url}/small"), 10, &p).unwrap().0, b"hello");
    assert_eq!(seen.lock().unwrap().last().map(String::as_str), Some("/small"));
    assert!(!seen.lock().unwrap().iter().any(|p| p == "/secret"), "no request went past the refusal");

    // The connect-time guard (the DNS-rebinding backstop) judges the dial itself, not just the
    // pre-flight resolution: with a strict policy the same loopback target is refused here too,
    // and nothing is dialled.
    let cfg = seagent_net::http::builder().http_status_as_error(false).max_redirects(0).build();
    let guarded = ureq::Agent::with_parts(cfg, ureq::unversioned::transport::DefaultConnector::default(), HopResolver { url: seagent_security::url_safety::UrlPolicy::default() });
    let e = guarded.get(&format!("http://127.0.0.1:{port}/x")).call().unwrap_err();
    assert!(matches!(&e, ureq::Error::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied && io.to_string().contains("private")), "{e}");
    assert_eq!(*hits.lock().unwrap(), 0, "the connect-time guard dialled nothing");
}

// ───────────────────────── PR acceptance through `kanban_complete` ─────────────────────────

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn gh_graphql() -> String {
    json!({"data": {"repository": {"pullRequest": {"headRefOid": SHA, "baseRefName": "main", "state": "OPEN", "baseRef": {"branchProtectionRule": {"requiredStatusChecks": [{"context": "ci", "app": {"databaseId": 15368}}]}}}}}}).to_string()
}

/// GitHub fake: one required check (`ci`, app 15368) on the exact head `SHA`.
fn gh_router(conclusion: &'static str) -> impl Fn(&str) -> Route + Send + 'static {
    move |path: &str| {
        if path.starts_with("/graphql") {
            Route::json(&gh_graphql())
        } else if path.contains("/rules/branches/main") {
            Route::json("[]")
        } else if path.contains("/check-runs") {
            Route::json(&json!({"total_count": 1, "check_runs": [{"id": 1, "name": "ci", "app": {"id": 15368}, "head_sha": SHA, "status": "completed", "conclusion": conclusion, "html_url": "https://ci.example/1"}]}).to_string())
        } else if path.contains("/commits/") && path.contains("/statuses") {
            Route::json("[]")
        } else if path.starts_with("/repos/o/r/pulls/7") {
            Route::json(&json!({"head": {"sha": SHA}, "base": {"ref": "main"}, "state": "open"}).to_string())
        } else {
            Route::status(404)
        }
    }
}

fn gh_cfg(api: &str) -> KanbanConfig {
    KanbanConfig { github_api: api.into(), github_token: "tok".into(), ..cfg() }
}

#[test]
fn complete_gates_on_exact_head_pr_acceptance() {
    let d = testutil::data();
    let orch = ctx(&d, "orch");
    let create = tool("kanban_create");
    let (green, seen) = serve(gh_router("success"));

    // 1. A PR-contract card completes only with a matching published PR and green checks.
    let a = create_card(&create, &orch, "Ship the PR", json!({"completion_contract": "o/r"}));
    claim_for(&d, "default", &a, "pr-worker", "dev", "ready");
    let w = ctx(&d, "pr-worker");
    let complete = with_cfg("kanban_complete", gh_cfg(&green));
    let v = call_ok(&complete, &w, json!({"summary": "published", "metadata": {"published_pr": "https://github.com/o/r/pull/7"}}));
    assert_eq!(v["task_id"], a.as_str());
    let t = board(&d, "default");
    assert_eq!(t.status_of(&a), Some("done"));
    let receipt = t.events_for(&a).into_iter().find(|e| e.kind == "pr_acceptance").and_then(|e| e.payload.clone()).expect("pr_acceptance receipt");
    assert_eq!(receipt["ok"], true);
    assert_eq!(receipt["classification"], "success");
    assert_eq!(receipt["head_sha"], SHA);
    assert_eq!(t.task(&a).unwrap().completion_contract.as_deref(), Some("https://github.com/o/r/pull/7"), "publication binds once");
    assert!(seen.lock().unwrap().iter().any(|p| p.starts_with("/graphql")), "the acceptance read really happened");

    // 2. Without a published PR the OWNER/REPO contract cannot complete.
    let b = create_card(&create, &orch, "No PR yet", json!({"completion_contract": "o/r"}));
    claim_for(&d, "default", &b, "pr-worker-2", "dev", "ready");
    let msg = call_err(&complete, &ctx(&d, "pr-worker-2"), json!({"summary": "done anyway"}));
    assert!(msg.contains("published_pr"), "{msg}");
    assert_eq!(board(&d, "default").status_of(&b), Some("running"), "a refused completion changes nothing");

    // 3. A red required check refuses completion and leaves the failure on the card.
    let (red, _) = serve(gh_router("failure"));
    let ccard = create_card(&create, &orch, "Red CI", json!({"completion_contract": "https://github.com/o/r/pull/7"}));
    claim_for(&d, "default", &ccard, "pr-worker-3", "dev", "ready");
    let msg = call_err(&with_cfg("kanban_complete", gh_cfg(&red)), &ctx(&d, "pr-worker-3"), json!({"summary": "please"}));
    assert!(msg.contains("PR acceptance"), "{msg}");
    let t = board(&d, "default");
    assert_eq!(t.status_of(&ccard), Some("running"));
    assert!(t.task(&ccard).unwrap().last_failure_error.as_deref().unwrap_or("").contains("PR acceptance"));

    // 4. An unreachable API is reported without leaking response bodies.
    let (auth, _) = serve(|_: &str| Route::status(404));
    let dcard = create_card(&create, &orch, "Auth broken", json!({"completion_contract": "https://github.com/o/r/pull/9"}));
    claim_for(&d, "default", &dcard, "pr-worker-4", "dev", "ready");
    let msg = call_err(&with_cfg("kanban_complete", gh_cfg(&auth)), &ctx(&d, "pr-worker-4"), json!({"summary": "s"}));
    assert!(msg.contains("GitHub"), "{msg}");
    assert!(!msg.contains("{}"), "response bodies are never echoed: {msg}");
    assert!(call_err(&create, &orch, json!({"title": "bad contract", "assignee": "dev", "completion_contract": "https://evil.com/o/r/pull/1"})).contains("completion_contract must be"));
}

// ───────────────────────── token redaction on the board itself ─────────────────────────

#[test]
fn secrets_never_reach_the_board_file() {
    let d = testutil::data();
    let c = ctx(&d, "orch");
    let a = create_card(&tool("kanban_create"), &c, "Secret hygiene", json!({}));
    let gh = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    let anthropic = "sk-ant-abcdefghijklmnopqrstuvwx";
    call_ok(&tool("kanban_comment"), &c, json!({"task_id": &a, "body": format!("{gh} and {anthropic}")}));
    call_ok(&tool("kanban_complete"), &c, json!({"task_id": &a, "summary": format!("used {gh}"), "metadata": {"token": gh}}));
    let raw = std::fs::read_to_string(store::board_file(&d, "default")).unwrap();
    assert!(!raw.contains(gh), "a GitHub token reached the board file");
    assert!(!raw.contains(anthropic), "an Anthropic key reached the board file");
    assert!(raw.contains("[REDACTED]"));
}

// ───────────────────────── several boards: a worker stays on its own board ─────────────────────────

#[test]
fn a_dispatched_worker_uses_its_own_board_not_the_current_pointer() {
    let d = testutil::data();
    let orch = ctx(&d, "orch");
    // A second board exists while `default` stays the current pointer (the daemon ticks
    // every board, so a worker's board is not necessarily the current one).
    crate::kanban::boards::create_board(&d, "proj", board_meta()).unwrap();
    assert_eq!(crate::kanban::current_board(&d), "default");

    let card = create_card(&tool("kanban_create"), &orch, "On proj", json!({"board": "proj"}));
    claim_for(&d, "proj", &card, "proj-worker", "dev", "ready");
    let w = ctx(&d, "proj-worker");

    // No `board` argument: `Live.slug` decides, so the completion lands on `proj`.
    call_ok(&tool("kanban_complete"), &w, json!({"summary": "done"}));
    assert_eq!(board(&d, "proj").status_of(&card), Some("done"));
    assert!(board(&d, "default").task(&card).is_none(), "the current board must stay untouched");

    // Effects name the worker's board as well, so approval/audit paths see the same file.
    let eff = tool("kanban_complete").effects(&w, &json!({"summary": "again"}));
    let Effect::Write { path } = &eff[0] else { panic!("kanban_complete must write the board: {eff:?}") };
    assert_eq!(path.file_name().and_then(|n| n.to_str()), Some("proj"), "effect points at the current board instead: {}", path.display());

    // An explicit `board` argument still wins (upstream: the call overrides the worker's board).
    call_ok(&tool("kanban_comment"), &w, json!({"task_id": &create_card(&tool("kanban_create"), &orch, "Other", json!({})), "body": "hi", "board": "default"}));
    assert!(board(&d, "default").task(&card).is_none());
}

fn board_meta() -> crate::kanban::boards::MetaPatch {
    crate::kanban::boards::MetaPatch { name: Some("Proj".into()), ..Default::default() }
}
