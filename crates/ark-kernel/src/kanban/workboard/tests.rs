//! Tool-layer tests for the OpenClaw `workboard_*` vocabulary: every name is reachable
//! through `WorkboardTool::call`, and the card / notification / sessions-board
//! roundtrips work on a temp data dir.

use super::*;
use crate::kanban::testutil::{self, ctx};
use ark_core::ToolCtx;
use serde_json::{json, Value};
use std::path::Path;

fn cfg() -> KanbanConfig {
    KanbanConfig { enabled: true, ..Default::default() }
}
fn tool(name: &'static str) -> WorkboardTool {
    WorkboardTool { name, cfg: cfg() }
}
fn call_ok(t: &WorkboardTool, c: &ToolCtx, args: Value) -> Value {
    let out = t.call(c, args);
    assert!(!out.is_error, "{} returned an error: {}", t.name, out.content);
    serde_json::from_str(&out.content).unwrap_or_else(|e| panic!("{} returned non-JSON ({e}): {}", t.name, out.content))
}
fn call_err(t: &WorkboardTool, c: &ToolCtx, args: Value) -> String {
    let out = t.call(c, args);
    assert!(out.is_error, "{} was expected to fail but returned: {}", t.name, out.content);
    out.content
}
fn board(data: &Path, slug: &str) -> BoardData {
    store::read_board(data, slug).unwrap()
}
fn create(c: &ToolCtx, board_id: &str, title: &str, extra: Value) -> String {
    let mut args = json!({"boardId": board_id, "title": title, "agentId": "dev"});
    if let Some(o) = extra.as_object() {
        args.as_object_mut().unwrap().extend(o.clone());
    }
    call_ok(&tool("workboard_create"), c, args)["card"]["id"].as_str().expect("card id").to_string()
}
fn claim(c: &ToolCtx, id: &str) -> String {
    let v = call_ok(&tool("workboard_claim"), c, json!({"id": id}));
    assert_eq!(v["card"]["status"], "running");
    v["token"].as_str().unwrap().to_string()
}
fn proj(c: &ToolCtx) -> String {
    call_ok(&tool("workboard_board_create"), c, json!({"id": "proj", "name": "Project", "description": "cards board"}));
    "proj".to_string()
}

// ───────────────────────── schema surface ─────────────────────────

/// `required` for the names that carry one (everything else accepts no mandatory arg).
const REQUIRED: &[(&str, &[&str])] = &[
    ("workboard_create", &["title"]),
    ("workboard_link", &["parentId", "childId"]),
    ("workboard_read", &["id"]),
    ("workboard_claim", &["id"]),
    ("workboard_heartbeat", &["id"]),
    ("workboard_release", &["id"]),
    ("workboard_comment", &["id", "body"]),
    ("workboard_proof", &["id"]),
    ("workboard_complete", &["id"]),
    ("workboard_attachment_add", &["id", "fileName", "contentBase64"]),
    ("workboard_attachment_read", &["id"]),
    ("workboard_attachment_delete", &["id", "attachmentId"]),
    ("workboard_block", &["id"]),
    ("workboard_unblock", &["id"]),
    ("workboard_move", &["id", "status"]),
    ("workboard_board_create", &["id"]),
    ("workboard_board_archive", &["id"]),
    ("workboard_board_delete", &["id"]),
    ("workboard_runs", &["id"]),
    ("workboard_specify", &["id"]),
    ("workboard_decompose", &["id", "children"]),
    ("workboard_notify_advance", &["subscriptionId"]),
    ("workboard_notify_unsubscribe", &["id"]),
    ("workboard_promote", &["id"]),
    ("workboard_reassign", &["id"]),
    ("workboard_reclaim", &["id"]),
    ("workboard_worker_log", &["id", "message"]),
    ("workboard_protocol_violation", &["id"]),
    ("workboard_sessions_board_move", &["sessionKey", "columnId"]),
];

#[test]
fn every_name_has_a_schema_and_is_dispatchable() {
    // OpenClaw registers 38 `workboard_*` tools; ark mirrors them 1:1.
    assert_eq!(NAMES.len(), 38, "OpenClaw workboard tool count");
    let uniq: std::collections::BTreeSet<&str> = NAMES.iter().copied().collect();
    assert_eq!(uniq.len(), NAMES.len(), "duplicate names in NAMES");
    for name in NAMES {
        assert!(name.starts_with("workboard_"), "{name} is not a workboard tool");
        let (desc, props, req) = schema(name);
        assert!(!desc.trim().is_empty(), "{name} has no description");
        let props = props.as_object().unwrap_or_else(|| panic!("{name} schema properties are not an object"));
        for r in &req {
            assert!(props.contains_key(*r), "{name}: required field {r} is not in properties");
        }
        let spec = tool(name).spec();
        assert_eq!(spec.name, *name);
        assert_eq!(spec.input_schema["type"], "object");
        assert_eq!(spec.input_schema["additionalProperties"], false, "{name} must reject unknown keys");
        assert_eq!(spec.parallel_safe, READ_ONLY.contains(name), "{name} parallel_safe");
        assert_eq!(spec.idempotent, READ_ONLY.contains(name), "{name} idempotent");
        assert!(!spec.pinned, "{name} is reached via the tool index, not pinned");
    }
    for (name, want) in REQUIRED {
        let (_, _, req) = schema(name);
        assert_eq!(&req[..], *want, "{name} required fields");
        assert!(props_has(name, want), "{name}: a required field is missing from properties");
    }
    // The two vocabularies' tool sets.
    let all: Vec<String> = all_tools(&cfg()).iter().map(|t| t.spec().name).collect();
    assert_eq!(all, NAMES.iter().map(|s| s.to_string()).collect::<Vec<_>>(), "all_tools mirrors NAMES");
    let w: Vec<String> = worker_tools(&cfg()).iter().map(|t| t.spec().name).collect();
    assert_eq!(w, WORKER.iter().map(|s| s.to_string()).collect::<Vec<_>>(), "a worker gets exactly the card verbs");
    for n in &w {
        assert!(NAMES.contains(&n.as_str()));
    }

    // Every name is really dispatched (no arm missing) — an empty call reaches the
    // handler and fails on its own required arguments, never on an unknown tool.
    let d = testutil::data();
    let c = ctx(&d, "wb-smoke");
    for name in NAMES {
        let out = tool(name).call(&c, json!({}));
        assert!(!out.content.contains("unknown workboard tool"), "{name} fell through the dispatcher: {}", out.content);
    }
    // Typos are refused before anything is written.
    let msg = call_err(&tool("workboard_create"), &c, json!({"title": "x", "agentid": "dev"}));
    assert!(msg.contains("unexpected parameter(s): agentid"), "{msg}");
}

fn props_has(name: &str, fields: &[&str]) -> bool {
    let props = schema(name).1;
    fields.iter().all(|f| props.get(*f).is_some())
}

// ───────────────────────── boards + card lifecycle ─────────────────────────

#[test]
fn board_and_card_lifecycle() {
    let d = testutil::data();
    let c = ctx(&d, "ag-1");
    let slug = proj(&c);
    let v = call_ok(&tool("workboard_boards"), &c, json!({}));
    assert!(v["boards"].as_array().unwrap().iter().any(|b| b["id"] == slug.as_str()), "{v}");
    assert_eq!(v["boards"][0]["kind"], "cards");

    // create: landing status, priority label, metadata links
    let id = create(&c, &slug, "Fix the flaky test", json!({"notes": "repro first", "priority": "high", "labels": ["ci"], "skills": ["rust"]}));
    let card = call_ok(&tool("workboard_read"), &c, json!({"id": &id}));
    assert_eq!(card["card"]["title"], "Fix the flaky test");
    assert_eq!(card["card"]["notes"], "repro first");
    assert_eq!(card["card"]["status"], "ready");
    assert_eq!(card["card"]["priority"], "high");
    assert_eq!(card["card"]["agentId"], "dev");
    assert_eq!(card["card"]["metadata"]["automation"]["skills"], json!(["rust"]));
    assert!(card["workerContext"].as_str().unwrap().contains("Fix the flaky test"));
    assert!(call_err(&tool("workboard_read"), &c, json!({"id": "t_missing"})).contains("card not found"));

    let list = call_ok(&tool("workboard_list"), &c, json!({"boardId": &slug}));
    assert_eq!(list["cards"].as_array().unwrap().len(), 1);
    assert_eq!(list["cards"][0]["id"], id.as_str());
    assert_eq!(call_ok(&tool("workboard_list"), &c, json!({"agentId": "nobody"}))["cards"].as_array().unwrap().len(), 0);
    assert_eq!(call_ok(&tool("workboard_list"), &c, json!({"status": "done"}))["cards"].as_array().unwrap().len(), 0);

    // claim → running + a one-time token that every later read redacts
    let token = claim(&c, &id);
    let card = call_ok(&tool("workboard_read"), &c, json!({"id": &id}));
    assert_eq!(card["card"]["metadata"]["claim"]["token"], "[redacted]");
    assert_eq!(card["card"]["metadata"]["claim"]["ownerId"], "ag-1");
    assert_eq!(card["card"]["metadata"]["attempts"].as_array().unwrap().len(), 1);
    // Another agent cannot touch a claimed card without the token.
    let other = ctx(&d, "ag-2");
    assert!(call_err(&tool("workboard_comment"), &other, json!({"id": &id, "body": "hi"})).contains("claimed by"));
    assert!(call_err(&tool("workboard_claim"), &other, json!({"id": &id})).contains("already claimed"));

    // heartbeat: refreshes the claim and keeps the note in the thread
    let v = call_ok(&tool("workboard_heartbeat"), &c, json!({"id": &id, "token": &token, "note": "halfway"}));
    assert!(v["card"]["metadata"]["comments"].as_array().unwrap().iter().any(|x| x["body"] == "halfway"), "{v}");
    assert!(call_err(&tool("workboard_heartbeat"), &other, json!({"id": &id})).contains("claimed by"));

    // comment + proof
    let v = call_ok(&tool("workboard_comment"), &c, json!({"id": &id, "token": &token, "body": "found it"}));
    assert!(v["card"]["metadata"]["comments"].as_array().unwrap().iter().any(|x| x["body"] == "found it"));
    let proof = call_ok(&tool("workboard_proof"), &c, json!({"id": &id, "token": &token, "status": "passed", "label": "ci", "command": "cargo test", "url": "https://ci.example/1"}));
    let proof_id = proof["proofId"].as_str().unwrap().to_string();
    assert!(call_err(&tool("workboard_proof"), &c, json!({"id": &id, "status": "great"})).contains("proof status must be"));
    assert!(call_err(&tool("workboard_proof"), &c, json!({"id": &id, "url": "ftp://x/1"})).contains("proof url must be http"));

    // complete resolves the pending proof in place and stores the summary
    let v = call_ok(&tool("workboard_complete"), &c, json!({"id": &id, "token": &token, "summary": "green on main", "proofId": &proof_id}));
    assert_eq!(v["card"]["status"], "done");
    assert_eq!(v["card"]["metadata"]["proof"][0]["id"], proof_id.as_str());
    assert_eq!(v["card"]["metadata"]["proof"][0]["status"], "passed");
    assert_eq!(v["card"]["metadata"]["automation"]["summary"], "green on main");
    assert!(v["card"]["metadata"]["comments"].as_array().unwrap().iter().any(|x| x["body"] == "green on main"));
    assert!(call_err(&tool("workboard_complete"), &c, json!({"id": &id, "summary": "again"})).contains("must be claimed"));

    // stats / runs / boards see the finished card
    let v = call_ok(&tool("workboard_stats"), &c, json!({"boardId": &slug}));
    assert_eq!(v["stats"]["by_status"]["done"], 1);
    assert_eq!(v["stats"]["total"], 1);
    let v = call_ok(&tool("workboard_runs"), &c, json!({"id": &id}));
    assert_eq!(v["attempts"].as_array().unwrap().len(), 1);
}

#[test]
fn block_unblock_move_promote_and_link() {
    let d = testutil::data();
    let c = ctx(&d, "ag-1");
    let slug = proj(&c);
    let id = create(&c, &slug, "Blocked card", json!({}));
    let token = claim(&c, &id);

    // block: reason kept, claim released, no silent re-claim
    let v = call_ok(&tool("workboard_block"), &c, json!({"id": &id, "token": &token, "reason": "waiting on the design"}));
    assert_eq!(v["card"]["status"], "blocked");
    assert_eq!(v["card"]["metadata"]["claim"], Value::Null);
    assert!(v["card"]["metadata"]["comments"].as_array().unwrap().iter().any(|x| x["body"] == "waiting on the design"));
    assert!(call_err(&tool("workboard_claim"), &c, json!({"id": &id})).contains("blocked"));
    assert!(call_err(&tool("workboard_block"), &c, json!({"id": &id})).contains("must be claimed"));

    // unblock: back to todo (never straight to ready without promotion)
    let v = call_ok(&tool("workboard_unblock"), &c, json!({"id": &id}));
    assert_eq!(v["card"]["status"], "todo");
    assert!(call_err(&tool("workboard_unblock"), &c, json!({"id": &id})).contains("not blocked"));

    // move: validates the target status, then promote forces it past holds
    assert!(call_err(&tool("workboard_move"), &c, json!({"id": &id, "status": "nope"})).contains("status must be one of"));
    let v = call_ok(&tool("workboard_move"), &c, json!({"id": &id, "status": "scheduled"}));
    assert_eq!(v["card"]["status"], "scheduled");
    call_ok(&tool("workboard_move"), &c, json!({"id": &id, "status": "todo"}));
    let v = call_ok(&tool("workboard_promote"), &c, json!({"id": &id, "force": true, "reason": "operator says go"}));
    assert_eq!(v["card"]["status"], "ready");
    assert_eq!(v["card"]["metadata"]["automation"]["scheduledAt"], Value::Null);
    // Only todo cards can be promoted.
    assert!(call_err(&tool("workboard_promote"), &c, json!({"id": &id})).contains("only todo cards can be promoted"));

    // link: a child of an open parent waits in todo, and dependency gating is reported
    let parent = create(&c, &slug, "Parent", json!({}));
    let child = create(&c, &slug, "Child", json!({"parents": [parent]}));
    let v = call_ok(&tool("workboard_read"), &c, json!({"id": &child}));
    assert_eq!(v["card"]["status"], "todo");
    assert!(v["card"]["metadata"]["links"].as_array().unwrap().iter().any(|l| l["type"] == "parent" && l["targetCardId"] == parent.as_str()));
    assert!(call_err(&tool("workboard_claim"), &c, json!({"id": &child})).contains("dependencies are not done"));
    // Linking after the fact works too.
    let late = create(&c, &slug, "Late child", json!({}));
    let v = call_ok(&tool("workboard_link"), &c, json!({"parentId": &parent, "childId": &late}));
    assert_eq!(v["card"]["status"], "todo");
    assert!(call_err(&tool("workboard_link"), &c, json!({"parentId": &late, "childId": &parent})).contains("cycle"));
    // Finishing the parent releases both children.
    let token = claim(&c, &parent);
    call_ok(&tool("workboard_complete"), &c, json!({"id": &parent, "token": &token, "summary": "parent done"}));
    assert_eq!(board(&d, &slug).status_of(&child), Some("ready"));
    assert_eq!(board(&d, &slug).status_of(&late), Some("ready"));

    // release returns an unclaimed-but-running card to the queue
    let token = claim(&c, &child);
    let v = call_ok(&tool("workboard_release"), &c, json!({"id": &child, "token": &token}));
    assert_ne!(v["card"]["status"], "running");
    let v = call_ok(&tool("workboard_reassign"), &c, json!({"id": &child, "agentId": "writer", "reason": "reroute"}));
    assert_eq!(v["card"]["agentId"], "writer");
    let v = call_ok(&tool("workboard_worker_log"), &c, json!({"id": &child, "level": "info", "message": "started"}));
    assert_eq!(v["card"]["metadata"]["workerLogs"][0]["message"], "started");
    assert!(call_err(&tool("workboard_worker_log"), &c, json!({"id": &child, "level": "chatty", "message": "x"})).contains("level must be"));
}

#[test]
fn attachments_proofs_and_claim_reclaim() {
    let d = testutil::data();
    let c = ctx(&d, "ag-1");
    let slug = proj(&c);
    let id = create(&c, &slug, "Attachment card", json!({}));
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(b"hello workboard");
    let v = call_ok(&tool("workboard_attachment_add"), &c, json!({"id": &id, "fileName": "notes.txt", "contentBase64": b64, "note": "the notes"}));
    let att = &v["card"]["metadata"]["attachments"][0];
    let aid = att["id"].as_str().unwrap().to_string();
    assert_eq!(att["fileName"], "notes.txt");
    assert_eq!(att["size"].as_u64(), Some(15));
    assert_eq!(att["mimeType"], "text/plain");
    let v = call_ok(&tool("workboard_attachment_read"), &c, json!({"id": &aid}));
    assert_eq!(v["fileName"], "notes.txt");
    assert_eq!(v["contentBase64"], b64);
    assert!(call_err(&tool("workboard_attachment_add"), &c, json!({"id": &id, "fileName": "x", "contentBase64": "%%"})).contains("not valid base64"));
    let v = call_ok(&tool("workboard_attachment_delete"), &c, json!({"id": &id, "attachmentId": &aid}));
    assert!(v["card"]["metadata"]["attachments"].as_array().unwrap().is_empty());

    // reclaim: a claimed card can be released by an operator and picked up again
    let _token = claim(&c, &id);
    let v = call_ok(&tool("workboard_reclaim"), &c, json!({"id": &id, "reason": "stale worker"}));
    assert_ne!(v["card"]["status"], "running");
    assert_eq!(v["card"]["metadata"]["claim"], Value::Null);
    assert!(v["card"]["metadata"]["comments"].as_array().unwrap().iter().any(|x| x["body"] == "stale worker"));

    // protocol violation blocks the card with a reason
    let _token = claim(&c, &id);
    let v = call_ok(&tool("workboard_protocol_violation"), &c, json!({"id": &id, "detail": "stopped silently"}));
    assert_eq!(v["card"]["status"], "blocked");
    // The violation is on the event log (with its detail) and on the block reason.
    let b = board(&d, &slug);
    assert!(b.events_for(&id).iter().any(|e| e.kind == "protocol_violation" && e.payload.as_ref().unwrap()["detail"] == "stopped silently"), "no protocol_violation event");
    let reason = b.events_for(&id).into_iter().rev().find(|e| e.kind == "blocked").and_then(|e| e.payload.as_ref()).and_then(|p| p["reason"].as_str()).unwrap_or("").to_string();
    assert!(reason.contains("protocol violation") && reason.contains("stopped silently"), "{reason}");
}

// ───────────────────────── notifications ─────────────────────────

#[test]
fn notify_subscribe_events_and_advance() {
    let d = testutil::data();
    let c = ctx(&d, "ag-1");
    let slug = proj(&c);
    let id = create(&c, &slug, "Notified card", json!({}));
    let token = claim(&c, &id);
    let v = call_ok(&tool("workboard_notify_subscribe"), &c, json!({"boardId": &slug, "cardId": &id, "sessionKey": "s-1", "eventKinds": ["completed"]}));
    let sub = v["subscription"]["id"].as_str().unwrap().to_string();
    assert_eq!(v["subscription"]["cardId"], id.as_str());
    assert_eq!(v["subscription"]["eventKinds"], json!(["completed"]));
    let list = call_ok(&tool("workboard_notify_list"), &c, json!({"cardId": &id}));
    assert_eq!(list["subscriptions"][0]["id"], sub.as_str());

    // Nothing yet: the cursor starts at the head of the log.
    let v = call_ok(&tool("workboard_notify_events"), &c, json!({"subscriptionId": &sub}));
    assert!(v["events"].as_array().unwrap().is_empty(), "{v}");

    call_ok(&tool("workboard_complete"), &c, json!({"id": &id, "token": &token, "summary": "done"}));
    let v = call_ok(&tool("workboard_notify_events"), &c, json!({"subscriptionId": &sub}));
    assert_eq!(v["events"].as_array().unwrap().len(), 1);
    assert_eq!(v["events"][0]["kind"], "completed");
    assert_eq!(v["events"][0]["cardId"], id.as_str());
    // Reading is replay-safe; advancing moves the cursor past the delivered event.
    assert_eq!(call_ok(&tool("workboard_notify_events"), &c, json!({"subscriptionId": &sub}))["events"].as_array().unwrap().len(), 1);
    let v = call_ok(&tool("workboard_notify_advance"), &c, json!({"subscriptionId": &sub}));
    assert_eq!(v["events"].as_array().unwrap().len(), 1);
    assert!(v["cursor"].as_u64().unwrap() > 0);
    assert!(call_ok(&tool("workboard_notify_events"), &c, json!({"subscriptionId": &sub}))["events"].as_array().unwrap().is_empty());
    // Unsubscribing removes it.
    assert_eq!(call_ok(&tool("workboard_notify_unsubscribe"), &c, json!({"id": &sub}))["deleted"], true);
    assert!(call_ok(&tool("workboard_notify_list"), &c, json!({"cardId": &id}))["subscriptions"].as_array().unwrap().is_empty());
    assert!(call_err(&tool("workboard_notify_advance"), &c, json!({"subscriptionId": "sub_missing"})).contains("subscription not found"));
}

// ───────────────────────── specify / decompose ─────────────────────────

#[test]
fn specify_and_decompose() {
    let d = testutil::data();
    let c = ctx(&d, "ag-1");
    let slug = proj(&c);

    // specify: a triage card becomes a specified todo/ready card
    let vague = create(&c, &slug, "make it better", json!({"status": "triage"}));
    assert!(call_err(&tool("workboard_specify"), &c, json!({"id": &vague, "priority": "later"})).contains("priority must be one of"));
    let v = call_ok(&tool("workboard_specify"), &c, json!({"id": &vague, "title": "Speed up the loader", "notes": "**Goal** <2s", "agentId": "writer", "priority": "urgent", "labels": ["perf"], "summary": "speced from triage"}));
    assert_eq!(v["card"]["title"], "Speed up the loader");
    assert_eq!(v["card"]["notes"], "**Goal** <2s");
    assert_eq!(v["card"]["priority"], "urgent");
    assert_eq!(v["card"]["agentId"], "writer");
    assert_eq!(v["card"]["status"], "ready");
    assert!(v["card"]["metadata"]["comments"].as_array().unwrap().iter().any(|x| x["body"] == "speced from triage"));
    // Only triage/backlog/todo cards may be specified.
    assert!(call_err(&tool("workboard_specify"), &c, json!({"id": &vague})).contains("only triage, backlog, or todo"));

    // decompose: children are linked to the parent, which completes by default
    let root = create(&c, &slug, "Ship the release", json!({"status": "todo"}));
    assert!(call_err(&tool("workboard_decompose"), &c, json!({"id": &root, "children": []})).contains("children are required"));
    let v = call_ok(&tool("workboard_decompose"), &c, json!({"id": &root, "summary": "split into two", "children": [{"title": "Write the notes", "agentId": "dev"}, {"title": "Tag the build", "agentId": "dev"}]}));
    assert_eq!(v["parent"]["status"], "done");
    let kids: Vec<String> = v["children"].as_array().unwrap().iter().map(|k| k["id"].as_str().unwrap().to_string()).collect();
    assert_eq!(kids.len(), 2);
    for k in &kids {
        assert_eq!(v["children"].as_array().unwrap().iter().find(|x| x["id"] == k.as_str()).unwrap()["status"], "ready");
        assert!(board(&d, &slug).parent_ids(k).contains(&root));
    }
    assert!(v["parent"]["metadata"]["automation"]["createdCardIds"].as_array().unwrap().len() == 2);

    // completeParent=false keeps the parent open for the orchestrator.
    let root2 = create(&c, &slug, "Keep me open", json!({}));
    let v = call_ok(&tool("workboard_decompose"), &c, json!({"id": &root2, "completeParent": false, "children": [{"title": "only child"}]}));
    assert_ne!(v["parent"]["status"], "done");
    let kid = v["children"][0]["id"].as_str().unwrap().to_string();
    assert_eq!(board(&d, &slug).status_of(&kid), Some("todo"), "a child of an open parent waits");
}

// ───────────────────────── sessions boards ─────────────────────────

#[test]
fn sessions_boards_read_update_and_move() {
    let d = testutil::data();
    let c = ctx(&d, "ag-1");
    // No Sessions board yet: card tools and the read both say so clearly.
    assert!(call_err(&tool("workboard_sessions_board_read"), &c, json!({})).contains("No Sessions board exists"));
    call_ok(&tool("workboard_board_create"), &c, json!({"id": "ops", "kind": "sessions", "name": "Ops"}));

    let v = call_ok(&tool("workboard_sessions_board_read"), &c, json!({"boardId": "ops"}));
    assert_eq!(v["board"]["kind"], "sessions");
    assert_eq!(v["columns"].as_array().unwrap().len(), 6, "the default spec ships six columns");
    assert_eq!(v["sessions"].as_array().unwrap().len(), 0);
    assert_eq!(v["total"], 0);

    // update replaces the ordered columns (exactly one fallback is required)
    let cols = json!([
        {"id": "active", "label": "Active", "description": "Runs in flight", "match": {"run": ["active"]}},
        {"id": "idle", "label": "Idle", "description": "Everything else", "fallback": true}
    ]);
    let v = call_ok(&tool("workboard_sessions_board_update"), &c, json!({"boardId": "ops", "columns": cols.clone()}));
    assert_eq!(v["board"]["sessions"]["columns"].as_array().unwrap().len(), 2);
    assert!(call_err(&tool("workboard_sessions_board_update"), &c, json!({"boardId": "ops", "columns": [{"id": "x", "label": "X", "description": "d"}]})).contains("2..12"));
    assert!(call_err(&tool("workboard_sessions_board_update"), &c, json!({"boardId": "ops", "columns": [{"id": "x", "label": "X", "description": "d"}, {"id": "y", "label": "Y", "description": "d"}]})).contains("fallback"));
    assert!(call_err(&tool("workboard_sessions_board_update"), &c, json!({"boardId": "ops", "scope": {"nope": 1}})).contains("Unknown scope field"));

    // move pins a session into a column
    let v = call_ok(&tool("workboard_sessions_board_move"), &c, json!({"boardId": "ops", "sessionKey": "sess-1", "columnId": "active"}));
    assert_eq!(v["columns"].as_array().unwrap().len(), 2);
    let b = board(&d, "ops");
    assert!(b.placements.iter().any(|p| p.session_key == "sess-1" && p.column_id == "active"), "{:?}", b.placements);
    assert!(call_err(&tool("workboard_sessions_board_move"), &c, json!({"boardId": "ops", "sessionKey": "sess-1", "columnId": "ghost"})).contains("column not found"));
    // Re-pinning the same session replaces its placement instead of duplicating it.
    call_ok(&tool("workboard_sessions_board_move"), &c, json!({"boardId": "ops", "sessionKey": "sess-1", "columnId": "idle"}));
    let b = board(&d, "ops");
    assert_eq!(b.placements.iter().filter(|p| p.session_key == "sess-1").count(), 1);
    assert_eq!(b.placements[0].column_id, "idle");

    // Sessions boards hold no cards.
    assert!(call_err(&tool("workboard_create"), &c, json!({"boardId": "ops", "title": "nope"})).contains("Sessions board"));
    // A cards board cannot be read as a Sessions board.
    proj(&c);
    assert!(call_err(&tool("workboard_sessions_board_read"), &c, json!({"boardId": "proj"})).contains("not a Sessions board"));
}

// ───────────────────────── board lifecycle + dispatch ─────────────────────────

#[test]
fn board_archive_delete_and_dispatch_tick() {
    let d = testutil::data();
    let c = ctx(&d, "ag-1");
    let slug = proj(&c);
    let id = create(&c, &slug, "Blocked forever", json!({}));
    let token = claim(&c, &id);
    call_ok(&tool("workboard_block"), &c, json!({"id": &id, "token": &token, "reason": "needs a human"}));

    // dispatch advances persisted state without launching workers.
    let v = call_ok(&tool("workboard_dispatch"), &c, json!({"boardId": &slug}));
    assert!(v["boards"].is_array(), "{v}");

    // a non-empty board cannot be deleted; the default board never can be either
    assert!(call_err(&tool("workboard_board_delete"), &c, json!({"id": &slug})).contains("still contains cards"));
    assert!(call_err(&tool("workboard_board_delete"), &c, json!({"id": "default"})).contains("default board"));
    assert!(call_err(&tool("workboard_board_archive"), &c, json!({"id": "default"})).contains("default board"));
    // archive hides the board from the default listing, restore brings it back
    let v = call_ok(&tool("workboard_board_archive"), &c, json!({"id": &slug}));
    assert_eq!(v["board"]["archived"], true);
    let v = call_ok(&tool("workboard_boards"), &c, json!({}));
    assert_eq!(v["boards"].as_array().unwrap().iter().find(|b| b["id"] == slug.as_str()).unwrap()["archived"], true);
    let v = call_ok(&tool("workboard_board_archive"), &c, json!({"id": &slug, "archived": false}));
    assert_eq!(v["board"]["archived"], false);

    // an empty board can be deleted
    call_ok(&tool("workboard_board_create"), &c, json!({"id": "empty-board"}));
    let v = call_ok(&tool("workboard_board_delete"), &c, json!({"id": "empty-board"}));
    assert_eq!(v["deleted"], true);
}
