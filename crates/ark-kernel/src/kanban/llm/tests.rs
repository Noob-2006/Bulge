//! Triage helpers driven by the aux model: `specify_task` (one-liner → spec) and
//! `decompose_task` (triage card → routed child graph), plus the ARP method path the
//! dashboard and `ark kanban specify|decompose` share. The model is scripted, so every
//! assertion is about board state and prompt content, never about a live provider.

use super::*;
use crate::kanban::ops::{self, NewTask};
use crate::kanban::{boards, testutil, KanbanProfile};

fn profiles(names: &[(&str, &str)]) -> std::collections::BTreeMap<String, KanbanProfile> {
    names.iter().map(|(n, d)| (n.to_string(), KanbanProfile { description: d.to_string(), ..Default::default() })).collect()
}

fn setup(cfg: impl FnOnce(&mut KanbanConfig)) -> (crate::kernel::Kernel, std::sync::Arc<testutil::Scripted>, std::path::PathBuf, String, String) {
    // The board engine only needs a slug; the aux model comes from the kernel.
    let (k, p, _ws) = testutil::kernel(|c| {
        c.kanban.enabled = true;
        cfg(&mut c.kanban)
    });
    let d = k.paths.data.clone();
    boards::create_board(&d, "proj", Default::default()).unwrap();
    let id = store::with_board(&d, "proj", |b| ops::create_task(b, NewTask { title: "wire up billing".into(), body: Some("we need invoices".into()), triage: true, ..Default::default() })).unwrap();
    (k, p, d, "proj".to_string(), id)
}

fn cfg_for(k: &crate::kernel::Kernel) -> KanbanConfig {
    k.cfg.kanban.clone()
}

fn task(d: &Path, slug: &str, id: &str) -> store::Task {
    store::read_board(d, slug).unwrap().task(id).cloned().unwrap_or_else(|| panic!("task {id} is gone"))
}

fn system_text(p: &testutil::Scripted, i: usize) -> String {
    p.seen.lock().unwrap()[i].system.iter().map(|s| s.text.clone()).collect()
}

fn user_text(p: &testutil::Scripted, i: usize) -> String {
    p.seen.lock().unwrap()[i].messages.iter().flat_map(|m| m.content.iter()).filter_map(|b| match b {
        ark_core::Block::Text { text } => Some(text.clone()),
        _ => None,
    }).collect()
}

#[test]
fn specify_promotes_the_card_with_the_tightened_spec() {
    let (k, p, d, slug, id) = setup(|c| c.identity = "specifier-bot".into());
    let cfg = cfg_for(&k);
    let spec = serde_json::json!({
        "title": "Add invoice generation to billing",
        "body": "**Goal**\nCustomers can download a PDF invoice.\n\n**Approach**\n- add the template\n\n**Acceptance criteria**\n- [ ] invoice downloads"
    });
    p.text(&spec.to_string());

    let out = specify_task(&k, &d, &slug, &cfg, &id, Some("dash"));
    assert!(out.ok, "{out:?}");
    assert_eq!(out.task_id, id);
    assert_eq!(out.new_title.as_deref(), Some("Add invoice generation to billing"));
    assert!(out.child_ids.is_empty() && !out.fanout);

    let t = task(&d, &slug, &id);
    assert_eq!(t.status, "ready", "specifying promotes triage out of the column straight to ready");
    assert_eq!(t.title, "Add invoice generation to billing");
    let body = t.body.unwrap();
    assert!(body.starts_with("**Goal**") && body.contains("Acceptance criteria"), "{body}");
    let b = store::read_board(&d, &slug).unwrap();
    assert_eq!(b.events_for(&id).iter().filter(|e| e.kind == "specified").count(), 1);
    assert!(b.comments_for(&id).iter().any(|c| c.author == "dash" && c.body.contains("promoted to todo")), "the author is recorded");

    // The specifier prompt is the one in SPECIFY_SYSTEM and carries the card.
    assert!(system_text(&p, 0).contains("Kanban triage specifier"));
    let user = user_text(&p, 0);
    assert!(user.contains("wire up billing") && user.contains("we need invoices"), "{user}");
}

#[test]
fn specify_falls_back_to_the_raw_reply_and_reports_unusable_answers() {
    let (k, p, d, slug, id) = setup(|_| {});
    let cfg = cfg_for(&k);

    // Not JSON at all: the whole reply becomes the body — the spec is still usable.
    p.text("Do this: add invoices, then reconcile them against the ledger.");
    let out = specify_task(&k, &d, &slug, &cfg, &id, None);
    assert!(out.ok, "{out:?}");
    assert_eq!(out.new_title, None);
    let t = task(&d, &slug, &id);
    assert_eq!(t.title, "wire up billing", "the title is only rewritten when the model gives one");
    assert_eq!(t.body.as_deref(), Some("Do this: add invoices, then reconcile them against the ledger."));
    // Default author when the caller supplies none.
    assert!(store::read_board(&d, &slug).unwrap().comments_for(&id).iter().any(|c| c.author == "specifier"));

    // `{}`: parseable but empty → the card is not touched and the reason says why.
    let (k2, p2, d2, slug2, id2) = setup(|_| {});
    p2.text("{}");
    let out = specify_task(&k2, &d2, &slug2, &cfg_for(&k2), &id2, None);
    assert!(!out.ok);
    assert_eq!(out.reason, "LLM response missing title and body");
    assert_eq!(task(&d2, &slug2, &id2).status, "triage", "a failed specify leaves the card in triage");

    // Empty reply and a card that is not in triage at all.
    p2.text("");
    let out = specify_task(&k2, &d2, &slug2, &cfg_for(&k2), &id2, None);
    assert!(!out.ok);
    assert_eq!(out.reason, "LLM returned an empty response");

    let done = store::with_board(&d2, &slug2, |b| ops::create_task(b, NewTask { title: "already planned".into(), triage: false, ..Default::default() })).unwrap();
    let out = specify_task(&k2, &d2, &slug2, &cfg_for(&k2), &done, None);
    assert!(!out.ok);
    assert!(out.reason.contains("not in triage") && out.reason.contains("ready"), "{:?}", out.reason);
    let out = specify_task(&k2, &d2, &slug2, &cfg_for(&k2), "t_missing", None);
    assert!(!out.ok);
    assert_eq!(out.reason, "unknown task id");
    assert!(p2.seen.lock().unwrap().len() <= 3, "a missing card never reaches the model");
}

#[test]
fn decompose_fans_out_a_routed_graph() {
    let (k, p, d, slug, id) = setup(|c| {
        c.profiles = profiles(&[("researcher", "collects sources"), ("writer", "writes prose"), ("reviewer", "gates quality")]);
        c.default_assignee = "writer".into();
        c.orchestrator_profile = "reviewer".into();
    });
    let cfg = cfg_for(&k);
    let graph = serde_json::json!({
        "fanout": true,
        "rationale": "research and drafting are independent",
        "tasks": [
            {"title": "Collect sources", "body": "find docs", "assignee": "researcher", "parents": []},
            {"title": "Draft the intro", "body": "write it", "assignee": "does-not-exist", "parents": [0]},
            {"title": "Polish the draft", "body": "tighten it", "assignee": null, "parents": [0, 9, 1]}
        ]
    });
    p.text(&graph.to_string());

    let out = decompose_task(&k, &d, &slug, &cfg, &id, Some("dash"));
    assert!(out.ok, "{out:?}");
    assert!(out.fanout);
    assert_eq!(out.reason, "decomposed into 3 children");
    assert_eq!(out.child_ids.len(), 3, "{out:?}");

    let b = store::read_board(&d, &slug).unwrap();
    let root = b.task(&id).unwrap();
    assert_eq!(root.status, "todo", "the root waits for its children");
    assert_eq!(root.assignee.as_deref(), Some("reviewer"), "the root goes to the orchestrator profile");
    let c0 = b.task(&out.child_ids[0]).unwrap();
    let c1 = b.task(&out.child_ids[1]).unwrap();
    let c2 = b.task(&out.child_ids[2]).unwrap();
    assert_eq!(c0.status, "ready", "a parentless child starts at once");
    assert_eq!(c0.assignee.as_deref(), Some("researcher"));
    assert_eq!(c1.status, "todo");
    assert_eq!(c1.assignee.as_deref(), Some("writer"), "an unknown profile falls back to the default assignee");
    assert_eq!(b.parent_ids(&c1.id), vec![c0.id.clone()]);
    assert_eq!(c2.assignee.as_deref(), Some("writer"), "null routes to the default as well");
    let mut want = vec![c0.id.clone(), c1.id.clone()];
    want.sort();
    assert_eq!(b.parent_ids(&c2.id), want, "out-of-range parent indices are dropped");
    for c in &out.child_ids {
        assert!(b.parent_ids(&id).contains(c), "the root depends on every child (parents = dependencies)");
    }
    assert!(b.comments_for(&id).iter().any(|c| c.body.contains("Decomposed into") && c.body.contains(&out.child_ids[0])));
    assert_eq!(b.events_for(&id).iter().filter(|e| e.kind == "decomposed").count(), 1);

    // The decomposer is told the roster (with descriptions) and the fallback profile.
    assert!(system_text(&p, 0).contains("Kanban decomposer"));
    let user = user_text(&p, 0);
    assert!(user.contains("researcher: collects sources") && user.contains("reviewer: gates quality"), "{user}");
    assert!(user.contains("Default assignee (used when no profile fits a task): writer"), "{user}");
    assert!(user.contains("wire up billing"), "{user}");
}

#[test]
fn decompose_can_leave_the_children_in_todo() {
    let (k, p, d, slug, id) = setup(|c| {
        c.profiles = profiles(&[("writer", "writes prose")]);
        c.auto_promote_children = false;
    });
    p.text(&serde_json::json!({"fanout": true, "tasks": [{"title": "a", "assignee": "writer"}, {"title": "b", "parents": [0]}]}).to_string());
    let out = decompose_task(&k, &d, &slug, &cfg_for(&k), &id, None);
    assert!(out.ok, "{out:?}");
    let b = store::read_board(&d, &slug).unwrap();
    for c in &out.child_ids {
        assert_eq!(b.status_of(c), Some("todo"), "auto_promote_children=false keeps the graph parked");
    }
}

#[test]
fn decompose_without_fanout_tightens_and_routes_the_card() {
    let (k, p, d, slug, id) = setup(|c| {
        c.profiles = profiles(&[("writer", "writes prose"), ("specialist", "does the hard part")]);
        c.default_assignee = "writer".into();
    });
    p.text(&serde_json::json!({"fanout": false, "rationale": "one unit", "title": "Add invoice PDFs", "body": "**Goal** invoices", "assignee": "specialist"}).to_string());
    let out = decompose_task(&k, &d, &slug, &cfg_for(&k), &id, None);
    assert!(out.ok, "{out:?}");
    assert!(!out.fanout, "a single card is not a fan-out");
    assert_eq!(out.reason, "single task (no fanout)");
    assert_eq!(out.new_title.as_deref(), Some("Add invoice PDFs"));
    let t = task(&d, &slug, &id);
    assert_eq!(t.status, "ready", "a single tightened card is dispatchable at once");
    assert_eq!(t.title, "Add invoice PDFs");
    assert_eq!(t.assignee.as_deref(), Some("specialist"), "an unassigned root takes the model's routing");

    // A root that already has an assignee keeps it: the model cannot silently re-route it.
    let (k2, p2, d2, slug2, id2) = setup(|c| c.profiles = profiles(&[("writer", "writes prose"), ("specialist", "does the hard part")]));
    store::with_board(&d2, &slug2, |b| ops::assign(b, &id2, Some("writer"))).unwrap();
    p2.text(&serde_json::json!({"fanout": false, "title": "t", "body": "b", "assignee": "specialist"}).to_string());
    let out = decompose_task(&k2, &d2, &slug2, &cfg_for(&k2), &id2, None);
    assert!(out.ok, "{out:?}");
    assert_eq!(task(&d2, &slug2, &id2).assignee.as_deref(), Some("writer"));
}

#[test]
fn decompose_reports_unusable_graphs_without_touching_the_card() {
    let (k, p, d, slug, id) = setup(|c| c.profiles = profiles(&[("writer", "writes prose")]));
    let cfg = cfg_for(&k);

    p.text("I could not produce JSON, sorry.");
    let out = decompose_task(&k, &d, &slug, &cfg, &id, None);
    assert!(!out.ok);
    assert_eq!(out.reason, "LLM returned malformed JSON");
    assert_eq!(task(&d, &slug, &id).status, "triage", "a bad reply never moves the card");

    for (payload, want) in [
        (serde_json::json!({"fanout": true, "tasks": []}), "fanout=true with empty tasks list"),
        (serde_json::json!({"fanout": true}), "fanout=true with empty tasks list"),
        (serde_json::json!({"fanout": true, "tasks": [{"body": "no title"}]}), "tasks[0].title is missing or empty"),
        (serde_json::json!({"fanout": true, "tasks": ["oops"]}), "tasks[0] is not an object"),
        (serde_json::json!({"fanout": false}), "fanout=false with no title/body"),
    ] {
        p.text(&payload.to_string());
        let out = decompose_task(&k, &d, &slug, &cfg, &id, None);
        assert!(!out.ok, "{payload} was accepted");
        assert!(out.reason.contains(want), "{payload} → {:?}", out.reason);
        assert_eq!(task(&d, &slug, &id).status, "triage");
    }

    // A cyclic graph is rejected by the store, and the error survives to the caller.
    p.text(&serde_json::json!({"fanout": true, "tasks": [{"title": "a", "parents": [1]}, {"title": "b", "parents": [0]}]}).to_string());
    let out = decompose_task(&k, &d, &slug, &cfg, &id, None);
    assert!(!out.ok);
    assert!(out.reason.starts_with("DB rejected graph:") && out.reason.contains("cyclic"), "{:?}", out.reason);
    assert_eq!(task(&d, &slug, &id).status, "triage");
    assert_eq!(store::read_board(&d, &slug).unwrap().tasks.len(), 1, "a rejected graph creates no cards");
}

#[test]
fn arp_methods_drive_specify_and_decompose() {
    use crate::kanban::methods;
    let (k, p, d, slug, id) = setup(|c| {
        c.profiles = profiles(&[("writer", "writes prose")]);
        c.default_assignee = "writer".into();
    });

    // Every method the dashboard may call is listed, and an unknown one is not ours.
    assert!(methods::NAMES.contains(&"kanban.specify") && methods::NAMES.contains(&"kanban.decompose"));
    assert!(methods::call(&k, "kanban.nope", &serde_json::json!({})).is_none());
    let (code, msg) = methods::call(&k, "kanban.specify", &serde_json::json!({"board": "proj"})).unwrap().unwrap_err();
    assert_eq!(code, -32602);
    assert!(msg.contains("missing `id`"), "{msg}");

    // `kanban.specify`: the dashboard actor is the author, the outcome is the JSON payload.
    p.text(&serde_json::json!({"title": "Invoice PDFs", "body": "**Goal** pdfs"}).to_string());
    let v = methods::call(&k, "kanban.specify", &serde_json::json!({"board": "proj", "id": id, "actor": "dashboard"})).unwrap().unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["reason"], "specified");
    assert_eq!(v["task_id"], id);
    assert_eq!(task(&d, &slug, &id).title, "Invoice PDFs");
    assert!(store::read_board(&d, &slug).unwrap().comments_for(&id).iter().any(|c| c.author == "dashboard"));

    // `kanban.decompose` on a fresh triage card returns the child ids.
    let second = store::with_board(&d, &slug, |b| ops::create_task(b, NewTask { title: "ship it".into(), triage: true, ..Default::default() })).unwrap();
    p.text(&serde_json::json!({"fanout": true, "tasks": [{"title": "a", "assignee": "writer"}, {"title": "b", "parents": [0]}]}).to_string());
    let v = methods::call(&k, "kanban.decompose", &serde_json::json!({"board": "proj", "id": second, "actor": "dashboard"})).unwrap().unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["fanout"], true);
    assert_eq!(v["child_ids"].as_array().unwrap().len(), 2);
    // An unknown card is an ok=false outcome, not an ARP error: the caller can show it.
    p.text("{}");
    let v = methods::call(&k, "kanban.specify", &serde_json::json!({"board": "proj", "id": "t_missing"})).unwrap().unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["reason"], "unknown task id");
    // Requests all went through the aux model path (one per call that reached it).
    assert_eq!(p.seen.lock().unwrap().len(), 2);
}
