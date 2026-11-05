//! ARP methods for the dashboard (web UI) and remote clients: `kanban.*` for the
//! board and `board.*` for per-session widget boards.

use super::boards::{self, MetaPatch};
use super::ops::{self, NewTask};
use super::{dispatch, now, resolve_board, store, widget_board, workflow};
use crate::kernel::Kernel;
use serde_json::{json, Value};
use std::path::Path;

pub const NAMES: &[&str] = &[
    "kanban.boards", "kanban.board", "kanban.show", "kanban.create", "kanban.move", "kanban.comment", "kanban.assign", "kanban.link", "kanban.unlink", "kanban.complete", "kanban.block", "kanban.unblock",
    "kanban.archive", "kanban.reclaim", "kanban.dispatch", "kanban.diagnostics", "kanban.specify", "kanban.decompose", "kanban.board_create", "kanban.board_remove", "kanban.workflow", "kanban.stats",
    "kanban.export", "kanban.import", "kanban.swarm",
    "board.get", "board.update", "board.widget_put", "board.widget_grant",
];

type Res = Result<Value, (i32, String)>;
fn bad(e: impl Into<String>) -> (i32, String) {
    (-32602, e.into())
}

/// `workers[]` of `kanban.swarm`: either a `profile:title[:skill,skill]` string or an
/// object `{profile, title, body?, skills?, priority?, max_runtime_seconds?}`.
fn swarm_worker(v: &Value) -> Result<super::swarm::WorkerSpec, String> {
    match v {
        Value::String(spec) => super::swarm::parse_worker(spec),
        Value::Object(o) => {
            let get = |k: &str| o.get(k).and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty());
            let (profile, title) = (get("profile").ok_or("workers[].profile is required")?, get("title").ok_or("workers[].title is required")?);
            let skills: Vec<String> = o.get("skills").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|s| s.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()).unwrap_or_default();
            Ok(super::swarm::WorkerSpec { profile: profile.into(), title: title.into(), body: get("body").unwrap_or(title).into(), skills, priority: o.get("priority").and_then(Value::as_i64).unwrap_or(0), max_runtime_seconds: o.get("max_runtime_seconds").and_then(Value::as_i64) })
        }
        other => Err(format!("workers entries must be strings or objects, got {other}")),
    }
}

fn task_row(b: &store::BoardData, t: &store::Task) -> Value {    json!({"id": t.id, "title": t.title, "status": t.status, "assignee": t.assignee, "priority": t.priority, "tenant": t.tenant, "labels": t.labels, "created_at": t.created_at, "updated_at": t.updated_at, "started_at": t.started_at, "completed_at": t.completed_at,
        "parents": b.parent_ids(&t.id), "children": b.child_ids(&t.id), "comments": b.comments_for(&t.id).len(), "attachments": b.attachments_for(&t.id).len(), "consecutive_failures": t.consecutive_failures,
        "last_failure_error": t.last_failure_error, "block_kind": t.block_kind, "running": t.status == "running", "latest_summary": b.runs_for(&t.id).into_iter().filter(|r| r.summary.is_some()).max_by_key(|r| r.id).and_then(|r| r.summary.clone())})
}

/// Serve `method` when it is ours; None otherwise.
pub fn call(k: &Kernel, method: &str, p: &Value) -> Option<Res> {
    if !NAMES.contains(&method) {
        return None;
    }
    Some(handle(k, method, p))
}

fn handle(k: &Kernel, method: &str, p: &Value) -> Res {
    super::attach(k);
    let data = k.paths.data.clone();
    let data = data.as_path();
    let cfg = &k.cfg.kanban;
    let lim = cfg.failure_limit;
    let s = |key: &str| p.get(key).and_then(|v| v.as_str()).map(str::trim).filter(|v| !v.is_empty());
    let need = |key: &str| s(key).ok_or_else(|| bad(format!("missing `{key}`")));
    let slug = resolve_board(data, s("board")).map_err(bad)?;
    let slug = slug.as_str();
    let actor = s("actor").unwrap_or("dashboard").to_string();
    let e = |x: String| (-32000, x);
    let interrupt = |sessions: Vec<String>| {
        for x in sessions {
            k.interrupt(&x);
        }
    };
    match method {
        "kanban.workflow" => Ok(workflow::to_json()),
        "kanban.boards" => Ok(json!(boards::list_boards(data, p["all"] == true).into_iter().map(|m| {
            let counts = boards::task_counts(data, &m.slug);
            json!({"meta": m, "counts": counts, "current": m.slug == super::current_board(data)})
        }).collect::<Vec<_>>())),
        "kanban.board" => {
            let b = store::read_board(data, slug).map_err(e)?;
            let inc = p["include_archived"] == true;
            let tasks: Vec<Value> = b.tasks.iter().filter(|t| inc || t.status != "archived").map(|t| task_row(&b, t)).collect();
            Ok(json!({"board": slug, "meta": boards::read_meta(data, slug), "workflow": workflow::to_json(), "tasks": tasks, "stats": ops::stats(&b), "revision": b.revision}))
        }
        "kanban.stats" => Ok(ops::stats(&store::read_board(data, slug).map_err(e)?)),
        "kanban.show" => {
            let id = need("id")?;
            let b = store::read_board(data, slug).map_err(e)?;
            let t = b.task(id).ok_or_else(|| bad(format!("task {id} not found")))?;
            Ok(json!({"task": t, "parents": b.parent_ids(id), "children": b.child_ids(id), "comments": b.comments_for(id), "events": b.events_for(id), "runs": b.runs_for(id), "attachments": b.attachments_for(id),
                "diagnostics": super::diagnostics::task_diagnostics(&b, id, now(), &cfg.diagnostics, lim), "worker_context": super::context::build_worker_context(&b, id, now()).unwrap_or_default()}))
        }
        "kanban.create" => {
            let meta = boards::read_meta(data, slug);
            let parents = p["parents"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
            let n = NewTask { title: need("title")?.into(), body: s("body").map(String::from), assignee: s("assignee").map(String::from), priority: p["priority"].as_i64().unwrap_or(0), parents, triage: p["triage"] == true, tenant: s("tenant").map(String::from), created_by: Some(actor), default_workdir: meta.default_workdir, ..Default::default() };
            let id = store::with_board(data, slug, |b| ops::create_task(b, n)).map_err(e)?;
            Ok(json!({"id": id}))
        }
        "kanban.move" => {
            let (id, st) = (need("id")?, need("status")?);
            let kill = store::with_board(data, slug, |b| ops::move_task(b, data, slug, id, st, &actor, lim)).map_err(e)?;
            interrupt(kill);
            Ok(json!({"ok": true, "status": store::read_board(data, slug).map_err(e)?.status_of(id)}))
        }
        "kanban.comment" => {
            let (id, body) = (need("id")?, need("body")?);
            let cid = store::with_board(data, slug, |b| ops::add_comment(b, id, &actor, body)).map_err(e)?;
            Ok(json!({"comment_id": cid}))
        }
        "kanban.assign" => {
            let id = need("id")?;
            store::with_board(data, slug, |b| ops::assign(b, id, s("assignee"))).map_err(e)?;
            Ok(json!({"ok": true}))
        }
        "kanban.link" => {
            let gated = store::with_board(data, slug, |b| ops::link(b, need("parent").map_err(|x| x.1)?, need("child").map_err(|x| x.1)?, None)).map_err(e)?;
            Ok(json!({"gated": gated}))
        }
        "kanban.unlink" => {
            let (pa, ch) = (need("parent")?, need("child")?);
            Ok(json!({"removed": store::with_board(data, slug, |b| Ok(ops::unlink(b, pa, ch, lim))).map_err(e)?}))
        }
        "kanban.complete" => {
            let id = need("id")?;
            let c = ops::Completion { summary: s("summary").map(String::from).or_else(|| Some(format!("Completed by {actor}."))), force: p["force"] == true, ..Default::default() };
            super::tools::complete_task(data, slug, cfg, id, c).map_err(|(r, x)| e(x.unwrap_or_else(|| format!("could not complete {id}: {r:?}"))))?;
            Ok(json!({"ok": true}))
        }
        "kanban.block" => {
            let id = need("id")?;
            let okb = store::with_board(data, slug, |b| ops::block(b, id, s("reason"), s("kind"), None)).map_err(e)?;
            Ok(json!({"ok": okb}))
        }
        "kanban.unblock" => Ok(json!({"ok": store::with_board(data, slug, |b| Ok(ops::unblock(b, need("id").map_err(|x| x.1)?))).map_err(e)?})),
        "kanban.archive" => {
            let id = need("id")?;
            let kill = store::with_board(data, slug, |b| ops::archive(b, data, slug, id, lim)).map_err(e)?;
            interrupt(kill.into_iter().collect());
            Ok(json!({"ok": true}))
        }
        "kanban.reclaim" => {
            let id = need("id")?;
            let r = store::with_board(data, slug, |b| Ok(ops::reclaim(b, id, s("reason")))).map_err(e)?;
            if let Some(Some(sess)) = &r {
                k.interrupt(sess);
            }
            Ok(json!({"ok": r.is_some()}))
        }
        "kanban.dispatch" => {
            let o = dispatch::TickOpts { dry_run: p["dry_run"] == true, ..Default::default() };
            if s("board").is_some() {
                let r = dispatch::tick_board(data, slug, cfg, &dispatch::KernelSpawner { k: k.clone() }, &o).map_err(e)?;
                return Ok(json!([r]));
            }
            Ok(json!(dispatch::tick_all(k, cfg, &o)))
        }
        "kanban.diagnostics" => {
            let b = store::read_board(data, slug).map_err(e)?;
            Ok(json!(super::diagnostics::board_diagnostics(&b, now(), &cfg.diagnostics, lim, s("severity"), s("task"))))
        }
        "kanban.specify" => Ok(super::llm::specify_task(k, data, slug, cfg, need("id")?, Some(&actor)).to_json()),
        "kanban.decompose" => Ok(super::llm::decompose_task(k, data, slug, cfg, need("id")?, Some(&actor)).to_json()),
        "kanban.export" => {
            let output = need("output")?;
            let r = super::transfer::export_board(data, slug, Path::new(output), p["attachments"] != false, p["logs"] == true).map_err(e)?;
            Ok(r)
        }
        "kanban.import" => {
            let archive = need("archive")?;
            super::transfer::import_board(data, Path::new(archive), s("as_slug"), p["switch"] == true).map_err(e)
        }
        "kanban.swarm" => {
            let workers = match p.get("workers") {
                Some(Value::Array(a)) if !a.is_empty() => a.iter().map(swarm_worker).collect::<Result<Vec<_>, String>>().map_err(bad)?,
                _ => return Err(bad("missing `workers` (one or more `profile:title[:skill,skill]` specs)")),
            };
            if !boards::board_exists(data, slug) {
                boards::create_board(data, slug, MetaPatch::default()).map_err(e)?;
            }
            let spec = super::swarm::SwarmSpec {
                goal: need("goal")?.into(),
                workers,
                verifier: need("verifier")?.into(),
                synthesizer: need("synthesizer")?.into(),
                root_title: s("root_title").map(String::from),
                tenant: s("tenant").map(String::from),
                created_by: s("created_by").map(String::from).or_else(|| Some(actor.clone()).filter(|a| !a.is_empty())),
                priority: p["priority"].as_i64().unwrap_or(0),
                idempotency_key: s("idempotency_key").map(String::from),
            };
            let created = store::with_board(data, slug, |b| super::swarm::create(b, spec, lim)).map_err(e)?;
            let mut v = created.to_json();
            v["board"] = json!(slug);
            Ok(v)
        }
        "kanban.board_create" => {
            let m = boards::create_board(data, need("slug")?, MetaPatch { name: s("name").map(String::from), description: s("description").map(String::from), icon: s("icon").map(String::from), color: s("color").map(String::from), default_workdir: s("default_workdir").map(String::from), kind: s("kind").map(String::from), ..Default::default() }).map_err(e)?;
            if p["switch"] == true {
                super::set_current_board(data, &m.slug).map_err(e)?;
            }
            Ok(json!(m))
        }
        "kanban.board_remove" => {
            let r = boards::remove_board(data, need("slug")?, p["delete"] != true).map_err(e)?;
            Ok(json!({"slug": r.slug, "action": r.action, "new_path": r.new_path}))
        }
        "board.get" => Ok(widget_board::to_json(&widget_board::get(data, need("sessionKey")?).map_err(e)?)),
        "board.update" => {
            let ops = p["ops"].as_array().cloned().ok_or_else(|| bad("missing `ops`"))?;
            Ok(widget_board::to_json(&widget_board::update(data, need("sessionKey")?, &ops).map_err(e)?))
        }
        "board.widget_put" => Ok(widget_board::to_json(&widget_board::widget_put(data, need("sessionKey")?, p).map_err(e)?)),
        "board.widget_grant" => Ok(widget_board::to_json(&widget_board::widget_grant(data, need("sessionKey")?, need("name")?, need("decision")?, p["revision"].as_u64().unwrap_or(0), need("instanceId")?).map_err(e)?)),
        _ => Err((-32601, format!("unknown method `{method}`"))),
    }
}
