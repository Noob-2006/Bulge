//! Working-state tools: `todo` (per-session task list) and `skill`
//! (read and author agentskills.io-style SKILL.md files).

use crate::util::{atomic_write, io_err};
use ark_core::tool::{arg_opt_str, arg_str};
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

// ───────────────────────── todo ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct Item {
    content: String,
    status: String,
}

const MAX_ITEMS: usize = 50;

/// Lenient item shapes: plain strings, `title`/`task` for content, missing or
/// synonym statuses. Anything still wrong is rejected with a clear message.
fn normalize_item(it: &mut Value) {
    if let Value::String(s) = it {
        *it = json!({"content": s.clone(), "status": "pending"});
        return;
    }
    crate::util::alias(it, "content", &["title", "task", "text", "name", "description"]);
    let Some(o) = it.as_object_mut() else { return };
    let st = o.get("status").and_then(Value::as_str).map(|s| s.to_ascii_lowercase().replace([' ', '-'], "_"));
    let canon = match st.as_deref() {
        None => "pending",
        Some("done" | "complete" | "completed" | "finished" | "ok") => "completed",
        Some("doing" | "active" | "in_progress" | "inprogress" | "started" | "running" | "current") => "in_progress",
        Some("todo" | "pending" | "not_started" | "open" | "waiting") => "pending",
        Some(_) => return, // leave it; validation names the allowed values
    };
    o.insert("status".into(), canon.into());
}

fn todo_path(ctx: &ToolCtx) -> PathBuf {
    ctx.home.join("todos").join(format!("{}.json", ctx.session_id))
}

fn render(items: &[Item]) -> String {
    if items.is_empty() {
        return "(no tasks)".into();
    }
    let done = items.iter().filter(|i| i.status == "completed").count();
    let mut s = format!("{done}/{} done\n", items.len());
    for (n, i) in items.iter().enumerate() {
        let mark = match i.status.as_str() {
            "completed" => "x",
            "in_progress" => ">",
            _ => " ",
        };
        s.push_str(&format!("[{mark}] {}. {}\n", n + 1, i.content));
    }
    s
}

pub struct Todo;

impl Tool for Todo {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "todo".into(),
            description: "Track a multi-step task. action=set replaces the whole list (items: [{content, status: pending|in_progress|completed}], at most one in_progress); action=list shows it.".into(),
            input_schema: json!({"type":"object","properties":{
                "action":{"type":"string","enum":["set","list"]},
                "items":{"type":"array","items":{"type":"object","properties":{"content":{"type":"string"},"status":{"type":"string","enum":["pending","in_progress","completed"]}},"required":["content","status"]}}},
                "required":["action"]}),
            parallel_safe: false,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![Effect::Write { path: todo_path(ctx) }]
    }
    fn call(&self, ctx: &ToolCtx, mut input: Value) -> ToolOutput {
        crate::util::rename(&mut input, "items", &["todos", "tasks", "steps", "list"]);
        // Single-item status change: {action: update|complete, step|index|id: n, status?}.
        let one = ["step", "index", "id", "item", "n"].iter().find_map(|k| input.get(*k).and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))));
        if let (Some(n), None) = (one, input.get("items")) {
            let mut items: Vec<Item> = fs::read_to_string(todo_path(ctx)).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
            let Some(idx) = (n as usize).checked_sub(1).filter(|i| *i < items.len()) else {
                return ToolOutput::err(format!("no task #{n}; action=list shows the numbering (1-based)"));
            };
            let act = input.get("action").and_then(Value::as_str).unwrap_or("");
            let mut st = json!({"content": items[idx].content, "status": input.get("status").cloned().unwrap_or_else(|| if matches!(act, "complete" | "done" | "finish") { "completed".into() } else { "in_progress".into() })});
            normalize_item(&mut st);
            let status = st["status"].as_str().unwrap_or("pending").to_string();
            // Starting a step moves on from the current one: earlier steps count as done, later ones go back to pending.
            if status == "in_progress" {
                for (i, other) in items.iter_mut().enumerate() {
                    if i != idx && other.status == "in_progress" {
                        other.status = if i < idx { "completed" } else { "pending" }.into();
                    }
                }
            }
            items[idx].status = status;
            input = json!({"action": "set", "items": items});
        }
        crate::util::action_synonyms(&mut input, &[("create", "set"), ("add", "set"), ("update", "set"), ("new", "set"), ("replace", "set"), ("write", "set"), ("show", "list"), ("get", "list"), ("read", "list"), ("view", "list")]);
        crate::util::infer_action(&mut input, &[("items", "set")]);
        // A plain string list ("a\nb") → one item per line.
        if let Some(Value::String(s)) = input.get("items") {
            let lines: Vec<Value> = s.lines().map(str::trim).filter(|l| !l.is_empty()).map(|l| Value::String(l.to_string())).collect();
            input["items"] = Value::Array(lines);
        }
        if let Some(items) = input.get_mut("items").and_then(Value::as_array_mut) {
            for it in items.iter_mut() {
                normalize_item(it);
            }
        }
        let p = todo_path(ctx);
        match arg_opt_str(&input, "action") {
            Some("list") => {
                let items: Vec<Item> = fs::read_to_string(&p).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
                ToolOutput::ok(render(&items))
            }
            Some("set") => {
                let items: Vec<Item> = match input.get("items").cloned().map(serde_json::from_value) {
                    Some(Ok(v)) => v,
                    Some(Err(e)) => return ToolOutput::err(format!("bad `items`: {e}")),
                    None => return ToolOutput::err("missing `items`"),
                };
                if items.len() > MAX_ITEMS {
                    return ToolOutput::err(format!("{} items; keep it under {MAX_ITEMS}", items.len()));
                }
                if let Some(b) = items.iter().find(|i| !matches!(i.status.as_str(), "pending" | "in_progress" | "completed")) {
                    return ToolOutput::err(format!("bad status `{}` (pending, in_progress, completed)", b.status));
                }
                if items.iter().any(|i| i.content.trim().is_empty()) {
                    return ToolOutput::err("empty task content");
                }
                if items.iter().filter(|i| i.status == "in_progress").count() > 1 {
                    return ToolOutput::err("only one task may be in_progress");
                }
                if let Some(d) = p.parent() {
                    if let Err(e) = fs::create_dir_all(d) {
                        return ToolOutput::err(io_err("create", d, &e));
                    }
                }
                match atomic_write(&p, serde_json::to_string(&items).unwrap_or_default().as_bytes()) {
                    Ok(()) => ToolOutput::ok(render(&items)),
                    Err(e) => ToolOutput::err(io_err("write", &p, &e)),
                }
            }
            _ => ToolOutput::err("action must be set or list"),
        }
    }
}

// ───────────────────────── skill ─────────────────────────

fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 64 && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') && !n.starts_with('-')
}

/// Same search order as the kernel's skill index: project first, then user.
fn skill_dirs(ctx: &ToolCtx) -> Vec<PathBuf> {
    let w = &ctx.workspace;
    let mut v = vec![w.join(".ark/skills"), w.join(".claude/skills"), w.join(".agents/skills"), ctx.home.join("skills")];
    if let Some(h) = std::env::var_os("HOME") {
        v.push(PathBuf::from(h).join(".claude/skills"));
    }
    v
}

fn own_dir(ctx: &ToolCtx, name: &str) -> PathBuf {
    ctx.home.join("skills").join(name)
}

pub struct Skill;

impl Tool for Skill {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "skill".into(),
            description: "Skills are reusable instructions (SKILL.md). action=view loads one by name (do this before using a skill from the index); action=create/update writes your own (name: lowercase-dashes, description, body) so future sessions can reuse a procedure that worked; action=archive retires one you wrote.".into(),
            input_schema: json!({"type":"object","properties":{
                "action":{"type":"string","enum":["view","create","update","archive"]},
                "name":{"type":"string"},
                "description":{"type":"string"},
                "body":{"type":"string"}},
                "required":["action","name"]}),
            parallel_safe: false,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let name = arg_opt_str(input, "name").unwrap_or("");
        match arg_opt_str(input, "action") {
            Some("view") => vec![],
            _ => vec![Effect::Write { path: own_dir(ctx, name) }],
        }
    }
    fn call(&self, ctx: &ToolCtx, mut input: Value) -> ToolOutput {
        crate::util::alias(&mut input, "body", &["content", "steps", "instructions", "text"]);
        crate::util::action_synonyms(&mut input, &[("read", "view"), ("show", "view"), ("get", "view"), ("add", "create"), ("new", "create"), ("write", "create"), ("edit", "update"), ("delete", "archive"), ("remove", "archive")]);
        crate::util::infer_action(&mut input, &[("body", "create"), ("description", "create"), ("name", "view")]);
        let name = match arg_str(&input, "name") {
            Ok(n) if valid_name(n) => n,
            Ok(n) => return ToolOutput::err(format!("bad skill name `{n}` (lowercase letters, digits, dashes; ≤64)")),
            Err(e) => return ToolOutput::err(e),
        };
        let dir = own_dir(ctx, name);
        let file = dir.join("SKILL.md");
        match arg_opt_str(&input, "action") {
            Some("view") => {
                for d in skill_dirs(ctx) {
                    let f = d.join(name).join("SKILL.md");
                    if let Ok(t) = fs::read_to_string(&f) {
                        let extra: Vec<String> = fs::read_dir(d.join(name)).into_iter().flatten().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n != "SKILL.md").collect();
                        let mut s = format!("{}\n\n{t}", f.display());
                        if !extra.is_empty() {
                            s.push_str(&format!("\n\n[other files in this skill: {}]", extra.join(", ")));
                        }
                        return ToolOutput::ok(s);
                    }
                }
                ToolOutput::err(format!("no skill `{name}`; the skill index in your instructions lists the available ones"))
            }
            Some(a @ ("create" | "update")) => {
                let exists = file.exists();
                if a == "create" && exists {
                    return ToolOutput::err(format!("skill `{name}` exists; use action=update"));
                }
                if a == "update" && !exists {
                    return ToolOutput::err(format!("you have no skill `{name}` to update (project skills are read-only); use action=create"));
                }
                let desc = arg_opt_str(&input, "description").unwrap_or("").trim();
                let body = arg_opt_str(&input, "body").unwrap_or("").trim();
                if desc.is_empty() || body.is_empty() {
                    return ToolOutput::err("`description` and `body` are required");
                }
                if desc.contains('\n') || desc.len() > 300 {
                    return ToolOutput::err("description must be one line, ≤300 chars");
                }
                if body.len() > 20_000 {
                    return ToolOutput::err("body over 20k chars; split it or move detail into files");
                }
                if let Err(e) = fs::create_dir_all(&dir) {
                    return ToolOutput::err(io_err("create", &dir, &e));
                }
                let text = format!("---\nname: {name}\ndescription: {}\n---\n\n{body}\n", serde_json::to_string(desc).unwrap_or_default());
                match atomic_write(&file, text.as_bytes()) {
                    Ok(()) => ToolOutput::ok(format!("{a}d skill `{name}` at {} (listed from the next session on)", file.display())),
                    Err(e) => ToolOutput::err(io_err("write", &file, &e)),
                }
            }
            Some("archive") => {
                if !file.exists() {
                    return ToolOutput::err(format!("you have no skill `{name}` (only your own skills can be archived)"));
                }
                // Never delete: move aside so a human can restore it.
                let to = ctx.home.join("skills/.archive").join(format!("{name}-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)));
                let _ = fs::create_dir_all(to.parent().unwrap());
                match fs::rename(&dir, &to) {
                    Ok(()) => ToolOutput::ok(format!("archived to {}", to.display())),
                    Err(e) => ToolOutput::err(io_err("archive", &dir, &e)),
                }
            }
            _ => ToolOutput::err("action must be view, create, update or archive"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ctx;

    #[test]
    fn todo_set_list_and_validation() {
        let c = ctx("todo");
        assert_eq!(Todo.call(&c, json!({"action":"list"})).content, "(no tasks)");
        let o = Todo.call(&c, json!({"action":"set","items":[{"content":"a","status":"completed"},{"content":"b","status":"in_progress"},{"content":"c","status":"pending"}]}));
        assert!(!o.is_error && o.content.contains("1/3 done") && o.content.contains("[>] 2. b"), "{}", o.content);
        assert!(Todo.call(&c, json!({"action":"list"})).content.contains("[x] 1. a"), "persisted");
        for bad in [json!({"action":"set"}), json!({"action":"set","items":5}), json!({"action":"set","items":[{"content":"a","status":"someday"}]}), json!({"action":"set","items":[{"content":"a","status":"in_progress"},{"content":"b","status":"in_progress"}]}), json!({"action":"set","items":[{"content":" ","status":"pending"}]}), json!({"action":"zap"})] {
            assert!(Todo.call(&c, bad.clone()).is_error, "{bad}");
        }
        let many: Vec<Value> = (0..51).map(|i| json!({"content": i.to_string(), "status":"pending"})).collect();
        assert!(Todo.call(&c, json!({"action":"set","items":many})).is_error);
        assert!(Todo.call(&c, json!({"action":"list"})).content.contains("1/3"), "failed set leaves list intact");
    }

    #[test]
    fn todo_and_skill_accept_common_shapes() {
        let c = ctx("todo2");
        let o = Todo.call(&c, json!({"items":["a", {"title":"b","status":"done"}, {"task":"c","status":"In Progress"}, {"content":"d"}]}));
        assert!(!o.is_error, "{}", o.content);
        assert!(o.content.contains("1/4 done") && o.content.contains("[x] 2. b") && o.content.contains("[>] 3. c") && o.content.contains("[ ] 4. d"), "{}", o.content);
        assert!(Todo.call(&c, json!({"items":[{"content":"a","status":"maybe"}]})).content.contains("bad status `maybe`"));
        let o = Todo.call(&c, json!({"action":"create","steps":["x","y"]}));
        assert!(o.content.contains("0/2 done"), "steps array kept as items: {}", o.content);
        assert!(Todo.call(&c, json!({"action":"set","items":"p\nq\n"})).content.contains("[ ] 2. q"));
        assert!(Todo.call(&c, json!({"action":"update","step":"2","status":"done"})).content.contains("[x] 2. q"));
        assert!(Todo.call(&c, json!({"action":"update","index":1})).content.contains("[>] 1. p"));
        // Seen with Haiku: starting step 2 while step 1 is in progress used to fail.
        let o = Todo.call(&c, json!({"action":"set","items":["p","q","r"]}));
        assert!(!o.is_error, "{}", o.content);
        Todo.call(&c, json!({"action":"update","step":2}));
        let o = Todo.call(&c, json!({"action":"update","step":"3"}));
        assert!(!o.is_error && o.content.contains("[x] 2. q") && o.content.contains("[>] 3. r"), "{}", o.content);
        let o = Todo.call(&c, json!({"action":"update","step":1}));
        assert!(o.content.contains("[>] 1. p") && o.content.contains("[ ] 3. r"), "later step goes back to pending: {}", o.content);
        assert!(Todo.call(&c, json!({"action":"complete","step":9})).is_error);
        // Seen with Haiku: `operation` in place of `action`.
        assert!(Todo.call(&c, json!({"operation":"list"})).content.contains("[x] 2. q"));
        let o = Skill.call(&c, json!({"name":"t","description":"d","steps":["1. a","2. b"]}));
        assert!(!o.is_error, "{}", o.content);
        assert!(Skill.call(&c, json!({"name":"t"})).content.contains("1. a\n2. b"), "action inferred: view");
    }

    #[test]
    fn skill_lifecycle_and_guards() {
        let c = ctx("skill");
        fs::create_dir_all(c.workspace.join(".ark/skills/proj")).unwrap();
        fs::write(c.workspace.join(".ark/skills/proj/SKILL.md"), "---\nname: proj\n---\nproject body").unwrap();
        fs::write(c.workspace.join(".ark/skills/proj/helper.sh"), "").unwrap();
        let v = Skill.call(&c, json!({"action":"view","name":"proj"}));
        assert!(v.content.contains("project body") && v.content.contains("helper.sh"));
        assert!(Skill.call(&c, json!({"action":"update","name":"proj","description":"x","body":"y"})).is_error, "project skills read-only");
        assert!(Skill.call(&c, json!({"action":"view","name":"nope"})).is_error);
        for bad in ["../etc", "Upper", "", "-x", "a/b"] {
            assert!(Skill.call(&c, json!({"action":"view","name":bad})).is_error, "{bad}");
        }
        assert!(Skill.call(&c, json!({"action":"create","name":"deploy","description":"d"})).is_error, "body required");
        assert!(Skill.call(&c, json!({"action":"create","name":"deploy","description":"a\nb","body":"x"})).is_error);
        assert!(!Skill.call(&c, json!({"action":"create","name":"deploy","description":"Ship \"it\"","body":"1. build"})).is_error);
        assert!(Skill.call(&c, json!({"action":"create","name":"deploy","description":"d","body":"x"})).is_error, "no silent overwrite");
        let t = fs::read_to_string(c.home.join("skills/deploy/SKILL.md")).unwrap();
        assert!(t.starts_with("---\nname: deploy\ndescription: \"Ship \\\"it\\\"\"\n---"), "{t}");
        assert!(!Skill.call(&c, json!({"action":"update","name":"deploy","description":"d2","body":"2. ship"})).is_error);
        assert!(Skill.call(&c, json!({"action":"view","name":"deploy"})).content.contains("2. ship"));
        assert!(!Skill.call(&c, json!({"action":"archive","name":"deploy"})).is_error);
        assert!(Skill.call(&c, json!({"action":"view","name":"deploy"})).is_error);
        assert_eq!(fs::read_dir(c.home.join("skills/.archive")).unwrap().count(), 1, "archived, not deleted");
    }
}
