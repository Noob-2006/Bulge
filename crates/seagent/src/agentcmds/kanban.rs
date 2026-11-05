//! `/kanban …` and `seagent kanban …` (Hermes `hermes_cli/kanban.py`, CommandDef "kanban"): one
//! parser for both surfaces over the board engine's ARP layer (`seagent_kernel::kanban::methods`),
//! so chat, CLI and the web dashboard drive the same code.
//!
//! Subcommands (Hermes names): `init`, `boards`, `create <title> [--body t] [--assignee a]
//! [--priority n] [--parent id]… [--triage]`, `list|ls [--status s] [--assignee a] [--all]`,
//! `show <id>`, `assign|reassign <id> <profile|none>`, `reclaim <id> [--reason r]`,
//! `diagnostics|diag [--severity s] [--task id]`, `link <parent> <child>`, `unlink <parent> <child>`,
//! `comment <id> <text>`, `complete <id> [--summary s] [--force]`, `edit <id> --title t|--body b`,
//! `block <id> [reason] [--kind k]`, `unblock <id>`, `archive <id>`, `move <id> <status>`,
//! `dispatch [--dry-run]`, `stats`, `log|runs <id>`, `context <id>`, `assignees`,
//! `specify <id>`, `decompose <id>`, `swarm <goal> --worker p:title[:skills]… --verifier p
//! --synthesizer p [--tenant t] [--priority n] [--created-by p] [--idempotency-key k]`,
//! `export|board export [<archive>] [--output f] [--no-attachments] [--include-logs]`,
//! `import|board import <archive> [--as slug] [--switch]`,
//! `board create <slug> [--name n] [--switch]`, `board rm <slug> [--delete]`.
//! `--board <slug>` selects a board for any of them.

use super::text;
use crate::slash::{Ctx, Reply};
use seagent_kernel::kanban::{self, methods, store};
use seagent_kernel::kernel::Kernel;
use serde_json::{json, Map, Value};

pub const USAGE: &str = "usage: kanban <init|boards|create|list|show|assign|reclaim|diagnostics|link|unlink|comment|complete|edit|block|unblock|archive|move|dispatch|stats|log|context|assignees|specify|decompose|swarm|export|import|board> [args] [--board <slug>]";

/// Split args: positionals and `--flag value` / `--switch` pairs (repeatable `--parent`,
/// `--worker`).
fn parse(argv: &[String]) -> (Vec<String>, Map<String, Value>) {
    const SWITCHES: &[&str] = &["triage", "all", "force", "dry-run", "switch", "delete", "json", "no-attachments", "include-logs"];
    let mut pos = vec![];
    let mut flags = Map::new();
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if let Some(f) = a.strip_prefix("--") {
            let (name, inline) = f.split_once('=').map(|(a, b)| (a.to_string(), Some(b.to_string()))).unwrap_or((f.to_string(), None));
            if SWITCHES.contains(&name.as_str()) && inline.is_none() {
                flags.insert(name, json!(true));
            } else {
                let v = inline.or_else(|| {
                    i += 1;
                    argv.get(i).cloned()
                }).unwrap_or_default();
                let list = match name.as_str() {
                    "parent" => Some("parents"),
                    "worker" => Some("workers"),
                    _ => None,
                };
                if let Some(key) = list {
                    flags.entry(key).or_insert_with(|| json!([])).as_array_mut().unwrap().push(json!(v));
                } else {
                    flags.insert(name, json!(v));
                }
            }
        } else {
            pos.push(a.clone());
        }
        i += 1;
    }
    (pos, flags)
}

fn call(k: &Kernel, m: &str, p: Value) -> Result<Value, String> {
    methods::call(k, m, &p).unwrap_or_else(|| Err((-32601, format!("unknown method {m}")))).map_err(|(_, e)| e)
}

fn task_line(t: &Value) -> String {
    let who = t["assignee"].as_str().map(|a| format!(" @{a}")).unwrap_or_default();
    format!("{:<12} {:<9} p{:<2} {}{who}", t["id"].as_str().unwrap_or(""), t["status"].as_str().unwrap_or(""), t["priority"].as_i64().unwrap_or(0), t["title"].as_str().unwrap_or(""))
}

/// Resolve an id prefix on the selected board (exact id wins).
fn resolve_id(k: &Kernel, board: &Option<String>, q: &str) -> Result<String, String> {
    let slug = kanban::resolve_board(&k.paths.data, board.as_deref())?;
    let b = store::read_board(&k.paths.data, &slug)?;
    if b.task(q).is_some() {
        return Ok(q.to_string());
    }
    let hits: Vec<&str> = b.tasks.iter().map(|t| t.id.as_str()).filter(|id| id.starts_with(q) || id.strip_prefix("t_").is_some_and(|r| r.starts_with(q))).collect();
    match hits.as_slice() {
        [one] => Ok(one.to_string()),
        [] => Err(format!("task {q} not found on board {slug}")),
        _ => Err(format!("ambiguous task id {q}: {}", hits.join(", "))),
    }
}

/// Run one kanban subcommand; text output (JSON with `--json`).
pub fn run(k: &Kernel, argv: &[String], actor: &str) -> Result<String, String> {
    let (pos, flags) = parse(argv);
    let sub = pos.first().map(String::as_str).unwrap_or("list");
    let board = flags.get("board").and_then(Value::as_str).map(String::from);
    let mut p = flags.clone();
    p.insert("actor".into(), json!(actor));
    let as_json = flags.get("json") == Some(&json!(true));
    let arg = |i: usize, what: &str| pos.get(i).cloned().ok_or_else(|| format!("usage: kanban {sub} <{what}>"));
    let id = |i: usize| -> Result<String, String> { resolve_id(k, &board, &arg(i, "task id")?) };
    let out = |v: Value, txt: String| if as_json { serde_json::to_string_pretty(&v).unwrap_or_default() } else { txt };
    match sub {
        "init" => {
            let slug = kanban::resolve_board(&k.paths.data, board.as_deref())?;
            let m = if kanban::boards::board_exists(&k.paths.data, &slug) { kanban::boards::read_meta(&k.paths.data, &slug) } else { kanban::boards::create_board(&k.paths.data, &slug, Default::default())? };
            let _ = store::read_board(&k.paths.data, &slug);
            Ok(format!("board {} ready at {}", m.slug, store::board_file(&k.paths.data, &m.slug).display()))
        }
        "boards" => {
            let v = call(k, "kanban.boards", Value::Object(p))?;
            let rows: Vec<String> = v.as_array().into_iter().flatten().map(|b| format!("{}{} {} {}", if b["current"] == true { "* " } else { "  " }, b["meta"]["slug"].as_str().unwrap_or(""), b["meta"]["name"].as_str().unwrap_or(""), b["counts"])).collect();
            Ok(out(v, if rows.is_empty() { "no boards".into() } else { rows.join("\n") }))
        }
        "board" => match pos.get(1).map(String::as_str) {
            Some("create" | "new") => {
                p.insert("slug".into(), json!(arg(2, "slug")?));
                let v = call(k, "kanban.board_create", Value::Object(p))?;
                Ok(out(v.clone(), format!("created board {}", v["slug"].as_str().unwrap_or(""))))
            }
            Some("rm" | "remove" | "archive") => {
                p.insert("slug".into(), json!(arg(2, "slug")?));
                let v = call(k, "kanban.board_remove", Value::Object(p))?;
                Ok(out(v.clone(), format!("board {} {}", v["slug"].as_str().unwrap_or(""), v["action"].as_str().unwrap_or(""))))
            }
            Some("export") => export(k, pos.get(2).map(String::as_str), pos.get(3).map(String::as_str), &flags, as_json),
            Some("import") => import(k, pos.get(2).map(String::as_str), &flags, as_json),
            _ => Err("usage: kanban board <create|rm|export|import> ...".into()),
        },
        "create" | "add" => {
            let title = pos[1..].join(" ");
            if title.trim().is_empty() {
                return Err("usage: kanban create <title> [--body t] [--assignee a] [--priority n] [--parent id]".into());
            }
            p.insert("title".into(), json!(title));
            if let Some(n) = flags.get("priority").and_then(Value::as_str) {
                p.insert("priority".into(), json!(n.parse::<i64>().map_err(|_| "--priority must be a number")?));
            }
            let v = call(k, "kanban.create", Value::Object(p))?;
            Ok(out(v.clone(), format!("created {}", v["id"].as_str().unwrap_or(""))))
        }
        "list" | "ls" => {
            let v = call(k, "kanban.board", json!({"board": board, "include_archived": flags.get("all") == Some(&json!(true))}))?;
            let st = flags.get("status").and_then(Value::as_str);
            let who = flags.get("assignee").and_then(Value::as_str);
            let rows: Vec<&Value> = v["tasks"].as_array().into_iter().flatten().filter(|t| st.is_none_or(|s| t["status"] == s) && who.is_none_or(|a| t["assignee"] == a)).collect();
            let txt = if rows.is_empty() { format!("no tasks on board {}", v["board"].as_str().unwrap_or("")) } else { rows.iter().map(|t| task_line(t)).collect::<Vec<_>>().join("\n") };
            Ok(out(json!(rows), txt))
        }
        "show" => {
            let v = call(k, "kanban.show", json!({"board": board, "id": id(1)?}))?;
            let t = &v["task"];
            let mut lines = vec![format!("{} — {}", t["id"].as_str().unwrap_or(""), t["title"].as_str().unwrap_or("")), format!("status: {} · priority {} · assignee {}", t["status"].as_str().unwrap_or(""), t["priority"], t["assignee"].as_str().unwrap_or("-"))];
            if let Some(b) = t["body"].as_str().filter(|b| !b.is_empty()) {
                lines.push(String::new());
                lines.push(b.to_string());
            }
            for (k2, label) in [("parents", "parents"), ("children", "children")] {
                if let Some(a) = v[k2].as_array().filter(|a| !a.is_empty()) {
                    lines.push(format!("{label}: {}", a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")));
                }
            }
            for c in v["comments"].as_array().into_iter().flatten() {
                lines.push(format!("💬 {}: {}", c["author"].as_str().unwrap_or(""), c["body"].as_str().unwrap_or("")));
            }
            Ok(out(v.clone(), lines.join("\n")))
        }
        "assign" | "reassign" => {
            let tid = id(1)?;
            let who = arg(2, "profile")?;
            let v = call(k, "kanban.assign", json!({"board": board, "id": tid, "assignee": if who == "none" { Value::Null } else { json!(who) }}))?;
            Ok(out(v, format!("{tid} → {who}")))
        }
        "reclaim" => {
            let tid = id(1)?;
            let v = call(k, "kanban.reclaim", json!({"board": board, "id": tid, "reason": flags.get("reason")}))?;
            Ok(out(v.clone(), if v["ok"] == true { format!("reclaimed {tid}") } else { format!("{tid} was not claimed") }))
        }
        "diagnostics" | "diag" => {
            let v = call(k, "kanban.diagnostics", json!({"board": board, "severity": flags.get("severity"), "task": flags.get("task")}))?;
            Ok(serde_json::to_string_pretty(&v).unwrap_or_default())
        }
        "link" | "unlink" => {
            let (pa, ch) = (id(1)?, id(2)?);
            let v = call(k, &format!("kanban.{sub}"), json!({"board": board, "parent": pa, "child": ch}))?;
            Ok(out(v, format!("{sub}ed {pa} → {ch}")))
        }
        "comment" => {
            let tid = id(1)?;
            let body = pos[2..].join(" ");
            if body.trim().is_empty() {
                return Err("usage: kanban comment <id> <text>".into());
            }
            let v = call(k, "kanban.comment", json!({"board": board, "id": tid, "body": body, "actor": actor}))?;
            Ok(out(v, format!("commented on {tid}")))
        }
        "complete" | "done" => {
            let tid = id(1)?;
            let v = call(k, "kanban.complete", json!({"board": board, "id": tid, "summary": flags.get("summary"), "force": flags.get("force"), "actor": actor}))?;
            Ok(out(v, format!("completed {tid}")))
        }
        "block" => {
            let tid = id(1)?;
            let reason = pos[2..].join(" ");
            let v = call(k, "kanban.block", json!({"board": board, "id": tid, "reason": if reason.is_empty() { flags.get("reason").cloned().unwrap_or(Value::Null) } else { json!(reason) }, "kind": flags.get("kind")}))?;
            Ok(out(v.clone(), if v["ok"] == true { format!("blocked {tid}") } else { format!("{tid} not blocked") }))
        }
        "unblock" | "archive" => {
            let tid = id(1)?;
            let v = call(k, &format!("kanban.{sub}"), json!({"board": board, "id": tid}))?;
            Ok(out(v, format!("{sub}ed {tid}")))
        }
        "move" => {
            let tid = id(1)?;
            let st = arg(2, "status")?;
            let v = call(k, "kanban.move", json!({"board": board, "id": tid, "status": st, "actor": actor}))?;
            Ok(out(v.clone(), format!("{tid} → {}", v["status"].as_str().unwrap_or(&st))))
        }
        "edit" => {
            let tid = id(1)?;
            let slug = kanban::resolve_board(&k.paths.data, board.as_deref())?;
            let (title, body) = (flags.get("title").and_then(Value::as_str).map(String::from), flags.get("body").and_then(Value::as_str).map(String::from));
            if title.is_none() && body.is_none() {
                return Err("usage: kanban edit <id> [--title t] [--body b]".into());
            }
            let ok = store::with_board(&k.paths.data, &slug, |b| Ok(kanban::ops::edit(b, &tid, kanban::ops::Edit { title, body, ..Default::default() })))?;
            Ok(if ok { format!("edited {tid}") } else { format!("{tid} unchanged") })
        }
        "dispatch" => {
            let v = call(k, "kanban.dispatch", json!({"board": board, "dry_run": flags.get("dry-run") == Some(&json!(true))}))?;
            Ok(serde_json::to_string_pretty(&v).unwrap_or_default())
        }
        "stats" => {
            let v = call(k, "kanban.stats", json!({"board": board}))?;
            Ok(serde_json::to_string_pretty(&v).unwrap_or_default())
        }
        "log" | "runs" => {
            let tid = id(1)?;
            let v = call(k, "kanban.show", json!({"board": board, "id": tid}))?;
            if sub == "runs" {
                let rows: Vec<String> = v["runs"].as_array().into_iter().flatten().map(|r| format!("#{} {} {} {}", r["id"], r["status"].as_str().unwrap_or(""), r["outcome"].as_str().unwrap_or("-"), r["summary"].as_str().unwrap_or(""))).collect();
                return Ok(out(v["runs"].clone(), if rows.is_empty() { "no runs".into() } else { rows.join("\n") }));
            }
            let rows: Vec<String> = v["events"].as_array().into_iter().flatten().map(|e| format!("{} {} {}", e["created_at"], e["kind"].as_str().unwrap_or(""), e["payload"])).collect();
            Ok(out(v["events"].clone(), if rows.is_empty() { "no events".into() } else { rows.join("\n") }))
        }
        "context" => {
            let v = call(k, "kanban.show", json!({"board": board, "id": id(1)?}))?;
            Ok(v["worker_context"].as_str().unwrap_or("").to_string())
        }
        "assignees" => {
            let v = call(k, "kanban.board", json!({"board": board}))?;
            let mut counts: std::collections::BTreeMap<String, u64> = Default::default();
            for t in v["tasks"].as_array().into_iter().flatten() {
                *counts.entry(t["assignee"].as_str().unwrap_or("(unassigned)").to_string()).or_default() += 1;
            }
            Ok(counts.iter().map(|(a, n)| format!("{a}: {n}")).collect::<Vec<_>>().join("\n"))
        }
        "specify" | "decompose" => {
            let v = call(k, &format!("kanban.{sub}"), json!({"board": board, "id": id(1)?, "actor": actor}))?;
            Ok(serde_json::to_string_pretty(&v).unwrap_or_default())
        }
        "swarm" => {
            let goal = pos[1..].join(" ");
            if goal.trim().is_empty() {
                return Err("usage: kanban swarm <goal> --worker profile:title[:skill,skill]… --verifier <profile> --synthesizer <profile>".into());
            }
            let workers = flags.get("workers").cloned().unwrap_or_else(|| json!([]));
            if workers.as_array().is_none_or(|a| a.is_empty()) {
                return Err("kanban swarm: at least one --worker is required".into());
            }
            for (flag, what) in [("verifier", "--verifier"), ("synthesizer", "--synthesizer")] {
                if flags.get(flag).and_then(Value::as_str).is_none_or(|v| v.trim().is_empty()) {
                    return Err(format!("kanban swarm: {what} is required"));
                }
            }
            p.insert("goal".into(), json!(goal));
            p.insert("workers".into(), workers);
            p.insert("priority".into(), json!(flags.get("priority").and_then(Value::as_str).and_then(|n| n.parse::<i64>().ok()).unwrap_or(0)));
            for (from, to) in [("idempotency-key", "idempotency_key"), ("created-by", "created_by"), ("root-title", "root_title")] {
                if let Some(v) = flags.get(from) {
                    p.insert(to.into(), v.clone());
                }
            }
            let v = call(k, "kanban.swarm", Value::Object(p))?;
            let ids = |key: &str| v[key].as_array().map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default();
            let text = format!(
                "Swarm root: {}\nWorkers: {}\nVerifier: {}\nSynthesizer: {}",
                v["root_id"].as_str().unwrap_or(""),
                ids("worker_ids"),
                v["verifier_id"].as_str().unwrap_or(""),
                v["synthesizer_id"].as_str().unwrap_or("")
            );
            Ok(out(v, text))
        }
        "export" => export(k, board.as_deref(), pos.get(1).map(String::as_str), &flags, as_json),
        "import" => import(k, pos.get(1).map(String::as_str), &flags, as_json),
        "help" | "-h" | "--help" => Ok(USAGE.into()),
        other => Err(format!("unknown kanban subcommand `{other}`\n{USAGE}")),
    }
}

/// `kanban export [<archive>] [--output f] [--no-attachments] [--include-logs]` — the whole
/// board as one archive (Hermes `kanban boards export`).
fn export(k: &Kernel, target: Option<&str>, archive: Option<&str>, flags: &Map<String, Value>, as_json: bool) -> Result<String, String> {
    let slug = kanban::resolve_board(&k.paths.data, target.or_else(|| flags.get("board").and_then(Value::as_str)))?;
    let output = flags.get("output").and_then(Value::as_str).map(String::from).or_else(|| archive.map(String::from)).unwrap_or_else(|| format!("{slug}.tar"));
    let v = call(k, "kanban.export", json!({"board": slug, "output": output, "attachments": flags.get("no-attachments") != Some(&json!(true)), "logs": flags.get("include-logs") == Some(&json!(true))}))?;
    if as_json {
        return Ok(serde_json::to_string_pretty(&v).unwrap_or_default());
    }
    Ok(format!(
        "Exported board {:?} → {}\n  Size:        {} bytes\n  Tasks:       {}\n  Comments:    {}\n  Attachments: {}\nImport it with `seagent kanban import <archive>`.",
        v["board"].as_str().unwrap_or(""),
        v["archive"].as_str().unwrap_or(""),
        v["size"].as_u64().unwrap_or(0),
        v["counts"]["tasks"].as_u64().unwrap_or(0),
        v["counts"]["task_comments"].as_u64().unwrap_or(0),
        v["counts"]["attachment_files"].as_u64().unwrap_or(0)
    ))
}

/// `kanban import <archive> [--as slug] [--switch]` — always a NEW board (Hermes
/// `kanban boards import`).
fn import(k: &Kernel, archive: Option<&str>, flags: &Map<String, Value>, as_json: bool) -> Result<String, String> {
    let archive = archive.map(String::from).ok_or("usage: kanban import <archive> [--as slug] [--switch]")?;
    let v = call(k, "kanban.import", json!({"archive": archive, "as_slug": flags.get("as"), "switch": flags.get("switch") == Some(&json!(true))}))?;
    if as_json {
        return Ok(serde_json::to_string_pretty(&v).unwrap_or_default());
    }
    let slug = v["board"].as_str().unwrap_or("");
    let mut lines = vec![format!("Imported board {slug:?} ({}).", v["name"].as_str().unwrap_or(""))];
    if v["renamed"] == true {
        lines.push(format!("  Renamed from {:?} — that slug was taken.", v["requested_board"].as_str().unwrap_or("")));
    }
    lines.push(format!("  Path:  {}", v["path"].as_str().unwrap_or("")));
    lines.push(format!("  Tasks: {}", v["counts"]["tasks"].as_u64().unwrap_or(0)));
    for w in v["warnings"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        lines.push(format!("  Note:  {w}"));
    }
    if v["activated"] == true {
        lines.push(format!("  Active board is now {slug:?}."));
    } else {
        lines.push(format!("  Switch to it with `seagent kanban boards` / `--board {slug}`."));
    }
    Ok(lines.join("\n"))
}

pub fn cmd_kanban(c: &Ctx, a: &str) -> Result<Reply, String> {
    let argv = seagent_kernel::commands::split_args(a);
    let actor = c.sender.as_ref().map(|s| s.sender.clone()).filter(|s| !s.is_empty()).unwrap_or_else(|| c.k.cfg.kanban.identity.clone());
    text(run(c.k, &argv, &actor)?)
}

/// `seagent kanban …` (argv excludes `kanban`).
pub fn cli(k: &Kernel, argv: &[String]) -> Result<String, String> {
    run(k, argv, &k.cfg.kanban.identity.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slash;
    use crate::testkit::kit;

    fn a(s: &str) -> Vec<String> {
        seagent_kernel::commands::split_args(s)
    }

    #[test]
    fn kanban_cli_and_slash_drive_the_board() {
        let t = kit();
        assert!(run(&t.k, &a("init"), "me").unwrap().contains("board default ready"));
        let made = run(&t.k, &a("create \"write docs\" --body \"for the API\" --assignee alice --priority 2"), "me").unwrap();
        let tid = made.strip_prefix("created ").unwrap().to_string();
        let child = run(&t.k, &a(&format!("create tests --parent {tid}")), "me").unwrap().strip_prefix("created ").unwrap().to_string();
        let l = run(&t.k, &a("ls"), "me").unwrap();
        assert!(l.contains("write docs") && l.contains("@alice") && l.contains("tests"), "{l}");
        assert!(run(&t.k, &a("list --assignee alice"), "me").unwrap().lines().count() == 1);
        let short = &tid[..tid.len().min(6)];
        let sh = run(&t.k, &a(&format!("show {short}")), "me").unwrap();
        assert!(sh.contains("for the API") && sh.contains(&format!("children: {child}")), "{sh}");
        run(&t.k, &a(&format!("comment {tid} looks good")), "bob").unwrap();
        assert!(run(&t.k, &a(&format!("show {tid}")), "me").unwrap().contains("💬 bob: looks good"));
        assert!(run(&t.k, &a(&format!("assign {tid} carol")), "me").unwrap().contains("carol"));
        assert!(run(&t.k, &a("assignees"), "me").unwrap().contains("carol: 1"));
        assert!(run(&t.k, &a(&format!("block {tid} waiting on review")), "me").unwrap().starts_with("blocked"));
        run(&t.k, &a(&format!("unblock {tid}")), "me").unwrap();
        assert!(run(&t.k, &a(&format!("edit {tid} --title \"write the docs\"")), "me").unwrap().starts_with("edited"));
        assert!(run(&t.k, &a(&format!("show {tid}")), "me").unwrap().contains("write the docs"));
        assert!(run(&t.k, &a(&format!("complete {tid} --summary shipped --force")), "me").unwrap().starts_with("completed"));
        assert!(run(&t.k, &a(&format!("log {tid}")), "me").unwrap().contains("completed") || run(&t.k, &a(&format!("log {tid}")), "me").unwrap().contains("comment"));
        let js: Value = serde_json::from_str(&run(&t.k, &a("stats --json"), "me").unwrap()).unwrap();
        assert!(js.is_object(), "{js}");
        assert!(run(&t.k, &a("bogus"), "me").unwrap_err().contains("unknown kanban subcommand"));
        assert!(run(&t.k, &a("show zzz"), "me").unwrap_err().contains("not found"));
        assert!(run(&t.k, &a("board create ops --name Ops"), "me").unwrap().contains("created board ops"));
        assert!(run(&t.k, &a("boards"), "me").unwrap().contains("ops"));
        // Same parser behind /kanban.
        let c = super::super::tests::ctx(&t.k, &t.ws, None);
        let r = slash::run(&c, "/kanban ls").unwrap().text.unwrap();
        assert!(r.contains("write the docs"), "{r}");
        assert!(slash::run(&c, "/kanban create from chat").unwrap().text.unwrap().starts_with("created "));
    }

    #[test]
    fn the_kanban_dashboard_page_calls_only_served_methods() {
        // The Control UI's workboard page is served by seagent-app (`/ui/pages.js`) and talks ARP.
        const JS: &str = include_str!("../../../../ui/web/pages.js");
        let calls: std::collections::BTreeSet<String> = JS
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '_'))
            .filter(|t| t.starts_with("kanban.") && t.len() > "kanban.".len())
            .map(String::from)
            .collect();
        assert!(calls.len() >= 9, "the workboard page stopped driving the board: {calls:?}");
        for m in ["kanban.boards", "kanban.board", "kanban.show", "kanban.create", "kanban.move", "kanban.comment", "kanban.complete", "kanban.archive", "kanban.board_create"] {
            assert!(calls.contains(m), "the workboard page no longer uses {m}");
        }
        let t = kit();
        for m in &calls {
            assert!(methods::NAMES.contains(&m.as_str()), "pages.js calls `{m}`, which the kernel does not serve");
            // Dispatched (even when the arguments are missing) ⇒ the page can reach it.
            assert!(methods::call(&t.k, m, &json!({"board": "default"})).is_some(), "pages.js calls `{m}`, which `methods::call` does not dispatch");
        }
        // systemd: the packaged unit runs the daemon, which ticks the dispatcher and serves
        // `kanban.*`/`board.*` over ARP — one service covers the dashboard and the dispatcher.
        const UNIT: &str = include_str!("../../../../packaging/systemd/seagentd.service");
        assert!(UNIT.contains("ExecStart=%h/.local/bin/seagent daemon run"), "the systemd unit no longer starts seagentd");
        assert!(UNIT.contains("WantedBy=default.target"));
    }

    #[test]
    fn kanban_export_import_and_swarm_on_both_surfaces() {
        let t = kit();
        run(&t.k, &a("init"), "me").unwrap();
        let tid = run(&t.k, &a("create \"write docs\" --assignee alice"), "me").unwrap().strip_prefix("created ").unwrap().to_string();
        run(&t.k, &a(&format!("comment {tid} looks good")), "bob").unwrap();
        let data = t.k.paths.data.clone();
        let arc = data.join("boards/default.tar");

        // export: text output names the board, the counts and the archive.
        let out = run(&t.k, &a(&format!("export --output {}", arc.display())), "me").unwrap();
        assert!(out.contains("Exported board \"default\"") && out.contains("Tasks:       1") && out.contains("Comments:    1"), "{out}");
        assert!(out.contains("seagent kanban import"), "the export tells you how to import it: {out}");
        assert!(arc.is_file());
        // `--json` is machine-readable, `--no-attachments` changes the counts.
        let js: Value = serde_json::from_str(&run(&t.k, &a(&format!("export --output {} --json", data.join("b/j.tar").display())), "me").unwrap()).unwrap();
        assert_eq!(js["counts"]["tasks"], 1);
        assert_eq!(js["counts"]["attachment_files"], 0);
        // `kanban board export <slug>` is the Hermes-shaped alias.
        let alias = data.join("boards/alias.tar");
        assert!(run(&t.k, &a(&format!("board export default {}", alias.display())), "me").unwrap().contains("Exported board \"default\""));
        // A board that does not exist is an actionable error, not an empty archive.
        let e = run(&t.k, &a(&format!("export --board ghost --output {}/g.tar", data.display())), "me").unwrap_err();
        assert!(e.contains("board \"ghost\" does not exist"), "{e}");
        assert!(!data.join("g.tar").exists());
        // A missing archive argument is a usage error.
        assert!(run(&t.k, &a("import"), "me").unwrap_err().contains("usage: kanban import <archive>"));

        // import: always a new board, and it switches only when asked.
        let out = run(&t.k, &a(&format!("import {} --as copy", arc.display())), "me").unwrap();
        assert!(out.contains("Imported board \"copy\"") && out.contains("Tasks: 1"), "{out}");
        assert!(out.contains("Switch to it with"), "the import suggests how to reach it: {out}");
        let copied = run(&t.k, &a("ls --board copy"), "me").unwrap();
        assert!(copied.contains("write docs") && copied.contains("@alice"), "{copied}");
        assert!(run(&t.k, &a(&format!("show {tid} --board copy")), "me").unwrap().contains("💬 bob: looks good"), "comments travel with the board");
        // The source slug is taken → suffixed, and `default` never lands on `default`.
        let out = run(&t.k, &a(&format!("board import {} --as copy", arc.display())), "me").unwrap();
        assert!(out.contains("Imported board \"copy-2\""), "{out}");
        assert!(out.contains("Renamed from \"copy\""), "{out}");
        let out = run(&t.k, &a(&format!("import {}", arc.display())), "me").unwrap();
        assert!(out.contains("Imported board \"default-imported\"") && out.contains("Renamed from \"default\""), "{out}");
        // --switch activates the imported board.
        let out = run(&t.k, &a(&format!("import {} --as live --switch", arc.display())), "me").unwrap();
        assert!(out.contains("Active board is now \"live\""), "{out}");
        assert!(run(&t.k, &a("boards"), "me").unwrap().contains("* live"));

        // swarm: the whole graph is created from one command (Hermes `kanban swarm`).
        let out = run(&t.k, &a("swarm \"ship the docs site\" --worker writer:draft-intro:humanizer --worker researcher:collect-refs --verifier reviewer --synthesizer writer --tenant acme --priority 2"), "me").unwrap();
        assert!(out.starts_with("Swarm root: ") && out.contains("Workers: ") && out.contains("Verifier: ") && out.contains("Synthesizer: "), "{out}");
        let root = out.lines().next().unwrap().trim_start_matches("Swarm root: ").to_string();
        let workers = out.lines().nth(1).unwrap().trim_start_matches("Workers: ").to_string();
        assert_eq!(workers.split(", ").count(), 2);
        let ready = run(&t.k, &a("ls --status ready --board live"), "me").unwrap();
        assert!(ready.contains("draft-intro") && ready.contains("collect-refs"), "specialists start in parallel: {ready}");
        let shown = run(&t.k, &a(&format!("show {root} --board live")), "me").unwrap();
        assert!(shown.contains("status: done") && shown.contains("shared blackboard"), "the root is completed at once and stays the blackboard: {shown}");
        let js: Value = serde_json::from_str(&run(&t.k, &a("swarm \"another goal\" --worker w:t --verifier v --synthesizer s --created-by bob --idempotency-key k1 --json"), "me").unwrap()).unwrap();
        assert!(js["root_id"].is_string() && js["worker_ids"].as_array().unwrap().len() == 1, "{js}");
        assert!(run(&t.k, &a(&format!("show {} --board live", js["root_id"].as_str().unwrap())), "me").unwrap().contains("assignee bob"), "--created-by anchors the root card");
        // Idempotency: the same key returns the same swarm instead of duplicating it.
        let again: Value = serde_json::from_str(&run(&t.k, &a("swarm \"another goal\" --worker w:t --verifier v --synthesizer s --created-by bob --idempotency-key k1 --json"), "me").unwrap()).unwrap();
        assert_eq!(again["root_id"], js["root_id"]);
        // Argument errors are caught before anything is written.
        assert!(run(&t.k, &a("swarm \"g\" --verifier v --synthesizer s"), "me").unwrap_err().contains("at least one --worker is required"));
        assert!(run(&t.k, &a("swarm \"g\" --worker a:b --synthesizer s"), "me").unwrap_err().contains("--verifier is required"));
        assert!(run(&t.k, &a("swarm \"g\" --worker a:b --verifier v"), "me").unwrap_err().contains("--synthesizer is required"));
        assert!(run(&t.k, &a("swarm"), "me").unwrap_err().contains("usage: kanban swarm"));
        assert!(run(&t.k, &a("swarm \"g\" --worker nope --verifier v --synthesizer s"), "me").unwrap_err().contains("worker must be profile:title"));

        // Same parser behind `/kanban` (chat + dashboard drive identical code).
        let c = super::super::tests::ctx(&t.k, &t.ws, None);
        let chat = data.join("boards/chat.tar");
        assert!(slash::run(&c, &format!("/kanban export --output {}", chat.display())).unwrap().text.unwrap().contains("Exported board"));
        assert!(slash::run(&c, &format!("/kanban import {} --as chatcopy", chat.display())).unwrap().text.unwrap().contains("Imported board \"chatcopy\""));
        let sw = slash::run(&c, "/kanban swarm \"from chat\" --worker a:b --verifier v --synthesizer s").unwrap().text.unwrap();
        assert!(sw.starts_with("Swarm root: "), "{sw}");
    }
}
