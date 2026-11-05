//! `seagent session …`: list/show/resume/fork/search/compact/model/rm plus the extended
//! maintenance subcommands (`agentcmds::sessions`).
//!
//! Split out of `main.rs` (audit D3: a file may not grow past 3000 lines).

use super::*;

pub fn fmt_ms(ms: u64) -> String {
    seagent_kernel::util::fmt_time((ms / 1000) as i64, 480)
}

pub fn cmd_session(a: &Args) -> R {
    let sub = a.pos(0).unwrap_or("list");
    match sub {
        // `seagent session review <id> reviewed|flagged|cleared [--note TEXT]`,
        // `seagent session review list [--status flagged]`, `seagent session review show <id>`.
        "review" => {
            let c = build(a, approver_for(a, false))?;
            let k = &c.k;
            let (method, params) = match a.pos(1).unwrap_or("list") {
                "list" | "ls" => ("session.review.list", json!({"status": a.val("status").unwrap_or("")})),
                "show" | "get" => ("session.review.get", json!({"id": find_session(k, a.need(2, "session")?)?})),
                id => {
                    let status = a.need(2, "reviewed|flagged|cleared")?;
                    ("session.review.set", json!({"id": find_session(k, id)?, "status": status, "note": a.val("note").unwrap_or("")}))
                }
            };
            let v = seagent_kernel::session_review::rpc(k, method, &params).expect("known method").map_err(|(_, e)| Fail::Usage(e))?;
            if a.flag("json") || method == "session.review.get" {
                println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
                return Ok(0);
            }
            let rows = if method == "session.review.set" { vec![v] } else { v.as_array().cloned().unwrap_or_default() };
            if rows.is_empty() {
                println!("no reviewed or flagged sessions");
            }
            for r in rows {
                println!("{}  {:<8} {}  by {}  {}", r["session"].as_str().unwrap_or(""), r["status"].as_str().unwrap_or(""), fmt_ms(r["at_ms"].as_u64().unwrap_or(0)), r["by"].as_str().unwrap_or(""), term::one_line(r["note"].as_str().unwrap_or(""), 80));
            }
            Ok(0)
        }
        "list" | "ls" => {
            let c = build(a, approver_for(a, false))?;
            let lim = a.num::<usize>("limit").map_err(Fail::Usage)?.unwrap_or(20);
            let list: Vec<_> = c.k.store.list().into_iter().filter(|s| a.flag("all") || s.parent.is_none()).take(lim).collect();
            if a.flag("json") {
                println!("{}", json!(list.iter().map(|s| json!({"id":s.id,"title":s.title,"model":s.model,"workspace":s.workspace,"updated":fmt_ms(s.updated_ms),"messages":s.messages})).collect::<Vec<_>>()));
                return Ok(0);
            }
            if list.is_empty() {
                println!("no sessions");
            }
            for s in list {
                println!("{}  {}  {:>4} msgs  {:<28} {}", s.id, fmt_ms(s.updated_ms), s.messages, term::one_line(&s.model, 28), term::one_line(s.title.as_deref().unwrap_or(""), 50));
            }
            Ok(0)
        }
        "show" | "cat" => {
            let c = build(a, approver_for(a, false))?;
            let id = find_session(&c.k, a.need(1, "session")?)?;
            let events = c.k.store.read(&id).map_err(|e| e.to_string())?;
            if a.flag("json") {
                for e in &events {
                    println!("{}", serde_json::to_string(e).unwrap_or_default());
                }
                return Ok(0);
            }
            let v = project(&events);
            println!("session {id}\nworkspace {}\nmodel {} · {} turns · {} tokens · {} compactions\n", v.workspace, v.model, v.turns, v.usage.total(), v.compactions);
            for m in &v.messages {
                for b in &m.content {
                    match (m.role, b) {
                        (Role::User, Block::Text { text }) => println!("› {text}\n"),
                        (Role::Assistant, Block::Text { text }) if !text.is_empty() => println!("{text}\n"),
                        (_, Block::ToolUse { name, input, .. }) => println!("  → {name} {}", term::one_line(&input.to_string(), 120)),
                        (_, Block::ToolResult { content, is_error, .. }) => println!("  {} {}", if *is_error { "✗" } else { "✓" }, term::one_line(content, 120)),
                        _ => {}
                    }
                }
            }
            Ok(0)
        }
        "resume" | "continue" => {
            let c = build_agent(a, approver_for(a, true), false)?;
            let id = find_session(&c.k, a.pos(1).unwrap_or("last"))?;
            let prompt = a.rest(2);
            if !prompt.trim().is_empty() {
                c.k.submit(&id, &prompt, "cli").map_err(|e| e.to_string())?;
            }
            let code = run_foreground(&c, &id, a, RunOpts::default())?;
            Ok(code)
        }
        "fork" => {
            let c = build(a, approver_for(a, false))?;
            let src = find_session(&c.k, a.need(1, "session")?)?;
            let v = project(&c.k.store.read(&src).map_err(|e| e.to_string())?);
            let new = c.k.create_session(Path::new(&v.workspace), Some(&v.model), None, Some(&format!("fork of {src}"))).map_err(|e| e.to_string())?;
            let mut log = c.k.store.open(&new).map_err(|e| e.to_string())?;
            let upto = if v.dangling.is_empty() { v.messages.len() } else { v.messages.len() - 1 };
            for m in &v.messages[..upto] {
                log.append(EventKind::Message { message: m.clone(), usage: None, model: None, inbox: None }).map_err(|e| e.to_string())?;
            }
            println!("{new}");
            Ok(0)
        }
        "search" => {
            let c = build(a, approver_for(a, false))?;
            let q = a.rest(1);
            if q.trim().is_empty() {
                return usage("missing <query>");
            }
            let hits = c.k.store.search(&q, a.num::<usize>("limit").map_err(Fail::Usage)?.unwrap_or(20));
            if hits.is_empty() {
                println!("no matches");
                return Ok(1);
            }
            for h in hits {
                println!("{} #{}  {}", h.session, h.seq, term::one_line(&h.snippet, 140));
            }
            Ok(0)
        }
        "export" => export::cmd_export(a),
        "verify-export" => export::cmd_verify(a),
        "trajectory" => export::cmd_trajectory(a),
        "upload-trace" => export::cmd_upload_trace(a),
        "compact" => {
            let c = build(a, approver_for(a, false))?;
            let id = find_session(&c.k, a.need(1, "session")?)?;
            println!("{}", if c.k.compact(&id).map_err(|e| e.to_string())? { "compacted" } else { "nothing to compact" });
            Ok(0)
        }
        "model" => {
            let c = build(a, approver_for(a, false))?;
            let id = find_session(&c.k, a.need(1, "session")?)?;
            let m = a.need(2, "provider/model")?;
            c.k.set_model(&id, m).map_err(|e| e.to_string())?;
            println!("model → {m}");
            Ok(0)
        }
        "rm" | "delete" => {
            let c = build(a, approver_for(a, false))?;
            let id = find_session(&c.k, a.need(1, "session")?)?;
            c.k.store.remove(&id).map_err(|e| e.to_string())?;
            println!("removed {id}");
            Ok(0)
        }
        // Extended maintenance (Hermes `hermes sessions …`, OpenClaw `sessions-cli`).
        "rename" | "prune" | "archive" | "unarchive" | "pin" | "unpin" | "pinned" | "label" | "group" | "stats" | "import" | "repair" => agentcmds::sessions::cli(a).map(|s| {
            if !s.is_empty() { println!("{s}"); }
            0
        }).map_err(Fail::Msg),
        other => usage(format!("unknown `session {other}`")),
    }
}
