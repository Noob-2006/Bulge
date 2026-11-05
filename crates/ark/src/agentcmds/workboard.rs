//! `/workboard list|show|create|move|dispatch|help` (OpenClaw `extensions/workboard/src/command.ts`)
//! and `/card` (the Workboard "card" widget, as a chat command): over the same board engine as
//! the `workboard_*` tools (`ark_kernel::kanban::workboard`). Card ids accept unambiguous
//! prefixes across boards; writes (create/move/dispatch) need an admin in channel chats.

use super::text;
use crate::slash::{Ctx, Reply};
use ark_kernel::kanban::{self, boards, dispatch, ops, store, workboard, workflow};
use serde_json::Value;

const HELP: &str = "/workboard list\n/workboard show <card-id>\n/workboard create <title>\n/workboard move <card-id> --status <status>\n/workboard dispatch";

fn card_line(c: &Value) -> String {
    let board = c["metadata"]["automation"]["boardId"].as_str().unwrap_or("default");
    let agent = c["agentId"].as_str().map(|a| format!(" @{a}")).unwrap_or_default();
    let id = c["id"].as_str().unwrap_or("");
    format!("{} {:<8} {:<6} [{board}]{agent} {}", &id[..id.len().min(8)], c["status"].as_str().unwrap_or(""), c["priority"].as_str().unwrap_or(""), c["title"].as_str().unwrap_or(""))
}

fn card_details(c: &Value) -> String {
    let mut l = vec![
        c["title"].as_str().unwrap_or("").to_string(),
        format!("id: {}", c["id"].as_str().unwrap_or("")),
        format!("status: {}", c["status"].as_str().unwrap_or("")),
        format!("priority: {}", c["priority"].as_str().unwrap_or("")),
        format!("board: {}", c["metadata"]["automation"]["boardId"].as_str().unwrap_or("default")),
    ];
    for (k, label) in [("agentId", "agent"), ("sessionKey", "session"), ("runId", "run")] {
        if let Some(v) = c[k].as_str() {
            l.push(format!("{label}: {v}"));
        }
    }
    if !c["metadata"]["archivedAt"].is_null() {
        l.push("archived: yes (excluded from dispatch)".into());
    }
    if let Some(n) = c["notes"].as_str().filter(|n| !n.is_empty()) {
        l.push(String::new());
        l.push(n.to_string());
    }
    l.join("\n")
}

fn card(data: &std::path::Path, q: &str) -> Result<Value, String> {
    let (slug, id) = workboard::resolve_prefix(data, q)?;
    let b = store::read_board(data, &slug)?;
    let t = b.task(&id).ok_or_else(|| format!("card {q} not found"))?;
    Ok(workboard::card_json(&b, &slug, t))
}

fn write_access(c: &Ctx) -> Result<(), String> {
    match &c.sender {
        Some(s) if !s.admin => Err("This command requires gateway scope: operator.write.".into()),
        _ => Ok(()),
    }
}

pub fn cmd_workboard(c: &Ctx, a: &str) -> Result<Reply, String> {
    let data = c.k.paths.data.clone();
    kanban::attach(c.k);
    let toks: Vec<&str> = a.split_whitespace().collect();
    let action = toks.first().copied().unwrap_or("list");
    let rest = toks.get(1..).unwrap_or(&[]);
    match action {
        "help" => text(HELP),
        "list" => {
            let mut rows = vec![];
            for m in boards::list_boards(&data, false) {
                let Ok(b) = store::read_board(&data, &m.slug) else { continue };
                for t in b.tasks.iter().filter(|t| t.archived_at.is_none() && t.status != "archived") {
                    rows.push(card_line(&workboard::card_json(&b, &m.slug, t)));
                }
            }
            rows.truncate(12);
            text(if rows.is_empty() { "No Workboard cards.".into() } else { rows.join("\n") })
        }
        "show" | "read" => {
            let Some(id) = rest.first() else { return text("Usage: /workboard show <card-id>") };
            text(card(&data, id).map(|c| card_details(&c)).unwrap_or_else(|e| e))
        }
        "create" | "move" | "dispatch" => {
            if let Err(e) = write_access(c) {
                return text(e);
            }
            match action {
                "create" => {
                    let title = rest.join(" ");
                    if title.trim().is_empty() {
                        return text("Usage: /workboard create <title>");
                    }
                    let slug = kanban::resolve_board(&data, None)?;
                    let actor = c.sender.as_ref().map(|s| s.sender.clone()).unwrap_or_else(|| c.k.cfg.kanban.identity.clone());
                    let id = store::with_board(&data, &slug, |b| ops::create_task(b, ops::NewTask { title: title.trim().into(), created_by: Some(actor), ..Default::default() }))?;
                    text(format!("Created {} {}", &id[..id.len().min(8)], title.trim()))
                }
                "move" => {
                    let id = rest.first().copied();
                    let st = rest.iter().position(|t| *t == "--status").and_then(|i| rest.get(i + 1)).copied();
                    let (Some(id), Some(st)) = (id, st) else { return text("Usage: /workboard move <card-id> --status <status>") };
                    if !workflow::WORKBOARD_STATUSES.contains(&st) {
                        return text(format!("status must be one of: {}.", workflow::WORKBOARD_STATUSES.join(", ")));
                    }
                    let (slug, tid) = match workboard::resolve_prefix(&data, id) {
                        Ok(x) => x,
                        Err(e) => return text(e),
                    };
                    let kill = store::with_board(&data, &slug, |b| ops::move_task(b, &data, &slug, &tid, st, "workboard", c.k.cfg.kanban.failure_limit))?;
                    for s in kill {
                        c.k.interrupt(&s);
                    }
                    text(card_line(&card(&data, &tid)?))
                }
                _ => {
                    let res = dispatch::tick_all(c.k, &c.k.cfg.kanban, &dispatch::TickOpts::default());
                    let started: Vec<_> = res.iter().flat_map(|r| r.spawned.iter().cloned()).collect();
                    let failed: Vec<_> = res.iter().flat_map(|r| r.spawn_failed.iter().cloned()).collect();
                    let promoted: u32 = res.iter().map(|r| r.promoted).sum();
                    let blocked: usize = res.iter().map(|r| r.auto_blocked.len()).sum();
                    // The emergency stop returns a pass with no work and `paused: Some(reason)`;
                    // say so first, or the operator reads "started=0" as "nothing was ready".
                    let mut l: Vec<String> = res.iter().filter_map(|r| r.paused.as_deref()).map(|m| format!("paused: {m}")).collect();
                    l.push(format!("dispatch: started={} failures={} promoted={promoted} blocked={blocked}", started.len(), failed.len()));
                    l.extend(started.iter().map(|(card, _, run)| format!("started {} run={run}", &card[..card.len().min(8)])));
                    l.extend(failed.iter().map(|(card, e)| format!("failed {} {e}", &card[..card.len().min(8)])));
                    text(l.join("\n"))
                }
            }
        }
        other => text(format!("Unknown Workboard action: {other}")),
    }
}

/// `/card [id]`: one card's details; without an id, the card this session is working on.
pub fn cmd_card(c: &Ctx, a: &str) -> Result<Reply, String> {
    let data = c.k.paths.data.clone();
    let q = a.trim();
    if !q.is_empty() {
        return text(card(&data, q).map(|c| card_details(&c)).unwrap_or_else(|e| e));
    }
    let Some(sid) = c.session.as_deref() else { return text("Usage: /card <card-id>") };
    for m in boards::list_boards(&data, false) {
        let Ok(b) = store::read_board(&data, &m.slug) else { continue };
        if let Some(t) = b.tasks.iter().find(|t| t.session_key.as_deref() == Some(sid) || b.runs_for(&t.id).iter().any(|r| r.worker_session.as_deref() == Some(sid))) {
            return text(card_details(&workboard::card_json(&b, &m.slug, t)));
        }
    }
    text("This session is not linked to a Workboard card. Usage: /card <card-id>")
}

#[cfg(test)]
mod tests {
    use super::super::tests::ctx;
    use crate::slash::{self, Sender, Surface};
    use crate::testkit::kit;

    #[test]
    fn workboard_and_card_commands() {
        let t = kit();
        let c = ctx(&t.k, &t.ws, None);
        let out = |c: &crate::slash::Ctx, l: &str| slash::run(c, l).unwrap().text.unwrap();
        assert_eq!(out(&c, "/workboard"), "No Workboard cards.");
        assert!(out(&c, "/workboard help").contains("/workboard move <card-id> --status <status>"));
        let made = out(&c, "/workboard create Ship the release");
        assert!(made.starts_with("Created ") && made.ends_with("Ship the release"), "{made}");
        let short = made.split_whitespace().nth(1).unwrap().to_string();
        let l = out(&c, "/workboard list");
        assert!(l.contains("[default]") && l.contains("Ship the release"), "{l}");
        let s = out(&c, &format!("/workboard show {short}"));
        assert!(s.starts_with("Ship the release\nid: ") && s.contains("board: default"), "{s}");
        assert!(out(&c, &format!("/workboard move {short} --status sideways")).starts_with("status must be one of: triage"));
        assert!(out(&c, &format!("/workboard move {short} --status review")).contains("review"));
        assert!(out(&c, &format!("/card {short}")).contains("status: review"));
        assert!(out(&c, "/card").contains("Usage: /card"));
        assert!(out(&c, "/workboard dispatch").starts_with("dispatch: started="));
        assert!(out(&c, "/workboard frob").starts_with("Unknown Workboard action: frob"));
        // `ark pause` (`<data>/ESTOP`): the pass dispatches nothing, and the human output says
        // why instead of leaving the operator to read `started=0` as "nothing was ready".
        ark_security::estop::engage(&c.k.paths.data, Some("maintenance")).unwrap();
        let d = out(&c, "/workboard dispatch");
        assert!(d.starts_with("paused: ark is paused (maintenance)"), "{d}");
        assert!(d.contains("`ark resume`") && d.contains("started=0"), "{d}");
        assert!(ark_security::estop::disengage(&c.k.paths.data));
        let mut ch = ctx(&t.k, &t.ws, None);
        ch.surface = Surface::Channel;
        ch.sender = Some(Sender { channel: "tg".into(), chat: "1".into(), sender: "u".into(), ..Default::default() });
        assert!(out(&ch, "/workboard create x").contains("operator.write"), "non-admin cannot write");
        assert!(out(&ch, "/workboard list").contains("Ship the release"), "reads are open");
    }
}
