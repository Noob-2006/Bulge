//! `seagent approvals …`, `seagent security …`, `seagent pause` / `seagent resume`.
//!
//! - approvals: status, test (dry-run verdict, exit 0 allow / 2 ask / 3 deny), suggest
//!   (mine allowed decisions into allowlist proposals), list/allow/revoke durable grants,
//!   session toggles (yolo, elevated, exec) — Hermes `hermes approvals`, OpenClaw
//!   `openclaw approvals` / `exec-policy`.
//! - security audit: config foot-guns (OpenClaw `security audit`, `--fix`, `--deep`) and
//!   the OSV supply-chain audit (Hermes `hermes security audit`).
//! - security scan / plugins / check-url / creds: plugin guard, capability consent,
//!   URL policy and credential-file mounts.

use crate::args::Args;
use crate::{usage, Fail, R};
use seagent_kernel::config::{project_config, Config, Paths};
use seagent_kernel::kernel::Kernel;
use seagent_security::approvals as ap;
use seagent_security::broker::Broker;
use seagent_security::{estop, osv, plugin_guard, url_safety};
use serde_json::{json, Value};
#[cfg(all(unix, test))]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub const HELP_LINES: &str = "  seagent approvals status | test -- <command…> | suggest [--days N] [--min-count N] [--apply 1,3]
                 mode [manual|smart|auto|off] | pending | resolve <id> once|session|permanent|deny [--reason T]
                 queue [preview] | queue allow|deny <id> | queue allow|deny --group N
                 list | allow <glob> [--exec] | revoke <id|pattern> | yolo|elevated|exec … -s ID
  seagent exec-policy show [-s ID] | preset yolo|cautious|deny-all | set [--security S] [--ask A] [--ask-fallback S]
  seagent security audit [--deep] [--fix] [--supply-chain] [--fail-on LEVEL] | scan <dir> | plugins [accept <name>]
               check-url <url> | creds
  seagent pause [reason…] | status | resume   global emergency stop for scheduled/channel work";

fn session_arg(k: &Kernel, a: &Args) -> Result<Option<String>, Fail> {
    match a.val("session") {
        Some(q) => {
            let all = k.store.list();
            let m: Vec<_> = all.into_iter().filter(|s| s.id == q || s.id.starts_with(q)).collect();
            match m.len() {
                1 => Ok(Some(m[0].id.clone())),
                0 => Err(format!("no session matches `{q}`").into()),
                _ => Err(format!("`{q}` is ambiguous").into()),
            }
        }
        None => Ok(None),
    }
}

pub fn cmd_approvals(a: &Args, k: &Kernel, ws: &Path) -> R {
    let data = k.paths.data.clone();
    let cfg = &k.cfg.approvals;
    match a.pos(0).unwrap_or("status") {
        // Deferred approvals (§0-2 #03): calls that needed the owner while nobody was
        // there. Answering one grants exactly that call, for `grant_ttl_days`.
        "queue" => {
            let items = ap::deferred(&data);
            match a.pos(1) {
                // gen2-409 (§0-2 #05): same-kind calls grouped with their impacts, answered at once.
                Some("preview") => {
                    let groups = ap::deferred_groups(&data);
                    if a.flag("json") {
                        println!("{}", json!(groups));
                    } else if groups.is_empty() {
                        println!("No deferred approvals.");
                    } else {
                        for (i, g) in groups.iter().enumerate() {
                            println!("[{}] {} × {}  tier {}  {}", i + 1, g.ids.len(), g.tool, g.tier, g.reason);
                            for (id, imp) in g.ids.iter().zip(&g.impacts).take(20) {
                                println!("      {id}  {imp}");
                            }
                            if g.ids.len() > 20 {
                                println!("      … {} more", g.ids.len() - 20);
                            }
                        }
                        println!("\n`seagent approvals queue allow --group N` answers a whole group once (tier 3 is never batched); `deny --group N` closes it.");
                    }
                    return Ok(0);
                }
                Some("allow") | Some("deny") if a.val("group").is_some() => {
                    let allow = a.pos(1) == Some("allow");
                    let n: usize = a.num("group").map_err(Fail::Usage)?.unwrap_or(0);
                    let groups = ap::deferred_groups(&data);
                    let g = groups.get(n.wrapping_sub(1)).ok_or_else(|| Fail::Usage(format!("group {n} out of range (1..{}); see `seagent approvals queue preview`", groups.len())))?;
                    let done = ap::resolve_group(&data, g, allow, cfg.grant_ttl_days, "cli")?;
                    println!("{} {done} queued {} call(s) ({})", if allow { "allowed" } else { "denied" }, g.tool, g.reason);
                    return Ok(0);
                }
                Some("allow") | Some("deny") => {
                    let allow = a.pos(1) == Some("allow");
                    let id = a.pos(2).ok_or_else(|| Fail::Usage("approvals queue allow|deny <id> | --group N".into()))?;
                    match ap::resolve_deferred(&data, id, allow, cfg.grant_ttl_days)? {
                        Some(it) => println!("{} {} ({})", if allow { "allowed" } else { "denied" }, it.tool, it.reason),
                        None => println!("no pending item `{id}`"),
                    }
                    return Ok(0);
                }
                _ => {}
            }
            if a.flag("json") {
                println!("{}", json!(items.iter().map(|d| json!({"id": d.id, "session": d.session, "tool": d.tool, "tier": d.tier, "summary": d.summary, "reason": d.reason, "created_at": d.created_at})).collect::<Vec<_>>()));
            } else if items.is_empty() {
                println!("No deferred approvals.");
            } else {
                for d in &items {
                    println!("{}  tier {}  {}  {}\n    {}", d.id, d.tier, d.tool, d.summary, d.reason);
                }
                println!("\n`seagent approvals queue allow <id>` runs it (grant for {} days); `deny <id>` closes it.", cfg.grant_ttl_days);
            }
            Ok(0)
        }
        "status" | "show" | "get" => {
            let sid = session_arg(k, a)?;
            let mut v = ap::describe(cfg, &data, sid.as_deref());
            let paused = estop::state(&data);
            v["paused"] = json!(paused.is_some());
            v["pause_reason"] = json!(paused.as_ref().and_then(|p| p.0.clone()));
            if a.flag("json") {
                println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            } else {
                println!("mode: {}{}", v["mode"].as_str().unwrap_or(""), if ap::process_yolo() { " (process --yolo / SEAGENT_YOLO active)" } else { "" });
                println!("exec: security={} ask={} ask_fallback={} safe_bins={}", v["exec"]["security"].as_str().unwrap_or(""), v["exec"]["ask"].as_str().unwrap_or(""), v["exec"]["ask_fallback"].as_str().unwrap_or(""), cfg.exec.safe_bins.join(","));
                println!("deny rules: {} · command allowlist: {} · durable grants: {} · strict_inline_eval: {}", cfg.deny.len(), cfg.allowlist.len(), v["durable_grants"], cfg.strict_inline_eval);
                println!("cron_mode: {} · unattended_mode: {} · elevated: {}", v["cron_mode"].as_str().unwrap_or(""), v["unattended_mode"].as_str().unwrap_or(""), if cfg.elevated.enabled { "enabled" } else { "disabled" });
                println!("trust presets: owner={} channel={} stranger={} · deferred: {}", v["trust_presets"]["owner"].as_str().unwrap_or(""), v["trust_presets"]["channel"].as_str().unwrap_or(""), v["trust_presets"]["stranger"].as_str().unwrap_or(""), v["deferred"]);
                match ap::fatigue_check(&data, cfg.fatigue_daily_asks) {
                    Ok(l) => println!("approval load: {l}"),
                    Err(w) => println!("approval load: WARNING {w}"),
                }
                if let Some((r, at)) = &paused {
                    println!("PAUSED since {}{} — `seagent resume` to continue", at.as_deref().unwrap_or("?"), r.as_ref().map(|r| format!(" ({r})")).unwrap_or_default());
                }
                if let Some(s) = sid {
                    println!("session {s}: yolo={} elevated={} exec={}", v["session_yolo"], v["elevated"]["level"].as_str().unwrap_or(""), v["session_exec"]);
                }
            }
            Ok(0)
        }
        "test" => {
            let command = a.rest(1);
            if command.trim().is_empty() {
                return usage("approvals test -- <command…>");
            }
            let sid = session_arg(k, a)?;
            let e = seagent_kernel::secgate::explain(k, sid.as_deref(), ws, &command);
            if a.flag("json") {
                println!("{}", json!({"command": command, "verdict": e.verdict, "rule": e.rule, "trace": e.trace}));
            } else {
                println!("verdict: {}\nrule: {}", e.verdict.to_uppercase(), e.rule);
                for t in &e.trace {
                    println!("  {t}");
                }
            }
            Ok(match e.verdict {
                "allow" => 0,
                "ask" => 2,
                _ => 3,
            })
        }
        "suggest" => {
            let days: u64 = a.num("days").map_err(Fail::Usage)?.unwrap_or(90);
            let min: usize = a.num("min-count").map_err(Fail::Usage)?.unwrap_or(2);
            let limit: usize = a.num("limit").map_err(Fail::Usage)?.unwrap_or(20);
            let since = if days == 0 { 0 } else { seagent_kernel::event::now_ms().saturating_sub(days * 86_400_000) };
            let props = seagent_kernel::secgate::suggest(k, since, min, limit);
            if let Some(spec) = a.val("apply") {
                let mut applied = vec![];
                for part in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    let n: usize = part.parse().map_err(|_| Fail::Usage(format!("invalid selection `{part}`")))?;
                    let p = props.get(n.wrapping_sub(1)).ok_or_else(|| Fail::Usage(format!("selection {n} out of range (1..{})", props.len())))?;
                    ap::add_grant(&data, ap::GrantKind::Command, &p.0, None, "suggest")?;
                    applied.push(p.0.clone());
                }
                if a.flag("json") {
                    println!("{}", json!({"applied": applied}));
                } else {
                    println!("added {} allowlist entr{}: {}", applied.len(), if applied.len() == 1 { "y" } else { "ies" }, applied.join(", "));
                }
                return Ok(0);
            }
            if a.flag("json") {
                println!("{}", json!(props.iter().map(|(g, c, e)| json!({"pattern": g, "count": c, "examples": e})).collect::<Vec<_>>()));
            } else if props.is_empty() {
                println!("No allowlist candidates found in approval history (see --min-count/--days). Destructive commands are never proposed.");
            } else {
                println!("Proposed command allowlist additions (from approval history):\n");
                for (i, (g, c, ex)) in props.iter().enumerate() {
                    println!("  {}. {g}    — approved {c}x", i + 1);
                    for e in ex {
                        println!("       e.g. {e}");
                    }
                }
                println!("\nNothing has been changed. Apply with: seagent approvals suggest --apply 1,3");
            }
            Ok(0)
        }
        "list" | "grants" => {
            let g = ap::grants(&data);
            if a.flag("json") {
                println!("{}", serde_json::to_string_pretty(&g).unwrap_or_default());
            } else {
                for p in &cfg.allowlist {
                    println!("config    command  {p}");
                }
                for p in &cfg.exec.allowlist {
                    println!("config    exec     {p}");
                }
                for x in &g {
                    println!("{}  {:<8} {}{}{}", x.id, format!("{:?}", x.kind).to_lowercase(), x.pattern, x.gate.as_ref().map(|g| format!("  [{g}]")).unwrap_or_default(), x.last_used_command.as_ref().map(|c| format!("  (last: {c})")).unwrap_or_default());
                }
                if g.is_empty() && cfg.allowlist.is_empty() && cfg.exec.allowlist.is_empty() {
                    println!("no allowlist entries");
                }
            }
            Ok(0)
        }
        "allow" => {
            let pat = a.rest(1);
            if pat.trim().is_empty() {
                return usage("approvals allow <command glob> | --exec <executable path glob>");
            }
            let kind = if a.flag("exec") { ap::GrantKind::Exec } else { ap::GrantKind::Command };
            let id = ap::add_grant(&data, kind, pat.trim(), None, "manual")?;
            println!("added {id}");
            Ok(0)
        }
        "revoke" | "rm" => {
            let n = ap::remove_grant(&data, a.need(1, "id|pattern")?)?;
            println!("removed {n}");
            Ok(if n == 0 { 1 } else { 0 })
        }
        sub @ ("yolo" | "elevated" | "exec") => {
            let sid = session_arg(k, a)?.ok_or_else(|| Fail::Usage(format!("approvals {sub} needs -s <session>")))?;
            let line = format!("/{sub} {}", a.rest(1));
            println!("{}", seagent_kernel::secgate::chat_command(k, &line, Some(&sid), None).unwrap_or_default());
            Ok(0)
        }
        "mode" => {
            // Hermes `/approvals [manual|smart|off]`: a persistent profile setting.
            let Some(m) = a.pos(1) else {
                println!("approval mode: {} (persistent setting; change with `seagent approvals mode manual|smart|auto|off`)", mode_name(cfg.mode));
                return Ok(0);
            };
            if parse_mode(m).is_none() {
                return usage("approvals mode manual|smart|auto|off");
            }
            println!("{}", persist_mode(&k.paths, ws, m)?);
            Ok(0)
        }
        "pending" => {
            // OpenClaw `approvals pending`: what the daemon is waiting on.
            let r = seagent_kernel::daemon::call(&k.paths.socket(), "gate.pending", json!({}))?;
            let items: Vec<Value> = r.as_array().cloned().unwrap_or_default().into_iter().filter(|i| i["kind"] == "approval").collect();
            if a.flag("json") {
                println!("{}", Value::Array(items));
            } else if items.is_empty() {
                println!("no pending approvals");
            } else {
                for i in &items {
                    println!("{}  [{}] {} — {}  {}", i["id"].as_str().unwrap_or(""), i["gate"].as_str().unwrap_or(""), i["tool"].as_str().unwrap_or(""), i["reason"].as_str().unwrap_or(""), crate::term::one_line(i["summary"].as_str().unwrap_or(""), 100));
                }
            }
            Ok(0)
        }
        "resolve" | "answer" => {
            // OpenClaw `approvals resolve <id> <allow-once|allow-always|deny> [--reason]`.
            let id = a.need(1, "id")?;
            let answer = resolve_answer(&a.rest(2), a.val("reason")).ok_or_else(|| Fail::Usage("approvals resolve <id> once|session|permanent|deny [--reason TEXT]".into()))?;
            seagent_kernel::daemon::call(&k.paths.socket(), "gate.answer", json!({"id": id, "answer": answer}))?;
            println!("resolved {id}: {}", answer.split_whitespace().next().unwrap_or(""));
            Ok(0)
        }
        other => usage(format!("unknown `approvals {other}`")),
    }
}

/// Persist `approvals.mode` (Hermes `/approvals <mode>`, `seagent approvals mode <mode>`).
pub fn persist_mode(paths: &Paths, ws: &Path, mode: &str) -> Result<String, String> {
    let want = parse_mode(mode).ok_or("usage: /approvals [manual|smart|auto|off]")?;
    let p = persist(paths, ws, "approvals", &[("mode", toml_str(mode_name(want)))], |c| c.approvals.mode == want)?;
    Ok(format!("approval mode: {} (persistent setting, saved to {}; applies to processes started from now on)", mode_name(want), p.display()))
}

fn mode_name(m: ap::Mode) -> &'static str {
    match m {
        ap::Mode::Manual => "manual",
        ap::Mode::Smart => "smart",
        ap::Mode::Auto => "auto",
        ap::Mode::Off => "off",
    }
}

fn parse_mode(s: &str) -> Option<ap::Mode> {
    Some(match s.trim().to_ascii_lowercase().as_str() {
        "manual" => ap::Mode::Manual,
        "smart" => ap::Mode::Smart,
        "auto" => ap::Mode::Auto,
        "off" => ap::Mode::Off,
        _ => return None,
    })
}

/// Normalise a decision word (+ optional reason) to the answer the approvers parse.
/// None when the word is not a decision (typos must not silently deny or allow).
pub fn resolve_answer(decision: &str, reason: Option<&str>) -> Option<String> {
    let d = decision.trim();
    let word = d.split(|c: char| c.is_whitespace() || c == ':').next().unwrap_or("").to_ascii_lowercase();
    let known = ["once", "allow", "yes", "y", "allow-once", "approve", "session", "always", "a", "permanent", "allow-always", "forever", "p", "deny", "no", "n", "reject"];
    if !known.contains(&word.as_str()) {
        return None;
    }
    if word == "p" {
        return Some("permanent".into());
    }
    match ap::parse_answer(d) {
        ("deny", r) => {
            let r = reason.map(str::to_string).or(r).unwrap_or_default();
            Some(format!("deny {r}").trim_end().to_string())
        }
        (c, _) => Some(c.to_string()),
    }
}

fn toml_str(s: &str) -> String {
    toml::Value::String(s.into()).to_string()
}

/// Set `key = value` lines in `[section]` of a TOML text, keeping everything else
/// (comments, order). Missing keys go right under the header; a missing section is appended.
pub fn set_toml_keys(text: &str, section: &str, kv: &[(&str, String)]) -> String {
    let header = format!("[{section}]");
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    let is_header = |l: &str| l.trim_start().starts_with('[');
    let head_of = |l: &str| l.split('#').next().unwrap_or("").trim().to_string();
    let Some(h) = lines.iter().position(|l| head_of(l) == header) else {
        let mut out = text.trim_end().to_string();
        if !out.is_empty() {
            out.push_str("\n\n");
        }
        out.push_str(&header);
        for (k, v) in kv {
            out.push_str(&format!("\n{k} = {v}"));
        }
        out.push('\n');
        return out;
    };
    let end = lines.iter().skip(h + 1).position(|l| is_header(l)).map(|i| h + 1 + i).unwrap_or(lines.len());
    let mut missing = vec![];
    for (k, v) in kv {
        let found = (h + 1..end).find(|&i| lines[i].trim_start().strip_prefix(k).is_some_and(|r| r.trim_start().starts_with('=')));
        match found {
            Some(i) => lines[i] = format!("{k} = {v}"),
            None => missing.push(format!("{k} = {v}")),
        }
    }
    for (j, l) in missing.into_iter().enumerate() {
        lines.insert(h + 1 + j, l);
    }
    lines.join("\n") + "\n"
}

/// Write keys into the user config, then reload and check they took effect (a project
/// config or an inline table may shadow them); on failure the file is restored.
fn persist(paths: &Paths, ws: &Path, section: &str, kv: &[(&str, String)], ok: impl Fn(&Config) -> bool) -> Result<PathBuf, String> {
    let p = paths.user_config();
    let before = std::fs::read_to_string(&p).ok();
    let after = set_toml_keys(before.as_deref().unwrap_or(""), section, kv);
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    std::fs::write(&p, &after).map_err(|e| format!("{}: {e}", p.display()))?;
    let _ = crate::ops::hostos::set_mode(&p, 0o600);
    let restore = || match &before {
        Some(t) => std::fs::write(&p, t).map_err(|e| e.to_string()),
        None => std::fs::remove_file(&p).map_err(|e| e.to_string()),
    };
    match Config::load(Some(&p), Some(&project_config(ws)), &[]) {
        Ok(c) if ok(&c) => Ok(p),
        Ok(_) => {
            restore()?;
            Err(format!("the new value did not become effective (another setting shadows [{section}] — check {} and {}); nothing changed", p.display(), project_config(ws).display()))
        }
        Err(e) => {
            restore()?;
            Err(format!("config would not load after the change ({e}); nothing changed"))
        }
    }
}

const EXEC_PRESETS: &[(&str, ap::ExecSecurity, ap::ExecAsk, ap::ExecSecurity)] = &[
    ("yolo", ap::ExecSecurity::Full, ap::ExecAsk::Off, ap::ExecSecurity::Full),
    ("cautious", ap::ExecSecurity::Allowlist, ap::ExecAsk::OnMiss, ap::ExecSecurity::Deny),
    ("deny-all", ap::ExecSecurity::Deny, ap::ExecAsk::Off, ap::ExecSecurity::Deny),
];

pub(crate) fn exec_policy_json(cfg: &Config, paths: &Paths) -> Value {
    let e = &cfg.approvals.exec;
    let exec_grants: Vec<String> = ap::grants(&paths.data).into_iter().filter(|g| g.kind == ap::GrantKind::Exec).map(|g| g.pattern).collect();
    json!({
        "configPath": paths.user_config(), "approvalsPath": ap::allowlist_path(&paths.data), "approvalsExists": ap::allowlist_path(&paths.data).exists(),
        "security": e.security.as_str(), "ask": e.ask.as_str(), "askFallback": e.ask_fallback.as_str(),
        "safeBins": e.safe_bins, "allowlist": e.allowlist, "grants": exec_grants, "strictInlineEval": cfg.approvals.strict_inline_eval,
        "note": "Session /exec overrides can only tighten security/ask, and apply to the next turn.",
    })
}

fn print_exec_policy(v: &Value) {
    println!("exec policy ({})", v["configPath"].as_str().unwrap_or(""));
    println!("  security     {}\n  ask          {}\n  ask_fallback {}", v["security"].as_str().unwrap_or(""), v["ask"].as_str().unwrap_or(""), v["askFallback"].as_str().unwrap_or(""));
    let list = |k: &str| v[k].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default();
    println!("  safe_bins    {}\n  allowlist    {}\n  grants       {}", list("safeBins"), list("allowlist"), list("grants"));
    println!("  {}", v["note"].as_str().unwrap_or(""));
}

/// `seagent exec-policy show | preset <yolo|cautious|deny-all> | set --security … --ask … --ask-fallback …`
/// (OpenClaw `exec-policy`): the `[approvals.exec]` defaults every session starts from.
pub fn cmd_exec_policy(a: &Args, cfg: &Config, paths: &Paths, ws: &Path) -> R {
    let (sec, ask, fb, label) = match a.pos(0).unwrap_or("show") {
        "show" | "get" => {
            let mut v = exec_policy_json(cfg, paths);
            if let Some(q) = a.val("session") {
                v["session"] = json!(q);
                v["sessionState"] = serde_json::to_value(ap::session_state(&paths.data, q).exec).unwrap_or_default();
            }
            if a.flag("json") {
                println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            } else {
                print_exec_policy(&v);
                if v.get("sessionState").is_some() {
                    println!("  session {}: {}", v["session"].as_str().unwrap_or(""), v["sessionState"]);
                }
            }
            return Ok(0);
        }
        "preset" => {
            let name = a.need(1, "name")?;
            let Some(&(_, s, k, f)) = EXEC_PRESETS.iter().find(|p| p.0 == name) else { return usage(format!("unknown exec-policy preset: {name} (yolo, cautious, deny-all)")) };
            (Some(s), Some(k), Some(f), json!({"preset": name}))
        }
        "set" => {
            let p = |flag: &str| a.val(flag).map(|v| ap::ExecSecurity::parse(v).ok_or_else(|| Fail::Usage(format!("--{flag}: `{v}` (deny|allowlist|full)")))).transpose();
            let s = p("security")?;
            let f = p("ask-fallback")?;
            let k = a.val("ask").map(|v| ap::ExecAsk::parse(v).ok_or_else(|| Fail::Usage(format!("--ask: `{v}` (off|on-miss|always)")))).transpose()?;
            if s.is_none() && k.is_none() && f.is_none() {
                return usage("Provide at least one of --security, --ask, or --ask-fallback.");
            }
            (s, k, f, json!({"applied": {"security": s.map(|x| x.as_str()), "ask": k.map(|x| x.as_str()), "askFallback": f.map(|x| x.as_str())}}))
        }
        other => return usage(format!("unknown `exec-policy {other}`")),
    };
    let mut kv = vec![];
    if let Some(s) = sec {
        kv.push(("security", toml_str(s.as_str())));
    }
    if let Some(k) = ask {
        kv.push(("ask", toml_str(k.as_str())));
    }
    if let Some(f) = fb {
        kv.push(("ask_fallback", toml_str(f.as_str())));
    }
    persist(paths, ws, "approvals.exec", &kv, |c| sec.is_none_or(|s| c.approvals.exec.security == s) && ask.is_none_or(|k| c.approvals.exec.ask == k) && fb.is_none_or(|f| c.approvals.exec.ask_fallback == f))?;
    let now = Config::load(Some(&paths.user_config()), Some(&project_config(ws)), &[])?;
    let mut v = exec_policy_json(&now, paths);
    if a.flag("json") {
        if let (Value::Object(m), Value::Object(l)) = (&mut v, label) {
            m.extend(l);
        }
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
    } else {
        match label.get("preset") {
            Some(p) => println!("Applied exec-policy preset: {}\n", p.as_str().unwrap_or("")),
            None => println!("Synchronized local exec policy.\n"),
        }
        print_exec_policy(&v);
    }
    Ok(0)
}

/// Persist `[approvals.exec]` from the console (same validation and rollback as
/// `seagent exec-policy set`), returning the effective policy.
pub(crate) fn set_exec_policy(paths: &Paths, ws: &Path, security: &str, ask: &str, fallback: &str) -> Result<Value, String> {
    let sec = ap::ExecSecurity::parse(security).ok_or_else(|| format!("security `{security}`: use deny|allowlist|full"))?;
    let ask = ap::ExecAsk::parse(ask).ok_or_else(|| format!("ask `{ask}`: use off|on-miss|always"))?;
    let fb = ap::ExecSecurity::parse(fallback).ok_or_else(|| format!("ask_fallback `{fallback}`: use deny|allowlist|full"))?;
    let kv = [("security", toml_str(sec.as_str())), ("ask", toml_str(ask.as_str())), ("ask_fallback", toml_str(fb.as_str()))];
    persist(paths, ws, "approvals.exec", &kv, |c| c.approvals.exec.security == sec && c.approvals.exec.ask == ask && c.approvals.exec.ask_fallback == fb)?;
    let now = Config::load(Some(&paths.user_config()), Some(&project_config(ws)), &[])?;
    Ok(exec_policy_json(&now, paths))
}

pub fn cmd_pause(a: &Args, paths: &Paths, resume: bool) -> R {
    if resume {
        if estop::disengage(&paths.data) {
            println!("▶️  seagent resumed — scheduled jobs, goals and channel turns pick up on the next tick.");
        } else {
            println!("seagent is not paused (no sentinel at {}).", estop::sentinel(&paths.data).display());
        }
        return Ok(0);
    }
    if a.pos(0) == Some("status") {
        match estop::state(&paths.data) {
            Some((r, at)) => println!("paused since {}{}", at.unwrap_or_else(|| "?".into()), r.map(|r| format!(" ({r})")).unwrap_or_default()),
            None => println!("not paused"),
        }
        return Ok(0);
    }
    let reason = a.val("reason").map(String::from).unwrap_or_else(|| a.rest(0));
    let already = estop::is_engaged(&paths.data);
    let p = estop::engage(&paths.data, Some(reason.as_str()).filter(|r| !r.trim().is_empty()))?;
    let why = estop::state(&paths.data).and_then(|(r, _)| r).map(|r| format!(" — reason: {r}")).unwrap_or_default();
    println!("⏸️  {}{why}\n    sentinel: {}\n    Scheduled jobs, goals and new channel turns are on hold. In-flight work keeps running.\n    Run `seagent resume` to lift the pause.", if already { "Still paused" } else { "seagent paused" }, p.display());
    Ok(0)
}

// ───────────────────────── security audit ─────────────────────────

#[derive(Debug, Clone)]
pub struct Finding {
    pub id: &'static str,
    pub severity: &'static str,
    pub title: String,
    pub detail: String,
    pub fix: Option<String>,
}

fn f(id: &'static str, severity: &'static str, title: impl Into<String>, detail: impl Into<String>, fix: Option<&str>) -> Finding {
    Finding { id, severity, title: title.into(), detail: detail.into(), fix: fix.map(String::from) }
}

fn mode_of(p: &Path) -> Option<u32> {
    crate::ops::hostos::mode_of(p).ok().map(|m| m & 0o777)
}

fn is_loopback(listen: &str) -> bool {
    seagent_security::exposure::is_loopback(listen)
}

// ─────────────────── public exposure (A8–A12) ───────────────────

/// One listening surface, owned so it can be built from a [`Config`] and lent to
/// `seagent_security::exposure::Surface` (which borrows its strings).
pub(crate) struct SurfaceCfg {
    pub name: String,
    pub listen: String,
    pub tls: bool,
    pub behind_proxy: bool,
    pub allow_public: bool,
    pub auth: seagent_security::exposure::AuthStrength,
    pub origins: Vec<String>,
    pub rate_limit: bool,
    pub enabled: bool,
    pub lan: bool,
}

impl SurfaceCfg {
    pub(crate) fn as_surface(&self) -> seagent_security::exposure::Surface<'_> {
        seagent_security::exposure::Surface {
            name: &self.name,
            listen: &self.listen,
            tls: self.tls,
            behind_proxy: self.behind_proxy,
            allow_public: self.allow_public,
            auth: self.auth,
            origins: &self.origins,
            rate_limit: self.rate_limit,
            enabled: self.enabled,
            lan: self.lan,
        }
    }
}

/// Channel settings that prove the caller is the platform, not an arbitrary client.
const CHANNEL_SECRETS: &[&str] = &["secret", "token", "verification_token", "encoding_aes_key", "signing_secret", "app_secret", "channel_secret", "auth_token", "push_token", "password"];
/// Settings naming a public https front door (tunnel or reverse proxy).
const CHANNEL_PUBLIC_URLS: &[&str] = &["webhook_url", "public_url", "public_base", "inbound_url", "outbound_url"];

/// Every surface this config can open a listening socket on, with what protects it.
pub(crate) fn exposure_surfaces(cfg: &Config) -> Vec<SurfaceCfg> {
    let mut out = Vec::new();
    if let Ok(app) = seagent_app::AppConfig::parse(&cfg.app) {
        let s = seagent_app::exposure::surface(&app);
        out.push(SurfaceCfg {
            name: "app server".into(),
            listen: s.listen.to_string(),
            tls: s.tls,
            behind_proxy: s.behind_proxy,
            allow_public: s.allow_public,
            auth: s.auth,
            origins: s.origins.to_vec(),
            rate_limit: s.rate_limit,
            enabled: s.enabled,
            lan: s.lan,
        });
    }
    // Channels open their own listeners (`listen`) for callback webhooks.
    for (name, t) in &cfg.channels {
        let Some(listen) = t.get("listen").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()) else { continue };
        let signed = CHANNEL_SECRETS.iter().any(|k| t.get(*k).is_some_and(|v| !v.is_str() || v.as_str().is_some_and(|s| !s.trim().is_empty())));
        let https = CHANNEL_PUBLIC_URLS.iter().any(|k| t.get(*k).and_then(|v| v.as_str()).is_some_and(|v| v.trim().to_ascii_lowercase().starts_with("https://")));
        // Who may call: a CIDR allowlist if the channel has one, otherwise a verified
        // signature — that is a channel's equivalent of an origin restriction.
        let mut callers: Vec<String> = t.get("allowed_source_cidrs").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
        if callers.is_empty() && signed {
            callers.push("signed-request".into());
        }
        out.push(SurfaceCfg {
            name: format!("channels.{name}"),
            listen: listen.to_string(),
            tls: false,
            behind_proxy: https,
            // A channel has no `allow_public` key yet: writing a non-loopback `listen` is the opt-in.
            allow_public: true,
            auth: if signed { seagent_security::exposure::AuthStrength::Token } else { seagent_security::exposure::AuthStrength::None },
            origins: callers,
            rate_limit: t.get("rate_limit").and_then(|v| v.as_integer()).is_some_and(|n| n > 0),
            enabled: true,
            lan: false,
        });
    }
    out
}

fn finding_from(p: seagent_security::exposure::Finding) -> Finding {
    Finding { id: p.id, severity: p.severity, title: p.title, detail: p.detail, fix: p.fix }
}

/// A12: exposure findings for `seagent security audit`, from the same `exposure::check` the
/// app server uses to refuse a bind.
pub(crate) fn exposure_findings(cfg: &Config) -> Vec<Finding> {
    let mut out = Vec::new();
    for s in exposure_surfaces(cfg) {
        out.extend(seagent_security::exposure::findings(&s.as_surface()).into_iter().map(finding_from));
    }
    // A10: which sub-endpoints answer on the app listener at all.
    if let Ok(app) = seagent_app::AppConfig::parse(&cfg.app) {
        if app.enabled {
            for (on, what, fix) in [
                (app.openai_api, "the OpenAI-compatible API (/v1)", "[app] openai_api = false"),
                (app.a2a.enabled, "the A2A endpoint (/a2a)", "[app.a2a] enabled = false"),
                (app.nodes, "device nodes (/node)", "[app] nodes = false"),
                (app.terminal, "the terminal page (a shell as the daemon's user)", "[app] terminal = false"),
            ] {
                if on {
                    out.push(f("exposure.endpoint_enabled", "info", format!("app server serves {what}"), format!("listen = {}", app.listen), Some(fix)));
                }
            }
            if !app.tokens.is_empty() {
                out.push(f("exposure.endpoint_enabled", "info", format!("{} scoped app token(s) are configured", app.tokens.len()), "[app] tokens", None));
            }
        }
    }
    out
}

/// LAN interconnect posture (docs/cross-platform.md): LAN mode, discovery, paired devices and
/// the identity certificate's age — for `seagent security audit` and `seagent doctor`.
pub(crate) fn lan_findings(cfg: &Config, data: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(app) = seagent_app::AppConfig::parse(&cfg.app) else { return out };
    if app.enabled && app.exposure.lan {
        out.push(f("lan.mode_on", "info", "LAN mode is on: devices on private networks can pair with this host", format!("listen = {}; private-range peers only, TLS, paired-device tokens", app.listen), Some("[app.exposure] lan = false")));
    }
    if app.enabled && seagent_app::lan::discovery_enabled(&app) {
        out.push(f("lan.discovery_on", "info", "this host advertises itself over mDNS (_seagent._tcp)", "TXT: protocol, host id, fingerprint prefix, name (no tokens)", Some("[app] discovery = \"off\"")));
        // UDP 5353 held exclusively (Bonjour / another responder without SO_REUSEADDR): the
        // responder can only announce, not answer. Say so instead of degrading silently.
        if let Err(e) = seagent_net::mdns::port_shareable() {
            out.push(f("lan.discovery_limited", "warn", "mDNS discovery is limited on this host", e, Some("stop the program holding UDP 5353 exclusively, or pair by address / QR code")));
        }
    }
    let devs = seagent_app::devices::list(data);
    let n = devs.len();
    if n > 0 {
        out.push(f("lan.paired_devices", "info", format!("{n} paired device(s) hold console tokens"), "seagent devices list", Some("seagent devices revoke ID")));
        // docs/SECURITY.md §8: where each device keeps its key. A file (or no key yet) is the
        // weaker case: whoever copies the app's data folder has the device.
        let mut stores: std::collections::BTreeMap<String, usize> = Default::default();
        for d in &devs {
            let s = if d["keyBound"] != true { "unbound".to_string() } else { d["keyStore"].as_str().filter(|s| !s.is_empty()).unwrap_or("unknown").to_string() };
            *stores.entry(s).or_default() += 1;
        }
        let summary = stores.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>().join(", ");
        let weak = stores.keys().any(|k| matches!(k.as_str(), "file" | "unbound"));
        out.push(f("lan.device_keys", if weak { "warn" } else { "info" }, format!("device key stores — {summary}"), "tpm / cng / secure-enclave / keychain / android-keystore / webcrypto keep the key non-exportable; file = the app's data folder; unbound = an older app (binds on its next start)", weak.then_some("update the app on those devices; [app.exposure] require_device_key = true refuses unbound ones")));
    }
    if let Some(id) = seagent_app::lan::load_identity(data) {
        let now = seagent_kernel::event::now_ms();
        let days = now.saturating_sub(id.created_ms) / 86_400_000;
        let expired = id.not_after_ms > 0 && id.not_after_ms <= now;
        let (sev, title) = if expired { ("warn", "the LAN certificate has expired (pinned apps keep working; browsers warn)".to_string()) } else { ("info", format!("LAN certificate {} is {days} day(s) old", id.sas())) };
        out.push(f("lan.certificate_age", sev, title, id.cert.display().to_string(), Some("seagent tls rotate --yes (every device must pair again)")));
    }
    out
}

/// `seagent doctor`: one line per surface that is reachable from the network without the
/// public-exposure layers.
pub(crate) fn exposure_warnings(cfg: &Config) -> Vec<String> {
    let mut out = Vec::new();
    for s in exposure_surfaces(cfg) {
        if let Some(w) = seagent_security::exposure::warning(&s.as_surface()) {
            out.push(w);
        }
    }
    out
}

/// Static audit of the effective config and state directories.
pub fn audit(cfg: &Config, paths: &Paths, ws: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    // Filesystem (OpenClaw audit.ts collectFilesystemFindings / audit-extra.async.ts).
    let user_cfg = paths.user_config();
    let is_link = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink());
    if let Some(mode) = mode_of(&user_cfg) {
        let link = is_link(&user_cfg);
        if link {
            out.push(f("fs.config.symlink", "warn", "config file is a symlink", format!("{}; make sure you trust its target", user_cfg.display()), None));
        }
        let d = format!("{} mode {mode:o}", user_cfg.display());
        if mode & 0o022 != 0 {
            out.push(f("fs.config.perms_writable", "critical", "config file is writable by others", format!("{d}; another user could change gate/approval/tool policies"), Some("chmod 600")));
        } else if !link && mode & 0o004 != 0 {
            out.push(f("fs.config.perms_world_readable", "critical", "config file is world-readable", format!("{d}; config can contain tokens and private settings"), Some("chmod 600")));
        } else if !link && mode & 0o040 != 0 {
            out.push(f("fs.config.perms_group_readable", "warn", "config file is group-readable", format!("{d}; config can contain tokens and private settings"), Some("chmod 600")));
        }
    }
    // The vault holds the actual secret values: readable by others is critical in seagent
    // (OpenClaw rates its credentials dir `warn` because it keeps only references there).
    let vault = paths.secrets();
    if let Some(mode) = mode_of(&vault) {
        let d = format!("{} mode {mode:o}", vault.display());
        if mode & 0o022 != 0 {
            out.push(f("fs.credentials_dir.perms_writable", "critical", "secret vault is writable by others", d, Some("chmod 600")));
        } else if mode & 0o044 != 0 {
            out.push(f("fs.credentials_dir.perms_readable", "critical", "secret vault is readable by others", d, Some("chmod 600")));
        }
    }
    for (dir, what) in [(paths.data.clone(), "state dir"), (paths.config_dir.clone(), "config dir")] {
        if is_link(&dir) {
            out.push(f("fs.state_dir.symlink", "warn", format!("{what} is a symlink"), format!("{}; treat this as an extra trust boundary", dir.display()), None));
        }
        if let Some(mode) = mode_of(&dir) {
            let d = format!("{} mode {mode:o}", dir.display());
            if mode & 0o002 != 0 {
                out.push(f("fs.state_dir.perms_world_writable", "critical", format!("{what} is world-writable"), format!("{d}; other users can write into seagent's state"), Some("chmod 700")));
            } else if mode & 0o020 != 0 {
                out.push(f("fs.state_dir.perms_group_writable", "warn", format!("{what} is group-writable"), format!("{d}; group users can write into seagent's state"), Some("chmod 700")));
            } else if mode & 0o044 != 0 {
                out.push(f("fs.state_dir.perms_readable", "warn", format!("{what} is readable by others"), format!("{d}; consider restricting to 700"), Some("chmod 700")));
            }
        }
    }
    if let Some(mode) = mode_of(&paths.sessions()).filter(|m| m & 0o044 != 0) {
        out.push(f("fs.sessions_store.perms_readable", "warn", "the sessions store is readable by others", format!("{} mode {mode:o}; transcripts can be sensitive", paths.sessions().display()), Some("chmod 700")));
    }
    // Secrets written inline in config files instead of {{secret:NAME}}.
    for p in [user_cfg.clone(), project_config(ws)] {
        if let Ok(text) = std::fs::read_to_string(&p) {
            for (i, line) in text.lines().enumerate() {
                let l = line.trim();
                if l.starts_with('#') || l.contains("{{secret:") {
                    continue;
                }
                if let Some(what) = seagent_kernel::gate::sensitive_content(l) {
                    out.push(f("config.secrets.inline", "critical", "a credential is written in a config file", format!("{}:{} ({what})", p.display(), i + 1), Some("move it to `seagent secrets set NAME` and reference {{secret:NAME}}")));
                } else if let Some((k, v)) = l.split_once('=') {
                    let k = k.trim().to_ascii_lowercase();
                    let v = v.trim().trim_matches('"');
                    if (k.ends_with("token") || k.ends_with("password") || k.ends_with("secret") || k == "api_key") && v.len() >= 12 && !v.starts_with('$') {
                        out.push(f("config.secrets.inline", "warn", format!("`{k}` holds a literal value"), format!("{}:{}", p.display(), i + 1), Some("use {{secret:NAME}}")));
                    }
                }
            }
        }
    }
    // Gateway / app server exposure.
    if let Ok(app) = seagent_app::AppConfig::parse(&cfg.app) {
        if app.enabled {
            let token = app.token.clone().unwrap_or_default();
            if !is_loopback(&app.listen) && token.trim().is_empty() && std::env::var("SEAGENT_APP_TOKEN").is_err() {
                out.push(f("gateway.bind_no_auth", "critical", "the app server listens beyond loopback without a token", app.listen.clone(), Some("set [app] token = \"{{secret:APP_TOKEN}}\"")));
            }
            if app.allow_origins.iter().any(|o| o == "*") {
                out.push(f("gateway.control_ui.allowed_origins_wildcard", "critical", "any web origin may open the control WebSocket", "app.allow_origins = [\"*\"]", None));
            }
            if app.nodes {
                out.push(f("gateway.nodes.enabled", "info", "device nodes may connect to /node", "app.nodes = true", None));
            }
        }
    }
    // A8–A12: every listening surface (app server, channel callbacks) against the same policy
    // the app server uses to refuse a public bind.
    out.extend(exposure_findings(cfg));
    out.extend(lan_findings(cfg, &paths.data));
    // Dangerous flags.
    use seagent_kernel::gate::Mode as G;
    if cfg.gate.privilege == G::Allow || cfg.gate.egress == G::Allow {
        out.push(f("config.insecure_or_dangerous_flags", "critical", "a gate is disabled", format!("gate.privilege = {:?}, gate.egress = {:?}", cfg.gate.privilege, cfg.gate.egress).to_lowercase(), Some("use \"ask\"")));
    }
    if cfg.approvals.mode == ap::Mode::Off {
        out.push(f("config.insecure_or_dangerous_flags", "critical", "approval prompts are off", "approvals.mode = \"off\"", None));
    }
    if ap::process_yolo() {
        out.push(f("config.insecure_or_dangerous_flags", "warn", "SEAGENT_YOLO is set in this environment", "every process started here skips approvals", None));
    }
    if cfg.approvals.cron_mode == ap::Unattended::Approve || cfg.approvals.unattended_mode == ap::Unattended::Approve {
        out.push(f("config.insecure_or_dangerous_flags", "warn", "unattended runs auto-approve flagged actions", "approvals.cron_mode / unattended_mode = \"approve\"", None));
    }
    if cfg.approvals.exec.ask_fallback == ap::ExecSecurity::Full {
        out.push(f("tools.exec.ask_fallback_full", "warn", "exec prompts that nobody can answer are allowed", "approvals.exec.ask_fallback = \"full\"", None));
    }
    for b in &cfg.approvals.exec.safe_bins {
        if seagent_kernel::interp::family_of(b).is_some() || ["env", "xargs", "find", "awk", "sed", "make"].contains(&b.as_str()) {
            out.push(f("tools.exec.safe_bins_interpreter_unprofiled", "critical", format!("`{b}` can run arbitrary code but is a safe bin"), "approvals.exec.safe_bins", Some("remove it; use exec allowlist entries instead")));
        }
    }
    if cfg.approvals.exec.security == ap::ExecSecurity::Allowlist && !cfg.approvals.strict_inline_eval && cfg.approvals.exec.allowlist.iter().any(|p| seagent_kernel::interp::family_of(p.rsplit('/').next().unwrap_or(p)).is_some()) {
        out.push(f("tools.exec.allowlist_interpreter_without_strict_inline_eval", "warn", "an interpreter is allowlisted without strict inline eval", "python/node -c/-e one-liners run without approval", Some("set approvals.strict_inline_eval = true")));
    }
    if cfg.approvals.elevated.enabled && cfg.approvals.elevated.allow_from.values().any(|v| v.iter().any(|x| x == "*")) {
        out.push(f("security.exposure.open_groups_with_elevated", "critical", "anyone may switch on elevated mode", "approvals.elevated.allow_from contains \"*\"", None));
    }
    // Channels open to anyone while the runtime tools are reachable.
    for (name, t) in &cfg.channels {
        let open = t.get("allow").and_then(|v| v.as_array()).is_some_and(|a| a.iter().any(|x| x.as_str() == Some("*"))) || t.get("dm_policy").and_then(|v| v.as_str()) == Some("open");
        if open {
            let origin = seagent_security::toolpolicy::Origin { model: cfg.model.default.clone(), channel: Some(name.clone()), sender: None };
            if cfg.tools.permits(&origin, "shell") {
                out.push(f("security.exposure.open_channels_with_exec", "critical", format!("channel `{name}` accepts anyone and can reach the shell tool"), "allow = [\"*\"] / dm_policy = \"open\"", Some("restrict senders, or [tools.by_channel.<name>] deny = [\"group:runtime\"]")));
            } else {
                out.push(f("security.exposure.open_channel", "warn", format!("channel `{name}` accepts messages from anyone"), "", None));
            }
        }
    }
    if !cfg.trusted_projects.is_empty() {
        out.push(f("security.trust_model.trusted_projects", "info", format!("{} project config(s) may define hooks, MCP servers and plugins", cfg.trusted_projects.len()), cfg.trusted_projects.join(", "), None));
    }
    // Plugins / MCP launchers.
    for (kind, map) in [("plugins", &cfg.plugins), ("mcp", &cfg.mcp)] {
        for (name, t) in map {
            let cmd = t.get("command").and_then(|v| v.as_str()).unwrap_or("");
            let args: Vec<String> = t.get("args").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
            if osv::ecosystem_for(cmd).is_some() && osv::component_from_launcher("", cmd, &args).is_none() {
                out.push(f("plugins.installs_unpinned_npm_specs", "warn", format!("{kind} `{name}` launches an unpinned package"), format!("{cmd} {}", args.join(" ")), Some("pin an exact version (pkg@1.2.3 / pkg==1.2.3)")));
            }
        }
    }
    if !cfg.security.scrub_env {
        out.push(f("config.insecure_or_dangerous_flags", "warn", "child processes inherit seagent's credentials", "security.scrub_env = false", None));
    }
    if !cfg.security.osv_check {
        out.push(f("config.osv_check_off", "info", "MCP/plugin packages are not checked against OSV malware advisories", "security.osv_check = false", None));
    }
    out.push(f("summary.attack_surface", "info", "attack surface", format!("{} channel(s), {} MCP server(s), {} plugin(s), {} hook(s), app server {}", cfg.channels.len(), cfg.mcp.len(), cfg.plugins.len(), cfg.hooks.len(), if seagent_app::AppConfig::parse(&cfg.app).map(|a| a.enabled).unwrap_or(false) { "on" } else { "off" }), None));
    out.retain(|x| !cfg.security.audit_suppress.iter().any(|s| s == x.id));
    out
}

/// Directories of plugins/MCP servers launched from local paths, for `--deep` scanning.
fn local_server_dirs(cfg: &Config) -> Vec<(String, PathBuf)> {
    let mut v = Vec::new();
    for (kind, map) in [("plugin", &cfg.plugins), ("mcp", &cfg.mcp)] {
        for (name, t) in map {
            let cmd = t.get("command").and_then(|x| x.as_str()).unwrap_or("");
            let args: Vec<&str> = t.get("args").and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|y| y.as_str()).collect()).unwrap_or_default();
            for cand in std::iter::once(cmd).chain(args) {
                let p = seagent_core::tool::expand_home(cand);
                if p.is_absolute() && p.exists() && !p.starts_with("/usr") && !p.starts_with("/bin") {
                    let dir = if p.is_dir() { p } else { p.parent().map(Path::to_path_buf).unwrap_or(p) };
                    v.push((format!("{kind}:{name}"), dir));
                    break;
                }
            }
        }
    }
    v
}

fn fix(paths: &Paths) -> Vec<String> {
    let mut done = vec![];
    for p in [paths.user_config(), paths.secrets()] {
        if mode_of(&p).is_some_and(|m| m & 0o077 != 0) && crate::ops::hostos::set_mode(&p, 0o600).is_ok() {
            done.push(format!("chmod 600 {}", p.display()));
        }
    }
    for d in [paths.data.clone(), paths.sessions(), paths.config_dir.clone()] {
        if mode_of(&d).is_some_and(|m| m & 0o077 != 0) && crate::ops::hostos::set_mode(&d, 0o700).is_ok() {
            done.push(format!("chmod 700 {}", d.display()));
        }
    }
    done
}

fn sev_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "warn" | "moderate" | "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

pub fn cmd_security(a: &Args, cfg: &Config, paths: &Paths, ws: &Path) -> R {
    match a.pos(0).unwrap_or("audit") {
        "audit" => {
            let fixed = if a.flag("fix") { fix(paths) } else { vec![] };
            let mut findings = audit(cfg, paths, ws);
            let mut supply: Option<(Vec<osv::Finding>, usize)> = None;
            if a.flag("deep") {
                for (label, dir) in local_server_dirs(cfg) {
                    let r = plugin_guard::scan_dir(&dir);
                    if r.verdict != "safe" {
                        findings.push(f("plugins.code_safety", if r.verdict == "dangerous" { "critical" } else { "warn" }, format!("{label}: plugin guard verdict {}", r.verdict), r.findings.iter().take(5).map(|x| format!("{} {}:{}", x.id, x.file, x.line)).collect::<Vec<_>>().join("; "), Some("review the code; `seagent security scan <dir>`")));
                    }
                }
                if seagent_kernel::daemon::call(&paths.socket(), "ping", json!({})).is_err() {
                    findings.push(f("gateway.probe_failed", "info", "the daemon is not answering", paths.socket().display().to_string(), None));
                }
            }
            if a.flag("supply-chain") || a.flag("deep") {
                let mut comps = osv::components_from_cargo_lock(include_str!("../../../Cargo.lock"), "seagent");
                for (kind, map) in [("plugin", &cfg.plugins), ("mcp", &cfg.mcp)] {
                    for (name, t) in map {
                        let cmd = t.get("command").and_then(|v| v.as_str()).unwrap_or("");
                        let args: Vec<String> = t.get("args").and_then(|v| v.as_array()).map(|x| x.iter().filter_map(|y| y.as_str().map(String::from)).collect()).unwrap_or_default();
                        comps.extend(osv::component_from_launcher(&format!("{kind}:{name}"), cmd, &args));
                    }
                }
                for (label, dir) in local_server_dirs(cfg) {
                    if let Ok(t) = std::fs::read_to_string(dir.join("requirements.txt")) {
                        comps.extend(osv::pins_from_requirements(&t, &label));
                    }
                    if let Ok(t) = std::fs::read_to_string(dir.join("package.json")) {
                        comps.extend(osv::pins_from_package_json(&t, &label));
                    }
                }
                let total = comps.len();
                match osv::audit(&comps) {
                    Ok(fs) => supply = Some((fs, total)),
                    Err(e) => {
                        eprintln!("audit failed: {e}");
                        return Ok(2);
                    }
                }
            }
            let fail_on = a.val("fail-on").unwrap_or("critical").to_ascii_lowercase();
            if !["low", "moderate", "medium", "warn", "high", "critical"].contains(&fail_on.as_str()) {
                return usage(format!("unknown --fail-on value: {fail_on} (choose from: low, moderate, high, critical)"));
            }
            let th = sev_rank(&fail_on);
            if a.flag("json") {
                let mut v = json!({"findings": findings.iter().map(|x| json!({"checkId": x.id, "severity": x.severity, "title": x.title, "detail": x.detail, "fix": x.fix})).collect::<Vec<_>>(), "fixed": fixed});
                if let Some((fs, total)) = &supply {
                    v["supply_chain"] = osv::render_json(fs, *total);
                }
                println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            } else {
                for x in &fixed {
                    println!("fixed: {x}");
                }
                let mut sorted = findings.clone();
                sorted.sort_by_key(|x| std::cmp::Reverse(sev_rank(x.severity)));
                for x in &sorted {
                    println!("{:<8} {:<52} {}{}", x.severity.to_uppercase(), x.id, x.title, if x.detail.is_empty() { String::new() } else { format!(" — {}", x.detail) });
                    if let Some(fx) = &x.fix {
                        println!("{:<61} fix: {fx}", "");
                    }
                }
                if let Some((fs, total)) = &supply {
                    println!("\n{}", osv::render_human(fs, *total));
                }
            }
            let bad = findings.iter().any(|x| sev_rank(x.severity) >= th) || supply.as_ref().is_some_and(|(fs, _)| fs.iter().any(|x| osv::severity_rank(&x.vuln.severity) >= th.min(4)));
            Ok(if bad { 1 } else { 0 })
        }
        "scan" => {
            let dir = PathBuf::from(a.need(1, "dir")?);
            let r = plugin_guard::scan_dir(&dir);
            if a.flag("json") {
                println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
            } else {
                println!("{}", plugin_guard::format_report(&dir.display().to_string(), &r));
            }
            if !cfg.security.install_policy.is_empty() {
                let req = json!({"targetType": "plugin", "targetName": dir.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(), "sourcePath": dir, "sourcePathKind": "directory", "scan": r});
                if let Err(e) = plugin_guard::install_policy(&cfg.security.install_policy, &req, std::time::Duration::from_secs(10)) {
                    println!("{e}");
                    return Ok(3);
                }
            }
            Ok(match r.verdict.as_str() {
                "safe" => 0,
                "caution" => 2,
                _ => 3,
            })
        }
        "plugins" => {
            let vault = std::sync::Arc::new(seagent_kernel::vault::Vault::load(&paths.secrets())?);
            let (plugins, warn) = crate::ext::start_plugins(cfg, &vault);
            for w in warn {
                eprintln!("seagent: warning: {w}");
            }
            let accept = a.pos(1) == Some("accept");
            let mut out = vec![];
            for p in &plugins {
                let caps = plugin_guard::summarize(&plugin_caps(p));
                if accept && (a.pos(2) == Some(p.name.as_str()) || a.flag("all")) {
                    plugin_guard::accept(&paths.data, &p.name, &caps)?;
                    println!("accepted capabilities of {}", p.name);
                    continue;
                }
                let w = plugin_guard::widened(&paths.data, &p.name, &caps);
                out.push(plugin_guard::consent_json(&p.name, &caps, &w));
                if !a.flag("json") {
                    if w.is_empty() {
                        println!("{}: consented", p.name);
                    } else {
                        for l in plugin_guard::consent_lines(&p.name, &caps, &w) {
                            println!("{l}");
                        }
                        println!("  → seagent security plugins accept {}", p.name);
                    }
                }
            }
            if a.flag("json") {
                println!("{}", Value::Array(out));
            }
            Ok(0)
        }
        "check-url" => {
            let url = a.need(1, "url")?;
            if let Some(m) = url_safety::check_website_access(url, &cfg.security.website_blocklist, &paths.config_dir) {
                println!("blocked: {m}");
                return Ok(3);
            }
            match url_safety::is_safe_url(url, &cfg.security.url_policy()) {
                Ok(()) => {
                    if let Some(q) = url_safety::sensitive_query_param_name(url) {
                        println!("allowed, but the URL carries a credential-named parameter `{q}`");
                        return Ok(2);
                    }
                    println!("allowed");
                    Ok(0)
                }
                Err(e) => {
                    println!("blocked: {e}");
                    Ok(3)
                }
            }
        }
        // Daemon-side broker (A2/A3/A4). The VM talks to this socket only; see
        // audit/round5/AB-interface.md. Runs until Ctrl-C.
        "broker" => {
            let b = cfg.security.broker.clone();
            let socket = b.socket_path(&paths.runtime);
            let policy = seagent_security::egress_proxy::Policy::from_config(&cfg.security.egress_proxy, cfg.security.url_policy(), cfg.security.website_blocklist.clone(), &paths.config_dir, &cfg.gate.egress_allow, &cfg.gate.egress_deny);
            let resolve: seagent_security::egress_proxy::Resolver = std::sync::Arc::new(|h: &str, p: u16| {
                use std::net::ToSocketAddrs;
                (h, p).to_socket_addrs().map(|it| it.map(|a| a.ip()).collect::<Vec<_>>()).map_err(|e| e.to_string())
            });
            let ctx = seagent_security::broker::Ctx {
                data: paths.data.clone(),
                session: a.val("session").unwrap_or("vm").to_string(),
                cfg: b.clone(),
                policy,
                resolve,
                secret: seagent_security::egress_proxy::env_secrets(),
                check_body: std::sync::Arc::new(|body: &str| seagent_security::risk::secret_kind(body).map(|k| format!("the body contains a {k}"))),
            };
            let br = Broker::serve(&socket, ctx)?;
            println!("broker listening on {} (exec allow: {} rule(s); Ctrl-C to stop)", br.path().display(), b.exec_allow.len());
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        "creds" | "credential-files" => {
            let home = PathBuf::from(std::env::var("HOME").unwrap_or_default());
            let dirs = seagent_security::paths::SeagentDirs { config_dir: paths.config_dir.clone(), data_dir: paths.data.clone() };
            let (m, errs) = seagent_security::credfiles::mounts(&cfg.security.credential_files, &home, "/home/sandbox", &dirs);
            for x in &m {
                println!("{} → {}", x.host.display(), x.container);
            }
            for e in &errs {
                println!("skipped: {e}");
            }
            Ok(if errs.is_empty() { 0 } else { 1 })
        }
        other => usage(format!("unknown `security {other}`")),
    }
}

/// What a running plugin declared it provides (the consent surface).
fn plugin_caps(p: &seagent_plugin::PluginHost) -> Value {
    json!({"hooks": p.hooks(), "channels": p.channels(), "commands": p.commands, "routes": p.routes, "providers": p.providers, "services": p.services,
        "cli": p.cli, "middleware": p.middleware_kinds(), "context_engine": p.context_engine, "memory": p.memory, "node_commands": p.node_commands, "ui": p.ui,
        "backends": p.backends, "dashboard_auth": p.dashboard_auth})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn audit_flags_foot_guns() {
        let root = seagent_core::tmp::scratch_path(format!("seagent-audit-{}", std::process::id()));
        let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run"), ..Default::default() };
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::create_dir_all(&paths.data).unwrap();
        std::fs::write(paths.user_config(), "[app]\nenabled = true\nlisten = \"0.0.0.0:8640\"\n[mcp.gh]\ncommand = \"npx\"\nargs = [\"-y\", \"some-mcp\"]\n# token = \"x\"\napi_key = \"sk-ant-REDACTEDREDACTEDREDACTED00\"\n").unwrap();
        std::fs::set_permissions(paths.user_config(), std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&paths.data, std::fs::Permissions::from_mode(0o777)).unwrap();
        let mut cfg = Config { app: toml::from_str("enabled = true\nlisten = \"0.0.0.0:8640\"").unwrap(), ..Default::default() };
        cfg.mcp.insert("gh".into(), toml::from_str("command = \"npx\"\nargs = [\"-y\", \"some-mcp\"]").unwrap());
        cfg.channels.insert("telegram".into(), toml::from_str("allow = [\"*\"]").unwrap());
        cfg.gate.egress = seagent_kernel::gate::Mode::Allow;
        cfg.approvals.exec.safe_bins.push("python3".into());
        let ids: Vec<&str> = audit(&cfg, &paths, &root).iter().map(|x| x.id).collect();
        for want in ["fs.config.perms_world_readable", "fs.state_dir.perms_world_writable", "config.secrets.inline", "gateway.bind_no_auth", "plugins.installs_unpinned_npm_specs", "security.exposure.open_channels_with_exec", "config.insecure_or_dangerous_flags", "tools.exec.safe_bins_interpreter_unprofiled", "summary.attack_surface"] {
            assert!(ids.contains(&want), "{want} missing from {ids:?}");
        }
        let done = fix(&paths);
        assert!(done.iter().any(|d| d.contains("chmod 600")) && done.iter().any(|d| d.contains("chmod 700")));
        let ids: Vec<&str> = audit(&cfg, &paths, &root).iter().map(|x| x.id).collect();
        assert!(!ids.contains(&"fs.state_dir.perms_world_writable"));
        cfg.security.audit_suppress = vec!["summary.attack_surface".into()];
        assert!(!audit(&cfg, &paths, &root).iter().any(|x| x.id == "summary.attack_surface"));
        assert!(is_loopback("127.0.0.1:8640") && is_loopback("[::1]:1") && !is_loopback("0.0.0.0:1"));
    }

    /// A12: the audit reports the same layers the app server refuses to start without.
    #[test]
    fn audit_flags_public_exposure() {
        let root = seagent_core::tmp::scratch_path(format!("seagent-audit-exposure-{}", seagent_kernel::util::random_hex(8)));
        let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run"), ..Default::default() };
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::create_dir_all(&paths.data).unwrap();

        let app_toml = "enabled = true\nlisten = \"0.0.0.0:8640\"\ntoken = \"t\"\nallow_origins = [\"*\"]\nopenai_api = true\n[exposure]\nrate_limit_per_min = 0\n";
        let mut cfg = Config { app: toml::from_str(app_toml).unwrap(), ..Config::default() };
        // A channel callback on the network with a signature secret but no rate limit.
        cfg.channels.insert("slack".into(), toml::from_str("listen = \"0.0.0.0:8650\"\nsecret = \"s\"").unwrap());
        // ... and one that stays on loopback: it must produce no exposure finding at all.
        cfg.channels.insert("hook".into(), toml::from_str("listen = \"127.0.0.1:8651\"\nsecret = \"s\"").unwrap());
        let findings = audit(&cfg, &paths, &root);
        let ids: Vec<&str> = findings.iter().map(|x| x.id).collect();
        for want in ["exposure.non_loopback", "exposure.allow_public_missing", "exposure.tls_missing", "exposure.weak_auth", "exposure.origins_wildcard", "exposure.no_rate_limit", "exposure.endpoint_enabled"] {
            assert!(ids.contains(&want), "{want} missing from {ids:?}");
        }
        // Each non-info finding carries a fix and a severity.
        for fd in findings.iter().filter(|x| x.id.starts_with("exposure.") && x.severity != "info") {
            assert!(fd.fix.as_deref().is_some_and(|x| !x.is_empty()), "{} has no fix", fd.id);
        }
        // Open-loopback surfaces stay quiet: the loopback channel contributes only nothing.
        assert!(findings.iter().filter(|x| x.title.contains("channels.hook")).all(|x| x.id == "exposure.endpoint_enabled"), "{findings:?}");
        // The doctor line names the surface, the address and one fix.
        let warnings = exposure_warnings(&cfg);
        assert!(warnings.iter().any(|w| w.contains("app server") && w.contains("0.0.0.0:8640") && w.contains("fix")), "{warnings:?}");
        assert!(warnings.iter().any(|w| w.contains("channels.slack")), "{warnings:?}");

        // A loopback-only config stays green.
        let cfg = Config { app: toml::from_str("enabled = true\nlisten = \"127.0.0.1:8640\"\ntoken = \"t\"").unwrap(), ..Config::default() };
        let ids: Vec<&str> = audit(&cfg, &paths, &root).iter().map(|x| x.id).collect();
        assert!(!ids.iter().any(|i| i.starts_with("exposure.") && *i != "exposure.endpoint_enabled"), "{ids:?}");
        assert!(exposure_warnings(&cfg).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }
}
