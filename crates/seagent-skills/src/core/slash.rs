//! Native slash commands of the skills system (Hermes `hermes_cli/commands.py` /skills,
//! /bundles, /curator, /reload-skills, /refine and `agent/skill_commands.py` /<skill-name>,
//! /<bundle>; OpenClaw commands-registry /plugins, commands-registry /skill, MIT). Registered with
//! `Kernel::add_slash`, so every surface (`seagent run`/`chat`, TUI, web, channels) reaches them.
//!
//! - `/skills …` — the `seagent skills` command set (search, install, inspect, list, check, update …),
//!   plus the pending-write queue (`pending`, `approve <id>`, `reject <id>`).
//! - `/skill <name> [instruction]` — load a skill exactly like `/<name>` (also a name that
//!   collides with a core command); `/skill list|search|view <name>` map to the `skill` tool.
//! - `/bundles …`, `/curator …` — as on the CLI; `/curator run --consolidate` forks a sub-agent,
//!   `/curator review [--apply]` writes the background review's candidate procedures.
//! - `/plugins [list|show|enable|disable|search|install|uninstall|marketplace] …`.
//! - `/reload-skills` — rescan the catalog and report added/removed/updated skills; the live delta
//!   announces the same difference on the next turn.
//! - `/refine [--apply] [name] [focus]` — one-shot refinement of the loaded/last skill from the
//!   steps this session ran: a proposal, or the applied patch.
//! - `/<bundle> [instruction]`, `/<skill> [/<skill2> …] [instruction]` — the skill (or every
//!   member) is loaded into one user message; names that collide with core commands are skipped.

use super::settings::{Settings, Store};
use super::{bundles, cli, invoke, manage, review, search};
use seagent_kernel::config::{Config, Paths};
use seagent_kernel::kernel::{Kernel, RunOpts};
use seagent_kernel::slash::{Slash, SlashCtx, SlashReply};
use std::path::{Path as StdPath, PathBuf};

/// Core command names and aliases a skill or bundle must never shadow.
pub const RESERVED: &[&str] = &[
    "new", "reset", "clear", "redraw", "status", "stop", "model", "compact", "compress", "undo", "history", "save", "export-session", "export-trajectory", "title", "name", "btw", "side", "plan", "review", "init", "learn", "queue", "q", "busy", "followup", "steer", "tell", "discard", "context", "ctx", "diff", "whoami", "id", "version", "v", "help", "commands", "platforms", "gateway", "config", "mcp", "tools", "toolsets", "personality", "verbose", "footer", "timestamps", "ts", "focus", "trace", "send", "activation", "allowlist", "statusbar", "sb", "copy", "paste", "image", "prompt", "compose", "quit", "exit", "skills", "skill", "bundles", "bundle", "curator", "plugins", "plugin", "memory", "journey", "reload-skills", "refine", "dreaming", "active-memory", "goal", "kanban", "cron", "sessions",
];

pub fn collision_note(name: &str) -> Option<String> {
    RESERVED.contains(&invoke::slug(name).as_str()).then(|| format!("skill `{name}` shares its name with the core command /{}; invoke it with `/skill {name}` or `skill action=view`", invoke::slug(name)))
}

pub struct SkillsSlash;

fn split_args(a: &str) -> Vec<String> {
    seagent_kernel::commands::split_args(a)
}

fn workspace(ctx: &SlashCtx) -> PathBuf {
    ctx.session.as_deref().and_then(|s| ctx.kernel.store.read(s).ok()).map(|e| PathBuf::from(seagent_kernel::projection::project(&e).workspace)).filter(|p| p.is_dir()).unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

/// A consolidation sub-agent for `/curator run --consolidate` (child of the current session).
pub fn fork(k: &Kernel, ws: &std::path::Path, parent: Option<&str>) -> impl Fn(&str) -> Result<String, String> {
    let (k, ws, parent) = (k.clone(), ws.to_path_buf(), parent.map(String::from));
    move |prompt: &str| {
        let id = k.create_session(&ws, Some(k.cfg.aux_model()), parent.as_deref(), Some("curator")).map_err(|e| e.to_string())?;
        k.submit(&id, prompt, "curator").map_err(|e| e.to_string())?;
        k.run(&id, RunOpts { depth: 1, ..Default::default() }).map(|o| o.text).map_err(|e| e.to_string())
    }
}

fn invoke_skill(cfg: &Config, paths: &Paths, ws: &StdPath, name: &str, args: &str, session: Option<&str>, explicit: bool) -> Option<Result<SlashReply, String>> {
    let s = Settings::load(cfg);
    let st = Store::new(paths);
    let l = invoke::Loader::new(cfg, paths, ws, &s);
    // Core commands always win — over skills and over bundles (upstream dispatch resolves them
    // before the skill/bundle maps). `/skill <name>` is the documented escape hatch.
    if !explicit && RESERVED.contains(&invoke::slug(name).as_str()) {
        return None;
    }
    if let Some(b) = bundles::get(&st, name) {
        return Some(l.invoke_bundle(&b, args, session).map(SlashReply::prompt));
    }
    l.invoke_stacked(name, args, session).map(|r| r.map(SlashReply::prompt))
}

/// `/skill …`: the tool's actions, or `/<name>` by another spelling.
fn skill_cmd(ctx: &SlashCtx, ws: &StdPath, args: &str) -> Result<SlashReply, String> {
    let k = &ctx.kernel;
    let (cfg, paths) = (&k.cfg, &k.paths);
    let s = Settings::load(cfg);
    let argv = split_args(args);
    let Some(sub) = argv.first().cloned() else {
        return Ok(SlashReply::text("usage: /skill <name> [instruction] | /skill list [category] | /skill search <query> | /skill view <name>"));
    };
    let rest = argv[1..].join(" ");
    match sub.as_str() {
        "list" | "ls" => {
            let (mut visible, hidden) = invoke::catalog_split(cfg, paths, ws, &s);
            let category = argv.get(1).cloned().filter(|c| !c.starts_with("--"));
            if let Some(c) = &category {
                visible.retain(|sk| sk.category.as_deref() == Some(c.as_str()) || invoke::group_of(sk) == *c);
            }
            let verbose = argv.iter().any(|a| a == "--verbose" || a == "-v");
            Ok(SlashReply::text(invoke::list_text(&visible, if category.is_some() { &[] } else { &hidden }, category.is_some(), verbose)))
        }
        "search" | "find" => {
            let cat = invoke::catalog(cfg, paths, ws, &s);
            let limit = argv.iter().position(|a| a == "--limit").and_then(|i| argv.get(i + 1)).and_then(|l| l.parse().ok());
            let query = argv[1..].iter().filter(|a| !a.starts_with("--") && a.parse::<usize>().is_err()).cloned().collect::<Vec<_>>().join(" ");
            let (hits, more) = search::search(&cat, &query, limit)?;
            Ok(SlashReply::text(search::render(query.trim(), &hits, more)))
        }
        "view" | "show" => {
            let name = argv.get(1).cloned().ok_or("usage: /skill view <name>")?;
            if s.is_disabled(&name) {
                return Err(format!("skill `{name}` is disabled ([skills] disabled); enable it with `seagent skills config enable {name}`"));
            }
            let l = invoke::Loader::new(cfg, paths, ws, &s);
            match super::skilltool::view_skill(&l, &name, ctx.session.as_deref()) {
                Some(Ok(t)) => Ok(SlashReply::text(t)),
                Some(Err(e)) => Err(e),
                None => Err(format!("no skill `{name}`")),
            }
        }
        _ => match invoke_skill(cfg, paths, ws, &sub, &rest, ctx.session.as_deref(), true) {
            Some(r) => Ok(r?),
            None => Err(format!("no skill `{sub}`")),
        },
    }
}

/// `/refine [--apply] [name] [focus]`.
fn refine_cmd(ctx: &SlashCtx, ws: &StdPath, args: &str) -> Result<SlashReply, String> {
    let k = &ctx.kernel;
    let (cfg, paths) = (&k.cfg, &k.paths);
    let s = Settings::load(cfg);
    let argv = split_args(args);
    let apply = argv.iter().any(|a| a == "--apply" || a == "-a");
    let words: Vec<String> = argv.iter().filter(|a| !a.starts_with('-')).cloned().collect();
    let session = ctx.session.clone().ok_or("/refine needs a session (it refines the steps this conversation ran)")?;
    // The first word names a skill when it resolves to one; otherwise it is focus text.
    let cat = invoke::catalog_loadable(cfg, paths, ws, &s);
    let (name, focus) = match words.first() {
        Some(w) if invoke::resolve(&cat, w).is_some() => (Some(w.clone()), words[1..].join(" ")),
        _ => (None, words.join(" ")),
    };
    let p = review::propose(cfg, paths, &s, ws, &session, name.as_deref(), &focus)?;
    if !apply {
        let mut out = format!(
            "Proposal for `{}` from this session's {} step(s) — not applied:\n\n{}\n\nApply it with `/refine --apply {}` (or `skill action=update name={} content=<the proposal>`).",
            p.name, p.steps, p.content, p.name, p.name
        );
        if !p.advisories.is_empty() {
            out.push_str(&format!("\n{}", p.advisories.join("\n")));
        }
        return Ok(SlashReply::text(out));
    }
    let mut text = review::apply(cfg, paths, &s, ws, &session, &p)?;
    if !p.advisories.is_empty() {
        text.push_str(&format!("\n{}", p.advisories.join("\n")));
    }
    Ok(SlashReply::text(text))
}

/// `/skills pending|approve <id>|reject <id>`: the write-approval queue (`[skills] write_approval`).
fn pending_cmd(ctx: &SlashCtx, argv: &[String]) -> Result<String, String> {
    let k = &ctx.kernel;
    let s = Settings::load(&k.cfg);
    let c = manage::Ctx { cfg: &k.cfg, paths: &k.paths, ws: &workspace(ctx), settings: &s, session: ctx.session.as_deref() };
    manage::cli(&c, argv).map_err(|e| e.replace("usage: skills", "usage: /skills"))
}

impl Slash for SkillsSlash {
    fn commands(&self) -> Vec<(String, String)> {
        vec![
            ("skills".into(), "Search, install, inspect and manage skills (/skills help)".into()),
            ("skill".into(), "Load a skill (/skill <name>) or list/search/view the catalog".into()),
            ("bundles".into(), "List, show, create or delete skill bundles".into()),
            ("curator".into(), "Skill-library curator: status, run, pin, archive, restore, rollback, review".into()),
            ("plugins".into(), "List, show, enable, disable, search or install plugins".into()),
            ("reload-skills".into(), "Rescan the skill catalog and report what changed".into()),
            ("refine".into(), "Refine the loaded skill from this session's steps (/refine --apply)".into()),
            ("<skill> [/<skill>…] [instruction]".into(), "Load a skill (or several) into this turn".into()),
            ("<bundle> [instruction]".into(), "Load every skill of a bundle".into()),
        ]
    }

    fn run(&self, ctx: &SlashCtx, name: &str, args: &str) -> Option<Result<SlashReply, String>> {
        let k = &ctx.kernel;
        let (cfg, paths) = (&k.cfg, &k.paths);
        let ws = workspace(ctx);
        let argv = split_args(args);
        let st = Store::new(paths);
        let s = Settings::load(cfg);
        match name {
            "skills" => {
                if argv.first().map(String::as_str) == Some("help") {
                    return Some(Ok(SlashReply::text("/skills list | search <q> | browse | inspect <id> | install <id> | uninstall <name> | check | update | audit | view <name> | setup <name> | usage | pending | drafts | approve <id> | reject <id> | lock <name> | unlock <name> | tap … | config disable <name>")));
                }
                if matches!(argv.first().map(String::as_str), Some("pending" | "drafts" | "approve" | "reject")) {
                    return Some(pending_cmd(ctx, &argv).map(SlashReply::text));
                }
                let c = crate::hub::cli::Ctx { cfg, paths, ws: &ws, ask: None };
                Some(crate::hub::cli::run(&c, &argv).map(SlashReply::text))
            }
            "skill" => Some(skill_cmd(ctx, &ws, args)),
            "reload-skills" => {
                let ix = super::index::shared(cfg, paths);
                Some(Ok(SlashReply::text(ix.reload(&ws.to_string_lossy()).render())))
            }
            "refine" => Some(refine_cmd(ctx, &ws, args)),
            "bundles" | "bundle" => Some(bundles::cli(&st, &argv).map(SlashReply::text)),
            "curator" => {
                let f = fork(k, &ws, ctx.session.as_deref());
                Some(cli::curator_cmd(cfg, paths, &s, &st, &argv, Some(&f)).map(SlashReply::text))
            }
            "plugins" | "plugin" => {
                let sub = argv.first().map(String::as_str).unwrap_or("list");
                if sub == "list" {
                    let pm = crate::hub::plugins::Plugins::new(cfg, paths);
                    let rows = pm.list();
                    return Some(Ok(SlashReply::text(if rows.is_empty() { "no plugins installed (/plugins search <q>, /plugins install <name>)".to_string() } else { rows.iter().map(|r| format!("{:<24} {:<8} {}", r["name"].as_str().unwrap_or(""), r["kind"].as_str().unwrap_or(""), if r["enabled"].as_bool() == Some(false) { "disabled" } else { "enabled" })).collect::<Vec<_>>().join("\n") })));
                }
                crate::hub::plugins::cli(cfg, paths, &argv).map(|r| r.map(SlashReply::text)).or_else(|| Some(Err(format!("unknown /plugins action `{sub}` (list, show, enable, disable, search, install, uninstall, marketplace)"))))
            }
            other => invoke_skill(cfg, paths, &ws, other, args, ctx.session.as_deref(), false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_and_invocation() {
        assert!(collision_note("status").is_some() && collision_note("deploy").is_none());
        let d = seagent_core::tmp::scratch_path(format!("seagent-skslash-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let paths = Paths { data: d.join("data"), config_dir: d.join("cfg"), runtime: d.join("run"), ..Default::default() };
        let ws = d.join("ws");
        for n in ["deploy", "status"] {
            std::fs::create_dir_all(ws.join(".seagent/skills").join(n)).unwrap();
            std::fs::write(ws.join(".seagent/skills").join(n).join("SKILL.md"), format!("---\nname: {n}\ndescription: d\n---\n{n} body")).unwrap();
        }
        let cfg = Config::default();
        let r = invoke_skill(&cfg, &paths, &ws, "deploy", "now", Some("s"), false).unwrap().unwrap();
        assert!(r.prompt.unwrap().contains("deploy body"));
        assert!(invoke_skill(&cfg, &paths, &ws, "status", "", None, false).is_none(), "core command wins");
        assert!(invoke_skill(&cfg, &paths, &ws, "unknown-x", "", None, false).is_none());
        // `/skill status` is the explicit escape hatch for a shadowed name.
        let r = invoke_skill(&cfg, &paths, &ws, "status", "", Some("s"), true).unwrap().unwrap();
        assert!(r.prompt.unwrap().contains("status body"), "an explicit /skill load bypasses the reserved rule");
        let st = Store::new(&paths);
        bundles::save(&st, "ship", &["deploy".into(), "missing".into()], "", "carefully", false).unwrap();
        let b = invoke_skill(&cfg, &paths, &ws, "ship", "go", None, false).unwrap().unwrap().prompt.unwrap();
        assert!(b.contains("\"ship\" skill bundle") && b.contains("Skills missing (skipped): missing") && b.contains("Bundle instruction: carefully") && b.contains("User instruction: go"), "{b}");
        // Core commands win over bundles too (upstream resolves them before the bundle map).
        bundles::save(&st, "status", &["deploy".into()], "", "", false).unwrap();
        assert!(invoke_skill(&cfg, &paths, &ws, "status", "", None, false).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }
}
