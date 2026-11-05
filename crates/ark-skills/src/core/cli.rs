//! `ark curator …` (Hermes `hermes_cli/curator.py`, MIT) and `ark bundles …` text commands,
//! shared with `/curator` and `/bundles`.
//!
//! curator: status · usage [--sort activity|recent|name] [--provenance p] [--json] · run
//! [--dry-run] [--consolidate] · pause · resume · pin · unpin · list-unmanaged · adopt
//! [--all-unmanaged] [--dry-run] · restore · list-archived · archive · prune [--days n]
//! [--dry-run] · backup [--reason r] · rollback [entry-id] [--list] [--id snap] · ledger
//! [--skill s] [--limit n] · purge [--days n] [--dry-run]

use super::settings::{Settings, Store};
use super::{curator, ledger, usage};
use serde_json::Value;

fn opt(argv: &[String], f: &str) -> Option<String> {
    argv.iter().position(|a| a == f).and_then(|i| argv.get(i + 1).cloned())
}

fn flag(argv: &[String], f: &str) -> bool {
    argv.iter().any(|a| a == f)
}

fn pos(argv: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        if matches!(argv[i].as_str(), "--sort" | "--provenance" | "--days" | "--reason" | "--id" | "--skill" | "--limit" | "-w" | "--workspace") {
            i += 2;
            continue;
        }
        if !argv[i].starts_with('-') {
            out.push(argv[i].clone());
        }
        i += 1;
    }
    out
}

/// `fork` runs the consolidation sub-agent (available on surfaces with a kernel). `cfg`/`paths` are
/// what the background-review pass needs to resolve skills (the store alone cannot gate them).
pub fn curator_cmd(cfg: &ark_kernel::config::Config, paths: &ark_kernel::config::Paths, s: &Settings, st: &Store, argv: &[String], fork: Option<super::Fork<'_>>) -> Result<String, String> {
    let p = pos(argv);
    let sub = p.first().map(String::as_str).unwrap_or("status");
    let skill = || p.get(1).cloned().ok_or_else(|| format!("usage: ark curator {sub} <skill>"));
    match sub {
        "status" => Ok(curator::status(s, st)),
        "usage" => {
            let mut rows = usage::report(s, st, &usage::local_skills(st));
            if let Some(pv) = opt(argv, "--provenance") {
                rows.retain(|r| r["provenance"] == pv.as_str());
            }
            // Default is `activity` (most-used first), like upstream `_USAGE_SORTS`.
            match opt(argv, "--sort").as_deref() {
                Some("name") => rows.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str())),
                Some("recent") => rows.sort_by_key(|r| std::cmp::Reverse(r["last_activity_at"].as_i64())),
                _ => rows.sort_by_key(|r| std::cmp::Reverse(r["activity_count"].as_i64())),
            }
            if flag(argv, "--json") {
                return Ok(serde_json::to_string_pretty(&rows).unwrap_or_default());
            }
            if rows.is_empty() {
                return Ok("curator: no skills found".into());
            }
            let fmt = |v: &Value| v.as_i64().map(|t| ark_kernel::util::fmt_time(t, 0)).unwrap_or_else(|| "never".into());
            let count = |p: &str| rows.iter().filter(|r| r["provenance"] == p).count();
            let mut out = format!("skills: {} total  (agent={}  bundled={}  hub={}  external={})\n\n", rows.len(), count("agent"), count("bundled"), count("hub"), count("external"));
            out.push_str(&format!("{:<40}  {:<8}  {:>4}  {:>4}  {:>5}  {:>4}  last_activity\n", "skill", "origin", "use", "view", "patch", "act"));
            for r in &rows {
                let n = |k: &str| r[k].as_i64().unwrap_or(0);
                out.push_str(&format!("{:<40}  {:<8}  {:>4}  {:>4}  {:>5}  {:>4}  {}\n", r["name"].as_str().unwrap_or("").chars().take(40).collect::<String>(), r["provenance"].as_str().unwrap_or(""), n("use_count"), n("view_count"), n("patch_count"), n("activity_count"), fmt(&r["last_activity_at"])));
            }
            Ok(out)
        }
        "run" => {
            let consolidate = flag(argv, "--consolidate").then_some(true);
            // `--sync` is the default (manual runs wait); `--background` is accepted for
            // command-line parity but this process has no scheduler to return to.
            let background = flag(argv, "--background") && !flag(argv, "--sync") && !flag(argv, "--synchronous");
            let r = curator::run(s, st, flag(argv, "--dry-run"), consolidate, fork);
            Ok(format!("{}\n{}{}{}", r.summary, r.log.iter().map(|l| format!("  {l}\n")).collect::<String>(), r.report_dir.map(|d| format!("report: {} ", d.display())).unwrap_or_default(), if background { "(ran synchronously: `ark curator run --background` has no scheduler to hand off to; use `/curator run --background` in a session)" } else { "" }))
        }
        "pause" => {
            curator::set_paused(st, true);
            Ok("curator paused".into())
        }
        // Background review's skill half (Hermes `agent/background_review.py`): turn the
        // candidate procedures recorded at turn end into SKILL.md files.
        "review" => {
            let apply = flag(argv, "--apply") && !flag(argv, "--dry-run");
            let r = super::review::review(cfg, paths, s, apply);
            let mut out = r.render();
            if !apply && r.seen > 0 {
                out.push_str("\napply them with `ark curator review --apply` (or `/curator review --apply`)");
            }
            Ok(out)
        }
        "resume" => {
            curator::set_paused(st, false);
            Ok("curator resumed".into())
        }
        "pin" | "unpin" => {
            let n = skill()?;
            let pin = sub == "pin";
            // Upstream messages: bundled/hub skills are out of scope, ineligible ones are refused,
            // and an unmanaged skill's pin is recorded but never acted on until `adopt`.
            if usage::provenance(s, st, &n) != "agent" {
                return Err(format!("'{n}' is bundled or hub-installed — {}", if pin { "cannot pin (only agent-created skills participate in curation)" } else { "there's nothing to unpin (curator only tracks agent-created skills)" }));
            }
            usage::set_pinned(s, st, &n, pin).map_err(|_| format!("could not {} '{n}' — the skill is not curation-eligible (protected built-in or external).", sub))?;
            if !usage::curator_managed(s, st, &n) {
                return Ok(format!("{}{n}' (recorded; this skill is unmanaged — {} Run `ark curator adopt {n}` to put it under curator management)", if pin { "pinned '" } else { "unpinned '" }, if pin { "auto-transitions never consider it." } else { "it was never under auto-transitions to begin with." }));
            }
            Ok(format!("{}{n}'{}", if pin { "pinned '" } else { "unpinned '" }, if pin { " (will bypass auto-transitions)" } else { "" }))
        }
        "list-unmanaged" => {
            let rows: Vec<String> = usage::local_skills(st).into_iter().filter(|k| usage::curation_eligible(s, st, &k.name) && !usage::curator_managed(s, st, &k.name)).map(|k| {
                let has_key = usage::load(st).get(&k.name).is_some_and(|r| r.get("created_by").is_some());
                format!("{:<30} {}", k.name, if has_key { "user-created" } else { "no provenance record" })
            }).collect();
            Ok(if rows.is_empty() { "no unmanaged skills".into() } else { rows.join("\n") })
        }
        "adopt" => {
            let names: Vec<String> = if flag(argv, "--all-unmanaged") { usage::local_skills(st).into_iter().filter(|k| usage::curation_eligible(s, st, &k.name) && !usage::curator_managed(s, st, &k.name)).map(|k| k.name).collect() } else { p[1..].to_vec() };
            if names.is_empty() {
                return Err("usage: ark curator adopt <skill…> | --all-unmanaged".into());
            }
            if flag(argv, "--dry-run") {
                return Ok(format!("would adopt: {}", names.join(", ")));
            }
            Ok(names.iter().map(|n| if usage::curator_managed(s, st, n) { format!("'{n}' is already curator-managed") } else { usage::adopt(s, st, n).unwrap_or_else(|e| e) }).collect::<Vec<_>>().join("\n"))
        }
        "restore" => usage::restore(s, st, &skill()?, "user"),
        "list-archived" => Ok({
            let v = usage::archived_names(st);
            if v.is_empty() { "no archived skills".into() } else { v.join("\n") }
        }),
        "archive" => {
            let n = skill()?;
            if usage::get(st, &n)["pinned"].as_bool() == Some(true) {
                return Err(format!("'{n}' is pinned — unpin first with `ark curator unpin {n}`"));
            }
            usage::archive(s, st, &n, "user")
        },
        "prune" => {
            let days = opt(argv, "--days").and_then(|d| d.parse().ok()).unwrap_or(s.curator.archive_after_days);
            if days < 1 {
                return Err("--days must be ≥ 1".into());
            }
            let v = curator::prune(s, st, days, flag(argv, "--dry-run"));
            Ok(if v.is_empty() {
                format!("nothing to prune (no unpinned skills idle >= {days}d)")
            } else {
                format!("{} {} skill(s) idle >= {days}d: {}", if flag(argv, "--dry-run") { "would archive" } else { "archived" }, v.len(), v.join(", "))
            })
        }
        "backup" => curator::backup(st, &opt(argv, "--reason").unwrap_or_else(|| "manual".into()), s.curator.backup_keep.max(1)).map(|d| format!("snapshot {}", d.display())),
        "rollback" => {
            if flag(argv, "--list") {
                let v = curator::list_backups(st);
                return Ok(if v.is_empty() { "no curator snapshots".into() } else { v.join("\n") });
            }
            match p.get(1) {
                Some(id) => ledger::rollback(s, st, id),
                None => curator::rollback_tree(st, opt(argv, "--id").as_deref()),
            }
        }
        "ledger" => {
            if flag(argv, "--compact") {
                let (entries, before, after) = ledger::compact(st)?;
                let (blobs, freed) = ledger::gc_blobs(st);
                let mb = |b: u64| b as f64 / (1024.0 * 1024.0);
                return Ok(format!("ledger compacted — {entries} entries, {:.1} MB → {:.1} MB; {blobs} unreferenced blob(s) removed ({:.1} MB)", mb(before), mb(after), mb(freed)));
            }
            let rows = ledger::list(st, opt(argv, "--skill").as_deref(), opt(argv, "--limit").and_then(|l| l.parse().ok()).unwrap_or(20));
            if rows.is_empty() {
                return Ok("ledger is empty (or skills.ledger is disabled)".into());
            }
            Ok(rows.iter().map(|e| format!("{}  {:<8} {:<11} {}  {}", e["id"].as_str().unwrap_or(""), e["actor"].as_str().unwrap_or(""), e["action"].as_str().unwrap_or(""), e["skill"].as_str().unwrap_or(""), e["note"].as_str().unwrap_or(""))).collect::<Vec<_>>().join("\n"))
        }
        "purge" => {
            let days = opt(argv, "--days").and_then(|d| d.parse().ok()).unwrap_or(s.curator.archive_ttl_days);
            curator::purge(s, st, days, flag(argv, "--dry-run")).map(|v| format!("{} {} archived skill(s){}", if flag(argv, "--dry-run") { "would purge" } else { "purged" }, v.len(), if v.is_empty() { String::new() } else { format!(": {}", v.join(", ")) }))
        }
        o => Err(format!("unknown `ark curator` subcommand `{o}` (status usage run pause resume pin unpin list-unmanaged adopt restore list-archived archive prune backup rollback ledger purge)")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_sort_pin_gates_and_ledger_compact() {
        let d = std::env::temp_dir().join(format!("ark-curcli2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let st = Store::at(&d);
        let (cfg, paths) = (ark_kernel::config::Config::default(), ark_kernel::config::Paths { data: d.clone(), config_dir: d.join("cfg"), runtime: d.join("run") });
        let s = Settings::from_table(&toml::Table::new());
        for n in ["busy", "quiet"] {
            std::fs::create_dir_all(st.skills.join(n)).unwrap();
            std::fs::write(st.skills.join(n).join("SKILL.md"), format!("---\nname: {n}\ndescription: d\n---\n")).unwrap();
        }
        usage::mutate(&st, "busy", |r| {
            r.insert("use_count".into(), serde_json::json!(3));
        });
        let a = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let r = |v: &[&str]| curator_cmd(&cfg, &paths, &s, &st, &a(v), None);
        // `usage` defaults to activity (most-used first, upstream `_USAGE_SORTS`) and names its columns.
        let out = r(&["usage"]).unwrap();
        assert!(out.starts_with("skills: 2 total"), "{out}");
        assert!(out.contains("last_activity") && out.contains("agent=2"), "{out}");
        assert!(out.find("busy").unwrap() < out.find("quiet").unwrap(), "{out}");
        assert!(r(&["usage", "--sort", "name"]).unwrap().find("busy").unwrap() < r(&["usage", "--sort", "name"]).unwrap().find("quiet").unwrap());
        assert!(r(&["usage", "--provenance", "bundled"]).unwrap().contains("no skills found"));
        // Unmanaged pins are recorded but called out; adopted ones protect.
        assert!(r(&["pin", "quiet"]).unwrap().contains("unmanaged") && r(&["pin", "quiet"]).unwrap().contains("ark curator adopt quiet"));
        assert!(r(&["adopt", "quiet"]).unwrap().contains("adopted") && r(&["adopt", "quiet"]).unwrap().contains("already curator-managed"));
        assert!(r(&["pin", "quiet"]).unwrap().contains("will bypass auto-transitions"));
        // A pinned skill is never archived from the CLI (upstream `_cmd_archive`).
        assert!(r(&["archive", "quiet"]).unwrap_err().contains("is pinned — unpin first"));
        assert!(!r(&["unpin", "quiet"]).unwrap().is_empty() && r(&["archive", "quiet"]).is_ok());
        let compact = r(&["ledger", "--compact"]).unwrap();
        assert!(compact.contains("ledger compacted") && compact.contains("unreferenced blob(s)"), "{compact}");
        assert!(r(&["run", "--background"]).unwrap().contains("ran synchronously"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn curator_commands() {
        let d = std::env::temp_dir().join(format!("ark-curcli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let st = Store::at(&d);
        let (cfg, paths) = (ark_kernel::config::Config::default(), ark_kernel::config::Paths { data: d.clone(), config_dir: d.join("cfg"), runtime: d.join("run") });
        let s = Settings::from_table(&toml::Table::new());
        std::fs::create_dir_all(st.skills.join("mine")).unwrap();
        std::fs::write(st.skills.join("mine/SKILL.md"), "---\nname: mine\ndescription: m\n---\n").unwrap();
        let a = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let r = |v: &[&str]| curator_cmd(&cfg, &paths, &s, &st, &a(v), None);
        assert!(r(&["list-unmanaged"]).unwrap().contains("mine"));
        assert!(r(&["adopt", "--all-unmanaged", "--dry-run"]).unwrap().contains("would adopt: mine"));
        assert!(r(&["adopt", "mine"]).unwrap().contains("adopted"));
        assert!(r(&["pin", "mine"]).unwrap().contains("pinned"));
        assert!(r(&["usage", "--json"]).unwrap().contains("\"pinned\": true"));
        assert!(r(&["unpin", "mine"]).is_ok());
        assert!(r(&["archive", "mine"]).unwrap().contains("archived"));
        assert_eq!(r(&["list-archived"]).unwrap(), "mine");
        assert!(r(&["restore", "mine"]).unwrap().contains("restored"));
        assert!(r(&["ledger"]).unwrap().contains("archive"));
        assert!(r(&["backup", "--reason", "t"]).unwrap().contains("snapshot"));
        assert!(!r(&["rollback", "--list"]).unwrap().contains("no curator"));
        assert!(r(&["pause"]).is_ok() && r(&["status"]).unwrap().contains("(paused)"));
        assert!(r(&["run", "--dry-run"]).unwrap().contains("[dry-run]"));
        assert!(r(&["run", "--consolidate"]).unwrap().contains("consolidation needs a running agent"));
        // `/curator run --consolidate` (and `/curator run`) hand the review prompt to a sub-agent.
        r(&["pause"]).unwrap();
        r(&["resume"]).unwrap();
        let calls = std::cell::Cell::new(0);
        let fork = |p: &str| {
            calls.set(calls.get() + 1);
            assert!(p.contains("Candidates:") && p.contains("- mine"), "{p}");
            Ok("merged nothing".to_string())
        };
        let out = curator_cmd(&cfg, &paths, &s, &st, &a(&["run", "--consolidate", "--dry-run"]), Some(&fork)).unwrap();
        assert_eq!(calls.get(), 1);
        assert!(out.contains("DRY-RUN — REPORT ONLY") || out.contains("llm: merged nothing"), "{out}");
        assert!(out.contains("llm: merged nothing") && out.contains("report: "), "{out}");
        assert!(r(&["prune", "--days", "0"]).is_err() && r(&["purge"]).is_err());
        assert!(r(&["nope"]).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
