//! `ark skills …` (Hermes `hermes_cli/subcommands/skills.py` + `hermes_cli/skills_hub.py`,
//! OpenClaw `skills-cli.ts`, MIT) — shared by the CLI and `/skills`:
//!
//! list · view · search · browse · install · inspect · uninstall · check · update · audit [--deep]
//! · lint · setup · sync · reset [--restore] · list-modified · diff · opt-out [--remove] · opt-in
//! [--sync] · repair-official · publish · snapshot export|import · tap list|add|remove · config
//! [enable|disable <name>] · trust · untrust · usage · blueprint … · ledger · rollback

use super::super::core::settings::{Settings, Store};
use super::super::core::{confedit, invoke, lint, setup, usage};
use super::install::{Hub, InstallOpts};
use super::model::{Lock, Taps};
use super::sync;
use ark_kernel::config::{Config, Paths};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Interactive prompt (`ark skills setup`) — None on surfaces that cannot ask.
pub type Ask<'a> = &'a dyn Fn(&str) -> Option<String>;

pub struct Ctx<'a> {
    pub cfg: &'a Config,
    pub paths: &'a Paths,
    pub ws: &'a Path,
    /// Interactive prompt (`ark skills setup`): None on surfaces that cannot ask.
    pub ask: Option<Ask<'a>>,
}

fn flag(argv: &[String], f: &str) -> bool {
    argv.iter().any(|a| a == f)
}

fn opt(argv: &[String], f: &str) -> Option<String> {
    argv.iter().position(|a| a == f).and_then(|i| argv.get(i + 1).cloned()).or_else(|| argv.iter().find_map(|a| a.strip_prefix(&format!("{f}=")).map(String::from)))
}

/// Positional args (flags and their values removed).
fn pos(argv: &[String]) -> Vec<String> {
    const VALUED: &[&str] = &["--source", "--limit", "--page", "--size", "--category", "--name", "--to", "--repo", "--skill", "-w", "--workspace", "--sort", "--provenance", "--id", "--days", "--version", "--tag"];
    let mut out = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if VALUED.contains(&a.as_str()) {
            i += 2;
            continue;
        }
        if !a.starts_with('-') {
            out.push(a.clone());
        }
        i += 1;
    }
    out
}

fn table(rows: &[(String, String, String, String)]) -> String {
    rows.iter().map(|(a, b, c, d)| format!("{a:<34} {b:<11} {c:<10} {d}")).collect::<Vec<_>>().join("\n")
}

/// Source label of a result row: a GitHub-tap row shows its provider (Hermes `_display_source`),
/// so the seven taps stay distinguishable instead of all reading `github`.
fn display_source(m: &super::model::SkillMeta) -> &str {
    m.extra.get("provider").and_then(Value::as_str).filter(|_| m.source == "github").unwrap_or(&m.source)
}

pub fn run(c: &Ctx, argv: &[String]) -> Result<String, String> {
    let s = Settings::load(c.cfg);
    let st = Store::new(c.paths);
    let hub = Hub::new(&s, &st);
    let p = pos(argv);
    let sub = p.first().map(String::as_str).unwrap_or("list");
    let arg = |i: usize, usage: &str| p.get(i).cloned().ok_or_else(|| format!("usage: ark skills {usage}"));
    let json_out = flag(argv, "--json");
    match sub {
        "list" | "ls" => {
            let src = opt(argv, "--source").unwrap_or_else(|| "all".into());
            let cat = invoke::catalog(c.cfg, c.paths, c.ws, &Settings { disabled: vec![], ..s.clone() });
            let hubbed = usage::hub_names(&st);
            let bundled = usage::bundled_names(&st);
            let mut rows = Vec::new();
            for k in &cat {
                let origin = if hubbed.contains(&k.name) { "hub" } else if bundled.contains(&k.name) || k.source == crate::skill::Source::Bundled { "builtin" } else { "local" };
                if src != "all" && src != origin {
                    continue;
                }
                let disabled = s.is_disabled(&k.name);
                if disabled && flag(argv, "--enabled-only") {
                    continue;
                }
                let (ready, _) = setup::readiness(&k.front, &[]);
                rows.push((k.name.clone(), k.source.label(), if disabled { "disabled".to_string() } else { ready.as_str().to_string() }, k.description.chars().take(70).collect()));
            }
            if json_out {
                return Ok(serde_json::to_string_pretty(&rows.iter().map(|r| json!({"name": r.0, "source": r.1, "status": r.2, "description": r.3})).collect::<Vec<_>>()).unwrap());
            }
            Ok(format!("{} skill(s)\n{}", rows.len(), table(&rows)))
        }
        "view" | "show" => {
            let n = arg(1, "view <name>")?;
            let cat = invoke::catalog(c.cfg, c.paths, c.ws, &s);
            let k = invoke::resolve(&cat, &n).ok_or_else(|| format!("no skill `{n}`"))?;
            Ok(format!("{} ({}, {})\n{}\n\n{}", k.name, k.source.label(), k.file.display(), k.description, k.body()?))
        }
        "search" | "browse" => {
            let q = if sub == "browse" { String::new() } else { arg(1, "search <query> [--source all|official|github|clawhub|skills-sh|lobehub|browse-sh|well-known] [--limit n] [--json]")? };
            let limit: usize = opt(argv, "--limit").or(opt(argv, "--size")).and_then(|l| l.parse().ok()).unwrap_or(if sub == "browse" { 20 } else { 25 });
            let page: usize = opt(argv, "--page").and_then(|x| x.parse().ok()).unwrap_or(1).max(1);
            let (r, _, late) = hub.search(&q, &opt(argv, "--source").unwrap_or_else(|| "all".into()), limit * page, Duration::from_secs(30));
            let r: Vec<_> = r.into_iter().skip(limit * (page - 1)).collect();
            if json_out {
                return Ok(serde_json::to_string_pretty(&r).unwrap());
            }
            let mut o = table(&r.iter().map(|m| (m.identifier.clone(), display_source(m).to_string(), m.trust_level.clone(), m.description.chars().take(70).collect())).collect::<Vec<_>>());
            if r.is_empty() {
                o = "no results".into();
            }
            if !late.is_empty() {
                o.push_str(&format!("\n(timed out: {})", late.join(", ")));
            }
            Ok(o)
        }
        "inspect" | "info" => {
            let id = arg(1, "inspect <identifier>")?;
            let (m, preview) = hub.inspect(&id).ok_or_else(|| format!("no registry knows `{id}`"))?;
            Ok(format!("{}\n  source: {} ({})\n  identifier: {}\n  tags: {}\n  {}\n\n{preview}", m.name, display_source(&m), m.trust_level, m.identifier, m.tags.join(", "), m.description))
        }
        "install" | "add" => {
            let mut id = arg(1, "install <identifier|url> [--category c] [--name n] [--version v] [--force]")?;
            // `--version` pins a ClawHub release (OpenClaw `skills-cli.ts`: `--version` and `--tag`
            // are separate selectors; a `@version` suffix means the same thing).
            if let Some(v) = opt(argv, "--version").filter(|v| !v.is_empty()) {
                if opt(argv, "--tag").is_some() {
                    return Err("Use either --version or --tag.".into());
                }
                if id.contains("://") || id.contains('/') && !id.starts_with('@') {
                    return Err(format!("--version applies to ClawHub skills only (`--version` with `{id}`); pass the release in the identifier instead"));
                }
                id = format!("{id}@{v}");
            }
            // A bundled name (or this repo's copy of one) restores the shipped skill instead of fetching it.
            if let Some(b) = sync::bundled_dir() {
                let bare = id.rsplit('/').next().unwrap_or(&id);
                if (bare == id || id.starts_with("NousResearch/hermes-agent/skills/")) && crate::skill::discover(&[(b.clone(), crate::skill::Source::Bundled)]).iter().any(|x| x.name == bare) && Lock(&st).get(bare).is_none() {
                    return sync::reset(&st, &b, bare, true);
                }
            }
            let i = hub.install(&id, &InstallOpts { category: opt(argv, "--category").unwrap_or_default(), name: opt(argv, "--name").unwrap_or_default(), force: flag(argv, "--force"), user_force: flag(argv, "--force") })?;
            let mut o = format!("{}\nInstalled '{}' → {}", i.report, i.name, i.path.display());
            if !i.advisory.is_empty() {
                o.push_str(&format!("\n{}", i.advisory));
            }
            if let Some(k) = crate::skill::discover(&[(st.skills.clone(), crate::skill::Source::User)]).into_iter().find(|k| k.name == i.name) {
                if let Some(n) = setup::setup_note(&k.front, &[]) {
                    o.push_str(&format!("\n{n}"));
                }
            }
            Ok(o)
        }
        "uninstall" | "remove" | "rm" => hub.uninstall(&arg(1, "uninstall <name>")?),
        "check" => {
            let rows = hub.check(p.get(1).map(String::as_str));
            if rows.is_empty() {
                return Ok("no hub-installed skills".into());
            }
            Ok(rows.iter().map(|(n, st, d)| format!("{n:<28} {st:<17} {d}")).collect::<Vec<_>>().join("\n"))
        }
        "update" => {
            let r = hub.update(p.get(1).map(String::as_str), flag(argv, "--force"));
            if r.is_empty() {
                return Ok("everything is up to date".into());
            }
            Ok(r.iter().map(|(n, x)| format!("{n}: {}", x.as_ref().map(String::as_str).unwrap_or_else(|e| e.as_str()))).collect::<Vec<_>>().join("\n"))
        }
        "audit" => {
            let r = hub.audit(p.get(1).map(String::as_str), flag(argv, "--deep"));
            Ok(if r.is_empty() { "no hub-installed skills to audit".into() } else { r.into_iter().map(|x| x.1).collect::<Vec<_>>().join("\n\n") })
        }
        "lint" => {
            let target = arg(1, "lint <name|path>")?;
            let file = if Path::new(&target).exists() {
                let p = PathBuf::from(&target);
                if p.is_dir() { p.join("SKILL.md") } else { p }
            } else {
                let cat = invoke::catalog(c.cfg, c.paths, c.ws, &s);
                invoke::resolve(&cat, &target).ok_or_else(|| format!("no skill `{target}`"))?.file.clone()
            };
            let f = lint::lint_skill(&file)?;
            let out = lint::format(&target, &f);
            if f.iter().any(|x| x.severity == "error") {
                Err(out)
            } else {
                Ok(out)
            }
        }
        "setup" => {
            let n = arg(1, "setup <name>")?;
            let cat = invoke::catalog(c.cfg, c.paths, c.ws, &s);
            let k = invoke::resolve(&cat, &n).ok_or_else(|| format!("no skill `{n}`"))?;
            let reqs = setup::required_env(&k.front);
            if reqs.is_empty() {
                return Ok(format!("{} needs no environment setup", k.name));
            }
            let vault = ark_kernel::vault::Vault::load(&c.paths.secrets())?;
            let ask = c.ask.ok_or("secure entry needs an interactive terminal: run `ark skills setup <name>` locally or `ark secrets set <NAME>`")?;
            let left = setup::capture(&reqs, &vault, |r| ask(&format!("{}{}: ", r.prompt, r.help.as_ref().map(|h| format!(" ({h})")).unwrap_or_default())))?;
            Ok(if left.is_empty() { format!("{} is ready", k.name) } else { format!("still missing: {}", left.join(", ")) })
        }
        "sync" => {
            let b = sync::bundled_dir().ok_or("this build ships no bundled skills")?;
            let r = sync::sync(&s, &st, &b)?;
            Ok(format!("added {}, updated {}, unchanged {}, kept your edits: {}, user-deleted: {}, retired: {}{}{}", r.added.len(), r.updated.len(), r.unchanged, if r.skipped_modified.is_empty() { "-".into() } else { r.skipped_modified.join(", ") }, r.skipped_deleted.len(), r.removed_from_manifest.len(), if r.relocated.is_empty() { String::new() } else { format!(", relocated: {}", r.relocated.join(", ")) }, if r.essential_only { " (opted out via .no-bundled-skills: essential skills only)" } else { "" }))
        }
        "reset" => sync::reset(&st, &sync::bundled_dir().ok_or("no bundled skills")?, &arg(1, "reset <name> [--restore]")?, flag(argv, "--restore")),
        "list-modified" => {
            let v = sync::list_modified(&st, &sync::bundled_dir().ok_or("no bundled skills")?);
            if json_out {
                return Ok(serde_json::to_string_pretty(&v.iter().map(|(n, d, b)| json!({"name": n, "dest": d, "bundled_src": b})).collect::<Vec<_>>()).unwrap());
            }
            Ok(if v.is_empty() { "no bundled skills were edited".into() } else { v.iter().map(|x| format!("{}  {}", x.0, x.1.display())).collect::<Vec<_>>().join("\n") })
        }
        "diff" => {
            let d = sync::diff(&st, &sync::bundled_dir().ok_or("no bundled skills")?, &arg(1, "diff <name>")?)?;
            Ok(if d.is_empty() { "identical to the bundled version".into() } else { d.iter().map(|(p, s, t)| format!("{p}: {s}\n{t}")).collect::<Vec<_>>().join("\n") })
        }
        "opt-out" => sync::opt_out(&st, &sync::bundled_dir().unwrap_or_default(), true, flag(argv, "--remove")),
        "opt-in" => {
            let mut o = sync::opt_out(&st, &sync::bundled_dir().unwrap_or_default(), false, false)?;
            if flag(argv, "--sync") {
                if let Some(b) = sync::bundled_dir() {
                    let r = sync::sync(&s, &st, &b)?;
                    o.push_str(&format!("; seeded {}", r.added.len()));
                }
            }
            Ok(o)
        }
        "repair-official" => {
            let n = arg(1, "repair-official <name|all> [--restore]")?;
            let off = super::sources::Official { http: &hub.http };
            let idx = off.index();
            let targets: Vec<Value> = idx.into_iter().filter(|e| n == "all" || e["name"] == n.as_str() || e["path"].as_str().is_some_and(|p| p.rsplit('/').next() == Some(n.as_str()))).collect();
            if targets.is_empty() {
                return Err(format!("no official optional skill `{n}`"));
            }
            let mut out = Vec::new();
            for e in targets {
                let id = format!("official/{}", e["path"].as_str().unwrap_or(""));
                let name = e["name"].as_str().unwrap_or("").to_string();
                let local = usage::find_local(&st, &name);
                if let Some(l) = local.as_ref().filter(|_| !flag(argv, "--restore")) {
                    // Backfill provenance when the local copy is byte-identical to the official one.
                    if let Some(b) = super::model::Source::fetch(&super::sources::Official { http: &hub.http }, &id) {
                        let lh = super::install::files_hash(&super::install::dir_files(&l.dir));
                        if lh == super::install::files_hash(&b.files) && Lock(&st).get(&name).is_none() {
                            let rel = l.dir.strip_prefix(&st.skills).map(|r| r.to_string_lossy().to_string()).unwrap_or(name.clone());
                            Lock(&st).record_install(&name, "official", &id, "builtin", "safe", &lh, &rel, &b.files.keys().cloned().collect::<Vec<_>>(), Default::default())?;
                            out.push(format!("{name}: provenance backfilled"));
                            continue;
                        }
                    }
                    out.push(format!("{name}: local copy differs (use --restore)"));
                } else if local.is_none() && !flag(argv, "--restore") {
                    out.push(format!("{name}: not installed"));
                } else {
                    if let Some(l) = &local {
                        let bak = st.skills.join(".restore-backup").join(&name);
                        let _ = std::fs::remove_dir_all(&bak);
                        std::fs::create_dir_all(bak.parent().unwrap()).map_err(|e| e.to_string())?;
                        std::fs::rename(&l.dir, &bak).map_err(|e| e.to_string())?;
                        let _ = Lock(&st).record_uninstall(&name);
                    }
                    out.push(match hub.install(&id, &InstallOpts { force: true, ..Default::default() }) {
                        Ok(i) => format!("{name}: restored → {}", i.path.display()),
                        Err(e) => format!("{name}: {e}"),
                    });
                }
            }
            Ok(out.join("\n"))
        }
        "publish" => publish(&hub, &arg(1, "publish <skill-path|name> [--to github|clawhub] [--repo owner/repo]")?, &opt(argv, "--to").unwrap_or_else(|| "github".into()), &opt(argv, "--repo").unwrap_or_default(), c),
        "snapshot" => match p.get(1).map(String::as_str) {
            Some("export") => {
                let out = arg(2, "snapshot export <file|->")?;
                let snap = json!({"ark_version": env!("CARGO_PKG_VERSION"), "exported_at": ark_kernel::util::unix_now(), "skills": Lock(&st).list().into_iter().map(|(n, e)| json!({"name": n, "source": e["source"], "identifier": e["identifier"], "category": e["install_path"].as_str().and_then(|p| p.rsplit_once('/')).map(|x| x.0).unwrap_or("")})).collect::<Vec<_>>(), "taps": Taps(&st).list().into_iter().map(|(r, p)| json!({"repo": r, "path": p})).collect::<Vec<_>>()});
                let text = serde_json::to_string_pretty(&snap).unwrap() + "\n";
                if out == "-" {
                    return Ok(text);
                }
                std::fs::write(&out, text).map_err(|e| e.to_string())?;
                Ok(format!("Snapshot exported: {out} ({} skill(s), {} tap(s))", snap["skills"].as_array().map_or(0, |a| a.len()), snap["taps"].as_array().map_or(0, |a| a.len())))
            }
            Some("import") => {
                let f = arg(2, "snapshot import <file> [--force]")?;
                let v: Value = serde_json::from_str(&std::fs::read_to_string(&f).map_err(|e| format!("{f}: {e}"))?).map_err(|_| format!("Invalid JSON in {f}"))?;
                for t in v["taps"].as_array().into_iter().flatten() {
                    if let Some(r) = t["repo"].as_str() {
                        let _ = Taps(&st).add(r, t["path"].as_str().unwrap_or("skills/"));
                    }
                }
                let mut out = Vec::new();
                let mut failed = false;
                for e in v["skills"].as_array().into_iter().flatten() {
                    let id = e["identifier"].as_str().unwrap_or("");
                    if id.is_empty() {
                        out.push(format!("skipped entry with no identifier: {}", e["name"].as_str().unwrap_or("?")));
                        continue;
                    }
                    match hub.install(id, &InstallOpts { category: e["category"].as_str().unwrap_or("").into(), name: e["name"].as_str().unwrap_or("").into(), force: flag(argv, "--force"), user_force: flag(argv, "--force") }) {
                        Ok(i) => out.push(format!("installed {}", i.name)),
                        Err(x) => {
                            failed = true;
                            out.push(format!("{id}: {}", x.lines().next().unwrap_or("")))
                        }
                    }
                }
                if failed {
                    Err(out.join("\n"))
                } else {
                    Ok(if out.is_empty() { "No skills in snapshot to install.".into() } else { out.join("\n") })
                }
            }
            _ => Err("usage: ark skills snapshot export <file|-> | import <file>".into()),
        },
        "tap" | "taps" => match p.get(1).map(String::as_str).unwrap_or("list") {
            "list" => Ok(hub.taps().iter().map(|(r, p)| format!("{r} ({p})")).collect::<Vec<_>>().join("\n")),
            "add" => Ok(if Taps(&st).add(&arg(2, "tap add <owner/repo> [path]")?, p.get(3).map(String::as_str).unwrap_or("skills/"))? { "tap added".into() } else { "already tapped".into() }),
            "remove" | "rm" => Ok(if Taps(&st).remove(&arg(2, "tap remove <owner/repo>")?)? { "tap removed".into() } else { "no such tap".into() }),
            o => Err(format!("unknown tap action `{o}`")),
        },
        "config" | "enable" | "disable" => {
            let (action, name) = match sub {
                "config" => (p.get(1).cloned().unwrap_or_else(|| "list".into()), p.get(2).cloned()),
                other => (other.to_string(), p.get(1).cloned()),
            };
            match action.as_str() {
                "list" => Ok(format!("disabled skills: {}", if s.disabled.is_empty() { "(none)".into() } else { s.disabled.join(", ") })),
                "enable" | "disable" => {
                    let n = name.ok_or("usage: ark skills config enable|disable <name>")?;
                    let mut d = s.disabled.clone();
                    d.retain(|x| *x != n);
                    if action == "disable" {
                        d.push(n.clone());
                    }
                    confedit::set(c.paths, &["skills", "disabled"], toml::Value::Array(d.into_iter().map(toml::Value::String).collect()))?;
                    Ok(format!("skill `{n}` {action}d"))
                }
                o => Err(format!("unknown config action `{o}` (list, enable, disable)")),
            }
        }
        "trust" | "untrust" => {
            let root = p.get(1).map(PathBuf::from).unwrap_or_else(|| c.ws.to_path_buf());
            let root = root.canonicalize().map_err(|e| format!("{}: {e}", root.display()))?.display().to_string();
            let mut list: Vec<String> = c.cfg.skills.get("trusted_project_dirs").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
            list.retain(|x| *x != root);
            if sub == "trust" {
                list.push(root.clone());
            }
            confedit::set(c.paths, &["skills", "trusted_project_dirs"], toml::Value::Array(list.into_iter().map(toml::Value::String).collect()))?;
            Ok(format!("{} {root} (project skills load from trusted roots when `[skills] require_project_trust = true`)", if sub == "trust" { "trusted" } else { "untrusted" }))
        }
        "usage" => {
            let cat = invoke::catalog(c.cfg, c.paths, c.ws, &s);
            let rows = usage::report(&s, &st, &cat);
            if json_out {
                return Ok(serde_json::to_string_pretty(&rows).unwrap());
            }
            Ok(rows.iter().map(|r| format!("{:<30} {:<9} uses={:<4} views={:<4} patches={:<4} {}", r["name"].as_str().unwrap_or(""), r["provenance"].as_str().unwrap_or(""), r["use_count"], r["view_count"], r["patch_count"], r["state"].as_str().unwrap_or(""))).collect::<Vec<_>>().join("\n"))
        }
        "blueprint" | "blueprints" => super::super::core::blueprints::cli(&st, c.ws, c.cfg.schedule.utc_offset_minutes, &argv[argv.iter().position(|a| a == sub).map(|i| i + 1).unwrap_or(argv.len())..]),
        // Ecosystem imports (OpenClaw / Hermes / Claude Code) — see `crate::compat`.
        "compat" => crate::compat::cli::run(c.cfg, c.paths, c.ws, argv),
        "ledger" => Ok(super::super::core::ledger::list(&st, opt(argv, "--skill").as_deref(), opt(argv, "--limit").and_then(|l| l.parse().ok()).unwrap_or(20)).iter().map(|e| format!("{}  {:<8} {:<11} {}  {}", e["id"].as_str().unwrap_or(""), e["actor"].as_str().unwrap_or(""), e["action"].as_str().unwrap_or(""), e["skill"].as_str().unwrap_or(""), e["note"].as_str().unwrap_or(""))).collect::<Vec<_>>().join("\n")),
        "rollback" => super::super::core::ledger::rollback(&s, &st, &arg(1, "rollback <ledger-entry-id>")?),
        // Skill writes the approval gate staged (`skill action=create|update|patch` with
        // `[skills] write_approval` on): review them from the CLI too, not only `/skills`.
        "pending" | "approve" | "reject" => {
            let mc = super::super::core::manage::Ctx { cfg: c.cfg, paths: c.paths, ws: c.ws, settings: &s, session: None };
            super::super::core::manage::cli(&mc, argv)
        }
        other => Err(format!("unknown `ark skills` subcommand `{other}`; try: list view search browse install inspect uninstall check update audit lint setup sync reset list-modified diff opt-out opt-in repair-official publish snapshot tap config enable disable trust untrust usage blueprint ledger rollback pending approve reject compat")),
    }
}

/// `ark skills publish`: scan, then fork the target repo, branch, upload, open a PR.
pub fn publish(hub: &Hub, target: &str, to: &str, repo: &str, c: &Ctx) -> Result<String, String> {
    let s = &hub.http.settings;
    let path = {
        let p = PathBuf::from(target);
        if p.join("SKILL.md").is_file() {
            p
        } else {
            let cat = invoke::catalog(c.cfg, c.paths, c.ws, s);
            invoke::resolve(&cat, target).map(|k| k.dir.clone()).ok_or_else(|| format!("No SKILL.md found at {target}"))?
        }
    };
    let md = std::fs::read_to_string(path.join("SKILL.md")).map_err(|e| e.to_string())?;
    let fm = crate::yaml::frontmatter(&md).0;
    let name = fm.get("name").and_then(Value::as_str).map(String::from).unwrap_or_else(|| path.file_name().unwrap().to_string_lossy().to_string());
    if fm.get("description").and_then(Value::as_str).is_none_or(|d| d.trim().is_empty()) {
        return Err("SKILL.md must have a 'description' in frontmatter.".into());
    }
    let r = ark_security::skills_guard::scan_dir(&path, "self");
    let report = ark_security::skills_guard::format_report(&r);
    if r.verdict == ark_security::skills_guard::Verdict::Dangerous {
        return Err(format!("{report}\nCannot publish a skill with DANGEROUS verdict."));
    }
    match to {
        "github" => {}
        "clawhub" => return Ok(format!("{report}\nClawHub publishing is not supported from the CLI yet; submit at https://clawhub.ai/submit")),
        o => return Err(format!("Unknown target: {o}. Use 'github' or 'clawhub'.")),
    }
    if repo.is_empty() {
        return Err("--repo required for GitHub publish (ark skills publish <path> --to github --repo owner/repo)".into());
    }
    if std::env::var(&s.hub.github_token_env).is_err() {
        return Err(format!("GitHub authentication required: set {} (e.g. `export {}=$(gh auth token)`)", s.hub.github_token_env, s.hub.github_token_env));
    }
    let api = &s.hub.github_api;
    let h = &hub.http;
    let fork = h.send_json("POST", &format!("{api}/repos/{repo}/forks"), &json!({}))?;
    let fork_repo = match fork.status {
        200 | 202 => fork.json().and_then(|v| v["full_name"].as_str().map(String::from)).ok_or("fork response without full_name")?,
        403 => return Err("GitHub token lacks permission to fork repos".into()),
        st => return Err(format!("Failed to fork {repo}: {st}")),
    };
    let branch = h.get_json(&format!("{api}/repos/{repo}")).and_then(|v| v["default_branch"].as_str().map(String::from)).unwrap_or_else(|| "main".into());
    let base = h.get_json(&format!("{api}/repos/{fork_repo}/git/refs/heads/{branch}")).and_then(|v| v["object"]["sha"].as_str().map(String::from)).ok_or("Failed to get base branch")?;
    let nb = format!("add-skill-{name}");
    h.send_json("POST", &format!("{api}/repos/{fork_repo}/git/refs"), &json!({"ref": format!("refs/heads/{nb}"), "sha": base}))?;
    use base64::Engine;
    for (rel, data) in super::install::dir_files(&path) {
        let r = h.send_json("PUT", &format!("{api}/repos/{fork_repo}/contents/skills/{name}/{rel}"), &json!({"message": format!("Add {name} skill: {rel}"), "content": base64::engine::general_purpose::STANDARD.encode(&data), "branch": nb}))?;
        if !(200..300).contains(&r.status) {
            return Err(format!("Failed to upload {rel}: {}", r.status));
        }
    }
    let pr = h.send_json("POST", &format!("{api}/repos/{repo}/pulls"), &json!({"title": format!("Add skill: {name}"), "body": format!("Submitting the `{name}` skill via the ark skills hub.\n\nThis skill was scanned by Skills Guard before submission."), "head": format!("{}:{nb}", fork_repo.split('/').next().unwrap_or("")), "base": branch}))?;
    if pr.status == 201 {
        Ok(format!("{report}\nPR created: {}", pr.json().and_then(|v| v["html_url"].as_str().map(String::from)).unwrap_or_default()))
    } else {
        Err(format!("Failed to create PR: {} {}", pr.status, pr.text().chars().take(200).collect::<String>()))
    }
}

#[cfg(test)]
mod tests {
    use super::super::http::testserver::{ok, serve};
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn cli_end_to_end_against_fake_registries() {
        let md = "---\nname: pdf-tools\ndescription: Work with PDF files\n---\nSee references/guide.md\n";
        let mut routes = super::super::install::tests::github_routes("acme/skills", "pdf-tools", md);
        let zip = super::super::zip::build_stored(&[("SKILL.md", b"---\nname: weather\ndescription: Weather now\n---\nUse wttr.in")]);
        routes.extend([
            ok("/claw/api/v1/skills/weather", json!({"skill": {"slug": "weather", "displayName": "Weather", "summary": "Weather now"}, "latestVersion": {"version": "1.2.0"}, "owner": {"handle": "steipete"}}).to_string()),
            ok("/claw/api/v1/download", zip),
            ok("/claw/api/v1/skills", json!({"items": [{"slug": "weather", "displayName": "Weather", "summary": "Weather now"}]}).to_string()),
            ok("/ssh/api/search", json!({"skills": [{"id": "acme/skills/pdf-tools", "name": "pdf-tools", "installs": 12}]}).to_string()),
            ok("/lobe/index.json", json!({"agents": [{"identifier": "translator", "meta": {"title": "Translator", "description": "Translate text", "tags": ["lang"]}}]}).to_string()),
            ok("/lobe/translator.json", json!({"identifier": "translator", "meta": {"title": "Translator", "description": "Translate text"}, "config": {"systemRole": "You translate."}}).to_string()),
            ok("/browse/api/skills", json!({"skills": [{"slug": "airbnb.com/search", "name": "airbnb-search", "description": "Search listings", "hostname": "airbnb.com"}]}).to_string()),
            ok("/browse/api/skills/airbnb.com/search", json!({"skillMdUrl": "SELF/md/airbnb.md"}).to_string()),
            ok("/site/.well-known/skills/index.json", json!({"skills": [{"name": "deploy-site", "description": "Deploy", "files": ["SKILL.md"]}]}).to_string()),
            ok("/site/.well-known/skills/deploy-site/SKILL.md", "---\nname: deploy-site\ndescription: Deploy\n---\nship"),
            ok("/raw-md/notes/SKILL.md", "---\nname: url-notes\ndescription: Notes\n---\nsee [x](extra.txt)"),
            ok("/raw-md/notes/extra.txt", "extra"),
            ok("/gh/repos/me/fork-target/forks", json!({"full_name": "bot/fork-target"}).to_string()),
            ok("/gh/repos/me/fork-target", json!({"default_branch": "main"}).to_string()),
            ok("/gh/repos/bot/fork-target/git/refs/heads/main", json!({"object": {"sha": "s1"}}).to_string()),
            ok("/gh/repos/bot/fork-target/git/refs", "{}"),
            ok("/gh/repos/bot/fork-target/contents/skills/pdf-tools/SKILL.md", "{}"),
            ok("/gh/repos/bot/fork-target/contents/skills/pdf-tools/references/guide.md", "{}"),
            ("/gh/repos/me/fork-target/pulls".into(), 201, vec![], json!({"html_url": "https://github.com/me/fork-target/pull/1"}).to_string().into_bytes()),
        ]);
        let (base, log) = serve(routes);
        // browse.sh's skillMdUrl must be absolute: patch after the server knows its port.
        let d = std::env::temp_dir().join(format!("ark-skillscli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("ws")).unwrap();
        let paths = Paths { data: d.join("data"), config_dir: d.join("cfg"), runtime: d.join("run") };
        let cfg = Config { skills: toml::from_str(&format!("tier1_advisory = false\n[hub]\nallow_private = true\ngithub_api = \"{base}/gh\"\ngithub_raw = \"{base}/raw\"\nclawhub = \"{base}/claw/api/v1\"\nskills_sh = \"{base}/ssh\"\nlobehub = \"{base}/lobe\"\nbrowse_sh = \"{base}/browse/api/skills\"\ntaps = [\"acme/skills\"]\n")).unwrap(), ..Default::default() };
        let c = Ctx { cfg: &cfg, paths: &paths, ws: &d.join("ws"), ask: None };
        let r = |v: &[&str]| run(&c, &a(v));
        let found = r(&["search", "weather", "--source", "clawhub"]).unwrap();
        assert!(found.contains("weather") && found.contains("clawhub"), "{found}");
        let i = r(&["install", "@steipete/weather"]).unwrap();
        assert!(i.contains("Installed 'weather'"), "{i}");
        assert!(log.lock().unwrap().iter().any(|l| l.starts_with("/claw/api/v1/download?slug=weather&version=1.2.0&owner=steipete")));
        assert!(r(&["install", "skills-sh/acme/skills/pdf-tools"]).unwrap().contains("pdf-tools"), "skills.sh resolves through GitHub");
        assert_eq!(Lock(&Store::new(&paths)).get("pdf-tools").unwrap()["source"], "skills.sh");
        assert!(r(&["install", "lobehub/translator"]).unwrap().contains("translator"));
        assert!(std::fs::read_to_string(paths.data.join("skills/translator/SKILL.md")).unwrap().contains("You translate."));
        assert!(r(&["install", &format!("well-known:{base}/site/.well-known/skills/deploy-site")]).unwrap().contains("deploy-site"));
        assert!(r(&["install", &format!("{base}/raw-md/notes/SKILL.md")]).unwrap().contains("url-notes"));
        assert!(paths.data.join("skills/url-notes/extra.txt").is_file());
        assert!(r(&["search", "translate", "--source", "lobehub"]).unwrap().contains("lobehub/translator"));
        assert!(r(&["search", "airbnb", "--source", "browse-sh"]).unwrap().contains("browse-sh/airbnb.com/search"));
        assert!(r(&["search", &format!("{base}/site"), "--source", "well-known"]).unwrap().contains("deploy-site"));
        assert!(r(&["search", "pdf", "--source", "skills-sh"]).unwrap().contains("skills-sh/acme/skills/pdf-tools"));
        let l = r(&["list", "--source", "hub"]).unwrap();
        assert!(l.starts_with("5 skill(s)") && l.contains("weather"), "{l}");
        assert!(r(&["check"]).unwrap().contains("weather"));
        assert!(r(&["view", "weather"]).unwrap().contains("wttr.in"));
        let snap = d.join("snap.json");
        assert!(r(&["snapshot", "export", snap.to_str().unwrap()]).unwrap().contains("5 skill(s)"));
        assert!(r(&["uninstall", "weather"]).unwrap().contains("Uninstalled"));
        assert!(r(&["snapshot", "import", snap.to_str().unwrap(), "--force"]).is_ok());
        assert!(paths.data.join("skills/weather/SKILL.md").is_file(), "reinstalled from snapshot");
        assert!(r(&["tap", "add", "me/more"]).unwrap().contains("added") && r(&["tap", "list"]).unwrap().contains("me/more"));
        assert!(r(&["config", "disable", "weather"]).unwrap().contains("disabled"));
        let cfg2 = Config::load(Some(&paths.user_config()), None, &[]).unwrap();
        assert!(Settings::load(&cfg2).is_disabled("weather"));
        assert!(r(&["trust"]).unwrap().contains("trusted"));
        assert!(r(&["lint", "pdf-tools"]).unwrap().contains("finding"));
        assert!(r(&["audit", "--deep"]).unwrap().contains("AST deep scan"));
        assert!(r(&["usage"]).unwrap().contains("weather"));
        assert!(r(&["frobnicate"]).unwrap_err().contains("unknown"));
        assert!(r(&["publish", "pdf-tools", "--repo", "me/fork-target"]).unwrap_err().contains("authentication"));
        // SAFETY: test-local env var, read back immediately by this thread only.
        unsafe { std::env::set_var("GITHUB_TOKEN", "test-token") };
        let pr = r(&["publish", "pdf-tools", "--repo", "me/fork-target"]).unwrap();
        unsafe { std::env::remove_var("GITHUB_TOKEN") };
        assert!(pr.contains("PR created: https://github.com/me/fork-target/pull/1"), "{pr}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Row “skills CLI (27/31 sub-commands)”: every documented sub-command must dispatch — on the
    /// CLI (`ark skills <sub>`) and on the slash surface (`/skills <sub>`), which share `run`.
    /// A dead base URL keeps every registry call local and instantly refused.
    #[test]
    fn every_documented_subcommand_dispatches_from_cli_and_slash() {
        use ark_core::{Block, Cancel, ModelCaps, ModelRequest, ModelResponse, Provider, ProviderError, StopReason, StreamEvent, Usage};
        use std::sync::Arc;
        struct P;
        impl Provider for P {
            fn id(&self) -> &str {
                "fake"
            }
            fn caps(&self, _: &str) -> ModelCaps {
                ModelCaps { context_window: 100_000, max_output: 4096, tools: false, vision: false, explicit_cache: false }
            }
            fn complete(&self, _: &ModelRequest, _: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, ProviderError> {
                Ok(ModelResponse { message: ark_core::Message { role: ark_core::Role::Assistant, content: vec![Block::text("ok")] }, stop: StopReason::EndTurn, usage: Usage::default(), model: "m".into() })
            }
        }
        struct R(Arc<P>);
        impl ark_kernel::kernel::Resolver for R {
            fn provider(&self, _: &str) -> Result<Arc<dyn Provider>, String> {
                Ok(self.0.clone())
            }
        }

        const SUBS: &[&str] = &[
            "list", "view", "search", "browse", "install", "inspect", "uninstall", "check", "update", "audit", "lint", "setup", "sync", "reset", "list-modified", "diff", "opt-out", "opt-in", "repair-official", "publish", "snapshot", "tap", "config", "enable", "disable", "trust", "untrust", "usage", "blueprint", "ledger", "rollback",
        ];
        let d = std::env::temp_dir().join(format!("ark-sksubs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("ws")).unwrap();
        let paths = Paths { data: d.join("data"), config_dir: d.join("cfg"), runtime: d.join("run") };
        let mut cfg = Config::default();
        cfg.model.default = "fake/m".into();
        cfg.skills = toml::from_str("[hub]\ngithub_api = \"http://127.0.0.1:9/gh\"\ngithub_raw = \"http://127.0.0.1:9/raw\"\nclawhub = \"http://127.0.0.1:9/claw\"\nskills_sh = \"http://127.0.0.1:9/ssh\"\nlobehub = \"http://127.0.0.1:9/lobe\"\nbrowse_sh = \"http://127.0.0.1:9/browse\"\n").unwrap();
        let c = Ctx { cfg: &cfg, paths: &paths, ws: &d.join("ws"), ask: None };
        // The unknown-sub-command text is the CLI's own table of what it supports.
        let unknown = run(&c, &a(&["frobnicate"])).unwrap_err();
        for s in SUBS {
            assert!(unknown.contains(s), "the unknown-subcommand hint lists `{s}`: {unknown}");
            let e = run(&c, &a(&[s])).err().unwrap_or_default();
            assert!(!e.contains("unknown `ark skills` subcommand"), "`ark skills {s}` dispatches: {e}");
        }

        // Same table through `/skills …`: build a kernel the way the binary does and route it.
        let k = ark_kernel::kernel::new_kernel(cfg.clone(), paths.clone(), Arc::new(R(Arc::new(P))), crate::host::tools(&cfg, &paths, &d.join("ws")), Arc::new(ark_kernel::vault::Vault::empty()), Arc::new(ark_kernel::approver::Policy { allow_privilege: true, allow_egress: false }));
        crate::host::attach(&k, &d.join("ws"));
        assert!(k.slash_commands().iter().any(|(n, _)| n == "skills"), "/skills is registered");
        for s in SUBS {
            let r = k.run_slash(&format!("/skills {s}"), None, "test").unwrap_or_else(|| panic!("/skills {s} is handled"));
            let text = match r {
                Ok(reply) => reply.text.unwrap_or_default(),
                Err(e) => e,
            };
            assert!(!text.contains("unknown `ark skills` subcommand"), "`/skills {s}` dispatches: {text}");
        }
        assert_eq!(k.run_slash("/skills help", None, "test").unwrap().unwrap().text.unwrap_or_default().chars().take(7).collect::<String>(), "/skills");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// `publish --to clawhub` is a pointer upstream and a pointer here (Hermes
    /// `hermes_cli/skills_hub.py:1379-1381`): no network, no fake publish, same URL; the GitHub
    /// path's preconditions (description, `--repo`, token) come first.
    #[test]
    fn publish_to_clawhub_is_a_pointer_like_upstream() {
        let d = std::env::temp_dir().join(format!("ark-skpub-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let sk = d.join("ws/.ark/skills/notes");
        std::fs::create_dir_all(&sk).unwrap();
        std::fs::write(sk.join("SKILL.md"), "---\nname: notes\ndescription: Keep notes\n---\nbody\n").unwrap();
        let paths = Paths { data: d.join("data"), config_dir: d.join("cfg"), runtime: d.join("run") };
        let cfg = Config::default();
        let c = Ctx { cfg: &cfg, paths: &paths, ws: &d.join("ws"), ask: None };
        let out = run(&c, &a(&["publish", "notes", "--to", "clawhub"])).unwrap();
        assert!(out.contains("ClawHub publishing is not supported from the CLI yet") && out.contains("https://clawhub.ai/submit"), "{out}");
        assert!(run(&c, &a(&["publish", "notes", "--to", "elsewhere"])).unwrap_err().contains("Unknown target: elsewhere. Use 'github' or 'clawhub'."));
        assert!(run(&c, &a(&["publish", "notes"])).unwrap_err().contains("--repo required for GitHub publish"));
        // A skill directory without a description is refused before any target handling.
        std::fs::write(sk.join("SKILL.md"), "---\nname: notes\n---\nbody\n").unwrap();
        assert!(run(&c, &a(&["publish", "notes", "--to", "clawhub"])).unwrap_err().contains("must have a 'description'"));
        // A snapshot entry with no identifier is skipped, not installed from "".
        let snap = d.join("s.json");
        std::fs::write(&snap, json!({"skills": [{"name": "ghost", "identifier": ""}]}).to_string()).unwrap();
        let out = run(&c, &a(&["snapshot", "import", snap.to_str().unwrap()])).unwrap();
        assert!(out.contains("skipped entry with no identifier: ghost"), "{out}");
        let _ = std::fs::remove_dir_all(&d);
    }
}
