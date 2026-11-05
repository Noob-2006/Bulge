//! Library CLI handlers: `seagent memory …` (Hermes hermes_cli/subcommands/memory.py setup /
//! status / off / reset, the existing seagent staging review, and OpenClaw memory-core
//! cli*.ts index / search / status / promote / rem / dreaming / backfill), `seagent journey`,
//! `seagent wiki`. Output is returned as text; errors are usage or operational failures.

use crate::{dreaming, events, index, migrate, oauth, recall, util, Host};
use seagent_tools::memory_store as store;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;

pub const USAGE: &str = "usage: seagent memory <show|add [--user] <text>|review|pending|accept <n|all>|reject <n|all>|approval [on|off|status]|setup [provider]|status [--json]|off|reset [--target all|memory|user] --yes|index [--force]|search <query> [--max N] [--corpus memory|sessions]|promote [--apply]|promote-explain <query>|rem-harness|rem|dreaming [status|on|off|run [phase]]|backfill sessions [--from D] [--to D] [--apply]|events [--limit N]|migrate-hermes <hermes_home>|honcho-host <old> <new>|oauth <provider> [--authorize-url U] [--token-url U] [--client-id ID] [--scope S] [--port N]|oauth-status <provider> [--json]|query <method> [json]|wiki [init|status|compile|ingest|lint|search|get|apply]>";

/// Provider override written by `memory setup <p>` / `memory off` (wins over `[memory] provider`).
pub fn provider_override(data: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(data.join("memory/provider.override")).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn staged(h: &Host) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(store::staging_dir(&h.data)).map(|r| r.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "json")).collect()).unwrap_or_default();
    v.sort();
    v
}

fn flag_val<'a>(args: &'a [String], f: &str) -> Option<&'a str> {
    args.iter().position(|a| a == f).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn positional(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut skip = false;
    for a in args {
        if skip {
            skip = false;
            continue;
        }
        if matches!(a.as_str(), "--max" | "--target" | "--from" | "--to" | "--limit" | "--corpus" | "--reveal" | "-w" | "--workspace") {
            skip = true;
            continue;
        }
        // Any other switch (`--json`, a `-w` value already skipped) is not a positional.
        if !a.starts_with('-') {
            out.push(a.clone());
        }
    }
    out
}

/// Provider-specific `SEAGENT_OAUTH_<PROVIDER>_*` first, then the generic `SEAGENT_OAUTH_*`.
fn oauth_env(provider: &str, name: &str) -> Option<String> {
    let key = provider.to_ascii_uppercase().replace(['-', '.'], "_");
    std::env::var(format!("SEAGENT_OAUTH_{key}_{name}"))
        .or_else(|_| std::env::var(format!("SEAGENT_OAUTH_{name}")))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// `OAuthConfig` for `memory oauth <provider>`: flags win over `SEAGENT_OAUTH_*`, over the default
/// (empty URLs / client id, port 0 = any free port). No provider ships a built-in endpoint, so
/// an empty config is reported as "does not support OAuth connect" by `oauth::start`.
fn oauth_config(args: &[String], provider: &str) -> oauth::OAuthConfig {
    let d = oauth::OAuthConfig::default();
    let pick = |flag: &str, name: &str, cur: String| flag_val(args, flag).map(str::to_string).or_else(|| oauth_env(provider, name)).unwrap_or(cur);
    oauth::OAuthConfig {
        authorize_url: pick("--authorize-url", "AUTHORIZE_URL", d.authorize_url),
        token_url: pick("--token-url", "TOKEN_URL", d.token_url),
        client_id: pick("--client-id", "CLIENT_ID", d.client_id),
        scope: pick("--scope", "SCOPE", d.scope),
        port: flag_val(args, "--port").and_then(|s| s.parse().ok()).or_else(|| oauth_env(provider, "PORT").and_then(|s| s.parse().ok())).unwrap_or(d.port),
        timeout_secs: oauth_env(provider, "TIMEOUT_SECS").and_then(|s| s.parse().ok()).unwrap_or(d.timeout_secs),
    }
}

/// One-line human summary of a `oauth::status` object (never the token itself).
fn oauth_summary(provider: &str, v: &Value) -> String {
    match v["status"].as_str().unwrap_or("unknown") {
        "connected" => format!("{provider}: connected (access token stored)"),
        "pending" => format!("{provider}: authorization pending; open {}", v["authorize_url"].as_str().unwrap_or("the authorize URL")),
        "error" => format!("{provider}: error: {}", v["error"].as_str().unwrap_or("unknown error")),
        s => format!("{provider}: {s} (no stored token)"),
    }
}

pub fn run(h: &Arc<Host>, argv: &[String]) -> Result<String, String> {
    run_with(h, argv, &[], &[])
}

/// `plugins`: installed plugin names (for `memory status`); `skill_roots` for `journey`.
pub fn run_with(h: &Arc<Host>, argv: &[String], plugins: &[String], skill_roots: &[(String, PathBuf)]) -> Result<String, String> {
    let verb = argv.first().map(String::as_str).unwrap_or("memory");
    let args = argv.get(1..).unwrap_or(&[]).to_vec();
    match verb {
        "journey" | "learning" | "memory-graph" => crate::journey::run(h, &args, skill_roots),
        "wiki" => crate::wiki::cli(h, &args),
        "index" => index_cmd(h, &args, None),
        _ => memory(h, &args, plugins),
    }
}

pub const INDEX_USAGE: &str = "usage: seagent index <status [--json]|sync|rebuild|bench <session> [--json]>";

/// `seagent index …`: the SQLite index (`<data>/index.db`). It is derived from the JSONL session
/// logs, the memory ledger and the memory files, so `rebuild` is always safe.
/// `cfg` (the kernel config) is needed by `bench` only.
pub fn index_cmd(h: &Arc<Host>, args: &[String], cfg: Option<&seagent_kernel::config::Config>) -> Result<String, String> {
    use seagent_kernel::sqlindex;
    let pos = positional(args);
    let json_out = args.iter().any(|a| a == "--json");
    let sessions = h.data.join("sessions");
    let sync_all = |h: &Arc<Host>| -> Result<String, String> {
        let s = sqlindex::sync_sessions(&h.data, &sessions)?;
        crate::memstore::sync(&h.data)?;
        let r = h.sync();
        let mut out = format!("sessions: {} ({} new message(s), {} tool result(s), {} removed); memory files: {} ({} changed, {} chunk(s), {} embedded)", s.sessions, s.messages, s.tool_results, s.removed, r.files, r.changed, r.chunks, r.embedded);
        for w in r.warnings {
            out.push_str(&format!("\nwarning: {w}"));
        }
        Ok(out)
    };
    match pos.first().map(String::as_str).unwrap_or("status") {
        "status" => {
            let counts = sqlindex::counts(&h.data)?;
            let trust = crate::memstore::trust_counts(&h.data);
            let size = std::fs::metadata(sqlindex::path(&h.data)).map(|m| m.len()).unwrap_or(0);
            if json_out {
                let c: serde_json::Map<String, Value> = counts.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
                let t: serde_json::Map<String, Value> = trust.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
                return Ok(serde_json::to_string_pretty(&json!({"path": sqlindex::path(&h.data), "schema_version": sqlindex::SCHEMA_VERSION, "bytes": size, "rows": c, "memories_by_trust": t})).unwrap_or_default());
            }
            let mut out = vec![format!("index: {} ({} bytes, schema v{}) — derived from sessions/*/events.jsonl, memory/memories.jsonl and memory/*.md; `seagent index rebuild` regenerates it", sqlindex::path(&h.data).display(), size, sqlindex::SCHEMA_VERSION)];
            out.extend(counts.iter().map(|(k, v)| format!("  {k}: {v}")));
            if !trust.is_empty() {
                out.push(format!("  memories by trust: {}", trust.iter().map(|(k, v)| format!("{k} {v}")).collect::<Vec<_>>().join(", ")));
            }
            Ok(out.join("\n"))
        }
        "sync" => sync_all(h),
        "rebuild" => {
            sqlindex::clear(&h.data)?;
            h.reset_index()?;
            Ok(format!("index cleared and rebuilt from the source files\n{}", sync_all(h)?))
        }
        "bench" => {
            let id = pos.get(1).ok_or("usage: seagent index bench <session>")?;
            let cfg = cfg.cloned().unwrap_or_default();
            let store = seagent_kernel::store::Store::new(&sessions);
            let events = store.read(id).map_err(|e| e.to_string())?;
            let b = seagent_kernel::ctxbench::replay(&events, &cfg);
            if json_out {
                return Ok(serde_json::to_string_pretty(&json!({"session": id, "requests": b.requests, "avg_raw": b.avg_raw, "avg_trimmed": b.avg_trimmed, "max_raw": b.max_raw, "max_trimmed": b.max_trimmed, "total_raw": b.total_raw, "total_trimmed": b.total_trimmed, "saved_pct": b.saved_pct(), "max_tool_result_chars": cfg.compaction.max_tool_result_chars, "keep_tool_results": cfg.compaction.keep_tool_results})).unwrap_or_default());
            }
            Ok(format!("session {id} (estimated input tokens per request, system + conversation; [compaction] max_tool_result_chars = {}, keep_tool_results = {})\n{}", cfg.compaction.max_tool_result_chars, cfg.compaction.keep_tool_results, b.render()))
        }
        other => Err(format!("unknown `index {other}`\n{INDEX_USAGE}")),
    }
}

fn memory(h: &Arc<Host>, args: &[String], plugins: &[String]) -> Result<String, String> {
    let pos = positional(args);
    let flag = |f: &str| args.iter().any(|a| a == f);
    let sub = pos.first().map(String::as_str).unwrap_or("show");
    let rest = pos.get(1..).unwrap_or(&[]).join(" ");
    match sub {
        "show" => {
            let mut out = Vec::new();
            for f in ["USER.md", "MEMORY.md"] {
                let s = std::fs::read_to_string(h.memory_dir().join(f)).unwrap_or_default();
                out.push(format!("── {f} ──\n{}\n", if s.trim().is_empty() { "(empty)" } else { s.trim() }));
            }
            Ok(out.join("\n"))
        }
        "add" => {
            if rest.trim().is_empty() {
                return Err("missing <text>".into());
            }
            store::apply_batch(&h.data, if flag("--user") { "user" } else { "memory" }, &[json!({"action": "add", "text": rest.trim()})]).map(|_| "saved".into())
        }
        "review" | "pending" => {
            let files = staged(h);
            if files.is_empty() {
                return Ok("no staged suggestions".into());
            }
            let mut out = Vec::new();
            for (i, f) in files.iter().enumerate() {
                let v = util::read_json(f).unwrap_or(Value::Null);
                out.push(format!("[{}] from session {}", i + 1, v["session"].as_str().unwrap_or("?")));
                for k in ["memory", "user"] {
                    for e in v[k].as_array().cloned().unwrap_or_default() {
                        out.push(format!("    {k}: {}", e.as_str().unwrap_or("")));
                    }
                }
                if let Some(o) = v.get("ops") {
                    for op in o["operations"].as_array().cloned().unwrap_or_default() {
                        out.push(format!("    {} {}: {}{}", o["file"].as_str().unwrap_or("memory"), op["action"].as_str().unwrap_or("?"), op["text"].as_str().unwrap_or(""), op["old"].as_str().map(|x| format!(" (entry matching `{x}`)")).unwrap_or_default()));
                    }
                }
            }
            Ok(out.join("\n"))
        }
        s @ ("accept" | "approve" | "reject" | "discard") => {
            let which = pos.get(1).ok_or("missing <n|all>")?;
            let files = staged(h);
            let pick: Vec<PathBuf> = if which == "all" {
                files
            } else {
                let n: usize = which.parse().map_err(|_| format!("`{which}` is not a number"))?;
                vec![files.get(n.wrapping_sub(1)).cloned().ok_or("no such suggestion")?]
            };
            let accept = s == "accept" || s == "approve";
            let mut notes = Vec::new();
            for f in &pick {
                if accept {
                    let v = util::read_json(f).ok_or_else(|| format!("{}: unreadable", f.display()))?;
                    match store::apply_staged(&h.data, &v) {
                        Ok(n) => notes.push(n),
                        Err(e) => return Err(format!("{}: {e} (the pending record was kept)", f.display())),
                    }
                }
                std::fs::remove_file(f).map_err(|e| e.to_string())?;
            }
            Ok(format!("{}ed {}", if accept { "accept" } else { "reject" }, pick.len()))
        }
        "approval" => {
            let p = h.memory_dir().join("write-approval");
            match pos.get(1).map(String::as_str).unwrap_or("status") {
                v @ ("on" | "off") => {
                    util::write_atomic(&p, v.as_bytes())?;
                    Ok(format!("memory write approval {}", if v == "on" { "on: agent memory writes are staged for review" } else { "off" }))
                }
                _ => Ok(format!("memory write approval: {} ({} pending)", if store::write_approval_enabled(&h.data) { "on" } else { "off" }, staged(h).len())),
            }
        }
        "setup" => {
            let p = pos.get(1).map(String::as_str).unwrap_or("");
            let guide = "Bundled providers: byterover (brv CLI), retaindb (RETAINDB_API_KEY).\nCatalog providers (honcho, hindsight, supermemory, mem0, openviking, holographic): install the plugin, then `seagent memory setup <name>`.\nOnly one external provider can be active at a time. Built-in memory (MEMORY.md/USER.md) is always active.";
            if p.is_empty() {
                return Ok(guide.into());
            }
            if !p.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c)) {
                return Err(format!("invalid provider name `{p}`"));
            }
            let check = match p {
                "byterover" => {
                    let b = crate::byterover::Byterover::new(h);
                    match &b.binary {
                        Some(bin) => format!("brv found at {}", bin.display()),
                        None => "warning: brv CLI not found. Install: npm install -g byterover-cli".into(),
                    }
                }
                "retaindb" => match crate::retaindb::RetainDb::new(h) {
                    Ok(r) => format!("RetainDB endpoint {} (project {})", r.base_url, r.project),
                    Err(e) => format!("warning: {e}"),
                },
                other => match migrate::check_provider(&h.data, other, plugins) {
                    migrate::ProviderState::Missing { message, .. } => format!("warning: {message}"),
                    _ => format!("plugin `{other}` is installed"),
                },
            };
            util::write_atomic(&h.memory_dir().join("provider.override"), p.as_bytes())?;
            Ok(format!("memory provider set to `{p}` (takes effect on the next start; or set [memory] provider = \"{p}\").\n{check}"))
        }
        "off" => {
            util::write_atomic(&h.memory_dir().join("provider.override"), b"builtin")?;
            Ok("external memory provider disabled (built-in MEMORY.md/USER.md only); takes effect on the next start".into())
        }
        "status" => {
            let mut st = h.status();
            let prov = provider_override(&h.data).unwrap_or_else(|| h.settings.provider.clone());
            st["provider"] = json!(if prov.is_empty() { "builtin".to_string() } else { prov.clone() });
            st["providerState"] = json!(format!("{:?}", migrate::check_provider(&h.data, &prov, plugins)));
            st["pending"] = json!(staged(h).len());
            st["writeApproval"] = json!(store::write_approval_enabled(&h.data));
            st["dreaming"] = dreaming::status_json(h);
            st["shortTerm"] = json!(recall::Store::load(&h.data).entries.len());
            let _ = crate::memstore::sync(&h.data);
            let trust: serde_json::Map<String, Value> = crate::memstore::trust_counts(&h.data).into_iter().map(|(k, v)| (k, json!(v))).collect();
            st["memoriesByTrust"] = Value::Object(trust);
            if flag("--json") {
                return Ok(serde_json::to_string_pretty(&st).unwrap_or_default());
            }
            let mut out = vec![
                format!("provider: {} ({})", st["provider"].as_str().unwrap_or(""), st["providerState"].as_str().unwrap_or("")),
                format!("embedding: {}", st["embedding"].as_str().unwrap_or("")),
                format!("index: {} file(s), {} chunk(s), {} vector(s); sources {}", st["files"], st["chunks"], st["vectors"], st["sources"]),
                format!("MEMORY.md {}/{} chars, USER.md {}/{} chars", std::fs::read_to_string(h.memory_dir().join("MEMORY.md")).map(|s| s.chars().count()).unwrap_or(0), store::cap_of("memory"), std::fs::read_to_string(h.memory_dir().join("USER.md")).map(|s| s.chars().count()).unwrap_or(0), store::cap_of("user")),
                format!("write approval: {} ({} pending)", if store::write_approval_enabled(&h.data) { "on" } else { "off" }, st["pending"]),
                format!("dreaming: {}", if st["dreaming"]["enabled"] == true { "on" } else { "off" }),
                format!("long-term memories by trust: {}", st["memoriesByTrust"].as_object().map(|m| if m.is_empty() { "none".to_string() } else { m.iter().map(|(k, v)| format!("{k} {v}")).collect::<Vec<_>>().join(", ") }).unwrap_or_default()),
            ];
            if let Some(e) = st["embeddingError"].as_str() {
                out.push(format!("embedding error: {e}"));
            }
            for w in st["warnings"].as_array().cloned().unwrap_or_default() {
                out.push(format!("warning: {}", w.as_str().unwrap_or("")));
            }
            Ok(out.join("\n"))
        }
        "reset" => {
            let target = flag_val(args, "--target").unwrap_or("all");
            let files: Vec<&str> = match target {
                "all" => vec!["MEMORY.md", "USER.md"],
                "memory" => vec!["MEMORY.md"],
                "user" => vec!["USER.md"],
                o => return Err(format!("--target `{o}`: use all, memory or user")),
            };
            if !flag("--yes") {
                return Err(format!("this erases {}; re-run with --yes to confirm", files.join(" and ")));
            }
            for f in &files {
                let p = h.memory_dir().join(f);
                if p.exists() {
                    std::fs::remove_file(&p).map_err(|e| format!("cannot remove {}: {e}", p.display()))?;
                }
            }
            Ok(format!("erased {}", files.join(", ")))
        }
        "index" => {
            if flag("--force") {
                h.reset_index()?;
            }
            let r = h.sync();
            let mut out = format!("indexed {} file(s): {} changed, {} removed, {} chunk(s), {} embedded", r.files, r.changed, r.removed, r.chunks, r.embedded);
            for w in r.warnings {
                out.push_str(&format!("\nwarning: {w}"));
            }
            Ok(out)
        }
        "search" => {
            if rest.trim().is_empty() {
                return Err("usage: seagent memory search <query>".into());
            }
            let max = flag_val(args, "--max").and_then(|s| s.parse().ok()).unwrap_or(h.settings.search.max_results);
            let sources: Vec<&str> = flag_val(args, "--corpus").map(|c| vec![c]).unwrap_or_default();
            let o = h.search(&rest, max, h.settings.search.min_score, &sources)?;
            if o.hits.is_empty() {
                return Ok(format!("no results ({})", o.mode));
            }
            Ok(o.hits.iter().map(|x| format!("{:.3}  {}\n    {}", x.score, x.citation(), util::clip(&util::compact_ws(&x.snippet), 200))).collect::<Vec<_>>().join("\n"))
        }
        "promote" => {
            let st = recall::Store::load(&h.data);
            let c = dreaming::rank(h, &st, util::now_ms(), false);
            if flag("--apply") {
                return dreaming::run(h, Some("deep"), util::now_ms());
            }
            if c.is_empty() {
                return Ok("no short-term candidates meet the promotion policy".into());
            }
            Ok(c.iter().map(|c| format!("{:.3}  {}:{}-{}  recalls={} queries={}\n    {}", c.score, c.entry.path, c.entry.start_line, c.entry.end_line, c.entry.recall_count, c.entry.query_hashes.len(), util::clip(&c.entry.snippet, 160))).collect::<Vec<_>>().join("\n"))
        }
        "promote-explain" => {
            let st = recall::Store::load(&h.data);
            let q = rest.to_lowercase();
            let ranked = dreaming::rank(h, &st, util::now_ms(), true);
            let d = &h.settings.dreaming.deep;
            let hits: Vec<String> = st
                .entries
                .values()
                .filter(|e| e.snippet.to_lowercase().contains(&q) || e.path.contains(&q))
                .map(|e| {
                    let r = ranked.iter().find(|c| c.key == e.key);
                    let why = match r {
                        Some(c) => format!("eligible (score {:.3})", c.score),
                        None if e.signals() < d.min_recall_count => format!("signal threshold ({} < {})", e.signals(), d.min_recall_count),
                        None if e.query_hashes.len() < d.min_unique_queries => format!("query threshold ({} < {})", e.query_hashes.len(), d.min_unique_queries),
                        None => format!("score threshold (< {})", d.min_score),
                    };
                    format!("{}  recalls={} daily={} queries={} days={} avg={:.3}{}\n    {why}", e.key, e.recall_count, e.daily_count, e.query_hashes.len(), e.recall_days.len(), e.avg_score(), if e.promoted_ms.is_some() { " (already promoted)" } else { "" })
                })
                .collect();
            Ok(if hits.is_empty() { format!("no short-term entry matches `{rest}`") } else { hits.join("\n") })
        }
        "rem-harness" => {
            let st = recall::Store::load(&h.data);
            let c = dreaming::rank(h, &st, util::now_ms(), false);
            Ok(serde_json::to_string_pretty(&json!({"shortTermEntries": st.entries.len(), "deepCandidates": c.iter().map(|c| json!({"key": c.key, "score": c.score, "snippet": c.entry.snippet})).collect::<Vec<_>>()})).unwrap_or_default())
        }
        "rem" => dreaming::run(h, Some("rem"), util::now_ms()),
        "dreaming" => dreaming::command(h, &pos.get(1..).unwrap_or(&[]).join(" ")),
        "backfill" => backfill(h, args),
        "events" => {
            let limit = flag_val(args, "--limit").and_then(|s| s.parse().ok()).unwrap_or(20);
            let all = events::list(&h.data, &[], None, usize::MAX);
            Ok(all.iter().rev().take(limit).rev().map(|(_, v)| v.to_string()).collect::<Vec<_>>().join("\n"))
        }
        // `seagent memory wiki` - the compiled wiki vault (same verbs as `seagent wiki`).
        "wiki" => crate::wiki::cli(h, args.get(1..).unwrap_or(&[])),
        "migrate-hermes" => migrate::import_hermes(&seagent_core::tool::expand_home(pos.get(1).ok_or("usage: seagent memory migrate-hermes <hermes_home>")?), &h.data),
        "honcho-host" => {
            let old = pos.get(1).ok_or("usage: seagent memory honcho-host <old> <new>")?;
            let new = pos.get(2).ok_or("usage: seagent memory honcho-host <old> <new>")?;
            if pos.len() > 3 {
                return Err(format!("usage: seagent memory honcho-host <old> <new> (got `{}`)\n{USAGE}", pos.join(" ")));
            }
            // The renamed profile's directory (Honcho writes `honcho.json` there), else the active
            // profile's data dir; `honcho_candidates` adds the default home and `~/.honcho/config.json`.
            let profile = std::env::var_os("SEAGENT_PROFILE_DIR").map(PathBuf::from).unwrap_or_else(|| h.data.clone());
            let default_home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
            let msgs = migrate::migrate_honcho_profile_host(old, new, &migrate::honcho_candidates(&profile, &default_home));
            Ok(if msgs.is_empty() { format!("no honcho config found (looked in {} and {})", profile.join("honcho.json").display(), default_home.join("honcho.json").display()) } else { msgs.join("\n") })
        }
        "oauth" => {
            let provider = pos.get(1).map(String::as_str).ok_or("usage: seagent memory oauth <provider>")?;
            let cfg = oauth_config(args, provider);
            let v = oauth::start(&h.data, provider, &cfg)?;
            Ok(format!(
                "waiting for the browser to authorize `{provider}`:\n  {}\nredirect URI: {}\nopen the URL, approve access, then poll `seagent memory oauth-status {provider}`; tokens are stored under {}\n{}",
                v["authorize_url"].as_str().unwrap_or(""),
                v["redirect_uri"].as_str().unwrap_or(""),
                h.data.join("memory/oauth").display(),
                oauth_summary(provider, &oauth::status(&h.data, provider))
            ))
        }
        "oauth-status" => {
            let provider = pos.get(1).map(String::as_str).ok_or("usage: seagent memory oauth-status <provider>")?;
            let st = oauth::status(&h.data, provider);
            let body = serde_json::to_string_pretty(&st).unwrap_or_default();
            if flag("--json") {
                return Ok(body);
            }
            Ok(format!("{}\n{body}", oauth_summary(provider, &st)))
        }
        "query" => {
            let method = pos.get(1).map(String::as_str).ok_or("usage: seagent memory query <method> [json]")?;
            let raw = pos.get(2..).unwrap_or(&[]).join(" ");
            let params: Value = if raw.trim().is_empty() { json!({}) } else { serde_json::from_str(&raw).map_err(|e| format!("query {method}: bad JSON params: {e}"))? };
            if !params.is_object() {
                return Err(format!("query {method}: params must be a JSON object, e.g. {{\"query\":\"nix\"}}"));
            }
            Ok(serde_json::to_string_pretty(&events::host_call(h, method, &params)?).unwrap_or_default())
        }
        other => Err(format!("unknown `memory {other}`\n{USAGE}")),
    }
}

/// Session backfill: trusted durable statements from retained session transcripts →
/// preview, or (`--apply`) staged as short-term recall signals for dreaming.
fn backfill(h: &Host, args: &[String]) -> Result<String, String> {
    let from = flag_val(args, "--from").map(|d| util::parse_day(d).ok_or(format!("bad --from date `{d}`"))).transpose()?;
    let to = flag_val(args, "--to").map(|d| util::parse_day(d).map(|t| t + 86_400_000).ok_or(format!("bad --to date `{d}`"))).transpose()?;
    let apply = args.iter().any(|a| a == "--apply");
    let s = crate::settings::SearchSettings { sources: vec!["sessions".into()], ..Default::default() };
    let mut st = recall::Store::load(&h.data);
    let mut found = Vec::new();
    for f in index::source_files(&h.data, &s) {
        let mt = std::fs::metadata(&f.abs).and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as u64).unwrap_or(0);
        if from.is_some_and(|f| mt < f) || to.is_some_and(|t| mt >= t) {
            continue;
        }
        let text = index::session_text(&std::fs::read_to_string(&f.abs).unwrap_or_default());
        for (i, l) in text.lines().enumerate() {
            if let Some(u) = l.strip_prefix("user: ") {
                if crate::vector::should_capture(u, 500, &h.settings.vector.custom_triggers) {
                    found.push((f.display.clone(), i + 1, u.to_string()));
                    if apply {
                        st.record_daily(&f.display, i + 1, i + 1, u, 0.7, mt.max(1), h.utc_offset_minutes);
                    }
                }
            }
        }
    }
    if apply {
        st.save(&h.data)?;
    }
    let mut out = vec![format!("{} candidate(s){}", found.len(), if apply { " staged into short-term memory" } else { " (preview; add --apply to stage)" })];
    out.extend(found.iter().take(50).map(|(p, l, t)| format!("  {p}#L{l}  {}", util::clip(t, 160))));
    Ok(out.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn memory_verbs() {
        let h = crate::test_host("cli", |_| {});
        assert_eq!(run(&h, &a("memory add uses nix")).unwrap(), "saved");
        run(&h, &a("memory add --user is a teacher")).unwrap();
        assert!(run(&h, &a("memory show")).unwrap().contains("is a teacher"));
        assert!(run(&h, &a("memory index")).unwrap().contains("indexed 2 file(s)"));
        assert!(run(&h, &a("memory search nix")).unwrap().contains("MEMORY.md#L1"));
        assert!(run(&h, &a("memory status")).unwrap().contains("provider: builtin"));
        assert!(run(&h, &a("memory status --json")).unwrap().contains("\"writeApproval\": false"));
        assert!(run(&h, &a("memory reset")).unwrap_err().contains("--yes"));
        assert_eq!(run(&h, &a("memory reset --target user --yes")).unwrap(), "erased USER.md");
        assert!(!h.memory_dir().join("USER.md").exists() && h.memory_dir().join("MEMORY.md").exists());
        assert!(run(&h, &a("memory setup")).unwrap().contains("Bundled providers"));
        assert!(run(&h, &a("memory setup retaindb")).unwrap().contains("warning"));
        assert_eq!(provider_override(&h.data).as_deref(), Some("retaindb"));
        run(&h, &a("memory off")).unwrap();
        assert_eq!(provider_override(&h.data).as_deref(), Some("builtin"));
        assert!(run(&h, &a("memory approval on")).unwrap().contains("staged"));
        assert!(store::write_approval_enabled(&h.data));
        assert!(run(&h, &a("memory frob")).is_err());
        assert!(run(&h, &a("memory dreaming status")).unwrap().contains("Dreaming status"));
        assert!(run(&h, &a("memory promote")).unwrap().contains("no short-term"));
    }

    #[test]
    fn review_accept_reject_staged_ops() {
        let h = crate::test_host("cli2", |_| {});
        run(&h, &a("memory add keeps notes")).unwrap();
        let dir = store::staging_dir(&h.data);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("0001.json"), r#"{"session":"s1","user":["likes jazz"]}"#).unwrap();
        std::fs::write(dir.join("0002.json"), r#"{"session":"s2","ops":{"file":"memory","operations":[{"action":"patch","old":"keeps","text":"writes","matched_entry":"keeps notes"}]}}"#).unwrap();
        std::fs::write(dir.join("0003.json"), r#"{"session":"s3","memory":["drop me"]}"#).unwrap();
        let r = run(&h, &a("memory review")).unwrap();
        assert!(r.contains("[1] from session s1") && r.contains("user: likes jazz") && r.contains("memory patch: writes (entry matching `keeps`)"));
        assert_eq!(run(&h, &a("memory reject 3")).unwrap(), "rejected 1");
        assert_eq!(run(&h, &a("memory accept all")).unwrap(), "accepted 2");
        assert_eq!(std::fs::read_to_string(h.memory_dir().join("MEMORY.md")).unwrap(), "writes notes");
        assert_eq!(std::fs::read_to_string(h.memory_dir().join("USER.md")).unwrap(), "likes jazz");
        assert_eq!(run(&h, &a("memory pending")).unwrap(), "no staged suggestions");
    }

    #[test]
    fn backfill_sessions() {
        let h = crate::test_host("cli3", |_| {});
        std::fs::create_dir_all(h.data.join("sessions/s1")).unwrap();
        std::fs::write(h.data.join("sessions/s1/events.jsonl"), r#"{"type":"message","message":{"role":"user","content":[{"type":"text","text":"Remember that I always use pnpm"}]}}"#).unwrap();
        assert!(run(&h, &a("memory backfill sessions")).unwrap().starts_with("1 candidate(s) (preview"));
        run(&h, &a("memory backfill sessions --apply")).unwrap();
        assert_eq!(recall::Store::load(&h.data).entries.len(), 1);
        assert!(run(&h, &a("memory backfill --from 2999-01-01")).unwrap().starts_with("0 candidate"));
        assert!(run(&h, &a("memory promote-explain pnpm")).unwrap().contains("signal threshold"));
    }

    #[test]
    fn oauth_verbs_report_status_and_usage() {
        let h = crate::test_host("cli-oauth", |_| {});
        // No provider config, no token: idle, and never a panic.
        let idle = run(&h, &a("memory oauth-status honcho --json")).unwrap();
        assert!(idle.contains("\"status\": \"idle\"") && !idle.contains("access_token"), "{idle}");
        assert!(run(&h, &a("memory oauth-status honcho")).unwrap().starts_with("honcho: idle (no stored token)"));
        // An invalid provider name is reported as an error status, not a crash.
        let bad = run(&h, &a("memory oauth-status ../evil --json")).unwrap();
        assert!(bad.contains("\"status\": \"error\"") && bad.contains("unknown memory provider"), "{bad}");
        assert!(!bad.contains("access_token"));
        // `oauth` validates the provider before opening a listener; nothing is stored.
        let e = run(&h, &a("memory oauth ../evil")).unwrap_err();
        assert!(e.contains("unknown memory provider"), "{e}");
        // A valid provider with no configured endpoint is an operational error, not a network call.
        let e = run(&h, &a("memory oauth honcho")).unwrap_err();
        assert!(e.contains("does not support OAuth connect"), "{e}");
        assert!(!h.data.join("memory/oauth/honcho.json").exists());
        assert!(USAGE.contains("oauth <provider>") && USAGE.contains("oauth-status <provider>"));
    }

    #[test]
    fn honcho_host_verb_rewrites_profile_configs() {
        let h = crate::test_host("cli-honcho", |_| {});
        let prof = crate::tmp("cli-profile");
        std::fs::write(prof.join("honcho.json"), r#"{"hosts":{"hermes_w2old":{"workspace":"w"},"local":{"aiPeer":"w2old"}}}"#).unwrap();
        std::env::set_var("SEAGENT_PROFILE_DIR", &prof);
        let out = run(&h, &a("memory honcho-host w2old w2new"));
        std::env::remove_var("SEAGENT_PROFILE_DIR");
        let out = out.unwrap();
        let cfg = prof.join("honcho.json");
        assert!(out.contains(&cfg.display().to_string()) && out.contains("hermes_w2new"), "{out}");
        let v = util::read_json(&cfg).unwrap();
        assert!(v["hosts"]["hermes_w2new"].is_object() && v["hosts"].get("hermes_w2old").is_none());
        assert_eq!(v["hosts"]["local"]["aiPeer"], "w2old", "peers are unchanged");
        assert!(run(&h, &a("memory honcho-host w2old w2new")).unwrap().starts_with("no honcho config found"));
        assert!(run(&h, &a("memory honcho-host only-old")).unwrap_err().contains("honcho-host <old> <new>"));
        assert!(USAGE.contains("honcho-host <old> <new>"));
    }

    #[test]
    fn query_verb_exposes_host_sdk() {
        let h = crate::test_host("cli-query", |_| {});
        let st = run(&h, &a("memory query status")).unwrap();
        assert!(st.contains("\"provider\"") && st.contains("\"files\""), "{st}");
        assert!(run(&h, &a("memory query events")).unwrap().contains("\"events\""));
        assert!(run(&h, &a(r#"memory query record {"type":"memory.write","payload":{"action":"add"}}"#)).unwrap().contains("\"ok\": true"));
        let ev = run(&h, &a("memory query events")).unwrap();
        assert!(ev.contains("memory.write"), "{ev}");
        assert!(run(&h, &a("memory query dreaming.status")).unwrap().contains("\"enabled\""));
        let e = run(&h, &a("memory query bogus")).unwrap_err();
        assert!(e.contains("unknown memory host method") && e.contains("search, get, events, status"), "{e}");
        assert!(run(&h, &a("memory query search not-json")).unwrap_err().contains("bad JSON"));
        assert!(USAGE.contains("query <method>"));
    }

    #[test]
    fn accept_replays_security_shaped_record() {
        let h = crate::test_host("cli-sec", |_| {});
        run(&h, &a("memory add keeps notes")).unwrap();
        let dir = store::staging_dir(&h.data);
        std::fs::create_dir_all(&dir).unwrap();
        // Shape 1: pure adds (seagent-security::approvals::stage_memory_writes).
        let adds = dir.join("2001.json");
        std::fs::write(&adds, r#"{"session":"sec1","origin":"foreground","created_ms":1700000000000,"memory":["staged by security"],"user":["prefers metric units"],"summary":"add 2"}"#).unwrap();
        // Shape 2: ops batch with a pinned entry.
        let ops = dir.join("2002.json");
        std::fs::write(&ops, r#"{"session":"sec2","origin":"escalation","created_ms":1700000000001,"ops":{"file":"memory","operations":[{"action":"patch","old":"keeps","text":"wrote","matched_entry":"keeps notes"}]},"summary":"patch keeps"}"#).unwrap();
        assert_eq!(run(&h, &a("memory accept all")).unwrap(), "accepted 2");
        let mem = std::fs::read_to_string(h.memory_dir().join("MEMORY.md")).unwrap();
        assert!(mem.contains("staged by security") && mem.contains("wrote notes"), "{mem}");
        assert!(std::fs::read_to_string(h.memory_dir().join("USER.md")).unwrap().contains("prefers metric units"));
        assert!(!adds.exists() && !ops.exists(), "applied staging records are removed");
        assert_eq!(run(&h, &a("memory pending")).unwrap(), "no staged suggestions");
    }
}
