//! `ark teams …` (Hermes `plugins/teams_pipeline/cli.py`, MIT) — the operator CLI for the Teams
//! meeting pipeline: list/inspect/replay jobs, dry-run meeting artifact resolution, and maintain
//! the Microsoft Graph subscriptions. Upstream exposes no model tools for this plugin, so the CLI
//! (plus `[meetings.teams]`) is the whole surface.

use super::graph::Client;
use super::models::{iso_z, now_secs};
use super::pipeline::{compact_job, Pipeline, PipelineConfig};
use super::store::Store;
use super::{client_for, store_path, TeamsConfig};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const SUBCOMMANDS: [(&str, &str); 12] = [
    ("list", "List recent Teams pipeline jobs"),
    ("show", "Show a stored Teams pipeline job"),
    ("run", "Replay a stored Teams pipeline job"),
    ("fetch", "Dry-run meeting artifact resolution"),
    ("subscriptions", "List Graph subscriptions"),
    ("subscribe", "Create a Microsoft Graph subscription"),
    ("renew-subscription", "Renew a Microsoft Graph subscription"),
    ("delete-subscription", "Delete a Microsoft Graph subscription"),
    ("maintain-subscriptions", "Renew near-expiry managed subscriptions"),
    ("token-health", "Inspect Graph token health"),
    ("validate", "Validate Teams pipeline configuration snapshot"),
    ("help", "This list"),
];

/// `--flag value`, `--flag=value` and bare `--flag` in one tiny parser (no clap here).
#[derive(Debug, Default)]
pub struct A {
    pub pos: Vec<String>,
    pub flags: BTreeMap<String, String>,
}

impl A {
    pub fn parse(argv: &[String]) -> A {
        let mut a = A::default();
        let mut i = 0;
        while i < argv.len() {
            let t = &argv[i];
            if let Some(rest) = t.strip_prefix("--") {
                if let Some((k, v)) = rest.split_once('=') {
                    a.flags.insert(k.to_string(), v.to_string());
                } else if argv.get(i + 1).is_some_and(|n| !n.starts_with("--")) {
                    a.flags.insert(rest.to_string(), argv[i + 1].clone());
                    i += 1;
                } else {
                    a.flags.insert(rest.to_string(), String::new());
                }
            } else {
                a.pos.push(t.clone());
            }
            i += 1;
        }
        a
    }
    /// Flag value ("" when absent).
    pub fn text(&self, key: &str) -> String {
        self.flags.get(key).map(|s| s.trim().to_string()).unwrap_or_default()
    }
    pub fn opt(&self, key: &str) -> Option<String> {
        Some(self.text(key)).filter(|s| !s.is_empty())
    }
    pub fn int(&self, key: &str, default: i64) -> i64 {
        self.text(key).parse().unwrap_or(default)
    }
    pub fn has(&self, key: &str) -> bool {
        self.flags.contains_key(key)
    }
}

fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

/// One printed record: its title and its `(label, value, required)` rows.
type Record<'a> = (String, Vec<(&'a str, Value, bool)>);

/// Bulleted records (upstream `_print_records`).
fn print_records(noun: &str, empty: &str, records: Vec<Record>) {
    if records.is_empty() {
        println!("{empty}");
        return;
    }
    println!("\n{} {noun}:\n", records.len());
    for (title, fields) in records {
        println!("  ◆ {title}");
        for (label, value, required) in fields {
            let shown = match &value {
                Value::Null => String::new(),
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            if required || !shown.is_empty() {
                println!("    {label}: {shown}");
            }
        }
        println!();
    }
}

/// Upstream `_graph_setup_hint`, pointed at ark's config file.
fn graph_setup_hint(paths: &ark_kernel::config::Paths) -> String {
    format!(
        "  Microsoft Graph is not configured. Add these to {}:\n\n    [meetings.teams]\n    tenant_id = \"...\"\n    client_id = \"...\"\n    client_secret = \"{{{{secret:MSGRAPH_CLIENT_SECRET}}}}\"\n\n  (or set MSGRAPH_TENANT_ID / MSGRAPH_CLIENT_ID / MSGRAPH_CLIENT_SECRET) and rerun this command.",
        paths.user_config().display()
    )
}

/// Graph only emits "created" for the artifact/callRecord collection resources; meetings use
/// "updated".
const CREATED_RESOURCE_PREFIXES: [&str; 3] = ["communications/onlinemeetings/getalltranscripts", "communications/onlinemeetings/getallrecordings", "communications/callrecords"];

pub fn default_change_type_for_resource(resource: &str) -> &'static str {
    let r = resource.trim().to_lowercase();
    if CREATED_RESOURCE_PREFIXES.iter().any(|p| r.starts_with(p)) {
        "created"
    } else {
        "updated"
    }
}

pub fn usage() -> String {
    let subs: Vec<&str> = SUBCOMMANDS.iter().map(|(n, _)| *n).collect();
    format!("usage: ark teams {{{}}} [options]   (see `ark teams help`)", subs.join("|"))
}

/// Dispatch `ark teams <sub> …`; `Err` carries the message the binary prints (Graph setup gets
/// upstream's hint appended).
pub fn run(cfg: &TeamsConfig, paths: &ark_kernel::config::Paths, argv: &[String]) -> Result<i32, String> {
    let a = A::parse(argv);
    let sub = a.pos.first().map(String::as_str).unwrap_or("");
    let graph = || -> Result<Client, String> {
        client_for(cfg).map_err(|e| format!("{}\n{}", e.message, graph_setup_hint(paths)))
    };
    let store = || -> Result<Store, String> { Store::open(&store_path(cfg)) };
    match sub {
        "help" | "--help" | "-h" | "" => {
            println!("{}", usage());
            for (name, help) in SUBCOMMANDS {
                println!("  {name:<22} {help}");
            }
            Ok(0)
        }
        "list" | "ls" => {
            let store = store()?;
            let status = a.text("status").to_lowercase();
            let mut jobs: Vec<Value> = store.list_jobs().into_values().filter(|j| status.is_empty() || j.get("status").and_then(Value::as_str).map(str::to_lowercase) == Some(status.clone())).collect();
            jobs.sort_by_key(|j| std::cmp::Reverse(j.get("updated_at").and_then(Value::as_str).unwrap_or("").to_string()));
            jobs.truncate(a.int("limit", 20).clamp(1, 100) as usize);
            if a.has("json") {
                print_json(&Value::Array(jobs));
                return Ok(0);
            }
            let records = jobs
                .iter()
                .map(|j| {
                    (
                        j.get("job_id").and_then(Value::as_str).unwrap_or("unknown").to_string(),
                        vec![
                            ("status", j.get("status").cloned().unwrap_or(Value::Null), true),
                            ("meeting", j.get("meeting_ref").and_then(|m| m.get("meeting_id")).cloned().unwrap_or(json!("unknown")), true),
                            ("strategy", j.get("selected_artifact_strategy").cloned().unwrap_or(Value::Null), false),
                            ("updated", j.get("updated_at").cloned().unwrap_or(Value::Null), false),
                            ("error", j.get("error_info").cloned().filter(|e| e.as_object().map(|o| !o.is_empty()).unwrap_or(false)).unwrap_or(Value::Null), false),
                        ],
                    )
                })
                .collect();
            print_records("Teams pipeline job(s)", "No Teams meeting pipeline jobs found.", records);
            Ok(0)
        }
        "show" => {
            let id = a.pos.get(1).cloned().unwrap_or_default();
            if id.is_empty() {
                println!("job_id is required");
                return Ok(0);
            }
            let store = store()?;
            match store.get_job(&id) {
                Some(job) => {
                    print_json(&compact_job(&job));
                    Ok(0)
                }
                None => {
                    println!("Unknown job: {id}");
                    Ok(0)
                }
            }
        }
        "run" | "replay" => {
            let id = a.pos.get(1).cloned().unwrap_or_default();
            if id.is_empty() {
                println!("job_id is required");
                return Ok(0);
            }
            let store = store()?;
            let client = std::sync::Arc::new(graph()?);
            let pipeline_cfg = PipelineConfig::from_table(&cfg.pipeline_table);
            let p = Pipeline::new(client.clone(), store, pipeline_cfg.clone());
            // `ark teams run` delivers the summary too (incoming webhook / Graph chat).
            let mut p = super::deliver::install(p, &pipeline_cfg, &Default::default(), paths, client);
            let job = p.run_job(&id)?;
            print_json(&compact_job(&job.to_value()));
            Ok(0)
        }
        "fetch" | "test" => {
            let meeting_id = a.opt("meeting-id");
            let join = a.opt("join-web-url");
            if meeting_id.is_none() && join.is_none() {
                println!("meeting_id or join_web_url is required");
                return Ok(0);
            }
            let c = graph()?;
            let r = super::meetings::resolve_meeting_reference(&c, meeting_id.as_deref(), join.as_deref(), a.opt("tenant-id").as_deref(), a.opt("organizer-user-id").as_deref()).map_err(|e| e.message().to_string())?;
            let (artifact, text) = super::meetings::fetch_preferred_transcript_text(&c, &r).map_err(|e| e.message().to_string())?;
            let recordings = super::meetings::list_recording_artifacts(&c, &r).map_err(|e| e.message().to_string())?;
            let call_record = super::meetings::enrich_meeting_with_call_record(&c, &r, a.opt("call-record-id").as_deref()).map_err(|e| e.message().to_string())?;
            print_json(&json!({
                "meeting_ref": r.to_value(),
                "transcript_available": artifact.is_some() && text.is_some(),
                "transcript_artifact": artifact.as_ref().map(|a| a.to_value()),
                "transcript_preview": text.map(|t| t.chars().take(240).collect::<String>()),
                "recording_count": recordings.len(),
                "recordings": recordings.iter().take(5).map(|r| r.to_value()).collect::<Vec<_>>(),
                "call_record": call_record.map(|c| c.to_value()),
            }));
            Ok(0)
        }
        "subscriptions" | "subs" => {
            let c = graph()?;
            let mut store = store()?;
            let subs = c.collect_paginated("/subscriptions", &[]).map_err(|e| e.message)?;
            for s in &subs {
                let _ = super::subs::sync_graph_subscription_record(&mut store, s, Some("active"), false);
            }
            if a.has("json") {
                print_json(&Value::Array(subs));
                return Ok(0);
            }
            let records = subs
                .iter()
                .map(|s| {
                    (
                        s.get("id").and_then(Value::as_str).unwrap_or("unknown").to_string(),
                        vec![
                            ("resource", s.get("resource").cloned().unwrap_or(json!("unknown")), true),
                            ("changeType", s.get("changeType").cloned().unwrap_or(json!("unknown")), true),
                            ("expires", s.get("expirationDateTime").cloned().unwrap_or(Value::Null), false),
                            ("notify", s.get("notificationUrl").cloned().unwrap_or(Value::Null), false),
                        ],
                    )
                })
                .collect();
            print_records("Microsoft Graph subscription(s)", "No Microsoft Graph subscriptions found.", records);
            Ok(0)
        }
        "subscribe" => {
            let resource = a.text("resource");
            let notification_url = a.text("notification-url");
            if resource.is_empty() || notification_url.is_empty() {
                println!("--resource and --notification-url are required");
                return Ok(2);
            }
            let c = graph()?;
            let mut store = store()?;
            let mut body = json!({
                "changeType": a.opt("change-type").unwrap_or_else(|| default_change_type_for_resource(&resource).to_string()),
                "notificationUrl": notification_url,
                "resource": resource,
                "expirationDateTime": a.opt("expiration").unwrap_or_else(|| iso_z(now_secs() + 3600)),
                "latestSupportedTlsVersion": a.opt("latest-supported-tls-version").unwrap_or_else(|| "v1_2".into()),
            });
            if let Some(s) = a.opt("client-state") {
                body["clientState"] = json!(s);
            }
            if let Some(u) = a.opt("lifecycle-notification-url") {
                body["lifecycleNotificationUrl"] = json!(u);
            }
            let created = c.post_json("/subscriptions", &body).map_err(|e| e.message)?;
            let _ = super::subs::sync_graph_subscription_record(&mut store, &created, Some("active"), false);
            print_json(&created);
            Ok(0)
        }
        "renew-subscription" => {
            let id = a.pos.get(1).cloned().unwrap_or_default();
            let expiration = a.text("expiration");
            if id.is_empty() || expiration.is_empty() {
                println!("subscription_id and --expiration are required");
                return Ok(0);
            }
            let c = graph()?;
            let mut store = store()?;
            let patched = c.patch_json(&format!("/subscriptions/{}", super::graph_path(&id)), &json!({"expirationDateTime": expiration})).map_err(|e| e.message)?;
            let mut merged = json!({"id": id, "expirationDateTime": expiration});
            if let (Some(dst), Some(src)) = (merged.as_object_mut(), patched.as_object()) {
                for (k, v) in src {
                    dst.insert(k.clone(), v.clone());
                }
            }
            let _ = super::subs::sync_graph_subscription_record(&mut store, &merged, Some("active"), true);
            print_json(&merged);
            Ok(0)
        }
        "delete-subscription" => {
            let id = a.pos.get(1).cloned().unwrap_or_default();
            if id.is_empty() {
                println!("subscription_id is required");
                return Ok(0);
            }
            let c = graph()?;
            let mut store = store()?;
            let result = c.delete(&format!("/subscriptions/{}", super::graph_path(&id))).map_err(|e| e.message)?;
            let deleted = store.delete_subscription(&id)?;
            print_json(&json!({"subscription_id": id, "result": result, "removed_from_store": deleted}));
            Ok(0)
        }
        "maintain-subscriptions" => {
            let c = graph()?;
            let mut store = store()?;
            let out = super::subs::maintain_graph_subscriptions(&c, &mut store, a.int("renew-within-hours", 24), a.int("extend-hours", 24), a.has("dry-run"), a.opt("client-state").as_deref())?;
            print_json(&out);
            Ok(0)
        }
        "token-health" => {
            let c = graph()?;
            let mut payload = c.token_health();
            if a.has("force-refresh") {
                match c.tokens.access_token(true) {
                    Ok(t) => {
                        payload["last_refresh_succeeded"] = json!(true);
                        payload["access_token_length"] = json!(t.len());
                    }
                    Err(e) => {
                        payload["last_refresh_succeeded"] = json!(false);
                        payload["refresh_error"] = json!(e.message);
                    }
                }
            }
            print_json(&payload);
            Ok(0)
        }
        "validate" => {
            let store = store()?;
            let mut issues: Vec<String> = Vec::new();
            let mut warnings: Vec<String> = Vec::new();
            let graph_cfg = match client_for(cfg) {
                Ok(_) => {
                    json!({"tenant_id": true, "client_id": true, "client_secret": true})
                }
                Err(_) => {
                    issues.push("Microsoft Graph app-only credentials are incomplete.".into());
                    json!({"tenant_id": false, "client_id": false, "client_secret": false})
                }
            };
            if cfg.pipeline_table.get("teams_delivery").is_some() || cfg.pipeline_table.get("teamsDelivery").is_some() {
                warnings.push("Teams outbound delivery needs the Teams channel adapter ([channels.teams]).".into());
            }
            print_json(&json!({
                "ok": issues.is_empty(),
                "issues": issues,
                "warnings": warnings,
                "graph_config": graph_cfg,
                "store_path": store.path.display().to_string(),
                "store_stats": store.stats(),
            }));
            Ok(0)
        }
        other => {
            println!("Unknown teams action: {other}\n{}", usage());
            Ok(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arg_parser_handles_equals_bools_and_positionals() {
        let a = A::parse(&["show".into(), "j1".into(), "--store-path=/x".into(), "--dry-run".into(), "--limit".into(), "5".into()]);
        assert_eq!(a.pos, vec!["show".to_string(), "j1".to_string()]);
        assert_eq!(a.text("store-path"), "/x");
        assert!(a.has("dry-run"));
        assert_eq!(a.int("limit", 20), 5);
        assert_eq!(a.int("missing", 7), 7);
        assert_eq!(a.opt("dry-run"), None, "a bare flag has no value");
    }

    #[test]
    fn change_type_defaults_match_upstream() {
        assert_eq!(default_change_type_for_resource("communications/onlineMeetings/getAllTranscripts"), "created");
        assert_eq!(default_change_type_for_resource("communications/callRecords"), "created");
        assert_eq!(default_change_type_for_resource("/me/events"), "updated");
        assert!(usage().contains("maintain-subscriptions"));
    }
}
