//! Microsoft Teams meeting pipeline (Hermes `plugins/teams_pipeline`, MIT).
//!
//! Ingest meeting transcripts/recordings over Microsoft Graph: change notifications become
//! durable jobs ([`pipeline`]), the meeting is resolved and its transcript fetched
//! ([`meetings`]), the transcript is summarised into a stored meeting record, and the configured
//! sinks are written ([`sinks`]). [`subs`] keeps the Graph subscriptions alive; [`cli`] is
//! `ark teams …`; [`store`] is the JSON state file; [`graph`] is app-only auth + the REST client.
//! Upstream registers no model tools — the CLI is the operator surface.
//!
//! ```toml
//! [meetings.teams]
//! tenant_id = "00000000-0000-0000-0000-000000000000"
//! client_id = "…"
//! client_secret = "{{secret:MSGRAPH_CLIENT_SECRET}}"
//! # base_url / authority_url / scope / store_path optional
//! [meetings.teams.pipeline]
//! transcript_preferred = true
//! transcript_required = false
//! transcription_fallback = true      # recording → STT when no transcript is published
//! transcript_min_chars = 80
//! stt_model = ""
//! [meetings.teams.pipeline.notion]   enabled = false, database_id = "…", api_key = "{{secret:NOTION_API_KEY}}"
//! [meetings.teams.pipeline.linear]   enabled = false, team_id = "…",   api_key = "{{secret:LINEAR_API_KEY}}"
//! [meetings.teams.pipeline.teams_delivery] enabled = false, chat_id = "…"
//! ```

pub mod cli;
pub mod deliver;
pub mod graph;
pub mod meetings;
pub mod models;
pub mod pipeline;
pub mod sinks;
pub mod store;
pub mod subs;

use ark_kernel::config::{Config, Paths};
use ark_kernel::kernel::Kernel;
use ark_kernel::vault::Vault;
use graph::{Client, GraphError};
use models::Job;
use pipeline::{Pipeline, PipelineConfig};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use store::Store;

/// `[meetings.teams]` with `{{secret:…}}` placeholders already resolved.
#[derive(Debug, Clone)]
pub struct TeamsConfig {
    pub table: toml::Table,
    pub pipeline_table: toml::Table,
    /// Resolved store path (`store_path`, `MSGRAPH_WEBHOOK_STORE_PATH`, else `<data>/…`).
    pub store_path: PathBuf,
}

fn substitute(t: &mut toml::Table, vault: &Vault) {
    for (_, v) in t.iter_mut() {
        match v {
            toml::Value::String(s) => {
                if s.contains("{{secret:") {
                    if let Some(resolved) = s.split("{{secret:").nth(1).and_then(|r| r.split("}}").next()).map(|name| vault.substitute(&format!("{{{{secret:{}}}}}", name.trim()))) {
                        if !resolved.contains("{{secret:") {
                            *s = resolved;
                        }
                    }
                }
            }
            toml::Value::Table(child) => substitute(child, vault),
            toml::Value::Array(items) => {
                for item in items.iter_mut() {
                    if let toml::Value::Table(child) = item {
                        substitute(child, vault);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Read `[meetings.teams]` out of the `[meetings]` table and resolve its secrets.
pub fn config(meetings: &toml::Table, paths: &Paths) -> TeamsConfig {
    let vault = Vault::load(&paths.secrets()).unwrap_or_else(|_| Vault::empty());
    let mut table = meetings.get("teams").and_then(|v| v.as_table()).cloned().unwrap_or_default();
    substitute(&mut table, &vault);
    let mut pipeline_table = table.get("pipeline").and_then(|v| v.as_table()).cloned().unwrap_or_default();
    substitute(&mut pipeline_table, &vault);
    let explicit = table.get("store_path").and_then(|v| v.as_str()).map(str::to_string);
    let store_path = store::resolve_path(explicit.as_deref(), &paths.data);
    TeamsConfig { table, pipeline_table, store_path }
}

/// Where this config's store lives.
pub fn store_path(cfg: &TeamsConfig) -> PathBuf {
    cfg.store_path.clone()
}

/// Percent-encoded path segment for Graph ids.
pub fn graph_path(segment: &str) -> String {
    ark_tools::web::http::enc(segment.trim())
}

/// Graph client for this config; `Err` is upstream's missing-credentials message.
pub fn client_for(cfg: &TeamsConfig) -> Result<Client, GraphError> {
    // Secrets are already resolved in `config()`; `from_config` still falls back to `MSGRAPH_*`.
    let no_secret = |_: &str| None;
    Client::from_config(&cfg.table, &no_secret)
}

/// `ark teams …`.
pub fn cli(meetings: &toml::Table, paths: &Paths, argv: &[String]) -> Result<i32, String> {
    let cfg = config(meetings, paths);
    cli::run(&cfg, paths, argv)
}

/// Serialises pipeline runs: the store is one JSON document rewritten atomically, so two workers
/// writing at once would drop each other's buckets (upstream runs the pipeline on one event loop).
fn pipeline_lock() -> std::sync::MutexGuard<'static, ()> {
    static L: Mutex<()> = Mutex::new(());
    L.lock().unwrap_or_else(|e| e.into_inner())
}

/// The pipeline as the running host uses it: Graph client, store path, `[meetings.teams.pipeline]`
/// and the injected output sink. Cheap to clone; every run opens its own [`Store`].
#[derive(Clone)]
pub struct Runtime {
    pub client: Arc<Client>,
    pub store_path: PathBuf,
    pub config: PipelineConfig,
    pub sink: Option<deliver::SummarySink>,
}

impl Runtime {
    /// The pipeline for one run: the store reopened from disk, the host sink injected.
    pub fn pipeline(&self) -> Result<Pipeline, String> {
        let store = Store::open(&self.store_path)?;
        let mut p = Pipeline::new(self.client.clone(), store, self.config.clone());
        if let Some(sink) = &self.sink {
            let sink = sink.clone();
            p = p.with_sink(Box::new(move |kind, payload, cfg, existing| sink(kind, payload, cfg, existing)));
        }
        Ok(p)
    }

    /// Persist the notification as a job **before** the caller acks, then run the pipeline on a
    /// detached thread — upstream `runtime.py::_schedule`: `create_job_from_notification`, then
    /// `run_job` as a background task, so a Graph retry storm can neither lose nor repeat work.
    pub fn schedule(&self, notification: &serde_json::Value) -> Result<Job, String> {
        let job = {
            let _g = pipeline_lock();
            self.pipeline()?.create_job_from_notification(notification)?
        };
        if job.status != "received" {
            // A duplicate delivery of a running/finished job: upstream returns without scheduling.
            return Ok(job);
        }
        let (rt, id, notification) = (self.clone(), job.job_id.clone(), notification.clone());
        std::thread::Builder::new()
            .name(format!("teams-pipeline-{id}"))
            .spawn(move || {
                let _g = pipeline_lock();
                if let Err(e) = rt.handle(&notification) {
                    eprintln!("ark: teams pipeline {id}: {e}");
                }
            })
            .map_err(|e| format!("cannot start the Teams pipeline worker: {e}"))?;
        Ok(job)
    }

    /// Create and run in this thread (upstream `run_notification`): the worker body, `ark teams run`
    /// and the tests.
    pub fn handle(&self, notification: &serde_json::Value) -> Result<Job, String> {
        let mut p = self.pipeline()?;
        p.run_notification(notification)
    }
}

/// What [`install`] bound (for the startup log and for tests).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Installed {
    /// Graph change notifications now create pipeline jobs (the webhook acks once the job is stored).
    pub notifications: bool,
    /// Summaries are delivered back to Teams (msteams adapter, incoming webhook or Graph chat).
    pub teams_sink: bool,
}

/// Wire the Teams meeting pipeline into the running daemon — upstream
/// `plugins/teams_pipeline/runtime.py::bind_gateway_runtime` (called from `gateway/run.py`):
///
/// * every Microsoft Graph change notification that `ark-channel`'s `msgraph_webhook` accepts becomes
///   a durable pipeline job (`Runtime::schedule`, bound with
///   [`ark_channel::msgraph_webhook::set_notification_scheduler`]);
/// * the summary is delivered back to Teams ([`deliver::teams_sink`]).
///
/// Nothing is bound without `[meetings.teams]` and working Graph credentials: the webhook then keeps
/// its "accept, then drop" default and the CLI keeps working, so a half-configured daemon never
/// panics and Graph is never left waiting.
pub fn install(k: &Kernel, cfg: &Config) -> Installed {
    install_at(&k.paths, cfg)
}

/// [`install`] for a host that only has the paths (tests, `ark teams …`).
pub fn install_at(paths: &Paths, cfg: &Config) -> Installed {
    let mut installed = Installed::default();
    if cfg.meetings.get("teams").and_then(|v| v.as_table()).is_none() {
        return installed;
    }
    let teams = config(&cfg.meetings, paths);
    let client = match client_for(&teams) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("ark: teams pipeline: {} — Microsoft Graph notifications stay accepted and dropped", e.message);
            return installed;
        }
    };
    if let Err(e) = Store::open(&teams.store_path) {
        eprintln!("ark: teams pipeline: {e} — Microsoft Graph notifications stay accepted and dropped");
        return installed;
    }
    let pipeline_cfg = PipelineConfig::from_table(&teams.pipeline_table);
    let sink = deliver::teams_sink(&pipeline_cfg, &cfg.channels, paths, client.clone());
    let rt = Runtime { client, store_path: teams.store_path.clone(), config: pipeline_cfg, sink };
    installed.teams_sink = rt.sink.is_some();
    let scheduler: ark_channel::msgraph_webhook::NotificationScheduler = Arc::new(move |n: &serde_json::Value| {
        rt.schedule(n).map(|_| ()).map_err(|e| {
            eprintln!("ark: teams pipeline: {e}");
            e
        })
    });
    ark_channel::msgraph_webhook::set_notification_scheduler(Some(scheduler));
    installed.notifications = true;
    installed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meetings::teams::graph::Credentials;
    use crate::meetings::teams::models::Job;
    use crate::meetings::teams::pipeline::{Pipeline, PipelineConfig};
    use serde_json::{json, Value};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// A local Graph stand-in: token endpoint, one meeting, one transcript, subscriptions.
    struct Fake {
        url: String,
        hits: Arc<Mutex<Vec<(String, String, String)>>>,
    }

    const VTT: &str = "WEBVTT\n\n00:00:01.000 --> 00:00:04.000\nAlice: welcome everyone to the weekly sync\n00:00:04.000 --> 00:00:08.000\nBob: action: send the deck, we decided to ship it\n";

    impl Fake {
        fn start() -> Fake {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", l.local_addr().unwrap());
            let hits = Arc::new(Mutex::new(Vec::new()));
            let h = hits.clone();
            let base = url.clone();
            std::thread::spawn(move || {
                for s in l.incoming() {
                    let Ok(mut s) = s else { continue };
                    let mut r = BufReader::new(s.try_clone().unwrap());
                    let mut head = String::new();
                    let mut len = 0usize;
                    loop {
                        let mut line = String::new();
                        if r.read_line(&mut line).unwrap_or(0) == 0 {
                            break;
                        }
                        let lower = line.to_ascii_lowercase();
                        if let Some(v) = lower.strip_prefix("content-length:") {
                            len = v.trim().parse().unwrap_or(0);
                        }
                        head.push_str(&line);
                        if line == "\r\n" || line == "\n" {
                            break;
                        }
                    }
                    if head.is_empty() {
                        continue;
                    }
                    let mut body = vec![0u8; len];
                    let _ = r.read_exact(&mut body);
                    let body = String::from_utf8_lossy(&body).into_owned();
                    let mut parts = head.lines().next().unwrap_or("").split_whitespace();
                    let method = parts.next().unwrap_or("").to_string();
                    let path = parts.next().unwrap_or("/").to_string();
                    h.lock().unwrap().push((method.clone(), path.clone(), body.clone()));
                    let (status, ctype, payload): (u16, &str, String) = if path.ends_with("/oauth2/v2.0/token") {
                        (200, "application/json", json!({"access_token": "tok", "expires_in": 3600, "token_type": "Bearer"}).to_string())
                    } else if path.starts_with("/download/") {
                        (200, "text/vtt", VTT.to_string())
                    } else if path.ends_with("/users/u1/onlineMeetings/MS1") {
                        (200, "application/json", json!({"id": "MS1", "subject": "Weekly sync", "joinWebUrl": "https://teams.microsoft.com/l/meetup-join/x", "organizer": {"identity": {"user": {"id": "u1"}}}, "participants": [{"displayName": "Alice"}], "startDateTime": "2026-01-01T09:00:00Z"}).to_string())
                    } else if path.ends_with("/users/u1/onlineMeetings/MS1/transcripts") {
                        (200, "application/json", json!({"value": [{"id": "T1", "displayName": "t.vtt", "status": "completed", "createdDateTime": "2026-01-01T10:00:00Z", "@microsoft.graph.downloadUrl": format!("{base}/download/T1.vtt")}]}).to_string())
                    } else if path.ends_with("/users/u1/onlineMeetings/MS1/recordings") {
                        (200, "application/json", json!({"value": []}).to_string())
                    } else if path == "/v1.0/subscriptions" && method == "GET" {
                        (200, "application/json", json!({"value": [{"id": "s1", "resource": "/communications/onlineMeetings/getAllTranscripts", "changeType": "created", "notificationUrl": "https://example.test/hook", "clientState": "state1", "expirationDateTime": crate::meetings::teams::models::iso_z(crate::meetings::teams::models::now_secs() + 3600)}]}).to_string())
                    } else if path == "/v1.0/subscriptions" && method == "POST" {
                        (201, "application/json", json!({"id": "s2", "resource": "me", "changeType": "updated", "notificationUrl": "https://example.test/hook", "expirationDateTime": "2026-01-02T00:00:00Z"}).to_string())
                    } else if path.starts_with("/v1.0/subscriptions/") && method == "PATCH" {
                        (200, "application/json", json!({"id": path.rsplit('/').next().unwrap_or("s1")}).to_string())
                    } else {
                        (404, "application/json", json!({"error": {"code": "NotFound", "message": "no route"}}).to_string())
                    };
                    let resp = format!("HTTP/1.1 {status} X\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}", payload.len());
                    let _ = s.write_all(resp.as_bytes());
                }
            });
            Fake { url, hits }
        }

        fn client(&self) -> Arc<Client> {
            let creds = Credentials::from_parts(Some("contoso".into()), Some("app".into()), Some("s3cret".into()), None, Some(self.url.clone())).unwrap();
            Arc::new(Client::new(creds, &format!("{}/v1.0", self.url)))
        }

        fn calls(&self) -> Vec<(String, String)> {
            self.hits.lock().unwrap().iter().map(|(m, p, _)| (m.clone(), p.clone())).collect()
        }
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ark-teams-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn paths_in(dir: &std::path::Path) -> Paths {
        Paths { data: dir.join("data"), config_dir: dir.join("config"), runtime: dir.join("run") }
    }

    #[test]
    fn notification_becomes_a_stored_meeting_summary() {
        let fake = Fake::start();
        let dir = tmp("pipeline");
        let store = Store::open(&dir.join("store.json")).unwrap();
        let summarize = |_r: &models::TeamsMeetingRef, text: &str, _a: &[models::MeetingArtifact]| Ok(format!("{{\"summary\": \"synced {} lines\", \"key_decisions\": [\"ship it\"], \"action_items\": [\"send the deck\"], \"risks\": [], \"confidence\": \"high\", \"confidence_notes\": \"clean audio\"}}", text.lines().count()));
        let mut p = Pipeline::new(fake.client(), store, PipelineConfig::default()).with_summarizer(Box::new(summarize));
        let job = p.run_notification(&json!({"id": "n1", "changeType": "created", "resource": "/users/u1/onlineMeetings/MS1/transcripts/T1"})).unwrap();
        assert_eq!(job.status, "completed", "{:?}", job.error_info);
        let summary = job.summary_payload.clone().unwrap();
        assert_eq!(summary.meeting_ref.meeting_id, "MS1");
        assert_eq!(summary.title.as_deref(), Some("Weekly sync"));
        assert_eq!(summary.summary, Some(format!("synced {} lines", VTT.trim().lines().count())));
        assert_eq!(summary.key_decisions, vec!["ship it".to_string()]);
        assert_eq!(summary.action_items, vec!["send the deck".to_string()]);
        assert_eq!(summary.confidence.as_deref(), Some("high"));
        assert_eq!(summary.participants, vec!["Alice".to_string()]);
        assert_eq!(summary.source_artifacts.len(), 1, "the transcript artifact is recorded");
        assert_eq!(job.selected_artifact_strategy.as_deref(), Some("transcript_first"));
        // The summary is on disk, and a duplicate delivery does not start a second job.
        let reopened = Store::open(&dir.join("store.json")).unwrap();
        assert_eq!(reopened.get_job(&job.job_id).unwrap()["status"], "completed");
        assert_eq!(reopened.list_jobs().len(), 1);
        let again = p.run_notification(&json!({"id": "n1", "changeType": "created", "resource": "/users/u1/onlineMeetings/MS1/transcripts/T1"})).unwrap();
        assert_eq!((again.job_id.as_str(), again.status.as_str()), (job.job_id.as_str(), "completed"));
        assert_eq!(p.store.list_jobs().len(), 1);
        // The transcript was fetched through Graph with a bearer token.
        let calls = fake.calls();
        assert!(calls.iter().any(|(m, p)| m == "POST" && p.ends_with("/oauth2/v2.0/token")), "{calls:?}");
        assert!(calls.iter().any(|(m, p)| m == "GET" && p == "/v1.0/users/u1/onlineMeetings/MS1/transcripts"), "{calls:?}");
        assert!(calls.iter().any(|(m, p)| m == "GET" && p.ends_with("/download/T1.vtt")), "{calls:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The webhook adapter's entry point, with no model installed: upstream's heuristic summary.
    #[test]
    fn webhook_entry_point_stores_a_heuristic_summary_without_a_model() {
        let fake = Fake::start();
        let dir = tmp("webhook");
        let rt = Runtime { client: fake.client(), store_path: dir.join("store.json"), config: PipelineConfig::default(), sink: None };
        let job = rt.handle(&json!({"id": "n9", "resource": "/users/u1/onlineMeetings/MS1/transcripts/T1"})).unwrap();
        assert_eq!(job.status, "completed", "{:?}", job.error_info);
        let s = job.summary_payload.clone().unwrap();
        assert!(!s.summary.clone().unwrap_or_default().is_empty());
        assert_eq!(s.confidence.as_deref(), Some("low"), "short transcript → low confidence");
        assert!(s.confidence_notes.unwrap_or_default().contains("heuristic"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_meeting_fails_the_job_and_duplicates_are_retryable() {
        let fake = Fake::start();
        let dir = tmp("failing");
        let store = Store::open(&dir.join("store.json")).unwrap();
        let mut p = Pipeline::new(fake.client(), store, PipelineConfig::default());
        let job = p.run_notification(&json!({"id": "n2", "resource": "/users/u1/onlineMeetings/M404/transcripts/T9"})).unwrap();
        assert_eq!(job.status, "failed");
        assert!(job.error_info.get("message").and_then(Value::as_str).unwrap_or("").contains("Teams meeting not found: M404"), "{:?}", job.error_info);
        // The job can be replayed by id.
        let replayed = p.run_job(&job.job_id).unwrap();
        assert_eq!(replayed.status, "failed");
        assert!(p.run_job("teams-job-nope").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn subscriptions_are_created_listed_and_renewed() {
        let fake = Fake::start();
        let dir = tmp("subs");
        let mut store = Store::open(&dir.join("store.json")).unwrap();
        let client = fake.client();
        // create
        let created = client.post_json("/subscriptions", &json!({"resource": "me", "notificationUrl": "https://example.test/hook", "changeType": "updated", "expirationDateTime": "2026-01-02T00:00:00Z"})).unwrap();
        subs::sync_graph_subscription_record(&mut store, &created, Some("active"), false).unwrap();
        assert_eq!(store.get_subscription("s2").unwrap()["status"], "active");
        // maintain: the near-expiry managed subscription (clientState state1) is renewed.
        let out = subs::maintain_graph_subscriptions(&client, &mut store, 24, 24, false, Some("state1")).unwrap();
        assert_eq!((out["renewed_count"].as_u64(), out["candidate_count"].as_u64(), out["synced_subscription_count"].as_u64()), (Some(1), Some(1), Some(1)), "{out}");
        let s1 = store.get_subscription("s1").unwrap();
        assert_eq!(s1["status"], "active");
        assert!(s1["latest_renewal_at"].is_string());
        assert!(crate::meetings::teams::models::parse_iso(s1["expiration_datetime"].as_str().unwrap()).unwrap() > crate::meetings::teams::models::now_secs() + 23 * 3600);
        // s2 was not reported remotely any more → flagged, never deleted.
        assert_eq!(store.get_subscription("s2").unwrap()["status"], "missing_remote");
        assert!(fake.calls().iter().any(|(m, p)| m == "PATCH" && p == "/v1.0/subscriptions/s1"));
        // dry-run changes nothing.
        let out = subs::maintain_graph_subscriptions(&client, &mut store, 24, 24, true, Some("state1")).unwrap();
        assert_eq!((out["dry_run"].as_bool(), out["renewed_count"].as_u64(), out["candidate_count"].as_u64()), (Some(true), Some(0), Some(1)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_credentials_message_and_cli_hint() {
        let dir = tmp("creds");
        let paths = paths_in(&dir);
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::write(paths.user_config(), "[meetings.teams]\n").unwrap();
        let meetings = toml::Table::new();
        let cfg = config(&meetings, &paths);
        let err = client_for(&cfg).unwrap_err();
        if std::env::var("MSGRAPH_TENANT_ID").is_err() {
            assert_eq!(err.message, "Missing Microsoft Graph configuration: MSGRAPH_TENANT_ID, MSGRAPH_CLIENT_ID, MSGRAPH_CLIENT_SECRET");
            // The CLI appends upstream's setup hint and fails with exit code 1 (Err) instead.
            let e = cli(&meetings, &paths, &["token-health".to_string()]).unwrap_err();
            assert!(e.contains("Missing Microsoft Graph configuration: MSGRAPH_TENANT_ID, MSGRAPH_CLIENT_ID, MSGRAPH_CLIENT_SECRET"), "{e}");
            assert!(e.contains("Microsoft Graph is not configured"), "{e}");
            assert!(e.contains("[meetings.teams]") && e.contains("client_secret"), "{e}");
        }
        // `list`/`validate` work without credentials.
        assert_eq!(cli(&meetings, &paths, &["list".to_string()]).unwrap(), 0);
        assert_eq!(cli(&meetings, &paths, &["validate".to_string()]).unwrap(), 0);
        assert_eq!(cli(&meetings, &paths, &["nope".to_string()]).unwrap(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_reads_pipeline_table_and_resolves_secrets() {
        let dir = tmp("config");
        let paths = paths_in(&dir);
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::write(paths.user_config(), "[meetings.teams]\nclient_secret = \"{{secret:NOPE_UNSET}}\"\nstore_path = \"\"\n[meetings.teams.pipeline]\ntranscript_min_chars = 40\ntranscript_required = true\n[meetings.teams.pipeline.notion]\nenabled = true\ndatabase_id = \"db\"\n").unwrap();
        let doc: toml::Table = std::fs::read_to_string(paths.user_config()).unwrap().parse().unwrap();
        let meetings = doc.get("meetings").and_then(|m| m.as_table()).cloned().unwrap();
        let cfg = config(&meetings, &paths);
        assert_eq!(cfg.store_path, paths.data.join("teams_pipeline_store.json"));
        let p = PipelineConfig::from_table(&cfg.pipeline_table);
        assert_eq!((p.transcript_min_chars, p.transcript_required, p.transcript_preferred), (40, true, true));
        assert_eq!(p.notion.as_ref().unwrap()["database_id"], json!("db"));
        // An unresolvable placeholder stays put and counts as "not configured".
        assert_eq!(cfg.table.get("client_secret").and_then(|v| v.as_str()), Some("{{secret:NOPE_UNSET}}"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stored_jobs_round_trip_through_the_cli_helpers() {
        let dir = tmp("jobs");
        let mut store = Store::open(&dir.join("store.json")).unwrap();
        store.upsert_job("j1", &json!({"status": "completed", "dedupe_key": "id:n1", "event_id": "id:n1", "source_event_type": "created", "summary_payload": {"meeting_ref": {"meeting_id": "M1"}, "transcript_text": "secret transcript body"}})).unwrap();
        let job: Job = Job::from_value(&store.get_job("j1").unwrap()).unwrap();
        assert_eq!(job.status, "completed");
        let compact = crate::meetings::teams::pipeline::compact_job(&store.get_job("j1").unwrap());
        assert!(compact["summary_payload"].get("transcript_text").is_none(), "the transcript is compacted away: {compact}");
        assert_eq!(compact["summary_payload"]["transcript_preview"], "secret transcript body");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- The wired path: Graph notification → webhook → job → pipeline → Teams sink -----------------

    /// Serialises the tests that bind the process-wide Graph notification scheduler.
    fn scheduler_lock() -> std::sync::MutexGuard<'static, ()> {
        static L: Mutex<()> = Mutex::new(());
        L.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A tiny HTTP stand-in that records every request and answers through `reply`.
    struct Catch {
        url: String,
        hits: Arc<Mutex<Vec<(String, String, String)>>>,
    }

    impl Catch {
        fn start(reply: fn(&str, &str) -> String) -> Catch {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", l.local_addr().unwrap());
            let hits = Arc::new(Mutex::new(Vec::new()));
            let h = hits.clone();
            std::thread::spawn(move || {
                for s in l.incoming() {
                    let Ok(mut s) = s else { continue };
                    let mut r = BufReader::new(s.try_clone().unwrap());
                    let (mut head, mut len) = (String::new(), 0usize);
                    loop {
                        let mut line = String::new();
                        if r.read_line(&mut line).unwrap_or(0) == 0 {
                            break;
                        }
                        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                            len = v.trim().parse().unwrap_or(0);
                        }
                        let done = line == "\r\n" || line == "\n";
                        head.push_str(&line);
                        if done {
                            break;
                        }
                    }
                    let mut body = vec![0u8; len];
                    let _ = r.read_exact(&mut body);
                    let body = String::from_utf8_lossy(&body).into_owned();
                    let mut parts = head.lines().next().unwrap_or("").split_whitespace();
                    let (method, path) = (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("/").to_string());
                    h.lock().unwrap().push((method.clone(), path.clone(), body.clone()));
                    let payload = reply(&method, &path);
                    let resp = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}", payload.len());
                    let _ = s.write_all(resp.as_bytes());
                }
            });
            Catch { url, hits }
        }

        fn posts(&self, needle: &str) -> Vec<String> {
            self.hits.lock().unwrap().iter().filter(|(m, p, _)| m == "POST" && p.contains(needle)).map(|(_, _, b)| b.clone()).collect()
        }
    }

    fn graph_token_reply(_m: &str, _p: &str) -> String {
        json!({"access_token": "tok", "expires_in": 3600, "token_type": "Bearer"}).to_string()
    }

    fn meetings_table(text: &str) -> toml::Table {
        let doc: toml::Table = toml::from_str(text).unwrap();
        doc.get("meetings").and_then(|m| m.as_table()).cloned().unwrap_or_default()
    }

    fn wait_for_job(store_path: &std::path::Path, want: &str) -> Value {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            if let Ok(store) = Store::open(store_path) {
                let jobs = store.list_jobs();
                if let Some((_, job)) = jobs.iter().find(|(_, j)| j["status"] == json!(want)) {
                    return job.clone();
                }
                if std::time::Instant::now() > deadline {
                    panic!("no {want} job after 20s: {jobs:?}");
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }

    /// End to end: `[meetings.teams]` + `teams_delivery` → `install_at` binds the webhook scheduler;
    /// a real Graph change notification posted to a real `msgraph_webhook` channel becomes a durable
    /// job (acks 202, no chat Inbound), the pipeline fetches the transcript from the fake Graph and the
    /// Teams sink posts the summary to the configured webhook. A replay adds nothing.
    #[test]
    fn graph_notification_becomes_a_job_and_the_summary_reaches_teams() {
        let _g = scheduler_lock();
        let fake = Fake::start();
        let teams = Catch::start(|_m, _p| "{}".to_string());
        let dir = tmp("e2e");
        let paths = paths_in(&dir);
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        let store_path = dir.join("store.json");
        let cfg = Config {
            meetings: meetings_table(&format!(
                "[meetings.teams]\ntenant_id = \"contoso\"\nclient_id = \"app\"\nclient_secret = \"s3cret\"\nbase_url = \"{}/v1.0\"\nauthority_url = \"{}/oauth2/v2.0/token\"\nstore_path = \"{}\"\n[meetings.teams.pipeline]\ntranscript_min_chars = 0\n[meetings.teams.pipeline.teams_delivery]\nenabled = true\nincoming_webhook_url = \"{}\"\n",
                fake.url, fake.url, store_path.display(), teams.url
            )),
            ..Default::default()
        };
        let installed = install_at(&paths, &cfg);
        assert_eq!(installed, Installed { notifications: true, teams_sink: true }, "both halves are wired");
        assert!(ark_channel::msgraph_webhook::notification_scheduler_installed());
        // A real notification posted to the channel `ark-channel` builds for `[channels.msgraph_webhook]`.
        let hook = ark_channel::msgraph_webhook::MsGraphWebhook::new(
            "graph",
            ark_channel::msgraph_webhook::MsGraphOpts { listen: "127.0.0.1:0", path: "/msgraph/webhook", health_path: "/health", client_state: "state1", accepted_resources: vec![], allowed_source_cidrs: vec![], prompt: None, max_seen_receipts: 100, max_body_bytes: 65536, poll_timeout: std::time::Duration::from_millis(50) },
        )
        .unwrap();
        let body = json!({"value": [{"id": "n1", "subscriptionId": "s1", "clientState": "state1", "changeType": "created", "resource": "/users/u1/onlineMeetings/MS1/transcripts/T1"}]}).to_string();
        let r = ark_tools::web::http::post_json(&format!("http://{}/msgraph/webhook", hook.local_addr()), &[("Content-Type", "application/json".to_string())], &serde_json::from_str(&body).unwrap(), 10).unwrap();
        assert_eq!(r.status, 202, "Graph gets its 202 while the job is durable");
        use ark_channel::Channel as _;
        assert!(hook.poll(&ark_core::Cancel::new()).unwrap().is_empty(), "the pipeline owns the notification, not the chat");
        // The job runs detached and completes against the fake Graph.
        let job = wait_for_job(&store_path, "completed");
        assert_eq!(job["meeting_ref"]["meeting_id"], json!("MS1"));
        assert!(job["summary_payload"]["summary"].as_str().unwrap_or("").contains("welcome everyone"), "{job}");
        let store = Store::open(&store_path).unwrap();
        let record = store.get_sink_record("teams:MS1").expect("the Teams sink record is stored");
        assert_eq!((record["delivered"].as_bool(), record["delivery_mode"].as_str()), (Some(true), Some("incoming_webhook")), "{record}");
        let posted = teams.posts("/");
        assert_eq!(posted.len(), 1, "one summary, one delivery: {posted:?}");
        assert!(posted[0].contains("## Action Items") && posted[0].contains("welcome everyone"), "{}", posted[0]);
        // A replay of the same notification is acked and changes nothing.
        let r = ark_tools::web::http::post_json(&format!("http://{}/msgraph/webhook", hook.local_addr()), &[("Content-Type", "application/json".to_string())], &serde_json::from_str(&body).unwrap(), 10).unwrap();
        assert_eq!(r.status, 202, "a duplicate delivery is acked");
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert_eq!(Store::open(&store_path).unwrap().list_jobs().len(), 1, "no second job");
        assert_eq!(teams.posts("/").len(), 1, "no second delivery");
        ark_channel::msgraph_webhook::set_notification_scheduler(None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The host sink prefers the running bot: with a Teams platform channel, summaries go out through
    /// `ark_channel`'s msteams adapter as a connector activity (no incoming webhook involved).
    #[test]
    fn a_teams_channel_delivers_the_summary_through_the_msteams_adapter() {
        let fake = Fake::start();
        let bot = Catch::start(|_m, p| {
            if p.ends_with("/oauth2/v2.0/token") {
                graph_token_reply("POST", p)
            } else {
                json!({"id": "act-1"}).to_string()
            }
        });
        let dir = tmp("bot");
        let paths = paths_in(&dir);
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        let mut cfg = Config {
            meetings: meetings_table(&format!(
                "[meetings.teams]\ntenant_id = \"contoso\"\nclient_id = \"app\"\nclient_secret = \"s3cret\"\nbase_url = \"{}/v1.0\"\nauthority_url = \"{}/oauth2/v2.0/token\"\nstore_path = \"{}\"\n[meetings.teams.pipeline]\ntranscript_min_chars = 0\n[meetings.teams.pipeline.teams_delivery]\nenabled = true\nchat_id = \"19:weekly@thread.tacv2\"\n",
                fake.url, fake.url, dir.join("store.json").display()
            )),
            ..Default::default()
        };
        cfg.channels.insert(
            "teams".into(),
            toml::from_str(&format!("kind = \"teams\"\napp_id = \"app\"\napp_password = \"pw\"\ntenant = \"contoso\"\nlogin_url = \"{}\"\nservice_url = \"{}/\"\n", bot.url, bot.url)).unwrap(),
        );
        let teams_cfg = config(&cfg.meetings, &paths);
        let pipeline_cfg = PipelineConfig::from_table(&teams_cfg.pipeline_table);
        let sink = deliver::teams_sink(&pipeline_cfg, &cfg.channels, &paths, fake.client()).expect("a Teams channel exists → a sink is injected");
        let rt = Runtime { client: fake.client(), store_path: teams_cfg.store_path.clone(), config: pipeline_cfg, sink: Some(sink) };
        let job = rt.handle(&json!({"id": "n1", "resource": "/users/u1/onlineMeetings/MS1/transcripts/T1"})).unwrap();
        assert_eq!(job.status, "completed", "{:?}", job.error_info);
        let activities = bot.posts("/v3/conversations/");
        assert_eq!(activities.len(), 1, "one connector activity: {:?}", bot.hits.lock().unwrap());
        let activity: Value = serde_json::from_str(&activities[0]).unwrap();
        assert_eq!(activity["type"], json!("message"));
        assert!(activity["text"].as_str().unwrap_or("").contains("## Key Decisions") && activity["text"].as_str().unwrap_or("").contains("send the deck"), "{activity}");
        let record = Store::open(&teams_cfg.store_path).unwrap().get_sink_record("teams:MS1").unwrap();
        assert_eq!((record["delivery_mode"].as_str(), record["target_type"].as_str()), (Some("msteams"), Some("conversation")), "{record}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Nothing configured → nothing bound: the webhook keeps its "accept, then drop" default and the
    /// daemon still answers Graph with a 202.
    #[test]
    fn without_meetings_teams_the_webhook_keeps_ack_then_drop() {
        let _g = scheduler_lock();
        ark_channel::msgraph_webhook::set_notification_scheduler(None);
        let dir = tmp("unconfigured");
        let paths = paths_in(&dir);
        let cfg = Config::default();
        assert_eq!(install_at(&paths, &cfg), Installed::default());
        assert!(!ark_channel::msgraph_webhook::notification_scheduler_installed(), "no scheduler without [meetings.teams]");
        let hook = ark_channel::msgraph_webhook::MsGraphWebhook::new(
            "graph",
            ark_channel::msgraph_webhook::MsGraphOpts { listen: "127.0.0.1:0", path: "/msgraph/webhook", health_path: "/health", client_state: "state1", accepted_resources: vec![], allowed_source_cidrs: vec![], prompt: None, max_seen_receipts: 10, max_body_bytes: 65536, poll_timeout: std::time::Duration::from_millis(50) },
        )
        .unwrap();
        let body = json!({"value": [{"id": "n1", "clientState": "state1", "resource": "/users/u1/onlineMeetings/MS1/transcripts/T1"}]});
        let r = ark_tools::web::http::post_json(&format!("http://{}/msgraph/webhook", hook.local_addr()), &[("Content-Type", "application/json".to_string())], &body, 10).unwrap();
        assert_eq!(r.status, 202);
        use ark_channel::Channel as _;
        let got = hook.poll(&ark_core::Cancel::new()).unwrap();
        assert_eq!(got.len(), 1, "the unchanged default: the notification is a chat message");
        assert_eq!(got[0].message_id, "id:n1");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A malformed or credential-less `[meetings.teams]` is a warning, never a panic, and binds nothing.
    #[test]
    fn a_broken_teams_config_binds_nothing() {
        let _g = scheduler_lock();
        ark_channel::msgraph_webhook::set_notification_scheduler(None);
        let dir = tmp("broken");
        let paths = paths_in(&dir);
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        // `[meetings] teams = 1` is not a table at all.
        let mut cfg = Config { meetings: meetings_table("teams = 1"), ..Default::default() };
        assert_eq!(install_at(&paths, &cfg), Installed::default());
        // An empty `[meetings.teams]` has no Graph credentials.
        cfg.meetings = meetings_table("[meetings.teams]\n");
        assert_eq!(install_at(&paths, &cfg), Installed::default());
        assert!(!ark_channel::msgraph_webhook::notification_scheduler_installed());
        // A store path that is a directory cannot be read: also just a warning.
        cfg.meetings = meetings_table(&format!("[meetings.teams]\ntenant_id = \"contoso\"\nclient_id = \"app\"\nclient_secret = \"s3cret\"\nstore_path = \"{}\"\n", dir.display()));
        assert_eq!(install_at(&paths, &cfg), Installed::default());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
