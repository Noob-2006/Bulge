//! Teams meeting pipeline (Hermes `plugins/teams_pipeline/pipeline.py`, MIT).
//!
//! Transcript-first: a Graph change notification becomes a durable job
//! (`received` → `resolving_meeting` → `fetching_transcript` → `summarizing` → … →
//! `completed`), the meeting's transcript is fetched and summarised into a stored
//! [`SummaryPayload`] (LLM when a model is configured, upstream's heuristic otherwise), and the
//! configured sinks (Notion, Linear, Teams delivery) are written in that order. A missing
//! transcript can fall back to downloading the recording and running it through STT; artifacts
//! that are not there yet leave the job `retry_scheduled`, everything else `failed`.
//!
//! Upstream is `async`; here each phase is a blocking call (the caller — CLI or webhook thread —
//! decides where it runs). `transcribe` and `summarize` are injectable so tests need no model.

use super::graph::Client;
use super::meetings::{self, MeetingsError};
use super::models::{Job, MeetingArtifact, SummaryPayload, TeamsMeetingRef};
use super::store::{notification_receipt_key, Store};
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};

pub const TERMINAL_STATES: &[&str] = &["completed", "failed", "retry_scheduled"];
pub const ACTIVE_STATES: &[&str] = &["received", "resolving_meeting", "fetching_transcript", "downloading_recording", "transcribing_audio", "summarizing", "writing_notion", "writing_linear", "sending_teams"];
const AUDIO_SUFFIXES: &[&str] = &["wav", "mp3", "m4a", "ogg", "flac", "aac", "webm"];
pub const SUMMARY_SYSTEM_PROMPT: &str = "You summarize meeting transcripts. Return only valid JSON with keys: summary, key_decisions, action_items, risks, confidence, confidence_notes.";

/// Pipeline knobs (`[meetings.teams.pipeline]`).
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    pub transcript_preferred: bool,
    pub transcript_required: bool,
    pub transcription_fallback: bool,
    pub stt_model: Option<String>,
    pub ffmpeg_extract_audio: bool,
    pub transcript_min_chars: usize,
    pub tmp_dir: Option<PathBuf>,
    pub notion: Option<Map<String, Value>>,
    pub linear: Option<Map<String, Value>>,
    pub teams_delivery: Option<Map<String, Value>>,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        PipelineConfig {
            transcript_preferred: true,
            transcript_required: false,
            transcription_fallback: true,
            stt_model: None,
            ffmpeg_extract_audio: true,
            transcript_min_chars: 80,
            tmp_dir: None,
            notion: None,
            linear: None,
            teams_delivery: None,
        }
    }
}

fn flag(t: &toml::Table, key: &str, default: bool) -> bool {
    t.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
}

fn text(t: &toml::Table, key: &str) -> Option<String> {
    t.get(key).and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

fn sub_table(t: &toml::Table, key: &str) -> Option<Map<String, Value>> {
    let v = t.get(key)?;
    serde_json::to_value(v).ok()?.as_object().cloned().filter(|m| !m.is_empty())
}

impl PipelineConfig {
    /// `[meetings.teams.pipeline]`.
    pub fn from_table(t: &toml::Table) -> PipelineConfig {
        let int = |key: &str, default: usize| -> usize {
            match t.get(key) {
                Some(toml::Value::Integer(n)) => (*n).max(0) as usize,
                Some(toml::Value::String(s)) => s.trim().parse().unwrap_or(default),
                _ => default,
            }
        };
        PipelineConfig {
            transcript_preferred: flag(t, "transcript_preferred", true),
            transcript_required: flag(t, "transcript_required", false),
            transcription_fallback: flag(t, "transcription_fallback", true),
            stt_model: text(t, "stt_model").or_else(|| text(t, "sttModel")),
            ffmpeg_extract_audio: flag(t, "ffmpeg_extract_audio", true),
            transcript_min_chars: int("transcript_min_chars", 80),
            tmp_dir: text(t, "tmp_dir").or_else(|| text(t, "tmpDir")).map(PathBuf::from),
            notion: sub_table(t, "notion"),
            linear: sub_table(t, "linear"),
            teams_delivery: sub_table(t, "teams_delivery").or_else(|| sub_table(t, "teamsDelivery")),
        }
    }
}

/// A pipeline failure whose class decides the job's final status.
#[derive(Debug, Clone, PartialEq)]
pub enum PipelineError {
    /// Retry later (artifact not published yet).
    Retryable(String),
    /// Terminal.
    Failed(String),
    Sink(String),
}

impl PipelineError {
    pub fn message(&self) -> &str {
        match self {
            PipelineError::Retryable(m) | PipelineError::Failed(m) | PipelineError::Sink(m) => m,
        }
    }
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl From<String> for PipelineError {
    fn from(s: String) -> Self {
        PipelineError::Failed(s)
    }
}

impl From<MeetingsError> for PipelineError {
    fn from(e: MeetingsError) -> Self {
        // Upstream only treats *artifact* absence as retryable; a missing meeting is terminal.
        if matches!(e, MeetingsError::ArtifactNotFound(_)) {
            PipelineError::Retryable(e.message().to_string())
        } else {
            PipelineError::Failed(e.message().to_string())
        }
    }
}

/// One summarised meeting (upstream `TeamsMeetingSummaryPayload` builder).
fn collect_call_metrics(artifacts: &[MeetingArtifact]) -> Map<String, Value> {
    let mut metrics = Map::new();
    for a in artifacts.iter().filter(|a| a.artifact_type == "call_record") {
        if let Some(m) = a.metadata.get("metrics").and_then(Value::as_object) {
            for (k, v) in m {
                metrics.insert(k.clone(), v.clone());
            }
        }
    }
    metrics.insert("artifact_count".into(), json!(artifacts.len()));
    metrics
}

fn collect_participants(r: &TeamsMeetingRef) -> Vec<String> {
    let Some(Value::Array(items)) = r.metadata.get("participants") else { return Vec::new() };
    items
        .iter()
        .filter_map(|p| p.get("displayName").and_then(Value::as_str).map(str::to_string).or_else(|| p.get("identity")?.get("user")?.get("displayName")?.as_str().map(str::to_string)))
        .collect()
}

/// Parse the model's JSON reply, tolerating prose or code fences (upstream `_parse_summary_json`).
pub fn parse_summary_json(content: &str) -> Map<String, Value> {
    let t = content.trim();
    if t.is_empty() {
        return heuristic_summary("");
    }
    let (s, e) = (t.find('{'), t.rfind('}'));
    let body = match (s, e) {
        (Some(s), Some(e)) if e > s => &t[s..=e],
        _ => t,
    };
    match serde_json::from_str::<Value>(body) {
        Ok(v) => {
            let mut out = Map::new();
            out.insert("summary".into(), json!(v.get("summary").and_then(Value::as_str).unwrap_or("").trim()));
            for key in ["key_decisions", "action_items", "risks"] {
                out.insert(key.into(), json!(clean_items(v.get(key))));
            }
            out.insert("confidence".into(), json!(v.get("confidence").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).unwrap_or("medium")));
            out.insert("confidence_notes".into(), json!(v.get("confidence_notes").and_then(Value::as_str).unwrap_or("").trim()));
            out
        }
        Err(_) => heuristic_summary(t),
    }
}

fn clean_items(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a.iter().map(|x| x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string())).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        Some(Value::String(s)) => s.split('\n').map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect(),
        _ => Vec::new(),
    }
}

/// Keyword summary used when no model answered (upstream `_heuristic_summary`).
pub fn heuristic_summary(transcript_text: &str) -> Map<String, Value> {
    let lines: Vec<String> = transcript_text.lines().map(|l| l.trim_matches(|c: char| c == ' ' || c == '-' || c == '*' || c == '\t').to_string()).filter(|l| !l.is_empty()).collect();
    let lowered: Vec<String> = lines.iter().map(|l| l.to_lowercase()).collect();
    let pick = |f: &dyn Fn(&str) -> bool, n: usize| -> Vec<String> { lines.iter().zip(lowered.iter()).filter(|(_, l)| f(l)).map(|(l, _)| l.clone()).take(n).collect() };
    let joined = lines.iter().take(3).cloned().collect::<Vec<_>>().join(" ");
    let summary = if joined.is_empty() { "Transcript unavailable or too sparse for a confident summary.".to_string() } else { joined.chars().take(1200).collect() };
    let mut out = Map::new();
    out.insert("summary".into(), json!(summary));
    out.insert("key_decisions".into(), json!(pick(&|l| l.contains("decide") || l.contains("decision"), 6)));
    out.insert("action_items".into(), json!(pick(&|l| ["action:", "todo:", "next step:", "follow up:"].iter().any(|p| l.starts_with(p)), 8)));
    out.insert("risks".into(), json!(pick(&|l| l.contains("risk") || l.contains("blocker"), 6)));
    out.insert("confidence".into(), json!(if transcript_text.trim().len() < 300 { "low" } else { "medium" }));
    out.insert("confidence_notes".into(), json!("Generated with heuristic fallback because no LLM summary response was available."));
    out
}

/// `# Title` + Summary / Key Decisions / Action Items / Risks (upstream `_render_summary_markdown`).
pub fn render_summary_markdown(p: &SummaryPayload) -> String {
    let bullets = |items: &[String]| -> String {
        if items.is_empty() {
            "- None".to_string()
        } else {
            items.iter().map(|i| format!("- {i}")).collect::<Vec<_>>().join("\n")
        }
    };
    let title = p.title.clone().unwrap_or_else(|| format!("Meeting {}", p.meeting_ref.meeting_id));
    let summary = p.summary.clone().filter(|s| !s.is_empty()).unwrap_or_else(|| "No summary available.".into());
    format!(
        "# {title}\n\n## Summary\n{summary}\n\n## Key Decisions\n{}\n\n## Action Items\n{}\n\n## Risks\n{}\n\nConfidence: {}\n{}",
        bullets(&p.key_decisions),
        bullets(&p.action_items),
        bullets(&p.risks),
        p.confidence.clone().unwrap_or_else(|| "unknown".into()),
        p.confidence_notes.clone().unwrap_or_default()
    )
    .trim()
    .to_string()
}

/// The stored summary for one meeting.
fn summary_payload(r: &TeamsMeetingRef, transcript: &str, artifacts: &[MeetingArtifact], parsed: &Map<String, Value>, cfg: &PipelineConfig) -> SummaryPayload {
    let str_list = |k: &str| parsed.get(k).and_then(Value::as_array).map(|a| a.iter().map(|x| x.as_str().unwrap_or("").trim().to_string()).filter(|s| !s.is_empty()).collect()).unwrap_or_default();
    let delivery = cfg.teams_delivery.clone().unwrap_or_default();
    let target = |k: &str| delivery.get(k).and_then(Value::as_str).map(str::to_string);
    SummaryPayload {
        meeting_ref: r.clone(),
        title: r.subject().or_else(|| Some(format!("Meeting {}", r.meeting_id))),
        start_time: r.metadata.get("startDateTime").and_then(Value::as_str).map(str::to_string),
        end_time: r.metadata.get("endDateTime").and_then(Value::as_str).map(str::to_string),
        participants: collect_participants(r),
        transcript_text: Some(transcript.to_string()).filter(|t| !t.is_empty()),
        summary: parsed.get("summary").and_then(Value::as_str).map(str::to_string),
        key_decisions: str_list("key_decisions"),
        action_items: str_list("action_items"),
        risks: str_list("risks"),
        call_metrics: collect_call_metrics(artifacts),
        source_artifacts: artifacts.to_vec(),
        confidence: parsed.get("confidence").and_then(Value::as_str).map(str::to_string),
        confidence_notes: parsed.get("confidence_notes").and_then(Value::as_str).map(str::to_string),
        notion_target: cfg.notion.as_ref().and_then(|n| n.get("database_id")).and_then(Value::as_str).map(str::to_string),
        linear_target: cfg.linear.as_ref().and_then(|n| n.get("team_id")).and_then(Value::as_str).map(str::to_string),
        teams_target: target("channel_id").or_else(|| target("chat_id")),
    }
}

/// The prompt handed to the model (upstream `_build_summary_prompt`).
pub fn build_summary_prompt(r: &TeamsMeetingRef, transcript: &str, artifacts: &[MeetingArtifact]) -> String {
    let lines: Vec<String> = artifacts.iter().map(|a| format!("- {}:{}:{}", a.artifact_type, a.artifact_id, a.display_name.clone().unwrap_or_default())).collect();
    let body = if lines.is_empty() { "- none".to_string() } else { lines.join("\n") };
    let head: String = transcript.chars().take(18000).collect();
    format!("Meeting ID: {}\nTitle: {}\nArtifacts:\n{body}\n\nTranscript:\n{head}", r.meeting_id, r.subject().unwrap_or_else(|| "Unknown".into()))
}

/// Notification → `(meeting_id, organizer_user_id, extra metadata)`.
///
/// Parsed resource paths win over flat fields; `resourceData.id` counts as a meeting id only when
/// it is not an artifact id; the id never comes back empty (falls back to an artifact id, then to
/// the receipt key).
pub fn meeting_ids_from_notification(notification: &Value) -> (String, Option<String>, Map<String, Value>) {
    let odata = |p: &Value, name: &str| p.get(format!("@{name}")).cloned().or_else(|| p.get(name).cloned());
    let resource_data = notification.get("resourceData").cloned().unwrap_or(json!({}));
    let odata_type = odata(&resource_data, "odata.type").and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
    let raw_paths = [
        odata(&resource_data, "odata.id").and_then(|v| v.as_str().map(str::to_string)),
        notification.get("resource").and_then(Value::as_str).map(str::to_string),
        resource_data.get("transcriptContentUrl").and_then(Value::as_str).map(str::to_string),
    ];
    let parsed: Vec<meetings::ParsedResource> = raw_paths.iter().map(|p| meetings::parse_graph_meeting_resource(p.as_deref().unwrap_or(""))).collect();
    let first = |pick: &dyn Fn(&meetings::ParsedResource) -> Option<String>| parsed.iter().find_map(pick);
    let payload_organizer = |p: &Value| -> Option<String> {
        let org = p.get("meetingOrganizer").or_else(|| p.get("organizer"));
        if let Some(org) = org {
            let user = org.get("user").or_else(|| org.get("identity").and_then(|i| i.get("user")));
            if let Some(id) = user.and_then(|u| u.get("id")).and_then(Value::as_str) {
                if !id.trim().is_empty() {
                    return Some(id.trim().to_string());
                }
            }
        }
        p.get("organizerUserId").or_else(|| p.get("organizer_user_id")).and_then(Value::as_str).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
    };
    let organizer_user_id = first(&|p| p.organizer_user_id.clone()).or_else(|| payload_organizer(&resource_data)).or_else(|| payload_organizer(notification));
    let mut meeting_id = first(&|p| p.meeting_id.clone()).or_else(|| resource_data.get("meetingId").and_then(Value::as_str).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())).or_else(|| notification.get("meetingId").and_then(Value::as_str).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
    let mut transcript_id = first(&|p| p.transcript_id.clone());
    let recording_id = first(&|p| p.recording_id.clone());
    let resource_data_id = resource_data.get("id").and_then(Value::as_str).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    if let Some(id) = resource_data_id.clone() {
        if !resource_data_id_is_artifact(notification, &resource_data, &odata_type) {
            meeting_id = meeting_id.or(Some(id));
        } else if transcript_id.is_none() && meetings::looks_like_transcript_id(&id, Some(&odata_type)) {
            transcript_id = Some(id);
        }
    }
    let meeting_id = meeting_id.or(transcript_id.clone()).or(recording_id.clone()).unwrap_or_else(|| notification_receipt_key(notification));
    let mut extra = Map::new();
    if let Some(t) = transcript_id {
        extra.insert("transcript_id".into(), json!(t));
    }
    if let Some(r) = recording_id {
        extra.insert("recording_id".into(), json!(r));
    }
    (meeting_id, organizer_user_id, extra)
}

fn resource_data_id_is_artifact(notification: &Value, resource_data: &Value, odata_type: &str) -> bool {
    let t = odata_type.to_lowercase();
    if t.contains("calltranscript") || t.contains("callrecording") {
        return true;
    }
    let resource = notification.get("resource").and_then(Value::as_str).unwrap_or("").to_lowercase();
    if ["getalltranscripts", "getallrecordings", "/transcripts", "/recordings"].iter().any(|m| resource.contains(m)) {
        return true;
    }
    meetings::looks_like_transcript_id(resource_data.get("id").and_then(Value::as_str).unwrap_or(""), Some(odata_type))
}

/// Sink order is part of the contract: Notion, then Linear, then Teams delivery.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SinkKind {
    Notion,
    Linear,
    Teams,
}

pub type SummarizeFn = Box<dyn Fn(&TeamsMeetingRef, &str, &[MeetingArtifact]) -> Result<String, String>>;
pub type TranscribeFn = Box<dyn Fn(&Path, Option<&str>) -> Result<String, String>>;
pub type SinkFn = Box<dyn Fn(SinkKind, &SummaryPayload, &Map<String, Value>, Option<&Value>) -> Result<Value, String>>;

/// Orchestrates one notification through to a stored summary.
pub struct Pipeline {
    pub client: std::sync::Arc<Client>,
    pub store: Store,
    pub config: PipelineConfig,
    summarize: SummarizeFn,
    transcribe: TranscribeFn,
    sink: SinkFn,
}

impl Pipeline {
    pub fn new(client: std::sync::Arc<Client>, store: Store, config: PipelineConfig) -> Pipeline {
        Pipeline { client, store, config, summarize: Box::new(default_summarize), transcribe: Box::new(default_transcribe), sink: Box::new(default_sink) }
    }

    /// Inject the summariser (tests; a host may plug in its own model call).
    #[allow(dead_code)]
    pub fn with_summarizer(mut self, f: SummarizeFn) -> Pipeline {
        self.summarize = f;
        self
    }

    /// Inject the recording → text step (tests; avoids needing `[media.stt]`).
    #[allow(dead_code)]
    pub fn with_transcriber(mut self, f: TranscribeFn) -> Pipeline {
        self.transcribe = f;
        self
    }

    /// Inject the output sinks (a host-provided Teams sender; [`super::deliver`] builds one).
    pub fn with_sink(mut self, f: SinkFn) -> Pipeline {
        self.sink = f;
        self
    }

    fn job(&self, id: &str) -> Result<Job, String> {
        let v = self.store.get_job(id).ok_or_else(|| format!("Unknown Teams pipeline job: {id}"))?;
        Job::from_value(&v)
    }

    fn persist(&mut self, job: &mut Job, updates: Value) -> Result<(), String> {
        let mut merged = job.to_value();
        if let (Some(dst), Some(src)) = (merged.as_object_mut(), updates.as_object()) {
            for (k, v) in src {
                dst.insert(k.clone(), v.clone());
            }
        }
        let stored = self.store.upsert_job(&job.job_id, &merged)?;
        *job = Job::from_value(&stored)?;
        Ok(())
    }

    fn status(&mut self, job: &mut Job, status: &str) -> Result<(), String> {
        self.persist(job, json!({"status": status}))
    }

    fn find_job_by_dedupe_key(&self, key: &str) -> Option<Job> {
        if key.is_empty() {
            return None;
        }
        self.store.list_jobs().values().filter_map(|v| Job::from_value(v).ok()).find(|j| j.dedupe_key == key)
    }

    /// Persist the notification and return the job (an existing one for a duplicate delivery).
    pub fn create_job_from_notification(&mut self, notification: &Value) -> Result<Job, String> {
        let event_id = notification_receipt_key(notification);
        self.store.record_receipt(&event_id, notification)?;
        if let Some(job) = self.find_job_by_dedupe_key(&event_id) {
            return Ok(job);
        }
        let resource_data = notification.get("resourceData").cloned().unwrap_or(json!({}));
        let (meeting_id, organizer_user_id, extra) = meeting_ids_from_notification(notification);
        let mut metadata = Map::new();
        metadata.insert("notification".into(), notification.clone());
        if let Some(j) = resource_data.get("joinWebUrl").cloned().filter(|v| !v.is_null()) {
            metadata.insert("join_web_url".into(), j);
        }
        if let Some(c) = resource_data.get("callRecordId").cloned().or_else(|| notification.get("callRecordId").cloned()).filter(|v| !v.is_null()) {
            metadata.insert("call_record_id".into(), c);
        }
        for (k, v) in extra {
            metadata.insert(k, v);
        }
        let tenant = resource_data.get("tenantId").cloned().or_else(|| notification.get("tenantId").cloned()).filter(|v| !v.is_null());
        let mut job = Job {
            job_id: format!("teams-job-{}", seagent_kernel::util::random_hex(6)),
            event_id: event_id.clone(),
            dedupe_key: event_id,
            source_event_type: notification.get("changeType").and_then(Value::as_str).map(str::to_string).filter(|s| !s.is_empty()).unwrap_or_else(|| "graph.notification".into()),
            status: "received".into(),
            meeting_ref: Some(TeamsMeetingRef {
                meeting_id,
                organizer_user_id,
                tenant_id: tenant.and_then(|v| v.as_str().map(str::to_string)),
                metadata,
                ..Default::default()
            }),
            ..Default::default()
        };
        self.persist(&mut job, json!({}))?;
        Ok(job)
    }

    /// `create_job_from_notification` then run, unless the job is already running/finished.
    pub fn run_notification(&mut self, notification: &Value) -> Result<Job, String> {
        let job = self.create_job_from_notification(notification)?;
        if TERMINAL_STATES.contains(&job.status.as_str()) || (ACTIVE_STATES.contains(&job.status.as_str()) && job.status != "received") {
            return Ok(job);
        }
        self.run_job(&job.job_id)
    }

    /// Run every phase, folding failures into the stored job status.
    pub fn run_job(&mut self, id: &str) -> Result<Job, String> {
        let mut job = self.job(id)?;
        let Some(mut meeting_ref) = job.meeting_ref.clone() else {
            return Err(format!("Job {} has no meeting_ref.", job.job_id));
        };
        let mut artifacts: Vec<MeetingArtifact> = Vec::new();
        match self.advance(&mut job, &mut meeting_ref, &mut artifacts) {
            Ok(()) => {
                self.status(&mut job, "completed")?;
                Ok(job)
            }
            Err(PipelineError::Retryable(m)) => {
                self.persist(&mut job, json!({"status": "retry_scheduled", "error_info": {"message": m, "retryable": true}}))?;
                Ok(job)
            }
            Err(e) => {
                self.persist(&mut job, json!({"status": "failed", "error_info": {"message": e.message(), "retryable": false}}))?;
                Ok(job)
            }
        }
    }

    /// Phases 1–4: resolve, transcript, call record, summary, sinks.
    fn advance(&mut self, job: &mut Job, meeting_ref: &mut TeamsMeetingRef, artifacts: &mut Vec<MeetingArtifact>) -> Result<(), PipelineError> {
        let client = self.client.clone();
        let (resolved, notification) = self.resolve_meeting(job, meeting_ref, &client)?;
        *meeting_ref = resolved.clone();
        let transcript = self.obtain_transcript(job, &resolved, &client, artifacts)?;
        let call_record_id = notification.get("callRecordId").and_then(Value::as_str).map(str::to_string);
        if let Some(a) = meetings::enrich_meeting_with_call_record(&client, &resolved, call_record_id.as_deref()).map_err(PipelineError::from)? {
            artifacts.push(a);
        }
        self.status(job, "summarizing")?;
        let text = transcript.unwrap_or_default();
        let content = (self.summarize)(&resolved, &text, artifacts).unwrap_or_else(|_| String::new());
        let parsed = if content.trim().is_empty() { heuristic_summary(&text) } else { parse_summary_json(&content) };
        let payload = summary_payload(&resolved, &text, artifacts, &parsed, &self.config);
        self.persist(job, json!({"summary_payload": payload.to_value()}))?;
        self.write_sinks(job, &payload, &client)
    }

    fn resolve_meeting(&mut self, job: &mut Job, meeting_ref: &TeamsMeetingRef, client: &Client) -> Result<(TeamsMeetingRef, Value), PipelineError> {
        self.status(job, "resolving_meeting")?;
        let notification = meeting_ref.metadata.get("notification").cloned().unwrap_or(json!({}));
        let mut meeting_id = meeting_ref.meeting_id.clone();
        let mut organizer = meeting_ref.organizer_user_id.clone();
        if notification.is_object() && !notification.as_object().map(Map::is_empty).unwrap_or(true) {
            let (parsed_id, parsed_org, _extra) = meeting_ids_from_notification(&notification);
            if organizer.is_none() {
                organizer = parsed_org;
            }
            if !parsed_id.is_empty() && !meetings::looks_like_transcript_id(&parsed_id, None) {
                meeting_id = parsed_id;
            }
        }
        let mut resolved = meetings::resolve_meeting_reference(client, Some(&meeting_id), meeting_ref.join_web_url().as_deref(), meeting_ref.tenant_id.as_deref(), organizer.as_deref()).map_err(PipelineError::from)?;
        for (k, v) in &meeting_ref.metadata {
            resolved.metadata.entry(k.clone()).or_insert_with(|| v.clone());
        }
        if resolved.organizer_user_id.is_none() {
            resolved.organizer_user_id = meeting_ref.organizer_user_id.clone();
        }
        self.persist(job, json!({"meeting_ref": resolved.to_value()}))?;
        Ok((resolved, notification))
    }

    /// Transcript first, then the recording → STT fallback.
    fn obtain_transcript(&mut self, job: &mut Job, r: &TeamsMeetingRef, client: &Client, artifacts: &mut Vec<MeetingArtifact>) -> Result<Option<String>, PipelineError> {
        let mut transcript: Option<String> = None;
        if self.config.transcript_preferred {
            self.status(job, "fetching_transcript")?;
            let (artifact, text) = meetings::fetch_preferred_transcript_text(client, r).map_err(PipelineError::from)?;
            if let (Some(a), Some(t)) = (artifact, text) {
                if t.trim().len() >= self.config.transcript_min_chars || self.config.transcript_min_chars == 0 {
                    artifacts.push(a);
                    transcript = Some(t);
                }
            }
        }
        if transcript.is_some() {
            self.persist(job, json!({"selected_artifact_strategy": "transcript_first"}))?;
            return Ok(transcript);
        }
        if self.config.transcript_required {
            return Err(PipelineError::Retryable(format!("Transcript unavailable for meeting {}.", r.meeting_id)));
        }
        if !self.config.transcription_fallback {
            return Err(PipelineError::Retryable(format!("No transcript available and transcription fallback disabled for {}.", r.meeting_id)));
        }
        self.status(job, "downloading_recording")?;
        let recordings = meetings::list_recording_artifacts(client, r).map_err(PipelineError::from)?;
        let Some(recording) = recordings.into_iter().next() else {
            return Err(PipelineError::Retryable(format!("Recording unavailable for meeting {}.", r.meeting_id)));
        };
        artifacts.push(recording.clone());
        let text = self.transcribe_recording(job, r, &recording, client)?;
        self.persist(job, json!({"selected_artifact_strategy": "recording_stt_fallback"}))?;
        Ok(Some(text))
    }

    fn transcribe_recording(&mut self, job: &mut Job, r: &TeamsMeetingRef, recording: &MeetingArtifact, client: &Client) -> Result<String, PipelineError> {
        let root = self.config.tmp_dir.clone().unwrap_or_else(|| seagent_kernel::config::Paths::from_env().data.join("tmp").join("teams_pipeline"));
        std::fs::create_dir_all(&root).map_err(|e| PipelineError::Failed(format!("cannot create {}: {e}", root.display())))?;
        let dir = root.join(format!("teams-recording-{}", seagent_kernel::util::random_hex(6)));
        std::fs::create_dir_all(&dir).map_err(|e| PipelineError::Failed(format!("cannot create {}: {e}", dir.display())))?;
        let out = (|| -> Result<String, PipelineError> {
            // `display_name` is organizer-controlled Graph data: keep the basename only.
            let base = recording.display_name.clone().unwrap_or_else(|| format!("{}.mp4", recording.artifact_id));
            let name = Path::new(&base).file_name().map(|n| n.to_string_lossy().into_owned()).filter(|n| !matches!(n.as_str(), "" | "." | "..")).unwrap_or_else(|| format!("{}.mp4", recording.artifact_id));
            let path = dir.join(name);
            meetings::download_recording_artifact(client, r, recording, &path).map_err(PipelineError::from)?;
            let audio = self.prepare_audio_path(&path)?;
            self.status(job, "transcribing_audio")?;
            let text = (self.transcribe)(&audio, self.config.stt_model.as_deref()).map_err(PipelineError::Retryable)?.trim().to_string();
            if text.is_empty() {
                return Err(PipelineError::Retryable("STT returned an empty transcript.".into()));
            }
            Ok(text)
        })();
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    fn prepare_audio_path(&self, recording: &Path) -> Result<PathBuf, PipelineError> {
        let ext = recording.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        if AUDIO_SUFFIXES.contains(&ext.as_str()) || !self.config.ffmpeg_extract_audio {
            return Ok(recording.to_path_buf());
        }
        let ffmpeg = seagent_media::audio::ffmpeg().ok_or_else(|| PipelineError::Retryable("Recording fallback requires ffmpeg for audio extraction, but ffmpeg was not found.".into()))?;
        let audio = recording.with_extension("wav");
        let out = seagent_core::platform::proc::command(ffmpeg).arg("-y").arg("-i").arg(recording).arg(&audio).stdin(std::process::Stdio::null()).output().map_err(|e| PipelineError::Retryable(format!("ffmpeg audio extraction failed: {e}")))?;
        if !out.status.success() {
            return Err(PipelineError::Retryable(format!("ffmpeg audio extraction failed: {}", String::from_utf8_lossy(&out.stderr).trim())));
        }
        Ok(audio)
    }

    fn write_sinks(&mut self, job: &mut Job, payload: &SummaryPayload, _client: &Client) -> Result<(), PipelineError> {
        // (sink, status word while it runs, its config table).
        type SinkSpec<'a> = (SinkKind, &'a str, Option<Map<String, Value>>);
        let sinks: [SinkSpec; 3] = [
            (SinkKind::Notion, "writing_notion", self.config.notion.clone()),
            (SinkKind::Linear, "writing_linear", self.config.linear.clone()),
            (SinkKind::Teams, "sending_teams", self.config.teams_delivery.clone()),
        ];
        for (kind, status, config) in sinks {
            let Some(config) = config else { continue };
            let enabled = config.get("enabled").and_then(Value::as_bool).unwrap_or(false);
            if !enabled {
                continue;
            }
            self.status(job, status)?;
            let key = format!("{}:{}", sink_name(kind), payload.meeting_ref.meeting_id);
            let existing = self.store.get_sink_record(&key);
            let record = (self.sink)(kind, payload, &config, existing.as_ref()).map_err(PipelineError::Sink)?;
            self.store.upsert_sink_record(&key, &record).map_err(PipelineError::Failed)?;
        }
        Ok(())
    }
}

pub fn sink_name(kind: SinkKind) -> &'static str {
    match kind {
        SinkKind::Notion => "notion",
        SinkKind::Linear => "linear",
        SinkKind::Teams => "teams",
    }
}

/// Default summariser: the agent's own model when one is installed (upstream
/// `async_call_llm(task="call", temperature=0.2, max_tokens=900)`), else an error so the caller
/// falls back to [`heuristic_summary`].
fn default_summarize(r: &TeamsMeetingRef, transcript: &str, artifacts: &[MeetingArtifact]) -> Result<String, String> {
    let llm = seagent_media::llm().ok_or("no LLM installed")?;
    let prompt = build_summary_prompt(r, transcript, artifacts);
    llm.complete(None, SUMMARY_SYSTEM_PROMPT, vec![seagent_core::Message::user(prompt)], 900, &seagent_core::Cancel::new())
}

/// Default STT: seagent-media's `[media.stt]` chain on the downloaded audio.
fn default_transcribe(path: &Path, model: Option<&str>) -> Result<String, String> {
    let paths = seagent_kernel::config::Paths::from_env();
    let media = crate::meetings::media(&paths).ok_or("no [media] configuration for STT")?;
    let _ = model;
    seagent_media::stt::transcribe_file(&media, path, &seagent_core::Cancel::new()).map(|(text, _)| text)
}

/// Default sinks: Notion / Linear HTTP writers, and Teams delivery through
/// [`super::sinks::teams_write`] (incoming webhook, or a Graph chat/channel message — upstream
/// `plugins/platforms/teams/summary_writer.py`). Graph mode needs credentials: a host that has the
/// `[meetings.teams]` client injects its own sink (`super::deliver`), this path falls back to the
/// `MSGRAPH_*` environment like upstream's `MicrosoftGraphTokenProvider.from_env()`.
pub fn default_sink(kind: SinkKind, payload: &SummaryPayload, config: &Map<String, Value>, existing: Option<&Value>) -> Result<Value, String> {
    match kind {
        SinkKind::Notion => super::sinks::notion_write(payload, config, existing),
        SinkKind::Linear => super::sinks::linear_write(payload, config, existing),
        SinkKind::Teams => {
            let client = Client::from_config(&toml::Table::new(), &|_: &str| None).ok();
            super::sinks::teams_write(payload, config, existing, client.as_ref())
        }
    }
}

/// `_compact_job` for the CLI: the transcript becomes a 240-char preview.
pub fn compact_job(job: &Value) -> Value {
    let mut out = job.clone();
    let mut empty = false;
    if let Some(summary) = out.get_mut("summary_payload").and_then(Value::as_object_mut) {
        if let Some(text) = summary.remove("transcript_text").and_then(|t| t.as_str().map(str::to_string)) {
            summary.insert("transcript_preview".into(), json!(text.chars().take(240).collect::<String>()));
        }
        empty = summary.is_empty();
    }
    if empty {
        if let Some(o) = out.as_object_mut() {
            o.insert("summary_payload".into(), Value::Null);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_parsing_tolerates_prose_and_falls_back() {
        let parsed = parse_summary_json("Sure! ```json\n{\"summary\": \"We shipped it.\", \"key_decisions\": [\"ship\"], \"action_items\": [\"  write docs  \", \"\"], \"risks\": [], \"confidence\": \"high\", \"confidence_notes\": \"clear audio\"}\n```");
        assert_eq!(parsed["summary"], "We shipped it.");
        assert_eq!(parsed["key_decisions"], json!(["ship"]));
        assert_eq!(parsed["action_items"], json!(["write docs"]), "items are trimmed and blanks dropped");
        assert_eq!(parsed["confidence"], "high");
        let h = parse_summary_json("no json here");
        assert_eq!(h["confidence"], "low", "short/absent transcript → heuristic");
        let h = heuristic_summary("Action: send the deck\nWe decided to ship\nRisk: none this week\nfiller line");
        assert_eq!(h["action_items"], json!(["Action: send the deck"]));
        assert_eq!(h["key_decisions"], json!(["We decided to ship"]));
        assert_eq!(h["risks"], json!(["Risk: none this week"]));
        assert_eq!(h["confidence"], "low");
    }

    #[test]
    fn notification_ids_prefer_resource_paths() {
        let n = json!({"id": "n1", "resource": "/users/u1/onlineMeetings/MS1/transcripts/T1", "changeType": "created"});
        let (id, org, extra) = meeting_ids_from_notification(&n);
        assert_eq!((id.as_str(), org.as_deref(), extra["transcript_id"].as_str()), ("MS1", Some("u1"), Some("T1")));
        // Only an artifact id: the meeting id falls back to it.
        let n = json!({"resource": "communications/onlineMeetings/getAllTranscripts", "resourceData": {"id": "VjFfVHJhbnNjcmlwdFYy", "meetingId": "MS2"}});
        assert_eq!(meeting_ids_from_notification(&n).0, "MS2");
        // Nothing usable at all: the receipt key keeps the job addressable.
        let n = json!({"resource": "unknown", "resourceData": {}});
        assert!(meeting_ids_from_notification(&n).0.starts_with("sha256:"));
    }

    #[test]
    fn markdown_and_prompt_shape() {
        let p = SummaryPayload {
            meeting_ref: TeamsMeetingRef { meeting_id: "M1".into(), ..Default::default() },
            title: Some("Weekly".into()),
            summary: Some("ok".into()),
            key_decisions: vec!["ship".into()],
            ..Default::default()
        };
        let md = render_summary_markdown(&p);
        assert!(md.starts_with("# Weekly\n\n## Summary\nok\n\n## Key Decisions\n- ship\n\n## Action Items\n- None"), "{md}");
        assert!(md.ends_with("Confidence: unknown"));
        let prompt = build_summary_prompt(&TeamsMeetingRef { meeting_id: "M1".into(), ..Default::default() }, "hello", &[]);
        assert!(prompt.contains("Meeting ID: M1") && prompt.contains("Artifacts:\n- none") && prompt.contains("Transcript:\nhello"));
    }
}
