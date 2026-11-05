//! Graph-backed Teams meeting helpers (Hermes `plugins/teams_pipeline/meetings.py`, MIT).
//!
//! Parses organizer / meeting / artifact ids out of Graph resource paths and `@odata.id`s (both
//! the `users/{id}/…` and the `users('{id}')/…` flavours), resolves a meeting reference (by id,
//! or by join URL through `$filter=JoinWebUrl eq '…'`), lists and downloads transcripts and
//! recordings, and enriches a meeting with its call record when the tenant grants
//! `CallRecords.Read.All`.

use super::graph::{Client, GraphError};
use super::models::{MeetingArtifact, TeamsMeetingRef};
use ark_tools::web::http::enc;
use ark_tools::web::ssrf::percent_decode;
use regex::Regex;
use serde_json::{json, Map, Value};
use std::path::Path;
use std::sync::OnceLock;

/// Resource-path parsing failures, mapped onto the pipeline's retryable/terminal split.
#[derive(Debug, Clone, PartialEq)]
pub enum MeetingsError {
    /// The meeting (or a requested artifact) does not exist — retry later.
    NotFound(String),
    /// Graph denied the call (401/403).
    Permission(String),
    /// The artifact exists but has no usable content — retry later.
    ArtifactNotFound(String),
    Other(String),
}

impl MeetingsError {
    pub fn message(&self) -> &str {
        match self {
            MeetingsError::NotFound(m) | MeetingsError::Permission(m) | MeetingsError::ArtifactNotFound(m) | MeetingsError::Other(m) => m,
        }
    }
}

impl std::fmt::Display for MeetingsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

fn wrap(err: GraphError, missing: &str) -> MeetingsError {
    if err.is_permission() {
        return MeetingsError::Permission(err.message);
    }
    if err.is_missing() {
        return MeetingsError::NotFound(missing.to_string());
    }
    MeetingsError::Other(err.message)
}

fn users_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(?:^|/)users(?:\('([^']+)'\)|/([^/'()]+))/onlineMeetings(?:\('([^']+)'\)|/([^/'?]+))").expect("users regex"))
}

fn comm_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(?:^|/)communications/onlineMeetings(?:\('([^']+)'\)|/([^/'?]+))").expect("communications regex"))
}

fn transcript_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)/transcripts(?:\('([^']+)'\)|/([^/'?]+))").expect("transcript regex"))
}

fn recording_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)/recordings(?:\('([^']+)'\)|/([^/'?]+))").expect("recording regex"))
}

/// Collection function names the meeting regex can capture in place of a real meeting id.
const RESOURCE_SENTINELS: &[&str] = &["getalltranscripts", "getallrecordings", "transcripts", "recordings"];

fn match_id(re: Option<&Regex>, text: &str, groups: &[usize]) -> Option<String> {
    let caps = re?.captures(text)?;
    groups.iter().find_map(|g| caps.get(*g)).map(|m| percent_decode(m.as_str())).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Organizer / meeting / artifact ids found in a Graph resource path or `@odata.id`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ParsedResource {
    pub organizer_user_id: Option<String>,
    pub meeting_id: Option<String>,
    pub transcript_id: Option<String>,
    pub recording_id: Option<String>,
}

pub fn parse_graph_meeting_resource(resource: &str) -> ParsedResource {
    let text = resource.trim();
    let users = users_re().captures(text).map(|c| {
        let get = |i: usize| c.get(i).map(|m| m.as_str().to_string());
        (get(1).or_else(|| get(2)), get(3).or_else(|| get(4)))
    });
    let (organizer, mut meeting) = users.unwrap_or((None, None));
    if meeting.is_none() {
        meeting = match_id(Some(comm_re()), text, &[1, 2]);
    }
    let meeting_id = meeting.map(|m| percent_decode(&m).trim().to_string()).filter(|m| !m.is_empty() && !RESOURCE_SENTINELS.contains(&m.to_lowercase().as_str()));
    ParsedResource {
        organizer_user_id: organizer.map(|o| percent_decode(&o).trim().to_string()).filter(|o| !o.is_empty()),
        meeting_id,
        transcript_id: match_id(Some(transcript_re()), text, &[1, 2]),
        recording_id: match_id(Some(recording_re()), text, &[1, 2]),
    }
}

/// True when a Graph id names a `callTranscript` artifact rather than an `onlineMeeting`.
pub fn looks_like_transcript_id(value: &str, odata_type: Option<&str>) -> bool {
    if odata_type.unwrap_or("").to_lowercase().contains("calltranscript") {
        return true;
    }
    let v = value.to_lowercase();
    v.contains("transcript") || decoded_id_hint(value).contains("transcript")
}

/// Best-effort base64 decode of a Graph id: `getAllTranscripts` `resourceData.id` blobs only carry
/// their `-TranscriptV2` marker in the decoded payload.
fn decoded_id_hint(value: &str) -> String {
    let stripped = value.trim();
    if stripped.len() < 16 {
        return String::new();
    }
    let padded = format!("{stripped}{}", "=".repeat((4 - stripped.len() % 4) % 4));
    for decode in [base64_decode_urlsafe as fn(&str) -> Option<Vec<u8>>, base64_decode_std] {
        if let Some(bytes) = decode(&padded) {
            return String::from_utf8_lossy(&bytes).to_lowercase();
        }
    }
    String::new()
}

fn base64_decode_std(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

fn base64_decode_urlsafe(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE.decode(s).ok()
}

fn organizer_user_id(payload: &Value) -> Option<String> {
    payload.get("organizer")?.get("identity")?.get("user")?.get("id")?.as_str().map(str::to_string).filter(|s| !s.trim().is_empty())
}

/// Organizer-scoped collection when the organizer is known (required for app-only access).
pub fn meetings_collection(organizer: Option<&str>) -> String {
    match organizer.map(str::trim).filter(|o| !o.is_empty()) {
        Some(o) => format!("/users/{}/onlineMeetings", enc(o)),
        None => "/communications/onlineMeetings".into(),
    }
}

pub fn meeting_path(r: &TeamsMeetingRef) -> String {
    format!("{}/{}", meetings_collection(r.organizer_user_id.as_deref()), enc(&r.meeting_id))
}

fn normalize_meeting_ref(payload: &Value, tenant_id: Option<&str>, organizer: Option<&str>) -> TeamsMeetingRef {
    let mut metadata = Map::new();
    for key in ["subject", "startDateTime", "endDateTime", "createdDateTime", "participants"] {
        if let Some(v) = payload.get(key).filter(|v| !v.is_null()) {
            metadata.insert(key.to_string(), v.clone());
        }
    }
    let thread_id = payload.get("chatInfo").and_then(|c| c.get("threadId")).and_then(Value::as_str).map(str::to_string).or_else(|| payload.get("threadId").and_then(Value::as_str).map(str::to_string));
    TeamsMeetingRef {
        meeting_id: payload.get("id").and_then(Value::as_str).unwrap_or("").trim().to_string(),
        organizer_user_id: organizer.map(str::to_string).or_else(|| organizer_user_id(payload)),
        join_web_url: payload.get("joinWebUrl").and_then(Value::as_str).map(str::to_string),
        calendar_event_id: payload.get("calendarEventId").and_then(Value::as_str).map(str::to_string),
        thread_id,
        tenant_id: tenant_id.map(str::to_string).or_else(|| payload.get("tenantId").and_then(Value::as_str).map(str::to_string)),
        metadata,
    }
}

fn normalize_artifact(kind: &str, payload: &Value) -> MeetingArtifact {
    let text = |keys: &[&str]| keys.iter().find_map(|k| payload.get(*k)).and_then(Value::as_str).map(str::to_string).filter(|s| !s.trim().is_empty());
    MeetingArtifact {
        artifact_type: kind.to_string(),
        artifact_id: payload.get("id").and_then(Value::as_str).unwrap_or("").trim().to_string(),
        display_name: text(&["displayName", "name"]),
        content_type: text(&["contentType", "fileMimeType"]),
        source_url: text(&["webUrl", "contentUrl"]),
        download_url: text(&["@microsoft.graph.downloadUrl", "downloadUrl", "recordingContentUrl", "transcriptContentUrl"]),
        created_at: text(&["createdDateTime"]),
        available_at: text(&["lastModifiedDateTime", "meetingEndDateTime"]),
        size_bytes: payload.get("size").and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))),
        metadata: payload.as_object().cloned().unwrap_or_default(),
    }
}

/// Resolve a meeting by id, or by join URL (`$filter=JoinWebUrl eq '…'`).
pub fn resolve_meeting_reference(client: &Client, meeting_id: Option<&str>, join_web_url: Option<&str>, tenant_id: Option<&str>, organizer_user_id: Option<&str>) -> Result<TeamsMeetingRef, MeetingsError> {
    let mut meeting_id = meeting_id.map(str::trim).filter(|m| !m.is_empty());
    let join_web_url = join_web_url.map(str::trim).filter(|u| !u.is_empty());
    if meeting_id.is_some_and(|m| looks_like_transcript_id(m, None)) {
        if join_web_url.is_none() {
            return Err(MeetingsError::Other("Refusing to GET /communications/onlineMeetings/{id} with a transcript id. Graph v1.0 does not support that id format; use the organizer-scoped meeting id from the notification @odata.id, or a join URL.".into()));
        }
        meeting_id = None;
    }
    let collection = meetings_collection(organizer_user_id);
    let payload = if let Some(id) = meeting_id {
        let missing = format!("Teams meeting not found: {id}");
        let v = client.get_json(&format!("{collection}/{}", enc(id)), &[]).map_err(|e| wrap(e, &missing))?;
        if !v.is_object() || v.get("id").and_then(Value::as_str).unwrap_or("").is_empty() {
            return Err(MeetingsError::NotFound(missing));
        }
        v
    } else if let Some(url) = join_web_url {
        let missing = format!("Teams meeting not found for join URL: {url}");
        let filter = format!("JoinWebUrl eq '{}'", url.replace('\'', "''"));
        let listing = client.get_json(&collection, &[("$filter", filter)]).map_err(|e| wrap(e, &missing))?;
        let candidate = listing.get("value").and_then(Value::as_array).and_then(|a| a.first()).cloned();
        candidate.ok_or(MeetingsError::NotFound(missing))?
    } else {
        return Err(MeetingsError::Other("Either meeting_id or join_web_url is required.".into()));
    };
    let r = normalize_meeting_ref(&payload, tenant_id, organizer_user_id);
    if r.meeting_id.is_empty() {
        return Err(MeetingsError::NotFound("Teams meeting not found".into()));
    }
    Ok(r)
}

fn list_artifacts(client: &Client, r: &TeamsMeetingRef, kind: &str) -> Result<Vec<MeetingArtifact>, MeetingsError> {
    let collection = format!("{kind}s");
    let items = client.collect_paginated(&format!("{}/{collection}", meeting_path(r)), &[]).map_err(|e| wrap(e, &format!("No {collection} found for Teams meeting {}", r.meeting_id)))?;
    Ok(items.iter().filter(|v| v.is_object()).map(|v| normalize_artifact(kind, v)).collect())
}

pub fn list_transcript_artifacts(client: &Client, r: &TeamsMeetingRef) -> Result<Vec<MeetingArtifact>, MeetingsError> {
    list_artifacts(client, r, "transcript")
}

pub fn list_recording_artifacts(client: &Client, r: &TeamsMeetingRef) -> Result<Vec<MeetingArtifact>, MeetingsError> {
    list_artifacts(client, r, "recording")
}

/// Prefer completed, downloadable, most recent transcripts (in that priority order).
fn transcript_sort_key(a: &MeetingArtifact) -> (u8, u8, String) {
    let status = a.metadata.get("status").and_then(Value::as_str).unwrap_or("").to_lowercase();
    let has_download = u8::from(a.download_url.is_some() || a.source_url.is_some());
    let completed = u8::from(matches!(status.as_str(), "available" | "completed" | "succeeded"));
    let stamp = a.available_at.clone().or_else(|| a.created_at.clone()).unwrap_or_default();
    (completed, has_download, stamp)
}

pub fn select_preferred_transcript(candidates: &[MeetingArtifact]) -> Option<MeetingArtifact> {
    candidates.iter().filter(|a| a.artifact_type == "transcript").max_by_key(|a| transcript_sort_key(a)).cloned()
}

/// Download one artifact to `dest` (streams; `dest` is replaced atomically).
fn download_artifact(client: &Client, r: &TeamsMeetingRef, a: &MeetingArtifact, dest: &Path, kind: &str) -> Result<u64, MeetingsError> {
    let path = a.download_url.clone().unwrap_or_else(|| format!("{}/{kind}s/{}/content", meeting_path(r), enc(&a.artifact_id)));
    client.download_to_file(&path, dest).map_err(|e| wrap(e, &format!("{kind} {} not found for meeting {}", a.artifact_id, r.meeting_id)))
}

pub fn download_transcript_text(client: &Client, r: &TeamsMeetingRef, t: &MeetingArtifact) -> Result<String, MeetingsError> {
    // Unique per call: two pipeline runs (tests, a duplicate delivery) must not delete each other's file.
    let guard = ark_core::tmp::TempDir::new("ark-teams-transcript");
    let dir = guard.path().to_path_buf();
    std::fs::create_dir_all(&dir).map_err(|e| MeetingsError::Other(format!("cannot create {}: {e}", dir.display())))?;
    let dest = dir.join("transcript.vtt");
    let r2 = download_artifact(client, r, t, &dest, "transcript");
    let text = match r2 {
        Ok(_) => std::fs::read_to_string(&dest).map(|s| s.trim().to_string()).map_err(|e| MeetingsError::Other(format!("cannot read transcript: {e}"))),
        Err(e) => Err(e),
    };
    let _ = std::fs::remove_dir_all(&dir);
    let text = text?;
    if text.is_empty() {
        return Err(MeetingsError::ArtifactNotFound(format!("Transcript {} for meeting {} was empty.", t.artifact_id, r.meeting_id)));
    }
    Ok(text)
}

pub fn fetch_preferred_transcript_text(client: &Client, r: &TeamsMeetingRef) -> Result<(Option<MeetingArtifact>, Option<String>), MeetingsError> {
    let Some(t) = select_preferred_transcript(&list_transcript_artifacts(client, r)?) else { return Ok((None, None)) };
    match download_transcript_text(client, r, &t) {
        Ok(text) => Ok((Some(t), Some(text))),
        Err(MeetingsError::ArtifactNotFound(_)) => Ok((None, None)),
        Err(e) => Err(e),
    }
}

pub fn download_recording_artifact(client: &Client, r: &TeamsMeetingRef, recording: &MeetingArtifact, dest: &Path) -> Result<u64, MeetingsError> {
    download_artifact(client, r, recording, dest, "recording")
}

/// Call records need `CallRecords.Read.All`, so a denial is soft (`None`), as upstream.
pub fn enrich_meeting_with_call_record(client: &Client, r: &TeamsMeetingRef, call_record_id: Option<&str>) -> Result<Option<MeetingArtifact>, MeetingsError> {
    let id = call_record_id.map(str::to_string).or_else(|| r.metadata.get("call_record_id").and_then(Value::as_str).map(str::to_string)).unwrap_or_default();
    if id.trim().is_empty() {
        return Ok(None);
    }
    let payload = match client.get_json(&format!("/communications/callRecords/{}", enc(id.trim())), &[]) {
        Ok(v) => v,
        Err(e) if e.is_missing() || e.is_permission() => return Ok(None),
        Err(e) => return Err(wrap(e, &format!("Call record not found: {id}"))),
    };
    let Some(record_id) = payload.get("id").and_then(Value::as_str).map(str::to_string) else { return Ok(None) };
    let mut metrics = Map::new();
    metrics.insert("version".into(), payload.get("version").cloned().unwrap_or(Value::Null));
    metrics.insert("modalities".into(), payload.get("modalities").cloned().unwrap_or(Value::Null));
    metrics.insert("participant_count".into(), json!(payload.get("participants").and_then(Value::as_array).map(Vec::len).unwrap_or(0)));
    metrics.insert("organizer".into(), organizer_user_id(&payload).map(|s| json!(s)).unwrap_or(Value::Null));
    if let Some(sessions) = payload.get("sessions").and_then(Value::as_array) {
        metrics.insert("session_count".into(), json!(sessions.len()));
    }
    let mut metadata = Map::new();
    metadata.insert("call_record".into(), payload.clone());
    metadata.insert("metrics".into(), Value::Object(metrics));
    Ok(Some(MeetingArtifact {
        artifact_type: "call_record".into(),
        artifact_id: record_id,
        display_name: payload.get("type").and_then(Value::as_str).map(str::to_string).or_else(|| Some("call_record".into())),
        source_url: payload.get("webUrl").and_then(Value::as_str).map(str::to_string),
        created_at: payload.get("startDateTime").and_then(Value::as_str).map(str::to_string),
        available_at: payload.get("endDateTime").and_then(Value::as_str).map(str::to_string),
        metadata,
        ..Default::default()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_users_and_communications_resource_paths() {
        let p = parse_graph_meeting_resource("/users/8a1b/onlineMeetings/MS1/transcripts/T1");
        assert_eq!((p.organizer_user_id.as_deref(), p.meeting_id.as_deref(), p.transcript_id.as_deref()), (Some("8a1b"), Some("MS1"), Some("T1")));
        let q = parse_graph_meeting_resource("communications/onlineMeetings('M%20S2')/recordings('R%201')");
        assert_eq!((q.organizer_user_id.as_deref(), q.meeting_id.as_deref(), q.recording_id.as_deref()), (None, Some("M S2"), Some("R 1")));
        // Collection function names are not meeting ids.
        let r = parse_graph_meeting_resource("/users/u1/onlineMeetings/getAllTranscripts");
        assert_eq!(r.meeting_id, None);
        assert_eq!(r.organizer_user_id.as_deref(), Some("u1"));
        assert_eq!(parse_graph_meeting_resource("@odata.id").meeting_id, None);
    }

    #[test]
    fn detects_transcript_ids_including_base64_payloads() {
        assert!(looks_like_transcript_id("VjFfVHJhbnNjcmlwdFYy", Some("")));
        assert!(looks_like_transcript_id("x-transcript-1", None));
        assert!(looks_like_transcript_id("whatever", Some("#microsoft.graph.callTranscript")));
        // "MS1" base64-decodes to bytes without the marker.
        assert!(!looks_like_transcript_id("TS1", None));
        assert!(!looks_like_transcript_id("", None));
    }

    #[test]
    fn paths_and_transcript_choice() {
        let r = TeamsMeetingRef { meeting_id: "M S1".into(), organizer_user_id: Some("u/1".into()), ..Default::default() };
        assert_eq!(meeting_path(&r), "/users/u%2F1/onlineMeetings/M%20S1");
        assert_eq!(meetings_collection(None), "/communications/onlineMeetings");
        let art = |id: &str, status: &str, url: Option<&str>, at: &str| MeetingArtifact {
            artifact_type: "transcript".into(),
            artifact_id: id.into(),
            download_url: url.map(str::to_string),
            available_at: Some(at.into()),
            metadata: [("status".to_string(), json!(status))].into_iter().collect(),
            ..Default::default()
        };
        let picked = select_preferred_transcript(&[art("old", "failed", None, "2026-01-01T00:00:00Z"), art("new", "completed", Some("https://d"), "2025-01-01T00:00:00Z"), art("mid", "completed", Some("https://d"), "2026-02-01T00:00:00Z")]).unwrap();
        assert_eq!(picked.artifact_id, "mid", "completed+downloadable+newest wins");
        assert!(select_preferred_transcript(&[]).is_none());
    }
}
