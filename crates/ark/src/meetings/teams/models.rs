//! Normalized models for the Teams meeting pipeline (Hermes `plugins/teams_pipeline/models.py`,
//! MIT).
//!
//! Rust fields keep upstream's snake_case names; reading accepts both snake_case and camelCase
//! keys (Graph payloads and jobs persisted by older versions use either) and writing drops
//! null/empty fields, exactly like upstream's `_Model.to_dict`. Timestamps stay ISO-8601 strings
//! (no date crate): [`parse_iso`] / [`iso_z`] convert to and from epoch seconds for comparisons.

use serde_json::{json, Map, Value};

/// Epoch seconds from an ISO-8601 timestamp (`Z`, `+HH:MM` or naive = UTC), second precision.
pub fn parse_iso(text: &str) -> Option<i64> {
    let t = text.trim();
    let (date, rest) = t.split_once(['T', ' '])?;
    let mut d = date.split('-');
    let (y, m, day): (i64, u32, u32) = (d.next()?.parse().ok()?, d.next()?.parse().ok()?, d.next()?.parse().ok()?);
    let rest = rest.trim_end_matches('Z');
    let (clock, offset) = match rest.find(['+', '-']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "+00:00"),
    };
    let mut c = clock.split(':');
    let hh: i64 = c.next()?.parse().ok()?;
    let mm: i64 = c.next().unwrap_or("0").parse().ok()?;
    let ss: i64 = c.next().unwrap_or("0").split('.').next().unwrap_or("0").parse().ok()?;
    if offset.len() < 6 {
        return None;
    }
    let oh: i64 = offset.get(1..3)?.parse().ok()?;
    let om: i64 = offset.get(4..6)?.parse().ok()?;
    let sign = if offset.starts_with('-') { -1 } else { 1 };
Some(ark_kernel::util::days_from_civil(y, m, day) * 86400 + hh * 3600 + mm * 60 + ss - sign * (oh * 3600 + om * 60))
}

/// `YYYY-MM-DDTHH:MM:SSZ` for epoch seconds (Graph's `expirationDateTime` shape).
pub fn iso_z(secs: i64) -> String {
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    let (y, m, d) = ark_kernel::util::civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// `payload[k] or payload[camelCase(k)]`, taking the first *truthy* value (upstream `_pick`).
fn pick<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    let o = v.as_object()?;
    let mut last = None;
    for k in keys {
        let x = o.get(*k);
        if let Some(x) = x.filter(|x| truthy(x)) {
            return Some(x);
        }
        last = x.or(last);
    }
    last.filter(|x| truthy(x))
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::String(s) => !s.trim().is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

fn text(v: &Value, keys: &[&str]) -> String {
    match pick(v, keys) {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(x) if !x.is_null() => x.to_string().trim_matches('"').trim().to_string(),
        _ => String::new(),
    }
}

fn opt_text(v: &Value, keys: &[&str]) -> Option<String> {
    Some(text(v, keys)).filter(|s| !s.is_empty())
}

fn strings(v: &Value, keys: &[&str]) -> Vec<String> {
    pick(v, keys)
        .and_then(Value::as_array)
        .map(|a| a.iter().map(|x| x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string())).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default()
}

fn map_of(v: &Value, keys: &[&str]) -> Map<String, Value> {
    pick(v, keys).and_then(Value::as_object).cloned().unwrap_or_default()
}

fn compact(pairs: Vec<(&str, Value)>) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        let empty = match &v {
            Value::Null => true,
            Value::String(s) => s.is_empty(),
            Value::Array(a) => a.is_empty(),
            Value::Object(o) => o.is_empty(),
            _ => false,
        };
        if !empty {
            m.insert(k.to_string(), v);
        }
    }
    Value::Object(m)
}

fn s(v: &Option<String>) -> Value {
    v.as_ref().map(|x| json!(x)).unwrap_or(Value::Null)
}

/// A Teams meeting reference (`onlineMeetings` resource).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TeamsMeetingRef {
    pub meeting_id: String,
    pub organizer_user_id: Option<String>,
    pub join_web_url: Option<String>,
    pub calendar_event_id: Option<String>,
    pub thread_id: Option<String>,
    pub tenant_id: Option<String>,
    pub metadata: Map<String, Value>,
}

impl TeamsMeetingRef {
    /// `meeting_id` is required (upstream `_REQUIRED`); aliases `id`.
    pub fn from_value(v: &Value) -> Result<TeamsMeetingRef, String> {
        let meeting_id = text(v, &["meeting_id", "id"]);
        if meeting_id.is_empty() {
            return Err("TeamsMeetingRef.meeting_id is required.".into());
        }
        Ok(TeamsMeetingRef {
            meeting_id,
            organizer_user_id: opt_text(v, &["organizer_user_id", "organizerUserId"]),
            join_web_url: opt_text(v, &["join_web_url", "joinWebUrl"]),
            calendar_event_id: opt_text(v, &["calendar_event_id", "calendarEventId"]),
            thread_id: opt_text(v, &["thread_id", "threadId"]),
            tenant_id: opt_text(v, &["tenant_id", "tenantId"]),
            metadata: map_of(v, &["metadata"]),
        })
    }
    pub fn to_value(&self) -> Value {
        compact(vec![
            ("meeting_id", json!(self.meeting_id)),
            ("organizer_user_id", s(&self.organizer_user_id)),
            ("join_web_url", s(&self.join_web_url)),
            ("calendar_event_id", s(&self.calendar_event_id)),
            ("thread_id", s(&self.thread_id)),
            ("tenant_id", s(&self.tenant_id)),
            ("metadata", Value::Object(self.metadata.clone())),
        ])
    }
    pub fn subject(&self) -> Option<String> {
        self.metadata.get("subject").and_then(Value::as_str).map(str::to_string)
    }
    pub fn join_web_url(&self) -> Option<String> {
        self.join_web_url.clone().or_else(|| self.metadata.get("join_web_url").and_then(Value::as_str).map(str::to_string))
    }
}

/// A transcript, recording or call record attached to a meeting.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MeetingArtifact {
    /// `transcript` | `recording` | `call_record`.
    pub artifact_type: String,
    pub artifact_id: String,
    pub display_name: Option<String>,
    pub content_type: Option<String>,
    pub source_url: Option<String>,
    pub download_url: Option<String>,
    pub created_at: Option<String>,
    pub available_at: Option<String>,
    pub size_bytes: Option<u64>,
    pub metadata: Map<String, Value>,
}

pub const ARTIFACT_TYPES: &[&str] = &["transcript", "recording", "call_record"];

impl MeetingArtifact {
    pub fn from_value(v: &Value) -> Result<MeetingArtifact, String> {
        let artifact_type = text(v, &["artifact_type", "artifactType"]);
        if !ARTIFACT_TYPES.contains(&artifact_type.as_str()) {
            return Err("MeetingArtifact.artifact_type must be transcript, recording, or call_record.".into());
        }
        let artifact_id = text(v, &["artifact_id", "id"]);
        if artifact_id.is_empty() {
            return Err("MeetingArtifact.artifact_id is required.".into());
        }
        let size = pick(v, &["size_bytes", "size"]).and_then(|x| x.as_u64().or_else(|| x.as_str().and_then(|s| s.trim().parse().ok())));
        Ok(MeetingArtifact {
            artifact_type,
            artifact_id,
            display_name: opt_text(v, &["display_name", "displayName", "name"]),
            content_type: opt_text(v, &["content_type", "contentType", "fileMimeType"]),
            source_url: opt_text(v, &["source_url", "sourceUrl", "webUrl", "contentUrl"]),
            download_url: opt_text(v, &["download_url", "downloadUrl", "@microsoft.graph.downloadUrl"]),
            created_at: opt_text(v, &["created_at", "createdDateTime"]),
            available_at: opt_text(v, &["available_at", "availableDateTime", "lastModifiedDateTime"]),
            size_bytes: size,
            metadata: map_of(v, &["metadata"]),
        })
    }
    pub fn to_value(&self) -> Value {
        compact(vec![
            ("artifact_type", json!(self.artifact_type)),
            ("artifact_id", json!(self.artifact_id)),
            ("display_name", s(&self.display_name)),
            ("content_type", s(&self.content_type)),
            ("source_url", s(&self.source_url)),
            ("download_url", s(&self.download_url)),
            ("created_at", s(&self.created_at)),
            ("available_at", s(&self.available_at)),
            ("size_bytes", self.size_bytes.map(|n| json!(n)).unwrap_or(Value::Null)),
            ("metadata", Value::Object(self.metadata.clone())),
        ])
    }
}

/// The summary stored on a job and handed to the output sinks.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SummaryPayload {
    pub meeting_ref: TeamsMeetingRef,
    pub title: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub participants: Vec<String>,
    pub transcript_text: Option<String>,
    pub summary: Option<String>,
    pub key_decisions: Vec<String>,
    pub action_items: Vec<String>,
    pub risks: Vec<String>,
    pub call_metrics: Map<String, Value>,
    pub source_artifacts: Vec<MeetingArtifact>,
    pub confidence: Option<String>,
    pub confidence_notes: Option<String>,
    pub notion_target: Option<String>,
    pub linear_target: Option<String>,
    pub teams_target: Option<String>,
}

impl SummaryPayload {
    /// `meeting_ref` is mandatory: a missing key is an error, not a half-empty payload.
    pub fn from_value(v: &Value) -> Result<SummaryPayload, String> {
        let meeting_ref = v.get("meeting_ref").ok_or("SummaryPayload.meeting_ref is required.")?;
        Ok(SummaryPayload {
            meeting_ref: TeamsMeetingRef::from_value(meeting_ref)?,
            title: opt_text(v, &["title"]),
            start_time: opt_text(v, &["start_time", "startTime"]),
            end_time: opt_text(v, &["end_time", "endTime"]),
            participants: strings(v, &["participants"]),
            transcript_text: opt_text(v, &["transcript_text", "transcriptText"]),
            summary: opt_text(v, &["summary"]),
            key_decisions: strings(v, &["key_decisions", "keyDecisions"]),
            action_items: strings(v, &["action_items", "actionItems"]),
            risks: strings(v, &["risks"]),
            call_metrics: map_of(v, &["call_metrics", "callMetrics"]),
            source_artifacts: pick(v, &["source_artifacts", "sourceArtifacts"]).and_then(Value::as_array).map(|a| a.iter().filter_map(|x| MeetingArtifact::from_value(x).ok()).collect()).unwrap_or_default(),
            confidence: opt_text(v, &["confidence"]),
            confidence_notes: opt_text(v, &["confidence_notes", "confidenceNotes"]),
            notion_target: opt_text(v, &["notion_target", "notionTarget"]),
            linear_target: opt_text(v, &["linear_target", "linearTarget"]),
            teams_target: opt_text(v, &["teams_target", "teamsTarget"]),
        })
    }
    pub fn to_value(&self) -> Value {
        compact(vec![
            ("meeting_ref", self.meeting_ref.to_value()),
            ("title", s(&self.title)),
            ("start_time", s(&self.start_time)),
            ("end_time", s(&self.end_time)),
            ("participants", json!(self.participants)),
            ("transcript_text", s(&self.transcript_text)),
            ("summary", s(&self.summary)),
            ("key_decisions", json!(self.key_decisions)),
            ("action_items", json!(self.action_items)),
            ("risks", json!(self.risks)),
            ("call_metrics", Value::Object(self.call_metrics.clone())),
            ("source_artifacts", Value::Array(self.source_artifacts.iter().map(|a| a.to_value()).collect())),
            ("confidence", s(&self.confidence)),
            ("confidence_notes", s(&self.confidence_notes)),
            ("notion_target", s(&self.notion_target)),
            ("linear_target", s(&self.linear_target)),
            ("teams_target", s(&self.teams_target)),
        ])
    }
}

/// One durable pipeline run.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Job {
    pub job_id: String,
    pub event_id: String,
    pub source_event_type: String,
    pub dedupe_key: String,
    pub status: String,
    pub retry_count: u32,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub meeting_ref: Option<TeamsMeetingRef>,
    pub selected_artifact_strategy: Option<String>,
    pub summary_payload: Option<SummaryPayload>,
    pub error_info: Map<String, Value>,
}

impl Job {
    /// Required fields: job_id, event_id, source_event_type, dedupe_key, status.
    pub fn from_value(v: &Value) -> Result<Job, String> {
        let req = |k: &str| -> Result<String, String> {
            let s = text(v, &[k]);
            if s.is_empty() {
                Err(format!("TeamsMeetingPipelineJob.{k} is required."))
            } else {
                Ok(s)
            }
        };
        Ok(Job {
            job_id: req("job_id")?,
            event_id: req("event_id")?,
            source_event_type: req("source_event_type")?,
            dedupe_key: req("dedupe_key")?,
            status: req("status")?,
            retry_count: pick(v, &["retry_count", "retryCount"]).and_then(Value::as_u64).unwrap_or(0) as u32,
            created_at: opt_text(v, &["created_at", "createdAt"]),
            updated_at: opt_text(v, &["updated_at", "updatedAt"]),
            meeting_ref: pick(v, &["meeting_ref", "meetingRef"]).and_then(|x| TeamsMeetingRef::from_value(x).ok()),
            selected_artifact_strategy: opt_text(v, &["selected_artifact_strategy", "selectedArtifactStrategy"]),
            summary_payload: pick(v, &["summary_payload", "summaryPayload"]).and_then(|x| SummaryPayload::from_value(x).ok()),
            error_info: map_of(v, &["error_info", "errorInfo"]),
        })
    }
    pub fn to_value(&self) -> Value {
        compact(vec![
            ("job_id", json!(self.job_id)),
            ("event_id", json!(self.event_id)),
            ("source_event_type", json!(self.source_event_type)),
            ("dedupe_key", json!(self.dedupe_key)),
            ("status", json!(self.status)),
            ("retry_count", json!(self.retry_count)),
            ("created_at", s(&self.created_at)),
            ("updated_at", s(&self.updated_at)),
            ("meeting_ref", self.meeting_ref.as_ref().map(|m| m.to_value()).unwrap_or(Value::Null)),
            ("selected_artifact_strategy", s(&self.selected_artifact_strategy)),
            ("summary_payload", self.summary_payload.as_ref().map(|p| p.to_value()).unwrap_or(Value::Null)),
            ("error_info", Value::Object(self.error_info.clone())),
        ])
    }
}

/// A Microsoft Graph change subscription as stored locally.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GraphSubscription {
    pub subscription_id: String,
    pub resource: String,
    pub change_type: String,
    pub notification_url: String,
    pub expiration_datetime: String,
    pub client_state: Option<String>,
    pub latest_renewal_at: Option<String>,
    pub status: Option<String>,
}

impl GraphSubscription {
    /// Required: subscription_id (`id`), resource, change_type, notification_url, expiration.
    pub fn from_value(v: &Value) -> Result<GraphSubscription, String> {
        let sub = GraphSubscription {
            subscription_id: text(v, &["subscription_id", "id"]),
            resource: text(v, &["resource"]),
            change_type: text(v, &["change_type", "changeType"]),
            notification_url: text(v, &["notification_url", "notificationUrl"]),
            expiration_datetime: text(v, &["expiration_datetime", "expirationDateTime"]),
            client_state: opt_text(v, &["client_state", "clientState"]),
            latest_renewal_at: opt_text(v, &["latest_renewal_at", "latestRenewalAt"]),
            status: opt_text(v, &["status"]),
        };
        for (name, value) in [("subscription_id", &sub.subscription_id), ("resource", &sub.resource), ("change_type", &sub.change_type), ("notification_url", &sub.notification_url)] {
            if value.is_empty() {
                return Err(format!("GraphSubscription.{name} is required."));
            }
        }
        if sub.expiration_datetime.is_empty() {
            return Err("GraphSubscription.expiration_datetime is required.".into());
        }
        Ok(sub)
    }
    pub fn to_value(&self) -> Value {
        compact(vec![
            ("subscription_id", json!(self.subscription_id)),
            ("resource", json!(self.resource)),
            ("change_type", json!(self.change_type)),
            ("notification_url", json!(self.notification_url)),
            ("expiration_datetime", json!(self.expiration_datetime)),
            ("client_state", s(&self.client_state)),
            ("latest_renewal_at", s(&self.latest_renewal_at)),
            ("status", s(&self.status)),
        ])
    }
    pub fn is_expired(&self, at: i64) -> bool {
        parse_iso(&self.expiration_datetime).map(|e| e <= at).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_round_trips_and_parses_offsets() {
        assert_eq!(iso_z(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_z(1_767_225_600), "2026-01-01T00:00:00Z");
        assert_eq!(parse_iso("2026-01-01T00:00:00Z"), Some(1_767_225_600));
        assert_eq!(parse_iso("2026-01-01T01:00:00+01:00"), Some(1_767_225_600));
        assert_eq!(parse_iso("2026-01-01T00:00:00.1234567Z"), Some(1_767_225_600));
        assert_eq!(parse_iso("not a date"), None);
    }

    #[test]
    fn models_accept_camel_and_snake_and_drop_empties() {
        let r = TeamsMeetingRef::from_value(&json!({"id": " M1 ", "joinWebUrl": "https://x", "metadata": {"subject": "Weekly"}})).unwrap();
        assert_eq!((r.meeting_id.as_str(), r.join_web_url.as_deref(), r.subject().as_deref()), ("M1", Some("https://x"), Some("Weekly")));
        assert!(TeamsMeetingRef::from_value(&json!({})).is_err(), "meeting_id is required");
        let v = r.to_value();
        assert!(v.get("organizer_user_id").is_none(), "nulls are dropped: {v}");

        let a = MeetingArtifact::from_value(&json!({"artifact_type": "recording", "id": "r1", "displayName": "a.mp4", "size": "12", "@microsoft.graph.downloadUrl": "https://d"})).unwrap();
        assert_eq!((a.artifact_id.as_str(), a.display_name.as_deref(), a.size_bytes), ("r1", Some("a.mp4"), Some(12)));
        assert!(MeetingArtifact::from_value(&json!({"artifact_type": "bogus", "id": "x"})).is_err());

        let job = Job::from_value(&json!({
            "job_id": "j", "event_id": "e", "source_event_type": "created", "dedupe_key": "d", "status": "received",
            "meeting_ref": {"meeting_id": "M1"}, "error_info": {"message": "x"}
        })).unwrap();
        assert_eq!((job.status.as_str(), job.meeting_ref.as_ref().unwrap().meeting_id.as_str(), job.error_info.len()), ("received", "M1", 1));
        for missing in ["job_id", "status"] {
            let mut v = json!({"job_id": "j", "event_id": "e", "source_event_type": "c", "dedupe_key": "d", "status": "received"});
            v[missing] = json!("");
            assert!(Job::from_value(&v).is_err(), "{missing} is required");
        }

        let sub = GraphSubscription::from_value(&json!({"id": "s1", "resource": "me", "changeType": "updated", "notificationUrl": "https://n", "expirationDateTime": "2026-01-01T00:00:00Z"})).unwrap();
        assert!(!sub.is_expired(1_767_225_599) && sub.is_expired(1_767_225_600));
    }
}
