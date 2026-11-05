//! Durable transcript store (OpenClaw `transcripts/store*.ts`, file-backed).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SourceLocator {
    #[serde(rename = "providerId")]
    pub provider_id: String,
    /// "live-voice" | "meeting" | "posthoc-transcript" | "recording" | "microphone".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(rename = "accountId", default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(rename = "guildId", default, skip_serializing_if = "Option::is_none")]
    pub guild_id: Option<String>,
    #[serde(rename = "channelId", default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    #[serde(rename = "meetingUrl", default, skip_serializing_if = "Option::is_none")]
    pub meeting_url: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Session {
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub source: SourceLocator,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(rename = "stoppedAt", default, skip_serializing_if = "Option::is_none")]
    pub stopped_at: Option<String>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Utterance {
    pub id: String,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(default = "yes")]
    pub r#final: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub speaker: Option<String>,
    pub text: String,
}

fn yes() -> bool {
    true
}

/// ISO-8601 UTC timestamp (`2026-11-03T10:15:00.123Z`).
pub fn now_iso() -> String {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    iso(d.as_secs() as i64, d.subsec_millis())
}

pub fn iso(secs: i64, ms: u32) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}.{ms:03}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// `transcript-<iso with - for :.>-<8 hex>` (OpenClaw `createTranscriptSessionId`).
pub fn new_session_id() -> String {
    let r: String = ark_net::crypto::random_bytes(4).iter().map(|b| format!("{b:02x}")).collect();
    format!("transcript-{}-{r}", now_iso().replace([':', '.'], "-"))
}

/// A path segment that cannot escape its directory.
pub fn safe_segment(s: &str) -> String {
    let v: String = s.chars().map(|c| if c.is_ascii_alphanumeric() || "-_.".contains(c) { c } else { '_' }).take(120).collect();
    let v = v.trim_matches('.').to_string();
    if v.is_empty() {
        "session".into()
    } else {
        v
    }
}

pub fn selector(s: &Session) -> String {
    format!("{}/{}", s.started_at.get(..10).unwrap_or("unknown"), safe_segment(&s.session_id))
}

pub struct Store {
    pub root: PathBuf,
}

impl Store {
    pub fn new(home: &Path) -> Store {
        Store { root: home.join("transcripts") }
    }
    fn dir(&self, s: &Session) -> PathBuf {
        self.root.join(selector(s))
    }
    pub fn write_session(&self, s: &Session) -> Result<(), String> {
        let d = self.dir(s);
        std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
        std::fs::write(d.join("session.json"), serde_json::to_vec_pretty(s).unwrap_or_default()).map_err(|e| e.to_string())
    }
    pub fn append(&self, s: &Session, u: &Utterance, max: usize) -> Result<bool, String> {
        let d = self.dir(s);
        std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
        if self.utterances(s).len() >= max {
            return Ok(false);
        }
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(d.join("utterances.jsonl")).map_err(|e| e.to_string())?;
        writeln!(f, "{}", serde_json::to_string(u).unwrap_or_default()).map_err(|e| e.to_string())?;
        Ok(true)
    }
    pub fn utterances(&self, s: &Session) -> Vec<Utterance> {
        std::fs::read_to_string(self.dir(s).join("utterances.jsonl")).unwrap_or_default().lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
    }
    pub fn write_summary(&self, s: &Session, summary: &Value, markdown: &str) -> Result<PathBuf, String> {
        let d = self.dir(s);
        std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
        std::fs::write(d.join("summary.json"), serde_json::to_vec_pretty(summary).unwrap_or_default()).map_err(|e| e.to_string())?;
        let p = d.join("notes.md");
        std::fs::write(&p, markdown).map_err(|e| e.to_string())?;
        Ok(p)
    }
    pub fn notes(&self, s: &Session) -> Option<String> {
        std::fs::read_to_string(self.dir(s).join("notes.md")).ok()
    }
    pub fn summary(&self, s: &Session) -> Option<Value> {
        std::fs::read(self.dir(s).join("summary.json")).ok().and_then(|b| serde_json::from_slice(&b).ok())
    }
    /// Every stored session, newest first.
    pub fn list(&self) -> Vec<Session> {
        let mut out = Vec::new();
        let Ok(days) = std::fs::read_dir(&self.root) else { return out };
        for day in days.flatten() {
            let Ok(sessions) = std::fs::read_dir(day.path()) else { continue };
            for s in sessions.flatten() {
                if let Some(sess) = std::fs::read(s.path().join("session.json")).ok().and_then(|b| serde_json::from_slice::<Session>(&b).ok()) {
                    out.push(sess);
                }
            }
        }
        out.sort_by(|a, b| b.started_at.cmp(&a.started_at).then(b.session_id.cmp(&a.session_id)));
        out
    }
    /// By exact selector, or by raw session id (legacy handle).
    pub fn find(&self, selector_or_id: &str, by_selector: bool) -> Option<Session> {
        self.list().into_iter().find(|s| if by_selector { selector(s) == selector_or_id } else { s.session_id == selector_or_id })
    }
}

pub fn session_json(s: &Session, utterances: usize) -> Value {
    json!({"sessionId": s.session_id, "selector": selector(s), "title": s.title, "providerId": s.source.provider_id, "startedAt": s.started_at, "stoppedAt": s.stopped_at, "utteranceCount": utterances})
}
