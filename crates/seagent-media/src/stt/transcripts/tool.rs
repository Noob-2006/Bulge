//! The `transcripts` tool (OpenClaw `src/agents/tools/transcripts-tool.ts`).

use super::sources::{find_source, sources, Capture};
use super::store::{now_iso, selector, session_json, new_session_id, Session, SourceLocator, Store};
use super::summary;
use crate::Media;
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

const STATUS_SELECTOR_LIMIT: usize = 3;
const STATUS_ACTIVE_MAX_ENTRIES: usize = 5;
const SHOW_MAX_CHARS: usize = 12_000;
/// Upstream's one message for a missing or doubled handle.
const SELECTION: &str = "Provide exactly one of selector or sessionId for stop, summarize, or show.";
const LIST_MAX_CHARS: usize = 4_000;

pub struct Transcripts {
    pub m: Arc<Media>,
}

struct Active {
    session: Session,
    root: PathBuf,
    capture: Box<dyn Capture>,
}

fn active() -> &'static Mutex<HashMap<String, Active>> {
    static A: OnceLock<Mutex<HashMap<String, Active>>> = OnceLock::new();
    A.get_or_init(Default::default)
}

fn s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(|x| x.as_str()).map(str::trim).filter(|x| !x.is_empty())
}

/// Invitation credentials stripped from a meeting locator (OpenClaw
/// `sanitizeTranscriptSourceLocator`: keep `scheme://host[:port]/path`).
fn meeting_url(u: &str) -> Option<String> {
    let (scheme, rest) = u.split_once("://")?;
    if !scheme.starts_with(|c: char| c.is_ascii_alphabetic()) || !scheme.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) {
        return None;
    }
    let rest = rest.split(['?', '#']).next().unwrap_or("");
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    // `user:pass@` is the part that must never be persisted.
    let host = authority.rsplit('@').next().unwrap_or("");
    if host.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{host}{path}"))
}

fn source_from(v: &Value, provider: &str) -> SourceLocator {
    let o = |k: &str| s(v, k).map(str::to_string);
    SourceLocator { provider_id: provider.into(), kind: None, account_id: o("accountId"), guild_id: o("guildId"), channel_id: o("channelId"), meeting_url: o("meetingUrl").and_then(|u| meeting_url(&u)) }
}

fn truncate(t: &str, n: usize) -> String {
    if t.chars().count() <= n {
        t.to_string()
    } else {
        t.chars().take(n).collect()
    }
}

impl Transcripts {
    fn persist_summary(&self, store: &Store, sess: &Session, cancel: &seagent_core::Cancel) -> Result<(PathBuf, Value), String> {
        let us = store.utterances(sess);
        let base = summary::summarize(sess, &us);
        let sum = if self.m.cfg.bool_or("transcripts.model_summary", true) { summary::model_notes(sess, &base, cancel).unwrap_or(base) } else { base };
        let md = summary::render_markdown(&sum);
        let p = store.write_summary(sess, &sum, &md)?;
        Ok((p, sum))
    }

    /// selector (exact) or sessionId (legacy handle), never both.
    fn select(&self, store: &Store, v: &Value) -> Result<Session, String> {
        match (s(v, "selector"), s(v, "sessionId")) {
            (Some(_), Some(_)) => Err(SELECTION.into()),
            (Some(sel), None) => store.find(sel, true).ok_or_else(|| format!("transcripts session not found: {sel}")),
            (None, Some(id)) => {
                if let Some(a) = active().lock().unwrap().get(id) {
                    return Ok(a.session.clone());
                }
                store.find(id, false).ok_or_else(|| format!("transcripts session not found: {id}"))
            }
            (None, None) => Err(SELECTION.into()),
        }
    }

    fn start(&self, ctx: &ToolCtx, store: &Store, v: &Value) -> Result<ToolOutput, String> {
        let pid = s(v, "providerId").unwrap_or("microphone");
        let p = find_source(pid).ok_or_else(|| format!("unknown transcripts provider: {pid}"))?;
        if !p.can_start() {
            return Err(format!("transcripts provider {} cannot start live capture", p.id()));
        }
        let id = s(v, "sessionId").map(str::to_string).unwrap_or_else(new_session_id);
        if active().lock().unwrap().contains_key(&id) {
            return Err(format!("transcripts session already active: {id}"));
        }
        let mut src = source_from(v, p.id());
        src.kind = p.kinds().first().map(|k| k.to_string());
        let sess = Session { session_id: id.clone(), title: s(v, "title").map(str::to_string), source: src, started_at: now_iso(), stopped_at: None, metadata: json!({"sessionIdOrigin": if s(v, "sessionId").is_some() { "supplied" } else { "generated" }, "agentSession": ctx.session_id}) };
        store.write_session(&sess)?;
        let root = store.root.clone();
        let (sink_sess, max) = (sess.clone(), super::max_utterances(&self.m));
        let home = root.parent().map(|p| p.to_path_buf()).unwrap_or_default();
        let sink: super::sources::Sink = Arc::new(move |u| {
            let _ = Store::new(&home).append(&sink_sess, &u, max);
        });
        let capture = p.start(&self.m, &sess, sink)?;
        let sel = selector(&sess);
        active().lock().unwrap().insert(id.clone(), Active { session: sess.clone(), root, capture });
        Ok(ToolOutput::ok(format!("Transcripts started: {id}\nSelector: {sel}\nProvider: {}", p.name())))
    }

    fn stop(&self, store: &Store, v: &Value, cancel: &seagent_core::Cancel) -> Result<ToolOutput, String> {
        let mut sess = self.select(store, v)?;
        let entry = active().lock().unwrap().remove(&sess.session_id);
        let Some(mut a) = entry else {
            return Ok(ToolOutput::ok(format!("Transcripts session no longer active: {}", selector(&sess))));
        };
        let _ = a.capture.stop();
        sess = a.session;
        let store = Store { root: a.root };
        sess.stopped_at = Some(now_iso());
        store.write_session(&sess)?;
        let n = store.utterances(&sess).len();
        let (path, _) = self.persist_summary(&store, &sess, cancel)?;
        Ok(ToolOutput::ok(format!("Transcripts stopped: {}\nSelector: {}\nUtterances: {n}\nSummary: {}", sess.session_id, selector(&sess), path.display())))
    }

    fn import(&self, store: &Store, v: &Value, cancel: &seagent_core::Cancel) -> Result<ToolOutput, String> {
        let pid = s(v, "providerId").unwrap_or("manual-transcript");
        let p = find_source(pid).ok_or_else(|| format!("unknown transcripts provider: {pid}"))?;
        if !p.can_import() {
            return Err(format!("transcripts provider {} cannot import transcripts", p.id()));
        }
        let text = v.get("transcript").and_then(|t| t.as_str()).filter(|t| !t.trim().is_empty()).ok_or("missing required parameter: transcript")?;
        let now = now_iso();
        let mut src = source_from(v, p.id());
        src.kind = p.kinds().first().map(|k| k.to_string());
        let sess = Session { session_id: s(v, "sessionId").map(str::to_string).unwrap_or_else(new_session_id), title: s(v, "title").map(str::to_string), source: src, started_at: now.clone(), stopped_at: Some(now), metadata: json!({"sessionIdOrigin": if s(v, "sessionId").is_some() { "supplied" } else { "generated" }}) };
        store.write_session(&sess)?;
        let us = p.import(&self.m, &sess, text, s(v, "speakerLabel"), cancel)?;
        let max = super::max_utterances(&self.m);
        for u in &us {
            store.append(&sess, u, max)?;
        }
        let (path, _) = self.persist_summary(store, &sess, cancel)?;
        Ok(ToolOutput::ok(format!("Transcript imported: {}\nSelector: {}\nUtterances: {}\nSummary: {}", sess.session_id, selector(&sess), us.len(), path.display())))
    }

    fn status(&self) -> ToolOutput {
        let provs: Vec<String> = sources().iter().map(|p| p.id().to_string()).collect();
        let a = active().lock().unwrap();
        let mut entries: Vec<&Active> = a.values().collect();
        entries.sort_by_key(|e| selector(&e.session));
        let mut lines = vec![format!("Transcripts providers: {}", if provs.is_empty() { "none".into() } else { provs.join(", ") }), format!("Active sessions: {}", entries.len())];
        for e in entries.iter().take(STATUS_ACTIVE_MAX_ENTRIES) {
            let src = &e.session.source;
            lines.push(json!({"selector": selector(&e.session), "providerId": src.provider_id, "accountId": src.account_id, "guildId": src.guild_id, "channelId": src.channel_id, "meetingUrl": src.meeting_url, "title": e.session.title.as_deref().map(|t| truncate(t, 120)), "capturing": e.capture.active()}).to_string());
        }
        if entries.len() > STATUS_ACTIVE_MAX_ENTRIES {
            lines.push("Additional active sessions omitted (display limit).".into());
        }
        if !entries.is_empty() {
            lines.push("Selectors:".into());
            lines.extend(entries.iter().take(STATUS_SELECTOR_LIMIT).map(|e| format!("active: {}", selector(&e.session))));
            if entries.len() > STATUS_SELECTOR_LIMIT {
                lines.push(format!("{} more; ask a local operator to run `transcripts list`.", entries.len() - STATUS_SELECTOR_LIMIT));
            }
        }
        ToolOutput::ok(lines.join("\n"))
    }

    fn list(&self, store: &Store, v: &Value) -> Result<ToolOutput, String> {
        let limit = match v.get("limit") {
            None | Some(Value::Null) => 20,
            Some(x) => x.as_u64().filter(|n| (1..=50).contains(n)).ok_or("limit must be an integer from 1 to 50.")? as usize,
        };
        let mut lines: Vec<String> = Vec::new();
        let mut used = 0; // characters already written, newlines included
        for sess in store.list().into_iter().take(limit) {
            let us = store.utterances(&sess);
            let sum = summary::summarize(&sess, &us);
            let parts: Vec<String> = sum["participants"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
            let name = find_source(&sess.source.provider_id).map(|p| p.name().to_string()).unwrap_or_else(|| sess.source.provider_id.clone());
            let title = truncate(&summary::sanitize(sess.title.as_deref().unwrap_or(&name)), 80);
            let date = sess.started_at.get(..16).unwrap_or(&sess.started_at).replace('T', " ");
            let participants = truncate(&parts.join(", "), 100);
            let line = format!("{date}  {title}  ({} utterances, {})  selector: {}", us.len(), if participants.is_empty() { "no speakers".into() } else { participants }, selector(&sess));
            let n = line.chars().count();
            if !lines.is_empty() {
                if used + 1 + n > LIST_MAX_CHARS - 100 {
                    lines.push("More meetings exist; use a smaller limit for a shorter list.".into());
                    break;
                }
                used += 1 + n;
            } else {
                used = n;
            }
            lines.push(line);
        }
        Ok(ToolOutput::ok(if lines.is_empty() { "No accessible meeting transcripts found.".into() } else { lines.join("\n") }))
    }

    fn show(&self, store: &Store, v: &Value) -> Result<ToolOutput, String> {
        let sess = self.select(store, v)?;
        let live = active().lock().unwrap().contains_key(&sess.session_id);
        let sel = selector(&sess);
        Ok(ToolOutput::ok(match store.notes(&sess) {
            None => format!("No summary exists yet for this meeting.{}", if live { " Capture is active." } else { "" }),
            Some(md) if md.chars().count() > SHOW_MAX_CHARS => {
                let marker = format!("\n[truncated; run `transcripts show` with selector {sel} for the full notes]");
                format!("{}{marker}", truncate(&md, SHOW_MAX_CHARS - marker.chars().count()))
            }
            Some(md) => md,
        }))
    }

    fn summarize(&self, store: &Store, v: &Value, cancel: &seagent_core::Cancel) -> Result<ToolOutput, String> {
        let sess = self.select(store, v)?;
        let (path, sum) = self.persist_summary(store, &sess, cancel)?;
        Ok(ToolOutput::ok(format!("Transcripts summarized: {}\nSelector: {}\nSummary: {}\n\n{}", sess.session_id, selector(&sess), path.display(), sum["overview"].as_str().unwrap_or(""))))
    }
}

impl Tool for Transcripts {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "transcripts".into(),
            description: "Start, stop, import, summarize, or inspect meeting transcript captures; list past meetings and read their notes.".into(),
            input_schema: json!({"type": "object", "additionalProperties": false, "required": ["action"], "properties": {
                "action": {"type": "string", "enum": ["start", "stop", "status", "import", "summarize", "list", "show"], "description": "start, stop, status, import, summarize, list, or show."},
                "sessionId": {"type": "string", "minLength": 1, "description": "Raw ID for start/import. Legacy stop/summarize/show handle; prefer selector for an exact capture. Cannot be combined with selector."},
                "selector": {"type": "string", "minLength": 1, "description": "Exact dated capture selector returned by start/import/status. Only for stop/summarize/show; supply this or sessionId, never both."},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20},
                "title": {"type": "string", "minLength": 1},
                "providerId": {"type": "string", "minLength": 1, "description": "Source provider: microphone (live, default for start), manual-transcript (default for import), audio-file (transcript = path of a recording), or a registered channel/meeting provider."},
                "accountId": {"type": "string", "minLength": 1},
                "guildId": {"type": "string", "minLength": 1},
                "channelId": {"type": "string", "minLength": 1},
                "meetingUrl": {"type": "string", "minLength": 1},
                "transcript": {"type": "string", "minLength": 1, "description": "Pasted transcript text for import (\"Speaker: text\" lines), or the recording path for providerId=audio-file."},
                "speakerLabel": {"type": "string", "minLength": 1}
            }}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }

    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let mut fx = vec![Effect::Write { path: ctx.home.join("transcripts") }];
        let action = s(input, "action").unwrap_or("");
        let pid = s(input, "providerId").unwrap_or(if action == "start" { "microphone" } else { "manual-transcript" });
        let transcribes = (action == "import" && find_source(pid).is_some_and(|p| p.id() == "audio-file")) || (action == "start" && find_source(pid).is_some_and(|p| p.id() == "microphone"));
        if action == "import" && find_source(pid).is_some_and(|p| p.id() == "audio-file") {
            if let Some(p) = s(input, "transcript") {
                fx.push(Effect::Read { path: ctx.resolve(p) });
            }
        }
        if transcribes {
            let prov = crate::stt::resolve_provider(&self.m);
            if crate::stt::CLOUD.contains(&prov.as_str()) {
                fx.push(Effect::Net { dest: prov, payload: "recorded audio for transcription".into() });
            }
        }
        fx
    }

    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        if !super::enabled(&self.m) {
            return ToolOutput::err("transcripts are disabled ([media.transcripts] enabled = false).");
        }
        let Some(action) = s(&input, "action") else { return ToolOutput::err("missing required parameter: action") };
        if input.get("selector").is_some() && !matches!(action, "stop" | "summarize" | "show") {
            return ToolOutput::err("selector is only supported for stop, summarize, or show.");
        }
        let store = Store::new(&ctx.home);
        let r = match action {
            "start" => self.start(ctx, &store, &input),
            "stop" => self.stop(&store, &input, &ctx.cancel),
            "status" => Ok(self.status()),
            "import" => {
                let mut v = input.clone();
                if s(&v, "providerId").is_some_and(|p| find_source(p).is_some_and(|x| x.id() == "audio-file")) {
                    if let Some(p) = s(&input, "transcript") {
                        v["transcript"] = json!(ctx.resolve(p).display().to_string());
                    }
                }
                self.import(&store, &v, &ctx.cancel)
            }
            "summarize" => self.summarize(&store, &input, &ctx.cancel),
            "list" => self.list(&store, &input),
            "show" => self.show(&store, &input),
            other => Err(format!("unsupported transcripts action: {other}")),
        };
        r.unwrap_or_else(ToolOutput::err)
    }
}

/// Sessions recorded in `home` (for CLIs: `seagent transcripts list`).
pub fn list_json(home: &std::path::Path) -> Value {
    let st = Store::new(home);
    json!(st.list().iter().map(|s| session_json(s, st.utterances(s).len())).collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ctx;

    #[test]
    fn meeting_urls_lose_invitation_credentials() {
        assert_eq!(meeting_url("https://user:secret@meet.example.com/abc-def?pwd=1#x").as_deref(), Some("https://meet.example.com/abc-def"));
        assert_eq!(meeting_url("https://meet.example.com").as_deref(), Some("https://meet.example.com"));
        assert_eq!(meeting_url("not a url"), None, "unparseable locators are not persisted");
        assert_eq!(meeting_url("https://?pwd=1"), None, "a locator without a host is not persisted");
        let loc = source_from(&json!({"meetingUrl": "https://user:secret@meet.example.com/abc?pwd=1", "accountId": "a1"}), "meeting");
        assert_eq!((loc.meeting_url.as_deref(), loc.account_id.as_deref()), (Some("https://meet.example.com/abc"), Some("a1")));
    }

    #[test]
    fn show_truncates_notes_to_the_character_budget() {
        let m = Arc::new(Media::new(crate::MediaConfig::from_toml("[transcripts]\nmodel_summary = false\n")));
        let tool = &crate::stt::transcripts::tools(&m)[0];
        let c = ctx("tr-show");
        let text: String = (0..1_500).map(|i| format!("Alice: hello there number {i}\n")).collect();
        let r = tool.call(&c, json!({"action": "import", "title": "Long", "transcript": text}));
        assert!(!r.is_error, "{}", r.content);
        let sel = r.content.lines().find_map(|l| l.strip_prefix("Selector:")).unwrap_or("").trim().to_string();
        let s = tool.call(&c, json!({"action": "show", "selector": sel}));
        assert!(s.content.chars().count() <= 12_000, "{} chars", s.content.chars().count());
        assert!(s.content.contains(&format!("[truncated; run `transcripts show` with selector {sel} for the full notes]")), "{}", &s.content[s.content.len() - 200..]);
        let full = tool.call(&c, json!({"action": "show", "sessionId": sel.split('/').nth(1).unwrap_or("")}));
        assert_eq!(full.content, s.content, "the raw sessionId handle shows the same notes");
        let l = tool.call(&c, json!({"action": "list", "limit": 1}));
        assert!(l.content.contains("Long  (1500 utterances"), "{}", l.content);
    }
}
