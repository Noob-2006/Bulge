//! Logbook (OpenClaw `extensions/logbook`, MIT; prompts adapted there from Dayflow, MIT): an
//! automatic work journal. A paired node's `screen.snapshot` is captured every
//! `capture_interval_seconds`; unchanged frames are marked idle; every
//! `analysis_interval_minutes` the active frames of a window go to a vision model as one batch
//! (≤ 16 images) that returns activity segments ("observations"); the default model then
//! revises the day's timeline cards from those observations (coverage-validated, one repair
//! round-trip). Standups and questions are answered from cards + observations only.
//!
//! ```toml
//! [integrations.logbook]
//! enabled = true                 # off by default: enabling opts into screen capture
//! capture_enabled = true
//! capture_interval_seconds = 30  # 5–600
//! analysis_interval_minutes = 15 # 3–120
//! node_id = ""                   # default: first connected node offering screen.snapshot
//! screen_index = 0
//! max_width = 1440
//! vision_model = ""              # provider/model; default: model.aux, else model.default (needs vision)
//! retention_days = 14            # frames only; cards and observations are kept
//! ```
//!
//! Storage stays on this host: `<data>/logbook/logbook.json` plus `frames/<day>/<ms>.<ext>`.
//! Surfaces: ARP `logbook.status|days|timeline|standup|ask|capture.set|analyze.now` and the
//! `logbook` tool.

use ark_core::{Block, Cancel, Effect, Message, Role, Tool, ToolCtx, ToolOutput, ToolSpec};
use ark_kernel::config::Config;
use ark_kernel::kernel::Kernel;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

pub const CARD_CATEGORIES: &[&str] = &["coding", "review", "writing", "research", "comms", "meetings", "design", "ops", "browsing", "media", "other"];
const CARD_MIN_MINUTES: u64 = 10;
const CARD_MAX_MINUTES: u64 = 60;
pub const CARD_LOOKBACK_MS: u64 = 45 * 60 * 1000;
const BATCH_MAX_GAP_MS: u64 = 2 * 60 * 1000;
pub const MAX_FRAMES_PER_CALL: usize = 16;
const COVERAGE_TOLERANCE_MS: u64 = 2 * 60 * 1000;
const CAPTURE_FAILURE_THRESHOLD: u32 = 3;
const CAPTURE_FAILURE_PAUSE_TICKS: u32 = 10;
pub const MODEL_MISSING: &str = "no vision model is configured for Logbook (set integrations.logbook.vision_model, or a vision-capable model.aux)";

#[derive(Debug, Clone, PartialEq)]
pub struct LogbookConfig {
    pub enabled: bool,
    pub capture_enabled: bool,
    pub capture_interval_seconds: u64,
    pub analysis_interval_minutes: u64,
    pub node_id: Option<String>,
    pub screen_index: u64,
    pub max_width: u64,
    pub vision_model: Option<String>,
    pub retention_days: u64,
}

fn clamp(v: Option<&toml::Value>, d: u64, lo: u64, hi: u64) -> u64 {
    let n = v.and_then(|v| v.as_float().or_else(|| v.as_integer().map(|i| i as f64))).unwrap_or(d as f64);
    (n.round().max(0.0) as u64).clamp(lo, hi)
}

impl LogbookConfig {
    pub fn parse(cfg: &Config) -> LogbookConfig {
        let empty = toml::Table::new();
        let t = cfg.integrations.get("logbook").and_then(|v| v.as_table()).unwrap_or(&empty);
        let s = |k: &str| t.get(k).and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()).map(String::from);
        LogbookConfig {
            enabled: t.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false),
            capture_enabled: t.get("capture_enabled").and_then(|v| v.as_bool()) != Some(false),
            capture_interval_seconds: clamp(t.get("capture_interval_seconds"), 30, 5, 600),
            analysis_interval_minutes: clamp(t.get("analysis_interval_minutes"), 15, 3, 120),
            node_id: s("node_id"),
            screen_index: clamp(t.get("screen_index"), 0, 0, 16),
            max_width: clamp(t.get("max_width"), 1440, 480, 3840),
            vision_model: s("vision_model"),
            retention_days: clamp(t.get("retention_days"), 14, 1, 365),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Frame {
    pub id: u64,
    pub captured_at_ms: u64,
    pub day: String,
    pub path: String,
    pub byte_size: u64,
    pub idle: bool,
    pub hash: String,
    #[serde(default)]
    pub batch: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Batch {
    pub id: u64,
    pub day: String,
    pub start_ms: u64,
    pub end_ms: u64,
    pub status: String,
    #[serde(default)]
    pub error: Option<String>,
    pub frame_ids: Vec<u64>,
    #[serde(default)]
    pub model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Observation {
    pub batch_id: u64,
    pub day: String,
    pub start_ms: u64,
    pub end_ms: u64,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Distraction {
    pub start_ms: u64,
    pub end_ms: u64,
    pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Card {
    pub day: String,
    pub start_ms: u64,
    pub end_ms: u64,
    pub title: String,
    pub summary: String,
    pub detail: String,
    pub category: String,
    #[serde(default)]
    pub app_primary: Option<String>,
    #[serde(default)]
    pub app_secondary: Option<String>,
    #[serde(default)]
    pub distractions: Vec<Distraction>,
    #[serde(default)]
    pub keyframe_id: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Db {
    pub next_id: u64,
    pub frames: Vec<Frame>,
    pub batches: Vec<Batch>,
    pub observations: Vec<Observation>,
    pub cards: Vec<Card>,
    pub standups: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub capture_paused: bool,
}

pub struct Logbook {
    pub dir: PathBuf,
    pub cfg: LogbookConfig,
    /// Minutes east of UTC for local clocks and day keys.
    pub offset_min: i32,
    lock: Mutex<()>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    failures: u32,
    backoff: u32,
    last_error: Option<String>,
    last_capture_ms: Option<u64>,
    analyzing: bool,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Local "YYYY-MM-DD" and "HH:MM:SS" for `ms` at `offset_min`.
pub fn day_key(ms: u64, offset_min: i32) -> String {
    ark_kernel::util::fmt_time((ms / 1000) as i64, offset_min)[..10].to_string()
}
pub fn clock(ms: u64, offset_min: i32) -> String {
    let s = ((ms / 1000) as i64 + offset_min as i64 * 60).rem_euclid(86_400);
    format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
}

/// Local midnight (ms) of `day`.
fn day_start(day: &str, offset_min: i32) -> Option<u64> {
    let (y, rest) = day.split_once('-')?;
    let (m, d) = rest.split_once('-')?;
    let (y, m, d): (i64, i64, i64) = (y.parse().ok()?, m.parse().ok()?, d.parse().ok()?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // Days from civil (Howard Hinnant).
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 - offset_min as i64 * 60;
    (secs >= 0).then_some(secs as u64 * 1000)
}

/// Upstream `clockToMs`: "HH:MM:SS" / "H:MM" with optional am/pm on a local day.
pub fn clock_to_ms(day: &str, c: &str, offset_min: i32) -> Option<u64> {
    let c = c.trim().to_lowercase();
    let (body, mer) = if let Some(b) = c.strip_suffix("pm") { (b.trim().to_string(), Some("pm")) } else if let Some(b) = c.strip_suffix("am") { (b.trim().to_string(), Some("am")) } else { (c.clone(), None) };
    let parts: Vec<&str> = body.split(':').collect();
    if !(2..=3).contains(&parts.len()) || parts[1].len() != 2 || parts.get(2).is_some_and(|s| s.len() != 2) || parts[0].is_empty() || parts[0].len() > 2 {
        return None;
    }
    let mut h: u64 = parts[0].parse().ok()?;
    let m: u64 = parts[1].parse().ok()?;
    let s: u64 = parts.get(2).map(|s| s.parse().ok()).unwrap_or(Some(0))?;
    if let Some(x) = mer {
        if !(1..=12).contains(&h) {
            return None;
        }
        if x == "pm" && h < 12 {
            h += 12;
        }
        if x == "am" && h == 12 {
            h = 0;
        }
    }
    if h > 23 || m > 59 || s > 59 {
        return None;
    }
    Some(day_start(day, offset_min)? + (h * 3600 + m * 60 + s) * 1000)
}

fn extract_json(raw: &str) -> String {
    let c = raw.replace("```json", "").replace("```", "");
    let c = c.trim();
    let Some(i) = c.find(['[', '{']) else { return c.to_string() };
    let close = if c.as_bytes()[i] == b'[' { ']' } else { '}' };
    match c.rfind(close) {
        Some(j) if j > i => c[i..=j].to_string(),
        _ => c.to_string(),
    }
}

/// Upstream `parseObservationSegments`.
pub fn parse_segments(raw: &str, day: &str, start: u64, end: u64, off: i32) -> Vec<(u64, u64, String)> {
    let Ok(v) = serde_json::from_str::<Value>(&extract_json(raw)) else { return vec![] };
    let list = if v.is_array() { v } else { v["segments"].clone() };
    let mut out = vec![];
    for e in list.as_array().into_iter().flatten() {
        let d = e["description"].as_str().map(str::trim).filter(|s| !s.is_empty());
        let s = e["start"].as_str().and_then(|c| clock_to_ms(day, c, off));
        let en = e["end"].as_str().and_then(|c| clock_to_ms(day, c, off));
        let (Some(d), Some(s), Some(en)) = (d, s, en) else { continue };
        let cs = s.min(end).max(start);
        let ce = en.min(end).max(cs);
        out.push((cs, ce, d.to_string()));
    }
    out.sort_by_key(|x| x.0);
    out
}

fn norm_domain(v: &Value) -> Option<String> {
    let s = v.as_str()?.trim().to_lowercase();
    let s = s.strip_prefix("https://").or_else(|| s.strip_prefix("http://")).unwrap_or(&s).to_string();
    let d = s.split(['/', '?', '#']).next().unwrap_or("").to_string();
    (!d.is_empty() && d.len() <= 100).then_some(d)
}

/// Upstream `parseCardsJson`.
pub fn parse_cards(raw: &str, day: &str, off: i32) -> Result<Vec<Card>, String> {
    let v: Value = serde_json::from_str(&extract_json(raw)).map_err(|e| format!("Output is not valid JSON: {e}"))?;
    let arr = v.as_array().ok_or("Output must be a JSON array of cards.")?;
    let (mut drafts, mut problems) = (vec![], vec![]);
    for (i, e) in arr.iter().enumerate() {
        if !e.is_object() {
            problems.push(format!("Card {i}: not an object."));
            continue;
        }
        let s = e["startTime"].as_str().and_then(|c| clock_to_ms(day, c, off));
        let en = e["endTime"].as_str().and_then(|c| clock_to_ms(day, c, off));
        let (Some(s), Some(en)) = (s, en) else {
            problems.push(format!("Card {i}: startTime/endTime must be HH:MM:SS local time."));
            continue;
        };
        if en <= s {
            problems.push(format!("Card {i}: endTime must be after startTime."));
            continue;
        }
        let t = |k: &str| e[k].as_str().map(str::trim).filter(|x| !x.is_empty()).map(String::from);
        let (Some(title), Some(summary)) = (t("title"), t("summary")) else {
            problems.push(format!("Card {i}: title and summary are required."));
            continue;
        };
        let cat = e["category"].as_str().map(|c| c.trim().to_lowercase()).filter(|c| CARD_CATEGORIES.contains(&c.as_str())).unwrap_or_else(|| "other".into());
        let distractions = e["distractions"].as_array().into_iter().flatten().filter_map(|d| {
            let s = d["startTime"].as_str().and_then(|c| clock_to_ms(day, c, off))?;
            let en = d["endTime"].as_str().and_then(|c| clock_to_ms(day, c, off))?;
            let title = d["title"].as_str().map(str::trim).filter(|x| !x.is_empty())?;
            (en > s).then(|| Distraction { start_ms: s, end_ms: en, title: title.into() })
        }).collect();
        drafts.push(Card { day: day.into(), start_ms: s, end_ms: en, title, summary, detail: t("detailedSummary").unwrap_or_default(), category: cat, app_primary: norm_domain(&e["appSites"]["primary"]), app_secondary: norm_domain(&e["appSites"]["secondary"]), distractions, keyframe_id: None });
    }
    if !problems.is_empty() {
        return Err(problems.join("\n"));
    }
    if drafts.is_empty() {
        return Err("Output contained no valid cards.".into());
    }
    drafts.sort_by_key(|c| c.start_ms);
    for i in 1..drafts.len() {
        let (pe, cs, ce) = (drafts[i - 1].end_ms, drafts[i].start_ms, drafts[i].end_ms);
        if pe > cs {
            let overlap = pe - cs;
            if overlap > 60_000 {
                return Err(format!("Cards {} and {i} overlap by {} minutes; adjacent cards must meet cleanly.", i - 1, (overlap as f64 / 60_000.0).round()));
            }
            if ce <= pe {
                return Err(format!("Card {i}: endTime must be after the previous card's endTime."));
            }
            drafts[i].start_ms = pe;
        }
    }
    Ok(drafts)
}

/// Upstream `validateCardCoverage`.
pub fn validate_coverage(drafts: &[Card], required: &[(u64, u64)], ws: u64, we: u64, off: i32) -> Result<(), String> {
    let hm = |ms: u64| clock(ms, off)[..5].to_string();
    let mut problems = vec![];
    for d in drafts {
        if d.start_ms + COVERAGE_TOLERANCE_MS < ws || d.end_ms > we + COVERAGE_TOLERANCE_MS {
            problems.push(format!("Card {}-{} lies outside the revision window {}-{}.", hm(d.start_ms), hm(d.end_ms), hm(ws), hm(we)));
        }
    }
    let mut cov: Vec<&Card> = drafts.iter().collect();
    cov.sort_by_key(|c| c.start_ms);
    for &(s, e) in required {
        let mut cur = s;
        for c in &cov {
            if c.end_ms <= cur {
                continue;
            }
            if c.start_ms > cur + COVERAGE_TOLERANCE_MS {
                break;
            }
            cur = cur.max(c.end_ms);
            if cur + COVERAGE_TOLERANCE_MS >= e {
                break;
            }
        }
        if cur + COVERAGE_TOLERANCE_MS < e {
            problems.push(format!("Time {}-{} from the previous timeline is not covered; do not drop existing cards or observed time.", hm(cur.max(s)), hm(e)));
        }
    }
    if problems.is_empty() { Ok(()) } else { Err(problems.join("\n")) }
}

/// Upstream `selectBatchFrames`: (frame ids, start, end) of the next closable window.
pub fn select_batch(frames: &[(u64, u64)], window_ms: u64, now: u64, force: bool, off: i32) -> Option<(Vec<u64>, u64, u64)> {
    let &(_, first) = frames.first()?;
    let first_day = day_key(first, off);
    let next_day = day_start(&first_day, off).map(|d| d + 86_400_000).unwrap_or(u64::MAX);
    let wend = (first + window_ms).min(next_day);
    let (mut sel, mut prev, mut early) = (vec![], first, false);
    for &(id, ts) in frames {
        if ts >= wend {
            early = day_key(ts, off) != first_day;
            break;
        }
        if !sel.is_empty() && ts - prev > BATCH_MAX_GAP_MS {
            early = true;
            break;
        }
        sel.push((id, ts));
        prev = ts;
    }
    let &(_, last) = sel.last()?;
    let elapsed = now >= wend;
    if !elapsed && !early && !force {
        return None;
    }
    let end = if elapsed && !early { wend } else { last + 1 };
    Some((sel.iter().map(|x| x.0).collect(), first, end))
}

pub fn observation_instructions(times: &[u64], start: u64, end: u64, off: i32) -> String {
    let (s, e) = (clock(start, off), clock(end, off));
    let t: Vec<String> = times.iter().map(|x| clock(*x, off)).collect();
    [
        format!("These are {} screenshots of one computer screen, captured in order between {s} and {e} (local time).", times.len()),
        format!("Capture timestamps: {}.", t.join(", ")),
        String::new(),
        "Write an activity log detailed enough that the user could reconstruct what they did.".into(),
        "For each segment ask: \"What EXACTLY did they do? What SPECIFIC things are visible?\"".into(),
        "Capture exact app/site names, file names, URLs, page or PR titles, usernames, search queries, and numbers when readable.".into(),
        String::new(),
        "Bad: \"Checked email\". Good: \"Gmail: read 'Budget approval' from dana@acme.com, replied briefly\".".into(),
        "Bad: \"Working on code\". Good: \"VS Code: editing store.ts, fixing a type error in replaceCardsInWindow\".".into(),
        String::new(),
        "Return 2-8 segments covering the whole window in order, no gaps, no overlaps.".into(),
        "If the screen barely changes, return one segment describing the sustained activity.".into(),
        "Group by GOAL, not app: debugging across editor, terminal, and browser is one segment.".into(),
        format!("Timestamps must be HH:MM:SS between {s} and {e}."),
        "Return ONLY JSON: {\"segments\": [{\"start\": \"HH:MM:SS\", \"end\": \"HH:MM:SS\", \"description\": \"...\"}]}".into(),
    ]
    .join("\n")
}

pub fn cards_prompt(day: &str, obs: &[Observation], prev: &[Card], ws: u64, we: u64, off: i32) -> String {
    let c = |ms| clock(ms, off);
    let transcript: Vec<String> = obs.iter().map(|o| format!("[{} - {}] {}", c(o.start_ms), c(o.end_ms), o.text)).collect();
    let previous: Vec<Value> = prev.iter().map(|k| json!({"startTime": c(k.start_ms), "endTime": c(k.end_ms), "category": k.category, "title": k.title, "summary": k.summary, "detailedSummary": k.detail,
        "distractions": k.distractions.iter().map(|d| json!({"startTime": c(d.start_ms), "endTime": c(d.end_ms), "title": d.title})).collect::<Vec<_>>(), "appSites": {"primary": k.app_primary.clone().unwrap_or_default(), "secondary": k.app_secondary.clone().unwrap_or_default()}})).collect();
    [
        "You are synthesizing a user's screen activity log into timeline cards. Each card is one coherent activity.".to_string(),
        String::new(),
        "CORE PRINCIPLE:".into(),
        format!("Each card = one main thing the user did. Time is a constraint ({CARD_MIN_MINUTES}-{CARD_MAX_MINUTES} min per card), not a goal."),
        String::new(),
        "SPLIT into a new card only when the user's GOAL changes, not just the tool. MERGE when consecutive activities serve the same goal (app switches, debugging across editor + terminal + browser, iterating on the same document). Default to merging: fewer rich cards beat many granular ones.".into(),
        String::new(),
        "DISTRACTIONS: a brief (<5 min) unrelated interruption inside a card. Anything sustained (>10 min) is its own card.".into(),
        String::new(),
        "CONTINUITY: adjacent cards meet cleanly; never introduce gaps or overlaps. Preserve genuine idle gaps from the source data.".into(),
        String::new(),
        format!("CATEGORY: one of {}.", CARD_CATEGORIES.join(", ")),
        String::new(),
        "APP SITES: identify the main app or site per card as a lowercase domain (figma.com, docs.google.com, github.com). Use \"terminal\" for terminals. Omit secondary when unclear. Never invent brands.".into(),
        String::new(),
        "REVISION CONTRACT:".into(),
        "\"Previous cards\" is a draft you are revising and extending with the new observations. Your output must cover the union of the previous cards' time range and the new observations' range; you may restructure freely inside it, but do not drop covered time. The final card may be shorter than the minimum.".into(),
        String::new(),
        format!("Day: {day}. Window under revision: {} to {}.", c(ws), c(we)),
        String::new(),
        "Previous cards:".into(),
        serde_json::to_string_pretty(&previous).unwrap_or_default(),
        String::new(),
        "New observations:".into(),
        if transcript.is_empty() { "(none)".into() } else { transcript.join("\n") },
        String::new(),
        "Return ONLY a raw JSON array, no code fences, in this exact shape:".into(),
        "[\n  {\n    \"startTime\": \"13:12:00\",\n    \"endTime\": \"13:41:00\",\n    \"category\": \"coding\",\n    \"title\": \"\",\n    \"summary\": \"\",\n    \"detailedSummary\": \"\",\n    \"distractions\": [{ \"startTime\": \"13:15:00\", \"endTime\": \"13:18:00\", \"title\": \"\" }],\n    \"appSites\": { \"primary\": \"\", \"secondary\": \"\" }\n  }\n]".into(),
    ]
    .join("\n")
}

pub fn correction_prompt(err: &str) -> String {
    format!("The previous JSON output failed validation:\n{err}\n\nReturn the FULL corrected JSON array (not a diff). Same coverage, no gaps or overlaps, JSON only.")
}

fn render_cards(cards: &[Card], off: i32, detail: bool) -> String {
    let v: Vec<String> = cards.iter().map(|k| format!("- {}-{} [{}] {}: {}{}", clock(k.start_ms, off), clock(k.end_ms, off), k.category, k.title, k.summary, if detail { format!(" {}", k.detail) } else { String::new() })).collect();
    v.join("\n")
}

pub fn standup_prompt(day: &str, cards: &[Card], prev: &[Card], off: i32) -> String {
    let r = |c: &[Card]| Some(render_cards(c, off, false)).filter(|s| !s.is_empty()).unwrap_or_else(|| "(no tracked activity)".into());
    format!("Write a concise daily standup for {day} based on the user's tracked screen activity.\n\nYesterday's timeline:\n{}\n\nToday's timeline so far:\n{}\n\nOutput markdown with exactly three sections: '## Done' (yesterday's concrete accomplishments, merged and deduplicated), '## Today' (in-progress threads worth continuing), '## Blockers' (only if evidence shows something stuck; otherwise write 'None observed').\nKeep it under 150 words. No preamble.", r(prev), r(cards))
}

pub fn ask_prompt(day: &str, cards: &[Card], obs: &[Observation], q: &str, off: i32) -> String {
    let c = Some(render_cards(cards, off, true)).filter(|s| !s.is_empty()).unwrap_or_else(|| "(none)".into());
    let o: Vec<String> = obs.iter().map(|o| format!("- {}-{}: {}", clock(o.start_ms, off), clock(o.end_ms, off), o.text)).collect();
    format!("Answer the user's question about their tracked day ({day}) using ONLY the evidence below.\nIf the evidence does not contain the answer, say so plainly. Reference times like 14:05 when useful.\n\nTimeline cards:\n{c}\n\nDetailed observations:\n{}\n\nQuestion: {q}\n\nAnswer in 1-4 sentences.", if o.is_empty() { "(none)".into() } else { o.join("\n") })
}

/// Where frames come from (a node in production, a closure in tests).
pub type Capture = Arc<dyn Fn(&LogbookConfig) -> Result<(String, Vec<u8>), String> + Send + Sync>;

/// `screen.snapshot` on the configured (or first capable) node.
pub fn node_capture() -> Capture {
    Arc::new(|c: &LogbookConfig| {
        let nodes = crate::node::live_nodes_with("screen.snapshot", c.node_id.as_deref().unwrap_or(""));
        let node = nodes.first().ok_or_else(|| "no connected node offers screen.snapshot".to_string())?;
        let v = crate::node::invoke(node, "screen.snapshot", json!({"screenIndex": c.screen_index, "maxWidth": c.max_width, "format": "jpeg", "quality": 70}), Duration::from_secs(30), None)?;
        if let Some(e) = v["error"].as_str() {
            return Err(e.to_string());
        }
        let b64 = v["base64"].as_str().filter(|s| !s.is_empty()).ok_or("screen.snapshot returned no image payload")?;
        let bytes = ark_net::crypto::b64_decode(b64.trim()).ok_or("screen.snapshot returned invalid image payload")?;
        Ok((v["mime"].as_str().unwrap_or("image/png").to_string(), bytes))
    })
}

impl Logbook {
    pub fn new(data: &Path, cfg: LogbookConfig, offset_min: i32) -> Logbook {
        Logbook { dir: data.join("logbook"), cfg, offset_min, lock: Mutex::new(()), state: Mutex::default() }
    }
    fn db_path(&self) -> PathBuf {
        self.dir.join("logbook.json")
    }
    pub fn read(&self) -> Db {
        std::fs::read_to_string(self.db_path()).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }
    fn with<R>(&self, f: impl FnOnce(&mut Db) -> R) -> Result<R, String> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut db = self.read();
        let r = f(&mut db);
        std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        ark_kernel::util::atomic_write(&self.db_path(), serde_json::to_string(&db).unwrap_or_default().as_bytes()).map_err(|e| e.to_string())?;
        Ok(r)
    }

    /// Store one captured frame; identical consecutive frames are idle.
    pub fn store_frame(&self, at: u64, mime: &str, bytes: &[u8]) -> Result<Frame, String> {
        let day = day_key(at, self.offset_min);
        let ext = if mime.contains("png") { "png" } else { "jpg" };
        let dir = self.dir.join("frames").join(&day);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join(format!("{at}.{ext}"));
        std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
        let hash = ark_net::crypto::hex(&ark_net::crypto::sha256(bytes));
        self.with(|db| {
            db.next_id += 1;
            let idle = db.frames.last().is_some_and(|f| f.hash == hash);
            let f = Frame { id: db.next_id, captured_at_ms: at, day, path: path.display().to_string(), byte_size: bytes.len() as u64, idle, hash, batch: None };
            db.frames.push(f.clone());
            f
        })
    }

    /// One capture tick (upstream `captureTick`, with failure backoff).
    pub fn capture_tick(&self, cap: &Capture) {
        if !self.cfg.capture_enabled || self.read().capture_paused {
            return;
        }
        {
            let mut st = self.state.lock().unwrap();
            if st.backoff > 0 {
                st.backoff -= 1;
                return;
            }
        }
        let r = cap(&self.cfg).and_then(|(mime, b)| self.store_frame(now_ms(), &mime, &b));
        let mut st = self.state.lock().unwrap();
        match r {
            Ok(f) => {
                st.last_capture_ms = Some(f.captured_at_ms);
                st.last_error = None;
                st.failures = 0;
            }
            Err(e) => {
                st.failures += 1;
                if st.failures >= CAPTURE_FAILURE_THRESHOLD {
                    st.backoff = CAPTURE_FAILURE_PAUSE_TICKS;
                    eprintln!("ark: logbook: capture failing ({e}); backing off for {CAPTURE_FAILURE_PAUSE_TICKS} ticks");
                }
                st.last_error = Some(e);
            }
        }
    }

    pub fn vision_model(&self, k: &Kernel) -> Option<String> {
        if let Some(m) = &self.cfg.vision_model {
            return m.contains('/').then(|| m.clone());
        }
        [k.cfg.aux_model().to_string(), k.cfg.model.default.clone()].into_iter().find(|m| {
            let (pid, name) = ark_kernel::context::split_model(m);
            k.resolver.provider(pid).is_ok_and(|p| p.caps(name).vision)
        })
    }

    /// Close every elapsed window into a pending batch.
    pub fn enqueue(&self, force: bool) -> Result<bool, String> {
        let (win, off) = (self.cfg.analysis_interval_minutes * 60_000, self.offset_min);
        let mut any = false;
        loop {
            let made = self.with(|db| {
                let pend: Vec<(u64, u64)> = db.frames.iter().filter(|f| f.batch.is_none() && !f.idle).map(|f| (f.id, f.captured_at_ms)).take(2000).collect();
                let Some((ids, s, e)) = select_batch(&pend, win, now_ms(), force, off) else { return false };
                db.next_id += 1;
                let bid = db.next_id;
                for f in db.frames.iter_mut().filter(|f| ids.contains(&f.id)) {
                    f.batch = Some(bid);
                }
                db.batches.push(Batch { id: bid, day: day_key(s, off), start_ms: s, end_ms: e, status: "pending".into(), error: None, frame_ids: ids, model: None });
                true
            })?;
            if !made {
                return Ok(any);
            }
            any = true;
            if force {
                return Ok(true);
            }
        }
    }

    fn set_status(&self, id: u64, status: &str, err: Option<String>, model: Option<String>) {
        let _ = self.with(|db| {
            if let Some(b) = db.batches.iter_mut().find(|b| b.id == id) {
                b.status = status.into();
                b.error = err;
                if model.is_some() {
                    b.model = model;
                }
            }
        });
    }

    /// Analyse one batch: observations from the vision model, then revised cards.
    pub fn run_batch(&self, k: &Kernel, b: &Batch) -> Result<(), String> {
        let vm = self.vision_model(k).ok_or(MODEL_MISSING)?;
        self.set_status(b.id, "running", None, Some(vm.clone()));
        let r = (|| {
            let db = self.read();
            let mut frames: Vec<&Frame> = db.frames.iter().filter(|f| b.frame_ids.contains(&f.id)).collect();
            if frames.len() > MAX_FRAMES_PER_CALL {
                let step = frames.len() as f64 / MAX_FRAMES_PER_CALL as f64;
                frames = (0..MAX_FRAMES_PER_CALL).map(|i| frames[(i as f64 * step) as usize]).collect();
            }
            let mut content = vec![];
            for f in &frames {
                let bytes = std::fs::read(&f.path).map_err(|e| format!("frame {}: {e}", f.id))?;
                let mt = ark_core::tool::image_media_type(&bytes).unwrap_or("image/jpeg");
                content.push(Block::Image { media_type: mt.into(), data: ark_core::tool::base64_encode(&bytes) });
            }
            content.push(Block::text(observation_instructions(&frames.iter().map(|f| f.captured_at_ms).collect::<Vec<_>>(), b.start_ms, b.end_ms, self.offset_min)));
            let (m, _, _) = k.sample(Some(&vm), "You extract structured activity logs from screenshots. Reply with JSON only.", vec![Message { role: Role::User, content }], vec![], 2000, &Cancel::new())?;
            let segs = parse_segments(&m.text(), &b.day, b.start_ms, b.end_ms, self.offset_min);
            if segs.is_empty() {
                return Err("vision model returned no usable segments".to_string());
            }
            self.with(|db| {
                db.observations.retain(|o| o.batch_id != b.id);
                db.observations.extend(segs.into_iter().map(|(s, e, t)| Observation { batch_id: b.id, day: b.day.clone(), start_ms: s, end_ms: e, text: t }));
            })?;
            self.revise_cards(k, b)
        })();
        match &r {
            Ok(()) => self.set_status(b.id, "done", None, None),
            Err(e) => {
                self.set_status(b.id, "error", Some(e.clone()), None);
                eprintln!("ark: logbook: batch {} failed: {e}", b.id);
            }
        }
        r
    }

    fn revise_cards(&self, k: &Kernel, b: &Batch) -> Result<(), String> {
        let db = self.read();
        let lb = b.start_ms.saturating_sub(CARD_LOOKBACK_MS);
        let prev: Vec<Card> = db.cards.iter().filter(|c| c.day == b.day && c.end_ms > lb && c.start_ms < b.end_ms).cloned().collect();
        let obs: Vec<Observation> = db.observations.iter().filter(|o| o.day == b.day && o.end_ms >= lb.min(b.start_ms) && o.start_ms <= b.end_ms).cloned().collect();
        let (ws, we) = prev.iter().fold((b.start_ms, b.end_ms), |(s, e), c| (s.min(c.start_ms), e.max(c.end_ms)));
        let prompt = cards_prompt(&b.day, &obs, &prev, ws, we, self.offset_min);
        let mut req: Vec<(u64, u64)> = prev.iter().map(|c| (c.start_ms, c.end_ms)).collect();
        req.push((b.start_ms, b.end_ms));
        let eval = |raw: &str| parse_cards(raw, &b.day, self.offset_min).and_then(|d| validate_coverage(&d, &req, ws, we, self.offset_min).map(|_| d));
        let model = k.cfg.model.default.clone();
        let (first, _, _) = k.sample(Some(&model), "", vec![Message::user(prompt.clone())], vec![], 4000, &Cancel::new())?;
        let mut parsed = eval(&first.text());
        if let Err(e) = &parsed {
            let (retry, _, _) = k.sample(Some(&model), "", vec![Message::user(prompt), Message::assistant(first.text()), Message::user(correction_prompt(e))], vec![], 4000, &Cancel::new())?;
            parsed = eval(&retry.text());
        }
        let mut drafts = parsed.map_err(|e| format!("card synthesis failed validation: {e}"))?;
        let frames: Vec<(u64, u64)> = db.frames.iter().filter(|f| f.day == b.day && !f.idle).map(|f| (f.id, f.captured_at_ms)).collect();
        for c in &mut drafts {
            let mid = c.start_ms + (c.end_ms - c.start_ms) / 2;
            c.keyframe_id = frames.iter().filter(|(_, t)| *t >= c.start_ms && *t <= c.end_ms).min_by_key(|(_, t)| t.abs_diff(mid)).map(|f| f.0);
        }
        self.with(|db| {
            db.cards.retain(|c| !(c.day == b.day && c.start_ms >= ws && c.end_ms <= we) && !(c.day == b.day && c.end_ms > ws && c.start_ms < we));
            db.cards.extend(drafts);
            db.cards.sort_by_key(|c| c.start_ms);
        })
    }

    /// Upstream `analysisTick` (up to 4 pending batches per tick).
    pub fn analysis_tick(&self, k: &Kernel) {
        if self.vision_model(k).is_none() {
            return;
        }
        {
            let mut st = self.state.lock().unwrap();
            if st.analyzing {
                return;
            }
            st.analyzing = true;
        }
        let _ = self.enqueue(false);
        for _ in 0..4 {
            let Some(b) = self.read().batches.into_iter().find(|b| b.status == "pending") else { break };
            let _ = self.run_batch(k, &b);
        }
        self.state.lock().unwrap().analyzing = false;
    }

    /// Upstream `analyzeNow`: retry failed batches, force-close the current window.
    pub fn analyze_now(&self, k: &Kernel) -> Value {
        if self.state.lock().unwrap().analyzing {
            return json!({"started": false, "reason": "analysis already running"});
        }
        if self.vision_model(k).is_none() {
            return json!({"started": false, "reason": MODEL_MISSING});
        }
        let _ = self.with(|db| {
            for b in db.batches.iter_mut().filter(|b| b.status == "error") {
                b.status = "pending".into();
                b.error = None;
            }
        });
        if !self.read().batches.iter().any(|b| b.status == "pending") && !self.enqueue(true).unwrap_or(false) {
            return json!({"started": false, "reason": "no unanalyzed activity captured yet"});
        }
        self.analysis_tick(k);
        json!({"started": true})
    }

    pub fn standup(&self, k: &Kernel, day: &str, refresh: bool) -> Result<String, String> {
        let db = self.read();
        if !refresh {
            if let Some(s) = db.standups.get(day) {
                return Ok(s.clone());
            }
        }
        let prev_day = day_start(day, self.offset_min).map(|d| day_key(d.saturating_sub(12 * 3_600_000), self.offset_min)).unwrap_or_default();
        let cards = |d: &str| db.cards.iter().filter(|c| c.day == d).cloned().collect::<Vec<_>>();
        let (m, _, _) = k.sample(None, "", vec![Message::user(standup_prompt(day, &cards(day), &cards(&prev_day), self.offset_min))], vec![], 800, &Cancel::new())?;
        let t = m.text().trim().to_string();
        let t2 = t.clone();
        self.with(|db| db.standups.insert(day.to_string(), t2))?;
        Ok(t)
    }

    pub fn ask(&self, k: &Kernel, day: &str, q: &str) -> Result<String, String> {
        let db = self.read();
        let cards: Vec<Card> = db.cards.iter().filter(|c| c.day == day).cloned().collect();
        let obs: Vec<Observation> = db.observations.iter().filter(|o| o.day == day).take(200).cloned().collect();
        let (m, _, _) = k.sample(None, "", vec![Message::user(ask_prompt(day, &cards, &obs, q, self.offset_min))], vec![], 600, &Cancel::new())?;
        Ok(m.text().trim().to_string())
    }

    /// Delete frames older than the retention window (cards and observations are kept).
    pub fn prune(&self, now: u64) -> usize {
        let cutoff = now.saturating_sub(self.cfg.retention_days * 86_400_000);
        self.with(|db| {
            let (old, keep): (Vec<Frame>, Vec<Frame>) = db.frames.drain(..).partition(|f| f.captured_at_ms < cutoff);
            db.frames = keep;
            for f in &old {
                let _ = std::fs::remove_file(&f.path);
            }
            old.len()
        })
        .unwrap_or(0)
    }

    pub fn days(&self) -> Vec<String> {
        let db = self.read();
        let mut d: Vec<String> = db.frames.iter().map(|f| f.day.clone()).chain(db.cards.iter().map(|c| c.day.clone())).collect();
        d.sort();
        d.dedup();
        d.reverse();
        d
    }

    pub fn timeline(&self, day: &str) -> Value {
        let db = self.read();
        let cards: Vec<&Card> = db.cards.iter().filter(|c| c.day == day).collect();
        let mut cats: std::collections::BTreeMap<String, u64> = Default::default();
        let mut apps: std::collections::BTreeMap<String, u64> = Default::default();
        let (mut tracked, mut distraction) = (0, 0);
        for c in &cards {
            let ms = c.end_ms - c.start_ms;
            tracked += ms;
            *cats.entry(c.category.clone()).or_default() += ms;
            if let Some(a) = &c.app_primary {
                *apps.entry(a.clone()).or_default() += ms;
            }
            distraction += c.distractions.iter().map(|d| d.end_ms - d.start_ms).sum::<u64>();
        }
        json!({"day": day, "cards": cards, "standup": db.standups.get(day), "stats": {"trackedMs": tracked, "distractionMs": distraction, "categories": cats.iter().map(|(c, ms)| json!({"category": c, "ms": ms})).collect::<Vec<_>>(), "apps": apps.iter().map(|(d, ms)| json!({"domain": d, "ms": ms})).collect::<Vec<_>>()}})
    }

    pub fn status(&self, k: &Kernel) -> Value {
        let db = self.read();
        let st = self.state.lock().unwrap();
        let count = |s: &str| db.batches.iter().filter(|b| b.status == s).count();
        json!({"enabled": self.cfg.enabled, "captureEnabled": self.cfg.capture_enabled && !db.capture_paused, "captureIntervalSeconds": self.cfg.capture_interval_seconds, "analysisIntervalMinutes": self.cfg.analysis_interval_minutes, "retentionDays": self.cfg.retention_days,
            "visionModel": self.vision_model(k), "modelMissing": self.vision_model(k).is_none().then_some(MODEL_MISSING), "frames": db.frames.len(), "lastCaptureAtMs": st.last_capture_ms, "lastCaptureError": st.last_error,
            "batches": {"pending": count("pending"), "running": count("running"), "done": count("done"), "error": count("error")}, "cards": db.cards.len()})
    }

    pub fn set_capture(&self, on: bool) -> Result<(), String> {
        self.with(|db| db.capture_paused = !on)
    }
}

static SERVICE: OnceLock<Arc<Logbook>> = OnceLock::new();

/// The daemon's logbook (when enabled).
pub fn service() -> Option<&'static Arc<Logbook>> {
    SERVICE.get()
}

/// arkd: start capture / analysis / prune loops when `[integrations.logbook] enabled`.
pub fn start(k: &Kernel) {
    let cfg = LogbookConfig::parse(&k.cfg);
    if !cfg.enabled || SERVICE.get().is_some() {
        return;
    }
    let lb = Arc::new(Logbook::new(&k.paths.data, cfg.clone(), k.cfg.schedule.utc_offset_minutes));
    let _ = SERVICE.set(lb.clone());
    lb.prune(now_ms());
    let cap = node_capture();
    let (l1, l2, k2) = (lb.clone(), lb.clone(), k.clone());
    std::thread::spawn(move || loop {
        l1.capture_tick(&cap);
        std::thread::sleep(Duration::from_secs(l1.cfg.capture_interval_seconds));
    });
    std::thread::spawn(move || {
        let mut ticks = 0u64;
        loop {
            std::thread::sleep(Duration::from_secs(60));
            l2.analysis_tick(&k2);
            ticks += 1;
            if ticks.is_multiple_of(60) {
                l2.prune(now_ms());
            }
        }
    });
}

fn today(lb: &Logbook) -> String {
    day_key(now_ms(), lb.offset_min)
}

/// ARP methods `logbook.*`.
pub fn call(k: &Kernel, method: &str, p: &Value) -> Option<Result<Value, (i32, String)>> {
    if !method.starts_with("logbook.") {
        return None;
    }
    let Some(lb) = service().cloned().or_else(|| LogbookConfig::parse(&k.cfg).enabled.then(|| Arc::new(Logbook::new(&k.paths.data, LogbookConfig::parse(&k.cfg), k.cfg.schedule.utc_offset_minutes)))) else {
        return Some(Err((-32000, "logbook is disabled ([integrations.logbook] enabled = false)".into())));
    };
    let day = p["day"].as_str().map(String::from).unwrap_or_else(|| today(&lb));
    let e = |x: String| (-32000, x);
    Some(match method {
        "logbook.status" => Ok(lb.status(k)),
        "logbook.days" => Ok(json!({"days": lb.days()})),
        "logbook.timeline" => Ok(lb.timeline(&day)),
        "logbook.standup" => lb.standup(k, &day, p["refresh"] == true).map(|t| json!({"day": day, "text": t})).map_err(e),
        "logbook.ask" => match p["question"].as_str().filter(|q| !q.trim().is_empty()) {
            Some(q) => lb.ask(k, &day, q).map(|t| json!({"day": day, "answer": t})).map_err(e),
            None => Err((-32602, "missing `question`".into())),
        },
        "logbook.capture.set" => lb.set_capture(p["enabled"] != false).map(|_| json!({"captureEnabled": p["enabled"] != false})).map_err(e),
        "logbook.analyze.now" => Ok(lb.analyze_now(k)),
        _ => Err((-32601, format!("unknown method `{method}`"))),
    })
}

/// The `logbook` tool: the same operations for the model.
pub struct LogbookTool {
    pub k: Arc<OnceLock<Kernel>>,
}

impl Tool for LogbookTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "logbook".into(),
            description: "The user's automatic work journal (screen-activity timeline). action=status | days | timeline {day?} | standup {day?, refresh?} | ask {question, day?} | analyze_now | capture {enabled}. Days are YYYY-MM-DD (default today). Answers come only from the recorded timeline.".into(),
            input_schema: json!({"type": "object", "properties": {"action": {"type": "string", "enum": ["status", "days", "timeline", "standup", "ask", "analyze_now", "capture"]}, "day": {"type": "string"}, "question": {"type": "string"}, "refresh": {"type": "boolean"}, "enabled": {"type": "boolean"}}, "required": ["action"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, _: &ToolCtx, input: Value) -> ToolOutput {
        let Some(k) = self.k.get() else { return ToolOutput::err("logbook is not available in this host") };
        let method = match input["action"].as_str().unwrap_or("") {
            "analyze_now" => "logbook.analyze.now".to_string(),
            "capture" => "logbook.capture.set".to_string(),
            a => format!("logbook.{a}"),
        };
        match call(k, &method, &input) {
            Some(Ok(v)) => ToolOutput::ok(serde_json::to_string_pretty(&v).unwrap_or_default()),
            Some(Err((_, e))) => ToolOutput::err(e),
            None => ToolOutput::err("unknown action"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_core::*;

    /// Vision → segments; cards → a card covering the batch; standup/ask → fixed text.
    struct Scripted {
        win: Mutex<Option<(u64, u64, i32)>>,
        bad_first: Mutex<bool>,
    }
    impl Provider for Scripted {
        fn id(&self) -> &str {
            "s"
        }
        fn caps(&self, _: &str) -> ModelCaps {
            ModelCaps { context_window: 100_000, max_output: 4096, tools: true, vision: true, explicit_cache: false }
        }
        fn complete(&self, req: &ModelRequest, _: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, ProviderError> {
            let last = req.messages.last().unwrap();
            let t = last.text();
            let (s, e, off) = self.win.lock().unwrap().unwrap();
            let text = if last.content.iter().any(|b| matches!(b, Block::Image { .. })) {
                json!({"segments": [{"start": clock(s, off), "end": clock(e, off), "description": "VS Code: editing store.rs"}]}).to_string()
            } else if t.contains("timeline cards") || t.contains("failed validation") {
                let mut bad = self.bad_first.lock().unwrap();
                if *bad {
                    *bad = false;
                    "not json at all".to_string()
                } else {
                    json!([{"startTime": clock(s, off), "endTime": clock(e, off), "category": "coding", "title": "Logbook store", "summary": "Edited store.rs", "detailedSummary": "d", "distractions": [], "appSites": {"primary": "https://code.visualstudio.com/x", "secondary": ""}}]).to_string()
                }
            } else if t.contains("daily standup") {
                "## Done\n- Logbook store\n## Today\n- tests\n## Blockers\nNone observed".into()
            } else {
                format!("At {} you edited store.rs.", &clock(s, off)[..5])
            };
            Ok(ModelResponse { message: Message::assistant(text), stop: StopReason::EndTurn, usage: Usage::default(), model: "s/v".into() })
        }
    }
    struct Res(Arc<Scripted>);
    impl ark_kernel::kernel::Resolver for Res {
        fn provider(&self, _: &str) -> Result<Arc<dyn Provider>, String> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn clocks_parsing_and_batch_selection() {
        let d0 = day_start("2026-11-03", 480).unwrap();
        assert_eq!(day_key(d0, 480), "2026-11-03");
        assert_eq!(clock_to_ms("2026-11-03", "13:05:09", 480), Some(d0 + (13 * 3600 + 5 * 60 + 9) * 1000));
        assert_eq!(clock_to_ms("2026-11-03", "1:05 pm", 480), Some(d0 + (13 * 3600 + 5 * 60) * 1000));
        assert_eq!(clock_to_ms("2026-11-03", "12:00 am", 480), Some(d0));
        assert_eq!(clock_to_ms("2026-11-03", "25:00", 480), None);
        assert!(parse_cards("[]", "2026-11-03", 480).unwrap_err().contains("no valid cards"));
        let over = json!([{"startTime": "10:00:00", "endTime": "10:30:00", "title": "a", "summary": "s"}, {"startTime": "10:20:00", "endTime": "10:50:00", "title": "b", "summary": "s"}]).to_string();
        assert!(parse_cards(&over, "2026-11-03", 480).unwrap_err().contains("overlap by 10 minutes"));
        let trim = json!([{"startTime": "10:00:00", "endTime": "10:30:30", "title": "a", "summary": "s", "category": "Weird"}, {"startTime": "10:30:00", "endTime": "10:50:00", "title": "b", "summary": "s"}]).to_string();
        let c = parse_cards(&format!("```json\n{trim}\n```"), "2026-11-03", 480).unwrap();
        assert_eq!(c[1].start_ms, c[0].end_ms, "sub-minute overlap trimmed");
        assert_eq!(c[0].category, "other");
        let t10 = clock_to_ms("2026-11-03", "10:00:00", 480).unwrap();
        assert!(validate_coverage(&c, &[(t10, t10 + 3_000_000)], t10, t10 + 3_000_000, 480).is_ok());
        assert!(validate_coverage(&c[..1], &[(t10, t10 + 3_000_000)], t10, t10 + 3_000_000, 480).unwrap_err().contains("not covered"));
        let win = 15 * 60_000;
        let frames = vec![(1, t10), (2, t10 + 30_000), (3, t10 + 60_000)];
        assert_eq!(select_batch(&frames, win, t10 + 120_000, false, 480), None, "window still open");
        assert_eq!(select_batch(&frames, win, t10 + 120_000, true, 480), Some((vec![1, 2, 3], t10, t10 + 60_001)), "forced: ends at last frame");
        assert_eq!(select_batch(&frames, win, t10 + win, false, 480), Some((vec![1, 2, 3], t10, t10 + win)), "elapsed: ends at the boundary");
        let gap = vec![(1, t10), (2, t10 + 10 * 60_000)];
        assert_eq!(select_batch(&gap, win, t10 + 11 * 60_000, false, 480), Some((vec![1], t10, t10 + 1)), "capture gap closes early");
    }

    #[test]
    fn capture_analyze_cards_standup_ask_and_prune() {
        let root = ark_core::tmp::scratch_path(format!("ark-logbook-{}", ark_kernel::util::random_hex(6)));
        let paths = ark_kernel::config::Paths { data: root.join("data"), config_dir: root.join("c"), runtime: root.join("r") };
        let mut cfg: Config = toml::from_str("[integrations.logbook]\nenabled = true\ncapture_interval_seconds = 1\nvision_model = \"s/v\"\n").unwrap();
        cfg.model.default = "s/m".into();
        let lc = LogbookConfig::parse(&cfg);
        assert_eq!(lc.capture_interval_seconds, 5, "clamped to the minimum");
        let sc = Arc::new(Scripted { win: Mutex::new(None), bad_first: Mutex::new(true) });
        let k = ark_kernel::kernel::new_kernel(cfg.clone(), paths.clone(), Arc::new(Res(sc.clone())), vec![], Arc::new(ark_kernel::vault::Vault::empty()), Arc::new(ark_kernel::approver::Policy { allow_privilege: false, allow_egress: false }));
        let lb = Logbook::new(&paths.data, lc, 480);
        let png = |n: u8| [b"\x89PNG\r\n\x1a\n".as_slice(), &[n; 16]].concat();
        let n = AtomicU8::new(0);
        let cap: Capture = Arc::new(move |_| Ok(("image/png".into(), png(n.fetch_add(1, std::sync::atomic::Ordering::SeqCst) / 2))));
        for _ in 0..4 {
            lb.capture_tick(&cap);
        }
        let db = lb.read();
        assert_eq!(db.frames.len(), 4);
        assert_eq!(db.frames.iter().filter(|f| f.idle).count(), 2, "unchanged frames are idle");
        // Timestamps render at second resolution, so script a window of a realistic length
        // (the captures themselves happen back-to-back in this test).
        let (s, e) = (db.frames[0].captured_at_ms, db.frames[2].captured_at_ms + 60_000);
        *sc.win.lock().unwrap() = Some((s, e, 480));
        let r = lb.analyze_now(&k);
        assert_eq!(r["started"], true, "{r}");
        let db = lb.read();
        assert_eq!(db.batches[0].status, "done", "{:?}", db.batches[0].error);
        assert_eq!(db.observations[0].text, "VS Code: editing store.rs");
        assert_eq!(db.cards.len(), 1, "repaired after one bad answer");
        assert_eq!(db.cards[0].app_primary.as_deref(), Some("code.visualstudio.com"));
        assert!(db.cards[0].keyframe_id.is_some());
        let day = db.cards[0].day.clone();
        assert_eq!(lb.days(), vec![day.clone()]);
        let tl = lb.timeline(&day);
        assert_eq!(tl["stats"]["categories"][0]["category"], "coding");
        assert!(lb.standup(&k, &day, false).unwrap().contains("## Done"));
        assert!(lb.read().standups.contains_key(&day), "standup cached");
        assert!(lb.ask(&k, &day, "when did I edit store.rs?").unwrap().contains("store.rs"));
        assert_eq!(lb.analyze_now(&k)["reason"], "no unanalyzed activity captured yet");
        lb.set_capture(false).unwrap();
        lb.capture_tick(&cap);
        assert_eq!(lb.read().frames.len(), 4, "paused");
        assert_eq!(lb.prune(now_ms() + 15 * 86_400_000), 4);
        assert_eq!(lb.read().cards.len(), 1, "cards kept");
        let failing: Capture = Arc::new(|_| Err("no node".into()));
        lb.set_capture(true).unwrap();
        for _ in 0..3 {
            lb.capture_tick(&failing);
        }
        assert_eq!(lb.status(&k)["lastCaptureError"], "no node");
        let _ = std::fs::remove_dir_all(&root);
    }

    use std::sync::atomic::AtomicU8;
}
