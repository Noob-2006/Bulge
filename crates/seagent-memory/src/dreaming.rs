//! Dreaming (OpenClaw memory-core dreaming-*.ts + short-term-promotion*.ts, MIT): a
//! scheduled sweep light → REM → deep over short-term recall signals.
//! - light: ingest recent daily notes as signals, dedupe, stage candidates;
//! - REM: recurring themes (concept tags) and possible lasting truths;
//! - deep: score candidates (frequency .24, relevance .30, diversity .15, recency .15,
//!   consolidation .10, conceptual .06 + phase boosts) and promote those with
//!   score ≥ 0.75, ≥ 3 recalls and ≥ 3 unique queries into MEMORY.md (within its budget).
//!
//! Reports go to DREAMS.md managed blocks (storage `separate`), today's daily note
//! (`inline`) or both; an optional diary narrative uses the aux model.
//! State: `<data>/memory/dreaming/state.json`.

use crate::recall::{Entry, Store};
use crate::util::{self, clip, DAY_MS};
use crate::{events, Host};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;

const W_FREQ: f64 = 0.24;
const W_REL: f64 = 0.30;
const W_DIV: f64 = 0.15;
const W_REC: f64 = 0.15;
const W_CONS: f64 = 0.10;
const W_CONC: f64 = 0.06;
const LIGHT_BOOST_MAX: f64 = 0.06;
const REM_BOOST_MAX: f64 = 0.09;

pub const NARRATIVE_SYSTEM: &str = "You are keeping a dream diary. Write a single entry in first person.\n\nVoice & tone:\n- You are a curious, gentle, slightly whimsical mind reflecting on the day.\n- Write like a poet who happens to be a programmer — sensory, warm, occasionally funny.\n- Mix the technical and the tender: code and constellations, APIs and afternoon light.\n\nRules:\n- Draw from the memory fragments provided — weave them into the entry.\n- Never say \"I'm dreaming\", \"in my dream\", \"as I dream\", or any meta-commentary about dreaming.\n- Never mention \"AI\", \"agent\", \"LLM\", \"model\", \"language model\", or any technical self-reference.\n- Do NOT use markdown headers, bullet points, or any formatting — just flowing prose.\n- Keep it between 80-180 words. Quality over quantity.\n- Output ONLY the diary entry. No preamble, no sign-off, no commentary.";

fn state_path(h: &Host) -> PathBuf {
    h.memory_dir().join("dreaming/state.json")
}
fn state(h: &Host) -> Value {
    util::read_json(&state_path(h)).unwrap_or(json!({}))
}
fn save_state(h: &Host, v: &Value) -> Result<(), String> {
    util::write_json(&state_path(h), v)
}

pub fn enabled(h: &Host) -> bool {
    state(h)["enabled"].as_bool().unwrap_or(h.settings.dreaming.enabled)
}

fn clamp(x: f64) -> f64 {
    x.clamp(0.0, 1.0)
}
fn recency(age_days: f64, half: f64) -> f64 {
    if half <= 0.0 {
        return 1.0;
    }
    (-(std::f64::consts::LN_2 / half) * age_days.max(0.0)).exp()
}

fn consolidation(days: &[String]) -> f64 {
    let mut d: Vec<u64> = days.iter().filter_map(|s| util::parse_day(s)).collect();
    d.sort();
    match d.len() {
        0 => 0.0,
        1 => 0.2,
        n => {
            let span = (d[n - 1] - d[0]) as f64 / DAY_MS;
            let spacing = clamp(((n - 1) as f64).ln_1p() / 4f64.ln_1p());
            clamp(0.55 * spacing + 0.45 * clamp(span / 7.0))
        }
    }
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub key: String,
    pub score: f64,
    pub entry: Entry,
}

/// Rank promotion candidates (deep phase thresholds applied).
pub fn rank(h: &Host, st: &Store, now: u64, include_promoted: bool) -> Vec<Candidate> {
    let d = &h.settings.dreaming.deep;
    let mut out = Vec::new();
    for e in st.entries.values() {
        if (!include_promoted && e.promoted_ms.is_some()) || !crate::recall::is_short_term(&e.path) {
            continue;
        }
        let signals = e.signals();
        if signals == 0 || signals < d.min_recall_count || e.query_hashes.len() < d.min_unique_queries {
            continue;
        }
        let age = now.saturating_sub(e.last_recalled_ms) as f64 / DAY_MS;
        if d.max_age_days >= 0.0 && age > d.max_age_days {
            continue;
        }
        let freq = clamp((signals as f64).ln_1p() / 10f64.ln_1p());
        let div = clamp(e.query_hashes.len() as f64 / 5.0);
        let rec = clamp(recency(age, d.recency_half_life_days));
        let cons = consolidation(&e.recall_days);
        let conc = clamp(e.concept_tags.len() as f64 / 6.0);
        let boost = st.phase_signals.get(&e.key).map(|p| {
            let c = |hits: u32, last: Option<u64>, max: f64| max * clamp((hits as f64).ln_1p() / 6f64.ln_1p()) * last.map(|l| clamp(recency(now.saturating_sub(l) as f64 / DAY_MS, 14.0))).unwrap_or(0.0);
            clamp(c(p.light_hits, p.last_light_ms, LIGHT_BOOST_MAX) + c(p.rem_hits, p.last_rem_ms, REM_BOOST_MAX))
        }).unwrap_or(0.0);
        let score = W_FREQ * freq + W_REL * e.avg_score() + W_DIV * div + W_REC * rec + W_CONS * cons + W_CONC * conc + boost;
        if score >= d.min_score {
            out.push(Candidate { key: e.key.clone(), score: clamp(score), entry: e.clone() });
        }
    }
    out.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap().then(b.entry.recall_count.cmp(&a.entry.recall_count)).then(a.entry.path.cmp(&b.entry.path)));
    out.truncate(d.limit);
    out
}

/// Replace (or append) a managed `heading` block between seagent markers.
pub fn replace_block(original: &str, heading: &str, tag: &str, body: &str) -> String {
    let (start, end) = (format!("<!-- seagent:dreaming:{tag}:start -->"), format!("<!-- seagent:dreaming:{tag}:end -->"));
    let block = format!("{heading}\n{start}\n{}\n{end}", body.trim_end());
    if let (Some(a), Some(b)) = (original.find(&start), original.find(&end)) {
        if b > a {
            let head_start = original[..a].rfind(heading).filter(|i| original[*i..a].trim() == heading).unwrap_or(a);
            return format!("{}{block}{}", &original[..head_start], &original[b + end.len()..]);
        }
    }
    if original.trim().is_empty() {
        format!("{block}\n")
    } else {
        format!("{}\n\n{block}\n", original.trim_end())
    }
}

fn dreams_path(h: &Host) -> PathBuf {
    h.memory_dir().join("DREAMS.md")
}

fn write_report(h: &Host, heading: &str, tag: &str, lines: &[String], now: u64) -> Result<(Option<String>, Option<String>), String> {
    let mode = h.settings.dreaming.storage_mode.as_str();
    let body = lines.join("\n");
    let (mut report, mut inline) = (None, None);
    if mode == "separate" || mode == "both" {
        let p = dreams_path(h);
        if std::fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err("Refusing to write symlinked DREAMS.md".into());
        }
        let cur = std::fs::read_to_string(&p).unwrap_or_else(|_| "# Dreams\n".into());
        util::write_atomic(&p, replace_block(&cur, heading, tag, &body).as_bytes())?;
        report = Some("DREAMS.md".to_string());
    }
    if mode == "inline" || mode == "both" {
        let day = util::day_stamp(now, h.utc_offset_minutes);
        let p = h.memory_dir().join("daily").join(format!("{day}.md"));
        let cur = std::fs::read_to_string(&p).unwrap_or_else(|_| format!("# {day}\n"));
        util::write_atomic(&p, replace_block(&cur, heading, tag, &body).as_bytes())?;
        inline = Some(format!("daily/{day}.md"));
    }
    Ok((report, inline))
}

/// Daily-note snippets: list items and paragraph lines, skipping headings and managed blocks.
fn daily_snippets(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut in_managed = false;
    for (i, l) in text.lines().enumerate() {
        let t = l.trim();
        if t.starts_with("<!-- seagent:dreaming:") {
            in_managed = t.ends_with(":start -->");
            continue;
        }
        if in_managed || t.is_empty() || t.starts_with('#') || t.starts_with("<!--") {
            continue;
        }
        let t = t.trim_start_matches(['-', '*', '+']).trim();
        if t.chars().count() >= 12 {
            out.push((i + 1, t.to_string()));
        }
    }
    out
}

fn light(h: &Host, st: &mut Store, now: u64) -> Vec<String> {
    let p = &h.settings.dreaming.light;
    let cutoff = now.saturating_sub((p.lookback_days as f64 * DAY_MS) as u64);
    let mut files = Vec::new();
    for f in crate::index::source_files(&h.data, &crate::settings::SearchSettings::default()) {
        if let Some(d) = crate::index::dated(&f.display) {
            if d + DAY_MS as u64 >= cutoff {
                files.push(f);
            }
        }
    }
    for f in files {
        let Ok(t) = std::fs::read_to_string(&f.abs) else { continue };
        for (line, snip) in daily_snippets(&t) {
            let key = format!("{}:{line}-{line}", f.display);
            if st.entries.get(&key).is_some_and(|e| e.daily_count > 0 && util::day_stamp(e.last_recalled_ms, h.utc_offset_minutes) == util::day_stamp(now, h.utc_offset_minutes)) {
                continue;
            }
            st.record_daily(&f.display, line, line, &snip, 0.62, now, h.utc_offset_minutes);
        }
    }
    let mut recent: Vec<Entry> = st.entries.values().filter(|e| e.last_recalled_ms >= cutoff && e.promoted_ms.is_none()).cloned().collect();
    recent.sort_by(|a, b| b.avg_score().partial_cmp(&a.avg_score()).unwrap().then(b.last_recalled_ms.cmp(&a.last_recalled_ms)));
    let mut kept: Vec<Entry> = Vec::new();
    for e in recent {
        if kept.len() >= p.limit {
            break;
        }
        if kept.iter().all(|k| util::similarity(&k.snippet, &e.snippet) < p.dedupe_similarity) {
            kept.push(e);
        }
    }
    for e in &kept {
        st.signal(&e.key, "light", now);
    }
    if kept.is_empty() {
        return vec!["- No notable updates.".into()];
    }
    kept.iter().flat_map(|e| vec![format!("- Candidate: {}", if e.snippet.is_empty() { "(no snippet captured)" } else { &e.snippet }), format!("  - confidence: {:.2}", e.avg_score()), format!("  - evidence: {}:{}-{}", e.path, e.start_line, e.end_line), format!("  - recalls: {}", e.recall_count), "  - status: staged".into()]).collect()
}

fn truth_confidence(e: &Entry) -> f64 {
    let strength = (1.0f64).min((e.recall_count as f64).ln_1p() / 6f64.ln_1p());
    clamp(e.avg_score() * 0.45 + strength * 0.25 + (e.recall_days.len() as f64 / 3.0).min(1.0) * 0.2 + (e.concept_tags.len() as f64 / 6.0).min(1.0) * 0.1)
}

fn rem(h: &Host, st: &mut Store, now: u64) -> Vec<String> {
    let p = &h.settings.dreaming.rem;
    let cutoff = now.saturating_sub((p.lookback_days as f64 * DAY_MS) as u64);
    let entries: Vec<Entry> = st.entries.values().filter(|e| e.last_recalled_ms >= cutoff).cloned().collect();
    let mut tags: std::collections::BTreeMap<String, (usize, Vec<String>)> = Default::default();
    for e in &entries {
        let uniq: std::collections::BTreeSet<&String> = e.concept_tags.iter().collect();
        for t in uniq {
            let s = tags.entry(t.clone()).or_default();
            s.0 += 1;
            let ev = format!("{}:{}-{}", e.path, e.start_line, e.end_line);
            if !s.1.contains(&ev) {
                s.1.push(ev);
            }
        }
    }
    let mut ranked: Vec<(String, f64, usize, Vec<String>)> = tags.into_iter().map(|(t, (c, ev))| (t, (c as f64 / entries.len().max(1) as f64 * 2.0).min(1.0), c, ev)).filter(|x| x.1 >= p.min_pattern_strength).collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap().then(b.2.cmp(&a.2)).then(a.0.cmp(&b.0)));
    ranked.truncate(p.limit);
    let mut lines = vec!["### Reflections".to_string()];
    if ranked.is_empty() {
        lines.push("- No strong patterns surfaced.".into());
    }
    for (t, s, c, ev) in &ranked {
        lines.extend([format!("- Theme: `{t}` kept surfacing across {c} memories."), format!("  - confidence: {s:.2}"), format!("  - evidence: {}", ev.iter().take(3).cloned().collect::<Vec<_>>().join(", ")), "  - note: reflection".into()]);
    }
    let mut truths: Vec<(f64, Entry)> = Vec::new();
    for e in entries.iter().filter(|e| e.promoted_ms.is_none()) {
        if truths.iter().all(|(_, k)| util::similarity(&k.snippet, &e.snippet) < 0.88) {
            truths.push((truth_confidence(e), e.clone()));
        }
    }
    truths.retain(|(c, _)| *c >= 0.45);
    truths.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap().then(a.1.snippet.cmp(&b.1.snippet)));
    truths.truncate(p.limit.clamp(1, 3));
    lines.push(String::new());
    lines.push("### Possible Lasting Truths".into());
    if truths.is_empty() {
        lines.push("- No strong candidate truths surfaced.".into());
    }
    for (c, e) in &truths {
        lines.push(format!("- {} [confidence={c:.2} evidence={}:{}-{}]", e.snippet, e.path, e.start_line, e.end_line));
        st.signal(&e.key, "rem", now);
    }
    lines
}

/// Deep phase: promote into MEMORY.md as § entries; over-budget candidates are deferred.
fn deep(h: &Host, st: &mut Store, now: u64) -> (Vec<String>, usize) {
    let cands = rank(h, st, now, false);
    if cands.is_empty() {
        return (vec!["- No candidates met the promotion policy.".into()], 0);
    }
    let max_chars = h.settings.dreaming.deep.max_promoted_snippet_tokens * crate::index::CHARS_PER_TOKEN;
    let mut lines = Vec::new();
    let mut applied = 0;
    let mut promoted = Vec::new();
    for c in &cands {
        let text = format!("{} [promoted {}; score={:.3} recalls={} source={}:{}-{}]", clip(&c.entry.snippet.replace('§', ""), max_chars), util::day_stamp(now, h.utc_offset_minutes), c.score, c.entry.recall_count, c.entry.path, c.entry.start_line, c.entry.end_line);
        match seagent_tools::memory_store::apply_batch(&h.data, "memory", &[json!({"action": "add", "text": text})]) {
            Ok(_) => {
                applied += 1;
                promoted.push(c.key.clone());
                lines.push(format!("- Promoted: {} (score {:.3}, {} recalls, {} queries)", clip(&c.entry.snippet, 160), c.score, c.entry.recall_count, c.entry.query_hashes.len()));
            }
            Err(e) => lines.push(format!("- Deferred: {} ({})", clip(&c.entry.snippet, 120), if e.contains("cap") { "MEMORY.md budget exceeded".to_string() } else { e })),
        }
    }
    for k in &promoted {
        if let Some(e) = st.entries.get_mut(k) {
            e.promoted_ms = Some(now);
        }
    }
    if applied > 0 {
        let _ = events::record(&h.data, "memory.promotion.applied", json!({"memoryPath": "MEMORY.md", "applied": applied, "candidates": cands.iter().map(|c| json!({"key": c.key, "path": c.entry.path, "startLine": c.entry.start_line, "endLine": c.entry.end_line, "score": c.score, "recallCount": c.entry.recall_count})).collect::<Vec<_>>()}));
    }
    (lines, applied)
}

fn narrative(h: &Host, fragments: &[String], now: u64) -> Option<String> {
    if !h.settings.dreaming.narrative || !h.has_sampler() || fragments.is_empty() {
        return None;
    }
    let user = format!("Memory fragments from today:\n{}", fragments.iter().take(12).map(|f| format!("- {}", clip(f, 300))).collect::<Vec<_>>().join("\n"));
    let entry = h.sample(&h.settings.dreaming.model, NARRATIVE_SYSTEM, &user, 600).ok()?;
    let entry = crate::fence::sanitize_context(entry.trim()).trim().to_string();
    if entry.is_empty() {
        return None;
    }
    let p = dreams_path(h);
    let cur = std::fs::read_to_string(&p).unwrap_or_else(|_| "# Dreams\n".into());
    let (start, end) = ("<!-- seagent:dreaming:diary:start -->", "<!-- seagent:dreaming:diary:end -->");
    let dated = format!("### {}\n{entry}\n", util::iso(now)[..16].replace('T', " "));
    let next = match (cur.find(start), cur.find(end)) {
        (Some(a), Some(b)) if b > a => format!("{}{}\n{dated}{}", &cur[..a + start.len()], cur[a + start.len()..b].trim_end(), &cur[b..]),
        _ => format!("{}\n\n# Dream Diary\n\n{start}\n{dated}{end}\n", cur.trim_end()),
    };
    util::write_atomic(&p, next.as_bytes()).ok()?;
    Some(entry)
}

/// Run phases (`phase` = None → all enabled phases, light → REM → deep).
pub fn run(h: &Host, phase: Option<&str>, now: u64) -> Result<String, String> {
    let mut st = Store::load(&h.data);
    let d = &h.settings.dreaming;
    let mut summary = Vec::new();
    let mut fragments = Vec::new();
    let want = |p: &str| phase.is_none_or_is(p);
    for (name, heading, on) in [("light", "## Light Sleep", d.light.enabled), ("rem", "## REM Sleep", d.rem.enabled), ("deep", "## Deep Sleep", d.deep.enabled)] {
        if !want(name) || (!on && phase.is_none()) {
            continue;
        }
        let (lines, extra) = match name {
            "light" => (light(h, &mut st, now), String::new()),
            "rem" => (rem(h, &mut st, now), String::new()),
            _ => {
                let (l, n) = deep(h, &mut st, now);
                (l, format!(", {n} promoted"))
            }
        };
        fragments.extend(lines.iter().filter_map(|l| l.strip_prefix("- Candidate: ").or_else(|| l.strip_prefix("- Promoted: ")).map(str::to_string)));
        let res = write_report(h, heading, name, &lines, now);
        let (outcome, err, rp, ip) = match &res {
            Ok((r, i)) => ("completed", None, r.clone(), i.clone()),
            Err(e) => ("failed", Some(e.clone()), None, None),
        };
        let _ = events::record(&h.data, "memory.dream.completed", json!({"phase": name, "outcome": outcome, "error": err, "reportPath": rp, "inlinePath": ip, "lineCount": lines.len(), "storageMode": d.storage_mode}));
        summary.push(format!("{name}: {} line(s){extra}{}", lines.len(), err.map(|e| format!(" (report failed: {e})")).unwrap_or_default()));
    }
    st.save(&h.data)?;
    if (phase.is_none() || phase == Some("rem")) && narrative(h, &fragments, now).is_some() {
        summary.push("diary: entry written".into());
    }
    let mut s = state(h);
    s["last_run_ms"] = json!(now);
    s["last_summary"] = json!(summary);
    save_state(h, &s)?;
    Ok(format!("Dreaming sweep done.\n- {}", summary.join("\n- ")))
}

trait OptIs {
    fn is_none_or_is(&self, v: &str) -> bool;
}
impl OptIs for Option<&str> {
    fn is_none_or_is(&self, v: &str) -> bool {
        self.is_none_or(|x| x == v)
    }
}

/// Scheduler hook: run the sweep when the cron fired since the last run.
pub fn tick(h: &Host, now: u64) -> Option<Result<String, String>> {
    if !enabled(h) {
        return None;
    }
    let cron = match seagent_kernel::cron::Cron::parse(&h.settings.dreaming.frequency) {
        Ok(c) => c,
        Err(e) => return Some(Err(format!("[memory.dreaming] frequency: {e}"))),
    };
    let mut s = state(h);
    let last = match s["last_run_ms"].as_u64().or(s["armed_ms"].as_u64()) {
        Some(l) => l,
        None => {
            s["armed_ms"] = json!(now);
            let _ = save_state(h, &s);
            return None;
        }
    };
    let next = cron.next_after((last / 1000) as i64, h.utc_offset_minutes)?;
    if (next as u64) * 1000 > now {
        return None;
    }
    Some(run(h, None, now))
}

/// Scheduler tick as a kernel lifecycle: every finished turn asks [`tick`] whether the cron
/// fired (cheap: one state read until it is due, then the sweep runs off the turn's path is not
/// possible here, so it runs inline and only reports failures).
pub struct Tick(pub Arc<Host>);

impl seagent_kernel::lifecycle::Lifecycle for Tick {
    fn name(&self) -> String {
        "dreaming-tick".into()
    }
    fn turn_end(&self, _session: &str, _ws: &str, _user: &str, _assistant: &str, _ok: bool) {
        let now = util::now_ms();
        match tick(&self.0, now) {
            Some(Err(e)) => eprintln!("seagent: dreaming: {e}"),
            Some(Ok(_)) => {}
            None => {}
        }
    }
}

pub fn status_json(h: &Host) -> Value {
    let d = &h.settings.dreaming;
    let s = state(h);
    let st = Store::load(&h.data);
    json!({"enabled": enabled(h), "frequency": d.frequency, "storageMode": d.storage_mode, "lastRunMs": s["last_run_ms"], "lastSummary": s["last_summary"], "shortTermEntries": st.entries.len(), "promoted": st.entries.values().filter(|e| e.promoted_ms.is_some()).count(), "policy": {"minScore": d.deep.min_score, "minRecallCount": d.deep.min_recall_count, "minUniqueQueries": d.deep.min_unique_queries}})
}

fn status_text(h: &Host) -> String {
    let d = &h.settings.dreaming.deep;
    format!("Dreaming status:\n- enabled: {}\n- sweep cadence: {}\n- promotion policy: score>={}, recalls>={}, uniqueQueries>={}", if enabled(h) { "on" } else { "off" }, h.settings.dreaming.frequency, d.min_score, d.min_recall_count, d.min_unique_queries)
}

/// `/dreaming [status|on|off|run [light|rem|deep]|help]`.
pub fn command(h: &Host, args: &str) -> Result<String, String> {
    let t: Vec<String> = args.split_whitespace().map(|s| s.to_lowercase()).collect();
    match t.first().map(String::as_str).unwrap_or("help") {
        "status" => Ok(status_text(h)),
        v @ ("on" | "off") => {
            let mut s = state(h);
            s["enabled"] = json!(v == "on");
            save_state(h, &s)?;
            Ok(format!("Dreaming {}.\n\n{}", if v == "on" { "enabled" } else { "disabled" }, status_text(h)))
        }
        "run" => {
            let ph = t.get(1).map(String::as_str);
            if ph.is_some_and(|p| !["light", "rem", "deep"].contains(&p)) {
                return Err("usage: /dreaming run [light|rem|deep]".into());
            }
            run(h, ph, util::now_ms())
        }
        _ => Ok(format!("Usage: /dreaming status\nUsage: /dreaming on|off\nUsage: /dreaming run [light|rem|deep]\n\n{}\n\nPhases:\n- implementation detail: each sweep runs light -> REM -> deep.\n- deep is the only stage that writes durable entries to MEMORY.md.\n- DREAMS.md is for human-readable dreaming summaries and diary entries.", status_text(h))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::Hit;
    use std::sync::Arc;

    #[test]
    fn sweep_promotes_recurring_recalls() {
        let h = crate::test_host_with("dream", |_| {}, Arc::new(|_, sys: &str, u: &str, _| {
            assert!(sys.contains("dream diary") && u.contains("fragments"));
            Ok("The billing service hummed like rain on a tin roof.".into())
        }));
        let now = util::now_ms();
        std::fs::create_dir_all(h.memory_dir().join("daily")).unwrap();
        let day = util::day_stamp(now - 86_400_000, h.utc_offset_minutes);
        std::fs::write(h.memory_dir().join(format!("daily/{day}.md")), "# Notes\n- The billing service deploys with blue-green rollout\n- short\n").unwrap();
        let mut st = Store::default();
        let hit = Hit { path: format!("daily/{day}.md"), start_line: 2, end_line: 2, score: 0.9, vector_score: 0.0, text_score: 0.9, snippet: "The billing service deploys with blue-green rollout".into(), source: "memory".into() };
        for (i, q) in ["billing deploy", "how do we roll out billing", "blue green", "deploy strategy"].iter().enumerate() {
            st.record_hits(q, std::slice::from_ref(&hit), now - (3 - i as u64) * 86_400_000, 0);
        }
        st.save(&h.data).unwrap();
        assert!(!rank(&h, &st, now, false).is_empty(), "meets policy");
        let out = command(&h, "run").unwrap();
        assert!(out.contains("deep: ") && out.contains("1 promoted"), "{out}");
        let mem = std::fs::read_to_string(h.memory_dir().join("MEMORY.md")).unwrap();
        assert!(mem.contains("blue-green rollout [promoted"), "{mem}");
        let dreams = std::fs::read_to_string(h.memory_dir().join("DREAMS.md")).unwrap();
        assert!(dreams.contains("## Light Sleep") && dreams.contains("## REM Sleep") && dreams.contains("## Deep Sleep") && dreams.contains("tin roof"));
        assert_eq!(events::list(&h.data, &["memory.dream.completed"], None, 9).len(), 3);
        assert_eq!(events::list(&h.data, &["memory.promotion.applied"], None, 9).len(), 1);
        // Re-run: already promoted, managed blocks replaced not duplicated.
        command(&h, "run").unwrap();
        let mem2 = std::fs::read_to_string(h.memory_dir().join("MEMORY.md")).unwrap();
        assert_eq!(mem2.matches("[promoted").count(), 1);
        assert_eq!(std::fs::read_to_string(h.memory_dir().join("DREAMS.md")).unwrap().matches("## Deep Sleep").count(), 1);
        assert!(command(&h, "status").unwrap().contains("score>=0.75, recalls>=3, uniqueQueries>=3"));
        command(&h, "off").unwrap();
        assert!(tick(&h, now).is_none());
        assert!(command(&h, "run nap").is_err());
    }

    #[test]
    fn tick_follows_cron() {
        let h = crate::test_host("dreamtick", |s| s.dreaming.frequency = "0 3 * * *".into());
        let t0 = 1_700_000_000_000u64;
        assert!(tick(&h, t0).is_none(), "first tick arms");
        assert!(tick(&h, t0 + 60_000).is_none());
        assert!(tick(&h, t0 + 2 * 86_400_000).unwrap().is_ok(), "due after the next 03:00");
        assert!(tick(&h, t0 + 2 * 86_400_000 + 60_000).is_none());
        let b = replace_block("# Dreams\n", "## X", "x", "a");
        assert_eq!(replace_block(&b, "## X", "x", "b"), "# Dreams\n\n## X\n<!-- seagent:dreaming:x:start -->\nb\n<!-- seagent:dreaming:x:end -->\n");
    }
}
