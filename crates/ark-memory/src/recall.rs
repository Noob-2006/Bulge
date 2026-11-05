//! Short-term recall signals (OpenClaw short-term-promotion-store.ts, MIT): every
//! memory_search hit on a short-term source (dated daily notes, session transcripts) is
//! counted per chunk with its query hash, day and concept tags. Dreaming's deep phase
//! promotes the chunks that keep being recalled. `<data>/memory/dreaming/short-term.json`.

use crate::index::{dated, Hit};
use crate::util::{self, sha256_hex};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct Entry {
    pub key: String,
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub source: String,
    pub snippet: String,
    pub recall_count: u32,
    /// Signals from light-sleep ingestion of daily notes (not interactive recalls).
    pub daily_count: u32,
    pub total_score: f64,
    pub max_score: f64,
    pub query_hashes: Vec<String>,
    pub recall_days: Vec<String>,
    pub concept_tags: Vec<String>,
    pub first_recalled_ms: u64,
    pub last_recalled_ms: u64,
    pub promoted_ms: Option<u64>,
}

impl Entry {
    pub fn signals(&self) -> u32 {
        self.recall_count + self.daily_count
    }
    pub fn avg_score(&self) -> f64 {
        let n = self.signals();
        if n == 0 {
            0.0
        } else {
            (self.total_score / n as f64).clamp(0.0, 1.0)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct PhaseSignal {
    pub light_hits: u32,
    pub rem_hits: u32,
    pub last_light_ms: Option<u64>,
    pub last_rem_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct Store {
    pub entries: BTreeMap<String, Entry>,
    pub phase_signals: BTreeMap<String, PhaseSignal>,
}

const STOP: &[&str] = &["that", "this", "with", "from", "have", "were", "they", "their", "there", "what", "when", "which", "would", "about", "into", "then", "than", "them", "been", "will", "your", "user", "assistant"];

/// Up to 6 salient concept tokens (≥4 chars or CJK bigrams), most frequent first.
pub fn concept_tags(text: &str) -> Vec<String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for t in util::tokens(text) {
        let cjk = t.chars().all(util::is_cjk);
        if (cjk && t.chars().count() == 2) || (!cjk && t.chars().count() >= 4 && !STOP.contains(&t.as_str()) && !t.chars().all(|c| c.is_ascii_digit())) {
            *counts.entry(t).or_default() += 1;
        }
    }
    let mut v: Vec<(String, usize)> = counts.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.into_iter().take(6).map(|(t, _)| t).collect()
}

pub fn is_short_term(path: &str) -> bool {
    path.starts_with("sessions/") || dated(path).is_some()
}

pub fn file(data: &Path) -> PathBuf {
    data.join("memory/dreaming/short-term.json")
}

impl Store {
    pub fn load(data: &Path) -> Store {
        util::read_json(&file(data)).and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default()
    }
    pub fn save(&self, data: &Path) -> Result<(), String> {
        util::write_json(&file(data), &serde_json::to_value(self).unwrap_or_default())
    }

    // The short-term entry fields are all distinct signals; bundling them into a struct would
    // only move the same values around at every call site.
    #[allow(clippy::too_many_arguments)]
    fn touch(&mut self, key: &str, path: &str, start: usize, end: usize, source: &str, snippet: &str, now: u64) -> &mut Entry {
        let e = self.entries.entry(key.to_string()).or_insert_with(|| Entry { key: key.into(), path: path.into(), start_line: start, end_line: end, source: source.into(), first_recalled_ms: now, ..Default::default() });
        e.snippet = util::clip(&util::compact_ws(snippet), 600);
        e.last_recalled_ms = now;
        e.concept_tags = concept_tags(snippet);
        e
    }

    /// Record interactive recalls of short-term hits. Returns (recorded, skipped).
    pub fn record_hits(&mut self, query: &str, hits: &[Hit], now: u64, offset_min: i32) -> (usize, usize) {
        let qh = sha256_hex(util::compact_ws(&query.to_lowercase()).as_bytes())[..16].to_string();
        let day = util::day_stamp(now, offset_min);
        let (mut rec, mut skip) = (0, 0);
        for h in hits {
            if !is_short_term(&h.path) {
                skip += 1;
                continue;
            }
            let key = format!("{}:{}-{}", h.path, h.start_line, h.end_line);
            let e = self.touch(&key, &h.path, h.start_line, h.end_line, &h.source, &h.snippet, now);
            e.recall_count += 1;
            e.total_score += h.score.clamp(0.0, 1.0);
            e.max_score = e.max_score.max(h.score);
            if !e.query_hashes.contains(&qh) {
                e.query_hashes.push(qh.clone());
            }
            if !e.recall_days.contains(&day) {
                e.recall_days.push(day.clone());
            }
            rec += 1;
        }
        (rec, skip)
    }

    /// Light-sleep daily-note ingestion signal (does not count as a user query).
    // Mirrors the public signal shape of `record_hits` / `touch`; a struct wrapper would make
    // the call sites in dreaming / flush noisier without changing the data flow.
    #[allow(clippy::too_many_arguments)]
    pub fn record_daily(&mut self, path: &str, start: usize, end: usize, snippet: &str, score: f64, now: u64, offset_min: i32) {
        let key = format!("{path}:{start}-{end}");
        let day = util::day_stamp(now, offset_min);
        let e = self.touch(&key, path, start, end, "memory", snippet, now);
        e.daily_count += 1;
        e.total_score += score.clamp(0.0, 1.0);
        e.max_score = e.max_score.max(score);
        if !e.recall_days.contains(&day) {
            e.recall_days.push(day);
        }
    }

    pub fn signal(&mut self, key: &str, phase: &str, now: u64) {
        let s = self.phase_signals.entry(key.to_string()).or_default();
        if phase == "light" {
            s.light_hits += 1;
            s.last_light_ms = Some(now);
        } else {
            s.rem_hits += 1;
            s.last_rem_ms = Some(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(path: &str, score: f64) -> Hit {
        Hit { path: path.into(), start_line: 1, end_line: 3, score, vector_score: 0.0, text_score: score, snippet: "Deployment pipeline uses blue green rollout".into(), source: "memory".into() }
    }

    #[test]
    fn records_short_term_only() {
        let mut s = Store::default();
        let (r, k) = s.record_hits("deploy", &[hit("daily/2026-10-01.md", 0.8), hit("MEMORY.md", 0.9)], 1_000, 0);
        assert_eq!((r, k), (1, 1));
        s.record_hits("Deploy ", &[hit("daily/2026-10-01.md", 0.6)], 2_000, 0);
        s.record_hits("rollout", &[hit("daily/2026-10-01.md", 0.7)], 86_400_000 * 2, 0);
        let e = &s.entries["daily/2026-10-01.md:1-3"];
        assert_eq!(e.recall_count, 3);
        assert_eq!(e.query_hashes.len(), 2, "case/whitespace-folded queries count once");
        assert_eq!(e.recall_days.len(), 2);
        assert!((e.avg_score() - 0.7).abs() < 1e-9);
        assert!(e.concept_tags.contains(&"deployment".to_string()));
        let d = crate::tmp("recall");
        s.save(&d).unwrap();
        assert_eq!(Store::load(&d), s);
        assert!(is_short_term("sessions/abc") && !is_short_term("notes/topic.md"));
    }
}
