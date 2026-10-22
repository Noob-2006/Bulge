//! The performance book: per-(role, model) outcomes with a Laplace-smoothed
//! believability score.
//!
//! Tracking outcomes is the Valve peer-review half of the design; ranking by
//! believability is the Bridgewater credibility half. The book is persisted as
//! deterministic pretty JSON so it can be read by humans and diffed.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const VERSION: u32 = 1;

/// The outcome of one attempt by a (role, model) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The deliverable was accepted.
    Accepted,
    /// The deliverable was rejected with feedback.
    Rejected,
    /// The attempt failed before or during review.
    Failed,
}

/// Accumulated outcomes for one (role, model) pair.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Record {
    /// Attempts accepted.
    pub accepted: u64,
    /// Attempts rejected.
    pub rejected: u64,
    /// Attempts that failed.
    pub failed: u64,
    /// Total tokens spent across attempts.
    pub tokens: u64,
    /// Time of the most recent attempt in Unix milliseconds.
    pub last_ms: u64,
}

impl Record {
    /// Total attempts recorded.
    pub fn attempts(&self) -> u64 {
        self.accepted + self.rejected + self.failed
    }

    /// Laplace-smoothed success rate: `(accepted + 1) / (attempts + 2)`.
    /// Returns 0.5 with no history.
    pub fn believability(&self) -> f64 {
        (self.accepted as f64 + 1.0) / (self.attempts() as f64 + 2.0)
    }

    /// Mean tokens per attempt, or `None` with no attempts.
    pub fn mean_tokens(&self) -> Option<f64> {
        let attempts = self.attempts();
        (attempts > 0).then(|| self.tokens as f64 / attempts as f64)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct BookFile {
    version: u32,
    records: Vec<BookRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BookRecord {
    role: String,
    model: String,
    #[serde(flatten)]
    record: Record,
}

/// Outcomes per (role, model), persisted as deterministic pretty JSON.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PerformanceBook {
    records: BTreeMap<(String, String), Record>,
}

impl PerformanceBook {
    /// Load a book. A missing file is an empty book; malformed JSON is an error.
    pub fn load(path: &Path) -> Result<PerformanceBook, String> {
        let source = match std::fs::read_to_string(path) {
            Ok(source) => source,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => {
                return Err(format!("read {}: {error}", path.display()));
            }
        };
        let file: BookFile = serde_json::from_str(&source)
            .map_err(|error| format!("parse {}: {error}", path.display()))?;
        if file.version != VERSION {
            return Err(format!(
                "unsupported performance book version {} (expected {VERSION})",
                file.version
            ));
        }
        let mut records = BTreeMap::new();
        for entry in file.records {
            records.insert((entry.role, entry.model), entry.record);
        }
        Ok(Self { records })
    }

    /// Atomically save the book: write `<path>.tmp` then rename it into place,
    /// creating parent directories.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create {}: {error}", parent.display()))?;
        }
        let file = BookFile {
            version: VERSION,
            records: self
                .records
                .iter()
                .map(|((role, model), record)| BookRecord {
                    role: role.clone(),
                    model: model.clone(),
                    record: record.clone(),
                })
                .collect(),
        };
        let json = serde_json::to_string_pretty(&file)
            .map_err(|error| format!("encode performance book: {error}"))?;
        let mut temporary = path.as_os_str().to_os_string();
        temporary.push(".tmp");
        let temporary = PathBuf::from(temporary);
        std::fs::write(&temporary, json)
            .map_err(|error| format!("write {}: {error}", temporary.display()))?;
        std::fs::rename(&temporary, path).map_err(|error| {
            format!(
                "rename {} to {}: {error}",
                temporary.display(),
                path.display()
            )
        })
    }

    /// Record one attempt for `role` and `model`.
    pub fn record(&mut self, role: &str, model: &str, verdict: Verdict, tokens: u64, at_ms: u64) {
        let record = self
            .records
            .entry((role.to_string(), model.to_string()))
            .or_default();
        match verdict {
            Verdict::Accepted => record.accepted += 1,
            Verdict::Rejected => record.rejected += 1,
            Verdict::Failed => record.failed += 1,
        }
        record.tokens += tokens;
        record.last_ms = at_ms;
    }

    /// The record for `role` and `model`, or the default when unknown.
    pub fn get(&self, role: &str, model: &str) -> Record {
        self.records
            .get(&(role.to_string(), model.to_string()))
            .cloned()
            .unwrap_or_default()
    }

    /// Rank `candidates` for `role`: higher believability first; ties (within
    /// 1e-9) broken by lower mean tokens (unknown mean sorts after known), then
    /// by the candidate's original position. Returns (model, believability).
    pub fn rank(&self, role: &str, candidates: &[String]) -> Vec<(String, f64)> {
        let mut ranked: Vec<(usize, String, f64, Option<f64>)> = candidates
            .iter()
            .enumerate()
            .map(|(index, model)| {
                let record = self.get(role, model);
                (
                    index,
                    model.clone(),
                    record.believability(),
                    record.mean_tokens(),
                )
            })
            .collect();
        ranked.sort_by(|left, right| {
            if (left.2 - right.2).abs() > 1e-9 {
                return right.2.total_cmp(&left.2);
            }
            let tokens = match (left.3, right.3) {
                (Some(left), Some(right)) => left.total_cmp(&right),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            };
            tokens.then_with(|| left.0.cmp(&right.0))
        });
        ranked
            .into_iter()
            .map(|(_, model, believability, _)| (model, believability))
            .collect()
    }

    /// The best candidate not in `exclude` (by [`PerformanceBook::rank`]), or
    /// `None` when every candidate was excluded.
    pub fn choose(&self, role: &str, candidates: &[String], exclude: &[String]) -> Option<String> {
        self.rank(role, candidates)
            .into_iter()
            .find(|(model, _)| !exclude.iter().any(|excluded| excluded == model))
            .map(|(model, _)| model)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn temp_dir(label: &str) -> TempDir {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "bulge-org-perf-{label}-{}-{sequence}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir(path)
    }

    fn candidates(models: &[&str]) -> Vec<String> {
        models.iter().map(|model| (*model).to_string()).collect()
    }

    #[test]
    fn believability_is_laplace_smoothed() {
        assert_eq!(Record::default().believability(), 0.5);
        assert_eq!(
            Record {
                accepted: 3,
                ..Record::default()
            }
            .believability(),
            0.8
        );
        assert_eq!(
            Record {
                accepted: 1,
                rejected: 1,
                ..Record::default()
            }
            .believability(),
            0.5
        );
    }

    #[test]
    fn mean_tokens_requires_attempts() {
        assert_eq!(Record::default().mean_tokens(), None);
        assert_eq!(
            Record {
                accepted: 2,
                tokens: 61,
                ..Record::default()
            }
            .mean_tokens(),
            Some(30.5)
        );
    }

    #[test]
    fn record_accumulates_every_outcome() {
        let mut book = PerformanceBook::default();
        book.record("implementer", "alpha", Verdict::Accepted, 10, 100);
        book.record("implementer", "alpha", Verdict::Rejected, 20, 200);
        book.record("implementer", "alpha", Verdict::Failed, 30, 300);
        let record = book.get("implementer", "alpha");
        assert_eq!(
            record,
            Record {
                accepted: 1,
                rejected: 1,
                failed: 1,
                tokens: 60,
                last_ms: 300,
            }
        );
        assert_eq!(record.attempts(), 3);
        assert_eq!(book.get("implementer", "missing"), Record::default());
    }

    #[test]
    fn rank_orders_by_believability_then_tokens_then_position() {
        let mut book = PerformanceBook::default();
        book.record("implementer", "alpha", Verdict::Accepted, 100, 1);
        book.record("implementer", "beta", Verdict::Accepted, 10, 2);
        book.record("implementer", "gamma", Verdict::Rejected, 50, 3);
        book.record("implementer", "delta", Verdict::Accepted, 10, 4);
        book.record("implementer", "delta", Verdict::Rejected, 10, 5);
        let ranked = book.rank(
            "implementer",
            &candidates(&["gamma", "alpha", "beta", "delta", "unknown"]),
        );
        let models: Vec<&str> = ranked.iter().map(|(model, _)| model.as_str()).collect();
        assert_eq!(models, ["beta", "alpha", "delta", "unknown", "gamma"]);
        assert!((ranked[0].1 - 2.0 / 3.0).abs() < 1e-12);

        let tied = book.rank("elsewhere", &candidates(&["first", "second"]));
        let models: Vec<&str> = tied.iter().map(|(model, _)| model.as_str()).collect();
        assert_eq!(models, ["first", "second"]);
    }

    #[test]
    fn choose_skips_excluded_and_returns_none_when_all_are_excluded() {
        let mut book = PerformanceBook::default();
        book.record("implementer", "alpha", Verdict::Accepted, 10, 1);
        book.record("implementer", "beta", Verdict::Rejected, 10, 2);
        let candidates = candidates(&["alpha", "beta"]);
        assert_eq!(
            book.choose("implementer", &candidates, &[]),
            Some("alpha".to_string())
        );
        assert_eq!(
            book.choose("implementer", &candidates, &["alpha".to_string()]),
            Some("beta".to_string())
        );
        assert_eq!(
            book.choose(
                "implementer",
                &candidates,
                &["alpha".to_string(), "beta".to_string()]
            ),
            None
        );
        assert_eq!(book.choose("implementer", &[], &[]), None);
    }

    #[test]
    fn save_load_round_trip_is_deterministic_and_sorted() {
        let dir = temp_dir("round-trip");
        let path = dir.0.join("nested").join("performance.json");
        let mut book = PerformanceBook::default();
        book.record("zeta", "beta", Verdict::Rejected, 3, 30);
        book.record("implementer", "alpha", Verdict::Accepted, 10, 10);
        book.record("zeta", "alpha", Verdict::Failed, 2, 20);

        book.save(&path).expect("save");
        let first = std::fs::read(&path).expect("read first save");
        book.save(&path).expect("save again");
        let second = std::fs::read(&path).expect("read second save");
        assert_eq!(first, second, "saves must be byte-identical");

        let text = String::from_utf8(first).expect("utf-8");
        assert!(text.contains("\"version\": 1"), "{text}");
        let implementer = text.find("\"implementer\"").expect("implementer record");
        let zeta_alpha = text.find("\"zeta\"").expect("zeta record");
        assert!(implementer < zeta_alpha, "records are not sorted: {text}");

        let loaded = PerformanceBook::load(&path).expect("load");
        assert_eq!(loaded, book);
    }

    #[test]
    fn missing_file_is_an_empty_book() {
        let dir = temp_dir("missing");
        let book = PerformanceBook::load(&dir.0.join("does-not-exist.json")).expect("load");
        assert_eq!(book, PerformanceBook::default());
    }

    #[test]
    fn malformed_json_is_an_error() {
        let dir = temp_dir("malformed");
        let path = dir.0.join("performance.json");
        std::fs::write(&path, "{not valid json").expect("write malformed");
        let error = PerformanceBook::load(&path).expect_err("malformed must fail");
        assert!(error.contains("parse"), "{error}");
    }
}
