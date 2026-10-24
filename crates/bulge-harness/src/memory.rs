//! Agent memory: evidence-cited lessons the agent accumulates across jobs and
//! retrieves by relevance before the next one (the "learns over use" goal).
//!
//! Modelled on Harness²'s experience library — every lesson carries a `cue`
//! (when it applies), the `lesson` itself, and `evidence` (why it is trusted) —
//! and on the user's own markdown-with-frontmatter memory layout: one file per
//! lesson under a `lessons/` directory, plus a one-line `INDEX.md`.
//!
//! Lessons are stored and retrieved by [`crate::store::MemoryStore`] (SQLite,
//! FTS5/BM25). This module keeps the lesson type, the `<lessons>` prompt block,
//! and the markdown form the earlier file-based memory used (read once, when the
//! store imports it).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Where lesson files live under a harness/memory root.
pub const LESSONS_DIR: &str = "lessons";

/// One accumulated lesson. `id` is its file stem (a slug); the rest is the
/// frontmatter contract, with the lesson text in the file body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Lesson {
    pub id: String,
    /// When this applies — the primary retrieval key.
    pub cue: String,
    /// What to do (the file body).
    pub lesson: String,
    /// Why it is trusted: the job, file, or result it came from.
    pub evidence: String,
    /// Confidence in [0, 1]; ties in relevance break toward higher confidence.
    pub confidence: f32,
    /// How many times this lesson has been retrieved (reserved for decay).
    pub uses: u32,
}

impl Lesson {
    /// A new lesson with no recorded uses and a clamped confidence.
    pub fn new(id: impl Into<String>, cue: impl Into<String>, lesson: impl Into<String>, evidence: impl Into<String>, confidence: f32) -> Self {
        Self {
            id: id.into(),
            cue: cue.into(),
            lesson: lesson.into(),
            evidence: evidence.into(),
            confidence: confidence.clamp(0.0, 1.0),
            uses: 0,
        }
    }

    /// Well-formed when every cited field is present (same bar as Harness²).
    pub fn is_well_formed(&self) -> bool {
        !self.cue.trim().is_empty() && !self.lesson.trim().is_empty() && !self.evidence.trim().is_empty()
    }
}

/// A `<lessons>` block for the system prompt: one `cue → lesson` line each.
/// Empty input yields an empty string (nothing to inject).
pub fn brief(lessons: &[Lesson]) -> String {
    if lessons.is_empty() {
        return String::new();
    }
    let mut out = String::from("<lessons>\n");
    for lesson in lessons {
        out.push_str("- ");
        out.push_str(lesson.cue.trim());
        out.push_str(" → ");
        out.push_str(lesson.lesson.trim());
        out.push('\n');
    }
    out.push_str("</lessons>");
    out
}

/// Render a lesson to its on-disk markdown form: a `---` frontmatter block
/// carrying the cited fields, then the lesson text as the body.
pub fn render(lesson: &Lesson) -> String {
    format!(
        "---\ncue: {}\nevidence: {}\nconfidence: {}\nuses: {}\n---\n{}\n",
        lesson.cue.trim(),
        lesson.evidence.trim(),
        lesson.confidence,
        lesson.uses,
        lesson.lesson.trim(),
    )
}

/// Parse one lesson file: a `---`-delimited frontmatter block (`cue`,
/// `evidence`, optional `confidence`/`uses`) followed by the lesson body.
pub fn parse(id: &str, source: &str) -> Result<Lesson, String> {
    let mut fields = BTreeMap::new();
    let mut lines = source.lines();
    if lines.next().map(str::trim) != Some("---") {
        return Err("a lesson file must start with a `---` frontmatter line".into());
    }
    let mut body_lines = Vec::new();
    let mut in_body = false;
    for line in lines {
        if !in_body {
            if line.trim() == "---" {
                in_body = true;
                continue;
            }
            if line.trim().is_empty() {
                continue;
            }
            let (key, value) = line.split_once(':').ok_or_else(|| format!("frontmatter line is not `key: value`: {line:?}"))?;
            fields.insert(key.trim().to_string(), value.trim().to_string());
        } else {
            body_lines.push(line);
        }
    }
    if !in_body {
        return Err("lesson frontmatter is not closed by a `---` line".into());
    }
    let cue = fields.get("cue").cloned().unwrap_or_default();
    if cue.trim().is_empty() {
        return Err("lesson needs a non-empty `cue:`".into());
    }
    let evidence = fields.get("evidence").cloned().unwrap_or_default();
    if evidence.trim().is_empty() {
        return Err("lesson needs a non-empty `evidence:`".into());
    }
    let confidence = match fields.get("confidence") {
        Some(raw) => raw.parse::<f32>().map_err(|_| format!("confidence is not a number: {raw:?}"))?.clamp(0.0, 1.0),
        None => 0.5,
    };
    let uses = match fields.get("uses") {
        Some(raw) => raw.parse::<u32>().map_err(|_| format!("uses is not an integer: {raw:?}"))?,
        None => 0,
    };
    let lesson = body_lines.join("\n").trim().to_string();
    if lesson.is_empty() {
        return Err("lesson body is empty".into());
    }
    Ok(Lesson { id: id.to_string(), cue, lesson, evidence, confidence, uses })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lesson(id: &str, cue: &str, body: &str, confidence: f32) -> Lesson {
        Lesson::new(id, cue, body, "seen in job j1", confidence)
    }

    #[test]
    fn brief_lists_retrieved_lessons() {
        let lessons = vec![lesson("a", "running cargo tests", "use --workspace", 0.9)];
        let text = brief(&lessons);
        assert!(text.starts_with("<lessons>"));
        assert!(text.contains("running cargo tests → use --workspace"));
        assert!(text.ends_with("</lessons>"));
        assert_eq!(brief(&[]), "");
    }

    #[test]
    fn render_then_parse_round_trips() {
        let original = Lesson::new("a", "running cargo tests", "use --workspace\nand -p for one crate", "job j1 step 4", 0.8);
        let parsed = parse("a", &render(&original)).expect("round-trips");
        assert_eq!(parsed, original);
    }

    #[test]
    fn parse_rejects_missing_cited_fields() {
        assert!(parse("a", "no frontmatter").is_err());
        assert!(parse("a", "---\nevidence: x\n---\nbody").is_err(), "missing cue");
        assert!(parse("a", "---\ncue: x\n---\nbody").is_err(), "missing evidence");
        assert!(parse("a", "---\ncue: x\nevidence: y\n---\n").is_err(), "empty body");
    }
}
