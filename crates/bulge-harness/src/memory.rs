//! Agent memory: evidence-cited lessons the agent accumulates across jobs and
//! retrieves by relevance before the next one (the "learns over use" goal).
//!
//! Modelled on Harness²'s experience library — every lesson carries a `cue`
//! (when it applies), the `lesson` itself, and `evidence` (why it is trusted) —
//! and on the user's own markdown-with-frontmatter memory layout: one file per
//! lesson under a `lessons/` directory, plus a one-line `INDEX.md`.
//!
//! Retrieval here is an in-process keyword ranker, not SQLite FTS: a deliberate,
//! dependency-free stand-in. The cue is weighted over the body, and confidence
//! breaks ties, so the few most relevant lessons surface for the system prompt.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Where lesson files live under a harness/memory root.
pub const LESSONS_DIR: &str = "lessons";
/// The human-readable index file name.
pub const INDEX_FILE: &str = "INDEX.md";

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

/// Lowercase alphanumeric word tokens (ASCII-folded), for overlap scoring.
fn tokens(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(|word| word.to_ascii_lowercase())
        .collect()
}

/// Relevance of one lesson to a query: cue overlap counts double, body overlap
/// once, then scaled by confidence. Zero when nothing overlaps.
fn relevance(lesson: &Lesson, query_tokens: &[String]) -> f32 {
    if query_tokens.is_empty() {
        return 0.0;
    }
    let cue: std::collections::HashSet<String> = tokens(&lesson.cue).into_iter().collect();
    let body: std::collections::HashSet<String> = tokens(&lesson.lesson).into_iter().collect();
    let mut score = 0.0_f32;
    for token in query_tokens {
        if cue.contains(token) {
            score += 2.0;
        } else if body.contains(token) {
            score += 1.0;
        }
    }
    // Confidence never zeroes a match (floor 0.1) but does order ties.
    score * (0.1 + 0.9 * lesson.confidence.clamp(0.0, 1.0))
}

/// The most relevant lessons for `query`, best first, up to `k`. Lessons that do
/// not overlap the query at all are left out. Deterministic: ties fall back to
/// higher confidence, then id order.
pub fn retrieve<'a>(lessons: &'a [Lesson], query: &str, k: usize) -> Vec<&'a Lesson> {
    let query_tokens = tokens(query);
    let mut scored: Vec<(f32, &Lesson)> = lessons
        .iter()
        .map(|lesson| (relevance(lesson, &query_tokens), lesson))
        .filter(|(score, _)| *score > 0.0)
        .collect();
    scored.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.1.confidence.partial_cmp(&a.1.confidence).unwrap_or(std::cmp::Ordering::Equal))
            .then_with(|| a.1.id.cmp(&b.1.id))
    });
    scored.into_iter().take(k).map(|(_, lesson)| lesson).collect()
}

/// A `<lessons>` block for the system prompt: one `cue → lesson` line each.
/// Empty input yields an empty string (nothing to inject).
pub fn brief(lessons: &[&Lesson]) -> String {
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

/// The `lessons/` directory under a memory root.
pub fn lessons_dir(root: &Path) -> PathBuf {
    root.join(LESSONS_DIR)
}

/// Load every parseable `*.md` lesson under `<root>/lessons/`, sorted by id.
/// Returns `(lessons, problems)`: a malformed file is reported, not fatal, so one
/// bad file never hides the rest.
pub fn load(root: &Path) -> std::io::Result<(Vec<Lesson>, Vec<String>)> {
    let dir = lessons_dir(root);
    let mut lessons = Vec::new();
    let mut problems = Vec::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        // No directory yet is simply an empty memory.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((lessons, problems)),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let Some(id) = path.file_stem().and_then(|s| s.to_str()) else { continue };
        let source = std::fs::read_to_string(&path)?;
        match parse(id, &source) {
            Ok(lesson) => lessons.push(lesson),
            Err(message) => problems.push(format!("{}: {message}", path.display())),
        }
    }
    lessons.sort_by(|a, b| a.id.cmp(&b.id));
    Ok((lessons, problems))
}

/// Write one lesson to `<root>/lessons/<id>.md` (creating the directory), then
/// rewrite `INDEX.md`. Rejects a not-well-formed lesson so the store never gains
/// a lesson missing its cue or evidence.
pub fn save(root: &Path, lesson: &Lesson) -> std::io::Result<()> {
    if !lesson.is_well_formed() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "lesson is missing cue, lesson, or evidence"));
    }
    let dir = lessons_dir(root);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join(format!("{}.md", lesson.id)), render(lesson))?;
    let (lessons, _) = load(root)?;
    std::fs::write(root.join(INDEX_FILE), index_markdown(&lessons))?;
    Ok(())
}

/// One-line-per-lesson index (id — cue), stable by id.
pub fn index_markdown(lessons: &[Lesson]) -> String {
    let mut out = String::from("# Lessons\n\n");
    for lesson in lessons {
        out.push_str(&format!("- {} — {}\n", lesson.id, lesson.cue.trim()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lesson(id: &str, cue: &str, body: &str, confidence: f32) -> Lesson {
        Lesson::new(id, cue, body, "seen in job j1", confidence)
    }

    #[test]
    fn retrieve_ranks_cue_matches_above_body_matches() {
        let lessons = vec![
            lesson("a", "running cargo tests", "use --workspace", 0.9),
            lesson("b", "editing TOML", "cargo manifests need a newline", 0.9),
            lesson("c", "writing docs", "keep it short", 0.9),
        ];
        let hits = retrieve(&lessons, "how do I run cargo tests", 3);
        assert_eq!(hits[0].id, "a", "cue match should win");
        assert_eq!(hits[1].id, "b", "body match ranks below cue match");
        assert_eq!(hits.len(), 2, "the unrelated lesson is left out");
    }

    #[test]
    fn retrieve_breaks_ties_by_confidence_then_id() {
        let lessons = vec![
            lesson("z", "cargo tests", "x", 0.5),
            lesson("a", "cargo tests", "x", 0.9),
            lesson("m", "cargo tests", "x", 0.9),
        ];
        let hits = retrieve(&lessons, "cargo tests", 3);
        assert_eq!(hits.iter().map(|l| l.id.as_str()).collect::<Vec<_>>(), vec!["a", "m", "z"]);
    }

    #[test]
    fn retrieve_empty_query_or_no_overlap_returns_nothing() {
        let lessons = vec![lesson("a", "cargo tests", "x", 0.9)];
        assert!(retrieve(&lessons, "", 3).is_empty());
        assert!(retrieve(&lessons, "unrelated words here", 3).is_empty());
    }

    #[test]
    fn brief_lists_retrieved_lessons() {
        let lessons = vec![lesson("a", "running cargo tests", "use --workspace", 0.9)];
        let hits = retrieve(&lessons, "cargo tests", 3);
        let text = brief(&hits);
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

    #[test]
    fn save_and_load_persist_lessons_and_skip_malformed() {
        let root = std::env::temp_dir().join(format!("bulge-mem-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&root);

        save(&root, &lesson("a", "running cargo tests", "use --workspace", 0.9)).unwrap();
        save(&root, &lesson("b", "editing TOML", "end with a newline", 0.7)).unwrap();
        // A malformed file alongside the good ones.
        std::fs::write(lessons_dir(&root).join("bad.md"), "not a lesson").unwrap();

        let (lessons, problems) = load(&root).unwrap();
        assert_eq!(lessons.len(), 2);
        assert_eq!(lessons[0].id, "a");
        assert_eq!(problems.len(), 1, "the malformed file is reported, not fatal");

        let index = std::fs::read_to_string(root.join(INDEX_FILE)).unwrap();
        assert!(index.contains("a — running cargo tests"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn save_rejects_an_ill_formed_lesson() {
        let root = std::env::temp_dir().join(format!("bulge-mem-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&root);
        let bad = Lesson::new("a", "cue", "lesson", "   ", 0.5); // blank evidence
        assert!(save(&root, &bad).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
