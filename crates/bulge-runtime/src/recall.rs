//! Recall past job transcripts: `bulge recall <query...> [--limit N]`.
//!
//! The job store is append-only JSONL. This module deliberately never parses the
//! event schema: it treats each `job.jsonl` as plain text and ranks it with the
//! same keyword-overlap style as the harness memory retriever, so a schema change
//! cannot break recall.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// The event-log file inside every job directory.
const JOB_FILE: &str = "job.jsonl";
/// How many hits the CLI shows unless `--limit` overrides it.
const DEFAULT_LIMIT: usize = 10;
/// Maximum characters in a snippet.
const SNIPPET_CHARS: usize = 200;

/// One search hit.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RecallHit {
    pub job_id: String,
    pub title: String,
    pub score: f32,
    /// A short excerpt around the best-matching line (<= ~200 chars, single line).
    pub snippet: String,
    /// File mtime (Unix seconds) for newest-first tie-breaking / display.
    pub modified: u64,
}

/// Lowercase alphanumeric word tokens (ASCII-folded), for overlap scoring.
fn tokens(text: &str) -> Vec<String> {
    // ASCII alphanumerics group into words; every other alphanumeric char (CJK,
    // etc.) is its own unigram token, so a Chinese query like "營收" matches a run
    // like "計算每月營收" instead of requiring the whole run to be identical.
    let mut out = Vec::new();
    let mut word = String::new();
    for c in text.chars() {
        if c.is_ascii_alphanumeric() {
            word.push(c.to_ascii_lowercase());
            continue;
        }
        if !word.is_empty() {
            out.push(std::mem::take(&mut word));
        }
        if c.is_alphanumeric() {
            out.push(c.to_lowercase().collect());
        }
    }
    if !word.is_empty() {
        out.push(word);
    }
    out
}

/// Distinct query tokens, in first-seen order.
fn distinct_tokens(query: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for token in tokens(query) {
        if seen.insert(token.clone()) {
            out.push(token);
        }
    }
    out
}

/// Score one job's raw text. `None` when no distinct query token occurs.
///
/// The integer part is the number of distinct matching query tokens; the
/// fractional part (at most 0.99) is a frequency bonus, so one extra distinct
/// match always outranks any amount of repetition.
fn score_text(text: &str, query_tokens: &[String], wanted: &HashSet<&str>) -> Option<(f32, String)> {
    let job_tokens = tokens(text);
    let mut counts: HashMap<&str, usize> = HashMap::with_capacity(job_tokens.len());
    for token in &job_tokens {
        *counts.entry(token.as_str()).or_insert(0) += 1;
    }

    let mut distinct = 0_u32;
    let mut total = 0_usize;
    for query_token in query_tokens {
        if let Some(&count) = counts.get(query_token.as_str()) {
            distinct += 1;
            total += count;
        }
    }
    if distinct == 0 {
        return None;
    }

    let bonus = (0.01 * total as f32).min(0.99);
    Some((distinct as f32 + bonus, snippet_for(text, wanted)))
}

/// The first line containing a query token, flattened and clipped, char-safe.
fn snippet_for(text: &str, wanted: &HashSet<&str>) -> String {
    // Prefer the job's own conclusion: the last `"summary":"…"` (a StatusChanged
    // event) carries what the job actually produced — the useful recall payload,
    // not a metadata line. Fall back to the first query-matching line.
    if let Some(summary) = extract_summary(text) {
        let clipped = clip_line(&summary);
        if !clipped.is_empty() {
            return clipped;
        }
    }
    for line in text.lines() {
        if tokens(line).iter().any(|token| wanted.contains(token.as_str())) {
            return clip_line(line);
        }
    }
    String::new()
}

/// Extract the last `"summary":"…"` JSON string value from the raw log text, with
/// the common escapes decoded. Best-effort and schema-agnostic: it scans for the
/// key and reads until the closing unescaped quote.
fn extract_summary(text: &str) -> Option<String> {
    let key = "\"summary\":\"";
    let pos = text.rfind(key)? + key.len();
    let mut out = String::new();
    let mut chars = text[pos..].chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') | Some('t') | Some('r') => out.push(' '),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some(other) => out.push(other),
                None => break,
            }
            continue;
        }
        if c == '"' {
            break;
        }
        out.push(c);
    }
    let trimmed = out.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Collapse a log line to one trimmed line and clip it to [`SNIPPET_CHARS`].
fn clip_line(line: &str) -> String {
    let cleaned = line.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.chars().count() > SNIPPET_CHARS {
        let mut clipped: String = cleaned.chars().take(SNIPPET_CHARS - 1).collect();
        clipped.push('…');
        clipped
    } else {
        cleaned
    }
}

/// Derive a display title from the first line that mentions a goal or title.
///
/// Schema-agnostic and deliberately best-effort: take the text after the last
/// `":"`, stop at the next key, and trim JSON punctuation. Falls back to the id.
fn title_for(text: &str, job_id: &str) -> String {
    for line in text.lines() {
        if !line.contains("goal") && !line.contains("title") {
            continue;
        }
        let Some(after_colon) = line.rfind("\":").map(|at| &line[at + 2..]) else {
            continue;
        };
        let raw = after_colon.split("\",").next().unwrap_or(after_colon);
        let title = raw.trim_matches(|c: char| c == '"' || c == '{' || c == '}' || c == ',' || c.is_whitespace());
        if !title.is_empty() {
            return title.to_string();
        }
    }
    job_id.to_string()
}

/// File mtime in Unix seconds, or 0 when unavailable.
fn modified_secs(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |duration| duration.as_secs())
}

/// Search all jobs under `jobs_dir` for `query`, returning up to `limit` hits,
/// best score first, newer first on ties. Empty query or missing dir => empty.
pub fn search(jobs_dir: &Path, query: &str, limit: usize) -> Vec<RecallHit> {
    let query_tokens = distinct_tokens(query);
    if query_tokens.is_empty() || limit == 0 {
        return Vec::new();
    }
    let wanted: HashSet<&str> = query_tokens.iter().map(String::as_str).collect();

    let Ok(entries) = std::fs::read_dir(jobs_dir) else {
        return Vec::new();
    };
    let mut hits = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(job_id) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let job_file = path.join(JOB_FILE);
        let Ok(raw) = std::fs::read_to_string(&job_file) else {
            continue;
        };
        let text = crate::run::strip_turn_context(&raw);
        let Some((score, snippet)) = score_text(&text, &query_tokens, &wanted) else {
            continue;
        };
        hits.push(RecallHit {
            job_id: job_id.to_string(),
            title: title_for(&text, job_id),
            score,
            snippet,
            modified: modified_secs(&job_file),
        });
    }

    hits.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.modified.cmp(&a.modified))
            .then_with(|| a.job_id.cmp(&b.job_id))
    });
    hits.truncate(limit);
    hits
}

/// Convenience over the default store (~/.bulge/jobs). Empty on any error.
pub fn search_default(query: &str, limit: usize) -> Vec<RecallHit> {
    let Ok(jobs) = bulge_util::fs::jobs_dir() else {
        return Vec::new();
    };
    search(&jobs, query, limit)
}

/// CLI entry: `bulge recall <query...> [--limit N]`. Prints hits, returns exit code.
pub fn dispatch(args: &[String]) -> i32 {
    match recall(args) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("error: {error}");
            2
        }
    }
}

fn recall(args: &[String]) -> Result<(), String> {
    let mut limit = DEFAULT_LIMIT;
    let mut query_words = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--limit" {
            let raw = iter.next().ok_or_else(|| "--limit needs a value".to_string())?;
            limit = raw.parse::<usize>().map_err(|_| format!("--limit expects a number, got {raw:?}"))?;
        } else {
            query_words.push(arg.clone());
        }
    }

    let query = query_words.join(" ").trim().to_string();
    if query.is_empty() {
        return Err("recall needs a search query".into());
    }

    let hits = search_default(&query, limit);
    if hits.is_empty() {
        println!("no matching jobs");
        return Ok(());
    }
    for hit in hits {
        println!("{}  score={:.1}  {}", hit.job_id, hit.score, hit.title);
        println!("    {}", hit.snippet);
    }
    Ok(())
}

// ---- agent-facing recall tool (host-handled by the driver) ----

/// Schema for the `recall` tool the model may call to search its own past jobs.
pub fn recall_tool() -> bulge_llm::ToolSchema {
    bulge_llm::ToolSchema {
        name: bulge_core::dispatch::RECALL_TOOL.into(),
        description: "Search your OWN past jobs (their transcripts) by keyword and get back a short \
            digest of the most relevant ones. Use it to reuse earlier work or decisions on a similar \
            task instead of starting from scratch. Supports English and Chinese queries."
            .into(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "Keywords describing what to recall." },
                "limit": { "type": "integer", "description": "Max results (default 5)." }
            },
            "required": ["query"]
        }),
        defer_loading: false,
    }
}

/// A [`bulge_core::driver::RecallHandler`] over a job store directory.
pub struct StoreRecall {
    pub jobs_dir: PathBuf,
}

impl bulge_core::driver::RecallHandler for StoreRecall {
    fn recall(&self, query: &str, limit: usize) -> String {
        let hits = search(&self.jobs_dir, query, limit);
        if hits.is_empty() {
            return "No matching past jobs.".to_string();
        }
        let mut out = String::new();
        for h in hits {
            out.push_str(&format!("- [{}] {} (score {:.1})\n    {}\n", h.job_id, h.title, h.score, h.snippet));
        }
        out
    }
}

/// The single most relevant past job for `goal` above `min_score`, as a one-line
/// pointer (id + title) for auto-injection at task start — a lightweight "have I
/// done something like this before?" nudge. Only the pointer is injected: the
/// snippet is new, uncached text on every job and is often a fragment of an
/// unrelated job's ending, so the agent pulls details with `recall` when it
/// actually wants them. `None` when nothing is clearly relevant.
pub fn most_relevant(jobs_dir: &Path, goal: &str, min_score: f32, exclude_id: &str) -> Option<String> {
    let hit = search(jobs_dir, goal, 4).into_iter().find(|h| h.job_id != exclude_id && h.score >= min_score)?;
    Some(format!("[{}] {}", hit.job_id, hit.title))
}
#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        std::env::temp_dir().join(format!("bulge-recall-{label}-{}-{nanos}", std::process::id()))
    }

    fn write_job(root: &Path, id: &str, text: &str) {
        let dir = root.join(id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(JOB_FILE), text).unwrap();
    }

    fn fixture(label: &str) -> PathBuf {
        let root = temp_root(label);
        write_job(
            &root,
            "job-login",
            "{\"title\":\"fix login bug\"}\n\
             {\"goal\":\"fix the login bug in auth\"}\n\
             {\"type\":\"message\",\"text\":\"the login token expired\"}\n",
        );
        write_job(
            &root,
            "job-docs",
            "{\"title\":\"write docs\"}\n\
             {\"goal\":\"write docs for the parser\"}\n\
             {\"type\":\"message\",\"text\":\"document the parser API\"}\n",
        );
        root
    }

    #[test]
    fn matching_job_ranks_first() {
        let root = fixture("rank");
        let hits = search(&root, "login bug", 10);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].job_id, "job-login");
        assert_eq!(hits[0].title, "fix login bug");

        let hits = search(&root, "parser docs", 10);
        assert_eq!(hits[0].job_id, "job-docs");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unmatched_query_returns_empty() {
        let root = fixture("unmatched");
        assert!(search(&root, "nonexistent llama", 10).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn limit_is_respected() {
        let root = temp_root("limit");
        write_job(&root, "job-a", "{\"title\":\"parser a\"}\nparser one\n");
        write_job(&root, "job-b", "{\"title\":\"parser b\"}\nparser two\n");
        write_job(&root, "job-c", "{\"title\":\"parser c\"}\nparser three\n");
        assert_eq!(search(&root, "parser", 2).len(), 2);
        assert_eq!(search(&root, "parser", 1).len(), 1);
        assert_eq!(search(&root, "parser", 0).len(), 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn snippet_contains_query_token_and_is_single_clipped_line() {
        let root = temp_root("snippet");
        let long = format!("{{\"title\":\"token story\"}}\ntoken {}", "x".repeat(500));
        write_job(&root, "job-snippet", &long);
        let hits = search(&root, "token", 10);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].snippet.to_lowercase().contains("token"));
        assert!(!hits[0].snippet.contains('\n'));
        assert!(hits[0].snippet.chars().count() <= SNIPPET_CHARS);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_dir_returns_empty() {
        let root = temp_root("missing").join("does-not-exist");
        assert!(search(&root, "anything", 10).is_empty());
    }

    #[test]
    fn empty_query_returns_empty() {
        let root = fixture("empty-query");
        assert!(search(&root, "", 10).is_empty());
        assert!(search(&root, "   ", 10).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }
}

