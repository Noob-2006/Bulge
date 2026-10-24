//! The per-turn context block (lessons, recent jobs, the workspace listing)
//! and its removal from stored messages.

use std::path::Path;

use bulge_harness::SurfaceSpec;
use super::{LESSON_COUNT, read_tree};

/// Wraps the per-turn context block inside a user turn. The block is logged as
/// part of the user message (so later requests replay identical bytes); the app
/// hides it from the user bubble and recall skips it when scoring past jobs.
pub const TURN_CONTEXT_OPEN: &str = "<turn-context>";
pub const TURN_CONTEXT_CLOSE: &str = "</turn-context>";

/// Most entries listed in the start-of-task workspace snapshot.
pub(crate) const WORKSPACE_LIST_LIMIT: usize = 80;
/// Directory depth of the workspace snapshot (1 = top level only).
pub(crate) const WORKSPACE_LIST_DEPTH: usize = 2;

/// The volatile context for one user turn: the durable profile (USER/MEMORY),
/// the most relevant past job, the retrieved lessons for this goal, and — on a
/// job's first turn — a bounded listing of the workspace. Empty when there is
/// nothing to add. Rendered once and persisted, never recomputed for a turn.
pub(crate) fn build_turn_context(harness_dir: &Path, goal: &str, jobs_dir: Option<&Path>, current_job_id: &str, workspace: Option<&Path>) -> String {
    let mut context = String::new();
    let memory_root = harness_dir.join("memory");

    // Most stable first (changes only when the workshop installs a skill), so
    // consecutive jobs share the longest possible cached prefix.
    let catalog = bulge_harness::skills_catalog(&read_tree(harness_dir), &SurfaceSpec::default());
    if !catalog.is_empty() {
        context.push_str("\n\n");
        context.push_str(&catalog);
    }

    // Durable profile surfaces: who the user is and how they want the agent to
    // work, plus durable environment facts. Bounded by the save-time char limits.
    // A memory that cannot be opened is reported and the turn goes on without it.
    let memory = bulge_harness::MemoryStore::open(&memory_root).map_err(|error| eprintln!("memory not used this turn: {error}")).ok();
    if let Some(memory) = &memory {
        for (target, title) in [(bulge_harness::ProfileTarget::User, "About the user"), (bulge_harness::ProfileTarget::Env, "Environment notes")] {
            match memory.profile(target) {
                Ok(profile) if !profile.sections.is_empty() => {
                    context.push_str(&format!("\n\n# {title}\n"));
                    context.push_str(&profile.render());
                }
                Ok(_) => {}
                Err(error) => eprintln!("memory: {error}"),
            }
        }
    }

    // Surface the single most relevant PAST job for this goal — a "have I done
    // something like this before?" nudge. Unlike Hermes (which keeps past
    // transcripts tool-only), bulge auto-surfaces the top match at task start.
    // Thresholded so it stays quiet when nothing is clearly related.
    if let Some(dir) = jobs_dir
        && let Some(past) = crate::recall::most_relevant(dir, goal, 2.0, current_job_id)
    {
        context.push_str("\n\n# Possibly relevant past task\n");
        context.push_str(&past);
        context.push_str("\n(Call `recall` with a query about it if its result would help; otherwise ignore it.)");
    }

    if let Some(memory) = &memory {
        match memory.retrieve(goal, LESSON_COUNT) {
            Ok(hits) => {
                let brief = bulge_harness::brief(&hits);
                if !brief.is_empty() {
                    context.push_str("\n\n");
                    context.push_str(&brief);
                }
            }
            Err(error) => eprintln!("memory: {error}"),
        }
    }

    if let Some(dir) = workspace {
        context.push_str("\n\n# Workspace at task start (/workspace; no need to list it again)\n");
        context.push_str(&workspace_listing(dir));
    }

    let body = context.trim();
    if body.is_empty() { String::new() } else { format!("{TURN_CONTEXT_OPEN}\n{body}\n{TURN_CONTEXT_CLOSE}") }
}

/// A sorted, bounded listing of `dir` (relative paths, `/` after directories),
/// skipping hidden entries and well-known dependency/build directories.
pub(crate) fn workspace_listing(dir: &Path) -> String {
    const SKIP: [&str; 4] = ["node_modules", "target", "__pycache__", ".git"];
    let mut lines = Vec::new();
    let mut truncated = false;
    let mut stack = vec![(dir.to_path_buf(), 1_usize)];
    let mut entries_seen = Vec::new();
    while let Some((path, depth)) = stack.pop() {
        let Ok(read) = std::fs::read_dir(&path) else { continue };
        let mut names: Vec<(String, bool)> = read
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
                (!name.starts_with('.') && !SKIP.contains(&name.as_str())).then_some((name, is_dir))
            })
            .collect();
        names.sort();
        for (name, is_dir) in names.into_iter().rev() {
            let full = path.join(&name);
            entries_seen.push((full.clone(), is_dir));
            if is_dir && depth < WORKSPACE_LIST_DEPTH {
                stack.push((full, depth + 1));
            }
        }
    }
    entries_seen.sort();
    for (full, is_dir) in entries_seen {
        if lines.len() == WORKSPACE_LIST_LIMIT {
            truncated = true;
            break;
        }
        let rel = full.strip_prefix(dir).unwrap_or(&full).to_string_lossy().into_owned();
        lines.push(if is_dir { format!("{rel}/") } else { rel });
    }
    if lines.is_empty() {
        return "(empty)".to_string();
    }
    if truncated {
        lines.push(format!("… (listing capped at {WORKSPACE_LIST_LIMIT} entries)"));
    }
    lines.join("\n")
}

/// Remove every `<turn-context>…</turn-context>` block from `text` (used by
/// recall so injected context never counts as a past job's own content).
pub fn strip_turn_context(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.contains(TURN_CONTEXT_OPEN) {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(TURN_CONTEXT_OPEN) {
        out.push_str(&rest[..start]);
        match rest[start..].find(TURN_CONTEXT_CLOSE) {
            Some(end) => rest = &rest[start + end + TURN_CONTEXT_CLOSE.len()..],
            None => {
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    std::borrow::Cow::Owned(out)
}
