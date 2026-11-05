//! `context_fetch` (kernel tool): retrieval instead of carrying old tool output in every
//! request (BATCH-next §6). Old tool results are clipped before each request
//! (`context::trim_old_tool_results`, `[compaction] max_tool_result_chars`) and large ones are
//! spilled to artifact files; the clip marker names this tool, which returns the full output
//! (or the lines matching a query, or a line window) from the session log / artifact file,
//! and searches every earlier tool output of the session through the SQLite index.

use crate::event::{Event, EventKind};
use ark_core::{Block, ToolSchema};
use serde_json::{json, Value};
use std::path::Path;

pub const NAME: &str = "context_fetch";
const MAX_CHARS: usize = 20_000;

pub fn schema() -> ToolSchema {
    ToolSchema {
        name: NAME.into(),
        description: "Fetch earlier tool output that was clipped or saved out of the conversation. `id` = the tool_use id named in a clip marker: returns that output in full (paged by `offset`/`limit` lines), or only the lines matching `query`. Without `id`, `query` searches every earlier tool output of this session. Prefer this over re-running a tool.".into(),
        input_schema: json!({"type":"object","properties":{
            "id":{"type":"string","description":"tool_use id from the clip marker"},
            "query":{"type":"string","description":"case-insensitive text to look for"},
            "offset":{"type":"integer","minimum":0,"description":"first line (0-based) of the page"},
            "limit":{"type":"integer","minimum":1,"description":"lines per page (default 200) or matches (default 40)"}
        }}),
    }
}

/// The full output of `id` as the session log has it: the artifact file when the result was
/// spilled, else the tool-result block.
fn full_output(events: &[Event], id: &str) -> Option<String> {
    for e in events.iter().rev() {
        if let EventKind::ToolSettled { tool_use_id, artifact: Some(a), .. } = &e.kind {
            if tool_use_id == id {
                if let Ok(s) = std::fs::read_to_string(a) {
                    return Some(s);
                }
            }
        }
    }
    events.iter().rev().find_map(|e| match &e.kind {
        EventKind::Message { message, .. } => message.content.iter().find_map(|b| match b {
            Block::ToolResult { tool_use_id, content, .. } if tool_use_id == id => Some(content.clone()),
            _ => None,
        }),
        _ => None,
    })
}

fn grep(text: &str, q: &str, limit: usize) -> (Vec<String>, usize) {
    let q = q.to_lowercase();
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut total = 0;
    for (i, l) in lines.iter().enumerate() {
        if l.to_lowercase().contains(&q) {
            total += 1;
            if out.len() < limit {
                out.push(format!("{}: {}", i + 1, clip(l, 400)));
            }
        }
    }
    (out, total)
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

/// Run the tool for `session` (its in-memory events) with the index under `data`.
pub fn run(events: &[Event], data: &Path, sessions_root: &Path, session: &str, input: &Value) -> Result<String, String> {
    let id = input["id"].as_str().map(str::trim).filter(|s| !s.is_empty());
    let query = input["query"].as_str().map(str::trim).filter(|s| !s.is_empty());
    let limit = input["limit"].as_u64().map(|n| n.max(1) as usize);
    if let Some(id) = id {
        let text = match full_output(events, id) {
            Some(t) => t,
            None => {
                crate::sqlindex::sync_session(data, sessions_root, session)?;
                crate::sqlindex::tool_result(data, session, id)?.map(|h| h.text).ok_or_else(|| format!("no tool output with id `{id}` in this session"))?
            }
        };
        if let Some(q) = query {
            let (hits, total) = grep(&text, q, limit.unwrap_or(40));
            if hits.is_empty() {
                return Ok(format!("`{q}` does not occur in the output of {id} ({} lines)", text.lines().count()));
            }
            return Ok(format!("{total} matching line(s) in the output of {id}{}:\n{}", if total > hits.len() { format!(", first {}", hits.len()) } else { String::new() }, hits.join("\n")));
        }
        let lines: Vec<&str> = text.lines().collect();
        let start = input["offset"].as_u64().unwrap_or(0) as usize;
        let start = start.min(lines.len());
        let mut end = (start + limit.unwrap_or(200)).min(lines.len());
        let mut page = lines[start..end].join("\n");
        if page.chars().count() > MAX_CHARS {
            page = clip(&page, MAX_CHARS);
            end = start + page.lines().count().max(1);
        }
        let more = if end < lines.len() { format!("; continue with {{\"id\":\"{id}\",\"offset\":{end}}}") } else { String::new() };
        return Ok(format!("output of {id}: lines {}-{} of {}{more}\n{page}", start + 1, end, lines.len()));
    }
    let Some(q) = query else { return Err("pass `id` (from a clip marker) and/or `query`".into()) };
    crate::sqlindex::sync_session(data, sessions_root, session)?;
    let hits = crate::sqlindex::search_tool_results(data, session, q, limit.unwrap_or(5).min(20))?;
    if hits.is_empty() {
        return Ok(format!("no earlier tool output of this session contains `{q}`"));
    }
    let mut out = Vec::new();
    for h in &hits {
        let (lines, total) = grep(&h.text, q, 3);
        out.push(format!("id {} ({}{}, {} chars, {total} matching line(s)):\n  {}", h.tool_use_id, if h.tool.is_empty() { "tool" } else { &h.tool }, if h.is_error { ", error" } else { "" }, h.text.chars().count(), lines.join("\n  ")));
    }
    Ok(format!("{}\nFetch one in full with {{\"id\": \"…\"}} (add \"query\" to see only matching lines).", out.join("\n")))
}
