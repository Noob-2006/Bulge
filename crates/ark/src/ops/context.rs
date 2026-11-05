//! `/context` — context-window usage for the current session: a glyph gauge, the per-category
//! breakdown, the `/context all` detail tables and compaction stats.
//!
//! Port of Hermes `agent/context_breakdown.py` (MIT): the same eight categories in the same
//! declaration order and with the same glyphs, the same 100-cell grid (20 columns × 5 rows, one
//! cell per percent of the window), the free-space row, the window line (with `~` when the
//! figure is an estimate) and the source line. ark has no provider usage anchor or
//! `context_engine` object, so the occupancy is `last_input_tokens` (provider-reported) when the
//! session has one, else the estimate over the same categories.

use ark_core::{Block, SystemSegment, ToolSpec};
use ark_kernel::config::CompactionConfig;
use ark_kernel::projection::View;

/// Cells per grid row (upstream `_GRID_COLUMNS`).
pub const GRID_COLUMNS: usize = 20;
/// Grid rows: 100 cells, one per percent of the window (upstream `_GRID_ROWS`).
pub const GRID_ROWS: usize = 5;
/// Rows per detail table; the data keeps everything (upstream `_DETAILS_TABLE_LIMIT`).
pub const DETAILS_LIMIT: usize = 15;
/// A free (unused) cell of the gauge.
pub const FREE: &str = "·";

/// Categories at zero are dropped, except these: a session always has a transcript, so zero
/// there is a measurement, not the absence of something optional (upstream `_ALWAYS_REPORTED`).
const ALWAYS_REPORTED: &[&str] = &["conversation"];

/// Tool names counted as "subagent definitions" (upstream `_SUBAGENT_TOOL_NAMES`, plus ark's
/// `spawn` which is the same delegation surface).
const SUBAGENT_TOOLS: &[&str] = &["spawn", "delegate_task"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Category {
    pub id: &'static str,
    pub glyph: &'static str,
    pub tokens: u64,
}

/// Upstream category labels (`gateway.context.category.<id>`).
pub fn label(id: &str) -> &'static str {
    match id {
        "system_prompt" => "System prompt",
        "role" => "Professional role",
        "tool_definitions" => "Tool definitions",
        "rules" => "Rules",
        "skills" => "Skills",
        "mcp" => "MCP",
        "subagent_definitions" => "Subagent definitions",
        "memory" => "Memory",
        _ => "Conversation",
    }
}

/// Token estimate (~4 characters per token) used where no tokenizer is available.
fn est(chars: usize) -> u64 {
    chars.div_ceil(4) as u64
}

fn schema_chars(set: &[&ToolSpec]) -> u64 {
    est(set.iter().map(|s| s.name.len() + s.description.len() + s.input_schema.to_string().len()).sum())
}

fn is_subagent(name: &str) -> bool {
    SUBAGENT_TOOLS.contains(&name)
}

fn conversation_tokens(v: &View) -> u64 {
    let (mut chars, mut media) = (0usize, 0u64);
    for m in &v.messages {
        for b in &m.content {
            match b {
                Block::Text { text } => chars += text.len(),
                Block::Thinking { text, .. } => chars += text.len(),
                Block::ToolUse { name, input, .. } => chars += input.to_string().len() + name.len(),
                Block::ToolResult { content, .. } => chars += content.len(),
                Block::Image { .. } => media += 1,
            }
        }
    }
    est(chars) + media * 1500
}

/// The eight upstream categories in declaration order. Zero-token rows are dropped (they read
/// as "not configured"), except `conversation`.
pub fn categories(v: &View, specs: &[ToolSpec]) -> Vec<Category> {
    let (mut system_prompt, mut rules, mut skills, mut memory, mut role) = (0usize, 0usize, 0usize, 0usize, 0usize);
    // The L0 professional core lives inside the identity; it is counted with the role.
    let core = ark_kernel::roles::core_text(&ark_kernel::config::Config::default()).unwrap_or_default();
    for s in &v.system {
        match s.id.as_str() {
            "project" => rules += s.text.len(),
            "skills" => skills += s.text.len(),
            "memory" => memory += s.text.len(),
            "role" => role += s.text.len(),
            "identity" if !core.is_empty() && s.text.contains(&core) => {
                role += core.len();
                system_prompt += s.text.len() - core.len();
            }
            // identity, the tool index and /personality all live in the prompt proper.
            _ => system_prompt += s.text.len(),
        }
    }
    let pinned: Vec<&ToolSpec> = specs.iter().filter(|s| s.pinned).collect();
    let (mcp, sub, builtin): (Vec<&ToolSpec>, Vec<&ToolSpec>, Vec<&ToolSpec>) =
        pinned.iter().copied().fold((vec![], vec![], vec![]), |(mut m, mut s, mut b), t| {
            if t.name.starts_with("mcp_") {
                m.push(t)
            } else if is_subagent(&t.name) {
                s.push(t)
            } else {
                b.push(t)
            }
            (m, s, b)
        });
    let all = [
        Category { id: "system_prompt", glyph: "■", tokens: est(system_prompt) },
        Category { id: "role", glyph: "▪", tokens: est(role) },
        Category { id: "tool_definitions", glyph: "▣", tokens: schema_chars(&builtin) },
        Category { id: "rules", glyph: "▩", tokens: est(rules) },
        Category { id: "skills", glyph: "▤", tokens: est(skills) },
        Category { id: "mcp", glyph: "▥", tokens: schema_chars(&mcp) },
        Category { id: "subagent_definitions", glyph: "▦", tokens: schema_chars(&sub) },
        Category { id: "memory", glyph: "▧", tokens: est(memory) },
        Category { id: "conversation", glyph: "▨", tokens: conversation_tokens(v) },
    ];
    all.into_iter().filter(|c| c.tokens > 0 || ALWAYS_REPORTED.contains(&c.id)).collect()
}

/// `GRID_ROWS` lines of `GRID_COLUMNS` cells: categories fill the grid in declaration order,
/// the rest is free space. A non-zero category always gets at least one cell.
pub fn grid(cats: &[Category], window: u64) -> Vec<String> {
    let total = GRID_COLUMNS * GRID_ROWS;
    let mut cells: Vec<&str> = Vec::new();
    if window > 0 {
        for c in cats {
            let n = if c.tokens == 0 { 0 } else { ((c.tokens as f64 / window as f64 * total as f64).round() as usize).max(1) };
            cells.extend(std::iter::repeat_n(c.glyph, n));
        }
        cells.truncate(total);
    }
    cells.resize(total, FREE);
    (0..GRID_ROWS).map(|r| cells[r * GRID_COLUMNS..(r + 1) * GRID_COLUMNS].join(" ")).collect()
}

fn commas_opt(n: u64) -> String {
    commas(n)
}

fn commas(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn pct(tokens: u64, denom: u64) -> f64 {
    if denom == 0 {
        0.0
    } else {
        tokens as f64 * 100.0 / denom as f64
    }
}

/// The full `/context` report. `details` also renders the `/context all` tables.
pub fn report(v: &View, specs: &[ToolSpec], window: u64, comp: &CompactionConfig, details: bool) -> String {
    let cats = categories(v, specs);
    let estimated_total: u64 = cats.iter().map(|c| c.tokens).sum();
    let mut o = String::new();
    for line in grid(&cats, window) {
        o.push_str(&line);
        o.push('\n');
    }
    let free_label = "Free space";
    let width = cats.iter().map(|c| label(c.id).len()).chain(std::iter::once(free_label.len())).max().unwrap_or(0);
    let denom = if window > 0 { window } else { estimated_total };
    o.push_str("\nEstimated usage by category\n");
    for c in &cats {
        o.push_str(&format!("  {} {:<width$} ~{} tokens ~{:.1}%\n", c.glyph, label(c.id), commas(c.tokens), pct(c.tokens, denom)));
    }
    if window > 0 {
        let free = window.saturating_sub(estimated_total);
        o.push_str(&format!("  {FREE} {free_label:<width$} ~{} tokens ~{:.1}%\n", commas(free), pct(free, window)));
    }
    let measured = v.last_input_tokens > 0;
    let mark = if measured { "" } else { "~" };
    let mut used = if measured { v.last_input_tokens } else { estimated_total };
    // A single prompt can never exceed the window; any excess is estimate drift.
    if window > 0 {
        used = used.min(window);
        o.push_str(&format!("\nContext window: {mark}{} / {} tokens ({mark}{}%)\n", commas(used), commas(window), (pct(used, window)).round() as u64));
    }
    o.push_str(&format!("Source: {}; category counts are local estimates.\n", if measured { "provider usage" } else { "local estimate" }));
    o.push_str(&format!(
        "compaction at {:.0}% ({} tokens), pruning old tool output at {:.0}%, {} compaction(s)\n",
        comp.threshold * 100.0,
        commas((window as f64 * comp.threshold) as u64),
        comp.prune_threshold * 100.0,
        v.compactions
    ));
    o.push_str(&format!(
        "{} messages · {} turns · {} tokens used so far (in {} / out {} / cache read {})",
        v.messages.len(),
        v.turns,
        v.usage.total(),
        v.usage.input_tokens,
        v.usage.output_tokens,
        v.usage.cache_read_tokens
    ));
    if details {
        for line in self::details(v, specs) {
            o.push('\n');
            o.push_str(&line);
        }
    } else {
        o.push('\n');
        o.push_str("Use /context all for per-skill and per-toolset costs.");
    }
    o
}

/// Pinned tools grouped the way `/toolsets` groups them (`@files`, `@shell`, …, `@mcp:<server>`),
/// mirroring `slash::toolsets` so this module stays readable on its own.
fn toolsets(specs: &[ToolSpec]) -> Vec<(String, Vec<String>)> {
    const BUILTIN: &[(&str, &[&str])] = &[
        ("files", &["read", "write", "edit", "patch", "glob", "grep"]),
        ("shell", &["shell", "job", "run"]),
        ("web", &["web_fetch", "web_search", "web_extract"]),
        ("memory", &["memory", "session_search"]),
        ("agents", &["spawn", "acp_delegate", "ask_user", "todo"]),
        ("skills", &["skill"]),
        ("channels", &["channel_send"]),
        ("nodes", &["node_invoke"]),
    ];
    let names: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();
    let mut out: Vec<(String, Vec<String>)> = BUILTIN
        .iter()
        .map(|(n, ts)| (n.to_string(), ts.iter().filter(|t| names.contains(t)).map(|t| t.to_string()).collect::<Vec<_>>()))
        .filter(|(_, v)| !v.is_empty())
        .collect();
    let mut servers: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for n in &names {
        if let Some(rest) = n.strip_prefix("mcp__") {
            if let Some((srv, _)) = rest.split_once("__") {
                servers.entry(format!("mcp:{srv}")).or_default().push(n.to_string());
            }
        } else if let Some((pre, _)) = n.split_once('_').filter(|(p, _)| *p == "a2a" || *p == "ark") {
            servers.entry(pre.to_string()).or_default().push(n.to_string());
        }
    }
    out.extend(servers);
    out
}

/// `/context all`: per-toolset schema cost and per-skill index cost (upstream
/// `compute_context_details` / `render_context_details_lines`), display-capped.
pub fn details(v: &View, specs: &[ToolSpec]) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let pinned: Vec<ToolSpec> = specs.iter().filter(|s| s.pinned).cloned().collect();
    if !pinned.is_empty() {
        let mut claimed: std::collections::BTreeSet<String> = Default::default();
        let mut rows: Vec<(String, usize, u64)> = Vec::new();
        for (name, members) in toolsets(&pinned) {
            let set: Vec<&ToolSpec> = pinned.iter().filter(|s| members.contains(&s.name)).collect();
            if set.is_empty() {
                continue;
            }
            claimed.extend(set.iter().map(|s| s.name.clone()));
            rows.push((name, set.len(), schema_chars(&set)));
        }
        let rest: Vec<&ToolSpec> = pinned.iter().filter(|s| !claimed.contains(&s.name)).collect();
        if !rest.is_empty() {
            rows.push(("other".into(), rest.len(), schema_chars(&rest)));
        }
        rows.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
        if !rows.is_empty() {
            lines.push("Toolsets by schema cost (largest first)".to_string());
            for (n, count, tokens) in rows.iter().take(DETAILS_LIMIT) {
                lines.push(format!("  @{n} {count} tools ~{} tokens", commas_opt(*tokens)));
            }
            if rows.len() > DETAILS_LIMIT {
                lines.push(format!("  … and {} more", rows.len() - DETAILS_LIMIT));
            }
        }
    }
    // One index line per skill: `- name: description (path)` in the `skills` segment.
    let skills: Vec<(String, u64)> = v
        .system
        .iter()
        .filter(|s| s.id == "skills")
        .flat_map(|s: &SystemSegment| s.text.lines())
        .filter_map(|l| {
            let (name, _) = l.strip_prefix("- ")?.split_once(':')?;
            Some((name.trim().to_string(), est(l.len() + 1)))
        })
        .collect();
    if !skills.is_empty() {
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push("Skills by cost (index = always-on; SKILL.md = cost when loaded)".to_string());
        for (name, tokens) in skills.iter().take(DETAILS_LIMIT) {
            // SKILL.md cost is only known once the file is loaded (upstream `n/a`).
            lines.push(format!("  {name:<28} index ~{}  SKILL.md n/a", commas(*tokens)));
        }
        if skills.len() > DETAILS_LIMIT {
            lines.push(format!("  … and {} more", skills.len() - DETAILS_LIMIT));
        }
    }
    lines
}

/// The machine-readable payload (OpenClaw `/context json`, upstream `compute_session_context_breakdown`
/// return value): categories with their glyph/token counts plus the occupancy and its provenance.
pub fn payload(v: &View, specs: &[ToolSpec], window: u64) -> serde_json::Value {
    let cats = categories(v, specs);
    let estimated_total: u64 = cats.iter().map(|c| c.tokens).sum();
    let measured = v.last_input_tokens > 0;
    let used = if measured { v.last_input_tokens.min(window.max(v.last_input_tokens)) } else { estimated_total };
    serde_json::json!({
        "model": v.model,
        "categories": cats.iter().map(|c| serde_json::json!({"id": c.id, "label": label(c.id), "glyph": c.glyph, "tokens": c.tokens})).collect::<Vec<_>>(),
        "context_max": window,
        "context_used": used,
        "context_percent": if window > 0 { (pct(used, window)).round() as u64 } else { 0 },
        "context_source": if measured { "provider_usage" } else { "local_estimate" },
        "context_estimated": !measured,
        "estimated_total": estimated_total,
        "compactions": v.compactions,
        "messages": v.messages.len(),
        "turns": v.turns,
        "usage": {"input_tokens": v.usage.input_tokens, "output_tokens": v.usage.output_tokens, "cache_read_tokens": v.usage.cache_read_tokens},
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_core::{Message, Role};
    use serde_json::json;

    fn spec(name: &str, pinned: bool) -> ToolSpec {
        ToolSpec { name: name.into(), description: format!("{name} does the {name} thing"), input_schema: json!({"type": "object", "properties": {"path": {"type": "string"}}}), parallel_safe: false, idempotent: false, pinned }
    }

    fn seg(id: &str, text: &str) -> SystemSegment {
        SystemSegment { id: id.into(), text: text.into(), cache: false }
    }

    fn view() -> View {
        View {
            model: "echo/m".into(),
            system: vec![
                seg("identity", "You are ark."),
                seg("tools", "# Tool index\n- web_fetch: fetch a URL\n"),
                seg("skills", "# Skills\n- deploy: Ship it. (/w/.ark/skills/deploy/SKILL.md)\n"),
                seg("memory", "# Memory\n## Your notes\nuses cargo\n"),
                seg("project", "## AGENTS.md\nrun cargo test\n"),
            ],
            messages: vec![Message::user("hello there")],
            last_input_tokens: 0,
            ..Default::default()
        }
    }

    fn ids(cats: &[Category]) -> Vec<&'static str> {
        cats.iter().map(|c| c.id).collect()
    }

    #[test]
    fn categories_follow_upstream_order_and_react_to_the_transcript() {
        let mut v = view();
        let specs = vec![spec("read", true), spec("write", true), spec("spawn", true)];
        let cats = categories(&v, &specs);
        assert_eq!(ids(&cats), ["system_prompt", "tool_definitions", "rules", "skills", "subagent_definitions", "memory", "conversation"], "declaration order, zero rows dropped");
        let get = |id: &str, c: &[Category]| c.iter().find(|x| x.id == id).map(|x| x.tokens);
        let conversation = get("conversation", &cats).unwrap();
        let tools = get("tool_definitions", &cats).unwrap();

        // The conversation row reacts to what was actually said (tool calls and results too).
        v.messages.push(Message { role: Role::Assistant, content: vec![Block::ToolUse { id: "1".into(), name: "read".into(), input: json!({"path": "a.txt"}) }] });
        v.messages.push(Message { role: Role::User, content: vec![Block::ToolResult { tool_use_id: "1".into(), content: "x".repeat(400), is_error: false }] });
        assert!(get("conversation", &categories(&v, &specs)).unwrap() > conversation);

        // Tool schemas react to the pinned set; mcp_* and subagent specs get their own rows.
        let mut specs2 = specs.clone();
        specs2.push(spec("mcp__fs__read", true));
        specs2.push(spec("grep", true));
        specs2.push(spec("web_fetch", false));
        let c2 = categories(&v, &specs2);
        assert!(get("tool_definitions", &c2).unwrap() > tools);
        assert!(get("mcp", &c2).unwrap() > 0, "mcp row appears for mcp_* tools");
        assert_eq!(get("subagent_definitions", &c2), get("subagent_definitions", &categories(&v, &specs)), "an unpinned tool costs nothing");
        // Rules come from the project segment, memory from the memory snapshot.
        v.system.retain(|s| s.id != "memory");
        assert!(!ids(&categories(&v, &specs2)).contains(&"memory"), "no memory configured: no row");
        assert!(get("rules", &categories(&v, &specs2)).unwrap() > 0);
        // An empty session still reports the conversation row (zero is a measurement).
        let empty = View::default();
        assert_eq!(ids(&categories(&empty, &[])), ["conversation"]);
    }

    #[test]
    fn grid_is_one_hundred_cells_with_free_space() {
        let cats = vec![
            Category { id: "system_prompt", glyph: "■", tokens: 20_000 },
            Category { id: "conversation", glyph: "▨", tokens: 5_000 },
        ];
        let g = grid(&cats, 100_000);
        assert_eq!(g.len(), GRID_ROWS);
        let cells: Vec<&str> = g.iter().flat_map(|l| l.split(' ')).collect();
        assert_eq!(cells.len(), GRID_COLUMNS * GRID_ROWS);
        assert_eq!(cells.iter().filter(|c| **c == "■").count(), 20, "one cell per percent");
        assert_eq!(cells.iter().filter(|c| **c == "▨").count(), 5);
        assert_eq!(cells.iter().filter(|c| **c == FREE).count(), 75);
        // No window known: no occupancy to draw.
        assert!(grid(&cats, 0).iter().all(|l| l.split(' ').all(|c| c == FREE)));
        // A tiny category is still visible.
        let tiny = vec![Category { id: "memory", glyph: "▧", tokens: 1 }];
        assert!(grid(&tiny, 1_000_000).join(" ").contains('▧'));
    }

    #[test]
    fn report_shows_gauge_window_source_and_compaction_stats() {
        let mut v = view();
        v.compactions = 2;
        v.usage.input_tokens = 1_000;
        v.usage.output_tokens = 200;
        v.usage.cache_read_tokens = 400;
        let comp = CompactionConfig::default();
        let r = report(&v, &[spec("read", true)], 100_000, &comp, false);
        assert!(r.contains("Estimated usage by category") && r.contains("System prompt") && r.contains("Free space"), "{r}");
        assert!(r.contains("  ■ System prompt") && r.contains("tokens ~"), "upstream row shape: {r}");
        assert!(r.contains("Use /context all for per-skill and per-toolset costs."), "{r}");
        assert!(r.contains("Source: local estimate; category counts are local estimates.") && r.contains("Context window: ~"), "no provider figure yet: estimated: {r}");
        assert!(r.contains("compaction at ") && r.contains("compaction(s)"), "{r}");
        assert!(r.contains("1 messages · 0 turns · 1200 tokens used so far (in 1000 / out 200 / cache read 400)"), "{r}");

        // A real provider reading replaces the estimate.
        v.last_input_tokens = 40_000;
        let r = report(&v, &[spec("read", true)], 100_000, &comp, false);
        assert!(r.contains("Context window: 40,000 / 100,000 tokens (40%)"), "{r}");
        assert!(r.contains("Source: provider usage") && !r.contains("~40,000"), "{r}");
        assert!(r.lines().filter(|l| l.contains('·')).count() >= 5, "grid rows render");

        // Details are opt-in and land after the stats.
        assert!(!r.contains("Toolsets by schema cost"));
        let all = report(&v, &[spec("read", true)], 100_000, &comp, true);
        assert!(all.contains("Toolsets by schema cost (largest first)") && all.contains("@files"), "{all}");
        assert!(all.lines().position(|l| l.starts_with("Toolsets by schema cost")).unwrap() > all.lines().position(|l| l.contains("messages ·")).unwrap());
    }

    #[test]
    fn details_list_toolsets_and_skills_capped_at_the_display_limit() {
        let mut v = view();
        let mut index = String::from("# Skills (read the SKILL.md file before using one)\n");
        for i in 0..20 {
            index.push_str(&format!("- skill-{i}: Does thing {i}. (/w/.ark/skills/skill-{i}/SKILL.md)\n"));
        }
        v.system.retain(|s| s.id != "skills");
        v.system.push(seg("skills", &index));
        let specs = vec![spec("read", true), spec("write", true), spec("shell", true), spec("mcp__fs__read", true), spec("spawn", true), spec("glob", false)];
        let d = details(&v, &specs);
        assert!(d.iter().any(|l| l == "Toolsets by schema cost (largest first)") && d.iter().any(|l| l.trim_start().starts_with("@files")), "{d:?}");
        assert!(d.iter().any(|l| l.trim_start().starts_with("@mcp:fs")) && d.iter().any(|l| l.trim_start().starts_with("@agents")), "{d:?}");
        assert!(!d.iter().any(|l| l.trim_start().starts_with("@other")), "every pinned tool found a toolset: {d:?}");
        assert!(d.iter().any(|l| l.starts_with("Skills by cost")) && d.iter().any(|l| l.trim_start().starts_with("skill-0 ")), "{d:?}");
        assert_eq!(d.iter().filter(|l| l.trim_start().starts_with("skill-")).count(), DETAILS_LIMIT);
        assert!(d.iter().any(|l| l.trim() == "… and 5 more"), "{d:?}");
        // Nothing configured: no tables at all.
        assert!(details(&View::default(), &[]).is_empty());
    }

    /// OpenClaw `/context json`: the same numbers as the text view, machine-readable.
    #[test]
    fn payload_matches_the_text_view() {
        let mut v = view();
        v.last_input_tokens = 25_000;
        v.compactions = 1;
        let p = payload(&v, &[spec("read", true), spec("mcp__fs__read", true)], 100_000);
        assert_eq!(p["context_max"], 100_000);
        assert_eq!(p["context_used"], 25_000);
        assert_eq!(p["context_percent"], 25);
        assert_eq!(p["context_source"], "provider_usage");
        assert_eq!(p["context_estimated"], false);
        assert_eq!(p["model"], "echo/m");
        let ids: Vec<&str> = p["categories"].as_array().unwrap().iter().filter_map(|c| c["id"].as_str()).collect();
        assert_eq!(ids, ["system_prompt", "tool_definitions", "rules", "skills", "mcp", "memory", "conversation"]);
        assert_eq!(p["categories"][0]["label"], "System prompt");
        let est: u64 = p["categories"].as_array().unwrap().iter().map(|c| c["tokens"].as_u64().unwrap()).sum();
        assert_eq!(p["estimated_total"], est);
        // No provider reading yet: the payload says so.
        v.last_input_tokens = 0;
        let p = payload(&v, &[], 0);
        assert_eq!((p["context_source"].as_str(), p["context_estimated"].as_bool(), p["context_percent"].as_u64()), (Some("local_estimate"), Some(true), Some(0)));
    }

    /// The professional role (L0 core inside the identity + the `role` segment) is its own row.
    #[test]
    fn role_tokens_are_their_own_category() {
        let core = ark_kernel::roles::core_text(&ark_kernel::config::Config::default()).unwrap();
        let v = View {
            system: vec![
                SystemSegment { id: "identity".into(), text: format!("You are Ark.\n\n{core}"), cache: false },
                SystemSegment { id: "role".into(), text: "# Professional role: x [role:x]\n".repeat(10), cache: false },
            ],
            ..Default::default()
        };
        let cats = categories(&v, &[]);
        let role = cats.iter().find(|c| c.id == "role").unwrap().tokens;
        let sys = cats.iter().find(|c| c.id == "system_prompt").unwrap().tokens;
        assert!(role > 250 && sys < 10, "core counted with the role: role {role}, system {sys}");
        assert!(report(&v, &[], 100_000, &CompactionConfig::default(), false).contains("Professional role"));
    }
}
