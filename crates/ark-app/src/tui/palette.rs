//! Fuzzy command palette (Hermes `ui-tui/src/app/slash/fuzzyScore.ts` +
//! `ui-tui/src/app/slashCatalog.ts`): `/palette`, also Ctrl+P.
//!
//! Candidates are the daemon's `command.list` (built-ins plus custom, plugin and MCP
//! prompts). Each item is tokenized — the whole lowercase text plus its alphanumeric
//! words — and scored in tiers: exact 0, prefix 1, substring 2 on the command's
//! name/aliases, and exact word 3, word prefix 4, word substring 5 on the description,
//! so typing `/summary` finds a command whose help mentions summaries even though no
//! name starts with it. Lower wins, [`NONE`] = no match. An empty query keeps the
//! catalog order; ties keep the original order (stable sort by score, then index).

use serde_json::Value;

/// No match (upstream `Number.POSITIVE_INFINITY`).
pub const NONE: u32 = u32::MAX;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Item {
    pub name: String,
    pub aliases: Vec<String>,
    pub args: String,
    pub description: String,
    pub category: String,
    pub source: String,
    /// Needs a terminal: the TUI runs it inline.
    pub local: bool,
    pub admin: bool,
}

impl Item {
    pub fn from_json(v: &Value) -> Option<Item> {
        Some(Item {
            name: v["name"].as_str()?.to_string(),
            aliases: v["aliases"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(String::from)).collect(),
            args: v["args"].as_str().unwrap_or("").to_string(),
            description: v["description"].as_str().unwrap_or("").to_string(),
            category: v["category"].as_str().unwrap_or("").to_string(),
            source: v["source"].as_str().unwrap_or("builtin").to_string(),
            local: v["local"].as_bool().unwrap_or(false),
            admin: v["admin"].as_bool().unwrap_or(false),
        })
    }

    /// `/name` with its argument placeholder, as the composer would receive it.
    pub fn invocation(&self) -> String {
        if self.args.is_empty() {
            format!("/{}", self.name)
        } else {
            format!("/{} ", self.name)
        }
    }

    /// One overlay row: `/name <args>  description  (category)`.
    pub fn row(&self) -> String {
        let mut s = format!("/{}", self.name);
        if !self.args.is_empty() {
            s.push(' ');
            s.push_str(&self.args);
        }
        if !self.description.is_empty() {
            s.push_str("  ");
            s.push_str(&self.description);
        }
        if !self.category.is_empty() && self.source == "builtin" {
            s.push_str(&format!("  ({})", self.category));
        } else if self.source != "builtin" {
            s.push_str(&format!("  ({})", self.source));
        }
        s
    }
}

pub fn items(v: &Value) -> Vec<Item> {
    v.as_array().into_iter().flatten().filter_map(Item::from_json).collect()
}

/// Lowercase the value and return it alongside its alphanumeric word tokens.
pub fn tokenize_search_text(value: &str) -> Vec<String> {
    let normalized = value.to_lowercase();
    let mut v = vec![normalized.clone()];
    v.extend(normalized.split(|c: char| !c.is_ascii_alphanumeric()).filter(|s| !s.is_empty()).map(String::from));
    v
}

/// Trim, drop leading slashes, lowercase — `/Model ` and `model` score alike.
pub fn normalize_query(query: &str) -> String {
    query.trim().trim_start_matches('/').to_lowercase()
}

pub fn score_fields(fields: &[String], query: &str, offset: u32) -> u32 {
    if query.is_empty() {
        return NONE;
    }
    if fields.iter().any(|f| f == query || format!("/{f}") == query) {
        return offset;
    }
    if fields.iter().any(|f| f.starts_with(query) || format!("/{f}").starts_with(query)) {
        return offset + 1;
    }
    if fields.iter().any(|f| f.contains(query)) {
        return offset + 2;
    }
    NONE
}

/// Score one item against a normalized query. Lower is better; [`NONE`] = no match.
pub fn score_item(item: &Item, query: &str) -> u32 {
    let mut command = Vec::new();
    for f in std::iter::once(item.name.as_str()).chain(item.aliases.iter().map(String::as_str)) {
        if !f.is_empty() {
            command.extend(tokenize_search_text(f));
        }
    }
    let description = tokenize_search_text(&item.description);
    score_fields(&command, query, 0).min(score_fields(&description, query, 3))
}

/// Matching indices, sorted by score then original index; the list untouched when the
/// query is empty (browsing keeps the caller's order).
pub fn rank(items: &[Item], query: &str) -> Vec<usize> {
    let q = normalize_query(query);
    if q.is_empty() {
        return (0..items.len()).collect();
    }
    let mut scored: Vec<(u32, usize)> = items.iter().enumerate().map(|(i, it)| (score_item(it, &q), i)).filter(|(s, _)| *s != NONE).collect();
    scored.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    scored.into_iter().map(|(_, i)| i).collect()
}

/// Overlay state: query, matches and the highlighted row.
#[derive(Debug, Default)]
pub struct Palette {
    pub open: bool,
    pub query: String,
    pub items: Vec<Item>,
    /// Indices into `items`, best first.
    pub matches: Vec<usize>,
    pub cursor: usize,
}

/// Rows the overlay shows at once.
pub const VISIBLE: usize = 8;

impl Palette {
    pub fn open_with(&mut self, items: Vec<Item>, query: &str) {
        self.open = true;
        self.items = items;
        self.query = query.trim_start_matches('/').to_string();
        self.refresh();
    }

    pub fn close(&mut self) {
        self.open = false;
        self.query.clear();
        self.matches.clear();
        self.cursor = 0;
    }

    pub fn refresh(&mut self) {
        self.matches = rank(&self.items, &self.query);
        self.cursor = 0;
    }

    pub fn push(&mut self, c: char) {
        self.query.push(c);
        self.refresh();
    }

    pub fn pop(&mut self) {
        if self.query.pop().is_some() {
            self.refresh();
        }
    }

    /// ↑/↓ wrap around the match list.
    pub fn move_cursor(&mut self, delta: isize) {
        if self.matches.is_empty() {
            self.cursor = 0;
            return;
        }
        self.cursor = (self.cursor as isize + delta).rem_euclid(self.matches.len() as isize) as usize;
    }

    pub fn selected(&self) -> Option<&Item> {
        self.matches.get(self.cursor).and_then(|i| self.items.get(*i))
    }

    /// The rows to draw: the window around the cursor.
    pub fn window(&self) -> &[usize] {
        let start = self.cursor.saturating_sub(VISIBLE - 1);
        &self.matches[start..(start + VISIBLE).min(self.matches.len())]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn it(name: &str, desc: &str) -> Item {
        Item { name: name.into(), description: desc.into(), ..Default::default() }
    }

    #[test]
    fn tokenize_normalize_and_tiers() {
        assert_eq!(tokenize_search_text("MCP Tool"), vec!["mcp tool", "mcp", "tool"]);
        assert_eq!(tokenize_search_text("mcp__srv__read"), vec!["mcp__srv__read", "mcp", "srv", "read"]);
        assert_eq!(normalize_query("  /Model "), "model");
        assert_eq!(normalize_query("///sb"), "sb");
        let m = it("model", "Show or switch this session's model");
        assert_eq!(score_item(&m, "model"), 0, "exact name");
        assert_eq!(score_item(&m, "mod"), 1, "prefix");
        assert_eq!(score_item(&m, "del"), 2, "substring");
        let s = it("compact", "Compact the context now; summary of the run");
        assert_eq!(score_item(&s, "summary"), 3, "description word exact");
        assert_eq!(score_item(&s, "summ"), 4, "description word prefix");
        assert_eq!(score_item(&s, "ummar"), 5, "description word substring");
        assert_eq!(score_item(&s, "zzz"), NONE);
        let alias = Item { name: "statusbar".into(), aliases: vec!["sb".into()], ..Default::default() };
        assert_eq!(score_item(&alias, "sb"), 0, "alias exact");
    }

    #[test]
    fn rank_is_stable_and_empty_query_keeps_order() {
        let items = vec![it("model", "switch model"), it("mock", "test fixture"), it("status", "session model and tokens")];
        assert_eq!(rank(&items, ""), vec![0, 1, 2]);
        assert_eq!(rank(&items, "   "), vec![0, 1, 2]);
        // "model" is an exact name hit (0); `status`'s description has the word (3);
        // `mock` matches neither the name nor the help text.
        assert_eq!(rank(&items, "model"), vec![0, 2]);
        assert_eq!(rank(&items, "/mod"), vec![0, 2], "leading slash ignored");
        // Equal scores keep the original order.
        let ties = vec![it("aa", "x"), it("ab", "x")];
        assert_eq!(rank(&ties, "a"), vec![0, 1]);
        assert!(rank(&items, "nothing-matches").is_empty());
    }

    #[test]
    fn palette_navigation_and_selection() {
        let items = items(&json!([
            {"name": "model", "args": "[provider/model]", "description": "Show or switch this session's model", "category": "Session", "local": false},
            {"name": "statusbar", "aliases": ["sb"], "args": "", "description": "Toggle the status bar", "category": "Display", "local": true},
            {"name": "copy", "args": "", "description": "Copy the last answer", "category": "Info", "local": true}
        ]));
        assert_eq!(items.len(), 3);
        assert!(items[1].local && items[1].aliases == vec!["sb".to_string()]);
        let mut p = Palette::default();
        p.open_with(items.clone(), "");
        assert!(p.open);
        assert_eq!(p.matches.len(), 3);
        assert_eq!(p.selected().unwrap().name, "model");
        p.move_cursor(1);
        assert_eq!(p.selected().unwrap().name, "statusbar");
        p.move_cursor(-1);
        p.move_cursor(-1);
        assert_eq!(p.selected().unwrap().name, "copy", "wraps around");
        assert_eq!(p.selected().unwrap().invocation(), "/copy");
        p.push('s');
        p.push('b');
        assert_eq!(p.matches.len(), 1);
        assert_eq!(p.selected().unwrap().name, "statusbar", "alias match");
        p.pop();
        assert_eq!(p.query, "s");
        p.close();
        assert!(!p.open && p.query.is_empty() && p.matches.is_empty());
        p.open_with(items.clone(), "");
        p.push('m');
        p.push('o');
        assert_eq!(p.selected().unwrap().name, "model");
        assert_eq!(p.selected().unwrap().invocation(), "/model ");
        assert_eq!(p.window(), &[0], "only `model` matches `mo`");
    }
}
