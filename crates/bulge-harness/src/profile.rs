//! Bounded profile surfaces: two small markdown files the caller can inject into
//! the system prompt — `USER.md` (who the user is and how they want the agent to
//! behave) and `MEMORY.md` (durable facts about this environment).
//!
//! Each file is an ordered set of `## key` sections, one fact per section, so a
//! caller can render a compact surface without parsing prose. The char budgets
//! are enforced on save: a profile that would overflow is rejected rather than
//! silently truncated, because the caller decides what to drop.
//!
//! Like `usage`, this is plain, dependency-free persistence: missing means empty
//! and saves are atomic, so a crash never leaves a half-written profile.

use std::path::Path;

/// Where the user profile lives.
pub const USER_FILE: &str = "USER.md";
/// Where the environment memory lives.
pub const MEMORY_FILE: &str = "MEMORY.md";
/// Char budgets (the system-prompt surface must stay small). Enforced on save.
pub const USER_LIMIT: usize = 1400;
pub const MEMORY_LIMIT: usize = 2200;

/// One titled section of a profile file, rendered as `## <key>\n<body>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub key: String,
    pub body: String,
}

/// An ordered set of `## key` sections. Missing file => empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Profile {
    pub sections: Vec<Section>,
}

impl Profile {
    /// Load the profile at `path`. A missing file is simply empty; any other read
    /// failure is reported so a broken surface is never silently replaced.
    pub fn load(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(source) => Ok(Self::parse(&source)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(format!("read {}: {error}", path.display())),
        }
    }

    /// Parse markdown: a line starting with `## ` opens a section (key = the rest,
    /// trimmed); body is the following lines up to the next `## ` or EOF, trimmed.
    /// Text before the first `## ` is ignored. Empty-body sections are kept only
    /// if they have a non-empty key.
    pub fn parse(text: &str) -> Self {
        let mut sections = Vec::new();
        let mut key: Option<String> = None;
        let mut body_lines: Vec<&str> = Vec::new();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("## ") {
                push_section(&mut sections, key.take(), &body_lines);
                body_lines.clear();
                key = Some(rest.trim().to_string());
            } else if key.is_some() {
                body_lines.push(line);
            }
        }
        push_section(&mut sections, key, &body_lines);
        Self { sections }
    }

    /// Render back to markdown: each section as `## {key}\n{body}` joined by a
    /// blank line. Keys and bodies are trimmed, so a round-trip is stable.
    pub fn render(&self) -> String {
        self.sections
            .iter()
            .map(|section| format!("## {}\n{}", section.key.trim(), section.body.trim()))
            .collect::<Vec<_>>()
            .join("\n\n")
    }

    /// The body of the section whose key matches exactly, ignoring surrounding
    /// whitespace on either side.
    pub fn get(&self, key: &str) -> Option<&str> {
        let key = key.trim();
        self.sections
            .iter()
            .find(|section| section.key.trim() == key)
            .map(|section| section.body.trim())
    }

    /// Replace the body of an existing section (exact trimmed key), or append a
    /// new one at the end. Existing sections keep their position.
    pub fn upsert(&mut self, key: &str, body: &str) {
        let key = key.trim();
        let body = body.trim();
        if let Some(section) = self
            .sections
            .iter_mut()
            .find(|section| section.key.trim() == key)
        {
            section.body = body.to_string();
            return;
        }
        self.sections.push(Section {
            key: key.to_string(),
            body: body.to_string(),
        });
    }

    /// Drop the section whose key matches exactly, ignoring surrounding
    /// whitespace. Returns whether anything was removed.
    pub fn remove(&mut self, key: &str) -> bool {
        let key = key.trim();
        let before = self.sections.len();
        self.sections.retain(|section| section.key.trim() != key);
        self.sections.len() != before
    }

    /// The rendered length, in chars (not bytes), so CJK text is measured fairly.
    pub fn char_len(&self) -> usize {
        self.render().chars().count()
    }

    /// Atomically save (temp-file + rename, like `UsageLedger::save`). Returns Err
    /// WITHOUT writing if the rendered content exceeds `limit` chars — the caller
    /// must trim first (never silently drop).
    pub fn save(&self, path: &Path, limit: usize) -> Result<(), String> {
        let source = self.render();
        let length = source.chars().count();
        if length > limit {
            return Err(format!(
                "profile is {length} chars, over the {limit}-char limit"
            ));
        }
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create {}: {error}", parent.display()))?;
        }
        let file = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(USER_FILE);
        let temp = path.with_file_name(format!("{file}.tmp-{}", std::process::id()));
        std::fs::write(&temp, source)
            .map_err(|error| format!("write {}: {error}", temp.display()))?;
        std::fs::rename(&temp, path).map_err(|error| {
            let _ = std::fs::remove_file(&temp);
            format!("rename {} to {}: {error}", temp.display(), path.display())
        })
    }
}

/// Collect one parsed section. A section with neither a key nor a body carries
/// no information, so it is dropped.
fn push_section(sections: &mut Vec<Section>, key: Option<String>, body_lines: &[&str]) {
    let Some(key) = key else {
        return;
    };
    let body = body_lines.join("\n").trim().to_string();
    if key.is_empty() && body.is_empty() {
        return;
    }
    sections.push(Section { key, body });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "bulge-profile-{}-{}-{label}",
            std::process::id(),
            line!()
        ))
    }

    #[test]
    fn parse_then_render_round_trips_multi_section_with_cjk() {
        let source = "\
preamble that is ignored

## Role
Rust developer who prefers 简体中文 answers.

## Style
Terse; no fluff.
- show the diff first
";
        let profile = Profile::parse(source);
        assert_eq!(profile.sections.len(), 2);
        assert_eq!(profile.get("Role"), Some("Rust developer who prefers 简体中文 answers."));
        assert_eq!(profile.get("Style"), Some("Terse; no fluff.\n- show the diff first"));

        let reparsed = Profile::parse(&profile.render());
        assert_eq!(reparsed, profile, "a round-trip is stable");
        assert_eq!(reparsed.render(), profile.render());
    }

    #[test]
    fn parse_keeps_titled_empty_sections_and_drops_untitled_ones() {
        let profile = Profile::parse("## \n\n## Empty\n\n## Body\nx\n");
        assert_eq!(profile.sections.len(), 2);
        assert_eq!(profile.sections[0].key, "Empty");
        assert_eq!(profile.sections[0].body, "");
        assert_eq!(profile.sections[1], Section { key: "Body".into(), body: "x".into() });
    }

    #[test]
    fn parse_ignores_preamble_until_the_first_section() {
        let profile = Profile::parse("no sections here\njust prose");
        assert!(profile.sections.is_empty());
    }

    #[test]
    fn upsert_replaces_in_place_then_appends_new() {
        let mut profile = Profile::parse("## A\none\n\n## B\ntwo\n");
        profile.upsert(" A ", "updated");
        assert_eq!(
            profile.sections,
            vec![
                Section { key: "A".into(), body: "updated".into() },
                Section { key: "B".into(), body: "two".into() },
            ],
            "an existing section keeps its position"
        );

        profile.upsert("C", "three");
        assert_eq!(profile.sections.last().unwrap().key, "C");
        assert_eq!(profile.sections.len(), 3);
    }

    #[test]
    fn remove_reports_whether_anything_was_removed() {
        let mut profile = Profile::parse("## A\none\n\n## B\ntwo\n");
        assert!(profile.remove(" A "));
        assert_eq!(profile.sections.len(), 1);
        assert_eq!(profile.sections[0].key, "B");
        assert!(!profile.remove(" A "), "already gone");
    }

    #[test]
    fn get_matches_the_trimmed_key() {
        let profile = Profile::parse("##  Build \nuse cargo\n");
        assert_eq!(profile.get("Build"), Some("use cargo"));
        assert_eq!(profile.get(" Build "), Some("use cargo"));
        assert_eq!(profile.get("Missing"), None);
    }

    #[test]
    fn char_len_counts_chars_not_bytes() {
        let mut profile = Profile::default();
        profile.upsert("K", "中文");
        assert_eq!(profile.char_len(), profile.render().chars().count());
        assert!(profile.char_len() < profile.render().len(), "CJK bytes exceed chars");
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = temp_dir("round-trip");
        let path = dir.join(USER_FILE);
        let _ = std::fs::remove_dir_all(&dir);

        let mut profile = Profile::default();
        profile.upsert("Role", "Rust developer; prefers 简体中文.");
        profile.save(&path, USER_LIMIT).expect("saves");

        let loaded = Profile::load(&path).expect("loads");
        assert_eq!(loaded, profile);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_over_the_limit_errors_without_creating_the_file() {
        let dir = temp_dir("too-big");
        let path = dir.join(USER_FILE);
        let _ = std::fs::remove_dir_all(&dir);

        let mut profile = Profile::default();
        profile.upsert("Long", &"x".repeat(100));
        let error = profile.save(&path, 10).expect_err("over the limit");
        assert!(error.contains("over the 10-char limit"));
        assert!(!path.exists(), "an over-budget profile is never written");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_loads_as_empty() {
        let dir = temp_dir("missing");
        let path = dir.join(MEMORY_FILE);
        let _ = std::fs::remove_dir_all(&dir);

        let profile = Profile::load(&path).expect("missing file is not an error");
        assert_eq!(profile, Profile::default());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
