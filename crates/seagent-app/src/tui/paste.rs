//! Large-paste collapse/expand (Hermes `ui-tui/src/components/pasteSections.tsx`,
//! `domain/pasteExpand.ts`). A paste above the threshold is stored under a short marker
//! in the composer, expanded again on submit, and shown collapsed in the transcript until
//! Ctrl+E. The model always receives the full text.

/// Collapse a paste at this many characters or lines.
pub const MAX_CHARS: usize = 4_000;
pub const MAX_LINES: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paste {
    pub id: usize,
    pub text: String,
}

pub fn is_large(text: &str) -> bool {
    text.chars().count() > MAX_CHARS || text.lines().count() > MAX_LINES
}

/// The composer marker for one stored paste.
pub fn placeholder(id: usize, text: &str) -> String {
    format!("[pasted #{} · {} chars · {} lines · Ctrl+E expands]", id, text.chars().count(), text.lines().count())
}

/// Store a large paste; small text passes through unchanged (no marker).
pub fn collapse(text: &str, id: usize) -> (String, Option<Paste>) {
    if is_large(text) {
        (placeholder(id, text), Some(Paste { id, text: text.to_string() }))
    } else {
        (text.to_string(), None)
    }
}

/// Put every stored paste back into a submitted line. Markers that no longer exist are
/// left alone (the user may have typed the same text deliberately).
pub fn expand(input: &str, pastes: &[Paste]) -> String {
    let mut out = input.to_string();
    for p in pastes {
        out = out.replace(&placeholder(p.id, &p.text), &p.text);
    }
    out
}

/// A transcript line: large text collapses to a one-line summary unless expanded.
pub fn display(text: &str, expanded: bool) -> String {
    if expanded || !is_large(text) {
        return text.to_string();
    }
    let chars = text.chars().count();
    let lines = text.lines().count();
    let first = text.lines().find(|l| !l.trim().is_empty()).map(|l| l.trim().chars().take(80).collect::<String>()).unwrap_or_default();
    format!("[pasted {chars} chars · {lines} lines — Ctrl+E expands]\n{first}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_pastes_get_a_marker_and_expand_on_submit() {
        let big = "x".repeat(MAX_CHARS + 1);
        assert!(is_large(&big));
        assert!(!is_large("short"));
        assert!(!is_large(&"line\n".repeat(MAX_LINES)), "exactly the line limit is not large");
        let (marker, paste) = collapse(&big, 1);
        let paste = paste.expect("stored");
        assert!(marker.starts_with("[pasted #1 · ") && marker.ends_with("Ctrl+E expands]"));
        assert_eq!(expand(&format!("look: {marker}"), &[paste]), format!("look: {big}"));
        // Small text passes through with no stored copy.
        assert_eq!(collapse("short", 2), ("short".to_string(), None));
        let small = Paste { id: 2, text: "tiny".into() };
        assert_eq!(expand("keep [pasted #1", &[small]), "keep [pasted #1");
    }

    #[test]
    fn transcript_collapses_until_expanded() {
        let big = "a\n".repeat(MAX_LINES + 2);
        let collapsed = display(&big, false);
        assert!(collapsed.starts_with("[pasted ") && collapsed.contains("Ctrl+E expands]"), "{collapsed}");
        assert_eq!(display(&big, true), big);
        assert_eq!(display("short", false), "short");
    }
}
