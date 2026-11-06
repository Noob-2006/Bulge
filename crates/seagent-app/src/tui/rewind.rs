//! Rewind picker (Hermes `ui-tui/src/components/rewindPicker.tsx`): Esc Esc on an idle
//! composer lists earlier prompts newest first. Enter rewinds to just before the picked
//! prompt and prefills it for editing; `f` forks a new session from that point. Nothing
//! is cut until the picker action runs, and prompts that carried attachments are not
//! offered (a text replay would drop them).

use serde_json::Value;

/// One replayable user prompt, numbered from 1 (oldest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    pub turn: usize,
    pub text: String,
}

impl Prompt {
    pub fn first_line(&self) -> String {
        self.text.lines().find(|l| !l.trim().is_empty()).map(|l| l.trim().to_string()).unwrap_or_default()
    }
}

/// Earlier prompts in `session.view` messages, oldest first. Only plain-text human turns
/// are targets: a turn with an image, a file or tool results has no lossless text replay.
pub fn targets(messages: &[Value]) -> Vec<Prompt> {
    let mut out = Vec::new();
    for m in messages {
        if m["role"].as_str() != Some("user") {
            continue;
        }
        let blocks = m["content"].as_array().cloned().unwrap_or_default();
        if blocks.is_empty() || blocks.iter().any(|b| b["type"].as_str() != Some("text")) {
            continue;
        }
        let text = blocks.iter().filter_map(|b| b["text"].as_str()).collect::<Vec<_>>().join("\n");
        if text.trim().is_empty() {
            continue;
        }
        out.push(Prompt { turn: out.len() + 1, text });
    }
    out
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Picker {
    pub open: bool,
    /// Newest first, matching the overlay's top row.
    pub prompts: Vec<Prompt>,
    pub cursor: usize,
}

impl Picker {
    pub fn open(&mut self, messages: &[Value]) -> bool {
        let mut prompts = targets(messages);
        prompts.reverse();
        self.prompts = prompts;
        self.cursor = 0;
        self.open = !self.prompts.is_empty();
        self.open
    }

    pub fn close(&mut self) {
        self.open = false;
        self.prompts.clear();
        self.cursor = 0;
    }

    pub fn move_cursor(&mut self, delta: isize) {
        if self.prompts.is_empty() {
            return;
        }
        self.cursor = (self.cursor as isize + delta).clamp(0, self.prompts.len() as isize - 1) as usize;
    }

    pub fn selected(&self) -> Option<&Prompt> {
        self.prompts.get(self.cursor)
    }

    /// `/undo N` / `/branch --at N`: how many turns to cut so the picked prompt is gone
    /// (newest-first row 0 cuts one turn, the oldest row cuts them all).
    pub fn rewind_turns(&self) -> u64 {
        (self.cursor + 1) as u64
    }

    /// The visible slice around the cursor (`visible` rows).
    pub fn window(&self, visible: usize) -> std::ops::Range<usize> {
        if self.prompts.is_empty() {
            return 0..0;
        }
        let start = self.cursor.saturating_sub(visible.saturating_sub(1) / 2).min(self.prompts.len().saturating_sub(visible));
        start..(start + visible).min(self.prompts.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn view() -> Vec<Value> {
        vec![
            json!({"role": "user", "content": [{"type": "text", "text": "first"}]}),
            json!({"role": "assistant", "content": [{"type": "text", "text": "a1"}]}),
            json!({"role": "user", "content": [{"type": "text", "text": "second\nline two"}]}),
            json!({"role": "assistant", "content": [{"type": "text", "text": "a2"}]}),
            json!({"role": "user", "content": [{"type": "text", "text": "third"}]}),
            // Attachments are not text-replayable and keep their number without an entry.
            json!({"role": "user", "content": [{"type": "text", "text": "with image"}, {"type": "image", "media_type": "image/png", "data": ""}]}),
            // Tool-result users are not human turns.
            json!({"role": "user", "content": [{"type": "tool_result", "tool_use_id": "1", "content": "x"}]}),
        ]
    }

    #[test]
    fn targets_skip_media_and_keep_prompt_numbers() {
        let t = targets(&view());
        assert_eq!(t.iter().map(|p| p.turn).collect::<Vec<_>>(), [1, 2, 3]);
        assert_eq!(t[1].first_line(), "second");
        let p = Picker::default();
        assert!(p.prompts.is_empty() && p.selected().is_none());
    }

    #[test]
    fn picker_is_newest_first_and_maps_to_undo_counts() {
        let mut p = Picker::default();
        assert!(p.open(&view()));
        assert_eq!(p.prompts.iter().map(|x| x.turn).collect::<Vec<_>>(), [3, 2, 1]);
        assert_eq!(p.prompts[0].text, "third");
        assert_eq!(p.rewind_turns(), 1);
        p.move_cursor(1);
        assert_eq!(p.selected().map(|x| x.text.as_str()), Some("second\nline two"));
        assert_eq!(p.rewind_turns(), 2, "cut the picked turn and everything after it");
        p.move_cursor(99);
        assert_eq!(p.selected().map(|x| x.turn), Some(1));
        assert_eq!(p.rewind_turns(), 3);
        p.move_cursor(-99);
        assert_eq!(p.selected().map(|x| x.turn), Some(3));
        p.close();
        assert!(!p.open && p.prompts.is_empty());
        // A conversation with no replayable prompts does not open.
        assert!(!p.open(&view()[6..]));
    }

    #[test]
    fn window_keeps_the_cursor_visible() {
        let mut p = Picker { open: true, prompts: (0..20).map(|i| Prompt { turn: i + 1, text: format!("p{i}") }).collect(), cursor: 0 };
        assert_eq!(p.window(5), 0..5);
        p.cursor = 10;
        assert_eq!(p.window(5), 8..13);
        p.cursor = 19;
        assert_eq!(p.window(5), 15..20);
    }
}
