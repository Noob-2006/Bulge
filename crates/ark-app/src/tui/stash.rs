//! Ctrl+S prompt stash (Hermes `hermes_cli/prompt_stash.py`): a session-scoped,
//! newest-first stack of parked composer drafts. One Ctrl+S parks a non-empty draft;
//! on an empty composer it restores the only draft, or opens a browse panel when there
//! are several (↑/↓ move, Enter restore, Delete/x drop, Ctrl+S or Esc close).

pub const PREVIEW_WIDTH: usize = 60;
pub const MAX_ITEMS: usize = 20;

/// Collapse a possibly multi-line draft into one preview line.
pub fn preview(text: &str, width: usize) -> String {
    if text.is_empty() {
        return String::new();
    }
    let flat = text.replace("\r\n", "\n").replace('\r', "\n").replace('\n', " ⏎ ").replace('\t', " ");
    let flat = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    if width > 1 && flat.chars().count() > width {
        return flat.chars().take(width - 1).collect::<String>() + "…";
    }
    flat
}

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub text: String,
    pub images: usize,
    pub stashed_at: std::time::SystemTime,
    pub preview: String,
}

#[derive(Debug, Default)]
pub struct Stash {
    items: Vec<Entry>,
    max: usize,
    pub panel_open: bool,
    pub cursor: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Noop,
    Stashed,
    Restored(String),
    OpenPanel,
    ClosePanel,
}

impl Stash {
    pub fn new() -> Stash {
        Stash { items: vec![], max: MAX_ITEMS, panel_open: false, cursor: 0 }
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
    pub fn items(&self) -> &[Entry] {
        &self.items
    }
    /// Status-bar indicator: `📌 2` idle, `📌 2 ▲` while browsing, empty when empty.
    pub fn indicator(&self) -> String {
        match (self.items.len(), self.panel_open) {
            (0, _) => String::new(),
            (n, true) => format!("📌 {n} ▲"),
            (n, false) => format!("📌 {n}"),
        }
    }
    /// Composer placeholder advertising the stash.
    pub fn placeholder_hint(&self) -> String {
        match self.items.len() {
            0 => String::new(),
            1 => format!("Ctrl+S to restore: {}", self.items[0].preview),
            n => format!("Ctrl+S to browse {n} stashed drafts"),
        }
    }
    /// Push a draft; a blank buffer with no images is a no-op.
    pub fn stash(&mut self, text: &str, images: usize) -> bool {
        if text.trim().is_empty() && images == 0 {
            return false;
        }
        let p = preview(text, PREVIEW_WIDTH);
        self.items.insert(0, Entry { text: text.to_string(), images, stashed_at: std::time::SystemTime::now(), preview: if p.is_empty() { "(images only)".into() } else { p } });
        self.items.truncate(self.max.max(1));
        self.close_panel();
        true
    }
    fn clamp(&self, v: usize) -> usize {
        if self.items.is_empty() {
            0
        } else {
            v.min(self.items.len() - 1)
        }
    }
    pub fn pop(&mut self, index: usize) -> Option<String> {
        if index >= self.items.len() {
            return None;
        }
        let e = self.items.remove(index);
        if self.items.is_empty() {
            self.panel_open = false;
        }
        self.cursor = self.clamp(self.cursor);
        Some(e.text)
    }
    pub fn clear(&mut self) {
        self.items.clear();
        self.close_panel();
    }
    pub fn open_panel(&mut self) -> bool {
        if self.items.is_empty() {
            return false;
        }
        self.panel_open = true;
        self.cursor = 0;
        true
    }
    pub fn close_panel(&mut self) {
        self.panel_open = false;
        self.cursor = 0;
    }
    pub fn move_cursor(&mut self, delta: isize) -> usize {
        let c = (self.cursor as isize + delta).max(0) as usize;
        self.cursor = self.clamp(c);
        self.cursor
    }
    pub fn delete_at_cursor(&mut self) -> bool {
        if self.items.is_empty() {
            return false;
        }
        let i = self.clamp(self.cursor);
        self.items.remove(i);
        if self.items.is_empty() {
            self.close_panel();
        } else {
            self.cursor = self.clamp(i);
        }
        true
    }
    pub fn restore_at_cursor(&mut self) -> Option<String> {
        if self.items.is_empty() {
            return None;
        }
        let r = self.pop(self.clamp(self.cursor));
        self.close_panel();
        r
    }
    /// One Ctrl+S press.
    pub fn ctrl_s(&mut self, buffer: &str, images: usize) -> Outcome {
        if self.panel_open {
            self.close_panel();
            return Outcome::ClosePanel;
        }
        if !buffer.trim().is_empty() || images > 0 {
            return if self.stash(buffer, images) { Outcome::Stashed } else { Outcome::Noop };
        }
        match self.items.len() {
            0 => Outcome::Noop,
            1 => self.pop(0).map(Outcome::Restored).unwrap_or(Outcome::Noop),
            _ => {
                self.open_panel();
                Outcome::OpenPanel
            }
        }
    }
    /// Panel rows: `▶ preview` for the cursor row.
    pub fn panel_rows(&self) -> Vec<String> {
        self.items.iter().enumerate().map(|(i, e)| format!("{} {}. {}", if i == self.cursor { "▶" } else { " " }, i + 1, e.preview)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctrl_s_gesture_and_panel() {
        assert_eq!(preview("a\nb\tc   d", 60), "a ⏎ b c d");
        assert_eq!(preview(&"x".repeat(80), 10), format!("{}…", "x".repeat(9)));
        let mut s = Stash::new();
        assert_eq!(s.ctrl_s("", 0), Outcome::Noop);
        assert_eq!(s.ctrl_s("first draft", 0), Outcome::Stashed);
        assert_eq!(s.indicator(), "📌 1");
        assert_eq!(s.placeholder_hint(), "Ctrl+S to restore: first draft");
        assert_eq!(s.ctrl_s("   ", 0), Outcome::Restored("first draft".into()));
        assert!(s.is_empty());
        s.ctrl_s("one", 0);
        s.ctrl_s("two", 0);
        assert_eq!(s.items()[0].text, "two", "newest first");
        assert_eq!(s.ctrl_s("", 0), Outcome::OpenPanel);
        assert_eq!(s.indicator(), "📌 2 ▲");
        s.move_cursor(5);
        assert_eq!(s.cursor, 1);
        assert_eq!(s.panel_rows()[1], "▶ 2. one");
        assert_eq!(s.ctrl_s("", 0), Outcome::ClosePanel);
        s.open_panel();
        s.move_cursor(1);
        assert_eq!(s.restore_at_cursor().as_deref(), Some("one"));
        assert!(!s.panel_open);
        s.open_panel();
        assert!(s.delete_at_cursor());
        assert!(s.is_empty() && !s.panel_open);
        for i in 0..30 {
            s.stash(&format!("d{i}"), 0);
        }
        assert_eq!(s.len(), MAX_ITEMS);
        assert_eq!(s.items()[0].text, "d29");
        assert!(s.stash("", 1));
        assert_eq!(s.items()[0].preview, "(images only)");
    }
}
