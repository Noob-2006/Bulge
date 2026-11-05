//! Memory-context fencing beyond the kernel's `fence`/`strip_fences` (Hermes
//! agent/memory_context.py, MIT): scrub provider output and streamed text of recalled
//! blocks, and drop repeated recall bullets inside one block.

use regex::Regex;

/// Strip fenced recall blocks (`<recalled-context …>`, `<memory-context>`), their system
/// notes and stray tags from text leaving the agent (provider output, UI text).
pub fn sanitize_context(text: &str) -> String {
    let mut t = seagent_kernel::lifecycle::strip_fences(text);
    for p in [
        r"(?is)<\s*memory-context\s*>.*?</\s*memory-context\s*>",
        r"(?is)<recalled-context[^>]*>.*?</recalled-context>",
        r"(?i)\[System note:\s*(The following is recalled memory context,\s*NOT new user input\.\s*Treat as (?:informational background data|authoritative reference data[^\]]*)\.|recalled background, not new user input\.[^\]]*)\]\s*",
        r"(?i)</?\s*memory-context\s*>",
        r"(?i)</?recalled-context[^>]*>",
    ] {
        t = Regex::new(p).unwrap().replace_all(&t, "").into_owned();
    }
    t
}

/// Streaming scrubber: recalled spans may straddle deltas, so partial tags are held back
/// and span interiors dropped. Both fence shapes (`<recalled-context …>` from
/// `build_block`/kernel, `<memory-context>` from Hermes providers) are scrubbed by one
/// scrubber. One per response; call `flush` at end of stream.
#[derive(Default)]
pub struct StreamScrubber {
    in_span: bool,
    /// Just closed a span: the fence's separator newlines go with it.
    skip_nl: bool,
    buf: String,
    /// Close tag of the span that is open.
    close: &'static str,
}

/// Opener (prefix; attributes may follow) → close tag, for each recalled-block shape.
const SPANS: [(&str, &str); 2] = [("<recalled-context", "</recalled-context>"), ("<memory-context", "</memory-context>")];

fn partial_suffix(buf: &str, tag: &str) -> usize {
    let b = buf.to_lowercase();
    (1..tag.len().min(b.len() + 1)).rev().find(|&i| b.is_char_boundary(b.len() - i) && tag.starts_with(&b[b.len() - i..])).unwrap_or(0)
}

/// Earliest opener in `buf`: (offset, opener, close tag that ends its span).
fn find_open(buf: &str) -> Option<(usize, &'static str, &'static str)> {
    let b = buf.to_lowercase();
    SPANS.iter().filter_map(|(o, c)| b.find(o).map(|i| (i, *o, *c))).min_by_key(|(i, _, _)| *i)
}

/// Longest tail of `buf` that could still grow into one of the openers.
fn held_open(buf: &str) -> usize {
    SPANS.iter().map(|(o, _)| partial_suffix(buf, o)).max().unwrap_or(0)
}

impl StreamScrubber {
    pub fn feed(&mut self, text: &str) -> String {
        let mut buf = std::mem::take(&mut self.buf) + text;
        let mut out = String::new();
        loop {
            if self.skip_nl {
                buf = buf.trim_start_matches('\n').to_string();
                if buf.is_empty() {
                    return out;
                }
                self.skip_nl = false;
            }
            if self.in_span {
                let close = self.close;
                match buf.to_lowercase().find(close) {
                    Some(i) => {
                        buf = buf[i + close.len()..].to_string();
                        self.in_span = false;
                        self.skip_nl = true;
                    }
                    None => {
                        let h = partial_suffix(&buf, close);
                        self.buf = buf[buf.len() - h..].to_string();
                        return out;
                    }
                }
            } else {
                match find_open(&buf) {
                    Some((i, open, close)) => {
                        out.push_str(buf[..i].trim_end_matches('\n'));
                        buf = buf[i + open.len()..].to_string();
                        self.in_span = true;
                        self.close = close;
                    }
                    None => {
                        let h = held_open(&buf);
                        // Hold trailing newlines back: they may be the fence separator.
                        let end = buf.len() - h;
                        let cut = buf[..end].trim_end_matches('\n').len();
                        out.push_str(&buf[..cut]);
                        self.buf = buf[cut..].to_string();
                        return out;
                    }
                }
            }
        }
    }
    /// Emit the held tail; inside an unterminated span it is discarded.
    pub fn flush(&mut self) -> String {
        let t = if self.in_span { String::new() } else { std::mem::take(&mut self.buf) };
        self.buf.clear();
        self.in_span = false;
        self.skip_nl = false;
        self.close = "";
        t
    }
}

/// Drop a self-contained bullet that an earlier line of the same section already states.
pub fn dedupe_recall_lines(text: &str) -> String {
    let lines: Vec<&str> = text.split('\n').collect();
    let bullet = Regex::new(r"^[-*+]\s+\S").unwrap();
    let mut seen = std::collections::HashSet::new();
    let mut kept = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let s = line.trim();
        if !s.is_empty() && line.starts_with(char::is_whitespace) {
            kept.push(*line);
            continue;
        }
        let is_b = bullet.is_match(s);
        if !s.is_empty() && !is_b {
            seen.clear();
        }
        let has_cont = lines.get(i + 1).is_some_and(|n| !n.trim().is_empty() && n.starts_with(char::is_whitespace));
        if is_b && !has_cont && !seen.insert(s.to_string()) {
            continue;
        }
        kept.push(*line);
    }
    kept.join("\n")
}

/// Fence a merged prefetch block for the model (dedupe + kernel fence).
pub fn build_block(source: &str, text: &str) -> String {
    seagent_kernel::lifecycle::fence(source, &dedupe_recall_lines(&sanitize_context(text)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_and_stream() {
        let t = format!("answer{} tail <memory-context>\nsecret\n</memory-context> end", seagent_kernel::lifecycle::fence("m", "likes tea"));
        let s = sanitize_context(&t);
        assert!(!s.contains("likes tea") && !s.contains("secret") && s.contains("answer") && s.contains("end"), "{s}");
        let full = format!("Hello{}World", seagent_kernel::lifecycle::fence("m", "hidden"));
        let mut sc = StreamScrubber::default();
        let mut out = String::new();
        for ch in full.as_bytes().chunks(5) {
            out.push_str(&sc.feed(std::str::from_utf8(ch).unwrap()));
        }
        out.push_str(&sc.flush());
        assert_eq!(out, "HelloWorld");
        let mut sc = StreamScrubber::default();
        assert_eq!(sc.feed("a <recalled-context x>never closed"), "a ");
        assert_eq!(sc.flush(), "");
    }

    #[test]
    fn scrubs_memory_context_spans() {
        // One scrubber drops `<memory-context>` spans too, split across deltas.
        let src = "a<memory-context>secret</memory-context>b";
        let mut sc = StreamScrubber::default();
        let mut out = String::new();
        for ch in src.as_bytes().chunks(3) {
            out.push_str(&sc.feed(std::str::from_utf8(ch).unwrap()));
        }
        out.push_str(&sc.flush());
        assert_eq!(out, "ab");
        // A lone opener with no close is dropped entirely (interior never escapes).
        let src = "keep<memory-context>secret with no close";
        let mut sc = StreamScrubber::default();
        let mut out = String::new();
        for ch in src.as_bytes().chunks(3) {
            out.push_str(&sc.feed(std::str::from_utf8(ch).unwrap()));
        }
        out.push_str(&sc.flush());
        assert_eq!(out, "keep");
        // Both shapes alternate in one stream.
        let src = "x<recalled-context source=\"m\">\n- tea\n</recalled-context>y<memory-context>z</memory-context>w";
        let mut sc = StreamScrubber::default();
        let mut out = String::new();
        for ch in src.as_bytes().chunks(4) {
            out.push_str(&sc.feed(std::str::from_utf8(ch).unwrap()));
        }
        out.push_str(&sc.flush());
        assert_eq!(out, "xyw");
    }

    #[test]
    fn dedupe_bullets_per_section() {
        let t = "## A\n- likes tea\n- likes tea\n## B\n- likes tea\n- dup\n  (logged)\n- dup";
        assert_eq!(dedupe_recall_lines(t), "## A\n- likes tea\n## B\n- likes tea\n- dup\n  (logged)\n- dup");
        assert!(build_block("memory", "- a\n- a").matches("- a").count() == 1);
    }
}
