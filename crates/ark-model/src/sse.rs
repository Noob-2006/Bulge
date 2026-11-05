//! Minimal incremental Server-Sent Events parser.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
}

#[derive(Debug, Default)]
pub struct SseParser {
    buf: Vec<u8>,
    event: Option<String>,
    data: Vec<String>,
}

impl SseParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed raw bytes; returns every event completed by them.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<SseEvent> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
            let mut line: Vec<u8> = self.buf.drain(..=pos).collect();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            self.line(&String::from_utf8_lossy(&line), &mut out);
        }
        out
    }

    /// Flush a trailing line and pending event when the stream ends without a blank line.
    pub fn finish(&mut self) -> Vec<SseEvent> {
        let mut out = Vec::new();
        if !self.buf.is_empty() {
            let rest = std::mem::take(&mut self.buf);
            let s = String::from_utf8_lossy(&rest);
            self.line(s.trim_end_matches('\r'), &mut out);
        }
        self.dispatch(&mut out);
        out
    }

    fn line(&mut self, line: &str, out: &mut Vec<SseEvent>) {
        if line.is_empty() {
            self.dispatch(out);
            return;
        }
        if line.starts_with(':') {
            return;
        }
        let (field, value) = match line.find(':') {
            Some(i) => {
                let v = &line[i + 1..];
                (&line[..i], v.strip_prefix(' ').unwrap_or(v))
            }
            None => (line, ""),
        };
        match field {
            "data" => self.data.push(value.to_string()),
            "event" => self.event = Some(value.to_string()),
            _ => {}
        }
    }

    fn dispatch(&mut self, out: &mut Vec<SseEvent>) {
        if self.data.is_empty() {
            self.event = None;
            return;
        }
        out.push(SseEvent {
            event: self.event.take(),
            data: std::mem::take(&mut self.data).join("\n"),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(e: Option<&str>, d: &str) -> SseEvent {
        SseEvent {
            event: e.map(String::from),
            data: d.into(),
        }
    }

    #[test]
    fn basic_and_named_events() {
        let mut p = SseParser::new();
        let out = p.feed(b"data: {\"a\":1}\n\nevent: ping\ndata: x\n\n");
        assert_eq!(out, vec![ev(None, "{\"a\":1}"), ev(Some("ping"), "x")]);
    }

    #[test]
    fn crlf_comments_and_multiline() {
        let mut p = SseParser::new();
        let out = p.feed(b": keepalive\r\ndata: line1\r\ndata:line2\r\nid: 7\r\nretry: 5\r\n\r\n");
        assert_eq!(out, vec![ev(None, "line1\nline2")]);
    }

    #[test]
    fn partial_chunks_across_reads() {
        let mut p = SseParser::new();
        assert!(p.feed(b"data: {\"he").is_empty());
        assert!(p.feed(b"llo\":true}\r").is_empty());
        assert!(p.feed(b"\n").is_empty());
        assert_eq!(
            p.feed(b"\r\ndata: [DONE]\n\n"),
            vec![ev(None, "{\"hello\":true}"), ev(None, "[DONE]")]
        );
    }

    #[test]
    fn utf8_split_across_reads() {
        let s = "data: 你好\n\n".as_bytes();
        let mut p = SseParser::new();
        assert!(p.feed(&s[..8]).is_empty());
        assert_eq!(p.feed(&s[8..]), vec![ev(None, "你好")]);
    }

    #[test]
    fn finish_flushes_unterminated_event() {
        let mut p = SseParser::new();
        assert!(p.feed(b"data: tail").is_empty());
        assert_eq!(p.finish(), vec![ev(None, "tail")]);
        assert!(p.finish().is_empty());
    }

    #[test]
    fn malformed_lines_are_ignored_not_fatal() {
        let mut p = SseParser::new();
        let out = p
            .feed(b"garbage without colon\nevent: only-event\n\n\xff\xfe: bad bytes\ndata: ok\n\n");
        assert_eq!(out, vec![ev(None, "ok")]);
    }

    #[test]
    fn event_without_data_is_dropped_and_does_not_leak() {
        let mut p = SseParser::new();
        let out = p.feed(b"event: a\n\ndata: x\n\n");
        assert_eq!(out, vec![ev(None, "x")]);
    }
}
