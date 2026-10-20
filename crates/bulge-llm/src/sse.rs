//! Incremental SSE framing (WHATWG event-stream rules).
//! MARK: M4 — transcribed by dsh; see marks/M4-sse.md.

use crate::protocol::SseEvent;

/// Push-based parser: feed arbitrary byte chunks, get complete events.
/// An unterminated trailing event is never emitted.
#[derive(Debug, Default)]
pub struct SseParser {
    /// Bytes of the current, not-yet-terminated line.
    buffer: Vec<u8>,
    /// Whether the leading BOM check has completed.
    started: bool,
    /// The previous line ended with `\r`; swallow a leading `\n` next time.
    skip_lf: bool,
    event: Option<String>,
    data: String,
    data_lines: usize,
}

impl SseParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed bytes. Returns complete events in order. Comment lines (`:`) are
    /// reported by incrementing the returned `comments` count (idle watchdog pulse).
    pub fn push(&mut self, bytes: &[u8]) -> SsePush {
        let mut out = SsePush::default();
        if bytes.is_empty() {
            return out;
        }
        self.buffer.extend_from_slice(bytes);

        // Strip a UTF-8 BOM at the very start, even when its bytes are split
        // across pushes. Until the first three bytes are known, hold off.
        if !self.started {
            let length = self.buffer.len();
            if length < 3 {
                let may_still_be_bom =
                    self.buffer[0] == 0xEF && (length == 1 || self.buffer[1] == 0xBB);
                if may_still_be_bom {
                    return out;
                }
                self.started = true;
            } else {
                self.started = true;
                if self.buffer.starts_with(&[0xEF, 0xBB, 0xBF]) {
                    self.buffer.drain(..3);
                }
            }
        }

        // A `\r` at the end of the previous chunk may be half of a `\r\n`.
        if self.skip_lf {
            if self.buffer.first() == Some(&b'\n') {
                self.buffer.remove(0);
            }
            self.skip_lf = false;
        }

        let mut line_start = 0;
        let mut cursor = 0;
        while cursor < self.buffer.len() {
            let byte = self.buffer[cursor];
            if byte != b'\n' && byte != b'\r' {
                cursor += 1;
                continue;
            }

            let line_end = cursor;
            let mut next = cursor + 1;
            let mut ends_with_cr = false;
            if byte == b'\r' {
                if next < self.buffer.len() {
                    if self.buffer[next] == b'\n' {
                        next += 1;
                    }
                } else {
                    ends_with_cr = true;
                }
            }

            process_line(
                &self.buffer[line_start..line_end],
                &mut self.event,
                &mut self.data,
                &mut self.data_lines,
                &mut out,
            );

            line_start = next;
            cursor = next;
            if ends_with_cr {
                self.skip_lf = true;
            }
        }

        if line_start > 0 {
            self.buffer.drain(..line_start);
        }

        out
    }
}

fn process_line(
    line: &[u8],
    event: &mut Option<String>,
    data: &mut String,
    data_lines: &mut usize,
    out: &mut SsePush,
) {
    if line.is_empty() {
        if *data_lines > 0 && !data.is_empty() {
            out.events.push(SseEvent {
                event: event.take(),
                data: std::mem::take(data),
            });
        } else {
            *event = None;
            data.clear();
        }
        *data_lines = 0;
        return;
    }

    if line[0] == b':' {
        out.comments += 1;
        return;
    }

    // Lines are split at byte boundaries before decoding, so a line is always
    // a complete UTF-8 sequence (unless the provider itself sent invalid bytes).
    let text = String::from_utf8_lossy(line);
    let (field, value) = match text.split_once(':') {
        Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
        None => (text.as_ref(), ""),
    };

    match field {
        "data" => {
            if *data_lines > 0 {
                data.push('\n');
            }
            data.push_str(value);
            *data_lines += 1;
        }
        "event" => {
            *event = if value.is_empty() {
                None
            } else {
                Some(value.to_owned())
            };
        }
        // Connection management fields are read and otherwise ignored here.
        "id" | "retry" => {}
        _ => {}
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SsePush {
    pub events: Vec<SseEvent>,
    pub comments: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data_event(data: &str) -> SseEvent {
        SseEvent {
            event: None,
            data: data.to_owned(),
        }
    }

    #[test]
    fn sse_complete_stream_dispatches_in_order() {
        let stream = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\"}\n",
            "\n",
            ": heartbeat\n",
            "\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\"}\n",
            "\n",
        );
        let mut parser = SseParser::new();
        let pushed = parser.push(stream.as_bytes());

        assert_eq!(pushed.comments, 1);
        assert_eq!(
            pushed.events,
            vec![
                SseEvent {
                    event: Some("message_start".to_owned()),
                    data: "{\"type\":\"message_start\"}".to_owned(),
                },
                SseEvent {
                    event: Some("content_block_delta".to_owned()),
                    data: "{\"type\":\"content_block_delta\"}".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn sse_byte_by_byte_matches_single_push() {
        let stream = concat!(
            "event: message\n",
            "data: 第一行\r\n",
            "data: 第二行\r\n",
            "\r\n",
            ": ping\r",
            "\r",
            "data: done\r",
            "\r",
        );
        let whole = SseParser::new().push(stream.as_bytes());

        let mut parser = SseParser::new();
        let mut bytewise = SsePush::default();
        for byte in stream.as_bytes() {
            let pushed = parser.push(std::slice::from_ref(byte));
            bytewise.events.extend(pushed.events);
            bytewise.comments += pushed.comments;
        }

        assert_eq!(whole, bytewise);
        assert_eq!(
            whole.events,
            vec![
                SseEvent {
                    event: Some("message".to_owned()),
                    data: "第一行\n第二行".to_owned(),
                },
                data_event("done"),
            ]
        );
        assert_eq!(whole.comments, 1);
    }

    #[test]
    fn sse_accepts_crlf_and_bare_cr_line_endings() {
        let mut parser = SseParser::new();
        let pushed = parser.push(b"data: a\r\n\r\ndata: b\r\rdata: c\n\n");
        assert_eq!(
            pushed.events,
            vec![data_event("a"), data_event("b"), data_event("c")]
        );
    }

    #[test]
    fn sse_crlf_split_across_pushes_is_one_terminator() {
        let mut parser = SseParser::new();
        let first = parser.push(b"data: a\r");
        assert!(first.events.is_empty());
        let second = parser.push(b"\n\r\n");
        assert_eq!(second.events, vec![data_event("a")]);
    }

    #[test]
    fn sse_multiline_data_is_joined_with_newline() {
        let mut parser = SseParser::new();
        let pushed = parser.push(b"event: custom\ndata: line 1\ndata: line 2\n\n");
        assert_eq!(
            pushed.events,
            vec![SseEvent {
                event: Some("custom".to_owned()),
                data: "line 1\nline 2".to_owned(),
            }]
        );
    }

    #[test]
    fn sse_comments_are_counted_and_do_not_dispatch() {
        let mut parser = SseParser::new();
        let pushed = parser.push(b": ping\n:no space\n\n: another\n\ndata: x\n\n");
        assert_eq!(pushed.comments, 3);
        assert_eq!(pushed.events, vec![data_event("x")]);
    }

    #[test]
    fn sse_utf8_character_split_across_pushes_is_preserved() {
        let stream = "data: 你好，世界\n\n";
        let bytes = stream.as_bytes();
        let split = "data: ".len() + 1; // inside the first Chinese character
        assert!(bytes[split].is_ascii() || std::str::from_utf8(&bytes[..split]).is_err());

        let mut parser = SseParser::new();
        let first = parser.push(&bytes[..split]);
        assert!(first.events.is_empty());
        let second = parser.push(&bytes[split..]);
        assert_eq!(second.events, vec![data_event("你好，世界")]);
    }

    #[test]
    fn sse_incomplete_trailing_event_is_not_dispatched() {
        let mut parser = SseParser::new();
        let pushed = parser.push(b"data: complete\n\ndata: incomplete\n");
        assert_eq!(pushed.events, vec![data_event("complete")]);

        let more = parser.push(b"\n");
        assert_eq!(more.events, vec![data_event("incomplete")]);
    }

    #[test]
    fn sse_bom_is_stripped_even_when_split_across_pushes() {
        let mut parser = SseParser::new();
        assert!(parser.push(b"\xEF").events.is_empty());
        assert!(parser.push(b"\xBB").events.is_empty());
        let pushed = parser.push(b"\xBFdata: bom\n\n");
        assert_eq!(pushed.events, vec![data_event("bom")]);
    }

    #[test]
    fn sse_strips_only_the_first_space_after_field_name() {
        let mut parser = SseParser::new();
        let pushed = parser.push(b"data:  two spaces\ndata:no-space\n\n");
        assert_eq!(pushed.events, vec![data_event(" two spaces\nno-space")]);
    }

    #[test]
    fn sse_frames_without_data_or_with_empty_data_do_not_dispatch() {
        let mut parser = SseParser::new();
        let pushed =
            parser.push(b"event: ping\nid: 7\nretry: 100\n\ndata:\n\ndata: \n\ndata: ok\n\n");
        assert_eq!(pushed.events, vec![data_event("ok")]);
    }
}
