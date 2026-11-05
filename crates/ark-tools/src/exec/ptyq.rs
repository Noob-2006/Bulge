//! Answer the blocking terminal queries programs send to a PTY (Hermes
//! `tools/pty_query_responder.py`, a port of openai/codex#41436). ark's PTY has no emulator on
//! the master side, so a program probing its terminal (device status `ESC[5n`, window size
//! `ESC[18t`, cursor position `ESC[6n`, DEC private mode `ESC[?<n>$p`) would block forever or
//! leak the raw query into the captured output. The scanner strips handled queries (also when
//! split across reads) and returns the bounded replies to write back; everything else passes.

const ESC: u8 = 0x1b;
const MAX_MODE_DIGITS: usize = 10;
const MAX_QUERY_BYTES: usize = MAX_MODE_DIGITS + 5;

pub struct PtyQueryResponder {
    answers: [(Vec<u8>, Vec<u8>); 3],
    pending: Vec<u8>,
}

impl PtyQueryResponder {
    pub fn new(rows: u16, cols: u16) -> Self {
        PtyQueryResponder {
            answers: [(b"\x1b[5n".to_vec(), b"\x1b[0n".to_vec()), (b"\x1b[18t".to_vec(), format!("\x1b[8;{rows};{cols}t").into_bytes()), (b"\x1b[6n".to_vec(), b"\x1b[1;1R".to_vec())],
            pending: Vec::new(),
        }
    }

    /// Scan a chunk: (output without handled queries, replies for the program's stdin).
    pub fn process(&mut self, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        if self.pending.is_empty() && !data.contains(&ESC) {
            return (data.to_vec(), Vec::new());
        }
        let mut out = Vec::with_capacity(data.len());
        let mut replies = Vec::new();
        for &b in data {
            if self.pending.is_empty() && b != ESC {
                out.push(b);
                continue;
            }
            if b == ESC {
                // A fresh ESC aborts any partial sequence: flush it through.
                out.append(&mut self.pending);
            }
            self.pending.push(b);
            let p = &self.pending;
            if p.len() == 1 || p.as_slice() == b"\x1b[" || (p[1] == b'[' && !(0x40..=0x7e).contains(&b) && p.len() < MAX_QUERY_BYTES) {
                continue;
            }
            let seq = std::mem::take(&mut self.pending);
            if let Some((_, r)) = self.answers.iter().find(|(q, _)| *q == seq) {
                replies.extend_from_slice(r);
            } else if seq.len() >= 5 && seq.starts_with(b"\x1b[?") && seq.ends_with(b"$p") && {
                let mode = &seq[3..seq.len() - 2];
                !mode.is_empty() && mode.len() <= MAX_MODE_DIGITS && mode.iter().all(u8::is_ascii_digit)
            } {
                // DEC private-mode query: report the mode as not recognised.
                replies.extend_from_slice(b"\x1b[?");
                replies.extend_from_slice(&seq[3..seq.len() - 2]);
                replies.extend_from_slice(b";0$y");
            } else {
                out.extend_from_slice(&seq);
            }
        }
        (out, replies)
    }

    /// Incomplete trailing sequence held back at end of stream.
    pub fn flush(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_queries_and_passes_everything_else() {
        let mut r = PtyQueryResponder::new(30, 100);
        let (o, a) = r.process(b"hi\x1b[6nthere\x1b[5n");
        assert_eq!((o.as_slice(), a.as_slice()), (&b"hithere"[..], &b"\x1b[1;1R\x1b[0n"[..]));
        let (o, a) = r.process(b"\x1b[18t");
        assert_eq!((o.len(), a.as_slice()), (0, &b"\x1b[8;30;100t"[..]));
        let (o, a) = r.process(b"\x1b[31mred\x1b[0m");
        assert_eq!((o.as_slice(), a.len()), (&b"\x1b[31mred\x1b[0m"[..], 0), "colors untouched");
        let (o, a) = r.process(b"\x1b[?2026$p");
        assert_eq!((o.len(), a.as_slice()), (0, &b"\x1b[?2026;0$y"[..]));
        let (o, a) = r.process("ü plain".as_bytes());
        assert_eq!((o.as_slice(), a.len()), ("ü plain".as_bytes(), 0));
    }

    #[test]
    fn split_queries_and_flush() {
        let mut r = PtyQueryResponder::new(24, 80);
        let (o1, a1) = r.process(b"a\x1b[");
        let (o2, a2) = r.process(b"6nb");
        assert_eq!((o1.as_slice(), a1.len()), (&b"a"[..], 0));
        assert_eq!((o2.as_slice(), a2.as_slice()), (&b"b"[..], &b"\x1b[1;1R"[..]));
        let (o, _) = r.process(b"\x1b[1");
        assert!(o.is_empty());
        assert_eq!(r.flush(), b"\x1b[1");
        let (o, _) = r.process(b"\x1b[\x1b[5n");
        assert_eq!(o, b"\x1b[", "a fresh ESC flushes the partial one");
    }
}
