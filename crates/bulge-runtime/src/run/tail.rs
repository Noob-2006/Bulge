//! Streaming the job log to a sink while the turn runs.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

/// Receives each complete JSONL log line as it is committed (one call per line,
/// newline stripped). The CLI prints to stdout; the desktop app forwards each
/// line to the webview. `Send` so it can live in the tailing task.
pub type LineSink = Box<dyn FnMut(&str) + Send>;

/// Stream newly-appended complete lines of a JSONL file to `sink` until `stop`
/// is cancelled, then flush once more. The store writes the log atomically with
/// fsync, so reading committed bytes is safe from this separate reader.
pub(crate) async fn tail_jsonl(path: PathBuf, stop: CancellationToken, mut sink: LineSink, start_offset: usize) {
    let mut offset = start_offset;
    loop {
        offset = flush_new_lines(&path, offset, &mut sink);
        tokio::select! {
            () = stop.cancelled() => break,
            () = tokio::time::sleep(Duration::from_millis(120)) => {}
        }
    }
    // Final flush: the last events were appended just before the loop ended.
    flush_new_lines(&path, offset, &mut sink);
}

/// Hand each complete line starting at `offset` to `sink`; return the new offset
/// (end of the last newline consumed).
pub(crate) fn flush_new_lines(path: &Path, offset: usize, sink: &mut LineSink) -> usize {
    let Ok(bytes) = std::fs::read(path) else { return offset };
    if bytes.len() <= offset {
        return offset;
    }
    let fresh = &bytes[offset..];
    let Some(last_newline) = fresh.iter().rposition(|&b| b == b'\n') else {
        return offset;
    };
    let printable = &fresh[..=last_newline];
    if let Ok(text) = std::str::from_utf8(printable) {
        for line in text.lines() {
            if !line.is_empty() {
                sink(line);
            }
        }
    }
    offset + last_newline + 1
}

/// The default sink: print each line to stdout, as the headless CLI does.
pub(crate) fn stdout_sink() -> LineSink {
    Box::new(|line: &str| {
        use std::io::Write;
        println!("{line}");
        let _ = std::io::stdout().flush();
    })
}
