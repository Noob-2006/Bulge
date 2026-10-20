//! Paged file / directory reading for the model.
//! MARK: M14 — transcribed by dsh; see marks/M14-read.md.

use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Page {
    /// `text` is numbered `N: line` (1-based). `next_offset` is set when more lines remain.
    Text { text: String, total_lines: usize, next_offset: Option<usize> },
    /// Sorted entries; directories end with `/`.
    Directory { entries: Vec<String>, total: usize, next_offset: Option<usize> },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReadError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("binary file: {0}")]
    Binary(String),
    #[error("offset {offset} is past the end ({total} lines)")]
    OffsetPastEnd { offset: usize, total: usize },
    #[error("io: {0}")]
    Io(String),
}

pub const DEFAULT_LIMIT: usize = 2000;
/// Longer lines are cut and marked so one minified line cannot flood context.
pub const MAX_LINE_CHARS: usize = 2000;

/// `offset` is 1-based (default 1); `limit` defaults to and is capped at `DEFAULT_LIMIT`.
pub fn read_page(path: &Path, offset: Option<usize>, limit: Option<usize>) -> Result<Page, ReadError> {
    let _ = (path, offset, limit);
    todo!("M14")
}
