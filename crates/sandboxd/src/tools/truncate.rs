//! Bound tool output for the model; spill the full text to a file.
//! MARK: M13 — transcribed by dsh; see marks/M13-truncate.md.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_lines: usize,
    pub max_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self { max_lines: 2000, max_bytes: 50 * 1024 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bounded {
    /// Text to show the model (head + gap + tail + notice when truncated).
    pub text: String,
    pub truncated: bool,
    /// Where the full text was written, when truncated.
    pub spill_path: Option<PathBuf>,
    pub total_lines: usize,
    pub total_bytes: usize,
}

/// If `text` fits `limits`, return it unchanged. Otherwise write the full text
/// to a new owner-only file in `spill_dir` and return head + tail within the
/// limits plus a notice naming the file and how to read it.
pub fn bound_output(text: &str, limits: Limits, spill_dir: &Path) -> std::io::Result<Bounded> {
    let _ = (text, limits, spill_dir);
    todo!("M13")
}
