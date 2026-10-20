//! Exact-string edit with tolerant matching.
//! MARK: M12 — transcribed by dsh; see marks/M12-edit.md.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditOutcome {
    /// Full new file content, with the file's original line endings and BOM preserved.
    pub content: String,
    pub replacements: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EditError {
    #[error("old_string must not be empty")]
    EmptyOldString,
    #[error("old_string and new_string are identical")]
    NoChange,
    #[error("old_string not found")]
    NotFound,
    #[error("old_string matches {0} locations; add context or set replace_all")]
    Ambiguous(usize),
}

/// Replace `old` with `new` in `content`. Matching tiers, first hit wins:
/// exact -> unicode-normalized -> per-line trailing-whitespace-insensitive.
pub fn apply_edit(content: &str, old: &str, new: &str, replace_all: bool) -> Result<EditOutcome, EditError> {
    let _ = (content, old, new, replace_all);
    todo!("M12")
}
