//! Repair tool calls that weak / local models emit as plain text.
//! MARK: M8 — transcribed by dsh; see marks/M8-repair.md.

mod grammar;
mod payload;

/// One tool call recovered from assistant text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairedCall {
    pub name: String,
    /// Compact JSON object text.
    pub arguments: String,
    /// Byte range in the source text that the call occupied.
    pub span: std::ops::Range<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct RepairOptions {
    /// Only these names may be repaired; empty = reject all.
    pub allowed_tools: Vec<String>,
    pub max_payload_bytes: usize,
}

/// Cheap pre-check: does the text look like it contains a tool call attempt?
pub fn looks_like_tool_call(text: &str) -> bool {
    let _ = text;
    todo!("M8")
}

/// Parse every standalone plain-text tool call block. Returns the calls and the
/// text with those spans removed. Text inside fenced code blocks is never repaired.
pub fn repair(text: &str, options: &RepairOptions) -> (Vec<RepairedCall>, String) {
    let _ = (text, options);
    todo!("M8")
}
