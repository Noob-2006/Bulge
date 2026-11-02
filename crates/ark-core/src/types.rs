//! Provider-neutral conversation model. Every adapter translates to and from these.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Assistant,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Block {
    Text { text: String },
    /// Model reasoning. Kept so providers that require it echoed back (Anthropic, DeepSeek) get it.
    Thinking {
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
    ToolUse { id: String, name: String, input: Value },
    ToolResult {
        tool_use_id: String,
        content: String,
        #[serde(default)]
        is_error: bool,
    },
    /// Image input (user messages): base64 `data` of `media_type` (image/png, image/jpeg…).
    Image { media_type: String, data: String },
}

impl Block {
    pub fn text(s: impl Into<String>) -> Self {
        Block::Text { text: s.into() }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: Vec<Block>,
}

impl Message {
    pub fn user(text: impl Into<String>) -> Self {
        Message { role: Role::User, content: vec![Block::text(text)] }
    }
    pub fn assistant(text: impl Into<String>) -> Self {
        Message { role: Role::Assistant, content: vec![Block::text(text)] }
    }
    /// Concatenated visible text of this message.
    pub fn text(&self) -> String {
        let mut out = String::new();
        for b in &self.content {
            if let Block::Text { text } = b {
                if !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(text);
            }
        }
        out
    }
    pub fn tool_uses(&self) -> impl Iterator<Item = (&str, &str, &Value)> {
        self.content.iter().filter_map(|b| match b {
            Block::ToolUse { id, name, input } => Some((id.as_str(), name.as_str(), input)),
            _ => None,
        })
    }
}

/// One stable segment of the system prompt. Segments are ordered most-stable first;
/// `cache` marks the last segment of a cacheable prefix (Anthropic breakpoint).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemSegment {
    pub id: String,
    pub text: String,
    #[serde(default)]
    pub cache: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolSchema {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelRequest {
    pub model: String,
    pub system: Vec<SystemSegment>,
    pub messages: Vec<Message>,
    pub tools: Vec<ToolSchema>,
    pub max_tokens: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// Index into `messages` after which a cache breakpoint should be placed (if supported).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_after_message: Option<usize>,
    /// Reasoning effort: "off", "low", "medium" or "high"; None = provider default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<String>,
}

impl ModelRequest {
    pub fn system_text(&self) -> String {
        self.system.iter().map(|s| s.text.as_str()).collect::<Vec<_>>().join("\n\n")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    EndTurn,
    ToolUse,
    MaxTokens,
    /// Provider refused / content filtered.
    Refusal,
    Other,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    #[serde(default)]
    pub cache_read_tokens: u64,
    #[serde(default)]
    pub cache_write_tokens: u64,
    /// True when the numbers came from a heuristic, not the provider.
    #[serde(default)]
    pub estimated: bool,
}

impl Usage {
    pub fn total(&self) -> u64 {
        self.input_tokens + self.output_tokens
    }
    pub fn add(&mut self, o: &Usage) {
        self.input_tokens += o.input_tokens;
        self.output_tokens += o.output_tokens;
        self.cache_read_tokens += o.cache_read_tokens;
        self.cache_write_tokens += o.cache_write_tokens;
        self.estimated |= o.estimated;
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelResponse {
    pub message: Message,
    pub stop: StopReason,
    pub usage: Usage,
    pub model: String,
}

/// Incremental output while a response streams.
#[derive(Debug, Clone, PartialEq)]
pub enum StreamEvent {
    TextDelta(String),
    ThinkingDelta(String),
    ToolUseStart { id: String, name: String },
}

/// Rough token estimate (≈4 bytes/token for latin, ≈1.5 chars/token for CJK).
pub fn estimate_tokens(s: &str) -> u64 {
    let mut ascii = 0u64;
    let mut other = 0u64;
    for c in s.chars() {
        if c.is_ascii() {
            ascii += 1
        } else {
            other += 1
        }
    }
    ascii / 4 + (other * 2) / 3 + 1
}

/// Rough cost of one image input (providers bill ~1–2k tokens for a typical screenshot).
pub const IMAGE_TOKENS: u64 = 1600;

pub fn estimate_request_tokens(req: &ModelRequest) -> u64 {
    let mut n = estimate_tokens(&req.system_text());
    for m in &req.messages {
        for b in &m.content {
            n += match b {
                Block::Text { text } | Block::Thinking { text, .. } => estimate_tokens(text),
                Block::ToolUse { name, input, .. } => estimate_tokens(name) + estimate_tokens(&input.to_string()),
                Block::ToolResult { content, .. } => estimate_tokens(content),
                Block::Image { .. } => IMAGE_TOKENS,
            } + 4;
        }
    }
    for t in &req.tools {
        n += estimate_tokens(&t.description) + estimate_tokens(&t.input_schema.to_string());
    }
    n
}
