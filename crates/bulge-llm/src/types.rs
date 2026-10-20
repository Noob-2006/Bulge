//! Provider-neutral request, message, and stream types.
//!
//! Every backend (HTTP wire protocols and the in-process local model) speaks
//! these types; wire formats exist only inside `protocol::*`.

use serde::{Deserialize, Serialize};

use crate::error::LlmError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// The first system message is the system prompt; later ones are
    /// in-history updates (see [`SystemPromptUpdate`]).
    System,
    User,
    Assistant,
    /// Result of one tool call; `Message::tool_call_id` names the call.
    Tool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ContentBlock {
    Text {
        text: String,
    },
    /// Model reasoning. `signature` is provider replay metadata and is only
    /// valid for the model recorded in `Message::source_model`.
    Reasoning {
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
    ToolCall {
        id: String,
        name: String,
        /// Raw JSON text exactly as produced by the model.
        arguments: String,
    },
    Image {
        media_type: String,
        /// Base64-encoded bytes.
        data: String,
    },
    /// Activates a deferred tool by name. Only valid in a `Role::System` message.
    ToolAddition {
        name: String,
    },
    /// Removes a tool by name. Only valid in a `Role::System` message.
    ToolRemoval {
        name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: Vec<ContentBlock>,
    /// Required for `Role::Tool`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
    /// Model that produced an assistant message; reasoning signatures are
    /// dropped when the target model differs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_model: Option<String>,
}

impl Message {
    pub fn text(role: Role, text: impl Into<String>) -> Self {
        Self {
            role,
            content: vec![ContentBlock::Text { text: text.into() }],
            tool_call_id: None,
            is_error: None,
            source_model: None,
        }
    }

    pub fn tool_result(call_id: impl Into<String>, text: impl Into<String>, is_error: bool) -> Self {
        Self {
            role: Role::Tool,
            content: vec![ContentBlock::Text { text: text.into() }],
            tool_call_id: Some(call_id.into()),
            is_error: is_error.then_some(true),
            source_model: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolSchema {
    pub name: String,
    pub description: String,
    /// JSON Schema object for the arguments.
    pub parameters: serde_json::Value,
    /// Declared but inactive until a `ToolAddition` block activates it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub defer_loading: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReasoningEffort {
    Off,
    Low,
    High,
    Max,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Purpose {
    Conversation,
    Compaction,
    Memory,
    Classify,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GenerateRequest {
    pub model: String,
    pub messages: Vec<Message>,
    #[serde(default)]
    pub tools: Vec<ToolSchema>,
    #[serde(default)]
    pub max_tokens: Option<u32>,
    #[serde(default)]
    pub temperature: Option<f32>,
    #[serde(default)]
    pub stop: Vec<String>,
    #[serde(default)]
    pub reasoning_effort: Option<ReasoningEffort>,
    pub purpose: Purpose,
}

/// How a route reads a system prompt that changes mid-conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SystemPromptUpdate {
    /// Only a leading system prompt is read; later updates are merged into it
    /// (breaks the prefix cache).
    #[default]
    LeadingOnly,
    /// The latest system message anywhere in history is the effective prompt;
    /// updates are appended and the cached prefix stays intact.
    InHistory,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelInfo {
    pub id: String,
    pub context_window: u32,
    pub max_tokens: u32,
    #[serde(default)]
    pub system_prompt_update: SystemPromptUpdate,
    /// Route honours `defer_loading` + `ToolAddition`.
    #[serde(default)]
    pub deferred_tools: bool,
    #[serde(default)]
    pub images: bool,
    #[serde(default)]
    pub reasoning: bool,
}

/// Disjoint counts: `input_tokens` excludes cached input.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub reasoning_tokens: u64,
}

impl TokenUsage {
    pub fn total(&self) -> u64 {
        self.input_tokens + self.output_tokens + self.cache_read_tokens + self.cache_write_tokens
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlockKind {
    Text,
    Reasoning,
    ToolCall,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FinishReason {
    Stop,
    ToolCalls,
    MaxTokens,
    Aborted,
    Error(LlmError),
}

/// Streaming protocol emitted by every backend. Block indexes are dense and
/// local (0, 1, 2, ...) regardless of wire indexes. `Usage` precedes the single
/// terminal `Finish`; nothing follows `Finish`.
#[derive(Debug, Clone, PartialEq)]
pub enum StreamChunk {
    BlockStart { index: usize, kind: BlockKind },
    TextDelta { index: usize, text: String },
    ReasoningDelta { index: usize, text: String },
    ToolCallDelta { index: usize, id: String, name: Option<String>, arguments_delta: String },
    /// Carries the assembled block (with final signature / arguments).
    BlockEnd { index: usize, block: ContentBlock },
    Usage(TokenUsage),
    Finish(FinishReason),
}
