//! Fold a chunk stream into one assistant message.

use crate::types::{ContentBlock, FinishReason, Message, Role, StreamChunk, TokenUsage};

#[derive(Debug, Clone, PartialEq)]
pub struct Assembled {
    pub message: Message,
    pub usage: TokenUsage,
    pub finish: FinishReason,
}

#[derive(Debug, Default)]
pub struct Assembler {
    blocks: Vec<Option<ContentBlock>>,
    usage: TokenUsage,
    finish: Option<FinishReason>,
}

impl Assembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, chunk: &StreamChunk) {
        match chunk {
            StreamChunk::BlockEnd { index, block } => {
                if self.blocks.len() <= *index {
                    self.blocks.resize(index + 1, None);
                }
                self.blocks[*index] = Some(block.clone());
            }
            StreamChunk::Usage(usage) => self.usage = *usage,
            StreamChunk::Finish(reason) => self.finish = Some(reason.clone()),
            _ => {}
        }
    }

    pub fn is_finished(&self) -> bool {
        self.finish.is_some()
    }

    /// Unclosed blocks are dropped. On `MaxTokens`, tool calls whose arguments
    /// are not a JSON object are dropped (truncated mid-call).
    pub fn finish(self, model: &str) -> Assembled {
        let finish = self.finish.unwrap_or(FinishReason::Aborted);
        let truncated = finish == FinishReason::MaxTokens;
        let content = self
            .blocks
            .into_iter()
            .flatten()
            .filter(|block| match block {
                ContentBlock::ToolCall { arguments, .. } if truncated => {
                    serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(arguments).is_ok()
                }
                _ => true,
            })
            .collect();
        Assembled {
            message: Message {
                role: Role::Assistant,
                content,
                tool_call_id: None,
                is_error: None,
                source_model: Some(model.to_owned()),
            },
            usage: self.usage,
            finish,
        }
    }
}
