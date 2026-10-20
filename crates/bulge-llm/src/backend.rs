//! The pluggable model core: every model source implements [`LlmBackend`].

use futures::stream::BoxStream;
use tokio_util::sync::CancellationToken;

use crate::types::{GenerateRequest, ModelInfo, StreamChunk};

pub trait LlmBackend: Send + Sync {
    /// Stable backend id from configuration (e.g. `deepseek`, `local`).
    fn id(&self) -> &str;

    fn models(&self) -> &[ModelInfo];

    /// Never fails out-of-band: every failure, including cancellation, ends the
    /// stream with `StreamChunk::Finish(FinishReason::Error | Aborted)`.
    fn stream(&self, request: GenerateRequest, cancel: CancellationToken) -> BoxStream<'static, StreamChunk>;
}
