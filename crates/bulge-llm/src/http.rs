//! HTTP backend: one [`WireProtocol`] + endpoint + key, with retry, idle
//! timeout, and cancellation. Outbound client only; nothing listens locally.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use futures::stream::BoxStream;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::backend::LlmBackend;
use crate::error::{ErrorCode, LlmError};
use crate::protocol::{EncodeContext, WireProtocol};
use crate::retry::RetryPolicy;
use crate::sse::SseParser;
use crate::types::{FinishReason, GenerateRequest, ModelInfo, StreamChunk};

/// Discover the models a provider currently offers: `GET {base_url}{models_path}`
/// with the protocol's auth headers, parsing the OpenAI/Anthropic shape
/// `{ "data": [ { "id": ... }, ... ] }`. Returns the model ids. Used to replace a
/// hardcoded model list with what the key can actually reach.
pub async fn list_models(base_url: &str, api_key: &str, protocol: &dyn WireProtocol) -> Result<Vec<String>, LlmError> {
    let url = format!("{}{}", base_url.trim_end_matches('/'), protocol.models_path());
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| LlmError::new(ErrorCode::Network, e.to_string()))?;
    let mut req = client.get(&url);
    for (name, value) in protocol.auth_headers(api_key) {
        req = req.header(name, value);
    }
    let resp = req.send().await.map_err(|e| LlmError::new(ErrorCode::Network, e.to_string()))?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.map_err(|e| LlmError::new(ErrorCode::MalformedResponse, e.to_string()))?;
    if !status.is_success() {
        return Err(protocol.classify_error(Some(status.as_u16()), &body, None, None));
    }
    let ids = body
        .get("data")
        .and_then(|d| d.as_array())
        .map(|arr| arr.iter().filter_map(|m| m.get("id").and_then(|i| i.as_str()).map(String::from)).collect::<Vec<_>>())
        .unwrap_or_default();
    Ok(ids)
}

#[derive(Debug, Clone)]
pub struct HttpBackendConfig {
    pub id: String,
    pub base_url: String,
    pub api_key: String,
    pub models: Vec<ModelInfo>,
    pub default_max_tokens: u32,
    pub stream_idle_timeout: Duration,
    pub retry: RetryPolicy,
}

pub struct HttpBackend {
    config: HttpBackendConfig,
    protocol: Arc<dyn WireProtocol>,
    client: reqwest::Client,
}

impl HttpBackend {
    pub fn new(config: HttpBackendConfig, protocol: Arc<dyn WireProtocol>) -> Result<Self, LlmError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| LlmError::new(ErrorCode::Network, e.to_string()))?;
        Ok(Self { config, protocol, client })
    }

    fn model_info(&self, id: &str) -> ModelInfo {
        self.config.models.iter().find(|m| m.id == id).cloned().unwrap_or_else(|| ModelInfo {
            id: id.to_owned(),
            context_window: 64_000,
            max_tokens: self.config.default_max_tokens,
            system_prompt_update: Default::default(),
            deferred_tools: false,
            images: false,
            reasoning: false,
        })
    }
}

impl LlmBackend for HttpBackend {
    fn id(&self) -> &str {
        &self.config.id
    }

    fn models(&self) -> &[ModelInfo] {
        &self.config.models
    }

    fn stream(&self, request: GenerateRequest, cancel: CancellationToken) -> BoxStream<'static, StreamChunk> {
        let (tx, rx) = mpsc::channel(64);
        let model = self.model_info(&request.model);
        let body = self
            .protocol
            .encode(&request, &EncodeContext { model: &model, default_max_tokens: self.config.default_max_tokens });
        let job = Job {
            config: self.config.clone(),
            protocol: self.protocol.clone(),
            client: self.client.clone(),
            model: request.model,
        };
        tokio::spawn(async move {
            let finish = match body {
                Err(error) => FinishReason::Error(error),
                Ok(body) => job.run(body, &tx, &cancel).await,
            };
            let _ = tx.send(StreamChunk::Finish(finish)).await;
        });
        tokio_stream_from(rx)
    }
}

fn tokio_stream_from(mut rx: mpsc::Receiver<StreamChunk>) -> BoxStream<'static, StreamChunk> {
    futures::stream::poll_fn(move |cx| rx.poll_recv(cx)).boxed()
}

struct Job {
    config: HttpBackendConfig,
    protocol: Arc<dyn WireProtocol>,
    client: reqwest::Client,
    model: String,
}

/// Outcome of one attempt. Retries are only allowed before any chunk reached
/// the consumer, so a consumer never sees a partially repeated response.
enum Attempt {
    Done(FinishReason),
    Failed { error: LlmError, emitted: bool },
}

impl Job {
    async fn run(&self, body: serde_json::Value, tx: &mpsc::Sender<StreamChunk>, cancel: &CancellationToken) -> FinishReason {
        let mut retry = 0;
        loop {
            let attempt = tokio::select! {
                () = cancel.cancelled() => return FinishReason::Aborted,
                attempt = self.attempt(&body, tx) => attempt,
            };
            match attempt {
                Attempt::Done(finish) => return finish,
                Attempt::Failed { error, emitted: true } => return FinishReason::Error(error),
                Attempt::Failed { error, emitted: false } => {
                    retry += 1;
                    let Some(delay) = self.config.retry.delay_for(retry, &error, jitter()) else {
                        return FinishReason::Error(error);
                    };
                    tokio::select! {
                        () = cancel.cancelled() => return FinishReason::Aborted,
                        () = tokio::time::sleep(delay) => {}
                    }
                }
            }
        }
    }

    async fn attempt(&self, body: &serde_json::Value, tx: &mpsc::Sender<StreamChunk>) -> Attempt {
        let failed = |error| Attempt::Failed { error, emitted: false };
        let url = format!("{}{}", self.config.base_url.trim_end_matches('/'), self.protocol.endpoint_path());
        let mut req = self.client.post(url).header("content-type", "application/json").header("accept", "text/event-stream");
        for (name, value) in self.protocol.auth_headers(&self.config.api_key) {
            req = req.header(name, value);
        }
        let response = match req.json(body).send().await {
            Ok(response) => response,
            Err(e) => return failed(LlmError::new(ErrorCode::Network, e.to_string())),
        };
        let status = response.status();
        if !status.is_success() {
            let header = |name: &str| response.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_owned);
            let retry_after = header("retry-after");
            let request_id = header("request-id").or_else(|| header("x-request-id"));
            let body = response.json::<serde_json::Value>().await.unwrap_or(serde_json::Value::Null);
            return failed(self.protocol.classify_error(Some(status.as_u16()), &body, retry_after.as_deref(), request_id.as_deref()));
        }

        let mut decoder = self.protocol.decoder(&self.model);
        let mut parser = SseParser::new();
        let mut bytes = response.bytes_stream();
        let mut emitted = false;
        let fail = |error, emitted| Attempt::Failed { error, emitted };
        loop {
            let next = tokio::time::timeout(self.config.stream_idle_timeout, bytes.next()).await;
            let chunk = match next {
                Err(_) => return fail(LlmError::new(ErrorCode::StreamIdle, "provider stream idle"), emitted),
                Ok(None) => {
                    return match decoder.on_close() {
                        Err(e) => fail(e, emitted),
                        Ok(chunks) => match self.forward(chunks, tx, &mut emitted).await {
                            Some(finish) => Attempt::Done(finish),
                            None => fail(LlmError::new(ErrorCode::StreamClosed, "stream ended without finish"), emitted),
                        },
                    };
                }
                Ok(Some(Err(e))) => return fail(LlmError::new(ErrorCode::Network, e.to_string()), emitted),
                Ok(Some(Ok(chunk))) => chunk,
            };
            for event in parser.push(&chunk).events {
                let chunks = match decoder.on_event(event) {
                    Ok(chunks) => chunks,
                    Err(e) => return fail(e, emitted),
                };
                if let Some(finish) = self.forward(chunks, tx, &mut emitted).await {
                    return Attempt::Done(finish);
                }
            }
        }
    }

    /// Forward chunks; the decoder's `Finish` is withheld and returned so the
    /// spawner emits exactly one terminal chunk.
    async fn forward(&self, chunks: Vec<StreamChunk>, tx: &mpsc::Sender<StreamChunk>, emitted: &mut bool) -> Option<FinishReason> {
        for chunk in chunks {
            if let StreamChunk::Finish(finish) = chunk {
                return Some(finish);
            }
            *emitted = true;
            if tx.send(chunk).await.is_err() {
                return Some(FinishReason::Aborted);
            }
        }
        None
    }
}

fn jitter() -> f64 {
    use std::hash::{BuildHasher, RandomState};
    (RandomState::new().hash_one(std::time::Instant::now()) % 1_000_000) as f64 / 1_000_000.0
}
