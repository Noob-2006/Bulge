//! Bounded command runtime: named handlers, admission policy, concurrency /
//! input / output / timeout limits, cooperative cancellation, panic isolation.
//! MARK: M11 — transcribed by dsh; see marks/M11-command-runtime.md.

use std::collections::{BTreeMap, HashMap, hash_map::Entry};
use std::future::Future;
use std::io::{self, Write};
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use bulge_proto::msg::Outcome;
use futures::FutureExt;
use serde_json::Value;
use tokio::sync::{Semaphore, watch};

const DEFAULT_MAX_CONCURRENCY: usize = 8;
const DEFAULT_MAX_INPUT_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_OUTPUT_BYTES: usize = 256 * 1024;
const DEFAULT_HANDLER_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_HANDLER_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MAX_COMMAND_NAME_BYTES: usize = 128;

type HandlerFuture = Pin<Box<dyn Future<Output = Result<Value, HandlerError>> + Send>>;
type Handler = Arc<dyn Fn(InvocationContext) -> HandlerFuture + Send + Sync>;
type AdmissionFuture = Pin<Box<dyn Future<Output = Result<(), HandlerError>> + Send>>;
type AdmissionPolicy = Arc<dyn Fn(Invocation) -> AdmissionFuture + Send + Sync>;

/// One host invocation as seen by a handler.
#[derive(Debug, Clone, PartialEq)]
pub struct Invocation {
    pub id: u64,
    pub command: String,
    pub params: Value,
    /// Requested timeout; clamped to the runtime maximum.
    pub timeout: Option<Duration>,
}

/// Cooperative cancellation shared by a handler and any child work it starts.
#[derive(Clone, Debug)]
pub struct CancellationToken {
    sender: Arc<watch::Sender<bool>>,
}

impl CancellationToken {
    fn new() -> Self {
        let (sender, _receiver) = watch::channel(false);
        Self {
            sender: Arc::new(sender),
        }
    }

    pub fn is_cancelled(&self) -> bool {
        *self.sender.borrow()
    }

    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let mut receiver = self.sender.subscribe();
        while !*receiver.borrow_and_update() {
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }

    fn cancel(&self) {
        self.sender.send_replace(true);
    }
}

#[derive(Clone, Debug)]
pub struct InvocationContext {
    pub invocation: Invocation,
    pub cancellation: CancellationToken,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
#[error("{code}: {message}")]
pub struct HandlerError {
    pub code: String,
    pub message: String,
}

impl HandlerError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum RuntimeBuildError {
    #[error("command name must match [A-Za-z0-9._-]{{1,128}}: {0}")]
    InvalidCommand(String),
    #[error("duplicate command registration: {0}")]
    DuplicateCommand(String),
    #[error("invalid limit: {0}")]
    InvalidLimit(&'static str),
}

pub struct CommandRuntimeBuilder {
    registrations: Vec<(String, Handler)>,
    admission_policy: Option<AdmissionPolicy>,
    max_concurrency: usize,
    max_input_bytes: usize,
    max_output_bytes: usize,
    default_timeout: Duration,
    max_timeout: Duration,
}

impl Default for CommandRuntimeBuilder {
    fn default() -> Self {
        Self {
            registrations: Vec::new(),
            admission_policy: None,
            max_concurrency: DEFAULT_MAX_CONCURRENCY,
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            default_timeout: DEFAULT_HANDLER_TIMEOUT,
            max_timeout: DEFAULT_MAX_HANDLER_TIMEOUT,
        }
    }
}

impl CommandRuntimeBuilder {
    pub fn command<F, Fut>(mut self, command: impl Into<String>, handler: F) -> Self
    where
        F: Fn(InvocationContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value, HandlerError>> + Send + 'static,
    {
        self.registrations.push((
            command.into(),
            Arc::new(move |context| Box::pin(handler(context))),
        ));
        self
    }

    /// Evaluated before every handler; a rejection becomes the outcome.
    pub fn admission_policy<F, Fut>(mut self, policy: F) -> Self
    where
        F: Fn(Invocation) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), HandlerError>> + Send + 'static,
    {
        self.admission_policy = Some(Arc::new(move |invocation| Box::pin(policy(invocation))));
        self
    }

    pub fn max_concurrency(mut self, maximum: usize) -> Self {
        self.max_concurrency = maximum;
        self
    }

    pub fn max_input_bytes(mut self, maximum: usize) -> Self {
        self.max_input_bytes = maximum;
        self
    }

    pub fn max_output_bytes(mut self, maximum: usize) -> Self {
        self.max_output_bytes = maximum;
        self
    }

    pub fn default_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = timeout;
        self
    }

    pub fn max_timeout(mut self, timeout: Duration) -> Self {
        self.max_timeout = timeout;
        self
    }

    pub fn build(self) -> Result<CommandRuntime, RuntimeBuildError> {
        if self.max_concurrency == 0 {
            return Err(RuntimeBuildError::InvalidLimit("maxConcurrency"));
        }
        if self.max_input_bytes == 0 {
            return Err(RuntimeBuildError::InvalidLimit("maxInputBytes"));
        }
        if self.max_output_bytes == 0 {
            return Err(RuntimeBuildError::InvalidLimit("maxOutputBytes"));
        }

        let mut handlers = BTreeMap::new();
        for (name, handler) in self.registrations {
            let command = name.trim().to_owned();
            if !valid_command_name(&command) {
                return Err(RuntimeBuildError::InvalidCommand(name));
            }
            if handlers.insert(command.clone(), handler).is_some() {
                return Err(RuntimeBuildError::DuplicateCommand(command));
            }
        }

        let max_timeout = nonzero_duration(self.max_timeout);
        Ok(CommandRuntime {
            inner: Arc::new(RuntimeInner {
                handlers,
                admission_policy: self.admission_policy,
                permits: Arc::new(Semaphore::new(self.max_concurrency)),
                active: ActiveInvocations::default(),
                max_input_bytes: self.max_input_bytes,
                max_output_bytes: self.max_output_bytes,
                default_timeout: nonzero_duration(self.default_timeout).min(max_timeout),
                max_timeout,
            }),
        })
    }
}

fn valid_command_name(command: &str) -> bool {
    !command.is_empty()
        && command.len() <= MAX_COMMAND_NAME_BYTES
        && command
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

struct RuntimeInner {
    handlers: BTreeMap<String, Handler>,
    admission_policy: Option<AdmissionPolicy>,
    permits: Arc<Semaphore>,
    active: ActiveInvocations,
    max_input_bytes: usize,
    max_output_bytes: usize,
    default_timeout: Duration,
    max_timeout: Duration,
}

/// Cheap to clone; all clones share handlers, limits, and active invocations.
#[derive(Clone)]
pub struct CommandRuntime {
    inner: Arc<RuntimeInner>,
}

impl CommandRuntime {
    pub fn builder() -> CommandRuntimeBuilder {
        CommandRuntimeBuilder::default()
    }

    /// Registered command names, sorted bytewise.
    pub fn command_names(&self) -> Vec<String> {
        self.inner.handlers.keys().cloned().collect()
    }

    /// Run one invocation through every gate and return its single outcome.
    /// Never panics: handler panics, timeouts, overload, oversized input or
    /// output, unknown commands, and cancellation all become `Outcome::Err`
    /// with a stable code.
    pub async fn evaluate(&self, invocation: Invocation) -> Outcome {
        let Some(handler) = self.inner.handlers.get(&invocation.command).cloned() else {
            return failure("COMMAND_NOT_FOUND", "no handler registered for command");
        };

        let cancellation = CancellationToken::new();
        let Some(tracking) = self.inner.active.track(invocation.id, &cancellation) else {
            return failure("DUPLICATE_INVOCATION", "invocation id is already executing");
        };
        let Ok(_permit) = self.inner.permits.clone().try_acquire_owned() else {
            return failure("OVERLOADED", "command runtime is at its concurrency limit");
        };

        let mut evaluation = self
            .evaluate_tracked(invocation, handler, cancellation, tracking)
            .await;
        if let Some(tracking) = evaluation.tracking.as_mut() {
            tracking.disarm();
        }
        drop(evaluation.tracking);
        evaluation.outcome
    }

    /// Request cancellation of one active invocation (no-op if unknown/finished).
    pub fn cancel(&self, id: u64) {
        self.inner.active.cancel(id);
    }

    /// Cancel every active invocation (host disconnect / shutdown).
    pub fn cancel_all(&self) {
        self.inner.active.cancel_all();
    }

    async fn evaluate_tracked(
        &self,
        invocation: Invocation,
        handler: Handler,
        cancellation: CancellationToken,
        tracking: ActiveInvocation,
    ) -> Evaluation {
        if !serialized_json_within_limit(&invocation.params, self.inner.max_input_bytes) {
            return Evaluation::tracked(
                failure(
                    "INPUT_TOO_LARGE",
                    "command parameters exceed the runtime limit",
                ),
                tracking,
            );
        }

        let mut timeout = self.resolve_timeout(&invocation);
        timeout = match self
            .evaluate_admission(&invocation, &cancellation, timeout)
            .await
        {
            Ok(remaining) => remaining,
            Err(outcome) => {
                cancellation.cancel();
                return Evaluation::tracked(outcome, tracking);
            }
        };

        if cancellation.is_cancelled() {
            return Evaluation::tracked(
                failure(
                    "INVOCATION_CANCELLED",
                    "command invocation was cancelled before handler execution",
                ),
                tracking,
            );
        }

        let future = match std::panic::catch_unwind(AssertUnwindSafe(|| {
            handler(InvocationContext {
                invocation: invocation.clone(),
                cancellation: cancellation.clone(),
            })
        })) {
            Ok(future) => future,
            Err(_) => {
                cancellation.cancel();
                return Evaluation::tracked(
                    failure("HANDLER_PANIC", "command handler panicked"),
                    tracking,
                );
            }
        };

        let outcome = self.execute_handler(future, timeout, &cancellation).await;
        Evaluation::tracked(outcome, tracking)
    }

    async fn execute_handler(
        &self,
        future: HandlerFuture,
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> Outcome {
        let handler = AssertUnwindSafe(future).catch_unwind();
        tokio::pin!(handler);
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        let outcome = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                return failure(
                    "INVOCATION_CANCELLED",
                    "command invocation was cancelled",
                );
            }
            () = &mut deadline => {
                cancellation.cancel();
                return failure(
                    "HANDLER_TIMEOUT",
                    "command handler exceeded its deadline",
                );
            }
            outcome = &mut handler => outcome,
        };
        match outcome {
            Err(_) => {
                cancellation.cancel();
                failure("HANDLER_PANIC", "command handler panicked")
            }
            Ok(Err(error)) => handler_failure(
                error,
                "HANDLER_ERROR",
                "command handler failed",
                self.inner.max_output_bytes,
            ),
            Ok(Ok(result)) => {
                if serialized_json_within_limit(&result, self.inner.max_output_bytes) {
                    Outcome::Ok { value: result }
                } else {
                    failure(
                        "OUTPUT_TOO_LARGE",
                        "command result exceeds the runtime limit",
                    )
                }
            }
        }
    }

    async fn evaluate_admission(
        &self,
        invocation: &Invocation,
        cancellation: &CancellationToken,
        timeout: Duration,
    ) -> Result<Duration, Outcome> {
        let Some(policy) = self.inner.admission_policy.as_ref() else {
            return Ok(timeout);
        };
        let started = Instant::now();
        let admission =
            std::panic::catch_unwind(AssertUnwindSafe(|| policy(invocation.clone())))
                .map_err(|_| failure("ADMISSION_PANIC", "command admission policy panicked"))?;
        let admission = AssertUnwindSafe(admission).catch_unwind();
        tokio::pin!(admission);
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);

        let outcome = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                return Err(failure(
                    "INVOCATION_CANCELLED",
                    "command invocation was cancelled during admission",
                ));
            }
            () = &mut deadline => {
                cancellation.cancel();
                return Err(failure(
                    "HANDLER_TIMEOUT",
                    "command admission exceeded its deadline",
                ));
            }
            outcome = &mut admission => outcome,
        };
        match outcome {
            Err(_) => Err(failure(
                "ADMISSION_PANIC",
                "command admission policy panicked",
            )),
            Ok(Err(error)) => Err(handler_failure(
                error,
                "ADMISSION_DENIED",
                "command denied by admission policy",
                self.inner.max_output_bytes,
            )),
            Ok(Ok(())) => {
                let remaining = timeout.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    cancellation.cancel();
                    Err(failure(
                        "HANDLER_TIMEOUT",
                        "command handler deadline already elapsed",
                    ))
                } else {
                    Ok(remaining)
                }
            }
        }
    }

    fn resolve_timeout(&self, invocation: &Invocation) -> Duration {
        let requested = invocation.timeout.unwrap_or(self.inner.default_timeout);
        if requested.is_zero() {
            self.inner.default_timeout
        } else {
            requested.min(self.inner.max_timeout)
        }
    }
}

fn handler_failure(
    error: HandlerError,
    fallback_code: &str,
    fallback_message: &str,
    max_output_bytes: usize,
) -> Outcome {
    let code = if error.code.is_empty() {
        fallback_code.to_owned()
    } else {
        error.code
    };
    let message = if error.message.is_empty() {
        fallback_message.to_owned()
    } else {
        error.message
    };
    let payload = serde_json::json!({"code": &code, "message": &message});
    if serialized_json_within_limit(&payload, max_output_bytes) {
        Outcome::Err { code, message }
    } else {
        failure(
            "OUTPUT_TOO_LARGE",
            "command error exceeds the runtime limit",
        )
    }
}

struct Evaluation {
    outcome: Outcome,
    tracking: Option<ActiveInvocation>,
}

impl Evaluation {
    fn tracked(outcome: Outcome, tracking: ActiveInvocation) -> Self {
        Self {
            outcome,
            tracking: Some(tracking),
        }
    }
}

struct ActiveInvocation {
    active: ActiveInvocations,
    id: u64,
    cancellation: CancellationToken,
    cancel_on_drop: bool,
}

impl ActiveInvocation {
    fn disarm(&mut self) {
        self.cancel_on_drop = false;
    }
}

impl Drop for ActiveInvocation {
    fn drop(&mut self) {
        if self.cancel_on_drop {
            self.cancellation.cancel();
        }
        self.active.untrack(self.id);
    }
}

#[derive(Clone, Default)]
struct ActiveInvocations {
    inner: Arc<Mutex<HashMap<u64, ActiveInvocationState>>>,
}

struct ActiveInvocationState {
    cancellation: CancellationToken,
}

impl ActiveInvocations {
    fn lock(&self) -> MutexGuard<'_, HashMap<u64, ActiveInvocationState>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn track(&self, id: u64, cancellation: &CancellationToken) -> Option<ActiveInvocation> {
        let mut active = self.lock();
        match active.entry(id) {
            Entry::Vacant(entry) => {
                entry.insert(ActiveInvocationState {
                    cancellation: cancellation.clone(),
                });
                Some(ActiveInvocation {
                    active: self.clone(),
                    id,
                    cancellation: cancellation.clone(),
                    cancel_on_drop: true,
                })
            }
            Entry::Occupied(_) => None,
        }
    }

    fn untrack(&self, id: u64) {
        self.lock().remove(&id);
    }

    fn cancel(&self, id: u64) {
        let cancellation = self.lock().get(&id).map(|state| state.cancellation.clone());
        if let Some(cancellation) = cancellation {
            cancellation.cancel();
        }
    }

    fn cancel_all(&self) {
        let active = std::mem::take(&mut *self.lock());
        for state in active.values() {
            state.cancellation.cancel();
        }
    }
}

fn failure(code: &str, message: &str) -> Outcome {
    Outcome::Err {
        code: code.to_owned(),
        message: message.to_owned(),
    }
}

fn nonzero_duration(value: Duration) -> Duration {
    value.max(Duration::from_millis(1))
}

struct LimitWriter {
    written: usize,
    maximum: usize,
}

impl Write for LimitWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next) = self.written.checked_add(bytes.len()) else {
            return Err(io::Error::other("serialized JSON exceeds byte limit"));
        };
        if next > self.maximum {
            return Err(io::Error::other("serialized JSON exceeds byte limit"));
        }
        self.written = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialized_json_within_limit(value: &Value, maximum: usize) -> bool {
    serde_json::to_writer(
        LimitWriter {
            written: 0,
            maximum,
        },
        value,
    )
    .is_ok()
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
