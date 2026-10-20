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
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::sync::{Barrier, Notify};

    fn invocation(id: u64, command: &str, params: Value) -> Invocation {
        Invocation {
            id,
            command: command.to_owned(),
            params,
            timeout: None,
        }
    }

    fn failure_code(outcome: &Outcome) -> Option<&str> {
        match outcome {
            Outcome::Err { code, .. } => Some(code),
            Outcome::Ok { .. } => None,
        }
    }

    fn assert_failure(outcome: &Outcome, code: &str) {
        assert_eq!(failure_code(outcome), Some(code), "outcome: {outcome:?}");
    }

    async fn wait_for_flag(flag: &AtomicBool) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !flag.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancellation observed by child task");
    }

    #[tokio::test]
    async fn routes_success_and_structured_handler_failure() {
        let runtime = CommandRuntime::builder()
            .command("example.ok", |context| async move {
                Ok(json!({"echo": context.invocation.params}))
            })
            .command("example.fail", |_context| async {
                Err(HandlerError::new("NOT_READY", "dependency unavailable"))
            })
            .command("example.empty", |_context| async {
                Err(HandlerError::new("", ""))
            })
            .build()
            .unwrap();

        assert_eq!(
            runtime
                .evaluate(invocation(1, "example.ok", json!({"value": 1})))
                .await,
            Outcome::Ok {
                value: json!({"echo": {"value": 1}})
            }
        );
        assert_eq!(
            runtime
                .evaluate(invocation(2, "example.fail", Value::Null))
                .await,
            Outcome::Err {
                code: "NOT_READY".to_owned(),
                message: "dependency unavailable".to_owned()
            }
        );
        assert_eq!(
            runtime
                .evaluate(invocation(3, "example.empty", Value::Null))
                .await,
            Outcome::Err {
                code: "HANDLER_ERROR".to_owned(),
                message: "command handler failed".to_owned()
            }
        );
        assert_failure(
            &runtime
                .evaluate(invocation(4, "example.missing", Value::Null))
                .await,
            "COMMAND_NOT_FOUND",
        );
    }

    #[tokio::test]
    async fn command_names_are_sorted_and_duplicates_rejected() {
        let runtime = CommandRuntime::builder()
            .command("z.last", |_context| async { Ok(Value::Null) })
            .command("a.first", |_context| async { Ok(Value::Null) })
            .command("m.middle", |_context| async { Ok(Value::Null) })
            .build()
            .unwrap();
        assert_eq!(
            runtime.command_names(),
            vec![
                "a.first".to_owned(),
                "m.middle".to_owned(),
                "z.last".to_owned()
            ]
        );

        let duplicate = CommandRuntime::builder()
            .command("example.status", |_context| async { Ok(Value::Null) })
            .command(" example.status ", |_context| async { Ok(Value::Null) })
            .build();
        assert!(matches!(
            duplicate,
            Err(RuntimeBuildError::DuplicateCommand(name)) if name == "example.status"
        ));
    }

    #[test]
    fn rejects_invalid_command_names_and_limits() {
        for command in [
            String::new(),
            "has space".to_owned(),
            "slash/name".to_owned(),
            "unicode-é".to_owned(),
            "x".repeat(MAX_COMMAND_NAME_BYTES + 1),
        ] {
            let result = CommandRuntime::builder()
                .command(command, |_context| async { Ok(Value::Null) })
                .build();
            assert!(matches!(result, Err(RuntimeBuildError::InvalidCommand(_))));
        }

        let zero_concurrency = CommandRuntime::builder().max_concurrency(0).build();
        assert!(matches!(
            zero_concurrency,
            Err(RuntimeBuildError::InvalidLimit("maxConcurrency"))
        ));
        let zero_input = CommandRuntime::builder().max_input_bytes(0).build();
        assert!(matches!(
            zero_input,
            Err(RuntimeBuildError::InvalidLimit("maxInputBytes"))
        ));
        let zero_output = CommandRuntime::builder().max_output_bytes(0).build();
        assert!(matches!(
            zero_output,
            Err(RuntimeBuildError::InvalidLimit("maxOutputBytes"))
        ));
    }

    #[tokio::test]
    async fn enforces_input_and_output_limits() {
        let runtime = CommandRuntime::builder()
            .max_input_bytes(8)
            .max_output_bytes(8)
            .command("example.echo", |context| async move {
                Ok(context.invocation.params)
            })
            .command("example.large", |_context| async { Ok(json!("1234567")) })
            .build()
            .unwrap();

        assert_failure(
            &runtime
                .evaluate(invocation(1, "example.echo", json!({"too": "large"})))
                .await,
            "INPUT_TOO_LARGE",
        );
        assert_failure(
            &runtime
                .evaluate(invocation(2, "example.large", Value::Null))
                .await,
            "OUTPUT_TOO_LARGE",
        );

        let error_runtime = CommandRuntime::builder()
            .max_output_bytes(64)
            .command("example.error", |_context| async {
                Err(HandlerError::new("DEPENDENCY_ERROR", "x".repeat(128)))
            })
            .build()
            .unwrap();
        assert_failure(
            &error_runtime
                .evaluate(invocation(3, "example.error", Value::Null))
                .await,
            "OUTPUT_TOO_LARGE",
        );
    }

    #[tokio::test]
    async fn timeout_cancels_handler_token_and_clamps_to_maximum() {
        let child_cancelled = Arc::new(AtomicBool::new(false));
        let observed = child_cancelled.clone();
        let runtime = CommandRuntime::builder()
            .default_timeout(Duration::from_millis(10))
            .max_timeout(Duration::from_millis(20))
            .command("example.wait", move |context| {
                let observed = observed.clone();
                async move {
                    let token = context.cancellation.clone();
                    tokio::spawn(async move {
                        token.cancelled().await;
                        observed.store(true, Ordering::SeqCst);
                    });
                    std::future::pending().await
                }
            })
            .build()
            .unwrap();
        let mut request = invocation(1, "example.wait", Value::Null);
        // A caller deadline above the runtime maximum is clamped down.
        request.timeout = Some(Duration::from_secs(60));

        assert_failure(
            &tokio::time::timeout(Duration::from_secs(2), runtime.evaluate(request))
                .await
                .expect("handler timed out"),
            "HANDLER_TIMEOUT",
        );
        tokio::task::yield_now().await;
        assert!(child_cancelled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn zero_requested_timeout_uses_the_default() {
        let runtime = CommandRuntime::builder()
            .default_timeout(Duration::from_millis(10))
            .max_timeout(Duration::from_secs(1))
            .command("example.wait", |_context| async {
                std::future::pending::<()>().await;
                Ok(Value::Null)
            })
            .build()
            .unwrap();
        let mut request = invocation(1, "example.wait", Value::Null);
        request.timeout = Some(Duration::ZERO);

        assert_failure(
            &tokio::time::timeout(Duration::from_secs(2), runtime.evaluate(request))
                .await
                .expect("default timeout applied"),
            "HANDLER_TIMEOUT",
        );
    }

    #[tokio::test]
    async fn ninth_concurrent_invocation_is_overloaded_without_queueing() {
        let barrier = Arc::new(Barrier::new(9));
        let runtime = CommandRuntime::builder()
            .max_concurrency(8)
            .command("example.block", {
                let barrier = barrier.clone();
                move |_context| {
                    let barrier = barrier.clone();
                    async move {
                        barrier.wait().await;
                        barrier.wait().await;
                        Ok(Value::Null)
                    }
                }
            })
            .build()
            .unwrap();

        let mut tasks = Vec::new();
        for id in 0..8 {
            let runtime = runtime.clone();
            tasks.push(tokio::spawn(async move {
                runtime
                    .evaluate(invocation(id, "example.block", Value::Null))
                    .await
            }));
        }
        barrier.wait().await;
        let ninth = runtime
            .evaluate(invocation(9, "example.block", Value::Null))
            .await;
        assert_failure(&ninth, "OVERLOADED");
        barrier.wait().await;
        for task in tasks {
            assert!(matches!(task.await.unwrap(), Outcome::Ok { .. }));
        }
    }

    #[tokio::test]
    async fn duplicate_active_invocation_is_rejected() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let handler_entered = entered.clone();
        let handler_release = release.clone();
        let runtime = CommandRuntime::builder()
            .max_concurrency(1)
            .command("example.block", move |_context| {
                let entered = handler_entered.clone();
                let release = handler_release.clone();
                async move {
                    entered.notify_one();
                    release.notified().await;
                    Ok(Value::Null)
                }
            })
            .build()
            .unwrap();

        let first_runtime = runtime.clone();
        let first = tokio::spawn(async move {
            first_runtime
                .evaluate(invocation(7, "example.block", Value::Null))
                .await
        });
        entered.notified().await;
        assert_failure(
            &runtime
                .evaluate(invocation(7, "example.block", Value::Null))
                .await,
            "DUPLICATE_INVOCATION",
        );
        release.notify_one();
        assert!(matches!(first.await.unwrap(), Outcome::Ok { .. }));
    }

    #[tokio::test]
    async fn cancel_only_cancels_the_target_invocation() {
        let entered = Arc::new(AtomicUsize::new(0));
        let cancelled_first = Arc::new(AtomicBool::new(false));
        let cancelled_second = Arc::new(AtomicBool::new(false));
        let runtime = CommandRuntime::builder()
            .max_concurrency(2)
            .command("example.wait", {
                let entered = entered.clone();
                let cancelled_first = cancelled_first.clone();
                let cancelled_second = cancelled_second.clone();
                move |context| {
                    let entered = entered.clone();
                    let cancelled_first = cancelled_first.clone();
                    let cancelled_second = cancelled_second.clone();
                    async move {
                        let id = context.invocation.id;
                        entered.fetch_add(1, Ordering::SeqCst);
                        let token = context.cancellation.clone();
                        let observed = if id == 1 {
                            cancelled_first
                        } else {
                            cancelled_second
                        };
                        tokio::spawn(async move {
                            token.cancelled().await;
                            observed.store(true, Ordering::SeqCst);
                        });
                        std::future::pending::<()>().await;
                        Ok(Value::Null)
                    }
                }
            })
            .build()
            .unwrap();

        let first_runtime = runtime.clone();
        let first = tokio::spawn(async move {
            first_runtime
                .evaluate(invocation(1, "example.wait", Value::Null))
                .await
        });
        let second_runtime = runtime.clone();
        let second = tokio::spawn(async move {
            second_runtime
                .evaluate(invocation(2, "example.wait", Value::Null))
                .await
        });
        while entered.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }

        runtime.cancel(1);
        assert_failure(
            &tokio::time::timeout(Duration::from_secs(2), first)
                .await
                .expect("first cancelled")
                .unwrap(),
            "INVOCATION_CANCELLED",
        );
        wait_for_flag(&cancelled_first).await;
        assert!(cancelled_first.load(Ordering::SeqCst));
        assert!(!cancelled_second.load(Ordering::SeqCst));

        runtime.cancel(2);
        assert_failure(
            &tokio::time::timeout(Duration::from_secs(2), second)
                .await
                .expect("second cancelled")
                .unwrap(),
            "INVOCATION_CANCELLED",
        );
        wait_for_flag(&cancelled_second).await;
        assert!(cancelled_second.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn cancel_all_cancels_every_active_invocation() {
        let entered = Arc::new(AtomicUsize::new(0));
        let runtime = CommandRuntime::builder()
            .max_concurrency(2)
            .command("example.wait", {
                let entered = entered.clone();
                move |context| {
                    let entered = entered.clone();
                    async move {
                        entered.fetch_add(1, Ordering::SeqCst);
                        context.cancellation.cancelled().await;
                        Ok(Value::Null)
                    }
                }
            })
            .build()
            .unwrap();

        let mut tasks = Vec::new();
        for id in 0..2 {
            let runtime = runtime.clone();
            tasks.push(tokio::spawn(async move {
                runtime
                    .evaluate(invocation(id, "example.wait", Value::Null))
                    .await
            }));
        }
        while entered.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
        runtime.cancel_all();
        for task in tasks {
            assert_failure(
                &tokio::time::timeout(Duration::from_secs(2), task)
                    .await
                    .expect("cancelled")
                    .unwrap(),
                "INVOCATION_CANCELLED",
            );
        }
    }

    #[tokio::test]
    async fn cancel_during_admission_prevents_handler_entry() {
        let admission_entered = Arc::new(Notify::new());
        let handler_ran = Arc::new(AtomicBool::new(false));
        let entered = admission_entered.clone();
        let handler_state = handler_ran.clone();
        let runtime = CommandRuntime::builder()
            .admission_policy(move |_invocation| {
                let entered = entered.clone();
                async move {
                    entered.notify_one();
                    std::future::pending().await
                }
            })
            .command("example.status", move |_context| {
                handler_state.store(true, Ordering::SeqCst);
                async { Ok(Value::Null) }
            })
            .build()
            .unwrap();

        let task_runtime = runtime.clone();
        let task = tokio::spawn(async move {
            task_runtime
                .evaluate(invocation(1, "example.status", Value::Null))
                .await
        });
        admission_entered.notified().await;
        runtime.cancel(1);
        assert_failure(
            &tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .expect("admission cancelled")
                .unwrap(),
            "INVOCATION_CANCELLED",
        );
        assert!(!handler_ran.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn admission_denial_and_panic_fail_closed() {
        let denied_ran = Arc::new(AtomicBool::new(false));
        let denied_state = denied_ran.clone();
        let denied = CommandRuntime::builder()
            .admission_policy(|_invocation| async {
                Err(HandlerError::new("LOCAL_POLICY_DENIED", "not allowed"))
            })
            .command("example.status", move |_context| {
                denied_state.store(true, Ordering::SeqCst);
                async { Ok(Value::Null) }
            })
            .build()
            .unwrap();
        assert_eq!(
            denied
                .evaluate(invocation(1, "example.status", Value::Null))
                .await,
            Outcome::Err {
                code: "LOCAL_POLICY_DENIED".to_owned(),
                message: "not allowed".to_owned()
            }
        );
        assert!(!denied_ran.load(Ordering::SeqCst));

        let panic_ran = Arc::new(AtomicBool::new(false));
        let panic_state = panic_ran.clone();
        let panicking = CommandRuntime::builder()
            .admission_policy(|_invocation| async {
                panic!("policy unavailable");
            })
            .command("example.status", move |_context| {
                panic_state.store(true, Ordering::SeqCst);
                async { Ok(Value::Null) }
            })
            .build()
            .unwrap();
        assert_failure(
            &panicking
                .evaluate(invocation(2, "example.status", Value::Null))
                .await,
            "ADMISSION_PANIC",
        );
        assert!(!panic_ran.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn converts_handler_panics_to_structured_failure() {
        let runtime = CommandRuntime::builder()
            .command("example.panic", |_context| async {
                panic!("handler bug");
                #[allow(unreachable_code)]
                Ok(Value::Null)
            })
            .build()
            .unwrap();
        assert_failure(
            &runtime
                .evaluate(invocation(1, "example.panic", Value::Null))
                .await,
            "HANDLER_PANIC",
        );

        let synchronous = CommandRuntime::builder()
            .command("example.sync-panic", |_context| {
                panic!("handler construction bug");
                #[allow(unreachable_code)]
                async {
                    Ok(Value::Null)
                }
            })
            .build()
            .unwrap();
        assert_failure(
            &synchronous
                .evaluate(invocation(2, "example.sync-panic", Value::Null))
                .await,
            "HANDLER_PANIC",
        );
    }

    #[test]
    fn cancellation_token_observes_cancel() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
        token.cancel();
        assert!(token.is_cancelled());
    }
}
