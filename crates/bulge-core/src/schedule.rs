//! Tool-call scheduling within one step.
//! MARK: M16 — transcribed by dsh; see marks/M16-tool-schedule.md.

use std::future::Future;
use std::ops::Range;

use futures::future::LocalBoxFuture;
use futures::stream::{FuturesUnordered, StreamExt};
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

/// One tool call requested by the model in this step, in model order.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedCall {
    pub call_id: String,
    pub name: String,
    /// Raw JSON text as produced by the model.
    pub raw_arguments: String,
    /// May run concurrently with adjacent concurrency-safe calls.
    pub concurrency_safe: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CallOutcome {
    Ok(Value),
    /// The tool ran (or tried to) and failed; shown to the model as an error.
    Err { code: String, message: String },
    /// Arguments were not a JSON object; the tool was not run.
    InvalidArguments(String),
    /// Not started because the step was cancelled.
    Skipped,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CallResult {
    pub call_id: String,
    pub outcome: CallOutcome,
}

/// Per-call scheduling state: the parsed arguments (or the reason they are
/// unusable) and the settled outcome, if any.
struct CallState {
    args: Option<Result<Map<String, Value>, String>>,
    outcome: Option<CallOutcome>,
}

/// Parse model arguments. An empty string means "no arguments" (`{}`); anything
/// else must decode to a JSON object.
fn parse_arguments(call: &PlannedCall) -> Result<Map<String, Value>, String> {
    if call.raw_arguments.is_empty() {
        return Ok(Map::new());
    }
    match serde_json::from_str::<Value>(&call.raw_arguments) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(format!("arguments for tool `{}` must be a JSON object", call.name)),
        Err(error) => {
            Err(format!("arguments for tool `{}` are not valid JSON: {error}", call.name))
        }
    }
}

/// Run `calls` and return exactly one result per call, in the original order.
///
/// Grouping: a maximal run of consecutive concurrency-safe calls executes
/// concurrently (at most `max_parallel` in flight); any other call is an
/// exclusive barrier that runs alone. Groups run in order. Arguments are
/// parsed first; a call with invalid arguments gets `InvalidArguments` and is
/// never executed. Once `cancel` fires, calls not yet started get `Skipped`;
/// calls already running are awaited (the executor sees the token).
///
/// `on_start` is invoked right before each call executes (the caller logs the
/// write-ahead `ToolClaimed` there); it is never invoked for invalid or
/// skipped calls.
pub async fn run_tool_calls<E, Fut, S>(
    calls: Vec<PlannedCall>,
    max_parallel: usize,
    cancel: &CancellationToken,
    mut on_start: S,
    execute: E,
) -> Vec<CallResult>
where
    E: Fn(PlannedCall, serde_json::Map<String, Value>, CancellationToken) -> Fut,
    Fut: Future<Output = CallOutcome>,
    S: FnMut(&PlannedCall, &serde_json::Map<String, Value>),
{
    // Zero means "no concurrency": run one call at a time.
    let max_parallel = max_parallel.max(1);

    let mut states: Vec<CallState> = calls
        .iter()
        .map(|call| CallState { args: Some(parse_arguments(call)), outcome: None })
        .collect();

    let mut index = 0;
    while index < calls.len() {
        if calls[index].concurrency_safe {
            // A maximal run of adjacent concurrency-safe calls is one pool.
            let start = index;
            while index < calls.len() && calls[index].concurrency_safe {
                index += 1;
            }
            run_parallel_group(
                &calls,
                &mut states,
                start..index,
                max_parallel,
                cancel,
                &mut on_start,
                &execute,
            )
            .await;
        } else {
            run_exclusive_call(&calls, &mut states, index, cancel, &mut on_start, &execute).await;
            index += 1;
        }
    }

    calls
        .into_iter()
        .zip(states)
        .map(|(call, state)| CallResult {
            call_id: call.call_id,
            // Every index is scheduled exactly once, so an outcome is always
            // present; `Skipped` is only a defensive fallback.
            outcome: state.outcome.unwrap_or(CallOutcome::Skipped),
        })
        .collect()
}

/// Run one exclusive (non concurrency-safe) call. It is a barrier: the caller
/// waits for it before scheduling anything else.
async fn run_exclusive_call<E, Fut, S>(
    calls: &[PlannedCall],
    states: &mut [CallState],
    index: usize,
    cancel: &CancellationToken,
    on_start: &mut S,
    execute: &E,
) where
    E: Fn(PlannedCall, Map<String, Value>, CancellationToken) -> Fut,
    Fut: Future<Output = CallOutcome>,
    S: FnMut(&PlannedCall, &Map<String, Value>),
{
    let Some(parsed) = states[index].args.take() else {
        states[index].outcome = Some(CallOutcome::Skipped);
        return;
    };
    match parsed {
        Err(message) => states[index].outcome = Some(CallOutcome::InvalidArguments(message)),
        Ok(args) => {
            if cancel.is_cancelled() {
                states[index].outcome = Some(CallOutcome::Skipped);
                return;
            }
            on_start(&calls[index], &args);
            let outcome = execute(calls[index].clone(), args, cancel.clone()).await;
            states[index].outcome = Some(outcome);
        }
    }
}

/// Run a maximal run of concurrency-safe calls as a bounded rolling pool. The
/// pool is polled in the caller's task; no runtime spawn is used.
async fn run_parallel_group<E, Fut, S>(
    calls: &[PlannedCall],
    states: &mut [CallState],
    range: Range<usize>,
    max_parallel: usize,
    cancel: &CancellationToken,
    on_start: &mut S,
    execute: &E,
) where
    E: Fn(PlannedCall, Map<String, Value>, CancellationToken) -> Fut,
    Fut: Future<Output = CallOutcome>,
    S: FnMut(&PlannedCall, &Map<String, Value>),
{
    let mut next = range.start;
    let mut running = 0usize;
    let mut in_flight: FuturesUnordered<LocalBoxFuture<'_, (usize, CallOutcome)>> =
        FuturesUnordered::new();

    loop {
        // Start as many calls as the pool allows. Cancellation is checked right
        // before each start; parsed arguments are settled without using a slot.
        while running < max_parallel && next < range.end {
            let index = next;
            next += 1;

            let Some(parsed) = states[index].args.take() else {
                states[index].outcome = Some(CallOutcome::Skipped);
                continue;
            };
            let args = match parsed {
                Ok(args) => args,
                Err(message) => {
                    states[index].outcome = Some(CallOutcome::InvalidArguments(message));
                    continue;
                }
            };
            if cancel.is_cancelled() {
                states[index].outcome = Some(CallOutcome::Skipped);
                continue;
            }

            on_start(&calls[index], &args);
            let call = calls[index].clone();
            let token = cancel.clone();
            in_flight.push(Box::pin(async move {
                let outcome = execute(call, args, token).await;
                (index, outcome)
            }));
            running += 1;
        }

        if running == 0 {
            break;
        }
        if let Some((index, outcome)) = in_flight.next().await {
            states[index].outcome = Some(outcome);
            running -= 1;
        } else {
            break;
        }
    }
}

pub const DEFAULT_MAX_PARALLEL: usize = 10;

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;

    fn call(id: &str, args: &str, concurrency_safe: bool) -> PlannedCall {
        PlannedCall {
            call_id: id.to_owned(),
            name: format!("tool_{id}"),
            raw_arguments: args.to_owned(),
            concurrency_safe,
        }
    }

    fn ok_id(id: &str) -> CallOutcome {
        CallOutcome::Ok(Value::String(id.to_owned()))
    }

    #[tokio::test]
    async fn results_keep_input_order_when_later_calls_finish_first() {
        let calls = vec![call("slow", "{}", true), call("fast", "{}", true)];
        let cancel = CancellationToken::new();
        let completed = Arc::new(Mutex::new(Vec::new()));

        let execute = {
            let completed = Arc::clone(&completed);
            move |call: PlannedCall, _args, _token| {
                let completed = Arc::clone(&completed);
                async move {
                    let delay =
                        if call.call_id == "slow" { Duration::from_millis(40) } else { Duration::from_millis(1) };
                    tokio::time::sleep(delay).await;
                    completed.lock().unwrap().push(call.call_id.clone());
                    ok_id(&call.call_id)
                }
            }
        };

        let results = run_tool_calls(calls, 10, &cancel, |_, _| {}, execute).await;

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].call_id, "slow");
        assert_eq!(results[0].outcome, ok_id("slow"));
        assert_eq!(results[1].call_id, "fast");
        assert_eq!(results[1].outcome, ok_id("fast"));
        assert_eq!(completed.lock().unwrap().as_slice(), ["fast".to_owned(), "slow".to_owned()]);
    }

    #[tokio::test]
    async fn concurrency_safe_calls_run_at_the_same_time() {
        let calls: Vec<_> = (0..3).map(|i| call(&format!("c{i}"), "{}", true)).collect();
        let cancel = CancellationToken::new();
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let execute = {
            let barrier = Arc::clone(&barrier);
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            move |_call: PlannedCall, _args, _token| {
                let barrier = Arc::clone(&barrier);
                let active = Arc::clone(&active);
                let peak = Arc::clone(&peak);
                async move {
                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    // All three must be in flight or this never resolves.
                    barrier.wait().await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    CallOutcome::Ok(Value::Null)
                }
            }
        };

        let results = tokio::time::timeout(
            Duration::from_secs(5),
            run_tool_calls(calls, DEFAULT_MAX_PARALLEL, &cancel, |_, _| {}, execute),
        )
        .await
        .expect("concurrency-safe calls must be started together");

        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|result| matches!(result.outcome, CallOutcome::Ok(_))));
        assert_eq!(peak.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn max_parallel_one_runs_safe_calls_one_at_a_time() {
        let calls: Vec<_> = (0..4).map(|i| call(&format!("c{i}"), "{}", true)).collect();
        let cancel = CancellationToken::new();
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let execute = {
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            move |_call: PlannedCall, _args, _token| {
                let active = Arc::clone(&active);
                let peak = Arc::clone(&peak);
                async move {
                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    CallOutcome::Ok(Value::Null)
                }
            }
        };

        let results = run_tool_calls(calls, 0, &cancel, |_, _| {}, execute).await;

        assert_eq!(results.len(), 4);
        assert!(results.iter().all(|result| matches!(result.outcome, CallOutcome::Ok(_))));
        assert_eq!(peak.load(Ordering::SeqCst), 1, "max_parallel=0 must behave like 1");
    }

    #[tokio::test]
    async fn concurrency_unsafe_call_is_a_barrier() {
        let calls = vec![
            call("a", "{}", true),
            call("b", "{}", true),
            call("x", "{}", false),
            call("c", "{}", true),
            call("d", "{}", true),
        ];
        let cancel = CancellationToken::new();
        let active = Arc::new(AtomicUsize::new(0));
        let peak_parallel = Arc::new(AtomicUsize::new(0));
        let unsafe_running = Arc::new(AtomicBool::new(false));

        let execute = {
            let active = Arc::clone(&active);
            let peak_parallel = Arc::clone(&peak_parallel);
            let unsafe_running = Arc::clone(&unsafe_running);
            move |call: PlannedCall, _args, _token| {
                let active = Arc::clone(&active);
                let peak_parallel = Arc::clone(&peak_parallel);
                let unsafe_running = Arc::clone(&unsafe_running);
                async move {
                    if call.call_id == "x" {
                        assert_eq!(active.load(Ordering::SeqCst), 0, "barrier must start alone");
                        unsafe_running.store(true, Ordering::SeqCst);
                        let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                        assert_eq!(now, 1, "barrier must be the only call running");
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        active.fetch_sub(1, Ordering::SeqCst);
                        unsafe_running.store(false, Ordering::SeqCst);
                    } else {
                        assert!(!unsafe_running.load(Ordering::SeqCst), "safe call overlapped the barrier");
                        let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                        peak_parallel.fetch_max(now, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        active.fetch_sub(1, Ordering::SeqCst);
                    }
                    ok_id(&call.call_id)
                }
            }
        };

        let results = run_tool_calls(calls, DEFAULT_MAX_PARALLEL, &cancel, |_, _| {}, execute).await;

        let ids: Vec<_> = results.iter().map(|result| result.call_id.as_str()).collect();
        assert_eq!(ids, ["a", "b", "x", "c", "d"]);
        assert!(results.iter().all(|result| matches!(result.outcome, CallOutcome::Ok(_))));
        assert_eq!(peak_parallel.load(Ordering::SeqCst), 2, "the safe group should overlap");
    }

    #[tokio::test]
    async fn invalid_arguments_are_not_executed_and_never_start() {
        let calls = vec![
            call("bad_json", "{not json", true),
            call("array", "[]", true),
            call("empty", "", true),
        ];
        let cancel = CancellationToken::new();
        let executed = Arc::new(Mutex::new(Vec::new()));
        let started = Arc::new(Mutex::new(Vec::new()));

        let on_start = {
            let started = Arc::clone(&started);
            move |call: &PlannedCall, args: &Map<String, Value>| {
                assert!(args.is_empty(), "empty arguments must parse as an empty object");
                started.lock().unwrap().push(call.call_id.clone());
            }
        };
        let execute = {
            let executed = Arc::clone(&executed);
            move |call: PlannedCall, _args, _token| {
                let executed = Arc::clone(&executed);
                async move {
                    executed.lock().unwrap().push(call.call_id.clone());
                    ok_id(&call.call_id)
                }
            }
        };

        let results = run_tool_calls(calls, DEFAULT_MAX_PARALLEL, &cancel, on_start, execute).await;

        assert_eq!(results.len(), 3);
        assert!(matches!(results[0].outcome, CallOutcome::InvalidArguments(_)));
        assert!(matches!(results[1].outcome, CallOutcome::InvalidArguments(_)));
        assert_eq!(results[2].outcome, ok_id("empty"));
        assert_eq!(executed.lock().unwrap().as_slice(), ["empty".to_owned()]);
        assert_eq!(started.lock().unwrap().as_slice(), ["empty".to_owned()]);
    }

    #[tokio::test]
    async fn cancellation_skips_unstarted_calls_and_keeps_started_results() {
        let calls = vec![call("first", "{}", true), call("second", "{}", true), call("third", "{}", true)];
        let cancel = CancellationToken::new();
        let started = Arc::new(Mutex::new(Vec::new()));

        let on_start = {
            let started = Arc::clone(&started);
            move |call: &PlannedCall, _args: &Map<String, Value>| {
                started.lock().unwrap().push(call.call_id.clone());
            }
        };
        let execute = {
            let cancel = cancel.clone();
            move |call: PlannedCall, _args, _token| {
                let cancel = cancel.clone();
                async move {
                    if call.call_id == "first" {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        cancel.cancel();
                    } else {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    ok_id(&call.call_id)
                }
            }
        };

        let results = run_tool_calls(calls, 2, &cancel, on_start, execute).await;

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].outcome, ok_id("first"));
        assert_eq!(results[1].outcome, ok_id("second"));
        assert_eq!(results[2].outcome, CallOutcome::Skipped);
        assert_eq!(
            started.lock().unwrap().as_slice(),
            ["first".to_owned(), "second".to_owned()],
            "skipped calls must not call on_start"
        );
    }

    #[tokio::test]
    async fn cancellation_before_start_skips_every_call() {
        let calls = vec![call("safe", "{}", true), call("unsafe", "{}", false)];
        let cancel = CancellationToken::new();
        cancel.cancel();
        let calls_started = Arc::new(AtomicUsize::new(0));

        let on_start = {
            let calls_started = Arc::clone(&calls_started);
            move |_call: &PlannedCall, _args: &Map<String, Value>| {
                calls_started.fetch_add(1, Ordering::SeqCst);
            }
        };

        let results = run_tool_calls(calls, DEFAULT_MAX_PARALLEL, &cancel, on_start, |_call, _args, _token| async {
            CallOutcome::Ok(Value::Null)
        })
        .await;

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|result| result.outcome == CallOutcome::Skipped));
        assert_eq!(calls_started.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn on_start_runs_once_per_executed_call_before_its_execution() {
        let calls = vec![
            call("a", r#"{"x":1}"#, true),
            call("invalid", "3", true),
            call("b", "", true),
        ];
        let cancel = CancellationToken::new();
        let log = Arc::new(Mutex::new(Vec::new()));

        let on_start = {
            let log = Arc::clone(&log);
            move |call: &PlannedCall, args: &Map<String, Value>| {
                if call.call_id == "a" {
                    assert_eq!(args.get("x"), Some(&Value::from(1)));
                }
                log.lock().unwrap().push(format!("start:{}", call.call_id));
            }
        };
        let execute = {
            let log = Arc::clone(&log);
            move |call: PlannedCall, _args, _token| {
                let log = Arc::clone(&log);
                async move {
                    log.lock().unwrap().push(format!("exec:{}", call.call_id));
                    ok_id(&call.call_id)
                }
            }
        };

        let results = run_tool_calls(calls, DEFAULT_MAX_PARALLEL, &cancel, on_start, execute).await;

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].outcome, ok_id("a"));
        assert!(matches!(results[1].outcome, CallOutcome::InvalidArguments(_)));
        assert_eq!(results[2].outcome, ok_id("b"));

        let log = log.lock().unwrap();
        assert_eq!(log.iter().filter(|entry| entry.starts_with("start:")).count(), 2);
        assert_eq!(log.iter().filter(|entry| entry.starts_with("exec:")).count(), 2);
        for id in ["a", "b"] {
            let start = log.iter().position(|entry| entry == &format!("start:{id}")).unwrap();
            let exec = log.iter().position(|entry| entry == &format!("exec:{id}")).unwrap();
            assert!(start < exec, "on_start must precede execution for {id}");
        }
    }
}
