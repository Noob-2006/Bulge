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
