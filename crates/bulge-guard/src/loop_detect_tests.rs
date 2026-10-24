use serde_json::json;

use super::*;

fn observe(
    detector: &mut LoopDetector,
    tool: &str,
    arguments: Value,
    ok: bool,
    result: Value,
) {
    detector.observe(Observation {
        tool: tool.to_owned(),
        arguments,
        ok,
        result,
    });
}

fn error_observation(detector: &mut LoopDetector, tool: &str, arguments: Value, error: Value) {
    observe(detector, tool, arguments, false, error);
}

#[test]
fn identical_errors_stop_at_three() {
    let mut detector = LoopDetector::new();
    let arguments = json!({"command": "cargo build"});

    for _ in 0..IDENTICAL_ERROR_STOP {
        error_observation(
            &mut detector,
            "shell",
            arguments.clone(),
            json!({"error": "compilation failed"}),
        );
    }

    let verdict = detector
        .check("shell", &arguments, false)
        .expect("identical errors should be detected");
    assert_eq!(verdict.level, Level::Critical);
    assert_eq!(verdict.detector, Detector::GenericRepeat);
    assert_eq!(verdict.count, IDENTICAL_ERROR_STOP);
    assert!(verdict.message.contains("shell"));
    assert!(verdict.message.contains("same error"));
}

#[test]
fn no_progress_poll_warns_at_ten_and_blocks_at_twenty() {
    let arguments = json!({"path": "state.json"});

    let mut warning_detector = LoopDetector::new();
    for _ in 0..WARNING_THRESHOLD {
        observe(
            &mut warning_detector,
            "read",
            arguments.clone(),
            true,
            json!({"changed": false}),
        );
    }
    let warning = warning_detector
        .check("read", &arguments, false)
        .expect("ten no-progress calls should warn");
    assert_eq!(warning.level, Level::Warning);
    assert_eq!(warning.detector, Detector::NoProgressPoll);
    assert_eq!(warning.count, WARNING_THRESHOLD);

    let mut critical_detector = LoopDetector::new();
    for _ in 0..CRITICAL_THRESHOLD {
        observe(
            &mut critical_detector,
            "read",
            arguments.clone(),
            true,
            json!({"changed": false}),
        );
    }
    let critical = critical_detector
        .check("read", &arguments, false)
        .expect("twenty no-progress calls should be critical");
    assert_eq!(critical.level, Level::Critical);
    assert_eq!(critical.detector, Detector::NoProgressPoll);
    assert_eq!(critical.count, CRITICAL_THRESHOLD);
}

#[test]
fn global_breaker_fires_at_the_history_limit() {
    let mut detector = LoopDetector::new();
    let arguments = json!({"path": "state.json"});

    for _ in 0..(HISTORY_SIZE + 5) {
        error_observation(
            &mut detector,
            "read",
            arguments.clone(),
            json!({"error": "permission denied"}),
        );
    }

    let verdict = detector
        .check("read", &arguments, false)
        .expect("the breaker should fire");
    assert_eq!(verdict.level, Level::Critical);
    assert_eq!(verdict.detector, Detector::GlobalCircuitBreaker);
    assert_eq!(verdict.count, HISTORY_SIZE);
}

#[test]
fn unknown_tool_repeats_are_critical() {
    let mut detector = LoopDetector::new();
    let arguments = json!({});

    for _ in 0..UNKNOWN_TOOL_THRESHOLD {
        error_observation(
            &mut detector,
            "missing_tool",
            arguments.clone(),
            json!({"error": "unknown tool: missing_tool"}),
        );
    }

    let verdict = detector
        .check("missing_tool", &arguments, true)
        .expect("repeated unknown tools should be detected");
    assert_eq!(verdict.level, Level::Critical);
    assert_eq!(verdict.detector, Detector::UnknownToolRepeat);
    assert_eq!(verdict.count, UNKNOWN_TOOL_THRESHOLD);
    assert!(verdict.message.contains("missing_tool"));
}

#[test]
fn changing_arguments_with_a_stable_outcome_is_churn() {
    let mut detector = LoopDetector::new();

    for index in 0..WARNING_THRESHOLD {
        error_observation(
            &mut detector,
            "search",
            json!({"query": format!("attempt-{index}")}),
            json!({"error": "no results"}),
        );
    }

    let verdict = detector
        .check("search", &json!({"query": "another attempt"}), false)
        .expect("argument churn should warn");
    assert_eq!(verdict.level, Level::Warning);
    assert_eq!(verdict.detector, Detector::ArgumentChurn);
    assert_eq!(verdict.count, WARNING_THRESHOLD);
    assert!(verdict.message.contains("argument patterns"));
}

#[test]
fn alternating_calls_are_ping_pong() {
    let mut detector = LoopDetector::new();
    let first = json!({"url": "https://example.test/a"});
    let second = json!({"url": "https://example.test/b"});

    for index in 0..WARNING_THRESHOLD {
        let arguments = if index % 2 == 0 {
            first.clone()
        } else {
            second.clone()
        };
        error_observation(
            &mut detector,
            "fetch",
            arguments,
            json!({"error": "timed out"}),
        );
    }

    let verdict = detector
        .check("fetch", &first, false)
        .expect("alternating calls should warn");
    assert_eq!(verdict.level, Level::Warning);
    assert_eq!(verdict.detector, Detector::PingPong);
    assert_eq!(verdict.count, WARNING_THRESHOLD);
    assert!(verdict.message.contains("alternating"));
}

#[test]
fn alternating_calls_with_stable_outcomes_become_critical() {
    let mut detector = LoopDetector::new();
    let first = json!({"url": "https://example.test/a"});
    let second = json!({"url": "https://example.test/b"});

    for index in 0..CRITICAL_THRESHOLD {
        let arguments = if index % 2 == 0 {
            first.clone()
        } else {
            second.clone()
        };
        error_observation(
            &mut detector,
            "fetch",
            arguments,
            json!({"error": "timed out"}),
        );
    }

    let verdict = detector
        .check("fetch", &first, false)
        .expect("long alternating calls should be critical");
    assert_eq!(verdict.level, Level::Critical);
    assert_eq!(verdict.detector, Detector::PingPong);
    assert_eq!(verdict.count, CRITICAL_THRESHOLD);
    assert!(verdict.message.contains("no progress"));
}

#[test]
fn volatile_result_fields_do_not_hide_a_loop() {
    let mut detector = LoopDetector::new();
    let arguments = json!({"command": "flaky"});

    for index in 0..WARNING_THRESHOLD {
        error_observation(
            &mut detector,
            "shell",
            arguments.clone(),
            json!({
                "error": "failed",
                "timestamp": 1_700_000_000 + index,
                "pid": 1000 + index,
                "durationMs": index,
                "id": format!("req-{index}-abcdef"),
            }),
        );
    }

    let verdict = detector
        .check("shell", &arguments, false)
        .expect("volatile fields should be stripped");
    assert_eq!(verdict.detector, Detector::NoProgressPoll);
    assert_eq!(verdict.count, WARNING_THRESHOLD);
}

#[test]
fn progress_resets_the_streak() {
    let mut detector = LoopDetector::new();
    let arguments = json!({"path": "state.json"});

    for _ in 0..WARNING_THRESHOLD {
        error_observation(
            &mut detector,
            "read",
            arguments.clone(),
            json!({"error": "not ready"}),
        );
    }
    observe(
        &mut detector,
        "read",
        arguments.clone(),
        true,
        json!({"value": "ready"}),
    );

    assert!(
        detector.check("read", &arguments, false).is_none(),
        "a changed outcome must reset the no-progress streak"
    );
}

#[test]
fn argument_object_key_order_is_ignored() {
    let mut detector = LoopDetector::new();
    let observed = json!({"alpha": 1, "beta": 2});

    for _ in 0..WARNING_THRESHOLD {
        error_observation(
            &mut detector,
            "read",
            observed.clone(),
            json!({"error": "not ready"}),
        );
    }

    let reordered = json!({"beta": 2, "alpha": 1});
    let verdict = detector
        .check("read", &reordered, false)
        .expect("key order must not create a new signature");
    assert_eq!(verdict.detector, Detector::NoProgressPoll);
    assert_eq!(verdict.count, WARNING_THRESHOLD);
}

#[test]
fn argument_array_order_is_preserved() {
    let mut detector = LoopDetector::new();
    let observed = json!({"paths": ["a", "b"]});

    for _ in 0..WARNING_THRESHOLD {
        error_observation(
            &mut detector,
            "read",
            observed.clone(),
            json!({"error": "not ready"}),
        );
    }

    let reordered = json!({"paths": ["b", "a"]});
    assert!(
        detector.check("read", &reordered, false).is_none(),
        "array order is part of the signature"
    );
}

#[test]
fn progress_by_same_output_is_not_flagged_until_it_repeats() {
    let mut detector = LoopDetector::new();
    let arguments = json!({"path": "state.json"});

    observe(
        &mut detector,
        "read",
        arguments.clone(),
        true,
        json!({"value": 1}),
    );
    assert!(detector.check("read", &arguments, false).is_none());
}
