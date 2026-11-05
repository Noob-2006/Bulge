//! Plugin stream hooks end to end: a real plugin process observes every streamed delta / tool
//! event out of band, and rewrites them in band (Hermes `agent/plugin_stream_hooks.py`).

use ark_core::{Cancel, Message, ModelCaps, ModelRequest, ModelResponse, Provider, ProviderError, StopReason, StreamEvent, Usage};
use ark_plugin::*;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn fixture() -> Option<PathBuf> {
    if Command::new("python3").arg("-c").arg("1").output().is_err() {
        eprintln!("python3 missing: skipping stream hook tests");
        return None;
    }
    Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/plugin/stream.py").canonicalize().unwrap())
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ark-stream-{tag}-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A provider that streams fixed events and answers with `final_text`.
struct Fake {
    deltas: Vec<StreamEvent>,
}

impl Provider for Fake {
    fn id(&self) -> &str {
        "fake"
    }
    fn caps(&self, _: &str) -> ModelCaps {
        ModelCaps::default()
    }
    fn complete(&self, req: &ModelRequest, on_event: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, ProviderError> {
        for e in &self.deltas {
            on_event(e.clone());
        }
        Ok(ModelResponse { message: Message::assistant("answer"), stop: StopReason::EndTurn, usage: Usage::default(), model: req.model.clone() })
    }
}

fn req() -> ModelRequest {
    ModelRequest { model: "m1".into(), system: vec![], messages: vec![Message::user("hi")], tools: vec![], max_tokens: 32, temperature: None, cache_after_message: None, reasoning: None, options: Default::default() }
}

fn lines(log: &Path) -> Vec<Value> {
    std::fs::read_to_string(log).unwrap_or_default().lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}

/// Wait until `pred` holds over the log, or 3 s pass.
fn wait_for(log: &Path, pred: impl Fn(&[Value]) -> bool) -> Vec<Value> {
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        let l = lines(log);
        if pred(&l) || Instant::now() > until {
            return l;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn tap(log: &Path, slow: f64, cfg: StreamConfig) -> Option<Arc<StreamTap>> {
    let f = fixture()?;
    let cfg = McpServerConfig { command: Some("python3".into()), args: vec!["-I".into(), f.to_string_lossy().into_owned(), "--log".into(), log.to_string_lossy().into_owned(), "--slow".into(), slow.to_string()], timeout_secs: Some(10), stream: cfg, ..Default::default() };
    let host = Arc::new(PluginHost::start("streamtap", &cfg, no_secrets()).unwrap());
    assert_eq!(host.stream_hooks(), ["on_stream_start", "on_stream_delta", "on_stream_end", "on_tool_event"]);
    StreamTap::new(host).map(Arc::new)
}

#[test]
fn observers_see_start_deltas_tool_events_and_end_off_the_token_path() {
    let Some(_) = fixture() else { return };
    let d = tmp("observe");
    let log = d.join("stream.jsonl");
    let Some(t) = tap(&log, 0.0, StreamConfig::default()) else { panic!("tap") };
    assert!(t.declares("on_stream_delta") && t.rewrites(), "declares observers and the inline rewrite");
    let inner = Arc::new(Fake { deltas: vec![StreamEvent::TextDelta("hello ".into()), StreamEvent::TextDelta("world".into()), StreamEvent::ToolUseStart { id: "c1".into(), name: "shell".into() }, StreamEvent::ThinkingDelta("hmm".into())] });
    let p = TappedProvider::new(inner, Arc::new(vec![t.clone()]));
    let mut seen = String::new();
    let resp = p.complete(&req(), &mut |e| {
        if let StreamEvent::TextDelta(t) = e {
            seen.push_str(&t)
        }
    }, &Cancel::new()).unwrap();
    assert_eq!(resp.message.text(), "answer");
    assert_eq!(seen, "hello world", "deltas reach the caller unchanged when the hook allows them");
    // Observer events arrive asynchronously on the plugin's own worker.
    let l = wait_for(&log, |l| l.iter().filter(|x| x["t"] == "stream" && x["event"] == "on_stream_end").count() >= 1);
    let ev: Vec<&str> = l.iter().filter(|x| x["t"] == "stream").map(|x| x["event"].as_str().unwrap_or("")).collect();
    assert!(ev.len() >= 5, "start + 2 text deltas + tool + end: {ev:?}\nfull log: {l:#?}");
    assert_eq!((ev[0], ev[1]), ("on_stream_start", "on_stream_delta"), "start precedes deltas: {ev:?}");
    let deltas: Vec<&Value> = l.iter().filter(|x| x["t"] == "stream" && x["event"] == "on_stream_delta").collect();
    assert_eq!((deltas[0]["delta"].as_str(), deltas[0]["kind"].as_str()), (Some("hello "), Some("text")));
    assert_eq!(deltas[0]["provider"].as_str(), Some("fake"), "payload names the provider");
    assert_eq!(deltas[0]["model"].as_str(), Some("m1"));
    assert!(deltas[0].get("stream_id").and_then(Value::as_str).is_some_and(|s| !s.is_empty()));
    assert!(deltas[0]["session_id"].is_null(), "provider-level taps have no session");
    assert!(l.iter().all(|x| !(x["event"] == "on_stream_delta" && x["kind"] == "reasoning")), "thinking deltas are opt-in");
    let tool = l.iter().find(|x| x["t"] == "stream" && x["event"] == "on_tool_event").expect("tool event");
    assert_eq!((tool["phase"].as_str(), tool["tool"].as_str(), tool["tool_use_id"].as_str()), (Some("start"), Some("shell"), Some("c1")));
    let end = l.iter().find(|x| x["t"] == "stream" && x["event"] == "on_stream_end").expect("end");
    assert_eq!((end["final_text"].as_str(), end["finished"].as_bool()), (Some("hello world"), Some(true)));
    assert_eq!(t.dropped(), 0, "the plugin kept up");
    assert_eq!(t.sent(), 5, "start, two deltas, the tool event and the end");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_plugin_rewrites_streamed_deltas_inline() {
    let Some(_) = fixture() else { return };
    let d = tmp("rewrite");
    let log = d.join("stream.jsonl");
    let Some(t) = tap(&log, 0.0, StreamConfig::default()) else { panic!("tap") };
    let inner = Arc::new(Fake { deltas: vec![StreamEvent::TextDelta("the SECRET is 42".into()), StreamEvent::TextDelta(" tail".into())] });
    let p = TappedProvider::new(inner, Arc::new(vec![t]));
    let mut seen = String::new();
    p.complete(&req(), &mut |e| {
        if let StreamEvent::TextDelta(t) = e {
            seen.push_str(&t)
        }
    }, &Cancel::new()).unwrap();
    assert_eq!(seen, "the <redacted> is 42 tail", "the hook rewrote the delta the caller saw");
    let l = wait_for(&log, |l| l.iter().any(|x| x["event"] == "on_stream_end"));
    let observed: Vec<&str> = l.iter().filter(|x| x["event"] == "on_stream_delta").filter_map(|x| x["delta"].as_str()).collect();
    assert_eq!(observed, vec!["the <redacted> is 42", " tail"], "observers see the text the model saw");
    assert!(l.iter().any(|x| x["t"] == "hook" && x["event"] == "stream_delta"), "the inline hook ran");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn reasoning_deltas_are_opt_in_and_a_slow_hook_does_not_hang_the_reply() {
    let Some(_) = fixture() else { return };
    let d = tmp("optin");
    let log = d.join("stream.jsonl");
    // reasoning_deltas = true, and a hook that sleeps 5 s (over HOOK_TIMEOUT) fails open.
    let Some(t) = tap(&log, 8.0, StreamConfig { enabled: true, reasoning_deltas: true }) else { panic!("tap") };
    assert!(t.reasoning_deltas());
    let inner = Arc::new(Fake { deltas: vec![StreamEvent::ThinkingDelta("why".into()), StreamEvent::TextDelta("SLOW".into()), StreamEvent::TextDelta("after".into())] });
    let p = TappedProvider::new(inner, Arc::new(vec![t]));
    let started = Instant::now();
    let mut seen = String::new();
    let r = p.complete(&req(), &mut |e| match e {
        StreamEvent::TextDelta(t) => seen.push_str(&t),
        StreamEvent::ThinkingDelta(t) => seen.push_str(&format!("<t>{t}")),
        _ => {}
    }, &Cancel::new());
    assert!(r.is_ok(), "a broken hook never fails the request");
    assert!(started.elapsed() < Duration::from_secs(12), "the delta hook timed out instead of stalling the stream");
    assert_eq!(seen, "<t>whySLOWafter", "a timed-out rewrite leaves the delta unchanged");
    let l = wait_for(&log, |l| l.iter().any(|x| x["event"] == "on_stream_end"));
    assert!(l.iter().any(|x| x["event"] == "on_stream_delta" && x["kind"] == "reasoning" && x["delta"] == "why"), "thinking deltas reach the observer when opted in");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn disabling_stream_hooks_builds_no_tap_and_still_streams() {
    let Some(_) = fixture() else { return };
    let d = tmp("off");
    let log = d.join("stream.jsonl");
    assert!(tap(&log, 0.0, StreamConfig { enabled: false, reasoning_deltas: false }).is_none(), "no tap when stream hooks are off");
    let inner = Arc::new(Fake { deltas: vec![StreamEvent::TextDelta("SECRET".into())] });
    let p = TappedProvider::new(inner, Arc::default());
    let mut seen = String::new();
    p.complete(&req(), &mut |e| {
        if let StreamEvent::TextDelta(t) = e {
            seen.push_str(&t)
        }
    }, &Cancel::new()).unwrap();
    assert_eq!(seen, "SECRET", "without a tap nothing rewrites the stream");
    assert!(!log.exists(), "no observer traffic");
    let _ = std::fs::remove_dir_all(&d);
    let _ = Mutex::new(json!({}));
}

/// A provider registry, as `main.rs` builds one (`Providers::new` + plugin providers).
struct Registry {
    p: Arc<dyn Provider>,
}

impl ark_kernel::kernel::Resolver for Registry {
    fn provider(&self, _id: &str) -> Result<Arc<dyn Provider>, String> {
        Ok(self.p.clone())
    }
}

#[test]
fn the_host_resolver_hands_out_tapped_providers() {
    let Some(_) = fixture() else { return };
    let d = tmp("resolver");
    let log = d.join("stream.jsonl");
    let inner = Arc::new(Fake { deltas: vec![StreamEvent::TextDelta("the SECRET".into())] });
    let plain: Arc<dyn ark_kernel::kernel::Resolver> = Arc::new(Registry { p: inner.clone() });
    // No taps: the resolver is returned as is (no wrapping cost, no behaviour change).
    assert!(Arc::ptr_eq(&ark_plugin::stream::tap_resolver(plain.clone(), vec![]), &plain));
    // With a tap (the same call `main.rs` makes), every provider the kernel asks for is wrapped.
    let Some(t) = tap(&log, 0.0, StreamConfig::default()) else { panic!("tap") };
    let r = ark_plugin::stream::tap_resolver(plain, vec![t]);
    let mut seen = String::new();
    r.provider("anything").unwrap().complete(&req(), &mut |e| {
        if let StreamEvent::TextDelta(t) = e {
            seen.push_str(&t)
        }
    }, &Cancel::new()).unwrap();
    assert_eq!(seen, "the <redacted>", "the plugin rewrote the delta the kernel's provider produced");
    assert!(wait_for(&log, |l| l.iter().any(|x| x["event"] == "on_stream_end")).iter().any(|x| x["event"] == "on_stream_start"));
    let _ = std::fs::remove_dir_all(&d);
}
