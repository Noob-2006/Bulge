//! Real WhatsApp bridge integration test (`bridges/whatsapp`, Baileys).
//!
//! Opt in with `ARK_REAL_WA_BRIDGE=http://127.0.0.1:<port>` pointing at a bridge
//! the operator started (`node bridge.js --port … --session <tmpdir>`; see
//! `tests/real/run.sh`); without it the test is skipped. Pairing needs a phone, so
//! this checks what a real *unpaired* bridge serves and how ark reads it.

mod support;

use ark_channel::whatsapp::{Settings, WhatsApp};
use serde_json::{json, Value};

fn bridge() -> Option<String> {
    std::env::var("ARK_REAL_WA_BRIDGE").ok().map(|s| s.trim().trim_end_matches('/').to_string()).filter(|s| !s.is_empty())
}

/// Build through the real config path, pointed at the running bridge.
fn open(url: &str, state: &std::path::Path) -> WhatsApp {
    let v = json!({"kind": "whatsapp", "bridge_url": url, "mode": "bot", "poll_timeout_secs": 3});
    // The `[channels.*]` path must accept these keys (unknown keys are errors).
    let cfg = ark_channel::config::parse_config("wa-real", &v).expect("parse");
    let secrets: ark_channel::config::Secrets = std::sync::Arc::new(|s: &str| s.to_string());
    let _ = ark_channel::config::build("wa-real", &cfg, state, &secrets).expect("config build");
    let st: Settings = serde_json::from_value(serde_json::Value::Object(cfg.settings.clone())).expect("settings");
    WhatsApp::open("wa-real", &st, state).expect("open")
}

/// A real, unpaired bridge answers `/health` and hands out a scannable QR.
#[test]
fn unpaired_bridge_serves_health_and_qr() {
    let Some(url) = bridge() else {
        support::skipped("whatsapp bridge", "ARK_REAL_WA_BRIDGE");
        return;
    };
    let scratch = support::Scratch::new("wa");
    let chan = open(&url, scratch.path());

    let h: Value = chan.health().expect("health");
    assert!(h["status"].is_string(), "status: {h}");
    assert!(h["queueLength"].is_number(), "queueLength: {h}");

    let q: Value = chan.qr().expect("qr");
    assert_eq!(q["status"].as_str(), Some("disconnected"), "an unpaired bridge is disconnected: {q}");
    // Baileys 7.0.0-rc13 pairing payload, as the real bridge serves it:
    // `https://wa.me/settings/linked_devices#2@<ref>,<noise>,<identity>,<adv>,<n>`
    // (version prefix `2@`, four or more comma-separated base64 parts). WhatsApp
    // needs the string whole, so ark must pass it through unchanged.
    let payload = q["qr"].as_str().unwrap_or_else(|| panic!("a real unpaired bridge must expose a QR: {q}"));
    assert!(payload.contains("2@"), "unexpected QR shape: {payload}");
    assert!(payload.split(',').count() >= 4, "unexpected QR shape: {payload}");
    assert!(payload.len() > 100, "qr too short: {payload}");
}
