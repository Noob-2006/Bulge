//! A5/A3 at the daemon broker: the component that asked may only use what it declared, and
//! a task envelope can widen the *host list* without opening the host's private space.
//!
//! These run in-process (no VM, no network): every assertion is about a decision the broker
//! makes before it dials anything.

use seagent_security::broker::{self, BrokerConfig, Ctx};
use seagent_security::capability::{self, Kind, Source};
use seagent_security::egress_proxy::{Policy, ProxyMode};
use serde_json::{json, Value};
use std::sync::Arc;

/// A self-removing scratch tree (`seagent_core::tmp::TempDir`): a panicking test must not leave
/// anything in `$TMPDIR`, and the broker writes its audit log here.
fn data(tag: &str) -> seagent_core::tmp::TempDir {
    seagent_core::tmp::TempDir::new(&format!("seagent-broker-cap-{tag}"))
}

fn ctx(d: &std::path::Path, allow: &[&str]) -> Ctx {
    let mut policy = Policy { mode: ProxyMode::Allowlist, ..Default::default() };
    policy.allow = allow.iter().map(|s| s.to_string()).collect();
    let mut c = Ctx::new(d.to_path_buf(), policy);
    c.session = "s-cap".into();
    c.cfg = BrokerConfig { exec_allow: vec!["echo *".into()], enforce_capabilities: true, ..Default::default() };
    c.resolve = Arc::new(|h: &str, _p: u16| h.parse::<std::net::IpAddr>().map(|ip| vec![ip]).map_err(|e| e.to_string()));
    c
}

fn err_code(v: &Value) -> &str {
    v["error"]["code"].as_str().unwrap_or("")
}

fn text(v: &Value) -> String {
    v.to_string()
}

#[test]
fn an_undeclared_component_cannot_use_the_broker_at_all() {
    let d = data("undeclared");
    let c = ctx(d.path(), &["example.com"]);
    // A third-party skill that never declared anything: refused, with a next step for the
    // operator (A5: undeclared ⇒ refused, never a default-allow).
    let e = broker::handle_for(&json!({"op": "egress", "url": "https://example.com/", "method": "GET"}), &c, "acme-skill");
    assert_eq!(err_code(&e), "capability", "{e}");
    assert!(text(&e).contains("no capability manifest") && text(&e).contains("declare"), "{e}");
    let x = broker::handle_for(&json!({"op": "exec", "argv": ["echo", "hi"]}), &c, "acme-skill");
    assert_eq!(err_code(&x), "capability", "{x}");
}

#[test]
fn a_component_reaches_only_the_hosts_and_secrets_it_declared() {
    let d = data("hosts");
    capability::register(capability::declared("cap-test-tool", Kind::Tool, Source::ThirdParty, &["net:api.cap-test.example".into(), "secret:CAP_TOKEN".into()]).unwrap());
    let c = ctx(d.path(), &["example.com"]);
    // Declared host, but the operator's policy does not allow it: still refused (two layers,
    // each has to say yes).
    let e = broker::handle_for(&json!({"op": "egress", "url": "https://api.cap-test.example/", "method": "GET"}), &c, "cap-test-tool");
    assert_eq!(err_code(&e), "denied", "the host policy is independent of the manifest: {e}");
    // Undeclared host, allowed by the operator: refused by the manifest.
    let e = broker::handle_for(&json!({"op": "egress", "url": "https://example.com/", "method": "GET"}), &c, "cap-test-tool");
    assert_eq!(err_code(&e), "capability", "{e}");
    assert!(text(&e).contains("net:example.com"), "{e}");
    // Undeclared secret: refused before the daemon hands it over (the host is allowed here so
    // the request reaches the header check).
    capability::register(capability::declared("cap-test-secret-tool", Kind::Tool, Source::ThirdParty, &["net:127.0.0.1".into(), "secret:CAP_TOKEN".into()]).unwrap());
    let c = ctx(d.path(), &["127.0.0.1"]);
    let e = broker::handle_for(&json!({"op": "egress", "url": "http://127.0.0.1:9/", "method": "GET", "headers": {"authorization": "secret:OTHER_TOKEN"}}), &c, "cap-test-secret-tool");
    assert_eq!(err_code(&e), "capability", "{e}");
    assert!(text(&e).contains("secret:OTHER_TOKEN"), "{e}");
}

#[test]
fn an_envelope_adds_a_host_but_never_opens_the_private_network() {
    let d = data("envelope");
    let c = ctx(d.path(), &[]);
    // A component that declares exactly the two hosts below, so this test is about the
    // envelope and the address floor — not about the manifest (covered above).
    capability::register(capability::declared("cap-test-loopback", Kind::Tool, Source::Operator, &["net:127.0.0.1".into(), "net:10.9.9.9".into(), "net:169.254.169.254".into()]).unwrap());
    let egress = |url: &str| broker::handle_for(&json!({"op": "egress", "url": url, "method": "GET"}), &c, "cap-test-loopback");
    // Without an envelope, a host the operator did not allow is refused.
    let e = egress("http://127.0.0.1:9/x");
    assert_eq!(err_code(&e), "denied", "{e}");
    assert!(text(&e).contains("not on the egress allowlist"), "{e}");
    // The task envelope names loopback for this session (§0-2 #01: no mid-task prompt for a
    // host the operator approved up front). The *name* check is satisfied …
    let spec = seagent_security::envelope::Spec {
        label: "cap-test".into(),
        session: Some("s-cap".into()),
        hosts: vec!["127.0.0.1".into()],
        max_tier: 2,
        ttl_ms: 60_000,
        ..Default::default()
    };
    let env = seagent_security::envelope::create(d.path(), &spec).expect("an envelope");
    let e = egress("http://127.0.0.1:9/x");
    // …and the address floor (a separate layer) is what refuses it now. The difference in the
    // message is the proof that the envelope widened the name list and nothing else.
    assert!(text(&e).contains("private/internal"), "the envelope does not open the private network: {e}");
    // A public host the operator's list does not know is exactly what an envelope is for:
    // name-level, it passes.
    let mut p = c.policy.clone();
    p.envelope_hosts.push("crates.io".into());
    assert!(p.check_host("crates.io").is_ok(), "the envelope's host passes the name check: {:?}", p.check_host("crates.io"));
    assert!(p.check_host("example.org").is_err(), "and no other host does");
    // …and the SSRF floor is a separate layer: an envelope that names a private address does
    // not open the private network.
    seagent_security::envelope::revoke(d.path(), &env.id).unwrap();
    let spec = seagent_security::envelope::Spec { hosts: vec!["10.9.9.9".into(), "169.254.169.254".into()], ..spec };

    seagent_security::envelope::create(d.path(), &spec).unwrap();
    for url in ["http://10.9.9.9/x", "http://169.254.169.254/latest/meta-data/"] {
        let e = egress(url);
        assert_eq!(err_code(&e), "denied", "the address floor still applies to {url}: {e}");
        assert!(text(&e).contains("private/internal") || text(&e).contains("cloud metadata"), "{url}: {e}");
    }
}

#[test]
fn a_tier_three_command_still_queues_even_for_a_destructive_component() {
    let d = data("tier3");
    let c = ctx(d.path(), &[]);
    // `shell` declares `destructive: true`, so the manifest does not refuse the request — and
    // that is exactly right: a manifest may let a component *ask*. The hard floor (A6) queues
    // it for the operator, who sees the actual command.
    let v = broker::handle_for(&json!({"op": "exec", "argv": ["rm", "-rf", "/srv/data"]}), &c, "shell");
    assert_eq!(v["ok"], true, "queued, not executed: {v}");
    assert_eq!(v["result"]["status"], "queued", "{v}");
    assert_eq!(v["result"]["tier"], 3, "{v}");
    assert!(v["result"]["approval_id"].as_str().is_some_and(|s| !s.is_empty()), "the operator gets an approval id: {v}");
    // A component that never declared destructive cannot even ask.
    capability::register(capability::declared("cap-gentle-tool", Kind::Skill, Source::ThirdParty, &["exec:*".into()]).unwrap());
    let v = broker::handle_for(&json!({"op": "exec", "argv": ["rm", "-rf", "/srv/data"]}), &c, "cap-gentle-tool");
    assert_eq!(err_code(&v), "capability", "a non-destructive manifest is a hard no: {v}");
}

#[test]
fn the_audit_trail_names_the_component_that_asked() {
    let d = data("audit");
    let c = ctx(d.path(), &["example.com"]);
    let _ = broker::handle_for(&json!({"op": "exec", "argv": ["echo", "hi"]}), &c, "shell");
    let _ = broker::handle_for(&json!({"op": "egress", "url": "https://nope.example/", "method": "GET"}), &c, "acme-skill");
    let log = std::fs::read_to_string(d.path().join("audit").join("broker.jsonl")).unwrap_or_default();
    let lines: Vec<Value> = log.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    assert!(lines.iter().any(|l| l["component"] == "shell" && l["op"] == "exec"), "{log}");
    assert!(lines.iter().any(|l| l["component"] == "acme-skill" && l["verdict"] == "denied"), "{log}");
    assert!(!log.contains("/srv/data"), "no command bodies beyond the subject line: {log}");
}
