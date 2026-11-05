//! End-to-end activation of `[security.egress_proxy]` (integration test: the proxy is a
//! process-wide singleton, so this must not share a test binary with the unit tests).
//!
//! What is proven here, with a real socket:
//!
//! * `SecurityConfig::activate_egress` starts the proxy and returns its URL;
//!   `running_url()` / `running_port()` agree;
//! * `envscrub::set_proxy` reaches children built through `envscrub::apply` as
//!   `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`, and `NO_PROXY`/`no_proxy` are gone;
//! * the deny list refuses a host by name (no DNS), `refusal()` reports the same verdict
//!   and `recent()` records the refusal; the JSONL log is written under `<data>/egress`;
//! * an `inject` rule whose value is `Bearer {{secret:…}}` arrives at the upstream server
//!   expanded, and never in the client's response, the client's own header or a child
//!   environment.

use ark_security::egress_proxy::{self, Inject, ProxyMode};
use ark_security::envscrub::{self, Surface};
use ark_security::SecurityConfig;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

/// The proxy is one per process: serialize the tests that reconfigure it.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// One data dir for the whole binary, so whichever test starts the proxy first decides
/// the log path and every test can read it back.
fn data_dir() -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("egress-data");
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn config(enabled: bool) -> SecurityConfig {
    let mut c = SecurityConfig::default();
    c.egress_proxy.enabled = enabled;
    c.egress_proxy.listen = "127.0.0.1:0".into();
    c
}

/// One request through the proxy; returns everything the proxy sent back.
fn through_proxy(url: &str, req: &str) -> String {
    let mut s = TcpStream::connect(url.trim_start_matches("http://")).expect("connect proxy");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn child_output(surface: Surface, var: &str) -> String {
    let mut c = Command::new("sh");
    c.arg("-c").arg(format!("printf %s \"${{{var}:-none}}\""));
    envscrub::apply(&mut c, surface);
    String::from_utf8_lossy(&c.output().unwrap().stdout).to_string()
}

/// Upstream server that answers `200 ok` and records the raw request head it received.
fn upstream() -> (u16, Arc<Mutex<Vec<String>>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut s) = c else { continue };
            let s2 = s2.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let mut head = String::new();
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    head.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if head.contains("\r\n\r\n") {
                        break;
                    }
                }
                s2.lock().unwrap().push(head);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
            });
        }
    });
    (port, seen)
}

#[test]
fn activation_starts_the_proxy_and_points_children_at_it() {
    let _g = serial();
    let c = config(true);
    let dir = data_dir();
    let url = c.activate_egress(Some(&dir), egress_proxy::env_secrets()).unwrap().expect("enabled proxy starts");
    assert!(url.starts_with("http://127.0.0.1:"), "{url}");
    assert_eq!(egress_proxy::running_url().as_deref(), Some(url.as_str()), "running_url() reports the bound address");
    let port: u16 = url.rsplit(':').next().unwrap().parse().unwrap();
    assert_eq!(egress_proxy::running_port(), Some(port), "running_port() is what [exec.docker] proxy_port must match");

    // What exec/shell/job/coderun children see: envscrub::apply adds the proxy vars.
    assert_eq!(envscrub::proxy_url().as_deref(), Some(url.as_str()));
    assert_eq!(child_output(Surface::Terminal, "HTTPS_PROXY"), url);
    assert_eq!(child_output(Surface::Sandbox, "HTTP_PROXY"), url);
    assert_eq!(child_output(Surface::Sandbox, "ALL_PROXY"), url);
    // NO_PROXY (inherited or set) never reaches a child: an exemption for localhost is an
    // SSRF path around the proxy.
    let mut c2 = Command::new("sh");
    c2.arg("-c").arg("printf %s \"${NO_PROXY:-none}/${no_proxy:-none}\"");
    c2.env("NO_PROXY", "localhost,127.0.0.1").env("no_proxy", "localhost");
    envscrub::apply(&mut c2, Surface::Terminal);
    assert_eq!(String::from_utf8_lossy(&c2.output().unwrap().stdout), "none/none");

    // Sandbox backends build their environment as a map: the same two rules apply.
    let mut m: std::collections::BTreeMap<String, String> =
        [("NO_PROXY".to_string(), "localhost".to_string()), ("PATH".to_string(), "/bin".to_string())].into();
    envscrub::filter_map(&mut m, Surface::Sandbox);
    assert_eq!(m.get("HTTPS_PROXY").map(String::as_str), Some(url.as_str()));
    assert_eq!(m.get("ALL_PROXY").map(String::as_str), Some(url.as_str()));
    assert!(!m.contains_key("NO_PROXY") && m.get("PATH").map(String::as_str) == Some("/bin"));

    // A refused host is still logged as JSON lines under <data>/egress/proxy.jsonl.
    let out = through_proxy(&url, "CONNECT denied-in-test.test:443 HTTP/1.1\r\n\r\n");
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    let log = std::fs::read_to_string(dir.join("egress").join("proxy.jsonl")).expect("JSONL log");
    let entry: serde_json::Value = serde_json::from_str(log.lines().last().unwrap()).unwrap();
    assert_eq!(entry["host"], "denied-in-test.test");
    assert_eq!(entry["allowed"], false);

    // A disabled config never stops the running proxy (one daemon, one proxy).
    assert_eq!(config(false).activate_egress(Some(&dir), egress_proxy::env_secrets()).unwrap().as_deref(), Some(url.as_str()));
    assert_eq!(egress_proxy::running_url().as_deref(), Some(url.as_str()));

    // Children that inherit ark's environment instead of calling `apply` (the shell tool,
    // background jobs, `[exec]` local backends, hooks) are covered by `set_proxy`'s copy
    // in the process environment.
    let out = Command::new("sh").arg("-c").arg("printf %s \"${HTTPS_PROXY:-none}\"").output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), url, "an inherited-env child is routed too");
    assert!(std::env::var_os("NO_PROXY").is_none() && std::env::var_os("http_proxy").is_none(), "no bypass variable survives in ark's own environment");

    // The kernel reaches all of this through `activate()` (`new_kernel` -> `cfg.security.activate()`).
    config(true).activate();
    assert_eq!(egress_proxy::running_url().as_deref(), Some(url.as_str()));
    assert_eq!(envscrub::proxy_url().as_deref(), Some(url.as_str()));
}

#[test]
fn deny_list_refuses_by_name_and_recent_records_it() {
    let _g = serial();
    let mut c = config(true);
    c.egress_proxy.deny = vec!["evil.test".into()];
    let url = c.activate_egress(Some(&data_dir()), egress_proxy::env_secrets()).unwrap().expect("url");

    // Name-only: no DNS lookup can rescue the host, and the static gate agrees.
    let why = egress_proxy::refusal("sub.evil.test").expect("denied host has a verdict");
    assert!(why.contains("deny list"), "{why}");
    assert!(egress_proxy::refusal("allowed.test").is_none());
    let out = through_proxy(&url, "CONNECT evil.test:443 HTTP/1.1\r\n\r\n");
    assert!(out.starts_with("HTTP/1.1 403") && out.contains("deny list"), "{out}");
    let last = egress_proxy::recent().pop().expect("logged");
    assert!(!last.allowed && last.host == "evil.test" && last.method == "CONNECT" && last.port == 443, "{last:?}");

    // Allowlist mode refuses unlisted hosts the same way (still before any DNS).
    let mut c = config(true);
    c.egress_proxy.mode = ProxyMode::Allowlist;
    c.egress_proxy.allow = vec!["localhost".into()];
    c.activate_egress(Some(&data_dir()), egress_proxy::env_secrets()).unwrap();
    let out = through_proxy(&url, "GET http://unlisted.test/ HTTP/1.1\r\n\r\n");
    assert!(out.starts_with("HTTP/1.1 403") && out.contains("allowlist"), "{out}");
    assert!(egress_proxy::refusal("unlisted.test").unwrap().contains("allowlist"));
    assert!(egress_proxy::refusal("localhost").is_none());
}

#[test]
fn injected_secret_reaches_upstream_only() {
    let _g = serial();
    std::env::set_var("ARK_TEST_EGRESS_SERVICE_TOKEN", "s3cr3t-tok-42");
    let (port, seen) = upstream();
    let mut c = config(true);
    c.egress_proxy.allow = vec!["localhost".into()];
    c.egress_proxy.inject = vec![Inject { host: "localhost".into(), header: "Authorization".into(), value: "Bearer {{secret:ARK_TEST_EGRESS_SERVICE_TOKEN}}".into() }];
    let url = c.activate_egress(Some(&data_dir()), egress_proxy::env_secrets()).unwrap().expect("url");

    let out = through_proxy(&url, &format!("GET http://localhost:{port}/v1/x?q=1 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer placeholder\r\n\r\n"));
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(!out.contains("s3cr3t-tok-42"), "the response must not echo the injected secret: {out}");
    assert!(!out.contains("placeholder"), "the client's own header is replaced, not forwarded: {out}");
    let heads = seen.lock().unwrap().clone();
    let head = heads.last().expect("upstream saw one request");
    assert!(head.starts_with("GET /v1/x?q=1 HTTP/1.1"), "origin-form request line: {head}");
    assert!(head.contains("Authorization: Bearer s3cr3t-tok-42"), "expanded `{{{{secret:…}}}}` reaches the upstream: {head}");
    assert!(!head.contains("placeholder"), "{head}");

    // The child environment is still scrubbed: a sandbox never gets the credential that
    // the proxy holds, so a compromised child cannot exfiltrate it directly.
    assert_eq!(child_output(Surface::Sandbox, "ARK_TEST_EGRESS_SERVICE_TOKEN"), "none");

    // An unset reference expands to "" with a warning instead of leaking the literal.
    assert_eq!(egress_proxy::expand_env_secrets("Bearer {{secret:ARK_TEST_NOT_SET_TOKEN}}"), "Bearer ");
    assert_eq!(egress_proxy::expand_env_secrets("plain value"), "plain value");
    assert_eq!(egress_proxy::expand_env_secrets("{{secret:ARK_TEST_EGRESS_SERVICE_TOKEN}}"), "s3cr3t-tok-42");
    std::env::remove_var("ARK_TEST_EGRESS_SERVICE_TOKEN");
}
