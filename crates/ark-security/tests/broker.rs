//! The daemon-side broker (A2/A3/A4) as the VM sees it: JSON lines over a unix socket.

use ark_security::broker::{self, Broker, BrokerConfig, Ctx};
use ark_security::egress_proxy::{EgressProxyConfig, Policy};
use ark_security::url_safety::{UrlPolicy, WebsiteBlocklist};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ark-broker-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn policy(allow: Vec<&str>) -> Policy {
    let cfg = EgressProxyConfig { allow: allow.into_iter().map(String::from).collect(), ..Default::default() };
    Policy::from_config(&cfg, UrlPolicy::default(), WebsiteBlocklist::default(), &tmp("cfg"), &[], &[])
}

fn ctx(dir: &std::path::Path, policy: Policy) -> Ctx {
    let mut c = Ctx::new(dir.to_path_buf(), policy);
    let secret = "s3cr3t-value-123456".to_string();
    c.secret = Arc::new(move |n: &str| if n == "TOKEN" { secret.clone() } else { String::new() });
    c.check_body = Arc::new(|body: &str| {
        if body.contains("s3cr3t-value-123456") {
            return Some("the body contains the value of vault secret TOKEN".into());
        }
        ark_security::risk::secret_kind(body).map(|k| format!("the body contains a {k}"))
    });
    c
}

/// A one-request HTTP server that echoes the Authorization header in the body.
fn echo_server() -> (String, std::thread::JoinHandle<String>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let h = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            match s.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if String::from_utf8_lossy(&buf).contains("\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let head = String::from_utf8_lossy(&buf).to_string();
        let auth = head.lines().find(|l| l.to_ascii_lowercase().starts_with("authorization:")).unwrap_or("").to_string();
        let body = format!("{{\"seen\":\"{}\"}}", auth.replace('"', "'"));
        let _ = write!(s, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
        let _ = s.flush();
        head
    });
    (format!("http://{addr}"), h)
}

fn req(v: Value, c: &Ctx) -> Value {
    broker::handle(&v, c)
}

/// The same request, attributed to a component that declares the loopback test server and the
/// `TOKEN` secret (A5). The `vm` default may not reach loopback at all, which
/// `crates/ark-security/tests/broker_capability.rs` asserts separately.
fn req_as(component: &str, v: Value, c: &Ctx) -> Value {
    broker::handle_for(&v, c, component)
}

fn public_component() {
    let _ = ark_security::capability::declared("broker-test-public", ark_security::capability::Kind::Tool, ark_security::capability::Source::Operator, &["net:*".into()]).map(ark_security::capability::register);
}

fn loopback_component() {
    let _ = ark_security::capability::declared(
        "broker-test-loopback",
        ark_security::capability::Kind::Tool,
        ark_security::capability::Source::Operator,
        &["net:127.0.0.1".into(), "secret:TOKEN".into(), "exec:echo *".into()],
    )
    .map(ark_security::capability::register);
}

#[test]
fn exec_runs_the_allowlist_and_queues_the_rest() {
    let dir = tmp("exec");
    let mut c = ctx(&dir, policy(vec![]));
    c.cfg = BrokerConfig { exec_allow: vec!["echo *".into()], ..Default::default() };
    let r = req(json!({"id":"1","op":"exec","argv":["/bin/echo","hello","broker"]}), &c);
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(r["result"]["status"], "ran");
    assert_eq!(r["result"]["stdout"].as_str().unwrap().trim(), "hello broker");
    assert!(r["result"]["tier"].as_u64().unwrap() <= 2);

    // Not on the allowlist: queued for the owner, nothing runs.
    let r = req(json!({"id":"2","op":"exec","argv":["/usr/bin/whoami"]}), &c);
    assert_eq!(r["result"]["status"], "queued", "{r}");
    assert!(r["result"]["approval_id"].as_str().unwrap().starts_with(|_c: char| _c.is_ascii_hexdigit()));
    assert_eq!(ark_security::approvals::deferred(&dir).len(), 1);

    // Even when the allowlist would match, tier 3 is never pre-authorised (§0-1 A6).
    c.cfg.exec_allow.push("rm *".into());
    let r = req(json!({"id":"3","op":"exec","argv":["rm","-rf","/var/backups/prod"]}), &c);
    assert_eq!(r["result"]["status"], "queued", "{r}");
    assert_eq!(r["result"]["tier"], 3);
    assert!(r["result"]["fallback"].as_str().unwrap().contains("do not retry"));

    // Argv only: a shell payload smuggled into one element is refused outright.
    let r = req(json!({"id":"4","op":"exec","argv":["sh","-c","id; rm -rf /"]}), &c);
    assert_eq!(r["ok"], false);
    assert_eq!(r["error"]["code"], "denied", "{r}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn egress_injects_secrets_and_refuses_them_on_the_way_out() {
    let dir = tmp("egress");
    let (url, server) = echo_server();
    let c = ctx(&dir, policy(vec!["127.0.0.1"]));
    loopback_component();
    let r = req_as("broker-test-loopback", json!({"id":"1","op":"egress","method":"GET","url":url,
        "headers":{"authorization":"secret:TOKEN"}}), &c);
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(r["result"]["code"], 200);
    let body = String::from_utf8(broker::b64_decode(r["result"]["body_b64"].as_str().unwrap())).unwrap();
    assert!(body.contains("s3cr3t-value"), "the daemon injected the secret: {body}");
    let head = server.join().unwrap();
    assert!(head.to_ascii_lowercase().contains("authorization: s3cr3t"), "{head}");
    // …but the audit trail never contains it.
    let log = std::fs::read_to_string(dir.join("audit/broker.jsonl")).unwrap();
    assert!(!log.contains("s3cr3t"), "no secret in the audit log: {log}");
    assert!(log.contains("\"verdict\":\"ok\""), "{log}");

    // A body carrying the secret is refused before it leaves (H11).
    let r = req_as("broker-test-loopback", json!({"id":"2","op":"egress","method":"POST","url":format!("{url}/upload"),
        "body_b64": broker::b64_encode(b"token=s3cr3t-value-123456")}), &c);
    assert_eq!(r["ok"], false, "{r}");
    assert_eq!(r["error"]["code"], "exfil", "{r}");
    // A raw credential shape, too.
    let r = req_as("broker-test-loopback", json!({"id":"3","op":"egress","method":"POST","url":format!("{url}/x"),
        "body_b64": broker::b64_encode(b"ghp_0123456789abcdefghijklmnopqrstuvwxyz")}), &c);
    assert_eq!(r["error"]["code"], "exfil", "{r}");
    public_component();
    // A host outside the policy is refused by name before any connection: the component
    // declares any public host, and the policy still has the last word.
    let r = req_as("broker-test-public", json!({"id":"4","op":"egress","method":"GET","url":"https://example.org/x"}), &c);
    assert_eq!(r["ok"], false, "{r}");
    assert_eq!(r["error"]["code"], "denied");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn socket_round_trip_speaks_the_documented_protocol() {
    let dir = tmp("sock");
    let sock = dir.join("run/broker.sock");
    let c = ctx(&dir, policy(vec!["127.0.0.1"]));
    let b = Broker::serve(&sock, c).unwrap();
    let s = std::os::unix::net::UnixStream::connect(&sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut w = s.try_clone().unwrap();
    writeln!(w, "{}", json!({"id":"a","op":"health"})).unwrap();
    writeln!(w, "{}", json!({"id":"b","op":"host.check","host":"127.0.0.1","port":443})).unwrap();
    writeln!(w, "{}", json!({"id":"c","op":"nope"})).unwrap();
    let mut lines = BufReader::new(s).lines();
    let mut got: Vec<Value> = Vec::new();
    for _ in 0..3 {
        let line = lines.next().unwrap().unwrap();
        got.push(serde_json::from_str(&line).unwrap());
    }
    let by_id = |id: &str| got.iter().find(|v| v["id"] == id).cloned().unwrap();
    assert_eq!(by_id("a")["ok"], true);
    assert_eq!(by_id("b")["result"]["allowed"], true);
    assert_eq!(by_id("c")["error"]["code"], "unsupported");
    b.stop();
    assert!(!sock.exists(), "the socket is removed on stop");
    let _ = std::fs::remove_dir_all(&dir);
}
