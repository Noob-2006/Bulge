//! `ark proxy` (OpenClaw `openclaw proxy`, `src/proxy-capture/*`): a local explicit
//! debug proxy that records traffic for inspection, plus validation of an
//! operator-managed network proxy.
//!
//! - `start [--host 127.0.0.1] [--port P]` runs the capture proxy in the foreground.
//! - `run [--host] [--port] -- <cmd…>` runs a child with `HTTP(S)_PROXY`/`ALL_PROXY`
//!   pointed at a capture proxy for its lifetime (one capture session).
//! - `sessions [--limit N]`, `query --preset P [--session ID]`, `blob --id ID`,
//!   `purge`, `coverage` inspect the capture store (`<data>/proxy-capture/`).
//! - `validate [--proxy-url URL] [--allowed-url U]… [--denied-url U]… [--timeout-ms N]`
//!   checks that allowed destinations pass through the proxy and denied ones are blocked.
//!
//! Plain-HTTP exchanges are captured in full (method, URL, status, timing, sizes,
//! redacted headers, request/response bodies as blobs up to 1 MiB). `CONNECT` tunnels
//! (HTTPS, WSS) are recorded as metadata only (host, port, bytes each way, duration):
//! ark does not mint a CA or intercept TLS — `coverage` reports which seams are
//! captured versus proxy-only. Query presets: double-sends, retry-storms,
//! cache-busting, ws-duplicate-frames, missing-ack, error-bursts.

use crate::args::Args;
use crate::R;
use ark_kernel::config::Paths;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const COMMANDS: &[&str] = &["proxy"];
pub const VALUE_FLAGS: &[&str] = &["host", "port", "preset", "id", "proxy-url", "allowed-url", "denied-url", "timeout-ms"];
pub const BOOL_FLAGS: &[&str] = &[];

const MAX_HEAD: usize = 64 * 1024;
const MAX_BLOB: usize = 1 << 20;
pub const PRESETS: &[&str] = &["double-sends", "retry-storms", "cache-busting", "ws-duplicate-frames", "missing-ack", "error-bursts"];
const SECRET_HEADERS: &[&str] = &["authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key", "x-goog-api-key", "anthropic-api-key", "openai-api-key"];

pub fn dir(paths: &Paths) -> PathBuf {
    paths.data.join("proxy-capture")
}

pub struct Store {
    root: PathBuf,
    lock: Mutex<()>,
}

impl Store {
    pub fn new(root: PathBuf) -> Store {
        let _ = std::fs::create_dir_all(root.join("blobs"));
        Store { root, lock: Mutex::new(()) }
    }
    fn append(&self, file: &str, v: &Value) {
        let _g = self.lock.lock().unwrap();
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(self.root.join(file)) {
            let _ = writeln!(f, "{v}");
        }
    }
    fn blob(&self, data: &[u8]) -> Option<String> {
        if data.is_empty() {
            return None;
        }
        let id = ark_net::crypto::hex(&ark_net::crypto::sha256(data))[..24].to_string();
        let p = self.root.join("blobs").join(&id);
        if !p.exists() {
            let _ = std::fs::write(&p, &data[..data.len().min(MAX_BLOB)]);
        }
        Some(id)
    }
    pub fn events(&self) -> Vec<Value> {
        read_jsonl(&self.root.join("events.jsonl"))
    }
    pub fn sessions(&self) -> Vec<Value> {
        read_jsonl(&self.root.join("sessions.jsonl"))
    }
}

fn read_jsonl(p: &Path) -> Vec<Value> {
    std::fs::read_to_string(p).unwrap_or_default().lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}

pub fn redact_headers(h: &[(String, String)]) -> Value {
    Value::Array(h.iter().map(|(k, v)| json!([k, if SECRET_HEADERS.contains(&k.to_lowercase().as_str()) { "[REDACTED]".to_string() } else { v.clone() }])).collect())
}

fn read_head(r: &mut BufReader<TcpStream>) -> Result<(String, Vec<(String, String)>), String> {
    let mut first = String::new();
    r.read_line(&mut first).map_err(|e| e.to_string())?;
    let mut headers = vec![];
    let mut total = first.len();
    loop {
        let mut l = String::new();
        let n = r.read_line(&mut l).map_err(|e| e.to_string())?;
        total += n;
        if n == 0 || total > MAX_HEAD {
            return Err("bad request head".into());
        }
        let t = l.trim_end();
        if t.is_empty() {
            break;
        }
        if let Some((k, v)) = t.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok((first.trim_end().to_string(), headers))
}

fn hdr<'a>(h: &'a [(String, String)], k: &str) -> Option<&'a str> {
    h.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
}

fn now() -> u64 {
    ark_kernel::event::now_ms()
}

fn pump(mut from: TcpStream, mut to: TcpStream) -> u64 {
    let mut buf = [0u8; 16 * 1024];
    let mut n = 0u64;
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(k) => {
                if to.write_all(&buf[..k]).is_err() {
                    break;
                }
                n += k as u64;
            }
        }
    }
    let _ = to.shutdown(Shutdown::Write);
    n
}

fn handle(client: TcpStream, store: &Store, session: &str, seq: u64) -> Result<(), String> {
    let started = Instant::now();
    let ts = now();
    let mut r = BufReader::new(client.try_clone().map_err(|e| e.to_string())?);
    let (line, headers) = read_head(&mut r)?;
    let mut parts = line.split_whitespace();
    let (method, target) = (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("").to_string());
    let id = format!("{session}-{seq}");
    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = target.rsplit_once(':').map(|(h, p)| (h.to_string(), p.parse::<u16>().unwrap_or(443))).unwrap_or((target.clone(), 443));
        let mut c = client;
        let up = match TcpStream::connect((host.as_str(), port)) {
            Ok(u) => u,
            Err(e) => {
                let _ = c.write_all(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n");
                store.append("events.jsonl", &json!({"id": id, "session": session, "ts": ts, "protocol": "connect", "method": "CONNECT", "host": host, "port": port, "status": 502, "error": e.to_string(), "durationMs": started.elapsed().as_millis() as u64}));
                return Ok(());
            }
        };
        c.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").map_err(|e| e.to_string())?;
        // Bytes the client already sent past the head stay in the BufReader buffer.
        let pre = r.buffer().to_vec();
        let mut up_w = up.try_clone().map_err(|e| e.to_string())?;
        if !pre.is_empty() {
            let _ = up_w.write_all(&pre);
        }
        let (cr, uw) = (c.try_clone().map_err(|e| e.to_string())?, up_w);
        let t = std::thread::spawn(move || pump(cr, uw));
        let down = pump(up, c);
        let upb = t.join().unwrap_or(0) + pre.len() as u64;
        store.append("events.jsonl", &json!({"id": id, "session": session, "ts": ts, "protocol": "connect", "method": "CONNECT", "host": host, "port": port, "status": 200, "bytesUp": upb, "bytesDown": down, "durationMs": started.elapsed().as_millis() as u64}));
        return Ok(());
    }
    // Absolute-URI plain HTTP.
    let rest = target.strip_prefix("http://").ok_or_else(|| "only absolute http:// URLs and CONNECT are proxied".to_string())?;
    let (authority, path) = rest.split_once('/').map(|(a, p)| (a.to_string(), format!("/{p}"))).unwrap_or((rest.to_string(), "/".into()));
    let (host, port) = authority.rsplit_once(':').and_then(|(h, p)| p.parse::<u16>().ok().map(|p| (h.to_string(), p))).unwrap_or((authority.clone(), 80));
    let len: usize = hdr(&headers, "content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut body = vec![0u8; len.min(64 << 20)];
    r.read_exact(&mut body).map_err(|e| e.to_string())?;
    let mut c = client;
    let mut up = match TcpStream::connect((host.as_str(), port)) {
        Ok(u) => u,
        Err(e) => {
            let _ = c.write_all(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n");
            store.append("events.jsonl", &json!({"id": id, "session": session, "ts": ts, "protocol": "http", "method": method, "url": target, "host": host, "status": 502, "error": e.to_string(), "durationMs": started.elapsed().as_millis() as u64}));
            return Ok(());
        }
    };
    let mut req = format!("{method} {path} HTTP/1.1\r\n");
    for (k, v) in &headers {
        let lk = k.to_lowercase();
        if lk == "proxy-connection" || lk == "proxy-authorization" || lk == "connection" || lk == "keep-alive" {
            continue;
        }
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("connection: close\r\n\r\n");
    up.write_all(req.as_bytes()).and_then(|_| up.write_all(&body)).map_err(|e| e.to_string())?;
    let resp = read_response(up);
    let _ = c.write_all(&resp);
    let _ = c.shutdown(Shutdown::Write);
    let split = resp.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4).unwrap_or(resp.len());
    let head = String::from_utf8_lossy(&resp[..split]).to_string();
    let status: u16 = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let rh: Vec<(String, String)> = head.lines().skip(1).filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))).collect();
    store.append("events.jsonl", &json!({"id": id, "session": session, "ts": ts, "protocol": "http", "method": method, "url": target, "host": host, "path": path, "status": status, "requestHeaders": redact_headers(&headers), "responseHeaders": redact_headers(&rh), "requestBytes": body.len(), "responseBytes": resp.len() - split, "requestBlob": store.blob(&body), "responseBlob": store.blob(&resp[split..]), "bodyHash": (!body.is_empty()).then(|| ark_net::crypto::hex(&ark_net::crypto::sha256(&body))[..16].to_string()), "durationMs": started.elapsed().as_millis() as u64}));
    Ok(())
}

/// One HTTP response from the origin: head, then content-length / chunked / until close.
fn read_response(up: TcpStream) -> Vec<u8> {
    let _ = up.set_read_timeout(Some(Duration::from_secs(120)));
    let mut r = BufReader::new(up);
    let mut out = vec![];
    let mut len: Option<usize> = None;
    let mut chunked = false;
    loop {
        let mut l = String::new();
        if r.read_line(&mut l).unwrap_or(0) == 0 {
            return out;
        }
        out.extend_from_slice(l.as_bytes());
        let t = l.trim_end().to_lowercase();
        if t.is_empty() {
            break;
        }
        if let Some(v) = t.strip_prefix("content-length:") {
            len = v.trim().parse().ok();
        }
        if t.starts_with("transfer-encoding:") && t.contains("chunked") {
            chunked = true;
        }
    }
    if chunked {
        loop {
            let mut l = String::new();
            if r.read_line(&mut l).unwrap_or(0) == 0 {
                break;
            }
            out.extend_from_slice(l.as_bytes());
            let n = usize::from_str_radix(l.trim().split(';').next().unwrap_or(""), 16).unwrap_or(0);
            let mut c = vec![0u8; n + 2];
            if r.read_exact(&mut c).is_err() {
                break;
            }
            out.extend_from_slice(&c);
            if n == 0 {
                break;
            }
        }
    } else if let Some(n) = len {
        let mut b = vec![0u8; n];
        let _ = r.read_exact(&mut b);
        out.extend_from_slice(&b);
    } else {
        let _ = r.read_to_end(&mut out);
    }
    out
}

pub struct Capture {
    pub url: String,
    pub session: String,
    stop: Arc<AtomicBool>,
    addr: std::net::SocketAddr,
    store: Arc<Store>,
}

impl Capture {
    pub fn start(store: Arc<Store>, host: &str, port: u16, label: &str) -> Result<Capture, String> {
        let l = TcpListener::bind((host, port)).map_err(|e| format!("bind {host}:{port}: {e}"))?;
        let addr = l.local_addr().map_err(|e| e.to_string())?;
        let session = format!("cap-{}", ark_kernel::util::random_hex(6));
        store.append("sessions.jsonl", &json!({"id": session, "startedAt": now(), "label": label, "proxyUrl": format!("http://{addr}")}));
        let stop = Arc::new(AtomicBool::new(false));
        let (st, s2, sid) = (stop.clone(), store.clone(), session.clone());
        std::thread::spawn(move || {
            let mut seq = 0u64;
            for c in l.incoming() {
                if st.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(c) = c else { continue };
                seq += 1;
                let (s3, sid2, n) = (s2.clone(), sid.clone(), seq);
                std::thread::spawn(move || {
                    let _ = c.set_read_timeout(Some(Duration::from_secs(300)));
                    let _ = handle(c, &s3, &sid2, n);
                });
            }
        });
        Ok(Capture { url: format!("http://{addr}"), session, stop, addr, store })
    }
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        self.store.append("sessions.jsonl", &json!({"id": self.session, "endedAt": now()}));
    }
}

/// Built-in query presets over captured events.
pub fn query(events: &[Value], preset: &str, session: Option<&str>) -> Result<Vec<Value>, String> {
    if !PRESETS.contains(&preset) {
        return Err(format!("--preset must be one of {}", PRESETS.join(", ")));
    }
    let ev: Vec<&Value> = events.iter().filter(|e| session.is_none_or(|s| e["session"] == s)).collect();
    let ts = |e: &Value| e["ts"].as_u64().unwrap_or(0);
    let mut out = vec![];
    match preset {
        "double-sends" => {
            for (i, a) in ev.iter().enumerate() {
                if a["protocol"] != "http" || a["method"] == "GET" {
                    continue;
                }
                if let Some(b) = ev[i + 1..].iter().find(|b| b["method"] == a["method"] && b["url"] == a["url"] && b["bodyHash"] == a["bodyHash"] && ts(b).saturating_sub(ts(a)) <= 2000) {
                    out.push(json!({"first": a["id"], "second": b["id"], "method": a["method"], "url": a["url"], "gapMs": ts(b).saturating_sub(ts(a))}));
                }
            }
        }
        "retry-storms" | "error-bursts" => {
            let key = |e: &Value| if preset == "retry-storms" { format!("{} {}", e["method"].as_str().unwrap_or(""), e["url"].as_str().or(e["host"].as_str()).unwrap_or("")) } else { e["host"].as_str().unwrap_or("").to_string() };
            let want = if preset == "retry-storms" { 5 } else { 3 };
            let mut groups: std::collections::BTreeMap<String, Vec<u64>> = Default::default();
            for e in &ev {
                if preset == "error-bursts" && e["status"].as_u64().is_none_or(|s| s < 500) {
                    continue;
                }
                groups.entry(key(e)).or_default().push(ts(e));
            }
            for (k, mut t) in groups {
                t.sort();
                if let Some(w) = t.windows(want).find(|w| w[want - 1] - w[0] <= 60_000) {
                    out.push(json!({"key": k, "count": t.len(), "windowStart": w[0], "windowMs": w[want - 1] - w[0]}));
                }
            }
        }
        "cache-busting" => {
            let mut groups: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> = Default::default();
            for e in ev.iter().filter(|e| e["protocol"] == "http") {
                let url = e["url"].as_str().unwrap_or("");
                if let Some((base, q)) = url.split_once('?') {
                    groups.entry(base.to_string()).or_default().insert(q.to_string());
                }
            }
            for (base, qs) in groups.into_iter().filter(|(_, q)| q.len() >= 5) {
                out.push(json!({"url": base, "distinctQueries": qs.len()}));
            }
        }
        "missing-ack" => {
            for e in ev.iter().filter(|e| e["status"].as_u64().unwrap_or(0) == 0 || (e["protocol"] == "connect" && e["bytesDown"] == 0 && e["status"] == 200)) {
                out.push(json!({"id": e["id"], "url": e["url"].as_str().or(e["host"].as_str()), "protocol": e["protocol"]}));
            }
        }
        _ => {} // ws-duplicate-frames: frames inside CONNECT tunnels are not decrypted.
    }
    Ok(out)
}

pub fn coverage() -> Vec<Value> {
    vec![
        json!({"id": "plain-http", "label": "Plain HTTP via HTTP_PROXY", "protocols": ["http"], "status": "captured", "notes": "Request/response heads (secrets redacted), bodies as blobs, status and timing."}),
        json!({"id": "provider-https", "label": "Model provider HTTPS (ureq honours HTTPS_PROXY)", "protocols": ["https", "sse"], "status": "proxy-only", "notes": "CONNECT tunnel metadata only (host, bytes, duration); ark does not intercept TLS."}),
        json!({"id": "channels", "label": "Channel REST/long-poll (Telegram, Slack, Discord REST)", "protocols": ["https"], "status": "proxy-only", "notes": "Routed through the proxy when the env var is set; payloads stay encrypted."}),
        json!({"id": "websockets", "label": "WebSocket gateways (Discord, Slack Socket Mode)", "protocols": ["wss"], "status": "proxy-only", "notes": "Tunnel lifetime and byte counts only; frames are not decoded (ws-duplicate-frames finds nothing)."}),
        json!({"id": "child-tools", "label": "Shell tools and MCP stdio servers started by `ark proxy run`", "protocols": ["http", "https"], "status": "proxy-only", "notes": "Only clients that honour *_PROXY are covered; raw sockets bypass it."}),
    ]
}

/// Validate an operator proxy: allowed URLs must succeed through it, denied ones must fail.
pub fn validate(proxy_url: &str, allowed: &[String], denied: &[String], timeout: Duration) -> Value {
    let proxy = match ureq::Proxy::new(proxy_url) {
        Ok(p) => p,
        Err(e) => return json!({"ok": false, "proxyUrl": proxy_url, "error": format!("invalid proxy URL: {e}")}),
    };
    let agent: ureq::Agent = ureq::Agent::config_builder().proxy(Some(proxy)).http_status_as_error(false).timeout_global(Some(timeout)).build().into();
    let probe = |u: &str| -> Result<u16, String> { agent.get(u).call().map(|r| r.status().as_u16()).map_err(|e| e.to_string()) };
    let mut checks = vec![];
    let mut ok = true;
    for u in allowed {
        let r = probe(u);
        let pass = matches!(r, Ok(s) if s < 400);
        ok &= pass;
        checks.push(json!({"kind": "allowed", "url": u, "pass": pass, "status": r.as_ref().ok(), "error": r.as_ref().err()}));
    }
    for u in denied {
        let r = probe(u);
        let pass = !matches!(r, Ok(s) if s < 400);
        ok &= pass;
        checks.push(json!({"kind": "denied", "url": u, "pass": pass, "status": r.as_ref().ok(), "error": r.as_ref().err()}));
    }
    json!({"ok": ok, "proxyUrl": proxy_url, "checks": checks})
}

pub fn dispatch(cmd: &str, a: &Args, raw: &[String]) -> Option<R> {
    if cmd != "proxy" {
        return None;
    }
    Some((|| -> R {
        let paths = Paths::from_env();
        // Built on use: `validate`/`coverage`/usage errors must not create the capture store.
        let store = || Arc::new(Store::new(dir(&paths)));
        let js = a.flag("json");
        let host = a.val("host").unwrap_or("127.0.0.1");
        let port = a.num::<u16>("port")?.unwrap_or(0);
        match a.pos(0).unwrap_or("sessions") {
            "start" => {
                let c = Capture::start(store(), host, port, "start")?;
                println!("debug proxy listening on {} (session {})\nexport HTTP_PROXY={0} HTTPS_PROXY={0}\nCtrl-C to stop.", c.url, c.session);
                loop {
                    std::thread::sleep(Duration::from_secs(3600));
                }
            }
            "run" => {
                let i = raw.iter().position(|s| s == "--").ok_or("usage: ark proxy run [--host H] [--port P] -- <command…>")?;
                let argv = &raw[i + 1..];
                if argv.is_empty() {
                    return crate::usage("usage: ark proxy run -- <command…>");
                }
                let c = Capture::start(store(), host, port, &argv.join(" "))?;
                eprintln!("capturing through {} (session {})", c.url, c.session);
                let st = std::process::Command::new(&argv[0]).args(&argv[1..]).env("HTTP_PROXY", &c.url).env("HTTPS_PROXY", &c.url).env("ALL_PROXY", &c.url).env("http_proxy", &c.url).env("https_proxy", &c.url).env_remove("NO_PROXY").env_remove("no_proxy").status();
                c.stop();
                eprintln!("capture session {} saved; inspect with `ark proxy query --session {} --preset error-bursts`", c.session, c.session);
                Ok(st.map_err(|e| format!("{}: {e}", argv[0]))?.code().unwrap_or(1))
            }
            "sessions" => {
                let limit = a.num::<usize>("limit")?.unwrap_or(20);
                let store = store();
                let ev = store.events();
                let mut merged: Vec<Value> = vec![];
                for s in store.sessions() {
                    match merged.iter_mut().find(|m| m["id"] == s["id"]) {
                        Some(m) => {
                            if let Some(e) = s.get("endedAt") {
                                m["endedAt"] = e.clone();
                            }
                        }
                        None => merged.push(s),
                    }
                }
                for m in &mut merged {
                    m["events"] = json!(ev.iter().filter(|e| e["session"] == m["id"]).count());
                }
                merged.reverse();
                merged.truncate(limit);
                if js {
                    println!("{}", json!({"sessions": merged}));
                } else if merged.is_empty() {
                    println!("no capture sessions (start one with `ark proxy run -- <cmd>`)");
                } else {
                    for m in merged {
                        println!("{}  {} events  {}", m["id"].as_str().unwrap_or(""), m["events"], m["label"].as_str().unwrap_or(""));
                    }
                }
                Ok(0)
            }
            "query" => {
                let preset = a.val("preset").ok_or("--preset is required")?;
                let r = query(&store().events(), preset, a.val("session"))?;
                if js {
                    println!("{}", json!({"preset": preset, "results": r}));
                } else if r.is_empty() {
                    println!("no {preset} found");
                } else {
                    for x in r {
                        println!("{x}");
                    }
                }
                Ok(0)
            }
            "blob" => {
                let id = a.val("id").ok_or("--id <blobId> is required")?;
                if !(id.len() == 24 && id.bytes().all(|b| b.is_ascii_hexdigit())) {
                    return Err("invalid blob id".into());
                }
                let b = std::fs::read(dir(&paths).join("blobs").join(id)).map_err(|_| format!("no blob {id}"))?;
                std::io::stdout().write_all(&b).map_err(|e| e.to_string())?;
                Ok(0)
            }
            "purge" => {
                let _ = std::fs::remove_dir_all(dir(&paths));
                println!("deleted all captured traffic metadata and blobs");
                Ok(0)
            }
            "coverage" => {
                let c = coverage();
                if js {
                    println!("{}", json!({"entries": c}));
                } else {
                    for e in c {
                        println!("{:<12} {:<60} {}", e["status"].as_str().unwrap_or(""), e["label"].as_str().unwrap_or(""), e["notes"].as_str().unwrap_or(""));
                    }
                }
                Ok(0)
            }
            "validate" => {
                let url = a.val("proxy-url").map(String::from).or_else(|| std::env::var("HTTPS_PROXY").ok()).or_else(|| std::env::var("HTTP_PROXY").ok()).ok_or("no proxy to validate: pass --proxy-url or set HTTPS_PROXY")?;
                let t = Duration::from_millis(a.num::<u64>("timeout-ms")?.unwrap_or(10_000));
                let mut allowed = a.vals("allowed-url");
                if allowed.is_empty() {
                    allowed.push("https://api.github.com/".into());
                }
                let v = validate(&url, &allowed, &a.vals("denied-url"), t);
                if js {
                    println!("{v}");
                } else {
                    for c in v["checks"].as_array().into_iter().flatten() {
                        println!("{} {} {}", if c["pass"] == true { "ok  " } else { "FAIL" }, c["kind"].as_str().unwrap_or(""), c["url"].as_str().unwrap_or(""));
                    }
                    if let Some(e) = v["error"].as_str() {
                        println!("{e}");
                    }
                }
                Ok(if v["ok"] == true { 0 } else { 1 })
            }
            other => crate::usage(format!("unknown `proxy {other}` (start | run -- <cmd> | sessions | query --preset P | blob --id ID | purge | coverage | validate)")),
        }
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::net::fake;

    #[test]
    fn captures_http_and_connect_and_queries() {
        let kit = crate::testkit::kit();
        let store = Arc::new(Store::new(dir(&kit.paths)));
        let (origin, _log) = fake::serve(Arc::new(|r: &fake::Req| if r.path.starts_with("/err") { (503, "text/plain".into(), b"down".to_vec()) } else { (200, "text/plain".into(), format!("echo {}", String::from_utf8_lossy(&r.body)).into_bytes()) }));
        let cap = Capture::start(store.clone(), "127.0.0.1", 0, "test").unwrap();
        let proxy_addr = cap.url.trim_start_matches("http://").to_string();
        let send = |req: String| -> String {
            let mut s = TcpStream::connect(&proxy_addr).unwrap();
            s.write_all(req.as_bytes()).unwrap();
            let mut out = String::new();
            let _ = s.read_to_string(&mut out);
            out
        };
        let o = origin.trim_start_matches("http://").to_string();
        let r = send(format!("POST {origin}/hello HTTP/1.1\r\nhost: {o}\r\nauthorization: Bearer sk-secret\r\ncontent-length: 5\r\n\r\nbody1"));
        assert!(r.starts_with("HTTP/1.1 200") && r.ends_with("echo body1"), "{r}");
        send(format!("POST {origin}/hello HTTP/1.1\r\nhost: {o}\r\ncontent-length: 5\r\n\r\nbody1"));
        for i in 0..3 {
            assert!(send(format!("GET {origin}/err?n={i} HTTP/1.1\r\nhost: {o}\r\n\r\n")).contains(" 503 "));
        }
        // CONNECT tunnel to the origin (plain TCP behind it)
        let mut s = TcpStream::connect(&proxy_addr).unwrap();
        write!(s, "CONNECT {o} HTTP/1.1\r\nhost: {o}\r\n\r\n").unwrap();
        let mut br = BufReader::new(s.try_clone().unwrap());
        let mut l = String::new();
        br.read_line(&mut l).unwrap();
        assert!(l.contains("200"));
        br.read_line(&mut l).unwrap();
        write!(s, "GET /t HTTP/1.1\r\nhost: x\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").unwrap();
        let mut rest = String::new();
        let _ = br.read_line(&mut rest);
        assert!(rest.contains("200"));
        drop(br);
        let _ = s.shutdown(Shutdown::Both);
        std::thread::sleep(Duration::from_millis(300));
        cap.stop();

        let ev = store.events();
        let http: Vec<&Value> = ev.iter().filter(|e| e["protocol"] == "http").collect();
        assert_eq!(http.len(), 5, "{ev:?}");
        let first = http.iter().find(|e| e["requestHeaders"].to_string().contains("authorization")).unwrap();
        assert!(first["requestHeaders"].to_string().contains("[REDACTED]") && !first["requestHeaders"].to_string().contains("sk-secret"));
        let blob = std::fs::read_to_string(dir(&kit.paths).join("blobs").join(first["responseBlob"].as_str().unwrap())).unwrap();
        assert_eq!(blob, "echo body1");
        assert!(ev.iter().any(|e| e["protocol"] == "connect" && e["bytesUp"].as_u64().unwrap() > 0));
        assert_eq!(query(&ev, "double-sends", None).unwrap().len(), 1);
        assert_eq!(query(&ev, "error-bursts", None).unwrap().len(), 1);
        assert!(query(&ev, "retry-storms", None).unwrap().is_empty());
        assert!(query(&ev, "nope", None).is_err());
        assert_eq!(query(&ev, "double-sends", Some("other")).unwrap().len(), 0);
        assert!(store.sessions().iter().any(|s| s["endedAt"].is_u64()));
        assert!(coverage().iter().any(|c| c["status"] == "captured"));
    }

    #[test]
    fn validate_allowed_and_denied() {
        let (origin, _) = fake::serve(Arc::new(|_: &fake::Req| (200, "text/plain".into(), b"ok".to_vec())));
        let kit = crate::testkit::kit();
        let cap = Capture::start(Arc::new(Store::new(dir(&kit.paths))), "127.0.0.1", 0, "v").unwrap();
        let v = validate(&cap.url, &[format!("{origin}/a")], &["http://127.0.0.1:1/".into()], Duration::from_secs(5));
        assert_eq!(v["ok"], true, "{v}");
        let v = validate(&cap.url, &["http://127.0.0.1:1/".into()], &[], Duration::from_secs(5));
        assert_eq!(v["ok"], false);
        assert!(validate("::bad::", &[], &[], Duration::from_secs(1))["error"].is_string());
        cap.stop();
    }

    #[test]
    fn dispatch_is_reachable_and_reports_usage() {
        let raw = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // `ops::dispatch` (MODULES order in ops/mod.rs) routes `proxy` here, before main.rs.
        let a = Args::parse(&["bogus".into()]).unwrap();
        let r = crate::ops::dispatch("proxy", &a, &raw(&["proxy", "bogus"])).expect("`proxy` is owned by ops::proxy");
        assert!(matches!(r, Err(crate::Fail::Usage(m)) if m.contains("unknown `proxy bogus`")));
        let a = Args::parse(&["run".into()]).unwrap();
        match crate::ops::dispatch("proxy", &a, &raw(&["proxy", "run"])) {
            Some(Err(e)) => assert!(e.to_string().contains("usage: ark proxy run"), "{e}"),
            _ => panic!("`proxy run` without -- must be refused"),
        }
        let a = Args::parse(&["query".into()]).unwrap();
        match crate::ops::dispatch("proxy", &a, &raw(&["proxy", "query"])) {
            Some(Err(e)) => assert!(e.to_string().contains("--preset is required"), "{e}"),
            _ => panic!("`proxy query` without --preset must be refused"),
        }
        // Commands this module does not own fall through.
        assert!(dispatch("dns", &Args::parse(&[]).unwrap(), &[]).is_none());
    }
}
