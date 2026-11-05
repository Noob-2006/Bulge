//! A scriptable fake DevTools endpoint for the meeting tests (`/json/version`, `/json/list` and a
//! browser-level WebSocket whose replies come from a handler).
//!
//! It mirrors `ark_browser::cdp::fake`, which is `#[cfg(test)]` inside ark-browser and therefore
//! not reachable from this crate's tests. `ark_net::ws` does the framing.

use ark_net::ws::Message;
use serde_json::{json, Value};
use std::io::Write;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

/// Handler: (method, params, sessionId) → (result, extra events to emit after it).
pub type Script = Arc<dyn Fn(&str, &Value, Option<&str>) -> (Value, Vec<Value>) + Send + Sync>;

pub struct Fake {
    pub http: String,
    pub seen: Arc<Mutex<Vec<Value>>>,
}

pub fn start(script: Script) -> Fake {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { break };
            let script = script.clone();
            let seen = seen2.clone();
            std::thread::spawn(move || {
                let Ok((head, rest)) = ark_net::ws::read_head(&mut s, 1 << 16) else { return };
                if head.starts_with("GET /json/version") {
                    let body = json!({"Browser": "FakeChrome/1.0", "webSocketDebuggerUrl": format!("ws://127.0.0.1:{port}/devtools/browser/fake")}).to_string();
                    let _ = write!(s, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                    return;
                }
                if head.starts_with("GET /json") {
                    let (r, _) = script("http:/json/list", &Value::Null, None);
                    let body = r.to_string();
                    let _ = write!(s, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                    return;
                }
                let Ok(mut ws) = ark_net::ws::WebSocket::accept(s, &head, rest) else { return };
                ws.set_max_message(64 << 20);
                while let Ok(m) = ws.recv_blocking() {
                    let Message::Text(t) = m else { break };
                    let v: Value = serde_json::from_str(&t).unwrap();
                    seen.lock().unwrap().push(v.clone());
                    let (result, events) = script(v["method"].as_str().unwrap_or(""), &v["params"], v["sessionId"].as_str());
                    let mut reply = json!({"id": v["id"], "result": result});
                    if let Some(sid) = v.get("sessionId") {
                        reply["sessionId"] = sid.clone();
                    }
                    if ws.send_text(&reply.to_string()).is_err() {
                        break;
                    }
                    for e in events {
                        if ws.send_text(&e.to_string()).is_err() {
                            break;
                        }
                    }
                }
            });
        }
    });
    Fake { http: format!("http://127.0.0.1:{port}"), seen }
}
