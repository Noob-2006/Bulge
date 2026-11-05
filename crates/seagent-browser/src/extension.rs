//! Browser-extension relay (Hermes `browser_extension_router.py`, OpenClaw
//! `extension-relay`, MIT): the seagent extension (ui/browser-extension) runs in the
//! user's own Chrome, drives tabs with `chrome.debugger`, and connects here over a
//! loopback WebSocket. seagent's CDP client connects to the same relay; the relay pumps
//! messages between them, so every browser tool works on the user's real tabs.
//!
//! - `ws://127.0.0.1:<port>/extension`: the extension; first frame
//!   `{"type":"hello","token":"…","version":1}`, answered `{"type":"welcome"}`.
//! - `ws://127.0.0.1:<port>/cdp`: seagent, `Authorization: Bearer <token>`.

use crate::config::BrowserConfig;
use crate::util;
use seagent_net::ws::{Message, WebSocket};
use serde_json::{json, Value};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const DEFAULT_PORT: u16 = 18792;

struct Relay {
    port: u16,
    token: String,
    ext: Mutex<Option<WebSocket<TcpStream>>>,
    ext_info: Mutex<Value>,
}

static RELAY: OnceLock<Arc<Relay>> = OnceLock::new();

/// The pairing token (created once, `<browser dir>/extension-token`, 0600).
pub fn token(dir: &Path) -> Result<String, String> {
    let p = dir.join("extension-token");
    if let Ok(t) = std::fs::read_to_string(&p) {
        if t.trim().len() >= 16 {
            return Ok(t.trim().to_string());
        }
    }
    let t = seagent_net::crypto::random_token(24);
    util::write_private(&p, t.as_bytes()).map_err(|e| e.to_string())?;
    Ok(t)
}

fn ensure(cfg: &BrowserConfig, dir: &Path) -> Result<Arc<Relay>, String> {
    if let Some(r) = RELAY.get() {
        return Ok(r.clone());
    }
    let port = if cfg.extension_control.port == 0 { DEFAULT_PORT } else { cfg.extension_control.port };
    let l = TcpListener::bind(("127.0.0.1", port)).map_err(|e| format!("extension relay: cannot listen on 127.0.0.1:{port}: {e}"))?;
    let port = l.local_addr().map(|a| a.port()).unwrap_or(port);
    let r = Arc::new(Relay { port, token: token(dir)?, ext: Mutex::new(None), ext_info: Mutex::new(Value::Null) });
    let r2 = r.clone();
    std::thread::Builder::new()
        .name("seagent-ext-relay".into())
        .spawn(move || {
            for s in l.incoming().flatten() {
                let r = r2.clone();
                std::thread::spawn(move || {
                    let _ = serve(&r, s);
                });
            }
        })
        .map_err(|e| e.to_string())?;
    let _ = RELAY.set(r.clone());
    Ok(RELAY.get().unwrap().clone())
}

/// Start the relay (once) and return the CDP URL for seagent plus the token.
/// Fails when no extension is connected yet.
pub fn relay(cfg: &BrowserConfig, dir: &Path) -> Result<(String, String), String> {
    if !cfg.extension_control.enabled && cfg.backend.trim() != "extension" {
        return Err("browser extension control is disabled (set browser.extension_control.enabled = true)".into());
    }
    let r = ensure(cfg, dir)?;
    let until = Instant::now() + Duration::from_secs(3);
    while r.ext.lock().unwrap().is_none() {
        if Instant::now() >= until {
            return Err(format!("No seagent browser extension is connected to 127.0.0.1:{}. Load ui/browser-extension as an unpacked extension in Chrome, paste the token from {} into its options, and retry.", r.port, dir.join("extension-token").display()));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok((format!("ws://127.0.0.1:{}/cdp", r.port), r.token.clone()))
}

/// Relay listener status (for `seagent browser status` / doctor).
pub fn status() -> Value {
    match RELAY.get() {
        Some(r) => json!({"listening": r.port, "extension_connected": r.ext.lock().unwrap().is_some(), "extension": r.ext_info.lock().unwrap().clone()}),
        None => json!({"listening": null}),
    }
}

/// Start listening without requiring a connected extension (CLI `seagent browser extension`).
pub fn listen(cfg: &BrowserConfig, dir: &Path) -> Result<u16, String> {
    ensure(cfg, dir).map(|r| r.port)
}

fn serve(r: &Relay, mut s: TcpStream) -> Result<(), String> {
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let (head, rest) = seagent_net::ws::read_head(&mut s, 1 << 16).map_err(|e| e.to_string())?;
    let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
    // Pages could open ws://127.0.0.1 too: only extensions (chrome-extension:// origin) or seagent (no origin).
    let origin = seagent_net::ws::header(&head, "origin").unwrap_or("");
    if path.starts_with("/extension") {
        if !origin.is_empty() && !origin.starts_with("chrome-extension://") {
            use std::io::Write;
            let _ = s.write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n");
            return Ok(());
        }
        let mut ws = WebSocket::accept(s, &head, rest).map_err(|e| e.to_string())?;
        ws.set_max_message(256 << 20);
        let hello = match ws.recv_blocking().map_err(|e| e.to_string())? {
            Message::Text(t) => serde_json::from_str::<Value>(&t).unwrap_or_default(),
            _ => Value::Null,
        };
        if hello["type"] != "hello" || !seagent_net::crypto::ct_eq(hello["token"].as_str().unwrap_or("").as_bytes(), r.token.as_bytes()) {
            let _ = ws.send_text(&json!({"type": "error", "error": "bad token"}).to_string());
            let _ = ws.send(&Message::Close(Some((4401, "bad token".into()))));
            return Ok(());
        }
        ws.send_text(&json!({"type": "welcome", "version": 1}).to_string()).map_err(|e| e.to_string())?;
        ws.get_ref().set_read_timeout(Some(Duration::from_millis(10))).ok();
        *r.ext_info.lock().unwrap() = json!({"version": hello["version"], "userAgent": hello["userAgent"]});
        *r.ext.lock().unwrap() = Some(ws);
        return Ok(());
    }
    if path.starts_with("/cdp") {
        let auth = seagent_net::ws::header(&head, "authorization").unwrap_or("");
        let ok = !origin.starts_with("http") && auth.strip_prefix("Bearer ").is_some_and(|t| seagent_net::crypto::ct_eq(t.as_bytes(), r.token.as_bytes()));
        if !ok {
            use std::io::Write;
            let _ = s.write_all(b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\n\r\n");
            return Ok(());
        }
        let Some(mut ext) = r.ext.lock().unwrap().take() else {
            use std::io::Write;
            let _ = s.write_all(b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n");
            return Ok(());
        };
        let mut seagent = WebSocket::accept(s, &head, rest).map_err(|e| e.to_string())?;
        seagent.set_max_message(256 << 20);
        seagent.get_ref().set_read_timeout(Some(Duration::from_millis(10))).ok();
        let _ = ext.send_text(&json!({"type": "attach"}).to_string());
        // Pump until either side closes; the extension slot is returned when seagent leaves.
        let ext_alive = loop {
            match seagent.recv() {
                Ok(Some(Message::Text(t))) => {
                    if ext.send_text(&t).is_err() {
                        break false;
                    }
                }
                Ok(Some(Message::Close(_))) | Err(_) => break true,
                _ => {}
            }
            match ext.recv() {
                Ok(Some(Message::Text(t))) => {
                    if seagent.send_text(&t).is_err() {
                        break true;
                    }
                }
                Ok(Some(Message::Close(_))) | Err(_) => {
                    let _ = seagent.send(&Message::Close(Some((1001, "extension disconnected".into()))));
                    break false;
                }
                _ => {}
            }
        };
        if ext_alive {
            let _ = ext.send_text(&json!({"type": "detach"}).to_string());
            *r.ext.lock().unwrap() = Some(ext);
        } else {
            *r.ext_info.lock().unwrap() = Value::Null;
        }
        return Ok(());
    }
    use std::io::Write;
    let _ = s.write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relays_cdp_between_seagent_and_the_extension() {
        let dir = seagent_core::tmp::scratch_path(format!("seagent-ext-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut cfg = BrowserConfig::default();
        cfg.extension_control.enabled = true;
        cfg.extension_control.port = util::free_port();
        let port = listen(&cfg, &dir).unwrap();
        let tok = token(&dir).unwrap();
        // A page origin is refused.
        let bad = WebSocket::connect(&format!("ws://127.0.0.1:{port}/extension"), &[("Origin", "https://evil.example")], Duration::from_secs(3));
        assert!(bad.is_err());
        // The fake extension: answers Target.getTargets like the real one.
        let (mut ext, _) = WebSocket::connect(&format!("ws://127.0.0.1:{port}/extension"), &[("Origin", "chrome-extension://abc")], Duration::from_secs(3)).unwrap();
        ext.send_text(&json!({"type": "hello", "token": tok, "version": 1}).to_string()).unwrap();
        assert!(matches!(ext.recv_blocking().unwrap(), Message::Text(t) if t.contains("welcome")));
        let h = std::thread::spawn(move || loop {
            let Ok(Message::Text(t)) = ext.recv_blocking() else { return };
            let v: Value = serde_json::from_str(&t).unwrap();
            if v["type"].is_string() {
                continue;
            }
            let _ = ext.send_text(&json!({"id": v["id"], "result": {"targetInfos": [{"targetId": "tab-7", "type": "page", "url": "https://mine.example/", "title": "Mine"}]}}).to_string());
        });
        let (ws, t) = relay(&cfg, &dir).unwrap();
        assert!(crate::cdp::Conn::connect(&ws, &[("Authorization", "Bearer nope")], Duration::from_secs(3)).is_err());
        let c = crate::cdp::Conn::connect(&ws, &[("Authorization", &format!("Bearer {t}"))], Duration::from_secs(3)).unwrap();
        let r = c.call("Target.getTargets", json!({}), None).unwrap();
        assert_eq!(r["targetInfos"][0]["targetId"], "tab-7");
        assert_eq!(status()["listening"], port);
        drop(h);
    }

    /// The shipped extension (ui/browser-extension) must speak exactly this relay's
    /// protocol; a manifest or a hello frame that drifts breaks pairing silently.
    #[test]
    fn the_bundled_extension_matches_the_relay_protocol() {
        let dir = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../ui/browser-extension"));
        let read = |name: &str| {
            std::fs::read_to_string(dir.join(name)).unwrap_or_else(|e| panic!("ui/browser-extension/{name}: {e}"))
        };

        let manifest: Value = serde_json::from_str(&read("manifest.json")).expect("manifest.json is not valid JSON");
        assert_eq!(manifest["manifest_version"], 3, "MV3 is required for a service worker");
        let worker = manifest["background"]["service_worker"].as_str().unwrap_or("");
        assert!(!worker.trim().is_empty(), "background.service_worker must be set");
        assert!(dir.join(worker).is_file(), "background.service_worker {worker} must exist");
        assert_eq!(manifest["options_ui"]["page"], "options.html");
        assert_eq!(manifest["action"]["default_popup"], "popup.html");
        let perms: Vec<&str> = manifest["permissions"].as_array().map(|a| a.iter().filter_map(|p| p.as_str()).collect()).unwrap_or_default();
        for need in ["debugger", "tabs", "storage", "activeTab"] {
            assert!(perms.contains(&need), "manifest permissions must include {need}");
        }

        let bg = read(worker);
        for needle in ["/extension", "\"hello\"", "\"welcome\"", "Target.attachToTarget", "chrome.debugger.sendCommand"] {
            assert!(bg.contains(needle), "background.js must contain {needle}");
        }
        assert!(
            bg.contains("version: 1") || bg.contains("\"version\":1"),
            "the hello frame must announce protocol version 1"
        );
        assert!(bg.contains("chrome.debugger.attach"), "the extension must attach chrome.debugger on `attach`");
        assert!(bg.contains("Target.createTarget") && bg.contains("Target.closeTarget"), "target commands are answered by the extension");

        for page in ["options.html", "popup.html"] {
            let html = read(page);
            let js = page.replace(".html", ".js");
            assert!(dir.join(&js).is_file(), "{page} must load an external {js}");
            assert!(html.contains(&format!("src=\"{js}\"")), "{page} must load {js} with a src attribute");
            for handler in ["onclick=", "onchange=", "onsubmit=", "onload="] {
                assert!(!html.contains(handler), "{page} must not use the inline handler {handler} (MV3 CSP)");
            }
            assert!(!html.contains("<script>"), "{page} must not contain an inline <script> block");
        }
        assert!(read("options.js").contains("chrome.storage.local"), "options.js must persist port/token in storage");
        assert!(read("popup.js").contains("openOptionsPage"), "popup.js must link to the options page");

        let readme = read("README.md");
        assert!(readme.contains("extension-token"), "README.md must tell the user where the token lives");
        assert!(readme.contains("seagent browser extension"), "README.md must document the relay command");
    }
}
