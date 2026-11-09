//! Device keys and the connected-devices panel in a real browser (docs/SECURITY.md §8;
//! `ui/web/devauth.js`, `ui/web/devsec.js`).
//!
//! Starts the real `seagent daemon run` in LAN mode with a 3 s device access-token lifetime,
//! opens the console in a real headless Chromium-family browser over CDP (Chrome, or Edge on
//! Windows) and checks: a browser pairs from a setup code with a WebCrypto key (bound,
//! `webcrypto`), renews its access token silently across several expiries while its WebSocket
//! stays up, the admin's devices panel lists it (key, address), a scope change reaches the open
//! socket, and "sign out all devices" ends it. `SEAGENT_SCREENSHOT_DIR=<dir>` saves a screenshot
//! of the devices panel there.
//!
//! `#[ignore]`; run with `SEAGENT_REAL_TESTS=1 cargo test -p seagent --test webui_devices -- --ignored`.

use seagent_browser::cdp::Conn;
use seagent_core::proc::{spawn_tied, wait_until, ChildGuard, PidGuard};
use seagent_core::tmp::TempDir;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

const ADMIN: &str = "webui-devices-admin-0001";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn http(port: u16, method: &str, path: &str, token: Option<&str>, body: &str) -> (u16, String) {
    let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", port)) else { return (0, String::new()) };
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    let auth = token.map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
    let _ = write!(s, "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out).to_string();
    let status = text.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    (status, text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default())
}

fn arp(port: u16, method: &str, params: Value) -> Value {
    let (st, body) = http(port, "POST", "/arp", Some(ADMIN), &json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string());
    assert_eq!(st, 200, "{method}: {body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert!(v.get("error").is_none(), "{method}: {v}");
    v["result"].clone()
}

struct Page {
    conn: Conn,
    sid: String,
}

impl Page {
    fn eval(&self, expr: &str) -> Value {
        let r = self.conn.call_with("Runtime.evaluate", json!({"expression": expr, "awaitPromise": true, "returnByValue": true}), Some(&self.sid), Duration::from_secs(30), &|| None).unwrap_or_else(|e| panic!("{expr}: {e}"));
        if let Some(ex) = r.get("exceptionDetails") {
            return json!({"__exception": ex["exception"]["description"].as_str().or(ex["text"].as_str()).unwrap_or("?")});
        }
        r["result"]["value"].clone()
    }
    fn until(&self, what: &str, expr: &str, secs: u64) {
        if !wait_until(Duration::from_secs(secs), || self.eval(expr) == json!(true)) {
            let state = self.eval("JSON.stringify({url: location.href, conn: (document.getElementById('conn') || {}).textContent, me: typeof S !== 'undefined' ? S.me : 'no S', body: document.body ? document.body.innerText.slice(0, 300) : ''})");
            panic!("timed out waiting for {what} ({expr}); page: {state}");
        }
    }
}

fn open_page(conn: &Conn, url: &str) -> Page {
    let t = conn.call("Target.createTarget", json!({"url": "about:blank"}), None).unwrap();
    let sid = conn.call("Target.attachToTarget", json!({"targetId": t["targetId"], "flatten": true}), None).unwrap()["sessionId"].as_str().unwrap().to_string();
    for m in ["Runtime.enable", "Page.enable"] {
        conn.call(m, json!({}), Some(&sid)).unwrap();
    }
    let _ = conn.call("Emulation.setDeviceMetricsOverride", json!({"width": 1280, "height": 900, "deviceScaleFactor": 1, "mobile": false}), Some(&sid));
    conn.call("Page.navigate", json!({"url": url}), Some(&sid)).unwrap();
    Page { conn: conn.clone(), sid }
}

fn daemon(home: &Path, ws: &Path, port: u16) -> ChildGuard {
    std::fs::create_dir_all(home.join("config")).unwrap();
    let ws_s = ws.display().to_string().replace('\\', "/");
    std::fs::write(
        home.join("config/config.toml"),
        format!(
            r#"[model]
default = "fake/fake-model"
[providers.fake]
format = "openai_chat"
base_url = "http://127.0.0.1:9/v1"
api_key_env = "FAKE_KEY"
[exec]
backend = "local"
[app]
enabled = true
listen = "127.0.0.1:{port}"
token = "{ADMIN}"
workspace = "{ws_s}"
discovery = "off"
[app.exposure]
lan = true
device_access_ttl_secs = 3
"#
        ),
    )
    .unwrap();
    let log = std::fs::File::create(home.join("daemon.log")).unwrap();
    let mut c = Command::new(env!("CARGO_BIN_EXE_seagent"));
    c.args(["daemon", "run"]).current_dir(ws).env("SEAGENT_HOME", home).env("SEAGENT_OFFLINE", "1").env("FAKE_KEY", "x").env("XDG_RUNTIME_DIR", "").env_remove("OPENAI_API_KEY").env_remove("ANTHROPIC_API_KEY").stdin(Stdio::null()).stdout(log.try_clone().unwrap()).stderr(log);
    ChildGuard::group(spawn_tied(c, true).expect("spawn seagentd"))
}

#[test]
#[ignore]
fn real_device_keys_renewal_and_devices_panel() {
    if std::env::var("SEAGENT_REAL_TESTS").ok().as_deref() != Some("1") {
        eprintln!("skipping: set SEAGENT_REAL_TESTS=1");
        return;
    }
    let exe = seagent_browser::launch::find_executable("").expect("SEAGENT_REAL_TESTS=1 needs a Chromium-family browser (Chrome / Edge)");
    let root = TempDir::new("seagent-webui-devices");
    let (home, ws) = (root.path().join("home"), root.path().join("ws"));
    std::fs::create_dir_all(&ws).unwrap();
    let port = free_port();
    let _d = daemon(&home, &ws, port);
    let log = || std::fs::read_to_string(home.join("daemon.log")).unwrap_or_default();
    assert!(wait_until(Duration::from_secs(60), || http(port, "GET", "/health", None, "").0 == 200), "app server never answered: {}", log());

    let profile = root.path().join("browser");
    let o = seagent_browser::launch::LaunchOpts { exe: &exe, user_data_dir: &profile, headless: true, no_sandbox: false, extra_args: &[], port: 0, managed: true, env: vec![] };
    let l = seagent_browser::launch::launch(&o, Duration::from_secs(30)).expect("launch the browser");
    let _b = PidGuard(l.pid);
    let conn = Conn::connect(&l.ws, &[], Duration::from_secs(10)).unwrap();
    let base = format!("http://127.0.0.1:{port}");

    // ── pair this browser from a setup code: a WebCrypto key is bound ──
    let offer = arp(port, "devices.pair.create", json!({"ttlMin": 5}));
    let dev = open_page(&conn, &format!("{base}/#setup={}", offer["setupCode"].as_str().unwrap()));
    dev.until("paired and connected", "typeof S !== 'undefined' && !!S.me && S.me.kind === 'device'", 60);
    let devices = arp(port, "devices.list", json!({}))["devices"].clone();
    assert_eq!(devices.as_array().unwrap().len(), 1, "{devices}");
    let d = &devices[0];
    assert_eq!((d["keyBound"].clone(), d["keyStore"].clone(), d["platform"].clone()), (json!(true), json!("webcrypto"), json!("web")), "{d}");
    let id = d["id"].as_str().unwrap().to_string();
    assert!(dev.eval("localStorage.getItem('seagent.token')").as_str().is_some_and(|t| t.starts_with("sed1_")), "the console token is stored");
    let first = dev.eval("DevAuth.current()");
    assert!(first.as_str().is_some_and(|t| t.starts_with("sea1_")), "and an access token is used: {first}");
    // The stored console token alone is useless as a bearer.
    let stolen = dev.eval("localStorage.getItem('seagent.token')").as_str().unwrap().to_string();
    assert_eq!(http(port, "POST", "/arp", Some(&stolen), &json!({"jsonrpc": "2.0", "id": 1, "method": "session.list"}).to_string()).0, 401);

    // ── silent renewal over several 3 s lifetimes; the socket never drops ──
    dev.eval("window.__ws0 = S.arp.ws; window.__closes = 0; S.arp.ws.addEventListener('close', () => window.__closes++); true");
    dev.until("three renewals", "DevAuth.renewals >= 3", 30);
    assert_eq!(dev.eval("S.arp.ws === window.__ws0 && window.__closes === 0"), json!(true), "the WebSocket stayed up across every expiry");
    assert_ne!(dev.eval("DevAuth.current()"), first, "a new access token");
    assert_eq!(dev.eval("S.arp.call('session.list').then(() => true, (e) => e.message)"), json!(true));
    assert_eq!(dev.eval("fetch('/arp', {method: 'POST', headers: {'content-type': 'application/json', authorization: 'Bearer ' + DevAuth.current()}, body: JSON.stringify({jsonrpc: '2.0', id: 2, method: 'session.list'})}).then(r => r.status)"), json!(200), "the renewed token works on new requests");
    assert_eq!(http(port, "POST", "/arp", first.as_str(), &json!({"jsonrpc": "2.0", "id": 1, "method": "session.list"}).to_string()).0, 401, "the first one has expired");

    // ── the admin's devices panel ──
    let admin = open_page(&conn, &format!("{base}/#token={ADMIN}"));
    admin.until("admin connected", "typeof S !== 'undefined' && !!S.me && !!S.arp", 60);
    admin.eval("document.querySelector('.nav-item[data-view=devices]').click(); true");
    admin.until("the devices panel", &format!("!!document.querySelector('#devSec [data-devsec-scope=\"{id}\"]') && !!document.querySelector('#devSecEvents .slist, #devSecEvents .none')"), 30);
    let panel = admin.eval("document.getElementById('devSec').innerText");
    for want in ["Browser on", "127.0.0.1"] {
        assert!(panel.as_str().is_some_and(|t| t.contains(want)), "{want} in {panel}");
    }
    if let Some(dir) = std::env::var_os("SEAGENT_SCREENSHOT_DIR") {
        admin.eval("document.getElementById('devSec').scrollIntoView(); true");
        std::thread::sleep(Duration::from_millis(300));
        let shot = conn.call("Page.captureScreenshot", json!({"format": "png"}), Some(&admin.sid)).unwrap();
        let png = seagent_net::crypto::b64_decode(shot["data"].as_str().unwrap()).unwrap();
        let p = Path::new(&dir).join("devices-panel.png");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&p, png).unwrap();
        eprintln!("screenshot: {}", p.display());
    }

    // ── scope change from the panel reaches the open socket ──
    admin.eval(&format!("(() => {{ const s = document.querySelector('[data-devsec-scope=\"{id}\"]'); s.value = 'read'; s.dispatchEvent(new Event('change')); return true; }})()"));
    assert!(wait_until(Duration::from_secs(10), || arp(port, "devices.list", json!({}))["devices"][0]["scope"] == "read"), "scope saved");
    dev.until("view only on the open socket", "S.arp.call('session.create', {}).then(() => false, (e) => /forbidden/.test(e.message))", 10);
    assert_eq!(dev.eval("S.arp.ws === window.__ws0"), json!(true), "without a reconnect");

    // ── sign out all devices ──
    admin.eval("window.confirm = () => true; document.querySelector('[data-devsec-signout]').click(); true");
    assert!(wait_until(Duration::from_secs(10), || arp(port, "devices.list", json!({}))["devices"].as_array().is_some_and(|a| a.is_empty())), "every device removed");
    dev.until("the device is signed out and asked to pair again", "window.__closes > 0 && DevAuth.revoked === true && document.getElementById('login').open", 60);
    let audit = arp(port, "audit.query", json!({"kind": "device.revoke_all"}));
    assert!(audit.as_array().is_some_and(|a| !a.is_empty()), "{audit}");
    conn.close();
}
