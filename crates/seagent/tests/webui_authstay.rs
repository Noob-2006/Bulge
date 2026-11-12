//! The console stays signed in, silently, in a real browser (`ui/web/app.js` start / reauth /
//! askToken, `ui/web/devauth.js`; docs/SECURITY.md §8).
//!
//! Starts the real `seagent daemon run` (LAN mode, a 3 s device access-token lifetime) and opens
//! the console in a real headless Chromium-family browser over CDP (Chrome, or Edge on Windows):
//!
//! * a paired browser (WebCrypto device key) whose tab is frozen — the extreme form of background
//!   timer throttling, and what a sleeping laptop looks like to the page — for many token
//!   lifetimes, then resumed: it renews and keeps working without a prompt; frozen again while
//!   the daemon restarts underneath it (its socket dies, its token was minted by the old process):
//!   it reconnects by itself; a jump of the page's wall clock (sleep / clock change) renews
//!   without a renewal loop; revoking the device still signs it out at once;
//! * the console inside the SE Agent app (the Tauri bridge `console_access_token`, stubbed here
//!   exactly as the app answers): a stale token in the address bar, a token rotated while the page
//!   is open plus a daemon restart, a bridge that fails for a while, and a page with no token at
//!   all — the login dialog is never shown, not once;
//! * a plain browser with a refused app token: the dialog says why, the 連線 button reports a
//!   wrong token and an unreachable host in Chinese, and connects with the right one.
//!
//! `SEAGENT_SCREENSHOT_DIR=<dir>` saves screenshots there. `#[ignore]`; run with
//! `SEAGENT_REAL_TESTS=1 cargo test -p seagent --test webui_authstay -- --ignored`.

use seagent_browser::cdp::Conn;
use seagent_core::proc::{spawn_tied, wait_until, ChildGuard, PidGuard};
use seagent_core::tmp::TempDir;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const ADMIN: &str = "webui-authstay-admin-0001";
const ROTATED: &str = "webui-authstay-rotated-0002";

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

fn arp(port: u16, token: &str, method: &str, params: Value) -> Value {
    let (st, body) = http(port, "POST", "/arp", Some(token), &json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string());
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
            panic!("timed out waiting for {what} ({expr}); page: {}", self.state());
        }
    }
    fn state(&self) -> Value {
        self.eval("JSON.stringify({url: location.href, conn: (document.getElementById('conn') || {}).textContent, login: !!(document.getElementById('login') || {}).open, shown: window.__loginShown, status: (document.getElementById('loginStatus') || {}).textContent, bridge: window.__bridgeCalls, renewals: window.DevAuth && DevAuth.renewals})")
    }
    /// The page answers a request over its live socket.
    fn works(&self) -> bool {
        self.eval("(typeof S !== 'undefined' && S.arp) ? Promise.race([S.arp.call('session.list').then(() => true, () => false), new Promise((r) => setTimeout(() => r(false), 4000))]) : false") == json!(true)
    }
    fn lifecycle(&self, state: &str) {
        self.conn.call("Page.setWebLifecycleState", json!({"state": state}), Some(&self.sid)).unwrap_or_else(|e| panic!("Page.setWebLifecycleState {state}: {e}"));
    }
    fn shot(&self, name: &str) {
        let Some(dir) = std::env::var_os("SEAGENT_SCREENSHOT_DIR") else { return };
        std::thread::sleep(Duration::from_millis(300));
        let shot = self.conn.call("Page.captureScreenshot", json!({"format": "png"}), Some(&self.sid)).unwrap();
        let png = seagent_net::crypto::b64_decode(shot["data"].as_str().unwrap()).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        let p = Path::new(&dir).join(format!("{name}.png"));
        std::fs::write(&p, png).unwrap();
        eprintln!("screenshot: {}", p.display());
    }
}

/// A page with `init` run before every document's own scripts.
fn open_page(conn: &Conn, init: &str, url: &str) -> Page {
    let t = conn.call("Target.createTarget", json!({"url": "about:blank"}), None).unwrap();
    let sid = conn.call("Target.attachToTarget", json!({"targetId": t["targetId"], "flatten": true}), None).unwrap()["sessionId"].as_str().unwrap().to_string();
    for m in ["Runtime.enable", "Page.enable"] {
        conn.call(m, json!({}), Some(&sid)).unwrap();
    }
    let _ = conn.call("Emulation.setDeviceMetricsOverride", json!({"width": 1280, "height": 860, "deviceScaleFactor": 1, "mobile": false}), Some(&sid));
    conn.call("Page.addScriptToEvaluateOnNewDocument", json!({"source": format!("{COUNT_LOGIN}\n{init}")}), Some(&sid)).unwrap();
    conn.call("Page.navigate", json!({"url": url}), Some(&sid)).unwrap();
    Page { conn: conn.clone(), sid }
}

/// Counts every time the login dialog is opened, from the first script on.
const COUNT_LOGIN: &str = "(() => { const o = HTMLDialogElement.prototype.showModal; window.__loginShown = 0; HTMLDialogElement.prototype.showModal = function () { if (this.id === 'login') window.__loginShown++; return o.call(this); }; })();";

/// The SE Agent app's bridge as the app answers it: `console_access_token` → the local agent's
/// current console token (here: whatever the test put in sessionStorage `__appToken`; none = the
/// app cannot mint one right now, e.g. its agent is restarting).
const FAKE_TAURI: &str = "window.__bridgeCalls = 0; window.__TAURI__ = { core: { invoke: async (cmd) => { if (cmd !== 'console_access_token') throw new Error('not allowed: ' + cmd); window.__bridgeCalls++; const t = sessionStorage.getItem('__appToken'); if (!t) throw new Error('the agent is restarting'); return { token: t, expiresAtMs: 0 }; } } };";

struct Daemon {
    home: std::path::PathBuf,
    ws: std::path::PathBuf,
    port: u16,
    child: Option<ChildGuard>,
}

impl Daemon {
    fn start(&mut self, token: &str) {
        std::fs::create_dir_all(self.home.join("config")).unwrap();
        let ws_s = self.ws.display().to_string().replace('\\', "/");
        std::fs::write(
            self.home.join("config/config.toml"),
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
token = "{token}"
workspace = "{ws_s}"
discovery = "off"
[app.exposure]
lan = true
device_access_ttl_secs = 3
"#,
                port = self.port
            ),
        )
        .unwrap();
        let log = std::fs::OpenOptions::new().create(true).append(true).open(self.home.join("daemon.log")).unwrap();
        let mut c = Command::new(env!("CARGO_BIN_EXE_seagent"));
        c.args(["daemon", "run"]).current_dir(&self.ws).env("SEAGENT_HOME", &self.home).env("SEAGENT_OFFLINE", "1").env("FAKE_KEY", "x").env("XDG_RUNTIME_DIR", "").env_remove("OPENAI_API_KEY").env_remove("ANTHROPIC_API_KEY").stdin(Stdio::null()).stdout(log.try_clone().unwrap()).stderr(log);
        self.child = Some(ChildGuard::group(spawn_tied(c, true).expect("spawn seagentd")));
        let port = self.port;
        assert!(wait_until(Duration::from_secs(60), || http(port, "GET", "/health", None, "").0 == 200), "app server never answered: {}", self.log());
    }
    fn stop(&mut self) {
        self.child = None;
        let port = self.port;
        assert!(wait_until(Duration::from_secs(30), || http(port, "GET", "/health", None, "").0 == 0), "the daemon did not stop");
    }
    fn log(&self) -> String {
        std::fs::read_to_string(self.home.join("daemon.log")).unwrap_or_default()
    }
}

#[test]
#[ignore]
fn real_console_stays_signed_in() {
    if std::env::var("SEAGENT_REAL_TESTS").ok().as_deref() != Some("1") {
        eprintln!("skipping: set SEAGENT_REAL_TESTS=1");
        return;
    }
    let exe = seagent_browser::launch::find_executable("").expect("SEAGENT_REAL_TESTS=1 needs a Chromium-family browser (Chrome / Edge)");
    let root = TempDir::new("seagent-webui-authstay");
    let mut d = Daemon { home: root.path().join("home"), ws: root.path().join("ws"), port: free_port(), child: None };
    std::fs::create_dir_all(&d.ws).unwrap();
    d.start(ADMIN);
    let port = d.port;
    let base = format!("http://127.0.0.1:{port}");

    let profile = root.path().join("browser");
    let o = seagent_browser::launch::LaunchOpts { exe: &exe, user_data_dir: &profile, headless: true, no_sandbox: false, extra_args: &[], port: 0, managed: true, env: vec![] };
    let l = seagent_browser::launch::launch(&o, Duration::from_secs(30)).expect("launch the browser");
    let _b = PidGuard(l.pid);
    let conn = Conn::connect(&l.ws, &[], Duration::from_secs(10)).unwrap();

    // ── a paired browser with a 3 s access token ──
    let offer = arp(port, ADMIN, "devices.pair.create", json!({"ttlMin": 5}));
    let dev = open_page(&conn, "", &format!("{base}/#setup={}", offer["setupCode"].as_str().unwrap()));
    dev.until("paired and connected", "typeof S !== 'undefined' && !!S.me && S.me.kind === 'device'", 60);
    let dev_id = arp(port, ADMIN, "devices.list", json!({}))["devices"][0]["id"].as_str().unwrap().to_string();

    // Frozen (no timer runs at all) for four lifetimes, then resumed: renewed, no prompt.
    let before = dev.eval("DevAuth.renewals").as_u64().unwrap();
    let token_before = dev.eval("DevAuth.current()");
    dev.lifecycle("frozen");
    std::thread::sleep(Duration::from_secs(12));
    assert_eq!(http(port, "POST", "/arp", token_before.as_str(), &json!({"jsonrpc": "2.0", "id": 1, "method": "session.list"}).to_string()).0, 401, "the token expired while the tab was frozen");
    dev.lifecycle("active");
    dev.until("renewed after the freeze", &format!("DevAuth.renewals > {before} && DevAuth.current() !== {token_before}"), 20);
    assert!(dev.works(), "the console answers after the freeze: {}", dev.state());
    dev.until("a renewed token works on a new request", "fetch('/arp', {method: 'POST', headers: {'content-type': 'application/json', authorization: 'Bearer ' + DevAuth.current()}, body: JSON.stringify({jsonrpc: '2.0', id: 2, method: 'session.list'})}).then(r => r.status === 200)", 10);

    // Frozen while the daemon restarts (a laptop asleep while the host restarts): the socket is
    // dead and the token was minted by the previous process; resumed, it reconnects by itself.
    dev.eval("window.__ws0 = S.arp.ws; true");
    dev.lifecycle("frozen");
    d.stop();
    std::thread::sleep(Duration::from_secs(4));
    d.start(ADMIN);
    std::thread::sleep(Duration::from_secs(4));
    dev.lifecycle("active");
    dev.until("a new socket after the restart", "S.arp.ws !== window.__ws0 && S.arp.ws.readyState === 1", 45);
    assert!(wait_until(Duration::from_secs(20), || dev.works()), "the console answers after the restart: {}", dev.state());

    // The page's clock jumps two hours (sleep / a clock change): renewed, and no renewal loop.
    let r0 = dev.eval("DevAuth.renewals").as_u64().unwrap();
    dev.eval("(() => { const real = Date.now.bind(Date); Date.now = () => real() + 7200000; window.dispatchEvent(new Event('focus')); return true; })()");
    dev.until("renewed after the clock jump", &format!("DevAuth.renewals > {r0}"), 20);
    std::thread::sleep(Duration::from_secs(10));
    let r1 = dev.eval("DevAuth.renewals").as_u64().unwrap();
    assert!(r1 - r0 <= 8, "no renewal loop after a clock jump: {} renewals in ~10 s of a 3 s lifetime", r1 - r0);
    assert!(dev.works(), "the console answers after the clock jump: {}", dev.state());
    assert_eq!(dev.eval("window.__loginShown"), json!(0), "the paired browser was never asked to sign in: {}", dev.state());
    dev.shot("authstay-device-after-freeze-restart-clock");

    // Revocation still takes effect at once.
    let t = Instant::now();
    arp(port, ADMIN, "devices.revoke", json!({"id": dev_id}));
    dev.until("the revoked device is asked to pair again", "DevAuth.revoked === true && document.getElementById('login').open", 30);
    assert!(t.elapsed() < Duration::from_secs(30));
    assert!(dev.eval("document.getElementById('loginStatus').textContent").as_str().is_some_and(|s| s.contains("撤銷")), "says it was revoked: {}", dev.state());
    dev.shot("authstay-device-revoked");

    // ── the console inside the SE Agent app ──
    // A stale token in the address bar (the page was opened before a rotation): never a prompt.
    let app = open_page(&conn, &format!("sessionStorage.setItem('__appToken', sessionStorage.getItem('__appToken') || '{ADMIN}'); {FAKE_TAURI}"), &format!("{base}/#token=stale-token-0000000000"));
    app.until("the app console connects through the bridge", &format!("typeof S !== 'undefined' && !!S.me && S.arp.token === '{ADMIN}' && document.getElementById('conn').classList.contains('live')"), 60);
    assert!(app.eval("window.__bridgeCalls").as_u64().unwrap() >= 1, "asked the app: {}", app.state());
    assert_eq!(app.eval("localStorage.getItem('seagent.token')"), json!(ADMIN), "and kept the working one");

    // Rotated while open, and the daemon restarted with the new one: the page asks the app again.
    d.stop();
    app.eval(&format!("sessionStorage.setItem('__appToken', '{ROTATED}'); true"));
    d.start(ROTATED);
    app.until("reconnected with the rotated token", &format!("S.arp.token === '{ROTATED}' && S.arp.ws.readyState === 1"), 45);
    assert!(wait_until(Duration::from_secs(20), || app.works()), "the app console answers after the rotation: {}", app.state());

    // The bridge cannot mint one for a while (its agent restarting) and the daemon refuses the
    // old one: the page keeps trying quietly, then connects once the bridge answers again.
    d.stop();
    app.eval("sessionStorage.removeItem('__appToken'); true");
    d.start(ADMIN);
    let calls = app.eval("window.__bridgeCalls").as_u64().unwrap();
    app.until("asked the app again (and again)", &format!("window.__bridgeCalls >= {} && !document.getElementById('conn').classList.contains('live')", calls + 2), 45);
    app.shot("authstay-app-bridge-retrying");
    app.eval(&format!("sessionStorage.setItem('__appToken', '{ADMIN}'); true"));
    app.until("connected once the bridge answers", &format!("S.arp.token === '{ADMIN}' && S.arp.ws.readyState === 1 && document.getElementById('conn').classList.contains('live')"), 45);

    // A page without any token (cleared storage, a link to `/`): the app supplies one.
    app.eval("localStorage.removeItem('seagent.token'); location.href = '/'; true");
    std::thread::sleep(Duration::from_secs(1));
    app.until("connected without any token of its own", "typeof S !== 'undefined' && !!S.me && document.getElementById('conn').classList.contains('live')", 45);
    assert_eq!(app.eval("window.__loginShown"), json!(0), "inside the app the login dialog never opened: {}", app.state());
    assert_eq!(app.eval("!!document.getElementById('logout')"), json!(false), "and there is no 'sign out this device' inside the app");
    app.shot("authstay-app-connected");

    // ── a plain browser whose saved app token is refused ──
    let web = open_page(&conn, "", &format!("{base}/#token=wrong-token-000000000"));
    web.until("asked, with the reason", "document.getElementById('login').open && /不正確或已失效/.test(document.getElementById('loginStatus').textContent)", 30);
    web.shot("authstay-browser-refused");
    // 連線 with a wrong token: the dialog stays and says so (it never just closes and reopens).
    web.eval("document.getElementById('loginStatus').textContent = ''; document.getElementById('token').value = 'still-wrong-000000000'; document.getElementById('loginBtn').click(); true");
    web.until("the wrong token is reported", "document.getElementById('login').open && /不正確或已失效/.test(document.getElementById('loginStatus').textContent)", 15);
    web.eval("document.getElementById('token').value = ''; document.getElementById('loginBtn').click(); true");
    web.until("an empty field is reported", "/請先貼上/.test(document.getElementById('loginStatus').textContent)", 15);
    // The host down: 連線 says it cannot reach it.
    d.stop();
    web.eval(&format!("document.getElementById('token').value = '{ADMIN}'; document.getElementById('loginBtn').click(); true"));
    web.until("an unreachable host is reported", "document.getElementById('login').open && /連不到 SE Agent/.test(document.getElementById('loginStatus').textContent)", 20);
    web.shot("authstay-browser-unreachable");
    d.start(ADMIN);
    web.eval("document.getElementById('loginBtn').click(); true");
    web.until("connected with the right token", "!document.getElementById('login').open && document.getElementById('conn').classList.contains('live')", 30);
    assert!(web.works(), "{}", web.state());

    // A connected browser with the app token rides out a daemon restart without a prompt.
    let shown = web.eval("window.__loginShown").as_u64().unwrap();
    d.stop();
    std::thread::sleep(Duration::from_secs(3));
    d.start(ADMIN);
    web.until("reconnected after the restart", "document.getElementById('conn').classList.contains('live') && S.arp.ws.readyState === 1", 45);
    assert_eq!(web.eval("window.__loginShown").as_u64().unwrap(), shown, "no prompt for a restart: {}", web.state());
    conn.close();
    let _ = d.log();
}
