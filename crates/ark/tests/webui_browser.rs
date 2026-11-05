//! Web UI behaviour in a real browser (gen2-518).
//!
//! Starts the real `ark daemon run` with the app server on, opens the UI in a real headless
//! Chrome over CDP (ark-browser's launcher and connection) and checks, page by page:
//! the page loads with no console error or uncaught exception, every Control UI page renders,
//! the main buttons work, and under RBAC a read-only token sees no write control (while the
//! server still refuses the write if it is attempted anyway).
//!
//! `#[ignore]`; run with `ARK_REAL_TESTS=1 cargo test -p ark --test webui_browser -- --ignored`
//! (or `tests/real/realtest.sh --only webui`). The daemon and Chrome are tied to this process
//! (`spawn_tied` / the launcher's PDEATHSIG) and held by guards.

use ark_browser::cdp::Conn;
use ark_core::proc::{spawn_tied, wait_until, ChildGuard, PidGuard};
use ark_core::tmp::TempDir;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const ADMIN: &str = "webui-admin-token-0001";
const READ: &str = "webui-read-token-0001";
const AUDITOR: &str = "webui-auditor-token-0001";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn http_ok(port: u16) -> bool {
    let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", port)) else { return false };
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = write!(s, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    let mut b = [0u8; 16];
    s.read(&mut b).is_ok_and(|n| b[..n].starts_with(b"HTTP/1.1 200"))
}

/// One attached page and everything it reported as an error.
struct Page {
    conn: Conn,
    sid: String,
    errors: Arc<Mutex<Vec<String>>>,
}

impl Page {
    fn eval(&self, expr: &str) -> Value {
        let r = self.conn.call_with("Runtime.evaluate", json!({"expression": expr, "awaitPromise": true, "returnByValue": true}), Some(&self.sid), Duration::from_secs(30), &|| None).unwrap_or_else(|e| panic!("{expr}: {e}"));
        if let Some(ex) = r.get("exceptionDetails") {
            return json!({"__exception": ex["exception"]["description"].as_str().or(ex["text"].as_str()).unwrap_or("?")});
        }
        r["result"]["value"].clone()
    }
    fn until(&self, what: &str, expr: &str) {
        if !wait_until(Duration::from_secs(20), || self.eval(expr) == json!(true)) {
            let state = self.eval("JSON.stringify({url: location.href, conn: (document.getElementById('conn') || {}).textContent, title: document.title, me: typeof S !== 'undefined' ? S.me : 'no S', body: document.body ? document.body.innerText.slice(0, 200) : ''})");
            panic!("timed out waiting for {what} ({expr}); page: {state}; errors: {:#?}", self.errors.lock().unwrap());
        }
    }
    fn goto(&self, url: &str) {
        self.conn.call("Page.navigate", json!({"url": url}), Some(&self.sid)).unwrap();
    }
    fn take_errors(&self) -> Vec<String> {
        std::mem::take(&mut *self.errors.lock().unwrap())
    }
}

fn open_page(conn: &Conn, errors: &Arc<Mutex<Vec<String>>>) -> Page {
    let t = conn.call("Target.createTarget", json!({"url": "about:blank"}), None).unwrap();
    let sid = conn.call("Target.attachToTarget", json!({"targetId": t["targetId"], "flatten": true}), None).unwrap()["sessionId"].as_str().unwrap().to_string();
    for m in ["Runtime.enable", "Log.enable", "Page.enable"] {
        conn.call(m, json!({}), Some(&sid)).unwrap();
    }
    Page { conn: conn.clone(), sid, errors: errors.clone() }
}

fn daemon(home: &Path, ws: &Path, port: u16) -> ChildGuard {
    std::fs::create_dir_all(home.join("config")).unwrap();
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
nodes = true
workspace = "{ws}"
tokens = [{{ token = "{READ}", scope = "read", name = "viewer" }}, {{ token = "{AUDITOR}", scope = "auditor", name = "auditor" }}]
"#,
            ws = ws.display()
        ),
    )
    .unwrap();
    let log = std::fs::File::create(home.join("daemon.log")).unwrap();
    let mut c = Command::new(env!("CARGO_BIN_EXE_ark"));
    c.args(["daemon", "run"]).current_dir(ws).env("ARK_HOME", home).env("ARK_OFFLINE", "1").env("FAKE_KEY", "x").env("XDG_RUNTIME_DIR", "").env_remove("OPENAI_API_KEY").env_remove("ANTHROPIC_API_KEY").stdin(Stdio::null()).stdout(log.try_clone().unwrap()).stderr(log);
    ChildGuard::group(spawn_tied(c, true).expect("spawn arkd"))
}

/// JS: render page `id` through the real UI and report how it went.
fn render_page_js(id: &str) -> String {
    format!(
        r#"(async () => {{
  await openPage({id:?});
  const b = document.getElementById('panelBody');
  for (let i = 0; i < 100 && b.querySelector('.star.spin'); i++) await new Promise(r => setTimeout(r, 50));
  const ok = b.children.length > 0 && !b.querySelector('.star.spin');
  const writes = [...b.querySelectorAll('button')].filter(x => !x.hidden && x.offsetParent !== null && !x.hasAttribute('data-read') && !x.hasAttribute('data-page')).map(x => x.id || x.textContent.trim());
  const enabled = [...b.querySelectorAll('input, select, textarea')].filter(x => !x.disabled && !x.hasAttribute('data-read')).length;
  const text = b.textContent.slice(0, 160);
  document.getElementById('panelDialog').close();
  return {{ ok, writes, enabled, text }};
}})()"#
    )
}

#[test]
#[ignore]
fn real_webui_pages_buttons_and_rbac() {
    if std::env::var("ARK_REAL_TESTS").ok().as_deref() != Some("1") {
        eprintln!("skipping: set ARK_REAL_TESTS=1");
        return;
    }
    let exe = ark_browser::launch::find_executable("").expect("ARK_REAL_TESTS=1 needs a Chromium-family browser");
    let root = TempDir::new("ark-webui");
    let (home, ws) = (root.path().join("home"), root.path().join("ws"));
    std::fs::create_dir_all(&ws).unwrap();
    let port = free_port();
    let _d = daemon(&home, &ws, port);
    let log = || std::fs::read_to_string(home.join("daemon.log")).unwrap_or_default();
    assert!(wait_until(Duration::from_secs(30), || http_ok(port)), "app server never answered: {}", log());

    let profile = root.path().join("chrome");
    let o = ark_browser::launch::LaunchOpts { exe: &exe, user_data_dir: &profile, headless: true, no_sandbox: false, extra_args: &[], port: 0, managed: true, env: vec![] };
    let l = ark_browser::launch::launch(&o, Duration::from_secs(30)).expect("launch Chrome");
    let _chrome = PidGuard(l.pid);
    let conn = Conn::connect(&l.ws, &[], Duration::from_secs(10)).unwrap();
    let errors: Arc<Mutex<Vec<String>>> = Arc::default();
    let errs = errors.clone();
    conn.on_event(Arc::new(move |_c, method, p, _sid| {
        let e = match method {
            "Runtime.exceptionThrown" => Some(format!("exception: {}", p["exceptionDetails"]["exception"]["description"].as_str().or(p["exceptionDetails"]["text"].as_str()).unwrap_or("?"))),
            "Runtime.consoleAPICalled" if p["type"] == "error" => Some(format!("console.error: {}", p["args"])),
            "Log.entryAdded" if p["entry"]["level"] == "error" => Some(format!("log[{}]: {} {}", p["entry"]["source"].as_str().unwrap_or(""), p["entry"]["text"].as_str().unwrap_or(""), p["entry"]["url"].as_str().unwrap_or(""))),
            _ => None,
        };
        if let Some(e) = e {
            errs.lock().unwrap().push(e);
        }
    }));
    let base = format!("http://127.0.0.1:{port}");

    // ── admin: load, every page, main buttons ──
    let p = open_page(&conn, &errors);
    p.goto(&format!("{base}/#token={ADMIN}"));
    p.until("connected", "typeof S !== 'undefined' && !!S.arp && !!S.me && document.getElementById('conn').textContent.includes('·')");
    assert_eq!(p.eval("document.body.classList.contains('ro')"), json!(false), "admin is not read-only");
    let pages: Vec<String> = serde_json::from_value(p.eval("Object.keys(PAGES)")).unwrap();
    assert!(pages.len() >= 10, "Control UI pages: {pages:?}");
    let mut broken = vec![];
    for id in &pages {
        let r = p.eval(&render_page_js(id));
        let errs = p.take_errors();
        if r["ok"] != true || !errs.is_empty() {
            broken.push(format!("{id}: {} {errs:?}", r["text"]));
        }
    }
    eprintln!("admin: {} pages rendered, broken: {broken:#?}", pages.len());
    assert!(broken.is_empty(), "pages that failed to render or logged errors as admin: {broken:#?}");

    // Main buttons: new chat, settings / devices / dashboards panels, language, theme.
    let before = p.eval("S.sessions.length").as_u64().unwrap_or(0);
    p.eval("document.getElementById('newSession').click()");
    p.until("a new session", &format!("S.sessions.length > {before} && !!S.current"));
    for b in ["showSettings", "showNodes", "showBoards"] {
        p.eval(&format!("document.getElementById('{b}').click()"));
        p.until(&format!("{b} panel"), "document.getElementById('panelDialog').open && !document.querySelector('#panelBody .star.spin') && document.getElementById('panelBody').children.length > 0");
        p.eval("document.getElementById('panelDialog').close()");
    }
    p.eval("document.getElementById('lang').click()");
    assert_eq!(p.eval("document.getElementById('newSession').textContent"), json!("+ New chat"));
    p.eval("document.getElementById('lang').click()");
    p.eval("(() => { const s = document.getElementById('theme'); s.value = 'midnight'; s.dispatchEvent(new Event('change')); })()");
    assert_eq!(p.eval("document.documentElement.getAttribute('data-theme')"), json!("midnight"));
    let errs = p.take_errors();
    assert!(errs.is_empty(), "errors while using the main buttons: {errs:#?}");

    // ── read-only roles: no write control anywhere, and the server refuses writes anyway ──
    for (label, token) in [("read", READ), ("auditor", AUDITOR)] {
        let r = open_page(&conn, &errors);
        r.goto(&format!("{base}/#token={token}"));
        r.until("connected", "typeof S !== 'undefined' && !!S.arp && !!S.me && document.getElementById('conn').textContent.includes('·')");
        assert_eq!(r.eval("document.body.classList.contains('ro')"), json!(true), "{label}: read-only mode");
        assert_eq!(r.eval("getComputedStyle(document.getElementById('newSession')).display"), json!("none"), "{label}: no new-chat button");
        assert_eq!(r.eval("getComputedStyle(document.getElementById('composer')).display"), json!("none"), "{label}: no composer");
        let mut leaks = vec![];
        for id in &pages {
            let v = r.eval(&render_page_js(id));
            if !v["writes"].as_array().is_none_or(|a| a.is_empty()) || v["enabled"].as_u64().unwrap_or(0) > 0 {
                leaks.push(format!("{id}: buttons {} enabled inputs {}", v["writes"], v["enabled"]));
            }
            let _ = r.take_errors(); // a read-only caller's denied reads are rendered as text, not thrown
        }
        assert!(leaks.is_empty(), "{label}: write controls visible: {leaks:#?}");
        let denied = r.eval("S.arp.call('session.create', {}).then(() => 'allowed', (e) => e.message)");
        assert!(denied.as_str().is_some_and(|s| s.contains("forbidden")), "{label}: server must refuse writes: {denied}");
        let _ = r.take_errors();
    }
    conn.close();
}
