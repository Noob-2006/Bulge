//! Runtime-path tests: the Lightpanda `serve` launcher and its Chrome fallback, `browser_exec`
//! (Browser Use harness) and `ark browser install` (Chrome for Testing). Everything here runs
//! against fake binaries/servers; nothing needs the network.

use crate::config::BrowserConfig;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

use crate::tests::{ctx, tool, SERIAL};

fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ark-{tag}-{}-{}", std::process::id(), ark_net::crypto::random_token(4)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn exe(path: &std::path::Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn with_path<T>(dir: &std::path::Path, f: impl FnOnce() -> T) -> T {
    let old = std::env::var_os("PATH");
    let mut paths = vec![dir.to_path_buf()];
    paths.extend(std::env::split_paths(old.as_deref().unwrap_or_default()));
    std::env::set_var("PATH", std::env::join_paths(paths).unwrap());
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    std::env::set_var("PATH", old.unwrap_or_default());
    match r {
        Ok(v) => v,
        Err(e) => std::panic::resume_unwind(e),
    }
}

/// `lightpanda serve --host 127.0.0.1 --port P` answered by a python DevTools endpoint.
const FAKE_LIGHTPANDA: &str = r#"#!/bin/sh
if [ "$1" = "help" ]; then echo "--http-cache-dir"; exit 0; fi
if [ "$1" != "serve" ]; then exit 1; fi
shift
port=""
while [ $# -gt 0 ]; do
  case "$1" in
    --port) port="$2"; shift ;;
  esac
  echo "$1" >> "$0.args"
  shift
done
exec python3 -c 'import sys,json
from http.server import BaseHTTPRequestHandler,HTTPServer
p=int(sys.argv[1])
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        b=json.dumps({"Browser":"Lightpanda/1.0","webSocketDebuggerUrl":"ws://127.0.0.1:%d/devtools/browser/lp" % p}).encode()
        self.send_response(200); self.send_header("content-type","application/json"); self.send_header("content-length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self,*a): pass
HTTPServer(("127.0.0.1",p),H).serve_forever()' "$port"
"#;

#[test]
fn lightpanda_serve_launches_with_hermes_flags() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = temp_dir("lp");
    exe(&dir.join("lightpanda"), FAKE_LIGHTPANDA);
    with_path(&dir, || {
        assert_eq!(crate::launch::lightpanda_binary().as_deref(), Some(dir.join("lightpanda").as_path()));
        let state = dir.join("state");
        let l = crate::launch::lightpanda_serve(&state, true).unwrap();
        assert!(l.http.starts_with("http://127.0.0.1:") && l.ws.contains("/devtools/browser/lp"), "{} {}", l.http, l.ws);
        assert!(state.join("lightpanda.log").is_file());
        let args = std::fs::read_to_string(dir.join("lightpanda.args")).unwrap();
        for f in ["--host", "127.0.0.1", "--http-cache-dir", "--block-private-networks"] {
            assert!(args.contains(f), "serve args: {args}");
        }
        crate::util::kill_group(l.pid, std::time::Duration::from_secs(1));
    });
}

/// A browser whose page exists but whose navigation always fails (a Lightpanda that cannot
/// render the page), for the fallback path.
fn failing_nav_fake() -> crate::cdp::fake::Fake {
    crate::cdp::fake::start(Arc::new(|m, _p, _sid| {
        match m {
            "Target.getTargets" => (json!({"targetInfos": [{"targetId": "LP1", "type": "page", "url": "https://lp.example/start", "title": "LP"}]}), vec![]),
            "Target.attachToTarget" => (json!({"sessionId": "LPS"}), vec![]),
            "Target.createTarget" => (json!({"targetId": "LP2"}), vec![]),
            "Target.closeTarget" | "Target.activateTarget" | "Target.detachFromTarget" => (json!({}), vec![]),
            "Page.getFrameTree" => (json!({"frameTree": {"frame": {"id": "M", "url": "https://lp.example/start"}}}), vec![]),
            "Page.navigate" => (json!({"frameId": "M", "errorText": "net::ERR_FAILED"}), vec![]),
            "Runtime.evaluate" => (json!({"result": {"value": ["https://lp.example/start", "LP"]}}), vec![]),
            "http:/json/list" => (json!([]), vec![]),
            _ => (json!({}), vec![]),
        }
    }))
}

fn open_page_fake(url: &str) -> crate::cdp::fake::Fake {
    let url = url.to_string();
    crate::cdp::fake::start(Arc::new(move |m, p, sid| {
        let u = url.clone();
        let ev = |method: &str, params: serde_json::Value| json!({"method": method, "params": params, "sessionId": sid});
        match m {
            "Target.getTargets" => (json!({"targetInfos": [{"targetId": "SC1", "type": "page", "url": u, "title": "Sidecar"}]}), vec![]),
            "Target.attachToTarget" => (json!({"sessionId": "SCS"}), vec![]),
            "Target.createTarget" => (json!({"targetId": "SC2"}), vec![]),
            "Target.closeTarget" | "Target.activateTarget" | "Target.detachFromTarget" => (json!({}), vec![]),
            "Page.getFrameTree" => (json!({"frameTree": {"frame": {"id": "M", "url": u}}}), vec![]),
            "Page.navigate" => (json!({"frameId": "M", "loaderId": "S"}), vec![ev("Page.frameNavigated", json!({"frame": {"id": "M", "url": p["url"].clone()}})), ev("Page.loadEventFired", json!({}))]),
            "Runtime.evaluate" => (json!({"result": {"value": [u, "Sidecar"]}}), vec![]),
            "Page.getLayoutMetrics" => (json!({"cssLayoutViewport": {"clientWidth": 800, "clientHeight": 600}}), vec![]),
            "http:/json/list" => (json!([]), vec![]),
            _ => (json!({}), vec![]),
        }
    }))
}

fn browser_over(kind: &str, f: &crate::cdp::fake::Fake, dir: PathBuf) -> Arc<crate::engine::Browser> {
    let ws = crate::cdp::resolve_ws(&f.http, None, std::time::Duration::from_secs(5)).unwrap();
    let conn = crate::cdp::Conn::connect(&ws, &[], std::time::Duration::from_secs(5)).unwrap();
    crate::engine::Browser::new(kind, kind, conn, Some(f.http.clone()), None, None, false, dir, std::time::Duration::from_secs(30), "must_respond", 300, false)
}

#[test]
fn lightpanda_navigation_failure_falls_back_to_chrome() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let c = ctx("lpfb", "sess-lpfb");
    let lp = failing_nav_fake();
    let side = open_page_fake("https://fallback.example/page");
    // `engine = lightpanda` with no cdp override: the manager key is `lightpanda`, which the
    // test fills with a fake that accepts tabs but fails every navigation.
    let cfg = BrowserConfig { engine: "lightpanda".into(), enabled: toml::Value::Boolean(true), ..Default::default() };
    let m = crate::manager::global();
    m.put_for_test("lightpanda", browser_over("lightpanda", &lp, c.home.join("browser/state/lightpanda")));
    m.put_for_test("sidecar", browser_over("local", &side, c.home.join("browser/state/sidecar")));
    let t = tool(&cfg, "browser_navigate");
    let o = t.call(&c, json!({"url": "https://fallback.example/page"}));
    assert!(!o.is_error, "the sidecar answers after lightpanda fails: {}", o.content);
    let v: serde_json::Value = serde_json::from_str(&o.content).unwrap_or_default();
    assert!(v["fallback_warning"].as_str().is_some_and(|w| w.contains("Lightpanda fallback")) && v["browser_engine_fallback"]["from"] == "lightpanda", "{}", o.content);
    assert_eq!(v["url"], "https://fallback.example/page", "{}", o.content);
    m.stop_all();
}

#[test]
fn browser_exec_runs_the_harness_with_cdp_env() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let c = ctx("exec", "sess-exec");
    let f = open_page_fake("https://exec.example/");
    let cfg = BrowserConfig {
        backend: "cdp".into(),
        cdp_url: f.http.clone(),
        enabled: toml::Value::Boolean(true),
        exec_enabled: true,
        exec_command: vec!["sh".into(), "-c".into(), "printf 'code=%s\\n' \"$(cat)\"; env | grep -E '^(BU_|BH_)' | sort".into()],
        ..Default::default()
    };
    let t = tool(&cfg, "browser");
    let nav = t.call(&c, json!({"action": "navigate", "url": "https://exec.example/"}));
    assert!(!nav.is_error, "{}", nav.content);
    let o = t.call(&c, json!({"action": "navigate", "url": "https://exec.example/"}));
    assert!(!o.is_error, "{}", o.content);
    let ex = tool(&cfg, "browser_exec");
    let o = ex.call(&c, json!({"code": "print('hello from browser use')", "session": "task_1"}));
    assert!(!o.is_error, "{}", o.content);
    let v: serde_json::Value = serde_json::from_str(&o.content).unwrap_or_default();
    assert_eq!(v["success"], true, "{}", o.content);
    let out = v["output"].as_str().unwrap_or("");
    assert!(out.contains("code=print('hello from browser use')"), "{out}");
    assert!(out.contains("BU_CDP_WS=ws://127.0.0.1:"), "{out}");
    assert!(out.contains("BU_CDP_URL=http://127.0.0.1:"), "{out}");
    assert!(out.contains("BU_NAME=task_1"), "{out}");
    assert!(out.contains("BH_AGENT_WORKSPACE="), "{out}");
    // The navigation guard runs over the code before anything launches.
    let o = ex.call(&c, json!({"code": "goto('https://x.test/?key=sk-ant-abcdefghijklmnopqrstuvwxyz')"}));
    assert!(o.is_error && o.content.contains("API key"), "{}", o.content);
    let o = ex.call(&c, json!({"code": "print(1)", "session": "../etc"}));
    assert!(o.is_error && o.content.contains("Invalid session name"), "{}", o.content);
    let mut broken = cfg.clone();
    broken.exec_command = vec!["/nonexistent/browser-harness".into()];
    let ex = tool(&broken, "browser_exec");
    let o = ex.call(&c, json!({"code": "print(1)"}));
    assert!(o.is_error && o.content.contains("Failed to launch browser-use CLI"), "{}", o.content);
    crate::manager::global().stop("cdp");
}

/// Build a stored (uncompressed) zip holding `chrome-linux64/chrome`.
fn make_zip(path: &std::path::Path) {
    let status = std::process::Command::new("python3")
        .arg("-c")
        .arg("import sys,zipfile; z=zipfile.ZipFile(sys.argv[1],'w'); z.writestr('chrome-linux64/chrome','#!/bin/sh\\necho fake chrome\\n'); z.writestr('chrome-linux64/icudtl.dat','x'); z.close()")
        .arg(path)
        .status()
        .expect("python3 for the test zip");
    assert!(status.success());
}

#[test]
fn browser_install_downloads_and_unpacks_chrome_for_testing() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = temp_dir("cft");
    let zip = dir.join("chrome-linux64.zip");
    make_zip(&zip);
    let body = std::fs::read(&zip).unwrap();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let zip_url = format!("http://{}/chrome-linux64.zip", l.local_addr().unwrap());
    let index = json!({"channels": {"Stable": {"version": "1.2.3", "downloads": {"chrome": [{"platform": "linux64", "url": zip_url}]}}}}).to_string();
    let u = zip_url.clone();
    std::thread::spawn(move || {
        for s in l.incoming().take(4) {
            let Ok(mut s) = s else { continue };
            let mut buf = [0u8; 4096];
            let n = std::io::Read::read(&mut s, &mut buf).unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            let (ctype, payload) = if head.contains("index.json") { ("application/json", index.clone().into_bytes()) } else { ("application/zip", body.clone()) };
            let _ = std::io::Write::write_all(&mut s, format!("HTTP/1.1 200 OK\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", payload.len()).as_bytes());
            let _ = std::io::Write::write_all(&mut s, &payload);
            let _ = u;
        }
    });
    let home = dir.join("home");
    // A `.zip` install_base_url is used as-is (the network index is only consulted otherwise).
    let cfg = BrowserConfig { install_base_url: zip_url.clone(), ..Default::default() };
    assert_eq!(crate::launch::chromium_download_url(&cfg, None).unwrap(), zip_url);
    let mut log = vec![];
    let exe = crate::launch::install_chromium(&cfg, &home, None, &mut |l| log.push(l.to_string())).unwrap();
    assert_eq!(exe, home.join("browsers/chrome-linux64/chrome"));
    assert!(exe.is_file() && home.join("browsers/chrome-linux64/icudtl.dat").is_file());
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&exe).unwrap().permissions().mode() & 0o111, 0o111, "the binary is executable");
    assert_eq!(crate::launch::installed_chrome_in(&home.join("browsers")).as_deref(), Some(exe.as_path()));
    assert!(log.iter().any(|l| l.contains("installed")), "{log:?}");
    // The source URL is recorded for `ark browser status`-style reporting.
    assert!(std::fs::read_to_string(home.join("browsers/chrome-linux64/.ark-source")).unwrap().contains("chrome-linux64.zip"));
    // A body that is not a zip is refused instead of unpacked.
    let l2 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bad_url = format!("http://{}/notazip.zip", l2.local_addr().unwrap());
    std::thread::spawn(move || {
        for s in l2.incoming().take(2) {
            let Ok(mut s) = s else { continue };
            let mut buf = [0u8; 1024];
            let _ = std::io::Read::read(&mut s, &mut buf);
            let _ = std::io::Write::write_all(&mut s, b"HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: 5\r\nconnection: close\r\n\r\n<html");
        }
    });
    let mut log = vec![];
    let e = crate::launch::install_chromium(&cfg, &home, Some(&bad_url), &mut |l| log.push(l.to_string())).unwrap_err();
    assert!(e.contains("did not return a zip archive"), "{e}");
    assert!(crate::launch::chromium_download_url(&cfg, Some("http://127.0.0.1:9/none.zip")).unwrap().ends_with("none.zip"), "an explicit --url always wins");
}
