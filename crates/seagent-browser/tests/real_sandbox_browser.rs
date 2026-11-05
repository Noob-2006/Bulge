//! Real sandbox-browser integration test: Chromium inside a container, driven over the
//! authenticated CDP relay, exactly the way `seagent` starts it.
//!
//! Opt in with
//! `SEAGENT_REAL_SANDBOX_IMAGE=seagent-sandbox-browser:trixie-slim SEAGENT_DOCKER=podman`
//! (`tests/real/sandbox_browser_up.sh` builds the image from `packaging/sandbox-browser`
//! and prints this line). Without them the tests skip and pass.
//!
//! What is proven here (nothing is faked):
//! * the shipped image starts: Xvfb + Chromium + the Basic-auth CDP relay + noVNC;
//! * seagent reaches it through `Manager::browser` (backend `sandbox`), i.e. the same path the
//!   `browser` tool uses, and drives a real page load, real JS and a real screenshot;
//! * the relay is the only way in: no credentials / a wrong token ⇒ 401, and Chromium's
//!   own DevTools port (9223) is never published on the host;
//! * the browser runs as the non-root `seagent` user and the container is removed when the
//!   browser is closed (nothing is left running).

use seagent_browser::actions;
use seagent_browser::config::BrowserConfig;
use seagent_browser::manager::{Env, Manager};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn image() -> Option<String> {
    std::env::var("SEAGENT_REAL_SANDBOX_IMAGE").ok().filter(|s| !s.trim().is_empty())
}

fn docker() -> String {
    // Same resolution seagent uses (`SEAGENT_DOCKER`, docker, podman) so the test proves the
    // fallback that makes the backend visible on podman-only machines.
    seagent_browser::sandbox::docker()
}

fn cli(args: &[&str]) -> Result<String, String> {
    let bin = docker();
    let out = std::process::Command::new(&bin)
        .args(args)
        .output()
        .map_err(|e| format!("{bin} {}: {e}", args.join(" ")))?;
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    if out.status.success() {
        Ok(text.trim().to_string())
    } else {
        Err(format!("{bin} {} failed: {}", args.join(" "), text.trim()))
    }
}

fn config(image: &str, headless: bool) -> BrowserConfig {
    let src = format!(
        "backend = \"sandbox\"\ncommand_timeout = 60\n[sandbox]\nimage = {image:?}\nheadless = {headless}\nnovnc = true\nnetwork = \"bridge\"\nstart_timeout_ms = 90000\n"
    );
    let table: toml::Table = toml::from_str(&src).expect("test config is valid TOML");
    BrowserConfig::parse(&table).expect("test config is a valid [browser] table")
}

/// A scratch `SEAGENT_HOME` under `TMPDIR`; the guard removes it on drop (also on panic).
struct Home(seagent_core::tmp::TempDir);

impl Home {
    fn new(tag: &str) -> Home {
        Home(seagent_core::tmp::TempDir::new(&format!("seagent-sbx-real-{tag}")))
    }
    fn env(&self, cfg: BrowserConfig) -> Env {
        Env { cfg, home: self.0.join(""), secrets: Arc::new(|s: &str| s.to_string()) }
    }
}

/// Removes the container seagent started if the test panics half way (seagent's own `on_close`
/// does it on the normal path; `rm -f` is idempotent).
struct Container(String);

impl Drop for Container {
    fn drop(&mut self) {
        let _ = cli(&["rm", "-f", &self.0]);
    }
}

fn container_name(b: &seagent_browser::engine::Browser) -> String {
    b.info.lock().unwrap().get("container").and_then(|v| v.as_str()).unwrap_or_default().to_string()
}

/// Minimal HTTP/1.1 GET over a loopback socket: (status, body). No new crate for one call.
fn http_get(url: &str, auth: Option<&str>) -> Result<(u16, String), String> {
    let rest = url.strip_prefix("http://").ok_or_else(|| format!("not an http url: {url}"))?;
    let (host_port, path) = rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((rest, "/".into()));
    let (host, port) = host_port.rsplit_once(':').ok_or_else(|| format!("no port in {url}"))?;
    let port: u16 = port.parse().map_err(|e| format!("bad port in {url}: {e}"))?;
    // The relay accepts one connection at a time in a small backlog; a rejected connect
    // (EAGAIN on the listen queue) is retried instead of failing the test.
    let mut attempt = 0;
    let mut s = loop {
        match TcpStream::connect((host, port)) {
            Ok(s) => break s,
            Err(e) if attempt < 20 && matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => {
                attempt += 1;
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("connect {host}:{port}: {e}")),
        }
    };
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let auth = auth.map(|a| format!("Authorization: {a}\r\n")).unwrap_or_default();
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n{auth}Connection: close\r\n\r\n");
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    // The relay hands the socket to Chromium, which keeps it alive after the body, so read
    // until the declared Content-Length is in, or until the (short) read timeout fires.
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if complete(&buf) || buf.len() > 1 << 20 {
                    break;
                }
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted) => break,
            Err(e) => return Err(format!("read {url}: {e}")),
        }
    }
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text.split_whitespace().nth(1).and_then(|c| c.parse().ok()).ok_or_else(|| format!("no status in reply: {}", &text[..text.len().min(200)]))?;
    Ok((status, text))
}

/// Headers received and, when the reply declares a length, the whole body.
fn complete(buf: &[u8]) -> bool {
    let text = String::from_utf8_lossy(buf);
    let Some((head, body)) = text.split_once("\r\n\r\n") else { return false };
    let len = head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case("content-length").then(|| v.trim().parse::<usize>().ok()).flatten()
    });
    len.is_none_or(|n| body.len() >= n) && !head.to_ascii_lowercase().contains("transfer-encoding: chunked")
}

fn wait_until(secs: u64, mut f: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < until {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// Serve a page from inside the container (its own loopback) so the navigation is a real
/// HTTP load without publishing anything on the host. Returns the URL Chromium can reach.
fn serve_fixture(container: &str) -> String {
    let html = "<html><head><title>sbx-fixture</title></head><body>\
                <div id=\"msg\">before-js</div>\
                <script>document.getElementById('msg').textContent = 'js-ran' + ':' + (6 * 7);</script>\
                </body></html>";
    let script = format!(
        "set -e; mkdir -p /tmp/fixture; cat > /tmp/fixture/index.html <<'HTML'\n{html}\nHTML\n(cd /tmp/fixture && nohup python3 -m http.server 9333 --bind 127.0.0.1 >/tmp/fixture.log 2>&1 &); \
         for i in $(seq 1 40); do curl -sf -o /dev/null http://127.0.0.1:9333/ && break; sleep 0.2; done; curl -sf -o /dev/null http://127.0.0.1:9333/"
    );
    cli(&["exec", container, "sh", "-c", &script]).expect("fixture page inside the container");
    "http://127.0.0.1:9333/".to_string()
}

fn wait_ready(b: &seagent_browser::engine::Browser, target: &str) {
    assert!(
        wait_until(30, || b.eval(target, "document.readyState").ok().and_then(|v| v.as_str().map(str::to_string)).as_deref() == Some("complete")),
        "page never finished loading"
    );
}

/// The whole point of B7: a real Chromium, in a container, driven by seagent over the relay.
#[test]
fn drives_a_real_chromium_inside_the_sandbox_container() {
    let Some(image) = image() else {
        eprintln!("skip: set SEAGENT_REAL_SANDBOX_IMAGE (see tests/real/sandbox_browser_up.sh)");
        return;
    };
    let home = Home::new("headed");
    let env = home.env(config(&image, false));
    let m = Manager::default();
    let b = m.browser(&env, "sandbox").expect("sandbox browser starts");
    assert_eq!(b.kind, "sandbox", "the browser came from the sandbox backend");
    let name = container_name(&b);
    assert!(name.starts_with("seagent-sbx-browser-"), "unexpected container name {name:?}");
    let _guard = Container(name.clone());

    // 1. The container is real, labelled, and runs as the non-root `seagent` user.
    let ps = cli(&["ps", "--filter", "label=seagent.sandbox=1", "--format", "{{.Names}}"]).unwrap();
    assert!(ps.lines().any(|l| l.trim() == name), "container {name} not in `ps`: {ps}");
    let uid = cli(&["exec", &name, "id", "-u"]).unwrap();
    assert_eq!(uid.trim(), "1000", "the browser must not run as root");
    let user = cli(&["exec", &name, "id", "-un"]).unwrap();
    assert_eq!(user.trim(), "seagent");

    // 2. Chromium's own DevTools port is never published; only the relay is.
    assert!(cli(&["port", &name, "9223"]).is_err(), "Chromium's raw CDP port 9223 must not be published");
    let ports = cli(&["port", &name]).unwrap();
    assert!(ports.lines().all(|l| l.trim().contains("-> 127.0.0.1:")), "every published port must be loopback: {ports}");
    assert!(ports.contains("9222") && ports.contains("6080"), "relay + noVNC are published: {ports}");

    // 3. The relay is the only door: no credentials and a wrong token are both 401.
    let http = b.http.clone().expect("sandbox browser records its http endpoint");
    assert_eq!(http_get(&format!("{http}/json/version"), None).unwrap().0, 401, "unauthenticated CDP must be refused");
    let wrong = format!("Basic {}", seagent_net::crypto::b64(b"seagent:not-the-token"));
    assert_eq!(http_get(&format!("{http}/json/version"), Some(&wrong)).unwrap().0, 401, "a wrong relay token must be refused");
    let good = b.auth.clone().expect("sandbox browser records its relay credentials");
    let (status, body) = http_get(&format!("{http}/json/version"), Some(&good)).unwrap();
    assert_eq!(status, 200, "the relay must accept seagent's own credentials: {body}");
    assert!(body.contains("Chrome/") || body.contains("Chromium"), "real browser identity in /json/version: {body}");

    // 4. A real navigation with real JS and a real screenshot, through seagent's CDP client.
    let url = serve_fixture(&name);
    let tab = b.new_tab(&url, None).expect("Target.createTarget");
    wait_ready(&b, &tab);
    let (href, title) = b.url_title(&tab);
    assert_eq!(title, "sbx-fixture", "page title (href {href})");
    assert_eq!(b.eval(&tab, "document.getElementById('msg').textContent").unwrap(), serde_json::json!("js-ran:42"), "page script ran inside the container");
    assert_eq!(b.eval(&tab, "navigator.userAgent.includes('Headless')").unwrap(), serde_json::json!(false), "headed container browser, not headless");
    let shot = actions::screenshot(&b, &tab, false, None, None, false, false).expect("screenshot");
    assert_eq!(&shot.data[..4], b"\x89PNG", "screenshot is a PNG");
    assert!(shot.data.len() > 2_000, "screenshot has pixels: {} bytes", shot.data.len());

    // 5. noVNC observer is up and loopback-only.
    let novnc = b.info.lock().unwrap().get("novnc_url").and_then(|v| v.as_str()).map(str::to_string).expect("novnc_url for a headed sandbox browser");
    assert!(novnc.starts_with("http://127.0.0.1:"), "noVNC must be loopback: {novnc}");
    let (status, body) = http_get(novnc.split('?').next().unwrap(), None).expect("GET novnc");
    assert_eq!(status, 200, "noVNC page is served");
    assert!(body.contains("noVNC") || body.contains("vnc"), "looks like the noVNC viewer");

    // 6. Closing the browser removes the container: nothing keeps running.
    b.close();
    assert!(wait_until(20, || !cli(&["ps", "-a", "--format", "{{.Names}}"]).unwrap_or_default().lines().any(|l| l.trim() == name)), "container {name} must be removed on close");
}

/// Headless mode: no Xvfb/noVNC, still the same authenticated CDP relay.
#[test]
fn headless_sandbox_browser_has_no_novnc_and_still_works() {
    let Some(image) = image() else {
        eprintln!("skip: set SEAGENT_REAL_SANDBOX_IMAGE");
        return;
    };
    let home = Home::new("headless");
    let env = home.env(config(&image, true));
    let m = Manager::default();
    let b = m.browser(&env, "sandbox").expect("headless sandbox browser starts");
    let name = container_name(&b);
    let _guard = Container(name.clone());
    assert!(b.info.lock().unwrap().get("novnc_url").is_none(), "headless mode must not advertise noVNC");
    assert!(cli(&["port", &name, "6080"]).is_err(), "headless mode must not publish 6080");
    let http = b.http.clone().unwrap();
    assert_eq!(http_get(&format!("{http}/json/version"), None).unwrap().0, 401, "headless keeps the auth gate");
    let url = serve_fixture(&name);
    let tab = b.new_tab(&url, None).expect("Target.createTarget");
    wait_ready(&b, &tab);
    assert_eq!(b.url_title(&tab).1, "sbx-fixture");
    assert_eq!(b.eval(&tab, "navigator.userAgent.includes('Headless')").unwrap(), serde_json::json!(true), "--headless=new is in use");
    b.close();
    let _ = wait_until(20, || !cli(&["ps", "-a", "--format", "{{.Names}}"]).unwrap_or_default().lines().any(|l| l.trim() == name));
}

/// The shipped image must carry the contract label seagent checks before `run`; a rebuilt
/// image is therefore pinned to the entrypoint it was built with.
#[test]
fn the_built_image_carries_the_contract_label() {
    let Some(image) = image() else {
        eprintln!("skip: set SEAGENT_REAL_SANDBOX_IMAGE");
        return;
    };
    let label = cli(&["image", "inspect", "--format", "{{index .Config.Labels \"org.seagent.sandbox-browser.contract\"}}", &image]).expect("image inspect");
    assert_eq!(label.trim(), seagent_browser::sandbox::CONTRACT);
    let entry = cli(&["image", "inspect", "--format", "{{index .Config.Entrypoint 0}}", &image]).expect("image inspect");
    assert_eq!(entry.trim(), "/usr/local/bin/sandbox-browser-entrypoint.sh");
    let _ = Path::new("/").exists();
}
