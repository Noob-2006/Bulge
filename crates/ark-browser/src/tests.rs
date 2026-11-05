//! Tool-level tests: a simulated page behind the fake CDP server. The real-Chromium cases live
//! in `tests_real.rs` (`ARK_REAL_TESTS=1 cargo test -p ark-browser real_ -- --ignored`).

use crate::config::BrowserConfig;
use ark_core::tool::SpawnRequest;
use ark_core::{Cancel, Tool, ToolCtx, ToolHost};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

/// The manager is process-global: tool tests take turns.
pub static SERIAL: Mutex<()> = Mutex::new(());

struct Host;
impl ToolHost for Host {
    fn spawn_agent(&self, _r: SpawnRequest, _c: &Cancel) -> Result<String, String> {
        Err("no".into())
    }
    fn ask_user(&self, _q: &str) -> Result<String, String> {
        Err("headless".into())
    }
    fn analyze_image(&self, q: &str, mime: &str, data: &str) -> Result<String, String> {
        Ok(format!("saw {mime} of {} b64 chars for: {}", data.len(), q.lines().next().unwrap_or("")))
    }
}

pub fn ctx(tag: &str, sid: &str) -> ToolCtx {
    // Removed when the test's thread ends, panic included (the old `temp_dir().join` left
    // `ark-bt-real-*` profiles behind).
    let ws = ark_core::tmp::scratch(&format!("ark-bt-{tag}"));
    ToolCtx { artifacts: ws.join(".artifacts"), home: ws.join(".home"), workspace: ws, session_id: sid.into(), cancel: Cancel::new(), host: Arc::new(Host), secrets: Arc::new(|s: &str| s.to_string()) }
}

pub(crate) fn tool(cfg: &BrowserConfig, name: &str) -> Arc<dyn Tool> {
    let t = toml::Table::try_from(cfg).unwrap();
    crate::tools(&t).unwrap().into_iter().find(|x| x.spec().name == name).unwrap_or_else(|| panic!("no tool {name}"))
}

pub(crate) fn call(cfg: &BrowserConfig, c: &ToolCtx, name: &str, input: Value) -> (bool, Value, String) {
    let o = tool(cfg, name).call(c, input);
    let v = serde_json::from_str(&o.content).unwrap_or(Value::Null);
    (!o.is_error, v, o.content)
}

/// An 8-byte-family PNG header carrying `w`×`h` in IHDR, so a test can read back the clip a
/// screenshot was taken with.
fn png_of(w: u32, h: u32) -> Vec<u8> {
    let mut v = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
    v.extend(w.to_be_bytes());
    v.extend(h.to_be_bytes());
    v.extend([8, 2, 0, 0, 0, 0, 0, 0, 0]);
    v
}

/// The page's recorded state: `typed` / `inserts` / `keys` / `submits` are what the page
/// received, `captures` the clip of every screenshot, `labels` the annotation boxes drawn.
pub fn page_state() -> Value {
    json!({"url": "about:blank", "typed": "", "inserts": [], "keys": [], "submits": 0, "clicks": 0, "captures": [], "labels": 0, "labels_removed": 0})
}

/// A one-page fake browser: an AX tree with a button and a textbox; records input.
/// `state` is the page (shared with the test when it wants to read what landed).
fn page_behind(state: Arc<Mutex<Value>>) -> crate::cdp::fake::Fake {
    crate::cdp::fake::start(Arc::new(move |m, p, sid| {
        let mut st = state.lock().unwrap();
        let ev = |method: &str, params: Value| json!({"method": method, "params": params, "sessionId": sid});
        match m {
            "Target.getTargets" => (json!({"targetInfos": [{"targetId": "PAGE1", "type": "page", "url": st["url"], "title": "Fake"}]}), vec![]),
            "Target.attachToTarget" => (json!({"sessionId": "SESS1"}), vec![]),
            "Page.getFrameTree" => (json!({"frameTree": {"frame": {"id": "MAIN", "url": st["url"]}}}), vec![]),
            "Page.navigate" => {
                st["url"] = p["url"].clone();
                (json!({"frameId": "MAIN", "loaderId": "L1"}), vec![ev("Page.frameNavigated", json!({"frame": {"id": "MAIN", "url": p["url"]}})), ev("Page.loadEventFired", json!({})), ev("Runtime.consoleAPICalled", json!({"type": "log", "args": [{"type": "string", "value": "hello from page"}]}))])
            }
            "Runtime.evaluate" => {
                let e = p["expression"].as_str().unwrap_or("");
                let v = if e.starts_with("[location.href") {
                    json!([st["url"], "Fake Page"])
                } else if e.starts_with("((boxes)") {
                    // The labels overlay: the page counts the boxes it drew.
                    let n = e.rsplit_once("})(").and_then(|(_, a)| serde_json::from_str::<Vec<Value>>(a.trim_end_matches(')')).ok()).map(|v| v.len()).unwrap_or(0);
                    st["labels"] = (st["labels"].as_i64().unwrap_or(0) + n as i64).into();
                    json!(n)
                } else if e.contains("__ark-annotations__") && e.contains("remove()") {
                    st["labels_removed"] = (st["labels_removed"].as_i64().unwrap_or(0) + 1).into();
                    Value::Null
                } else if e.contains("data-ark-ci") || e.contains("document.images") {
                    json!([])
                } else if e == "window.location.href" {
                    st["url"].clone()
                } else if e == "document.title" {
                    json!("Fake Page")
                } else {
                    Value::Null
                };
                (json!({"result": {"type": "object", "value": v}}), vec![])
            }
            "Accessibility.getFullAXTree" => (json!({"nodes": [
                {"nodeId": "1", "role": {"value": "RootWebArea"}, "name": {"value": "Fake Page"}, "childIds": ["2", "3"], "backendDOMNodeId": 1},
                {"nodeId": "2", "role": {"value": "button"}, "name": {"value": "Sign in"}, "childIds": [], "backendDOMNodeId": 20},
                {"nodeId": "3", "role": {"value": "textbox"}, "name": {"value": "Email"}, "childIds": [], "backendDOMNodeId": 30}
            ]}), vec![]),
            "DOM.getContentQuads" => (json!({"quads": [match p["backendNodeId"].as_i64() {
                Some(30) => json!([10, 60, 210, 60, 210, 90, 10, 90]),
                _ => json!([10, 10, 110, 10, 110, 40, 10, 40]),
            }]}), vec![]),
            // The border box of the element, for element screenshots.
            "DOM.getBoxModel" => (json!({"model": {"border": match p["backendNodeId"].as_i64() {
                Some(30) => json!([10, 60, 210, 60, 210, 90, 10, 90]),
                _ => json!([10, 10, 110, 10, 110, 40, 10, 40]),
            }}}), vec![]),
            "DOM.getDocument" => (json!({"root": {"nodeId": 1}}), vec![]),
            "DOM.querySelector" => (json!({"nodeId": if p["selector"] == "#c" { 2 } else { 0 }}), vec![]),
            "DOM.describeNode" => (json!({"node": {"backendNodeId": 20, "nodeId": 2}}), vec![]),
            "DOM.resolveNode" => (json!({"object": {"objectId": format!("obj-{}", p["backendNodeId"])}}), vec![]),
            "Runtime.callFunctionOn" => (json!({"result": {"value": "value"}}), vec![]),
            "Input.dispatchMouseEvent" => {
                if p["type"] == "mouseReleased" {
                    st["clicks"] = (st["clicks"].as_i64().unwrap() + 1).into();
                }
                (json!({}), vec![])
            }
            "Input.insertText" => {
                st["typed"] = p["text"].clone();
                let t = p["text"].as_str().unwrap_or("").to_string();
                st["inserts"].as_array_mut().unwrap().push(json!(t));
                (json!({}), vec![])
            }
            // The page receives keystrokes: a keyDown whose text is Enter submits it.
            "Input.dispatchKeyEvent" => {
                let key = p["key"].as_str().unwrap_or("").to_string();
                if p["type"] == "keyDown" {
                    st["keys"].as_array_mut().unwrap().push(json!(key));
                    if key == "Enter" {
                        st["submits"] = (st["submits"].as_i64().unwrap() + 1).into();
                    }
                }
                (json!({}), vec![])
            }
            "Page.getLayoutMetrics" => (json!({"cssLayoutViewport": {"clientWidth": 800, "clientHeight": 600}, "cssVisualViewport": {"pageX": 0, "pageY": 0}, "visualViewport": {"clientWidth": 800}, "cssContentSize": {"width": 800, "height": 1600}}), vec![]),
            // The image is a PNG whose IHDR carries the clip's size, so tests can read back
            // exactly what region was captured.
            "Page.captureScreenshot" => {
                st["captures"].as_array_mut().unwrap().push(p.clone());
                let (w, h) = (p["clip"]["width"].as_f64().unwrap_or(800.0), p["clip"]["height"].as_f64().unwrap_or(600.0));
                (json!({"data": ark_net::crypto::b64(&png_of(w as u32, h as u32))}), vec![])
            }
            "Page.printToPDF" => (json!({"data": ark_net::crypto::b64(b"%PDF-1.7 fake")}), vec![]),
            "Page.getNavigationHistory" => (json!({"currentIndex": 1, "entries": [{"id": 1, "url": "https://first.example/"}, {"id": 2, "url": st["url"]}]}), vec![]),
            "Page.navigateToHistoryEntry" => {
                st["url"] = "https://first.example/".into();
                (json!({}), vec![ev("Page.frameNavigated", json!({"frame": {"id": "MAIN", "url": "https://first.example/"}})), ev("Page.loadEventFired", json!({}))])
            }
            "Network.getAllCookies" => (json!({"cookies": [{"name": "sid", "value": "ghp_abcdefghijklmnopqrstuvwxyz0123456789"}]}), vec![]),
            "http:/json/list" => (json!([]), vec![]),
            _ => (json!({}), vec![]),
        }
    }))
}

fn fake_page() -> crate::cdp::fake::Fake {
    page_behind(Arc::new(Mutex::new(page_state())))
}

/// The fake page plus the state it recorded (text typed, keys pressed, submits, captures).
fn fake_page_recording() -> (crate::cdp::fake::Fake, Arc<Mutex<Value>>) {
    let st = Arc::new(Mutex::new(page_state()));
    (page_behind(st.clone()), st)
}

#[test]
fn hermes_tools_against_a_fake_cdp_browser() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let f = fake_page();
    let cfg = BrowserConfig { backend: "cdp".into(), cdp_url: f.http.clone(), enabled: toml::Value::Boolean(true), ..Default::default() };
    let c = ctx("hermes", "sess-hermes");
    let (ok, _, raw) = call(&cfg, &c, "browser_snapshot", json!({}));
    assert!(!ok && raw.contains("browser_navigate first"));
    let (ok, _, raw) = call(&cfg, &c, "browser_navigate", json!({"url": "https://x.test/?key=sk-ant-abcdefghijklmnopqrstuvwxyz"}));
    assert!(!ok && raw.contains("API key"));
    let (ok, v, raw) = call(&cfg, &c, "browser_navigate", json!({"url": "https://app.example/login"}));
    assert!(ok, "{raw}");
    assert_eq!(v["url"], "https://app.example/login");
    assert!(v["snapshot"].as_str().unwrap().contains("button \"Sign in\" [ref=e1]"), "{raw}");
    assert_eq!(v["element_count"], 2);
    let (ok, v, raw) = call(&cfg, &c, "browser_click", json!({"ref": "@e1"}));
    assert!(ok, "{raw}");
    assert_eq!(v["clicked"], "@e1");
    let (ok, v, _) = call(&cfg, &c, "browser_type", json!({"ref": "e2", "text": "me@example.com"}));
    assert!(ok && v["element"] == "@e2");
    let (ok, _, raw) = call(&cfg, &c, "browser_click", json!({"ref": "e99"}));
    assert!(!ok && raw.contains("Unknown ref"));
    let (ok, v, _) = call(&cfg, &c, "browser_console", json!({}));
    assert!(ok && v["console_messages"][0]["text"] == "hello from page", "{v}");
    let (ok, v, _) = call(&cfg, &c, "browser_console", json!({"expression": "document.title"}));
    assert!(ok && v["result"] == "Fake Page" && v["result_type"] == "str");
    let (ok, v, _) = call(&cfg, &c, "browser_vision", json!({"question": "what is shown?"}));
    assert!(ok && v["analysis"].as_str().unwrap().starts_with("saw image/png"), "{v}");
    assert!(std::path::Path::new(v["screenshot_path"].as_str().unwrap()).is_file());
    let (ok, v, _) = call(&cfg, &c, "browser_cdp", json!({"method": "Network.getAllCookies"}));
    assert!(ok && v["result"]["cookies"][0]["value"] == "[REDACTED]", "{v}");
    let (ok, v, _) = call(&cfg, &c, "browser_back", json!({}));
    assert!(ok && v["url"] == "https://first.example/", "{v}");
    let (ok, _, raw) = call(&cfg, &c, "browser_dialog", json!({"action": "accept"}));
    assert!(!ok && raw.contains("No dialog"));
    let (ok, _, _) = call(&cfg, &c, "browser_press", json!({"key": "Enter"}));
    assert!(ok);
    let (ok, v, _) = call(&cfg, &c, "browser_scroll", json!({"direction": "down"}));
    assert!(ok && v["scrolled"] == "down");
    let (ok, v, _) = call(&cfg, &c, "browser_vault", json!({"action": "list"}));
    assert!(ok && v["hint"].as_str().unwrap().contains("save_login"));
    let seen = f.seen.lock().unwrap();
    assert!(seen.iter().any(|m| m["method"] == "Input.insertText" && m["params"]["text"] == "me@example.com"));
    assert!(seen.iter().filter(|m| m["method"] == "Input.dispatchMouseEvent" && m["params"]["type"] == "mousePressed").any(|m| m["params"]["x"] == 60.0 && m["params"]["y"] == 25.0));
    crate::manager::global().stop("cdp");
}

#[test]
fn a_human_takeover_fences_every_browser_tool() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let f = fake_page();
    let cfg = BrowserConfig { backend: "cdp".into(), cdp_url: f.http.clone(), enabled: toml::Value::Boolean(true), ..Default::default() };
    let c = ctx("fence", "sess-fence");
    let (ok, _, raw) = call(&cfg, &c, "browser_navigate", json!({"url": "https://app.example/login"}));
    assert!(ok, "{raw}");
    // A person takes over from the web console (a plain CDP browser, not the Bot Desktop).
    crate::lease::acquire(&c.home, "web-viewer-0001", "typing a password").unwrap();
    for (tool, input) in [("browser_click", json!({"ref": "e1"})), ("browser_type", json!({"ref": "e2", "text": "x"})), ("browser_snapshot", json!({})), ("browser_navigate", json!({"url": "https://app.example/other"}))] {
        let (ok, _, raw) = call(&cfg, &c, tool, input);
        if ok || !raw.contains("human has taken over") {
            crate::manager::global().stop("cdp");
            panic!("{tool} acted during a takeover: {raw}");
        }
    }
    crate::lease::release(&c.home, Some("web-viewer-0001"), false).unwrap();
    let (ok, _, raw) = call(&cfg, &c, "browser_click", json!({"ref": "e1"}));
    crate::manager::global().stop("cdp");
    assert!(ok, "after hand-back: {raw}");
}

#[test]
fn the_desktop_vm_backend_drives_the_vm_chromium_under_the_vm_lease() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let cfg = BrowserConfig { desktop_vm: "desk".into(), enabled: toml::Value::Boolean(true), ..Default::default() };
    assert_eq!(cfg.backend(), "vm");
    let c = ctx("vmb", "sess-vmb");
    let (ok, _, raw) = call(&cfg, &c, "browser_navigate", json!({"url": "https://app.example/"}));
    assert!(!ok && raw.contains("desktop VM `desk` is not running") && raw.contains("ark vm desktop start desk"), "{raw}");
    // The VM is up: it names its Chromium's DevTools endpoint.
    let f = fake_page();
    let vm = crate::manager::vm_home(&c.home, "desk");
    std::fs::create_dir_all(&vm).unwrap();
    std::fs::write(vm.join(crate::manager::VM_CDP_FILE), format!("{}\n", f.http)).unwrap();
    let (ok, _, raw) = call(&cfg, &c, "browser_navigate", json!({"url": "https://app.example/"}));
    assert!(ok, "{raw}");
    // A person takes over the VM from the console: its lease, not the host's, fences the tools.
    crate::lease::acquire(&vm, "web-viewer-0002", "checking the page").unwrap();
    let (ok, _, raw) = call(&cfg, &c, "browser_click", json!({"ref": "e1"}));
    let oc = tool(&cfg, "browser").call(&c, json!({"action": "snapshot"}));
    crate::lease::release(&vm, Some("web-viewer-0002"), false).unwrap();
    let (after, _, raw2) = call(&cfg, &c, "browser_click", json!({"ref": "e1"}));
    crate::manager::global().stop("vm:desk");
    assert!(!ok && raw.contains("human has taken over"), "{raw}");
    assert!(format!("{oc:?}").contains("human has taken over"), "{oc:?}");
    assert!(after, "after hand-back: {raw2}");
}

#[test]
fn openclaw_browser_tool_against_a_fake_cdp_browser() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let f = fake_page();
    let cfg = BrowserConfig { backend: "cdp".into(), cdp_url: f.http.clone(), enabled: toml::Value::Boolean(true), ..Default::default() };
    let c = ctx("oc", "sess-oc");
    let t = tool(&cfg, "browser");
    let r = |input: Value| t.call(&c, input);
    let o = r(json!({"action": "navigate", "url": "https://shop.example/"}));
    assert!(!o.is_error && o.content.contains("EXTERNAL_UNTRUSTED_CONTENT") && o.content.contains("[ref=e1]"), "{}", o.content);
    let o = r(json!({"action": "snapshot", "query": "sign"}));
    assert!(o.content.contains("1 matching line(s)"), "{}", o.content);
    let o = r(json!({"action": "tabs"}));
    assert!(o.content.contains("\"tabId\": \"t1\""), "{}", o.content);
    let o = r(json!({"action": "act", "request": {"kind": "type", "ref": "e2", "text": "abc", "submit": true}}));
    assert!(!o.is_error, "{}", o.content);
    let o = r(json!({"action": "act", "kind": "batch", "actions": [{"kind": "click", "ref": "e1"}, {"kind": "press", "key": "Tab"}]}));
    assert!(!o.is_error && o.content.contains("\"results\""), "{}", o.content);
    let o = r(json!({"action": "act", "kind": "resize", "width": 9000, "height": 10}));
    assert!(o.is_error && o.content.contains("8192"));
    let o = r(json!({"action": "act", "kind": "wait"}));
    assert!(o.is_error && o.content.contains("wait requires at least one of"));
    let o = r(json!({"action": "screenshot", "fullPage": true}));
    assert!(!o.is_error && o.content.contains("Screenshot saved to"), "{}", o.content);
    let o = r(json!({"action": "pdf", "path": "out/page.pdf"}));
    assert!(o.content.starts_with("FILE:") && c.workspace.join("out/page.pdf").is_file(), "{}", o.content);
    let o = r(json!({"action": "console", "level": "warn"}));
    assert!(o.content.contains("\"messages\": []"), "{}", o.content);
    let o = r(json!({"action": "requests"}));
    assert!(o.content.contains("\"requests\""));
    let o = r(json!({"action": "emulate"}));
    assert!(o.is_error && o.content.contains("emulate requires"));
    let o = r(json!({"action": "emulate", "colorScheme": "dark", "device": "iPhone 13"}));
    assert!(!o.is_error, "{}", o.content);
    let o = r(json!({"action": "dialog", "accept": false}));
    assert!(o.content.contains("\"armed\":true"), "{}", o.content);
    let o = r(json!({"action": "upload", "paths": ["missing.txt"], "inputRef": "e2"}));
    assert!(o.is_error && o.content.contains("not found"));
    std::fs::write(c.workspace.join("up.txt"), "x").unwrap();
    let o = r(json!({"action": "upload", "paths": ["up.txt"], "inputRef": "e2"}));
    assert!(!o.is_error, "{}", o.content);
    let o = r(json!({"action": "profiles"}));
    assert!(o.content.contains("\"user\""));
    let o = r(json!({"action": "doctor"}));
    assert!(o.content.contains("CDP HTTP endpoint is reachable"), "{}", o.content);
    let o = r(json!({"action": "open", "url": "file:///etc/passwd"}));
    assert!(o.is_error && o.content.contains("unsupported protocol"));
    assert!(f.seen.lock().unwrap().iter().any(|m| m["method"] == "Emulation.setEmulatedMedia"));
    crate::manager::global().stop("cdp");
}

/// The JSON line of a screenshot reply and the file it saved.
fn shot_of(o: &ark_core::ToolOutput) -> (std::path::PathBuf, Value) {
    let v: Value = serde_json::from_str(o.content.rsplit('\n').next().unwrap()).unwrap_or_else(|_| panic!("no screenshot JSON in: {}", o.content));
    (std::path::PathBuf::from(v["path"].as_str().expect("screenshot path")), v)
}

/// IHDR width/height of a PNG (the fake page's images carry the clip size there).
fn png_dims(b: &[u8]) -> (u32, u32) {
    assert!(b.starts_with(b"\x89PNG\r\n\x1a\n"), "not a PNG: {b:?}");
    (u32::from_be_bytes(b[16..20].try_into().unwrap()), u32::from_be_bytes(b[20..24].try_into().unwrap()))
}

/// G10: element (ref and selector) clips, fullPage and the labels overlay against a fake
/// page — the saved PNG's size and the clip/label commands are asserted, not just "no error".
#[test]
fn screenshots_clip_by_element_and_fullpage_and_draw_labels() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (f, st) = fake_page_recording();
    let cfg = BrowserConfig { backend: "cdp".into(), cdp_url: f.http.clone(), enabled: toml::Value::Boolean(true), ..Default::default() };
    let c = ctx("shots", "sess-shots");
    let t = tool(&cfg, "browser");
    let o = t.call(&c, json!({"action": "navigate", "url": "https://shop.example/"}));
    assert!(!o.is_error && o.content.contains("[ref=e1]"), "{}", o.content);

    // Element by ref: the button's border box (10,10 100x30) is the clip.
    let o = t.call(&c, json!({"action": "screenshot", "ref": "e1"}));
    assert!(!o.is_error, "{}", o.content);
    let (p, v) = shot_of(&o);
    assert_eq!(png_dims(&std::fs::read(&p).unwrap()), (100, 30), "element clip is the element's box");
    assert_eq!(v["labels"], false);

    // Element by selector resolves through DOM.getDocument / querySelector / describeNode.
    let o = t.call(&c, json!({"action": "screenshot", "element": "#c"}));
    assert!(!o.is_error, "{}", o.content);
    let (p, _) = shot_of(&o);
    assert_eq!(png_dims(&std::fs::read(&p).unwrap()), (100, 30));

    // fullPage: the whole 800x1600 content, captured beyond the viewport.
    let o = t.call(&c, json!({"action": "screenshot", "fullPage": true}));
    assert!(!o.is_error, "{}", o.content);
    let (p, _) = shot_of(&o);
    assert_eq!(png_dims(&std::fs::read(&p).unwrap()), (800, 1600));
    let caps = st.lock().unwrap()["captures"].clone();
    let last = caps.as_array().unwrap().last().unwrap().clone();
    assert_eq!(last["captureBeyondViewport"], true, "{last}");
    assert_eq!((last["clip"]["width"].as_f64(), last["clip"]["height"].as_f64()), (Some(800.0), Some(1600.0)));

    // fullPage + element is refused before any capture (one image is not the other).
    let o = t.call(&c, json!({"action": "screenshot", "fullPage": true, "ref": "e1"}));
    assert!(o.is_error && o.content.contains("fullPage is not supported for element screenshots"), "{}", o.content);

    // Labels: one annotation per ref, drawn on the page and removed again.
    let o = t.call(&c, json!({"action": "screenshot", "labels": true}));
    assert!(!o.is_error, "{}", o.content);
    let (_, v) = shot_of(&o);
    assert_eq!((v["labels"].as_bool(), v["labelsCount"].as_i64(), v["labelsSkipped"].as_i64()), (Some(true), Some(2), Some(0)), "{v}");
    let ann = v["annotations"].as_array().unwrap();
    assert_eq!(ann.len(), 2, "{v}");
    assert_eq!((ann[0]["ref"].as_str(), ann[1]["ref"].as_str()), (Some("e1"), Some("e2")));
    let box_of = |a: &Value| (a["box"]["x"].as_f64(), a["box"]["y"].as_f64(), a["box"]["width"].as_f64(), a["box"]["height"].as_f64());
    assert_eq!(box_of(&ann[0]), (Some(10.0), Some(10.0), Some(100.0), Some(30.0)));
    assert_eq!(box_of(&ann[1]), (Some(10.0), Some(60.0), Some(200.0), Some(30.0)));
    let s = st.lock().unwrap();
    assert_eq!((s["labels"].as_i64(), s["labels_removed"].as_i64()), (Some(2), Some(1)), "the overlay was drawn once and removed: {s}");
    assert!(f.seen.lock().unwrap().iter().any(|m| m["method"] == "Runtime.evaluate" && m["params"]["expression"].as_str().unwrap_or("").starts_with("((boxes)")));
    drop(s);
    crate::manager::global().stop("cdp");
}

/// G11: `act type` reaches the page as text and its `submit` presses Enter — the fake page
/// records both, so a dropped `submit` (or an unconditional Enter) fails this test.
#[test]
fn act_type_records_keystrokes_and_submits() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (f, st) = fake_page_recording();
    let cfg = BrowserConfig { backend: "cdp".into(), cdp_url: f.http.clone(), enabled: toml::Value::Boolean(true), ..Default::default() };
    let c = ctx("acttype", "sess-acttype");
    let t = tool(&cfg, "browser");
    let o = t.call(&c, json!({"action": "navigate", "url": "https://shop.example/"}));
    assert!(!o.is_error, "{}", o.content);

    let o = t.call(&c, json!({"action": "act", "request": {"kind": "type", "ref": "e2", "text": "ark-42", "submit": true}}));
    assert!(!o.is_error, "{}", o.content);
    {
        let s = st.lock().unwrap();
        assert_eq!(s["typed"], "ark-42", "the text landed in the field: {s}");
        assert_eq!(s["inserts"], json!(["ark-42"]));
        assert_eq!(s["keys"], json!(["Enter"]), "submit is exactly one Enter keyDown: {s}");
        assert_eq!(s["submits"], 1, "{s}");
    }
    // The text arrived before the submit, not after.
    let seen = f.seen.lock().unwrap();
    let pos = |pred: &dyn Fn(&Value) -> bool| seen.iter().position(pred);
    let text_at = pos(&|m| m["method"] == "Input.insertText" && m["params"]["text"] == "ark-42").expect("insertText");
    let enter_at = pos(&|m| m["method"] == "Input.dispatchKeyEvent" && m["params"]["key"] == "Enter" && m["params"]["type"] == "keyDown").expect("Enter keydown");
    assert!(text_at < enter_at, "insertText before Enter");
    assert!(seen[enter_at]["params"]["text"] == "\r", "Enter carries a submit text: {}", seen[enter_at]);
    drop(seen);

    // Without submit the field still fills but no Enter is sent.
    let o = t.call(&c, json!({"action": "act", "request": {"kind": "type", "ref": "e2", "text": "second"}}));
    assert!(!o.is_error, "{}", o.content);
    let s = st.lock().unwrap();
    assert_eq!((s["typed"].as_str(), s["submits"].as_i64(), s["keys"].as_array().unwrap().len()), (Some("second"), Some(1), 1), "{s}");
    drop(s);
    crate::manager::global().stop("cdp");
}

/// Tiny HTTP server for the real-browser test.
pub(crate) fn serve(html: &'static str) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut s = s;
            let mut b = [0u8; 4096];
            let n = s.read(&mut b).unwrap_or(0);
            let req = String::from_utf8_lossy(&b[..n]).to_string();
            let (ctype, body): (&str, Vec<u8>) = if req.starts_with("GET /file.txt") { ("text/plain", b"download me".to_vec()) } else { ("text/html", html.as_bytes().to_vec()) };
            let extra = if req.starts_with("GET /file.txt") { "content-disposition: attachment; filename=\"file.txt\"\r\n" } else { "" };
            let _ = write!(s, "HTTP/1.1 200 OK\r\ncontent-type: {ctype}\r\n{extra}content-length: {}\r\nconnection: close\r\n\r\n", body.len());
            let _ = s.write_all(&body);
        }
    });
    base
}

pub(crate) const PAGE: &str = r#"<!doctype html><html><head><title>Real Test</title></head><body>
<h1>Hello ark</h1>
<button id="b" onclick="document.getElementById('out').textContent='clicked'; console.log('btn clicked')">Press me</button>
<input id="name" aria-label="Name">
<select id="s" aria-label="Color"><option value="r">Red</option><option value="g">Green</option></select>
<button id="c" onclick="document.getElementById('out').textContent = confirm('Sure?') ? 'yes' : 'no'">Confirm</button>
<input type="file" id="f" aria-label="Upload">
<a href="/file.txt" id="dl">Download file</a>
<p id="out">idle</p>
<form id="login"><input type="email" aria-label="Email"><input type="password" aria-label="Password"></form>
<script>setTimeout(() => { throw new Error('boom') }, 10)</script>
</body></html>"#;

