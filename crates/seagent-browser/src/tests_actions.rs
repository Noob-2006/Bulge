//! Tool-level tests for the actions that only the real-Chromium run used to cover
//! (hover, drag, fill, select, focus, close, open, download, text, get_images, vault fill,
//! status/start/stop) plus the Lightpanda serve and fallback paths.
//!
//! The fake is a scripted page: elements sit at distinct coordinates so mouse movements can
//! be asserted, a checkbox toggles on the click the fill path sends, and the download link
//! emits the DevTools download events while writing the file the supervisor expects.

use crate::config::BrowserConfig;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use crate::tests::{call, ctx, tool, SERIAL};

/// A fake page with a login form, a checkbox, a select, two drag targets and a download link.
/// `downloads` is the directory the browser will look in, so the fake can "save" the file.
fn fake_page2(downloads: std::path::PathBuf) -> crate::cdp::fake::Fake {
    let state = Arc::new(Mutex::new(json!({"url": "about:blank", "typed": "", "checked": false, "clicks": 0, "tabs": ["PAGE2"]})));
    let dl = Arc::new(downloads);
    crate::cdp::fake::start(Arc::new(move |m, p, sid| {
        let mut st = state.lock().unwrap();
        let ev = |method: &str, params: Value| json!({"method": method, "params": params, "sessionId": sid});
        match m {
            "Target.getTargets" => {
                let tabs: Vec<Value> = st["tabs"].as_array().cloned().unwrap_or_default().into_iter().map(|id| json!({"targetId": id, "type": "page", "url": st["url"], "title": "Login"})).collect();
                (json!({"targetInfos": tabs}), vec![])
            }
            "Target.attachToTarget" => (json!({"sessionId": "SESS2"}), vec![]),
            "Target.createTarget" => {
                if let Some(a) = st["tabs"].as_array_mut() {
                    if !a.iter().any(|t| t == "PAGE3") {
                        a.push(json!("PAGE3"));
                    }
                }
                (json!({"targetId": "PAGE3"}), vec![])
            }
            "Target.closeTarget" => {
                let id = p["targetId"].as_str().unwrap_or("").to_string();
                if let Some(a) = st["tabs"].as_array_mut() {
                    a.retain(|t| t != id.as_str());
                }
                (json!({}), vec![])
            }
            "Target.activateTarget" | "Target.detachFromTarget" => (json!({}), vec![]),
            "Page.getFrameTree" => (json!({"frameTree": {"frame": {"id": "MAIN", "url": st["url"]}}}), vec![]),
            "Page.navigate" => {
                st["url"] = p["url"].clone();
                (json!({"frameId": "MAIN", "loaderId": "L2"}), vec![ev("Page.frameNavigated", json!({"frame": {"id": "MAIN", "url": p["url"]}})), ev("Page.loadEventFired", json!({}))])
            }
            "Runtime.evaluate" => {
                let e = p["expression"].as_str().unwrap_or("");
                let v = if e.contains("document.images") {
                    json!([{"src": "https://img.example/photo.png", "alt": "Photo", "width": 640, "height": 480}])
                } else if e.starts_with("[location.href") {
                    json!([st["url"], "Login"])
                } else if e.contains("window.location.href") {
                    // vault_tool::page_origin
                    st["url"].clone()
                } else if e.starts_with("!!document.querySelector") {
                    // vault_tool::TAB_PROBES: this page has a login form.
                    json!(true)
                } else if e.contains("data-seagent-vault-slot") && !e.contains("const expectedOrigin") {
                    // vault::inspection_js: the fake page's username + password fields.
                    json!([
                        {"autocomplete": "username", "formIndex": 0, "index": 0, "maxLength": null, "label": "Email", "name": "email", "type": "text"},
                        {"autocomplete": "current-password", "formIndex": 0, "index": 1, "maxLength": null, "label": "Password", "name": "password", "type": "password"}
                    ])
                } else if e.contains("const expectedOrigin") {
                    // vault::fill_js writes the password and reports how many fields it filled.
                    if e.contains("\"current-password\"") || e.contains("current-password") {
                        st["filled"] = json!(true);
                        json!({"filled": 1})
                    } else {
                        json!({"filled": 0})
                    }
                } else if e.contains("innerText") {
                    json!("Hello seagent page text")
                } else if e.contains("input[type=password]") {
                    json!("[REDACTED]")
                } else {
                    Value::Null
                };
                (json!({"result": {"type": "object", "value": v}}), vec![])
            }
            "Accessibility.getFullAXTree" => (json!({"nodes": [
                {"nodeId": "1", "role": {"value": "RootWebArea"}, "name": {"value": "Login"}, "childIds": ["2", "3", "4", "5", "6", "7", "8", "9"], "backendDOMNodeId": 1},
                {"nodeId": "2", "role": {"value": "button"}, "name": {"value": "Sign in"}, "childIds": [], "backendDOMNodeId": 20},
                {"nodeId": "3", "role": {"value": "textbox"}, "name": {"value": "Email"}, "childIds": [], "backendDOMNodeId": 30},
                {"nodeId": "4", "role": {"value": "button"}, "name": {"value": "Drag source"}, "childIds": [], "backendDOMNodeId": 40},
                {"nodeId": "5", "role": {"value": "button"}, "name": {"value": "Drop target"}, "childIds": [], "backendDOMNodeId": 50},
                {"nodeId": "6", "role": {"value": "checkbox"}, "name": {"value": "Remember me"}, "childIds": [], "backendDOMNodeId": 60},
                {"nodeId": "7", "role": {"value": "combobox"}, "name": {"value": "Color"}, "childIds": [], "backendDOMNodeId": 70},
                {"nodeId": "8", "role": {"value": "link"}, "name": {"value": "Download file"}, "childIds": [], "backendDOMNodeId": 80},
                {"nodeId": "9", "role": {"value": "heading"}, "name": {"value": "Hello seagent"}, "childIds": [], "backendDOMNodeId": 90}
            ]}), vec![]),
            "DOM.getContentQuads" => {
                let q = match p["backendNodeId"].as_i64().unwrap_or(0) {
                    20 => json!([[10, 10, 110, 10, 110, 40, 10, 40]]),
                    30 => json!([[10, 50, 210, 50, 210, 90, 10, 90]]),
                    40 => json!([[10, 100, 70, 100, 70, 140, 10, 140]]),
                    50 => json!([[200, 100, 260, 100, 260, 140, 200, 140]]),
                    60 => json!([[10, 160, 30, 160, 30, 180, 10, 180]]),
                    70 => json!([[10, 200, 150, 200, 150, 230, 10, 230]]),
                    80 => json!([[200, 200, 300, 200, 300, 230, 200, 230]]),
                    _ => json!([[10, 240, 100, 240, 100, 260, 10, 260]]),
                };
                (json!({"quads": q}), vec![])
            }
            "DOM.resolveNode" => (json!({"object": {"objectId": format!("obj-{}", p["backendNodeId"])}}), vec![]),
            "DOM.focus" | "DOM.scrollIntoViewIfNeeded" => (json!({}), vec![]),
            "Runtime.callFunctionOn" => {
                let f = p["functionDeclaration"].as_str().unwrap_or("");
                let v = if f.contains("checked") {
                    st["checked"].clone()
                } else if f.contains("tagName !== 'SELECT'") {
                    json!(["g"])
                } else if f.contains("'value' in this") || f.contains("textContent = t") {
                    Value::Null
                } else {
                    json!("value")
                };
                (json!({"result": {"value": v}}), vec![])
            }
            "Input.dispatchMouseEvent" => {
                let (x, y) = (p["x"].as_f64().unwrap_or(0.0), p["y"].as_f64().unwrap_or(0.0));
                if p["type"] == "mousePressed" {
                    st["clicks"] = (st["clicks"].as_i64().unwrap_or(0) + 1).into();
                    // The checkbox (10..30 × 160..180) toggles; the download link saves a file.
                    if (10.0..30.0).contains(&x) && (160.0..180.0).contains(&y) {
                        st["checked"] = (!st["checked"].as_bool().unwrap_or(false)).into();
                    }
                    if (200.0..300.0).contains(&x) && (200.0..230.0).contains(&y) {
                        std::fs::create_dir_all(&*dl).unwrap();
                        std::fs::write(dl.join("dl-guid"), "download me").unwrap();
                        return (
                            json!({}),
                            vec![
                                ev("Browser.downloadWillBegin", json!({"guid": "dl-guid", "url": "https://mine.example/file.txt", "suggestedFilename": "file.txt", "frameId": "MAIN"})),
                                ev("Browser.downloadProgress", json!({"guid": "dl-guid", "state": "completed", "receivedBytes": 11, "totalBytes": 11})),
                            ],
                        );
                    }
                }
                (json!({}), vec![])
            }
            "Input.insertText" => {
                st["typed"] = p["text"].clone();
                (json!({}), vec![])
            }
            "Page.getLayoutMetrics" => (json!({"cssLayoutViewport": {"clientWidth": 800, "clientHeight": 600}, "cssVisualViewport": {"pageX": 0, "pageY": 0}, "visualViewport": {"clientWidth": 800}, "cssContentSize": {"width": 800, "height": 1600}}), vec![]),
            "Page.captureScreenshot" => (json!({"data": seagent_net::crypto::b64(b"\x89PNG fake")}), vec![]),
            "Page.printToPDF" => (json!({"data": seagent_net::crypto::b64(b"%PDF-1.7 fake")}), vec![]),
            "Page.getNavigationHistory" => (json!({"currentIndex": 0, "entries": [{"id": 1, "url": st["url"]}]}), vec![]),
            "Browser.getVersion" => (json!({"product": "Chrome/120.0 fake"}), vec![]),
            "Network.getAllCookies" => (json!({"cookies": []}), vec![]),
            "http:/json/list" => (json!([]), vec![]),
            _ => (json!({}), vec![]),
        }
    }))
}

fn browser_cfg(f: &crate::cdp::fake::Fake) -> BrowserConfig {
    BrowserConfig { backend: "cdp".into(), cdp_url: f.http.clone(), enabled: toml::Value::Boolean(true), ..Default::default() }
}

/// The ref of the snapshot line whose text contains `name`.
fn refs(snap: &str, name: &str) -> String {
    snap.lines().find(|l| l.contains(name)).and_then(|l| l.split("[ref=").nth(1)).map(|r| r.split(']').next().unwrap().to_string()).unwrap_or_else(|| panic!("no ref for {name} in {snap}"))
}

fn started(c: &seagent_core::ToolCtx) -> String {
    c.home.join("browser/state/cdp/downloads").display().to_string()
}

/// The JSON payload of a tool result: OpenClaw wraps page-derived output in an
/// `<<<EXTERNAL_UNTRUSTED_CONTENT>>>` envelope and pretty-prints it.
fn payload(content: &str) -> Value {
    let head = "\nSource: Browser\n---\n";
    let body = match (content.find(head), content.rfind("<<<END_EXTERNAL_UNTRUSTED_CONTENT")) {
        (Some(i), Some(j)) if j > i => &content[i + head.len()..j],
        _ => content,
    };
    serde_json::from_str(body.trim()).unwrap_or_else(|e| panic!("tool result is not JSON ({e}): {content}"))
}

#[test]
fn openclaw_act_hover_drag_fill_select_focus_and_close() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let c = ctx("act2", "sess-act2");
    let f = fake_page2(started(&c).into());
    let cfg = browser_cfg(&f);
    let t = tool(&cfg, "browser");
    let r = |input: Value| t.call(&c, input);
    let o = r(json!({"action": "open", "url": "https://login.example/form"}));
    assert!(!o.is_error, "open succeeds on a fake page: {}", o.content);
    assert!(o.content.contains("login.example"), "{}", o.content);
    let o = r(json!({"action": "snapshot"}));
    let snap = o.content;
    assert!(snap.contains("Sign in"), "{}", snap);
    let (email, checkbox, color) = (refs(&snap, "Email"), refs(&snap, "Remember me"), refs(&snap, "Color"));
    let (src, dst) = (refs(&snap, "Drag source"), refs(&snap, "Drop target"));
    // hover moves the pointer onto the element centre (60,25).
    let o = r(json!({"action": "act", "kind": "hover", "ref": "e1"}));
    assert!(!o.is_error, "{}", o.content);
    {
        let seen = f.seen.lock().unwrap();
        let moves: Vec<String> = seen.iter().filter(|m| m["method"] == "Input.dispatchMouseEvent").map(|m| m["params"].to_string()).collect();
        assert!(seen.iter().any(|m| m["method"] == "Input.dispatchMouseEvent" && m["params"]["type"] == "mouseMoved" && m["params"]["x"] == 60.0 && m["params"]["y"] == 25.0), "hover point: {moves:?}");
    }
    // drag: press at the source centre, move 10 steps, release at the target centre.
    let o = r(json!({"action": "act", "kind": "drag", "startRef": src, "endRef": dst}));
    assert!(!o.is_error, "{}", o.content);
    {
        let seen = f.seen.lock().unwrap();
        let moves: Vec<&Value> = seen.iter().filter(|m| m["method"] == "Input.dispatchMouseEvent" && m["params"]["type"] == "mouseMoved").collect();
        assert!(moves.iter().any(|m| m["params"]["x"] == 40.0 && m["params"]["y"] == 120.0), "drag start");
        assert!(moves.iter().any(|m| m["params"]["x"] == 230.0 && m["params"]["y"] == 120.0), "drag end: {}", serde_json::to_string(&moves).unwrap());
        assert!(seen.iter().any(|m| m["method"] == "Input.dispatchMouseEvent" && m["params"]["type"] == "mouseReleased" && m["params"]["x"] == 230.0));
    }
    // fill: a text field and a checkbox (a click, because it is unchecked).
    let o = r(json!({"action": "act", "kind": "fill", "fields": [{"ref": email, "type": "text", "value": "me@x.example"}, {"ref": checkbox, "type": "checkbox", "value": true}]}));
    assert!(!o.is_error && payload(&o.content)["filled"] == 2, "{}", o.content);
    assert!(f.seen.lock().unwrap().iter().any(|m| m["method"] == "Input.insertText" && m["params"]["text"] == "me@x.example"));
    let o = r(json!({"action": "act", "kind": "fill", "fields": [{"ref": email, "value": "x", "bogus": 1}]}));
    assert!(o.is_error && o.content.contains("unsupported field key"), "{}", o.content);
    // select answers with the option values it matched.
    let o = r(json!({"action": "act", "kind": "select", "ref": color, "values": ["Green"]}));
    assert!(!o.is_error && payload(&o.content)["selected"] == json!(["g"]), "{}", o.content);
    // evaluate returns a tool result (the policy is covered by policy::tests).
    let o = r(json!({"action": "act", "kind": "evaluate", "fn": "() => 2 + 2"}));
    assert!(!o.is_error && payload(&o.content)["ok"] == true, "{}", o.content);
    // focus activates the tab; close removes one.
    let o = r(json!({"action": "focus", "targetId": "PAGE2"}));
    assert!(!o.is_error && payload(&o.content)["ok"] == true, "{}", o.content);
    assert!(f.seen.lock().unwrap().iter().any(|m| m["method"] == "Target.activateTarget" && m["params"]["targetId"] == "PAGE2"));
    let o = r(json!({"action": "close", "targetId": "PAGE3"}));
    assert!(!o.is_error && payload(&o.content)["closed"] == "PAGE3", "{}", o.content);
    assert!(f.seen.lock().unwrap().iter().any(|m| m["method"] == "Target.closeTarget" && m["params"]["targetId"] == "PAGE3"));
    crate::manager::global().stop("cdp");
}

#[test]
fn openclaw_status_start_stop_text_and_download() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let c = ctx("life", "sess-life");
    let f = fake_page2(started(&c).into());
    let cfg = browser_cfg(&f);
    let t = tool(&cfg, "browser");
    let r = |input: Value| t.call(&c, input);
    let o = r(json!({"action": "start"}));
    assert!(!o.is_error && payload(&o.content)["running"] == true, "start: {}", o.content);
    let o = r(json!({"action": "status"}));
    assert!(payload(&o.content)["running"] == true, "status: {}", o.content);
    let o = r(json!({"action": "text"}));
    assert!(!o.is_error && o.content.contains("Hello seagent page text"), "text: {}", o.content);
    // download: clicking the link writes the file where the action was told to.
    let snap = r(json!({"action": "snapshot"})).content;
    let link = refs(&snap, "Download file");
    let o = r(json!({"action": "download", "ref": link, "path": "dl.txt", "timeoutMs": 20000}));
    assert!(!o.is_error, "download: {}", o.content);
    assert_eq!(std::fs::read_to_string(c.workspace.join("dl.txt")).unwrap(), "download me");
    // waitfordownload with nothing new fails after its timeout instead of hanging.
    let o = r(json!({"action": "waitfordownload", "timeoutMs": 300}));
    assert!(o.is_error && o.content.contains("no download completed"), "{}", o.content);
    let o = r(json!({"action": "stop"}));
    assert!(!o.is_error && payload(&o.content)["stopped"] == true, "stop: {}", o.content);
}

#[test]
fn hermes_get_images_and_vault_fill_against_a_fake_browser() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let c = ctx("img", "sess-img");
    let f = fake_page2(started(&c).into());
    let cfg = browser_cfg(&f);
    let t = tool(&cfg, "browser");
    let o = t.call(&c, json!({"action": "open", "url": "https://shop.example/account"}));
    assert!(!o.is_error, "{}", o.content);
    let (ok, v, raw) = call(&cfg, &c, "browser_get_images", json!({}));
    assert!(ok && v["count"] == 1, "{raw}");
    assert_eq!(v["images"][0]["alt"], "Photo");
    assert_eq!(v["images"][0]["width"], 640);
    // The vault fills the password field model-blind, on the item's exact origin.
    let origin = crate::vault::normalize_origin("https://shop.example/account").unwrap();
    let item = crate::vault::add(&c.home, "login", "local", &origin, std::collections::BTreeMap::from([("identifier".into(), "me@x.example".into()), ("password".into(), "Very-Secret-Pw-42".into())])).unwrap();
    let (ok, v, raw) = call(&cfg, &c, "browser_vault", json!({"action": "fill", "handle": item.id}));
    assert!(ok && v["filled_fields"] == 1, "{raw}");
    assert!(!raw.contains("Very-Secret-Pw-42"), "the secret never appears in the result: {raw}");
    // A handle bound to another origin is refused before any fill.
    let other = crate::vault::normalize_origin("https://evil.example/").unwrap();
    let bad = crate::vault::add(&c.home, "login", "local", &other, std::collections::BTreeMap::from([("password".into(), "x".into())])).unwrap();
    let (ok, v, raw) = call(&cfg, &c, "browser_vault", json!({"action": "fill", "handle": bad.id}));
    assert!(!ok && v["success"] == false && raw.contains("origin_mismatch"), "{raw}");
    // save_login asks the user (here: a test prompter), stores the item and fills it.
    crate::vault::set_prompter(Some(Box::new(|label: &str, _masked: bool| if label.contains("username") { Some("me2@x.example".into()) } else { Some("Second-Pw-77".into()) })));
    let (ok, v, raw) = call(&cfg, &c, "browser_vault", json!({"action": "save_login", "label": "shop"}));
    assert!(ok && v["success"] == true, "{raw}");
    assert!(!raw.contains("Second-Pw-77"));
    let stored = crate::vault::load(&c.home).unwrap();
    assert!(stored.iter().any(|i| i.label == "shop" && i.origin == origin), "{stored:?}");
    // unlock: the local store is always open; only the external managers can be locked.
    let (ok, v, raw) = call(&cfg, &c, "browser_vault", json!({"action": "unlock", "backend": "local"}));
    assert!(!ok && v["error"].as_str().unwrap_or("").contains("No unlockable vault backend"), "{raw}");
    let (ok, v, raw) = call(&cfg, &c, "browser_vault", json!({"action": "list"}));
    assert!(ok && v["items"].as_array().is_some_and(|a| a.iter().any(|i| i["backend"] == "local")), "{raw}");
    crate::vault::set_prompter(None);
    crate::manager::global().stop("cdp");
}
