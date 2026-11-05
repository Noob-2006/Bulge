//! computer.act v2 browser actions (OpenClaw `get_browser_state`, `browser_navigate`,
//! `browser_click`, `browser_type`, MIT) through the Chrome DevTools Protocol of a browser
//! the user started with `--remote-debugging-port` (`cdp_url` in node.toml, loopback only).
//! `browserRef` is the endpoint, `pageRef` a target id, `elementRef` a `data-seagent-ref` the
//! snapshot stamped on interactive elements.

use seagent_net::ws::{Message, WebSocket};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

const T: Duration = Duration::from_secs(15);

/// Interactive elements → `[{elementRef, role, label, value?, bounds}]`, refs stamped in the page.
const SNAPSHOT_JS: &str = r#"(() => {
  const obs = Math.random().toString(36).slice(2, 10);
  window.__arkObs = obs;
  const sel = 'a[href],button,input,select,textarea,summary,[role=button],[role=link],[role=checkbox],[role=tab],[role=menuitem],[contenteditable=""],[contenteditable=true],[onclick]';
  const out = [];
  let n = 0;
  for (const el of document.querySelectorAll(sel)) {
    const r = el.getBoundingClientRect();
    if (r.width <= 0 || r.height <= 0 || getComputedStyle(el).visibility === 'hidden') continue;
    const ref = 'e' + (++n);
    el.setAttribute('data-seagent-ref', ref);
    const label = (el.getAttribute('aria-label') || el.innerText || el.placeholder || el.title || el.name || '').trim().slice(0, 120);
    const e = { elementRef: ref, role: el.getAttribute('role') || el.tagName.toLowerCase(), label, bounds: { x: Math.round(r.x), y: Math.round(r.y), width: Math.round(r.width), height: Math.round(r.height) } };
    if ('value' in el && el.type !== 'password' && el.value) e.value = String(el.value).slice(0, 200);
    if (el.type === 'password') e.value = '••••';
    out.push(e);
    if (out.length >= 300) break;
  }
  return { observationId: obs, url: location.href, title: document.title, elements: out };
})()"#;

/// Only a browser on this machine: the endpoint hands out full control of it.
pub fn endpoint(cdp_url: &str) -> Result<String, String> {
    let u = cdp_url.trim().trim_end_matches('/');
    if u.is_empty() {
        return Err("browser actions need `cdp_url` in node.toml (a browser started with --remote-debugging-port)".into());
    }
    let rest = u.strip_prefix("http://").ok_or("cdp_url must be http://127.0.0.1:<port>")?;
    let host = rest.rsplit_once(':').map(|(h, _)| h).unwrap_or(rest);
    if !matches!(host, "127.0.0.1" | "localhost" | "[::1]") {
        return Err("cdp_url must point at this machine (127.0.0.1, localhost or [::1])".into());
    }
    Ok(u.to_string())
}

fn targets(base: &str) -> Result<Vec<Value>, String> {
    let agent: ureq::Agent = seagent_net::http::builder().timeout_global(Some(T)).build().into();
    let mut r = agent.get(&format!("{base}/json/list")).call().map_err(|e| format!("CDP {base}: {e}"))?;
    let v: Value = serde_json::from_str(&r.body_mut().read_to_string().map_err(|e| e.to_string())?).map_err(|e| format!("CDP /json/list: {e}"))?;
    Ok(v.as_array().cloned().unwrap_or_default().into_iter().filter(|t| t["type"] == "page").collect())
}

/// One CDP session on a page target.
struct Page {
    ws: WebSocket<seagent_net::Stream>,
    next: u64,
}

impl Page {
    fn open(base: &str, page: &str) -> Result<Page, String> {
        let t = targets(base)?.into_iter().find(|t| t["id"] == page).ok_or_else(|| format!("no page `{page}` (get_browser_state lists them)"))?;
        let url = t["webSocketDebuggerUrl"].as_str().ok_or("page has no webSocketDebuggerUrl (another DevTools client attached?)")?;
        let (mut ws, _) = WebSocket::connect(url, &[], T).map_err(|e| format!("CDP connect: {e}"))?;
        ws.set_max_message(16 << 20);
        ws.set_read_timeout(Some(Duration::from_millis(200))).ok();
        Ok(Page { ws, next: 1 })
    }

    fn send(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next;
        self.next += 1;
        self.ws.send_text(&json!({"id": id, "method": method, "params": params}).to_string()).map_err(|e| e.to_string())?;
        let until = Instant::now() + T;
        while Instant::now() < until {
            let Some(Message::Text(t)) = self.ws.recv().map_err(|e| format!("CDP: {e}"))? else { continue };
            let v: Value = serde_json::from_str(&t).unwrap_or_default();
            if v["id"] != id {
                continue; // events
            }
            if let Some(e) = v.get("error") {
                return Err(format!("CDP {method}: {}", e["message"].as_str().unwrap_or("error")));
            }
            return Ok(v["result"].clone());
        }
        Err(format!("CDP {method}: timed out"))
    }

    fn eval(&mut self, expr: &str) -> Result<Value, String> {
        let r = self.send("Runtime.evaluate", json!({"expression": expr, "returnByValue": true, "awaitPromise": true}))?;
        if let Some(e) = r.get("exceptionDetails") {
            return Err(format!("page script failed: {}", e["exception"]["description"].as_str().or(e["text"].as_str()).unwrap_or("exception")));
        }
        Ok(r["result"]["value"].clone())
    }

    /// Stale-observation guard (OC `COMPUTER_STALE_OBSERVATION`), then `f(element)` in the page.
    fn on_element(&mut self, p: &Value, body: &str) -> Result<Value, String> {
        let r = element_ref(p)?.ok_or("needs elementRef from get_browser_state")?;
        let obs = p["observationId"].as_str().unwrap_or("");
        let js = format!(
            "(() => {{ if ({obs:?} && window.__arkObs !== {obs:?}) return {{stale: true}}; const el = document.querySelector('[data-seagent-ref=\"{r}\"]'); if (!el) return {{missing: true}}; el.scrollIntoView({{block: 'center'}}); {body} }})()"
        );
        let v = self.eval(&js)?;
        if v["stale"] == true {
            return Err("COMPUTER_STALE_OBSERVATION: the page changed since that observation; call get_browser_state again".into());
        }
        if v["missing"] == true {
            return Err(format!("element {r} is gone; call get_browser_state again"));
        }
        Ok(v)
    }
}

/// `e<n>` refs only: they are spliced into page script.
fn element_ref(p: &Value) -> Result<Option<&str>, String> {
    match &p["elementRef"] {
        Value::Null => Ok(None),
        Value::String(r) if r.len() < 12 && r.starts_with('e') && r.len() > 1 && r[1..].chars().all(|c| c.is_ascii_digit()) => Ok(Some(r)),
        other => Err(format!("bad elementRef {other} (use one from get_browser_state)")),
    }
}

pub fn act(cdp_url: &str, p: &Value) -> Result<Value, String> {
    let base = endpoint(cdp_url)?;
    element_ref(p)?;
    let action = p["action"].as_str().unwrap_or("");
    let page = p["pageRef"].as_str().filter(|s| !s.is_empty());
    if action == "get_browser_state" && page.is_none() {
        let pages: Vec<Value> = targets(&base)?.iter().map(|t| json!({"pageRef": t["id"], "title": t["title"], "url": t["url"]})).collect();
        return Ok(json!({"browserRef": base, "pages": pages}));
    }
    let page = page.ok_or_else(|| format!("{action} needs pageRef (get_browser_state without one lists pages)"))?;
    let mut pg = Page::open(&base, page)?;
    match action {
        "get_browser_state" => {
            let v = pg.eval(SNAPSHOT_JS)?;
            let mut obs = json!({"kind": "browser", "observationId": v["observationId"], "elements": v["elements"]});
            if p["includeScreenshot"] == true {
                let s = pg.send("Page.captureScreenshot", json!({"format": "png"}))?;
                obs["base64"] = s["data"].clone();
                obs["format"] = json!("png");
            }
            Ok(json!({"browserRef": base, "pageRef": page, "url": v["url"], "title": v["title"], "observation": obs}))
        }
        "browser_navigate" => {
            let url = p["url"].as_str().filter(|u| u.starts_with("https://") || u.starts_with("http://")).ok_or("browser_navigate needs an http(s) url")?;
            let r = pg.send("Page.navigate", json!({"url": url}))?;
            if let Some(e) = r["errorText"].as_str() {
                return Err(format!("navigate: {e}"));
            }
            Ok(json!({"ok": true, "url": url}))
        }
        "browser_click" if p["elementRef"].is_null() => {
            let (x, y) = (p["x"].as_f64().ok_or("browser_click needs elementRef or x, y")?, p["y"].as_f64().ok_or("browser_click needs y")?);
            for t in ["mousePressed", "mouseReleased"] {
                pg.send("Input.dispatchMouseEvent", json!({"type": t, "x": x, "y": y, "button": "left", "clickCount": 1}))?;
            }
            Ok(json!({"ok": true, "x": x, "y": y}))
        }
        "browser_click" => {
            pg.on_element(p, "el.click(); return {ok: true};")?;
            Ok(json!({"ok": true, "elementRef": p["elementRef"]}))
        }
        "browser_type" => {
            let text = p["text"].as_str().ok_or("browser_type needs text")?;
            let clear = if p["replace"] == true { "if ('value' in el) el.value = ''; else el.textContent = '';" } else { "" };
            pg.on_element(p, &format!("el.focus(); {clear} return {{ok: true}};"))?;
            pg.send("Input.insertText", json!({"text": text}))?;
            Ok(json!({"ok": true, "elementRef": p["elementRef"]}))
        }
        other => Err(format!("computer.act action `{other}` is not supported by the CDP backend")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    #[test]
    fn only_loopback_endpoints() {
        assert_eq!(endpoint("http://127.0.0.1:9222/").unwrap(), "http://127.0.0.1:9222");
        assert!(endpoint("http://localhost:9222").is_ok() && endpoint("http://[::1]:9222").is_ok());
        for bad in ["", "https://127.0.0.1:9222", "http://10.0.0.2:9222", "http://evil.example:9222", "ws://127.0.0.1:9222"] {
            assert!(endpoint(bad).is_err(), "{bad}");
        }
    }

    /// A fake DevTools endpoint: /json/list over HTTP, then one page's WebSocket.
    fn fake_browser(script: Vec<(&'static str, Value)>) -> (String, std::thread::JoinHandle<Vec<Value>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for s in l.incoming() {
                let mut s = s.unwrap();
                let (head, rest) = seagent_net::ws::read_head(&mut s, 1 << 16).unwrap();
                if head.starts_with("GET /json/list") {
                    let body = json!([{"id": "P1", "type": "page", "title": "Home", "url": "https://example.com/", "webSocketDebuggerUrl": format!("ws://127.0.0.1:{port}/devtools/page/P1")}, {"id": "W", "type": "service_worker"}]).to_string();
                    let _ = write!(s, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                    continue;
                }
                let mut ws = WebSocket::accept(s, &head, rest).unwrap();
                for (method, result) in &script {
                    let Message::Text(t) = ws.recv_blocking().unwrap() else { break };
                    let v: Value = serde_json::from_str(&t).unwrap();
                    assert_eq!(v["method"], *method);
                    ws.send_text(&json!({"method": "Page.frameNavigated", "params": {}}).to_string()).unwrap();
                    ws.send_text(&json!({"id": v["id"], "result": result}).to_string()).unwrap();
                    seen.push(v);
                }
                return seen;
            }
            seen
        });
        (format!("http://127.0.0.1:{port}"), h)
    }

    #[test]
    fn lists_pages_snapshots_and_clicks_by_ref() {
        let (url, h) = fake_browser(vec![]);
        let v = act(&url, &json!({"action": "get_browser_state"})).unwrap();
        assert_eq!(v["pages"], json!([{"pageRef": "P1", "title": "Home", "url": "https://example.com/"}]));
        drop(h);

        let snap = json!({"result": {"type": "object", "value": {"observationId": "o1", "url": "https://example.com/", "title": "Home", "elements": [{"elementRef": "e1", "role": "button", "label": "Go"}]}}});
        let (url, h) = fake_browser(vec![("Runtime.evaluate", snap)]);
        let v = act(&url, &json!({"action": "get_browser_state", "pageRef": "P1"})).unwrap();
        assert_eq!((v["observation"]["observationId"].as_str(), v["observation"]["elements"][0]["elementRef"].as_str()), (Some("o1"), Some("e1")));
        assert!(h.join().unwrap()[0]["params"]["expression"].as_str().unwrap().contains("data-seagent-ref"));

        let (url, h) = fake_browser(vec![("Runtime.evaluate", json!({"result": {"value": {"stale": true}}}))]);
        assert!(act(&url, &json!({"action": "browser_click", "pageRef": "P1", "elementRef": "e1", "observationId": "old"})).unwrap_err().contains("STALE"));
        drop(h);

        let (url, h) = fake_browser(vec![("Runtime.evaluate", json!({"result": {"value": {"ok": true}}})), ("Input.insertText", json!({}))]);
        act(&url, &json!({"action": "browser_type", "pageRef": "P1", "elementRef": "e2", "text": "héllo", "replace": true})).unwrap();
        let seen = h.join().unwrap();
        assert!(seen[0]["params"]["expression"].as_str().unwrap().contains("[data-seagent-ref=\\\"e2\\\"]") || seen[0]["params"]["expression"].as_str().unwrap().contains("[data-seagent-ref=\"e2\"]"));
        assert_eq!(seen[1]["params"]["text"], "héllo");
        assert!(act(&url, &json!({"action": "browser_click", "pageRef": "P1", "elementRef": "x'); evil("})).unwrap_err().contains("bad elementRef"), "refs are checked before they reach the page");
    }
}
