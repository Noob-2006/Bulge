//! Camofox backend: the anti-detection Firefox server's REST API (Hermes
//! `browser_camofox.py`, MIT). Tabs are per (userId, sessionKey); refs come from its
//! own snapshot. No CDP, so browser_cdp / dialogs / console are unavailable.

use crate::config::BrowserConfig;
use crate::policy;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Tab {
    pub user_id: String,
    pub tab_id: Option<String>,
    pub session_key: String,
    pub managed: bool,
}

#[derive(Default)]
pub struct Camofox {
    tabs: Mutex<HashMap<String, Tab>>,
    vnc: Mutex<HashMap<String, Option<String>>>,
}

pub struct Client {
    pub base: String,
    pub key: Option<String>,
    pub timeout: Duration,
}

fn uuid5ish(seed: &str, n: usize) -> String {
    ark_net::crypto::hex(&ark_net::crypto::sha256(seed.as_bytes()))[..n].to_string()
}

impl Client {
    pub fn new(cfg: &BrowserConfig) -> Client {
        let key = std::env::var("CAMOFOX_API_KEY").ok().filter(|k| !k.trim().is_empty()).or_else(|| Some(cfg.camofox.api_key.clone()).filter(|k| !k.is_empty()));
        Client { base: cfg.camofox_url(), key, timeout: cfg.command_timeout() }
    }

    fn req(&self, method: &str, path: &str, body: Option<Value>, timeout: Option<Duration>) -> Result<(u16, Vec<u8>), String> {
        let a: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(timeout.unwrap_or(self.timeout))).http_status_as_error(false).build().into();
        let url = format!("{}{path}", self.base);
        let auth = self.key.as_ref().filter(|_| path != "/health").map(|k| format!("Bearer {k}"));
        let r = match method {
            "GET" | "DELETE" => {
                let mut q = if method == "GET" { a.get(&url) } else { a.delete(&url) };
                if let Some(h) = &auth {
                    q = q.header("Authorization", h);
                }
                q.call()
            }
            _ => {
                let mut q = a.post(&url);
                if let Some(h) = &auth {
                    q = q.header("Authorization", h);
                }
                q.header("Content-Type", "application/json").send(body.unwrap_or(json!({})).to_string())
            }
        };
        let mut r = r.map_err(|e| format!("Cannot connect to Camofox at {}. Is the server running? Start with: npm start (in camofox-browser dir) or: docker run -p 9377:9377 -e CAMOFOX_PORT=9377 jo-inc/camofox-browser ({e})", self.base))?;
        let st = r.status().as_u16();
        let b = r.body_mut().read_to_vec().map_err(|e| e.to_string())?;
        Ok((st, b))
    }

    pub fn json(&self, method: &str, path: &str, body: Option<Value>, timeout: Option<Duration>) -> Result<Value, String> {
        let (st, b) = self.req(method, path, body, timeout)?;
        if !(200..300).contains(&st) {
            return Err(format!("Camofox {method} {path}: HTTP {st} {}", crate::util::cut(&String::from_utf8_lossy(&b), 300)));
        }
        Ok(serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    pub fn bytes(&self, path: &str) -> Result<Vec<u8>, String> {
        let (st, b) = self.req("GET", path, None, None)?;
        if !(200..300).contains(&st) {
            return Err(format!("Camofox GET {path}: HTTP {st}"));
        }
        Ok(b)
    }
}

fn rewrite_loopback(cfg: &BrowserConfig, url: &str) -> Option<String> {
    let on = std::env::var("CAMOFOX_REWRITE_LOOPBACK_URLS").ok().map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")).unwrap_or(cfg.camofox.rewrite_loopback_urls);
    if !on {
        return None;
    }
    let h = policy::parse_url(url)?;
    if !(h.host == "localhost" || h.host == "localhost.localdomain" || h.host.parse::<std::net::IpAddr>().is_ok_and(|i| i.is_loopback())) {
        return None;
    }
    let alias = std::env::var("CAMOFOX_LOOPBACK_HOST_ALIAS").ok().filter(|v| !v.is_empty()).unwrap_or_else(|| cfg.camofox.loopback_host_alias.clone());
    let alias = if alias.contains(':') { format!("[{alias}]") } else { alias };
    let (scheme, rest) = url.split_once("://")?;
    let (auth, tail) = rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()));
    let (userinfo, hp) = auth.rsplit_once('@').map(|(u, h)| (format!("{u}@"), h)).unwrap_or((String::new(), auth));
    let port = if hp.starts_with('[') { hp.split_once("]:").map(|(_, p)| format!(":{p}")) } else { hp.rsplit_once(':').map(|(_, p)| format!(":{p}")) }.unwrap_or_default();
    Some(format!("{scheme}://{userinfo}{alias}{port}{tail}"))
}

impl Camofox {
    fn identity(&self, cfg: &BrowserConfig, home: &std::path::Path, task: &str) -> Tab {
        if let Some(t) = self.tabs.lock().unwrap().get(task) {
            return t.clone();
        }
        let ext_user = std::env::var("CAMOFOX_USER_ID").ok().filter(|v| !v.is_empty()).or_else(|| Some(cfg.camofox.user_id.clone()).filter(|v| !v.is_empty()));
        let ext_key = std::env::var("CAMOFOX_SESSION_KEY").ok().filter(|v| !v.is_empty()).or_else(|| Some(cfg.camofox.session_key.clone()).filter(|v| !v.is_empty()));
        let short: String = task.chars().take(16).collect();
        let t = if let Some(u) = ext_user {
            Tab { user_id: u, tab_id: None, session_key: ext_key.unwrap_or_else(|| format!("task_{short}")), managed: true }
        } else if cfg.camofox.managed_persistence {
            let dir = home.join("browser_auth/camofox");
            Tab { user_id: format!("ark_{}", uuid5ish(&format!("camofox-user:{}", dir.display()), 10)), tab_id: None, session_key: format!("task_{}", uuid5ish(&format!("camofox-session:{}:{task}", dir.display()), 16)), managed: true }
        } else {
            Tab { user_id: format!("ark_{}", ark_net::crypto::random_token(5)), tab_id: None, session_key: format!("task_{short}"), managed: false }
        };
        self.tabs.lock().unwrap().insert(task.into(), t.clone());
        t
    }

    fn save(&self, task: &str, t: &Tab) {
        self.tabs.lock().unwrap().insert(task.into(), t.clone());
    }

    fn current(&self, task: &str) -> Result<Tab, String> {
        self.tabs.lock().unwrap().get(task).filter(|t| t.tab_id.is_some()).cloned().ok_or_else(|| "No browser session. Call browser_navigate first.".into())
    }

    fn vnc(&self, c: &Client) -> Option<String> {
        let mut m = self.vnc.lock().unwrap();
        m.entry(c.base.clone())
            .or_insert_with(|| {
                let v = c.json("GET", "/health", None, Some(Duration::from_secs(5))).ok()?;
                let port = v["vncPort"].as_u64().filter(|p| (1..=65535).contains(p))?;
                let host = policy::parse_url(&c.base)?.host;
                Some(format!("http://{host}:{port}"))
            })
            .clone()
    }

    /// Guard: the current page must not be private when the SSRF guard applies (fail-open).
    fn guard(&self, cfg: &BrowserConfig, c: &Client, t: &Tab, what: &str) -> Result<(), String> {
        if !policy::ssrf_guard(cfg) {
            return Ok(());
        }
        let Some(tab) = &t.tab_id else { return Ok(()) };
        if let Ok(v) = c.json("POST", &format!("/tabs/{tab}/evaluate"), Some(json!({"expression": "window.location.href", "userId": t.user_id})), None) {
            let u = v["result"].as_str().unwrap_or("").trim_matches(['"', '\'']).to_string();
            if !u.is_empty() && (policy::always_blocked(&u) || policy::is_private(&u)) {
                return Err(format!("Blocked: page URL targets a private or internal address ({u}). Refusing to {what} on this page in this browser mode."));
            }
        }
        Ok(())
    }

    pub fn navigate(&self, cfg: &BrowserConfig, home: &std::path::Path, task: &str, url: &str) -> Result<Value, String> {
        let c = Client::new(cfg);
        let mut t = self.identity(cfg, home, task);
        let target = rewrite_loopback(cfg, url);
        let go = target.clone().unwrap_or_else(|| url.to_string());
        let adopt = std::env::var("CAMOFOX_ADOPT_EXISTING_TAB").ok().map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")).unwrap_or(cfg.camofox.adopt_existing_tab);
        if t.tab_id.is_none() && t.managed && adopt {
            if let Ok(v) = c.json("GET", &format!("/tabs?userId={}", ark_net::urlencode(&t.user_id)), None, Some(Duration::from_secs(5))) {
                let tabs = v["tabs"].as_array().cloned().unwrap_or_default();
                let mine: Vec<&Value> = tabs.iter().filter(|x| x["listItemId"] == t.session_key.as_str()).collect();
                let pick = if mine.is_empty() { tabs.last() } else { mine.last().copied() };
                t.tab_id = pick.and_then(|x| x["tabId"].as_str().map(str::to_string));
            }
        }
        let mut out = match &t.tab_id {
            None => {
                let v = c.json("POST", "/tabs", Some(json!({"userId": t.user_id, "listItemId": t.session_key, "url": go})), None).map_err(|e| format!("Navigation failed: {e}"))?;
                t.tab_id = v["tabId"].as_str().map(str::to_string);
                json!({"success": true, "url": v["url"].as_str().unwrap_or(&go), "title": v["title"]})
            }
            Some(tab) => match c.json("POST", &format!("/tabs/{tab}/navigate"), Some(json!({"userId": t.user_id, "url": go})), Some(Duration::from_secs(60))) {
                Ok(v) => json!({"success": true, "url": v["url"].as_str().unwrap_or(&go), "title": v["title"]}),
                Err(e) if e.contains("HTTP 404") => {
                    let v = c.json("POST", "/tabs", Some(json!({"userId": t.user_id, "listItemId": t.session_key, "url": go})), None).map_err(|e| format!("Navigation failed: {e}"))?;
                    t.tab_id = v["tabId"].as_str().map(str::to_string);
                    json!({"success": true, "url": go})
                }
                Err(e) => return Err(format!("Navigation failed: {e}")),
            },
        };
        self.save(task, &t);
        if let Some(r) = target {
            out["requested_url"] = url.into();
            out["url_rewrite"] = json!({"from": url, "to": r, "original_url": url, "rewritten_url": r});
            out["warning"] = format!("Rewrote loopback URL for Docker-hosted Camofox: {url} -> {r}").into();
        }
        if let Some(v) = self.vnc(&c) {
            out["vnc_url"] = v.clone().into();
            out["vnc_hint"] = format!("Watch or take over the browser at {v}").into();
        }
        if let Ok(s) = self.snapshot(cfg, task) {
            out["snapshot"] = s["snapshot"].clone();
            out["element_count"] = s["element_count"].clone();
        }
        Ok(out)
    }

    pub fn snapshot(&self, cfg: &BrowserConfig, task: &str) -> Result<Value, String> {
        let c = Client::new(cfg);
        let t = self.current(task)?;
        self.guard(cfg, &c, &t, "read a page snapshot")?;
        let v = c.json("GET", &format!("/tabs/{}/snapshot?userId={}", t.tab_id.as_ref().unwrap(), ark_net::urlencode(&t.user_id)), None, None)?;
        Ok(json!({"success": true, "snapshot": policy::redact(v["snapshot"].as_str().unwrap_or("")), "element_count": v["refsCount"]}))
    }

    pub fn act(&self, cfg: &BrowserConfig, task: &str, action: &str, arg: &Value) -> Result<Value, String> {
        let c = Client::new(cfg);
        let t = self.current(task)?;
        let tab = t.tab_id.clone().unwrap();
        let what = match action {
            "click" => "click",
            "type" => "type",
            "press" => "press",
            _ => "act",
        };
        if matches!(action, "click" | "type" | "press") {
            self.guard(cfg, &c, &t, what)?;
        }
        let r = |k: &str| arg[k].as_str().unwrap_or("").trim_start_matches('@').to_string();
        match action {
            "click" => {
                let v = c.json("POST", &format!("/tabs/{tab}/click"), Some(json!({"userId": t.user_id, "ref": r("ref")})), None)?;
                Ok(json!({"success": true, "clicked": r("ref"), "url": v["url"]}))
            }
            "type" => {
                c.json("POST", &format!("/tabs/{tab}/type"), Some(json!({"userId": t.user_id, "ref": r("ref"), "text": arg["text"]})), None)?;
                Ok(json!({"success": true, "typed": policy::redact(arg["text"].as_str().unwrap_or("")), "element": r("ref")}))
            }
            "scroll" => {
                c.json("POST", &format!("/tabs/{tab}/scroll"), Some(json!({"userId": t.user_id, "direction": arg["direction"]})), None)?;
                Ok(json!({"success": true, "scrolled": arg["direction"]}))
            }
            "back" => {
                let v = c.json("POST", &format!("/tabs/{tab}/back"), Some(json!({"userId": t.user_id})), None)?;
                Ok(json!({"success": true, "url": v["url"]}))
            }
            "press" => {
                c.json("POST", &format!("/tabs/{tab}/press"), Some(json!({"userId": t.user_id, "key": arg["key"]})), None)?;
                Ok(json!({"success": true, "pressed": arg["key"]}))
            }
            "evaluate" => {
                let v = c.json("POST", &format!("/tabs/{tab}/evaluate"), Some(json!({"expression": arg["expression"], "userId": t.user_id})), None).map_err(|e| if ["404", "405", "501"].iter().any(|x| e.contains(&format!("HTTP {x}"))) { "JavaScript evaluation is not supported by this Camofox server. Use browser_snapshot or browser_vision to inspect page state.".to_string() } else { e })?;
                self.guard(cfg, &c, &t, "evaluate")?;
                let res = v["result"].clone();
                let parsed = res.as_str().and_then(|s| serde_json::from_str(s).ok()).unwrap_or(res);
                Ok(json!({"success": true, "result": policy::redact_json(&parsed)}))
            }
            _ => Err(format!("{action} is not supported by the Camofox backend")),
        }
    }

    /// Images parsed from the snapshot (Camofox has no images endpoint).
    pub fn images(&self, cfg: &BrowserConfig, task: &str) -> Result<Value, String> {
        let c = Client::new(cfg);
        let t = self.current(task)?;
        self.guard(cfg, &c, &t, "extract page images")?;
        let snap = self.snapshot(cfg, task)?;
        let text = snap["snapshot"].as_str().unwrap_or("");
        let re = regex::Regex::new(r#"img\s+"([^"]*)""#).unwrap();
        let url = regex::Regex::new(r"/url:\s*(\S+)").unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let mut imgs = vec![];
        for (i, l) in lines.iter().enumerate() {
            let s = l.trim_start();
            if s.starts_with("- img ") || s.starts_with("img ") {
                let alt = re.captures(s).map(|c| c[1].to_string()).unwrap_or_default();
                let src = lines.get(i + 1).and_then(|n| url.captures(n)).map(|c| c[1].to_string()).unwrap_or_default();
                imgs.push(json!({"src": src, "alt": alt}));
            }
        }
        Ok(json!({"success": true, "count": imgs.len(), "images": imgs}))
    }

    pub fn screenshot(&self, cfg: &BrowserConfig, task: &str) -> Result<Vec<u8>, String> {
        let c = Client::new(cfg);
        let t = self.current(task)?;
        self.guard(cfg, &c, &t, "capture a screenshot")?;
        c.bytes(&format!("/tabs/{}/screenshot?userId={}", t.tab_id.as_ref().unwrap(), ark_net::urlencode(&t.user_id)))
    }

    pub fn close(&self, cfg: &BrowserConfig, task: &str) -> Value {
        let t = self.tabs.lock().unwrap().remove(task);
        let mut out = json!({"success": true, "closed": true});
        if let Some(t) = t {
            if let Err(e) = Client::new(cfg).json("DELETE", &format!("/sessions/{}", ark_net::urlencode(&t.user_id)), None, None) {
                out["warning"] = e.into();
            }
        }
        out
    }

    /// End of task: managed identities keep their server-side profile.
    pub fn soft_close(&self, cfg: &BrowserConfig, task: &str) {
        let managed = self.tabs.lock().unwrap().get(task).is_some_and(|t| t.managed);
        if managed {
            self.tabs.lock().unwrap().remove(task);
        } else {
            self.close(cfg, task);
        }
    }
}

pub const CONSOLE_NOTE: &str = "Console log capture is not available with the Camofox backend. Use browser_snapshot or browser_vision to inspect page state.";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::tests::http_fake;

    #[test]
    fn rest_flow_and_loopback_rewrite() {
        let (base, seen) = http_fake(|m, p, _| match (m, p.split('?').next().unwrap()) {
            ("GET", "/health") => (200, "{\"vncPort\":6080}".into()),
            ("POST", "/tabs") => (200, "{\"tabId\":\"T1\",\"url\":\"http://host.docker.internal:3000/\",\"title\":\"Dev\"}".into()),
            ("GET", "/tabs/T1/snapshot") => (200, "{\"snapshot\":\"- img \\\"Logo\\\"\\n  /url: https://x.example/l.png\\n- button \\\"Go\\\" [e1]\",\"refsCount\":1}".into()),
            ("POST", "/tabs/T1/click") => (200, "{\"url\":\"http://x/\"}".into()),
            ("POST", "/tabs/T1/evaluate") => (200, "{\"result\":\"https://x.example/\"}".into()),
            ("DELETE", _) => (200, "{}".into()),
            _ => (404, "{}".into()),
        });
        let mut cfg = BrowserConfig::default();
        cfg.camofox.url = base.clone();
        cfg.camofox.rewrite_loopback_urls = true;
        cfg.backend = "camofox".into();
        cfg.allow_private_urls = Some(true);
        let home = std::env::temp_dir();
        let cf = Camofox::default();
        let v = cf.navigate(&cfg, &home, "task1", "http://localhost:3000/").unwrap();
        assert_eq!(v["url_rewrite"]["to"], "http://host.docker.internal:3000/");
        assert!(v["vnc_url"].as_str().unwrap().ends_with(":6080"));
        assert_eq!(v["element_count"], 1);
        assert_eq!(cf.act(&cfg, "task1", "click", &json!({"ref": "@e1"})).unwrap()["clicked"], "e1");
        let imgs = cf.images(&cfg, "task1").unwrap();
        assert_eq!((imgs["images"][0]["alt"].as_str(), imgs["images"][0]["src"].as_str()), (Some("Logo"), Some("https://x.example/l.png")));
        assert!(cf.act(&cfg, "nope", "click", &json!({})).unwrap_err().contains("browser_navigate first"));
        cf.close(&cfg, "task1");
        let seen = seen.lock().unwrap();
        assert!(seen.iter().any(|s| s.0 == "POST" && s.1 == "/tabs" && s.3.contains("host.docker.internal")));
        assert!(seen.iter().any(|s| s.0 == "DELETE" && s.1.starts_with("/sessions/ark_")));
        assert_eq!(rewrite_loopback(&cfg, "https://example.com/"), None);
    }
}
