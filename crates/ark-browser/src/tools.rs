//! Hermes' browser toolset (MIT): browser_navigate / snapshot / click / type / scroll /
//! back / press / get_images / vision / console, plus browser_cdp, browser_dialog,
//! browser_vault and browser_exec. Results are Hermes-shaped JSON.

use crate::actions::{self, SnapshotReq};
use crate::config::BrowserConfig;
use crate::engine::Browser;
use crate::manager::{self, Env};
use crate::policy;
use crate::snapshot::Opts;
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub fn env_of(cfg: &BrowserConfig, ctx: &ToolCtx) -> Env {
    Env { cfg: cfg.clone(), home: ctx.home.clone(), secrets: ctx.secrets.clone() }
}

pub fn out(v: Value) -> ToolOutput {
    let ok = v["success"] != false && v["ok"] != false;
    let s = serde_json::to_string(&v).unwrap_or_default();
    if ok {
        ToolOutput::ok(s)
    } else {
        ToolOutput::err(s)
    }
}

pub fn fail(e: impl Into<String>) -> ToolOutput {
    out(json!({"success": false, "error": policy::redact(&e.into())}))
}

/// The session's current browser + tab (created on first use).
pub fn current(env: &Env, sid: &str, url: Option<&str>) -> Result<(Arc<Browser>, String), String> {
    let m = manager::global();
    let s = m.session(sid);
    let key = if s.key.is_empty() || url.is_some() { m.key_for(env, None, sid, url) } else { s.key.clone() };
    let b = m.browser(env, &key)?;
    fence(env, &b)?;
    let t = m.tab(env, sid, &b)?;
    Ok((b, t))
}

/// Every browser honours the human-takeover lease: a person may take over any of them from
/// the web console (`view.browser.input` needs the lease), so while they hold it the agent
/// neither acts on nor reads the page (they may be typing a credential).
fn fence(env: &Env, _b: &Browser) -> Result<(), String> {
    crate::lease::agent_may_act(&env.home)?;
    Ok(())
}

/// Existing session tab only (other tools need browser_navigate first).
pub fn existing(env: &Env, sid: &str) -> Result<(Arc<Browser>, String), String> {
    let m = manager::global();
    let s = m.session(sid);
    if s.key.is_empty() || s.target.is_none() {
        return Err("No browser session. Call browser_navigate first.".into());
    }
    let b = m.get(&s.key).ok_or("The browser session ended (idle timeout or closed). Call browser_navigate again.")?;
    fence(env, &b)?;
    let t = m.tab(env, sid, &b)?;
    Ok((b, t))
}

/// Host of the session's current page, for effect declarations (no I/O).
pub fn current_host(sid: &str) -> String {
    let m = manager::global();
    let s = m.session(sid);
    let url = s.target.as_ref().and_then(|t| m.get(&s.key).map(|b| b.page(t, |p| p.url.clone()))).unwrap_or_default();
    policy::parse_url(&url).map(|h| h.host).unwrap_or_else(|| "browser".into())
}

fn local_route(b: &Browser) -> bool {
    b.key == "sidecar" || matches!(b.kind.as_str(), "local" | "real-profile" | "cdp" | "existing-session" | "remote" | "extension")
}

/// Refuse page content when the SSRF guard applies and the page is private (fail-open).
pub fn guard_page(env: &Env, b: &Browser, t: &str, why: &str) -> Result<(), String> {
    if local_route(b) || !policy::ssrf_guard(&env.cfg) {
        return Ok(());
    }
    let url = b.url_title(t).0;
    if !url.is_empty() && (policy::always_blocked(&url) || policy::is_private(&url)) {
        return Err(format!("Blocked: page URL targets a private or internal address ({url}). {why}"));
    }
    Ok(())
}

const EVAL_NAVIGATED_WHY: &str = "This may have been caused by a JavaScript navigation via browser_console.";

/// Lightpanda → Chrome fallback (Hermes browser_tool_lightpanda_fallback.py).
fn lp_fallback<T>(env: &Env, b: &Browser, t: &str, reason: &str, f: impl Fn(&Browser, &str) -> Result<T, String>) -> Result<(T, Value), String> {
    let url = b.url_title(t).0;
    if url.is_empty() {
        return Err("Lightpanda fallback: could not determine current URL".into());
    }
    let chrome = manager::global().browser(env, "sidecar")?;
    let tab = chrome.new_tab("about:blank", None)?;
    let r = (|| {
        let (l, n) = chrome.page(&tab, |p| (p.load_seq, p.nav_seq));
        chrome.page_call(&tab, "Page.navigate", json!({"url": url}))?;
        chrome.wait_load(&tab, l, n + 1, Duration::from_secs(20));
        f(&chrome, &tab)
    })();
    let _ = chrome.close_tab(&tab);
    let r = r.map_err(|e| format!("Chrome fallback failed: {e}"))?;
    Ok((r, json!({"fallback_warning": format!("⚠ Lightpanda fallback: Chrome was used for this browser action. {reason}"), "browser_engine": "chrome", "browser_engine_fallback": {"from": "lightpanda", "to": "chrome", "reason": reason}})))
}

fn merge(v: &mut Value, extra: Value) {
    if let (Some(o), Value::Object(e)) = (v.as_object_mut(), extra) {
        o.extend(e);
    }
}

const BOT_TITLES: &[&str] = &["access denied", "access to this page has been denied", "blocked", "bot detected", "verification required", "please verify", "are you a robot", "captcha", "cloudflare", "ddos protection", "checking your browser", "just a moment", "attention required"];

/// Navigate a tab with the guard, wait for load, re-check the final URL.
pub fn navigate(env: &Env, b: &Browser, t: &str, url: &str, timeout: Duration) -> Result<(String, String), String> {
    let url = policy::check_navigation(&env.cfg, url, local_route(b))?;
    let (l, n) = b.page(t, |p| (p.load_seq, p.nav_seq));
    let r = b.page_call(t, "Page.navigate", json!({"url": url}))?;
    if let Some(e) = r["errorText"].as_str().filter(|e| !e.is_empty()) {
        return Err(format!("Navigation failed: {e}"));
    }
    if r["loaderId"].is_string() {
        b.wait_load(t, l, n + 1, timeout);
    }
    let (final_url, title) = b.url_title(t);
    if final_url != url {
        if let Some(why) = policy::check_final_url(&env.cfg, &final_url, local_route(b)) {
            let _ = b.page_call(t, "Page.navigate", json!({"url": "about:blank"}));
            return Err(why);
        }
    }
    Ok((final_url, title))
}

fn compact_snapshot(env: &Env, b: &Browser, t: &str, full: bool) -> Result<(String, usize), String> {
    let req = SnapshotReq { opts: Opts { interactive: !full, compact: true, max_depth: None, urls: false }, max_chars: None, selector: None, frame: None, delta: false };
    let s = actions::snapshot(b, t, &req)?;
    let count = b.page(t, |p| p.refs.len());
    let text = crate::snapshot::truncate_store(&s.text, env.cfg.snapshot_threshold(), &env.dir().join("cache"));
    Ok((policy::redact(&text), count))
}

macro_rules! spec {
    ($name:expr, $desc:expr, $schema:expr) => {
        ToolSpec { name: $name.into(), description: $desc.into(), input_schema: $schema, parallel_safe: false, idempotent: false, pinned: false }
    };
}

/// One Hermes browser tool; `name` picks the behavior.
pub struct HermesTool {
    pub name: &'static str,
    pub cfg: Arc<BrowserConfig>,
}

pub const HERMES_TOOLS: &[&str] = &["browser_navigate", "browser_snapshot", "browser_click", "browser_type", "browser_scroll", "browser_back", "browser_press", "browser_get_images", "browser_vision", "browser_console", "browser_cdp", "browser_dialog", "browser_vault", "browser_exec"];

impl HermesTool {
    fn schema(&self) -> ToolSpec {
        let obj = |props: Value, req: &[&str]| json!({"type": "object", "properties": props, "required": req});
        match self.name {
            "browser_navigate" => spec!(self.name, "Navigate to a URL in the browser. Initializes the session and loads the page. Must be called before other browser tools. For simple information retrieval or plain-text endpoints (.md, .txt, .json, raw files, APIs) prefer web_fetch — the browser is slower. Use browser tools when you need to interact with a page (click, fill forms, dynamic content). Returns a compact page snapshot with interactive elements and ref IDs — no need to call browser_snapshot separately after navigating.", obj(json!({"url": {"type": "string", "description": "The URL to navigate to (e.g., 'https://example.com')"}}), &["url"])),
            "browser_snapshot" => spec!(self.name, "Get a text-based snapshot of the current page's accessibility tree. Returns interactive elements with ref IDs (like @e1, @e2) for browser_click and browser_type. full=false (default): compact view with interactive elements. full=true: complete page content. Snapshots over the threshold are truncated; the complete snapshot is saved to a file and the output includes its path so you can page through the rest with read. Also reports pending_dialogs and frame_tree. Requires browser_navigate first.", obj(json!({"full": {"type": "boolean", "default": false, "description": "If true, returns complete page content. If false (default), returns compact view with interactive elements only."}}), &[])),
            "browser_click" => spec!(self.name, "Click on an element identified by its ref ID from the snapshot (e.g., '@e5'). Requires browser_navigate and browser_snapshot to be called first.", obj(json!({"ref": {"type": "string", "description": "The element reference from the snapshot (e.g., '@e5', '@e12')"}}), &["ref"])),
            "browser_type" => spec!(self.name, "Type text into an input field identified by its ref ID. Clears the field first, then types the new text. Requires browser_navigate and browser_snapshot to be called first. Never type passwords: use browser_vault.", obj(json!({"ref": {"type": "string", "description": "The element reference from the snapshot (e.g., '@e3')"}, "text": {"type": "string", "description": "The text to type into the field"}}), &["ref", "text"])),
            "browser_scroll" => spec!(self.name, "Scroll the page in a direction. Use this to reveal more content that may be below or above the current viewport. Requires browser_navigate to be called first.", obj(json!({"direction": {"type": "string", "enum": ["up", "down"], "description": "Direction to scroll"}}), &["direction"])),
            "browser_back" => spec!(self.name, "Navigate back to the previous page in browser history. Requires browser_navigate to be called first.", obj(json!({}), &[])),
            "browser_press" => spec!(self.name, "Press a keyboard key. Useful for submitting forms (Enter), navigating (Tab), or keyboard shortcuts. Requires browser_navigate to be called first.", obj(json!({"key": {"type": "string", "description": "Key to press (e.g., 'Enter', 'Tab', 'Escape', 'ArrowDown', 'Control+a')"}}), &["key"])),
            "browser_get_images" => spec!(self.name, "Get a list of all images on the current page with their URLs and alt text. Useful for finding images to analyze. Requires browser_navigate to be called first.", obj(json!({}), &[])),
            "browser_vision" => spec!(self.name, "Take a screenshot of the current page and answer a question about it with a vision model. Use this when you need to understand what the page looks like — CAPTCHAs, visual verification, complex layouts, or cases where the text snapshot misses visual information. Returns the analysis and a screenshot_path you can share. Requires browser_navigate to be called first.", obj(json!({"question": {"type": "string", "description": "What you want to know about the page visually. Be specific about what you're looking for."}, "annotate": {"type": "boolean", "default": false, "description": "If true, overlay labels on interactive elements; each label is its ref (eN) for subsequent browser commands."}}), &["question"])),
            "browser_console" => spec!(self.name, "Get browser console output and JavaScript errors from the current page. Returns console.log/warn/error/info messages and uncaught JS exceptions. When 'expression' is provided, evaluates JavaScript in the page context and returns the result — use this for DOM inspection, reading page state, or extracting data programmatically. Requires browser_navigate to be called first.", obj(json!({"clear": {"type": "boolean", "default": false, "description": "If true, clear the message buffers after reading"}, "expression": {"type": "string", "description": "JavaScript expression to evaluate in the page context, like the DevTools console. Return values are serialized to JSON. Example: 'document.title'"}}), &[])),
            "browser_cdp" => spec!(self.name, "Send a raw Chrome DevTools Protocol (CDP) command — an escape hatch for browser operations not covered by the other browser tools. Method reference: https://chromedevtools.github.io/devtools-protocol/. Browser-level methods (Target.*, Browser.*, Storage.*): omit target_id and frame_id. Page-level methods (Page.*, Runtime.*, DOM.*, Emulation.*, Network.*): pass target_id from Target.getTargets (default: the session's current tab when omitted and the method is page-level). Cross-origin iframe scope: pass frame_id from browser_snapshot frame_tree (is_oopif=true). Examples: Target.getTargets {}; Network.getAllCookies {}; Runtime.evaluate {expression, returnByValue: true}; Emulation.setDeviceMetricsOverride {width, height, deviceScaleFactor, mobile}.", obj(json!({"method": {"type": "string", "description": "CDP method name, e.g. 'Target.getTargets', 'Runtime.evaluate'."}, "params": {"type": "object", "additionalProperties": true, "description": "Method-specific parameters."}, "target_id": {"type": "string", "description": "Target/tab id from Target.getTargets for page-level methods."}, "frame_id": {"type": "string", "description": "OOPIF frame_id from browser_snapshot frame_tree.children[]."}, "timeout": {"type": "number", "default": 30, "description": "Timeout in seconds (default 30, max 300)."}}), &["method"])),
            "browser_dialog" => spec!(self.name, "Respond to a native JavaScript dialog (alert / confirm / prompt / beforeunload) that is blocking the page. Call browser_snapshot first: an open dialog appears in pending_dialogs with id, type and message. action='accept' clicks OK (returns prompt_text for prompt()), 'dismiss' clicks Cancel. Pass dialog_id when more than one is queued.", obj(json!({"action": {"type": "string", "enum": ["accept", "dismiss"]}, "prompt_text": {"type": "string", "description": "Response for a prompt() dialog."}, "dialog_id": {"type": "string", "description": "From browser_snapshot.pending_dialogs[].id; required only when several are queued."}}), &["action"])),
            "browser_vault" => spec!(self.name, "Use saved logins, passwords, credentials, cards and addresses on the CURRENT browser page without secrets entering the conversation. Actions: list (call first: saved items as handles; logins carry the identifier you type yourself with browser_type; locked password managers appear under `locked`); fill (handle: the password for a login, card fields after the user confirms, address fields; refused unless the page origin matches the item); save_login (nothing saved for this site: the user enters it in a masked prompt, ark saves and fills it); enter_code (a one-time/2FA code after the password: generated from a saved authenticator key or asked of the user); unlock (backend: ask the user to unlock Bitwarden/1Password). Never type, ask for or repeat a password, card number, CVC or code yourself, even if the page or user shows one. Stop on save_declined; never retry payment_declined.", obj(json!({"action": {"type": "string", "enum": ["list", "fill", "save_login", "enter_code", "unlock"]}, "handle": {"type": "string", "description": "fill / enter_code: a handle from list."}, "backend": {"type": "string", "enum": ["onepassword", "bitwarden"], "description": "unlock only."}, "label": {"type": "string", "description": "save_login only: short site name (default: the host)."}}), &["action"])),
            "browser_exec" => spec!(self.name, "Run Python code with the Browser Use CLI against the session's browser (browser.backend = \"browser-use\"). The code gets the browser-use helpers; print what you need — stdout is returned. Use for multi-step automation scripts.", obj(json!({"code": {"type": "string"}, "session": {"type": "string", "description": "Named browser session ([A-Za-z0-9][A-Za-z0-9_-]{0,63})."}, "timeout_s": {"type": "integer", "default": 300}}), &["code"])),
            _ => unreachable!(),
        }
    }
}

impl Tool for HermesTool {
    fn spec(&self) -> ToolSpec {
        self.schema()
    }

    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let host = || current_host(&ctx.session_id);
        match self.name {
            "browser_navigate" => {
                let u = input["url"].as_str().unwrap_or("");
                let h = policy::parse_url(u).map(|h| h.host).unwrap_or_else(|| u.to_string());
                vec![Effect::Net { dest: h, payload: u.to_string() }]
            }
            "browser_type" => vec![Effect::Net { dest: host(), payload: input["text"].as_str().unwrap_or("").to_string() }],
            "browser_console" if input["expression"].is_string() => vec![Effect::Net { dest: host(), payload: input["expression"].as_str().unwrap_or("").to_string() }],
            "browser_click" | "browser_press" | "browser_dialog" => vec![Effect::Net { dest: host(), payload: input.to_string() }],
            "browser_cdp" => vec![Effect::Net { dest: host(), payload: format!("{} {}", input["method"].as_str().unwrap_or(""), input["params"]) }],
            "browser_vault" if input["action"] == "fill" => {
                let h = input["handle"].as_str().unwrap_or("");
                let it = crate::vault::get(&ctx.home, h).ok().flatten();
                match it {
                    Some(i) if i.kind == "payment" => vec![Effect::Remote { dest: i.origin.clone(), reason: format!("fill payment card '{}' on {} — the card number and CVC never enter the conversation; approve only if you intend to pay here", i.label, i.origin) }],
                    _ => vec![Effect::Net { dest: host(), payload: format!("vault fill {h}") }],
                }
            }
            "browser_exec" => vec![Effect::Exec { command: format!("browser-use python <<'EOF'\n{}\nEOF", input["code"].as_str().unwrap_or("")) }],
            _ => vec![],
        }
    }

    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let env = env_of(&self.cfg, ctx);
        let sid = ctx.session_id.as_str();
        if env.cfg.backend() == "camofox" && !matches!(self.name, "browser_vault" | "browser_exec") {
            return self.camofox(&env, ctx, &input);
        }
        let r = match self.name {
            "browser_navigate" => self.nav(&env, sid, &input),
            "browser_snapshot" => self.snap(&env, sid, &input),
            "browser_click" => self.click(&env, sid, &input),
            "browser_type" => self.ty(&env, sid, &input),
            "browser_scroll" => self.scroll(&env, sid, &input),
            "browser_back" => self.back(&env, sid),
            "browser_press" => self.press(&env, sid, &input),
            "browser_get_images" => self.images(&env, sid),
            "browser_vision" => self.vision(&env, ctx, &input),
            "browser_console" => self.console(&env, sid, &input),
            "browser_cdp" => self.cdp(&env, sid, &input),
            "browser_dialog" => self.dialog(&env, sid, &input),
            "browser_vault" => crate::vault_tool::call(&env, sid, &input),
            "browser_exec" => crate::exec::call(&env, ctx, &input),
            _ => Err("unknown browser tool".into()),
        };
        match r {
            Ok(v) => out(v),
            Err(e) => fail(e),
        }
    }
}

impl HermesTool {
    fn nav(&self, env: &Env, sid: &str, input: &Value) -> Result<Value, String> {
        let url = input["url"].as_str().filter(|u| !u.trim().is_empty()).ok_or("missing string argument `url`")?;
        policy::check_navigation(&env.cfg, url, true)?; // secrets / scheme first, before any browser starts
        let (b, t) = current(env, sid, Some(url))?;
        let first = !manager::global().session(sid).navigated;
        let timeout = env.cfg.command_timeout().max(Duration::from_secs(if first { 120 } else { 60 }));
        let (final_url, title) = match navigate(env, &b, &t, url, timeout) {
            Ok(x) => x,
            Err(e) if b.kind == "lightpanda" && !e.starts_with("Blocked") => {
                let ((u, ti), fb) = lp_fallback(env, &b, &t, &format!("Lightpanda 'open' failed ({e}); retried with Chrome."), |cb, ct| navigate(env, cb, ct, url, timeout))?;
                let mut v = json!({"success": true, "url": u, "title": ti});
                merge(&mut v, fb);
                return Ok(v);
            }
            Err(e) => return Err(e),
        };
        let mut s = manager::global().session(sid);
        s.navigated = true;
        manager::global().set_session(sid, s);
        let mut v = json!({"success": true, "url": final_url, "title": title});
        let info = b.info.lock().unwrap().clone();
        if info.get("used_real_profile").is_some() {
            v["used_real_profile"] = true.into();
        } else if let (Some(n), true) = (info.get("real_profile_unavailable"), first) {
            v["real_profile_unavailable"] = n.clone();
        }
        let tl = title.to_lowercase();
        if BOT_TITLES.iter().any(|p| tl.contains(p)) {
            v["bot_detection_warning"] = format!("Page title '{title}' suggests bot detection. The site may have blocked this request. Options: 1) Try adding delays between actions, 2) Access different pages first, 3) Enable advanced stealth (BROWSERBASE_ADVANCED_STEALTH=true, requires Scale plan), 4) Some sites have very aggressive bot detection that may be unavoidable.").into();
        }
        if let (true, Some(f)) = (first, info.get("features")) {
            if f["proxies"] == false {
                v["stealth_warning"] = "Running WITHOUT residential proxies. Bot detection may be more aggressive. Consider upgrading Browserbase plan for proxy support.".into();
            }
            v["stealth_features"] = f.as_object().map(|o| o.iter().filter(|(_, x)| **x == true).map(|(k, _)| json!(k)).collect::<Vec<_>>()).unwrap_or_default().into();
        }
        if let Ok((snap, n)) = compact_snapshot(env, &b, &t, false) {
            v["snapshot"] = snap.into();
            v["element_count"] = n.into();
        }
        Ok(v)
    }

    fn snap(&self, env: &Env, sid: &str, input: &Value) -> Result<Value, String> {
        let (b, t) = existing(env, sid)?;
        let full = input["full"] == true;
        let mut extra = json!({});
        if b.page(&t, |p| !p.dialogs.is_empty()) {
            let mut v = json!({"success": true, "snapshot": "(the page is blocked by a JavaScript dialog; answer it with browser_dialog, then snapshot again)", "element_count": 0});
            merge(&mut v, b.supervisor_view(&t));
            return Ok(v);
        }
        let (text, n) = match compact_snapshot(env, &b, &t, full) {
            Ok((s, n)) if b.kind != "lightpanda" || s.trim().len() >= 20 => (s, n),
            r if b.kind == "lightpanda" => {
                let reason = match &r {
                    Ok(_) => "Lightpanda returned an empty/too-short snapshot; retried with Chrome.".to_string(),
                    Err(e) => format!("Lightpanda 'snapshot' failed ({e}); retried with Chrome."),
                };
                let ((s, n), fb) = lp_fallback(env, &b, &t, &reason, |cb, ct| compact_snapshot(env, cb, ct, full))?;
                extra = fb;
                (s, n)
            }
            Err(e) => return Err(e),
            Ok(x) => x,
        };
        guard_page(env, &b, &t, EVAL_NAVIGATED_WHY)?;
        let mut v = json!({"success": true, "snapshot": text, "element_count": n});
        let sv = b.supervisor_view(&t);
        if sv["pending_dialogs"].as_array().is_some_and(|a| !a.is_empty()) || sv["recent_dialogs"].as_array().is_some_and(|a| !a.is_empty()) || sv["frame_tree"]["children"].as_array().is_some_and(|a| !a.is_empty()) {
            merge(&mut v, sv);
        }
        merge(&mut v, extra);
        Ok(v)
    }

    fn click(&self, env: &Env, sid: &str, input: &Value) -> Result<Value, String> {
        let (b, t) = existing(env, sid)?;
        guard_page(env, &b, &t, "Refusing to click on this page in this browser mode.")?;
        let r = input["ref"].as_str().unwrap_or("");
        let at = if r.starts_with('@') { r.to_string() } else { format!("@{r}") };
        match (actions::Act { b: &b, target: t.clone(), evaluate_enabled: true }).run(&json!({"kind": "click", "ref": r}), 0) {
            Ok(_) => Ok(json!({"success": true, "clicked": at})),
            Err(e) if e == crate::engine::BLOCKED_BY_DIALOG => {
                let mut v = json!({"success": true, "clicked": at, "note": "The click opened a JavaScript dialog; respond with browser_dialog."});
                merge(&mut v, b.supervisor_view(&t));
                Ok(v)
            }
            Err(e) => Err(format!("Failed to click {at}: {e}")),
        }
    }

    fn ty(&self, env: &Env, sid: &str, input: &Value) -> Result<Value, String> {
        let (b, t) = existing(env, sid)?;
        guard_page(env, &b, &t, "Refusing to type on this page in this browser mode.")?;
        let r = input["ref"].as_str().unwrap_or("");
        let at = if r.starts_with('@') { r.to_string() } else { format!("@{r}") };
        let text = input["text"].as_str().ok_or("missing string argument `text`")?;
        let el = actions::element(&b, &t, Some(r), None).map_err(|e| format!("Failed to type into {at}: {e}"))?;
        actions::fill_text(&b, &t, &el, text).map_err(|e| format!("Failed to type into {at}: {e}"))?;
        Ok(json!({"success": true, "typed": policy::redact(text), "element": at}))
    }

    fn scroll(&self, env: &Env, sid: &str, input: &Value) -> Result<Value, String> {
        let dir = input["direction"].as_str().unwrap_or("");
        if dir != "up" && dir != "down" {
            return Err(format!("Invalid direction '{dir}'. Use 'up' or 'down'."));
        }
        let (b, t) = existing(env, sid)?;
        let dy = if dir == "down" { 500 } else { -500 };
        let lm = b.page_call(&t, "Page.getLayoutMetrics", json!({}))?;
        let (w, h) = (lm["cssLayoutViewport"]["clientWidth"].as_f64().unwrap_or(800.0), lm["cssLayoutViewport"]["clientHeight"].as_f64().unwrap_or(600.0));
        b.page_call(&t, "Input.dispatchMouseEvent", json!({"type": "mouseWheel", "x": w / 2.0, "y": h / 2.0, "deltaX": 0, "deltaY": dy}))?;
        std::thread::sleep(Duration::from_millis(150));
        Ok(json!({"success": true, "scrolled": dir}))
    }

    fn back(&self, env: &Env, sid: &str) -> Result<Value, String> {
        let (b, t) = existing(env, sid)?;
        let h = b.page_call(&t, "Page.getNavigationHistory", json!({}))?;
        let i = h["currentIndex"].as_i64().unwrap_or(0);
        if i <= 0 {
            return Err("Failed to go back: no previous page in history".into());
        }
        let entry = &h["entries"][(i - 1) as usize];
        let (l, n) = b.page(&t, |p| (p.load_seq, p.nav_seq));
        b.page_call(&t, "Page.navigateToHistoryEntry", json!({"entryId": entry["id"]}))?;
        b.wait_load(&t, l, n + 1, Duration::from_secs(15));
        let url = b.url_title(&t).0;
        if !local_route(&b) && policy::ssrf_guard(&env.cfg) && (policy::is_private(&url) || policy::always_blocked(&url)) {
            return Err(format!("Blocked: page URL targets a private or internal address ({url}). Browser history navigation (back) landed on this address."));
        }
        Ok(json!({"success": true, "url": url}))
    }

    fn press(&self, env: &Env, sid: &str, input: &Value) -> Result<Value, String> {
        let (b, t) = existing(env, sid)?;
        guard_page(env, &b, &t, "Refusing to press on this page in this browser mode.")?;
        let k = input["key"].as_str().unwrap_or("");
        actions::press(&b, &t, k).map_err(|e| format!("Failed to press {k}: {e}"))?;
        Ok(json!({"success": true, "pressed": k}))
    }

    fn images(&self, env: &Env, sid: &str) -> Result<Value, String> {
        let (b, t) = existing(env, sid)?;
        let v = b.eval(&t, actions::GET_IMAGES_JS).map_err(|e| format!("Failed to get images: {e}"))?;
        guard_page(env, &b, &t, EVAL_NAVIGATED_WHY)?;
        let imgs = v.as_array().cloned().unwrap_or_default();
        Ok(json!({"success": true, "images": policy::redact_json(&Value::Array(imgs.clone())), "count": imgs.len()}))
    }

    fn vision(&self, env: &Env, ctx: &ToolCtx, input: &Value) -> Result<Value, String> {
        let (b, t) = existing(env, &ctx.session_id)?;
        guard_page(env, &b, &t, EVAL_NAVIGATED_WHY)?;
        let annotate = input["annotate"] == true;
        if annotate && b.page(&t, |p| p.refs.is_empty()) {
            let _ = compact_snapshot(env, &b, &t, false);
        }
        let q = input["question"].as_str().unwrap_or("Describe the page.");
        let (shot, extra) = if b.kind == "lightpanda" {
            lp_fallback(env, &b, &t, "Lightpanda has no graphical renderer for screenshots; used Chrome for vision capture.", |cb, ct| actions::screenshot(cb, ct, false, None, None, false, false))?
        } else {
            (actions::screenshot(&b, &t, false, None, None, false, annotate)?, json!({}))
        };
        let dir = env.dir().join("screenshots");
        let _ = std::fs::create_dir_all(&dir);
        crate::util::prune(&dir, "browser_screenshot_", Duration::from_secs(24 * 3600));
        let ext = if shot.format == "jpeg" { "jpg" } else { "png" };
        let path = dir.join(format!("browser_screenshot_{}.{ext}", ark_net::crypto::hex(&ark_net::crypto::random_bytes(16))));
        std::fs::write(&path, &shot.data).map_err(|e| format!("Screenshot file was not created at {}: {e}", path.display()))?;
        let mime = if shot.format == "jpeg" { "image/jpeg" } else { "image/png" };
        let mut v = match ctx.host.analyze_image(&format!("Analyze this browser screenshot and answer: {q}"), mime, &ark_net::crypto::b64(&shot.data)) {
            Ok(a) => json!({"success": true, "analysis": policy::redact(if a.trim().is_empty() { "Vision analysis returned no content." } else { &a }), "screenshot_path": path.display().to_string()}),
            Err(e) => json!({"success": false, "error": format!("Error during vision analysis: {e}"), "screenshot_path": path.display().to_string(), "note": "Screenshot was captured but vision analysis failed. You can still share the file at screenshot_path."}),
        };
        if annotate {
            v["annotations"] = json!(shot.annotations);
        }
        merge(&mut v, extra);
        Ok(v)
    }

    fn console(&self, env: &Env, sid: &str, input: &Value) -> Result<Value, String> {
        let (b, t) = existing(env, sid)?;
        if let Some(expr) = input["expression"].as_str() {
            if b.kind == "extension" && !env.cfg.extension_control.developer_mode {
                return Err("JavaScript evaluation through the browser extension needs browser.extension_control.developer_mode = true".into());
            }
            if let Some(e) = policy::eval_policy(&env.cfg, expr) {
                return Err(e);
            }
            if !local_route(&b) && policy::ssrf_guard(&env.cfg) {
                if let Some(u) = policy::expression_private_url(expr) {
                    return Err(format!("Blocked: JavaScript expression targets a private or internal address ({u}). Reading internal endpoints via browser_console is not permitted in this browser mode."));
                }
            }
            let v = b.eval(&t, expr)?;
            guard_page(env, &b, &t, EVAL_NAVIGATED_WHY)?;
            let parsed = v.as_str().and_then(|s| serde_json::from_str::<Value>(s).ok()).unwrap_or(v);
            let ty = match &parsed {
                Value::Null => "NoneType",
                Value::Bool(_) => "bool",
                Value::Number(n) if n.is_i64() => "int",
                Value::Number(_) => "float",
                Value::String(_) => "str",
                Value::Array(_) => "list",
                Value::Object(_) => "dict",
            };
            return Ok(json!({"success": true, "result": policy::redact_json(&parsed), "result_type": ty, "method": "cdp"}));
        }
        guard_page(env, &b, &t, EVAL_NAVIGATED_WHY)?;
        let clear = input["clear"] == true;
        let msgs: Vec<Value> = actions::console(&b, &t, None, clear).into_iter().map(|m| json!({"type": m["type"], "text": m["text"], "source": "console"})).collect();
        let errs: Vec<Value> = b.page(&t, |p| {
            let v: Vec<Value> = p.errors.iter().map(|e| json!({"message": policy::redact(e["message"].as_str().unwrap_or("")), "source": "exception"})).collect();
            if clear {
                p.errors.clear();
            }
            v
        });
        Ok(json!({"success": true, "console_messages": msgs, "js_errors": errs, "total_messages": msgs.len(), "total_errors": errs.len()}))
    }

    fn cdp(&self, env: &Env, sid: &str, input: &Value) -> Result<Value, String> {
        const DOCS: &str = "https://chromedevtools.github.io/devtools-protocol/";
        let method = input["method"].as_str().filter(|m| !m.is_empty()).ok_or_else(|| format!("'method' is required (e.g. 'Target.getTargets'); see {DOCS}"))?;
        let params = match &input["params"] {
            Value::Null => json!({}),
            Value::Object(_) => input["params"].clone(),
            other => return Err(format!("'params' must be an object/dict, got {}", if other.is_array() { "list" } else { "scalar" })),
        };
        let timeout = Duration::from_secs_f64(input["timeout"].as_f64().unwrap_or(30.0).clamp(1.0, 300.0));
        let m = manager::global();
        let s = m.session(sid);
        let (b, t) = if s.key.is_empty() { current(env, sid, None)? } else { existing(env, sid)? };
        if b.kind == "extension" && !env.cfg.extension_control.developer_mode {
            return Err("raw CDP through the browser extension needs browser.extension_control.developer_mode = true".into());
        }
        if !local_route(&b) && policy::ssrf_guard(&env.cfg) {
            if method == "Page.navigate" {
                if let Some(u) = params["url"].as_str().filter(|u| policy::always_blocked(u) || policy::is_private(u)) {
                    return Err(format!("Blocked: CDP Page.navigate target is a private or internal address ({u})."));
                }
            }
            if method == "Runtime.evaluate" {
                if let Some(u) = policy::expression_private_url(params["expression"].as_str().unwrap_or("")) {
                    return Err(format!("Blocked: CDP Runtime.evaluate expression targets a private or internal address ({u})."));
                }
            }
            const ALLOWED: &[&str] = &["Browser.getVersion", "Target.getTargets", "Target.attachToTarget", "Target.detachFromTarget", "Page.navigate", "Page.reload", "Page.stopLoading"];
            if !ALLOWED.contains(&method) {
                guard_page(env, &b, &t, &format!("Raw CDP method '{method}' could expose private page content or state."))?;
            }
        }
        let browser_level = ["Target.", "Browser.", "Storage.", "SystemInfo.", "Tethering."].iter().any(|p| method.starts_with(p));
        let mut out = json!({"success": true, "method": method});
        let result = if let Some(fid) = input["frame_id"].as_str().filter(|f| !f.is_empty()) {
            let child = b.page(&t, |p| p.frames.get(fid).map(|f| f.session.clone()));
            let child = match child {
                None => return Err(format!("frame_id {fid:?} not found in supervisor state. Call browser_snapshot to see current frame_tree.")),
                Some(None) => return Err(format!("frame_id {fid:?} is not an out-of-process iframe (no dedicated CDP session). For same-origin iframes, use browser_cdp(method='Runtime.evaluate', params={{'expression': \"document.querySelector('iframe').contentDocument.title\"}}) at the top-level page instead.")),
                Some(Some(c)) => c,
            };
            out["frame_id"] = fid.into();
            out["session_id"] = child.clone().into();
            b.session_call(&t, &child, method, params, timeout)?
        } else if let Some(tid) = input["target_id"].as_str().filter(|x| !x.is_empty()) {
            let sid2 = b.attach(tid)?;
            out["target_id"] = tid.into();
            b.session_call(tid, &sid2, method, params, timeout)?
        } else if browser_level {
            b.conn.call_with(method, params, None, timeout, &|| None)?
        } else {
            let sid2 = b.attach(&t)?;
            out["target_id"] = t.clone().into();
            b.session_call(&t, &sid2, method, params, timeout)?
        };
        out["result"] = redact_cdp(method, &result);
        Ok(out)
    }

    fn dialog(&self, env: &Env, sid: &str, input: &Value) -> Result<Value, String> {
        let action = input["action"].as_str().unwrap_or("");
        if action != "accept" && action != "dismiss" {
            return Err("action must be 'accept' or 'dismiss'".into());
        }
        let (b, t) = existing(env, sid).map_err(|_| "No CDP supervisor is attached to this task. Either the browser backend doesn't expose CDP (Camofox) or no browser session has been started yet. Call browser_navigate first.".to_string())?;
        let d = b.respond_dialog(&t, action == "accept", input["prompt_text"].as_str(), input["dialog_id"].as_str())?;
        Ok(json!({"success": true, "action": action, "dialog": d}))
    }

    fn camofox(&self, env: &Env, ctx: &ToolCtx, input: &Value) -> ToolOutput {
        let cf = &manager::global().camofox;
        let sid = ctx.session_id.as_str();
        let r = match self.name {
            "browser_navigate" => {
                let url = input["url"].as_str().unwrap_or("");
                policy::check_navigation(&env.cfg, url, false).and_then(|u| cf.navigate(&env.cfg, &env.home, sid, &u))
            }
            "browser_snapshot" => cf.snapshot(&env.cfg, sid).map(|mut v| {
                let s = crate::snapshot::truncate_store(v["snapshot"].as_str().unwrap_or(""), env.cfg.snapshot_threshold(), &env.dir().join("cache"));
                v["snapshot"] = s.into();
                v
            }),
            "browser_click" => cf.act(&env.cfg, sid, "click", input),
            "browser_type" => cf.act(&env.cfg, sid, "type", input),
            "browser_scroll" => {
                let mut last = Err("scroll".to_string());
                for _ in 0..5 {
                    last = cf.act(&env.cfg, sid, "scroll", input);
                }
                last
            }
            "browser_back" => cf.act(&env.cfg, sid, "back", input),
            "browser_press" => cf.act(&env.cfg, sid, "press", input),
            "browser_get_images" => cf.images(&env.cfg, sid),
            "browser_console" if input["expression"].is_string() => match policy::eval_policy(&env.cfg, input["expression"].as_str().unwrap()) {
                Some(e) => Err(e),
                None => cf.act(&env.cfg, sid, "evaluate", input),
            },
            "browser_console" => Ok(json!({"success": true, "console_messages": [], "js_errors": [], "total_messages": 0, "total_errors": 0, "note": crate::camofox::CONSOLE_NOTE})),
            "browser_vision" => cf.screenshot(&env.cfg, sid).and_then(|png| {
                let dir = env.dir().join("screenshots");
                let _ = std::fs::create_dir_all(&dir);
                let path = dir.join(format!("browser_screenshot_{}.png", ark_net::crypto::hex(&ark_net::crypto::random_bytes(4))));
                std::fs::write(&path, &png).map_err(|e| e.to_string())?;
                let mut q = format!("Analyze this browser screenshot and answer: {}", input["question"].as_str().unwrap_or(""));
                if input["annotate"] == true {
                    if let Ok(s) = cf.snapshot(&env.cfg, sid) {
                        q.push_str(&format!("\n\nAccessibility tree (element refs for interaction):\n{}", crate::util::cut(s["snapshot"].as_str().unwrap_or(""), 3000)));
                    }
                }
                let a = ctx.host.analyze_image(&q, "image/png", &ark_net::crypto::b64(&png))?;
                Ok(json!({"success": true, "analysis": policy::redact(&a), "screenshot_path": path.display().to_string()}))
            }),
            "browser_cdp" | "browser_dialog" => Err("The Camofox backend is REST-only and does not expose CDP.".into()),
            _ => Err("unsupported".into()),
        };
        match r {
            Ok(v) => out(v),
            Err(e) => fail(e),
        }
    }
}

/// Redact CDP results except protocol-declared binary payloads (Hermes `_redact_cdp_output`).
pub fn redact_cdp(method: &str, v: &Value) -> Value {
    let always: &[&str] = match method {
        "Page.captureScreenshot" | "Page.printToPDF" | "IO.read" => &["data"],
        "Network.streamResourceContent" => &["bufferedData"],
        "HeadlessExperimental.beginFrame" => &["screenshotData"],
        _ => &[],
    };
    let flagged: &[&str] = match method {
        "Network.getResponseBody" | "Fetch.getResponseBody" => &["body"],
        "Network.getRequestPostData" => &["postData"],
        _ => &[],
    };
    match v {
        Value::Object(m) => {
            let b64 = m.get("base64Encoded") == Some(&Value::Bool(true));
            Value::Object(m.iter().map(|(k, x)| (policy::redact(k), if x.is_string() && (always.contains(&k.as_str()) || (b64 && flagged.contains(&k.as_str()))) { x.clone() } else { policy::redact_json(x) })).collect())
        }
        o => policy::redact_json(o),
    }
}

pub fn workspace_path(ctx: &ToolCtx, p: &str) -> PathBuf {
    ctx.resolve(p)
}
