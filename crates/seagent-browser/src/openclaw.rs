//! OpenClaw's `browser` tool (extensions/browser/src/browser-tool*.ts, MIT): one tool
//! with `action` = doctor | status | start | stop | profiles | importprofile | tabs |
//! open | focus | close | snapshot | screenshot | navigate | console | requests |
//! errors | text | emulate | pdf | download | waitfordownload | upload | dialog | act.

use crate::actions::{self, Act, SnapshotReq};
use crate::config::BrowserConfig;
use crate::engine::Browser;
use crate::manager::{self, Env};
use crate::policy;
use crate::snapshot::{self, Opts};
use crate::tools::{self, env_of};
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub const ACTIONS: &[&str] = &["doctor", "status", "start", "stop", "profiles", "importprofile", "tabs", "open", "focus", "close", "snapshot", "screenshot", "navigate", "console", "requests", "errors", "text", "emulate", "pdf", "download", "waitfordownload", "upload", "dialog", "act"];
pub const ACT_KINDS: &[&str] = &["batch", "click", "clickCoords", "type", "press", "hover", "scrollIntoView", "drag", "select", "fill", "resize", "wait", "evaluate", "close"];

pub struct BrowserTool {
    pub cfg: Arc<BrowserConfig>,
}

fn act_props() -> Value {
    json!({
        "targetId": {"type": "string", "description": "Prefer suggestedTargetId/tabId/label; raw CDP targetId."},
        "ref": {"type": "string", "description": "snapshot ref."},
        "actions": {"type": "array", "items": {"type": "object", "additionalProperties": true}, "description": "batch actions."},
        "stopOnError": {"type": "boolean", "description": "Stop on error; default true."},
        "doubleClick": {"type": "boolean"}, "button": {"type": "string"}, "modifiers": {"type": "array", "items": {"type": "string"}},
        "x": {"type": "number"}, "y": {"type": "number"}, "text": {"type": "string"}, "submit": {"type": "boolean"}, "slowly": {"type": "boolean"},
        "key": {"type": "string", "description": "Escape, Enter, Control+Shift+T; aliases Esc, Return, Del, Ctrl, Cmd."},
        "delayMs": {"type": "integer", "minimum": 0}, "startRef": {"type": "string"}, "endRef": {"type": "string"},
        "values": {"type": "array", "items": {"type": "string"}}, "fields": {"type": "array", "items": {"type": "object", "additionalProperties": true}},
        "width": {"type": "integer", "minimum": 1, "maximum": 8192}, "height": {"type": "integer", "minimum": 1, "maximum": 8192},
        "timeMs": {"type": "integer", "minimum": 0}, "selector": {"type": "string"}, "url": {"type": "string"}, "loadState": {"type": "string"},
        "textGone": {"type": "string"}, "timeoutMs": {"type": "integer", "minimum": 1}, "fn": {"type": "string"}
    })
}

impl BrowserTool {
    fn description(&self) -> String {
        format!("Control a browser over the Chrome DevTools Protocol. Available actions: {}. Browser choice: omit profile to use the configured default (the isolated seagent-managed `{}` browser); when existing logins matter use action=profiles and pick a profile by name (`user` attaches to your running Chrome). When using refs from snapshot (e.g. e12), keep the same tab: pass targetId from the snapshot response into subsequent actions; targetId also accepts tabId handles (t1) and labels from action=tabs. navigate returns the loaded page's compact snapshot inline (efficient interactive tier; use action=snapshot for a full one); do not call snapshot after navigate. After a single act that triggers navigation, snapshot before using refs. Use snapshot+act for UI automation; avoid act:wait unless no reliable UI state exists. For page prose use action=text with optional selector and maxChars. Use snapshot query to keep lines matching all whitespace-separated tokens. Use requests for the recent network log (filter, limit default 50, clear) and errors for page errors. Use emulate with device, colorScheme, timezoneId, or locale. For file chooser uploads pass the trigger ref with paths; use inputRef or element to set a file input directly. Repeated snapshots mark newly appeared ref elements with [new]. target selects browser location (sandbox|host).", ACTIONS.join(", "), self.cfg.default_profile)
    }
}

impl Tool for BrowserTool {
    fn spec(&self) -> ToolSpec {
        let mut props = json!({
            "action": {"type": "string", "enum": ACTIONS},
            "target": {"type": "string", "enum": ["sandbox", "host", "node"]},
            "profile": {"type": "string", "description": "default if omitted."},
            "systemProfile": {"type": "string"}, "into": {"type": "string"},
            "targetUrl": {"type": "string"}, "label": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1}, "maxChars": {"type": "integer", "minimum": 0},
            "mode": {"type": "string", "enum": ["efficient"]}, "snapshotFormat": {"type": "string", "enum": ["aria", "ai"]},
            "refs": {"type": "string", "enum": ["role", "aria"]}, "interactive": {"type": "boolean"}, "compact": {"type": "boolean"},
            "depth": {"type": "integer", "minimum": 0}, "frame": {"type": "string"},
            "labels": {"type": "boolean", "description": "Label snapshot/screenshot."}, "fullPage": {"type": "boolean"}, "element": {"type": "string"},
            "type": {"type": "string", "enum": ["png", "jpeg"]}, "urls": {"type": "boolean"}, "path": {"type": "string"},
            "level": {"type": "string"}, "filter": {"type": "string"}, "clear": {"type": "boolean"}, "query": {"type": "string"},
            "device": {"type": "string"}, "colorScheme": {"type": "string", "enum": ["dark", "light", "no-preference", "none"]},
            "timezoneId": {"type": "string"}, "locale": {"type": "string"},
            "paths": {"type": "array", "items": {"type": "string"}}, "inputRef": {"type": "string"},
            "dialogId": {"type": "string"}, "accept": {"type": "boolean"}, "promptText": {"type": "string"},
            "kind": {"type": "string", "enum": ACT_KINDS, "description": "batch uses actions."},
        });
        let ap = act_props();
        for (k, v) in ap.as_object().unwrap() {
            props[k] = v.clone();
        }
        let mut req = json!({"type": "object", "properties": {"kind": {"type": "string", "enum": ACT_KINDS}}, "description": "act"});
        for (k, v) in ap.as_object().unwrap() {
            req["properties"][k] = v.clone();
        }
        props["request"] = req;
        ToolSpec { name: "browser".into(), description: self.description(), input_schema: json!({"type": "object", "properties": props, "required": ["action"]}), parallel_safe: false, idempotent: false, pinned: false }
    }

    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let host = || tools::current_host(&ctx.session_id);
        let url = input["targetUrl"].as_str().or(input["url"].as_str()).unwrap_or("");
        let uhost = || policy::parse_url(url).map(|h| h.host).unwrap_or_else(|| url.to_string());
        let mut e = vec![];
        match input["action"].as_str().unwrap_or("") {
            "open" | "navigate" => e.push(Effect::Net { dest: uhost(), payload: url.to_string() }),
            "act" | "dialog" => e.push(Effect::Net { dest: host(), payload: input.to_string() }),
            "upload" => {
                for p in input["paths"].as_array().into_iter().flatten().filter_map(|p| p.as_str()) {
                    e.push(Effect::Read { path: ctx.resolve(p) });
                }
                e.push(Effect::Net { dest: host(), payload: "file upload".into() });
            }
            "screenshot" | "pdf" | "download" | "waitfordownload" => {
                if let Some(p) = input["path"].as_str() {
                    e.push(Effect::Write { path: ctx.resolve(p) });
                }
            }
            _ => {}
        }
        e
    }

    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let env = env_of(&self.cfg, ctx);
        match run(&env, ctx, &input) {
            Ok(Reply::Json(v)) => tools::out(v),
            Ok(Reply::Text(t, ok)) => {
                if ok {
                    ToolOutput::ok(t)
                } else {
                    ToolOutput::err(t)
                }
            }
            Err(e) => ToolOutput::err(policy::redact(&e)),
        }
    }
}

enum Reply {
    Json(Value),
    Text(String, bool),
}

fn s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v[k].as_str().filter(|x| !x.trim().is_empty())
}

fn browser_for(env: &Env, ctx: &ToolCtx, p: &Value, url: Option<&str>) -> Result<Arc<Browser>, String> {
    let m = manager::global();
    let key = match s(p, "target") {
        Some("sandbox") => "sandbox".to_string(),
        Some("node") => return Err("target=node: use node_invoke with computer.act browser_* actions on the paired node.".into()),
        _ => {
            let sess = m.session(&ctx.session_id);
            if s(p, "profile").is_none() && !sess.key.is_empty() && m.get(&sess.key).is_some() && url.is_none() {
                sess.key
            } else {
                m.key_for(env, s(p, "profile"), &ctx.session_id, url)
            }
        }
    };
    m.browser(env, &key)
}

/// The tab an action addresses: explicit targetId, else the session's current tab.
fn tab(env: &Env, ctx: &ToolCtx, b: &Browser, p: &Value) -> Result<String, String> {
    let m = manager::global();
    match s(p, "targetId").or_else(|| s(&p["request"], "targetId")) {
        Some(r) => {
            let t = b.resolve_tab(r, None)?;
            b.attach(&t)?;
            m.focus(&ctx.session_id, b, &t);
            Ok(t)
        }
        None => m.tab(env, &ctx.session_id, b),
    }
}

fn efficient(b: &Browser, t: &str) -> Result<actions::SnapshotOut, String> {
    actions::snapshot(b, t, &SnapshotReq { opts: Opts { interactive: true, compact: true, max_depth: Some(snapshot::EFFICIENT_DEPTH), urls: false }, max_chars: Some(snapshot::EFFICIENT_MAX_CHARS), selector: None, frame: None, delta: true })
}

fn page_state(b: &Browser, t: &str) -> String {
    match efficient(b, t) {
        Ok(s) => policy::wrap_untrusted(&s.text, true, "\n[truncated — retry with a smaller maxChars or limit]").0,
        Err(e) => format!("[page snapshot unavailable: {}. Use action=snapshot to read the page.]", policy::wrap_untrusted(&e, false, "").0),
    }
}

fn json_wrapped(kind: &str, payload: &Value) -> Reply {
    let marker = match kind {
        "console" => "\n[truncated — retry with a stricter level or targetId]",
        "requests" => "\n[truncated — retry with a narrower filter or smaller limit]",
        "errors" => "\n[truncated — retry with a smaller limit]",
        "tabs" => "\n[truncated — retry with action=snapshot and a specific targetId]",
        "download" => "\n[truncated — retry with a specific targetId and download ref]",
        _ => "\n[truncated — inspect the affected targetId with action=snapshot]",
    };
    let ok = payload["ok"] != false;
    Reply::Text(policy::wrap_untrusted(&serde_json::to_string_pretty(&policy::redact_json(payload)).unwrap_or_default(), false, marker).0, ok)
}

fn out_dir(ctx: &ToolCtx, sub: &str) -> PathBuf {
    ctx.artifacts.join("browser").join(sub)
}

fn out_path(ctx: &ToolCtx, p: &Value, sub: &str, name: String) -> Result<PathBuf, String> {
    let path = match s(p, "path") {
        Some(x) => ctx.resolve(x),
        None => out_dir(ctx, sub).join(name),
    };
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    Ok(path)
}

fn run(env: &Env, ctx: &ToolCtx, p: &Value) -> Result<Reply, String> {
    let action = s(p, "action").ok_or("action is required")?;
    let m = manager::global();
    let sid = ctx.session_id.as_str();
    match action {
        "doctor" => return Ok(Reply::Json(doctor(env, s(p, "profile")))),
        "status" => {
            let key = m.key_for(env, s(p, "profile"), sid, None);
            let b = m.get(&key);
            let prof = s(p, "profile").unwrap_or(&env.cfg.default_profile);
            return Ok(Reply::Json(json!({"ok": true, "enabled": env.cfg.enabled() != Some(false), "running": b.is_some(), "profile": prof, "backend": env.cfg.backend(), "driver": b.as_ref().map(|b| b.kind.clone()), "transport": "cdp", "pid": b.as_ref().and_then(|b| b.pid), "cdpUrl": b.as_ref().and_then(|b| b.http.clone()).map(|u| crate::cdp::redact_url(&u)), "browsers": m.status(), "extension": crate::extension::status()})));
        }
        "profiles" => {
            let v: Vec<Value> = manager::profiles(&env.cfg).into_iter().map(|(n, pc)| json!({"name": n, "driver": if pc.driver.is_empty() { "managed".to_string() } else { pc.driver.clone() }, "running": m.get(&format!("profile:{n}")).is_some(), "default": n == env.cfg.default_profile, "color": if pc.color.is_empty() { "#FF4500".to_string() } else { pc.color.clone() }})).collect();
            return Ok(Reply::Json(json!({"ok": true, "profiles": v})));
        }
        "start" => {
            let b = browser_for(env, ctx, p, None)?;
            let _ = m.tab(env, sid, &b)?;
            let mut v = json!({"ok": true, "running": true, "profile": b.key, "driver": b.kind, "pid": b.pid, "cdpUrl": b.http.as_deref().map(crate::cdp::redact_url)});
            for (k, x) in b.info.lock().unwrap().iter() {
                v[k] = x.clone();
            }
            return Ok(Reply::Json(v));
        }
        "stop" => {
            let key = m.key_for(env, s(p, "profile"), sid, None);
            let key = if m.get(&key).is_none() { m.session(sid).key } else { key };
            return Ok(Reply::Json(json!({"ok": true, "stopped": m.stop(&key), "profile": key})));
        }
        "importprofile" => {
            let into = s(p, "into").unwrap_or("imported");
            crate::config::valid_profile_name(into)?;
            let rb = crate::launch::detect_real_browser()?;
            let dst = env.dir().join("profiles").join(into);
            let src = crate::launch::snapshot_real_profile(&rb, &dst, s(p, "systemProfile").unwrap_or(""))?;
            return Ok(Reply::Json(json!({"ok": true, "profile": into, "from": format!("{} / {src}", rb.name), "userDataDir": dst.display().to_string(), "note": format!("Copied cookies and logins into managed profile `{into}`; add [browser.profiles.{into}] to use it by name.")})));
        }
        _ => {}
    }
    let url = s(p, "targetUrl").or(s(p, "url")).filter(|_| matches!(action, "open" | "navigate"));
    let b = browser_for(env, ctx, p, url)?;
    crate::lease::agent_may_act(&crate::manager::lease_home(&env.home, &b.key))?;
    match action {
        "tabs" => {
            let tabs = b.tabs(None)?;
            Ok(json_wrapped("tabs", &json!({"running": true, "tabs": tabs, "tabCount": tabs.len()})))
        }
        "open" => {
            let url = policy::check_navigation(&env.cfg, url.ok_or("open requires url or targetUrl")?, b.key == "sidecar" || !env.cfg.is_cloud())?;
            let t = b.new_tab("about:blank", None)?;
            m.focus(sid, &b, &t);
            let (u, title) = tools::navigate(env, &b, &t, &url, Duration::from_secs(30))?;
            if let Some(l) = s(p, "label") {
                b.set_label(&t, l)?;
            }
            let tab = b.tabs(None)?.into_iter().find(|x| x["targetId"] == t.as_str()).unwrap_or(json!({"targetId": t}));
            Ok(Reply::Json(json!({"ok": true, "targetId": t, "tabId": tab["tabId"], "suggestedTargetId": tab["suggestedTargetId"], "url": u, "title": title})))
        }
        "focus" => {
            let t = b.resolve_tab(s(p, "targetId").ok_or("focus requires targetId")?, None)?;
            b.call("Target.activateTarget", json!({"targetId": t}))?;
            m.focus(sid, &b, &t);
            if let Some(l) = s(p, "label") {
                b.set_label(&t, l)?;
            }
            Ok(Reply::Json(json!({"ok": true, "targetId": t})))
        }
        "close" => {
            let t = match s(p, "targetId") {
                Some(r) => b.resolve_tab(r, None)?,
                None => m.session(sid).target.ok_or("close requires targetId")?,
            };
            b.close_tab(&t)?;
            Ok(Reply::Json(json!({"ok": true, "closed": t})))
        }
        "navigate" => {
            let t = tab(env, ctx, &b, p)?;
            let (u, title) = tools::navigate(env, &b, &t, url.ok_or("navigate requires url or targetUrl")?, Duration::from_secs(30))?;
            Ok(Reply::Text(format!("{}\n\n{}", serde_json::to_string(&json!({"ok": true, "targetId": t, "url": u, "title": title})).unwrap(), page_state(&b, &t)), true))
        }
        "snapshot" => {
            let t = tab(env, ctx, &b, p)?;
            tools::guard_page(env, &b, &t, "Refusing to read a page snapshot in this browser mode.")?;
            snapshot_action(env, ctx, &b, &t, p)
        }
        "screenshot" => {
            let t = tab(env, ctx, &b, p)?;
            let jpeg = s(p, "type") == Some("jpeg");
            let r = s(p, "ref");
            if p["labels"] == true && b.page(&t, |pg| pg.refs.is_empty()) {
                let _ = efficient(&b, &t);
            }
            let shot = actions::screenshot(&b, &t, p["fullPage"] == true, r, s(p, "element"), jpeg, p["labels"] == true)?;
            let ext = if shot.format == "jpeg" { "jpg" } else { "png" };
            let path = out_path(ctx, p, "screenshots", format!("screenshot-{}.{ext}", crate::util::now_ms()))?;
            std::fs::write(&path, &shot.data).map_err(|e| e.to_string())?;
            let url = b.page(&t, |pg| pg.url.clone());
            Ok(Reply::Text(format!("[Screenshot saved to \"{}\". Share it by path.]\n{}", path.display(), json!({"ok": true, "path": path.display().to_string(), "targetId": t, "url": url, "labels": p["labels"] == true, "labelsCount": shot.labels, "labelsSkipped": shot.skipped, "annotations": shot.annotations, "bytes": shot.data.len()})), true))
        }
        "pdf" => {
            let t = tab(env, ctx, &b, p)?;
            let data = actions::pdf(&b, &t)?;
            let path = out_path(ctx, p, "pdf", format!("page-{}.pdf", crate::util::now_ms()))?;
            std::fs::write(&path, data).map_err(|e| e.to_string())?;
            Ok(Reply::Text(format!("FILE:{}", path.display()), true))
        }
        "console" => {
            let t = tab(env, ctx, &b, p)?;
            let msgs = actions::console(&b, &t, s(p, "level"), p["clear"] == true);
            let url = b.page(&t, |pg| pg.url.clone());
            Ok(json_wrapped("console", &json!({"ok": true, "targetId": t, "url": url, "messages": msgs})))
        }
        "requests" | "errors" => {
            let t = tab(env, ctx, &b, p)?;
            let limit = p["limit"].as_u64().unwrap_or(50).max(1) as usize;
            let mut v = actions::debug_log(&b, &t, action, s(p, "filter").filter(|_| action == "requests"), limit, p["clear"] == true);
            v["ok"] = true.into();
            v["targetId"] = t.clone().into();
            v["url"] = b.page(&t, |pg| pg.url.clone()).into();
            Ok(json_wrapped(action, &v))
        }
        "text" => {
            let t = tab(env, ctx, &b, p)?;
            tools::guard_page(env, &b, &t, "Refusing to read page text in this browser mode.")?;
            let max = (p["maxChars"].as_u64().unwrap_or(snapshot::DEFAULT_MAX_CHARS as u64) as usize).clamp(1, snapshot::DEFAULT_MAX_CHARS);
            let (text, cut) = actions::page_text(&b, &t, s(p, "selector"), max)?;
            let (w, cut2) = policy::wrap_untrusted(&policy::redact(&text), true, "\n[truncated — retry with a narrower selector]");
            Ok(Reply::Text(if cut || cut2 { format!("Page text was truncated. Retry with a narrower selector.\n{w}") } else { w }, true))
        }
        "emulate" => {
            let t = tab(env, ctx, &b, p)?;
            let mut applied = vec![];
            for f in ["device", "colorScheme", "timezoneId", "locale"] {
                if let Some(v) = s(p, f) {
                    actions::emulate(&b, &t, f, v)?;
                    applied.push(f);
                }
            }
            if applied.is_empty() {
                return Err("emulate requires at least one of device, colorScheme, timezoneId, or locale.".into());
            }
            Ok(Reply::Json(json!({"ok": true, "targetId": t, "applied": applied})))
        }
        "download" | "waitfordownload" => {
            let t = tab(env, ctx, &b, p)?;
            let timeout = Duration::from_millis(p["timeoutMs"].as_u64().unwrap_or(120_000));
            let since = crate::util::now_ms();
            let dest = s(p, "path").map(|x| ctx.resolve(x));
            if action == "download" {
                if b.kind == "existing-session" || b.kind == "extension" {
                    return Err("download is not supported on attached user browsers (501); use a managed profile".into());
                }
                let r = s(p, "ref").ok_or("download requires ref")?;
                if dest.is_none() {
                    return Err("download requires path".into());
                }
                Act { b: &b, target: t.clone(), evaluate_enabled: false }.run(&json!({"kind": "click", "ref": r}), 0)?;
            }
            let d = actions::wait_download(&b, if action == "download" { since } else { since.saturating_sub(2000) }, dest.as_deref(), timeout)?;
            Ok(json_wrapped("download", &json!({"ok": true, "targetId": t, "download": d})))
        }
        "upload" => {
            let t = tab(env, ctx, &b, p)?;
            let paths: Vec<PathBuf> = p["paths"].as_array().into_iter().flatten().filter_map(|x| x.as_str()).map(|x| ctx.resolve(x)).collect();
            if paths.is_empty() {
                return Err("paths are required".into());
            }
            let v = actions::upload(&b, &t, &paths, s(p, "ref"), s(p, "inputRef"), s(p, "element"), Duration::from_millis(p["timeoutMs"].as_u64().unwrap_or(20_000)))?;
            Ok(Reply::Json(v))
        }
        "dialog" => {
            let t = tab(env, ctx, &b, p)?;
            let accept = p["accept"].as_bool().ok_or("accept is required")?;
            let pending = b.page(&t, |pg| !pg.dialogs.is_empty());
            if pending || s(p, "dialogId").is_some() {
                let d = b.respond_dialog(&t, accept, s(p, "promptText"), s(p, "dialogId"))?;
                return Ok(Reply::Json(json!({"ok": true, "targetId": t, "dialog": d})));
            }
            let ms = p["timeoutMs"].as_u64().unwrap_or(120_000);
            b.page(&t, |pg| pg.armed_dialog = Some((accept, s(p, "promptText").map(str::to_string), std::time::Instant::now() + Duration::from_millis(ms))));
            Ok(Reply::Json(json!({"ok": true, "targetId": t, "armed": true, "accept": accept, "timeoutMs": ms})))
        }
        "act" => {
            let req = if p["request"].is_object() { p["request"].clone() } else { p.clone() };
            if let Some(tid) = s(&req, "targetId") {
                if s(p, "targetId").is_some_and(|x| x != tid) {
                    return Err("action targetId must match request targetId".into());
                }
            }
            let t = tab(env, ctx, &b, p)?;
            let kind = s(&req, "kind").ok_or("act requires kind")?;
            if matches!(kind, "click" | "type" | "press" | "fill" | "select" | "drag") {
                tools::guard_page(env, &b, &t, &format!("Refusing to {kind} on this page in this browser mode."))?;
            }
            let eval_ok = env.cfg.evaluate_enabled && !(b.kind == "extension" && !env.cfg.extension_control.developer_mode);
            if kind == "evaluate" {
                if let Some(e) = policy::eval_policy(&env.cfg, s(&req, "fn").unwrap_or("")) {
                    return Err(e);
                }
            }
            let nav0 = b.page(&t, |pg| pg.nav_seq);
            let r = Act { b: &b, target: t.clone(), evaluate_enabled: eval_ok }.run(&req, 0);
            let mut r = match r {
                Ok(v) => v,
                Err(e) if e == crate::engine::BLOCKED_BY_DIALOG => {
                    let sv = b.supervisor_view(&t);
                    return Ok(Reply::Text(format!("{e}\n{}", json!({"ok": false, "error": e, "browserState": {"dialogs": {"pending": sv["pending_dialogs"], "recent": sv["recent_dialogs"]}}})), false));
                }
                Err(e) => return Err(e),
            };
            if kind == "close" {
                return Ok(Reply::Json(r));
            }
            std::thread::sleep(actions::NAV_GRACE);
            r["targetId"] = t.clone().into();
            let navigated = b.page(&t, |pg| pg.nav_seq) > nav0;
            let mut text = match json_wrapped("act", &r) {
                Reply::Text(t, _) => t,
                Reply::Json(_) => unreachable!(),
            };
            if let Some(a) = r.get("aborted") {
                text.push_str(&if a["reason"] == "navigation" { format!("\nBatch aborted after action {} because the page navigated; {} remaining action(s) skipped. Earlier refs are stale.", a["afterAction"], a["skipped"]) } else { format!("\nBatch aborted after action {} because the page or browser context closed; {} remaining action(s) skipped. Take a new snapshot before continuing.", a["afterAction"], a["skipped"]) });
            }
            if navigated && kind == "batch" {
                text.push_str(&format!("\n\n{}", page_state(&b, &t)));
            }
            Ok(Reply::Text(text, r["ok"] != false))
        }
        other => Err(format!("unknown browser action `{other}`; actions: {}", ACTIONS.join(", "))),
    }
}

fn snapshot_action(env: &Env, ctx: &ToolCtx, b: &Browser, t: &str, p: &Value) -> Result<Reply, String> {
    let efficient_mode = s(p, "mode") == Some("efficient");
    let format = s(p, "snapshotFormat").unwrap_or("ai");
    if format == "aria" && (efficient_mode || p["labels"] == true) {
        return Err("labels/mode=efficient require format=ai".into());
    }
    if format == "aria" {
        let sid = b.attach(t)?;
        let tree = b.session_call(t, &sid, "Accessibility.getFullAXTree", json!({}), b.timeout)?;
        let limit = p["limit"].as_u64().unwrap_or(500).clamp(1, 2000) as usize;
        let mut ax = tree["nodes"].as_array().cloned().unwrap_or_default();
        snapshot::redact_sensitive_ax_values(&mut ax, |bk| actions::describe_field(b, t, &sid, bk));
        let nodes: Vec<Value> = ax.iter().filter(|n| n["ignored"] != true).take(limit).enumerate().map(|(i, n)| json!({"ref": format!("ax{}", i + 1), "role": snapshot::ax_str(&n["role"]), "name": policy::redact(&snapshot::ax_str(&n["name"])), "value": snapshot::ax_str(&n["value"]), "backendDOMNodeId": n["backendDOMNodeId"]})).collect();
        let url = b.page(t, |pg| pg.url.clone());
        return Ok(Reply::Text(policy::wrap_untrusted(&serde_json::to_string_pretty(&json!({"ok": true, "format": "aria", "targetId": t, "url": url, "nodes": nodes})).unwrap(), true, "\n[truncated — retry with a smaller maxChars or limit]").0, true));
    }
    let max_chars = match p["maxChars"].as_u64() {
        Some(0) => None,
        Some(n) => Some(n as usize),
        None => Some(if efficient_mode { snapshot::EFFICIENT_MAX_CHARS } else { snapshot::DEFAULT_MAX_CHARS }),
    };
    let opts = Opts {
        interactive: p["interactive"].as_bool().unwrap_or(efficient_mode),
        compact: p["compact"].as_bool().unwrap_or(efficient_mode),
        max_depth: p["depth"].as_u64().map(|d| d as usize).or(efficient_mode.then_some(snapshot::EFFICIENT_DEPTH)),
        urls: p["urls"] == true,
    };
    let snap = actions::snapshot(b, t, &SnapshotReq { opts, max_chars, selector: s(p, "selector").map(str::to_string), frame: s(p, "frame").map(str::to_string), delta: true })?;
    let mut body = policy::redact(&snap.text);
    if let Some(q) = s(p, "query") {
        let lines = snapshot::query_lines(&body, q);
        body = if lines.is_empty() { "No matching lines in the returned snapshot. Refine the query or take a broader snapshot.".into() } else { format!("{} matching line(s) in the returned snapshot{}.\n{}", lines.len(), if snap.truncated { " (source truncated)" } else { "" }, lines.join("\n")) };
    }
    let mut head = json!({"ok": true, "format": "ai", "targetId": t, "url": snap.url, "title": policy::redact(&snap.title), "stats": snap.stats, "truncated": snap.truncated});
    if let Some(n) = snap.new_elements {
        head["newElements"] = n.into();
    }
    let sv = b.supervisor_view(t);
    if sv["pending_dialogs"].as_array().is_some_and(|a| !a.is_empty()) {
        head["blockedByDialog"] = true.into();
        head["dialogs"] = sv["pending_dialogs"].clone();
    }
    let mut text = format!("{}\n{}", head, policy::wrap_untrusted(&body, true, "\n[truncated — retry with a smaller maxChars or limit]").0);
    if p["labels"] == true {
        let shot = actions::screenshot(b, t, false, None, None, false, true)?;
        let path = out_path(ctx, &json!({}), "screenshots", format!("labels-{}.png", crate::util::now_ms()))?;
        std::fs::write(&path, &shot.data).map_err(|e| e.to_string())?;
        text.push_str(&format!("\n[Labeled screenshot saved to \"{}\" ({} labels).]", path.display(), shot.labels));
    }
    let _ = env;
    Ok(Reply::Text(text, true))
}

/// Browser readiness report (OpenClaw `buildBrowserDoctorReport` + doctor-browser notes).
pub fn doctor(env: &Env, profile: Option<&str>) -> Value {
    let cfg = &env.cfg;
    let mut checks = vec![];
    let mut add = |id: &str, label: &str, status: &str, summary: String, fix: Option<&str>| {
        let mut c = json!({"id": id, "label": label, "status": status, "summary": summary});
        if let Some(f) = fix {
            c["fixHint"] = f.into();
        }
        checks.push(c);
    };
    add("plugin-enabled", "Browser tools", if cfg.enabled() == Some(false) { "fail" } else { "pass" }, if cfg.enabled() == Some(false) { "disabled".into() } else { "enabled".into() }, Some("Set browser.enabled = true (or \"auto\")."));
    let backend = cfg.backend();
    let prof = profile.unwrap_or(&cfg.default_profile).to_string();
    add("profile", "Profile", "info", format!("{prof} via {backend}"), None);
    match backend.as_str() {
        "local" => {
            match crate::launch::find_executable(&cfg.executable) {
                Ok(p) => add("managed-executable", "Chromium executable", "pass", format!("{} at {}", crate::launch::kind_of(&p), p.display()), None),
                Err(e) => add("managed-executable", "Chromium executable", "fail", e, Some("Install Chrome/Chromium/Brave/Edge or set browser.executable.")),
            }
            add("headless-mode", "Headless mode", "info", if cfg.headless { "Managed browsers use headless mode by default".into() } else { "Managed browsers run headed".into() }, None);
            if !cfg!(any(windows, target_os = "macos")) && !cfg.headless && std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() && manager::desktop_env(&env.home).is_empty() {
                add("display", "Display", "warn", "No DISPLAY or WAYLAND_DISPLAY is set while headed mode is selected (browser.headless = false). Managed browser launch needs a desktop session, `seagent screen start`, or browser.headless = true.".into(), None);
            }
            #[cfg(unix)]
            if (unsafe { libc::geteuid() }) == 0 && cfg.no_sandbox == toml::Value::Boolean(false) {
                add("linux-sandbox", "Linux sandbox", "warn", "Running as root while browser.no_sandbox is false".into(), Some("Set browser.no_sandbox = true for container/root Chromium runtimes."));
            }
            let key = format!("profile:{prof}");
            match manager::global().get(&key) {
                Some(b) => {
                    add("cdp-http", "CDP HTTP", "pass", "CDP HTTP endpoint is reachable".into(), None);
                    let ok = b.call("Browser.getVersion", json!({})).is_ok();
                    add("cdp-websocket", "CDP WebSocket", if ok { "pass" } else { "fail" }, if ok { "CDP WebSocket is reachable".into() } else { "CDP WebSocket is not reachable".into() }, Some("Check Chrome launch logs, stale locks, proxy env, and port conflicts."));
                }
                None => add("cdp-http", "CDP HTTP", "info", "Browser is launchable but not running".into(), None),
            }
        }
        "cdp" => {
            let u = cfg.cdp_override();
            match crate::cdp::resolve_ws(&u, None, Duration::from_secs(3)) {
                Ok(_) => add("cdp-http", "CDP endpoint", "pass", format!("CDP HTTP endpoint is reachable ({})", crate::cdp::redact_url(&u)), None),
                Err(e) => add("cdp-http", "CDP endpoint", "fail", format!("CDP HTTP endpoint is not reachable: {e}"), Some("Start Chrome with --remote-debugging-port=9222 or run /browser connect.")),
            }
        }
        "camofox" => {
            let c = crate::camofox::Client::new(cfg);
            let ok = c.json("GET", "/health", None, Some(Duration::from_secs(3))).is_ok();
            add("camofox", "Camofox server", if ok { "pass" } else { "fail" }, format!("{} {}", c.base, if ok { "is reachable" } else { "is not reachable" }), Some("docker run -p 9377:9377 -e CAMOFOX_PORT=9377 jo-inc/camofox-browser"));
        }
        "lightpanda" => match crate::launch::lightpanda_binary() {
            Some(p) => add("lightpanda", "Lightpanda", "pass", format!("lightpanda at {}", p.display()), None),
            None => add("lightpanda", "Lightpanda", "fail", "no lightpanda binary".into(), Some("Install from https://lightpanda.io/docs/run-locally/installation/one-liner")),
        },
        "sandbox" => {
            let cli = crate::sandbox::docker();
            let ok = crate::sandbox::available();
            add(&cli, "Sandbox browser container CLI", if ok { "pass" } else { "fail" }, if ok { format!("{cli} is installed") } else { format!("{cli} is not installed") }, Some("Install docker or podman (or set SEAGENT_DOCKER) and build packaging/sandbox-browser."));
        }
        "extension" => {
            let st = crate::extension::status();
            add("extension-relay", "Extension relay", if st["extension_connected"] == true { "pass" } else { "warn" }, st.to_string(), Some("Load ui/browser-extension in Chrome and paste the token from `seagent browser extension`."));
        }
        cloud => {
            let ok = crate::cloud::available(cloud, &*env.secrets);
            add("cloud-credentials", "Cloud credentials", if ok { "pass" } else { "fail" }, format!("{cloud}: {}", if ok { "credentials found" } else { "credentials missing" }), Some("Set the provider API key in the environment or `seagent secret set`."));
        }
    }
    if cfg.use_real_profile {
        match crate::launch::detect_real_browser() {
            Ok(rb) => add("real-profile", "Real profile", "pass", format!("{} profile at {}", rb.name, rb.data_dir.display()), None),
            Err(e) => add("real-profile", "Real profile", "warn", e, None),
        }
    }
    let ok = !checks.iter().any(|c| c["status"] == "fail");
    json!({"ok": ok, "profile": prof, "transport": if backend == "extension" { "extension" } else { "cdp" }, "checks": checks})
}
