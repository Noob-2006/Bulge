//! Backend contract (Hermes `tools/computer_use/backend.py`, MIT): every driver — native
//! xdotool/ydotool + AT-SPI or cua-driver over MCP — returns these shapes.

use serde_json::{json, Map, Value};

/// One interactable element on the current screen.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Element {
    /// 1-based SOM index.
    pub index: u32,
    pub role: String,
    pub label: String,
    /// x, y, w, h (logical px); all zero = unknown.
    pub bounds: [i64; 4],
    pub app: String,
    /// Backend handle: AT-SPI `<bus>|<path>` (native) or cua-driver `element_token`.
    pub handle: String,
}

impl Element {
    pub fn bounds_unknown(&self) -> bool {
        self.bounds[2] <= 0 || self.bounds[3] <= 0
    }
    pub fn center(&self) -> Option<(i64, i64)> {
        (!self.bounds_unknown()).then(|| (self.bounds[0] + self.bounds[2] / 2, self.bounds[1] + self.bounds[3] / 2))
    }
}

/// A screen capture. mode "vision" → image only; "ax" → elements only; "som" → both.
#[derive(Debug, Clone, Default)]
pub struct Capture {
    pub mode: String,
    pub width: u32,
    pub height: u32,
    pub image: Option<Vec<u8>>,
    pub mime: String,
    pub elements: Vec<Element>,
    pub app: String,
    pub window_title: String,
    /// Guidance for lanes that return no elements on purpose.
    pub note: String,
    /// The AX-walk bound the backend asked for (0 = n/a).
    pub ax_max_elements: usize,
}

/// Result of an input action. `ok` is transport success only; `effect` / `escalation`
/// are the semantic verdict the model follows (verify → escalate ladder).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ActionResult {
    pub ok: bool,
    pub action: String,
    pub message: String,
    pub meta: Map<String, Value>,
    pub verified: Option<bool>,
    /// confirmed | unverifiable | suspected_noop
    pub effect: Option<String>,
    pub escalation: Option<Value>,
    pub path: Option<String>,
    pub degraded: Option<bool>,
    pub delivery_mode: Option<String>,
    pub code: Option<String>,
}

impl ActionResult {
    pub fn ok(action: &str, message: impl Into<String>) -> Self {
        ActionResult { ok: true, action: action.into(), message: message.into(), ..Default::default() }
    }
    pub fn refuse(action: &str, message: impl Into<String>) -> Self {
        ActionResult { ok: false, action: action.into(), message: message.into(), ..Default::default() }
    }
    pub fn code(mut self, c: &str) -> Self {
        self.code = Some(c.into());
        self
    }

    /// Next ladder step from the evidence, in precedence order (Hermes `_classify_action_result`).
    pub fn verdict(&self) -> Value {
        if self.effect.as_deref() == Some("confirmed") || self.verified == Some(true) {
            return json!({"decision": "done"});
        }
        if self.effect.as_deref() == Some("unverifiable") {
            return json!({"decision": "verify_fresh_state", "hint": "Input was delivered but not confirmed. Re-capture and check the result BEFORE any retry — do not repeat the input on an escalation recommendation alone."});
        }
        if self.effect.as_deref() == Some("suspected_noop") || !self.ok || self.code.is_some() {
            let delivered = self.meta.get("delivered_chars").and_then(Value::as_i64);
            let requested = self.meta.get("requested_chars").and_then(Value::as_i64);
            if matches!(self.action.as_str(), "type" | "type_text") && self.code.as_deref() == Some("type_text_incomplete") && requested.is_some_and(|r| r > 0) && delivered.is_some_and(|d| d <= 0) {
                return json!({"decision": "escalate", "recommended": "set_value", "hint": "0 characters landed: this input drops synthetic keystrokes, so no delivery rung will fix it. Climb to the set_value action on the field's element index instead — it is an action, not a delivery mode, and sets the value through the accessibility API, bypassing event filtering. Re-capture first if the index is stale."});
            }
            let mut v = json!({"decision": "escalate"});
            if let Some(r) = self.escalation.as_ref().and_then(|e| e.get("recommended")) {
                v["recommended"] = r.clone();
            }
            v["hint"] = json!("The input likely did not land. Climb one rung following `recommended`: 'px' → re-issue by coordinate; 'foreground' (or a failed pixel click) → re-issue with delivery_mode='foreground' (separate approval). Do not predict the rung from the app being Electron/Chromium — react to this signal.");
            return v;
        }
        json!({"decision": "verify_fresh_state", "hint": "Transport succeeded but the effect is unproven. Re-capture and confirm before continuing."})
    }

    /// The JSON payload the model sees (Hermes `_action_payload`; key order is contract).
    pub fn payload(&self) -> Value {
        let mut m = Map::new();
        m.insert("ok".into(), json!(self.ok));
        m.insert("action".into(), json!(self.action));
        if !self.message.is_empty() {
            m.insert("message".into(), json!(self.message));
        }
        if let Some(v) = self.verified {
            m.insert("verified".into(), json!(v));
        }
        for (k, v) in [("effect", &self.effect), ("path", &self.path), ("delivery_mode", &self.delivery_mode), ("code", &self.code)] {
            if let Some(v) = v {
                m.insert(k.into(), json!(v));
            }
        }
        if let Some(e) = &self.escalation {
            m.insert("escalation".into(), e.clone());
        }
        if let Some(d) = self.degraded {
            m.insert("degraded".into(), json!(d));
        }
        if !self.meta.is_empty() {
            m.insert("meta".into(), Value::Object(self.meta.clone()));
        }
        m.insert("verdict".into(), self.verdict());
        Value::Object(m)
    }
}

/// Where pointer input lands.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Point {
    Element(u32),
    Xy(i64, i64),
    None,
}

/// delivery_mode + bring_to_front (input actions only).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Delivery {
    pub mode: Option<String>,
    pub bring_to_front: bool,
}

/// One computer-use driver. Actions a driver cannot perform return
/// `ActionResult { ok: false, code: "unsupported_action" }` rather than changing the schema.
pub trait Backend: Send {
    fn name(&self) -> &'static str;
    fn capture(&mut self, mode: &str, app: Option<&str>, pid: Option<i64>, window_id: Option<i64>) -> Result<Capture, String>;
    fn click(&mut self, at: Point, button: &str, count: u32, modifiers: &[String], d: &Delivery) -> ActionResult;
    fn drag(&mut self, from: Point, to: Point, button: &str, modifiers: &[String], d: &Delivery) -> ActionResult;
    fn scroll(&mut self, direction: &str, amount: u32, at: Point, modifiers: &[String], d: &Delivery) -> ActionResult;
    fn type_text(&mut self, text: &str, d: &Delivery) -> ActionResult;
    fn key(&mut self, keys: &str, d: &Delivery) -> ActionResult;
    fn set_value(&mut self, value: &str, element: Option<u32>) -> ActionResult;
    fn list_apps(&mut self) -> Result<Vec<Value>, String>;
    fn list_windows(&mut self) -> Result<Vec<Value>, String> {
        Ok(vec![])
    }
    fn focus_app(&mut self, app: &str, raise: bool) -> ActionResult;
    /// The sticky target's app (for the `app=` mismatch guard).
    fn last_app(&self) -> Option<String> {
        None
    }
    /// Exact (pid, window_id) of the sticky target, for `capture_after` re-captures.
    fn last_target(&self) -> Option<(i64, i64)> {
        None
    }
    fn wait(&mut self, seconds: f64) -> ActionResult {
        let s = seconds.clamp(0.0, 30.0);
        std::thread::sleep(std::time::Duration::from_secs_f64(s));
        ActionResult::ok("wait", format!("waited {seconds:.2}s"))
    }
    fn stop(&mut self) {}
}

/// PNG / JPEG pixel size from the header bytes.
pub fn image_size(b: &[u8]) -> Option<(u32, u32)> {
    if b.len() >= 24 && b.starts_with(b"\x89PNG\r\n\x1a\n") {
        let be = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        return Some((be(16), be(20)));
    }
    if b.starts_with(&[0xFF, 0xD8]) {
        let mut i = 2;
        while i + 9 < b.len() {
            if b[i] != 0xFF {
                i += 1;
                continue;
            }
            let m = b[i + 1];
            let len = u16::from_be_bytes([b[i + 2], b[i + 3]]) as usize;
            if (0xC0..=0xCF).contains(&m) && !matches!(m, 0xC4 | 0xC8 | 0xCC) {
                let h = u16::from_be_bytes([b[i + 5], b[i + 6]]) as u32;
                let w = u16::from_be_bytes([b[i + 7], b[i + 8]]) as u32;
                return Some((w, h));
            }
            i += 2 + len;
        }
    }
    None
}

pub fn mime_of(b: &[u8]) -> &'static str {
    if b.starts_with(&[0xFF, 0xD8]) {
        "image/jpeg"
    } else {
        "image/png"
    }
}

#[cfg(test)]
pub(crate) fn tiny_png(w: u32, h: u32) -> Vec<u8> {
    let mut v = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
    v.extend(w.to_be_bytes());
    v.extend(h.to_be_bytes());
    v.extend([8, 2, 0, 0, 0, 0, 0, 0, 0]);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_ladder_matches_hermes() {
        let mut r = ActionResult::ok("click", "");
        assert_eq!(r.verdict()["decision"], "verify_fresh_state");
        r.effect = Some("confirmed".into());
        assert_eq!(r.verdict()["decision"], "done");
        r.effect = Some("suspected_noop".into());
        r.escalation = Some(json!({"recommended": "px"}));
        assert_eq!(r.verdict(), json!({"decision": "escalate", "recommended": "px", "hint": r.verdict()["hint"]}));
        let mut t = ActionResult::refuse("type_text", "").code("type_text_incomplete");
        t.meta.insert("delivered_chars".into(), json!(0));
        t.meta.insert("requested_chars".into(), json!(5));
        assert_eq!(t.verdict()["recommended"], "set_value");
        let p = t.payload();
        assert_eq!(p["ok"], false);
        assert_eq!(p["code"], "type_text_incomplete");
        assert_eq!(p.as_object().unwrap().keys().next_back().unwrap(), "verdict");
    }

    #[test]
    fn image_headers() {
        assert_eq!(image_size(&tiny_png(640, 480)), Some((640, 480)));
        let jpeg = [0xFF, 0xD8, 0xFF, 0xC0, 0, 17, 8, 0, 200, 1, 44, 3, 0, 0, 0];
        assert_eq!(image_size(&jpeg), Some((300, 200)));
        assert_eq!(mime_of(&jpeg), "image/jpeg");
        let e = Element { bounds: [10, 20, 100, 40], ..Default::default() };
        assert_eq!(e.center(), Some((60, 40)));
        assert!(Element::default().bounds_unknown());
    }
}
