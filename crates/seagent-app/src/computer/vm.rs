//! computer_use on a desktop VM (`target = "vm:<name>"`): a [`Backend`] over QMP
//! (`seagent_vm::desktop`). Pure pixels: captures are full-screen PNG `screendump`s and every
//! input is an absolute pointer / keyboard event, so there is no accessibility tree and no
//! element index — the model acts by coordinate on the screenshot it was given.

use super::backend::{ActionResult, Backend, Capture, Delivery, Point};
use seagent_vm::desktop::{DesktopVms, Input};
use serde_json::{json, Value};
use std::sync::Arc;

pub struct VmBackend {
    pub vms: Arc<DesktopVms>,
    pub name: String,
}

const NOTE: &str = "desktop VM: full-screen screenshot only (no accessibility tree, no element indices) — act with `coordinate` in this screenshot's pixels";

impl VmBackend {
    fn act(&self, action: &str, ev: Input) -> ActionResult {
        match self.vms.input(&self.name, &ev) {
            Ok(v) => {
                let mut r = ActionResult::ok(action, format!("{} delivered to vm:{}", ev.kind(), self.name));
                r.effect = Some("unverifiable".into());
                r.path = Some("qmp".into());
                if let Some(n) = v["typed"].as_u64() {
                    r.meta.insert("delivered_chars".into(), json!(n));
                }
                r
            }
            Err(e) => ActionResult::refuse(action, e).code("vm_input_failed"),
        }
    }

    /// Pixel position of `at` (None = an element index, which a VM does not have).
    fn xy(at: Point) -> Option<(Option<i64>, Option<i64>)> {
        match at {
            Point::Xy(x, y) => Some((Some(x), Some(y))),
            Point::None => Some((None, None)),
            Point::Element(_) => None,
        }
    }

    fn no_elements(action: &str) -> ActionResult {
        ActionResult::refuse(action, "a desktop VM has no element indices: pass `coordinate` [x, y] from the screenshot").code("unsupported_action")
    }
}

fn no_mods(action: &str, m: &[String]) -> Option<ActionResult> {
    (!m.is_empty()).then(|| ActionResult::refuse(action, "modifiers are not supported on a desktop VM click/drag/scroll; use action='key' for shortcuts").code("unsupported_action"))
}

impl Backend for VmBackend {
    fn name(&self) -> &'static str {
        "vm"
    }
    fn capture(&mut self, mode: &str, _app: Option<&str>, _pid: Option<i64>, _window_id: Option<i64>) -> Result<Capture, String> {
        let png = self.vms.screenshot(&self.name)?;
        let (w, h) = super::backend::image_size(&png).unwrap_or((self.vms.cfg.width, self.vms.cfg.height));
        Ok(Capture { mode: if mode == "ax" { "vision".into() } else { mode.into() }, width: w, height: h, image: Some(png), mime: "image/png".into(), elements: vec![], app: format!("vm:{}", self.name), window_title: String::new(), note: NOTE.into(), ax_max_elements: 0 })
    }
    fn click(&mut self, at: Point, button: &str, count: u32, modifiers: &[String], _d: &Delivery) -> ActionResult {
        if let Some(r) = no_mods("click", modifiers) {
            return r;
        }
        match Self::xy(at) {
            Some((x, y)) => self.act("click", Input::Click { x, y, button: button.into(), count: count.clamp(1, 3) }),
            None => Self::no_elements("click"),
        }
    }
    fn drag(&mut self, from: Point, to: Point, button: &str, modifiers: &[String], _d: &Delivery) -> ActionResult {
        if let Some(r) = no_mods("drag", modifiers) {
            return r;
        }
        match (from, to) {
            (Point::Xy(a, b), Point::Xy(c, d)) => self.act("drag", Input::Drag { from: (a, b), to: (c, d), button: button.into() }),
            _ => ActionResult::refuse("drag", "a desktop VM drag needs from_coordinate and to_coordinate").code("unsupported_action"),
        }
    }
    fn scroll(&mut self, direction: &str, amount: u32, at: Point, modifiers: &[String], _d: &Delivery) -> ActionResult {
        if let Some(r) = no_mods("scroll", modifiers) {
            return r;
        }
        let n = amount.clamp(1, 50) as i64;
        let (dx, dy) = match direction {
            "up" => (0, -n),
            "left" => (-n, 0),
            "right" => (n, 0),
            _ => (0, n),
        };
        match Self::xy(at) {
            Some((x, y)) => self.act("scroll", Input::Scroll { x, y, dx, dy }),
            None => Self::no_elements("scroll"),
        }
    }
    fn type_text(&mut self, text: &str, _d: &Delivery) -> ActionResult {
        let mut r = self.act("type", Input::Type { text: text.into() });
        r.meta.insert("requested_chars".into(), json!(text.chars().count()));
        r
    }
    fn key(&mut self, keys: &str, _d: &Delivery) -> ActionResult {
        self.act("key", Input::Key { keys: keys.into() })
    }
    fn set_value(&mut self, _value: &str, _element: Option<u32>) -> ActionResult {
        ActionResult::refuse("set_value", "set_value needs an accessibility tree, which a desktop VM does not expose: click the control and type instead").code("unsupported_action")
    }
    fn list_apps(&mut self) -> Result<Vec<Value>, String> {
        Ok(vec![])
    }
    fn focus_app(&mut self, _app: &str, _raise: bool) -> ActionResult {
        ActionResult::refuse("focus_app", "focus_app is not available on a desktop VM: click the window (or use key alt+tab)").code("unsupported_action")
    }
}

#[cfg(test)]
#[cfg_attr(not(unix), allow(dead_code, unused_imports))]
mod tests {
    use crate::computer::fake_driver::{ctx, run};
    use crate::computer::hermes::ComputerUseTool;
    use crate::computer::ComputerUseConfig;
    use seagent_core::{Effect, Tool};
    use seagent_vm::desktop::fake;
    use serde_json::json;
    use std::sync::Arc;

    #[cfg(unix)]
    /// computer_use with `target = "vm:desk"`: screenshot to the model, coordinate input over
    /// QMP, its own approval scope, and refusal while a human holds the VM's lease.
    #[test]
    fn computer_use_drives_a_desktop_vm_and_respects_its_lease() {
        let d = seagent_core::tmp::TempDir::new("seagent-cu-vm");
        let vms = Arc::new(fake::fake_vms(&d));
        let cfg = ComputerUseConfig { vision: false, ..Default::default() };
        let mut t = ComputerUseTool::new(Arc::new(cfg));
        t.vms = Some(vms.clone());
        let c = ctx(&d.join("home"), "s-vm");
        // Not running yet: a clear error, no panic.
        let (o, v) = run(&t, &c, json!({"action": "capture", "target": "vm:desk"}));
        assert!(o.is_error && v["error"].as_str().unwrap().contains("not running"), "{}", o.content);
        let qmp = fake::start_fake(&vms, &d, "desk", 1280, 800);

        let (o, _) = run(&t, &c, json!({"action": "capture", "mode": "som", "target": "vm:desk"}));
        assert!(!o.is_error, "{}", o.content);
        assert!(o.content.contains("capture mode=som 1280x800 app=vm:desk") && o.content.contains("no element indices"), "{}", o.content);
        assert!(o.content.contains("image/png"), "the screenshot goes to the model: {}", o.content);

        let click = json!({"action": "click", "coordinate": [640, 400], "target": "vm:desk"});
        let eff = t.effects(&c, &click);
        assert!(matches!(&eff[..], [Effect::Remote { dest, .. }] if dest == "desktop:vm:desk:click"), "{eff:?}");
        assert!(t.effects(&c, &json!({"action": "capture", "target": "vm:desk"})).is_empty(), "capture is free");
        let (o, v) = run(&t, &c, click.clone());
        assert!(!o.is_error && v["ok"] == true && v["path"] == "qmp", "{}", o.content);
        let (_, v) = run(&t, &c, json!({"action": "type", "text": "seagent", "target": "vm:desk"}));
        assert_eq!(v["meta"]["delivered_chars"], 7, "{v}");
        let (_, v) = run(&t, &c, json!({"action": "key", "keys": "ctrl+l", "target": "vm:desk"}));
        assert_eq!(v["ok"], true);
        let (_, v) = run(&t, &c, json!({"action": "click", "element": 3, "target": "vm:desk"}));
        assert_eq!(v["code"], "unsupported_action", "no element indices on a VM");
        assert!(qmp.events().iter().any(|e| e["type"] == "btn" && e["data"]["button"] == "left"));

        // A human takes the VM: every call, capture included, is refused; the host is untouched.
        seagent_browser::lease::acquire(&vms.lease_home("desk"), "viewer-cu-1", "").unwrap();
        let (o, v) = run(&t, &c, json!({"action": "capture", "target": "vm:desk"}));
        assert!(o.is_error && v["code"] == "human_has_control", "{}", o.content);
        let (_, v) = run(&t, &c, click);
        assert_eq!(v["code"], "human_has_control");
        assert_eq!(seagent_browser::lease::get(&c.home).holder, "agent");
        seagent_browser::lease::release(&vms.lease_home("desk"), Some("viewer-cu-1"), false).unwrap();

        // Default target from config; unknown targets are named.
        let mut t2 = ComputerUseTool::new(Arc::new(ComputerUseConfig { vision: false, target: "vm:desk".into(), ..Default::default() }));
        t2.vms = Some(vms.clone());
        let (o, _) = run(&t2, &c, json!({"action": "capture"}));
        assert!(o.content.contains("app=vm:desk"), "{}", o.content);
        let (_, v) = run(&t2, &c, json!({"action": "capture", "target": "mars"}));
        assert!(v["error"].as_str().unwrap().contains("vm:<name>"), "{v}");
        vms.stop("desk").unwrap();
        drop(qmp);
    }
}
