//! computer.act v2 accessibility on Windows: the substitute for AT-SPI (`a11y.rs`).
//!
//! | action | Windows API |
//! |---|---|
//! | `list_windows` | `EnumWindows` (the Bot Desktop's `EnumDesktopWindows` when it is an isolated desktop): visible, un-cloaked, un-owned top-level windows with a title -- the Alt+Tab set |
//! | `list_apps` | those windows grouped by process image (`QueryFullProcessImageNameW`; a UWP frame is named after the app it hosts) |
//! | `get_accessibility_tree` / `get_window_state` | UI Automation control view (`IUIAutomation::ElementFromHandle` + `ControlViewWalker`) |
//! | element click | UIA `Invoke`, else `Toggle`, `SelectionItem.Select`, `ExpandCollapse.Expand`, `LegacyIAccessible.DoDefaultAction` |
//! | `set_value` | UIA `ValuePattern.SetValue` |
//! | `bring_to_front` | `ShowWindow(SW_RESTORE)` + `SetForegroundWindow` (input attached to the foreground thread) |
//!
//! The JSON is the AT-SPI module's: windows `{app, windowRef, title, role, bounds}`, elements
//! `{elementRef, role, label, value, depth, bounds}` with roles in AT-SPI's vocabulary (so the
//! SOM filter treats panes, groups and static text as layout everywhere) -- never the
//! localized UIA control-type names. Refs are stateless: `hwnd:<handle>` for a window,
//! `uia:<handle>:<i.j.k>` for the element reached by those child indexes of the control view.
//! Coordinates are physical screen pixels (the process is DPI-aware, like `SendInput` and the
//! GDI screenshot).

#![cfg_attr(not(windows), allow(dead_code))]

/// `hwnd:<n>` (also accepts the window of an element ref).
pub fn window_of(r: &str) -> Option<isize> {
    if let Some(n) = r.strip_prefix("hwnd:") {
        return n.parse().ok().filter(|h| *h != 0);
    }
    parse_element_ref(r).map(|(h, _)| h)
}

pub fn window_ref(hwnd: isize) -> String {
    format!("hwnd:{hwnd}")
}

/// `uia:<hwnd>:<i.j.k>` (an empty path is the window's own element).
pub fn element_ref(hwnd: isize, path: &[usize]) -> String {
    format!("uia:{hwnd}:{}", path.iter().map(usize::to_string).collect::<Vec<_>>().join("."))
}

pub fn parse_element_ref(r: &str) -> Option<(isize, Vec<usize>)> {
    let rest = r.strip_prefix("uia:")?;
    let (h, p) = rest.split_once(':')?;
    let h: isize = h.parse().ok().filter(|h| *h != 0)?;
    let path = if p.is_empty() { vec![] } else { p.split('.').map(|i| i.parse().ok()).collect::<Option<Vec<usize>>>()? };
    (path.len() <= 64).then_some((h, path))
}

/// UIA control type id -> the role name the AT-SPI path reports for the same kind of element
/// (`native::LAYOUT_ROLES` drops the layout ones from the SOM list).
pub fn role_name(control_type: i32) -> &'static str {
    match control_type {
        50000 => "push button",
        50001 => "calendar",
        50002 => "check box",
        50003 => "combo box",
        50004 => "entry",
        50005 => "link",
        50006 => "image",
        50007 => "list item",
        50008 => "list",
        50009 => "menu",
        50010 => "menu bar",
        50011 => "menu item",
        50012 => "progress bar",
        50013 => "radio button",
        50014 => "scroll bar",
        50015 => "slider",
        50016 => "spin button",
        50017 => "status bar",
        50018 => "page tab list",
        50019 => "page tab",
        50020 => "label",
        50021 => "tool bar",
        50022 => "tool tip",
        50023 => "tree",
        50024 => "tree item",
        50025 => "custom",
        50026 => "grouping",
        50027 => "thumb",
        50028 => "table",
        50029 => "table row",
        50030 => "document",
        50031 => "split button",
        50032 => "window",
        50033 => "panel",
        50034 => "header",
        50035 => "column header",
        50036 => "table",
        50037 => "title bar",
        50038 => "separator",
        50039 => "panel",
        50040 => "tool bar",
        _ => "unknown",
    }
}

/// Control types whose value (`ValuePattern`) is read into the element's `value`.
pub fn has_value(control_type: i32) -> bool {
    matches!(control_type, 50003 | 50004 | 50030 | 50015 | 50016)
}

/// The app name of a process image path: its file stem (`C:...msedge.exe` -> `msedge`).
pub fn app_name(image: &str) -> String {
    let file = image.rsplit(['\\', '/']).next().unwrap_or(image);
    file.strip_suffix(".exe").or_else(|| file.strip_suffix(".EXE")).unwrap_or(file).to_string()
}

/// Window classes whose UIA tree is built lazily, on the first client query (Chromium:
/// Chrome, Edge, Electron apps, CEF).
pub fn lazy_tree(class: &str) -> bool {
    class.starts_with("Chrome_WidgetWin") || class.starts_with("CefBrowserWindow")
}

/// Fewer elements than this from a lazy window means its tree was not built yet.
pub const LAZY_MIN: usize = 8;

/// `query` matches an element when it is in its label, role or value (case-insensitive).
pub fn matches(query: &str, label: &str, role: &str, value: &str) -> bool {
    query.is_empty() || format!("{label} {role} {value}").to_lowercase().contains(&query.to_lowercase())
}

/// Windows grouped into apps, in the windows' (z-)order: `{app, windowRef, windows, pid}`.
pub fn group_apps(windows: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut apps: Vec<serde_json::Value> = vec![];
    for w in windows {
        let name = w["app"].as_str().unwrap_or("");
        match apps.iter_mut().find(|a| a["app"] == name) {
            Some(a) => a["windows"] = serde_json::json!(a["windows"].as_u64().unwrap_or(0) + 1),
            None => apps.push(serde_json::json!({"app": name, "windowRef": w["windowRef"], "windows": 1, "pid": w["pid"]})),
        }
    }
    apps
}

#[cfg(windows)]
pub use sys::act;

#[cfg(windows)]
mod sys {
    use super::*;
    use serde_json::{json, Value};
    use windows::core::BSTR;
    use windows::Win32::Foundation::HWND as WHWND;
    use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED};
    use windows::Win32::UI::Accessibility::*;
    use windows_sys::Win32::Foundation::{CloseHandle, BOOL, HWND, LPARAM, RECT, TRUE};
    use windows_sys::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_CLOAKED};
    use windows_sys::Win32::System::StationsAndDesktops::{CloseDesktop, EnumDesktopWindows, OpenDesktopW};
    use windows_sys::Win32::System::Threading::{AttachThreadInput, GetCurrentThreadId, OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION};
    use windows_sys::Win32::UI::WindowsAndMessaging::*;

    fn dpi_aware() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        // SAFETY: process-wide flag; the same call `host_os` makes before SendInput.
        ONCE.call_once(|| unsafe {
            SetProcessDPIAware();
        });
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    fn text(h: HWND) -> String {
        let mut buf = [0u16; 512];
        // SAFETY: buffer and its length.
        let n = unsafe { GetWindowTextW(h, buf.as_mut_ptr(), buf.len() as i32) };
        String::from_utf16_lossy(&buf[..n.max(0) as usize])
    }

    fn class(h: HWND) -> String {
        let mut buf = [0u16; 256];
        // SAFETY: buffer and its length.
        let n = unsafe { GetClassNameW(h, buf.as_mut_ptr(), buf.len() as i32) };
        String::from_utf16_lossy(&buf[..n.max(0) as usize])
    }

    fn pid_of(h: HWND) -> u32 {
        let mut pid = 0u32;
        // SAFETY: out pointer to a local.
        unsafe { GetWindowThreadProcessId(h, &mut pid) };
        pid
    }

    fn image(pid: u32) -> Option<String> {
        // SAFETY: limited query handle, closed below; buffer and its length.
        unsafe {
            let p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if p == 0 {
                return None;
            }
            let mut buf = [0u16; 1024];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(p, 0, buf.as_mut_ptr(), &mut len);
            CloseHandle(p);
            (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
        }
    }

    fn children(h: HWND) -> Vec<HWND> {
        unsafe extern "system" fn cb(h: HWND, l: LPARAM) -> BOOL {
            (*(l as *mut Vec<HWND>)).push(h);
            TRUE
        }
        let mut v: Vec<HWND> = vec![];
        // SAFETY: the callback only pushes into `v`, which outlives the call.
        unsafe { EnumChildWindows(h, Some(cb), &mut v as *mut Vec<HWND> as LPARAM) };
        v
    }

    /// The app a window belongs to (a UWP `ApplicationFrameWindow` is named after the
    /// process of the CoreWindow it hosts, not ApplicationFrameHost).
    fn app_of(h: HWND) -> (String, u32) {
        let pid = pid_of(h);
        let name = image(pid).map(|i| app_name(&i)).unwrap_or_else(|| format!("pid {pid}"));
        if name.eq_ignore_ascii_case("ApplicationFrameHost") {
            if let Some((n, p)) = children(h).into_iter().map(pid_of).find(|p| *p != pid).and_then(|p| image(p).map(|i| (app_name(&i), p))) {
                return (n, p);
            }
        }
        (name, pid)
    }

    fn top_level() -> Vec<HWND> {
        unsafe extern "system" fn cb(h: HWND, l: LPARAM) -> BOOL {
            (*(l as *mut Vec<HWND>)).push(h);
            TRUE
        }
        let mut v: Vec<HWND> = vec![];
        let desk = crate::node::env_var("SEAGENT_BD_DESKTOP").unwrap_or_default();
        let name = desk.rsplit('\\').next().unwrap_or("").to_string();
        // SAFETY: the callback only pushes into `v`; the desktop handle is closed after.
        unsafe {
            if !name.is_empty() && !name.eq_ignore_ascii_case("Default") {
                const DESKTOP_READOBJECTS: u32 = 0x0001;
                const DESKTOP_ENUMERATE: u32 = 0x0040;
                let w = wide(&name);
                let d = OpenDesktopW(w.as_ptr(), 0, 0, DESKTOP_READOBJECTS | DESKTOP_ENUMERATE);
                if d != 0 {
                    EnumDesktopWindows(d, Some(cb), &mut v as *mut Vec<HWND> as LPARAM);
                    CloseDesktop(d);
                    return v;
                }
            }
            EnumWindows(Some(cb), &mut v as *mut Vec<HWND> as LPARAM);
        }
        v
    }

    /// The Alt+Tab rule: visible, not cloaked (suspended UWP / other virtual desktop), not a
    /// tool window, un-owned, with a title.
    fn listed(h: HWND) -> bool {
        // SAFETY: plain window queries on a handle EnumWindows returned.
        unsafe {
            if IsWindowVisible(h) == 0 || GetWindow(h, GW_OWNER) != 0 {
                return false;
            }
            let ex = GetWindowLongW(h, GWL_EXSTYLE) as u32;
            if ex & WS_EX_TOOLWINDOW != 0 {
                return false;
            }
            let mut cloaked = 0u32;
            if DwmGetWindowAttribute(h, DWMWA_CLOAKED as u32, &mut cloaked as *mut u32 as *mut _, 4) == 0 && cloaked != 0 {
                return false;
            }
        }
        !text(h).trim().is_empty()
    }

    /// On-screen bounds (none while minimized: Windows parks those at -32000, -32000).
    fn rect(h: HWND) -> Option<Value> {
        let mut r = RECT { left: 0, top: 0, right: 0, bottom: 0 };
        // SAFETY: plain window queries; out pointer to a local.
        (unsafe { IsIconic(h) == 0 && GetWindowRect(h, &mut r) != 0 } && r.right > r.left).then(|| json!({"x": r.left, "y": r.top, "width": r.right - r.left, "height": r.bottom - r.top}))
    }

    pub fn windows() -> Vec<Value> {
        dpi_aware();
        // SAFETY: plain window query.
        let fg = unsafe { GetForegroundWindow() };
        top_level()
            .into_iter()
            .filter(|h| listed(*h))
            .map(|h| {
                let (app, pid) = app_of(h);
                // SAFETY: plain window query.
                let min = unsafe { IsIconic(h) } != 0;
                json!({"app": app, "pid": pid, "windowRef": window_ref(h), "title": text(h), "role": "window", "class": class(h), "bounds": rect(h), "minimized": min, "focused": h == fg})
            })
            .collect()
    }

    fn live(h: isize) -> Result<HWND, String> {
        // SAFETY: IsWindow accepts any value.
        if unsafe { IsWindow(h) } == 0 {
            return Err(format!("window {} is gone; call list_windows again", window_ref(h)));
        }
        Ok(h)
    }

    /// Run `f` with a UI Automation client on this thread (COM initialized for it).
    fn with_uia<R>(f: impl FnOnce(&IUIAutomation) -> Result<R, String>) -> Result<R, String> {
        dpi_aware();
        // SAFETY: COM is initialized for this thread (balanced below when it was us); every
        // UIA object is dropped inside `f`, before CoUninitialize.
        unsafe {
            let inited = CoInitializeEx(None, COINIT_MULTITHREADED).is_ok();
            let r = CoCreateInstance::<_, IUIAutomation>(&CUIAutomation, None, CLSCTX_INPROC_SERVER).map_err(|e| format!("UI Automation is unavailable: {e}")).and_then(|u| f(&u));
            if inited {
                CoUninitialize();
            }
            r
        }
    }

    fn whwnd(h: HWND) -> WHWND {
        WHWND(h as *mut core::ffi::c_void)
    }

    /// The element `r` names: its window's element, then the child indexes of the control view.
    fn resolve(u: &IUIAutomation, r: &str) -> Result<IUIAutomationElement, String> {
        let (h, path) = parse_element_ref(r).ok_or_else(|| format!("bad elementRef `{r}` (expected uia:<window>:<path> from get_accessibility_tree)"))?;
        let h = live(h)?;
        // SAFETY: COM calls on live interfaces.
        unsafe {
            let w = u.ControlViewWalker().map_err(|e| e.to_string())?;
            let mut el = u.ElementFromHandle(whwnd(h)).map_err(|e| format!("UI Automation: {e}"))?;
            for (depth, i) in path.iter().enumerate() {
                let mut c = w.GetFirstChildElement(&el).map_err(|_| stale(r, depth))?;
                for _ in 0..*i {
                    c = w.GetNextSiblingElement(&c).map_err(|_| stale(r, depth))?;
                }
                el = c;
            }
            Ok(el)
        }
    }

    fn stale(r: &str, depth: usize) -> String {
        format!("element {r} is no longer in its window (the tree changed at depth {}); call get_accessibility_tree again", depth + 1)
    }

    struct Walk<'a> {
        walker: &'a IUIAutomationTreeWalker,
        hwnd: isize,
        minimized: bool,
        query: String,
        depth: usize,
        limit: usize,
        visits: usize,
        out: Vec<Value>,
    }

    impl Walk<'_> {
        fn visit(&mut self, el: &IUIAutomationElement, path: &mut Vec<usize>) {
            self.visits += 1;
            if self.out.len() >= self.limit || self.visits > self.limit * 4 {
                return;
            }
            // SAFETY: property reads on a live element.
            let (name, ct, b, off) = unsafe { (el.CurrentName().map(|s| s.to_string()).unwrap_or_default(), el.CurrentControlType().map(|c| c.0).unwrap_or(0), el.CurrentBoundingRectangle().ok(), el.CurrentIsOffscreen().map(|o| o.as_bool()).unwrap_or(false)) };
            let role = role_name(ct);
            let value = if has_value(ct) {
                // SAFETY: pattern query on a live element; absent pattern = no value.
                unsafe { el.GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId).and_then(|p| p.CurrentValue()).map(|v| v.to_string()).unwrap_or_default() }
            } else {
                String::new()
            };
            let mut e = json!({"elementRef": element_ref(self.hwnd, path), "role": role, "depth": path.len()});
            if !name.is_empty() {
                e["label"] = json!(name);
            }
            if !value.is_empty() {
                e["value"] = json!(value.chars().take(500).collect::<String>());
            }
            match b {
                Some(r) if !off && !self.minimized && r.right > r.left && r.bottom > r.top => e["bounds"] = json!({"x": r.left, "y": r.top, "width": r.right - r.left, "height": r.bottom - r.top}),
                _ if off || self.minimized => e["offscreen"] = json!(true),
                _ => {}
            }
            if matches(&self.query, &name, role, &value) {
                self.out.push(e);
            }
            if path.len() >= self.depth {
                return;
            }
            // SAFETY: tree walking on live elements; Err = no (more) children.
            let mut child = unsafe { self.walker.GetFirstChildElement(el) };
            let mut i = 0;
            while let Ok(c) = child {
                path.push(i);
                self.visit(&c, path);
                path.pop();
                if self.out.len() >= self.limit || self.visits > self.limit * 4 || i >= 500 {
                    break;
                }
                i += 1;
                child = unsafe { self.walker.GetNextSiblingElement(&c) };
            }
        }
    }

    fn tree(p: &Value) -> Result<Value, String> {
        let root = p["windowRef"].as_str().or(p["elementRef"].as_str()).map(str::to_string);
        // No windowRef: the foreground window (the AT-SPI path walks the whole desktop, which
        // on Windows is every app's tree at once).
        let root = match root {
            Some(r) => r,
            // SAFETY: plain window query.
            None => window_ref(live(unsafe { GetForegroundWindow() }).map_err(|_| "no foreground window; pass windowRef from list_windows".to_string())?),
        };
        let start_ref = if root.starts_with("hwnd:") { element_ref(window_of(&root).ok_or_else(|| format!("bad windowRef `{root}`"))?, &[]) } else { root.clone() };
        let (hwnd, path) = parse_element_ref(&start_ref).ok_or_else(|| format!("bad windowRef `{root}` (expected hwnd:<n> from list_windows)"))?;
        let depth = p["depth"].as_u64().unwrap_or(8).min(64) as usize;
        let limit = p["maxElements"].as_u64().unwrap_or(200).clamp(1, 2000) as usize;
        let query = p["query"].as_str().unwrap_or("").to_string();
        // A minimized window's elements sit at -32000, -32000: no bounds to click there.
        // SAFETY: plain window query.
        let minimized = unsafe { IsIconic(hwnd) } != 0;
        let walk = |path: &mut Vec<usize>| {
            with_uia(|u| {
                let el = resolve(u, &start_ref)?;
                // SAFETY: COM call on a live interface.
                let walker = unsafe { u.ControlViewWalker() }.map_err(|e| e.to_string())?;
                let mut w = Walk { walker: &walker, hwnd, minimized, query: query.clone(), depth: depth + path.len(), limit, visits: 0, out: vec![] };
                w.visit(&el, path);
                Ok(w.out)
            })
        };
        let mut elements = walk(&mut path.clone())?;
        // Chromium / Electron build their accessibility tree when a UIA client first asks: the
        // first walk sees the frame's caption buttons only. Walk again once it is built.
        if query.is_empty() && lazy_tree(&class(hwnd)) && elements.len() < LAZY_MIN && limit > elements.len() {
            for _ in 0..3 {
                std::thread::sleep(std::time::Duration::from_millis(400));
                let again = walk(&mut path.clone())?;
                let grew = again.len() > elements.len();
                elements = again;
                if grew && elements.len() >= LAZY_MIN {
                    break;
                }
            }
        }
        Ok(json!(elements))
    }

    /// The element's own action: Invoke, Toggle, Select, Expand, then the MSAA default action.
    fn activate(r: &str) -> Result<Value, String> {
        with_uia(|u| {
            let el = resolve(u, r)?;
            // SAFETY: pattern calls on a live element; a missing pattern is an Err, tried next.
            unsafe {
                if let Ok(p) = el.GetCurrentPatternAs::<IUIAutomationInvokePattern>(UIA_InvokePatternId) {
                    return p.Invoke().map(|_| json!({"ok": true, "elementRef": r, "via": "invoke"})).map_err(|e| format!("Invoke: {e}"));
                }
                if let Ok(p) = el.GetCurrentPatternAs::<IUIAutomationTogglePattern>(UIA_TogglePatternId) {
                    return p.Toggle().map(|_| json!({"ok": true, "elementRef": r, "via": "toggle"})).map_err(|e| format!("Toggle: {e}"));
                }
                if let Ok(p) = el.GetCurrentPatternAs::<IUIAutomationSelectionItemPattern>(UIA_SelectionItemPatternId) {
                    return p.Select().map(|_| json!({"ok": true, "elementRef": r, "via": "select"})).map_err(|e| format!("Select: {e}"));
                }
                if let Ok(p) = el.GetCurrentPatternAs::<IUIAutomationExpandCollapsePattern>(UIA_ExpandCollapsePatternId) {
                    return p.Expand().map(|_| json!({"ok": true, "elementRef": r, "via": "expand"})).map_err(|e| format!("Expand: {e}"));
                }
                if let Ok(p) = el.GetCurrentPatternAs::<IUIAutomationLegacyIAccessiblePattern>(UIA_LegacyIAccessiblePatternId) {
                    if p.DoDefaultAction().is_ok() {
                        return Ok(json!({"ok": true, "elementRef": r, "via": "default_action"}));
                    }
                }
            }
            Ok(json!({"ok": false, "elementRef": r, "error": "the element has no invoke / toggle / select / expand / default action; click its bounds by coordinate"}))
        })
    }

    fn set_value(r: &str, v: &str) -> Result<Value, String> {
        with_uia(|u| {
            let el = resolve(u, r)?;
            // SAFETY: pattern calls on a live element.
            unsafe {
                let Ok(p) = el.GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId) else { return Ok(json!({"ok": false, "elementRef": r, "error": "not an editable value (no ValuePattern)"})) };
                if p.CurrentIsReadOnly().map(|b| b.as_bool()).unwrap_or(false) {
                    return Ok(json!({"ok": false, "elementRef": r, "error": "the value is read-only"}));
                }
                p.SetValue(&BSTR::from(v)).map_err(|e| format!("SetValue: {e}"))?;
                let now = p.CurrentValue().map(|s| s.to_string()).unwrap_or_default();
                Ok(json!({"ok": true, "elementRef": r, "verified": now == v}))
            }
        })
    }

    fn bring_to_front(r: &str) -> Result<Value, String> {
        let h = live(window_of(r).ok_or_else(|| format!("bad windowRef `{r}` (expected hwnd:<n> from list_windows)"))?)?;
        // The top-level window of a child handle.
        // SAFETY: plain window calls; input attachment is undone before returning.
        unsafe {
            let h = match GetAncestor(h, GA_ROOT) {
                0 => h,
                a => a,
            };
            if IsIconic(h) != 0 {
                ShowWindow(h, SW_RESTORE);
            }
            let fg = GetForegroundWindow();
            let (me, them) = (GetCurrentThreadId(), GetWindowThreadProcessId(fg, std::ptr::null_mut()));
            let attached = them != 0 && them != me && AttachThreadInput(me, them, TRUE) != 0;
            BringWindowToTop(h);
            SetForegroundWindow(h);
            if attached {
                AttachThreadInput(me, them, 0);
            }
            Ok(json!({"ok": GetForegroundWindow() == h, "windowRef": window_ref(h)}))
        }
    }

    /// `list_apps` / `list_windows` / `get_accessibility_tree` / `get_window_state` /
    /// `set_value` / `bring_to_front` / element click -- the AT-SPI module's contract.
    pub fn act(p: &Value) -> Result<Value, String> {
        let action = p["action"].as_str().unwrap_or("");
        match action {
            "list_windows" => Ok(json!({"windows": windows()})),
            "list_apps" => Ok(json!({"apps": group_apps(&windows())})),
            "get_accessibility_tree" | "get_window_state" => Ok(json!({"observation": {"kind": "window", "observationId": seagent_net::crypto::random_token(8), "elements": tree(p)?}})),
            "set_value" => {
                let r = p["elementRef"].as_str().ok_or("set_value needs elementRef")?;
                let v = p["value"].as_str().ok_or("set_value needs value")?;
                if v.len() > 4000 {
                    return Err("value longer than 4000 bytes".into());
                }
                set_value(r, v)
            }
            "bring_to_front" => bring_to_front(p["windowRef"].as_str().or(p["elementRef"].as_str()).ok_or("bring_to_front needs windowRef")?),
            _ => activate(p["elementRef"].as_str().ok_or("needs elementRef")?),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The real desktop this runs on (read-only: nothing is clicked, typed or raised): a
        /// window list with this host's windows, apps grouped from it, and a UIA tree of one
        /// of them whose refs resolve back to elements. Skipped without an interactive desktop
        /// (a service session lists no windows).
        #[test]
        fn the_real_desktop_lists_windows_and_walks_one_tree() {
            let ws = windows();
            if ws.is_empty() {
                eprintln!("skipping: no top-level windows on this desktop (non-interactive session)");
                return;
            }
            for w in &ws {
                assert!(w["windowRef"].as_str().is_some_and(|r| window_of(r).is_some()), "{w}");
                assert!(w["title"].as_str().is_some_and(|t| !t.trim().is_empty()), "{w}");
                assert!(w["app"].as_str().is_some_and(|a| !a.is_empty()), "{w}");
            }
            let apps = act(&json!({"action": "list_apps"})).unwrap();
            let n: u64 = apps["apps"].as_array().unwrap().iter().map(|a| a["windows"].as_u64().unwrap()).sum();
            assert_eq!(n as usize, ws.len(), "every window is counted under one app: {apps}");
            // A tree of the first window that has one (some elevated / hung windows refuse UIA).
            let mut walked = false;
            for w in &ws {
                let Ok(t) = act(&json!({"action": "get_accessibility_tree", "windowRef": w["windowRef"], "depth": 3, "maxElements": 40})) else { continue };
                let els = t["observation"]["elements"].as_array().unwrap();
                if els.is_empty() {
                    continue;
                }
                assert_eq!(els[0]["role"], "window", "the walk starts at the window's own element: {t}");
                for e in els {
                    let r = e["elementRef"].as_str().unwrap();
                    assert!(parse_element_ref(r).is_some_and(|(h, p)| window_of(w["windowRef"].as_str().unwrap()) == Some(h) && p.len() == e["depth"].as_u64().unwrap() as usize), "{e}");
                    assert!(e["role"].as_str().unwrap().is_ascii(), "roles are not localized: {e}");
                }
                let last = els.last().unwrap()["elementRef"].as_str().unwrap().to_string();
                with_uia(|u| resolve(u, &last).map(|_| ())).unwrap_or_else(|e| panic!("{last} does not resolve: {e}"));
                walked = true;
                break;
            }
            assert!(walked, "no window on this desktop exposed a UI Automation tree: {ws:?}");
        }

        #[test]
        fn gone_windows_and_bad_refs_are_errors() {
            assert!(act(&json!({"action": "get_accessibility_tree", "windowRef": "hwnd:1"})).unwrap_err().contains("gone"));
            assert!(act(&json!({"action": "set_value", "elementRef": "uia:1:0", "value": "x"})).unwrap_err().contains("gone"));
            assert!(act(&json!({"action": "left_click", "elementRef": ":1.3|/org/a11y"})).unwrap_err().contains("bad elementRef"));
            assert!(act(&json!({"action": "bring_to_front", "windowRef": "w1"})).unwrap_err().contains("bad windowRef"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn refs_round_trip_and_reject_garbage() {
        assert_eq!(window_ref(132_456), "hwnd:132456");
        assert_eq!(window_of("hwnd:132456"), Some(132_456));
        assert_eq!(element_ref(77, &[]), "uia:77:");
        assert_eq!(element_ref(77, &[0, 3, 12]), "uia:77:0.3.12");
        assert_eq!(parse_element_ref("uia:77:0.3.12"), Some((77, vec![0, 3, 12])));
        assert_eq!(parse_element_ref("uia:77:"), Some((77, vec![])));
        assert_eq!(window_of("uia:77:0.3"), Some(77), "an element ref names its window");
        for bad in ["", "hwnd:", "hwnd:0", "hwnd:x", "uia:0:1", "uia:77", "uia:77:1..2", "uia:77:-1", ":1.3|/org/a11y/atspi/accessible/42", "uia:x:1"] {
            assert!(window_of(bad).is_none(), "{bad}");
            assert!(parse_element_ref(bad).is_none(), "{bad}");
        }
        let deep = format!("uia:5:{}", vec!["0"; 65].join("."));
        assert!(parse_element_ref(&deep).is_none(), "paths are bounded");
    }

    #[test]
    fn roles_use_the_atspi_vocabulary_so_layout_is_dropped() {
        assert_eq!(role_name(50000), "push button");
        assert_eq!(role_name(50004), "entry");
        assert_eq!(role_name(50011), "menu item");
        for layout in [50020, 50026, 50033, 50032, 50021, 50017, 50038] {
            assert!(crate::computer::native::LAYOUT_ROLES.contains(&role_name(layout)), "{layout} -> {}", role_name(layout));
        }
        for target in [50000, 50002, 50003, 50004, 50005, 50007, 50011, 50019, 50024] {
            assert!(!crate::computer::native::LAYOUT_ROLES.contains(&role_name(target)), "{target} -> {}", role_name(target));
        }
        assert_eq!(role_name(1), "unknown");
        assert!(has_value(50004) && !has_value(50000));
    }

    #[test]
    fn app_names_and_grouping() {
        assert_eq!(app_name(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"), "msedge");
        assert_eq!(app_name(r"C:\Windows\EXPLORER.EXE"), "EXPLORER");
        assert_eq!(app_name("Code"), "Code");
        let ws = [json!({"app": "msedge", "windowRef": "hwnd:1", "pid": 10}), json!({"app": "Code", "windowRef": "hwnd:2", "pid": 11}), json!({"app": "msedge", "windowRef": "hwnd:3", "pid": 10})];
        let apps = group_apps(&ws);
        assert_eq!(apps, vec![json!({"app": "msedge", "windowRef": "hwnd:1", "windows": 2, "pid": 10}), json!({"app": "Code", "windowRef": "hwnd:2", "windows": 1, "pid": 11})]);
        assert!(matches("", "x", "y", "z"));
        assert!(matches("SAVE", "Save as", "push button", ""));
        assert!(matches("entry", "", "entry", ""));
        assert!(!matches("open", "Save", "push button", ""));
        assert!(lazy_tree("Chrome_WidgetWin_1") && lazy_tree("CefBrowserWindow") && !lazy_tree("Notepad") && !lazy_tree("WindowsForms10.Window.8.app.0.1"));
    }
}
