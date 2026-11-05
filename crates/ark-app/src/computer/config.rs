//! `[computer_use]` config (Hermes `computer_use.*` + `bot_desktop.*` in config.yaml, OpenClaw
//! `computer` tool / `cua-computer` plugin settings). Every key has a documented default; see `DEFAULTS`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ComputerUseConfig {
    /// "auto" (tools appear when a usable display backend exists), true, false.
    pub enabled: toml::Value,
    /// auto | native | xdotool | ydotool | cua. auto = cua-driver when installed, else native
    /// (xdotool/ydotool + AT-SPI, the same code the paired-node `computer.act` uses).
    pub backend: String,
    /// Tool surfaces to offer: "computer_use" (Hermes) and/or "computer" (OpenClaw).
    pub tools: Vec<String>,
    /// cua-driver executable ("" = $ARK_CUA_DRIVER_CMD, then <home>/bin/cua-driver, then PATH).
    pub driver_cmd: String,
    /// cua-driver permission mode: standard | bounded (bounded needs capability_manifest).
    pub permission_mode: String,
    pub capability_manifest: String,
    /// Bound on the driver's accessibility walk per capture (0 = driver default).
    pub ax_max_elements: u32,
    /// Elements returned per capture; the rest spill to a file.
    pub max_elements: usize,
    /// cua-driver screenshot downscale (0 = native size).
    pub max_image_dimension: u32,
    /// Pass --no-overlay to cua-driver (unset = auto: off on X11/headless, on for Wayland).
    pub no_overlay: Option<bool>,
    /// cua-driver anonymous telemetry (off unless opted in).
    pub cua_telemetry: bool,
    /// Let cua-driver use its native Wayland backend instead of XWayland.
    pub native_wayland: bool,
    /// Describe captures with the session's vision model (tool results here carry text only).
    pub vision: bool,
    /// Per-call timeout, seconds.
    pub timeout: u64,
    /// Mode of the follow-up capture `capture_after = true` takes: som | vision | ax.
    pub capture_after_mode: String,
    /// Default desktop `computer_use` acts on: "host" (this machine's display / Bot Desktop) or
    /// "vm:<name>" (a `[desktop_vm]` desktop VM). A call's `target` argument overrides it.
    pub target: String,
    pub bot_desktop: BotDesktopConfig,
}

/// Hermes `bot_desktop.*`: a headless Xfce screen per ark home the agent drives.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BotDesktopConfig {
    /// Start the screen on first computer_use call when this host has no display.
    pub auto_start: bool,
    pub geometry: String,
    /// Stop a screen nobody used for this long (0 = never).
    pub idle_stop_minutes: u64,
    /// Refuse to start below this much free memory (0 = no gate).
    pub min_free_memory_mb: u64,
    /// Name shown in the VNC title ("" = "default").
    pub profile: String,
}

impl Default for BotDesktopConfig {
    fn default() -> Self {
        BotDesktopConfig { auto_start: false, geometry: "1440x900".into(), idle_stop_minutes: 30, min_free_memory_mb: 1536, profile: String::new() }
    }
}

impl Default for ComputerUseConfig {
    fn default() -> Self {
        ComputerUseConfig {
            enabled: toml::Value::String("auto".into()),
            backend: "auto".into(),
            tools: vec!["computer_use".into(), "computer".into()],
            driver_cmd: String::new(),
            permission_mode: "standard".into(),
            capability_manifest: String::new(),
            ax_max_elements: 200,
            max_elements: 100,
            max_image_dimension: 1456,
            no_overlay: None,
            cua_telemetry: false,
            native_wayland: false,
            vision: true,
            timeout: 30,
            capture_after_mode: "som".into(),
            target: "host".into(),
            bot_desktop: BotDesktopConfig::default(),
        }
    }
}

/// Documented defaults (checked by a test).
pub const DEFAULTS: &str = r#"[computer_use]
enabled = "auto"            # "auto": tools appear when a display backend is usable; true / false
backend = "auto"            # auto | native | xdotool | ydotool | cua (auto: cua-driver if installed, else native)
tools = ["computer_use", "computer"]   # Hermes computer_use and/or OpenClaw computer
driver_cmd = ""             # cua-driver binary ("" = $ARK_CUA_DRIVER_CMD, <data>/bin/cua-driver, PATH)
permission_mode = "standard"   # standard | bounded (needs capability_manifest)
capability_manifest = ""
ax_max_elements = 200       # accessibility walk bound per capture (0 = driver default)
max_elements = 100          # elements returned per capture; the full tree spills to a file
max_image_dimension = 1456  # cua-driver screenshot downscale (0 = native)
# no_overlay =              # unset: auto (off on X11/headless, on for Wayland)
cua_telemetry = false
native_wayland = false
vision = true               # describe captures with the session's vision model
timeout = 30                # seconds per desktop call
capture_after_mode = "som"  # follow-up capture for capture_after = true: som | vision | ax
target = "host"             # default desktop for computer_use: "host" or "vm:<name>" (a [desktop_vm] VM)
[computer_use.bot_desktop]
auto_start = false          # start the headless screen when this host has no display
geometry = "1440x900"
idle_stop_minutes = 30      # 0 = never stop an idle screen
min_free_memory_mb = 1536   # 0 = no memory gate
profile = ""                # VNC title ("" = default)
"#;

impl ComputerUseConfig {
    pub fn parse(t: &toml::Table) -> Result<ComputerUseConfig, String> {
        let c = ComputerUseConfig::deserialize(toml::Value::Table(t.clone())).map_err(|e| format!("[computer_use]: {e}"))?;
        if !matches!(c.backend.as_str(), "auto" | "native" | "xdotool" | "ydotool" | "cua") {
            return Err(format!("[computer_use] backend must be auto, native, xdotool, ydotool or cua, got `{}`", c.backend));
        }
        if !matches!(c.permission_mode.as_str(), "standard" | "bounded") {
            return Err(format!("[computer_use] permission_mode must be standard or bounded, got `{}`", c.permission_mode));
        }
        if c.permission_mode == "bounded" && c.capability_manifest.trim().is_empty() {
            return Err("[computer_use] permission_mode = \"bounded\" needs capability_manifest".into());
        }
        if !matches!(c.capture_after_mode.as_str(), "som" | "vision" | "ax") {
            return Err(format!("[computer_use] capture_after_mode must be som, vision or ax, got `{}`", c.capture_after_mode));
        }
        if let Some(t) = c.tools.iter().find(|t| !matches!(t.as_str(), "computer_use" | "computer")) {
            return Err(format!("[computer_use] tools: unknown `{t}` (computer_use, computer)"));
        }
        if c.target != "host" && c.target.strip_prefix("vm:").is_none_or(|n| ark_vm::desktop::valid_name(n).is_err()) {
            return Err(format!("[computer_use] target must be \"host\" or \"vm:<name>\", got `{}`", c.target));
        }
        parse_geometry(&c.bot_desktop.geometry).ok_or_else(|| format!("[computer_use.bot_desktop] geometry must be WxH, got `{}`", c.bot_desktop.geometry))?;
        Ok(c)
    }

    /// `enabled`: Some(bool) when forced, None for "auto".
    pub fn enabled(&self) -> Option<bool> {
        match &self.enabled {
            toml::Value::Boolean(b) => Some(*b),
            toml::Value::String(s) if s == "true" => Some(true),
            toml::Value::String(s) if s == "false" || s == "off" => Some(false),
            _ => None,
        }
    }

    pub fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.timeout.clamp(5, 600))
    }

    /// `no_overlay` resolved (Hermes `_cua_no_overlay` on Linux).
    pub fn no_overlay(&self, env: &dyn Fn(&str) -> Option<String>) -> bool {
        if let Some(v) = self.no_overlay {
            return v;
        }
        let wayland = env("XDG_SESSION_TYPE").as_deref() == Some("wayland") || env("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty());
        env("DISPLAY").is_none_or(|v| v.is_empty()) || !wayland
    }
}

pub fn parse_geometry(g: &str) -> Option<(u32, u32)> {
    let (w, h) = g.trim().split_once('x')?;
    let (w, h) = (w.parse::<u32>().ok()?, h.parse::<u32>().ok()?);
    ((320..=8192).contains(&w) && (200..=8192).contains(&h)).then_some((w, h))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_doc_matches_struct() {
        let t: toml::Table = toml::from_str(DEFAULTS).unwrap();
        let doc = ComputerUseConfig::parse(t["computer_use"].as_table().unwrap()).unwrap();
        let def = ComputerUseConfig::default();
        assert_eq!(serde_json::to_value(&doc).unwrap(), serde_json::to_value(&def).unwrap());
        assert_eq!(def.enabled(), None);
        assert!(ComputerUseConfig::parse(&toml::from_str("backend = \"x\"").unwrap()).is_err());
        assert!(ComputerUseConfig::parse(&toml::from_str("permission_mode = \"bounded\"").unwrap()).is_err());
        assert!(ComputerUseConfig::parse(&toml::from_str("nope = 1").unwrap()).is_err());
        assert!(ComputerUseConfig::parse(&toml::from_str("[bot_desktop]\ngeometry = \"big\"").unwrap()).is_err());
        assert_eq!(parse_geometry("1440x900"), Some((1440, 900)));
    }

    #[test]
    fn overlay_auto_follows_the_session_type() {
        let c = ComputerUseConfig::default();
        let x11 = |k: &str| (k == "DISPLAY").then(|| ":0".to_string());
        let wl = |k: &str| match k {
            "DISPLAY" => Some(":0".to_string()),
            "WAYLAND_DISPLAY" => Some("wayland-0".to_string()),
            _ => None,
        };
        assert!(c.no_overlay(&x11), "X11: overlay off");
        assert!(!c.no_overlay(&wl), "Wayland keeps the overlay");
        assert!(c.no_overlay(&|_| None), "headless: off");
        assert!(!ComputerUseConfig { no_overlay: Some(false), ..c }.no_overlay(&x11));
    }
}
