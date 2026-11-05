//! `[desktop_vm]` — the graphical desktop VM the agent drives by screenshots and simulated
//! input (computer use) and a human can watch / take over from the web console.
//!
//! ```toml
//! [desktop_vm]
//! enabled = true                # false hides the VM targets (CLI build/start still work)
//! default = "desk"              # VM name used when a call names none
//! qemu = "qemu-system-x86_64"
//! qemu_img = "qemu-img"
//! accel = "auto"                # auto (KVM when /dev/kvm is usable, else TCG + warning) | kvm | tcg
//! memory_mb = 2048
//! cpus = 2
//! width = 1280                  # screen size (EDID preferred mode + xrandr in the guest)
//! height = 800
//! disk_gb = 12                  # virtual size of the provisioned image (per-VM overlays share it)
//! network = "user"              # user (QEMU user-mode NAT) | none
//! start_url = "about:blank"     # what the guest's Chromium opens at login
//! image_url = "…"               # pinned Debian 13 generic cloud image (see DEFAULT_IMAGE_URL)
//! image_sha256 = "…"
//! extra_packages = []           # Debian packages added to the provisioned desktop
//! build_timeout_secs = 2400
//! stop_timeout_secs = 30        # ACPI power-off grace before `quit` / SIGTERM
//! idle_timeout_secs = 0         # stop a VM nobody looked at / drove for this long (0 = never)
//! ```

use serde::{Deserialize, Serialize};

/// Debian 13 (trixie) "generic" cloud image (cloud-init, full kernel with DRM/USB HID), pinned.
pub const DEFAULT_IMAGE_URL: &str = "https://cloud.debian.org/images/cloud/trixie/20261026-2643/debian-13-generic-amd64-20261026-2643.qcow2";
/// sha256 of [`DEFAULT_IMAGE_URL`] (Debian publishes SHA512SUMS; this was checked against it).
pub const DEFAULT_IMAGE_SHA256: &str = "7740a80114c1b5e6456c65713c76f4006e8b00eb50d8a122924ba823b9959fc5";

/// The desktop the provisioner installs (no recommends: Xfce, LightDM auto-login, Chromium).
pub const BASE_PACKAGES: &[&str] = &[
    "xserver-xorg-core",
    "xserver-xorg-input-libinput",
    "x11-xserver-utils",
    "lightdm",
    "lightdm-gtk-greeter",
    "xfce4-session",
    "xfwm4",
    "xfce4-panel",
    "xfdesktop4",
    "xfce4-settings",
    "xfce4-terminal",
    "thunar",
    // Relays the guest Chromium's DevTools port to the NIC so the host's hostfwd reaches it.
    "socat",
    "dbus-x11",
    "at-spi2-core",
    "chromium",
    "fonts-dejavu-core",
    // Traditional Chinese (and Japanese / Korean) pages must not render as tofu.
    "fonts-noto-cjk",
    "locales",
    // Paste non-ASCII text arriving on the org.ark.text channel (clipboard + ctrl+v).
    "xdotool",
    "xclip",
    "xdg-utils",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DesktopConfig {
    pub enabled: bool,
    pub default: String,
    pub qemu: String,
    pub qemu_img: String,
    pub accel: String,
    pub memory_mb: u32,
    pub cpus: u16,
    pub width: u32,
    pub height: u32,
    pub disk_gb: u32,
    pub network: String,
    pub start_url: String,
    pub image_url: String,
    pub image_sha256: String,
    pub extra_packages: Vec<String>,
    pub build_timeout_secs: u64,
    pub stop_timeout_secs: u64,
    pub idle_timeout_secs: u64,
}

impl Default for DesktopConfig {
    fn default() -> Self {
        DesktopConfig {
            enabled: true,
            default: "desk".into(),
            qemu: "qemu-system-x86_64".into(),
            qemu_img: "qemu-img".into(),
            accel: "auto".into(),
            memory_mb: 2048,
            cpus: 2,
            width: 1280,
            height: 800,
            disk_gb: 12,
            network: "user".into(),
            start_url: "about:blank".into(),
            image_url: DEFAULT_IMAGE_URL.into(),
            image_sha256: DEFAULT_IMAGE_SHA256.into(),
            extra_packages: vec![],
            build_timeout_secs: 2400,
            stop_timeout_secs: 30,
            idle_timeout_secs: 0,
        }
    }
}

impl DesktopConfig {
    /// Parse the `[desktop_vm]` table (any serde value; `null` = defaults) and validate it.
    pub fn parse<T: Serialize>(t: &T) -> Result<DesktopConfig, String> {
        let v = serde_json::to_value(t).map_err(|e| format!("[desktop_vm]: {e}"))?;
        if v.is_null() || v.as_object().is_some_and(|m| m.is_empty()) {
            return Ok(DesktopConfig::default());
        }
        let c: DesktopConfig = serde_json::from_value(v).map_err(|e| format!("[desktop_vm]: {e}"))?;
        c.validate()?;
        Ok(c)
    }

    pub fn validate(&self) -> Result<(), String> {
        if !matches!(self.accel.as_str(), "auto" | "kvm" | "tcg") {
            return Err(format!("desktop_vm.accel `{}`: use auto | kvm | tcg", self.accel));
        }
        if !matches!(self.network.as_str(), "user" | "none") {
            return Err(format!("desktop_vm.network `{}`: use user | none", self.network));
        }
        if !(640..=3840).contains(&self.width) || !(480..=2160).contains(&self.height) {
            return Err(format!("desktop_vm screen {}x{} is out of range (640x480 … 3840x2160)", self.width, self.height));
        }
        if !(512..=65536).contains(&self.memory_mb) {
            return Err(format!("desktop_vm.memory_mb {} is out of range (512 … 65536)", self.memory_mb));
        }
        if !(1..=64).contains(&self.cpus) {
            return Err(format!("desktop_vm.cpus {} is out of range (1 … 64)", self.cpus));
        }
        if !(4..=1024).contains(&self.disk_gb) {
            return Err(format!("desktop_vm.disk_gb {} is out of range (4 … 1024)", self.disk_gb));
        }
        super::valid_name(&self.default).map_err(|e| format!("desktop_vm.default: {e}"))?;
        if self.image_sha256.len() != 64 || !self.image_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("desktop_vm.image_sha256 must be a 64-character hex sha256".into());
        }
        for p in &self.extra_packages {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'+' | b'.')) {
                return Err(format!("desktop_vm.extra_packages: `{p}` is not a Debian package name"));
            }
        }
        if self.start_url.chars().any(|c| c.is_whitespace() || c == '\'' || c == '"' || c == '\\' || c.is_control()) {
            return Err("desktop_vm.start_url must be one URL without spaces or quotes".into());
        }
        Ok(())
    }

    /// Every package the provisioner installs.
    pub fn packages(&self) -> Vec<String> {
        BASE_PACKAGES.iter().map(|s| s.to_string()).chain(self.extra_packages.iter().cloned()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_parse_and_bad_values_are_named() {
        assert_eq!(DesktopConfig::parse(&serde_json::Value::Null).unwrap(), DesktopConfig::default());
        let c = DesktopConfig::parse(&json!({"width": 1920, "height": 1080, "accel": "tcg"})).unwrap();
        assert_eq!((c.width, c.height, c.accel.as_str(), c.memory_mb), (1920, 1080, "tcg", 2048));
        assert!(DesktopConfig::parse(&json!({"accel": "hvf"})).unwrap_err().contains("accel"));
        assert!(DesktopConfig::parse(&json!({"width": 100})).unwrap_err().contains("out of range"));
        assert!(DesktopConfig::parse(&json!({"bogus": 1})).unwrap_err().contains("bogus"));
        assert!(DesktopConfig::parse(&json!({"extra_packages": ["vim; rm -rf /"]})).is_err());
        assert!(DesktopConfig::parse(&json!({"default": "../x"})).is_err());
        assert!(DesktopConfig::parse(&json!({"start_url": "a' b"})).is_err());
        assert!(DesktopConfig::default().packages().iter().any(|p| p == "chromium"));
    }
}
