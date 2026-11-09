//! The macOS substitute for the Linux Xvnc + Xfce Bot Desktop ([`super::screen`]) and the
//! Windows isolated desktop ([`super::screen_windows`]).
//!
//! macOS has no public per-process desktop object. The agent's headed browser therefore runs
//! in the user's own Aqua login session (its CDP screenshots and the computer_use driver work
//! there), and the isolation the Linux/Windows desktops give is provided instead by a dedicated
//! **window set** this module records so the rest of seagent treats a macOS host as "desktop
//! supported, already running": there is nothing to start or stop, and `SEAGENT_BD_DESKTOP` is
//! not published, so [`crate::launch`] spawns the browser normally onto the login session.
//!
//! A fully headless macOS desktop (no attached display) needs either a virtual display — the
//! private `CGVirtualDisplay`, or a hardware HDMI emulator — or a secondary `launchd` GUI
//! session; both are host-provisioning choices documented in docs/cross-platform.md rather than
//! something seagent sets up. This module keeps the same shape as the other two so callers are
//! branch-free, and its pure helpers are unit-tested on every target.
#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};

/// This home's desktop stand-in. macOS keeps no separate desktop object, so this only names the
/// login session the browser already runs on.
#[derive(Debug, Clone)]
pub struct MacDesktop {
    pub home: PathBuf,
    pub profile: String,
    pub geometry: String,
}

impl MacDesktop {
    pub fn new(home: &Path, profile: &str, geometry: &str) -> MacDesktop {
        MacDesktop { home: home.to_path_buf(), profile: profile.to_string(), geometry: geometry.to_string() }
    }

    /// The login session's display name (for `seagent screen status`).
    pub fn session_name(&self) -> String {
        session_name(&self.profile)
    }

    /// macOS has no desktop to start or stop: the login session is always the agent's screen.
    pub fn running(&self) -> bool {
        true
    }

    /// Nothing to start (the browser runs on the login session); reported as already running.
    pub fn start(&self) -> Result<(), String> {
        Ok(())
    }

    /// Nothing to stop.
    pub fn stop(&self) -> bool {
        false
    }

    /// Whether a GUI session is attached (`CGMainDisplayID` has a real display). A headless Mac
    /// with no virtual display returns false, so `status` can tell the operator to attach one.
    pub fn has_display(&self) -> bool {
        has_attached_display()
    }
}

/// The login-session name is a sanitised profile, like the other two platforms' desktop names.
pub fn session_name(profile: &str) -> String {
    let p: String = profile.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).take(64).collect();
    format!("seagent-{}", if p.is_empty() { "default".into() } else { p })
}

/// Is a real display attached? Uses CoreGraphics `CGGetActiveDisplayList`.
pub fn has_attached_display() -> bool {
    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGGetActiveDisplayList(max_displays: u32, active: *mut u32, count: *mut u32) -> i32;
    }
    let mut count: u32 = 0;
    // SAFETY: the query form (null list) only fills `count`.
    let err = unsafe { CGGetActiveDisplayList(0, std::ptr::null_mut(), &mut count) };
    err == 0 && count > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_names_are_sanitised() {
        assert_eq!(session_name("work"), "seagent-work");
        assert_eq!(session_name("a b/c"), "seagent-a_b_c");
        assert_eq!(session_name(""), "seagent-default");
        let d = MacDesktop::new(Path::new("/h"), "work", "1440x900");
        assert!(d.running() && !d.stop() && d.start().is_ok());
        assert_eq!(d.session_name(), "seagent-work");
        // has_display just must not panic (true on an attached Mac, false headless).
        let _ = d.has_display();
    }
}
