//! The agent's computer: the desktop VM the daemon brings up by itself (`[desktop_vm] autostart`).
//!
//! When the daemon starts, a supervisor thread makes sure the default desktop VM
//! (`[desktop_vm] default`, normally `desk`) is running: on the first run it builds the image
//! (download + provisioning, several minutes; progress in `<data>/vm/desktop/agent-vm.json` and
//! `build.log`), then boots the VM, and from then on restarts it if it dies. A person who
//! stops the VM (`view.vm.stop`, the console's VM controls, `seagent vm desktop stop`) leaves a
//! `user-stopped` marker in the VM's directory, and the supervisor leaves that VM alone until it
//! is started again. The browser and computer-use tools act on this VM by default
//! (`[computer_use] target = "vm:<default>"`), so what the agent does is what the 工作區 shows.

use seagent_vm::desktop::DesktopVms;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// How often the supervisor checks the VM.
const TICK: Duration = Duration::from_secs(20);
/// After a failed build, wait this long before trying again on its own.
const BUILD_RETRY: Duration = Duration::from_secs(30 * 60);
/// After a failed boot, wait this long before trying again.
const START_RETRY: Duration = Duration::from_secs(60);
/// Lines of the build log kept in the status file.
const LOG_TAIL: usize = 12;

const STATE_FILE: &str = "agent-vm.json";
const BUILD_LOG: &str = "build.log";
const USER_STOPPED: &str = "user-stopped";

/// Where the supervisor keeps its state (next to the VMs: `<data>/vm/desktop`).
pub fn state_dir(data: &Path) -> PathBuf {
    data.join("vm").join("desktop")
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// The supervisor's last published state (`{phase, vm, message, since_ms, log}`), or a
/// `{phase: "idle"}` stub when it never ran in this home.
pub fn status(data: &Path) -> Value {
    std::fs::read(state_dir(data).join(STATE_FILE)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_else(|| json!({"phase": "idle"}))
}

fn publish(data: &Path, v: &Value) {
    let dir = state_dir(data);
    let _ = std::fs::create_dir_all(&dir);
    let tmp = dir.join(format!("{STATE_FILE}.tmp"));
    if std::fs::write(&tmp, serde_json::to_vec_pretty(v).unwrap_or_default()).is_ok() {
        let _ = std::fs::rename(&tmp, dir.join(STATE_FILE));
    }
}

/// A person stopped `name` on purpose: the supervisor must not bring it back.
pub fn mark_user_stopped(vms: &DesktopVms, name: &str, stopped: bool) {
    let f = vms.vm_dir(name).join(USER_STOPPED);
    if stopped {
        let _ = std::fs::create_dir_all(vms.vm_dir(name));
        let _ = std::fs::write(f, now_ms().to_string());
    } else {
        let _ = std::fs::remove_file(f);
    }
}

pub fn user_stopped(vms: &DesktopVms, name: &str) -> bool {
    vms.vm_dir(name).join(USER_STOPPED).exists()
}

/// One-line summary for tool errors: why the agent's VM is not usable yet.
pub fn why_not_running(data: &Path) -> Option<String> {
    let s = status(data);
    let vm = s["vm"].as_str().unwrap_or("desk");
    let msg = s["message"].as_str().unwrap_or("");
    match s["phase"].as_str()? {
        "building" => Some(format!("the desktop VM `{vm}` is being built for its first use ({msg}); it starts by itself when the build finishes — tell the user it is getting ready and try again in a few minutes")),
        "starting" => Some(format!("the desktop VM `{vm}` is booting; try again in a few seconds")),
        "failed" => Some(format!("the desktop VM `{vm}` could not be brought up: {msg}")),
        "user-stopped" => Some(format!("a person stopped the desktop VM `{vm}`; ask them to start it again (工作區 → 啟動) before using it")),
        _ => None,
    }
}

/// Wakes the supervisor (a manual "build now" / "start" from the console).
#[derive(Clone, Default)]
pub struct Kick(Arc<AtomicBool>);

impl Kick {
    pub fn now(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    fn take(&self) -> bool {
        self.0.swap(false, Ordering::SeqCst)
    }
}

static KICK: std::sync::OnceLock<Kick> = std::sync::OnceLock::new();

/// Ask the running supervisor to act now (build / start without waiting for its next tick).
pub fn kick() {
    if let Some(k) = KICK.get() {
        k.now();
    }
}

/// Start the supervisor (once per process). Does nothing when `[desktop_vm]` is disabled, has
/// `autostart = false`, or the platform has no VM at all (iOS).
pub fn spawn(vms: DesktopVms, data: PathBuf) -> Option<std::thread::JoinHandle<()>> {
    if !vms.cfg.enabled || !vms.cfg.autostart || cfg!(target_os = "ios") || cfg!(target_os = "android") {
        return None;
    }
    let kick = KICK.get_or_init(Kick::default).clone();
    std::thread::Builder::new().name("agent-vm".into()).spawn(move || supervise(&vms, &data, &kick, &AtomicBool::new(false))).ok()
}

/// What the supervisor does next, given what it sees (pure, for tests).
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    Build,
    Start,
    Wait(&'static str),
}

pub fn decide(running: bool, user_stopped: bool, image_built: bool, build_blocked: bool, start_blocked: bool) -> Step {
    if running {
        Step::Wait("running")
    } else if user_stopped {
        Step::Wait("user-stopped")
    } else if !image_built {
        if build_blocked {
            Step::Wait("failed")
        } else {
            Step::Build
        }
    } else if start_blocked {
        Step::Wait("failed")
    } else {
        Step::Start
    }
}

/// The supervisor loop (returns when `stop` is set; the daemon never sets it).
pub fn supervise(vms: &DesktopVms, data: &Path, kick: &Kick, stop: &AtomicBool) {
    let name = vms.cfg.default.clone();
    let mut build_after: Option<std::time::Instant> = None;
    let mut start_after: Option<std::time::Instant> = None;
    let mut last_error = String::new();
    let mut since = now_ms();
    let mut last_phase = String::new();
    while !stop.load(Ordering::SeqCst) {
        if kick.take() {
            build_after = None;
            start_after = None;
        }
        let now = std::time::Instant::now();
        let step = decide(vms.is_running(&name), user_stopped(vms, &name), vms.image_built(), build_after.is_some_and(|t| now < t), start_after.is_some_and(|t| now < t));
        match step {
            Step::Build => {
                since = now_ms();
                let log_path = state_dir(data).join(BUILD_LOG);
                let _ = std::fs::create_dir_all(state_dir(data));
                let mut file = std::fs::File::create(&log_path).ok();
                let mut tail: std::collections::VecDeque<String> = Default::default();
                publish(data, &json!({"phase": "building", "vm": name, "message": "downloading the base image", "since_ms": since, "log": []}));
                let mut last_pub = std::time::Instant::now();
                let r = vms.build(false, &mut |line: &str| {
                    if let Some(f) = file.as_mut() {
                        use std::io::Write;
                        let _ = writeln!(f, "{line}");
                    }
                    tail.push_back(line.to_string());
                    while tail.len() > LOG_TAIL {
                        tail.pop_front();
                    }
                    // Progress lines can come many times a second (downloads): publish ≤ 1/s.
                    if last_pub.elapsed() >= Duration::from_secs(1) {
                        last_pub = std::time::Instant::now();
                        publish(data, &json!({"phase": "building", "vm": name, "message": line, "since_ms": since, "log": tail}));
                    }
                });
                match r {
                    Ok(_) => {
                        last_error.clear();
                        build_after = None;
                        eprintln!("seagentd: desktop VM image built ({})", log_path.display());
                    }
                    Err(e) => {
                        eprintln!("seagentd: warning: desktop VM image build failed: {e} (log: {})", log_path.display());
                        last_error = e;
                        build_after = Some(std::time::Instant::now() + BUILD_RETRY);
                        publish(data, &json!({"phase": "failed", "vm": name, "message": format!("image build failed: {last_error}"), "since_ms": now_ms(), "log": tail, "retry_in_secs": BUILD_RETRY.as_secs()}));
                    }
                }
                continue;
            }
            Step::Start => {
                since = now_ms();
                publish(data, &json!({"phase": "starting", "vm": name, "message": "booting", "since_ms": since}));
                match vms.start(&name) {
                    Ok(st) => {
                        last_error.clear();
                        start_after = None;
                        let warn = st.warning.clone().unwrap_or_default();
                        eprintln!("seagentd: desktop VM `{name}` started (accel {}){}", st.accel, if warn.is_empty() { String::new() } else { format!(" — {warn}") });
                        publish(data, &json!({"phase": "running", "vm": name, "message": warn, "since_ms": now_ms(), "accel": st.accel}));
                        last_phase = "running".into();
                    }
                    Err(e) => {
                        eprintln!("seagentd: warning: desktop VM `{name}` did not start: {e}");
                        last_error = e;
                        start_after = Some(std::time::Instant::now() + START_RETRY);
                        publish(data, &json!({"phase": "failed", "vm": name, "message": last_error, "since_ms": now_ms(), "retry_in_secs": START_RETRY.as_secs()}));
                    }
                }
            }
            Step::Wait(phase) => {
                // Keep the published phase truthful (a VM can stop or be stopped between ticks).
                if phase != last_phase && phase != "failed" {
                    since = now_ms();
                    publish(data, &json!({"phase": phase, "vm": name, "message": "", "since_ms": since}));
                }
                if phase != "failed" {
                    last_phase = phase.to_string();
                } else {
                    last_phase.clear();
                }
            }
        }
        // Sleep in short slices so a kick (console "start now") is served quickly.
        let until = std::time::Instant::now() + TICK;
        while std::time::Instant::now() < until && !stop.load(Ordering::SeqCst) {
            if kick.0.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    let _ = (last_error, since);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_supervisor_builds_then_starts_and_respects_a_person() {
        assert_eq!(decide(false, false, false, false, false), Step::Build, "first run: build the image");
        assert_eq!(decide(false, false, true, false, false), Step::Start, "image ready: boot it");
        assert_eq!(decide(true, false, true, false, false), Step::Wait("running"));
        assert_eq!(decide(false, true, true, false, false), Step::Wait("user-stopped"), "a person stopped it: leave it alone");
        assert_eq!(decide(false, true, false, false, false), Step::Wait("user-stopped"), "…even before the image exists");
        assert_eq!(decide(false, false, false, true, false), Step::Wait("failed"), "a failed build waits for its retry");
        assert_eq!(decide(false, false, true, false, true), Step::Wait("failed"), "a failed boot waits for its retry");
    }

    #[test]
    fn status_and_markers_round_trip() {
        let home = seagent_core::tmp::scratch("seagent-agent-vm");
        let data = home.join("data");
        assert_eq!(status(&data)["phase"], "idle");
        assert!(why_not_running(&data).is_none());
        publish(&data, &json!({"phase": "building", "vm": "desk", "message": "apt-get install"}));
        assert_eq!(status(&data)["phase"], "building");
        assert!(why_not_running(&data).unwrap().contains("being built"));
        let cfg = seagent_vm::desktop::DesktopConfig::default();
        let vms = DesktopVms::new(cfg, &data, &home.join("cache"), &home.join("run"));
        assert!(!user_stopped(&vms, "desk"));
        mark_user_stopped(&vms, "desk", true);
        assert!(user_stopped(&vms, "desk"));
        mark_user_stopped(&vms, "desk", false);
        assert!(!user_stopped(&vms, "desk"));
    }

    #[test]
    fn disabled_or_manual_configs_spawn_nothing() {
        let home = seagent_core::tmp::scratch("seagent-agent-vm-off");
        for c in [seagent_vm::desktop::DesktopConfig { enabled: false, ..Default::default() }, seagent_vm::desktop::DesktopConfig { autostart: false, ..Default::default() }] {
            let vms = DesktopVms::new(c, &home.join("data"), &home.join("cache"), &home.join("run"));
            assert!(spawn(vms, home.join("data")).is_none());
        }
    }
}
