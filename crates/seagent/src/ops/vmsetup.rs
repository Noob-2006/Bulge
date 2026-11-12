//! The built-in VM as the GUI shows it (setup wizard and Settings → Virtual machine): which
//! hypervisor runtime and accelerator are in use, whether the guest image is ready, which
//! sandbox the agent's tools run in right now and what that sandbox can reach — plus the
//! one-click "Set up / repair VM" (verify the bundled files, then boot a throwaway VM and run
//! `uname -a` in it) and, on Windows, the button that opens the Windows Features dialog so
//! the user can turn on "Windows Hypervisor Platform" themselves. Nothing here changes a
//! system setting, and nothing asks the user to type a command.
//!
//! Exposed as `ui.vm.*` (console, app token) and `setup.vm_*` (first-run wizard, setup token).

use seagent_kernel::config::Paths;
use seagent_vm::isolation::{Capabilities, ProviderKind};
use serde_json::{json, Value};
use std::path::Path;
use std::time::{Duration, Instant};

/// The `[exec]` config this status describes (the daemon's own file, re-read each call).
fn exec_cfg(paths: &Paths) -> seagent_tools::exec::ExecConfig {
    crate::exec_cli::exec_config(paths).unwrap_or_default()
}

/// Everything the VM panel shows.
pub fn status(paths: &Paths) -> Value {
    let cfg = exec_cfg(paths);
    let bundle = seagent_vm::bundle::locate();
    let vm_cfg = seagent_vm::bundle::apply(&cfg.vm);
    let caps = seagent_vm::policy::capabilities(&cfg.vm, &paths.data);
    let env = seagent_tools::exec::ExecEnv::new(cfg.clone());
    let plan = env.plan("main", &paths.default_workspace(), &paths.data);
    report(&vm_cfg, &caps, bundle.as_ref(), &plan, image_state(&cfg.vm, &paths.data, bundle.as_ref()))
}

/// The image the next VM would boot, verified (hashes included).
fn image_state(cfg: &seagent_vm::VmConfig, data: &Path, bundle: Option<&seagent_vm::bundle::Bundle>) -> Value {
    match seagent_vm::image::GuestImage::find(cfg, data) {
        Ok(img) => {
            let from_bundle = bundle.is_some_and(|b| img.dir == b.image_dir());
            let manifest = seagent_vm::image::sha256_file(&img.dir.join(seagent_vm::image::MANIFEST_FILE)).unwrap_or_default();
            json!({
                "state": "ready",
                "source": if from_bundle { "bundled" } else { img.manifest.source.as_str() },
                "dir": img.dir.display().to_string(),
                "manifest_sha256": manifest,
                "pinned": match seagent_vm::bundle::PINNED_MANIFEST_SHA256 { Some(p) if from_bundle && p.eq_ignore_ascii_case(&manifest) => "matches the hash this build was released with", Some(_) if from_bundle => "mismatch", Some(_) => "not the bundled image (a user-built or configured one is used)", None => "not pinned (development build)" },
                "bytes": img.manifest.kernel.size + img.manifest.initramfs.size,
            })
        }
        Err(e) => json!({"state": if bundle.is_some() { "damaged" } else { "missing" }, "detail": e}),
    }
}

/// [`status`] from parts (tests build the parts for any OS).
pub fn report(cfg: &seagent_vm::VmConfig, caps: &Capabilities, bundle: Option<&seagent_vm::bundle::Bundle>, plan: &seagent_vm::policy::Plan, image: Value) -> Value {
    let os = caps.os;
    let (want, note) = seagent_vm::provider::select(cfg, caps);
    let best = caps.best_vm();
    let accel = best.map(|(_, a)| a);
    let runtime_path = match os {
        seagent_vm::host::HostOs::Macos => caps.vfkit.clone().or_else(|| caps.qemu.clone()),
        seagent_vm::host::HostOs::Linux => caps.firecracker.clone().or_else(|| caps.qemu.clone()),
        _ => caps.qemu.clone(),
    };
    let bundled_exe = bundle.and_then(|b| b.runtime_exe());
    let runtime = json!({
        "kind": bundle.map(|b| b.info.runtime.kind.clone()).filter(|k| !k.is_empty()).unwrap_or_else(|| best.map(|(k, _)| k.name().to_string()).unwrap_or_default()),
        "path": runtime_path.as_ref().map(|p| p.display().to_string()),
        "source": match (&runtime_path, &bundled_exe) { (Some(p), Some(b)) if p == b => "bundled", (Some(_), _) => "installed on this computer", (None, _) => "missing" },
        "version": bundle.map(|b| b.info.runtime.version.clone()).unwrap_or_default(),
        "license": bundle.map(|b| b.info.runtime.license.clone()).unwrap_or_default(),
    });
    let ready = image["state"] == "ready" && best.is_some();
    let active_vm = plan.uses_microvm();
    let mut advice: Vec<Value> = vec![];
    if os == seagent_vm::host::HostOs::Windows && !caps.whpx && runtime_path.is_some() {
        advice.push(json!({
            "id": "enable_whpx",
            "text": "The VM runs without hardware acceleration (software emulation), so it is slow. Turn on “Windows Hypervisor Platform” in Windows Features and restart Windows to make it fast. SE Agent does not change this setting for you.",
            "action": "open_hypervisor_settings",
            "button": "Open Windows Features",
        }));
    }
    if os == seagent_vm::host::HostOs::Linux && !caps.kvm {
        advice.push(json!({"id": "kvm", "text": "/dev/kvm is missing or this user may not open it, so no microVM can start. Turn on virtualisation (VT-x / AMD-V) in the firmware, and ask the administrator to give this user access to KVM (the `kvm` group)."}));
    }
    if os == seagent_vm::host::HostOs::Macos && !caps.hvf {
        advice.push(json!({"id": "hvf", "text": "This Mac reports no Hypervisor.framework (kern.hv_support = 0), so the VM cannot start here."}));
    }
    if image["state"] != "ready" {
        advice.push(json!({"id": "repair", "text": "The guest image is not usable. Click “Set up / repair VM” to check the files the installer shipped; reinstalling the app restores them.", "action": "repair", "button": "Set up / repair VM"}));
    }
    let message = if active_vm {
        format!("The agent's tools run in a microVM ({} with {}).", plan.provider.as_deref().unwrap_or(want.name()), accel.map(|a| a.label()).unwrap_or("?"))
    } else if ready {
        "The microVM is ready, but the current [exec] settings choose another backend.".to_string()
    } else {
        format!("The microVM is not ready, so the agent's tools run in the {} instead ({}).", plan.level.label(), plan.backend)
    };
    json!({
        "os": os.name(),
        "arch": caps.arch,
        "bundled": bundle.is_some(),
        "bundle_dir": bundle.map(|b| b.dir.display().to_string()),
        "runtime": runtime,
        "accel": accel.map(|a| json!({"name": a.name(), "label": a.label(), "hardware": a.is_hardware()})),
        "hardware": {"whpx": caps.whpx, "hvf": caps.hvf, "kvm": caps.kvm},
        "image": image,
        "vm": {"ready": ready, "provider": best.map(|(k, _)| k.name()), "selected": want.name(), "note": note},
        "active": {"backend": plan.backend, "provider": plan.provider, "level": plan.level.label(), "microvm": active_vm, "warning": plan.warning, "reason": plan.reason},
        "reach": reach(cfg, plan),
        "advice": advice,
        "message": message,
    })
}

/// What the active sandbox can reach, in plain words.
fn reach(cfg: &seagent_vm::VmConfig, plan: &seagent_vm::policy::Plan) -> Vec<String> {
    if !plan.uses_microvm() {
        return vec![plan.warning.clone().unwrap_or_else(|| format!("{}: shares this computer's kernel", plan.backend))];
    }
    vec![
        "Its own Linux kernel; commands run as an unprivileged user (uid 1000) inside the VM.".into(),
        "Files: a copy of the workspace, synced back after each command. Your home folder, keys and other host files are not visible.".into(),
        if cfg.network == "none" {
            "Network: none.".into()
        } else {
            "Network: no direct access. Outbound requests go through SE Agent's broker and only reach allowed hosts (package registries, docs, source hosts, plus what you allow).".into()
        },
    ]
}

/// "Set up / repair VM": check the bundled runtime and image, then boot a throwaway VM and run
/// `uname -a` in it. Returns every step, the guest's answer and the fresh status.
pub fn repair(paths: &Paths) -> Value {
    let cfg = exec_cfg(paths);
    let mut steps: Vec<Value> = vec![];
    let step = |steps: &mut Vec<Value>, name: &str, r: Result<String, String>| {
        steps.push(match r {
            Ok(d) => json!({"name": name, "ok": true, "detail": d}),
            Err(e) => json!({"name": name, "ok": false, "detail": e}),
        });
    };
    match seagent_vm::bundle::locate() {
        Some(b) => {
            step(&mut steps, "bundled hypervisor files", b.verify_runtime().map(|n| format!("{n} files verified in {}", b.runtime_dir().display())));
            step(&mut steps, "bundled guest image", b.image().map(|img| format!("kernel + initramfs verified ({} bytes) in {}", img.manifest.kernel.size + img.manifest.initramfs.size, img.dir.display())));
        }
        None => step(&mut steps, "bundled VM", Err("this installation carries no bundled VM (a development build or a server install)".into())),
    }
    let all_ok = |steps: &[Value]| steps.iter().all(|s| s["ok"] == true);
    let mut uname = None;
    let mut boot_ms = None;
    if all_ok(&steps) {
        let t = Instant::now();
        match probe(&cfg.vm, &paths.data) {
            Ok((kind, out)) => {
                boot_ms = Some(t.elapsed().as_millis() as u64);
                step(&mut steps, "test VM", Ok(format!("{} booted and answered in {:.1} s", kind.name(), t.elapsed().as_secs_f64())));
                uname = Some(out.trim().to_string());
            }
            Err(e) => step(&mut steps, "test VM", Err(e)),
        }
    }
    let ok = all_ok(&steps);
    json!({"ok": ok, "steps": steps, "uname": uname, "boot_ms": boot_ms, "status": status(paths)})
}

/// Boot one VM with the agent's own settings, run `uname -a`, shut it down.
fn probe(cfg: &seagent_vm::VmConfig, data: &Path) -> Result<(ProviderKind, String), String> {
    let mgr = seagent_vm::VmManager::new(cfg.clone(), data.to_path_buf());
    let (kind, warning) = mgr.selection();
    if !kind.is_vm() {
        return Err(format!("no microVM can start here: {}", warning.unwrap_or_default()));
    }
    let ws = data.join("vm").join(format!("probe-{}", std::process::id()));
    std::fs::create_dir_all(&ws).map_err(|e| format!("{}: {e}", ws.display()))?;
    let mut req = seagent_vm::pool::VmExec::new("vm-probe", seagent_vm::trust::TrustTier::Owner, &ws, "uname -a");
    // Software emulation (no WHPX) boots in seconds, not milliseconds; give it room.
    req.timeout = Duration::from_secs(180);
    let r = mgr.exec(&req);
    mgr.shutdown_all(Duration::from_secs(10));
    let _ = std::fs::remove_dir_all(&ws);
    let out = r.map_err(|e| format!("{} VM: {e}", kind.name()))?;
    if out.code != Some(0) {
        return Err(format!("`uname -a` in the VM exited {:?}: {}", out.code, out.text()));
    }
    Ok((kind, out.text()))
}

/// The Windows Features dialog (where "Windows Hypervisor Platform" is turned on). Opening a
/// dialog is all this does; the user decides.
pub fn open_hypervisor_settings() -> Result<Value, String> {
    seagent_vm::host::open_hypervisor_settings().map(|what| json!({"opened": what}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_vm::host::{Accel, HostOs};
    use seagent_vm::policy::{Origin, Plan};
    use seagent_vm::IsolationLevel;

    fn vm_plan() -> Plan {
        Plan { backend: "vm".into(), provider: Some("qemu".into()), level: IsolationLevel::MicroVm, origin: Origin::AutoMicroVm, warning: None, reason: "auto".into() }
    }

    fn os_sandbox_plan() -> Plan {
        Plan { backend: "appcontainer".into(), provider: None, level: IsolationLevel::OsSandbox, origin: Origin::AutoFallback, warning: Some("no microVM available on this windows machine".into()), reason: "auto".into() }
    }

    fn windows(whpx: bool) -> Capabilities {
        Capabilities { os: HostOs::Windows, whpx, qemu: Some(r"C:\SE Agent\vm\runtime\qemu\qemu-system-x86_64.exe".into()), kernel: Some("k".into()), initramfs: Some("i".into()), arch: "x86_64".into(), ..Default::default() }
    }

    #[test]
    fn windows_with_whpx_reports_the_microvm_and_what_it_can_reach() {
        let v = report(&seagent_vm::VmConfig::default(), &windows(true), None, &vm_plan(), json!({"state": "ready"}));
        assert_eq!(v["vm"]["ready"], true);
        assert_eq!(v["accel"]["name"], Accel::Whpx.name());
        assert_eq!(v["active"]["microvm"], true);
        assert!(v["message"].as_str().unwrap().contains("microVM"));
        assert!(v["reach"].as_array().unwrap().iter().any(|r| r.as_str().unwrap().contains("broker")));
        assert!(v["advice"].as_array().unwrap().is_empty(), "nothing to fix: {v}");
    }

    #[test]
    fn windows_without_whpx_offers_the_windows_features_button_but_still_boots() {
        let v = report(&seagent_vm::VmConfig::default(), &windows(false), None, &vm_plan(), json!({"state": "ready"}));
        assert_eq!(v["accel"]["name"], "tcg");
        assert_eq!(v["accel"]["hardware"], false);
        let a = &v["advice"][0];
        assert_eq!(a["id"], "enable_whpx");
        assert_eq!(a["action"], "open_hypervisor_settings");
        assert!(a["text"].as_str().unwrap().contains("Windows Hypervisor Platform") && a["text"].as_str().unwrap().contains("does not change this setting"));
    }

    #[test]
    fn a_missing_image_says_which_sandbox_runs_instead_and_offers_repair() {
        let mut caps = windows(true);
        caps.kernel = None;
        let v = report(&seagent_vm::VmConfig::default(), &caps, None, &os_sandbox_plan(), json!({"state": "missing", "detail": "no guest image"}));
        assert_eq!(v["vm"]["ready"], false);
        assert_eq!(v["active"]["backend"], "appcontainer");
        let msg = v["message"].as_str().unwrap();
        assert!(msg.contains("not ready") && msg.contains("appcontainer"), "{msg}");
        assert!(v["advice"].as_array().unwrap().iter().any(|a| a["action"] == "repair"));
        assert!(!v.to_string().contains("seagent sandbox"), "no terminal command in the GUI status: {v}");
    }

    #[test]
    fn linux_and_macos_say_why_no_vm_can_start() {
        let linux = Capabilities { os: HostOs::Linux, kvm: false, firecracker: Some("/usr/lib/SE Agent/vm/runtime/firecracker/firecracker".into()), kernel: Some("k".into()), initramfs: Some("i".into()), ..Default::default() };
        let v = report(&seagent_vm::VmConfig::default(), &linux, None, &os_sandbox_plan(), json!({"state": "ready"}));
        assert_eq!(v["advice"][0]["id"], "kvm");
        assert_eq!(v["runtime"]["path"], "/usr/lib/SE Agent/vm/runtime/firecracker/firecracker");
        let mac = Capabilities { os: HostOs::Macos, hvf: true, vfkit: Some("/Applications/SE Agent.app/Contents/Resources/vm/runtime/vfkit/vfkit".into()), kernel: Some("k".into()), initramfs: Some("i".into()), ..Default::default() };
        let v = report(&seagent_vm::VmConfig::default(), &mac, None, &vm_plan(), json!({"state": "ready"}));
        assert_eq!(v["vm"]["provider"], "vfkit");
        assert_eq!(v["accel"]["name"], "hvf");
    }

    #[test]
    fn repair_without_a_bundle_says_so_and_does_not_boot() {
        let d = seagent_core::tmp::TempDir::new("seagent-vmsetup-repair");
        let paths = Paths { data: d.path().join("data"), config_dir: d.path().join("cfg"), runtime: d.path().join("run"), ..Default::default() };
        // The test binary has no bundle next to it and SEAGENT_VM_BUNDLE is not set by tests.
        if seagent_vm::bundle::locate().is_some() {
            return;
        }
        let v = repair(&paths);
        assert_eq!(v["ok"], false);
        assert_eq!(v["steps"][0]["name"], "bundled VM");
        assert!(v["uname"].is_null());
    }
}
