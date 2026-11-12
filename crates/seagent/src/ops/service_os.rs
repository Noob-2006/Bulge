//! `seagent service` backends for the systems without systemd (docs/cross-platform.md,
//! 常駐服務 row). `ops::service` keeps the systemd / OpenRC code for Linux unchanged and hands
//! every other OS to this module:
//!
//! - **macOS — launchd LaunchAgent** `~/Library/LaunchAgents/ai.seagent.seagentd.plist`
//!   (the plist text is `service::plist`), loaded with `launchctl bootstrap gui/<uid>`,
//!   removed with `bootout`, restarted with `kickstart -k`. `--system` writes a LaunchDaemon
//!   plist and prints the `sudo` commands (seagent never escalates).
//! - **Windows — Task Scheduler** (default, no admin): a per-user task `SEAgent` that starts
//!   `seagent daemon run` at logon. It is created from XML rather than `/SC ONLOGON /TR …`
//!   because only the XML form can lift the scheduler's defaults that would kill a daemon
//!   (3-day execution limit, stop on battery) and add restart-on-failure; `/Run`, `/End`,
//!   `/Delete` and `/Query` manage it. **`--system` — a real Windows Service** `SEAgent`
//!   (`sc.exe create … binPath= "<exe> daemon service" start= auto`, restart on failure), which
//!   needs an elevated prompt; `daemon service` is the SCM entry point (`ops::winservice`).
//! - **Android** — the daemon lives in the host app's foreground service; **iOS** — no
//!   background daemon at all (the app is the agent). Both answer with an explicit error.
//!
//! The text builders (task XML, `sc.exe` argv, names) are pure and tested on every host
//! (on Linux nothing else here is used, and the Windows builders only on Windows: the `allow`).

#![cfg_attr(not(any(target_os = "macos", windows, target_os = "android", target_os = "ios")), allow(dead_code, unused_imports))]
// (the Linux case is covered by the line above; one `allow` per target keeps clippy quiet)
#![cfg_attr(any(target_os = "macos", target_os = "android", target_os = "ios"), allow(dead_code))]

use crate::ops::service::Issue;
#[cfg(any(target_os = "macos", windows, target_os = "android", target_os = "ios"))]
use crate::{args::Args, R};
#[cfg(any(target_os = "macos", windows, target_os = "android", target_os = "ios"))]
use seagent_kernel::config::Paths;
use std::path::Path;
#[cfg(target_os = "macos")]
use std::path::PathBuf;

#[cfg(any(windows, target_os = "macos"))]
fn run(prog: &str, args: &[&str]) -> Result<String, String> {
    let o = seagent_core::platform::proc::command(prog).args(args).stdin(std::process::Stdio::null()).output().map_err(|e| format!("{prog}: {e}"))?;
    let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    if o.status.success() {
        Ok(text)
    } else {
        Err(format!("`{prog} {}` failed: {}", args.join(" "), text.trim()))
    }
}

/// The daemon's arguments after the program: `[-p NAME] daemon <verb> -w WS`.
pub fn daemon_args(verb: &str, workspace: &Path) -> Vec<String> {
    let mut v = vec![];
    if let Some(p) = crate::ops::service::profile_arg().strip_prefix(" -p ") {
        v.extend(["-p".to_string(), p.to_string()]);
    }
    v.extend(["daemon".into(), verb.into(), "-w".into(), workspace.display().to_string()]);
    v
}

// ───────────────────────── Windows ─────────────────────────

/// Task / service name: `SEAgent`, or `SEAgent-<profile>` (one per profile, like the units).
pub fn windows_name() -> String {
    match crate::ops::service::unit_name().trim_end_matches(".service").strip_prefix("seagentd-") {
        Some(p) => format!("SEAgent-{p}"),
        None => "SEAgent".into(),
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Task Scheduler definition: at logon of `user`, least privilege, no time limit, keep running
/// on battery, restart three times a minute apart after a crash, never two at once.
pub fn task_xml(exe: &Path, workspace: &Path, user: &str) -> String {
    let args: Vec<String> = daemon_args("run", workspace).iter().map(|a| seagent_core::platform::term::windows_quote(a)).collect();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>
<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">
  <RegistrationInfo>
    <Description>SE Agent daemon (seagent service install)</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id=\"Author\">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context=\"Author\">
    <Exec>
      <Command>{exe}</Command>
      <Arguments>{args}</Arguments>
      <WorkingDirectory>{ws}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
",
        user = xml_escape(user),
        exe = xml_escape(&exe.display().to_string()),
        args = xml_escape(&args.join(" ")),
        ws = xml_escape(&workspace.display().to_string()),
    )
}

/// `sc.exe` argv that registers the Windows Service (auto start; the SCM runs
/// `<exe> daemon service`). `sc.exe` wants `key=` and the value as separate arguments.
pub fn sc_create_args(name: &str, exe: &Path, workspace: &Path) -> Vec<String> {
    let mut cmdline = vec![seagent_core::platform::term::windows_quote(&exe.display().to_string())];
    cmdline.extend(daemon_args("service", workspace).iter().map(|a| seagent_core::platform::term::windows_quote(a)));
    vec!["create".into(), name.into(), "binPath=".into(), cmdline.join(" "), "start=".into(), "auto".into(), "DisplayName=".into(), "SE Agent daemon".into()]
}

/// Restart the service 5 s after the first two crashes and 60 s after later ones.
pub fn sc_failure_args(name: &str) -> Vec<String> {
    ["failure", name, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/60000"].iter().map(|s| s.to_string()).collect()
}

#[cfg(windows)]
mod win {
    use super::*;

    pub fn current_user() -> String {
        let user = std::env::var("USERNAME").unwrap_or_else(|_| seagent_core::platform::sysinfo::current_user());
        match std::env::var("USERDOMAIN").ok().filter(|d| !d.is_empty()) {
            Some(d) => format!("{d}\\{user}"),
            None => user,
        }
    }

    fn schtasks(args: &[&str]) -> Result<String, String> {
        run("schtasks.exe", args)
    }

    fn sc(args: &[&str]) -> Result<String, String> {
        run("sc.exe", args)
    }

    pub fn task_exists() -> bool {
        schtasks(&["/Query", "/TN", &windows_name()]).is_ok()
    }

    pub fn service_exists() -> bool {
        sc(&["query", &windows_name()]).is_ok()
    }

    /// schtasks reads task XML most reliably as UTF-16LE with a BOM.
    fn write_utf16(p: &Path, text: &str) -> Result<(), String> {
        let mut b = vec![0xFF, 0xFE];
        for u in text.encode_utf16() {
            b.extend(u.to_le_bytes());
        }
        std::fs::write(p, b).map_err(|e| format!("{}: {e}", p.display()))
    }

    pub fn install_task(ws: &Path, start: bool) -> Result<String, String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let name = windows_name();
        let xml = seagent_core::tmp::scratch_path(format!("seagent-task-{}.xml", std::process::id()));
        write_utf16(&xml, &task_xml(&exe, ws, &current_user()))?;
        let r = schtasks(&["/Create", "/TN", &name, "/XML", &xml.to_string_lossy(), "/F"]);
        let _ = std::fs::remove_file(&xml);
        r?;
        let mut msg = format!("created the Task Scheduler task `{name}`: seagent daemon run at every logon (per user, least privilege, restarts after a crash)");
        if start {
            schtasks(&["/Run", "/TN", &name])?;
            msg.push_str(&format!("\n`{name}` started"));
        }
        Ok(msg)
    }

    pub fn install_service(ws: &Path) -> Result<String, String> {
        if !seagent_core::platform::sysinfo::is_root() {
            return Err("installing a Windows Service needs an elevated prompt (Run as administrator). Without admin rights use `seagent service install`, which starts the daemon at logon through Task Scheduler.".into());
        }
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let name = windows_name();
        let create: Vec<String> = sc_create_args(&name, &exe, ws);
        sc(&create.iter().map(String::as_str).collect::<Vec<_>>())?;
        let _ = sc(&["description", &name, "SE Agent daemon (seagent daemon service)"]);
        let fail: Vec<String> = sc_failure_args(&name);
        let _ = sc(&fail.iter().map(String::as_str).collect::<Vec<_>>());
        sc(&["start", &name])?;
        Ok(format!("installed and started the Windows Service `{name}` (automatic start, LocalSystem account: it keeps its own state under the system profile; configure it with `seagent setup` from an elevated prompt)"))
    }

    pub fn uninstall(system: bool) -> Result<String, String> {
        let name = windows_name();
        if system {
            let _ = sc(&["stop", &name]);
            sc(&["delete", &name])?;
            return Ok(format!("removed the Windows Service `{name}`"));
        }
        let _ = schtasks(&["/End", "/TN", &name]);
        schtasks(&["/Delete", "/TN", &name, "/F"])?;
        Ok(format!("removed the Task Scheduler task `{name}`"))
    }

    pub fn status(system: bool) -> Result<String, String> {
        let name = windows_name();
        if system || (!task_exists() && service_exists()) {
            return sc(&["query", &name]);
        }
        if !task_exists() {
            return Ok("not installed (seagent service install)".into());
        }
        schtasks(&["/Query", "/TN", &name, "/V", "/FO", "LIST"])
    }

    pub fn restart() -> Result<(), String> {
        let name = windows_name();
        if service_exists() {
            let _ = sc(&["stop", &name]);
            for _ in 0..60 {
                if sc(&["query", &name]).is_ok_and(|s| s.contains("STOPPED")) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            return sc(&["start", &name]).map(|_| ());
        }
        let _ = schtasks(&["/End", "/TN", &name]);
        schtasks(&["/Run", "/TN", &name]).map(|_| ())
    }

    pub fn audit() -> Vec<Issue> {
        let name = windows_name();
        let Ok(xml) = schtasks(&["/Query", "/TN", &name, "/XML"]) else {
            if service_exists() {
                return vec![];
            }
            return vec![Issue { code: "unit-missing", message: format!("the Task Scheduler task `{name}` is not installed (seagent service install)"), fix: None }];
        };
        let exe = std::env::current_exe().unwrap_or_default();
        let cmd = xml.split("<Command>").nth(1).and_then(|s| s.split("</Command>").next()).unwrap_or("").replace("&amp;", "&");
        let mut v = vec![];
        if cmd.is_empty() {
            v.push(Issue { code: "unit-no-execstart", message: format!("task `{name}` has no command"), fix: Some("reinstall") });
        } else if !Path::new(&cmd).exists() {
            v.push(Issue { code: "unit-binary-missing", message: format!("task `{name}` runs {cmd}, which does not exist"), fix: Some("reinstall") });
        } else if Path::new(&cmd).canonicalize().ok() != exe.canonicalize().ok() {
            v.push(Issue { code: "unit-binary-stale", message: format!("task `{name}` runs {cmd}, not this seagent ({})", exe.display()), fix: Some("reinstall") });
        }
        if !xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>") {
            v.push(Issue { code: "unit-stop-timeout", message: format!("task `{name}` has an execution time limit: Task Scheduler would stop the daemon"), fix: Some("reinstall") });
        }
        v
    }
}

// ───────────────────────── macOS ─────────────────────────

/// `~/Library/LaunchAgents/<label>.plist`.
#[cfg(target_os = "macos")]
fn agent_plist() -> PathBuf {
    seagent_core::layout::home().join("Library").join("LaunchAgents").join(format!("{}.plist", crate::ops::service::launchd_label()))
}

#[cfg(target_os = "macos")]
mod mac {
    use super::*;

    pub fn domain() -> String {
        format!("gui/{}", seagent_core::platform::sysinfo::current_uid().unwrap_or(0))
    }

    pub fn target() -> String {
        format!("{}/{}", domain(), crate::ops::service::launchd_label())
    }

    pub fn loaded() -> bool {
        run("launchctl", &["print", &target()]).is_ok()
    }

    pub fn install(ws: &Path, start: bool) -> Result<String, String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let p = agent_plist();
        let log = Paths::from_env().daemon_log();
        std::fs::create_dir_all(p.parent().unwrap_or(Path::new("."))).map_err(|e| e.to_string())?;
        std::fs::write(&p, crate::ops::service::plist(&exe, ws, &log)).map_err(|e| format!("{}: {e}", p.display()))?;
        let mut msg = format!("wrote {}", p.display());
        if start {
            // A loaded agent keeps its old definition: unload first (fails harmlessly when not loaded).
            let _ = run("launchctl", &["bootout", &target()]);
            run("launchctl", &["bootstrap", &domain(), &p.to_string_lossy()])?;
            msg.push_str(&format!("\nloaded into launchd ({}): it starts now and at every login", target()));
        }
        Ok(msg)
    }

    pub fn audit() -> Vec<Issue> {
        let p = agent_plist();
        let Ok(installed) = std::fs::read_to_string(&p) else {
            return vec![Issue { code: "unit-missing", message: format!("{} is not installed (seagent service install)", p.display()), fix: None }];
        };
        let exe = std::env::current_exe().unwrap_or_default();
        let bin = installed.split("<key>ProgramArguments</key>").nth(1).and_then(|s| s.split("<string>").nth(1)).and_then(|s| s.split("</string>").next()).unwrap_or("").replace("&amp;", "&");
        let mut v = vec![];
        if bin.is_empty() || !Path::new(&bin).exists() {
            v.push(Issue { code: "unit-binary-missing", message: format!("{} runs `{bin}`, which does not exist", p.display()), fix: Some("reinstall") });
        } else if Path::new(&bin).canonicalize().ok() != exe.canonicalize().ok() {
            v.push(Issue { code: "unit-binary-stale", message: format!("{} runs {bin}, not this seagent ({})", p.display(), exe.display()), fix: Some("reinstall") });
        }
        if !loaded() {
            v.push(Issue { code: "linger-off", message: format!("{} is not loaded in launchd (seagent service install)", crate::ops::service::launchd_label()), fix: Some("reinstall") });
        }
        v
    }
}

// ───────────────────────── entry points used by ops::service ─────────────────────────

#[cfg(target_os = "android")]
const MOBILE: &str = "on Android the SE Agent daemon is managed by the host app (a foreground service); install and start it from the SE Agent app";
#[cfg(target_os = "ios")]
const MOBILE: &str = "handled by the app on iOS: the agent runs inside the SE Agent app's own process (it starts with the app, and in iOS background tasks for schedules); there is no separate daemon to install";

/// Install the per-user autostart (`start`: also start it now).
#[cfg(any(target_os = "macos", windows, target_os = "android", target_os = "ios"))]
pub fn install_user(ws: &Path, start: bool) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    return mac::install(ws, start);
    #[cfg(windows)]
    return win::install_task(ws, start);
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let _ = (ws, start);
        Err(MOBILE.into())
    }
}

/// The installed autostart, audited like the systemd unit.
#[cfg(any(target_os = "macos", windows, target_os = "android", target_os = "ios"))]
pub fn audit(_ws: &Path) -> Vec<Issue> {
    #[cfg(target_os = "macos")]
    return mac::audit();
    #[cfg(windows)]
    return win::audit();
    #[cfg(any(target_os = "android", target_os = "ios"))]
    vec![]
}

/// The service manager runs the daemon (so a restart goes through it).
#[cfg(any(target_os = "macos", windows, target_os = "android", target_os = "ios"))]
pub fn managed() -> bool {
    #[cfg(target_os = "macos")]
    return mac::loaded();
    #[cfg(windows)]
    return win::task_exists() || win::service_exists();
    #[cfg(any(target_os = "android", target_os = "ios"))]
    false
}

/// Restart through the service manager.
#[cfg(any(target_os = "macos", windows, target_os = "android", target_os = "ios"))]
pub fn restart_managed() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    return run("launchctl", &["kickstart", "-k", &mac::target()]).map(|_| ());
    #[cfg(windows)]
    return win::restart();
    #[cfg(any(target_os = "android", target_os = "ios"))]
    Err(MOBILE.into())
}

/// Step 7 of the setup wizard ("start at boot") on this OS.
#[cfg(any(target_os = "macos", windows, target_os = "android", target_os = "ios"))]
pub fn autostart(paths: &Paths) -> String {
    // The workspace the wizard just saved (`[app] workspace`), else the default one — never the
    // daemon's working directory, which for the desktop app is its install folder.
    let ws = std::fs::read_to_string(paths.user_config())
        .ok()
        .and_then(|t| t.parse::<toml::Table>().ok())
        .and_then(|r| r.get("app").and_then(|a| a.get("workspace")).and_then(|v| v.as_str()).map(std::path::PathBuf::from))
        .unwrap_or_else(|| paths.default_workspace());
    #[cfg(any(target_os = "macos", windows))]
    {
        if managed() {
            return "autostart enabled (already installed)".into();
        }
        match install_user(&ws, false) {
            Ok(m) => format!("autostart enabled · {}", m.lines().next().unwrap_or("")),
            Err(e) => format!("autostart failed: {e}"),
        }
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let _ = ws;
        MOBILE.into()
    }
}

/// Lines for `seagent doctor` on this OS: the shell, the control endpoint, the autostart and
/// the VM providers that isolation can use here.
#[cfg(not(target_os = "linux"))]
pub fn doctor_checks(paths: &seagent_kernel::config::Paths) -> Vec<(String, Result<String, String>)> {
    let mut v: Vec<(String, Result<String, String>)> = vec![];
    let have = |b: &str| seagent_core::platform::layout::which(b).map(|p| p.display().to_string());
    #[cfg(windows)]
    {
        let sh = seagent_core::platform::shell::active();
        v.push(("shell".into(), Ok(format!("{} ({}; {})", sh.kind.as_str(), sh.program.display(), sh.reason))));
        v.push(("control endpoint".into(), Ok(format!("named pipe {}", seagent_core::platform::ipc::endpoint_display(&paths.socket())))));
        let name = windows_name();
        v.push((
            "autostart".into(),
            if win::service_exists() {
                Ok(format!("Windows Service `{name}`"))
            } else if win::task_exists() {
                Ok(format!("Task Scheduler task `{name}` (at logon)"))
            } else {
                Err("not installed: `seagent service install` (Task Scheduler, no admin) or `seagent service install --system` (Windows Service, elevated)".into())
            },
        ));
        let _ = &have;
        v.extend(windows_vm_checks(paths));
    }
    #[cfg(target_os = "macos")]
    {
        v.push(("control endpoint".into(), Ok(format!("unix socket {}", paths.socket().display()))));
        v.push(("launchd agent".into(), if mac::loaded() { Ok(mac::target()) } else if agent_plist().exists() { Err(format!("{} exists but is not loaded (seagent service install)", agent_plist().display())) } else { Err("not installed (seagent service install)".into()) }));
        let vms: Vec<&str> = [("vfkit", "vfkit (Virtualization.framework)"), ("qemu-system-aarch64", "QEMU (HVF)"), ("qemu-system-x86_64", "QEMU (HVF)")].iter().filter(|(b, _)| have(b).is_some()).map(|(_, n)| *n).collect();
        v.push(("VM providers".into(), if vms.is_empty() { Err("none found (install vfkit or QEMU for microVM isolation)".into()) } else { Ok(vms.join(", ")) }));
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let _ = (paths, &have);
        v.push(("autostart".into(), Ok(MOBILE.into())));
    }
    v
}

/// The microVM side of `seagent doctor` on Windows, from the same selection the VM backend
/// makes (`seagent_vm::provider::select` over `seagent_vm::policy::capabilities`): the provider
/// `exec.vm` picks and its accelerator, then each substitute's own state — WHPX probed through
/// `WinHvPlatform.dll`, Hyper-V by edition / service / module, VirtualBox and QEMU by binary.
/// (Before, this was a PATH lookup that missed `C:\Program Files\qemu` and took the
/// container tool `hcsdiag` for Hyper-V.)
#[cfg(windows)]
fn windows_vm_checks(paths: &Paths) -> Vec<(String, Result<String, String>)> {
    use seagent_vm::host::Accel;
    let cfg = crate::exec_cli::exec_config(paths).map(|c| c.vm).unwrap_or_default();
    let caps = seagent_vm::policy::capabilities(&cfg, &paths.data);
    let (kind, warning) = seagent_vm::provider::select(&cfg, &caps);
    let accel = seagent_vm::provider::accel_of(kind, &caps);
    let mut v: Vec<(String, Result<String, String>)> = vec![];
    v.push((
        "VM provider".into(),
        match accel {
            Some(Accel::Tcg) => Err(format!("{} (accelerator: {}) — {}", kind.name(), Accel::Tcg.label(), warning.unwrap_or_default())),
            Some(a) => Ok(format!("{} (accelerator: {})", kind.name(), a.label())),
            None => Err(format!("no microVM ({}): {}", kind.name(), seagent_vm::policy::blockers(&caps))),
        },
    ));
    let hw = accel.is_some_and(|a| a.is_hardware());
    v.push((
        "  WHPX (Windows Hypervisor Platform)".into(),
        if caps.whpx {
            Ok("available (WHvGetCapability: hypervisor present) → qemu -accel whpx".into())
        } else {
            Err("unavailable: turn on the optional feature \"Windows Hypervisor Platform\" (Settings → System → Optional features → More Windows features, or elevated `dism /online /enable-feature /featurename:HypervisorPlatform`), then reboot".into())
        },
    ));
    v.push((
        "  Hyper-V".into(),
        match (&caps.hyperv, &caps.hyperv_blocker) {
            (Some(_), _) => Ok("installed (VM creation needs an elevated session or Hyper-V Administrators)".into()),
            (None, Some(why)) if hw => Ok(why.clone()),
            (None, why) => Err(why.clone().unwrap_or_else(|| "not installed".into())),
        },
    ));
    let bin = |p: &Option<std::path::PathBuf>, missing: &str| p.as_ref().map(|p| p.display().to_string()).ok_or_else(|| missing.to_string());
    v.push(("  QEMU".into(), bin(&caps.qemu, "qemu-system-x86_64 not found (winget install SoftwareFreedomConservancy.QEMU)")));
    let vbox = bin(&caps.vbox, "VBoxManage not found");
    v.push(("  VirtualBox".into(), if hw { Ok(vbox.unwrap_or_else(|e| e)) } else { vbox }));
    v.push((
        "  guest image".into(),
        match (&caps.kernel, &caps.initramfs) {
            (Some(k), Some(_)) => Ok(format!("{} (+ initramfs{})", k.display(), if caps.disk_image.is_some() { ", disk.raw" } else { "" })),
            _ => Err("not built: `seagent sandbox vm image build`, or copy vmlinux + initramfs.cpio.gz (+ manifest.json) into <data>\\vm\\image".into()),
        },
    ));
    v
}

/// `seagent service <sub>` on this OS.
#[cfg(any(target_os = "macos", windows, target_os = "android", target_os = "ios"))]
// Mobile: the early `return` is the whole body (the desktop arms below are cfg'd out).
#[cfg_attr(any(target_os = "android", target_os = "ios"), allow(clippy::needless_return))]
pub fn dispatch(sub: &str, a: &Args, paths: &Paths) -> R {
    let system = a.flag("system");
    // The early `return` ends the function on mobile, where the desktop `match` below is cfg'd out.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    #[allow(clippy::needless_return)]
    {
        let _ = (system, paths);
        return match sub {
            "status" | "audit" => {
                println!("{MOBILE}");
                Ok(0)
            }
            "logs" => crate::ops::logs::show(a),
            _ => Err(MOBILE.to_string().into()),
        };
    }
    #[cfg(any(target_os = "macos", windows))]
    match sub {
        "install" => {
            let ws = crate::workspace(a)?;
            #[cfg(windows)]
            let msg = if system { win::install_service(&ws)? } else { install_user(&ws, !a.flag("no-start"))? };
            #[cfg(target_os = "macos")]
            let msg = if system { mac_system_daemon(&ws, paths)? } else { install_user(&ws, !a.flag("no-start"))? };
            println!("{msg}");
            Ok(0)
        }
        "uninstall" => {
            #[cfg(windows)]
            println!("{}", win::uninstall(system)?);
            #[cfg(target_os = "macos")]
            {
                if system {
                    println!("run: sudo launchctl bootout system/{0} && sudo rm /Library/LaunchDaemons/{0}.plist", crate::ops::service::launchd_label());
                    return Ok(0);
                }
                let _ = run("launchctl", &["bootout", &mac::target()]);
                let p = agent_plist();
                let _ = std::fs::remove_file(&p);
                println!("removed {}", p.display());
            }
            Ok(0)
        }
        "status" => {
            #[cfg(windows)]
            println!("{}", win::status(system)?.trim_end());
            #[cfg(target_os = "macos")]
            match run("launchctl", &["print", &mac::target()]) {
                Ok(s) => println!("{}", s.trim_end()),
                Err(_) if agent_plist().exists() => println!("{} is installed but not loaded (seagent service install)", agent_plist().display()),
                Err(_) => println!("not installed (seagent service install)"),
            }
            Ok(0)
        }
        "print" => {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let ws = crate::workspace(a)?;
            #[cfg(windows)]
            if system {
                println!("sc.exe {}", sc_create_args(&windows_name(), &exe, &ws).iter().map(|s| seagent_core::platform::term::windows_quote(s)).collect::<Vec<_>>().join(" "));
            } else {
                print!("{}", task_xml(&exe, &ws, &win::current_user()));
            }
            #[cfg(target_os = "macos")]
            print!("{}", crate::ops::service::plist(&exe, &ws, &paths.daemon_log()));
            Ok(0)
        }
        "restart" => {
            let drain = a.num::<u64>("drain").map_err(crate::Fail::Usage)?.unwrap_or(60);
            println!("{}", crate::ops::service::restart(paths, std::time::Duration::from_secs(drain))?);
            Ok(0)
        }
        "logs" => crate::ops::logs::show(a),
        "audit" => {
            let issues = audit(&crate::workspace(a)?);
            for i in &issues {
                println!("✗ [{}] {}", i.code, i.message);
            }
            if issues.is_empty() {
                println!("✓ the installed autostart matches this seagent");
            } else if issues.iter().any(|i| i.fix == Some("reinstall")) {
                println!("fix: seagent service install");
            }
            Ok(if issues.is_empty() { 0 } else { 1 })
        }
        other => crate::usage(format!("unknown `service {other}` (install [--system] [--no-start], uninstall [--system], status, print [--system], restart [--drain S], logs, audit)")),
    }
}

/// macOS `--system`: a LaunchDaemon plist written next to us, with the `sudo` steps printed.
#[cfg(target_os = "macos")]
fn mac_system_daemon(ws: &Path, paths: &Paths) -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let label = crate::ops::service::launchd_label();
    let f = seagent_core::tmp::scratch_path(format!("{label}.plist"));
    std::fs::write(&f, crate::ops::service::plist(&exe, ws, &paths.daemon_log())).map_err(|e| format!("{}: {e}", f.display()))?;
    Ok(format!("wrote {} — seagent does not run sudo itself; install it as a LaunchDaemon with:\n  sudo install -m 0644 {} /Library/LaunchDaemons/{label}.plist\n  sudo launchctl bootstrap system /Library/LaunchDaemons/{label}.plist", f.display(), f.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_task_and_service_definitions() {
        let exe = Path::new("C:\\Program Files\\SE Agent\\seagent.exe");
        let ws = Path::new("C:\\Users\\amy\\work & play");
        let x = task_xml(exe, ws, "PC\\amy");
        for want in ["<LogonTrigger>", "<UserId>PC\\amy</UserId>", "<RunLevel>LeastPrivilege</RunLevel>", "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>", "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>", "<RestartOnFailure>", "<Command>C:\\Program Files\\SE Agent\\seagent.exe</Command>", "work &amp; play</WorkingDirectory>"] {
            assert!(x.contains(want), "task XML lacks {want}:\n{x}");
        }
        assert!(x.contains("daemon run -w &quot;C:\\Users\\amy\\work &amp; play&quot;</Arguments>"), "{x}");
        let sc = sc_create_args("SEAgent", exe, ws);
        assert_eq!(&sc[..4], ["create", "SEAgent", "binPath=", "\"C:\\Program Files\\SE Agent\\seagent.exe\" daemon service -w \"C:\\Users\\amy\\work & play\""]);
        assert_eq!(&sc[4..6], ["start=", "auto"]);
        assert!(sc_failure_args("SEAgent").contains(&"restart/5000/restart/5000/restart/60000".to_string()));
        assert!(windows_name().starts_with("SEAgent"));
    }
}
