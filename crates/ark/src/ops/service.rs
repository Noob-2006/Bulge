//! Service management (OpenClaw `daemon install` + service audit + restart-storm guard,
//! Hermes `gateway install/uninstall/status/restart`).
//!
//! - systemd user unit (default) or system unit (`--system`, `User=` set; needs root — ark
//!   never escalates, it prints the `sudo` commands instead).
//! - launchd agent plist (`--launchd`; installed with `launchctl` on macOS, printed elsewhere).
//! - Windows schtasks: N/A — ark has no Windows build (unix sockets, POSIX signals).
//! - One unit per profile: `arkd.service`, `arkd-<profile>.service`.
//! - `audit` compares the installed unit with what this version would write.
//! - Restart storms: each daemon start is logged to `<data>/restarts.log`; three or more
//!   within ten minutes print a warning (also shown by `ark doctor`).
//! - `restart --drain SECS`: wait for running turns to finish, then restart.

use crate::args::Args;
use crate::{usage, R};
use ark_kernel::config::Paths;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const COMMANDS: &[&str] = &["service"];
pub const VALUE_FLAGS: &[&str] = &["drain", "lines", "user-name"];
pub const BOOL_FLAGS: &[&str] = &["system", "launchd", "sysusers", "tmpfiles"];

pub const STORM_WINDOW_SECS: i64 = 600;
pub const STORM_THRESHOLD: usize = 3;

pub fn unit_name() -> String {
    match crate::ops::profile::current().as_str() {
        "default" | "custom ARK_HOME" => "arkd.service".into(),
        p => format!("arkd-{p}.service"),
    }
}

fn profile_arg() -> String {
    match crate::ops::profile::current().as_str() {
        "default" | "custom ARK_HOME" => String::new(),
        p => format!(" -p {p}"),
    }
}

pub fn user_unit_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config")).join("systemd/user")
}

/// Where a system instance keeps everything (`StateDirectory=ark`).
pub const SYSTEM_HOME: &str = "/var/lib/ark";
/// The dedicated system account of the system service (created by `sysusers.d`).
pub const SYSTEM_USER: &str = "ark";
/// Default workspace of the system instance.
pub const SYSTEM_WORKSPACE: &str = "/var/lib/ark/workspace";

/// The systemd unit. `user` = `Some(name)` for a system unit (dedicated account, state under
/// `/var/lib/ark`, sandboxing that only a system manager can apply).
///
/// This is the one source of unit text: `packaging/systemd/*.service` are generated from it
/// (`ARK_BLESS=1 cargo test -p ark packaged_units` rewrites them), and `nix/nixos.nix` is checked
/// against the same hardening list by a test.
pub fn unit(exe: &Path, workspace: &Path, user: Option<&str>) -> String {
    let home_env = std::env::var("ARK_HOME").ok().filter(|_| crate::ops::profile::current() == "custom ARK_HOME").map(|h| format!("Environment=ARK_HOME={h}\n")).unwrap_or_default();
    render_unit(exe, workspace, user, &profile_arg(), &home_env)
}

/// Pure renderer behind [`unit`] (`prof` = ` -p name` or empty, `home_env` = an `Environment=` line).
pub fn render_unit(exe: &Path, workspace: &Path, user: Option<&str>, prof: &str, home_env: &str) -> String {
    let (who, target, sandbox) = match user {
        Some(u) => (
            format!("User={u}\nGroup={u}\nStateDirectory=ark ark/workspace\nStateDirectoryMode=0750\nEnvironment=ARK_HOME={SYSTEM_HOME}\n"),
            "multi-user.target",
            "# A system manager can apply the full sandbox (user units cannot without user namespaces).
PrivateTmp=yes
ProtectSystem=full
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
# Not set on purpose: MemoryDenyWriteExecute (breaks Node/V8 bridges), ProtectHome and
# RestrictNamespaces (the sandboxes ark may run need them).
",
        ),
        None => (
            String::new(),
            "default.target",
            "# Not set on purpose: MemoryDenyWriteExecute (breaks Node/V8 bridges), ProtectHome (ark works
# in $HOME), RestrictNamespaces (breaks sandboxes ark may run). PrivateTmp/ProtectKernel* need
# unprivileged user namespaces in user units; enable them in a drop-in if your distro allows.
",
        ),
    };
    let home_env = if user.is_some() { "" } else { home_env };
    format!(
        "[Unit]
Description=ark agent daemon{desc}
Documentation=https://github.com/ark-agent/ark
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=notify
NotifyAccess=main
{who}{home_env}ExecStart={exe}{prof} daemon run -w {ws}
WorkingDirectory={ws}
Restart=on-failure
RestartSec=5s
# SIGTERM to arkd first (it interrupts runs and saves state), then the rest of the group.
KillMode=mixed
TimeoutStopSec=30s
# ark refuses sudo by policy; make that impossible rather than merely discouraged.
NoNewPrivileges=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
RestrictRealtime=yes
UMask=0077
{sandbox}
[Install]
WantedBy={target}
",
        desc = if user.is_some() { " (system)" } else { "" },
        exe = exe.display(),
        ws = workspace.display(),
    )
}

/// `sysusers.d` entry creating the dedicated account (`systemd-sysusers`).
pub fn sysusers(user: &str) -> String {
    format!("# ark agent daemon: dedicated system account (systemd-sysusers)\nu {user} - \"ark agent\" {SYSTEM_HOME} /usr/sbin/nologin\n")
}

/// `tmpfiles.d` entry for the system instance's directories (also created by `StateDirectory=`).
pub fn tmpfiles(user: &str) -> String {
    format!("# ark agent daemon: state and workspace of the system instance\nd {SYSTEM_HOME} 0750 {user} {user} -\nd {SYSTEM_WORKSPACE} 0750 {user} {user} -\n")
}

pub fn launchd_label() -> String {
    format!("ai.ark.{}", unit_name().trim_end_matches(".service"))
}

/// launchd LaunchAgent: keep alive on crash, log to the data dir.
pub fn plist(exe: &Path, workspace: &Path, log: &Path) -> String {
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let mut args = vec![exe.display().to_string()];
    if let Some(p) = profile_arg().strip_prefix(" -p ") {
        args.extend(["-p".to_string(), p.to_string()]);
    }
    args.extend(["daemon".into(), "run".into(), "-w".into(), workspace.display().to_string()]);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key><string>{}</string>\n  <key>ProgramArguments</key>\n  <array>\n{}  </array>\n  <key>WorkingDirectory</key><string>{}</string>\n  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n  <key>ThrottleInterval</key><integer>5</integer>\n  <key>ExitTimeOut</key><integer>30</integer>\n  <key>StandardOutPath</key><string>{log}</string>\n  <key>StandardErrorPath</key><string>{log}</string>\n</dict>\n</plist>\n",
        launchd_label(),
        args.iter().map(|a| format!("    <string>{}</string>\n", esc(a))).collect::<String>(),
        esc(&workspace.display().to_string()),
        log = esc(&log.display().to_string()),
    )
}

fn systemctl(system: bool, args: &[&str]) -> bool {
    let mut c = std::process::Command::new("systemctl");
    if !system {
        c.arg("--user");
    }
    c.args(args).status().map(|s| s.success()).unwrap_or(false)
}

// ───────────── restart storms ─────────────

fn restarts_log(paths: &Paths) -> PathBuf {
    paths.data.join("restarts.log")
}

/// Starts within the window, newest last.
pub fn recent_starts(paths: &Paths, now: i64) -> Vec<i64> {
    let text = std::fs::read_to_string(restarts_log(paths)).unwrap_or_default();
    text.lines().filter_map(|l| l.strip_prefix('[')?.split(']').next()?.parse::<i64>().ok()).filter(|t| now - t < STORM_WINDOW_SECS && *t <= now).collect()
}

/// Called at daemon start: log it, and warn when starts pile up (crash loop).
pub fn record_start(paths: &Paths) -> Option<String> {
    let now = ark_kernel::util::unix_now();
    let p = restarts_log(paths);
    let _ = std::fs::create_dir_all(&paths.data);
    let old = std::fs::read_to_string(&p).unwrap_or_default();
    // Keep the log small: the last 200 lines.
    let mut lines: Vec<&str> = old.lines().collect();
    let skip = lines.len().saturating_sub(199);
    lines.drain(..skip);
    let entry = format!("[{now}] start pid={} version={}", std::process::id(), env!("CARGO_PKG_VERSION"));
    let _ = std::fs::write(&p, format!("{}{entry}\n", lines.iter().map(|l| format!("{l}\n")).collect::<String>()));
    let n = recent_starts(paths, now).len();
    (n >= STORM_THRESHOLD).then(|| format!("restart storm: arkd started {n} times in the last {} minutes — check `ark logs` / `ark service logs` for the crash", STORM_WINDOW_SECS / 60))
}

// ───────────── audit ─────────────

#[derive(Debug, Clone, PartialEq)]
pub struct Issue {
    pub code: &'static str,
    pub message: String,
    pub fix: Option<&'static str>,
}

fn directive<'a>(text: &'a str, key: &str) -> Vec<&'a str> {
    text.lines().filter_map(|l| l.trim().strip_prefix(key)?.strip_prefix('=')).map(str::trim).collect()
}

fn secs(v: &str) -> Option<u64> {
    let v = v.trim();
    if let Some(m) = v.strip_suffix("min") {
        return m.trim().parse::<u64>().ok().map(|x| x * 60);
    }
    v.trim_end_matches('s').trim().parse().ok()
}

/// Audit an installed unit's text against expectations.
pub fn audit_text(installed: &str, expected: &str, exe: &Path) -> Vec<Issue> {
    let mut v = vec![];
    let mut add = |code, message: String, fix| v.push(Issue { code, message, fix });
    let exec = directive(installed, "ExecStart").first().map(|s| s.to_string()).unwrap_or_default();
    let bin = exec.split_whitespace().next().unwrap_or("");
    if bin.is_empty() {
        add("unit-no-execstart", "unit has no ExecStart".into(), Some("reinstall"));
    } else if !Path::new(bin).exists() {
        add("unit-binary-missing", format!("ExecStart points at {bin}, which does not exist"), Some("reinstall"));
    } else if Path::new(bin).canonicalize().ok() != exe.canonicalize().ok() {
        add("unit-binary-stale", format!("ExecStart runs {bin}, not this ark ({})", exe.display()), Some("reinstall"));
    }
    if !directive(installed, "After").iter().any(|a| a.contains("network-online.target")) {
        add("unit-after-network", "missing After=network-online.target".into(), Some("reinstall"));
    }
    if !directive(installed, "Wants").iter().any(|a| a.contains("network-online.target")) {
        add("unit-wants-network", "missing Wants=network-online.target".into(), Some("reinstall"));
    }
    if directive(installed, "KillMode").first().copied().unwrap_or("control-group") != "mixed" {
        add("unit-killmode", "KillMode=mixed is needed so arkd can save running turns before the group is killed".into(), Some("reinstall"));
    }
    if directive(installed, "TimeoutStopSec").first().and_then(|s| secs(s)).unwrap_or(90) < 20 {
        add("unit-stop-timeout", "TimeoutStopSec below 20s cuts off the shutdown drain".into(), Some("reinstall"));
    }
    if directive(installed, "Type").first().copied() != Some("notify") {
        add("unit-type", "Type=notify lets systemd know when arkd is actually ready".into(), Some("reinstall"));
    }
    if directive(installed, "NoNewPrivileges").first().copied() != Some("yes") {
        add("unit-hardening", "NoNewPrivileges=yes is missing (ark must never gain privileges)".into(), Some("reinstall"));
    }
    let norm = |t: &str| t.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect::<Vec<_>>().join("\n");
    let drifted = norm(installed) != norm(expected);
    if drifted && v.is_empty() {
        v.push(Issue { code: "unit-drift", message: "installed unit differs from what this version writes (edited by hand or from an older ark)".into(), fix: Some("reinstall") });
    }
    v
}

pub fn linger_enabled() -> Option<bool> {
    let user = std::env::var("USER").ok()?;
    let o = std::process::Command::new("loginctl").args(["show-user", &user, "-p", "Linger"]).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).trim() == "Linger=yes")
}

/// Full audit of the installed user unit (empty = fine or not installed → one issue).
pub fn audit(ws: &Path) -> Vec<Issue> {
    let path = user_unit_dir().join(unit_name());
    let Ok(installed) = std::fs::read_to_string(&path) else {
        return vec![Issue { code: "unit-missing", message: format!("{} is not installed (ark service install)", unit_name()), fix: None }];
    };
    let exe = std::env::current_exe().unwrap_or_default();
    let ws = directive(&installed, "WorkingDirectory").first().map(PathBuf::from).unwrap_or_else(|| ws.to_path_buf());
    let mut v = audit_text(&installed, &unit(&exe, &ws, None), &exe);
    if linger_enabled() == Some(false) {
        v.push(Issue { code: "linger-off", message: "lingering is off: arkd stops when you log out (loginctl enable-linger $USER)".into(), fix: None });
    }
    v
}

/// Result of trying to keep the user service alive after logout and start it at boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Linger {
    Already,
    Enabled,
    /// Could not be done without authorisation: the command for the person to run themselves.
    Manual(String),
}

/// Turn lingering on without ever raising an authorisation prompt (`--no-ask-password`: if
/// polkit would need to ask, it fails and we print the command instead). Pure over its inputs
/// so the decision is testable; [`ensure_linger`] wires the real `loginctl`.
pub fn ensure_linger_with(status: Option<bool>, enable: &dyn Fn() -> Result<(), String>, user: &str) -> Linger {
    if status == Some(true) {
        return Linger::Already;
    }
    match enable() {
        Ok(()) => Linger::Enabled,
        Err(_) => Linger::Manual(format!("sudo loginctl enable-linger {user}")),
    }
}

pub fn ensure_linger() -> Linger {
    let user = std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).unwrap_or_default();
    ensure_linger_with(
        linger_enabled(),
        &|| {
            let ok = std::process::Command::new("loginctl")
                .args(["--no-ask-password", "enable-linger", &user])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
            if ok && linger_enabled() != Some(false) {
                Ok(())
            } else {
                Err("loginctl enable-linger needs authorisation".into())
            }
        },
        &user,
    )
}

pub fn install_user(ws: &Path, start: bool) -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = user_unit_dir();
    let path = dir.join(unit_name());
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::write(&path, unit(&exe, ws, None)).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut msg = format!("wrote {}", path.display());
    if start {
        if !(systemctl(false, &["daemon-reload"]) && systemctl(false, &["enable", "--now", &unit_name()])) {
            return Err(format!("{msg}\nsystemctl --user failed (no user session bus?). Start it later with: systemctl --user enable --now {}", unit_name()));
        }
        msg.push_str(&format!("\n{} enabled and started.\nTo keep it running after logout and start it at boot: loginctl enable-linger $USER", unit_name()));
    }
    Ok(msg)
}

/// Wait up to `drain` for running turns, then restart through systemd or stop + start.
pub fn restart(paths: &Paths, drain: Duration) -> Result<String, String> {
    let sock = paths.socket();
    let until = Instant::now() + drain;
    let mut waited = false;
    while Instant::now() < until {
        match ark_kernel::daemon::call(&sock, "ping", json!({})) {
            Ok(r) if r["running"].as_array().is_some_and(|a| !a.is_empty()) => {
                waited = true;
                std::thread::sleep(Duration::from_millis(500));
            }
            _ => break,
        }
    }
    let still = ark_kernel::daemon::call(&sock, "ping", json!({})).ok().and_then(|r| r["running"].as_array().map(|a| a.len())).unwrap_or(0);
    let active = std::process::Command::new("systemctl").args(["--user", "is-active", "--quiet", &unit_name()]).status().is_ok_and(|s| s.success());
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    if active {
        if !systemctl(false, &["restart", &unit_name()]) {
            return Err("systemctl --user restart failed".into());
        }
    } else {
        let _ = std::process::Command::new(&exe).args(["daemon", "stop"]).status();
        let ok = std::process::Command::new(&exe).args(["daemon", "start"]).status().is_ok_and(|s| s.success());
        if !ok {
            return Err("arkd did not come back; see `ark logs`".into());
        }
    }
    Ok(format!("arkd restarted{}{}", if waited { " after draining running turns" } else { "" }, if still > 0 { format!(" ({still} turn(s) were still running at the drain deadline and were interrupted; they resume on start)") } else { String::new() }))
}

/// For `/restart` from inside the daemon: a detached helper does the drain + restart.
pub fn restart_detached(drain_secs: u64) -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut c = std::process::Command::new(exe);
    c.args(["service", "restart", "--drain", &drain_secs.to_string()]).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    use std::os::unix::process::CommandExt;
    unsafe {
        c.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    c.spawn().map_err(|e| e.to_string())?;
    Ok(format!("restarting arkd once running turns finish (up to {drain_secs}s)…"))
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if cmd != "service" && !(cmd == "daemon" && a.pos(0) == Some("install")) {
        return None;
    }
    Some((|| -> R {
        let paths = Paths::from_env();
        let sub = if cmd == "daemon" { "install" } else { a.pos(0).unwrap_or("status") };
        let system = a.flag("system");
        let name = unit_name();
        match sub {
            "install" if a.flag("launchd") => {
                let exe = std::env::current_exe().map_err(|e| e.to_string())?;
                let body = plist(&exe, &crate::workspace(a)?, &paths.data.join("arkd.log"));
                let p = PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join("Library/LaunchAgents").join(format!("{}.plist", launchd_label()));
                if cfg!(target_os = "macos") {
                    std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
                    std::fs::write(&p, body).map_err(|e| e.to_string())?;
                    let ok = std::process::Command::new("launchctl").arg("load").arg("-w").arg(&p).status().is_ok_and(|s| s.success());
                    println!("wrote {}{}", p.display(), if ok { " and loaded it" } else { " (launchctl load failed)" });
                } else {
                    print!("{body}");
                    eprintln!("(launchd is macOS-only; on this system use `ark service install`)");
                }
                Ok(0)
            }
            "install" if system => {
                let exe = std::env::current_exe().map_err(|e| e.to_string())?;
                let user = a.val("user-name").unwrap_or(SYSTEM_USER).to_string();
                let ws = match a.val("workspace") {
                    Some(_) => crate::workspace(a)?,
                    None => PathBuf::from(SYSTEM_WORKSPACE),
                };
                let dir = std::env::temp_dir().join(format!("ark-service-{}", std::process::id()));
                std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
                let (unit_f, users_f, tmp_f) = (dir.join(&name), dir.join("ark-sysusers.conf"), dir.join("ark-tmpfiles.conf"));
                std::fs::write(&unit_f, unit(&exe, &ws, Some(&user))).map_err(|e| e.to_string())?;
                std::fs::write(&users_f, sysusers(&user)).map_err(|e| e.to_string())?;
                std::fs::write(&tmp_f, tmpfiles(&user)).map_err(|e| e.to_string())?;
                let e = exe.to_string_lossy();
                if e.starts_with("/home/") || e.starts_with("/root/") {
                    eprintln!("warning: {e} is under a home directory; user `{user}` cannot run it. Install ark to /usr/local/bin first (sudo install -m 0755 {e} /usr/local/bin/ark) and re-run from there.");
                }
                println!("wrote {} — ark does not run sudo itself; install the system account, directories and unit with:\n  sudo install -m 0644 {} /etc/sysusers.d/ark.conf && sudo systemd-sysusers\n  sudo install -m 0644 {} /etc/tmpfiles.d/ark.conf && sudo systemd-tmpfiles --create\n  sudo install -m 0644 {} /etc/systemd/system/{name}\n  sudo systemctl daemon-reload && sudo systemctl enable --now {name}\nState lives in {SYSTEM_HOME} (ARK_HOME), owned by `{user}`; put the config at {SYSTEM_HOME}/config/config.toml.", dir.display(), users_f.display(), tmp_f.display(), unit_f.display());
                Ok(0)
            }
            "install" => {
                println!("{}", install_user(&crate::workspace(a)?, !a.flag("no-start"))?);
                Ok(0)
            }
            "uninstall" => {
                if system {
                    println!("run: sudo systemctl disable --now {name} && sudo rm /etc/systemd/system/{name} && sudo systemctl daemon-reload");
                    return Ok(0);
                }
                let unit = user_unit_dir().join(&name);
                let _ = systemctl(false, &["disable", "--now", &name]);
                let _ = std::fs::remove_file(&unit);
                let _ = systemctl(false, &["daemon-reload"]);
                println!("removed {}", unit.display());
                Ok(0)
            }
            "status" => {
                if !user_unit_dir().join(&name).exists() {
                    println!("not installed (ark service install)");
                    return Ok(0);
                }
                systemctl(system, &["status", "--no-pager", &name]);
                Ok(0)
            }
            "print" => {
                let exe = std::env::current_exe().map_err(|e| e.to_string())?;
                if a.flag("sysusers") {
                    print!("{}", sysusers(a.val("user-name").unwrap_or(SYSTEM_USER)));
                } else if a.flag("tmpfiles") {
                    print!("{}", tmpfiles(a.val("user-name").unwrap_or(SYSTEM_USER)));
                } else if system {
                    let ws = if a.val("workspace").is_some() { crate::workspace(a)? } else { PathBuf::from(SYSTEM_WORKSPACE) };
                    print!("{}", unit(&exe, &ws, Some(a.val("user-name").unwrap_or(SYSTEM_USER))));
                } else {
                    print!("{}", unit(&exe, &crate::workspace(a)?, None));
                }
                Ok(0)
            }
            "restart" => {
                let drain = a.num::<u64>("drain").map_err(crate::Fail::Usage)?.unwrap_or(60);
                println!("{}", restart(&paths, Duration::from_secs(drain))?);
                Ok(0)
            }
            "logs" => {
                let n = a.val("lines").unwrap_or("100");
                let mut c = std::process::Command::new("journalctl");
                c.args(["--user", "-u", &name, "-n", n, "--no-pager"]);
                if a.flag("follow") {
                    c.arg("-f");
                }
                if !c.status().is_ok_and(|s| s.success()) {
                    return crate::ops::logs::show(a);
                }
                Ok(0)
            }
            "audit" => {
                let issues = audit(&crate::workspace(a)?);
                let starts = recent_starts(&paths, ark_kernel::util::unix_now()).len();
                if a.flag("json") {
                    println!("{}", json!({"issues": issues.iter().map(|i| json!({"code": i.code, "message": i.message})).collect::<Vec<_>>(), "recent_starts": starts}));
                } else {
                    for i in &issues {
                        println!("✗ [{}] {}", i.code, i.message);
                    }
                    println!("{} daemon start(s) in the last {} minutes{}", starts, STORM_WINDOW_SECS / 60, if starts >= STORM_THRESHOLD { " — restart storm!" } else { "" });
                    if issues.is_empty() {
                        println!("✓ {name} matches this version");
                    } else if issues.iter().any(|i| i.fix == Some("reinstall")) {
                        println!("fix: ark service install   (or ark doctor --fix)");
                    }
                }
                Ok(if issues.is_empty() { 0 } else { 1 })
            }
            other => usage(format!("unknown `service {other}` (install [--system|--launchd] [--no-start], uninstall, status, print [--system|--sysusers|--tmpfiles], restart [--drain S], logs, audit)")),
        }
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_plist_and_audit() {
        let exe = std::env::current_exe().unwrap();
        let ws = Path::new("/srv/ws");
        let u = unit(&exe, ws, None);
        assert!(u.contains("KillMode=mixed") && u.contains("WantedBy=default.target") && u.contains(" daemon run -w /srv/ws"));
        assert!(unit(&exe, ws, Some("amy")).contains("User=amy\nGroup=amy") && unit(&exe, ws, Some("amy")).contains("multi-user.target"));
        assert!(audit_text(&u, &u, &exe).is_empty(), "{:?}", audit_text(&u, &u, &exe));
        let old = u.replace("KillMode=mixed", "KillMode=process").replace("TimeoutStopSec=30s", "TimeoutStopSec=5").replace(&exe.display().to_string(), "/nonexistent/ark");
        let codes: Vec<&str> = audit_text(&old, &u, &exe).iter().map(|i| i.code).collect();
        assert_eq!(codes, ["unit-binary-missing", "unit-killmode", "unit-stop-timeout"]);
        let drift = u.replace("RestartSec=5s", "RestartSec=1s");
        assert_eq!(audit_text(&drift, &u, &exe)[0].code, "unit-drift");
        let p = plist(&exe, ws, Path::new("/tmp/a&b.log"));
        assert!(p.contains("<string>daemon</string>") && p.contains("a&amp;b.log") && p.contains("<key>KeepAlive</key>"));
    }

    fn repo(rel: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(rel)
    }

    /// `ARK_BLESS=1` rewrites the packaged file instead of failing.
    fn same_as_file(rel: &str, want: &str) {
        let p = repo(rel);
        if std::env::var_os("ARK_BLESS").is_some() {
            std::fs::write(&p, want).unwrap();
        }
        let got = std::fs::read_to_string(&p).unwrap_or_default();
        assert_eq!(got, want, "{rel} is generated from ops/service.rs; refresh it with: ARK_BLESS=1 cargo test -p ark packaged_units");
    }

    #[test]
    fn packaged_units_are_generated_from_the_one_source() {
        same_as_file("packaging/systemd/arkd.service", &render_unit(Path::new("%h/.local/bin/ark"), Path::new("%h"), None, "", ""));
        same_as_file("packaging/systemd/arkd-system.service", &render_unit(Path::new("/usr/bin/ark"), Path::new(SYSTEM_WORKSPACE), Some(SYSTEM_USER), "", ""));
        same_as_file("packaging/systemd/ark-sysusers.conf", &sysusers(SYSTEM_USER));
        same_as_file("packaging/systemd/ark-tmpfiles.conf", &tmpfiles(SYSTEM_USER));
    }

    #[test]
    fn system_unit_uses_the_dedicated_account_and_state_directory() {
        let u = render_unit(Path::new("/usr/bin/ark"), Path::new(SYSTEM_WORKSPACE), Some("ark"), "", "");
        for want in ["User=ark\nGroup=ark", "StateDirectory=ark ark/workspace", "Environment=ARK_HOME=/var/lib/ark", "ProtectSystem=full", "PrivateTmp=yes", "ProtectKernelLogs=yes", "WantedBy=multi-user.target", "NoNewPrivileges=yes", "Type=notify"] {
            assert!(u.contains(want), "system unit lacks {want}:\n{u}");
        }
        // The user unit never carries system-only directives, and a custom ARK_HOME shows up there only.
        let user = render_unit(Path::new("/x/ark"), Path::new("/w"), None, "", "Environment=ARK_HOME=/h\n");
        assert!(!user.contains("StateDirectory") && !user.contains("ProtectSystem") && user.contains("Environment=ARK_HOME=/h"));
        assert!(!render_unit(Path::new("/x/ark"), Path::new("/w"), Some("ark"), "", "Environment=ARK_HOME=/h\n").contains("ARK_HOME=/h"));
        assert!(sysusers("ark").starts_with("# ") && sysusers("ark").contains("u ark - \"ark agent\" /var/lib/ark"));
        assert!(tmpfiles("ark").contains("d /var/lib/ark/workspace 0750 ark ark -"));
        // audit accepts what we render.
        let exe = std::env::current_exe().unwrap();
        let sys = render_unit(&exe, Path::new(SYSTEM_WORKSPACE), Some("ark"), "", "");
        assert!(audit_text(&sys, &sys, &exe).is_empty());
    }

    #[test]
    fn nixos_module_carries_the_same_hardening() {
        let nix = std::fs::read_to_string(repo("nix/nixos.nix")).unwrap();
        let u = render_unit(Path::new("/usr/bin/ark"), Path::new(SYSTEM_WORKSPACE), Some("ark"), "", "");
        let key_re = |l: &str| l.split_once('=').map(|(k, _)| k.to_string());
        for line in u.lines().filter(|l| !l.starts_with('#')) {
            let Some(k) = key_re(line) else { continue };
            if ["Description", "Documentation", "After", "Wants", "ExecStart", "WantedBy", "Environment", "StartLimitIntervalSec", "StartLimitBurst", "WorkingDirectory", "RestartSec"].contains(&k.as_str()) {
                continue;
            }
            assert!(nix.contains(&format!("{k} =")), "nix/nixos.nix lacks {k} (kept in step with ops/service.rs)");
        }
        assert!(nix.contains("ARK_HOME = \"/var/lib/ark\"") && nix.contains("users.users.ark"));
    }

    #[test]
    fn restart_storm_detection() {
        let root = std::env::temp_dir().join(format!("ark-storm-{}", ark_kernel::util::random_hex(4)));
        let p = Paths { data: root.join("data"), config_dir: root.join("c"), runtime: root.join("r") };
        assert!(record_start(&p).is_none());
        assert!(record_start(&p).is_none());
        assert!(record_start(&p).unwrap().contains("3 times"));
        let now = ark_kernel::util::unix_now();
        std::fs::write(restarts_log(&p), format!("[{}] start\n[{}] start\n", now - 4000, now - 3000)).unwrap();
        assert!(record_start(&p).is_none(), "old starts are outside the window");
    }
}
