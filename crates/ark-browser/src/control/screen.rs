//! Bot Desktop screen runtime and `ark screen status|start|stop|install` (Hermes
//! `tools/bot_desktop/runtime.py`, `install.py`, `hermes_cli/subcommands/computer_use_screen.py`, MIT).
//!
//! On a headless Linux host ark gives its home one Xfce screen: TigerVNC's Xvnc on a
//! private 0600 Unix socket (no TCP), a minimal component-wise Xfce under a private dbus
//! session (`launcher.sh`). The launcher publishes `DISPLAY` / `XAUTHORITY` /
//! `DBUS_SESSION_BUS_ADDRESS` to `<home>/bot-desktop/env`, which headed browsers and
//! `computer_use` read ([`crate::manager::desktop_env`]). A human may take control through
//! the lease ([`crate::lease`]); `stop` refuses while they hold it unless `--force`.

use crate::{lease, util};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The launcher, embedded (written to `<home>/bot-desktop/launcher.sh` at start).
pub const LAUNCHER: &str = include_str!("launcher.sh");

/// Binaries the launcher execs (Hermes `REQUIRED_BINARIES`).
pub const REQUIRED_BINARIES: &[&str] = &[
    "Xvnc",
    "xfwm4",
    "xfce4-panel",
    "xfdesktop",
    "xfsettingsd",
    "dbus-run-session",
    "xauth",
    "xdpyinfo",
    "setxkbmap",
    "xprop",
];

/// Distro packages per package manager (Hermes `PACKAGES`).
pub fn packages(pm: &str) -> &'static [&'static str] {
    match pm {
        "apt" => &[
            "tigervnc-standalone-server",
            "xfce4-panel",
            "xfwm4",
            "xfdesktop4",
            "xfce4-settings",
            "xfce4-terminal",
            "dbus-x11",
            "x11-xserver-utils",
            "x11-utils",
            "x11-xkb-utils",
            "xauth",
            "fonts-dejavu-core",
        ],
        "dnf" => &[
            "tigervnc-x11-server",
            "xfce4-panel",
            "xfwm4",
            "xfdesktop",
            "xfce4-settings",
            "xfce4-terminal",
            "dbus-daemon",
            "xsetroot",
            "xset",
            "xdpyinfo",
            "xprop",
            "xorg-x11-xauth",
            "setxkbmap",
            "dejavu-sans-fonts",
        ],
        "pacman" => &[
            "tigervnc",
            "xfce4-panel",
            "xfwm4",
            "xfdesktop",
            "xfce4-settings",
            "xfce4-terminal",
            "dbus",
            "xorg-xsetroot",
            "xorg-xset",
            "xorg-xdpyinfo",
            "xorg-xprop",
            "xorg-xauth",
            "xorg-setxkbmap",
            "ttf-dejavu",
        ],
        _ => &[],
    }
}

/// Display numbers below 10 collide with real seats; scan a private band (Hermes `_DISPLAY_MIN/_MAX`).
const DISPLAY_MIN: u32 = 20;
const DISPLAY_MAX: u32 = 89;
/// Hermes `resources.DEFAULT_MIN_FREE_MB`.
pub const DEFAULT_MIN_FREE_MB: u64 = 1536;

/// Where and how this home's desktop runs. Every host probe is a field so tests can fake it.
#[derive(Debug, Clone)]
pub struct Desktop {
    pub home: PathBuf,
    pub profile: String,
    pub geometry: String,
    pub min_free_mb: u64,
    /// `PATH` used to look binaries up (`None` = the process PATH).
    pub path: Option<String>,
    /// Launcher script override (tests); default = the embedded [`LAUNCHER`].
    pub launcher: Option<PathBuf>,
    /// X lock directory (`/tmp` by protocol).
    pub x_lock_dir: PathBuf,
    /// The kernel's bound Unix sockets table.
    pub unix_table: PathBuf,
    pub euid_root: bool,
    pub wait: Duration,
}

impl Desktop {
    pub fn new(home: &Path) -> Desktop {
        Desktop {
            home: home.to_path_buf(),
            profile: "default".into(),
            geometry: "1440x900".into(),
            min_free_mb: DEFAULT_MIN_FREE_MB,
            path: None,
            launcher: None,
            x_lock_dir: PathBuf::from("/tmp"),
            unix_table: PathBuf::from("/proc/net/unix"),
            euid_root: unsafe { libc::geteuid() } == 0,
            wait: Duration::from_secs(15),
        }
    }

    /// `[bot_desktop]` keys: `geometry`, `min_free_memory_mb`.
    pub fn with_config(mut self, t: &toml::Table) -> Desktop {
        if let Some(b) = t.get("bot_desktop").and_then(|v| v.as_table()) {
            if let Some(g) = b
                .get("geometry")
                .and_then(|v| v.as_str())
                .filter(|g| parse_geometry(g))
            {
                self.geometry = g.to_string();
            }
            if let Some(n) = b.get("min_free_memory_mb").and_then(|v| v.as_integer()) {
                self.min_free_mb = n.max(0) as u64;
            }
        }
        self
    }

    pub fn state_dir(&self) -> PathBuf {
        self.home.join("bot-desktop")
    }

    fn which(&self, bin: &str) -> Option<PathBuf> {
        match &self.path {
            None => util::which(bin),
            Some(p) => std::env::split_paths(p)
                .map(|d| d.join(bin))
                .find(|f| f.is_file()),
        }
    }

    pub fn missing_binaries(&self) -> Vec<String> {
        REQUIRED_BINARIES
            .iter()
            .filter(|b| self.which(b).is_none())
            .map(|b| b.to_string())
            .collect()
    }

    pub fn package_manager(&self) -> Option<&'static str> {
        [("apt-get", "apt"), ("dnf", "dnf"), ("pacman", "pacman")]
            .into_iter()
            .find(|(bin, _)| self.which(bin).is_some())
            .map(|(_, pm)| pm)
    }

    /// The install command as the human would type it here (`sudo` unless root).
    pub fn install_command(&self) -> Option<String> {
        let pm = self.package_manager()?;
        let pkgs = packages(pm).join(" ");
        let body = match pm {
            "apt" => format!("apt-get install -y --no-install-recommends {pkgs}"),
            "dnf" => format!("dnf install -y {pkgs}"),
            _ => format!("pacman -S --needed --noconfirm {pkgs}"),
        };
        Some(if self.euid_root {
            body
        } else {
            format!("sudo {body}")
        })
    }

    pub fn installable(&self) -> bool {
        self.package_manager().is_some() && (self.euid_root || self.which("sudo").is_some())
    }

    /// The live launcher's pid: `launcher.pid` holds `"<pid> <starttime>"`; a recycled pid with a
    /// different start time is someone else's process and never ours.
    pub fn launcher_pid(&self) -> Option<i32> {
        let raw = std::fs::read_to_string(self.state_dir().join("launcher.pid")).ok()?;
        let mut it = raw.split_whitespace();
        let pid: i32 = it.next()?.parse().ok()?;
        let born: u64 = it.next()?.parse().ok()?;
        (start_time(pid) == Some(born) && util::pid_alive(pid)).then_some(pid)
    }

    pub fn published_env(&self) -> Vec<(String, String)> {
        if self.launcher_pid().is_none() {
            return vec![];
        }
        std::fs::read_to_string(self.state_dir().join("env"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            .collect()
    }

    pub fn rfb_socket(&self) -> Option<PathBuf> {
        let s = self.state_dir().join("rfb.sock");
        (self.launcher_pid().is_some() && s.exists()).then_some(s)
    }

    fn x_lock_pid(&self, num: u32) -> Option<i32> {
        std::fs::read_to_string(self.x_lock_dir.join(format!(".X{num}-lock")))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    fn x_socket_bound(&self, num: u32) -> bool {
        let want = format!("/tmp/.X11-unix/X{num}");
        std::fs::read_to_string(&self.unix_table)
            .unwrap_or_default()
            .lines()
            .any(|l| {
                l.split_whitespace()
                    .last()
                    .is_some_and(|p| p.trim_start_matches('@') == want)
            })
    }

    /// A live X server owns `:num` (lock names a running pid, or its socket is bound).
    pub fn display_in_use(&self, num: u32) -> bool {
        self.x_lock_pid(num).is_some_and(util::pid_alive) || self.x_socket_bound(num)
    }

    /// The recorded number when free, else the first free one in the band.
    pub fn pick_display(&self) -> Result<u32, String> {
        let recorded = std::fs::read_to_string(self.state_dir().join("display"))
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok());
        if let Some(n) = recorded.filter(|n| !self.display_in_use(*n)) {
            return Ok(n);
        }
        (DISPLAY_MIN..=DISPLAY_MAX)
            .find(|n| !self.display_in_use(*n))
            .ok_or_else(|| "no free X display number in the Bot Desktop band".to_string())
    }

    pub fn memory_blocker(&self, need: u64) -> Option<String> {
        if need == 0 {
            return None;
        }
        let avail = mem_available_mb()?;
        (avail < need).then(|| format!("Not enough free memory for a desktop: {avail} MB available, {need} MB needed (bot_desktop.min_free_memory_mb)"))
    }

    pub fn status(&self) -> Status {
        let missing = self.missing_binaries();
        let pid = self.launcher_pid();
        let env = self.published_env();
        let display = env
            .iter()
            .find(|(k, _)| k == "DISPLAY")
            .map(|(_, v)| v.clone());
        let running = pid.is_some() && display.is_some();
        Status {
            profile: self.profile.clone(),
            supported: cfg!(target_os = "linux"),
            installed: missing.is_empty(),
            install_command: if missing.is_empty() {
                None
            } else {
                self.install_command()
            },
            missing: missing.clone(),
            running,
            pid,
            display,
            socket: self.rfb_socket().map(|p| p.display().to_string()),
            geometry: self.geometry.clone(),
            blocker: if running || !missing.is_empty() {
                None
            } else {
                self.memory_blocker(self.min_free_mb)
            },
            browser: if cfg!(target_os = "linux") {
                crate::launch::find_executable("")
                    .ok()
                    .map(|p| p.display().to_string())
            } else {
                None
            },
            memory_available_mb: mem_available_mb(),
            memory_limit_mb: mem_limit_mb(),
            // ark runs screens on the gateway host only (no sandbox placement), so nothing is pending.
            placement: "gateway".into(),
            image_switch: None,
        }
    }

    /// Start this home's desktop (idempotent); blocks until the launcher publishes its env.
    pub fn start(&self) -> Result<Status, String> {
        if !cfg!(target_os = "linux") {
            return Err("Bot Desktop runs on Linux gateway hosts only".into());
        }
        let missing = self.missing_binaries();
        if !missing.is_empty() {
            let need = format!(
                "Bot Desktop needs {} on the gateway host",
                missing.join(", ")
            );
            if self.package_manager().is_none() {
                return Err(format!("{need}, and no supported package manager (apt/dnf/pacman) is available to install them. Install TigerVNC (Xvnc) and the Xfce core components with this distro's own tooling."));
            }
            if !self.installable() {
                return Err(format!("{need}, and this host cannot install them: the process is unprivileged and there is no sudo."));
            }
            return Err(format!(
                "{need}. Install: {}",
                self.install_command().unwrap_or_default()
            ));
        }
        let sd = self.state_dir();
        util::private_dir(&sd).map_err(|e| e.to_string())?;
        let _lock = Flock::new(&sd.join("start.lock"));
        if self.launcher_pid().is_some() && !self.published_env().is_empty() {
            return Ok(self.status());
        }
        if let Some(b) = self.memory_blocker(self.min_free_mb) {
            return Err(b);
        }
        let r = self.spawn_and_wait(&sd);
        if r.is_err() {
            // A recorded number left after a failed launch would wedge every retry on it.
            let _ = std::fs::remove_file(sd.join("display"));
        }
        r
    }

    fn spawn_and_wait(&self, sd: &Path) -> Result<Status, String> {
        let num = self.pick_display()?;
        std::fs::write(sd.join("display"), num.to_string()).map_err(|e| e.to_string())?;
        let env_file = sd.join("env");
        let _ = std::fs::remove_file(&env_file);
        let script = match &self.launcher {
            Some(p) => p.clone(),
            None => {
                let p = sd.join("launcher.sh");
                std::fs::write(&p, LAUNCHER).map_err(|e| e.to_string())?;
                p
            }
        };
        let log = std::fs::File::create(sd.join("launcher.log")).map_err(|e| e.to_string())?;
        let mut cmd = std::process::Command::new("bash");
        cmd.arg(&script);
        for k in [
            "DISPLAY",
            "XAUTHORITY",
            "WAYLAND_DISPLAY",
            "DBUS_SESSION_BUS_ADDRESS",
            "SESSION_MANAGER",
        ] {
            cmd.env_remove(k);
        }
        if let Some(p) = &self.path {
            cmd.env("PATH", p);
        }
        cmd.envs([
            ("ARK_BD_PROFILE", self.profile.clone()),
            ("ARK_BD_DISPLAY_NUM", num.to_string()),
            ("ARK_BD_SOCKET", sd.join("rfb.sock").display().to_string()),
            ("ARK_BD_XAUTH", sd.join("Xauthority").display().to_string()),
            ("ARK_BD_ENV_FILE", env_file.display().to_string()),
            ("ARK_BD_CONFIG_HOME", sd.join("xdg").display().to_string()),
            ("ARK_BD_GEOMETRY", self.geometry.clone()),
        ]);
        if let Ok(exe) = crate::launch::find_executable("") {
            cmd.env("ARK_BD_BROWSER_EXEC", &exe);
            let udd = self.home.join("browser").join("profiles").join("default");
            cmd.env(
                "ARK_BD_BROWSER_EXEC_LINE",
                format!(
                    "Exec={} --user-data-dir={} --no-first-run",
                    desktop_quote(&exe.display().to_string()),
                    desktop_quote(&udd.display().to_string())
                ),
            );
        }
        use std::os::unix::process::CommandExt;
        cmd.process_group(0)
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().map_err(|e| e.to_string())?)
            .stderr(log);
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("could not start the Bot Desktop launcher: {e}"))?;
        let pid = child.id() as i32;
        std::fs::write(
            sd.join("launcher.pid"),
            format!("{pid} {}", start_time(pid).unwrap_or(0)),
        )
        .map_err(|e| e.to_string())?;
        let deadline = Instant::now() + self.wait;
        while Instant::now() < deadline {
            if let Ok(Some(code)) = child.try_wait() {
                let log = std::fs::read(sd.join("launcher.log")).unwrap_or_default();
                let tail =
                    String::from_utf8_lossy(&log[log.len().saturating_sub(2000)..]).into_owned();
                let _ = std::fs::remove_file(sd.join("launcher.pid"));
                return Err(format!(
                    "Bot Desktop launcher exited with {}:\n{tail}",
                    code.code().unwrap_or(-1)
                ));
            }
            if env_file.exists() && sd.join("rfb.sock").exists() {
                let _ = std::fs::write(sd.join("activity"), util::now_ms().to_string());
                // The launcher is reaped by whoever stops it; detach the handle.
                std::mem::forget(child);
                return Ok(self.status());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        // Giving up takes the launch down, or it would publish a moment later as "running".
        util::kill_group(pid, Duration::from_secs(2));
        let _ = child.wait();
        for n in ["launcher.pid", "env", "rfb.sock"] {
            let _ = std::fs::remove_file(sd.join(n));
        }
        Err(format!(
            "Bot Desktop did not publish its display within {}s (see {})",
            self.wait.as_secs(),
            sd.join("launcher.log").display()
        ))
    }

    /// Stop this home's desktop; true when a running launcher was signalled.
    pub fn stop(&self) -> bool {
        let sd = self.state_dir();
        if !sd.exists() {
            return false;
        }
        let _lock = Flock::new(&sd.join("start.lock"));
        let Some(pid) = self.launcher_pid() else {
            let _ = std::fs::remove_file(sd.join("env"));
            return false;
        };
        util::kill_group(pid, Duration::from_secs(5));
        let mut st = 0;
        unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG) };
        for n in ["launcher.pid", "env", "activity"] {
            let _ = std::fs::remove_file(sd.join(n));
        }
        true
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Status {
    pub profile: String,
    pub supported: bool,
    pub installed: bool,
    pub missing: Vec<String>,
    pub running: bool,
    pub pid: Option<i32>,
    pub display: Option<String>,
    pub socket: Option<String>,
    pub geometry: String,
    pub install_command: Option<String>,
    /// Headed Chromium the desktop's Browser icon and the agent's headed browser share.
    pub browser: Option<String>,
    pub blocker: Option<String>,
    pub memory_available_mb: Option<u64>,
    pub memory_limit_mb: Option<u64>,
    /// `gateway` (ark never places a screen inside a sandbox).
    pub placement: String,
    /// A pending default-image switch the UI could approve (only sandbox placement has one).
    pub image_switch: Option<Value>,
}

impl Status {
    pub fn to_json(&self) -> Value {
        json!({"profile": self.profile, "supported": self.supported, "installed": self.installed, "missing": self.missing, "running": self.running, "pid": self.pid,
            "display": self.display, "socket": self.socket, "geometry": self.geometry, "install_command": self.install_command, "browser": self.browser,
            "blocker": self.blocker, "memory_available_mb": self.memory_available_mb, "memory_limit_mb": self.memory_limit_mb,
            "placement": self.placement, "image_switch": self.image_switch})
    }
}

fn parse_geometry(g: &str) -> bool {
    g.split_once('x').is_some_and(|(w, h)| {
        w.parse::<u32>().is_ok_and(|w| (320..=7680).contains(&w))
            && h.parse::<u32>().is_ok_and(|h| (240..=4320).contains(&h))
    })
}

/// Desktop-entry Exec quoting (spec §Exec: double quotes, escape `"` `` ` `` `$` `\`).
fn desktop_quote(s: &str) -> String {
    if !s.contains([' ', '"', '\'', '\\', '$', '`']) {
        return s.to_string();
    }
    let mut o = String::from("\"");
    for c in s.chars() {
        if matches!(c, '"' | '`' | '$' | '\\') {
            o.push('\\');
        }
        o.push(c);
    }
    o.push('"');
    o
}

/// Process start time in clock ticks (`/proc/<pid>/stat` field 22): pid identity across recycling.
pub fn start_time(pid: i32) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    s.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

fn mem_available_mb() -> Option<u64> {
    mem_info().0
}

/// `(available_mb, limit_mb)`: the host's MemAvailable, tightened by a cgroup v2 limit when there is one
/// (Hermes `resources.memory_info`).
fn mem_info() -> (Option<u64>, Option<u64>) {
    let Some(s) = std::fs::read_to_string("/proc/meminfo").ok() else {
        return (None, None);
    };
    let Some(kb) = s
        .lines()
        .find_map(|l| l.strip_prefix("MemAvailable:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse::<u64>().ok())
    else {
        return (None, None);
    };
    let mut mb = kb / 1024;
    let lim = std::fs::read_to_string("/sys/fs/cgroup/memory.max")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok());
    let cur = std::fs::read_to_string("/sys/fs/cgroup/memory.current")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok());
    if let (Some(l), Some(c)) = (lim, cur) {
        mb = mb.min(l.saturating_sub(c) / (1024 * 1024));
    }
    (Some(mb), lim.map(|l| l / (1024 * 1024)))
}

fn mem_limit_mb() -> Option<u64> {
    mem_info().1
}

struct Flock(Option<std::fs::File>);

impl Flock {
    fn new(p: &Path) -> Flock {
        use std::os::unix::io::AsRawFd;
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .ok();
        if let Some(f) = &f {
            unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) };
        }
        Flock(f)
    }
}

impl Drop for Flock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        if let Some(f) = &self.0 {
            unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

/// Interaction for `screen install` (confirmation and the sudo password come from the terminal).
pub trait Io {
    fn line(&mut self, s: &str);
    /// Is a terminal attached? Only then is `install` allowed to ask (Hermes: `sys.stdin.isatty()`);
    /// a piped run proceeds, so an unattended `ark screen install` never blocks on a prompt.
    fn interactive(&self) -> bool {
        false
    }
    fn confirm(&mut self, _q: &str) -> bool {
        false
    }
    fn password(&mut self) -> Option<String> {
        None
    }
}

/// Collects output; never confirms (non-interactive callers pass `-y`).
#[derive(Default)]
pub struct Collect(pub Vec<String>);

impl Io for Collect {
    fn line(&mut self, s: &str) {
        self.0.push(s.to_string());
    }
}

pub const SCREEN_HELP: &str = "usage: ark screen <status [--json] | start | stop [--force] | install [-y]>\n\nOn a headless Linux host ark gives its home one Xfce screen (TigerVNC Xvnc on a private Unix socket).\nThe agent's computer_use and headed browser act on it; a human can take over for logins, 2FA or\nCAPTCHAs, then hand control back.\n  status   whether the screen is installed/running and who holds control\n  start    start the screen\n  stop     stop it (refused while a human holds control, unless --force)\n  install  install TigerVNC + Xfce core via apt/dnf/pacman";

/// `ark screen …` (also `ark computer-use screen …`): exit code; output goes to `io`.
pub fn screen_cli(d: &Desktop, args: &[String], io: &mut dyn Io) -> i32 {
    let flag = |f: &str| args.iter().any(|a| a == f);
    match args.first().map(String::as_str) {
        Some("status") => {
            let st = d.status();
            if flag("--json") {
                let mut v = st.to_json();
                v["lease"] = lease::public_view(&d.home);
                io.line(&serde_json::to_string_pretty(&v).unwrap_or_default());
                return if st.running { 0 } else { 1 };
            }
            if !st.supported {
                io.line("Bot Desktop screens run on Linux gateway hosts only (this host keeps its real display).");
                return 1;
            }
            if !st.installed {
                io.line(&format!(
                    "Bot Desktop: packages missing → {}",
                    st.missing.join(", ")
                ));
                io.line(&format!(
                    "  Install: {}",
                    st.install_command
                        .clone()
                        .unwrap_or_else(|| "ark screen install".into())
                ));
                return 1;
            }
            if st.running {
                let l = lease::public_view(&d.home);
                let who = if l["holder"] == "human" {
                    format!("human (viewer {})", l["viewer_hash"].as_str().unwrap_or(""))
                } else {
                    "agent".into()
                };
                io.line(&format!(
                    "Bot Desktop [{}]: running on DISPLAY {} ({}), pid {}",
                    st.profile,
                    st.display.clone().unwrap_or_default(),
                    st.geometry,
                    st.pid.unwrap_or(0)
                ));
                io.line(&format!(
                    "  control: {who}   rfb socket: {}",
                    st.socket.clone().unwrap_or_default()
                ));
                io.line("  View it: the ark UI → Desktop (web /view/desktop)");
                return 0;
            }
            if let Some(b) = &st.blocker {
                io.line(&format!(
                    "Bot Desktop [{}]: installed, not running. {b}",
                    st.profile
                ));
                return 1;
            }
            io.line(&format!(
                "Bot Desktop [{}]: installed, not running. Start: ark screen start",
                st.profile
            ));
            1
        }
        Some("start") => match d.start() {
            Ok(st) => {
                io.line(&format!(
                    "Bot Desktop [{}]: running on DISPLAY {} ({})",
                    st.profile,
                    st.display.unwrap_or_default(),
                    st.geometry
                ));
                0
            }
            Err(e) => {
                io.line(&format!("Bot Desktop: {e}"));
                1
            }
        },
        Some("stop") => {
            // A human mid-takeover is never yanked by a stray `screen stop`; decided under the lease lock.
            match lease::release(&d.home, None, !flag("--force")) {
                Ok(l) if l.holder == "human" => {
                    io.line("Bot Desktop: a human holds this screen; re-run with --force to take it down anyway.");
                    return 1;
                }
                _ => {}
            }
            io.line(if d.stop() {
                "Bot Desktop: stopped"
            } else {
                "Bot Desktop: was not running"
            });
            0
        }
        Some("install") => install(d, flag("-y") || flag("--yes"), io),
        // Bare `ark screen` prints the help and succeeds (Hermes `screen._cmd`); an unknown action
        // is a parser error.
        None => {
            io.line(SCREEN_HELP);
            0
        }
        _ => {
            io.line(SCREEN_HELP);
            2
        }
    }
}

/// Exit code for "no sudo on this host" (Hermes `install.NO_SUDO`).
pub const NO_SUDO: i32 = -2;

fn install(d: &Desktop, yes: bool, io: &mut dyn Io) -> i32 {
    if !cfg!(target_os = "linux") {
        io.line("Bot Desktop screens run on Linux gateway hosts only.");
        return 1;
    }
    if d.missing_binaries().is_empty() {
        io.line("Bot Desktop: packages already installed.");
        return 0;
    }
    let Some(cmd) = d.install_command() else {
        io.line("Bot Desktop: no supported package manager (apt/dnf/pacman) found. Install TigerVNC (Xvnc) and the Xfce core (xfwm4, xfce4-panel, xfdesktop, xfce4-settings) by hand.");
        return 1;
    };
    io.line(&format!("Bot Desktop: installing → {cmd}"));
    if !yes && io.interactive() && !io.confirm("Proceed? [Y/n] ") {
        return 1;
    }
    let rc = run_install(d, &cmd, io);
    if rc == NO_SUDO {
        io.line(&format!(
            "Bot Desktop: this host has no sudo. Run as root on the host:\n  {}",
            cmd.trim_start_matches("sudo ")
        ));
        return 1;
    }
    if rc != 0 {
        io.line(&format!("Bot Desktop: installer exited {rc}"));
        return if rc > 0 { rc } else { 1 };
    }
    let missing = d.missing_binaries();
    if !missing.is_empty() {
        io.line(&format!(
            "Bot Desktop: still missing {}",
            missing.join(", ")
        ));
        return 1;
    }
    io.line("Bot Desktop: ready. Start with `ark screen start`.");
    0
}

/// Run the package install; sudo's password goes on stdin (`-S`), never on the command line.
fn run_install(d: &Desktop, cmd: &str, io: &mut dyn Io) -> i32 {
    let mut argv: Vec<String> = cmd.split_whitespace().map(str::to_string).collect();
    let mut stdin: Option<String> = None;
    if argv[0] == "sudo" {
        let Some(sudo) = d.which("sudo") else {
            io.line(&format!(
                "install needs root and this host has no sudo; run on the host as root: {}",
                cmd.trim_start_matches("sudo ")
            ));
            return NO_SUDO;
        };
        argv[0] = sudo.display().to_string();
        let nopasswd = std::process::Command::new(&sudo)
            .args(["-n", "true"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !nopasswd {
            let Some(pw) = io.password().filter(|p| !p.is_empty()) else {
                io.line("install cancelled: no sudo password provided");
                return -1;
            };
            argv.splice(1..1, ["-S".to_string(), "-p".to_string(), String::new()]);
            stdin = Some(format!("{pw}\n"));
        }
    } else if let Some(p) = d.which(&argv[0]) {
        argv[0] = p.display().to_string();
    }
    io.line(&format!("$ {cmd}"));
    use std::io::{BufRead, Write};
    let mut c = std::process::Command::new(&argv[0]);
    c.args(&argv[1..])
        .env("DEBIAN_FRONTEND", "noninteractive")
        .env("LC_ALL", "C.UTF-8")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(p) = &d.path {
        c.env("PATH", p);
    }
    let mut child = match c.spawn() {
        Ok(c) => c,
        Err(e) => {
            io.line(&format!("install failed to start: {e}"));
            return 1;
        }
    };
    if let (Some(mut si), Some(pw)) = (child.stdin.take(), stdin) {
        let _ = si.write_all(pw.as_bytes());
    }
    let err = child.stderr.take();
    let errs = std::thread::spawn(move || {
        err.map(|e| {
            std::io::BufReader::new(e)
                .lines()
                .map_while(Result::ok)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
    });
    if let Some(out) = child.stdout.take() {
        for l in std::io::BufReader::new(out).lines().map_while(Result::ok) {
            io.line(&l);
        }
    }
    for l in errs.join().unwrap_or_default() {
        io.line(&l);
    }
    child.wait().map(|s| s.code().unwrap_or(-9)).unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_bin(dir: &Path, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn scratch(tag: &str) -> PathBuf {
        let d = ark_core::tmp::scratch_path(format!("ark-screen-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn desk(tag: &str) -> (Desktop, PathBuf) {
        let root = scratch(tag);
        let bin = root.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let mut d = Desktop::new(&root.join("home"));
        d.path = Some(format!("{}:/usr/bin:/bin", bin.display()));
        d.x_lock_dir = root.join("xlocks");
        std::fs::create_dir_all(&d.x_lock_dir).unwrap();
        d.unix_table = root.join("unix");
        std::fs::write(
            &d.unix_table,
            "Num RefCount Protocol Flags Type St Inode Path\n",
        )
        .unwrap();
        d.min_free_mb = 0;
        d.euid_root = false;
        d.wait = Duration::from_secs(5);
        (d, bin)
    }

    #[test]
    fn status_missing_and_install_command() {
        let (d, bin) = desk("status");
        // Only apt-get on the fake PATH: every desktop binary is missing (unless the host ships them).
        fake_bin(&bin, "apt-get", "exit 0");
        let mut d = d;
        d.path = Some(bin.display().to_string());
        let st = d.status();
        assert!(!st.installed && st.missing.contains(&"Xvnc".to_string()));
        let cmd = st.install_command.unwrap();
        assert!(
            cmd.starts_with(
                "sudo apt-get install -y --no-install-recommends tigervnc-standalone-server"
            ),
            "{cmd}"
        );
        let mut io = Collect::default();
        assert_eq!(screen_cli(&d, &["status".into()], &mut io), 1);
        assert!(io.0[0].contains("packages missing → Xvnc"), "{:?}", io.0);
        let e = d.start().unwrap_err();
        assert!(
            e.contains("Bot Desktop needs Xvnc") && e.contains("no sudo"),
            "{e}"
        );
        // install without sudo: hand the human the root command.
        let mut io = Collect::default();
        assert_eq!(screen_cli(&d, &["install".into(), "-y".into()], &mut io), 1);
        assert!(io.0.iter().any(|l| l.contains("has no sudo")), "{:?}", io.0);
        let mut io = Collect::default();
        assert_eq!(screen_cli(&d, &["bogus".into()], &mut io), 2);
    }

    #[test]
    fn install_runs_package_manager_with_sudo_password_on_stdin() {
        let (mut d, bin) = desk("install");
        let log = bin.join("log");
        // sudo -n fails (needs password); sudo -S reads the password and runs the command, which
        // "installs" every required binary into the fake PATH.
        let mk = REQUIRED_BINARIES
            .iter()
            .map(|b| {
                format!(
                    "printf '#!/bin/sh\\n' > {0}/{b}; /bin/chmod +x {0}/{b}",
                    bin.display()
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        fake_bin(&bin, "sudo", &format!("if [ \"$1\" = -n ]; then exit 1; fi; read pw; echo \"pw=$pw args=$*\" >> {}; shift 3; \"$@\"", log.display()));
        fake_bin(&bin, "apt-get", &format!("echo installing; {mk}"));
        d.path = Some(bin.display().to_string());
        struct Pw(Vec<String>);
        impl Io for Pw {
            fn line(&mut self, s: &str) {
                self.0.push(s.into());
            }
            fn interactive(&self) -> bool {
                true
            }
            fn confirm(&mut self, q: &str) -> bool {
                self.0.push(q.into());
                true
            }
            fn password(&mut self) -> Option<String> {
                Some("hunter2".into())
            }
        }
        let mut io = Pw(vec![]);
        assert_eq!(
            screen_cli(&d, &["install".into()], &mut io),
            0,
            "{:?}",
            io.0
        );
        assert!(io.0.iter().any(|l| l == "installing"), "{:?}", io.0);
        assert!(
            io.0.iter().any(|l| l == "Proceed? [Y/n] "),
            "a terminal is asked before apt runs: {:?}",
            io.0
        );
        assert!(io.0.last().unwrap().contains("ready"));
        let l = std::fs::read_to_string(&log).unwrap();
        assert!(
            l.starts_with("pw=hunter2 args=-S -p  ") && l.contains("apt-get install -y"),
            "{l}"
        );
        assert!(
            !io.0.iter().any(|l| l.contains("hunter2")),
            "password never echoed"
        );
        let mut io = Collect::default();
        assert_eq!(screen_cli(&d, &["install".into()], &mut io), 0);
        assert_eq!(io.0, vec!["Bot Desktop: packages already installed."]);
    }

    #[test]
    fn start_status_stop_with_fake_launcher() {
        let (mut d, bin) = desk("start");
        for b in REQUIRED_BINARIES {
            fake_bin(&bin, b, "exit 0");
        }
        // The fake launcher publishes the env file + socket like launcher.sh, then idles.
        let l = bin.join("launcher.sh");
        std::fs::write(&l, "printf 'DISPLAY=:%s\\nXAUTHORITY=%s\\n' \"$ARK_BD_DISPLAY_NUM\" \"$ARK_BD_XAUTH\" > \"$ARK_BD_ENV_FILE\"; : > \"$ARK_BD_SOCKET\"; exec sleep 30\n").unwrap();
        d.launcher = Some(l);
        // :20 is taken by a live X server (lock names our own pid) → the next number is used.
        std::fs::write(
            d.x_lock_dir.join(".X20-lock"),
            format!("{}\n", std::process::id()),
        )
        .unwrap();
        std::fs::write(&d.unix_table, "x 1 0 0 1 1 1 @/tmp/.X11-unix/X21\n").unwrap();
        assert_eq!(d.pick_display().unwrap(), 22);
        let st = d.start().unwrap();
        assert!(st.running, "{st:?}");
        assert_eq!(st.display.as_deref(), Some(":22"));
        assert!(st.socket.unwrap().ends_with("rfb.sock"));
        // manager::desktop_env reads the same files.
        assert!(crate::manager::desktop_env(&d.home)
            .iter()
            .any(|(k, v)| k == "DISPLAY" && v == ":22"));
        let again = d.start().unwrap();
        assert_eq!(again.pid, st.pid, "idempotent");
        let mut io = Collect::default();
        assert_eq!(screen_cli(&d, &["status".into()], &mut io), 0);
        assert!(
            io.0[0].contains("running on DISPLAY :22") && io.0[1].contains("control: agent"),
            "{:?}",
            io.0
        );
        assert!(io.0[2].contains("/view/desktop"), "{:?}", io.0);
        // `status --json` carries the pane payload (Hermes `DesktopStatus.as_dict` + the lease).
        let mut io = Collect::default();
        assert_eq!(screen_cli(&d, &["status".into(), "--json".into()], &mut io), 0);
        let v: Value = serde_json::from_str(&io.0.join("\n")).unwrap();
        assert_eq!(v["running"], true);
        assert_eq!(v["placement"], "gateway");
        assert!(v["image_switch"].is_null());
        assert!(v["lease"].is_object(), "{v}");
        for k in [
            "profile",
            "supported",
            "installed",
            "missing",
            "running",
            "pid",
            "display",
            "socket",
            "geometry",
            "install_command",
            "browser",
            "blocker",
            "memory_available_mb",
            "memory_limit_mb",
        ] {
            assert!(v.get(k).is_some(), "status payload lost `{k}`: {v}");
        }
        // A human holds the screen: stop refuses without --force.
        lease::acquire(&d.home, "viewer-x", "login").unwrap();
        let mut io = Collect::default();
        assert_eq!(screen_cli(&d, &["stop".into()], &mut io), 1);
        assert!(io.0[0].contains("--force"));
        let mut io = Collect::default();
        assert_eq!(
            screen_cli(&d, &["stop".into(), "--force".into()], &mut io),
            0
        );
        assert_eq!(io.0, vec!["Bot Desktop: stopped"]);
        assert!(!d.status().running);
        let pid = st.pid.unwrap();
        std::thread::sleep(Duration::from_millis(200));
        assert!(!util::pid_alive(pid));
        let mut io = Collect::default();
        screen_cli(&d, &["stop".into()], &mut io);
        assert_eq!(io.0, vec!["Bot Desktop: was not running"]);
    }

    #[test]
    fn failed_launch_reports_log_tail_and_frees_display() {
        let (mut d, bin) = desk("fail");
        for b in REQUIRED_BINARIES {
            fake_bin(&bin, b, "exit 0");
        }
        let l = bin.join("launcher.sh");
        std::fs::write(&l, "echo 'Xvnc exited during startup' >&2; exit 3\n").unwrap();
        d.launcher = Some(l);
        let e = d.start().unwrap_err();
        assert!(
            e.contains("exited with 3") && e.contains("Xvnc exited during startup"),
            "{e}"
        );
        assert!(!d.state_dir().join("display").exists());
        let mut io = Collect::default();
        assert_eq!(screen_cli(&d, &["start".into()], &mut io), 1);
    }

    #[test]
    fn embedded_launcher_seeds_config_only() {
        // launcher.sh's seed-only mode builds the xfconf tree without an X server.
        let root = scratch("seed");
        let cfg = root.join("xdg");
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(LAUNCHER)
            .env("ARK_BD_PROFILE", "t")
            .env("ARK_BD_DISPLAY_NUM", "77")
            .env("ARK_BD_SOCKET", root.join("s/rfb.sock"))
            .env("ARK_BD_XAUTH", root.join("Xa"))
            .env("ARK_BD_ENV_FILE", root.join("env"))
            .env("ARK_BD_CONFIG_HOME", &cfg)
            .env("ARK_BD_SEED_ONLY", "1")
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap();
        if !out.status.success() && String::from_utf8_lossy(&out.stderr).contains("xauth") {
            return; // host without xauth: the seed step needs it before seeding
        }
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let x = cfg.join("xfce4/xfconf/xfce-perchannel-xml");
        assert!(std::fs::read_to_string(x.join("xfce4-screensaver.xml"))
            .unwrap()
            .contains("\"enabled\" type=\"bool\" value=\"false\""));
        assert!(x.join("xfce4-panel.xml").exists());
        assert!(cfg.join("autostart/light-locker.desktop").exists());
    }
}
