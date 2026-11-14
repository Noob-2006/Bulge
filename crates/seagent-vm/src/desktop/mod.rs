//! Graphical desktop VMs (`[desktop_vm]`, `seagent vm desktop …`): a QEMU guest with a real
//! screen that the agent operates purely through screenshots and simulated mouse/keyboard
//! (computer use) and that a human can watch and take over from the web console.
//!
//! Unlike the tool-isolation microVMs in [`crate::pool`] (no display, no NIC, guest agent
//! channel), a desktop VM is a whole Debian + Xfce + Chromium machine:
//! * `-machine q35` with KVM when `/dev/kvm` is usable (TCG with a warning otherwise);
//! * a std VGA adapter whose EDID prefers the configured size (default 1280×800), read
//!   back with QMP `screendump` (PNG) — no VNC client is needed to see it;
//! * a USB tablet (absolute pointer) and the PS/2 keyboard, driven with QMP
//!   `input-send-event` ([`qmp::deliver`]);
//! * QEMU's own VNC server on a private unix socket (`vnc.sock`) for full-rate viewers, and
//!   the QMP socket (`qmp.sock`), both in `<runtime>/dvm/<name>/` (0700);
//! * user-mode NAT networking (`network = "user"`), or none; with it, the guest Chromium's
//!   DevTools port is forwarded to a free port on host loopback and named in
//!   `<data>/vm/desktop/<name>/cdp.url` while the VM runs, so seagent's browser tools drive the
//!   window a person sees (any local user can reach a loopback port, as with `cdp_url`);
//! * a persistent copy-on-write disk per VM: `<data>/vm/desktop/<name>/disk.qcow2` on top of
//!   the provisioned image in `<cache>/desktop-vm/` ([`image`]);
//! * the human-takeover control lease (same format as the Bot Desktop one) lives in
//!   `<data>/vm/desktop/<name>/bot-desktop/lease.json` ([`DesktopVms::lease_home`]).
//!
//! QEMU daemonizes (`-daemonize -pidfile`), so a VM outlives the CLI that started it; a VM
//! is "running" while its pid is alive *and* that process's command line names this VM's
//! QMP socket (pid reuse cannot be mistaken for it). [`DesktopVms::reap`] clears what a dead
//! VM left behind and stops VMs idle past `idle_timeout_secs`.
//!
//! Other hosts (docs/cross-platform.md): macOS runs the same QEMU with `hvf` (Intel Macs; the
//! desktop image is x86_64, so Apple Silicon emulates it under TCG and says so) and unix
//! sockets. Windows QEMU has neither unix sockets nor `-daemonize`: QMP and the text port are
//! TCP servers on 127.0.0.1 whose ports are recorded in the `qmp.sock` / `text.sock` files
//! ([`crate::channel::Endpoint`]), there is no VNC socket, the detached QEMU's pid is written
//! by seagent, and `whpx` accelerates it when the Windows Hypervisor Platform is on.

pub mod agent;
pub mod config;
pub mod fake;
pub mod image;
pub mod keys;
pub mod mux;
pub mod qmp;
pub mod timezone;

pub use config::DesktopConfig;
pub use qmp::Input;

use crate::channel::Endpoint;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Bumped when the image layout (what the provisioner sets up) changes incompatibly.
/// 4: the in-VM shell agent service (`seagent-agent.service`, [`agent`]).
pub const IMAGE_LAYOUT: u32 = 4;

/// `<vm_dir>/cdp.url`: read by seagent-browser (`manager::VM_CDP_FILE`) to drive the guest Chromium.
pub const CDP_FILE: &str = "cdp.url";
/// Guest port of the DevTools relay (`seagent-cdp-relay.service` in the image).
const GUEST_CDP_PORT: u16 = 9223;

/// A port on host loopback nobody listens on right now (QEMU binds it a moment later).
fn free_loopback_port() -> Result<u16, String> {
    std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).map(|a| a.port()).map_err(|e| format!("no free loopback port for the VM browser: {e}"))
}

/// VM names: `[a-z0-9][a-z0-9-]{0,31}` (they become directory names and QEMU `-name`).
pub fn valid_name(n: &str) -> Result<(), String> {
    let ok = !n.is_empty() && n.len() <= 32 && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') && !n.starts_with('-');
    if ok {
        Ok(())
    } else {
        Err(format!("`{n}` is not a desktop VM name (1-32 of a-z, 0-9, '-', not starting with '-')"))
    }
}

pub(crate) fn now_s() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub(crate) fn resolve_bin(b: &str) -> Result<PathBuf, String> {
    crate::isolation::which(b).or_else(|| package_manager_bin(b)).ok_or_else(|| format!("`{b}` not found ({}, or set [desktop_vm] qemu / qemu_img)", qemu_install_hint()))
}

/// A bare name in the package managers' prefixes that a GUI app's PATH leaves out (an app
/// started from Finder / the Dock gets launchd's `/usr/bin:/bin:/usr/sbin:/sbin`, without
/// Homebrew's `/opt/homebrew/bin` or MacPorts' `/opt/local/bin`).
fn package_manager_bin(b: &str) -> Option<PathBuf> {
    if b.contains('/') || b.contains('\\') {
        return None;
    }
    let dirs: &[&str] = if cfg!(target_os = "macos") { &["/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin"] } else if cfg!(unix) { &["/usr/local/bin", "/usr/bin", "/snap/bin"] } else { &[] };
    dirs.iter().map(|d| Path::new(d).join(b)).find(|p| p.is_file())
}

/// How this host gets QEMU (the Windows installer ships it; elsewhere it is the system's).
pub fn qemu_install_hint() -> &'static str {
    if cfg!(windows) {
        "reinstall SE Agent: the installer ships QEMU in vm\\runtime\\qemu"
    } else if cfg!(target_os = "macos") {
        "install QEMU: `brew install qemu` (Homebrew) or `sudo port install qemu` (MacPorts)"
    } else {
        "install QEMU: Debian/Ubuntu `sudo apt install qemu-system-x86 qemu-utils`, Fedora `sudo dnf install qemu-system-x86 qemu-img`, Arch `sudo pacman -S qemu-desktop`"
    }
}

pub(crate) fn run_tool(bin: &Path, args: &[&str]) -> Result<String, String> {
    let o = crate::host::command(bin).args(args).stdin(Stdio::null()).output().map_err(|e| format!("{}: {e}", bin.display()))?;
    if !o.status.success() {
        return Err(format!("{} {}: {}", bin.display(), args.first().unwrap_or(&""), String::from_utf8_lossy(&o.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Is `/dev/kvm` usable by this user?
pub fn kvm_usable() -> bool {
    crate::host::kvm_usable()
}

/// The accelerator for `cfg.accel`, with the warning to show when it is the slow one.
pub fn accel(cfg: &DesktopConfig) -> (&'static str, Option<String>) {
    match cfg.accel.as_str() {
        "tcg" => ("tcg", Some("desktop_vm.accel = \"tcg\": software emulation, expect a slow desktop".into())),
        "kvm" => ("kvm", None),
        "whpx" => ("whpx", None),
        "hvf" => ("hvf", None),
        _ if cfg!(windows) && crate::host::whpx_available() => ("whpx", None),
        _ if cfg!(windows) => ("tcg", Some("the Windows Hypervisor Platform is not enabled: the desktop VM runs under TCG software emulation (slow). Enable the optional feature `HypervisorPlatform` for -accel whpx.".into())),
        // The desktop image is x86_64: HVF accelerates it on Intel Macs only.
        _ if cfg!(target_os = "macos") && cfg!(target_arch = "x86_64") && crate::host::hvf_available() => ("hvf", None),
        _ if cfg!(target_os = "macos") => ("tcg", Some("the desktop image is x86_64 and this Mac cannot accelerate it (Apple Silicon, or no Hypervisor.framework): it runs under TCG software emulation (slow)".into())),
        _ if kvm_usable() => ("kvm", None),
        _ => ("tcg", Some("/dev/kvm is missing or not writable: the desktop VM runs under TCG software emulation (slow). Add this user to the `kvm` group for hardware virtualisation.".into())),
    }
}

/// What `status` / `list` report for one VM (also the `view.desktop.list` source).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct VmStatus {
    pub name: String,
    pub running: bool,
    pub pid: Option<u32>,
    pub width: u32,
    pub height: u32,
    pub accel: String,
    pub memory_mb: u32,
    pub cpus: u16,
    pub disk: String,
    pub disk_exists: bool,
    pub image: String,
    pub image_built: bool,
    pub qmp: String,
    pub vnc: String,
    /// The guest Chromium's DevTools endpoint on host loopback (running, user networking).
    pub cdp: Option<String>,
    pub console_log: String,
    pub started_at: Option<u64>,
    pub idle_secs: Option<u64>,
    pub warning: Option<String>,
}

/// One QMP user at a time per VM (QEMU serves a single QMP client per socket).
fn qmp_lock(sock: &Path) -> Arc<Mutex<()>> {
    static M: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();
    M.get_or_init(Default::default).lock().unwrap().entry(sock.to_path_buf()).or_default().clone()
}

fn pid_alive(pid: u32) -> bool {
    crate::host::pid_alive(pid)
}

fn private_dir(p: &Path) -> Result<(), String> {
    crate::host::private_dir(p)
}

/// The endpoint behind one of the VM's socket names (the socket itself on unix).
fn endpoint(p: &Path) -> Endpoint {
    Endpoint::locate(p).unwrap_or_else(|_| Endpoint::Unix(p.to_path_buf()))
}

/// What a VM leaves in its run dir while it runs (cleared at start and stop).
const RUN_FILES: &[&str] = &["qmp.sock", "vnc.sock", "text.sock", "chan.sock", "chan.key", "agent.bin", "qemu.pid", "screen", "last_used"];

/// Write a file only this user can read (the run dir is 0700 already; the key is 0600 too).
fn write_private(p: &Path, data: &[u8]) -> Result<(), String> {
    std::fs::write(p, data).map_err(|e| format!("write {}: {e}", p.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// QEMU arguments for the guest agent channel, on the VM's existing virtio-serial bus: the
/// `seagent0` port (exactly the microVM provider's chardev + port), the per-boot key by fw_cfg
/// when the channel is a loopback TCP port other local processes could reach (Windows), and
/// this boot's agent binary by fw_cfg when the host has one.
pub fn channel_args(chan: &Endpoint, key: &Path, agent_bin: Option<&Path>) -> Vec<String> {
    let mut a = vec!["-chardev".into(), chan.qemu_chardev(agent::GUEST_PORT), "-device".into(), format!("virtserialport,chardev={0},name={0}", agent::GUEST_PORT)];
    if matches!(chan, Endpoint::Tcp(_)) {
        a.extend(["-fw_cfg".into(), format!("name={},file={}", crate::proto::FW_CFG_KEY_NAME, key.display())]);
    }
    if let Some(b) = agent_bin {
        a.extend(["-fw_cfg".into(), format!("name={},file={}", agent::FW_CFG_AGENT_NAME, b.display())]);
    }
    a
}

/// Connected agent channels, per VM run dir, with the QEMU pid they belong to.
type Channels = Mutex<HashMap<PathBuf, (u32, Arc<mux::Mux>)>>;

fn channels() -> &'static Channels {
    static C: OnceLock<Channels> = OnceLock::new();
    C.get_or_init(Default::default)
}

fn forget_channel(run: &Path) {
    if let Some((_, m)) = channels().lock().unwrap().remove(run) {
        m.shutdown();
    }
}

/// The desktop VMs of one seagent home.
#[derive(Debug, Clone)]
pub struct DesktopVms {
    pub cfg: DesktopConfig,
    data: PathBuf,
    cache: PathBuf,
    runtime: PathBuf,
}

impl DesktopVms {
    /// `data` / `cache` / `runtime` are the seagent home's (`seagent_kernel::config::Paths`).
    pub fn new(cfg: DesktopConfig, data: &Path, cache: &Path, runtime: &Path) -> DesktopVms {
        DesktopVms { cfg, data: data.to_path_buf(), cache: cache.to_path_buf(), runtime: runtime.to_path_buf() }
    }

    pub fn image_dir(&self) -> PathBuf {
        self.cache.join("desktop-vm")
    }
    /// The provisioned image for the current config (exists once `build` ran).
    pub fn image_path(&self) -> PathBuf {
        self.image_dir().join(format!("desktop-{}.qcow2", image::recipe(&self.cfg)))
    }
    pub fn image_built(&self) -> bool {
        self.image_path().is_file() && self.image_path().with_extension("json").is_file()
    }
    /// The image manifest (`build` writes it), if built.
    pub fn image_manifest(&self) -> Option<Value> {
        serde_json::from_str(&std::fs::read_to_string(self.image_path().with_extension("json")).ok()?).ok()
    }
    /// Was the image provisioned with the in-VM agent service (the shell runs inside the VM)?
    /// `false` for an image built before it: rebuild with `seagent vm desktop build --force`.
    pub fn image_has_agent(&self) -> bool {
        self.image_manifest().is_some_and(|m| m["guest_agent"]["service"].as_bool() == Some(true))
    }

    /// The image the disk overlay of `name` was made from, when that image predates the in-VM
    /// agent (or is gone) while the current one has it: such an overlay never runs the shell.
    pub fn stale_overlay(&self, name: &str) -> Option<PathBuf> {
        if !self.disk_path(name).is_file() || !self.image_has_agent() {
            return None;
        }
        let old = PathBuf::from(self.state(name)["image"].as_str()?);
        if old == self.image_path() {
            return None;
        }
        let has_agent = std::fs::read_to_string(old.with_extension("json")).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()).is_some_and(|m| m["guest_agent"]["service"].as_bool() == Some(true));
        (!has_agent || !old.is_file()).then_some(old)
    }

    /// The agent channel of running VM `name` (connected once, shared by every caller, and
    /// reconnected after the VM or the channel went away). `wait`: how long a VM that is still
    /// booting may take to bring its agent up.
    pub fn channel(&self, name: &str, wait: Duration) -> Result<Arc<mux::Mux>, String> {
        valid_name(name)?;
        let Some(pid) = self.pid(name) else {
            return Err(format!("desktop VM `{name}` is not running (start it with `seagent vm desktop start {name}`)"));
        };
        let run = self.run_dir(name);
        let l = qmp_lock(&self.chan_path(name));
        let _g = l.lock().unwrap();
        if let Some((p, m)) = channels().lock().unwrap().get(&run) {
            if *p == pid && m.alive() {
                return Ok(m.clone());
            }
        }
        forget_channel(&run);
        let m = self.connect_agent(name, wait)?;
        channels().lock().unwrap().insert(run, (pid, m.clone()));
        Ok(m)
    }

    fn connect_agent(&self, name: &str, wait: Duration) -> Result<Arc<mux::Mux>, String> {
        let hint = || {
            if self.image_has_agent() {
                format!("is it still booting? the agent logs to the guest journal (`journalctl -u seagent-agent`); console: {}", self.vm_dir(name).join("console.log").display())
            } else {
                "the desktop image predates the in-VM shell: rebuild it with `seagent vm desktop build --force`, then restart the VM".to_string()
            }
        };
        let deadline = Instant::now() + wait;
        let ch = crate::channel::Channel::connect(&self.chan_path(name), crate::channel::Transport::Serial, wait).map_err(|e| format!("agent channel of desktop VM `{name}`: {e} (VM started by an older seagent? restart it)"))?;
        if let Some(key) = std::fs::read(self.chan_key_path(name)).ok().filter(|k| !k.is_empty()) {
            ch.authenticate(&key, wait).map_err(|e| format!("the agent in desktop VM `{name}` did not answer: {e}; {}", hint()))?;
            return Ok(mux::Mux::new(ch));
        }
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match ch.recv(left.clamp(Duration::from_millis(1), Duration::from_secs(1)))? {
                Some(h @ crate::proto::GuestMsg::Hello { .. }) => return Ok(mux::Mux::with_greeting(ch, Some(h))),
                // The guest's Hello went to an earlier connection; it answers, so it is up.
                Some(crate::proto::GuestMsg::Pong { .. }) => return Ok(mux::Mux::with_greeting(ch, None)),
                Some(_) => {}
                None if left.is_zero() => return Err(format!("the agent in desktop VM `{name}` did not answer within {}s: {}", wait.as_secs(), hint())),
                None => ch.send(&crate::proto::HostMsg::Ping { id: 0 })?,
            }
        }
    }

    pub fn vm_dir(&self, name: &str) -> PathBuf {
        self.data.join("vm").join("desktop").join(name)
    }
    pub fn run_dir(&self, name: &str) -> PathBuf {
        self.runtime.join("dvm").join(name)
    }
    pub fn qmp_path(&self, name: &str) -> PathBuf {
        self.run_dir(name).join("qmp.sock")
    }
    /// Host end of the guest's `org.seagent.text` port (non-ASCII typing).
    pub fn text_path(&self, name: &str) -> PathBuf {
        self.run_dir(name).join("text.sock")
    }
    pub fn vnc_path(&self, name: &str) -> PathBuf {
        self.run_dir(name).join("vnc.sock")
    }
    /// Host end of the guest agent channel (virtio-serial port `seagent0`, [`agent`]).
    pub fn chan_path(&self, name: &str) -> PathBuf {
        self.run_dir(name).join("chan.sock")
    }
    /// The per-boot channel key (loopback TCP channels, i.e. Windows), given to the guest by fw_cfg.
    pub fn chan_key_path(&self, name: &str) -> PathBuf {
        self.run_dir(name).join("chan.key")
    }
    /// The agent binary given to the guest by fw_cfg at this boot ([`agent::FW_CFG_AGENT_NAME`]).
    pub fn agent_bin_path(&self, name: &str) -> PathBuf {
        self.run_dir(name).join("agent.bin")
    }
    fn pid_path(&self, name: &str) -> PathBuf {
        self.run_dir(name).join("qemu.pid")
    }
    fn disk_path(&self, name: &str) -> PathBuf {
        self.vm_dir(name).join("disk.qcow2")
    }
    /// The guest Chromium's DevTools URL on the host while `name` runs (see `cmdline`).
    pub fn cdp_url(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(self.vm_dir(name).join(CDP_FILE)).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
    }
    /// The `home` the human-takeover lease of this VM lives under (`<home>/bot-desktop/lease.json`).
    pub fn lease_home(&self, name: &str) -> PathBuf {
        self.vm_dir(name)
    }

    /// Known VMs: every one with a directory, plus the configured default.
    pub fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(self.data.join("vm").join("desktop")).into_iter().flatten().flatten().filter(|e| e.path().is_dir()).map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| valid_name(n).is_ok()).collect();
        if !v.contains(&self.cfg.default) {
            v.push(self.cfg.default.clone());
        }
        v.sort();
        v
    }

    /// The live QEMU pid of `name`, if it runs.
    pub fn pid(&self, name: &str) -> Option<u32> {
        let pid: u32 = std::fs::read_to_string(self.pid_path(name)).ok()?.trim().parse().ok()?;
        if !pid_alive(pid) {
            return None;
        }
        let cmd = crate::host::process_identity(pid)?;
        if cfg!(windows) {
            // Windows reports the image path only; the pid file is ours and private.
            return cmd.to_ascii_lowercase().contains("qemu").then_some(pid);
        }
        let want = self.qmp_path(name).display().to_string();
        cmd.contains(&want).then_some(pid)
    }
    pub fn is_running(&self, name: &str) -> bool {
        self.pid(name).is_some()
    }

    fn state(&self, name: &str) -> Value {
        std::fs::read_to_string(self.vm_dir(name).join("state.json")).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null)
    }

    /// Current framebuffer size: the last frame's, else the configured one.
    pub fn screen_size(&self, name: &str) -> (u32, u32) {
        std::fs::read_to_string(self.run_dir(name).join("screen"))
            .ok()
            .and_then(|s| {
                let (w, h) = s.trim().split_once('x')?;
                Some((w.parse().ok()?, h.parse().ok()?))
            })
            .unwrap_or((self.cfg.width, self.cfg.height))
    }

    /// Count an action in the VM (a shell command) as use, for `idle_timeout_secs`.
    pub fn mark_used(&self, name: &str) {
        if self.is_running(name) {
            self.touch(name);
        }
    }

    fn touch(&self, name: &str) {
        let _ = std::fs::write(self.run_dir(name).join("last_used"), now_s().to_string());
    }

    fn idle_secs(&self, name: &str) -> Option<u64> {
        let t: u64 = std::fs::read_to_string(self.run_dir(name).join("last_used")).ok()?.trim().parse().ok()?;
        Some(now_s().saturating_sub(t))
    }

    pub fn status(&self, name: &str) -> VmStatus {
        let pid = self.pid(name);
        let st = self.state(name);
        let (w, h) = if pid.is_some() { self.screen_size(name) } else { (self.cfg.width, self.cfg.height) };
        VmStatus {
            name: name.to_string(),
            running: pid.is_some(),
            pid,
            width: w,
            height: h,
            accel: st["accel"].as_str().map(str::to_string).unwrap_or_else(|| accel(&self.cfg).0.to_string()),
            memory_mb: self.cfg.memory_mb,
            cpus: self.cfg.cpus,
            disk: self.disk_path(name).display().to_string(),
            disk_exists: self.disk_path(name).is_file(),
            image: self.image_path().display().to_string(),
            image_built: self.image_built(),
            qmp: self.qmp_path(name).display().to_string(),
            vnc: self.vnc_path(name).display().to_string(),
            cdp: pid.and_then(|_| self.cdp_url(name)),
            console_log: self.vm_dir(name).join("console.log").display().to_string(),
            started_at: pid.and(st["started_at"].as_u64()),
            idle_secs: pid.and_then(|_| self.idle_secs(name)),
            warning: st["warning"].as_str().map(str::to_string),
        }
    }

    pub fn list(&self) -> Vec<VmStatus> {
        self.names().iter().map(|n| self.status(n)).collect()
    }

    /// The QEMU arguments for `name` (split out so tests can assert the machine shape).
    /// `cdp_port`: host loopback port forwarded to the guest's DevTools relay (user networking).
    pub fn cmdline(&self, name: &str, image_disk: &Path, accel: &str, cdp_port: Option<u16>) -> Vec<String> {
        let c = &self.cfg;
        // VGA memory: two full frames at 32 bpp, rounded up to a power of two (≥ 16 MiB).
        let vgamem = ((c.width as u64 * c.height as u64 * 8) >> 20).max(16).next_power_of_two();
        let url = c.start_url.replace(',', ",,");
        let mut a: Vec<String> = vec![
            "-name".into(),
            format!("seagent-desktop-{name}"),
            "-machine".into(),
            if accel == "whpx" { "q35,accel=whpx,kernel-irqchip=off".into() } else { format!("q35,accel={accel}") },
            "-cpu".into(),
            if accel == "kvm" || accel == "hvf" { "host".into() } else { "max".into() },
            "-smp".into(),
            c.cpus.to_string(),
            "-m".into(),
            c.memory_mb.to_string(),
            "-drive".into(),
            format!("file={},if=virtio,format=qcow2,discard=unmap", image_disk.display()),
            "-device".into(),
            format!("VGA,xres={},yres={},edid=on,vgamem_mb={vgamem}", c.width, c.height),
            "-device".into(),
            "qemu-xhci,id=xhci".into(),
            "-device".into(),
            "usb-tablet,bus=xhci.0".into(),
            "-device".into(),
            "virtio-rng-pci".into(),
            // Text channel for non-ASCII typing (`org.seagent.text`, see `type_text`).
            "-device".into(),
            "virtio-serial-pci".into(),
            "-chardev".into(),
            endpoint(&self.text_path(name)).qemu_chardev("seagenttext"),
            "-device".into(),
            "virtserialport,chardev=seagenttext,name=org.seagent.text".into(),
        ];
        let agent_bin = self.agent_bin_path(name);
        a.extend(channel_args(&endpoint(&self.chan_path(name)), &self.chan_key_path(name), agent_bin.is_file().then_some(agent_bin.as_path())));
        a.extend([
            "-smbios".into(),
            format!("type=11,value=seagent-res={}x{},value=seagent-url={url}", c.width, c.height),
        ]);
        // The guest's clock follows the host's zone (or the configured one); valid_tz keeps
        // commas and shell characters out of the SMBIOS string.
        if let Some(tz) = timezone::resolve(&c.timezone).filter(|t| timezone::valid_tz(t)) {
            if let Some(s) = a.last_mut() {
                s.push_str(&format!(",value=seagent-tz={tz}"));
            }
        }
        if c.network == "user" {
            let fwd = cdp_port.map(|p| format!(",hostfwd=tcp:127.0.0.1:{p}-:{GUEST_CDP_PORT}")).unwrap_or_default();
            a.extend(["-netdev".into(), format!("user,id=n0{fwd}"), "-device".into(), "virtio-net-pci,netdev=n0".into()]);
        } else {
            a.extend(["-nic".into(), "none".into()]);
        }
        // VNC on a private unix socket. Windows QEMU has no unix sockets and frames come over QMP
        // anyway, so no VNC server at all there (`-vnc none` still loads a keymap file the
        // bundle does not ship) and no window either.
        if cfg!(unix) {
            a.extend(["-vnc".into(), format!("unix:{}", self.vnc_path(name).display())]);
        } else {
            a.extend(["-display".into(), "none".into()]);
        }
        a.extend([
            "-qmp".into(),
            endpoint(&self.qmp_path(name)).qemu_monitor(),
            "-monitor".into(),
            "none".into(),
            "-parallel".into(),
            "none".into(),
            "-serial".into(),
            format!("file:{}", self.vm_dir(name).join("console.log").display()),
            "-pidfile".into(),
            self.pid_path(name).display().to_string(),
        ]);
        if cfg!(unix) {
            a.push("-daemonize".into());
        }
        a
    }

    /// Boot `name` (creating its disk overlay on first use). Idempotent: a running VM is
    /// reported as is.
    pub fn start(&self, name: &str) -> Result<VmStatus, String> {
        valid_name(name)?;
        if self.is_running(name) {
            return Ok(self.status(name));
        }
        let img = self.image_path();
        if !self.image_built() {
            return Err(format!("no desktop image yet ({}): run `seagent vm desktop build` first", img.display()));
        }
        let qemu = resolve_bin(&self.cfg.qemu)?;
        let (vm, run) = (self.vm_dir(name), self.run_dir(name));
        private_dir(&vm)?;
        private_dir(&run)?;
        if cfg!(unix) && [self.qmp_path(name), self.vnc_path(name), self.text_path(name), self.chan_path(name)].iter().any(|p| p.as_os_str().len() > 100) {
            return Err(format!("runtime dir {} is too long for unix sockets (≤ 100 bytes); set a shorter SEAGENT runtime dir", run.display()));
        }
        for p in [&vm, &run, &img] {
            if p.to_string_lossy().contains(',') {
                return Err(format!("{} contains ',', which QEMU option syntax cannot carry", p.display()));
            }
        }
        for f in RUN_FILES {
            let _ = std::fs::remove_file(run.join(f));
        }
        let disk = self.disk_path(name);
        // An overlay made from an image without the in-VM agent could never run the shell in
        // the VM: it is kept once as `disk.qcow2.prev` and a fresh one starts from this image.
        let stale = self.stale_overlay(name);
        if stale.is_some() {
            std::fs::rename(&disk, disk.with_extension("qcow2.prev")).map_err(|e| format!("set aside the old disk of `{name}`: {e}"))?;
        }
        if !disk.is_file() {
            let qemu_img = resolve_bin(&self.cfg.qemu_img)?;
            run_tool(&qemu_img, &["create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", &img.display().to_string(), &disk.display().to_string()])?;
        }
        let (acc, warn) = accel(&self.cfg);
        let _ = std::fs::remove_file(vm.join(CDP_FILE));
        let cdp_port = if self.cfg.network == "user" { Some(free_loopback_port()?) } else { None };
        if !cfg!(unix) {
            // Loopback ports for QMP and the text channel, recorded where the sockets would be.
            Endpoint::allocate(&self.qmp_path(name))?;
            Endpoint::allocate(&self.text_path(name))?;
            // The agent channel is a loopback port any local process can reach: both ends prove
            // a per-boot key before a frame counts (`Channel::authenticate`), as the microVMs do.
            if let Endpoint::Tcp(_) = Endpoint::allocate(&self.chan_path(name))? {
                write_private(&self.chan_key_path(name), crate::proto::random_hex(32).as_bytes())?;
            }
        }
        // This boot's agent (fw_cfg); without one the copy baked into the image runs.
        let agent = agent::find(&self.data).and_then(|a| write_private(&self.agent_bin_path(name), &a.bytes).map(|_| a));
        if cfg!(unix) {
            let out = crate::host::command(&qemu).args(self.cmdline(name, &disk, acc, cdp_port)).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).output().map_err(|e| format!("start {}: {e}", qemu.display()))?;
            if !out.status.success() {
                return Err(format!("qemu failed to start the desktop VM: {}", String::from_utf8_lossy(&out.stderr).trim()));
            }
        } else {
            // No -daemonize on Windows: a detached QEMU whose pid seagent records itself.
            let log = std::fs::File::create(vm.join("qemu.log")).map_err(|e| e.to_string())?;
            let child = crate::host::spawn_vmm(crate::host::command(&qemu).args(self.cmdline(name, &disk, acc, cdp_port)).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::from(log))).map_err(|e| format!("start {}: {e}", qemu.display()))?;
            std::fs::write(self.pid_path(name), child.id().to_string()).map_err(|e| e.to_string())?;
        }
        let t0 = Instant::now();
        let qmp_up = |n: &str| cfg!(unix) || endpoint(&self.qmp_path(n)).connect().is_ok();
        while !(self.qmp_path(name).exists() && self.is_running(name) && qmp_up(name)) {
            if t0.elapsed() > Duration::from_secs(15) {
                self.kill(name);
                return Err("qemu daemonized but its QMP socket never appeared".into());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let warn = match (&stale, warn) {
            (Some(old), w) => Some(format!("{}the old disk of `{name}` was made from an image without the in-VM shell ({}); it is kept as disk.qcow2.prev and `{name}` started from the current image", w.map(|w| format!("{w}; ")).unwrap_or_default(), old.display())),
            (None, w) => w,
        };
        let agent_state = match &agent {
            Ok(a) => json!({"sha256": a.sha256, "source": a.source}),
            Err(e) => json!({"error": e}),
        };
        let state = json!({"started_at": now_s(), "accel": acc, "warning": warn, "image": img.display().to_string(), "width": self.cfg.width, "height": self.cfg.height, "agent": agent_state});
        std::fs::write(vm.join("state.json"), state.to_string()).map_err(|e| e.to_string())?;
        if let Some(p) = cdp_port {
            std::fs::write(vm.join(CDP_FILE), format!("http://127.0.0.1:{p}\n")).map_err(|e| e.to_string())?;
        }
        self.touch(name);
        Ok(self.status(name))
    }

    fn wait_exit(&self, pid: u32, d: Duration) -> bool {
        let t0 = Instant::now();
        while pid_alive(pid) {
            if t0.elapsed() > d {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        true
    }

    fn cleanup(&self, name: &str) {
        forget_channel(&self.run_dir(name));
        for f in RUN_FILES {
            let _ = std::fs::remove_file(self.run_dir(name).join(f));
        }
        let _ = std::fs::remove_file(self.vm_dir(name).join(CDP_FILE));
    }

    fn kill(&self, name: &str) {
        if let Some(pid) = self.pid(name) {
            // The pid was checked to be this VM's QEMU (command line names its socket).
            crate::host::kill_pid(pid, false);
            if !self.wait_exit(pid, Duration::from_secs(3)) {
                crate::host::kill_pid(pid, true);
                self.wait_exit(pid, Duration::from_secs(2));
            }
        }
        self.cleanup(name);
    }

    /// Stop `name`: ACPI power-off (clean guest shutdown, the disk overlay stays
    /// consistent), then QMP `quit`, then signals. `Ok(false)` = it was not running.
    pub fn stop(&self, name: &str) -> Result<bool, String> {
        valid_name(name)?;
        let Some(pid) = self.pid(name) else {
            self.cleanup(name);
            return Ok(false);
        };
        let qmp_cmd = |cmd: &str| {
            let l = qmp_lock(&self.qmp_path(name));
            let _g = l.lock().unwrap();
            qmp::Qmp::connect(&self.qmp_path(name), Duration::from_secs(5)).and_then(|mut q| q.execute(cmd, None)).is_ok()
        };
        if qmp_cmd("system_powerdown") && self.wait_exit(pid, Duration::from_secs(self.cfg.stop_timeout_secs)) {
            self.cleanup(name);
            return Ok(true);
        }
        qmp_cmd("quit");
        if !self.wait_exit(pid, Duration::from_secs(3)) {
            self.kill(name);
        }
        self.cleanup(name);
        Ok(true)
    }

    /// Stop `name` and delete its disk overlay (the next start begins from the current image).
    pub fn reset(&self, name: &str) -> Result<(), String> {
        self.stop(name)?;
        for f in ["disk.qcow2", "state.json"] {
            let p = self.vm_dir(name).join(f);
            if p.exists() {
                std::fs::remove_file(&p).map_err(|e| format!("remove {}: {e}", p.display()))?;
            }
        }
        Ok(())
    }

    /// Clear what dead VMs left behind and stop VMs idle past `idle_timeout_secs`.
    /// Returns how many VMs were stopped.
    pub fn reap(&self) -> usize {
        let mut n = 0;
        for name in self.names() {
            if !self.is_running(&name) {
                if self.run_dir(&name).join("qemu.pid").exists() {
                    self.cleanup(&name);
                }
                continue;
            }
            let t = self.cfg.idle_timeout_secs;
            if t > 0 && self.idle_secs(&name).is_some_and(|s| s >= t) && self.stop(&name).unwrap_or(false) {
                n += 1;
            }
        }
        n
    }

    fn with_qmp<T>(&self, name: &str, f: impl FnOnce(&mut qmp::Qmp) -> Result<T, String>) -> Result<T, String> {
        valid_name(name)?;
        let r = self.with_qmp_quiet(name, f);
        if self.is_running(name) {
            self.touch(name);
        }
        r
    }

    /// [`Self::with_qmp`] without touching the idle clock (a console watching the screen must
    /// not keep an otherwise idle VM alive).
    fn with_qmp_quiet<T>(&self, name: &str, f: impl FnOnce(&mut qmp::Qmp) -> Result<T, String>) -> Result<T, String> {
        valid_name(name)?;
        if !self.is_running(name) {
            return Err(format!("desktop VM `{name}` is not running (start it with `seagent vm desktop start {name}` or view.vm.start)"));
        }
        let l = qmp_lock(&self.qmp_path(name));
        let _g = l.lock().unwrap();
        let mut q = qmp::Qmp::connect(&self.qmp_path(name), Duration::from_secs(10))?;
        f(&mut q)
    }

    /// The VM's screen as PNG bytes.
    pub fn screenshot(&self, name: &str) -> Result<Vec<u8>, String> {
        valid_name(name)?;
        let png = self.peek(name);
        if self.is_running(name) {
            self.touch(name);
        }
        png
    }

    /// [`Self::screenshot`] for the console's live stream: does not count as use, so watching
    /// never keeps an idle VM from being stopped.
    pub fn peek(&self, name: &str) -> Result<Vec<u8>, String> {
        let tmp = self.run_dir(name).join(format!("frame-{}.png", seagent_net::crypto::hex(&seagent_net::crypto::sha256(format!("{:?}{}", std::thread::current().id(), now_s()).as_bytes()))[..10].to_owned()));
        let png = self.with_qmp_quiet(name, |q| q.screendump_png(&tmp))?;
        if let Some((w, h)) = qmp::png_size(&png) {
            let _ = std::fs::write(self.run_dir(name).join("screen"), format!("{w}x{h}"));
        }
        Ok(png)
    }

    /// Type text a US keyboard cannot (CJK, accents, emoji): one base64 line on the guest's
    /// `org.seagent.text` virtio-serial port; the guest session's `seagent-text-input` types it with
    /// xclip + ctrl+v, then answers "ok". Needs an image built with that helper (IMAGE_LAYOUT ≥ 2).
    pub fn type_text(&self, name: &str, text: &str) -> Result<usize, String> {
        use base64::Engine as _;
        use std::io::Write as _;
        valid_name(name)?;
        if !self.is_running(name) {
            return Err(format!("desktop VM `{name}` is not running"));
        }
        if text.len() > 16 * 1024 {
            return Err("text longer than 16 KiB".into());
        }
        let mut s = endpoint(&self.text_path(name)).connect().map_err(|e| format!("text channel of `{name}`: {e} (VM started by an older seagent?)"))?;
        s.set_write_timeout(Some(Duration::from_secs(5))).ok();
        let line = format!("{}\n", base64::engine::general_purpose::STANDARD.encode(text.as_bytes()));
        s.write_all(line.as_bytes()).map_err(|e| format!("text channel write: {e}"))?;
        // Stay connected until the guest says it typed it: QEMU only drains the socket while the
        // guest has the port open, and a disconnect before that would drop the text.
        let n = text.chars().count();
        s.set_read_timeout(Some(Duration::from_millis(5000 + 120 * n as u64))).ok();
        let mut ack = String::new();
        std::io::BufRead::read_line(&mut std::io::BufReader::new(&s), &mut ack).map_err(|e| format!("the guest did not confirm the text ({e}); is this an image without seagent-text-input? rebuild with `seagent vm desktop build` and `seagent vm desktop reset`"))?;
        if ack.trim() != "ok" {
            return Err(format!("the guest text helper answered {:?}", ack.trim()));
        }
        self.touch(name);
        Ok(n)
    }

    /// Deliver one input event (screen pixels). `{ok, type, typed?}`. ASCII text goes over QMP
    /// key events; text with other characters goes over the guest text channel ([`Self::type_text`]).
    pub fn input(&self, name: &str, ev: &Input) -> Result<Value, String> {
        if !self.run_dir(name).join("screen").exists() && matches!(ev, Input::Move { .. } | Input::Click { x: Some(_), .. } | Input::Drag { .. } | Input::Down { x: Some(_), .. } | Input::Up { x: Some(_), .. } | Input::Scroll { x: Some(_), .. }) {
            // Learn the real framebuffer size once so pixel coordinates scale exactly.
            self.screenshot(name)?;
        }
        let (w, h) = self.screen_size(name);
        if let Input::Type { text } = ev {
            if text.chars().any(|c| c != '\n' && keys::char_key(c).is_none()) {
                // Pasting a newline does not submit (an address bar keeps it as text), so each
                // line goes through the channel and every newline is a real Enter key press.
                let mut n = 0;
                for (i, line) in text.split('\n').enumerate() {
                    if i > 0 {
                        self.with_qmp(name, |q| qmp::deliver(q, &Input::Key { keys: "Enter".into() }, w, h))?;
                        n += 1;
                    }
                    if !line.is_empty() {
                        n += self.type_text(name, line)?;
                    }
                }
                return Ok(json!({"ok": true, "type": "type", "width": w, "height": h, "typed": n, "via": "text-channel"}));
            }
        }
        let typed = self.with_qmp(name, |q| qmp::deliver(q, ev, w, h))?;
        let mut v = json!({"ok": true, "type": ev.kind(), "width": w, "height": h});
        if matches!(ev, Input::Type { .. }) {
            v["typed"] = typed.into();
        }
        Ok(v)
    }

    /// Build (or reuse) the provisioned image.
    pub fn build(&self, force: bool, log: &mut dyn FnMut(&str)) -> Result<PathBuf, String> {
        image::build(self, force, log)
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests;
