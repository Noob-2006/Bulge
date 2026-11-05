//! Graphical desktop VMs (`[desktop_vm]`, `ark vm desktop …`): a QEMU guest with a real
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
//! * user-mode NAT networking (`network = "user"`), or none;
//! * a persistent copy-on-write disk per VM: `<data>/vm/desktop/<name>/disk.qcow2` on top of
//!   the provisioned image in `<cache>/desktop-vm/` ([`image`]);
//! * the human-takeover control lease (same format as the Bot Desktop one) lives in
//!   `<data>/vm/desktop/<name>/bot-desktop/lease.json` ([`DesktopVms::lease_home`]).
//!
//! QEMU daemonizes (`-daemonize -pidfile`), so a VM outlives the CLI that started it; a VM
//! is "running" while its pid is alive *and* that process's command line names this VM's
//! QMP socket (pid reuse cannot be mistaken for it). [`DesktopVms::reap`] clears what a dead
//! VM left behind and stops VMs idle past `idle_timeout_secs`.

pub mod config;
pub mod fake;
pub mod image;
pub mod keys;
pub mod qmp;

pub use config::DesktopConfig;
pub use qmp::Input;

use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Bumped when the image layout (what the provisioner sets up) changes incompatibly.
pub const IMAGE_LAYOUT: u32 = 2;

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
    crate::isolation::which(b).ok_or_else(|| format!("`{b}` not found (install QEMU, or set [desktop_vm] qemu / qemu_img)"))
}

pub(crate) fn run_tool(bin: &Path, args: &[&str]) -> Result<String, String> {
    let o = Command::new(bin).args(args).stdin(Stdio::null()).output().map_err(|e| format!("{}: {e}", bin.display()))?;
    if !o.status.success() {
        return Err(format!("{} {}: {}", bin.display(), args.first().unwrap_or(&""), String::from_utf8_lossy(&o.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Is `/dev/kvm` usable by this user?
pub fn kvm_usable() -> bool {
    std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm").is_ok()
}

/// The accelerator for `cfg.accel`, with the warning to show when it is the slow one.
pub fn accel(cfg: &DesktopConfig) -> (&'static str, Option<String>) {
    match cfg.accel.as_str() {
        "tcg" => ("tcg", Some("desktop_vm.accel = \"tcg\": software emulation, expect a slow desktop".into())),
        "kvm" => ("kvm", None),
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
    // SAFETY: signal 0 only checks that the process exists.
    if unsafe { libc::kill(pid as i32, 0) } != 0 {
        return false;
    }
    // A zombie is gone for our purposes.
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    !stat.rsplit(')').next().unwrap_or("").trim_start().starts_with('Z')
}

fn private_dir(p: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(p).map_err(|e| format!("create {}: {e}", p.display()))?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
}

/// The desktop VMs of one ark home.
#[derive(Debug, Clone)]
pub struct DesktopVms {
    pub cfg: DesktopConfig,
    data: PathBuf,
    cache: PathBuf,
    runtime: PathBuf,
}

impl DesktopVms {
    /// `data` / `cache` / `runtime` are the ark home's (`ark_kernel::config::Paths`).
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
    pub fn vm_dir(&self, name: &str) -> PathBuf {
        self.data.join("vm").join("desktop").join(name)
    }
    pub fn run_dir(&self, name: &str) -> PathBuf {
        self.runtime.join("dvm").join(name)
    }
    pub fn qmp_path(&self, name: &str) -> PathBuf {
        self.run_dir(name).join("qmp.sock")
    }
    /// Host end of the guest's `org.ark.text` port (non-ASCII typing).
    pub fn text_path(&self, name: &str) -> PathBuf {
        self.run_dir(name).join("text.sock")
    }
    pub fn vnc_path(&self, name: &str) -> PathBuf {
        self.run_dir(name).join("vnc.sock")
    }
    fn pid_path(&self, name: &str) -> PathBuf {
        self.run_dir(name).join("qemu.pid")
    }
    fn disk_path(&self, name: &str) -> PathBuf {
        self.vm_dir(name).join("disk.qcow2")
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
        let cmd = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        let want = self.qmp_path(name).display().to_string();
        String::from_utf8_lossy(&cmd).contains(&want).then_some(pid)
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
    pub fn cmdline(&self, name: &str, image_disk: &Path, accel: &str) -> Vec<String> {
        let c = &self.cfg;
        // VGA memory: two full frames at 32 bpp, rounded up to a power of two (≥ 16 MiB).
        let vgamem = ((c.width as u64 * c.height as u64 * 8) >> 20).max(16).next_power_of_two();
        let url = c.start_url.replace(',', ",,");
        let mut a: Vec<String> = vec![
            "-name".into(),
            format!("ark-desktop-{name}"),
            "-machine".into(),
            format!("q35,accel={accel}"),
            "-cpu".into(),
            if accel == "kvm" { "host".into() } else { "max".into() },
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
            // Text channel for non-ASCII typing (`org.ark.text`, see `type_text`).
            "-device".into(),
            "virtio-serial-pci".into(),
            "-chardev".into(),
            format!("socket,id=arktext,path={},server=on,wait=off", self.text_path(name).display()),
            "-device".into(),
            "virtserialport,chardev=arktext,name=org.ark.text".into(),
            "-smbios".into(),
            format!("type=11,value=ark-res={}x{},value=ark-url={url}", c.width, c.height),
        ];
        if c.network == "user" {
            a.extend(["-netdev".into(), "user,id=n0".into(), "-device".into(), "virtio-net-pci,netdev=n0".into()]);
        } else {
            a.extend(["-nic".into(), "none".into()]);
        }
        a.extend([
            "-vnc".into(),
            format!("unix:{}", self.vnc_path(name).display()),
            "-qmp".into(),
            format!("unix:{},server=on,wait=off", self.qmp_path(name).display()),
            "-monitor".into(),
            "none".into(),
            "-parallel".into(),
            "none".into(),
            "-serial".into(),
            format!("file:{}", self.vm_dir(name).join("console.log").display()),
            "-pidfile".into(),
            self.pid_path(name).display().to_string(),
            "-daemonize".into(),
        ]);
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
            return Err(format!("no desktop image yet ({}): run `ark vm desktop build` first", img.display()));
        }
        let qemu = resolve_bin(&self.cfg.qemu)?;
        let (vm, run) = (self.vm_dir(name), self.run_dir(name));
        private_dir(&vm)?;
        private_dir(&run)?;
        if [self.qmp_path(name), self.vnc_path(name), self.text_path(name)].iter().any(|p| p.as_os_str().len() > 100) {
            return Err(format!("runtime dir {} is too long for unix sockets (≤ 100 bytes); set a shorter ARK runtime dir", run.display()));
        }
        for p in [&vm, &run, &img] {
            if p.to_string_lossy().contains(',') {
                return Err(format!("{} contains ',', which QEMU option syntax cannot carry", p.display()));
            }
        }
        for f in ["qmp.sock", "vnc.sock", "text.sock", "qemu.pid", "screen", "last_used"] {
            let _ = std::fs::remove_file(run.join(f));
        }
        let disk = self.disk_path(name);
        if !disk.is_file() {
            let qemu_img = resolve_bin(&self.cfg.qemu_img)?;
            run_tool(&qemu_img, &["create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", &img.display().to_string(), &disk.display().to_string()])?;
        }
        let (acc, warn) = accel(&self.cfg);
        let out = Command::new(&qemu).args(self.cmdline(name, &disk, acc)).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).output().map_err(|e| format!("start {}: {e}", qemu.display()))?;
        if !out.status.success() {
            return Err(format!("qemu failed to start the desktop VM: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        let t0 = Instant::now();
        while !(self.qmp_path(name).exists() && self.is_running(name)) {
            if t0.elapsed() > Duration::from_secs(15) {
                self.kill(name);
                return Err("qemu daemonized but its QMP socket never appeared".into());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let state = json!({"started_at": now_s(), "accel": acc, "warning": warn, "image": img.display().to_string(), "width": self.cfg.width, "height": self.cfg.height});
        std::fs::write(vm.join("state.json"), state.to_string()).map_err(|e| e.to_string())?;
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
        for f in ["qmp.sock", "vnc.sock", "text.sock", "qemu.pid", "screen", "last_used"] {
            let _ = std::fs::remove_file(self.run_dir(name).join(f));
        }
    }

    fn kill(&self, name: &str) {
        if let Some(pid) = self.pid(name) {
            // SAFETY: the pid was checked to be this VM's QEMU (command line names its socket).
            unsafe { libc::kill(pid as i32, libc::SIGTERM) };
            if !self.wait_exit(pid, Duration::from_secs(3)) {
                unsafe { libc::kill(pid as i32, libc::SIGKILL) };
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
        if !self.is_running(name) {
            return Err(format!("desktop VM `{name}` is not running (start it with `ark vm desktop start {name}` or view.vm.start)"));
        }
        let l = qmp_lock(&self.qmp_path(name));
        let _g = l.lock().unwrap();
        let mut q = qmp::Qmp::connect(&self.qmp_path(name), Duration::from_secs(10))?;
        let r = f(&mut q);
        self.touch(name);
        r
    }

    /// The VM's screen as PNG bytes.
    pub fn screenshot(&self, name: &str) -> Result<Vec<u8>, String> {
        let tmp = self.run_dir(name).join(format!("frame-{}.png", ark_net::crypto::hex(&ark_net::crypto::sha256(format!("{:?}{}", std::thread::current().id(), now_s()).as_bytes()))[..10].to_owned()));
        let png = self.with_qmp(name, |q| q.screendump_png(&tmp))?;
        if let Some((w, h)) = qmp::png_size(&png) {
            let _ = std::fs::write(self.run_dir(name).join("screen"), format!("{w}x{h}"));
        }
        Ok(png)
    }

    /// Type text a US keyboard cannot (CJK, accents, emoji): one base64 line on the guest's
    /// `org.ark.text` virtio-serial port; the guest session's `ark-text-input` types it with
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
        let mut s = std::os::unix::net::UnixStream::connect(self.text_path(name)).map_err(|e| format!("text channel of `{name}`: {e} (VM started by an older ark?)"))?;
        s.set_write_timeout(Some(Duration::from_secs(5))).ok();
        let line = format!("{}\n", base64::engine::general_purpose::STANDARD.encode(text.as_bytes()));
        s.write_all(line.as_bytes()).map_err(|e| format!("text channel write: {e}"))?;
        // Stay connected until the guest says it typed it: QEMU only drains the socket while the
        // guest has the port open, and a disconnect before that would drop the text.
        let n = text.chars().count();
        s.set_read_timeout(Some(Duration::from_millis(5000 + 120 * n as u64))).ok();
        let mut ack = String::new();
        std::io::BufRead::read_line(&mut std::io::BufReader::new(&s), &mut ack).map_err(|e| format!("the guest did not confirm the text ({e}); is this an image without ark-text-input? rebuild with `ark vm desktop build` and `ark vm desktop reset`"))?;
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
mod tests;
