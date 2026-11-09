//! seagent-vm-guest — the guest half of seagent's microVM boundary (B1/B2/B3).
//!
//! One static binary, three roles chosen by argv:
//!
//! * **init** (no argument, or `init`). Installed as `/sbin/init` in the image
//!   and started by the kernel (`rdinit=/sbin/init`). As PID 1 — the only root
//!   process that ever exists in the VM — it mounts `/dev` (devtmpfs), `/proc`,
//!   `/sys`, `/dev/pts`, `/dev/shm` and a sized tmpfs on `/tmp`, creates the
//!   workspace and the broker socket directory, applies the resource ceilings
//!   from the `seagent.*` kernel parameters, and then **drops to uid/gid 1000 for
//!   good**. Only `CAP_SYS_BOOT` is kept — that is all `Shutdown` needs (an ACPI
//!   power-off where the firmware has one, a guest reset otherwise, which both
//!   VMMs turn into "the VM is gone"); nothing else survives the drop, so a tool
//!   that escapes its own process still cannot reconfigure the VM (B2).
//!   After the drop it connects the one channel to the host (`/dev/vport0p1`
//!   for virtio-serial/QEMU, AF_VSOCK listen for Firecracker), sends `Hello`
//!   with the uid it actually runs as, and serves frames.
//!
//! * **broker-send** (`seagent-vm-guest broker-send '<json>'`, also reachable as
//!   `/usr/bin/seagent-broker`). The only route by which a program *inside* the VM
//!   can ask the seagent daemon for something (egress, a privileged command): it
//!   writes the request to `/run/seagent/broker.sock`, the agent forwards it as a
//!   `GuestMsg::Broker` over the channel, and the host decides (A2/A3/A4). The
//!   guest has no NIC, no host path and no host socket — there is no other way
//!   out, which is what makes the guest-side allow-list unnecessary and the
//!   host-side one authoritative.
//!
//! * **version** prints the agent and protocol version (used by the image
//!   script and the boot test).
//!
//! The wire format is exactly the host's (`seagent_vm::proto`): `u32` big-endian
//! length + UTF-8 JSON, binary payloads base64. Frames are handled one at a
//! time by a reader that never blocks on a command: each `Exec` gets its own
//! thread, output chunks are serialised behind one mutex, and `Stdin`/`Signal`/
//! `Resize` are answered from the reader thread so a chatty command cannot
//! starve its own control messages.

use seagent_vm::limits::{apply_guest_limits, Limits};
use seagent_vm::proto::{
    check_rel_path, decode, encode, FileBlob, GuestMsg, HostMsg, AGENT_HOME, AGENT_UID, BROKER_SOCKET, GUEST_WORKSPACE, MAX_FRAME, SERIAL_DEVICE, UART_DEVICE, UART_DEVICE_PL011, VERSION,
    VSOCK_PORT,
};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

const MIB: u64 = 1024 * 1024;
/// Output chunk size; base64 of this stays far below `MAX_FRAME`.
const OUT_CHUNK: usize = 16 * 1024;
/// Largest total `Push` payload accepted in one frame.
const MAX_PUSH_TOTAL: usize = 32 * 1024 * 1024;
/// Largest broker request / reply an in-VM client may exchange.
const MAX_BROKER_BODY: usize = 4 * 1024 * 1024;
/// How long an in-VM client waits for the daemon's answer.
const BROKER_TIMEOUT: Duration = Duration::from_secs(120);
/// Grace period between `SIGTERM` and `SIGKILL`.
const KILL_GRACE: Duration = Duration::from_secs(5);
/// Sentinel meaning "the child was reaped but its status is unknown".
const REAP_TIMEOUT: Duration = Duration::from_secs(30);

// ── console logging ─────────────────────────────────────────────────────────

static CONSOLE: OnceLock<Mutex<File>> = OnceLock::new();

/// Log one line to the serial console (the boot log the host keeps in
/// `console.log`). Never fails the caller: a VM without a console still works.
fn log(msg: &str) {
    if let Some(c) = CONSOLE.get() {
        let mut g = lock(c);
        let _ = writeln!(g, "seagent-vm-guest: {msg}");
        let _ = g.flush();
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panicking command thread must not take the whole VM down: the data is
    // plain (fds, maps) and stays consistent.
    m.lock().unwrap_or_else(|p| p.into_inner())
}

// ── entry point ─────────────────────────────────────────────────────────────

pub fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let prog = argv.first().cloned().unwrap_or_default();
    // `/usr/bin/seagent-broker` is a symlink to this binary: invoked that way, the
    // first argument *is* the request (that is the command an in-VM program
    // uses), so the role is chosen by the name it was called under.
    let as_broker = Path::new(&prog).file_name().and_then(|n| n.to_str()).is_some_and(|n| n == "seagent-broker");
    let role = argv.get(1).map(String::as_str);
    let code = if as_broker {
        match role {
            Some("-") | None => broker_send(&read_stdin_or_fail()),
            Some(body) => broker_send(body),
        }
    } else {
        match role {
            Some("version") | Some("--version") | Some("-V") => {
                let _ = writeln!(std::io::stdout(), "{}", version_line());
                0
            }
            Some("broker-send") => match argv.get(2) {
                Some(body) => broker_send(body),
                None => {
                    eprintln!("usage: seagent-vm-guest broker-send '<json>'   (or: echo '<json>' | seagent-broker -)");
                    2
                }
            },
            Some("-") => broker_send(&read_stdin_or_fail()),
            Some("init") | None => run_init(),
            Some(other) => {
                eprintln!("seagent-vm-guest: unknown role `{other}` (expected: init, broker-send, version)");
                2
            }
        }
    };
    std::process::exit(code);
}

fn read_stdin_or_fail() -> String {
    let mut body = String::new();
    match std::io::stdin().read_to_string(&mut body) {
        Ok(_) => body.trim().to_string(),
        Err(e) => {
            eprintln!("seagent-broker: read the request from stdin: {e}");
            String::new()
        }
    }
}

fn version_line() -> String {
    format!("seagent-vm-guest {} protocol {}", env!("CARGO_PKG_VERSION"), VERSION)
}

// ── kernel command line ─────────────────────────────────────────────────────

/// Everything the host tells the guest through `-append` (see
/// `provider::qemu::cmdline_append`).
#[derive(Debug, Clone, PartialEq)]
pub struct GuestCfg {
    /// VM id (`seagent.vm=`), also the hostname.
    pub vm: String,
    /// Trust tier (`seagent.tier=`); carried for logs only — the guest never trusts
    /// it for a decision.
    pub tier: String,
    /// `virtio-serial` or `vsock` (`seagent.channel=`).
    pub channel: String,
    /// Where the workspace appears in the guest (`seagent.workspace=`).
    pub workspace: PathBuf,
    /// Size of the `/tmp` tmpfs in MB (`seagent.disk_mb=`).
    pub disk_mb: u64,
    /// `RLIMIT_NPROC` for the agent uid (`seagent.nproc=`).
    pub nproc: u64,
    /// `RLIMIT_NOFILE` (`seagent.nofile=`, defaults to the crate default).
    pub nofile: u64,
    /// `seagent.workspace_ro=1`: the agent refuses every write (B2).
    pub workspace_ro: bool,
}

impl Default for GuestCfg {
    fn default() -> Self {
        let l = Limits::default();
        GuestCfg {
            vm: "seagent-vm".into(),
            tier: "default".into(),
            channel: String::new(),
            workspace: PathBuf::from(GUEST_WORKSPACE),
            disk_mb: l.disk_mb,
            nproc: l.nproc,
            nofile: l.nofile,
            workspace_ro: false,
        }
    }
}

impl GuestCfg {
    fn limits(&self) -> Limits {
        Limits { nproc: self.nproc, nofile: self.nofile, cpu_seconds: 0, disk_mb: self.disk_mb, exec_timeout_secs: 0 }
    }
}

/// Parse `/proc/cmdline`. Unknown parameters (the kernel's own included) are
/// ignored; a value that would be dangerous is *rejected* rather than
/// reinterpreted, so `seagent.workspace=../../etc` leaves the default in place.
pub fn parse_cmdline(line: &str) -> GuestCfg {
    let mut cfg = GuestCfg::default();
    for tok in line.split_whitespace() {
        let Some((key, val)) = tok.split_once('=') else { continue };
        match key {
            "seagent.vm" => {
                if !val.is_empty() && val.len() <= 63 {
                    cfg.vm = val.to_string();
                }
            }
            "seagent.tier" => cfg.tier = val.to_string(),
            "seagent.channel" => {
                if matches!(val, "virtio-serial" | "vsock" | "uart") {
                    cfg.channel = val.to_string();
                }
            }
            "seagent.workspace" => match guest_abs_path(val) {
                Some(p) => cfg.workspace = p,
                None => cfg.workspace = PathBuf::from(GUEST_WORKSPACE),
            },
            "seagent.disk_mb" => {
                if let Ok(n) = val.parse::<u64>() {
                    cfg.disk_mb = n.clamp(16, 65536);
                }
            }
            "seagent.nproc" => {
                if let Ok(n) = val.parse::<u64>() {
                    if n > 0 {
                        cfg.nproc = n;
                    }
                }
            }
            "seagent.nofile" => {
                if let Ok(n) = val.parse::<u64>() {
                    if n > 0 {
                        cfg.nofile = n;
                    }
                }
            }
            "seagent.workspace_ro" => cfg.workspace_ro = matches!(val, "1" | "true" | "yes"),
            _ => {}
        }
    }
    cfg
}

/// A plain absolute guest path with no `.`/`..` component and no trailing junk.
pub fn guest_abs_path(v: &str) -> Option<PathBuf> {
    if !v.starts_with('/') || v.len() > 255 {
        return None;
    }
    let ok = v.split('/').skip(1).all(|c| !c.is_empty() && c != "." && c != "..");
    if !ok {
        return None;
    }
    Some(PathBuf::from(v))
}

// ── mounts, identity, privileges ────────────────────────────────────────────

fn mount(src: &str, target: &str, fstype: &str, flags: libc::c_ulong, data: Option<&str>) -> Result<(), String> {
    let c_src = CString::new(src).map_err(|e| format!("mount source {src}: {e}"))?;
    let c_tgt = CString::new(target).map_err(|e| format!("mount target {target}: {e}"))?;
    let c_fs = CString::new(fstype).map_err(|e| format!("mount fstype {fstype}: {e}"))?;
    let c_data = match data {
        Some(d) => Some(CString::new(d).map_err(|e| format!("mount data {d}: {e}"))?),
        None => None,
    };
    let ptr = c_data.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
    // SAFETY: every pointer is a valid NUL-terminated string outliving the call.
    let rc = unsafe { libc::mount(c_src.as_ptr(), c_tgt.as_ptr(), c_fs.as_ptr(), flags, ptr.cast()) };
    if rc != 0 {
        return Err(format!("mount {fstype} on {target}: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

fn open_console() {
    for dev in ["/dev/console", "/dev/ttyS0", "/dev/tty1"] {
        let Ok(f) = OpenOptions::new().write(true).open(dev) else { continue };
        let _ = CONSOLE.set(Mutex::new(f));
        return;
    }
}

/// Mount everything a toolbox needs. `devtmpfs` and `proc` are mandatory: the
/// rest is best-effort (a kernel without `sysfs` still runs commands).
///
/// Order matters: `devtmpfs` covers whatever the initramfs had in `/dev`, so the
/// sub-directories are created *after* mounting it.
fn mount_guest_fs() -> Result<(), String> {
    for dir in ["/dev", "/proc", "/sys", "/tmp", "/run"] {
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {dir}: {e}"))?;
    }
    // The kernel may not have mounted devtmpfs for us (Firecracker's kernel
    // does not when it is not built with CONFIG_DEVTMPFS_MOUNT): without /dev
    // there is no console, no null and no virtio port.
    if !Path::new("/dev/null").exists() {
        mount("devtmpfs", "/dev", "devtmpfs", 0, Some("mode=0755"))?;
    }
    open_console();
    for dir in ["/dev/pts", "/dev/shm"] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            log(&format!("mkdir {dir}: {e}"));
        }
    }
    // A fresh devpts instance per VM: no pty leaks in from anywhere else.
    if let Err(e) = mount("devpts", "/dev/pts", "devpts", 0, Some("newinstance,ptmxmode=0666,mode=0620")) {
        log(&format!("/dev/pts not mounted: {e}"));
    }
    if let Err(e) = mount("tmpfs", "/dev/shm", "tmpfs", 0, Some("mode=1777")) {
        log(&format!("/dev/shm not mounted: {e}"));
    }
    // devtmpfs does not create the pty multiplexer on a kernel without
    // CONFIG_LEGACY_PTYS; without it `posix_openpt` fails and pty commands do
    // not work at all.
    ensure_ptmx()?;
    mount("proc", "/proc", "proc", 0, None)?;
    if mount("sysfs", "/sys", "sysfs", 0, None).is_err() {
        log("/sys not mounted (no sysfs in this kernel)");
    }
    Ok(())
}

/// `/dev/ptmx` (char 5:2), created as root before the privilege drop.
fn ensure_ptmx() -> Result<(), String> {
    if Path::new("/dev/ptmx").exists() {
        return Ok(());
    }
    let c = CString::new("/dev/ptmx").map_err(|e| format!("ptmx path: {e}"))?;
    // SAFETY: mknod with a valid path; we are still root here.
    let rc = unsafe { libc::mknod(c.as_ptr(), libc::S_IFCHR | 0o666, libc::makedev(5, 2)) };
    if rc != 0 {
        return Err(format!("mknod /dev/ptmx: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

fn mount_tmpfs(cfg: &GuestCfg) -> Result<(), String> {
    let opts = format!("mode=1777,size={}m", cfg.disk_mb);
    mount("tmpfs", "/tmp", "tmpfs", 0, Some(&opts))
}

fn set_hostname(name: &str) -> Result<(), String> {
    let sanitized: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '-' }).take(63).collect();
    let bytes = if sanitized.is_empty() { b"seagent-vm".to_vec() } else { sanitized.into_bytes() };
    // SAFETY: `bytes` is valid for the length we pass.
    let rc = unsafe { libc::sethostname(bytes.as_ptr().cast(), bytes.len()) };
    if rc != 0 {
        return Err(format!("sethostname: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// chown a path to the agent uid/gid. Only called while still root.
fn chown_agent(path: &Path) -> Result<(), String> {
    let c = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|e| format!("{}: {e}", path.display()))?;
    // SAFETY: valid NUL-terminated path.
    let rc = unsafe { libc::chown(c.as_ptr(), AGENT_UID, AGENT_UID) };
    if rc != 0 {
        return Err(format!("chown {}: {}", path.display(), std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Become uid/gid 1000 and never get back. `PR_SET_KEEPCAPS` + a one-capability
/// `capset` keeps exactly `CAP_SYS_BOOT` (poweroff), nothing else.
fn drop_privileges(uid: u32, gid: u32) -> Result<(), String> {
    // SAFETY: plain syscalls on ourselves, before any command thread exists.
    unsafe {
        if libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0 {
            return Err(format!("prctl(PR_SET_KEEPCAPS): {}", std::io::Error::last_os_error()));
        }
        if libc::setgroups(0, std::ptr::null()) != 0 {
            return Err(format!("setgroups: {}", std::io::Error::last_os_error()));
        }
        if libc::setgid(gid) != 0 {
            return Err(format!("setgid({gid}): {}", std::io::Error::last_os_error()));
        }
        if libc::setuid(uid) != 0 {
            return Err(format!("setuid({uid}): {}", std::io::Error::last_os_error()));
        }
    }
    if unsafe { libc::getuid() } != uid || unsafe { libc::geteuid() } != uid {
        return Err(format!("uid is still {} after setuid", unsafe { libc::getuid() }));
    }
    if unsafe { libc::getgid() } != gid {
        return Err("gid did not change".into());
    }
    // The proof that matters (B2): root cannot be regained.
    if unsafe { libc::setuid(0) } == 0 {
        return Err("setuid(0) succeeded after the drop; refusing to run".into());
    }
    keep_only_cap_sys_boot().map_err(|e| format!("capset: {e}"))?;
    Ok(())
}

const CAP_SYS_BOOT: u32 = 22;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const CAP_VERSION_3: u32 = 0x2008_0522;

/// Leave the agent with `CAP_SYS_BOOT` only (used once, for poweroff).
fn keep_only_cap_sys_boot() -> Result<(), String> {
    let hdr = CapHeader { version: CAP_VERSION_3, pid: 0 };
    let mut data = [CapData { effective: 0, permitted: 0, inheritable: 0 }; 2];
    data[0].permitted = 1 << CAP_SYS_BOOT;
    data[0].effective = 1 << CAP_SYS_BOOT;
    // SAFETY: the kernel writes at most two CapData words for version 3.
    let rc = unsafe { libc::syscall(libc::SYS_capset, &hdr as *const CapHeader, data.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

fn kernel_release() -> String {
    // SAFETY: `utsname` is plain data; the kernel fills it in.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return "unknown".into();
    }
    // SAFETY: the kernel NUL-terminates every field.
    unsafe { CStr::from_ptr(u.release.as_ptr()) }.to_string_lossy().into_owned()
}

// ── the channel ─────────────────────────────────────────────────────────────

/// How the guest reaches the host: the virtio-serial port (QEMU) or a vsock
/// listener (Firecracker). Both carry the same frames.
enum TransportSetup {
    /// The port and the channel name it is (`virtio-serial`, or `uart` for COM2).
    Serial(File, &'static str),
    VsockListener(RawFd),
}

/// The guest end of the `uart` channel (COM2). x86_64: always the 16550 `ttyS1`. aarch64:
/// arm64 VirtualBox / Hyper-V emulate PL011s, so the second one (`ttyAMA1`) when it exists,
/// else `ttyS1` (a machine model with 16550s).
fn uart_device() -> &'static str {
    #[cfg(target_arch = "aarch64")]
    {
        uart_device_in(|p| Path::new(p).exists())
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        UART_DEVICE
    }
}

#[cfg_attr(not(any(test, target_arch = "aarch64")), allow(dead_code))]
fn uart_device_in(exists: impl Fn(&str) -> bool) -> &'static str {
    if exists(UART_DEVICE_PL011) {
        UART_DEVICE_PL011
    } else {
        UART_DEVICE
    }
}

/// Raw 8N1 at 115200 baud, through the kernel's own `TCGETS2`/`TCSETS2` ioctls rather than
/// libc's termios wrappers: glibc 2.42 gave `cfsetspeed` & co. new symbol versions, and a
/// `+crt-static` GNU build of the agent (the fallback when no musl toolchain exists) then
/// failed to link (`undefined symbol: cfsetspeed@GLIBC_2.2.5`). The ioctl is the same on
/// musl and glibc, so both builds configure the port identically (what `cfmakeraw` did).
fn uart_raw_115200(f: &File) -> Result<(), String> {
    // SAFETY: TCGETS2 fills a `termios2` we own; TCSETS2 reads it back.
    unsafe {
        let mut t: libc::termios2 = std::mem::zeroed();
        if libc::ioctl(f.as_raw_fd(), libc::TCGETS2 as _, &mut t) != 0 {
            return Err(format!("TCGETS2: {}", std::io::Error::last_os_error()));
        }
        t.c_iflag &= !(libc::IGNBRK | libc::BRKINT | libc::PARMRK | libc::ISTRIP | libc::INLCR | libc::IGNCR | libc::ICRNL | libc::IXON);
        t.c_oflag &= !libc::OPOST;
        t.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);
        t.c_cflag &= !(libc::CSIZE | libc::PARENB | libc::CBAUD);
        t.c_cflag |= libc::CS8 | libc::B115200;
        t.c_ispeed = 115_200;
        t.c_ospeed = 115_200;
        t.c_cc[libc::VMIN] = 1;
        t.c_cc[libc::VTIME] = 0;
        if libc::ioctl(f.as_raw_fd(), libc::TCSETS2 as _, &t) != 0 {
            return Err(format!("TCSETS2: {}", std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

fn prepare_transport(cfg: &GuestCfg) -> Result<TransportSetup, String> {
    if cfg.channel == "uart" {
        // VirtualBox / Hyper-V: the host end of COM2 is a socket or named pipe; the guest
        // side is a plain 16550, put in raw 8N1 so no byte of a frame is reinterpreted.
        let dev = uart_device();
        let f = OpenOptions::new().read(true).write(true).open(dev).map_err(|e| format!("cannot open {dev}: {e}"))?;
        uart_raw_115200(&f).map_err(|e| format!("{dev}: {e}"))?;
        return Ok(TransportSetup::Serial(f, "uart"));
    }
    if cfg.channel != "vsock" {
        // The virtio-serial port shows up during kernel boot; give it a moment.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !Path::new(SERIAL_DEVICE).exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        match OpenOptions::new().read(true).write(true).open(SERIAL_DEVICE) {
            Ok(f) => return Ok(TransportSetup::Serial(f, "virtio-serial")),
            Err(e) => {
                if cfg.channel == "virtio-serial" {
                    return Err(format!("cannot open {SERIAL_DEVICE}: {e}"));
                }
            }
        }
    }
    // AF_VSOCK listener. The host (Firecracker) connects to VMADDR_CID_ANY:port.
    // SAFETY: plain socket calls.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(format!("AF_VSOCK socket: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: `addr` is fully initialised and the size matches `sockaddr_vm`.
    let addr = unsafe {
        let mut a: libc::sockaddr_vm = std::mem::zeroed();
        a.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        a.svm_cid = libc::VMADDR_CID_ANY;
        a.svm_port = VSOCK_PORT;
        a
    };
    let size = std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;
    // SAFETY: the address is valid for `size` bytes.
    let rc = unsafe { libc::bind(fd, (&addr as *const libc::sockaddr_vm).cast(), size) };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        // SAFETY: we own `fd`.
        unsafe { libc::close(fd) };
        return Err(format!("vsock bind port {VSOCK_PORT}: {e}"));
    }
    // SAFETY: listening on our own socket.
    if unsafe { libc::listen(fd, 4) } != 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(format!("vsock listen: {e}"));
    }
    Ok(TransportSetup::VsockListener(fd))
}

/// One connected channel: a read half owned by the reader thread and a write
/// half serialised behind a mutex (several command threads stream output).
struct Conn {
    r: File,
    w: Arc<Mutex<File>>,
    buf: Vec<u8>,
    pending: std::collections::VecDeque<HostMsg>,
    transport: &'static str,
    cid: Option<u32>,
}

impl Conn {
    fn read_frame(&mut self) -> Result<Option<HostMsg>, String> {
        let mut chunk = [0u8; 64 * 1024];
        loop {
            if let Some(m) = self.pending.pop_front() {
                return Ok(Some(m));
            }
            let (frames, used) = decode::<HostMsg>(&self.buf)?;
            if used > 0 {
                self.buf.drain(..used);
                self.pending.extend(frames);
                continue;
            }
            match self.r.read(&mut chunk) {
                Ok(0) => return Ok(None),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("channel read: {e}")),
            }
            if self.buf.len() > MAX_FRAME + 4 {
                return Err("frame larger than the protocol maximum".into());
            }
        }
    }
}

fn serial_conn(f: File, transport: &'static str) -> Result<Conn, String> {
    let w = f.try_clone().map_err(|e| format!("clone channel fd: {e}"))?;
    Ok(Conn { r: f, w: Arc::new(Mutex::new(w)), buf: Vec::new(), pending: Default::default(), transport, cid: None })
}

fn vsock_conn(listener: RawFd) -> Result<Conn, String> {
    // SAFETY: `listener` is our listening socket.
    let fd = unsafe { libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut()) };
    if fd < 0 {
        return Err(format!("vsock accept: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: we just created the fd and own it from here on.
    let f = unsafe { File::from_raw_fd(fd) };
    let w = f.try_clone().map_err(|e| format!("clone channel fd: {e}"))?;
    let cid = vsock_local_cid(f.as_raw_fd());
    Ok(Conn { r: f, w: Arc::new(Mutex::new(w)), buf: Vec::new(), pending: Default::default(), transport: "vsock", cid })
}

fn vsock_local_cid(fd: RawFd) -> Option<u32> {
    // SAFETY: zeroed address struct, kernel fills it in.
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;
    // SAFETY: valid pointers for `len` bytes.
    let rc = unsafe { libc::getsockname(fd, (&mut addr as *mut libc::sockaddr_vm).cast(), &mut len) };
    if rc == 0 {
        Some(addr.svm_cid)
    } else {
        None
    }
}

// ── reaper ──────────────────────────────────────────────────────────────────

/// One thread owns `waitpid(-1)` for the whole VM. Commands ask it for their
/// pid's status; orphans reparented to PID 1 are reaped here too, otherwise the
/// guest would slowly fill with zombies.
struct Reaper {
    done: Mutex<HashMap<i32, i32>>,
    cv: Condvar,
    /// Commands spawned so far, and the signal that one was: with no child to wait for,
    /// the reaper sleeps until the next spawn instead of polling.
    spawns: Mutex<u64>,
    spawned: Condvar,
}

impl Reaper {
    fn start() -> Arc<Reaper> {
        let r = Arc::new(Reaper { done: Mutex::new(HashMap::new()), cv: Condvar::new(), spawns: Mutex::new(0), spawned: Condvar::new() });
        let for_thread = r.clone();
        std::thread::spawn(move || loop {
            let seen = *lock(&for_thread.spawns);
            let mut status: libc::c_int = 0;
            // SAFETY: plain waitpid on any child.
            let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
            if pid > 0 {
                let mut done = lock(&for_thread.done);
                done.insert(pid, status);
                for_thread.cv.notify_all();
                continue;
            }
            let err = std::io::Error::last_os_error();
            if err.kind() == ErrorKind::Interrupted {
                continue;
            }
            // ECHILD: nothing to reap right now. Wait for the next spawn (bounded, for
            // orphans reparented to PID 1) instead of a blind 100 ms sleep: that sleep was
            // paid by every command started while the VM was idle — and the pool runs two per
            // tool call (the command, then `find` for the sync back) — a flat ~100-200 ms per
            // call, measured under QEMU+WHPX. A spawn after `seen` was read is never missed:
            // the counter has moved, so there is no wait at all.
            let g = lock(&for_thread.spawns);
            if *g == seen {
                let _ = for_thread.spawned.wait_timeout(g, Duration::from_millis(100));
            }
        });
        r
    }

    /// A command was just spawned: wake the reaper if it is idle.
    fn spawned(&self) {
        *lock(&self.spawns) += 1;
        self.spawned.notify_all();
    }

    fn wait(&self, pid: i32, timeout: Duration) -> Option<i32> {
        let deadline = Instant::now() + timeout;
        let mut done = lock(&self.done);
        loop {
            if let Some(st) = done.remove(&pid) {
                return Some(st);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            done = match self.cv.wait_timeout(done, left) {
                Ok((g, _)) => g,
                Err(p) => p.into_inner().0,
            };
        }
    }
}

fn exit_code(status: i32) -> (Option<i32>, Option<i32>) {
    if libc::WIFEXITED(status) {
        (Some(libc::WEXITSTATUS(status)), None)
    } else if libc::WIFSIGNALED(status) {
        (None, Some(libc::WTERMSIG(status)))
    } else {
        (None, None)
    }
}

// ── exec plumbing ───────────────────────────────────────────────────────────

struct ExecHandle {
    /// Process group id of the command (its own group: a `Signal` kills the
    /// whole tree, not just the shell).
    pgid: i32,
    stdin: Option<File>,
    /// Pty master, when the host asked for one: used for stdin and `Resize`.
    pty: Option<File>,
}

struct Agent {
    cfg: GuestCfg,
    limits: Mutex<Limits>,
    w: Arc<Mutex<File>>,
    execs: Mutex<HashMap<u64, ExecHandle>>,
    broker_clients: Mutex<HashMap<u64, UnixStream>>,
    next_broker: AtomicU64,
    reaper: Arc<Reaper>,
}

impl Agent {
    fn send(&self, m: &GuestMsg) -> Result<(), String> {
        let bytes = encode(m)?;
        let mut w = lock(&self.w);
        w.write_all(&bytes).and_then(|_| w.flush()).map_err(|e| format!("channel write: {e}"))
    }

    fn shell(&self) -> Result<&'static str, String> {
        for sh in ["/bin/bash", "/bin/sh"] {
            if Path::new(sh).is_file() {
                return Ok(sh);
            }
        }
        Err("no shell (/bin/bash or /bin/sh) in the guest image".into())
    }
}

fn sanitised_env(env: &[(String, String)]) -> Vec<(String, String)> {
    env.iter().filter(|(k, _)| !k.is_empty() && !k.contains('=') && !k.contains('\0')).cloned().collect()
}

fn pipe_pair() -> Result<(File, File), String> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: the kernel writes two fds.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(format!("pipe: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: both fds are fresh and owned by us.
    Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
}

fn set_winsize(f: &File, rows: u16, cols: u16) -> Result<(), String> {
    let ws = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
    // SAFETY: TIOCSWINSZ takes a `winsize` pointer; `ws` outlives the call.
    let rc = unsafe { libc::syscall(libc::SYS_ioctl, f.as_raw_fd(), libc::TIOCSWINSZ as libc::c_ulong, &ws as *const libc::winsize) };
    if rc != 0 {
        return Err(format!("ioctl(TIOCSWINSZ): {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Allocate a pty pair of the requested size. The master is opened `O_NOCTTY`
/// so PID 1 never acquires a controlling terminal (which would make it subject
/// to `SIGTTIN`).
fn open_pty(rows: u16, cols: u16) -> Result<(File, File), String> {
    // SAFETY: plain pty allocation calls.
    unsafe {
        let fd = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        if fd < 0 {
            return Err(format!("posix_openpt: {}", std::io::Error::last_os_error()));
        }
        let master = File::from_raw_fd(fd);
        if libc::grantpt(fd) != 0 {
            return Err(format!("grantpt: {}", std::io::Error::last_os_error()));
        }
        if libc::unlockpt(fd) != 0 {
            return Err(format!("unlockpt: {}", std::io::Error::last_os_error()));
        }
        let mut name = [0 as libc::c_char; 128];
        if libc::ptsname_r(fd, name.as_mut_ptr(), name.len()) != 0 {
            return Err(format!("ptsname_r: {}", std::io::Error::last_os_error()));
        }
        let path = CStr::from_ptr(name.as_ptr()).to_string_lossy().into_owned();
        let slave = OpenOptions::new().read(true).write(true).open(&path).map_err(|e| format!("open {path}: {e}"))?;
        set_winsize(&master, rows.max(1), cols.max(1))?;
        Ok((master, slave))
    }
}

/// rlimits for one command, applied in the child (after `fork`, before `exec`):
/// only async-signal-safe calls here.
fn child_rlimits(l: Limits) {
    let set = |res: libc::c_int, v: u64| {
        if v == 0 {
            return;
        }
        let rl = libc::rlimit { rlim_cur: v, rlim_max: v };
        // SAFETY: setrlimit on our own (child) process.
        unsafe { libc::setrlimit(res as _, &rl) };
    };
    set(libc::RLIMIT_NPROC as libc::c_int, l.nproc);
    set(libc::RLIMIT_NOFILE as libc::c_int, l.nofile);
    set(libc::RLIMIT_CORE as libc::c_int, 0);
    set(libc::RLIMIT_FSIZE as libc::c_int, l.disk_mb.saturating_mul(MIB));
    if l.cpu_seconds > 0 {
        set(libc::RLIMIT_CPU as libc::c_int, l.cpu_seconds);
    }
}

struct ExecReq {
    id: u64,
    script: String,
    cwd: Option<String>,
    env: Vec<(String, String)>,
    login: bool,
    stdin: bool,
    pty: Option<(u16, u16)>,
    timeout_secs: u64,
}

fn start_exec(agent: &Arc<Agent>, req: ExecReq) -> Result<(), String> {
    if lock(&agent.execs).contains_key(&req.id) {
        return Err(format!("exec id {} is already running", req.id));
    }
    let cwd = match &req.cwd {
        Some(c) => PathBuf::from(c),
        None => agent.cfg.workspace.clone(),
    };
    if !cwd.is_dir() {
        return Err(format!("cwd {} is not a directory in the guest", cwd.display()));
    }
    let shell = agent.shell()?;
    let lims = *lock(&agent.limits);
    let mut cmd = Command::new(shell);
    cmd.arg(if req.login { "-lc" } else { "-c" }).arg(&req.script);
    cmd.current_dir(&cwd);
    cmd.env_clear();
    cmd.env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    cmd.env("HOME", AGENT_HOME);
    cmd.env("USER", "agent").env("LOGNAME", "agent").env("SHELL", shell);
    cmd.env("TMPDIR", "/tmp").env("LANG", "C.UTF-8");
    for (k, v) in sanitised_env(&req.env) {
        cmd.env(k, v);
    }

    let mut stdin_file: Option<File> = None;
    let mut pty_file: Option<File> = None;
    let out: File;
    if let Some((rows, cols)) = req.pty {
        let (master, slave) = open_pty(rows, cols)?;
        cmd.env("TERM", "xterm-256color");
        cmd.stdin(Stdio::from(slave.try_clone().map_err(|e| format!("pty clone: {e}"))?));
        cmd.stdout(Stdio::from(slave.try_clone().map_err(|e| format!("pty clone: {e}"))?));
        cmd.stderr(Stdio::from(slave));
        stdin_file = Some(master.try_clone().map_err(|e| format!("pty clone: {e}"))?);
        pty_file = Some(master.try_clone().map_err(|e| format!("pty clone: {e}"))?);
        out = master;
        // SAFETY: the closure only makes async-signal-safe syscalls in the child.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // fd 0 is the pty slave (std dup2'd it before this hook).
                if libc::syscall(libc::SYS_ioctl, 0, libc::TIOCSCTTY as libc::c_ulong, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                child_rlimits(lims);
                Ok(())
            });
        }
    } else {
        let (r, w) = pipe_pair()?;
        cmd.env("TERM", "dumb");
        cmd.stdout(Stdio::from(w.try_clone().map_err(|e| format!("pipe clone: {e}"))?));
        cmd.stderr(Stdio::from(w));
        out = r;
        if req.stdin {
            let (sr, sw) = pipe_pair()?;
            cmd.stdin(Stdio::from(sr));
            stdin_file = Some(sw);
        } else {
            cmd.stdin(Stdio::null());
        }
        cmd.process_group(0);
        // SAFETY: the closure only calls setrlimit in the child.
        unsafe {
            cmd.pre_exec(move || {
                child_rlimits(lims);
                Ok(())
            });
        }
    }
    let child = cmd.spawn().map_err(|e| format!("spawn {shell}: {e}"))?;
    let pid = child.id() as i32;
    // The reaper thread owns waitpid from here on.
    drop(child);
    agent.reaper.spawned();
    let pgid = pid;
    lock(&agent.execs).insert(req.id, ExecHandle { pgid, stdin: stdin_file, pty: pty_file });

    let a = agent.clone();
    let id = req.id;
    std::thread::spawn(move || {
        pump_output(a, id, out, pid);
    });

    if req.timeout_secs > 0 {
        let a = agent.clone();
        let id = req.id;
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(req.timeout_secs));
            if lock(&a.execs).contains_key(&id) {
                log(&format!("exec {id} hit its {}-second timeout", req.timeout_secs));
                terminate(a, id, false);
            }
        });
    }
    Ok(())
}

/// Stream one command's merged output, then its exit status.
fn pump_output(agent: Arc<Agent>, id: u64, mut out: File, pid: i32) {
    let mut chunk = vec![0u8; OUT_CHUNK];
    loop {
        match out.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if agent.send(&GuestMsg::Out { id, data: B64.encode(&chunk[..n]) }).is_err() {
                    // The host is gone: stop the command and let the EOF path
                    // shut the VM down.
                    kill_group(pid, libc::SIGKILL);
                    break;
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            // EIO: the pty slave closed (command finished).
            Err(_) => break,
        }
    }
    let status = agent.reaper.wait(pid, REAP_TIMEOUT);
    let (code, signal) = status.map(exit_code).unwrap_or((None, None));
    lock(&agent.execs).remove(&id);
    let _ = agent.send(&GuestMsg::Exit { id, code, signal });
}

fn kill_group(pgid: i32, sig: libc::c_int) {
    if pgid <= 1 {
        return;
    }
    // SAFETY: negative pid = "this process group", which the command leads.
    unsafe { libc::kill(-pgid, sig) };
}

/// SIGTERM (then SIGKILL after a grace period), or SIGKILL at once with `force`.
fn terminate(agent: Arc<Agent>, id: u64, force: bool) {
    let pgid = match lock(&agent.execs).get(&id) {
        Some(h) => h.pgid,
        None => return,
    };
    if force {
        kill_group(pgid, libc::SIGKILL);
        return;
    }
    kill_group(pgid, libc::SIGTERM);
    std::thread::spawn(move || {
        std::thread::sleep(KILL_GRACE);
        if lock(&agent.execs).contains_key(&id) {
            kill_group(pgid, libc::SIGKILL);
        }
    });
}

// ── workspace files (Push / Pull) ───────────────────────────────────────────

/// Canonical workspace root (created by init, owned by the agent).
fn workspace_root(agent: &Agent) -> Result<PathBuf, String> {
    std::fs::canonicalize(&agent.cfg.workspace).map_err(|e| format!("workspace {}: {e}", agent.cfg.workspace.display()))
}

/// Resolve a host-supplied relative path inside the workspace. `check_rel_path`
/// is the protocol-level rule (no `..`, no absolute, no empty components); the
/// canonical check catches a symlink a previous command left behind.
fn resolve_in_workspace(root: &Path, rel: &str) -> Result<PathBuf, String> {
    check_rel_path(rel)?;
    let mut p = root.to_path_buf();
    for comp in rel.split('/') {
        p.push(comp);
        if let Ok(meta) = std::fs::symlink_metadata(&p) {
            if meta.file_type().is_symlink() {
                return Err(format!("`{rel}` crosses a symlink; refusing to leave the workspace"));
            }
        }
    }
    Ok(p)
}

fn push_files(agent: &Agent, id: u64, files: Vec<FileBlob>) -> GuestMsg {
    if agent.cfg.workspace_ro {
        return GuestMsg::Err { id, message: "workspace is read-only (seagent.workspace_ro=1); Push refused".into() };
    }
    let root = match workspace_root(agent) {
        Ok(r) => r,
        Err(e) => return GuestMsg::Err { id, message: e },
    };
    let mut total = 0usize;
    let mut written = 0u64;
    for f in files {
        let data = match B64.decode(f.data.as_bytes()) {
            Ok(d) => d,
            Err(e) => return GuestMsg::Err { id, message: format!("`{}`: not valid base64: {e}", f.path) },
        };
        total += data.len();
        if total > MAX_PUSH_TOTAL {
            return GuestMsg::Err { id, message: format!("Push exceeds {MAX_PUSH_TOTAL} bytes") };
        }
        let path = match resolve_in_workspace(&root, &f.path) {
            Ok(p) => p,
            Err(e) => return GuestMsg::Err { id, message: e },
        };
        let Some(parent) = path.parent() else {
            return GuestMsg::Err { id, message: format!("`{}` has no parent directory", f.path) };
        };
        if let Err(e) = std::fs::create_dir_all(parent) {
            return GuestMsg::Err { id, message: format!("mkdir {}: {e}", parent.display()) };
        }
        // Write through a temp file in the same directory and rename: a reader
        // never sees a half-written file, and the rename cannot be tricked into
        // following a symlink the command planted at `path`.
        let tmp = parent.join(format!(".seagent-push-{}-{id}-{written}", std::process::id()));
        match std::fs::write(&tmp, &data) {
            Ok(()) => {}
            Err(e) => return GuestMsg::Err { id, message: format!("write {}: {e}", tmp.display()) },
        }
        let mode = f.mode & 0o777;
        if let Err(e) = std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(if mode == 0 { 0o644 } else { mode })) {
            let _ = std::fs::remove_file(&tmp);
            return GuestMsg::Err { id, message: format!("chmod {}: {e}", tmp.display()) };
        }
        if let Err(e) = std::fs::rename(&tmp, &path) {
            let _ = std::fs::remove_file(&tmp);
            return GuestMsg::Err { id, message: format!("rename to {}: {e}", path.display()) };
        }
        written += 1;
    }
    GuestMsg::Ok { id, detail: json!({ "files": written, "bytes": total }) }
}

fn pull_files(agent: &Agent, id: u64, paths: Vec<String>) -> GuestMsg {
    let root = match workspace_root(agent) {
        Ok(r) => r,
        Err(e) => return GuestMsg::Err { id, message: e },
    };
    let mut out = Vec::new();
    let mut total = 0usize;
    for rel in paths {
        let path = match resolve_in_workspace(&root, &rel) {
            Ok(p) => p,
            Err(e) => return GuestMsg::Err { id, message: e },
        };
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            // A file the command never created is simply not in the answer.
            Err(_) => continue,
        };
        if !meta.is_file() {
            return GuestMsg::Err { id, message: format!("`{rel}` is not a regular file") };
        }
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => return GuestMsg::Err { id, message: format!("read {rel}: {e}") },
        };
        total += data.len();
        if total > MAX_PUSH_TOTAL {
            return GuestMsg::Err { id, message: format!("Pull exceeds {MAX_PUSH_TOTAL} bytes") };
        }
        let mode = std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o777;
        out.push(FileBlob { path: rel, data: B64.encode(&data), mode });
    }
    GuestMsg::Files { id, files: out }
}

// ── broker (in-VM clients → host daemon) ────────────────────────────────────

fn start_broker(agent: Arc<Agent>) -> Result<(), String> {
    let _ = std::fs::remove_file(BROKER_SOCKET);
    let listener = UnixListener::bind(BROKER_SOCKET).map_err(|e| format!("bind {BROKER_SOCKET}: {e}"))?;
    // Only the agent user may ask the daemon for something.
    let _ = std::fs::set_permissions(BROKER_SOCKET, std::os::unix::fs::PermissionsExt::from_mode(0o600));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    let a = agent.clone();
                    std::thread::spawn(move || broker_client(a, s));
                }
                Err(e) => {
                    log(&format!("broker accept: {e}"));
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    });
    log(&format!("broker listening on {BROKER_SOCKET}"));
    Ok(())
}

/// One in-VM client: read its request, forward it to the host, keep the socket
/// in the id→client map so the reader thread can answer it later.
fn broker_client(agent: Arc<Agent>, mut stream: UnixStream) {
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    let mut body = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                body.push(byte[0]);
                if body.len() > MAX_BROKER_BODY {
                    let _ = stream.write_all(b"{\"ok\":false,\"error\":\"broker request too large\"}\n");
                    return;
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return,
        }
    }
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            let _ = stream.write_all(format!("{{\"ok\":false,\"error\":\"broker request is not JSON: {}\"}}\n", escape(&e.to_string())).as_bytes());
            return;
        }
    };
    let kind = match req.get("kind").and_then(Value::as_str) {
        Some(k) if !k.is_empty() => k.to_string(),
        _ => {
            let _ = stream.write_all(b"{\"ok\":false,\"error\":\"broker request needs a `kind` string\"}\n");
            return;
        }
    };
    let payload = req.get("payload").cloned().unwrap_or(Value::Null);
    let id = agent.next_broker.fetch_add(1, Ordering::SeqCst);
    match stream.try_clone() {
        Ok(s) => {
            lock(&agent.broker_clients).insert(id, s);
        }
        Err(e) => {
            let _ = stream.write_all(format!("{{\"ok\":false,\"error\":\"broker: {}\"}}\n", escape(&e.to_string())).as_bytes());
            return;
        }
    }
    if let Err(e) = agent.send(&GuestMsg::Broker { id, kind, payload }) {
        lock(&agent.broker_clients).remove(&id);
        let _ = stream.write_all(format!("{{\"ok\":false,\"error\":\"{}\"}}\n", escape(&e)).as_bytes());
        return;
    }
    // The answer is written by the reader thread when `BrokerReply` arrives.
    let a = agent.clone();
    std::thread::spawn(move || {
        std::thread::sleep(BROKER_TIMEOUT);
        if let Some(mut s) = lock(&a.broker_clients).remove(&id) {
            let _ = s.write_all(b"{\"ok\":false,\"error\":\"the seagent daemon did not answer the broker request in time\"}\n");
        }
    });
}

fn answer_broker(agent: &Agent, id: u64, ok: bool, payload: Value) {
    let Some(mut s) = lock(&agent.broker_clients).remove(&id) else {
        log(&format!("BrokerReply for unknown id {id}"));
        return;
    };
    let reply = if ok { json!({ "ok": true, "payload": payload }) } else { json!({ "ok": false, "error": payload }) };
    let mut line = serde_json::to_vec(&reply).unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"reply is not encodable\"}".to_vec());
    line.push(b'\n');
    let _ = s.write_all(&line);
    let _ = s.flush();
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', " ")
}

/// `seagent-vm-guest broker-send '<json>'`: the in-VM half of the broker.
fn broker_send(body: &str) -> i32 {
    let body = body.trim();
    let req: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("seagent-broker: request is not JSON: {e}");
            return 2;
        }
    };
    if req.get("kind").and_then(Value::as_str).is_none() {
        eprintln!("seagent-broker: request needs a `kind` string, e.g. {{\"kind\":\"egress.http\",\"payload\":{{...}}}}");
        return 2;
    }
    let mut stream = match UnixStream::connect(BROKER_SOCKET) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("seagent-broker: cannot reach the seagent guest agent on {BROKER_SOCKET}: {e}");
            return 1;
        }
    };
    let mut line = serde_json::to_vec(&req).unwrap_or_default();
    line.push(b'\n');
    if let Err(e) = stream.write_all(&line) {
        eprintln!("seagent-broker: send: {e}");
        return 1;
    }
    stream.set_read_timeout(Some(BROKER_TIMEOUT + Duration::from_secs(5))).ok();
    let mut reply = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                reply.push(byte[0]);
                if reply.len() > MAX_BROKER_BODY {
                    eprintln!("seagent-broker: reply too large");
                    return 1;
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => {
                eprintln!("seagent-broker: read reply: {e}");
                return 1;
            }
        }
    }
    let text = String::from_utf8_lossy(&reply).trim().to_string();
    if text.is_empty() {
        eprintln!("seagent-broker: the agent closed the connection without a reply");
        return 1;
    }
    // The reply is this program's output (a binary's stdout, not library logging).
    let _ = writeln!(std::io::stdout(), "{text}");
    match serde_json::from_str::<Value>(&text) {
        Ok(v) if v.get("ok").and_then(Value::as_bool) == Some(true) => 0,
        _ => 1,
    }
}

// ── the serving loop ────────────────────────────────────────────────────────

fn run_init() -> i32 {
    let mut cfg = GuestCfg::default();
    if let Err(e) = mount_guest_fs() {
        // No console yet? The kernel's own serial output still shows the panic.
        eprintln!("seagent-vm-guest: cannot mount the guest file systems: {e}");
        return 1;
    }
    if let Ok(line) = std::fs::read_to_string("/proc/cmdline") {
        cfg = parse_cmdline(&line);
    }
    log(&format!("starting: vm={} tier={} channel={} workspace={} disk_mb={} nproc={}{}", cfg.vm, cfg.tier, if cfg.channel.is_empty() { "auto" } else { &cfg.channel }, cfg.workspace.display(), cfg.disk_mb, cfg.nproc, if cfg.workspace_ro { " workspace_ro" } else { "" }));

    if let Err(e) = mount_tmpfs(&cfg) {
        log(&format!("/tmp tmpfs: {e}"));
    }
    for dir in [cfg.workspace.clone(), PathBuf::from(AGENT_HOME), PathBuf::from("/run/seagent")] {
        if let Err(e) = std::fs::create_dir_all(&dir) {
            log(&format!("mkdir {}: {e}", dir.display()));
        }
    }
    if let Err(e) = set_hostname(&cfg.vm) {
        log(&format!("hostname: {e}"));
    }

    // A per-boot channel key, when the host gave one: fw_cfg (Windows QEMU's loopback TCP
    // channel) or the SMBIOS serial (VirtualBox / Hyper-V named-pipe COM2 on Windows). Read
    // while still root: both sysfs files are 0400, so no command run later as the agent user
    // can learn it.
    let key = seagent_vm::proto::channel_key_from(
        std::fs::read(seagent_vm::proto::FW_CFG_KEY).ok().as_deref(),
        std::fs::read_to_string(seagent_vm::proto::DMI_KEY_FILE).ok().as_deref(),
    );
    if key.is_some() {
        log("channel key present: the host must authenticate before any frame is served");
    }

    // The virtio-serial port has to be opened while we are still root: devtmpfs
    // gives it mode 0600 root:root and there is no udev in the VM.
    let transport = match prepare_transport(&cfg) {
        Ok(t) => t,
        Err(e) => {
            log(&format!("channel: {e}"));
            return 1;
        }
    };

    apply_guest_limits(&cfg.limits());
    let _ = firmware_can_power_off(); // read the FADT while still root
    for dir in [&cfg.workspace, &PathBuf::from(AGENT_HOME), &PathBuf::from("/run/seagent")] {
        if let Err(e) = chown_agent(dir) {
            log(&e);
        }
    }
    if let Err(e) = drop_privileges(AGENT_UID, AGENT_UID) {
        log(&format!("privilege drop failed, refusing to serve: {e}"));
        return 1;
    }
    log(&format!("running as uid {} gid {}", unsafe { libc::getuid() }, unsafe { libc::getgid() }));

    let mut conn = match transport {
        TransportSetup::Serial(f, name) => match serial_conn(f, name) {
            Ok(c) => c,
            Err(e) => {
                log(&format!("channel: {e}"));
                return 1;
            }
        },
        TransportSetup::VsockListener(fd) => {
            log(&format!("waiting for the host on vsock port {VSOCK_PORT}"));
            match vsock_conn(fd) {
                Ok(c) => c,
                Err(e) => {
                    log(&format!("channel: {e}"));
                    return 1;
                }
            }
        }
    };
    log(&format!("channel connected ({})", conn.transport));

    let agent = Arc::new(Agent {
        cfg: cfg.clone(),
        limits: Mutex::new(cfg.limits()),
        w: conn.w.clone(),
        execs: Mutex::new(HashMap::new()),
        broker_clients: Mutex::new(HashMap::new()),
        next_broker: AtomicU64::new(1),
        reaper: Reaper::start(),
    });
    if let Err(e) = start_broker(agent.clone()) {
        log(&format!("broker: {e}"));
    }

    let hello = GuestMsg::Hello {
        version: VERSION,
        agent: format!("seagent-vm-guest {}", env!("CARGO_PKG_VERSION")),
        kernel: kernel_release(),
        cid: conn.cid,
        transport: conn.transport.to_string(),
        uid: unsafe { libc::getuid() },
        nonce: key.as_ref().map(|_| seagent_vm::proto::random_hex(16)),
    };
    let auth = key.map(|k| {
        let challenge = match &hello {
            GuestMsg::Hello { nonce, .. } => nonce.clone().unwrap_or_default(),
            _ => String::new(),
        };
        (k, challenge, hello.clone())
    });
    if let Err(e) = agent.send(&hello) {
        log(&format!("hello: {e}"));
        return 1;
    }
    log("hello sent; serving frames");

    serve(&mut conn, agent.clone(), auth);

    // Shutdown: kill whatever still runs, then power the VM off.
    let pids: Vec<i32> = lock(&agent.execs).values().map(|h| h.pgid).collect();
    for p in pids {
        kill_group(p, libc::SIGKILL);
    }
    let _ = std::fs::remove_file(BROKER_SOCKET);
    log("shutting down");
    power_off()
}

/// `auth`: the channel key and our Hello nonce when the host must authenticate first
/// (`HostMsg::Auth`); until it has, every other frame is refused, so a local process that
/// reached the channel can neither run commands nor shut the VM down.
fn serve(conn: &mut Conn, agent: Arc<Agent>, mut auth: Option<(Vec<u8>, String, GuestMsg)>) {
    loop {
        let msg = match conn.read_frame() {
            Ok(Some(m)) => m,
            Ok(None) if auth.is_some() => {
                // An unauthenticated peer hung up (a local process that grabbed the loopback
                // port first): that is not our host leaving, so do not power off — wait for
                // the next connection (the virtio-serial port reads EOF until one exists).
                conn.buf.clear();
                conn.pending.clear();
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            Ok(None) => {
                log("host closed the channel");
                return;
            }
            Err(e) if auth.is_some() => {
                // Garbage from an unauthenticated peer is dropped, not a reason to shut down.
                log(&format!("channel (unauthenticated peer): {e}"));
                conn.buf.clear();
                conn.pending.clear();
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(e) => {
                log(&format!("channel: {e}"));
                return;
            }
        };
        if let Some((key, challenge, hello)) = &auth {
            match &msg {
                HostMsg::Auth { nonce, mac } => match seagent_vm::proto::guest_auth_answer(key, challenge, nonce, mac) {
                    Ok(answer) => {
                        let _ = agent.send(&answer);
                        log("channel authenticated");
                        auth = None;
                    }
                    Err(e) => {
                        log(&e);
                        let _ = agent.send(&GuestMsg::Err { id: 0, message: e });
                    }
                },
                other => {
                    let _ = agent.send(&GuestMsg::Err { id: other.id().unwrap_or(0), message: "the channel is not authenticated (HostMsg::Auth first)".into() });
                    // Whoever is connected now may not have seen our Hello (a process that
                    // grabbed the port first took it): repeat the challenge, same nonce.
                    let _ = agent.send(hello);
                }
            }
            continue;
        }
        match msg {
            // Already authenticated, or a channel without a key: nothing to do.
            HostMsg::Auth { .. } => {}
            HostMsg::Exec { id, script, cwd, env, login, stdin, pty, timeout_secs } => {
                let req = ExecReq { id, script, cwd, env, login, stdin, pty, timeout_secs };
                if let Err(e) = start_exec(&agent, req) {
                    let _ = agent.send(&GuestMsg::Err { id, message: e });
                }
            }
            HostMsg::Stdin { id, data } => {
                let bytes = match B64.decode(data.as_bytes()) {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = agent.send(&GuestMsg::Err { id, message: format!("stdin is not base64: {e}") });
                        continue;
                    }
                };
                let mut handle = lock(&agent.execs);
                match handle.get_mut(&id).and_then(|h| h.stdin.as_mut()) {
                    Some(f) => {
                        if let Err(e) = f.write_all(&bytes) {
                            drop(handle);
                            let _ = agent.send(&GuestMsg::Err { id, message: format!("stdin write: {e}") });
                        }
                    }
                    None => {
                        drop(handle);
                        let _ = agent.send(&GuestMsg::Err { id, message: format!("exec {id} has no stdin") });
                    }
                }
            }
            HostMsg::Eof { id } => {
                let mut handle = lock(&agent.execs);
                match handle.get_mut(&id) {
                    Some(h) if h.pty.is_some() => {
                        // A pty has no half-close: end the input with ^D.
                        if let Some(f) = h.stdin.as_mut() {
                            let _ = f.write_all(b"\x04");
                        }
                    }
                    Some(h) => {
                        h.stdin = None;
                    }
                    None => {
                        drop(handle);
                        let _ = agent.send(&GuestMsg::Err { id, message: format!("exec {id} is not running") });
                    }
                }
            }
            HostMsg::Signal { id, force } => {
                if !lock(&agent.execs).contains_key(&id) {
                    let _ = agent.send(&GuestMsg::Err { id, message: format!("exec {id} is not running") });
                    continue;
                }
                terminate(agent.clone(), id, force);
            }
            HostMsg::Resize { id, rows, cols } => {
                let handle = lock(&agent.execs);
                match handle.get(&id).and_then(|h| h.pty.as_ref()) {
                    Some(pty) => {
                        if let Err(e) = set_winsize(pty, rows.max(1), cols.max(1)) {
                            drop(handle);
                            let _ = agent.send(&GuestMsg::Err { id, message: e });
                        }
                    }
                    None => {
                        drop(handle);
                        let _ = agent.send(&GuestMsg::Err { id, message: format!("exec {id} has no pty") });
                    }
                }
            }
            HostMsg::BrokerReply { id, ok, payload } => answer_broker(&agent, id, ok, payload),
            HostMsg::Pull { id, paths } => {
                let reply = pull_files(&agent, id, paths);
                let _ = agent.send(&reply);
            }
            HostMsg::Push { id, files } => {
                let reply = push_files(&agent, id, files);
                let _ = agent.send(&reply);
            }
            HostMsg::Limits { nproc, nofile, cpu_seconds } => {
                let mut l = lock(&agent.limits);
                l.nproc = nproc.unwrap_or(l.nproc).max(1);
                l.nofile = nofile.unwrap_or(l.nofile).max(1);
                l.cpu_seconds = cpu_seconds.unwrap_or(l.cpu_seconds);
                let detail = json!({ "nproc": l.nproc, "nofile": l.nofile, "cpu_seconds": l.cpu_seconds });
                drop(l);
                let _ = agent.send(&GuestMsg::Ok { id: 0, detail });
            }
            HostMsg::Ping { id } => {
                let _ = agent.send(&GuestMsg::Pong { id });
            }
            HostMsg::Shutdown => return,
        }
    }
}

/// Does the firmware offer an ACPI power-off path?
///
/// The FADT (`/sys/firmware/acpi/tables/FACP`) carries `PM1a_CNT_BLK` at offset
/// 0x56; when it is zero there is no power-management block, so
/// `reboot(RB_POWER_OFF)` only halts this kernel and the VMM keeps running.
/// Firecracker's FADT has exactly that (`00 00 00 00`); QEMU's q35 has `0x620`.
/// Decided once, as root, before the privilege drop: `/sys/firmware/acpi/tables/FACP` is mode
/// 0400, so a check made at `Shutdown` time (as uid 1000) always failed and the agent always
/// reset the VM — harmless where the VMM exits on a reset (QEMU `-no-reboot`, Firecracker), a
/// fresh reboot under VirtualBox (found there: the guest came straight back up).
static CAN_POWER_OFF: OnceLock<bool> = OnceLock::new();

fn firmware_can_power_off() -> bool {
    *CAN_POWER_OFF.get_or_init(read_fadt_power_off)
}

fn read_fadt_power_off() -> bool {
    match std::fs::read("/sys/firmware/acpi/tables/FACP") {
        Ok(t) if t.len() >= 0x5a => u32::from_le_bytes([t[0x56], t[0x57], t[0x58], t[0x59]]) != 0,
        _ => false,
    }
}

fn power_off() -> i32 {
    // B3: `Shutdown` means "the VM is gone", and there are two ways to ask for
    // that. With an ACPI power-management block (QEMU) `RB_POWER_OFF` really
    // powers the machine down. Without one (Firecracker emulates no PM device)
    // the same call only halts the kernel — "reboot: System halted", the VMM
    // keeps running — so the agent asks for a *reset* instead, which is what
    // both VMMs turn into "the VM is gone": Firecracker stops the process on a
    // guest reset, and QEMU runs with `-no-reboot`.
    // SAFETY: PID 1 with CAP_SYS_BOOT (the one capability the agent kept).
    if firmware_can_power_off() {
        log("powering the VM off (ACPI S5)");
        unsafe { libc::reboot(libc::RB_POWER_OFF) };
        log(&format!("reboot(RB_POWER_OFF) failed: {}", std::io::Error::last_os_error()));
    }
    log("resetting the VM (no ACPI power-off device; the VMM exits on a reset)");
    // SAFETY: as above.
    unsafe { libc::reboot(libc::RB_AUTOBOOT) };
    log(&format!("reboot(RB_AUTOBOOT) failed: {}", std::io::Error::last_os_error()));
    0
}

// ── tests (compiled into the integration tests via #[path]) ─────────────────

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn defaults_are_safe() {
        let c = parse_cmdline("console=ttyS0 quiet rdinit=/sbin/init");
        assert_eq!(c.workspace, PathBuf::from(GUEST_WORKSPACE));
        assert!(c.nproc > 0);
        assert!(!c.workspace_ro);
    }

    #[test]
    fn the_uart_channel_prefers_the_pl011_only_when_present() {
        assert_eq!(uart_device_in(|p| p == UART_DEVICE_PL011), UART_DEVICE_PL011);
        assert_eq!(uart_device_in(|_| false), UART_DEVICE);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(uart_device(), UART_DEVICE, "x86_64 never probes: always the 16550 ttyS1");
    }

    #[test]
    fn seagent_parameters_are_parsed() {
        let line = "console=ttyS0 rdinit=/sbin/init root=/dev/ram seagent.vm=s-42 seagent.tier=owner seagent.channel=virtio-serial seagent.workspace=/workspace seagent.disk_mb=64 seagent.nproc=128 seagent.nofile=2048 seagent.workspace_ro=1";
        let c = parse_cmdline(line);
        assert_eq!(c.vm, "s-42");
        assert_eq!(c.tier, "owner");
        assert_eq!(c.channel, "virtio-serial");
        assert_eq!(c.disk_mb, 64);
        assert_eq!(c.nproc, 128);
        assert_eq!(c.nofile, 2048);
        assert!(c.workspace_ro, "a read-only workspace must survive parsing");
        let l = c.limits();
        assert_eq!((l.nproc, l.nofile, l.disk_mb), (128, 2048, 64));
    }

    #[test]
    fn hostile_values_do_not_escape() {
        let c = parse_cmdline("seagent.workspace=../../etc seagent.disk_mb=notanumber seagent.channel=tcp seagent.nproc=0 seagent.vm=");
        assert_eq!(c.workspace, PathBuf::from(GUEST_WORKSPACE), "relative workspace rejected");
        assert_eq!(c.disk_mb, GuestCfg::default().disk_mb);
        assert_eq!(c.channel, "", "unknown transports are not trusted");
        assert_eq!(c.nproc, GuestCfg::default().nproc, "0 would block every fork");
        assert_eq!(c.vm, "seagent-vm");
    }

    #[test]
    fn guest_paths_must_be_plain_and_absolute() {
        assert_eq!(guest_abs_path("/workspace"), Some(PathBuf::from("/workspace")));
        assert_eq!(guest_abs_path("/srv/a-b/c"), Some(PathBuf::from("/srv/a-b/c")));
        for bad in ["/", "//x", "/a//b", "/a/../b", "/a/./b", "x/y", ""] {
            assert_eq!(guest_abs_path(bad), None, "{bad}");
        }
    }

    #[test]
    fn exit_status_decoding() {
        // exit(3)
        assert_eq!(exit_code(3 << 8), (Some(3), None));
        // killed by SIGKILL
        assert_eq!(exit_code(9), (None, Some(9)));
    }

    #[test]
    fn version_line_names_the_protocol() {
        let v = version_line();
        assert!(v.contains("seagent-vm-guest"), "{v}");
        assert!(v.contains(&VERSION.to_string()), "{v}");
    }
}
