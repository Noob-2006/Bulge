//! bulge-vmm: read a [`VmmConfig`] as JSON from stdin, configure libkrun, and
//! hand the process over to the VM (`krun_start_enter` does not return on
//! success). Secrets arrive on stdin, never on argv or in the environment.

use std::ffi::{CString, c_char};
use std::io::Read;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VmmConfig {
    rootfs: PathBuf,
    cpus: u8,
    ram_mib: u32,
    /// Inherited fd of the network socketpair end (QEMU stream framing).
    /// `None` = no network device at all.
    #[serde(default)]
    net_fd: Option<i32>,
    #[serde(default)]
    mac: Option<[u8; 6]>,
    /// Host directories shared read-only into the guest, by tag.
    #[serde(default)]
    shares: Vec<Share>,
    /// vsock ports the guest listens on, exposed as host unix sockets.
    #[serde(default)]
    vsock_listen: Vec<VsockPort>,
    /// One-shot virtual files on the root filesystem (bootstrap secrets).
    #[serde(default)]
    one_shot_files: Vec<OneShotFile>,
    exec: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: Vec<String>,
    #[serde(default)]
    workdir: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Share {
    tag: String,
    host_path: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VsockPort {
    port: u32,
    host_socket: PathBuf,
    /// true: the guest listens, the host connects via `host_socket` (control).
    /// false: the host listens on `host_socket`, the guest connects to `port`
    /// (used for the guest's outbound egress gateway).
    #[serde(default = "default_true")]
    listen: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OneShotFile {
    /// Path relative to the guest root, without a leading slash.
    path: String,
    contents: String,
    mode: u32,
}

const ROOT_FS_TAG: &str = "/dev/root";
/// libkrun NET_FEATURE_* set used for passt/gvproxy (COMPAT_NET_FEATURES).
const COMPAT_NET_FEATURES: u32 = (1 << 0) | (1 << 1) | (1 << 7) | (1 << 10) | (1 << 11) | (1 << 14);
const VIRTIOFS_DAX_WINDOW: u64 = 1 << 29;

#[link(name = "krun")]
unsafe extern "C" {
    fn krun_create_ctx() -> i32;
    fn krun_set_vm_config(ctx: u32, num_vcpus: u8, ram_mib: u32) -> i32;
    fn krun_set_root(ctx: u32, root_path: *const c_char) -> i32;
    fn krun_add_virtiofs3(ctx: u32, tag: *const c_char, path: *const c_char, shm_size: u64, read_only: bool) -> i32;
    fn krun_add_net_unixstream(ctx: u32, path: *const c_char, fd: i32, mac: *const u8, features: u32, flags: u32) -> i32;
    fn krun_disable_implicit_vsock(ctx: u32) -> i32;
    fn krun_add_vsock(ctx: u32, tsi_features: u32) -> i32;
    fn krun_add_vsock_port2(ctx: u32, port: u32, path: *const c_char, listen: bool) -> i32;
    fn krun_fs_add_overlay_file(
        ctx: u32,
        fs_tag: *const c_char,
        path: *const c_char,
        data: *const u8,
        len: usize,
        mode: u32,
        one_shot: bool,
    ) -> i32;
    fn krun_set_workdir(ctx: u32, workdir: *const c_char) -> i32;
    fn krun_set_exec(ctx: u32, exec_path: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> i32;
    fn krun_start_enter(ctx: u32) -> i32;
}

fn main() {
    if let Err(message) = run() {
        eprintln!("bulge-vmm: {message}");
        std::process::exit(1);
    }
}

fn cstr(value: &str) -> Result<CString, String> {
    CString::new(value).map_err(|_| format!("embedded NUL in {value:?}"))
}

fn path_cstr(path: &std::path::Path) -> Result<CString, String> {
    cstr(path.to_str().ok_or_else(|| format!("non-UTF-8 path {path:?}"))?)
}

fn check(step: &str, code: i32) -> Result<(), String> {
    if code < 0 { Err(format!("{step} failed: errno {}", -code)) } else { Ok(()) }
}

fn run() -> Result<(), String> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).map_err(|e| format!("read config: {e}"))?;
    let config: VmmConfig = serde_json::from_str(&input).map_err(|e| format!("parse config: {e}"))?;
    drop(input);

    // Keep every CString alive until krun_start_enter: libkrun may keep pointers.
    let mut keep: Vec<CString> = Vec::new();
    let mut hold = |value: CString| -> *const c_char {
        let ptr = value.as_ptr();
        keep.push(value);
        ptr
    };

    // SAFETY: every pointer passed below comes from a CString held in `keep`
    // (or a stack array) that outlives krun_start_enter; libkrun copies or
    // borrows them only for the lifetime of the context.
    unsafe {
        let ctx = krun_create_ctx();
        check("krun_create_ctx", ctx)?;
        let ctx = ctx as u32;
        check("krun_set_vm_config", krun_set_vm_config(ctx, config.cpus, config.ram_mib))?;
        check("krun_set_root", krun_set_root(ctx, hold(path_cstr(&config.rootfs)?)))?;

        for share in &config.shares {
            let tag = hold(cstr(&share.tag)?);
            let path = hold(path_cstr(&share.host_path)?);
            check("krun_add_virtiofs3", krun_add_virtiofs3(ctx, tag, path, VIRTIOFS_DAX_WINDOW, true))?;
        }

        if let Some(fd) = config.net_fd {
            let mac = config.mac.unwrap_or([0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee]);
            check(
                "krun_add_net_unixstream",
                krun_add_net_unixstream(ctx, std::ptr::null(), fd, mac.as_ptr(), COMPAT_NET_FEATURES, 0),
            )?;
        }

        // A vsock device without TSI: the guest gets no socket hijacking path
        // to the host network; vsock only carries the listed control ports.
        check("krun_disable_implicit_vsock", krun_disable_implicit_vsock(ctx))?;
        check("krun_add_vsock", krun_add_vsock(ctx, 0))?;
        for port in &config.vsock_listen {
            let path = hold(path_cstr(&port.host_socket)?);
            check("krun_add_vsock_port2", krun_add_vsock_port2(ctx, port.port, path, port.listen))?;
        }

        for file in &config.one_shot_files {
            let tag = hold(cstr(ROOT_FS_TAG)?);
            let path = hold(cstr(&file.path)?);
            let data = file.contents.as_bytes();
            check(
                "krun_fs_add_overlay_file",
                krun_fs_add_overlay_file(ctx, tag, path, data.as_ptr(), data.len(), file.mode, true),
            )?;
        }

        if let Some(workdir) = &config.workdir {
            check("krun_set_workdir", krun_set_workdir(ctx, hold(cstr(workdir)?)))?;
        }

        let exec = hold(cstr(&config.exec)?);
        let mut argv: Vec<*const c_char> = Vec::with_capacity(config.args.len() + 1);
        for arg in &config.args {
            argv.push(hold(cstr(arg)?));
        }
        argv.push(std::ptr::null());
        let mut envp: Vec<*const c_char> = Vec::with_capacity(config.env.len() + 1);
        for var in &config.env {
            envp.push(hold(cstr(var)?));
        }
        envp.push(std::ptr::null());
        check("krun_set_exec", krun_set_exec(ctx, exec, argv.as_ptr(), envp.as_ptr()))?;

        // Only returns on configuration failure.
        let code = krun_start_enter(ctx);
        Err(format!("krun_start_enter returned {code}"))
    }
}
