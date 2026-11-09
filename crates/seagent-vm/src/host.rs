//! The host side of a VM, per operating system (docs/cross-platform.md, "microVM 隔離"):
//! which hardware accelerator this machine offers, where the hypervisor tools live, and how
//! a VMM process is started, confined, watched and stopped.
//!
//! Linux keeps exactly what it had: `/dev/kvm`, the VMM in its own process group,
//! SIGTERM → SIGKILL to that group. The other systems get their own substitute instead of a
//! stub:
//!
//! * **Windows** — WHPX (the Windows Hypervisor Platform QEMU accelerates with) is probed by
//!   asking `WinHvPlatform.dll` itself (`WHvGetCapability(HypervisorPresent)`), Hyper-V by its
//!   management service binary; the VMM runs in a Job Object whose memory and CPU-rate caps
//!   are the VM's size plus head-room (the cgroup substitute) and which kills it on close.
//! * **macOS** — Hypervisor.framework from `sysctl kern.hv_support`; QEMU/vfkit already size
//!   the VM, so there is no extra host-side ceiling to add.
//! * **Android** — `/dev/kvm` (pKVM devices) and the AVF `vm` tool under
//!   `/apex/com.android.virt`.
//! * **iOS** — nothing: the platform does not let an app run a hypervisor, and this module
//!   never claims otherwise.
//!
//! Nothing in here depends on `seagent-core` (layer rule: seagent-vm sits on seagent-net only),
//! so the few process/file helpers it needs are local and deliberately small.

use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
#[cfg(unix)]
use std::time::Duration;

/// The operating system a decision is made for. A field of [`crate::Capabilities`], so the
/// selection table is a pure function that tests can run for every OS on a Linux CI box.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HostOs {
    Linux,
    Android,
    Macos,
    Windows,
    Ios,
    Other,
}

impl HostOs {
    pub fn current() -> HostOs {
        if cfg!(target_os = "android") {
            HostOs::Android
        } else if cfg!(target_os = "linux") {
            HostOs::Linux
        } else if cfg!(target_os = "macos") {
            HostOs::Macos
        } else if cfg!(windows) {
            HostOs::Windows
        } else if cfg!(target_os = "ios") {
            HostOs::Ios
        } else {
            HostOs::Other
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            HostOs::Linux => "linux",
            HostOs::Android => "android",
            HostOs::Macos => "macos",
            HostOs::Windows => "windows",
            HostOs::Ios => "ios",
            HostOs::Other => "other",
        }
    }
}

impl Default for HostOs {
    fn default() -> Self {
        HostOs::current()
    }
}

/// What makes a guest run at native speed — or the honest admission that nothing does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Accel {
    /// Linux / Android `/dev/kvm`.
    Kvm,
    /// Windows Hypervisor Platform (QEMU `-accel whpx`).
    Whpx,
    /// macOS Hypervisor.framework (QEMU `-accel hvf`, and what Virtualization.framework uses).
    Hvf,
    /// Hyper-V's own VM worker (Windows).
    Hyperv,
    /// VirtualBox's own ring-0 driver (VT-x / AMD-V, or the Hyper-V API on Windows 11).
    Vbox,
    /// QEMU TCG: software emulation. Still a separate guest kernel, but slow, and the whole
    /// emulator is attack surface.
    Tcg,
}

impl Accel {
    pub fn name(self) -> &'static str {
        match self {
            Accel::Kvm => "kvm",
            Accel::Whpx => "whpx",
            Accel::Hvf => "hvf",
            Accel::Hyperv => "hyperv",
            Accel::Vbox => "vbox",
            Accel::Tcg => "tcg",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Accel::Kvm => "KVM",
            Accel::Whpx => "Windows Hypervisor Platform",
            Accel::Hvf => "Hypervisor.framework",
            Accel::Hyperv => "Hyper-V",
            Accel::Vbox => "VirtualBox (VT-x/AMD-V)",
            Accel::Tcg => "none (TCG software emulation)",
        }
    }
    pub fn is_hardware(self) -> bool {
        self != Accel::Tcg
    }
}

/// `/dev/kvm` exists and this user may open it read-write (Linux, pKVM Android).
pub fn kvm_usable() -> bool {
    cfg!(any(target_os = "linux", target_os = "android")) && std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm").is_ok()
}

/// The Windows Hypervisor Platform is enabled *and* the hypervisor is running. Asks the
/// platform DLL itself: the DLL exists only with the optional feature, and
/// `WHvCapabilityCodeHypervisorPresent` is false when VT-x is off in firmware.
#[cfg(windows)]
pub fn whpx_available() -> bool {
    use windows_sys::Win32::Foundation::FreeLibrary;
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
    type GetCap = unsafe extern "system" fn(u32, *mut core::ffi::c_void, u32, *mut u32) -> i32;
    let name: Vec<u16> = "WinHvPlatform.dll\0".encode_utf16().collect();
    // SAFETY: plain dynamic loading; the symbol is cast to its documented signature.
    unsafe {
        let lib = LoadLibraryW(name.as_ptr());
        if lib == 0 {
            return false;
        }
        let present = match GetProcAddress(lib, c"WHvGetCapability".as_ptr().cast()) {
            Some(f) => {
                let f: GetCap = std::mem::transmute(f);
                let mut present: i32 = 0;
                let mut written: u32 = 0;
                f(0, (&mut present as *mut i32).cast(), 4, &mut written) >= 0 && present != 0
            }
            None => false,
        };
        FreeLibrary(lib);
        present
    }
}
#[cfg(not(windows))]
pub fn whpx_available() -> bool {
    false
}

/// Hypervisor.framework is usable on this Mac (`sysctl kern.hv_support` = 1).
#[cfg(target_os = "macos")]
pub fn hvf_available() -> bool {
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>();
    // SAFETY: sysctlbyname with a correctly sized output buffer.
    let rc = unsafe { libc::sysctlbyname(c"kern.hv_support".as_ptr(), (&mut v as *mut libc::c_int).cast(), &mut len, std::ptr::null_mut(), 0) };
    rc == 0 && v == 1
}
#[cfg(not(target_os = "macos"))]
pub fn hvf_available() -> bool {
    false
}

/// Hyper-V is installed: its management service *and* the `Hyper-V` PowerShell module the
/// provider drives (`New-VM` …) are on disk. Whether *this* user may create VMs (an elevated
/// session or `Hyper-V Administrators`) only shows when `New-VM` runs.
pub fn hyperv_available() -> bool {
    cfg!(windows) && hyperv_files().0 && hyperv_files().1
}

/// (`vmms.exe`, the `Hyper-V` PowerShell module) present.
fn hyperv_files() -> (bool, bool) {
    let sys = system_root().join("System32");
    (sys.join("vmms.exe").is_file(), sys.join("WindowsPowerShell").join("v1.0").join("Modules").join("Hyper-V").is_dir())
}

/// Why the Hyper-V provider cannot run on this machine, or `None` when it is installed.
/// Windows Home editions (`EditionID` `Core*`) have no Hyper-V role at all — only the
/// hypervisor that WSL2 and the Windows Hypervisor Platform use — so the fix there is a
/// different provider (QEMU+WHPX), not a feature to enable.
pub fn hyperv_unavailable() -> Option<String> {
    if !cfg!(windows) {
        return Some("Hyper-V exists on Windows only".into());
    }
    let (vmms, module) = hyperv_files();
    hyperv_reason(windows_edition().as_deref(), vmms, module)
}

/// [`hyperv_unavailable`] as a pure function of what was probed (tests run it on any OS).
pub fn hyperv_reason(edition: Option<&str>, vmms: bool, module: bool) -> Option<String> {
    if vmms && module {
        return None;
    }
    if let Some(ed) = edition.filter(|e| is_home_edition(e)) {
        return Some(format!(
            "unavailable on Windows Home (EditionID `{ed}`): Home has no Hyper-V role or Hyper-V PowerShell module (Pro, Enterprise or Education do); QEMU+WHPX or VirtualBox are used instead"
        ));
    }
    Some(match (vmms, module) {
        (false, false) => "not installed (no vmms service, no Hyper-V PowerShell module): Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All (elevated), then reboot".into(),
        (true, false) => "the Hyper-V PowerShell module is missing: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell (elevated)".into(),
        _ => "the Hyper-V management service (vmms) is missing: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All (elevated), then reboot".into(),
    })
}

/// `Core`, `CoreN`, `CoreSingleLanguage`, `CoreCountrySpecific`: the Home editions.
pub fn is_home_edition(edition_id: &str) -> bool {
    edition_id.starts_with("Core")
}

/// `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EditionID` (`Core`, `Professional`, …).
#[cfg(windows)]
pub fn windows_edition() -> Option<String> {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
    let key: Vec<u16> = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\0".encode_utf16().collect();
    let value: Vec<u16> = "EditionID\0".encode_utf16().collect();
    let mut buf = [0u16; 128];
    let mut len = (buf.len() * 2) as u32;
    // SAFETY: NUL-terminated key/value names; `len` is the buffer size in bytes.
    let rc = unsafe { RegGetValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), value.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut len) };
    if rc != 0 {
        return None;
    }
    let n = (len as usize / 2).min(buf.len());
    Some(String::from_utf16_lossy(&buf[..n]).trim_end_matches('\0').to_string())
}
#[cfg(not(windows))]
pub fn windows_edition() -> Option<String> {
    None
}

/// The AVF `vm` tool (Android Virtualization Framework, pKVM devices).
pub fn avf_tool() -> Option<PathBuf> {
    if !cfg!(target_os = "android") {
        return None;
    }
    let p = PathBuf::from("/apex/com.android.virt/bin/vm");
    p.is_file().then_some(p)
}

fn system_root() -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
}

/// Directories where hypervisor tools live when they are not on `PATH` (GUI-launched apps on
/// macOS get a minimal PATH; Windows installers rarely touch it).
pub fn tool_dirs() -> Vec<PathBuf> {
    let mut v = vec![];
    if cfg!(windows) {
        let pf = PathBuf::from(std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into()));
        v.push(pf.join("qemu"));
        if let Ok(p) = std::env::var("VBOX_MSI_INSTALL_PATH") {
            v.push(PathBuf::from(p));
        }
        v.push(pf.join("Oracle").join("VirtualBox"));
        v.push(system_root().join("System32").join("WindowsPowerShell").join("v1.0"));
    } else if cfg!(target_os = "macos") {
        v.extend(["/opt/homebrew/bin", "/usr/local/bin", "/Applications/VirtualBox.app/Contents/MacOS"].map(PathBuf::from));
    }
    v
}

/// `which` over `PATH`, then [`tool_dirs`]; on Windows also with `.exe`.
pub fn find_tool(name: &str) -> Option<PathBuf> {
    crate::isolation::which(name).or_else(|| tool_dirs().into_iter().find_map(|d| exe_in(&d, name)))
}

pub(crate) fn exe_in(dir: &Path, name: &str) -> Option<PathBuf> {
    let p = dir.join(name);
    if p.is_file() {
        return Some(p);
    }
    if cfg!(windows) && Path::new(name).extension().is_none() {
        let e = dir.join(format!("{name}.exe"));
        return e.is_file().then_some(e);
    }
    None
}

/// The QEMU system emulator that matches this host for hardware acceleration: KVM/WHPX/HVF
/// can only run guests of the host's own architecture.
pub fn native_qemu() -> &'static str {
    if cfg!(target_arch = "aarch64") && !cfg!(target_os = "linux") {
        "qemu-system-aarch64"
    } else {
        "qemu-system-x86_64"
    }
}

/// Homebrew's UEFI firmware for `qemu-system-aarch64 -M virt` (Apple Silicon).
pub fn edk2_aarch64(qemu: &Path) -> Option<PathBuf> {
    let mut c: Vec<PathBuf> = vec![];
    if let Some(prefix) = qemu.parent().and_then(Path::parent) {
        c.push(prefix.join("share/qemu/edk2-aarch64-code.fd"));
    }
    c.extend(["/opt/homebrew/share/qemu/edk2-aarch64-code.fd", "/usr/local/share/qemu/edk2-aarch64-code.fd"].map(PathBuf::from));
    c.into_iter().find(|p| p.is_file())
}

// ── VMM processes ───────────────────────────────────────────────────────────

/// Start a VMM so that it can be stopped as a unit: its own process group on unix, its own
/// console process group (no console window) on Windows.
pub fn spawn_vmm(cmd: &mut Command) -> std::io::Result<Child> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW};
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
    cmd.spawn()
}

/// SIGTERM the VMM's process group, wait up to a second, then SIGKILL (unix); terminate and
/// reap (Windows). `spawn_vmm` made the group ours alone, so this never reaches another process.
pub fn stop_vmm(child: &mut Child) {
    #[cfg(unix)]
    {
        let pid = child.id() as i32;
        // SAFETY: we own this process group (process_group(0) at spawn).
        unsafe { libc::kill(-pid, libc::SIGTERM) };
        for _ in 0..50 {
            if matches!(child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if matches!(child.try_wait(), Ok(None)) {
            // SAFETY: as above; only our own child group.
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            let _ = child.wait();
        }
    }
    #[cfg(not(unix))]
    {
        if matches!(child.try_wait(), Ok(None)) {
            let _ = child.kill();
        }
        let _ = child.wait();
    }
}

/// Does `pid` name a live (non-zombie) process?
pub fn pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // SAFETY: signal 0 only checks that the process exists.
        if unsafe { libc::kill(pid as i32, 0) } != 0 {
            return false;
        }
        // A zombie is gone for our purposes (only visible where /proc exists).
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        !stat.rsplit(')').next().unwrap_or("").trim_start().starts_with('Z')
    }
    #[cfg(windows)]
    {
        win::alive(pid)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        false
    }
}

/// Ask (`force = false`) or force a process that is not our child to exit.
pub fn kill_pid(pid: u32, force: bool) {
    #[cfg(unix)]
    // SAFETY: callers pass a pid they verified is their VMM.
    unsafe {
        libc::kill(pid as i32, if force { libc::SIGKILL } else { libc::SIGTERM });
    }
    #[cfg(windows)]
    {
        // No polite signal reaches a console-less process: both mean TerminateProcess.
        let _ = force;
        win::terminate(pid);
    }
    #[cfg(not(any(unix, windows)))]
    let _ = (pid, force);
}

/// The command line (Linux, macOS) or executable path (Windows) of `pid`, to tell a VMM from
/// a recycled pid.
pub fn process_identity(pid: u32) -> Option<String> {
    if cfg!(target_os = "linux") || cfg!(target_os = "android") {
        return std::fs::read(format!("/proc/{pid}/cmdline")).ok().map(|b| String::from_utf8_lossy(&b).into_owned());
    }
    #[cfg(windows)]
    {
        return win::image_path(pid);
    }
    #[cfg(not(windows))]
    {
        let o = Command::new("ps").args(["-ww", "-o", "command=", "-p", &pid.to_string()]).output().ok()?;
        o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
    }
}

/// Host-side resource ceiling around a VMM process: a Job Object on Windows (the cgroup v2
/// substitute: memory cap = guest RAM + VMM head-room, CPU-rate hard cap = vCPUs' share of the
/// host, kill-on-close). Elsewhere the VMM's own `-m`/`-smp` (or the cgroup the daemon runs in
/// on Linux) is the ceiling and this is empty.
#[derive(Debug, Default)]
pub struct VmmJob {
    #[cfg(windows)]
    handle: isize,
}

/// Memory the VMM itself may use on top of guest RAM (device emulation, page tables, caches).
pub const VMM_OVERHEAD_MB: u64 = 256;

impl VmmJob {
    pub fn confine(child: &Child, mem_mb: u32, vcpu: u16) -> Result<VmmJob, String> {
        #[cfg(windows)]
        {
            let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) as u64;
            let rate = ((vcpu as u64 * 10_000) / cpus.max(1)).clamp(100, 10_000) as u32;
            win::job(child, (mem_mb as u64 + VMM_OVERHEAD_MB) << 20, rate).map(|handle| VmmJob { handle })
        }
        #[cfg(not(windows))]
        {
            let _ = (child, mem_mb, vcpu);
            Ok(VmmJob::default())
        }
    }
}

#[cfg(windows)]
impl Drop for VmmJob {
    fn drop(&mut self) {
        if self.handle != 0 {
            // SAFETY: our own job handle; KILL_ON_JOB_CLOSE ends whatever is still inside.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle) };
        }
    }
}

/// CPU time (in `hz` ticks) and resident set (KiB) of a VMM, per OS.
#[allow(deprecated)] // libc's mach timebase items point at the `mach2` crate; no new dependency for one call
pub fn usage(pid: u32) -> Option<(u64, u64)> {
    #[cfg(windows)]
    {
        win::usage(pid)
    }
    #[cfg(target_os = "macos")]
    {
        let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
        // SAFETY: PROC_PIDTASKINFO into a correctly sized struct.
        let n = unsafe { libc::proc_pidinfo(pid as libc::c_int, libc::PROC_PIDTASKINFO, 0, (&mut info as *mut libc::proc_taskinfo).cast(), size) };
        // Mach absolute time (ns on Intel, 24 MHz ticks on Apple Silicon) → ns → 100 Hz ticks.
        let mut tb = libc::mach_timebase_info_data_t { numer: 1, denom: 1 };
        // SAFETY: fills a plain struct.
        unsafe { libc::mach_timebase_info(&mut tb) };
        let ns = (info.pti_total_user + info.pti_total_system) as u128 * tb.numer.max(1) as u128 / tb.denom.max(1) as u128;
        (n == size).then(|| ((ns / 10_000_000) as u64, info.pti_resident_size / 1024))
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

// ── files ───────────────────────────────────────────────────────────────────

/// Create `p` (and parents) readable only by this user: mode 0700 on unix. On Windows the
/// per-user data/runtime directories already carry an owner-only inherited DACL.
pub fn private_dir(p: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(p).map_err(|e| format!("create {}: {e}", p.display()))?;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(p).map_err(|e| format!("create {}: {e}", p.display()))
    }
}

/// Unix permission bits of `md`, or the closest equivalent (read-only → 0o444).
pub fn mode_bits(md: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        md.permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        if md.permissions().readonly() {
            0o444
        } else {
            0o644
        }
    }
}

/// Recreate a relative symlink `link -> target` (workspace snapshots). Windows only allows
/// symlinks with Developer Mode or elevation: `Ok(false)` there means "this host cannot make
/// the link" and the caller records it instead of faking it with a copy.
pub fn relink(target: &Path, link: &Path) -> std::io::Result<bool> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).map(|_| true)
    }
    #[cfg(windows)]
    {
        let resolved = link.parent().unwrap_or(Path::new(".")).join(target);
        let made = if resolved.is_dir() { std::os::windows::fs::symlink_dir(target, link) } else { std::os::windows::fs::symlink_file(target, link) };
        Ok(made.is_ok())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, link);
        Ok(false)
    }
}

/// Mark a script executable (test fakes, generated helpers).
pub fn make_executable(p: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755))
    }
    #[cfg(not(unix))]
    {
        let _ = p;
        Ok(())
    }
}

#[cfg(windows)]
mod win {
    //! The handful of Win32 calls the VMM lifecycle needs.
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, STILL_ACTIVE};
    use windows_sys::Win32::System::JobObjects::*;
    use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows_sys::Win32::System::Threading::*;

    struct H(isize);
    impl Drop for H {
        fn drop(&mut self) {
            if self.0 != 0 {
                // SAFETY: a handle this module opened.
                unsafe { CloseHandle(self.0) };
            }
        }
    }
    fn open(pid: u32, access: u32) -> Option<H> {
        // SAFETY: OpenProcess has no preconditions; a 0 handle is a failure.
        let h = unsafe { OpenProcess(access, 0, pid) };
        (h != 0).then_some(H(h))
    }

    pub fn alive(pid: u32) -> bool {
        let Some(h) = open(pid, PROCESS_QUERY_LIMITED_INFORMATION) else { return false };
        let mut code = 0u32;
        // SAFETY: valid process handle and out pointer.
        unsafe { GetExitCodeProcess(h.0, &mut code) != 0 && code == STILL_ACTIVE as u32 }
    }

    pub fn terminate(pid: u32) {
        if let Some(h) = open(pid, PROCESS_TERMINATE) {
            // SAFETY: valid handle with PROCESS_TERMINATE.
            unsafe { TerminateProcess(h.0, 1) };
        }
    }

    pub fn image_path(pid: u32) -> Option<String> {
        let h = open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        // SAFETY: the buffer holds `len` UTF-16 units.
        let ok = unsafe { QueryFullProcessImageNameW(h.0, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) };
        (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }

    pub fn usage(pid: u32) -> Option<(u64, u64)> {
        let h = open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
        let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut c, mut e, mut k, mut u) = (z, z, z, z);
        // SAFETY: valid handle, four out pointers.
        if unsafe { GetProcessTimes(h.0, &mut c, &mut e, &mut k, &mut u) } == 0 {
            return None;
        }
        let ft = |f: FILETIME| ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64;
        // 100 ns units → 100 Hz ticks (what the /proc reader reports).
        let ticks = (ft(k) + ft(u)) / 100_000;
        let mut m: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
        m.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        // SAFETY: valid handle, correctly sized counters.
        let rss = if unsafe { K32GetProcessMemoryInfo(h.0, &mut m, m.cb) } != 0 { m.WorkingSetSize as u64 / 1024 } else { 0 };
        Some((ticks, rss))
    }

    /// A kill-on-close job with a job-wide memory cap and a hard CPU-rate cap (1/100 % units).
    pub fn job(child: &std::process::Child, mem_bytes: u64, cpu_rate: u32) -> Result<isize, String> {
        use std::os::windows::io::AsRawHandle;
        // SAFETY: anonymous job, default security.
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job == 0 {
            return Err(format!("CreateJobObject: {}", std::io::Error::last_os_error()));
        }
        let mut ext: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        ext.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_JOB_MEMORY;
        ext.JobMemoryLimit = mem_bytes as usize;
        let mut cpu: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = unsafe { std::mem::zeroed() };
        cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        cpu.Anonymous.CpuRate = cpu_rate;
        // SAFETY: structs sized as declared; the process handle belongs to `child`.
        let ok = unsafe {
            SetInformationJobObject(job, JobObjectExtendedLimitInformation, (&ext as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(), std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32) != 0
                && AssignProcessToJobObject(job, child.as_raw_handle() as isize) != 0
        };
        if !ok {
            let e = std::io::Error::last_os_error();
            // SAFETY: our own handle.
            unsafe { CloseHandle(job) };
            return Err(format!("Job Object for the VMM: {e}"));
        }
        // The CPU cap is best effort (needs Windows 8+; refused inside some nested jobs).
        // SAFETY: as above.
        unsafe { SetInformationJobObject(job, JobObjectCpuRateControlInformation, (&cpu as *const JOBOBJECT_CPU_RATE_CONTROL_INFORMATION).cast(), std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32) };
        Ok(job)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_running_os_and_accelerators_are_named_honestly() {
        assert_eq!(HostOs::current(), if cfg!(target_os = "linux") { HostOs::Linux } else { HostOs::current() });
        assert_eq!(HostOs::default(), HostOs::current());
        assert!(!Accel::Tcg.is_hardware() && Accel::Kvm.is_hardware() && Accel::Whpx.is_hardware());
        assert!(Accel::Tcg.label().contains("software"));
        if cfg!(target_os = "linux") {
            assert!(!whpx_available() && !hvf_available() && !hyperv_available() && avf_tool().is_none(), "no foreign accelerator is ever reported on Linux");
            assert_eq!(native_qemu(), "qemu-system-x86_64", "Linux keeps its QEMU binary");
        }
    }

    #[test]
    fn hyperv_is_explained_per_edition_and_missing_part() {
        assert_eq!(hyperv_reason(Some("Professional"), true, true), None, "installed = usable");
        for home in ["Core", "CoreN", "CoreSingleLanguage", "CoreCountrySpecific"] {
            assert!(is_home_edition(home));
            let r = hyperv_reason(Some(home), false, false).unwrap();
            assert!(r.contains("Windows Home") && r.contains(home) && !r.contains("Enable-WindowsOptionalFeature"), "Home cannot enable Hyper-V: {r}");
        }
        for pro in ["Professional", "Enterprise", "Education", "ServerStandard"] {
            assert!(!is_home_edition(pro));
            assert!(hyperv_reason(Some(pro), false, false).unwrap().contains("Microsoft-Hyper-V-All"), "Pro: name the feature to enable");
        }
        assert!(hyperv_reason(Some("Professional"), true, false).unwrap().contains("PowerShell module"));
        assert!(hyperv_reason(None, false, false).unwrap().contains("not installed"));
        if cfg!(windows) {
            let ed = windows_edition().expect("every Windows has an EditionID");
            assert_eq!(hyperv_unavailable().is_some(), !hyperv_available());
            if is_home_edition(&ed) {
                assert!(!hyperv_available() && hyperv_unavailable().unwrap().contains("Windows Home"), "{ed}");
            }
        } else {
            assert!(windows_edition().is_none() && hyperv_unavailable().is_some());
        }
    }

    #[test]
    fn our_own_process_is_alive_and_identifiable() {
        assert!(pid_alive(std::process::id()));
        if cfg!(target_os = "linux") {
            assert!(process_identity(std::process::id()).is_some_and(|c| !c.is_empty()));
        }
    }
}
