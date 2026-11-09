//! Per-OS glue of the CLI binary (docs/cross-platform.md): the process, terminal, file-mode,
//! network and desktop calls that the command modules used to make with `libc` directly.
//!
//! Rule one of the port applies: on Linux every function here is the code that lived at the
//! call site, moved unchanged (same syscalls, same order). macOS / Android share the POSIX
//! branch. Windows gets its own branch on `seagent_core::platform` and `windows-sys`:
//!
//! | need | Unix | Windows |
//! |---|---|---|
//! | Ctrl-C counter / stop flag | `signal(SIGINT/SIGTERM)` | `SetConsoleCtrlHandler` |
//! | detach a helper | `setsid` in `pre_exec` | `DETACHED_PROCESS` + `CREATE_NEW_PROCESS_GROUP` |
//! | hidden input | termios `ECHO` off | console mode without `ENABLE_ECHO_INPUT` |
//! | the terminal | `/dev/tty` | `CONIN$` / `CONOUT$` |
//! | `chmod 0600/0700` | `set_permissions` | owner-only DACL (`fs_private::set_private`) |
//! | `access(W_OK)` | `access(2)` | create-and-remove a probe file |
//! | daemon reachable | unix socket connect | named pipe connect (`platform::ipc`) |
//! | open a URL | `xdg-open` / `open` | `rundll32 url.dll,FileProtocolHandler` |
//! | interface addresses | `getifaddrs` (caller) | `GetAdaptersAddresses` |
//!
//! Nothing here prints.

use std::io;
use std::path::Path;
use std::process::Command;
#[cfg(windows)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU32, Ordering};

// ───────────────────────── Ctrl-C ─────────────────────────

/// Ctrl-C presses since [`catch_sigint`]; the second one exits with status 130 at once.
pub static SIGINTS: AtomicU32 = AtomicU32::new(0);

#[cfg(unix)]
extern "C" fn on_sigint(_: libc::c_int) {
    if SIGINTS.fetch_add(1, Ordering::SeqCst) >= 1 {
        // Second Ctrl-C: give up immediately. The log is append-only and fsynced,
        // so the next run recovers.
        unsafe { libc::_exit(130) };
    }
}

#[cfg(windows)]
unsafe extern "system" fn on_ctrl_c(kind: u32) -> windows_sys::Win32::Foundation::BOOL {
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};
    if kind != CTRL_C_EVENT && kind != CTRL_BREAK_EVENT {
        return 0;
    }
    if SIGINTS.fetch_add(1, Ordering::SeqCst) >= 1 {
        windows_sys::Win32::System::Threading::ExitProcess(130);
    }
    1
}

/// Reset [`SIGINTS`] and count Ctrl-C presses instead of dying on the first one.
pub fn catch_sigint() {
    SIGINTS.store(0, Ordering::SeqCst);
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGINT, on_sigint as *const () as libc::sighandler_t);
    }
    #[cfg(windows)]
    // SAFETY: registers a handler that only touches an atomic (or exits).
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_ctrl_c), 1);
    }
}

/// Back to the default Ctrl-C behaviour (terminate).
pub fn default_sigint() {
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
    }
    #[cfg(windows)]
    // SAFETY: removes the handler registered by `catch_sigint`.
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_ctrl_c), 0);
    }
}

#[cfg(windows)]
static STOP_FLAG: std::sync::atomic::AtomicPtr<AtomicBool> = std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

#[cfg(windows)]
unsafe extern "system" fn on_stop(_kind: u32) -> windows_sys::Win32::Foundation::BOOL {
    let f = STOP_FLAG.load(Ordering::SeqCst);
    if f.is_null() {
        return 0;
    }
    (*f).store(true, Ordering::SeqCst);
    1
}

/// Windows form of the `SIGINT` / `SIGTERM` → stop-flag handlers of the long-running loops:
/// Ctrl-C, Ctrl-Break, closing the console, logoff and shutdown set `flag`. (Unix callers keep
/// their own `signal(2)` handlers.)
#[cfg(windows)]
pub fn on_stop_signals(flag: &'static AtomicBool) {
    STOP_FLAG.store(flag as *const AtomicBool as *mut AtomicBool, Ordering::SeqCst);
    // SAFETY: the handler only stores to a `'static` atomic.
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_stop), 1);
    }
}

// ───────────────────────── processes ─────────────────────────

/// Detach a helper from our terminal and signals: `setsid` on Unix; on Windows no console and
/// a new process group (Ctrl-C in our console does not reach it).
pub fn detach(cmd: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, DETACHED_PROCESS};
        // No console inherited, none created (CREATE_NO_WINDOW also covers a console-subsystem
        // grandchild), and Ctrl-C in the caller's console never reaches it.
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
        // CreateProcess inherits *every* inheritable handle, not only the three it is given. When
        // our own stdout/stderr are pipes (the desktop app capturing `seagent daemon start`), the
        // long-lived helper would keep their write ends open and the reader would never see EOF.
        // std re-duplicates a std handle as inheritable whenever a later child inherits it, so
        // clearing the flag on the originals is safe.
        use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
        for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            // SAFETY: GetStdHandle has no preconditions; SetHandleInformation only changes the
            // inherit flag of a handle we own (null / invalid handles are skipped).
            unsafe {
                let h = GetStdHandle(which);
                if h != 0 && h != INVALID_HANDLE_VALUE {
                    SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0);
                }
            }
        }
    }
}

/// Is `pid` running? `kill(pid, 0)` on Unix (what the call sites always did); `OpenProcess`
/// on Windows.
pub fn pid_alive(pid: i64) -> bool {
    #[cfg(unix)]
    {
        // SAFETY: signal 0 only checks existence/permission.
        pid > 0 && unsafe { libc::kill(pid as i32, 0) } == 0
    }
    #[cfg(not(unix))]
    {
        pid > 0 && pid <= i32::MAX as i64 && seagent_core::platform::proc::alive(pid as i32)
    }
}

/// Ask `pid` to stop: `SIGTERM` on Unix, `SIGKILL` when `force`. Windows has no polite signal
/// for a process in another console, so both terminate it with its whole process tree: a
/// detached helper started through a launcher (Git's `bin\sh.exe` → `usr\bin\sh.exe`) would
/// otherwise outlive the launcher with a dead parent.
pub fn terminate(pid: i64, force: bool) {
    if pid <= 0 || pid > i32::MAX as i64 {
        return;
    }
    #[cfg(unix)]
    // SAFETY: plain kill(2) on a pid the caller spawned.
    unsafe {
        libc::kill(pid as i32, if force { libc::SIGKILL } else { libc::SIGTERM });
    }
    #[cfg(not(unix))]
    {
        let _ = force;
        #[cfg(windows)]
        seagent_core::platform::proc::kill_tree(pid as i32);
        #[cfg(not(windows))]
        seagent_core::platform::proc::kill_group(pid as i32, std::time::Duration::ZERO);
    }
}

/// The local daemon answers on its control endpoint (unix socket / named pipe).
pub fn daemon_reachable(socket: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::net::UnixStream::connect(socket).is_ok()
    }
    #[cfg(not(unix))]
    {
        seagent_core::platform::ipc::IpcStream::connect(socket).is_ok()
    }
}

// ───────────────────────── files ─────────────────────────

/// `chmod mode`. Windows has no mode bits: an owner-only `mode` (nothing for group/other)
/// becomes the protected owner-only DACL, anything else leaves the inherited ACL alone.
pub fn set_mode(p: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        if mode & 0o077 == 0 {
            seagent_core::platform::fs_private::set_private(p)
        } else {
            Ok(())
        }
    }
}

/// The permission bits of `p` (follows symlinks). Windows synthesises them: `0o644` / `0o755`
/// when `fs_private::is_private` (a DACL check on Windows) says others have access, `0o600` /
/// `0o700` otherwise (also when the DACL cannot be read: the files seagent writes get the
/// owner-only DACL through [`set_mode`] / [`create_private`], and refusing every secret file
/// would make the checks useless), write bits cleared for read-only files and exec bits for directories
/// and [`is_executable`] files — so `mode & 0o077` keeps meaning "others can read it" and
/// `mode & 0o111` "it runs".
pub fn mode_of(p: &Path) -> io::Result<u32> {
    let md = std::fs::metadata(p)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(md.permissions().mode())
    }
    #[cfg(not(unix))]
    {
        let private = seagent_core::platform::fs_private::is_private(p).unwrap_or(true);
        let mut m = if private { 0o600 } else { 0o644 };
        if md.is_dir() || is_executable(p, &md) {
            m |= if private { 0o100 } else { 0o111 };
        }
        if md.permissions().readonly() {
            m &= !0o222;
        }
        Ok(m)
    }
}

/// Would exec run it? Unix: a regular file with an exec bit. Windows: a regular file with an
/// extension from `PATHEXT` (default `.COM;.EXE;.BAT;.CMD`) or `.ps1`.
pub fn is_executable(p: &Path, md: &std::fs::Metadata) -> bool {
    if !md.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = p;
        md.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let ext = p.extension().and_then(|e| e.to_str()).map(|e| format!(".{}", e.to_ascii_lowercase())).unwrap_or_default();
        let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into()).to_ascii_lowercase();
        !ext.is_empty() && (ext == ".ps1" || pathext.split(';').any(|x| x == ext))
    }
}

/// Can this user create files in `dir`? `access(W_OK)` on Unix; on Windows (whose ACLs the
/// read-only attribute does not describe) a probe file is created and removed.
pub fn writable(dir: &Path) -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::access(std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap_or_default().as_ptr(), libc::W_OK) == 0 }
    }
    #[cfg(not(unix))]
    {
        let probe = dir.join(format!(".seagent-write-probe-{}", std::process::id()));
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&probe) {
            Ok(f) => {
                drop(f);
                let _ = std::fs::remove_file(&probe);
                true
            }
            Err(e) => e.kind() == io::ErrorKind::AlreadyExists,
        }
    }
}

/// Write `body` to a new file that only this user can read (`create_new`, mode 0600 /
/// owner-only DACL). Fails when the file exists.
pub fn create_private(p: &Path, body: &[u8]) -> io::Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(p)?
    };
    #[cfg(not(unix))]
    let mut f = seagent_core::platform::fs_private::open_private(p, seagent_core::platform::fs_private::OpenMode::CreateNew)?;
    f.write_all(body)
}

/// A symbolic link `link` → `target` (Windows: a file or directory link, which needs
/// Developer Mode or the symlink privilege; the error says so).
pub fn symlink(target: &Path, link: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    {
        let r = if target.is_dir() { std::os::windows::fs::symlink_dir(target, link) } else { std::os::windows::fs::symlink_file(target, link) };
        r.map_err(|e| io::Error::new(e.kind(), format!("{e} (Windows symlinks need Developer Mode or an elevated prompt; install without --link to copy instead)")))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, link);
        Err(io::Error::new(io::ErrorKind::Unsupported, "no symlinks on this target"))
    }
}

/// `ELOOP` (symlink loop) as this OS reports it (`ERROR_CANT_RESOLVE_FILENAME` on Windows).
pub const ELOOP: i32 = if cfg!(windows) { 1921 } else { ELOOP_UNIX };
#[cfg(unix)]
const ELOOP_UNIX: i32 = libc::ELOOP;
#[cfg(not(unix))]
const ELOOP_UNIX: i32 = -1;

/// `ENOTDIR` (a path component is a file) as this OS reports it (`ERROR_DIRECTORY` /
/// `ERROR_PATH_NOT_FOUND` on Windows; the latter is also `NotFound`).
pub fn is_enotdir(e: &io::Error) -> bool {
    #[cfg(unix)]
    {
        e.raw_os_error() == Some(libc::ENOTDIR)
    }
    #[cfg(not(unix))]
    {
        matches!(e.raw_os_error(), Some(267) | Some(3))
    }
}

/// `/etc/hostname`, read as the Linux call sites always read it; the OS host name elsewhere
/// (`platform::sysinfo::hostname`: `gethostname` / `GetComputerNameExW`).
pub fn etc_hostname() -> io::Result<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/etc/hostname")
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(seagent_core::platform::sysinfo::hostname())
    }
}

// ───────────────────────── terminal ─────────────────────────

/// The controlling terminal, for reading (and on Unix writing): `/dev/tty`, `CONIN$`.
pub const TTY_IN: &str = if cfg!(windows) { "CONIN$" } else { "/dev/tty" };
/// The controlling terminal, for writing: `/dev/tty`, `CONOUT$`.
pub const TTY_OUT: &str = if cfg!(windows) { "CONOUT$" } else { "/dev/tty" };

/// Echo off on a terminal until dropped (a secret being typed). `newline`: still echo the
/// final Enter (`ECHONL`; Windows writes the newline to stderr on drop instead).
pub struct EchoOff {
    #[cfg(unix)]
    fd: i32,
    #[cfg(unix)]
    old: libc::termios,
    #[cfg(windows)]
    handle: isize,
    #[cfg(windows)]
    old: u32,
    #[cfg(windows)]
    newline: bool,
}

impl EchoOff {
    /// On the terminal `f` (opened from [`TTY_IN`]); `None` when it is not a terminal.
    pub fn file(f: &std::fs::File, newline: bool) -> Option<EchoOff> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            Self::fd(f.as_raw_fd(), newline)
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            Self::handle(f.as_raw_handle() as isize, newline)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (f, newline);
            None
        }
    }

    /// On stdin; `None` when stdin is not a terminal.
    pub fn stdin(newline: bool) -> Option<EchoOff> {
        #[cfg(unix)]
        {
            Self::fd(0, newline)
        }
        #[cfg(windows)]
        // SAFETY: GetStdHandle has no preconditions.
        unsafe {
            Self::handle(windows_sys::Win32::System::Console::GetStdHandle(windows_sys::Win32::System::Console::STD_INPUT_HANDLE), newline)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = newline;
            None
        }
    }

    #[cfg(unix)]
    fn fd(fd: i32, newline: bool) -> Option<EchoOff> {
        let mut old: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut old) } != 0 {
            return None;
        }
        let mut quiet = old;
        quiet.c_lflag &= !libc::ECHO;
        if newline {
            quiet.c_lflag |= libc::ECHONL;
        }
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) };
        Some(EchoOff { fd, old })
    }

    #[cfg(windows)]
    fn handle(handle: isize, newline: bool) -> Option<EchoOff> {
        use windows_sys::Win32::System::Console::{GetConsoleMode, SetConsoleMode, ENABLE_ECHO_INPUT};
        let mut old = 0u32;
        // SAFETY: console mode calls on a handle the caller owns.
        unsafe {
            if GetConsoleMode(handle, &mut old) == 0 {
                return None;
            }
            SetConsoleMode(handle, old & !ENABLE_ECHO_INPUT);
        }
        Some(EchoOff { handle, old, newline })
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.old);
        }
        #[cfg(windows)]
        {
            // SAFETY: restores the mode captured in `handle`.
            unsafe { windows_sys::Win32::System::Console::SetConsoleMode(self.handle, self.old) };
            if self.newline {
                eprintln!();
            }
        }
    }
}

// ───────────────────────── desktop ─────────────────────────

/// Open `url` in the default browser, output discarded. Linux and other Unixes: `xdg-open`;
/// macOS: `open`; Windows: the URL protocol handler (`rundll32 url.dll,FileProtocolHandler`,
/// which unlike `cmd /C start` does not reinterpret `&` in the URL).
pub fn open_url(url: &str) -> bool {
    let mut c = if cfg!(target_os = "macos") {
        Command::new("open")
    } else if cfg!(windows) {
        let mut c = Command::new("rundll32.exe");
        c.arg("url.dll,FileProtocolHandler");
        c
    } else {
        Command::new("xdg-open")
    };
    c.arg(url).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().is_ok()
}

/// Windows browsers that take `--app=URL` (a chromeless app window), most likely first.
#[cfg(any(windows, test))]
fn windows_app_browsers(env: &dyn Fn(&str) -> Option<String>) -> Vec<std::path::PathBuf> {
    let mut v = vec![];
    let roots = ["ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"];
    for rel in ["Microsoft\\Edge\\Application\\msedge.exe", "Google\\Chrome\\Application\\chrome.exe", "BraveSoftware\\Brave-Browser\\Application\\brave.exe"] {
        for r in roots {
            if let Some(base) = env(r).filter(|b| !b.is_empty()) {
                v.push(std::path::PathBuf::from(format!("{}\\{rel}", base.trim_end_matches('\\'))));
            }
        }
    }
    v
}

/// Open `url` as an app window (`--app=`) of a Chromium browser when one is installed, else
/// in the default browser. The Linux list stays at the call site (`seagent app open`).
#[cfg_attr(not(any(windows, target_os = "macos")), allow(dead_code))]
pub fn open_app_window(url: &str) -> bool {
    let quiet = |c: &mut Command| {
        c.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    };
    #[cfg(windows)]
    {
        let env = |k: &str| std::env::var(k).ok();
        let on_path = ["msedge", "chrome"].iter().filter_map(|b| seagent_core::platform::layout::which(b));
        for exe in windows_app_browsers(&env).into_iter().filter(|p| p.is_file()).chain(on_path) {
            let mut c = Command::new(exe);
            c.arg(format!("--app={url}"));
            quiet(&mut c);
            if c.spawn().is_ok() {
                return true;
            }
        }
    }
    #[cfg(target_os = "macos")]
    for app in ["Google Chrome", "Microsoft Edge", "Brave Browser", "Chromium"] {
        // `open -a` fails fast (status 1) when the application is not installed.
        let mut c = Command::new("open");
        c.args(["-na", app, "--args", &format!("--app={url}")]);
        quiet(&mut c);
        if c.status().is_ok_and(|s| s.success()) {
            return true;
        }
    }
    let _ = quiet;
    open_url(url)
}

// ───────────────────────── network ─────────────────────────

/// Unicast addresses of this host's interfaces (`GetAdaptersAddresses`); Unix callers walk
/// `getifaddrs` themselves.
#[cfg(windows)]
pub fn local_ips() -> Vec<std::net::IpAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH};
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6};
    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    let mut size: u32 = 16 * 1024;
    for _ in 0..4 {
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let head = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        // SAFETY: `buf` is `size` bytes, 8-aligned; the list is only read while `buf` lives.
        let rc = unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, std::ptr::null(), head, &mut size) };
        if rc == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if rc != 0 {
            return vec![];
        }
        let mut out = vec![];
        // SAFETY: walking the linked lists GetAdaptersAddresses built inside `buf`.
        unsafe {
            let mut a = head;
            while !a.is_null() {
                let mut u = (*a).FirstUnicastAddress;
                while !u.is_null() {
                    let sa = (*u).Address.lpSockaddr;
                    if !sa.is_null() {
                        if (*sa).sa_family == AF_INET {
                            let s = &*(sa as *const SOCKADDR_IN);
                            out.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(s.sin_addr.S_un.S_addr))));
                        } else if (*sa).sa_family == AF_INET6 {
                            let s = &*(sa as *const SOCKADDR_IN6);
                            out.push(IpAddr::V6(Ipv6Addr::from(s.sin6_addr.u.Byte)));
                        }
                    }
                    u = (*u).Next;
                }
                a = (*a).Next;
            }
        }
        return out;
    }
    vec![]
}

/// `doctor`: first line of `<bin> --version`.
#[cfg(not(windows))]
pub fn tool_version(bin: &str) -> Result<String, String> {
    std::process::Command::new(bin).arg("--version").output().map(|o| String::from_utf8_lossy(&o.stdout).lines().next().unwrap_or("").to_string()).map_err(|e| e.to_string())
}

/// `doctor`: first line of `<bin> --version`. On Windows the `WindowsApps\python3.exe` Store alias
/// runs, prints nothing useful and exits 9009, so only a successful `--version` counts as installed.
#[cfg(windows)]
pub fn tool_version(bin: &str) -> Result<String, String> {
    match std::process::Command::new(bin).arg("--version").output() {
        Ok(o) if o.status.success() && !(o.stdout.is_empty() && o.stderr.is_empty()) => Ok(String::from_utf8_lossy(if o.stdout.is_empty() { &o.stderr } else { &o.stdout }).lines().next().unwrap_or("").trim().to_string()),
        Ok(o) => Err(format!("not usable (`{bin} --version` exited {})", o.status.code().unwrap_or(-1))),
        Err(e) => Err(e.to_string()),
    }
}

/// `doctor`'s bash check.
#[cfg(not(windows))]
pub fn doctor_bash() -> Result<String, String> {
    tool_version("bash")
}

/// `doctor`'s bash check. `bash` on PATH is usually System32\bash.exe (the WSL launcher): only the
/// bash the shell detection picked (Git Bash / MSYS2 / SEAGENT_SHELL) counts.
#[cfg(windows)]
pub fn doctor_bash() -> Result<String, String> {
    match seagent_core::platform::layout::bash() {
        Some(p) => tool_version(&p.to_string_lossy()),
        None => Err("not found (Git for Windows / MSYS2; System32\\bash.exe is the WSL launcher and does not count): bash scripts and lang=bash are unavailable, tool calls use PowerShell".into()),
    }
}

/// `doctor`'s python3 (code mode) check.
#[cfg(not(windows))]
pub fn doctor_python3() -> Result<String, String> {
    tool_version("python3")
}

/// `doctor`'s python3 (code mode) check: `py -3` or a real python (never the WindowsApps Store
/// alias), as code mode runs it.
#[cfg(windows)]
pub fn doctor_python3() -> Result<String, String> {
    let Some((p, args)) = seagent_core::platform::layout::python3() else {
        return Err("not found (py -3 / python3 / python; the WindowsApps Store alias does not count)".into());
    };
    let shown = std::iter::once(p.display().to_string()).chain(args.iter().cloned()).collect::<Vec<_>>().join(" ");
    match std::process::Command::new(&p).args(&args).arg("--version").output() {
        Ok(o) if o.status.success() && !(o.stdout.is_empty() && o.stderr.is_empty()) => Ok(format!("{} ({shown})", String::from_utf8_lossy(if o.stdout.is_empty() { &o.stderr } else { &o.stdout }).trim())),
        Ok(o) => Err(format!("{shown} is not usable (--version exited {})", o.status.code().unwrap_or(-1))),
        Err(e) => Err(format!("{shown}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_and_writability() {
        let d = seagent_core::tmp::TempDir::new("seagent-hostos");
        let f = d.path().join("secret");
        create_private(&f, b"x").unwrap();
        assert!(create_private(&f, b"y").is_err(), "create_private never overwrites");
        assert_eq!(mode_of(&f).unwrap() & 0o077, 0);
        set_mode(&f, 0o644).unwrap();
        #[cfg(unix)]
        assert_eq!(mode_of(&f).unwrap() & 0o777, 0o644);
        assert!(writable(d.path()));
        assert!(!pid_alive(0) && !pid_alive(-1));
        assert!(pid_alive(std::process::id() as i64));
        assert!(!daemon_reachable(&d.path().join("no-such.sock")));
    }

    #[test]
    fn windows_browser_candidates_cover_edge_and_chrome() {
        let env = |k: &str| match k {
            "ProgramFiles" => Some("C:\\Program Files".to_string()),
            "LOCALAPPDATA" => Some("C:\\Users\\a\\AppData\\Local\\".to_string()),
            _ => None,
        };
        let v: Vec<String> = windows_app_browsers(&env).iter().map(|p| p.display().to_string()).collect();
        assert_eq!(v[0], "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe");
        assert!(v.contains(&"C:\\Users\\a\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe".to_string()), "{v:?}");
    }
}
