//! Terminals: raw mode for the TUIs, the window size, waiting for a key, and pseudo-terminals
//! for the exec backends.
//!
//! * **Unix** — termios exactly as `seagent-app`'s TUI does it (`cfmakeraw`, `VMIN = 0`,
//!   `VTIME = 1`: reads return after 100 ms with nothing), `TIOCGWINSZ` on stdout, and the
//!   `posix_openpt` sequence of `seagent-tools`' local backend.
//! * **Windows** — console modes: input loses line editing / echo / Ctrl-C processing and gains
//!   `ENABLE_VIRTUAL_TERMINAL_INPUT` (keys arrive as the same escape sequences as on Unix);
//!   output gains `ENABLE_VIRTUAL_TERMINAL_PROCESSING` and `DISABLE_NEWLINE_AUTO_RETURN` (the
//!   `OPOST`-off half of `cfmakeraw`). Console reads have no `VTIME`, so poll with
//!   [`wait_stdin`] before reading. PTYs are ConPTY ([`ConPty`]).
//!
//! The escape sequences a TUI writes (alternate screen, cursor, bracketed paste) stay with the
//! TUI: this module never writes to the terminal.

use std::io;
use std::time::Duration;

/// Raw mode on stdin until dropped (or [`RawMode::suspend`]ed for `$EDITOR`).
pub struct RawMode {
    #[cfg(unix)]
    orig: libc::termios,
    #[cfg(unix)]
    raw: libc::termios,
    #[cfg(windows)]
    modes: Vec<(isize, u32, u32)>,
}

impl RawMode {
    /// Enter raw mode. Fails when stdin is not a terminal / console.
    #[cfg(unix)]
    pub fn enter() -> io::Result<RawMode> {
        // SAFETY: plain termios calls on stdin.
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut t) != 0 {
                return Err(io::Error::last_os_error());
            }
            let orig = t;
            libc::cfmakeraw(&mut t);
            t.c_cc[libc::VMIN] = 0;
            t.c_cc[libc::VTIME] = 1;
            libc::tcsetattr(0, libc::TCSANOW, &t);
            Ok(RawMode { orig, raw: t })
        }
    }

    /// Enter raw mode. Fails when stdin is not a console.
    #[cfg(windows)]
    pub fn enter() -> io::Result<RawMode> {
        use windows_sys::Win32::System::Console::*;
        // SAFETY: plain console calls on the std handles.
        unsafe {
            let hin = GetStdHandle(STD_INPUT_HANDLE);
            let mut in0 = 0u32;
            if GetConsoleMode(hin, &mut in0) == 0 {
                return Err(io::Error::last_os_error());
            }
            let in_raw = (in0 & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT)) | ENABLE_VIRTUAL_TERMINAL_INPUT;
            let mut modes = vec![(hin, in0, in_raw)];
            let hout = GetStdHandle(STD_OUTPUT_HANDLE);
            let mut out0 = 0u32;
            if GetConsoleMode(hout, &mut out0) != 0 {
                modes.push((hout, out0, out0 | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN));
            }
            let r = RawMode { modes };
            r.resume();
            Ok(r)
        }
    }

    #[cfg(not(any(unix, windows)))]
    pub fn enter() -> io::Result<RawMode> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "no terminal on this target"))
    }

    /// Hand the terminal back (cooked mode) — e.g. while `$EDITOR` runs.
    pub fn suspend(&self) {
        #[cfg(unix)]
        // SAFETY: restore the saved terminal state.
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &self.orig);
        }
        #[cfg(windows)]
        for &(h, orig, _) in &self.modes {
            // SAFETY: handle and mode captured in `enter`.
            unsafe { windows_sys::Win32::System::Console::SetConsoleMode(h, orig) };
        }
    }

    /// Re-apply raw mode after [`RawMode::suspend`].
    pub fn resume(&self) {
        #[cfg(unix)]
        // SAFETY: re-apply the raw termios captured in `enter`.
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &self.raw);
        }
        #[cfg(windows)]
        for &(h, _, raw) in &self.modes {
            // SAFETY: handle captured in `enter`.
            unsafe { windows_sys::Win32::System::Console::SetConsoleMode(h, raw) };
        }
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        self.suspend();
    }
}

/// `(columns, rows)` of the terminal on stdout; `None` when it is not one.
pub fn window_size() -> Option<(u16, u16)> {
    #[cfg(unix)]
    // SAFETY: TIOCGWINSZ fills a winsize struct.
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(1, libc::TIOCGWINSZ as _, &mut ws) == 0 && ws.ws_col > 0 {
            return Some((ws.ws_col, ws.ws_row));
        }
        None
    }
    #[cfg(windows)]
    // SAFETY: zeroed POD out-parameter.
    unsafe {
        use windows_sys::Win32::System::Console::*;
        let mut i: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
        if GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &mut i) == 0 {
            return None;
        }
        let cols = (i.srWindow.Right - i.srWindow.Left + 1).max(0) as u16;
        let rows = (i.srWindow.Bottom - i.srWindow.Top + 1).max(0) as u16;
        (cols > 0).then_some((cols, rows))
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

/// Wait up to `timeout` for input on stdin; true when a read will find something.
/// (Windows: any console input event counts, including focus / mouse events.)
pub fn wait_stdin(timeout: Duration) -> bool {
    let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    #[cfg(unix)]
    {
        let mut p = libc::pollfd { fd: 0, events: libc::POLLIN, revents: 0 };
        // SAFETY: one valid pollfd.
        unsafe { libc::poll(&mut p, 1, ms) > 0 }
    }
    #[cfg(windows)]
    // SAFETY: plain wait on the stdin handle.
    unsafe {
        use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE};
        windows_sys::Win32::System::Threading::WaitForSingleObject(GetStdHandle(STD_INPUT_HANDLE), ms as u32) == windows_sys::Win32::Foundation::WAIT_OBJECT_0
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = ms;
        false
    }
}

/// Let stdout interpret ANSI escapes (colours, cursor movement). Unix terminals always do;
/// Windows consoles need `ENABLE_VIRTUAL_TERMINAL_PROCESSING`. False when stdout is no console.
pub fn enable_ansi() -> bool {
    #[cfg(windows)]
    // SAFETY: plain console calls on stdout.
    unsafe {
        use windows_sys::Win32::System::Console::*;
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut m = 0u32;
        GetConsoleMode(h, &mut m) != 0 && SetConsoleMode(h, m | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
    #[cfg(not(windows))]
    {
        use std::io::IsTerminal;
        std::io::stdout().is_terminal()
    }
}

// ───────────────────────── Unix PTY ─────────────────────────

/// A pseudo-terminal pair `(master, slave)` of `rows` × `cols`, both close-on-exec.
#[cfg(unix)]
pub fn open_pty(rows: u16, cols: u16) -> io::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    use std::os::fd::{FromRawFd, OwnedFd};
    fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
        if r < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(r)
        }
    }
    // SAFETY: standard posix_openpt sequence; fds are checked and owned.
    unsafe {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let m = cvt(libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC))?;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let m = cvt(libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY))?;
        let master = OwnedFd::from_raw_fd(m);
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        cvt(libc::fcntl(m, libc::F_SETFD, libc::FD_CLOEXEC))?;
        cvt(libc::grantpt(m))?;
        cvt(libc::unlockpt(m))?;
        let name = pts_name(m)?;
        let s = cvt(libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC))?;
        let slave = OwnedFd::from_raw_fd(s);
        let ws = libc::winsize { ws_row: rows.max(1), ws_col: cols.max(1), ws_xpixel: 0, ws_ypixel: 0 };
        libc::ioctl(m, libc::TIOCSWINSZ as _, &ws);
        Ok((master, slave))
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn pts_name(m: libc::c_int) -> io::Result<std::ffi::CString> {
    let mut name = [0 as libc::c_char; 128];
    // SAFETY: `name` has room for 128 bytes, NUL included.
    if unsafe { libc::ptsname_r(m, name.as_mut_ptr(), name.len()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: ptsname_r wrote a NUL-terminated string.
    Ok(unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }.to_owned())
}

/// `ptsname` is not reentrant here (no `ptsname_r` in every libc): serialise it.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn pts_name(m: libc::c_int) -> io::Result<std::ffi::CString> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: the returned static buffer is copied before the lock is released.
    unsafe {
        let p = libc::ptsname(m);
        if p.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(std::ffi::CStr::from_ptr(p).to_owned())
    }
}

/// Resize the PTY whose master is `fd`.
#[cfg(unix)]
pub fn set_pty_size(fd: std::os::fd::BorrowedFd<'_>, rows: u16, cols: u16) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let ws = libc::winsize { ws_row: rows.max(1), ws_col: cols.max(1), ws_xpixel: 0, ws_ypixel: 0 };
    // SAFETY: TIOCSWINSZ with a valid winsize on an open fd.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ as _, &ws) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ───────────────────────── Windows ConPTY ─────────────────────────

/// One argument quoted for a Windows command line (the `CommandLineToArgvW` / MSVCRT rules).
pub fn windows_quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\x0b', '"']) {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

/// `program` and `args` joined into one Windows command line.
/// An MSYS2 program (Git Bash, its coreutils) globs and brace-expands unquoted arguments, so
/// its arguments are always [`super::layout::msys_quote`]d.
pub fn windows_command_line(program: &str, args: &[&str]) -> String {
    if super::layout::is_msys_program(std::path::Path::new(program)) {
        return std::iter::once(windows_quote(program)).chain(args.iter().map(|a| super::layout::msys_quote(a))).collect::<Vec<_>>().join(" ");
    }
    std::iter::once(program).chain(args.iter().copied()).map(windows_quote).collect::<Vec<_>>().join(" ")
}

/// A ConPTY pseudo console: write keystrokes to [`ConPty::input`], read the rendered VT
/// stream from [`ConPty::output`]. Drop it after the child exited, or the output read never
/// sees end-of-file.
#[cfg(windows)]
pub struct ConPty {
    hpc: windows_sys::Win32::System::Console::HPCON,
    input: std::fs::File,
    output: std::fs::File,
}

/// A process attached to a [`ConPty`]; also registered as a kill-on-close job, so
/// `platform::proc::kill_group(child.id())` stops its whole tree.
#[cfg(windows)]
pub struct PtyChild {
    process: std::os::windows::io::OwnedHandle,
    pid: u32,
}

#[cfg(windows)]
impl ConPty {
    /// A pseudo console of `rows` × `cols`.
    pub fn open(rows: u16, cols: u16) -> io::Result<ConPty> {
        use std::os::windows::io::{FromRawHandle, RawHandle};
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Console::{CreatePseudoConsole, COORD};
        use windows_sys::Win32::System::Pipes::CreatePipe;
        // SAFETY: pipe handles are created, handed to ConPTY (which duplicates its ends) and
        // the ends we keep become owned Files.
        unsafe {
            let (mut in_r, mut in_w, mut out_r, mut out_w) = (0, 0, 0, 0);
            if CreatePipe(&mut in_r, &mut in_w, std::ptr::null(), 0) == 0 {
                return Err(io::Error::last_os_error());
            }
            if CreatePipe(&mut out_r, &mut out_w, std::ptr::null(), 0) == 0 {
                let e = io::Error::last_os_error();
                CloseHandle(in_r);
                CloseHandle(in_w);
                return Err(e);
            }
            let mut hpc = 0;
            let size = COORD { X: cols.max(1) as i16, Y: rows.max(1) as i16 };
            let hr = CreatePseudoConsole(size, in_r, out_w, 0, &mut hpc);
            CloseHandle(in_r);
            CloseHandle(out_w);
            let input = std::fs::File::from_raw_handle(in_w as RawHandle);
            let output = std::fs::File::from_raw_handle(out_r as RawHandle);
            if hr != 0 {
                return Err(io::Error::other(format!("CreatePseudoConsole failed (HRESULT {hr:#x})")));
            }
            Ok(ConPty { hpc, input, output })
        }
    }

    pub fn resize(&self, rows: u16, cols: u16) -> io::Result<()> {
        use windows_sys::Win32::System::Console::{ResizePseudoConsole, COORD};
        // SAFETY: live pseudo console handle.
        let hr = unsafe { ResizePseudoConsole(self.hpc, COORD { X: cols.max(1) as i16, Y: rows.max(1) as i16 }) };
        if hr != 0 {
            return Err(io::Error::other(format!("ResizePseudoConsole failed (HRESULT {hr:#x})")));
        }
        Ok(())
    }

    /// Writer for the child's keyboard input.
    pub fn input(&self) -> io::Result<std::fs::File> {
        self.input.try_clone()
    }

    /// Reader for the child's terminal output.
    pub fn output(&self) -> io::Result<std::fs::File> {
        self.output.try_clone()
    }

    /// Start `command_line` (see [`windows_command_line`]) on this console. `env`: the full
    /// environment (`None` inherits ours). The child is put in a kill-on-close job.
    pub fn spawn(&self, command_line: &str, cwd: Option<&std::path::Path>, env: Option<&[(std::ffi::OsString, std::ffi::OsString)]>) -> io::Result<PtyChild> {
        use super::fs_private::win::wide;
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::{FromRawHandle, OwnedHandle, RawHandle};
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::*;
        // SAFETY: the attribute list lives in `attr` until DeleteProcThreadAttributeList; all
        // strings are NUL-terminated and outlive CreateProcessW.
        unsafe {
            let mut size = 0usize;
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size);
            let mut attr = vec![0u64; size.div_ceil(8).max(1)];
            let list = attr.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
            if InitializeProcThreadAttributeList(list, 1, 0, &mut size) == 0 {
                return Err(io::Error::last_os_error());
            }
            if UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize, self.hpc as *const std::ffi::c_void, std::mem::size_of_val(&self.hpc), std::ptr::null_mut(), std::ptr::null()) == 0 {
                let e = io::Error::last_os_error();
                DeleteProcThreadAttributeList(list);
                return Err(e);
            }
            let mut si: STARTUPINFOEXW = std::mem::zeroed();
            si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
            // No std handles: the console is the pseudo console, never our redirected pipes.
            si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            si.lpAttributeList = list;
            let mut cmd = wide(command_line);
            let cwd_w = cwd.map(|c| wide(c.as_os_str()));
            let env_w: Option<Vec<u16>> = env.map(|vars| {
                let mut b: Vec<u16> = vec![];
                for (k, v) in vars {
                    b.extend(k.encode_wide());
                    b.push('=' as u16);
                    b.extend(v.encode_wide());
                    b.push(0);
                }
                b.push(0);
                b
            });
            let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
            let ok = CreateProcessW(
                std::ptr::null(),
                cmd.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                env_w.as_ref().map_or(std::ptr::null(), |e| e.as_ptr().cast()),
                cwd_w.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
                &si.StartupInfo,
                &mut pi,
            );
            let e = io::Error::last_os_error();
            DeleteProcThreadAttributeList(list);
            if ok == 0 {
                return Err(e);
            }
            CloseHandle(pi.hThread);
            let child = PtyChild { process: OwnedHandle::from_raw_handle(pi.hProcess as RawHandle), pid: pi.dwProcessId };
            if let Err(e) = super::proc::win::adopt_handle(pi.hProcess, pi.dwProcessId) {
                let _ = child.kill();
                return Err(io::Error::other(format!("cannot put pid {} in a job object: {e}", child.pid)));
            }
            Ok(child)
        }
    }
}

#[cfg(windows)]
impl Drop for ConPty {
    fn drop(&mut self) {
        // SAFETY: we own the pseudo console handle.
        unsafe { windows_sys::Win32::System::Console::ClosePseudoConsole(self.hpc) };
    }
}

#[cfg(windows)]
impl PtyChild {
    pub fn id(&self) -> u32 {
        self.pid
    }

    fn wait_ms(&self, ms: u32) -> io::Result<Option<u32>> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
        let h = self.process.as_raw_handle() as isize;
        // SAFETY: owned process handle.
        unsafe {
            if WaitForSingleObject(h, ms) != WAIT_OBJECT_0 {
                return Ok(None);
            }
            let mut code = 0u32;
            if GetExitCodeProcess(h, &mut code) == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Some(code))
        }
    }

    /// The exit code once the child has exited.
    pub fn try_wait(&self) -> io::Result<Option<u32>> {
        self.wait_ms(0)
    }

    /// Block until the child exits; its exit code.
    pub fn wait(&self) -> io::Result<u32> {
        loop {
            if let Some(c) = self.wait_ms(windows_sys::Win32::System::Threading::INFINITE)? {
                return Ok(c);
            }
        }
    }

    /// Terminate the child process itself (use `proc::kill_group(id)` for its whole tree).
    pub fn kill(&self) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        // SAFETY: owned process handle with full access.
        if unsafe { windows_sys::Win32::System::Threading::TerminateProcess(self.process.as_raw_handle() as isize, 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_command_line_quoting() {
        assert_eq!(windows_quote("plain"), "plain");
        assert_eq!(windows_quote(""), "\"\"");
        assert_eq!(windows_quote("a b"), "\"a b\"");
        assert_eq!(windows_quote("say \"hi\""), "\"say \\\"hi\\\"\"");
        assert_eq!(windows_quote("C:\\dir with space\\"), "\"C:\\dir with space\\\\\"");
        assert_eq!(windows_quote("C:\\no\\space"), "C:\\no\\space");
        // An installed Git Bash is an MSYS2 program: every argument is quoted (no globbing).
        let bash = "C:\\Program Files\\Git\\bin\\bash.exe";
        let c = if super::super::layout::is_msys_program(std::path::Path::new(bash)) { "\"-c\"" } else { "-c" };
        assert_eq!(windows_command_line(bash, &["-c", "echo hi"]), format!("\"{bash}\" {c} \"echo hi\""));
        // A native program keeps the plain MSVCRT rules.
        assert_eq!(windows_command_line("C:\\Windows\\System32\\cmd.exe", &["/c", "a*"]), "C:\\Windows\\System32\\cmd.exe /c a*");
    }

    #[cfg(unix)]
    #[test]
    fn pty_pair_with_size() {
        use std::io::{Read, Write};
        use std::os::fd::AsFd;
        let (m, s) = open_pty(24, 80).unwrap();
        set_pty_size(m.as_fd(), 30, 100).unwrap();
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::ioctl(std::os::fd::AsRawFd::as_raw_fd(&s), libc::TIOCGWINSZ as _, &mut ws) }, 0);
        assert_eq!((ws.ws_row, ws.ws_col), (30, 100));
        let mut slave = std::fs::File::from(s);
        let mut master = std::fs::File::from(m);
        slave.write_all(b"ping\n").unwrap();
        let mut buf = [0u8; 16];
        let n = master.read(&mut buf).unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("ping"));
    }

    #[cfg(unix)]
    #[test]
    fn no_terminal_in_tests_is_handled() {
        // Under `cargo test` stdin is usually not a tty: enter() must fail cleanly, not panic.
        use std::io::IsTerminal;
        if !std::io::stdin().is_terminal() {
            assert!(RawMode::enter().is_err());
        }
        let _ = window_size();
        let _ = wait_stdin(Duration::from_millis(1));
    }
}
