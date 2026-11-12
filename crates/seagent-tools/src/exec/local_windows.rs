//! The Windows half of the local backend (`exec::local`), the substitutes of
//! docs/cross-platform.md for what `local_unix` does with Unix primitives:
//!
//! * **output** — one anonymous pipe for stdout + stderr (as on Unix), drained by a reader
//!   thread into a bounded channel: Windows pipes have no `poll`, and the channel's
//!   `recv_timeout` gives `ExecChild::read` the same "wait at most `timeout`" contract. The
//!   bound keeps the old back-pressure: a child that writes faster than seagent reads blocks.
//! * **terminal** — ConPTY (`seagent_core::platform::term::ConPty`). The pseudo console is
//!   closed as soon as the child exits so the output stream reaches end-of-file.
//! * **process group** — a kill-on-close Job Object per command
//!   (`seagent_core::platform::proc`): the tree dies with seagent however seagent ends (the
//!   PDEATHSIG substitute), and `kill` terminates the whole job. A soft kill sends
//!   `CTRL_BREAK` to the command's console process group (`^C` through a terminal); where
//!   that cannot be delivered the job is terminated.
//! * **detached** — a PowerShell wrapper (always present as `powershell.exe`) starts the
//!   command, waits, and publishes the exit code to the exit file (`.tmp` + move), the same
//!   protocol as the Unix `/bin/sh` wrapper. The command line travels in environment
//!   variables, pre-quoted by the `CommandLineToArgvW` rules, so no shell re-parses it. The
//!   wrapper leaves seagent's job (`CREATE_BREAKAWAY_FROM_JOB` when allowed) to survive a
//!   restart; stopping it later uses `taskkill /T /F`, which follows the process tree.
//!
//! Exit codes are reported as codes; a command seagent force-killed reports `signal 9`, the
//! same shape the Unix backend gives, so callers keep one meaning for "killed".

use super::local::{exit_file_status, proc_start_time, register_child, PreExec};
use seagent_core::exec::{ExecChild, ExecRequest, ExitInfo};
use seagent_core::platform::term::{windows_command_line, windows_quote, ConPty, PtyChild};
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;
use windows_sys::Win32::System::Threading::{CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW};

// ───────────── building blocks (shared with the AppContainer backend) ─────────────

/// Output drained by a reader thread; `read` waits on the channel with a timeout.
pub(super) struct Output {
    rx: mpsc::Receiver<Vec<u8>>,
    pending: Vec<u8>,
    at: usize,
    eof: bool,
}

impl Output {
    /// Start a thread that reads `r` to end-of-file (a broken pipe is end-of-file too).
    pub(super) fn spawn(mut r: impl Read + Send + 'static) -> io::Result<Output> {
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(16);
        std::thread::Builder::new().name("seagent-exec-out".into()).spawn(move || {
            let mut buf = vec![0u8; 16384];
            loop {
                match r.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
        })?;
        Ok(Output { rx, pending: vec![], at: 0, eof: false })
    }

    fn read(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        if self.at >= self.pending.len() {
            if self.eof {
                return Ok(0);
            }
            match self.rx.recv_timeout(timeout) {
                Ok(v) => {
                    self.pending = v;
                    self.at = 0;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => return Err(io::ErrorKind::TimedOut.into()),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    self.eof = true;
                    return Ok(0);
                }
            }
        }
        let n = buf.len().min(self.pending.len() - self.at);
        buf[..n].copy_from_slice(&self.pending[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

/// A started Windows process: std `Child` (pipes), ConPTY child, or the AppContainer
/// backend's own `CreateProcessW` child.
pub(super) trait WinProc: Send {
    fn pid(&self) -> u32;
    /// The exit code once the process has exited.
    fn exit_code(&mut self) -> io::Result<Option<i32>>;
    /// Terminate the whole tree at once (its job).
    fn terminate(&mut self);
}

impl WinProc for Child {
    fn pid(&self) -> u32 {
        self.id()
    }
    fn exit_code(&mut self) -> io::Result<Option<i32>> {
        Ok(Child::try_wait(self)?.map(|s| s.code().unwrap_or(1)))
    }
    fn terminate(&mut self) {
        seagent_core::platform::proc::kill_group(self.id() as i32, Duration::ZERO);
        let _ = Child::kill(self);
    }
}

impl WinProc for PtyChild {
    fn pid(&self) -> u32 {
        self.id()
    }
    fn exit_code(&mut self) -> io::Result<Option<i32>> {
        Ok(PtyChild::try_wait(self)?.map(|c| c as i32))
    }
    fn terminate(&mut self) {
        seagent_core::platform::proc::kill_group(self.id() as i32, Duration::ZERO);
        let _ = PtyChild::kill(self);
    }
}

/// A pseudo console kept open while its child runs; dropping it closes the console.
pub(super) trait Console: Send {
    fn resize(&self, rows: u16, cols: u16) -> io::Result<()>;
}

impl Console for ConPty {
    fn resize(&self, rows: u16, cols: u16) -> io::Result<()> {
        ConPty::resize(self, rows, cols)
    }
}

/// Creation flags of an attached command: its own console process group (so `CTRL_BREAK`
/// reaches it and not us), and no console window when seagent itself has none (a service
/// or the desktop shell) — otherwise every command would flash a window.
pub(super) fn creation_flags() -> u32 {
    // SAFETY: plain query of this process's console window.
    let has_console = unsafe { windows_sys::Win32::System::Console::GetConsoleWindow() } != 0;
    CREATE_NEW_PROCESS_GROUP | if has_console { 0 } else { CREATE_NO_WINDOW }
}

/// The full environment `cmd` would give its child (ours, then its changes), for the
/// `CreateProcessW` paths that cannot use `Command` itself. Windows names are
/// case-insensitive: one entry per name, sorted the way `CreateProcessW` expects.
pub(super) fn full_env(cmd: &Command) -> Vec<(OsString, OsString)> {
    let mut m: std::collections::BTreeMap<String, (OsString, OsString)> = std::env::vars_os().map(|(k, v)| (k.to_string_lossy().to_uppercase(), (k, v))).collect();
    for (k, v) in cmd.get_envs() {
        let key = k.to_string_lossy().to_uppercase();
        match v {
            Some(v) => m.insert(key, (k.to_os_string(), v.to_os_string())),
            None => m.remove(&key),
        };
    }
    m.into_values().collect()
}

/// `cmd`'s program and arguments as one Windows command line.
pub(super) fn command_line(cmd: &Command) -> String {
    let prog = cmd.get_program().to_string_lossy().into_owned();
    let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
    windows_command_line(&prog, &args.iter().map(String::as_str).collect::<Vec<_>>())
}

/// `cmd` unchanged, or — for an MSYS2 program (Git Bash), which globs and brace-expands
/// unquoted arguments — the same command with every argument `msys_quote`d.
fn msys_requoted(cmd: Command) -> Command {
    use seagent_core::platform::layout::{is_msys_program, msys_quote};
    if !is_msys_program(Path::new(cmd.get_program())) {
        return cmd;
    }
    let mut c = seagent_core::platform::proc::command(cmd.get_program());
    for a in cmd.get_args() {
        c.raw_arg(msys_quote(&a.to_string_lossy()));
    }
    if let Some(d) = cmd.get_current_dir() {
        c.current_dir(d);
    }
    c.env_clear().envs(full_env(&cmd));
    c
}

/// Is the active shell a POSIX one (EOF on a terminal is `^D`; PowerShell wants `^Z`)?
fn posix_shell() -> bool {
    seagent_core::platform::shell::active().kind.is_posix()
}

fn refuse_hook(extra: &Option<PreExec>) -> io::Result<()> {
    if extra.is_some() {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "pre-exec hooks (Unix sandboxes) are not available on Windows"));
    }
    Ok(())
}

// ───────────── attached commands ─────────────

/// Merged output pipe or ConPTY, own Job Object, dies with seagent.
pub(super) fn spawn_attached(mut cmd: Command, req: &ExecRequest, extra: Option<PreExec>) -> io::Result<Box<dyn ExecChild>> {
    refuse_hook(&extra)?;
    if let Some((rows, cols)) = req.pty {
        let console = ConPty::open(rows, cols)?;
        let cwd = cmd.get_current_dir().map(Path::to_path_buf);
        let env = full_env(&cmd);
        let child = console.spawn(&command_line(&cmd), cwd.as_deref(), Some(&env))?;
        register_child(child.id(), "");
        let out = Output::spawn(console.output()?)?;
        let input: Box<dyn Write + Send> = Box::new(console.input()?);
        let mut c = LocalChild::from_parts(Box::new(child), Some(out), Some(input), Some(Box::new(console)));
        c.feed(req)?;
        return Ok(Box::new(c));
    }
    cmd = msys_requoted(cmd);
    let (r, w) = std::io::pipe()?;
    cmd.stdout(Stdio::from(w.try_clone()?)).stderr(Stdio::from(w));
    cmd.stdin(if req.stdin || req.stdin_data.is_some() { Stdio::piped() } else { Stdio::null() });
    cmd.creation_flags(creation_flags());
    let mut child = cmd.spawn()?;
    drop(cmd); // closes our copies of the write end: EOF once the command's tree is done
    if let Err(e) = seagent_core::platform::proc::adopt(&child) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::other(format!("cannot put pid {} in a job object: {e}", child.id())));
    }
    register_child(child.id(), "");
    let stdin: Option<Box<dyn Write + Send>> = child.stdin.take().map(|s| Box::new(s) as Box<dyn Write + Send>);
    let mut c = LocalChild::from_parts(Box::new(child), Some(Output::spawn(r)?), stdin, None);
    c.feed(req)?;
    Ok(Box::new(c))
}

// ───────────── detached commands ─────────────

/// The wrapper: start the command line from the environment, wait, publish the exit code.
const DETACH_WRAPPER: &str = "$f=$env:SEAGENT_EXIT_FILE; \
$si=New-Object System.Diagnostics.ProcessStartInfo; \
$si.FileName=$env:SEAGENT_DETACH_PROGRAM; $si.Arguments=$env:SEAGENT_DETACH_ARGS; $si.UseShellExecute=$false; \
Remove-Item Env:SEAGENT_DETACH_PROGRAM,Env:SEAGENT_DETACH_ARGS,Env:SEAGENT_EXIT_FILE; \
$s=127; try { $p=[System.Diagnostics.Process]::Start($si); $p.WaitForExit(); $s=$p.ExitCode } catch { [Console]::Error.WriteLine($_.Exception.Message) }; \
[System.IO.File]::WriteAllText($f+'.tmp',[string]$s); Move-Item -Force -LiteralPath ($f+'.tmp') -Destination $f";

/// Windows PowerShell 5.1 ships with every Windows since 7: the wrapper never depends on the
/// shell the operator picked.
fn windows_powershell() -> PathBuf {
    if let Some(root) = std::env::var_os("SystemRoot") {
        let p = PathBuf::from(root).join("System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        if p.is_file() {
            return p;
        }
    }
    PathBuf::from("powershell.exe")
}

/// Detached: own process group outside seagent's job, output appended to `log_file`, exit
/// status written to `exit_file` by the PowerShell wrapper.
pub(super) fn spawn_detached(cmd: Command, req: &ExecRequest, extra: Option<PreExec>) -> io::Result<Box<dyn ExecChild>> {
    refuse_hook(&extra)?;
    let log = req.log_file.clone().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "detached process needs log_file"))?;
    let exit = req.exit_file.clone().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "detached process needs exit_file"))?;
    let _ = std::fs::remove_file(&exit);
    // Not an append-only handle: Git Bash exits 1 at startup on one (`open_child_log`).
    let out = seagent_core::platform::proc::open_child_log(&log)?;
    let msys = seagent_core::platform::layout::is_msys_program(Path::new(cmd.get_program()));
    let quote = if msys { seagent_core::platform::layout::msys_quote } else { windows_quote };
    let args: Vec<String> = cmd.get_args().map(|a| quote(&a.to_string_lossy())).collect();
    let mut w = seagent_core::platform::proc::command(windows_powershell());
    w.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", DETACH_WRAPPER]);
    if let Some(d) = cmd.get_current_dir() {
        w.current_dir(d);
    }
    for (k, v) in cmd.get_envs() {
        match v {
            Some(v) => w.env(k, v),
            None => w.env_remove(k),
        };
    }
    w.env("SEAGENT_DETACH_PROGRAM", cmd.get_program()).env("SEAGENT_DETACH_ARGS", args.join(" ")).env("SEAGENT_EXIT_FILE", &exit);
    w.stdin(Stdio::null()).stdout(Stdio::from(out.try_clone()?)).stderr(Stdio::from(out));
    // Leave seagent's own job when the job allows it, so a restart does not take it down.
    w.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB);
    let child = match w.spawn() {
        Err(e) if e.raw_os_error() == Some(windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED as i32) => {
            w.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
            w.spawn()?
        }
        r => r?,
    };
    register_child(child.id(), "detached");
    let pid = child.id();
    let mut c = LocalChild::from_parts(Box::new(child), None, None, None);
    c.detached = Some(Detached { pid, log: File::open(&log)?, exit_file: exit, start: proc_start_time(pid) });
    Ok(Box::new(c))
}

pub(super) struct Detached {
    pub pid: u32,
    pub log: File,
    pub exit_file: PathBuf,
    pub start: Option<u64>,
}

/// `taskkill /T /F`: the detached wrapper is in no job of ours, so its tree is found by
/// parent links.
fn kill_tree(pid: u32) {
    let sys = std::env::var_os("SystemRoot").map(|r| PathBuf::from(r).join("System32\\taskkill.exe")).filter(|p| p.is_file()).unwrap_or_else(|| PathBuf::from("taskkill.exe"));
    let _ = seagent_core::platform::proc::command(sys).args(["/T", "/F", "/PID", &pid.to_string()]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).creation_flags(CREATE_NO_WINDOW).status();
}

// ───────────── the child ─────────────

pub struct LocalChild {
    proc: Option<Box<dyn WinProc>>,
    out: Option<Output>,
    input: Option<Box<dyn Write + Send>>,
    console: Option<Box<dyn Console>>,
    pty: bool,
    pub(super) detached: Option<Detached>,
    exit: Option<ExitInfo>,
    force_killed: bool,
}

impl LocalChild {
    pub(super) fn from_parts(proc: Box<dyn WinProc>, out: Option<Output>, input: Option<Box<dyn Write + Send>>, console: Option<Box<dyn Console>>) -> LocalChild {
        let pty = console.is_some();
        LocalChild { proc: Some(proc), out, input, console, pty, detached: None, exit: None, force_killed: false }
    }

    /// Write `req.stdin_data` right after the start (closing stdin unless the caller keeps it).
    pub(super) fn feed(&mut self, req: &ExecRequest) -> io::Result<()> {
        if let Some(d) = &req.stdin_data {
            self.write_stdin(d)?;
            if !req.stdin {
                self.close_stdin();
            }
        }
        Ok(())
    }

    /// Re-attach to a detached process after an seagent restart (no stdin, no wait()).
    pub fn reattach(pid: u32, start: Option<u64>, log: &Path, exit_file: &Path, offset: u64) -> io::Result<LocalChild> {
        let mut f = File::open(log)?;
        f.seek(SeekFrom::Start(offset))?;
        Ok(LocalChild { proc: None, out: None, input: None, console: None, pty: false, detached: Some(Detached { pid, log: f, exit_file: exit_file.to_path_buf(), start }), exit: None, force_killed: false })
    }

    fn pgid(&self) -> u32 {
        self.proc.as_ref().map(|p| p.pid()).or(self.detached.as_ref().map(|d| d.pid)).unwrap_or(0)
    }

    pub fn start_time(&self) -> Option<u64> {
        self.detached.as_ref().and_then(|d| d.start)
    }

    fn finish(&mut self, code: i32) -> ExitInfo {
        if self.force_killed {
            ExitInfo { code: None, signal: Some(9) }
        } else if let Some(sig) = msys_signal(code) {
            ExitInfo { code: None, signal: Some(sig) }
        } else {
            ExitInfo::code(code)
        }
    }
}

/// MSYS / Cygwin bash reports "killed by signal N" to Windows as exit code `N << 8` (a bash
/// `exit` status is always 0–255), so `kill -9 $$` reads as signal 9, as on Unix.
fn msys_signal(code: i32) -> Option<i32> {
    let sig = code >> 8;
    (code & 0xff == 0 && (1..=64).contains(&sig) && seagent_core::platform::shell::active().kind.is_posix()).then_some(sig)
}

impl ExecChild for LocalChild {
    fn pid(&self) -> Option<u32> {
        let p = self.pgid();
        (p > 0).then_some(p)
    }
    fn read(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        if let Some(d) = self.detached.as_mut() {
            let n = d.log.read(buf)?;
            if n > 0 {
                return Ok(n);
            }
            if self.exit.is_some() || exit_file_status(&d.exit_file).is_some() {
                // One more read: output written just before the exit file.
                return d.log.read(buf);
            }
            std::thread::sleep(timeout.min(Duration::from_millis(50)));
            return Err(io::ErrorKind::TimedOut.into());
        }
        let Some(out) = self.out.as_mut() else { return Ok(0) };
        let n = out.read(buf, timeout)?;
        if n == 0 {
            self.out = None;
        }
        Ok(n)
    }
    fn write_stdin(&mut self, data: &[u8]) -> io::Result<()> {
        match self.input.as_mut() {
            Some(s) => {
                s.write_all(data)?;
                s.flush()
            }
            None => Err(io::Error::new(io::ErrorKind::BrokenPipe, "stdin is closed (start the process with stdin or pty to write to it)")),
        }
    }
    fn close_stdin(&mut self) {
        if self.pty {
            // EOF on a terminal: ^D for bash, ^Z + Enter for PowerShell / cmd. The console
            // input stays open (as the Unix PTY master does).
            let _ = self.write_stdin(if posix_shell() { b"\x04" } else { b"\x1a\r\n" });
            return;
        }
        self.input = None;
    }
    fn try_wait(&mut self) -> io::Result<Option<ExitInfo>> {
        if let Some(e) = self.exit {
            return Ok(Some(e));
        }
        if let Some(p) = self.proc.as_mut() {
            if let Some(code) = p.exit_code()? {
                let mut e = self.finish(code);
                if let Some(d) = &self.detached {
                    // The wrapper's own status is not the command's: the exit file is.
                    e = exit_file_status(&d.exit_file).unwrap_or(e);
                }
                // Closing the pseudo console ends its output stream (after the last frame).
                self.console = None;
                self.exit = Some(e);
            }
        } else if let Some(d) = &self.detached {
            if let Some(e) = exit_file_status(&d.exit_file) {
                self.exit = Some(e);
            } else if !pid_alive(d.pid, d.start) {
                self.exit = Some(ExitInfo { code: None, signal: None });
            }
        }
        Ok(self.exit)
    }
    fn kill(&mut self, force: bool) {
        if self.exit.is_some() {
            return;
        }
        if let Some(d) = &self.detached {
            kill_tree(d.pid);
            return;
        }
        let Some(pid) = self.proc.as_ref().map(|p| p.pid()) else { return };
        if !force {
            if self.pty {
                // Through the terminal, as a user would: ^C.
                if self.write_stdin(b"\x03").is_ok() {
                    return;
                }
            } else {
                use windows_sys::Win32::System::Console::{GenerateConsoleCtrlEvent, CTRL_BREAK_EVENT};
                // SAFETY: plain call; `pid` leads the console process group we created.
                if unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) } != 0 {
                    return;
                }
            }
        }
        self.force_killed = true;
        if let Some(p) = self.proc.as_mut() {
            p.terminate();
        }
    }
    fn resize(&mut self, rows: u16, cols: u16) -> io::Result<()> {
        match &self.console {
            Some(c) => c.resize(rows, cols),
            None => Err(io::Error::new(io::ErrorKind::Unsupported, "this process has no terminal (start it with pty=true)")),
        }
    }
    fn is_pty(&self) -> bool {
        self.pty
    }
}

impl Drop for LocalChild {
    fn drop(&mut self) {
        if self.detached.is_some() {
            return; // a running detached process keeps going
        }
        if let Some(p) = self.proc.as_mut() {
            if matches!(p.exit_code(), Ok(None)) {
                p.terminate();
            }
        }
        self.console = None;
    }
}

/// Is `pid` alive and still the process we started (creation time matches)?
pub fn pid_alive(pid: u32, start: Option<u64>) -> bool {
    seagent_core::platform::proc::alive(pid as i32) && (start.is_none() || proc_start_time(pid) == start)
}
