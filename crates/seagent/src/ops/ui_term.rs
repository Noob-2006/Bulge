//! Control UI terminal (OpenClaw `pages/terminal` + terminal panel host): a real PTY
//! running the user's shell in the workspace, driven over ARP by polling —
//! `ui.terminal.open` → id, `write` (keystrokes), `read` (output since an offset),
//! `resize`, `close`. Off unless `[app] terminal = true`; at most `MAX_TERMS` at once,
//! idle ones are reaped after `IDLE`, and each keeps the last `KEEP` bytes of output.
//!
//! Unix: `posix_openpt`, the shell as session leader with the PTY as controlling terminal.
//! Windows: a ConPTY pseudo console (`platform::term::ConPty`) running PowerShell / cmd /
//! Git Bash, the child in a kill-on-close job; the same RPCs and output buffering.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::FromRawFd;
#[cfg(unix)]
use std::os::fd::{OwnedFd, RawFd};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_TERMS: usize = 8;
pub const KEEP: usize = 256 * 1024;
pub const IDLE: Duration = Duration::from_secs(30 * 60);

/// Programs `ui.terminal.open` may name. The RPC is reachable from the Web UI, so any page that
/// can reach the endpoint (or a prompt-injected model driving it) can send a `shell` value:
/// letting that be an arbitrary path would let it execute any binary on the host. A request may
/// therefore only name one of these short names, and only through a `$PATH` lookup.
pub const ALLOWED_PROGRAMS: &[&str] =
    &["x-terminal-emulator", "gnome-terminal", "konsole", "xterm", "kitty", "wezterm", "alacritty"];

/// Shells the PTY may run: the terminal page is a shell, and these are the only programs it
/// needs. Everything else is refused even when it exists on `$PATH`.
#[cfg(not(windows))]
pub const ALLOWED_SHELLS: &[&str] = &["sh", "bash", "zsh", "fish", "dash", "ksh"];
/// Windows shells (found through `PATH` + `PATHEXT`).
#[cfg(windows)]
pub const ALLOWED_SHELLS: &[&str] = &["pwsh", "powershell", "cmd", "bash", "sh"];

type Res = Result<Value, (i32, String)>;

#[cfg(unix)]
type Child = std::process::Child;

/// The shell on a pseudo console; dropping it closes the console (the reader sees EOF).
#[cfg(windows)]
struct Child {
    proc: seagent_core::platform::term::PtyChild,
    pty: seagent_core::platform::term::ConPty,
}

#[cfg(windows)]
struct WinExit(u32);

#[cfg(windows)]
impl WinExit {
    fn code(&self) -> Option<i32> {
        Some(self.0 as i32)
    }
}

#[cfg(windows)]
impl Child {
    /// The shell and everything it started (its job object).
    fn kill(&mut self) -> std::io::Result<()> {
        seagent_core::platform::proc::kill_group(self.proc.id() as i32, Duration::ZERO);
        Ok(())
    }
    fn wait(&mut self) -> std::io::Result<u32> {
        self.proc.wait()
    }
    fn try_wait(&mut self) -> std::io::Result<Option<WinExit>> {
        self.proc.try_wait().map(|c| c.map(WinExit))
    }
}

struct Term {
    /// Keystrokes go here: the PTY master (Unix) / the pseudo console's input pipe (Windows).
    master: std::fs::File,
    child: Child,
    /// Output buffer and the absolute offset of its first byte.
    out: Arc<Mutex<(Vec<u8>, u64, bool)>>,
    last: Instant,
}

#[derive(Default)]
pub struct Terminals(Mutex<HashMap<String, Term>>);

impl Drop for Terminals {
    fn drop(&mut self) {
        if let Ok(mut m) = self.0.lock() {
            for (_, mut t) in m.drain() {
                let _ = t.child.kill();
                let _ = t.child.wait();
            }
        }
    }
}

fn fail(e: impl Into<String>) -> (i32, String) {
    (-32000, e.into())
}

/// Resolve a client-supplied program name to an absolute executable: a short name from the
/// allowlist, looked up on `path` (never a shell string, never a path the caller chose).
///
/// The last check is a writability test: a group/world-writable binary on `$PATH` can be swapped
/// by another local user between the check and the exec, so it is refused outright.
fn resolve_program(name: &str, path: &std::ffi::OsStr) -> Result<std::path::PathBuf, String> {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    let name = name.trim();
    if name.is_empty() {
        return Err("no program name given".into());
    }
    if name.contains('/') || name.contains('\\') {
        return Err(format!(
            "refusing `{name}`: the terminal takes an allowlisted program name, not a path \
             (absolute paths and `..` are not allowed); use one of {}",
            allowed_list()
        ));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) || name.contains("..") {
        return Err(format!("refusing `{name}`: it contains shell metacharacters; use a plain program name"));
    }
    if !ALLOWED_PROGRAMS.contains(&name) && !ALLOWED_SHELLS.contains(&name) {
        return Err(format!("refusing `{name}`: not an allowed terminal program (allowed: {})", allowed_list()));
    }
    // Windows: `sh` / `bash` are Git Bash / MSYS2 (PATH's `bash.exe` is WSL's launcher).
    #[cfg(not(unix))]
    if matches!(name, "sh" | "bash") {
        if let Some(b) = seagent_core::platform::layout::bash() {
            return Ok(seagent_core::platform::layout::simplify_verbatim(&b));
        }
    }
    // Windows: `PATHEXT` decides what runs (`pwsh` → pwsh.exe); there are no mode bits to check.
    #[cfg(not(unix))]
    if let Some(p) = seagent_core::platform::layout::which_in_pathext(name, Some(path), std::env::var("PATHEXT").ok().as_deref()) {
        return std::fs::canonicalize(&p).map_err(|e| format!("{}: {e}", p.display()));
    }
    #[cfg(unix)]
    for dir in std::env::split_paths(path) {
        let p = dir.join(name);
        // Follow symlinks (`/bin/sh` is one on most systems): the target is what gets executed.
        let Ok(md) = std::fs::metadata(&p) else { continue };
        if !md.is_file() || md.permissions().mode() & 0o111 == 0 {
            continue;
        }
        if md.permissions().mode() & 0o022 != 0 {
            return Err(format!("refusing `{}`: it is group/world writable, so another local user could replace it", p.display()));
        }
        return std::fs::canonicalize(&p).map_err(|e| format!("{}: {e}", p.display()));
    }
    Err(format!("`{name}` was not found on PATH (allowed: {})", allowed_list()))
}

fn allowed_list() -> String {
    ALLOWED_PROGRAMS.iter().chain(ALLOWED_SHELLS).copied().collect::<Vec<_>>().join(", ")
}

/// A new PTY pair: (master, slave). (Other Unixes: `platform::term::open_pty`, which copes
/// with a libc without `ptsname_r` / `O_CLOEXEC` on `posix_openpt`.)
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn openpty() -> Result<(OwnedFd, OwnedFd), String> {
    seagent_core::platform::term::open_pty(24, 80).map_err(|e| format!("openpty: {e}"))
}

/// A new PTY pair: (master, slave).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn openpty() -> Result<(OwnedFd, OwnedFd), String> {
    // SAFETY: plain libc calls; every fd is checked and wrapped in OwnedFd.
    unsafe {
        let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        if m < 0 {
            return Err(format!("posix_openpt: {}", std::io::Error::last_os_error()));
        }
        let master = OwnedFd::from_raw_fd(m);
        if libc::grantpt(m) != 0 || libc::unlockpt(m) != 0 {
            return Err(format!("grantpt/unlockpt: {}", std::io::Error::last_os_error()));
        }
        let mut name = [0 as libc::c_char; 128];
        if libc::ptsname_r(m, name.as_mut_ptr(), name.len()) != 0 {
            return Err("ptsname_r failed".into());
        }
        let s = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        if s < 0 {
            return Err(format!("open pty slave: {}", std::io::Error::last_os_error()));
        }
        Ok((master, OwnedFd::from_raw_fd(s)))
    }
}

#[cfg(unix)]
fn set_size(fd: RawFd, cols: u16, rows: u16) {
    let ws = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
    // SAFETY: TIOCSWINSZ with a valid winsize on an open pty fd.
    unsafe {
        libc::ioctl(fd, libc::TIOCSWINSZ, &ws);
    }
}

/// The shell on a ConPTY of `cols` × `rows` in `ws`.
#[cfg(windows)]
fn spawn(ws: &Path, shell: &Path, cols: u16, rows: u16) -> Result<Term, String> {
    use seagent_core::platform::term::{windows_command_line, ConPty};
    let pty = ConPty::open(rows, cols).map_err(|e| format!("ConPTY: {e}"))?;
    let mut env: Vec<(std::ffi::OsString, std::ffi::OsString)> = std::env::vars_os().filter(|(k, _)| k != "TERM" && k != "SEAGENT_TERMINAL").collect();
    env.push(("TERM".into(), "xterm-256color".into()));
    env.push(("SEAGENT_TERMINAL".into(), "1".into()));
    let proc = pty.spawn(&windows_command_line(&shell.to_string_lossy(), &[]), Some(ws), Some(&env)).map_err(|e| format!("{}: {e}", shell.display()))?;
    let master = pty.input().map_err(|e| e.to_string())?;
    let out = pump(pty.output().map_err(|e| e.to_string())?);
    Ok(Term { master, child: Child { proc, pty }, out, last: Instant::now() })
}

/// Copy everything the terminal prints into the shared buffer (bounded to `KEEP`).
fn pump(mut reader: std::fs::File) -> Arc<Mutex<(Vec<u8>, u64, bool)>> {
    let out = Arc::new(Mutex::new((Vec::new(), 0u64, false)));
    let o = out.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut g = o.lock().unwrap();
                    g.0.extend_from_slice(&buf[..n]);
                    if g.0.len() > KEEP {
                        let cut = g.0.len() - KEEP;
                        g.0.drain(..cut);
                        g.1 += cut as u64;
                    }
                }
            }
        }
        o.lock().unwrap().2 = true;
    });
    out
}

#[cfg(unix)]
fn spawn(ws: &Path, shell: &Path, cols: u16, rows: u16) -> Result<Term, String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let (master, slave) = openpty()?;
    set_size(master.as_raw_fd(), cols, rows);
    let sfd = slave.as_raw_fd();
    let mut cmd = seagent_core::platform::proc::command(shell);
    cmd.current_dir(ws).env("TERM", "xterm-256color").env("SEAGENT_TERMINAL", "1");
    let io = |f: &OwnedFd| f.try_clone().map(std::process::Stdio::from).map_err(|e| e.to_string());
    cmd.stdin(io(&slave)?).stdout(io(&slave)?).stderr(io(&slave)?);
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            libc::setsid();
            libc::ioctl(sfd, libc::TIOCSCTTY as _, 0);
            Ok(())
        });
    }
    let child = cmd.spawn().map_err(|e| format!("{}: {e}", shell.display()))?;
    drop(slave);
    let master = std::fs::File::from(master);
    let reader = master.try_clone().map_err(|e| e.to_string())?;
    let out = pump(reader);
    Ok(Term { master, child, out, last: Instant::now() })
}

fn reap(m: &mut HashMap<String, Term>) {
    let mut stale = vec![];
    for (k, t) in m.iter_mut() {
        let exited = t.child.try_wait().ok().flatten().is_some() && t.out.lock().unwrap().2;
        if t.last.elapsed() > IDLE || (exited && t.last.elapsed() > Duration::from_secs(60)) {
            stale.push(k.clone());
        }
    }
    for k in stale {
        if let Some(mut t) = m.remove(&k) {
            let _ = t.child.kill();
            let _ = t.child.wait();
        }
    }
}

pub fn call(terms: &Terminals, enabled: bool, ws: &Path, op: &str, p: &Value) -> Res {
    if op == "status" {
        return Ok(json!({"enabled": enabled, "open": terms.0.lock().unwrap().len(), "max": MAX_TERMS}));
    }
    if !enabled {
        return Err((-32001, "the terminal is disabled; set `[app] terminal = true` in config.toml and restart the daemon".into()));
    }
    let id = p["id"].as_str().unwrap_or("").to_string();
    let mut m = terms.0.lock().unwrap();
    reap(&mut m);
    let cols = p["cols"].as_u64().unwrap_or(100).clamp(10, 500) as u16;
    let rows = p["rows"].as_u64().unwrap_or(30).clamp(4, 300) as u16;
    match op {
        "open" => {
            if m.len() >= MAX_TERMS {
                return Err(fail(format!("too many terminals open (max {MAX_TERMS}); close one first")));
            }
            // A client may only name an allowlisted program; without one the daemon runs its own
            // `$SHELL` (trusted: it is the daemon user's environment, not request input).
            let (program, why) = match p["shell"].as_str().map(str::trim).filter(|s| !s.is_empty()) {
                Some(name) => {
                    let path = resolve_program(name, &std::env::var_os("PATH").unwrap_or_default()).map_err(fail)?;
                    (path, format!("requested `{name}`"))
                }
                #[cfg(unix)]
                None => {
                    let shell = std::env::var("SHELL").ok().filter(|s| Path::new(s).is_absolute() && Path::new(s).is_file()).unwrap_or_else(|| "/bin/sh".into());
                    (std::path::PathBuf::from(shell), "default $SHELL".into())
                }
                // Windows: this machine's shell (Git Bash, pwsh or Windows PowerShell), else %ComSpec%.
                #[cfg(not(unix))]
                None => {
                    let sh = seagent_core::platform::shell::active();
                    let program = if sh.program.is_absolute() { Some(sh.program.clone()) } else { seagent_core::platform::layout::which(&sh.program.to_string_lossy()) };
                    let program = program.or_else(|| std::env::var_os("ComSpec").map(std::path::PathBuf::from)).ok_or_else(|| fail("no shell found (set SEAGENT_SHELL)"))?;
                    (program, format!("default shell ({})", sh.reason))
                }
            };
            // Which binary a Web UI request launched is worth a line in seagentd.log.
            eprintln!("seagentd: ui.terminal: launching {} ({why}) in {}", program.display(), ws.display());
            let t = spawn(ws, &program, cols, rows).map_err(fail)?;
            let id = seagent_kernel::util::random_hex(8);
            m.insert(id.clone(), t);
            Ok(json!({"id": id, "shell": program.display().to_string(), "cwd": ws.display().to_string()}))
        }
        _ => {
            let t = m.get_mut(&id).ok_or_else(|| (-32602, format!("no terminal `{id}`")))?;
            t.last = Instant::now();
            match op {
                "write" => {
                    let data = p["data"].as_str().unwrap_or("");
                    t.master.write_all(data.as_bytes()).map_err(|e| fail(e.to_string()))?;
                    Ok(json!({"written": data.len()}))
                }
                "read" => {
                    let since = p["offset"].as_u64().unwrap_or(0);
                    let g = t.out.lock().unwrap();
                    let start = since.saturating_sub(g.1) as usize;
                    let chunk = &g.0[start.min(g.0.len())..];
                    let exited = t.child.try_wait().ok().flatten().map(|s| s.code());
                    Ok(json!({"data": String::from_utf8_lossy(chunk), "offset": g.1 + g.0.len() as u64, "truncated": since < g.1, "exited": exited.is_some(), "code": exited.flatten()}))
                }
                "resize" => {
                    #[cfg(unix)]
                    {
                        use std::os::fd::AsRawFd;
                        set_size(t.master.as_raw_fd(), cols, rows);
                    }
                    #[cfg(windows)]
                    t.child.pty.resize(rows, cols).map_err(|e| fail(e.to_string()))?;
                    Ok(json!({"cols": cols, "rows": rows}))
                }
                "close" => {
                    let mut t = m.remove(&id).unwrap();
                    let _ = t.child.kill();
                    let _ = t.child.wait();
                    Ok(json!({"closed": id}))
                }
                other => Err((-32601, format!("unknown terminal method `{other}`"))),
            }
        }
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;

    #[test]
    fn terminal_program_is_allowlisted_and_resolved_on_path() {
        use std::os::unix::fs::PermissionsExt;
        let d = seagent_core::tmp::TempDir::new("seagent-tmp");
        // Absolute paths, `..` and separators are refused before any lookup: a Web UI request
        // must not be able to name a binary (that is what made this an arbitrary-exec RPC).
        for bad in ["/bin/sh", "/usr/bin/xterm", "../xterm", "sub/xterm", "xterm;sh", "$(id)", "x term"] {
            let e = resolve_program(bad, d.path().as_os_str()).unwrap_err();
            assert!(e.contains("refusing"), "{bad}: {e}");
        }
        // An unknown short name is refused even when it exists on the search path.
        let rm = d.path().join("rm");
        std::fs::write(&rm, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&rm, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(resolve_program("rm", d.path().as_os_str()).unwrap_err().contains("not an allowed"));
        assert!(resolve_program("xterm", d.path().as_os_str()).unwrap_err().contains("not found on PATH"));
        // An allowed name resolves to an absolute executable.
        let term = d.path().join("xterm");
        std::fs::write(&term, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&term, std::fs::Permissions::from_mode(0o755)).unwrap();
        let got = resolve_program("xterm", d.path().as_os_str()).unwrap();
        assert!(got.is_absolute() && got == std::fs::canonicalize(&term).unwrap(), "{got:?}");
        // A group/world-writable target is refused: another local user could swap it under us.
        std::fs::set_permissions(&term, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(resolve_program("xterm", d.path().as_os_str()).unwrap_err().contains("writable"));
        // The RPC refuses the same way and leaves no terminal behind.
        let terms = Terminals::default();
        let ws = std::env::current_dir().unwrap();
        assert!(call(&terms, true, &ws, "open", &json!({"shell": "/bin/sh"})).unwrap_err().1.contains("refusing"));
        assert!(call(&terms, true, &ws, "open", &json!({"shell": "no-such-term"})).unwrap_err().1.contains("not an allowed"));
        assert_eq!(terms.0.lock().unwrap().len(), 0);
    }

    #[test]
    fn pty_terminal_round_trip_and_gate() {
        let terms = Terminals::default();
        let ws = std::env::current_dir().unwrap();
        assert!(call(&terms, false, &ws, "open", &json!({})).unwrap_err().1.contains("disabled"));
        assert_eq!(call(&terms, false, &ws, "status", &json!({})).unwrap()["enabled"], false);
        let id = call(&terms, true, &ws, "open", &json!({"shell": "sh", "cols": 80, "rows": 24})).unwrap()["id"].as_str().unwrap().to_string();
        call(&terms, true, &ws, "write", &json!({"id": id, "data": "tty -s && echo T$((1+1))TY; stty size; echo seagent-$((6*7))\n"})).unwrap();
        let mut out = String::new();
        let mut off = 0;
        for _ in 0..100 {
            let r = call(&terms, true, &ws, "read", &json!({"id": id, "offset": off})).unwrap();
            out.push_str(r["data"].as_str().unwrap());
            off = r["offset"].as_u64().unwrap();
            if out.contains("seagent-42") {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(out.contains("seagent-42") && out.contains("T2TY") && out.contains("24 80"), "{out}");
        call(&terms, true, &ws, "resize", &json!({"id": id, "cols": 120, "rows": 40})).unwrap();
        call(&terms, true, &ws, "close", &json!({"id": id})).unwrap();
        assert!(call(&terms, true, &ws, "read", &json!({"id": id})).unwrap_err().1.contains("no terminal"));
    }
}
