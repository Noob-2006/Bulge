//! External programs (ffmpeg, whisper.cpp, piper, arecord, players, user TTS/STT
//! commands): PATH lookup and a run with stdin, timeout and cancellation.
//!
//! Unix runs exactly what the argv says. Windows (docs/cross-platform.md): names resolve
//! through `PATHEXT` (so `.cmd`/`.bat` shims start), user command lines run in this
//! machine's shell ([`shell_argv`]: Git Bash, else PowerShell), and the `env -i K=V … prog`
//! prefix the STT/TTS command providers build is applied in-process, since Windows has no
//! `env` program.

use seagent_core::Cancel;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// First executable named `name` on `$PATH` (or `name` itself when it is a path).
#[cfg(unix)]
pub fn which(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        let p = PathBuf::from(name);
        return is_exec(&p).then_some(p);
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(name)).find(|p| is_exec(p))
}

#[cfg(unix)]
fn is_exec(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
}

/// First executable named `name` on `%PATH%`, trying the `PATHEXT` extensions (or `name`
/// itself when it is a path).
#[cfg(not(unix))]
pub fn which(name: &str) -> Option<PathBuf> {
    seagent_core::platform::layout::which(name)
}

/// Environment Windows programs need to start at all (a cleared environment without
/// `SystemRoot` breaks Winsock and most of the CRT); kept by the command providers'
/// `env -i` scrub next to their unix allowlist.
pub const WINDOWS_BASE_ENV: &[&str] = &["SystemRoot", "SystemDrive", "windir", "ComSpec", "PATHEXT", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "ProgramData", "ProgramFiles", "ProgramFiles(x86)", "USERNAME", "COMPUTERNAME", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE"];

/// `argv` for running the user command `line` through a shell: `sh -c LINE` on unix, this
/// machine's shell elsewhere (`seagent_core::platform::shell`).
pub fn shell_argv(line: &str) -> Vec<String> {
    #[cfg(unix)]
    {
        vec!["sh".into(), "-c".into(), line.into()]
    }
    #[cfg(not(unix))]
    {
        let (prog, args) = seagent_core::platform::shell::argv(seagent_core::platform::shell::Style::Sh, line);
        std::iter::once(prog).chain(args).map(|a| a.to_string_lossy().into_owned()).collect()
    }
}

/// A `Command` for [`shell_argv`] (the long-lived recorder/player pipes in realtime voice).
pub fn shell_command(line: &str) -> Command {
    let argv = shell_argv(line);
    let mut c = seagent_core::platform::layout::program_command(&argv[0]);
    seagent_core::platform::layout::msys_args(&mut c, &argv[1..]);
    c
}

/// First of `names` found on `$PATH`.
pub fn which_any(names: &[&str]) -> Option<PathBuf> {
    names.iter().find_map(|n| which(n))
}

#[derive(Debug, Clone)]
pub struct Output {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

impl Output {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
    /// `Err` with the tail of stderr unless the exit status was 0.
    pub fn check(self, what: &str) -> Result<Output, String> {
        if self.success() {
            Ok(self)
        } else {
            let tail: String = self.stderr.trim().chars().rev().take(600).collect::<Vec<_>>().into_iter().rev().collect();
            Err(format!("{what} exited with {}: {tail}", self.code.map(|c| c.to_string()).unwrap_or_else(|| "a signal".into())))
        }
    }
}

/// Run `argv` (no shell), feeding `stdin`, killing it after `timeout` or on cancel.
pub fn run(argv: &[String], stdin: Option<&[u8]>, timeout: Duration, cancel: &Cancel) -> Result<Output, String> {
    run_env(argv, stdin, &[], timeout, cancel)
}

pub fn run_env(argv: &[String], stdin: Option<&[u8]>, env: &[(String, String)], timeout: Duration, cancel: &Cancel) -> Result<Output, String> {
    run_env_in(argv, stdin, env, None, timeout, cancel)
}

/// [`run_env`] in working directory `cwd` (the Windows form of the unix `sh -c 'cd "$0" &&
/// exec "$@"'` wrapper; unix callers keep the wrapper).
pub fn run_env_in(argv: &[String], stdin: Option<&[u8]>, env: &[(String, String)], cwd: Option<&std::path::Path>, timeout: Duration, cancel: &Cancel) -> Result<Output, String> {
    let (prog, args) = argv.split_first().ok_or("empty command")?;
    #[cfg(unix)]
    let mut cmd = Command::new(prog);
    #[cfg(not(unix))]
    let (mut cmd, prog, args) = {
        // `env -i K=V … prog args`: clear, keep the Windows base set, apply the pairs.
        let (scrub, prog, args) = match (prog.as_str(), args.first().map(String::as_str)) {
            ("env", Some("-i")) => {
                let rest = &args[1..];
                let n = rest.iter().take_while(|a| a.contains('=') && !a.starts_with('=')).count();
                let (pairs, tail) = rest.split_at(n);
                let (p, a) = tail.split_first().ok_or("empty command after env -i")?;
                (Some(pairs), p, a)
            }
            _ => (None, prog, args),
        };
        // PATHEXT shims, `sh`/`bash` = Git Bash, `python3` = `py -3` (`layout::program_command`).
        let mut cmd = seagent_core::platform::layout::program_command(prog);
        if let Some(pairs) = scrub {
            cmd.env_clear();
            for k in WINDOWS_BASE_ENV {
                if let Some(v) = std::env::var_os(k) {
                    cmd.env(k, v);
                }
            }
            for p in pairs {
                if let Some((k, v)) = p.split_once('=') {
                    cmd.env(k, v);
                }
            }
        }
        (cmd, prog, args)
    };
    seagent_core::platform::layout::msys_args(&mut cmd, args);
    cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    let mut child = cmd.spawn().map_err(|e| format!("cannot run `{prog}`: {e}"))?;
    if let (Some(data), Some(mut si)) = (stdin.map(|d| d.to_vec()), child.stdin.take()) {
        std::thread::spawn(move || {
            let _ = si.write_all(&data);
        });
    }
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let out_t = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = so.read_to_end(&mut b);
        b
    });
    let err_t = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = se.read_to_end(&mut b);
        b
    });
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
            break Some(s);
        }
        if cancel.is_cancelled() || start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = out_t.join().unwrap_or_default();
    let stderr = String::from_utf8_lossy(&err_t.join().unwrap_or_default()).into_owned();
    match status {
        Some(s) => Ok(Output { code: s.code(), stdout, stderr }),
        None if cancel.is_cancelled() => Err(format!("`{prog}` cancelled")),
        None => Err(format!("`{prog}` timed out after {}s", timeout.as_secs())),
    }
}

/// Expand `{name}` placeholders in a user command template, shell-quoting each value
/// (Hermes `tts.providers.<name>.command` / OpenClaw tts-local-cli placeholders).
pub fn render_template(template: &str, vars: &[(&str, &str)]) -> String {
    let mut out = template.to_string();
    for (k, v) in vars {
        out = out.replace(&format!("{{{k}}}"), &shell_quote(v));
    }
    out
}

pub fn shell_quote(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./=:,+@%".contains(c)) {
        s.to_string()
    } else if !posix_shell() {
        // PowerShell: single quotes are literal, a quote inside is doubled.
        format!("'{}'", s.replace('\'', "''"))
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// Does [`shell_argv`] run a POSIX shell? Always on unix; on Windows only with Git Bash/MSYS.
fn posix_shell() -> bool {
    cfg!(unix) || seagent_core::platform::shell::active().kind.is_posix()
}

/// Run a user command line through `sh -c` (this machine's shell on Windows).
pub fn run_shell(line: &str, stdin: Option<&[u8]>, env: &[(String, String)], timeout: Duration, cancel: &Cancel) -> Result<Output, String> {
    run_env(&shell_argv(line), stdin, env, timeout, cancel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)] // cat / sleep / sh
    fn runs_with_stdin_and_times_out() {
        let o = run(&["cat".into()], Some(b"hi"), Duration::from_secs(5), &Cancel::new()).unwrap();
        assert_eq!((o.success(), o.stdout.as_slice()), (true, &b"hi"[..]));
        let e = run(&["sleep".into(), "5".into()], None, Duration::from_millis(100), &Cancel::new()).unwrap_err();
        assert!(e.contains("timed out"), "{e}");
        let f = run(&["sh".into(), "-c".into(), "echo boom >&2; exit 3".into()], None, Duration::from_secs(5), &Cancel::new()).unwrap().check("x").unwrap_err();
        assert!(f.contains("exited with 3") && f.contains("boom"), "{f}");
        assert!(which("sh").is_some() && which("definitely-not-a-binary-xyz").is_none());
    }

    #[test]
    #[cfg(unix)] // POSIX quoting; Windows quotes for its active shell
    fn templates_quote_values() {
        assert_eq!(render_template("say {text} > {out}", &[("text", "it's me"), ("out", "/tmp/a.wav")]), "say 'it'\\''s me' > /tmp/a.wav");
    }

    #[test]
    fn shell_argv_wraps_the_line() {
        let a = shell_argv("echo hi");
        assert_eq!(a.last().map(String::as_str), Some("echo hi"));
        #[cfg(unix)]
        assert_eq!(a, ["sh", "-c", "echo hi"]);
    }
}
