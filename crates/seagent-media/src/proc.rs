//! External programs (ffmpeg, whisper.cpp, piper, arecord, players, user TTS/STT
//! commands): PATH lookup and a run with stdin, timeout and cancellation.

use seagent_core::Cancel;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// First executable named `name` on `$PATH` (or `name` itself when it is a path).
pub fn which(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        let p = PathBuf::from(name);
        return is_exec(&p).then_some(p);
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(name)).find(|p| is_exec(p))
}

fn is_exec(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
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
    let (prog, args) = argv.split_first().ok_or("empty command")?;
    let mut cmd = Command::new(prog);
    cmd.args(args).stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
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
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// Run a user command line through `sh -c`.
pub fn run_shell(line: &str, stdin: Option<&[u8]>, env: &[(String, String)], timeout: Duration, cancel: &Cancel) -> Result<Output, String> {
    run_env(&["sh".into(), "-c".into(), line.into()], stdin, env, timeout, cancel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
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
    fn templates_quote_values() {
        assert_eq!(render_template("say {text} > {out}", &[("text", "it's me"), ("out", "/tmp/a.wav")]), "say 'it'\\''s me' > /tmp/a.wav");
    }
}
