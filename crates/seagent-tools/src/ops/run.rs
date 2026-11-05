//! Running a fixed argv (no shell) with a timeout, an output cap and cancellation. Used by
//! `deploy` (kubectl / helm / docker compose / systemctl) and `compliance_check` (read-only
//! probes). The child is always reaped: on timeout or cancel it is killed and waited for.

use seagent_core::Cancel;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const OUTPUT_CAP: usize = 256 * 1024;

#[derive(Debug, Clone, Default)]
pub struct RunOut {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

impl RunOut {
    pub fn ok(&self) -> bool {
        self.code == Some(0) && !self.timed_out
    }
    /// stdout + stderr for display, each trimmed.
    pub fn text(&self) -> String {
        let mut s = self.stdout.trim_end().to_string();
        if !self.stderr.trim().is_empty() {
            if !s.is_empty() {
                s.push('\n');
            }
            s.push_str(self.stderr.trim_end());
        }
        if self.timed_out {
            s.push_str("\n[timed out]");
        }
        s
    }
}

fn reader(mut r: impl Read + Send + 'static) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut r).take(OUTPUT_CAP as u64).read_to_end(&mut buf);
        // Drain the rest so the child never blocks on a full pipe.
        let _ = std::io::copy(&mut r, &mut std::io::sink());
        String::from_utf8_lossy(&buf).into_owned()
    })
}

/// Run `argv` (argv[0] looked up on PATH) in `cwd`. `Err` only when it cannot start.
pub fn run(argv: &[String], cwd: Option<&Path>, timeout: Duration, cancel: &Cancel) -> Result<RunOut, String> {
    let (prog, args) = argv.split_first().ok_or("empty command")?;
    let mut cmd = Command::new(prog);
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    // ETXTBSY: a just-written executable can still be open for writing in a sibling fork
    // (another thread spawning at the same moment); it clears within milliseconds.
    let mut tries = 0;
    let mut child = loop {
        match cmd.spawn() {
            Ok(c) => break c,
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && tries < 20 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(format!("cannot run `{prog}`: {e}")),
        }
    };
    let out = reader(child.stdout.take().expect("piped"));
    let err = reader(child.stderr.take().expect("piped"));
    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) => {}
            Err(_) => break None,
        }
        if start.elapsed() >= timeout || cancel.is_cancelled() {
            timed_out = start.elapsed() >= timeout;
            let _ = child.kill();
            break child.wait().ok();
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Ok(RunOut { code: status.and_then(|s| s.code()), stdout: out.join().unwrap_or_default(), stderr: err.join().unwrap_or_default(), timed_out })
}

/// A display / audit form of an argv: shell-quoted where needed.
pub fn join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            if !a.is_empty() && a.chars().all(|c| c.is_ascii_alphanumeric() || "-_./=:,@%+".contains(c)) {
                a.clone()
            } else {
                format!("'{}'", a.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_times_out_and_quotes() {
        let c = Cancel::new();
        let o = run(&["sh".into(), "-c".into(), "echo out; echo err >&2; exit 3".into()], None, Duration::from_secs(5), &c).unwrap();
        assert_eq!(o.code, Some(3));
        assert_eq!(o.text(), "out\nerr");
        let t = run(&["sleep".into(), "5".into()], None, Duration::from_millis(100), &c).unwrap();
        assert!(t.timed_out && !t.ok());
        assert!(run(&["/nonexistent/seagent-x".into()], None, Duration::from_secs(1), &c).is_err());
        assert_eq!(join(&["kubectl".into(), "apply".into(), "-f".into(), "a b.yaml".into(), "it's".into()]), "kubectl apply -f 'a b.yaml' 'it'\\''s'");
    }
}
