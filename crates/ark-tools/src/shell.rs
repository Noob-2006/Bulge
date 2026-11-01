use crate::util::io_err;
use ark_core::tool::{arg_opt_str, arg_str};
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::io::Read as _;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_TIMEOUT: u64 = 120;
const MAX_TIMEOUT: u64 = 3600;
const HALF_CAP: usize = 512 * 1024;
/// After the main process exits, how long to wait for background children
/// that still hold the output pipes.
const DRAIN_GRACE: Duration = Duration::from_millis(500);

/// Keeps the first and last HALF_CAP bytes of a stream.
#[derive(Default)]
struct Capture {
    head: Vec<u8>,
    tail: Vec<u8>,
    total: usize,
}

impl Capture {
    fn push(&mut self, data: &[u8]) {
        self.total += data.len();
        let room = HALF_CAP.saturating_sub(self.head.len());
        let (h, t) = data.split_at(room.min(data.len()));
        self.head.extend_from_slice(h);
        self.tail.extend_from_slice(t);
        if self.tail.len() > 2 * HALF_CAP {
            let cut = self.tail.len() - HALF_CAP;
            self.tail.drain(..cut);
        }
    }
    fn render(&self) -> String {
        let kept = self.head.len() + self.tail.len().min(HALF_CAP);
        if self.total <= kept {
            let mut all = self.head.clone();
            all.extend_from_slice(&self.tail);
            return String::from_utf8_lossy(&all).into_owned();
        }
        let tail = &self.tail[self.tail.len().saturating_sub(HALF_CAP)..];
        format!(
            "{}\n…[output truncated: {} bytes omitted of {} total]…\n{}",
            String::from_utf8_lossy(&self.head),
            self.total - self.head.len() - tail.len(),
            self.total,
            String::from_utf8_lossy(tail)
        )
    }
}

fn kill_group(pgid: i32, sig: i32) {
    // SAFETY: plain syscall; negative pid targets the process group.
    unsafe {
        libc::kill(-pgid, sig);
    }
}

pub struct Shell;

impl Tool for Shell {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "shell".into(),
            description: "Run a bash command in the workspace. Returns combined stdout/stderr and exit code. Use {{secret:NAME}} for credentials.".into(),
            input_schema: json!({"type":"object","properties":{
                "command":{"type":"string"},
                "timeout_secs":{"type":"integer","minimum":1,"maximum":MAX_TIMEOUT,"default":DEFAULT_TIMEOUT},
                "cwd":{"type":"string","description":"Working directory (default: workspace)"}},
                "required":["command"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: true,
        }
    }
    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        match arg_str(input, "command") {
            Ok(c) => vec![Effect::Exec { command: c.to_string() }],
            Err(_) => vec![],
        }
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let command = match arg_str(&input, "command") {
            Ok(c) if !c.trim().is_empty() => c,
            Ok(_) => return ToolOutput::err("command must not be empty"),
            Err(e) => return ToolOutput::err(e),
        };
        let timeout = match input.get("timeout_secs") {
            None | Some(Value::Null) => DEFAULT_TIMEOUT,
            Some(v) => match v.as_u64() {
                Some(t) if (1..=MAX_TIMEOUT).contains(&t) => t,
                _ => return ToolOutput::err(format!("timeout_secs must be an integer in 1..={MAX_TIMEOUT}")),
            },
        };
        let cwd = ctx.resolve(arg_opt_str(&input, "cwd").unwrap_or("."));
        if !cwd.is_dir() {
            return ToolOutput::err(format!("cwd {} is not an existing directory", cwd.display()));
        }
        let resolved = (ctx.secrets)(command);
        let mut cmd = Command::new("bash");
        cmd.arg("-c").arg(&resolved).current_dir(&cwd).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let parent = std::process::id() as i32;
        // SAFETY: setpgid, prctl, getppid are async-signal-safe.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                die_with_parent(parent);
                Ok(())
            });
        }
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => return ToolOutput::err(io_err("start bash in", &cwd, &e)),
        };
        let pgid = child.id() as i32;
        let cap = Arc::new(Mutex::new(Capture::default()));
        let readers: Vec<_> = [child.stdout.take().map(|s| Box::new(s) as Box<dyn std::io::Read + Send>), child.stderr.take().map(|s| Box::new(s) as _)]
            .into_iter()
            .flatten()
            .map(|mut r| {
                let cap = cap.clone();
                thread::spawn(move || {
                    let mut buf = [0u8; 8192];
                    while let Ok(n) = r.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        cap.lock().unwrap().push(&buf[..n]);
                    }
                })
            })
            .collect();

        let deadline = Instant::now() + Duration::from_secs(timeout);
        let mut stopped: Option<&str> = None;
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break Some(s),
                Ok(None) => {}
                Err(_) => break None,
            }
            let why = if ctx.cancel.is_cancelled() {
                Some("cancelled")
            } else if Instant::now() >= deadline {
                Some("timed out")
            } else {
                None
            };
            if let Some(why) = why {
                stopped = Some(why);
                kill_group(pgid, libc::SIGTERM);
                let grace = Instant::now() + Duration::from_secs(2);
                while Instant::now() < grace && matches!(child.try_wait(), Ok(None)) {
                    thread::sleep(Duration::from_millis(20));
                }
                kill_group(pgid, libc::SIGKILL);
                break child.wait().ok();
            }
            thread::sleep(Duration::from_millis(20));
        };
        if stopped.is_some() {
            // Background members may have ignored SIGTERM; make sure the group is gone.
            kill_group(pgid, libc::SIGKILL);
        }
        let drain_until = Instant::now() + DRAIN_GRACE;
        let mut lingering = false;
        for r in readers {
            while !r.is_finished() && Instant::now() < drain_until {
                thread::sleep(Duration::from_millis(10));
            }
            if r.is_finished() {
                let _ = r.join();
            } else {
                lingering = true;
            }
        }
        let mut out = cap.lock().unwrap().render();
        if lingering {
            out.push_str("\n[note: background processes are still running and holding output; their later output is not captured]");
        }
        if let Some(why) = stopped {
            let msg = if why == "timed out" { format!("timed out after {timeout}s; process group killed") } else { "cancelled; process group killed".into() };
            return ToolOutput::err(format!("{out}\n[{msg}]"));
        }
        match status {
            Some(s) if s.success() => ToolOutput::ok(if out.is_empty() { "[exit 0, no output]".into() } else { format!("{out}\n[exit 0]") }),
            Some(s) => match (s.code(), s.signal()) {
                (Some(c), _) => ToolOutput::err(format!("{out}\n[exit {c}]")),
                (None, Some(sig)) => ToolOutput::err(format!("{out}\n[killed by signal {sig}]")),
                _ => ToolOutput::err(format!("{out}\n[exited abnormally]")),
            },
            None => ToolOutput::err(format!("{out}\n[could not collect exit status]")),
        }
    }
}

/// If ark is killed (even SIGKILL), the command dies too instead of finishing
/// unobserved: crash recovery reports "side effects unknown", and an orphan
/// completing later would make that report wrong.
#[cfg(target_os = "linux")]
pub fn die_with_parent(parent: i32) {
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
        if libc::getppid() != parent {
            libc::_exit(137); // parent already gone before prctl took effect
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn die_with_parent(_parent: i32) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ctx;

    fn group_alive(pgid: i32) -> bool {
        unsafe { libc::kill(-pgid, 0) == 0 }
    }

    #[test]
    fn success_and_exit_codes() {
        let c = ctx("sh");
        let o = Shell.call(&c, json!({"command":"echo hi; echo err >&2"}));
        assert!(!o.is_error);
        assert!(o.content.contains("hi") && o.content.contains("err") && o.content.ends_with("[exit 0]"));
        let o = Shell.call(&c, json!({"command":"echo partial; exit 3"}));
        assert!(o.is_error && o.content.contains("partial") && o.content.contains("[exit 3]"));
        let o = Shell.call(&c, json!({"command":"kill -9 $$"}));
        assert!(o.is_error && o.content.contains("signal 9"), "{}", o.content);
        assert_eq!(Shell.call(&c, json!({"command":"true"})).content, "[exit 0, no output]");
    }

    #[test]
    fn bad_args() {
        let c = ctx("shbad");
        assert!(Shell.call(&c, json!({})).is_error);
        assert!(Shell.call(&c, json!({"command":"   "})).is_error);
        assert!(Shell.call(&c, json!({"command":"true","timeout_secs":0})).is_error);
        assert!(Shell.call(&c, json!({"command":"true","timeout_secs":99999})).is_error);
        assert!(Shell.call(&c, json!({"command":"true","timeout_secs":"5"})).is_error);
        assert!(Shell.call(&c, json!({"command":"true","cwd":"nope"})).content.contains("not an existing directory"));
    }

    #[test]
    fn cwd_is_honored() {
        let c = ctx("shcwd");
        std::fs::create_dir(c.workspace.join("sub")).unwrap();
        let o = Shell.call(&c, json!({"command":"pwd","cwd":"sub"}));
        assert!(o.content.contains("/sub"), "{}", o.content);
    }

    #[test]
    fn timeout_kills_whole_group() {
        let c = ctx("shto");
        let pidfile = c.workspace.join("pgid");
        let cmd = format!("echo $$ > {}; sleep 30 & sleep 30", pidfile.display());
        let t = Instant::now();
        let o = Shell.call(&c, json!({"command":cmd,"timeout_secs":1}));
        assert!(t.elapsed() < Duration::from_secs(6), "took {:?}", t.elapsed());
        assert!(o.is_error && o.content.contains("timed out after 1s"), "{}", o.content);
        let pgid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
        let gone = (0..100).any(|_| {
            thread::sleep(Duration::from_millis(20));
            !group_alive(pgid)
        });
        assert!(gone, "process group {pgid} still alive");
    }

    #[test]
    fn sigterm_ignoring_child_still_dies() {
        let c = ctx("shterm");
        let t = Instant::now();
        let o = Shell.call(&c, json!({"command":"trap '' TERM; sleep 30","timeout_secs":1}));
        assert!(o.is_error && t.elapsed() < Duration::from_secs(8));
    }

    #[test]
    fn cancel_mid_run() {
        let c = ctx("shcancel");
        let cancel = c.cancel.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(300));
            cancel.cancel();
        });
        let t = Instant::now();
        let o = Shell.call(&c, json!({"command":"echo started; sleep 30"}));
        assert!(t.elapsed() < Duration::from_secs(5));
        assert!(o.is_error && o.content.contains("cancelled") && o.content.contains("started"), "{}", o.content);
    }

    #[test]
    fn output_is_capped_head_and_tail() {
        let c = ctx("shcap");
        let o = Shell.call(&c, json!({"command":"echo FIRST; head -c 3000000 /dev/zero | tr '\\0' x; echo; echo LAST"}));
        assert!(!o.is_error);
        assert!(o.content.contains("FIRST") && o.content.contains("LAST"));
        assert!(o.content.contains("output truncated"));
        assert!(o.content.len() < 1_200_000, "{}", o.content.len());
    }

    #[test]
    fn background_process_does_not_block_return() {
        let c = ctx("shbg");
        let t = Instant::now();
        let o = Shell.call(&c, json!({"command":"(sleep 3; echo late) & echo now"}));
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        assert!(o.content.contains("now") && o.content.contains("background processes"));
    }

    #[test]
    fn secrets_substituted_only_at_exec() {
        let c = ctx("shsec");
        let input = json!({"command":"echo token={{secret:TOKEN}}"});
        assert_eq!(Shell.effects(&c, &input), vec![Effect::Exec { command: "echo token={{secret:TOKEN}}".into() }]);
        let o = Shell.call(&c, input);
        assert!(o.content.contains("token=s3cr3t"));
        assert!(Shell.effects(&c, &json!({})).is_empty());
    }
}
