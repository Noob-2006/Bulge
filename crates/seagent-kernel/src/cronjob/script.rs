//! Cron pre-run scripts and `no_agent` jobs (Hermes `cron/scheduler_script.py`).
//!
//! Scripts live in `<data>/scripts/` and MUST resolve inside it (relative, absolute and `~`
//! paths are all checked; traversal and symlink escapes are refused). `.sh`/`.bash` run with
//! bash, anything else with `python3` (the shebang is deliberately not honoured: a small,
//! auditable surface). The child gets a scrubbed environment (no provider keys / tokens), its
//! own process group (killed as a group on timeout), and its output is redacted before it is
//! returned to the prompt or a delivery target.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const DEFAULT_TIMEOUT_SECS: u64 = 3600;

pub fn scripts_dir(data: &Path) -> PathBuf {
    data.join("scripts")
}

/// Create-time check (Hermes `_validate_cron_script_path`): relative to the scripts dir, no
/// traversal, must exist. `None` = fine.
pub fn validate_for_create(data: &Path, script: &str) -> Option<String> {
    let raw = script.trim();
    if raw.is_empty() {
        return None;
    }
    let dir = scripts_dir(data);
    if raw.starts_with('/') || raw.starts_with('~') || Path::new(raw).is_absolute() {
        return Some(format!("Script path must be relative to {}/. Got absolute or home-relative path: {raw:?}. Place scripts in {}/ and use just the filename.", dir.display(), dir.display()));
    }
    resolve(data, raw).err()
}

/// Run-time resolution (Hermes `_resolve_script_path`).
pub fn resolve(data: &Path, script: &str) -> Result<PathBuf, String> {
    if script.contains('\0') {
        return Err(format!("Blocked: script path contains a NUL byte: {script:?}"));
    }
    let dir = scripts_dir(data);
    let _ = std::fs::create_dir_all(&dir);
    let dir_real = dir.canonicalize().map_err(|e| format!("{}: {e}", dir.display()))?;
    let raw = seagent_core::expand_home(script.trim());
    let joined = if raw.is_absolute() { raw } else { dir.join(raw) };
    let real = match joined.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            // Lexical check first so a missing file outside the dir is still reported as an escape.
            let lexical = normalize(&joined);
            if !lexical.starts_with(&dir_real) && !lexical.starts_with(&dir) {
                return Err(format!("Blocked: script path resolves outside the scripts directory ({}): {script:?}", dir_real.display()));
            }
            return Err(format!("Script not found: {}. Cron scripts are looked up only in {}; create it there first.", joined.display(), dir_real.display()));
        }
    };
    if !real.starts_with(&dir_real) {
        return Err(format!("Blocked: script path resolves outside the scripts directory ({}): {script:?}", dir_real.display()));
    }
    if !real.is_file() {
        return Err(format!("Script path is not a file: {}", real.display()));
    }
    Ok(real)
}

fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            c => out.push(c),
        }
    }
    out
}

/// Environment for the child: PATH/HOME/LANG/TZ-style basics only; nothing that looks like a
/// credential (Hermes `build_subprocess_env`, SECURITY.md §2.3).
pub fn scrubbed_env() -> Vec<(String, String)> {
    const KEEP: &[&str] = &["PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM", "SHELL", "TMPDIR", "XDG_RUNTIME_DIR"];
    // Windows: names are case-insensitive (`Path`), and a child without `SystemRoot` cannot
    // even open a socket; these carry no credentials.
    #[cfg(windows)]
    const KEEP_OS: &[&str] = &["PATH", "SystemRoot", "windir", "SystemDrive", "ComSpec", "PATHEXT", "TEMP", "TMP", "USERPROFILE", "USERNAME", "APPDATA", "LOCALAPPDATA", "ProgramData", "ProgramFiles", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "OS"];
    #[cfg(windows)]
    let keep = |k: &str| KEEP.contains(&k) || KEEP_OS.iter().any(|n| n.eq_ignore_ascii_case(k));
    #[cfg(not(windows))]
    let keep = |k: &str| KEEP.contains(&k);
    std::env::vars().filter(|(k, _)| keep(k) && !secretish(k)).collect()
}

/// The interpreter for a script: `bash` for `.sh` / `.bash`, else `python3` (Unix: those
/// names on `PATH`, as always; Windows: the platform's bash, the Python launcher).
fn interpreter(bash: bool) -> Result<(String, Command), String> {
    #[cfg(windows)]
    {
        if bash {
            let sh = seagent_core::platform::shell::active();
            if sh.kind != seagent_core::platform::shell::ShellKind::Bash {
                return Err(format!("Script execution failed: bash is not available on windows (no Git Bash / MSYS2 found; this machine's shell is {}); use a .py script or install Git for Windows", sh.kind.as_str()));
            }
            return Ok(("bash".into(), seagent_core::platform::proc::command(&sh.program)));
        }
        Ok(("python3".into(), crate::coderun::python_command()))
    }
    #[cfg(not(windows))]
    {
        let interp = if bash { "bash" } else { "python3" };
        Ok((interp.into(), seagent_core::platform::proc::command(interp)))
    }
}

fn secretish(k: &str) -> bool {
    let u = k.to_ascii_uppercase();
    ["KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "API"].iter().any(|w| u.contains(w))
}

/// `(ok, output)`: on failure `output` is the error text for the model / alert.
pub fn run(data: &Path, script: &str, workdir: Option<&Path>, timeout: Duration, redact: &dyn Fn(&str) -> String) -> (bool, String) {
    let path = match resolve(data, script) {
        Ok(p) => p,
        Err(e) => return (false, e),
    };
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    let (interp, mut cmd) = match interpreter(ext == "sh" || ext == "bash") {
        Ok(x) => x,
        Err(e) => return (false, e),
    };
    let cwd = workdir.map(Path::to_path_buf).unwrap_or_else(|| path.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from(".")));
    // Windows: MSYS bash needs `C:/…/x.sh` (no `\\?\`, no backslashes); Unix: the path as is.
    let script_arg = if interp == "bash" { seagent_core::platform::shell::path_arg(&path) } else { path.clone().into_os_string() };
    cmd.arg(&script_arg).current_dir(&cwd).env_clear().envs(scrubbed_env()).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    // Own process group (Windows: a new group plus a Job Object, added by `childproc::spawn`).
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    #[cfg(not(unix))]
    seagent_core::platform::proc::new_group(&mut cmd, false);
    let mut child = match crate::childproc::spawn(&mut cmd) {
        Ok(c) => c,
        Err(e) => return (false, format!("Script execution failed: {interp}: {e}")),
    };
    let mut so = child.stdout.take();
    let mut se = child.stderr.take();
    let t_out = std::thread::spawn(move || {
        let mut b = Vec::new();
        if let Some(s) = so.as_mut() {
            let _ = s.read_to_end(&mut b);
        }
        b
    });
    let t_err = std::thread::spawn(move || {
        let mut b = Vec::new();
        if let Some(s) = se.as_mut() {
            let _ = s.read_to_end(&mut b);
        }
        b
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if start.elapsed() >= timeout => {
                // Whole process group: backgrounded grandchildren die with the script.
                crate::childproc::kill_group_now(child.id() as i32);
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return (false, format!("Script execution failed: {e}")),
        }
    };
    let stdout = redact(String::from_utf8_lossy(&t_out.join().unwrap_or_default()).trim());
    let stderr = redact(String::from_utf8_lossy(&t_err.join().unwrap_or_default()).trim());
    let Some(status) = status else {
        return (false, format!("Script timed out after {}s: {}", timeout.as_secs(), path.display()));
    };
    if !status.success() {
        let mut parts = vec![format!("Script exited with code {}", status.code().map(|c| c.to_string()).unwrap_or_else(|| "signal".into()))];
        if !stderr.is_empty() {
            parts.push(format!("stderr:\n{stderr}"));
        }
        if !stdout.is_empty() {
            parts.push(format!("stdout:\n{stdout}"));
        }
        return (false, parts.join("\n"));
    }
    (true, stdout)
}

/// Hermes `_parse_wake_gate`: false only when the last non-empty stdout line is JSON
/// `{"wakeAgent": false}` (agent skipped, nothing delivered).
pub fn wake_gate(output: &str) -> bool {
    let Some(last) = output.lines().rev().find(|l| !l.trim().is_empty()) else { return true };
    match serde_json::from_str::<serde_json::Value>(last.trim()) {
        Ok(serde_json::Value::Object(o)) => o.get("wakeAgent") != Some(&serde_json::Value::Bool(false)),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data() -> PathBuf {
        let d = seagent_core::tmp::scratch_path(format!("seagent-cronscript-{}", crate::util::random_hex(8)));
        std::fs::create_dir_all(scripts_dir(&d)).unwrap();
        d
    }

    #[test]
    fn paths_are_confined_to_the_scripts_dir() {
        let d = data();
        std::fs::write(scripts_dir(&d).join("ok.sh"), "echo hi").unwrap();
        std::fs::write(d.join("outside.sh"), "echo no").unwrap();
        assert!(validate_for_create(&d, "ok.sh").is_none());
        assert!(validate_for_create(&d, "/etc/passwd").unwrap().contains("must be relative"));
        assert!(validate_for_create(&d, "~/x.sh").unwrap().contains("must be relative"));
        assert!(validate_for_create(&d, "../outside.sh").unwrap().contains("outside the scripts directory"));
        assert!(validate_for_create(&d, "missing.sh").unwrap().contains("Script not found"));
        // Windows: creating a symlink needs Developer Mode / the privilege; skip when refused.
        if crate::util::symlink_file(&d.join("outside.sh"), &scripts_dir(&d).join("link.sh")).is_ok() {
            assert!(resolve(&d, "link.sh").unwrap_err().contains("outside"), "symlink escape");
        }
        assert!(resolve(&d, "a\0b").unwrap_err().contains("NUL"));
        assert!(resolve(&d, &d.join("outside.sh").to_string_lossy()).unwrap_err().contains("outside"), "absolute at run time too");
    }

    #[cfg(unix)]
    #[test]
    fn runs_with_scrubbed_env_timeout_and_redaction() {
        let d = data();
        let s = scripts_dir(&d);
        std::fs::write(s.join("env.sh"), "echo \"key=${OPENAI_API_KEY:-unset}\"; echo token sk-live-123").unwrap();
        std::env::set_var("OPENAI_API_KEY", "sk-should-not-leak");
        let redact = |t: &str| t.replace("sk-live-123", "[REDACTED]");
        let (ok, out) = run(&d, "env.sh", None, Duration::from_secs(10), &redact);
        assert!(ok, "{out}");
        assert!(out.contains("key=unset") && out.contains("[REDACTED]") && !out.contains("sk-"), "{out}");
        std::fs::write(s.join("fail.sh"), "echo partial; echo boom >&2; exit 3").unwrap();
        let (ok, out) = run(&d, "fail.sh", None, Duration::from_secs(10), &|t| t.to_string());
        assert!(!ok);
        assert!(out.starts_with("Script exited with code 3") && out.contains("stderr:\nboom") && out.contains("stdout:\npartial"), "{out}");
        std::fs::write(s.join("slow.sh"), "sleep 30 & sleep 30").unwrap();
        let t0 = Instant::now();
        let (ok, out) = run(&d, "slow.sh", None, Duration::from_millis(300), &|t| t.to_string());
        assert!(!ok && out.contains("timed out"), "{out}");
        assert!(t0.elapsed() < Duration::from_secs(5), "group killed, pipes closed");
        let ws = d.join("wd");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(s.join("pwd.sh"), "pwd").unwrap();
        let (_, out) = run(&d, "pwd.sh", Some(&ws), Duration::from_secs(5), &|t| t.to_string());
        assert!(out.ends_with("/wd"), "{out}");
    }

    #[test]
    fn wake_gate_only_on_explicit_false() {
        assert!(wake_gate(""));
        assert!(wake_gate("data\n{\"wakeAgent\": true}"));
        assert!(!wake_gate("data\n{\"wakeAgent\": false}\n\n"));
        assert!(wake_gate("{\"wakeAgent\": false}\nmore"));
        assert!(wake_gate("not json"));
    }
}
