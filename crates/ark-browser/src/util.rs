//! Small helpers shared by the browser modules.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Longest prefix of `s` with at most `n` bytes, on a char boundary.
pub fn cut(s: &str, n: usize) -> &str {
    if s.len() <= n {
        return s;
    }
    let mut i = n;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    &s[..i]
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

pub fn now_s() -> f64 {
    now_ms() as f64 / 1000.0
}

pub fn which(bin: &str) -> Option<PathBuf> {
    if bin.contains('/') {
        let p = PathBuf::from(bin);
        return p.is_file().then_some(p);
    }
    std::env::var_os("PATH").and_then(|p| std::env::split_paths(&p).map(|d| d.join(bin)).find(|f| f.is_file()))
}

/// Create a directory readable only by the owner.
pub fn private_dir(p: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(p)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
}

/// Write a file atomically with mode 0600.
pub fn write_private(p: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = p.with_extension(format!("tmp{}", std::process::id()));
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, p)
}

/// Run a command with a timeout; Ok((status, stdout, stderr)).
pub fn run(argv: &[&str], timeout: Duration, stdin: Option<&[u8]>, env: &[(&str, &str)]) -> Result<(i32, String, String), String> {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    let (bin, args) = argv.split_first().ok_or("empty command")?;
    let mut cmd = Command::new(bin);
    cmd.args(args).stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().map_err(|e| format!("{bin}: {e}"))?;
    if let (Some(data), Some(mut si)) = (stdin, child.stdin.take()) {
        let data = data.to_vec();
        std::thread::spawn(move || {
            let _ = si.write_all(&data);
        });
    }
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let ho = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = so.read_to_end(&mut b);
        b
    });
    let he = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = se.read_to_end(&mut b);
        b
    });
    let until = std::time::Instant::now() + timeout;
    let status = loop {
        if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
            break s;
        }
        if std::time::Instant::now() >= until {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{bin} timed out after {}s", timeout.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let out = String::from_utf8_lossy(&ho.join().unwrap_or_default()).into_owned();
    let err = String::from_utf8_lossy(&he.join().unwrap_or_default()).into_owned();
    Ok((status.code().unwrap_or(-1), out, err))
}

/// A free loopback TCP port.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).map(|a| a.port()).unwrap_or(0)
}

/// Is a process alive (and not a zombie)?
pub fn pid_alive(pid: i32) -> bool {
    if pid <= 0 || unsafe { libc::kill(pid, 0) } != 0 {
        return false;
    }
    !std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| s.rsplit(')').next().is_some_and(|r| r.trim_start().starts_with('Z')))
}

/// Terminate a process group: TERM, then KILL after `grace`.
pub fn kill_group(pgid: i32, grace: Duration) {
    if pgid <= 1 {
        return;
    }
    unsafe { libc::kill(-pgid, libc::SIGTERM) };
    let until = std::time::Instant::now() + grace;
    while std::time::Instant::now() < until && pid_alive(pgid) {
        std::thread::sleep(Duration::from_millis(50));
    }
    unsafe { libc::kill(-pgid, libc::SIGKILL) };
}

/// Remove files matching `prefix*` in `dir` older than `age` (screenshot/recording cleanup).
pub fn prune(dir: &Path, prefix: &str, age: Duration) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if !name.starts_with(prefix) {
            continue;
        }
        if e.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|el| el > age) {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Keep at most `n` newest files with `prefix` in `dir`.
pub fn keep_newest(dir: &Path, prefix: &str, n: usize) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut v: Vec<(SystemTime, PathBuf)> = rd.flatten().filter(|e| e.file_name().to_string_lossy().starts_with(prefix)).filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path()))).collect();
    v.sort();
    let extra = v.len().saturating_sub(n);
    for (_, p) in v.into_iter().take(extra) {
        let _ = std::fs::remove_file(p);
    }
}

pub fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(cut("héllo", 2), "h");
        let (code, out, _) = run(&["sh", "-c", "read x; echo got $x"], Duration::from_secs(5), Some(b"hi\n"), &[]).unwrap();
        assert_eq!((code, out.trim()), (0, "got hi"));
        assert!(run(&["sleep", "5"], Duration::from_millis(200), None, &[]).unwrap_err().contains("timed out"));
        assert!(pid_alive(std::process::id() as i32) && !pid_alive(0));
        assert!(free_port() > 0);
    }
}
