//! Running the bundled `seagent` binary (desktop: a Tauri sidecar next to the app executable;
//! Android: `libseagent.so` in nativeLibraryDir). No Tauri types here, so it is unit-testable.
//! iOS has no binary to run (the agent is linked in-process, `boot::run`), so most of this is
//! unused there.
//!
//! The CLI surface used (all of it exists in the agent today unless marked PROPOSED):
//! - `seagent setup bootstrap`           → idempotent `[app]` config; stderr has `console: http://…`
//! - `seagent daemon status`             → exit 0 when the daemon answers
//! - `seagent daemon start` / `stop`     → detached daemon (desktop)
//! - `seagent setup link --json`         → `{"url": "http://…/setup#token=…", "expires_ms": …}`,
//!   non-zero exit once setup is done (wizard locked)
//! - `seagent app token`                 → the console token on one line
//! - `seagent pause` / `resume` / `pause status`, `seagent service restart`
//! - PROPOSED `seagent setup status --json` → `{"done": bool, "listen": "…", "console_url": "…"}`
//!   (today `seagent setup status` falls into the interactive wizard, so it is NOT called).
//! - PROPOSED `seagent app token --json`  → `{"token": "…", "url": "http://…"}`, non-zero when unset.

#![cfg_attr(target_os = "ios", allow(dead_code))]

use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Agent {
    pub exe: PathBuf,
    pub env: Vec<(String, OsString)>,
}

#[derive(Debug, Clone)]
pub struct Out {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Out {
    pub fn ok(&self) -> bool {
        self.code == Some(0)
    }
    /// One line for the "details" log.
    pub fn summary(&self, args: &[&str]) -> String {
        let tail = |s: &str| s.lines().rev().take(6).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n    ");
        let mut s = format!("$ seagent {} → exit {}", args.join(" "), self.code.map(|c| c.to_string()).unwrap_or_else(|| "killed".into()));
        if !self.stdout.trim().is_empty() && !args.contains(&"token") && !args.contains(&"link") {
            s.push_str(&format!("\n  stdout: {}", tail(&self.stdout)));
        }
        if !self.stderr.trim().is_empty() {
            s.push_str(&format!("\n  stderr: {}", tail(&self.stderr)));
        }
        s
    }
}

pub const EXE_SUFFIX: &str = std::env::consts::EXE_SUFFIX;

/// Where a sidecar can be: next to the app (bundles: Tauri strips the target triple), or the
/// `binaries/seagent-<triple>` source file during development. `SEAGENT_BIN` overrides both.
pub fn sidecar_candidates(app_exe: &Path, triple: &str) -> Vec<PathBuf> {
    let mut v = vec![];
    if let Some(p) = std::env::var_os("SEAGENT_BIN") {
        v.push(PathBuf::from(p));
    }
    if let Some(dir) = app_exe.parent() {
        v.push(dir.join(format!("seagent{EXE_SUFFIX}")));
        v.push(dir.join(format!("seagent-{triple}{EXE_SUFFIX}")));
        // macOS .app: Contents/MacOS/<app> — the sidecar sits in the same directory (covered above).
    }
    v.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("binaries").join(format!("seagent-{triple}{EXE_SUFFIX}")));
    v
}

impl Agent {
    pub fn locate(app_exe: &Path, triple: &str, share: Option<PathBuf>) -> Result<Agent, String> {
        let tried = sidecar_candidates(app_exe, triple);
        let exe = tried.iter().find(|p| p.is_file()).cloned().ok_or_else(|| format!("the bundled seagent binary is missing (looked in: {})", tried.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")))?;
        let mut env = vec![];
        if let Some(s) = share.filter(|s| s.is_dir()) {
            env.push(("SEAGENT_SHARE_DIR".to_string(), s.into_os_string()));
        }
        Ok(Agent { exe, env })
    }

    /// Point the agent at the VM bundle the installer ships (`<resources>/vm`, staged by
    /// `packaging/vm/bundle.sh`): `SEAGENT_VM_BUNDLE`, read by `seagent_vm::bundle`. Only a
    /// directory that carries a `bundle.json` is passed, so a build without the VM changes nothing.
    pub fn with_vm_bundle(&mut self, dir: Option<PathBuf>) {
        if let Some(d) = dir.filter(|d| d.join("bundle.json").is_file()) {
            self.env.retain(|(k, _)| k != "SEAGENT_VM_BUNDLE");
            self.env.push(("SEAGENT_VM_BUNDLE".to_string(), d.into_os_string()));
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(&self.exe);
        c.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        // Machine-readable output: no colours (stdin is null, so nothing can prompt).
        c.env("NO_COLOR", "1");
        for (k, v) in &self.env {
            c.env(k, v);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            c.creation_flags(CREATE_NO_WINDOW);
        }
        c
    }

    /// Run to completion (killed after `timeout`), capturing both streams.
    pub fn run(&self, args: &[&str], timeout: Duration) -> Result<Out, String> {
        let mut child = self.command(args).spawn().map_err(|e| format!("{}: {e}", self.exe.display()))?;
        let mut so = child.stdout.take();
        let mut se = child.stderr.take();
        let t1 = std::thread::spawn(move || {
            let mut s = String::new();
            if let Some(o) = so.as_mut() {
                let _ = o.take(1 << 20).read_to_string(&mut s);
            }
            s
        });
        let t2 = std::thread::spawn(move || {
            let mut s = String::new();
            if let Some(e) = se.as_mut() {
                let _ = e.take(1 << 20).read_to_string(&mut s);
            }
            s
        });
        let until = Instant::now() + timeout;
        let code = loop {
            match child.try_wait().map_err(|e| e.to_string())? {
                Some(st) => break st.code(),
                None if Instant::now() >= until => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        };
        Ok(Out { code, stdout: t1.join().unwrap_or_default(), stderr: t2.join().unwrap_or_default() })
    }
}

/// `console: http://127.0.0.1:8640` from `seagent setup bootstrap` (stderr).
pub fn parse_console_line(text: &str) -> Option<String> {
    text.lines().find_map(|l| l.trim().strip_prefix("console:").map(|u| u.trim().trim_end_matches('/').to_string())).filter(|u| u.starts_with("http://") || u.starts_with("https://"))
}

/// `[app] enabled on http://127.0.0.1:8640 · …` from `seagent app status`.
pub fn parse_app_status(text: &str) -> Option<String> {
    let i = text.find(" on http")?;
    let rest = &text[i + 4..];
    Some(rest.split_whitespace().next()?.trim_end_matches('/').to_string())
}

/// `{"url": …}` from `seagent setup link --json`; only a loopback/LAN `/setup#token=` URL.
pub fn parse_link_json(stdout: &str) -> Option<String> {
    let v: serde_json::Value = stdout.lines().rev().find_map(|l| serde_json::from_str(l.trim()).ok())?;
    let u = v["url"].as_str()?;
    (u.starts_with("http") && u.contains("/setup#token=")).then(|| u.to_string())
}

/// `{"console_url": "http://127.0.0.1:8641/", …}` from `seagent setup status --json` → the base
/// URL without the trailing slash (the address the daemon really serves).
pub fn parse_status_json(stdout: &str) -> Option<String> {
    let v: serde_json::Value = stdout.lines().rev().find_map(|l| serde_json::from_str(l.trim()).ok())?;
    let u = v["console_url"].as_str()?.trim_end_matches('/');
    (u.starts_with("http://") || u.starts_with("https://")).then(|| u.to_string())
}

/// `seagent app token` prints the token, or (exit 0!) a multi-line how-to when there is none.
pub fn parse_token(stdout: &str) -> Option<String> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(stdout.trim()) {
        return v["token"].as_str().map(String::from).filter(|t| valid_token(t));
    }
    let t = stdout.trim();
    valid_token(t).then(|| t.to_string())
}

/// `http://127.0.0.1:8640/#token=abc&page=x` → `abc` (the console URL the boot opened).
pub fn token_in_url(u: &str) -> Option<String> {
    let frag = u.split_once('#')?.1;
    frag.split('&').find_map(|kv| kv.strip_prefix("token=")).map(String::from).filter(|t| valid_token(t))
}

fn valid_token(t: &str) -> bool {
    t.len() >= 16 && t.len() <= 512 && t.chars().all(|c| c.is_ascii_alphanumeric() || "-_.~+/=".contains(c))
}

/// `http://127.0.0.1:8640` → (`127.0.0.1:8640`, host header).
pub fn host_port(base: &str) -> Option<String> {
    let rest = base.strip_prefix("http://")?;
    let hp = rest.split('/').next()?;
    (!hp.is_empty()).then(|| if hp.contains(':') { hp.to_string() } else { format!("{hp}:80") })
}

/// GET `<base>/health` → 200 within `timeout` (plain HTTP on loopback; std only).
pub fn health(base: &str, timeout: Duration) -> bool {
    use std::io::Write;
    use std::net::{TcpStream, ToSocketAddrs};
    let Some(hp) = host_port(base) else { return false };
    let Some(addr) = hp.to_socket_addrs().ok().and_then(|mut a| a.next()) else { return false };
    let Ok(mut s) = TcpStream::connect_timeout(&addr, timeout) else { return false };
    let _ = s.set_read_timeout(Some(timeout));
    let _ = s.set_write_timeout(Some(timeout));
    if s.write_all(format!("GET /health HTTP/1.0\r\nHost: {hp}\r\nAccept: application/json\r\n\r\n").as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).unwrap_or(0);
    let head = String::from_utf8_lossy(&buf[..n]);
    head.starts_with("HTTP/1.") && head.split_whitespace().nth(1) == Some("200")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cli_output() {
        assert_eq!(parse_console_line("  minted APP_TOKEN (vault)\n  wrote /x/config.toml\n  console: http://127.0.0.1:8640\n").as_deref(), Some("http://127.0.0.1:8640"));
        assert_eq!(parse_console_line("nothing"), None);
        assert_eq!(parse_app_status("[app] enabled on http://127.0.0.1:9000 · ui true · openai api false").as_deref(), Some("http://127.0.0.1:9000"));
        assert_eq!(parse_link_json("{\"url\":\"http://127.0.0.1:8640/setup#token=abc\",\"expires_ms\":1}\n").as_deref(), Some("http://127.0.0.1:8640/setup#token=abc"));
        assert_eq!(parse_link_json("setup is already complete"), None);
        assert_eq!(parse_status_json("{\"console_url\":\"http://127.0.0.1:8641/\",\"done\":false,\"listen\":\"127.0.0.1:8641\"}\n").as_deref(), Some("http://127.0.0.1:8641"));
        assert_eq!(parse_status_json("{\"error\":\"x\"}"), None);
        assert_eq!(parse_token("Zq3_abcdefghijklmnopqrstuv\n").as_deref(), Some("Zq3_abcdefghijklmnopqrstuv"));
        assert_eq!(parse_token("尚未設定 token。最簡單是執行 `seagent setup`；或手動：\n  echo x | seagent secrets set APP_TOKEN"), None);
        assert_eq!(parse_token("{\"token\":\"abcdefghijklmnopqrstuvwxyz\",\"url\":\"http://x\"}").as_deref(), Some("abcdefghijklmnopqrstuvwxyz"));
        assert_eq!(token_in_url("http://127.0.0.1:8640/#token=abcdefghijklmnopqrstuvwxyz&page=logs").as_deref(), Some("abcdefghijklmnopqrstuvwxyz"));
        assert_eq!(token_in_url("http://127.0.0.1:8640/setup#rerun"), None);
        assert_eq!(token_in_url("http://127.0.0.1:8640/"), None);
        assert_eq!(host_port("http://127.0.0.1:8640").as_deref(), Some("127.0.0.1:8640"));
        assert_eq!(host_port("http://[::1]:8640/").as_deref(), Some("[::1]:8640"));
    }

    #[test]
    fn the_vm_bundle_is_handed_to_the_agent_only_when_it_is_there() {
        let base = std::env::temp_dir().join(format!("seagent-desktop-vmbundle-{}", std::process::id()));
        let vm = base.join("vm");
        std::fs::create_dir_all(&vm).unwrap();
        let mut a = Agent { exe: PathBuf::from("seagent"), env: vec![] };
        a.with_vm_bundle(Some(vm.clone()));
        assert!(a.env.is_empty(), "no bundle.json: nothing passed");
        std::fs::write(vm.join("bundle.json"), "{}").unwrap();
        a.with_vm_bundle(Some(vm.clone()));
        a.with_vm_bundle(Some(vm.clone()));
        assert_eq!(a.env, vec![("SEAGENT_VM_BUNDLE".to_string(), vm.clone().into_os_string())], "set once");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn health_against_a_tiny_server() {
        use std::io::Write;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming().take(1) {
                let mut s = s.unwrap();
                let mut b = [0u8; 256];
                let _ = s.read(&mut b);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 11\r\n\r\n{\"ok\":true}");
            }
        });
        assert!(health(&format!("http://127.0.0.1:{port}"), Duration::from_secs(2)));
        assert!(!health("http://127.0.0.1:1", Duration::from_millis(300)));
    }
}
