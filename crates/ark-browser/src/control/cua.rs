//! `ark computer-use install|status|doctor|permissions|screen` (Hermes
//! `hermes_cli/subcommands/computer_use.py`, `tools_config_cua.py`,
//! `tools/computer_use/{cua_backend_driver,doctor,permissions}.py`, MIT).
//!
//! The `computer_use` toolset drives the desktop through trycua's `cua-driver` (stdio MCP).
//! `install` fetches the pinned release (same artifacts and SHA-256 pins as Hermes'
//! `pm/lock.json`) into `<home>/bin/cua-driver`; an explicit `$ARK_CUA_DRIVER_CMD` is
//! externally owned and only validated. `status` checks the driver's runtime contract
//! (`cua-driver manifest`), `doctor` runs its `health_report` MCP tool, `permissions` reports
//! readiness (macOS TCC grants are a macOS concept: on Linux readiness is driver health).

use super::screen::{self, Desktop};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

pub const DRIVER_ENV: &str = "ARK_CUA_DRIVER_CMD";
pub const PINNED_VERSION: &str = "0.21.0";
/// Hermes `_CUA_DRIVER_RUNTIME_CONTRACT_MIN`.
const CONTRACT_MIN: (u64, u64, u64) = (0, 20, 0);
/// Verb → flags the 0.20 contract needs (Hermes `_CUA_DRIVER_RUNTIME_CONTRACT_ARGS`).
const CONTRACT_ARGS: &[(&str, &[&str])] = &[
    ("mcp", &["--grant", "--socket"]),
    (
        "serve",
        &[
            "--approve-capability-manifest",
            "--capability-manifest",
            "--embedded",
            "--permission-mode",
            "--socket",
        ],
    ),
    ("stop", &["--socket"]),
];

/// A downloadable driver build: URL + SHA-256 (Hermes `pm/lock.json` cua-driver 0.21.0).
#[derive(Debug, Clone, PartialEq)]
pub struct Artifact {
    pub url: String,
    pub sha256: String,
}

pub fn pinned_artifact() -> Option<Artifact> {
    let (arch, sha) = match std::env::consts::ARCH {
        "x86_64" => (
            "linux-x86_64",
            "cf29bfaad16737e31e72f38dad2a6424f24b21a4ac2edea885e83cb9d5034135",
        ),
        "aarch64" => (
            "linux-arm64",
            "6b3a308c6741dd8291aad22a308bd2ec8eb52eab64687be007ac86ceaf7e3307",
        ),
        _ => return None,
    };
    if !cfg!(target_os = "linux") {
        return None;
    }
    Some(Artifact { url: format!("https://github.com/trycua/cua/releases/download/cua-driver-rs-v{PINNED_VERSION}/cua-driver-rs-{PINNED_VERSION}-{arch}-binary.tar.gz"), sha256: sha.into() })
}

/// Everything the commands need; fields are injectable for tests.
pub struct Cu {
    pub home: PathBuf,
    /// `$ARK_CUA_DRIVER_CMD` (explicit, externally managed driver).
    pub override_cmd: Option<String>,
    pub artifact: Option<Artifact>,
    /// `[computer_use] backend` (only `cua`/`auto` run cua-driver checks).
    pub backend: String,
    pub desktop: Desktop,
    /// Where the hand-written daemon units live (`$XDG_CONFIG_HOME`, else `~/.config`).
    pub config_home: Option<PathBuf>,
}

/// A systemd user unit / XDG autostart entry whose Exec runs cua-driver (Hermes `cua_daemon_units`).
#[derive(Debug, Clone, PartialEq)]
pub struct DaemonUnit {
    /// `systemd user unit` / `XDG autostart entry`.
    pub kind: &'static str,
    pub unit: String,
    /// The Exec target as written.
    pub target: String,
    /// Does it run `cua-driver serve`?
    pub serve: bool,
    /// Its `--socket` path (`%h` expanded), when it names one.
    pub socket: Option<String>,
}

impl Cu {
    pub fn new(home: &Path, cfg: &toml::Table) -> Cu {
        let backend = cfg
            .get("computer_use")
            .and_then(|v| v.get("backend"))
            .and_then(|v| v.as_str())
            .unwrap_or("auto")
            .to_string();
        let explicit = cfg
            .get("computer_use")
            .and_then(|v| v.get("driver_cmd"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string);
        Cu {
            home: home.to_path_buf(),
            override_cmd: std::env::var(DRIVER_ENV)
                .ok()
                .filter(|s| !s.trim().is_empty())
                .or(explicit),
            artifact: pinned_artifact(),
            backend,
            desktop: Desktop::new(home).with_config(cfg),
            config_home: None,
        }
    }

    /// `$XDG_CONFIG_HOME` (both systemd --user and XDG autostart honour it), else `~/.config`.
    pub fn config_base(&self) -> PathBuf {
        if let Some(c) = &self.config_home {
            return c.clone();
        }
        std::env::var("XDG_CONFIG_HOME")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| ark_core::tool::expand_home("~/.config"))
    }

    /// Every systemd user unit / XDG autostart entry whose Exec runs cua-driver — the hand-written
    /// daemon units Linux relies on (cua-driver ships no managed autostart of its own).
    pub fn daemon_units(&self) -> Vec<DaemonUnit> {
        let base = self.config_base();
        // `%h` in the unit means the user's home (a trailing slash is harmless in the joined path).
        let home = ark_core::tool::expand_home("~/");
        let mut out = vec![];
        for (kind, dir, suffix, key) in [
            (
                "systemd user unit",
                base.join("systemd").join("user"),
                ".service",
                "ExecStart",
            ),
            (
                "XDG autostart entry",
                base.join("autostart"),
                ".desktop",
                "Exec",
            ),
        ] {
            let Ok(rd) = std::fs::read_dir(&dir) else {
                continue;
            };
            let mut names: Vec<String> = rd
                .flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(suffix))
                .collect();
            names.sort();
            for name in names {
                let Ok(text) = std::fs::read_to_string(dir.join(&name)) else {
                    continue;
                };
                for line in text.lines() {
                    let Some(rest) = line.trim().strip_prefix(&format!("{key}=")) else {
                        continue;
                    };
                    let tokens: Vec<&str> = rest.split_whitespace().collect();
                    // The first token is the executable; systemd's prefix modifiers (-, +, :, !)
                    // never start a path.
                    let Some(exe) = tokens.first().filter(|e| e.contains("cua-driver")) else {
                        continue;
                    };
                    let socket = tokens
                        .iter()
                        .position(|t| *t == "--socket")
                        .and_then(|i| tokens.get(i + 1))
                        .map(|s| {
                            ark_core::tool::expand_home(&s.replace("%h", &home.display().to_string()))
                                .display()
                                .to_string()
                        });
                    out.push(DaemonUnit {
                        kind,
                        unit: name.clone(),
                        target: exe.trim_start_matches(['-', '+', ':', '!']).to_string(),
                        serve: tokens[1..].contains(&"serve"),
                        socket,
                    });
                }
            }
        }
        out
    }

    pub fn managed_path(&self) -> PathBuf {
        self.home.join("bin").join("cua-driver")
    }

    /// The driver `computer_use` would run: override, then `<home>/bin/cua-driver`, then PATH.
    pub fn resolve(&self) -> Option<PathBuf> {
        if let Some(o) = &self.override_cmd {
            let p = ark_core::tool::expand_home(o.trim());
            return if p.components().count() > 1 {
                p.is_file().then_some(p)
            } else {
                crate::util::which(o.trim())
            };
        }
        let m = self.managed_path();
        if m.is_file() {
            return Some(m);
        }
        crate::util::which("cua-driver")
    }
}

fn run(bin: &Path, args: &[&str], timeout: Duration) -> Result<(i32, String, String), String> {
    let b = bin.display().to_string();
    let mut argv = vec![b.as_str()];
    argv.extend_from_slice(args);
    crate::util::run(&argv, timeout, None, &[])
}

fn semver(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim().trim_start_matches('v');
    let core = s.split(['-', '+']).next()?;
    let mut it = core.split('.');
    let t = (
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    );
    it.next().is_none().then_some(t)
}

/// Why a parsed manifest fails the contract, or "" when it passes.
pub fn manifest_reason(m: Option<&Value>) -> String {
    let Some(m) = m.filter(|m| m.is_object()) else {
        return "driver manifest is missing or invalid".into();
    };
    let Some(v) = m["binary_version"].as_str().and_then(semver) else {
        return "driver manifest does not report a semantic version".into();
    };
    if v < CONTRACT_MIN {
        return "ark computer use requires cua-driver 0.20.0 or newer".into();
    }
    if !m["mcp_invocation"]["args"]
        .as_array()
        .is_some_and(|a| a.iter().all(Value::is_string))
    {
        return "driver manifest does not provide an MCP launch command".into();
    }
    let advertised = |verb: &str| -> Vec<String> {
        m["subcommands"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|c| c["name"] == verb)
            .flat_map(|c| c["args"].as_array().cloned().unwrap_or_default())
            .filter_map(|a| a["name"].as_str().map(str::to_string))
            .collect()
    };
    let missing: Vec<String> = CONTRACT_ARGS
        .iter()
        .flat_map(|(verb, flags)| {
            let have = advertised(verb);
            flags
                .iter()
                .filter(move |f| !have.iter().any(|h| h == *f))
                .map(move |f| format!("{verb} {f}"))
                .collect::<Vec<_>>()
        })
        .collect();
    if missing.is_empty() {
        String::new()
    } else {
        format!("driver manifest is missing: {}", missing.join(", "))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Contract {
    pub ready: bool,
    pub version: Option<String>,
    pub reason: String,
}

pub fn contract(bin: &Path) -> Contract {
    match run(bin, &["manifest"], Duration::from_secs(5)) {
        Err(e) => Contract {
            ready: false,
            version: None,
            reason: format!("manifest check failed: {e}"),
        },
        Ok((code, out, err)) if code != 0 => Contract {
            ready: false,
            version: None,
            reason: crate::util::cut(
                err.trim()
                    .lines()
                    .last()
                    .or(out.trim().lines().last())
                    .unwrap_or("manifest command failed"),
                200,
            )
            .to_string(),
        },
        Ok((_, out, _)) => {
            let m: Option<Value> = serde_json::from_str(out.trim()).ok();
            let reason = manifest_reason(m.as_ref());
            Contract {
                ready: reason.is_empty(),
                version: m
                    .as_ref()
                    .and_then(|m| m["binary_version"].as_str())
                    .map(str::to_string),
                reason,
            }
        }
    }
}

fn first_line(s: &str) -> String {
    s.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(|l| crate::util::cut(l, 120).to_string())
        .unwrap_or_default()
}

/// Output sink for the commands (CLI prints, tests collect).
pub type Out<'a> = &'a mut dyn screen::Io;

fn other_backend(cu: &Cu, out: Out) -> Option<i32> {
    match cu.backend.as_str() {
        "auto" | "cua" | "" => None,
        b => {
            out.line(&format!(
                "Computer Use backend: {b} — cua-driver checks do not apply to this backend."
            ));
            Some(0)
        }
    }
}

pub fn install(cu: &Cu, upgrade: bool, out: Out) -> i32 {
    let fresh = cu.resolve().is_none();
    let bin = if let Some(o) = &cu.override_cmd {
        match cu.resolve() {
            Some(b) => b,
            None => {
                out.line(&format!(
                    "    {DRIVER_ENV} does not resolve to an executable: {o}"
                ));
                out.line("    Fix or unset the override before running computer-use install.");
                return 1;
            }
        }
    } else {
        let m = cu.managed_path();
        if m.is_file() && !upgrade && contract(&m).ready {
            m
        } else {
            out.line("    Preparing the pinned cua-driver...");
            match fetch(cu) {
                Ok(p) => p,
                Err(e) => {
                    out.line(&format!("    cua-driver preparation failed: {e}"));
                    return 1;
                }
            }
        }
    };
    let c = contract(&bin);
    if !c.ready {
        out.line(&format!(
            "    cua-driver runtime contract is unusable: {}.",
            if c.reason.is_empty() {
                "unknown error"
            } else {
                &c.reason
            }
        ));
        out.line(if cu.override_cmd.is_some() {
            "    Update the binary selected by ARK_CUA_DRIVER_CMD, or unset the override."
        } else {
            "    Run: ark computer-use doctor"
        });
        return 1;
    }
    out.line(&format!(
        "    cua-driver ready: {}.",
        c.version.unwrap_or_else(|| "unknown version".into())
    ));
    if fresh {
        out.line("    Linux: computer_use acts on the Bot Desktop screen when one runs (`ark screen start`), else on $DISPLAY.");
    }
    0
}

/// Download, verify (SHA-256) and unpack the pinned build into `<home>/bin/cua-driver`.
fn fetch(cu: &Cu) -> Result<PathBuf, String> {
    let a = cu
        .artifact
        .clone()
        .ok_or("cua-driver does not publish a build for this platform")?;
    let mut resp = ark_net::http::agent().get(&a.url)
        .call()
        .map_err(|e| format!("download {}: {e}", a.url))?;
    let body = resp
        .body_mut()
        .with_config()
        .limit(256 * 1024 * 1024)
        .read_to_vec()
        .map_err(|e| format!("download {}: {e}", a.url))?;
    let got = ark_net::crypto::hex(&ark_net::crypto::sha256(&body));
    if !got.eq_ignore_ascii_case(&a.sha256) {
        return Err(format!(
            "checksum mismatch for {} (expected {}, got {got})",
            a.url, a.sha256
        ));
    }
    let stage = cu.home.join("pm").join("cua-driver").join(PINNED_VERSION);
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(&stage).map_err(|e| e.to_string())?;
    let tgz = stage.join("download.tar.gz");
    std::fs::write(&tgz, &body).map_err(|e| e.to_string())?;
    let (code, _, err) = crate::util::run(
        &[
            "tar",
            "-xzf",
            &tgz.display().to_string(),
            "-C",
            &stage.display().to_string(),
            "--no-same-owner",
        ],
        Duration::from_secs(120),
        None,
        &[],
    )?;
    let _ = std::fs::remove_file(&tgz);
    if code != 0 {
        return Err(format!("unpacking failed: {}", err.trim()));
    }
    let found = find_file(&stage, "cua-driver", 4).ok_or("the archive has no cua-driver binary")?;
    let dst = cu.managed_path();
    std::fs::create_dir_all(dst.parent().unwrap()).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&dst);
    std::os::unix::fs::symlink(&found, &dst)
        .or_else(|_| std::fs::copy(&found, &dst).map(|_| ()))
        .map_err(|e| e.to_string())?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&found, std::fs::Permissions::from_mode(0o755));
    Ok(dst)
}

fn find_file(dir: &Path, name: &str, depth: u32) -> Option<PathBuf> {
    let rd = std::fs::read_dir(dir).ok()?;
    let mut dirs = vec![];
    for e in rd.flatten() {
        let p = e.path();
        if p.is_file() && p.file_name().is_some_and(|n| n == name) {
            return Some(p);
        }
        if p.is_dir() {
            dirs.push(p);
        }
    }
    if depth == 0 {
        return None;
    }
    dirs.into_iter()
        .find_map(|d| find_file(&d, name, depth - 1))
}

pub fn status(cu: &Cu, out: Out) -> i32 {
    if let Some(rc) = other_backend(cu, out) {
        return rc;
    }
    let Some(path) = cu.resolve() else {
        out.line("cua-driver: not installed");
        out.line("  Run: ark computer-use install");
        return 1;
    };
    let c = contract(&path);
    let origin = if cu.override_cmd.is_some() {
        " [custom binary from ARK_CUA_DRIVER_CMD]"
    } else {
        ""
    };
    let v = c
        .version
        .as_deref()
        .map(first_line)
        .filter(|v| !v.is_empty())
        .map(|v| format!(" ({v})"))
        .unwrap_or_default();
    out.line(&format!(
        "cua-driver: installed at {}{origin}{v}",
        path.display()
    ));
    if !c.ready {
        out.line(&format!(
            "  ⚠ Repair required: {}",
            if c.reason.is_empty() {
                "runtime contract is incomplete"
            } else {
                &c.reason
            }
        ));
        out.line(if cu.override_cmd.is_some() { "    Update the binary selected by ARK_CUA_DRIVER_CMD, or unset the override and run: ark computer-use install --upgrade" } else { "    Run: ark computer-use install" });
        return 1;
    }
    // Linux: a hand-written daemon unit whose `serve` is dead is invisible to the binary contract
    // (the manifest still looks healthy), so probe each unit's socket before calling the install ready.
    let mut rc = 0;
    if cfg!(target_os = "linux") {
        for u in cu.daemon_units() {
            if u.serve && daemon_listening(&path, u.socket.as_deref()) == Some(false) {
                out.line(&format!(
                    "  ✗ Daemon unit {}: no `cua-driver serve` is listening on {}",
                    u.unit,
                    u.socket.as_deref().unwrap_or("the default socket")
                ));
                out.line(&format!(
                    "    Check: systemctl --user status {}  (reinstalling the driver does not start it)",
                    u.unit
                ));
                rc = 1;
            }
        }
    }
    out.line(if cu.override_cmd.is_some() {
        "  ✓ Runtime contract ready (externally managed)."
    } else {
        "  ✓ Runtime contract ready (ark pin)."
    });
    rc
}

/// Is a `cua-driver serve` daemon answering? `cua-driver status [--socket S]` exits 0 only when one
/// does; `None` when the probe itself could not tell (Hermes `cua_daemon_listening`).
pub fn daemon_listening(bin: &Path, socket: Option<&str>) -> Option<bool> {
    let mut args = vec!["status"];
    if let Some(s) = socket {
        args.extend(["--socket", s]);
    }
    match run(bin, &args, Duration::from_secs(3)) {
        Err(_) => None,
        Ok((0, _, _)) => Some(true),
        Ok((_, o, e)) => {
            let said = format!("{o}\n{e}").to_ascii_lowercase();
            said.contains("not running").then_some(false)
        }
    }
}

/// A minimal stdio MCP session with `<driver> mcp` (newline-delimited JSON-RPC).
struct Mcp {
    child: std::process::Child,
    out: BufReader<std::process::ChildStdout>,
}

impl Mcp {
    fn open(bin: &Path) -> Result<Mcp, String> {
        let mut child = Command::new(bin)
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                format!(
                    "cua-driver could not be started from {}: {e}",
                    bin.display()
                )
            })?;
        let out = BufReader::new(child.stdout.take().unwrap());
        Ok(Mcp { child, out })
    }
    fn rpc(&mut self, id: u64, method: &str, params: Value) -> Result<Value, String> {
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let si = self.child.stdin.as_mut().ok_or("stdin closed")?;
        writeln!(si, "{msg}")
            .and_then(|_| si.flush())
            .map_err(|e| e.to_string())?;
        loop {
            let mut line = String::new();
            if self.out.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
                return Err(format!(
                    "cua-driver mcp produced no response for '{method}'"
                ));
            }
            let Ok(v) = serde_json::from_str::<Value>(line.trim()) else {
                return Err(format!(
                    "{method} response was not valid JSON: {}",
                    crate::util::cut(&line, 200)
                ));
            };
            if v.get("id").and_then(Value::as_u64) != Some(id) {
                continue; // notifications
            }
            if let Some(e) = v.get("error") {
                return Err(format!("{method} JSON-RPC error: {e}"));
            }
            return Ok(v.get("result").cloned().unwrap_or(json!({})));
        }
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let until = std::time::Instant::now() + Duration::from_secs(3);
        while std::time::Instant::now() < until {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn valid_report(v: &Value) -> bool {
    v.get("schema_version").is_some() && v.get("overall").is_some() && v["checks"].is_array()
}

/// `health_report` from a tools/call result (structuredContent, or a JSON text block on older drivers).
pub fn extract_report(result: &Value) -> Result<Value, String> {
    let text = || {
        result["content"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|c| c["type"] == "text")
            .filter_map(|c| c["text"].as_str().map(str::to_string))
            .collect::<Vec<_>>()
    };
    if result["isError"] == true {
        return Err(text()
            .into_iter()
            .next()
            .unwrap_or_else(|| "health_report returned isError=true".into()));
    }
    if valid_report(&result["structuredContent"]) {
        return Ok(result["structuredContent"].clone());
    }
    for t in text() {
        if let Ok(v) = serde_json::from_str::<Value>(&t) {
            if valid_report(&v) {
                return Ok(v);
            }
        }
    }
    Err(
        "health_report response carried neither structuredContent nor a parseable JSON text block"
            .into(),
    )
}

fn render(report: &Value, bin: &Path, cli_version: &str) -> Vec<String> {
    let overall = report["overall"].as_str().unwrap_or("?");
    let glyph = match overall {
        "ok" => "✅",
        "degraded" => "⚠️",
        "failed" => "❌",
        _ => "•",
    };
    let rv = report["driver_version"].as_str().unwrap_or("?");
    let hv = if cli_version.is_empty() {
        rv
    } else {
        cli_version
    };
    let mut l = vec![
        format!(
            "{glyph} cua-driver {hv} on {} — {overall}",
            report["platform"].as_str().unwrap_or("?")
        ),
        format!("  binary: {}", bin.display()),
    ];
    if !cli_version.is_empty()
        && rv != "?"
        && !cli_version.contains(rv)
        && !rv.contains(cli_version)
    {
        l.push(format!("  ⚠️ version mismatch: health_report says '{rv}' but binary --version is '{cli_version}'"));
    }
    for c in report["checks"].as_array().into_iter().flatten() {
        let st = c["status"].as_str().unwrap_or("?");
        let g = match st {
            "pass" => "✅",
            "fail" => "❌",
            "skip" => "⏭️",
            "warn" => "⚠️",
            _ => "•",
        };
        l.push(format!(
            "  {g} {}: {}",
            c["name"].as_str().unwrap_or("?"),
            c["message"].as_str().unwrap_or("")
        ));
        if let Some(h) = c["hint"].as_str() {
            l.push(format!("      → {h}"));
        }
        if let Some(d) = c["data"].as_object() {
            for (k, v) in d {
                l.push(format!(
                    "      {k}={}",
                    v.as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| v.to_string())
                ));
            }
        }
    }
    l
}

pub fn doctor(cu: &Cu, include: &[String], skip: &[String], json_out: bool, out: Out) -> i32 {
    if let Some(rc) = other_backend(cu, out) {
        return rc;
    }
    let Some(bin) = cu.resolve() else {
        out.line("cua-driver: not installed (looked for ARK_CUA_DRIVER_CMD, <home>/bin/cua-driver and PATH).\n  Run: ark computer-use install");
        return 2;
    };
    let report = (|| {
        let mut m = Mcp::open(&bin)?;
        m.rpc(1, "initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "ark", "version": env!("CARGO_PKG_VERSION")}}))?;
        let mut args = json!({});
        if !include.is_empty() {
            args["include"] = json!(include);
        }
        if !skip.is_empty() {
            args["skip"] = json!(skip);
        }
        let r = m.rpc(
            2,
            "tools/call",
            json!({"name": "health_report", "arguments": args}),
        )?;
        extract_report(&r)
    })();
    let report = match report {
        Ok(r) => r,
        Err(e) => {
            out.line(&format!("cua-driver health_report failed: {e}"));
            return 2;
        }
    };
    let cli_v = run(&bin, &["--version"], Duration::from_secs(5))
        .map(|(_, o, e)| first_line(if o.trim().is_empty() { &e } else { &o }))
        .unwrap_or_default();
    if json_out {
        let mut p = report.clone();
        p["ark_identity"] =
            json!({"resolved_binary": bin.display().to_string(), "cli_version": cli_v});
        out.line(&serde_json::to_string_pretty(&p).unwrap_or_default());
    } else {
        for l in render(&report, &bin, &cli_v) {
            out.line(&l);
        }
    }
    if report["overall"] == "ok" {
        0
    } else {
        1
    }
}

/// OS-aware readiness (Hermes `computer_use_status`); the key set is the payload contract.
pub fn readiness(cu: &Cu) -> Value {
    readiness_on(cu, std::env::consts::OS)
}

/// [`readiness`] for an explicit `sys.platform` name (tests drive the macOS branch this way).
pub fn readiness_on(cu: &Cu, plat: &str) -> Value {
    let bin = cu.resolve();
    let mut v = json!({"platform": plat, "platform_supported": matches!(plat, "linux" | "macos" | "windows"), "installed": bin.is_some(), "version": null, "ready": null, "can_grant": plat == "macos", "checks": [], "source": null, "error": null, "accessibility": null, "screen_recording": null, "screen_recording_capturable": null});
    let Some(bin) = bin else { return v };
    if let Ok((_, o, _)) = run(&bin, &["--version"], Duration::from_secs(5)) {
        let v1 = first_line(&o);
        if !v1.is_empty() {
            v["version"] = Value::from(v1);
        }
    }
    let doctor = run(&bin, &["doctor", "--json"], Duration::from_secs(12))
        .ok()
        .and_then(|(_, o, _)| serde_json::from_str::<Value>(o.trim()).ok());
    if let Some(d) = &doctor {
        let checks: Vec<Value> = d["probes"].as_array().into_iter().flatten().map(|p| json!({"label": p["label"].as_str().unwrap_or(""), "status": p["status"].as_str().unwrap_or(""), "message": p["message"].as_str().unwrap_or("")})).collect();
        v["checks"] = json!(checks);
    }
    if plat == "macos" {
        // TCC grants attach to cua-driver's own identity; "ready" means both grants are in place.
        match run(
            &bin,
            &["permissions", "status", "--json"],
            Duration::from_secs(10),
        )
        .ok()
        .and_then(|(_, o, _)| serde_json::from_str::<Value>(o.trim()).ok())
        {
            Some(d) => {
                for k in ["accessibility", "screen_recording", "screen_recording_capturable"] {
                    if d[k].is_boolean() {
                        v[k] = d[k].clone();
                    }
                }
                if d["source"].is_object() {
                    v["source"] = d["source"].clone();
                }
                v["ready"] = json!(v["accessibility"] == true && v["screen_recording"] == true);
            }
            None => v["error"] = json!("cua-driver permissions status gave no report"),
        }
    } else if doctor.is_some() {
        v["ready"] = json!(doctor.as_ref().unwrap()["ok"].as_bool().unwrap_or(false));
    }
    v
}

fn glyph(v: &Value) -> &'static str {
    match v {
        Value::Bool(true) => "✅",
        Value::Bool(false) => "❌",
        _ => "•",
    }
}

/// Recovery text for grants the daemon reports missing while System Settings shows CuaDriver ON
/// (a grant written for an earlier build stops matching after a driver update).
pub fn stale_tcc_hint(missing: &[&str]) -> String {
    let svc = |f: &str| match f {
        "accessibility" => Some("Accessibility"),
        "screen_recording" => Some("ScreenCapture"),
        _ => None,
    };
    let resets: Vec<String> = missing
        .iter()
        .filter_map(|f| svc(f))
        .map(|s| format!("tccutil reset {s} com.trycua.driver"))
        .collect();
    if resets.is_empty() {
        return String::new();
    }
    format!("If System Settings already shows CuaDriver ON, the stored grant is stale (it no longer matches the installed driver's signature): run `{}`, then `ark computer-use permissions grant`.", resets.join(" && "))
}

/// The human-readable `permissions status` body (after the version line).
pub fn permissions_lines(st: &Value) -> Vec<String> {
    let mut l = vec![];
    if st["can_grant"] == true {
        l.push(format!("  {} Accessibility", glyph(&st["accessibility"])));
        l.push(format!("  {} Screen Recording", glyph(&st["screen_recording"])));
        if st["ready"] != true {
            l.push("  Grant: ark computer-use permissions grant".into());
            let missing: Vec<&str> = ["accessibility", "screen_recording"]
                .into_iter()
                .filter(|f| st[*f] == false)
                .collect();
            let hint = stale_tcc_hint(&missing);
            if !hint.is_empty() {
                l.push(format!("  {hint}"));
            }
        }
    } else {
        l.push(format!(
            "  {} driver health (no permission toggles on {})",
            glyph(&st["ready"]),
            st["platform"].as_str().unwrap_or("?")
        ));
    }
    for c in st["checks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| c["status"] != "ok")
    {
        l.push(format!(
            "  ⚠ {}: {}",
            c["label"].as_str().unwrap_or(""),
            c["message"].as_str().unwrap_or("")
        ));
    }
    if let Some(e) = st["error"].as_str() {
        l.push(format!("  ⚠ {e}"));
    }
    l
}

pub fn permissions(cu: &Cu, args: &[String], out: Out) -> i32 {
    match args.first().map(String::as_str) {
        Some("status") => {
            let json_out = args.iter().any(|a| a == "--json");
            if !json_out {
                if let Some(rc) = other_backend(cu, out) {
                    return rc;
                }
            }
            let st = readiness(cu);
            if json_out {
                out.line(&serde_json::to_string_pretty(&st).unwrap_or_default());
                return if st["ready"] == true { 0 } else { 1 };
            }
            if st["platform_supported"] != true {
                out.line(&format!(
                    "Computer Use is not supported on {}.",
                    st["platform"].as_str().unwrap_or("?")
                ));
                return 1;
            }
            if st["installed"] != true {
                out.line("cua-driver: not installed. Run: ark computer-use install");
                return 1;
            }
            out.line(&format!(
                "cua-driver: {} ({})",
                st["version"].as_str().unwrap_or("installed"),
                st["platform"].as_str().unwrap_or("?")
            ));
            for l in permissions_lines(&st) {
                out.line(&l);
            }
            if st["ready"] == true {
                0
            } else {
                1
            }
        }
        Some("grant") => {
            if let Some(rc) = other_backend(cu, out) {
                return rc;
            }
            // TCC grants exist only on macOS (attached to CuaDriver.app's identity).
            out.line("Computer Use permissions are a macOS concept; nothing to grant here.");
            64
        }
        _ => {
            out.line("usage: ark computer-use permissions <status [--json] | grant>");
            // Bare `permissions` prints the help and succeeds (Hermes `_cu_permissions`); an unknown
            // action is a parser error.
            if args.is_empty() {
                0
            } else {
                2
            }
        }
    }
}

pub const HELP: &str = "usage: ark computer-use <install [--upgrade] | status | doctor [--include C] [--skip C] [--json] | permissions <status|grant> | screen …>\n\nInstall or check the cua-driver binary used by the computer_use toolset.\n  install      fetch the pinned cua-driver (or validate ARK_CUA_DRIVER_CMD)\n  status       check the selected driver and its runtime contract\n  doctor       run cua-driver's health_report and show its check matrix\n  permissions  report readiness (macOS: Accessibility + Screen Recording)\n  screen       the headless Bot Desktop screen (see `ark screen`)";

/// `ark computer-use …`: exit code; output through `out`.
pub fn computer_use_cli(cu: &Cu, args: &[String], out: Out) -> i32 {
    let rest = args.get(1..).unwrap_or(&[]);
    match args.first().map(String::as_str) {
        Some("install") => install(cu, rest.iter().any(|a| a == "--upgrade"), out),
        Some("status") => status(cu, out),
        Some("doctor") => {
            let mut inc = vec![];
            let mut skip = vec![];
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--include" if i + 1 < rest.len() => {
                        inc.push(rest[i + 1].clone());
                        i += 1;
                    }
                    "--skip" if i + 1 < rest.len() => {
                        skip.push(rest[i + 1].clone());
                        i += 1;
                    }
                    _ => {}
                }
                i += 1;
            }
            doctor(cu, &inc, &skip, rest.iter().any(|a| a == "--json"), out)
        }
        Some("permissions") => permissions(cu, rest, out),
        Some("screen") => screen::screen_cli(&cu.desktop, rest, out),
        // Bare `ark computer-use` prints the help and succeeds (Hermes `cmd_computer_use`); an unknown
        // subcommand is a parser error, exit 2.
        None => {
            out.line(HELP);
            0
        }
        _ => {
            out.line(HELP);
            2
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::screen::Collect;

    const MANIFEST: &str = r#"{"binary_version":"0.21.0","mcp_invocation":{"command":"cua-driver","args":["mcp"]},"subcommands":[{"name":"mcp","args":[{"name":"--socket"},{"name":"--grant"}]},{"name":"serve","args":[{"name":"--socket"},{"name":"--permission-mode"},{"name":"--capability-manifest"},{"name":"--approve-capability-manifest"},{"name":"--embedded"}]},{"name":"stop","args":[{"name":"--socket"}]}]}"#;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ark-cua-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A fake cua-driver: manifest / --version / doctor --json / a stdio MCP server.
    fn fake_driver(path: &Path, manifest: &str, overall: &str) {
        use std::os::unix::fs::PermissionsExt;
        let report = format!(
            r#"{{"schema_version":1,"platform":"linux","driver_version":"0.21.0","overall":"{overall}","checks":[{{"name":"display","status":"pass","message":"X11 :22"}},{{"name":"screenshot_probe","status":"{}","message":"probe","hint":"start the screen"}}]}}"#,
            if overall == "ok" { "pass" } else { "fail" }
        );
        let script = format!(
            "#!/bin/sh\ncase \"$1\" in\n manifest) echo '{manifest}';;\n --version) echo 'cua-driver 0.21.0';;\n doctor) echo '{{\"ok\":{ok},\"probes\":[{{\"label\":\"X11\",\"status\":\"{st}\",\"message\":\"m\"}}]}}';;\n mcp) while read line; do id=$(echo \"$line\" | sed 's/.*\"id\":\\([0-9]*\\).*/\\1/'); case \"$line\" in *initialize*) echo '{{\"jsonrpc\":\"2.0\",\"id\":'$id',\"result\":{{\"serverInfo\":{{\"version\":\"0.21.0\"}}}}}}';; *health_report*) echo \"$line\" > \"$0.args\"; echo '{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/x\"}}'; echo '{{\"jsonrpc\":\"2.0\",\"id\":'$id',\"result\":{{\"structuredContent\":{report}}}}}';; esac; done;;\nesac\n",
            ok = overall == "ok",
            st = if overall == "ok" { "ok" } else { "fail" }
        );
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, script).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn cu(home: &Path) -> Cu {
        Cu {
            home: home.into(),
            override_cmd: None,
            artifact: None,
            backend: "auto".into(),
            desktop: Desktop::new(home),
            config_home: Some(home.join("xdg-config")),
        }
    }

    #[test]
    fn manifest_contract_rules() {
        let ok: Value = serde_json::from_str(MANIFEST).unwrap();
        assert_eq!(manifest_reason(Some(&ok)), "");
        assert_eq!(
            manifest_reason(None),
            "driver manifest is missing or invalid"
        );
        let mut old = ok.clone();
        old["binary_version"] = json!("0.19.9");
        assert!(manifest_reason(Some(&old)).contains("0.20.0 or newer"));
        let mut nov = ok.clone();
        nov["binary_version"] = json!("latest");
        assert!(manifest_reason(Some(&nov)).contains("semantic version"));
        let mut gap = ok.clone();
        gap["subcommands"][2]["args"] = json!([]);
        assert_eq!(
            manifest_reason(Some(&gap)),
            "driver manifest is missing: stop --socket"
        );
        assert_eq!(semver("v0.21.0-beta"), Some((0, 21, 0)));
    }

    #[test]
    fn status_doctor_permissions_with_fake_driver() {
        let home = scratch("status");
        let c = cu(&home);
        let mut o = Collect::default();
        assert_eq!(computer_use_cli(&c, &["status".into()], &mut o), 1);
        assert_eq!(
            o.0,
            vec![
                "cua-driver: not installed",
                "  Run: ark computer-use install"
            ]
        );
        let mut o = Collect::default();
        assert_eq!(computer_use_cli(&c, &["doctor".into()], &mut o), 2);
        fake_driver(&c.managed_path(), MANIFEST, "ok");
        let mut o = Collect::default();
        assert_eq!(
            computer_use_cli(&c, &["status".into()], &mut o),
            0,
            "{:?}",
            o.0
        );
        assert!(
            o.0[0].contains("installed at")
                && o.0[0].contains("(0.21.0)")
                && o.0[1].contains("ark pin"),
            "{:?}",
            o.0
        );
        let mut o = Collect::default();
        assert_eq!(
            computer_use_cli(
                &c,
                &["doctor".into(), "--include".into(), "display".into()],
                &mut o
            ),
            0,
            "{:?}",
            o.0
        );
        assert!(
            o.0[0].starts_with("✅ cua-driver cua-driver 0.21.0 on linux — ok"),
            "{:?}",
            o.0
        );
        assert!(o.0.iter().any(|l| l.contains("display: X11 :22")));
        let args = std::fs::read_to_string(c.managed_path().with_extension("args")).unwrap();
        assert!(args.contains(r#""include":["display"]"#), "{args}");
        let mut o = Collect::default();
        assert_eq!(
            computer_use_cli(&c, &["doctor".into(), "--json".into()], &mut o),
            0
        );
        let v: Value = serde_json::from_str(&o.0.join("\n")).unwrap();
        assert_eq!(v["overall"], "ok");
        assert!(v["ark_identity"]["resolved_binary"]
            .as_str()
            .unwrap()
            .ends_with("cua-driver"));
        let mut o = Collect::default();
        assert_eq!(
            computer_use_cli(&c, &["permissions".into(), "status".into()], &mut o),
            0,
            "{:?}",
            o.0
        );
        assert!(o.0[1].contains("✅ driver health"));
        let mut o = Collect::default();
        assert_eq!(
            computer_use_cli(&c, &["permissions".into(), "grant".into()], &mut o),
            64
        );
        assert!(o.0[0].contains("macOS concept"));
        // degraded driver → doctor exit 1, permissions not ready.
        fake_driver(&c.managed_path(), MANIFEST, "degraded");
        let mut o = Collect::default();
        assert_eq!(computer_use_cli(&c, &["doctor".into()], &mut o), 1);
        assert!(o.0.iter().any(|l| l.contains("→ start the screen")));
        let mut o = Collect::default();
        assert_eq!(
            computer_use_cli(
                &c,
                &["permissions".into(), "status".into(), "--json".into()],
                &mut o
            ),
            1
        );
        // an old driver fails the contract.
        fake_driver(
            &c.managed_path(),
            &MANIFEST.replace("0.21.0", "0.10.2"),
            "ok",
        );
        let mut o = Collect::default();
        assert_eq!(computer_use_cli(&c, &["status".into()], &mut o), 1);
        assert!(
            o.0[1].contains("Repair required") && o.0[1].contains("0.20.0"),
            "{:?}",
            o.0
        );
        // another backend: cua checks do not apply.
        let mut other = cu(&home);
        other.backend = "xdotool".into();
        let mut o = Collect::default();
        assert_eq!(computer_use_cli(&other, &["status".into()], &mut o), 0);
        assert!(o.0[0].contains("do not apply"));
        let mut o = Collect::default();
        assert_eq!(computer_use_cli(&c, &[], &mut o), 0, "bare → help, success");
        assert!(o.0[0].starts_with("usage: ark computer-use"));
        let mut o = Collect::default();
        assert_eq!(computer_use_cli(&c, &["bogus".into()], &mut o), 2);
        let mut o = Collect::default();
        assert_eq!(computer_use_cli(&c, &["permissions".into()], &mut o), 0, "bare permissions → help");
        let mut o = Collect::default();
        assert_eq!(
            computer_use_cli(&c, &["permissions".into(), "bogus".into()], &mut o),
            2
        );
        let mut o = Collect::default();
        assert_eq!(
            computer_use_cli(&c, &["screen".into(), "help".into()], &mut o),
            2,
            "screen delegates"
        );
        let mut o = Collect::default();
        assert_eq!(
            computer_use_cli(&c, &["screen".into()], &mut o),
            0,
            "bare `computer-use screen` → screen help, success"
        );
        assert!(o.0[0].starts_with("usage: ark screen"));
    }

    /// A fake driver whose `status` reports a dead daemon (what a crashed `cua-driver serve` says).
    fn fake_dead_daemon(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let script = format!(
            "#!/bin/sh\ncase \"$1\" in\n manifest) echo '{MANIFEST}';;\n --version) echo 'cua-driver 0.21.0';;\n status) echo 'cua-driver: daemon not running' >&2; exit 1;;\n *) exit 0;;\nesac\n"
        );
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, script).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn linux_daemon_units_are_probed_by_status() {
        let home = scratch("daemon");
        let c = cu(&home);
        fake_driver(&c.managed_path(), MANIFEST, "ok");
        let base = c.config_base();
        let units = base.join("systemd").join("user");
        std::fs::create_dir_all(&units).unwrap();
        std::fs::write(
            units.join("cua-driver.service"),
            "[Service]\nExecStart=%h/bin/cua-driver serve --socket %h/.cua/driver.sock\n",
        )
        .unwrap();
        std::fs::write(units.join("unrelated.service"), "[Service]\nExecStart=/usr/bin/true\n").unwrap();
        std::fs::create_dir_all(base.join("autostart")).unwrap();
        std::fs::write(
            base.join("autostart/cua-mcp.desktop"),
            "[Desktop Entry]\nExec=cua-driver mcp\n",
        )
        .unwrap();
        let u = c.daemon_units();
        assert_eq!(u.len(), 2, "{u:?}");
        assert_eq!(u[0].kind, "systemd user unit");
        assert_eq!(u[0].unit, "cua-driver.service");
        assert!(u[0].serve && u[0].target.ends_with("cua-driver"));
        assert!(
            u[0].socket.as_deref().is_some_and(|s| s.ends_with(".cua/driver.sock")),
            "{:?}",
            u[0]
        );
        assert!(!u[1].serve && u[1].socket.is_none());
        // This driver answers `status` with 0 → the daemon is up: the contract is all there is to report.
        let mut o = Collect::default();
        assert_eq!(computer_use_cli(&c, &["status".into()], &mut o), 0, "{:?}", o.0);
        assert!(o.0.last().unwrap().contains("ark pin"));
        // A dead `serve` is invisible to the manifest check, so status has to catch it (exit 1).
        fake_dead_daemon(&c.managed_path());
        let mut o = Collect::default();
        assert_eq!(computer_use_cli(&c, &["status".into()], &mut o), 1, "{:?}", o.0);
        assert!(
            o.0.iter().any(|l| l.contains("✗ Daemon unit cua-driver.service")
                && l.contains(".cua/driver.sock")),
            "{:?}",
            o.0
        );
        assert!(o.0.iter().any(|l| l.contains("systemctl --user status cua-driver.service")));
        assert!(o.0.last().unwrap().contains("ark pin"));
    }

    #[test]
    fn macos_readiness_folds_tcc_grants() {
        use std::os::unix::fs::PermissionsExt;
        let home = scratch("mac");
        let c = cu(&home);
        let script = "#!/bin/sh\ncase \"$1\" in\n --version) echo 'cua-driver 0.21.0';;\n doctor) echo '{\"ok\":true,\"probes\":[]}';;\n permissions) echo '{\"accessibility\":false,\"screen_recording\":true,\"screen_recording_capturable\":false,\"source\":{\"kind\":\"tcc\"}}';;\nesac\n";
        std::fs::create_dir_all(c.managed_path().parent().unwrap()).unwrap();
        std::fs::write(c.managed_path(), script).unwrap();
        std::fs::set_permissions(c.managed_path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let st = readiness_on(&c, "macos");
        assert_eq!(st["can_grant"], true, "{st}");
        assert_eq!(st["accessibility"], false);
        assert_eq!(st["screen_recording"], true);
        assert_eq!(st["ready"], false, "both grants are required");
        assert!(st["source"].is_object());
        assert_eq!(st["screen_recording_capturable"], false);
        let l = permissions_lines(&st);
        assert!(l[0].contains("❌ Accessibility"), "{l:?}");
        assert!(l[1].contains("✅ Screen Recording"), "{l:?}");
        assert!(l.iter().any(|x| x.contains("ark computer-use permissions grant")));
        assert!(
            l.iter().any(|x| x.contains("tccutil reset Accessibility com.trycua.driver")),
            "{l:?}"
        );
        assert!(!l.iter().any(|x| x.contains("ScreenCapture")), "only the missing grant is named");
        // Off macOS there are no TCC rows: readiness is driver health.
        let linux = json!({"platform":"linux","ready":true,"can_grant":false,"checks":[{"label":"X11","status":"ok","message":"m"}]});
        assert!(permissions_lines(&linux)[0].contains("✅ driver health"));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn install_downloads_verifies_and_unpacks() {
        let home = scratch("install");
        // Build a release-shaped tarball: cua-driver-rs-0.21.0/cua-driver.
        let src = home.join("src/cua-driver-rs-0.21.0");
        fake_driver(&src.join("cua-driver"), MANIFEST, "ok");
        let tgz = home.join("rel.tar.gz");
        assert!(Command::new("tar")
            .args([
                "-czf",
                &tgz.display().to_string(),
                "-C",
                &home.join("src").display().to_string(),
                "cua-driver-rs-0.21.0"
            ])
            .status()
            .unwrap()
            .success());
        let body = std::fs::read(&tgz).unwrap();
        let sha = ark_net::crypto::hex(&ark_net::crypto::sha256(&body));
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/rel.tar.gz", l.local_addr().unwrap());
        std::thread::spawn(move || {
            for s in l.incoming().take(2) {
                let mut s = s.unwrap();
                let mut buf = [0u8; 4096];
                let _ = std::io::Read::read(&mut s, &mut buf);
                let _ = s.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                );
                let _ = s.write_all(&body);
            }
        });
        let mut c = cu(&home);
        c.artifact = Some(Artifact {
            url: url.clone(),
            sha256: "00".repeat(32),
        });
        let mut o = Collect::default();
        assert_eq!(install(&c, false, &mut o), 1);
        assert!(
            o.0.iter().any(|l| l.contains("checksum mismatch")),
            "{:?}",
            o.0
        );
        c.artifact = Some(Artifact { url, sha256: sha });
        let mut o = Collect::default();
        assert_eq!(install(&c, false, &mut o), 0, "{:?}", o.0);
        assert!(o.0.iter().any(|l| l.contains("cua-driver ready: 0.21.0")));
        assert!(c.managed_path().exists());
        assert_eq!(c.resolve().unwrap(), c.managed_path());
        // Re-running without --upgrade keeps the ready driver (no download).
        let mut o = Collect::default();
        assert_eq!(install(&c, false, &mut o), 0);
        assert!(!o.0.iter().any(|l| l.contains("Preparing")));
        // A bad override is reported, never replaced.
        let mut bad = cu(&home);
        bad.override_cmd = Some("/nonexistent/cua-driver".into());
        let mut o = Collect::default();
        assert_eq!(install(&bad, false, &mut o), 1);
        assert!(o.0[0].contains("does not resolve"));
        assert!(pinned_artifact()
            .is_none_or(|a| a.url.contains("cua-driver-rs-v0.21.0") && a.sha256.len() == 64));
    }
}
