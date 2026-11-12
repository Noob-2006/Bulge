//! Sandbox browser: Chromium inside a docker container, viewable through noVNC
//! (OpenClaw `src/agents/sandbox/browser.ts` + `sandbox-browser-entrypoint.sh`, MIT).
//! The container publishes CDP (behind a token-checking relay) and noVNC on loopback
//! ports; seagent connects with `Authorization: Basic seagent:<token>`.

use crate::engine::Browser;
use crate::manager::{Env, Manager};
use crate::util;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const CONTRACT_LABEL: &str = "org.seagent.sandbox-browser.contract";
pub const CONTRACT: &str = "2026-11-cdp-relay-auth";

/// Which container CLI the sandbox uses: `SEAGENT_DOCKER`, else `docker`, else `podman`.
/// Linux distributions ship podman far more often than docker, and its CLI is
/// compatible for the five verbs this module needs (`run`, `rm`, `ps`, `port`,
/// `image inspect`). Picking `docker` blindly made the backend invisible on
/// podman-only machines even when `SEAGENT_DOCKER=podman` was set.
fn pick(env: Option<&str>, has_docker: bool, has_podman: bool) -> String {
    match env.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) => v.to_string(),
        None if has_docker => "docker".into(),
        None if has_podman => "podman".into(),
        None => "docker".into(),
    }
}

pub fn docker() -> String {
    let env = std::env::var("SEAGENT_DOCKER").ok();
    pick(env.as_deref(), util::which("docker").is_some(), util::which("podman").is_some())
}

/// Is the container CLI this config would use actually installed?
pub fn available() -> bool {
    util::which(&docker()).is_some()
}

/// Path of that CLI (for `seagent doctor`).
pub fn cli_path() -> Option<std::path::PathBuf> {
    util::which(&docker())
}

fn d(args: &[&str], t: Duration) -> Result<String, String> {
    let bin = docker();
    let mut argv = vec![bin.as_str()];
    argv.extend_from_slice(args);
    let (code, out, err) = util::run(&argv, t, None, &[])?;
    if code != 0 {
        return Err(format!("docker {}: {}", args.first().unwrap_or(&""), err.trim()));
    }
    Ok(out.trim().to_string())
}

fn mapped(name: &str, port: &str) -> Result<u16, String> {
    let out = d(&["port", name, &format!("{port}/tcp")], Duration::from_secs(10))?;
    out.lines().find_map(|l| l.rsplit(':').next()?.trim().parse().ok()).ok_or_else(|| format!("docker port {name} {port}: no mapping in `{out}`"))
}

pub fn start(m: &Manager, env: &Env) -> Result<Arc<Browser>, String> {
    let sc = &env.cfg.sandbox;
    if sc.network == "host" {
        return Err("sandbox browser network \"host\" is blocked (it would expose the host's loopback services)".into());
    }
    let label = d(&["image", "inspect", "--format", &format!("{{{{index .Config.Labels \"{CONTRACT_LABEL}\"}}}}"), &sc.image], Duration::from_secs(20)).map_err(|e| format!("{e}. Build the image with: docker build -t {} packaging/sandbox-browser", sc.image))?;
    if label != CONTRACT {
        return Err(format!("Sandbox browser image {} is stale or incompatible (label {CONTRACT_LABEL}={label:?}, want {CONTRACT}); rebuild it from packaging/sandbox-browser.", sc.image));
    }
    let token = seagent_net::crypto::random_token(24);
    let novnc = sc.novnc && !sc.headless;
    let vnc_pw: String = seagent_net::crypto::random_token(8).chars().filter(|c| c.is_ascii_alphanumeric()).take(8).collect();
    let name = format!("seagent-sbx-browser-{}", seagent_net::crypto::random_token(4).to_ascii_lowercase().replace(['-', '_'], "x"));
    let mut args: Vec<String> = vec!["run".into(), "-d".into(), "--rm".into(), "--init".into(), "--name".into(), name.clone(), "--label".into(), "seagent.sandbox=1".into(), "--network".into(), sc.network.clone(), "-p".into(), "127.0.0.1::9222".into()];
    if novnc {
        args.extend(["-p".into(), "127.0.0.1::6080".into()]);
    }
    for (k, v) in [("SEAGENT_BROWSER_CDP_AUTH_TOKEN", token.as_str()), ("SEAGENT_BROWSER_HEADLESS", if sc.headless { "1" } else { "0" }), ("SEAGENT_BROWSER_ENABLE_NOVNC", if novnc { "1" } else { "0" }), ("SEAGENT_BROWSER_NOVNC_PASSWORD", vnc_pw.as_str()), ("SEAGENT_BROWSER_NO_SANDBOX", "1")] {
        args.extend(["-e".into(), format!("{k}={v}")]);
    }
    args.push(sc.image.clone());
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    d(&a, Duration::from_secs(60))?;
    let cleanup = {
        let name = name.clone();
        move || {
            let _ = d(&["rm", "-f", &name], Duration::from_secs(20));
        }
    };
    let port = match mapped(&name, "9222") {
        Ok(p) => p,
        Err(e) => {
            cleanup();
            return Err(e);
        }
    };
    let auth = format!("Basic {}", seagent_net::crypto::b64(format!("seagent:{token}").as_bytes()));
    let http = format!("http://127.0.0.1:{port}");
    let until = Instant::now() + Duration::from_millis(sc.start_timeout_ms.max(1000));
    let ws = loop {
        if let Ok(ws) = crate::cdp::resolve_ws(&http, Some(&auth), Duration::from_millis(800)) {
            break ws;
        }
        if Instant::now() >= until {
            cleanup();
            return Err(format!("Sandbox browser CDP did not become reachable on 127.0.0.1:{port} within {}ms. The hung container has been forcefully removed.", sc.start_timeout_ms));
        }
        std::thread::sleep(Duration::from_millis(150));
    };
    let conn = crate::cdp::Conn::connect(&ws, &[("Authorization", &auth)], Duration::from_secs(15)).inspect_err(|_| cleanup())?;
    let b = Browser::new("sandbox", "sandbox", conn, Some(http), Some(auth), None, false, env.dir().join("state/sandbox"), env.cfg.command_timeout(), &env.cfg.dialog_policy, env.cfg.dialog_timeout_s, false);
    {
        let mut i = b.info.lock().unwrap();
        i.insert("container".into(), name.clone().into());
        if novnc {
            if let Ok(p) = mapped(&name, "6080") {
                i.insert("novnc_url".into(), format!("http://127.0.0.1:{p}/vnc.html?autoconnect=1&password={vnc_pw}").into());
            }
        }
    }
    *b.on_close.lock().unwrap() = Some(Box::new(cleanup));
    let _ = m;
    Ok(b)
}

#[cfg(test)]
#[cfg_attr(not(unix), allow(dead_code, unused_imports))]
mod tests {
    use super::*;
    use crate::config::BrowserConfig;

    #[test]
    fn the_container_cli_is_seagent_docker_then_docker_then_podman() {
        assert_eq!(pick(Some("podman"), true, true), "podman", "SEAGENT_DOCKER wins");
        assert_eq!(pick(Some("  "), false, true), "podman", "a blank SEAGENT_DOCKER is unset");
        assert_eq!(pick(None, true, true), "docker", "docker stays the default when both exist");
        assert_eq!(pick(None, false, true), "podman", "podman-only machines (most Linux) work without configuration");
        assert_eq!(pick(None, false, false), "docker", "nothing installed: keep docker in the error message");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_host_network_and_stale_images() {
        let dir = seagent_core::tmp::scratch_path(format!("seagent-sbx-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("docker");
        std::fs::write(&fake, "#!/bin/sh\necho \"$@\" >> \"$(dirname \"$0\")/calls\"\ncase \"$1\" in image) echo old-contract ;; esac\n").unwrap();
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::env::set_var("SEAGENT_DOCKER", &fake);
        let mut cfg = BrowserConfig::default();
        let e = Env { cfg: cfg.clone(), home: dir.clone(), secrets: Arc::new(|s: &str| s.to_string()) };
        let m = Manager::default();
        assert!(start(&m, &e).err().unwrap().contains("stale or incompatible"));
        cfg.sandbox.network = "host".into();
        let e = Env { cfg, ..e };
        assert!(start(&m, &e).err().unwrap().contains("blocked"));
        std::env::remove_var("SEAGENT_DOCKER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The image seagent ships in `packaging/sandbox-browser` must match what `start` expects:
    /// the contract label, the relay/noVNC ports, and an `SEAGENT_BROWSER_*` entrypoint that
    /// speaks the same environment contract (no leftover `OPENCLAW_*` names).
    fn packaging_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/sandbox-browser")
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_image_matches_the_contract() {
        let dir = packaging_dir();
        let dockerfile_path = dir.join("Dockerfile");
        let entry_path = dir.join("entrypoint.sh");
        let dockerfile = std::fs::read_to_string(&dockerfile_path)
            .unwrap_or_else(|e| panic!("{}: {e} (the sandbox backend cannot start without it)", dockerfile_path.display()));
        let script = std::fs::read_to_string(&entry_path).unwrap_or_else(|e| panic!("{}: {e}", entry_path.display()));

        let label = format!("LABEL {CONTRACT_LABEL}=\"{CONTRACT}\"");
        assert!(dockerfile.contains(&label), "Dockerfile must stamp `{label}` (the label `start` inspects)");
        assert!(dockerfile.contains("FROM debian:trixie-slim"), "the image is built from debian:trixie-slim");
        assert!(dockerfile.contains("chromium"), "the image must install Chromium");
        assert!(dockerfile.contains("EXPOSE 9222"), "the relay port must be exposed");
        assert!(dockerfile.contains("6080"), "the noVNC port must be exposed");
        assert!(dockerfile.contains("ENTRYPOINT"), "the image needs an ENTRYPOINT");
        assert!(dockerfile.contains("/usr/local/bin/sandbox-browser-entrypoint.sh"), "entrypoint.sh must be installed");
        assert!(!dockerfile.contains("--network host") && !dockerfile.contains("network=host"), "host networking is blocked");

        for needle in ["SEAGENT_BROWSER_CDP_AUTH_TOKEN", "SEAGENT_BROWSER_HEADLESS", "SEAGENT_BROWSER_ENABLE_NOVNC", "SEAGENT_BROWSER_NOVNC_PASSWORD", "SEAGENT_BROWSER_NO_SANDBOX", "9222", "9223", "websockify", "websockify --web=/usr/share/novnc", "Xvfb", "x11vnc"] {
            assert!(script.contains(needle), "entrypoint.sh must mention `{needle}`");
        }
        assert!(script.contains("Basic"), "the relay must gate on HTTP Basic auth");
        assert!(script.contains("401"), "the relay must answer unauthenticated requests with 401");
        assert!(!script.contains("OPENCLAW_"), "entrypoint.sh still carries the upstream OPENCLAW_* contract");
        // The environment `start` passes must all be read here (with a default).
        for needle in ["SEAGENT_BROWSER_CDP_AUTH_TOKEN", "SEAGENT_BROWSER_HEADLESS", "SEAGENT_BROWSER_ENABLE_NOVNC", "SEAGENT_BROWSER_NOVNC_PASSWORD", "SEAGENT_BROWSER_NO_SANDBOX"] {
            assert!(script.contains(&format!("{needle}:-")), "entrypoint.sh must read `{needle}` with a default");
        }

        let path = entry_path.to_str().unwrap();
        match seagent_core::platform::proc::command("bash").args(["-n", path]).output() {
            Ok(out) => assert!(out.status.success(), "bash -n {} failed: {}", entry_path.display(), String::from_utf8_lossy(&out.stderr)),
            Err(_) => return, // no bash on this host: nothing to syntax-check with
        }

        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&entry_path).unwrap().permissions().mode();
        assert_ne!(mode & 0o111, 0, "entrypoint.sh must be executable (mode {:o})", mode);
    }

    /// Fail closed: an unset token must abort the container, not expose Chromium's CDP.
    /// `PATH=/nonexistent` proves the check happens before anything is spawned.
    #[test]
    fn sandbox_entrypoint_fails_closed_without_a_token() {
        let entry = packaging_dir().join("entrypoint.sh");
        if !entry.exists() {
            return;
        }
        // Unix: `bash` from PATH; Windows: Git Bash (never the WSL launcher), path as `C:/…`.
        let Some(bash) = seagent_core::platform::layout::bash() else { return };
        let out = match seagent_core::platform::proc::command(bash).arg(seagent_core::platform::shell::path_arg(&entry)).env_clear().env("PATH", "/nonexistent").env("SEAGENT_BROWSER_CDP_AUTH_TOKEN", "").output() {
            Ok(o) => o,
            Err(_) => return, // no bash on this host
        };
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(!out.status.success(), "entrypoint must fail closed without a token, got success with: {text}");
        assert!(text.to_lowercase().contains("token"), "expected a token warning on stderr, got: {text}");
    }
}
