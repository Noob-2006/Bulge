//! `browser_exec` (Hermes `browser_use_cli.py`, MIT): run Python with the Browser Use
//! harness against the session's browser. The code goes on stdin of
//! `browser.exec_command` (default `python3 -m browser_harness.run`) with `BU_CDP_URL`
//! / `BU_CDP_WS` pointing at the browser seagent already drives.

use crate::manager::Env;
use crate::{policy, tools, util};
use seagent_core::ToolCtx;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

pub fn valid_session(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 64 && b[0].is_ascii_alphanumeric() && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-')
}

pub fn call(env: &Env, ctx: &ToolCtx, input: &Value) -> Result<Value, String> {
    let code = input["code"].as_str().filter(|c| !c.trim().is_empty()).ok_or("No code provided. Pass Python code in `code`.")?;
    let session = input["session"].as_str().unwrap_or("default");
    if !valid_session(session) {
        return Err(format!("Invalid session name {session:?} (use [A-Za-z0-9][A-Za-z0-9_-]{{0,63}})"));
    }
    let timeout = input["timeout_s"].as_u64().unwrap_or(300).clamp(5, 1800);
    let urls = regex::Regex::new(r#"https?://[^\s'"`)\]<>]+"#).unwrap();
    for m in urls.find_iter(code) {
        policy::check_navigation(&env.cfg, m.as_str().trim_end_matches(['.', ',', ';']), false)?;
    }
    let (b, _t) = tools::current(env, &ctx.session_id, None)?;
    let ws = b.conn.url().to_string();
    let argv: Vec<String> = if env.cfg.exec_command.is_empty() { vec!["python3".into(), "-m".into(), "browser_harness.run".into()] } else { env.cfg.exec_command.clone() };
    let workspace = env.dir().join("browser-use").join("workspace").join(ctx.session_id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').collect::<String>());
    let _ = std::fs::create_dir_all(&workspace);
    let mut envv: Vec<(String, String)> = vec![("ANONYMIZED_TELEMETRY".into(), "false".into()), ("BU_NAME".into(), session.into()), ("BH_AGENT_WORKSPACE".into(), workspace.display().to_string()), ("BU_CDP_WS".into(), ws.clone()), ("NO_PROXY".into(), "127.0.0.1,localhost".into())];
    if let Some(h) = &b.http {
        envv.push(("BU_CDP_URL".into(), h.clone()));
    }
    let e: Vec<(&str, &str)> = envv.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let a: Vec<&str> = argv.iter().map(String::as_str).collect();
    let start = Instant::now();
    let (rc, stdout, stderr) = util::run(&a, Duration::from_secs(timeout), Some(code.as_bytes()), &e).map_err(|e| {
        if e.contains("timed out") {
            format!("browser-use exec timed out after {timeout}s. Split the work into smaller steps or raise timeout_s (max 1800).")
        } else {
            format!("Failed to launch browser-use CLI: {e}. Install the Browser Use harness (pip install browser-use) or set browser.exec_command.")
        }
    })?;
    let mut out = json!({"success": rc == 0, "exit_code": rc, "output": policy::redact(&stdout), "session": session, "workspace": workspace.display().to_string()});
    if !stderr.trim().is_empty() {
        let s = policy::redact(&stderr);
        out["stderr"] = if s.len() > 4000 { format!("{}… (stderr truncated)", util::cut(&s, 4000)) } else { s }.into();
    }
    let img = regex::Regex::new(r"(/[^\s'\x22]+\.(?:png|jpe?g|webp))").unwrap();
    if let Some(p) = img.find_iter(&stdout).map(|m| m.as_str().to_string()).filter(|p| std::fs::metadata(p).ok().and_then(|m| m.modified().ok()).and_then(|t| t.elapsed().ok()).is_some_and(|el| el <= start.elapsed() + Duration::from_secs(1))).last() {
        out["screenshot_path"] = p.into();
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn session_names() {
        assert!(super::valid_session("work_1-a") && !super::valid_session("-x") && !super::valid_session("a b") && !super::valid_session(""));
    }
}
