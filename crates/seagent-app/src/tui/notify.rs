//! Terminal-native desktop notifications (Hermes `hermes_cli/terminal_notify.py`):
//! OSC 9 (`ESC ] 9 ; body BEL` — Ghostty, iTerm2, Kitty, WezTerm raise an OS notification)
//! plus Warp's structured OSC 777 `warp://cli-agent` protocol when the running Warp build
//! supports it. Sent with a BEL when a turn completes (`bell_on_complete`) or the agent
//! blocks on you (`bell_on_prompt`: approvals, questions). Works over SSH.

use serde_json::json;
use std::collections::HashMap;
use std::io::Write;

const WARP_PROTOCOL_VERSION: i64 = 1;
/// Last Warp release per channel that advertised the protocol but could not render it
/// (compared lexicographically, like Warp's should-use-structured.sh).
const WARP_LAST_BROKEN: &[(&str, &str)] = &[("stable", "v0.2026.03.25.08.24.stable_05"), ("preview", "v0.2026.03.25.08.24.preview_05")];

fn strip_c0(s: &str) -> String {
    s.chars().filter(|c| !(('\0'..='\x1f').contains(c) || *c == '\x7f')).collect()
}

pub fn osc9(body: &str) -> String {
    format!("\x1b]9;{}\x07", strip_c0(body))
}

pub fn warp_supported(env: &HashMap<String, String>) -> bool {
    let get = |k: &str| env.get(k).map(String::as_str).unwrap_or("");
    let client = get("WARP_CLIENT_VERSION");
    if get("TERM_PROGRAM") != "WarpTerminal" || get("WARP_CLI_AGENT_PROTOCOL_VERSION").is_empty() || client.is_empty() {
        return false;
    }
    !WARP_LAST_BROKEN.iter().any(|(ch, last)| client.contains(ch) && client <= *last)
}

/// `event` is `stop` or `permission_request`.
pub fn warp_osc777(env: &HashMap<String, String>, event: &str, detail: &str, session: &str, cwd: &str) -> String {
    let advertised = env.get("WARP_CLI_AGENT_PROTOCOL_VERSION").and_then(|v| v.parse::<i64>().ok()).unwrap_or(1);
    let project = std::path::Path::new(cwd).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let mut p = json!({"v": advertised.min(WARP_PROTOCOL_VERSION), "agent": "seagent", "event": event, "session_id": session, "cwd": cwd, "project": project});
    let key = if event == "permission_request" { "summary" } else { "response" };
    p[key] = json!(detail.chars().take(200).collect::<String>());
    format!("\x1b]777;notify;warp://cli-agent;{}\x07", serde_json::to_string(&p).unwrap_or_default())
}

/// BEL + OSC 9 (+ Warp OSC 777 when supported) for a blocking prompt or a turn end.
pub fn sequence(env: &HashMap<String, String>, context: &str, prompt: bool, session: &str, detail: &str, cwd: &str) -> String {
    let mut s = format!("\x07{}", osc9(&format!("seagent: {context}")));
    if warp_supported(env) {
        s.push_str(&warp_osc777(env, if prompt { "permission_request" } else { "stop" }, if detail.is_empty() { context } else { detail }, session, cwd));
    }
    s
}

/// Write raw escapes to `/dev/tty`, falling back to stdout. Never fails.
pub fn write_tty(seq: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open("/dev/tty") {
        if f.write_all(seq.as_bytes()).is_ok() {
            return;
        }
    }
    let mut o = std::io::stdout();
    let _ = o.write_all(seq.as_bytes());
    let _ = o.flush();
}

pub fn env_map() -> HashMap<String, String> {
    std::env::vars().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osc9_and_warp_payloads() {
        assert_eq!(osc9("done\x07\x1b[31m!"), "\x1b]9;done[31m!\x07");
        let mut env = HashMap::new();
        assert!(!warp_supported(&env));
        env.insert("TERM_PROGRAM".into(), "WarpTerminal".into());
        env.insert("WARP_CLI_AGENT_PROTOCOL_VERSION".into(), "3".into());
        env.insert("WARP_CLIENT_VERSION".into(), "v0.2026.03.25.08.24.stable_05".into());
        assert!(!warp_supported(&env), "known-broken release");
        env.insert("WARP_CLIENT_VERSION".into(), "v0.2026.04.01.00.00.stable_01".into());
        assert!(warp_supported(&env));
        let s = sequence(&env, "turn complete", false, "s1", "", "/home/u/proj");
        assert!(s.starts_with("\x07\x1b]9;seagent: turn complete\x07\x1b]777;notify;warp://cli-agent;"));
        let payload: serde_json::Value = serde_json::from_str(s.rsplit("cli-agent;").next().unwrap().trim_end_matches('\x07')).unwrap();
        assert_eq!(payload["v"], 1);
        assert_eq!(payload["event"], "stop");
        assert_eq!(payload["project"], "proj");
        assert_eq!(payload["response"], "turn complete");
        let p = warp_osc777(&env, "permission_request", &"x".repeat(300), "s", "/");
        assert!(p.contains("\"summary\":\"") && !p.contains(&"x".repeat(201)));
        assert_eq!(sequence(&HashMap::new(), "approval needed", true, "", "", "/"), "\x07\x1b]9;seagent: approval needed\x07");
    }
}
