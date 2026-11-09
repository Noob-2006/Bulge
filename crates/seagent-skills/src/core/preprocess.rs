//! SKILL.md preprocessing (Hermes `agent/skill_preprocessing.py`, MIT): `${SEAGENT_SKILL_DIR}` /
//! `${SEAGENT_SESSION_ID}` template tokens (the `HERMES_` spellings of imported skills work too)
//! and opt-in inline shell `` !`cmd` `` expansion run in the skill directory. Unresolvable
//! tokens stay as written so the author can spot them; one failing snippet becomes an
//! `[inline-shell …]` marker instead of breaking the message. Community hub installs never
//! auto-execute (the install gate refused their inline shell; `--force` must not re-arm it).

use super::settings::Settings;
use regex::Regex;
use std::io::Read;
use std::path::Path;
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Cap inline-shell output so a runaway command can't blow out the context.
pub const INLINE_SHELL_MAX_OUTPUT: usize = 4000;

fn template_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\$\{(SEAGENT|HERMES)_(SKILL_DIR|SESSION_ID)\}").unwrap())
}
fn shell_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"!`([^`\n]+)`").unwrap())
}

pub fn substitute_template_vars(content: &str, skill_dir: Option<&Path>, session: Option<&str>) -> String {
    template_re()
        .replace_all(content, |c: &regex::Captures| {
            let v = match &c[2] {
                // Spelled for the shell that runs the skill's commands (Unix: as is; Windows
                // Git Bash: `C:/…`, whose backslashes it would otherwise eat).
                "SKILL_DIR" => skill_dir.map(seagent_core::platform::shell::path_str),
                _ => session.filter(|s| !s.is_empty()).map(String::from),
            };
            v.unwrap_or_else(|| c[0].to_string())
        })
        .into_owned()
}

/// Keep head and tail of oversized output (`compression_marker.elide`).
pub fn elide(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let half = max / 2;
    let mut a = half;
    while !s.is_char_boundary(a) {
        a -= 1;
    }
    let mut z = s.len() - half;
    while !s.is_char_boundary(z) {
        z += 1;
    }
    format!("{}\n[… {} chars elided …]\n{}", &s[..a], z - a, &s[z..])
}

/// Run one snippet with `bash -c` (Windows: this machine's shell, `seagent_core::platform::shell`);
/// stdout (stderr when stdout is empty), trimmed and capped.
pub fn run_inline_shell(command: &str, cwd: Option<&Path>, timeout: u64) -> String {
    let mut c = seagent_core::platform::shell::command(seagent_core::platform::shell::Style::Bash, command);
    c.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(d) = cwd {
        c.current_dir(d);
    }
    // Skill-author code: scrubbed like the other code-execution surfaces.
    seagent_security::envscrub::apply(&mut c, seagent_security::envscrub::Surface::Code);
    let mut child = match c.spawn() {
        Ok(ch) => ch,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return "[inline-shell error: bash not found]".into(),
        Err(e) => return format!("[inline-shell error: {e}]"),
    };
    let (mut out, mut err) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let ho = std::thread::spawn(move || {
        let mut s = Vec::new();
        let _ = out.read_to_end(&mut s);
        s
    });
    let he = std::thread::spawn(move || {
        let mut s = Vec::new();
        let _ = err.read_to_end(&mut s);
        s
    });
    let deadline = Instant::now() + Duration::from_secs(timeout.max(1));
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return format!("[inline-shell error: {e}]"),
        }
    };
    let Some(status) = status else { return format!("[inline-shell timeout after {timeout}s: {command}]") };
    let stdout = String::from_utf8_lossy(&ho.join().unwrap_or_default()).trim_end_matches('\n').to_string();
    let stderr = String::from_utf8_lossy(&he.join().unwrap_or_default()).trim_end_matches('\n').to_string();
    let output = if stdout.is_empty() { stderr } else { stdout };
    if !status.success() && output.is_empty() {
        return format!("[inline-shell exit {} with no output: {command}]", status.code().unwrap_or(-1));
    }
    elide(&output, INLINE_SHELL_MAX_OUTPUT)
}

pub fn expand_inline_shell(content: &str, skill_dir: Option<&Path>, timeout: u64) -> String {
    if !content.contains("!`") {
        return content.to_string();
    }
    shell_re()
        .replace_all(content, |c: &regex::Captures| {
            let cmd = c[1].trim();
            if cmd.is_empty() {
                String::new()
            } else {
                run_inline_shell(cmd, skill_dir, timeout)
            }
        })
        .into_owned()
}

/// Whether `skill_dir` lies inside a community-trust hub install (provenance from the hub lock
/// of the skills tree that owns it). An unreadable lock fails closed.
pub fn is_community_hub_skill(skill_dir: &Path) -> bool {
    let Ok(target) = skill_dir.canonicalize() else { return false };
    for root in target.ancestors() {
        let lock = root.join(".hub/lock.json");
        if !lock.is_file() {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&lock) else { return true };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else { return true };
        let Some(inst) = v.get("installed").and_then(|i| i.as_object()) else { return true };
        for e in inst.values() {
            let rel = e.get("install_path").and_then(|p| p.as_str()).unwrap_or("");
            if e.get("trust_level").and_then(|t| t.as_str()) == Some("community") && !rel.is_empty() {
                if let Ok(p) = root.join(rel).canonicalize() {
                    if target.starts_with(&p) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Apply the configured template and inline-shell preprocessing.
pub fn preprocess(content: &str, skill_dir: Option<&Path>, session: Option<&str>, s: &Settings) -> String {
    if content.is_empty() {
        return String::new();
    }
    let mut c = content.to_string();
    if s.template_vars {
        c = substitute_template_vars(&c, skill_dir, session);
    }
    if s.inline_shell && !skill_dir.is_some_and(is_community_hub_skill) {
        c = expand_inline_shell(&c, skill_dir, s.inline_shell_timeout);
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_vars_and_inline_shell() {
        let d = seagent_core::tmp::scratch_path(format!("seagent-pre-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let t = substitute_template_vars("run ${SEAGENT_SKILL_DIR}/x.sh in ${HERMES_SESSION_ID}", Some(&d), Some("s1"));
        assert_eq!(t, format!("run {}/x.sh in s1", seagent_core::platform::shell::path_str(&d)));
        assert_eq!(substitute_template_vars("${SEAGENT_SESSION_ID}", None, None), "${SEAGENT_SESSION_ID}", "unresolvable stays");
        let mut s = Settings::from_table(&toml::Table::new());
        assert_eq!(preprocess("today !`echo hi`", Some(&d), None, &s), "today !`echo hi`", "inline shell off by default");
        s.inline_shell = true;
        #[cfg(unix)]
        assert_eq!(preprocess("today !`echo hi` / !`pwd`", Some(&d), None, &s), format!("today hi / {}", d.canonicalize().unwrap().display()));
        // Windows: Git Bash's `pwd` is `/tmp/…`; `pwd -W` names the same directory as `C:/…`.
        #[cfg(windows)]
        assert_eq!(preprocess("today !`echo hi` / !`pwd -W`", Some(&d), None, &s), format!("today hi / {}", seagent_core::platform::shell::path_str(&seagent_core::platform::layout::canonicalize(&d).unwrap())));
        assert_eq!(expand_inline_shell("!`echo err >&2`", None, 5), "err");
        assert!(expand_inline_shell("!`exit 3`", None, 5).contains("[inline-shell exit 3 with no output"));
        assert!(expand_inline_shell("!`sleep 5`", None, 1).contains("timeout after 1s"));
        let big = expand_inline_shell("!`head -c 9000 /dev/zero | tr '\\0' a`", None, 5);
        assert!(big.len() < 4200 && big.contains("elided"));
        // Community hub installs never auto-execute.
        std::fs::create_dir_all(d.join(".hub")).unwrap();
        std::fs::create_dir_all(d.join("evil")).unwrap();
        std::fs::write(d.join(".hub/lock.json"), r#"{"version":1,"installed":{"evil":{"trust_level":"community","install_path":"evil"}}}"#).unwrap();
        assert!(is_community_hub_skill(&d.join("evil")));
        assert_eq!(preprocess("!`echo pwned`", Some(&d.join("evil")), None, &s), "!`echo pwned`");
        std::fs::write(d.join(".hub/lock.json"), "{broken").unwrap();
        assert!(is_community_hub_skill(&d.join("evil")), "unreadable lock fails closed");
        let _ = std::fs::remove_dir_all(&d);
    }
}
