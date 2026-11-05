//! Sudo password plumbing for the shell tool (Hermes `tools/terminal_tool_sudo.py`).
//!
//! Command-position `sudo` words (found by a quote-aware shell scanner, following `env`
//! options and leading `VAR=value` assignments) are rewritten to `sudo -S -p ''` when a
//! password is available, and the caller prepends one password line per invocation to the
//! child's stdin (`sudo -S` consumes exactly one line each). Password sources, in order: the
//! vault secret named by `exec.sudo_password_secret` (default `SUDO_PASSWORD`), the process
//! environment variable of that name, then a per-session cache. Without a password the
//! command runs unchanged and fails with sudo's own "a password is required"; headless
//! sessions then get a tip on how to configure one. A rejected cached password is dropped.

use std::collections::HashMap;
use std::sync::Mutex;

/// One shell token starting at `start`: quoted runs (unterminated allowed; backslash escapes
/// in double quotes), backslash escapes, or any char that is not whitespace or `;|&()`.
fn read_token(cmd: &[char], start: usize) -> usize {
    let n = cmd.len();
    let mut i = start;
    while i < n {
        let c = cmd[i];
        if c == '\'' {
            i += 1;
            while i < n && cmd[i] != '\'' {
                i += 1;
            }
            if i < n {
                i += 1;
            }
        } else if c == '"' {
            i += 1;
            while i < n && cmd[i] != '"' {
                if cmd[i] == '\\' && i + 1 < n {
                    i += 1;
                }
                i += 1;
            }
            if i < n {
                i += 1;
            }
        } else if c == '\\' && i + 1 < n {
            i += 2;
        } else if c.is_whitespace() || ";|&()".contains(c) {
            break;
        } else {
            i += 1;
        }
    }
    i
}

fn looks_like_assignment(tok: &str) -> bool {
    let Some((name, _)) = tok.split_once('=') else { return false };
    let mut ch = name.chars();
    matches!(ch.next(), Some(c) if c.is_ascii_alphabetic() || c == '_') && ch.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Kind {
    Ws,
    Comment,
    Op,
    Word,
}

/// Events tiling `cmd` exactly: (kind, start, end, at_command_start), char indices.
fn scan(cmd: &[char]) -> Vec<(Kind, usize, usize, bool)> {
    let n = cmd.len();
    let mut out = Vec::new();
    let mut i = 0;
    let mut at_start = true;
    while i < n {
        let c = cmd[i];
        let was = at_start;
        let (kind, end);
        if c.is_whitespace() {
            kind = Kind::Ws;
            end = i + 1;
            at_start = at_start || c == '\n';
        } else if c == '#' {
            kind = Kind::Comment;
            end = (i..n).find(|&j| cmd[j] == '\n').unwrap_or(n);
        } else if i + 1 < n && matches!((c, cmd[i + 1]), ('&', '&') | ('|', '|') | (';', ';')) {
            kind = Kind::Op;
            end = i + 2;
            at_start = true;
        } else if ";|&()".contains(c) {
            kind = Kind::Op;
            end = i + 1;
            at_start = c != ')';
        } else {
            kind = Kind::Word;
            end = read_token(cmd, i).max(i + 1);
            let tok: String = cmd[i..end].iter().collect();
            at_start = at_start && looks_like_assignment(&tok);
        }
        out.push((kind, i, end, was));
        i = end;
    }
    out
}

/// Unquote a single shell word (`'a'`, `"a"`, `a\ b`); None when it is not one literal word.
fn unquote(t: &str) -> Option<String> {
    let mut out = String::new();
    let mut it = t.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\'' => loop {
                match it.next() {
                    Some('\'') => break,
                    Some(x) => out.push(x),
                    None => return None,
                }
            },
            '"' => loop {
                match it.next() {
                    Some('"') => break,
                    Some('\\') => out.push(it.next()?),
                    Some(x) => out.push(x),
                    None => return None,
                }
            },
            '\\' => out.push(it.next()?),
            x => out.push(x),
        }
    }
    Some(out)
}

/// Rewrite literal command-position `sudo` words to `sudo -S -p ''`; returns (command, count).
/// `env` options and assignments are followed (`env -u X FOO=1 sudo …`), shell payloads are not.
pub fn rewrite(command: &str) -> (String, usize) {
    let cmd: Vec<char> = command.chars().collect();
    let mut out = String::with_capacity(command.len() + 16);
    let mut count = 0;
    let (mut in_env, mut env_operand, mut env_options) = (false, false, false);
    const VALUE_OPTS: [&str; 6] = ["-u", "--unset", "-C", "--chdir", "-a", "--argv0"];
    const FLAG_OPTS: [&str; 6] = ["-i", "--ignore-environment", "-0", "--null", "-v", "--debug"];
    for (kind, s, e, at_start) in scan(&cmd) {
        let text: String = cmd[s..e].iter().collect();
        out.push_str(&text);
        if kind == Kind::Op || (kind == Kind::Ws && text == "\n") {
            in_env = false;
            env_operand = false;
            env_options = false;
        }
        if kind != Kind::Word || !(at_start || in_env) {
            continue;
        }
        if text.chars().any(|c| "$`*?[]~<>{}".contains(c)) {
            in_env = false;
            continue;
        }
        let Some(word) = unquote(&text) else {
            in_env = false;
            continue;
        };
        if in_env {
            if env_operand {
                env_operand = false;
                continue;
            }
            if env_options && (word == "-" || word == "--") {
                env_options = false;
                continue;
            }
            if env_options && VALUE_OPTS.contains(&word.as_str()) {
                env_operand = true;
                continue;
            }
            if env_options && (FLAG_OPTS.contains(&word.as_str()) || VALUE_OPTS.iter().any(|o| o.starts_with("--") && word.starts_with(&format!("{o}="))) || ["-u", "-C", "-a"].iter().any(|o| word.starts_with(o) && word.len() > 2)) {
                continue;
            }
            if env_options && word.starts_with('-') {
                in_env = false;
                continue;
            }
            if looks_like_assignment(&word) {
                env_options = false;
                continue;
            }
        } else if looks_like_assignment(&text) {
            continue;
        }
        let exe = word.rsplit('/').next().unwrap_or(&word);
        in_env = exe == "env";
        env_options = in_env;
        if exe == "sudo" {
            out.push_str(" -S -p ''");
            count += 1;
        }
    }
    (out, count)
}

pub fn count(command: &str) -> usize {
    rewrite(command).1
}

const HEADLESS_FAILURES: [&str; 3] = ["sudo: a password is required", "sudo: no tty present", "sudo: a terminal is required"];
const WRONG_PASSWORD: [&str; 4] = ["sudo: authentication failed", "sudo: incorrect password attempt", "sudo: maximum 3 incorrect authentication attempts", "sudo: 3 incorrect password attempts"];

static CACHE: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

/// Remember a password a person typed for this session (never shared across sessions).
pub fn cache_password(session: &str, password: &str) {
    let mut g = CACHE.lock().unwrap();
    let m = g.get_or_insert_with(HashMap::new);
    if password.is_empty() {
        m.remove(session);
    } else {
        m.insert(session.to_string(), password.to_string());
    }
}

fn cached(session: &str) -> Option<String> {
    CACHE.lock().unwrap().as_ref().and_then(|m| m.get(session).cloned())
}

/// The prepared command: what to run and the stdin lines to feed first.
#[derive(Debug, Clone, PartialEq)]
pub struct Prepared {
    pub command: String,
    /// One `password\n` per sudo invocation; None = nothing to feed.
    pub stdin: Option<String>,
    /// The password came from the session cache (dropped again if sudo rejects it).
    pub from_cache: bool,
}

/// Rewrite `command` when a password is available. `lookup` resolves the configured secret
/// name (vault, then environment).
pub fn prepare(command: &str, secret_name: &str, session: &str, lookup: &dyn Fn(&str) -> Option<String>) -> Prepared {
    let (rewritten, n) = rewrite(command);
    if n == 0 {
        return Prepared { command: command.to_string(), stdin: None, from_cache: false };
    }
    let configured = (!secret_name.is_empty()).then(|| lookup(secret_name)).flatten();
    let (pw, from_cache) = match configured {
        Some(p) => (Some(p), false),
        None => (cached(session), true),
    };
    match pw {
        Some(p) => Prepared { command: rewritten, stdin: Some(format!("{p}\n").repeat(n)), from_cache },
        None => Prepared { command: command.to_string(), stdin: None, from_cache: false },
    }
}

/// After the command ran: drop a rejected cached password and append the headless tip.
pub fn after(p: &Prepared, original: &str, session: &str, secret_name: &str, output: &str) -> Option<String> {
    let lower = output.to_ascii_lowercase();
    if p.from_cache && p.stdin.is_some() && WRONG_PASSWORD.iter().any(|m| lower.contains(m)) && count(original) > 0 {
        cache_password(session, "");
        return Some("[sudo rejected the cached password; it was forgotten for this session]".into());
    }
    if p.stdin.is_none() && HEADLESS_FAILURES.iter().any(|f| output.contains(f)) {
        let name = if secret_name.is_empty() { "SUDO_PASSWORD" } else { secret_name };
        return Some(format!("Tip: this session cannot prompt for a sudo password. Store one with `ark secrets set {name}` (or set ${name} for the agent), or run the command without sudo."));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_only_command_position_sudo() {
        assert_eq!(rewrite("sudo apt update"), ("sudo -S -p '' apt update".into(), 1));
        assert_eq!(rewrite("sudo a && sudo b"), ("sudo -S -p '' a && sudo -S -p '' b".into(), 2));
        assert_eq!(rewrite("echo sudo"), ("echo sudo".into(), 0));
        assert_eq!(rewrite("echo 'sudo x'; ls"), ("echo 'sudo x'; ls".into(), 0));
        assert_eq!(rewrite("FOO=1 /usr/bin/sudo ls").1, 1);
        assert_eq!(rewrite("env -u HOME X=1 sudo id"), ("env -u HOME X=1 sudo -S -p '' id".into(), 1));
        assert_eq!(rewrite("# sudo in a comment\nsudo id").1, 1);
        assert_eq!(rewrite("cat file | sudo tee /etc/x").1, 1);
        assert_eq!(rewrite("$SUDO ls").1, 0, "expansions are not literal executables");
        assert_eq!(rewrite("bash -c 'sudo ls'").1, 0, "payloads are not parsed");
        assert_eq!(rewrite("(sudo id)").1, 1);
        assert_eq!(rewrite("\"sudo\" id").1, 1);
    }

    #[test]
    fn prepare_feeds_one_line_per_invocation_and_tips() {
        let lookup = |n: &str| (n == "SUDO_PASSWORD").then(|| "pw".to_string());
        let p = prepare("sudo a; sudo b", "SUDO_PASSWORD", "s1", &lookup);
        assert_eq!(p.command, "sudo -S -p '' a; sudo -S -p '' b");
        assert_eq!(p.stdin.as_deref(), Some("pw\npw\n"));
        let none = |_: &str| None;
        let p = prepare("sudo a", "SUDO_PASSWORD", "s2", &none);
        assert_eq!((p.command.as_str(), p.stdin.is_none()), ("sudo a", true));
        assert!(after(&p, "sudo a", "s2", "SUDO_PASSWORD", "sudo: a password is required").unwrap().contains("ark secrets set SUDO_PASSWORD"));
        assert!(after(&p, "sudo a", "s2", "SUDO_PASSWORD", "fine").is_none());
        let p = prepare("ls", "SUDO_PASSWORD", "s2", &lookup);
        assert_eq!((p.command.as_str(), p.stdin.is_none()), ("ls", true));
    }

    #[test]
    fn cached_password_is_per_session_and_dropped_when_rejected() {
        let none = |_: &str| None;
        cache_password("cs", "typed");
        let p = prepare("sudo x", "SUDO_PASSWORD", "cs", &none);
        assert_eq!(p.stdin.as_deref(), Some("typed\n"));
        assert!(p.from_cache);
        assert!(prepare("sudo x", "SUDO_PASSWORD", "other", &none).stdin.is_none(), "never shared across sessions");
        assert!(after(&p, "sudo x", "cs", "SUDO_PASSWORD", "Sorry\nsudo: 3 incorrect password attempts").is_some());
        assert!(prepare("sudo x", "SUDO_PASSWORD", "cs", &none).stdin.is_none(), "forgotten");
    }
}
