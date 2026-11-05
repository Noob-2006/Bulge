//! Approval floors: decisions that never reach a prompt and that no bypass
//! (`--yolo`, `/yolo`, `approvals.mode = "off"`, cron approve mode) can lift.
//! Ported from Hermes `tools/approval_detection.py` (HARDLINE_PATTERNS, sudo -S
//! guard, parser limits) and `tools/approval_floors.py` (`approvals.deny` globs).

use crate::glob::fnmatch;
use regex::Regex;
use std::sync::OnceLock;

pub const PARSER_LIMIT: &str = "command parser limit exceeded";
const MAX_COMMAND_CHARS: usize = 128_000;
const MAX_SEPARATOR_FREE_CHARS: usize = 4_096;
const MAX_SEGMENTS: usize = 25_000;

/// Command position: start, newline, `$(` or backtick, optionally behind sudo/env/exec/nohup/setsid/time.
const CMDPOS: &str = r"(?:^|[\n`]|\$\()\s*(?:sudo\s+(?:-[^\s]+\s+)*)?(?:env\s+(?:\w+=\S*\s+)*)?(?:(?:exec|nohup|setsid|time)\s+)*\s*";
const SYSTEM_DIRS: &str = r"/home|/home/\*|/root|/root/\*|/etc|/etc/\*|/usr|/usr/\*|/var|/var/\*|/bin|/bin/\*|/sbin|/sbin/\*|/boot|/boot/\*|/lib|/lib/\*";

fn rm_path(alt: &str) -> String {
    format!(r#"(?:["'](?:{alt})["']|(?:{alt})(?:\s|$|[)`;|&]))"#)
}

struct Rule {
    re: Regex,
    what: &'static str,
    /// Positionless rules see quoted prose as data (matched on a quote-masked copy).
    quote_masked: bool,
}

fn rules() -> &'static [Rule] {
    static R: OnceLock<Vec<Rule>> = OnceLock::new();
    R.get_or_init(|| {
        let rm = format!(r"{CMDPOS}rm\s+(-[^\s]*\s+)*");
        let table: Vec<(String, &'static str, bool)> = vec![
            (format!("{rm}{}", rm_path(r"/(?:(?:\.\.?)?/)*(?:\.\.?)?\**|/ \*")), "recursive delete of root filesystem", false),
            (format!("{rm}{}", rm_path(SYSTEM_DIRS)), "recursive delete of system directory", false),
            (format!("{rm}{}", rm_path(r"(?:~|\$\{?HOME\}?)(?:/?|/\*)?")), "recursive delete of home directory", false),
            (format!(r"{CMDPOS}mkfs(\.[a-z0-9]+)?\b"), "format filesystem (mkfs)", false),
            (format!(r"{CMDPOS}dd\b[^\n]*\bof=/dev/(sd|nvme|hd|mmcblk|vd|xvd)[a-z0-9]*"), "dd to raw block device", false),
            (r">\s*/dev/(sd|nvme|hd|mmcblk|vd|xvd)[a-z0-9]*\b".into(), "redirect to raw block device", true),
            (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:".into(), "fork bomb", true),
            (format!(r"{CMDPOS}kill\s+(-[^\s]+\s+)*-1\b"), "kill all processes", false),
            (format!(r"{CMDPOS}(shutdown|reboot|halt|poweroff)\b"), "system shutdown/reboot", false),
            (format!(r"{CMDPOS}init\s+[06]\b"), "init 0/6 (shutdown/reboot)", false),
            (format!(r"{CMDPOS}systemctl\s+(poweroff|reboot|halt|kexec)\b"), "systemctl poweroff/reboot", false),
            (format!(r"{CMDPOS}telinit\s+[06]\b"), "telinit 0/6 (shutdown/reboot)", false),
        ];
        table.into_iter().map(|(p, what, quote_masked)| Rule { re: Regex::new(&format!("(?is){p}")).expect("hardline regex"), what, quote_masked }).collect()
    })
}

const SHELL_CARRIERS: &[&str] = &["eval", "sh", "bash", "zsh", "ksh", "dash", "source", "."];

/// Bound parser work: oversized or separator-dense payloads fail closed.
pub fn parser_limit_exceeded(command: &str) -> bool {
    if command.len() > MAX_COMMAND_CHARS {
        return true;
    }
    let seps = command.chars().filter(|c| matches!(c, ';' | '&' | '|' | '\n')).count();
    if command.len() > MAX_SEPARATOR_FREE_CHARS && seps == 0 {
        return true;
    }
    seps >= MAX_SEGMENTS
}

/// Strip ANSI escapes and NULs, fold full-width ASCII (ｒｍ → rm), join `\<newline>`
/// continuations and collapse `$IFS` / `${IFS…}` to a space (Hermes `_normalize_command_for_detection`).
pub fn normalize(command: &str) -> String {
    static IFS: OnceLock<Regex> = OnceLock::new();
    let command = command.replace("\\\r\n", "").replace("\\\n", "");
    let command = IFS.get_or_init(|| Regex::new(r"\$\{IFS\b[^}]*\}|\$IFS\b").unwrap()).replace_all(&command, " ");
    let mut out = String::with_capacity(command.len());
    let mut chars = command.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // CSI: ESC [ … final byte in @..~
            if chars.peek() == Some(&'[') {
                chars.next();
                for d in chars.by_ref() {
                    if ('@'..='~').contains(&d) {
                        break;
                    }
                }
            } else {
                chars.next();
            }
            continue;
        }
        if c == '\0' {
            continue;
        }
        out.push(crate::threat::fold_char(c));
    }
    out
}

/// Replace unquoted `;`, `|`, `&`, `&&`, `||` with newlines so command-position
/// anchors see every command start. Redirect `&` (`2>&1`, `&>`) is kept.
pub fn mark_command_starts(command: &str) -> String {
    let b: Vec<char> = command.chars().collect();
    let mut out = String::with_capacity(command.len());
    let mut quote: Option<char> = None;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match quote {
            Some(q) => {
                if c == '\\' && q == '"' && i + 1 < b.len() {
                    out.push(c);
                    out.push(b[i + 1]);
                    i += 2;
                    continue;
                }
                if c == q {
                    quote = None;
                }
                out.push(c);
            }
            None => match c {
                '\\' if i + 1 < b.len() => {
                    out.push(c);
                    out.push(b[i + 1]);
                    i += 2;
                    continue;
                }
                '\'' | '"' => {
                    quote = Some(c);
                    out.push(c);
                }
                ';' | '|' => out.push('\n'),
                // Subshell / brace-group / process-substitution openers start a command too.
                '(' => out.push_str("(\n"),
                '{' if b.get(i + 1).is_some_and(|n| n.is_whitespace()) && (out.trim_end().is_empty() || out.trim_end().ends_with(['\n', '('])) => out.push_str("{\n"),
                '&' => {
                    let prev = if i > 0 { b[i - 1] } else { ' ' };
                    let next = b.get(i + 1).copied().unwrap_or(' ');
                    if prev == '>' || prev == '<' || next == '>' {
                        out.push(c);
                    } else {
                        out.push('\n');
                    }
                }
                c => out.push(c),
            },
        }
        i += 1;
    }
    // Shell keywords (`then reboot`, `do rm -rf /`, `! halt`) put the next word at command position.
    static KW: OnceLock<Regex> = OnceLock::new();
    let kw = KW.get_or_init(|| Regex::new(r"(?m)^(\s*)(?:(?:if|then|else|elif|do|while|until|!)\s+)+").unwrap());
    kw.replace_all(&out, "$1").into_owned()
}

/// Blank out quoted string content (quotes kept); `$(...)` and backticks inside
/// double quotes stay raw because the shell executes them.
pub fn mask_quoted(command: &str) -> String {
    let b: Vec<char> = command.chars().collect();
    let mut out = String::with_capacity(command.len());
    let mut quote: Option<char> = None;
    let mut subst = 0usize;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match quote {
            None => {
                if c == '\'' || c == '"' {
                    quote = Some(c);
                }
                out.push(c);
            }
            Some(q) => {
                if subst > 0 {
                    if c == ')' {
                        subst -= 1;
                    }
                    out.push(c);
                } else if c == q {
                    quote = None;
                    out.push(c);
                } else if q == '"' && c == '$' && b.get(i + 1) == Some(&'(') {
                    subst += 1;
                    out.push_str("$(");
                    i += 1;
                } else {
                    out.push(' ');
                }
            }
        }
        i += 1;
    }
    out
}

/// Undo trivial quoting tricks (`r\m`, `git st""atus`, `'r''m'`).
pub fn deobfuscate(command: &str) -> String {
    let s = command.replace("\"\"", "").replace("''", "");
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.peek() {
                if n.is_ascii_alphanumeric() || *n == '-' || *n == '/' {
                    continue;
                }
            }
        }
        out.push(c);
    }
    out
}

/// Every spelling of `command` the floors look at. `extra` are inner payloads the
/// caller's shell parser surfaced (`bash -c '…'`, `$(…)`, one argv per simple command).
pub fn variants(command: &str, extra: &[String]) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    let mut push = |s: String| {
        if !s.trim().is_empty() && !v.contains(&s) {
            v.push(s);
        }
    };
    let n = normalize(command);
    push(n.clone());
    push(deobfuscate(&n));
    if let Some(h) = std::env::var("HOME").ok().filter(|h| h.len() > 1) {
        if n.contains(&h) {
            push(n.replace(&h, "~"));
        }
    }
    for e in extra {
        let e = normalize(e);
        push(deobfuscate(&e));
        push(e);
    }
    v
}

fn has_carrier(s: &str) -> bool {
    s.split(|c: char| c.is_whitespace() || matches!(c, ';' | '|' | '&' | '(' | '`' | '\n')).any(|w| {
        let name = w.rsplit('/').next().unwrap_or(w).trim_matches(|c| c == '"' || c == '\'');
        SHELL_CARRIERS.contains(&name)
    })
}

/// Hardline floor: Some(description) when the command must never run via the agent.
pub fn detect(command: &str, extra: &[String]) -> Option<&'static str> {
    if parser_limit_exceeded(command) {
        return Some(PARSER_LIMIT);
    }
    for v in variants(command, extra) {
        let marked = mark_command_starts(&v);
        // Positionless rules (redirects, fork bomb) have no command word: they read the
        // unmarked text, quote-masked unless a shell carrier executes the quoted part.
        let masked = if has_carrier(&v) { v.clone() } else { mask_quoted(&v) };
        for r in rules() {
            let target = if r.quote_masked { &masked } else { &marked };
            if r.re.is_match(target) {
                return Some(r.what);
            }
        }
    }
    None
}

/// `sudo -S` with no configured sudo password: the model is guessing one on stdin.
pub fn sudo_stdin(command: &str, password_configured: bool) -> Option<&'static str> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?i)(?:^|[;&|`\n]|&&|\|\||\$\()\s*sudo\s+-S\b").unwrap());
    (!password_configured && re.is_match(&normalize(command))).then_some("sudo password guessing via stdin (sudo -S)")
}

/// `approvals.deny` globs: case-insensitive, over every normalised variant.
pub fn user_deny(command: &str, extra: &[String], globs: &[String]) -> Option<String> {
    let globs: Vec<String> = globs.iter().map(|g| g.trim().to_lowercase()).filter(|g| !g.is_empty()).collect();
    if globs.is_empty() {
        return None;
    }
    for v in variants(command, extra) {
        let cand = v.trim().to_lowercase();
        for g in &globs {
            if fnmatch(g, &cand) {
                return Some(g.clone());
            }
        }
        // Each top-level segment on its own too (`ls && <denied>`).
        for seg in mark_command_starts(&v).lines() {
            let seg = seg.trim().to_lowercase();
            if seg.is_empty() || seg == cand {
                continue;
            }
            if let Some(g) = globs.iter().find(|g| fnmatch(g, &seg)) {
                return Some(g.clone());
            }
        }
    }
    None
}

pub fn hardline_message(description: &str) -> String {
    let mut m = format!(
        "BLOCKED (hardline): {description}. This command is on the unconditional blocklist and cannot be executed via the agent — not even with --yolo, /yolo, approvals.mode=off, or cron approve mode. If you genuinely need to run it, run it yourself in a terminal outside the agent."
    );
    if description == PARSER_LIMIT {
        m.push_str(" RECOVERY: this block fires on oversized/unparseable inline command payloads (heredocs, giant one-liners), not on the operation itself. Write the script to a file with the write tool, then run it: shell(command=\"bash /path/script.sh\"). Do not retry inline.");
    }
    m
}

pub fn user_deny_message(pattern: &str) -> String {
    format!("BLOCKED: this command matches the user-defined deny rule '{pattern}' (approvals.deny in config). It cannot be executed via the agent — not even with --yolo, /yolo, or approvals.mode=off. Do NOT retry or rephrase this command; the user has explicitly forbidden it.")
}

pub fn sudo_stdin_message(description: &str) -> String {
    format!("BLOCKED: {description}. Do not pipe passwords to 'sudo -S' — this is a brute-force attack vector. Store SUDO_PASSWORD with `ark secrets set SUDO_PASSWORD` if the agent needs sudo, or run the sudo command manually in your own terminal.")
}

/// Hermes `_has_allowlist_shell_operator`: true when the command is too compound for
/// the plain-text allowlist shortcut.
pub fn has_shell_operator(command: &str) -> bool {
    const CONTROL: &str = "\n\r;&|<>`$()";
    let b: Vec<char> = command.chars().collect();
    let mut quote: Option<char> = None;
    let mut reinterpretable = false;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == '\\' && quote != Some('\'') {
            if b.get(i + 1).is_some_and(|n| CONTROL.contains(*n)) {
                reinterpretable = true;
            }
            i += 2;
            continue;
        }
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else if q == '"' && (c == '`' || c == '$') {
                    return true;
                } else if CONTROL.contains(c) {
                    reinterpretable = true;
                }
            }
            None => {
                if c == '\'' || c == '"' {
                    quote = Some(c);
                } else if c == '$' {
                    if b.get(i + 1) == Some(&'(') {
                        return true;
                    }
                } else if CONTROL.contains(c) && c != '(' && c != ')' {
                    return true;
                }
            }
        }
        i += 1;
    }
    if quote.is_some() {
        return true;
    }
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?:^|[ \t])(?:-[^-\s]*[ce]|--(?:command|eval))(?:[= \t]|$)").unwrap());
    reinterpretable && re.is_match(command)
}

/// Hermes `_command_matches_permanent_allowlist`: exact text or a glob entry.
pub fn matches_command_allowlist(command: &str, patterns: &[String]) -> Option<String> {
    let command = command.trim();
    if command.is_empty() || has_shell_operator(command) {
        return None;
    }
    patterns.iter().map(|p| p.trim()).find(|p| !p.is_empty() && (command == *p || (p.contains(['*', '?', '[']) && fnmatch(p, command)))).map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardline_catches_catastrophic_commands() {
        for (cmd, what) in [
            ("rm -rf /", "root"),
            ("sudo rm -rf / --no-preserve-root", "root"),
            ("rm -rf \"/\"", "root"),
            ("echo x && rm -fr /etc", "system"),
            ("rm -rf ~", "home"),
            ("rm -rf $HOME/", "home"),
            ("echo $(rm -rf /)", "root"),
            ("mkfs.ext4 /dev/sda1", "mkfs"),
            ("dd if=/dev/zero of=/dev/sda bs=1M", "dd"),
            ("cat img > /dev/nvme0n1", "redirect"),
            (":(){ :|:& };:", "fork"),
            ("kill -9 -1", "kill"),
            ("nohup reboot", "shutdown"),
            ("ls; shutdown -h now", "shutdown"),
            ("systemctl poweroff", "poweroff"),
            ("init 0", "init"),
            ("r\\m -rf /", "root"),
            ("ｒｍ -rf /", "root"),
            ("bash -c 'cat x > /dev/sda'", "redirect"),
            ("rm -rf \\\n/", "root"),
            ("rm${IFS}-rf${IFS}/", "root"),
            ("rm$IFS-rf$IFS/", "root"),
            ("(reboot)", "shutdown"),
            ("{ reboot; }", "shutdown"),
            ("if true; then reboot; fi", "shutdown"),
            ("while true; do rm -rf /; done", "root"),
        ] {
            let d = detect(cmd, &[]).unwrap_or_else(|| panic!("{cmd} not caught"));
            assert!(d.contains(what) || what == "root" && d.contains("root"), "{cmd}: {d}");
        }
    }

    #[test]
    fn hardline_ignores_prose_and_ordinary_work() {
        for cmd in [
            "echo 'rm -rf /'",
            "git commit -m \"never dd of=/dev/sda\"",
            "grep -r 'shutdown' logs/",
            "echo \"cat f > /dev/sda\"",
            "rm -rf ./build /tmp/x",
            "rm -rf target",
            "ls /etc",
            "echo reboot",
            "kill -9 1234",
            "cargo build 2>&1 | tee log",
            "git commit -m \"(reboot) later\"",
            "echo {a,b}",
            "ls 2>&1 >/dev/null",
        ] {
            assert_eq!(detect(cmd, &[]), None, "{cmd}");
        }
    }

    #[test]
    fn inner_payloads_from_the_parser_are_scanned() {
        // The kernel passes `sh -c` payloads it decoded; a quoted carrier keeps the raw text.
        assert!(detect("python3 -c x", &["rm -rf /".into()]).is_some());
    }

    #[test]
    fn parser_limit_fails_closed() {
        assert_eq!(detect(&"a".repeat(5000), &[]), Some(PARSER_LIMIT));
        assert_eq!(detect(&"a;".repeat(26_000), &[]), Some(PARSER_LIMIT));
        assert!(hardline_message(PARSER_LIMIT).contains("RECOVERY"));
    }

    #[test]
    fn sudo_stdin_guard() {
        assert!(sudo_stdin("echo pw | sudo -S apt update", false).is_some());
        assert!(sudo_stdin("echo pw | sudo -S apt update", true).is_none());
        assert!(sudo_stdin("sudo apt update", false).is_none());
    }

    #[test]
    fn user_deny_rules_survive_quoting_tricks() {
        let globs = vec!["git push --force*".to_string(), "DOCKER RM *".to_string()];
        assert_eq!(user_deny("git push --force origin main", &[], &globs).as_deref(), Some("git push --force*"));
        assert!(user_deny("git pu\"\"sh --force x", &[], &globs).is_some());
        assert!(user_deny("ls && docker rm abc", &[], &globs).is_some(), "segment match, case-insensitive");
        assert!(user_deny("git push origin", &[], &globs).is_none());
        assert!(user_deny("x", &[], &[]).is_none());
    }

    #[test]
    fn allowlist_shortcut_refuses_compound_commands() {
        let pats = vec!["podman *".to_string(), "make test".to_string()];
        assert!(matches_command_allowlist("podman ps -a", &pats).is_some());
        assert!(matches_command_allowlist("make test", &pats).is_some());
        assert!(matches_command_allowlist("podman ps; rm -rf x", &pats).is_none());
        assert!(matches_command_allowlist("podman run \"$(id)\"", &pats).is_none());
        assert!(matches_command_allowlist("podman exec -c 'a;b'", &pats).is_none(), "quoted control char handed to -c");
        assert!(!has_shell_operator("cargo bench -- '^a(b|c)$'"), "quoted metachar is literal");
        assert!(has_shell_operator("echo 'unterminated"));
    }
}
