//! Failure hints for the shell tool (Hermes `tools/terminal_hints.py`): a bounded scan of a
//! failed command's output mapped to ONE short recovery hint (first match wins, patterns in
//! production-frequency order, only the first 4000 chars are scanned), exit-code-only hints,
//! and a masked-success warning when `cmd | tail` / `cmd || echo …` hides a failure. Pure
//! functions; the exit status is never changed.

use regex::Regex;
use std::sync::OnceLock;

const SCAN_CHARS: usize = 4000;

fn window(output: &str) -> &str {
    match output.char_indices().nth(SCAN_CHARS) {
        Some((i, _)) => &output[..i],
        None => output,
    }
}

fn missing_command(m: &str) -> String {
    match m {
        "python" => "This system has no bare `python` — use `python3`, or the project venv's interpreter (e.g. .venv/bin/python).".into(),
        "pip" => "This system has no bare `pip` — use `pip3`, `python3 -m pip`, or the project venv's pip (e.g. .venv/bin/pip).".into(),
        _ => format!("`{m}` is not installed or not on PATH. Verify with `which {m}`; install it or use an absolute path instead of retrying the same command."),
    }
}

type Rule = (Regex, fn(&str) -> String);

fn rules() -> &'static [Rule] {
    static R: OnceLock<Vec<Rule>> = OnceLock::new();
    R.get_or_init(|| {
        let r = |p: &str| Regex::new(p).expect("hint pattern");
        vec![
            (r(r#"Unknown JSON field: "?(\w+)"#), |g| format!("The installed gh does not support the JSON field '{g}'. The valid field list is printed in the output above — retry using only fields from that list.")),
            (r(r"(?m)(^CONFLICT |Automatic merge failed|needs merge)"), |_| "Git merge conflict. Do not retry this command. Resolve the conflicted files listed above (edit, then `git add`), then continue (`git rebase --continue` / commit the merge) — or abort with `--abort`.".into()),
            (r(r"(?:bash: line \d+: |bash: |sh: \d*:? ?)?([\w.+-]+): command not found"), |g| missing_command(g)),
            (r(r"(?:ModuleNotFoundError|ImportError): No module named '?([\w.]+)"), |g| format!("Python cannot import '{g}'. Most often the wrong interpreter is running: activate the project venv (e.g. `source .venv/bin/activate`) or invoke its python directly. Only pip install if the package is genuinely absent from that venv.")),
            (r(r"(?:fatal|error):.*?'([^']+)' already exists"), |g| format!("'{g}' already exists — retrying unchanged will keep failing. Reuse it, choose another name, or delete it first if it is genuinely stale.")),
            (r(r"(API rate limit|was submitted too quickly)"), |_| "GitHub API rate limit hit — immediate retries will keep failing. Continue with other work and retry this operation later.".into()),
            (r(r"(Permission denied|EACCES)"), |_| "Permission denied. Check ownership/mode of the target path (`ls -la`); prefer a user-writable location. Only escalate to sudo if the task genuinely requires it.".into()),
        ]
    })
}

fn exit_hint(code: i32) -> Option<&'static str> {
    Some(match code {
        126 => "Exit 126: the file was found but is not executable — `chmod +x` it or invoke it via its interpreter (e.g. `bash script.sh`).",
        137 => "Exit 137: the process was SIGKILLed — usually out-of-memory or an external kill. Reduce memory use or check `dmesg | tail` before retrying.",
        124 => "Exit 124: the command hit its timeout. Raise timeout_secs or run it in the background with `job` (notify=true).",
        _ => return None,
    })
}

/// One short recovery hint for a failed command (None for exit 0 or nothing recognised).
pub fn annotate_failure(_command: &str, exit_code: i32, output: &str) -> Option<String> {
    if exit_code == 0 {
        return None;
    }
    let w = window(output);
    if !w.is_empty() {
        for (rx, f) in rules() {
            if let Some(c) = rx.captures(w) {
                return Some(f(c.get(1).map(|m| m.as_str()).unwrap_or("")));
            }
        }
    }
    exit_hint(exit_code).map(String::from)
}

const READONLY_HEADS: [&str; 17] = ["grep", "rg", "ag", "find", "ls", "cat", "head", "tail", "jq", "awk", "sed", "strings", "zcat", "journalctl", "dmesg", "echo", "printf"];
const PASSTHROUGH: [&str; 9] = ["tail", "head", "cat", "tee", "less", "more", "wc", "sort", "uniq"];

fn failure_shapes() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?m)(error\[E\d+\]|error: could not compile|error: aborting due to|Traceback \(most recent call last\)|^(?:=+ )?\d+ failed|^FAILED (?:\S+::|\S+\.py)|compilation terminated\.|npm ERR!|BUILD FAILED|Build FAILED|FAILED: |^make(?:\[\d+\])?: \*\*\*)").unwrap())
}

fn first_token(command: &str) -> &str {
    for tok in command.split_whitespace() {
        if !tok.contains('=') || tok.starts_with(['=', '.', '/']) {
            return tok.rsplit('/').next().unwrap_or(tok);
        }
    }
    ""
}

/// The last top-level `|` (not `||`) followed only by a passthrough consumer.
fn piped_into_passthrough(cmd: &str) -> bool {
    let b = cmd.as_bytes();
    let Some(i) = (0..b.len()).rev().find(|&i| b[i] == b'|' && b.get(i + 1) != Some(&b'|') && (i == 0 || b[i - 1] != b'|')) else { return false };
    let rest = &cmd[i + 1..];
    if rest.contains('|') {
        return false;
    }
    let head = rest.split_whitespace().next().unwrap_or("");
    PASSTHROUGH.contains(&head)
}

fn or_fallback(cmd: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\|\|\s*(?:echo\b|printf\b|true\b|:\s|:$)").unwrap()).is_match(cmd)
}

/// Warning when an exit-0 result likely masks a failure (caller only asks on exit 0).
pub fn annotate_masked_success(command: &str, output: &str) -> Option<&'static str> {
    let w = window(output);
    if command.is_empty() || w.is_empty() || READONLY_HEADS.contains(&first_token(command)) || !failure_shapes().is_match(w) {
        return None;
    }
    if piped_into_passthrough(command) {
        return Some("exit_code 0 here is the status of the last pipeline command (tail/head/cat/...), NOT of the command before the pipe — and the output contains failure indicators. Treat this run as FAILED until proven otherwise: re-run the command WITHOUT the pipe (output is truncated head/tail automatically, so piping through tail/head is never needed) to get the real exit code.");
    }
    if or_fallback(command) {
        return Some("exit_code 0 here is the status of the `||` fallback (echo/true), NOT of the command before it — and the output contains failure indicators. Treat this run as FAILED until proven otherwise: re-run the command bare to get its real exit code.");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_hints_first_match_and_exit_codes() {
        assert!(annotate_failure("python x.py", 127, "bash: line 1: python: command not found").unwrap().contains("python3"));
        assert!(annotate_failure("foo", 127, "bash: foo: command not found").unwrap().contains("`which foo`"));
        assert!(annotate_failure("python3 a.py", 1, "ModuleNotFoundError: No module named 'requests'").unwrap().contains("'requests'"));
        assert!(annotate_failure("git merge x", 1, "CONFLICT (content): Merge conflict in a.txt").unwrap().contains("merge conflict"));
        assert!(annotate_failure("gh pr list --json foo", 1, "Unknown JSON field: \"foo\"").unwrap().contains("'foo'"));
        assert!(annotate_failure("git branch x", 128, "fatal: a branch named 'x' already exists").unwrap().contains("'x' already exists"));
        assert!(annotate_failure("touch /x", 1, "touch: cannot touch '/x': Permission denied").unwrap().starts_with("Permission denied"));
        assert!(annotate_failure("./run", 126, "").unwrap().contains("chmod +x"));
        assert!(annotate_failure("x", 137, "Killed").unwrap().contains("SIGKILL"));
        assert_eq!(annotate_failure("x", 0, "command not found"), None);
        assert_eq!(annotate_failure("x", 2, "something else"), None);
        let far = format!("{}bash: foo: command not found", "x".repeat(5000));
        assert_eq!(annotate_failure("foo", 2, &far), None, "only the head is scanned");
    }

    #[test]
    fn masked_success_needs_shape_and_failure() {
        let out = "error[E0425]: cannot find value\nerror: could not compile `x`";
        assert!(annotate_masked_success("cargo build 2>&1 | tail -20", out).unwrap().contains("last pipeline command"));
        assert!(annotate_masked_success("cargo build || echo FAILED", out).unwrap().contains("fallback"));
        assert_eq!(annotate_masked_success("cargo build", out), None);
        assert_eq!(annotate_masked_success("grep error log | head", out), None, "read-only heads are excluded");
        assert_eq!(annotate_masked_success("cargo build | tail", "Finished"), None);
        assert_eq!(annotate_masked_success("a || b | tail", "x"), None);
    }
}
