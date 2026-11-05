//! `seagent console` (Hermes `hermes console`, `console_engine.py`): a curated line-command
//! REPL over a safe subset of the seagent CLI. It is not a shell: shell syntax (pipes,
//! redirection, `;`, `$(…)`, backticks) is refused, only registered command paths run,
//! interactive/long-running/server commands are blocked with a reason, and commands
//! that change state ask for confirmation first (refused without a TTY). Each command
//! runs as `seagent <argv…>` with colour off; output is ANSI-stripped and capped.

use crate::args::Args;
use crate::R;
use std::io::{BufRead, IsTerminal, Write};

pub const COMMANDS: &[&str] = &["console"];
pub const VALUE_FLAGS: &[&str] = &[];
pub const BOOL_FLAGS: &[&str] = &[];

pub const OUTPUT_LIMIT: usize = 20_000;

#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    Ok,
    Error,
    ConfirmRequired,
    Exit,
    Clear,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub status: Status,
    pub output: String,
    pub command: String,
    pub confirmation: String,
}

impl Outcome {
    fn new(status: Status, output: impl Into<String>) -> Outcome {
        Outcome { status, output: output.into(), command: String::new(), confirmation: String::new() }
    }
}

pub struct Cmd {
    pub path: &'static [&'static str],
    pub usage: &'static str,
    pub summary: &'static str,
    /// seagent argv prefix the arguments are appended to.
    pub argv: &'static [&'static str],
    /// Non-empty = mutating; the confirmation prompt.
    pub confirm: &'static str,
}

pub const TABLE: &[Cmd] = &[
    Cmd { path: &["status"], usage: "status", summary: "Show daemon status.", argv: &["daemon", "status"], confirm: "" },
    Cmd { path: &["version"], usage: "version", summary: "Show seagent version information.", argv: &["version"], confirm: "" },
    Cmd { path: &["doctor"], usage: "doctor", summary: "Run diagnostics without auto-fix.", argv: &["doctor"], confirm: "" },
    Cmd { path: &["dump"], usage: "dump", summary: "Setup summary for support.", argv: &["dump"], confirm: "" },
    Cmd { path: &["logs"], usage: "logs [-n N] [--level L] [--grep TEXT]", summary: "Show recent seagent logs.", argv: &["logs"], confirm: "" },
    Cmd { path: &["sessions", "list"], usage: "sessions list [--limit N]", summary: "List recent sessions.", argv: &["session", "list"], confirm: "" },
    Cmd { path: &["sessions", "show"], usage: "sessions show <id>", summary: "Show one session.", argv: &["session", "show"], confirm: "" },
    Cmd { path: &["config", "show"], usage: "config show", summary: "Show current configuration.", argv: &["config", "show"], confirm: "" },
    Cmd { path: &["config", "path"], usage: "config path", summary: "Print the config file path.", argv: &["config", "path"], confirm: "" },
    Cmd { path: &["config", "get"], usage: "config get <key>", summary: "Show one configuration value.", argv: &["config", "get"], confirm: "" },
    Cmd { path: &["config", "check"], usage: "config check", summary: "Validate the configuration.", argv: &["config", "validate"], confirm: "" },
    Cmd { path: &["cron", "list"], usage: "cron list", summary: "List scheduled jobs.", argv: &["schedule", "list"], confirm: "" },
    Cmd { path: &["profile"], usage: "profile", summary: "Show the active profile.", argv: &["profile", "show"], confirm: "" },
    Cmd { path: &["profile", "list"], usage: "profile list", summary: "List profiles.", argv: &["profile", "list"], confirm: "" },
    Cmd { path: &["worktree", "list"], usage: "worktree list", summary: "Audit managed git worktrees.", argv: &["worktree", "list"], confirm: "" },
    Cmd { path: &["project", "list"], usage: "project list", summary: "List projects.", argv: &["project", "list"], confirm: "" },
    Cmd { path: &["backup", "list"], usage: "backup list", summary: "List backups.", argv: &["backup", "list"], confirm: "" },
    Cmd { path: &["config", "set"], usage: "config set <key> <value>", summary: "Set a configuration value.", argv: &["config", "set"], confirm: "Update seagent configuration?" },
    Cmd { path: &["config", "unset"], usage: "config unset <key>", summary: "Remove a configuration value.", argv: &["config", "unset"], confirm: "Update seagent configuration?" },
    Cmd { path: &["config", "migrate"], usage: "config migrate", summary: "Update config with new options.", argv: &["config", "migrate"], confirm: "Update seagent configuration with missing defaults?" },
    Cmd { path: &["cron", "run"], usage: "cron run <job>", summary: "Run a scheduled job now.", argv: &["schedule", "run"], confirm: "Trigger this cron job?" },
    Cmd { path: &["cron", "enable"], usage: "cron enable <job>", summary: "Resume a paused job.", argv: &["schedule", "enable"], confirm: "Resume this cron job?" },
    Cmd { path: &["cron", "rm"], usage: "cron rm <job>", summary: "Delete a scheduled job.", argv: &["schedule", "rm"], confirm: "Delete this cron job?" },
    Cmd { path: &["backup", "create"], usage: "backup create", summary: "Create a backup archive.", argv: &["backup", "create"], confirm: "Create a backup now?" },
    Cmd { path: &["worktree", "prune"], usage: "worktree prune [--dry-run]", summary: "Reclaim clean managed worktrees.", argv: &["worktree", "prune"], confirm: "Remove clean worktrees and merged branches?" },
    Cmd { path: &["sessions", "export"], usage: "sessions export <id> [--format F] [--out PATH]", summary: "Export a session.", argv: &["session", "export"], confirm: "Export session data?" },
    Cmd { path: &["send"], usage: "send <session> <message>", summary: "Queue a message into a session.", argv: &["send"], confirm: "Send this message?" },
];

const BLOCKED_TOP: &[&str] = &["chat", "run", "call", "tui", "setup", "onboard", "daemon", "app", "acp", "acp-client", "attach", "update", "uninstall", "reset", "service", "gateway", "proxy", "console", "secrets", "secret", "login", "logout", "auth", "model", "models", "node", "mcp", "shell"];

const BLOCKED_PAIRS: &[(&str, &str, &str)] = &[
    ("config", "edit", "`config edit` opens an editor and is not available in seagent console."),
    ("profile", "alias", "`profile alias` creates shell wrappers and is not available in seagent console."),
    ("logs", "--follow", "`logs --follow` streams output and is not available in seagent console."),
    ("logs", "-f", "`logs -f` streams output and is not available in seagent console."),
];

const SHELL_TOKENS: &[&str] = &["|", "||", "&", "&&", ";", ">", ">>", "<", "<<", "2>", "2>>"];

/// POSIX-ish word splitting with quotes and backslash escapes.
pub fn split(line: &str) -> Result<Vec<String>, String> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut have = false;
    let mut q: Option<char> = None;
    let mut it = line.chars().peekable();
    while let Some(c) = it.next() {
        match (q, c) {
            (Some(qc), c) if c == qc => q = None,
            (Some('"'), '\\') => {
                if let Some(n) = it.next() {
                    cur.push(n);
                }
            }
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                q = Some(c);
                have = true;
            }
            (None, '\\') => {
                if let Some(n) = it.next() {
                    cur.push(n);
                    have = true;
                }
            }
            (None, c) if c.is_whitespace() => {
                if have || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    have = false;
                }
            }
            (None, c) => cur.push(c),
        }
    }
    if q.is_some() {
        return Err("Could not parse command: No closing quotation".into());
    }
    if have || !cur.is_empty() {
        out.push(cur);
    }
    Ok(out)
}

fn shell_syntax(line: &str, toks: &[String]) -> bool {
    line.contains("$(") || line.contains('`') || toks.iter().any(|t| SHELL_TOKENS.contains(&t.as_str())) || line.chars().any(|c| "|<>;".contains(c))
}

pub fn strip_ansi(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\x1b' {
            match it.peek() {
                Some('[') => {
                    it.next();
                    for d in it.by_ref() {
                        if ('@'..='~').contains(&d) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    it.next();
                    while let Some(d) = it.next() {
                        if d == '\x07' || (d == '\x1b' && it.peek() == Some(&'\\')) {
                            if d == '\x1b' {
                                it.next();
                            }
                            break;
                        }
                    }
                }
                _ => {
                    it.next();
                }
            }
        } else {
            o.push(c);
        }
    }
    o
}

fn lev(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            cur.push((prev[j] + usize::from(ca != *cb)).min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

/// Runs `seagent <argv>` → combined output and exit code.
pub type Runner = Box<dyn Fn(&[String]) -> (i32, String)>;

pub fn exe_runner() -> Runner {
    Box::new(|argv: &[String]| {
        let exe = std::env::current_exe().unwrap_or_else(|_| "seagent".into());
        match std::process::Command::new(exe).args(argv).env("NO_COLOR", "1").env("SEAGENT_CONSOLE", "1").stdin(std::process::Stdio::null()).output() {
            Ok(o) => {
                let mut s = String::from_utf8_lossy(&o.stdout).to_string();
                let e = String::from_utf8_lossy(&o.stderr);
                if !e.trim().is_empty() {
                    if !s.is_empty() && !s.ends_with('\n') {
                        s.push('\n');
                    }
                    s.push_str(&e);
                }
                (o.status.code().unwrap_or(1), s)
            }
            Err(e) => (1, format!("could not run seagent: {e}")),
        }
    })
}

pub struct Engine {
    pub history: Vec<String>,
    pub limit: usize,
    run: Runner,
}

impl Engine {
    pub fn new(run: Runner) -> Engine {
        Engine { history: vec![], limit: OUTPUT_LIMIT, run }
    }

    pub fn help_text(&self, subject: Option<&str>) -> Result<String, String> {
        if let Some(s) = subject {
            let toks: Vec<String> = s.split_whitespace().map(String::from).collect();
            let (c, _) = self.resolve(&toks)?;
            return Ok(format!("{}\n{}", c.usage, c.summary));
        }
        let mut v: Vec<&Cmd> = TABLE.iter().collect();
        v.sort_by_key(|c| c.usage);
        let mut l = vec!["seagent console".to_string(), String::new(), "Supported commands:".into()];
        for c in v {
            l.push(format!("{} {:<32} {}", if c.confirm.is_empty() { "  " } else { " *" }, c.usage, c.summary));
        }
        l.extend([String::new(), "* requires confirmation".into(), "Built-ins: help, help <command>, history, clear, exit, quit".into()]);
        Ok(l.join("\n"))
    }

    fn rejection(toks: &[String]) -> Option<String> {
        let first = toks[0].as_str();
        if first.starts_with('-') {
            return Some(format!("{first} is not available in seagent console."));
        }
        if BLOCKED_TOP.contains(&first) && !TABLE.iter().any(|c| c.path[0] == first && toks.get(1).is_some_and(|t| c.path.get(1) == Some(&t.as_str()))) {
            return Some(format!("`seagent {first}` is not available in seagent console."));
        }
        let second = toks.get(1).map(|s| s.as_str()).unwrap_or("");
        BLOCKED_PAIRS.iter().find(|(a, b, _)| *a == first && (*b == second || toks.iter().any(|t| t == b))).map(|(_, _, m)| m.to_string())
    }

    fn resolve<'t>(&self, toks: &'t [String]) -> Result<(&'static Cmd, &'t [String]), String> {
        if let Some(r) = Self::rejection(toks) {
            return Err(r);
        }
        for size in (1..=toks.len().min(3)).rev() {
            if let Some(c) = TABLE.iter().find(|c| c.path.len() == size && c.path.iter().zip(&toks[..size]).all(|(a, b)| *a == b)) {
                return Ok((c, &toks[size..]));
            }
        }
        let probe = if toks.len() > 1 { format!("{} {}", toks[0], toks[1]) } else { toks[0].clone() };
        let mut cands: Vec<(usize, String)> = TABLE.iter().map(|c| c.path.join(" ")).map(|p| (lev(&probe, &p), p)).filter(|(d, p)| (*d as f64) <= (probe.len().max(p.len()) as f64) * 0.55).collect();
        cands.sort();
        cands.dedup_by(|a, b| a.1 == b.1);
        let sugg: Vec<String> = cands.into_iter().take(3).map(|(_, p)| p).collect();
        Err(format!("Unsupported seagent console command: {probe}.{}", if sugg.is_empty() { String::new() } else { format!(" Did you mean: {}?", sugg.join(", ")) }))
    }

    fn cap(&self, s: String) -> String {
        if s.len() <= self.limit {
            return s;
        }
        let mut cut = self.limit;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}\n... output truncated ({} bytes omitted)", &s[..cut], s.len() - cut)
    }

    pub fn execute(&mut self, line: &str, confirmed: bool) -> Outcome {
        let raw = line.trim();
        if raw.is_empty() {
            return Outcome::new(Status::Ok, "");
        }
        let err = |m: String| Outcome { status: Status::Error, output: m, command: raw.to_string(), confirmation: String::new() };
        let mut toks = match split(raw) {
            Ok(t) => t,
            Err(e) => return err(e),
        };
        if toks.first().is_some_and(|t| t == "seagent") {
            toks.remove(0);
        }
        if toks.is_empty() {
            return Outcome::new(Status::Ok, self.help_text(None).unwrap_or_default());
        }
        if shell_syntax(raw, &toks) {
            return err("seagent console does not run shell syntax. Use one supported seagent command at a time.".into());
        }
        match toks[0].as_str() {
            "help" => {
                let subject = toks[1..].join(" ");
                return match self.help_text(Some(subject.as_str()).filter(|s| !s.is_empty())) {
                    Ok(t) => Outcome::new(Status::Ok, t),
                    Err(e) => err(e),
                };
            }
            "history" => {
                let h: Vec<String> = self.history.iter().enumerate().map(|(i, c)| format!("{}: {c}", i + 1)).collect();
                return Outcome::new(Status::Ok, if h.is_empty() { "No history yet.".into() } else { h.join("\n") });
            }
            "clear" => return Outcome::new(Status::Clear, "\x1b[2J\x1b[H"),
            "exit" | "quit" => return Outcome::new(Status::Exit, ""),
            _ => {}
        }
        let (c, args) = match self.resolve(&toks) {
            Ok(x) => x,
            Err(e) => return err(e),
        };
        if !c.confirm.is_empty() && !confirmed {
            return Outcome { status: Status::ConfirmRequired, output: String::new(), command: raw.to_string(), confirmation: c.confirm.to_string() };
        }
        let mut argv: Vec<String> = c.argv.iter().map(|s| s.to_string()).collect();
        argv.extend(args.iter().cloned());
        if !c.confirm.is_empty() && c.path == ["config", "migrate"] {
            argv.push("--yes".into());
        }
        let (code, out) = (self.run)(&argv);
        self.history.push(raw.to_string());
        let out = self.cap(strip_ansi(&out).trim_end().to_string());
        Outcome { status: if code == 0 { Status::Ok } else { Status::Error }, output: out, command: raw.to_string(), confirmation: String::new() }
    }
}

/// The REPL loop over arbitrary streams (testable).
pub fn repl(engine: &mut Engine, input: &mut dyn BufRead, out: &mut dyn Write, err: &mut dyn Write, interactive: bool) -> i32 {
    if interactive {
        let _ = writeln!(out, "seagent console. Type `help` for commands, `exit` to quit.");
    }
    loop {
        if interactive {
            let _ = write!(out, "seagent> ");
            let _ = out.flush();
        }
        let mut line = String::new();
        if input.read_line(&mut line).unwrap_or(0) == 0 {
            if interactive {
                let _ = writeln!(out);
            }
            return 0;
        }
        let mut r = engine.execute(&line, false);
        if r.status == Status::ConfirmRequired {
            if !interactive {
                let _ = writeln!(err, "Confirmation required: {}", r.confirmation);
                return 1;
            }
            let _ = write!(out, "{} [y/N] ", r.confirmation);
            let _ = out.flush();
            let mut ans = String::new();
            let _ = input.read_line(&mut ans);
            if !matches!(ans.trim().to_lowercase().as_str(), "y" | "yes") {
                let _ = writeln!(out, "Cancelled.");
                continue;
            }
            r = engine.execute(&r.command, true);
        }
        if !r.output.is_empty() {
            if r.status == Status::Error {
                let _ = writeln!(err, "{}", r.output);
            } else {
                let _ = writeln!(out, "{}", r.output);
            }
        }
        if r.status == Status::Exit {
            return 0;
        }
    }
}

pub fn dispatch(cmd: &str, _a: &Args, _raw: &[String]) -> Option<R> {
    if cmd != "console" {
        return None;
    }
    let mut e = Engine::new(exe_runner());
    let stdin = std::io::stdin();
    let interactive = stdin.is_terminal();
    let mut lock = stdin.lock();
    Some(Ok(repl(&mut e, &mut lock, &mut std::io::stdout(), &mut std::io::stderr(), interactive)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn engine() -> (Engine, Arc<Mutex<Vec<Vec<String>>>>) {
        let calls = Arc::new(Mutex::new(vec![]));
        let c2 = calls.clone();
        let e = Engine::new(Box::new(move |argv: &[String]| {
            c2.lock().unwrap().push(argv.to_vec());
            if argv[0] == "fail" {
                return (2, "boom".into());
            }
            (0, format!("\x1b[1mran\x1b[0m {}", argv.join(" ")))
        }));
        (e, calls)
    }

    #[test]
    fn curated_commands_guards_and_confirmation() {
        let (mut e, calls) = engine();
        let r = e.execute("sessions list --limit 5", false);
        assert_eq!(r.status, Status::Ok);
        assert_eq!(r.output, "ran session list --limit 5", "ANSI stripped");
        assert_eq!(calls.lock().unwrap()[0], ["session", "list", "--limit", "5"]);
        assert_eq!(e.execute("seagent version", false).output, "ran version", "leading `seagent` is dropped");

        for bad in ["status | cat", "logs > out.txt", "doctor; rm -rf /", "echo $(id)", "doctor `id`"] {
            let r = e.execute(bad, false);
            assert!(r.status == Status::Error && r.output.contains("shell syntax"), "{bad}: {r:?}");
        }
        assert!(e.execute("chat hello", false).output.contains("`seagent chat` is not available"));
        assert!(e.execute("config edit", false).output.contains("opens an editor"));
        assert!(e.execute("logs -f", false).output.contains("streams output"));
        assert!(e.execute("--help", false).output.contains("not available"));
        let r = e.execute("sesions list", false);
        assert!(r.output.contains("Unsupported") && r.output.contains("Did you mean: sessions list"), "{}", r.output);

        let n = calls.lock().unwrap().len();
        let r = e.execute("config set model.default a/b", false);
        assert_eq!(r.status, Status::ConfirmRequired);
        assert_eq!(r.confirmation, "Update seagent configuration?");
        assert_eq!(calls.lock().unwrap().len(), n, "nothing ran before confirmation");
        let r = e.execute(&r.command, true);
        assert_eq!(r.status, Status::Ok);
        assert_eq!(calls.lock().unwrap().last().unwrap(), &["config", "set", "model.default", "a/b"]);

        assert!(e.execute("history", false).output.contains("1: sessions list --limit 5"));
        assert_eq!(e.execute("clear", false).status, Status::Clear);
        assert_eq!(e.execute("quit", false).status, Status::Exit);
        assert!(e.execute("help", false).output.contains("* requires confirmation"));
        assert!(e.execute("help cron run", false).output.starts_with("cron run <job>"));
        assert_eq!(split("a 'b c' \"d \\\"e\\\"\" f\\ g").unwrap(), ["a", "b c", "d \"e\"", "f g"]);
        assert!(split("'open").is_err());
        e.limit = 10;
        assert!(e.execute("version", false).output.contains("output truncated"));
    }

    /// Every curated entry resolves, and routes to a command the crate actually registers.
    #[test]
    fn table_routes_to_registered_commands() {
        assert!(crate::ops::owns("console"), "console is registered in ops::MODULES");
        let e = Engine::new(Box::new(|_: &[String]| (0, String::new())));
        for c in TABLE {
            let toks: Vec<String> = c.path.iter().map(|s| s.to_string()).collect();
            assert!(e.resolve(&toks).is_ok(), "{} resolves", c.usage);
            assert!(crate::BUILTINS.contains(&c.argv[0]) || crate::ops::owns(c.argv[0]), "{} -> seagent {}", c.usage, c.argv[0]);
        }
        let a = Args::parse(&[]).unwrap();
        assert!(dispatch("project", &a, &[]).is_none(), "other commands fall through");
    }

    #[test]
    fn repl_refuses_unconfirmed_mutation_without_tty() {
        let (mut e, calls) = engine();
        let mut out = vec![];
        let mut err = vec![];
        let rc = repl(&mut e, &mut "status\ncron run j1\n".as_bytes(), &mut out, &mut err, false);
        assert_eq!(rc, 1);
        assert!(String::from_utf8_lossy(&err).contains("Confirmation required: Trigger this cron job?"));
        assert_eq!(calls.lock().unwrap().len(), 1);
        let (mut e, calls) = engine();
        let rc = repl(&mut e, &mut "cron run j1\ny\nexit\n".as_bytes(), &mut vec![], &mut vec![], true);
        assert_eq!(rc, 0);
        assert_eq!(calls.lock().unwrap()[0], ["schedule", "run", "j1"]);
        let (mut e, calls) = engine();
        repl(&mut e, &mut "cron run j1\nn\n".as_bytes(), &mut vec![], &mut vec![], true);
        assert!(calls.lock().unwrap().is_empty(), "declined");
    }
}
