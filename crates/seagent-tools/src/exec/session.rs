//! Persistent shell state for the `shell` tool (Hermes `tools/environments/local.py` +
//! `base_session_env.py`): instead of keeping one bash alive, every command is a fresh
//! `bash -c` whose script starts with a snapshot of the previous call's state —
//! `builtin cd -- <cwd>` plus one `export K=V` per exported variable — and ends with a
//! small epilogue that dumps `pwd -P` and `export -p` into a private file, parsed back
//! into [`ShellState`] afterwards. So `cd /tmp` or `export FOO=bar` in one call is visible
//! in the next one, without a stateful shell process to babysit.
//!
//! The snapshot file lives in `<seagent home>/shell/<scope key>/state`, is created under
//! `umask 077` (it can hold the user's own exports) and is published atomically
//! (`state.tmp` + `mv`), so a crashed command never leaves a half-written snapshot.
//! Credential-shaped names are never stored while `[exec] scrub_env` is on, and names a
//! single call injected (`env` argument / `[exec] env`) are not persisted: they belong to
//! that call only.

use seagent_core::exec::ExecBackend;
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

/// Variables the shell maintains itself; replaying them would fight bash.
const NOT_REPLAYED: &[&str] = &["PWD", "OLDPWD", "SHLVL", "_", "SHELLOPTS", "BASHOPTS", "BASH_ARGC", "BASH_ARGV", "PS1", "PS2", "PS4", "IFS", "OPTIND"];
/// A single value above this is not replayed (keeps every script small).
const MAX_VALUE: usize = 8 * 1024;
/// Upper bound for the whole prologue.
const MAX_PROLOGUE: usize = 96 * 1024;

/// Per-session, per-backend shell state: working directory + exported environment.
pub struct ShellState {
    /// Where the next command starts.
    pub cwd: PathBuf,
    /// `[exec] persistent_shell` on a host-sharing backend (else nothing is kept).
    pub persistent: bool,
    /// Exported environment of the last command, replayed before the next one.
    pub env: BTreeMap<String, String>,
    /// `<home>/shell/<scope key>`; empty = no snapshot file.
    pub dir: PathBuf,
}

impl ShellState {
    pub fn new(backend: &dyn ExecBackend, workspace: &Path, persistent: bool) -> ShellState {
        // The snapshot prologue / epilogue are bash. A host shell that is PowerShell (Windows
        // without Git Bash) gets no persistence rather than a script it cannot parse.
        let posix = backend.id() != "local" || seagent_core::platform::shell::active().kind.is_posix();
        ShellState { cwd: workspace.to_path_buf(), persistent: persistent && posix, env: BTreeMap::new(), dir: PathBuf::new() }
    }

    /// Point the snapshot at `<home>/shell/<scope>` (created private, 0700), loading what a
    /// previous call left there. The file — not this struct — is the session's real state,
    /// so a fresh `ShellState` (a new `ExecEnv`, e.g. after a config reload) resumes the
    /// `cd` / exports of the last command instead of starting over in the workspace.
    /// `skip` are the names this call passes in its own `env`: they are not carried over.
    pub fn set_state_dir(&mut self, home: &Path, scope: &str, skip: &[String], scrub: bool, passthrough: &[String]) -> io::Result<()> {
        let dir = home.join("shell").join(scope);
        if self.dir != dir {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
            }
            #[cfg(not(unix))]
            {
                std::fs::create_dir_all(&dir)?;
                seagent_core::platform::fs_private::set_private(&dir)?;
            }
            self.dir = dir;
            self.reload(skip, scrub, passthrough);
        }
        Ok(())
    }

    /// Is the snapshot file usable (persistence on and a state dir configured)?
    pub fn ready(&self) -> bool {
        self.persistent && !self.dir.as_os_str().is_empty()
    }

    pub fn state_file(&self) -> PathBuf {
        self.dir.join("state")
    }

    /// Shell lines that restore `cwd` and the previous exports. `skip` names belong to
    /// this call only; names the shell owns are never replayed.
    pub fn prologue(&self, cwd: &Path, skip: &[String], scrub: bool, passthrough: &[String]) -> String {
        let mut s = String::from("builtin cd -- ");
        s.push_str(&quote(&cwd.to_string_lossy()));
        s.push_str(&format!(" 2>/dev/null || {{ printf 'cannot cd to %s\\n' {} >&2; exit 126; }}\n", quote(&cwd.to_string_lossy())));
        let mut budget = MAX_PROLOGUE;
        for (k, v) in &self.env {
            if !replay(k, v, skip, scrub, passthrough) {
                continue;
            }
            let line = format!("export {}={}\n", k, quote(v));
            if line.len() > budget {
                break;
            }
            budget -= line.len();
            s.push_str(&line);
        }
        s
    }

    /// Shell lines that dump the resulting `pwd -P` and `export -p` for the next call.
    /// Writes nothing to the command's output and never changes its exit status. `skip`
    /// names belong to this call only (`env` argument), so they are dropped instead of
    /// being recorded: a later call — or the same session in a new `ExecEnv` — must not
    /// inherit them from the snapshot.
    pub fn epilogue(&self, skip: &[String]) -> String {
        if !self.ready() {
            return String::new();
        }
        let mut prefix = String::new();
        let names: Vec<&str> = skip.iter().map(String::as_str).filter(|n| is_ident(n)).collect();
        if !names.is_empty() {
            prefix.push_str(&format!("unset {} 2>/dev/null\n", names.join(" ")));
        }
        // `$$` makes the temporary name per-invocation: two parallel calls of one session
        // (the same snapshot dir) must not overwrite each other's dump mid-write.
        let dir = quote(&self.dir.to_string_lossy());
        let tmp = format!("{dir}/state.tmp.$$");
        let file = quote(&self.state_file().to_string_lossy());
        format!("{prefix}( umask 077; {{ pwd -P; export -p; }} > {tmp} ) 2>/dev/null && mv -f {tmp} {file} 2>/dev/null || rm -f {tmp} 2>/dev/null || true\n")
    }

    /// Re-read what the epilogue just wrote; a missing or damaged file keeps the old state.
    pub fn reload(&mut self, skip: &[String], scrub: bool, passthrough: &[String]) {
        if !self.ready() {
            return;
        }
        let Ok(text) = std::fs::read_to_string(self.state_file()) else { return };
        let (cwd, vars) = parse_state(&text);
        if let Some(c) = cwd {
            if c.is_dir() {
                self.cwd = c;
            }
        }
        self.env.clear();
        for (k, v) in vars {
            if replay(&k, &v, skip, scrub, passthrough) {
                self.env.insert(k, v);
            }
        }
    }
}

/// Should this variable be carried over to the next command?
fn replay(name: &str, value: &str, skip: &[String], scrub: bool, passthrough: &[String]) -> bool {
    is_ident(name)
        && !NOT_REPLAYED.contains(&name)
        && value.len() <= MAX_VALUE
        && !skip.iter().any(|s| s == name)
        // A credential never enters the snapshot while scrubbing is on (Hermes keeps its
        // per-session vars out for the same reason: the file outlives the call).
        && !(scrub && super::sandbox::is_secret_env(name) && !super::sandbox::passthrough_forwards(name, passthrough))
}

fn is_ident(name: &str) -> bool {
    let mut c = name.chars();
    matches!(c.next(), Some(c) if c.is_ascii_alphabetic() || c == '_') && c.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn quote(s: &str) -> String {
    super::sh_quote(s)
}

/// First line = `pwd -P`, then the `export -p` dump (`declare -x NAME="value"`).
fn parse_state(text: &str) -> (Option<PathBuf>, Vec<(String, String)>) {
    let mut lines = text.split('\n');
    let cwd = lines.next().map(|l| l.trim_end_matches('\r')).filter(|l| !l.is_empty()).map(PathBuf::from);
    let rest: Vec<&str> = lines.collect();
    let mut vars = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        let line = rest[i].trim_end_matches('\r');
        i += 1;
        let Some(body) = line.strip_prefix("declare -") else { continue };
        let Some((flags, decl)) = body.split_once(' ') else { continue };
        if !flags.contains('x') {
            continue;
        }
        let Some((name, value)) = decl.split_once('=') else { continue };
        if !is_ident(name) {
            continue;
        }
        // bash 3.2 prints a value containing a newline as a multi-line quoted block.
        let mut value = value.to_string();
        while unterminated(&value) && i < rest.len() {
            value.push('\n');
            value.push_str(rest[i].trim_end_matches('\r'));
            i += 1;
        }
        vars.push((name.to_string(), unquote(&value)));
    }
    (cwd, vars)
}

/// Does a quoted dump value still wait for its closing quote on a later line?
fn unterminated(v: &str) -> bool {
    let quote = if v.starts_with("$'") {
        '\''
    } else if v.starts_with('"') {
        '"'
    } else {
        return false;
    };
    let body = &v[1..];
    let mut esc = false;
    let mut last = None;
    for (i, c) in body.char_indices() {
        if esc {
            esc = false;
            continue;
        }
        match c {
            '\\' => esc = true,
            c if c == quote => last = Some(i),
            _ => {}
        }
    }
    last != Some(body.len().saturating_sub(1))
}

/// Undo bash's `export -p` quoting: `"…"` (backslash escapes) or `$'…'` (ANSI-C).
fn unquote(v: &str) -> String {
    if let Some(inner) = v.strip_prefix("$'").and_then(|s| s.strip_suffix('\'')) {
        return ansi_c(inner);
    }
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        let mut out = String::with_capacity(v.len());
        let mut it = v[1..v.len() - 1].chars();
        while let Some(c) = it.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match it.next() {
                Some(c @ ('"' | '\\' | '$' | '`')) => out.push(c),
                Some(c) => {
                    out.push('\\');
                    out.push(c);
                }
                None => out.push('\\'),
            }
        }
        return out;
    }
    v.to_string()
}

fn ansi_c(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('a') => out.push('\x07'),
            Some('b') => out.push('\x08'),
            Some('f') => out.push('\x0c'),
            Some('v') => out.push('\x0b'),
            Some('e') => out.push('\x1b'),
            Some(c @ ('\\' | '\'' | '"' | '?')) => out.push(c),
            Some('x') => {
                let mut n = 0u32;
                for _ in 0..2 {
                    match it.peek().and_then(|c| c.to_digit(16)) {
                        Some(d) => {
                            n = n * 16 + d;
                            it.next();
                        }
                        None => break,
                    }
                }
                out.push(char::from_u32(n).unwrap_or('\u{fffd}'));
            }
            Some(c @ '0'..='7') => {
                let mut n = c.to_digit(8).unwrap_or(0);
                for _ in 0..2 {
                    match it.peek().and_then(|c| c.to_digit(8)) {
                        Some(d) => {
                            n = n * 8 + d;
                            it.next();
                        }
                        None => break,
                    }
                }
                out.push(char::from_u32(n).unwrap_or('\u{fffd}'));
            }
            Some(c) => {
                out.push('\\');
                out.push(c);
            }
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shell::Shell;
    use crate::testutil::ctx;
    use seagent_core::Tool;
    use serde_json::json;

    fn state() -> ShellState {
        let mut s = ShellState::new(&crate::exec::local::LocalBackend::new(), Path::new("/w"), true);
        s.dir = PathBuf::from("/state");
        s
    }

    #[test]
    fn parses_export_dump_quoting() {
        let dump = "/tmp/sub\n\
                    declare -x SIMPLE=\"abc\"\n\
                    declare -x EMPTY=\"\"\n\
                    declare -x SPACES=\"a b'c\"\n\
                    declare -x QUOTED=\"q\\\"x\\\\y\\$z\"\n\
                    declare -x MULTI=$'l1\\nl2'\n\
                    declare -x LITERAL=\"l1\n\
                    l2\"\n\
                    declare -x UNSET\n\
                    declare -x bad-name=\"x\"\n";
        let (cwd, vars) = parse_state(dump);
        assert_eq!(cwd.as_deref(), Some(Path::new("/tmp/sub")));
        let m: std::collections::HashMap<_, _> = vars.into_iter().collect();
        assert_eq!(m["SIMPLE"], "abc");
        assert_eq!(m["EMPTY"], "");
        assert_eq!(m["SPACES"], "a b'c");
        assert_eq!(m["QUOTED"], "q\"x\\y$z");
        assert_eq!(m["MULTI"], "l1\nl2");
        assert_eq!(m["LITERAL"], "l1\nl2", "bash 3.2 multi-line quoting");
        assert!(!m.contains_key("UNSET") && !m.contains_key("bad-name"));
    }

    #[test]
    fn prologue_replays_exports_but_never_secrets_or_call_env() {
        let mut s = state();
        s.env.insert("FOO".into(), "a b".into());
        s.env.insert("OPENAI_API_KEY".into(), "sk-x".into());
        s.env.insert("PWD".into(), "/elsewhere".into());
        s.env.insert("CALL_ONLY".into(), "1".into());
        let p = s.prologue(Path::new("/tmp/x y"), &["CALL_ONLY".to_string()], true, &[]);
        assert!(p.starts_with("builtin cd -- '/tmp/x y'"), "{p}");
        assert!(p.contains("export FOO='a b'\n"), "{p}");
        assert!(!p.contains("OPENAI_API_KEY"), "credentials stay out of the snapshot: {p}");
        assert!(!p.contains("PWD=") && !p.contains("CALL_ONLY"), "{p}");
        // scrub off: the user's own export of a credential-named variable survives
        let p = s.prologue(Path::new("/w"), &[], false, &[]);
        assert!(p.contains("export OPENAI_API_KEY=sk-x"), "{p}");
        assert!(s.epilogue(&[]).contains("umask 077") && s.epilogue(&[]).contains("export -p"));
    }

    #[test]
    fn cd_and_export_survive_between_calls() {
        let c = ctx("shpersist");
        assert!(!Shell.call(&c, json!({"command":"cd /tmp"})).is_error);
        let o = Shell.call(&c, json!({"command":"pwd"}));
        assert!(!o.is_error && o.content.contains("/tmp"), "{}", o.content);
        let o = Shell.call(&c, json!({"command":"export FOO=bar"}));
        assert!(!o.is_error, "{}", o.content);
        let o = Shell.call(&c, json!({"command":"echo \"v=$FOO\""}));
        assert!(!o.is_error && o.content.contains("v=bar"), "{}", o.content);
        // A different session starts from the workspace, not from /tmp.
        let other = ctx("shpersist-other");
        let o = Shell.call(&other, json!({"command":"pwd; echo \"v=${FOO:-unset}\""}));
        let name = other.workspace.file_name().unwrap().to_string_lossy().into_owned();
        assert!(o.content.contains(&name), "a fresh session starts in its workspace: {}", o.content);
        assert!(o.content.contains("v=unset"), "{}", o.content);
    }

    #[test]
    fn non_persistent_shell_keeps_nothing() {
        let backend = crate::exec::local::LocalBackend::new();
        let mut off = ShellState::new(&backend, Path::new("/w"), false);
        off.dir = PathBuf::from("/state");
        assert!(!off.ready(), "persistent_shell = false");
        assert!(off.epilogue(&[]).is_empty(), "nothing is written");
        let mut on = ShellState::new(&backend, Path::new("/w"), true);
        on.dir = PathBuf::from("/state");
        assert!(on.ready());
        assert!(on.epilogue(&[]).contains("state"));
    }

    #[test]
    fn state_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let c = ctx("shperm");
        let o = Shell.call(&c, json!({"command":"export SEAGENT_PERM=x"}));
        assert!(!o.is_error, "{}", o.content);
        let dir = c.home.join("shell").join(crate::exec::global().scope_key(&c.session_id, &c.workspace));
        let mode = std::fs::metadata(dir.join("state")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "snapshot permissions");
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        assert!(std::fs::read_to_string(dir.join("state")).unwrap().lines().next().is_some(), "pwd first line");
    }
}
