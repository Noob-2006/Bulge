//! `.env` loading (Hermes `env_loader`): `<config dir>/.env`, then `<workspace>/.ark/.env`
//! when the workspace is in `trusted_projects`. Variables already in the process
//! environment win; credential-looking values must be ASCII (they become HTTP headers).
//! `/reload` re-reads the files and re-applies what changed.

use crate::args::Args;
use crate::R;
use ark_kernel::config::Paths;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const COMMANDS: &[&str] = &[];
pub const VALUE_FLAGS: &[&str] = &[];
pub const BOOL_FLAGS: &[&str] = &[];

pub fn dispatch(_cmd: &str, _a: &Args, _raw: &[String]) -> Option<R> {
    None
}

const CREDENTIAL_SUFFIXES: &[&str] = &["_API_KEY", "_TOKEN", "_SECRET", "_KEY"];

/// Values this process set from .env files (name → value), so reloads may update them.
static LOADED: Mutex<BTreeMap<String, String>> = Mutex::new(BTreeMap::new());

/// Parse dotenv text: `KEY=value`, `export KEY=value`, `#` comments, single quotes
/// (literal), double quotes (`\n \t \" \\` escapes, may span lines), inline ` #` comments
/// after unquoted values.
pub fn parse(text: &str) -> Vec<(String, String)> {
    let mut out = vec![];
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let l = line.trim_start();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let l = l.strip_prefix("export ").unwrap_or(l);
        let Some((k, v)) = l.split_once('=') else { continue };
        let k = k.trim();
        if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || k.starts_with(|c: char| c.is_ascii_digit()) {
            continue;
        }
        let v = v.trim_start();
        let val = if let Some(rest) = v.strip_prefix('"') {
            let mut buf = rest.to_string();
            while !closes(&buf) {
                match lines.next() {
                    Some(n) => {
                        buf.push('\n');
                        buf.push_str(n);
                    }
                    None => break,
                }
            }
            let mut s = String::new();
            let mut it = buf.chars();
            while let Some(c) = it.next() {
                match c {
                    '\\' => match it.next() {
                        Some('n') => s.push('\n'),
                        Some('t') => s.push('\t'),
                        Some('r') => s.push('\r'),
                        Some(o) => s.push(o),
                        None => {}
                    },
                    '"' => break,
                    c => s.push(c),
                }
            }
            s
        } else if let Some(rest) = v.strip_prefix('\'') {
            rest.split('\'').next().unwrap_or("").to_string()
        } else {
            v.split(" #").next().unwrap_or("").trim_end().to_string()
        };
        out.push((k.to_string(), val));
    }
    out
}

fn closes(s: &str) -> bool {
    let mut esc = false;
    for c in s.chars() {
        match (esc, c) {
            (true, _) => esc = false,
            (false, '\\') => esc = true,
            (false, '"') => return true,
            _ => {}
        }
    }
    false
}

fn files(paths: &Paths, cwd: &Path) -> Vec<PathBuf> {
    let mut v = vec![paths.config_dir.join(".env")];
    let trusted = std::fs::read_to_string(paths.user_config()).ok().and_then(|t| t.parse::<toml::Table>().ok()).and_then(|t| t.get("trusted_projects").and_then(|a| a.as_array()).cloned()).unwrap_or_default();
    let ws = cwd.canonicalize().ok();
    if trusted.iter().filter_map(|x| x.as_str()).any(|t| Path::new(t).canonicalize().ok() == ws && ws.is_some()) {
        v.push(cwd.join(".ark/.env"));
    }
    v
}

/// Apply files to the environment. Returns (applied, skipped-because-already-set, warnings).
fn apply(files: &[PathBuf], reload: bool) -> (Vec<String>, Vec<String>, Vec<String>) {
    let (mut applied, mut skipped, mut warn) = (vec![], vec![], vec![]);
    let mut loaded = LOADED.lock().unwrap();
    for f in files {
        let Ok(text) = std::fs::read_to_string(f) else { continue };
        for (k, mut v) in parse(&text) {
            if CREDENTIAL_SUFFIXES.iter().any(|s| k.ends_with(s)) && !v.is_ascii() {
                v.retain(|c| c.is_ascii());
                warn.push(format!("{k} in {} had non-ASCII characters (removed; credentials must be plain ASCII)", f.display()));
            }
            let ours = loaded.get(&k).is_some_and(|prev| std::env::var(&k).ok().as_deref() == Some(prev));
            match std::env::var(&k) {
                Ok(cur) if cur == v => {}
                Ok(_) if !(reload && ours) => skipped.push(k),
                _ => {
                    std::env::set_var(&k, &v);
                    loaded.insert(k.clone(), v);
                    applied.push(k);
                }
            }
        }
    }
    (applied, skipped, warn)
}

pub fn early() {
    let paths = Paths::from_env();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let (_, _, warn) = apply(&files(&paths, &cwd), false);
    for w in warn {
        eprintln!("ark: warning: {w}");
    }
}

/// `/reload`: re-read the .env files; returns the names that changed.
pub fn reload(paths: &Paths, cwd: &Path) -> Result<String, String> {
    let fs = files(paths, cwd);
    let (applied, skipped, warn) = apply(&fs, true);
    let mut o = if applied.is_empty() { "no changes".to_string() } else { format!("reloaded {}", applied.join(", ")) };
    if !skipped.is_empty() {
        o.push_str(&format!("\nkept the process value of {} (set outside .env)", skipped.join(", ")));
    }
    for w in warn {
        o.push_str(&format!("\n{w}"));
    }
    o.push_str(&format!("\nfrom {}", fs.iter().filter(|f| f.exists()).map(|f| f.display().to_string()).collect::<Vec<_>>().join(", ")));
    Ok(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dotenv_syntax() {
        let t = "# c\nA=1\nexport B = two words # note\nC=\"x\\ny \\\"q\\\"\"\nD='lit $X'\nE=\"multi\nline\"\n1BAD=x\nbad line\nF=\n";
        let v = parse(t);
        assert_eq!(v, vec![("A".into(), "1".into()), ("B".into(), "two words".into()), ("C".into(), "x\ny \"q\"".into()), ("D".into(), "lit $X".into()), ("E".into(), "multi\nline".into()), ("F".into(), String::new())]);
    }

    #[test]
    fn process_env_wins_and_reload_updates_ours() {
        let d = std::env::temp_dir().join(format!("ark-env-{}", ark_kernel::util::random_hex(6)));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join(".env");
        std::env::set_var("ARK_T_PRESET_X1", "process");
        std::fs::write(&f, "ARK_T_PRESET_X1=file\nARK_T_NEW_X1=one\nARK_T_SECRET_X1_TOKEN=abcé\n").unwrap();
        let (a, s, w) = apply(std::slice::from_ref(&f), false);
        assert_eq!(std::env::var("ARK_T_PRESET_X1").unwrap(), "process");
        assert!(s.contains(&"ARK_T_PRESET_X1".to_string()) && a.contains(&"ARK_T_NEW_X1".to_string()));
        assert_eq!(std::env::var("ARK_T_SECRET_X1_TOKEN").unwrap(), "abc");
        assert_eq!(w.len(), 1);
        std::fs::write(&f, "ARK_T_NEW_X1=two\n").unwrap();
        let (a, _, _) = apply(&[f], true);
        assert_eq!((a, std::env::var("ARK_T_NEW_X1").unwrap()), (vec!["ARK_T_NEW_X1".to_string()], "two".to_string()));
    }
}
