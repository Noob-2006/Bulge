//! Tiny argument parser: positionals, `--flag value`, `--flag=value`, `-x value`,
//! boolean switches. Unknown flags are errors (typos must not silently pass).

use std::collections::HashMap;

pub const VALUE_FLAGS: &[&str] = &["agent", "model", "workspace", "set", "budget-tokens", "budget-usd", "max-steps", "session", "rounds", "from", "limit", "lang", "timeout", "url", "header", "cwd", "permission-mode", "relay", "setup-code", "ttl", "tls-fingerprint", "name", "days", "type", "label", "priority", "api-key", "as", "min-count", "apply", "fail-on", "security", "ask", "ask-fallback", "reason", "phase", "port", "ready-timeout", "format", "out", "retention-days", "max-size-mb", "dataset", "env", "preset", "for-tool", "payload-file", "payload", "output-schema", "references", "aggregator", "ref-reasoning", "title", "min-messages", "max-messages"];
pub const BOOL_FLAGS: &[&str] = &["yes", "allow-privilege", "allow-egress", "json", "quiet", "reuse", "user", "now", "help", "follow", "fork", "all", "device", "no-browser", "no-start", "list", "pair", "queue", "account", "billing", "import", "yolo", "exec", "deep", "fix", "supply-chain", "verbose", "detect-only", "save", "skip-start", "installed-only", "keep-orphans", "force", "no-redact", "public", "accept-hooks", "link", "default", "include-pinned", "include-archived", "check-only"];

#[derive(Debug, Default)]
pub struct Args {
    pub pos: Vec<String>,
    vals: HashMap<String, Vec<String>>,
    bools: Vec<String>,
}

fn long(short: &str) -> Option<&'static str> {
    Some(match short {
        "m" => "model",
        "w" => "workspace",
        "y" => "yes",
        "q" => "quiet",
        "h" => "help",
        "s" => "session",
        "f" => "follow",
        _ => return None,
    })
}

impl Args {
    pub fn parse(raw: &[String]) -> Result<Args, String> {
        let mut a = Args::default();
        let mut i = 0;
        let mut only_pos = false;
        while i < raw.len() {
            let r = &raw[i];
            i += 1;
            if only_pos || r == "-" || !r.starts_with('-') {
                a.pos.push(r.clone());
                continue;
            }
            if r == "--" {
                only_pos = true;
                continue;
            }
            let (name, inline) = if let Some(rest) = r.strip_prefix("--") {
                match rest.split_once('=') {
                    Some((n, v)) => (n.to_string(), Some(v.to_string())),
                    None => (rest.to_string(), None),
                }
            } else {
                let s = &r[1..];
                (long(s).ok_or_else(|| format!("unknown option -{s}"))?.to_string(), None)
            };
            if VALUE_FLAGS.contains(&name.as_str()) || crate::ops::is_value_flag(&name) {
                let v = match inline {
                    Some(v) => v,
                    None => {
                        let v = raw.get(i).cloned().ok_or_else(|| format!("--{name} needs a value"))?;
                        i += 1;
                        v
                    }
                };
                a.vals.entry(name).or_default().push(v);
            } else if BOOL_FLAGS.contains(&name.as_str()) || crate::ops::is_bool_flag(&name) {
                if inline.is_some() {
                    return Err(format!("--{name} takes no value"));
                }
                a.bools.push(name);
            } else {
                return Err(format!("unknown option --{name}"));
            }
        }
        Ok(a)
    }
    pub fn val(&self, k: &str) -> Option<&str> {
        self.vals.get(k).and_then(|v| v.last()).map(|s| s.as_str())
    }
    pub fn vals(&self, k: &str) -> Vec<String> {
        self.vals.get(k).cloned().unwrap_or_default()
    }
    pub fn flag(&self, k: &str) -> bool {
        self.bools.iter().any(|b| b == k)
    }
    pub fn num<T: std::str::FromStr>(&self, k: &str) -> Result<Option<T>, String> {
        match self.val(k) {
            None => Ok(None),
            Some(v) => v.parse().map(Some).map_err(|_| format!("--{k}: `{v}` is not a valid number")),
        }
    }
    pub fn pos(&self, i: usize) -> Option<&str> {
        self.pos.get(i).map(|s| s.as_str())
    }
    pub fn need(&self, i: usize, what: &str) -> Result<&str, String> {
        self.pos(i).ok_or_else(|| format!("missing <{what}>"))
    }
    pub fn rest(&self, from: usize) -> String {
        self.pos.iter().skip(from).cloned().collect::<Vec<_>>().join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(v: &[&str]) -> Result<Args, String> {
        Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn parses_mixed() {
        let a = p(&["fix", "-m", "a/b", "the", "--set", "x=1", "--set=y=2", "--yes", "bug", "--", "--not-a-flag"]).unwrap();
        assert_eq!(a.pos, ["fix", "the", "bug", "--not-a-flag"]);
        assert_eq!(a.val("model"), Some("a/b"));
        assert_eq!(a.vals("set"), ["x=1", "y=2"]);
        assert!(a.flag("yes") && !a.flag("json"));
        assert_eq!(a.rest(1), "the bug --not-a-flag");
    }

    #[test]
    fn rejects_bad_input() {
        assert!(p(&["--modle", "x"]).unwrap_err().contains("unknown option --modle"));
        assert!(p(&["-z"]).is_err());
        assert!(p(&["--model"]).unwrap_err().contains("needs a value"));
        assert!(p(&["--yes=1"]).is_err());
        let a = p(&["--max-steps", "ten"]).unwrap();
        assert!(a.num::<u64>("max-steps").is_err());
        assert!(a.need(0, "prompt").is_err());
    }
}
