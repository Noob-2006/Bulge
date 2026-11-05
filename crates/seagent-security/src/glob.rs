//! Two glob dialects used by approval rules.
//!
//! - [`fnmatch`]: Python `fnmatch.fnmatchcase` (Hermes `approvals.deny` and
//!   `command_allowlist`): `*` and `?` match any character including `/`,
//!   `[...]` / `[!...]` are character classes.
//! - [`path_glob`]: OpenClaw exec allowlist patterns: `**` crosses `/`, `*` and
//!   `?` stay inside one path segment, a leading `~` is the home directory.

/// Python `fnmatch.fnmatchcase(text, pattern)`.
pub fn fnmatch(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    fn_rec(&p, &t)
}

fn fn_rec(p: &[char], t: &[char]) -> bool {
    // Iterative with backtracking on the last `*` (linear-ish, no exponential blowup).
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() {
            match p[pi] {
                '*' => {
                    star = Some((pi, ti));
                    pi += 1;
                    continue;
                }
                '?' => {
                    pi += 1;
                    ti += 1;
                    continue;
                }
                '[' => {
                    if let Some((matched, next)) = class(p, pi, t[ti]) {
                        if matched {
                            pi = next;
                            ti += 1;
                            continue;
                        }
                    } else if t[ti] == '[' {
                        // Unterminated class: a literal `[`.
                        pi += 1;
                        ti += 1;
                        continue;
                    }
                }
                c if c == t[ti] => {
                    pi += 1;
                    ti += 1;
                    continue;
                }
                _ => {}
            }
        }
        match star {
            Some((sp, st)) => {
                pi = sp + 1;
                ti = st + 1;
                star = Some((sp, st + 1));
            }
            None => return false,
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// `[...]` at `p[i]`: Some((matches, index after `]`)), None when unterminated.
fn class(p: &[char], i: usize, c: char) -> Option<(bool, usize)> {
    let mut j = i + 1;
    let negate = j < p.len() && (p[j] == '!' || p[j] == '^');
    if negate {
        j += 1;
    }
    let start = j;
    let mut hit = false;
    while j < p.len() && (p[j] != ']' || j == start) {
        if j + 2 < p.len() && p[j + 1] == '-' && p[j + 2] != ']' {
            if p[j] <= c && c <= p[j + 2] {
                hit = true;
            }
            j += 3;
        } else {
            if p[j] == c {
                hit = true;
            }
            j += 1;
        }
    }
    if j >= p.len() {
        return None;
    }
    Some((hit != negate, j + 1))
}

/// OpenClaw `matchesExecAllowlistPattern`: `**` → any, `*` → `[^/]*`, `?` → `[^/]`.
/// `..`/`.` segments in the target are normalised first when the pattern has wildcards.
pub fn path_glob(pattern: &str, target: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return false;
    }
    let pattern = expand_home(pattern);
    let wild = pattern.contains('*') || pattern.contains('?');
    let target = if wild && target.split('/').any(|s| s == "." || s == "..") { normalize(target) } else { target.to_string() };
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = target.chars().collect();
    seg_rec(&p, 0, &t, 0, &mut 0)
}

fn seg_rec(p: &[char], pi: usize, t: &[char], ti: usize, steps: &mut usize) -> bool {
    *steps += 1;
    if *steps > 100_000 {
        return false;
    }
    if pi == p.len() {
        return ti == t.len();
    }
    if p[pi] == '*' {
        let double = pi + 1 < p.len() && p[pi + 1] == '*';
        let next = if double { pi + 2 } else { pi + 1 };
        let mut k = ti;
        loop {
            if seg_rec(p, next, t, k, steps) {
                return true;
            }
            if k == t.len() || (!double && t[k] == '/') {
                return false;
            }
            k += 1;
        }
    }
    if ti == t.len() {
        return false;
    }
    match p[pi] {
        '?' if t[ti] != '/' => seg_rec(p, pi + 1, t, ti + 1, steps),
        c if c == t[ti] => seg_rec(p, pi + 1, t, ti + 1, steps),
        _ => false,
    }
}

pub fn expand_home(p: &str) -> String {
    if p == "~" || p.starts_with("~/") {
        if let Some(h) = std::env::var_os("HOME") {
            return format!("{}{}", h.to_string_lossy(), &p[1..]);
        }
    }
    p.to_string()
}

/// Lexical `.`/`..` resolution for absolute and relative paths.
pub fn normalize(p: &str) -> String {
    let abs = p.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|l| *l != "..") {
                    parts.pop();
                } else if !abs {
                    parts.push("..");
                }
            }
            c => parts.push(c),
        }
    }
    let joined = parts.join("/");
    if abs {
        format!("/{joined}")
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnmatch_matches_python_semantics() {
        assert!(fnmatch("git push *", "git push origin main"));
        assert!(fnmatch("podman *", "podman run -it x"));
        assert!(!fnmatch("git push *", "git pull"));
        assert!(fnmatch("rm -rf /*", "rm -rf /home/x/y"), "`*` crosses slashes");
        assert!(fnmatch("a?c", "abc") && !fnmatch("a?c", "ac"));
        assert!(fnmatch("[abc]x", "bx") && !fnmatch("[!abc]x", "bx") && fnmatch("[a-c]1", "c1"));
        assert!(fnmatch("*", "") && fnmatch("**", "anything"));
        assert!(fnmatch("x[", "x["), "unterminated class is literal");
        assert!(!fnmatch("abc", "abcd"));
        // Pathological pattern stays fast.
        let long = "a".repeat(5000);
        assert!(!fnmatch("*a*a*a*a*a*b", &long));
    }

    #[test]
    fn path_glob_segments() {
        assert!(path_glob("/usr/bin/rg", "/usr/bin/rg"));
        assert!(path_glob("/opt/**/bin/rg", "/opt/x/y/bin/rg"));
        assert!(path_glob("/opt/*/bin/rg", "/opt/x/bin/rg"));
        assert!(!path_glob("/opt/*/bin/rg", "/opt/x/y/bin/rg"), "* stays in one segment");
        assert!(path_glob("/usr/bin/*", "/usr/bin/../bin/git"), "dot segments normalised for wildcards");
        assert!(!path_glob("/usr/bin/?", "/usr/bin//"));
        assert!(!path_glob("", "/x"));
        if let Some(h) = std::env::var_os("HOME") {
            assert!(path_glob("~/bin/*", &format!("{}/bin/tool", h.to_string_lossy())));
        }
    }

    #[test]
    fn normalize_paths() {
        assert_eq!(normalize("/a/b/../c/./d"), "/a/c/d");
        assert_eq!(normalize("/../.."), "/");
        assert_eq!(normalize("a/../../b"), "../b");
    }
}
