//! Hand-written glob matcher, .gitignore-aware walker, and the glob/grep tools.

use crate::util::{display_path, io_err, is_binary, truncate_str};
use ark_core::tool::{arg_opt_bool, arg_opt_str, arg_opt_u64, arg_str};
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use regex::RegexBuilder;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

const SKIP_DIRS: [&str; 3] = [".git", "target", "node_modules"];
const MAX_VISIT: usize = 200_000;
const MAX_GREP_FILE: u64 = 10 * 1024 * 1024;

// ---------- glob matching ----------

/// Expand `{a,b}` alternatives (nested allowed).
pub fn expand_braces(p: &str) -> Vec<String> {
    let bytes: Vec<char> = p.chars().collect();
    let Some(open) = bytes.iter().position(|&c| c == '{') else { return vec![p.to_string()] };
    let mut depth = 0;
    let mut close = None;
    let mut splits = Vec::new();
    for (i, &c) in bytes.iter().enumerate().skip(open) {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            ',' if depth == 1 => splits.push(i),
            _ => {}
        }
    }
    let Some(close) = close else { return vec![p.to_string()] };
    let pre: String = bytes[..open].iter().collect();
    let post: String = bytes[close + 1..].iter().collect();
    let mut bounds = vec![open];
    bounds.extend(&splits);
    bounds.push(close);
    let mut out = Vec::new();
    for w in bounds.windows(2) {
        let alt: String = bytes[w[0] + 1..w[1]].iter().collect();
        out.extend(expand_braces(&format!("{pre}{alt}{post}")));
    }
    out
}

/// Match one path segment against a pattern with `*`, `?`, `[...]`.
pub fn match_segment(pat: &str, s: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let s: Vec<char> = s.chars().collect();
    seg(&p, &s)
}

fn seg(p: &[char], s: &[char]) -> bool {
    match p.first() {
        None => s.is_empty(),
        Some('*') => (0..=s.len()).any(|i| seg(&p[1..], &s[i..])),
        Some('?') => !s.is_empty() && seg(&p[1..], &s[1..]),
        Some('[') => {
            let Some(end) = p.iter().skip(1).position(|&c| c == ']').map(|i| i + 1) else {
                return s.first() == Some(&'[') && seg(&p[1..], &s[1..]);
            };
            let Some(&c) = s.first() else { return false };
            let mut class = &p[1..end];
            let negate = matches!(class.first(), Some('!') | Some('^'));
            if negate {
                class = &class[1..];
            }
            let mut hit = false;
            let mut i = 0;
            while i < class.len() {
                if i + 2 < class.len() && class[i + 1] == '-' {
                    hit |= class[i] <= c && c <= class[i + 2];
                    i += 3;
                } else {
                    hit |= class[i] == c;
                    i += 1;
                }
            }
            hit != negate && seg(&p[end + 1..], &s[1..])
        }
        Some(&ch) => s.first() == Some(&ch) && seg(&p[1..], &s[1..]),
    }
}

/// Match `/`-separated segments; `**` spans zero or more segments.
pub fn match_segments(pat: &[&str], path: &[&str]) -> bool {
    match pat.first() {
        None => path.is_empty(),
        Some(&"**") => (0..=path.len()).any(|i| match_segments(&pat[1..], &path[i..])),
        Some(p) => !path.is_empty() && match_segment(p, path[0]) && match_segments(&pat[1..], &path[1..]),
    }
}

pub fn glob_match(pattern: &str, rel: &str) -> bool {
    let rel: Vec<&str> = rel.split('/').filter(|s| !s.is_empty()).collect();
    expand_braces(pattern).iter().any(|p| {
        let segs: Vec<&str> = p.trim_start_matches("./").split('/').filter(|s| !s.is_empty()).collect();
        match_segments(&segs, &rel)
    })
}

// ---------- .gitignore ----------

#[derive(Debug, Clone)]
struct Rule {
    pat: String,
    anchored: bool,
    dir_only: bool,
    negate: bool,
}

fn parse_gitignore(text: &str) -> Vec<Rule> {
    text.lines()
        .filter_map(|l| {
            let mut l = l.trim_end();
            if l.is_empty() || l.starts_with('#') {
                return None;
            }
            let negate = l.starts_with('!');
            if negate {
                l = &l[1..];
            }
            let dir_only = l.ends_with('/');
            let l = l.trim_end_matches('/');
            let anchored = l.contains('/');
            let pat = l.trim_start_matches('/').to_string();
            (!pat.is_empty()).then_some(Rule { pat, anchored, dir_only, negate })
        })
        .collect()
}

fn rule_hit(r: &Rule, rel: &str, is_dir: bool) -> bool {
    if r.dir_only && !is_dir {
        return false;
    }
    if r.anchored {
        glob_match(&r.pat, rel)
    } else {
        let name = rel.rsplit('/').next().unwrap_or(rel);
        match_segment(&r.pat, name)
    }
}

fn ignored(stack: &[(PathBuf, Vec<Rule>)], path: &Path, is_dir: bool) -> bool {
    let mut result = false;
    for (base, rules) in stack {
        let Ok(rel) = path.strip_prefix(base) else { continue };
        let rel = rel.to_string_lossy().replace('\\', "/");
        for r in rules {
            if rule_hit(r, &rel, is_dir) {
                result = !r.negate;
            }
        }
    }
    result
}

/// All regular files under `root`, honoring SKIP_DIRS and .gitignore files.
pub fn walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut visited = 0usize;
    let mut stack = Vec::new();
    visit(root, &mut stack, &mut out, &mut visited);
    out
}

fn visit(dir: &Path, stack: &mut Vec<(PathBuf, Vec<Rule>)>, out: &mut Vec<PathBuf>, visited: &mut usize) {
    let pushed = match fs::read_to_string(dir.join(".gitignore")) {
        Ok(t) => {
            stack.push((dir.to_path_buf(), parse_gitignore(&t)));
            true
        }
        Err(_) => false,
    };
    if let Ok(rd) = fs::read_dir(dir) {
        let mut entries: Vec<_> = rd.filter_map(|e| e.ok()).collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            *visited += 1;
            if *visited > MAX_VISIT {
                break;
            }
            let path = e.path();
            let Ok(ft) = e.file_type() else { continue };
            // Never follow symlinked directories (cycles); symlinked files are fine.
            let is_dir = ft.is_dir();
            let is_file = ft.is_file() || (ft.is_symlink() && path.is_file());
            if is_dir && SKIP_DIRS.contains(&e.file_name().to_string_lossy().as_ref()) {
                continue;
            }
            if ignored(stack, &path, is_dir) {
                continue;
            }
            if is_dir {
                visit(&path, stack, out, visited);
            } else if is_file {
                out.push(path);
            }
        }
    }
    if pushed {
        stack.pop();
    }
}

fn rel_of(base: &Path, p: &Path) -> String {
    p.strip_prefix(base).unwrap_or(p).to_string_lossy().replace('\\', "/")
}

// ---------- tools ----------

pub struct Glob;

impl Tool for Glob {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "glob".into(),
            description: "Find files by glob pattern (`**` spans directories, `{a,b}` alternatives). Respects .gitignore. Newest first.".into(),
            input_schema: json!({"type":"object","properties":{
                "pattern":{"type":"string","description":"e.g. src/**/*.rs"},
                "path":{"type":"string","description":"Directory to search (default: workspace)"}},
                "required":["pattern"]}),
            parallel_safe: true,
            idempotent: true,
            pinned: true,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        vec![Effect::Read { path: ctx.resolve(arg_opt_str(input, "path").unwrap_or(".")) }]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let pattern = match arg_str(&input, "pattern") {
            Ok(p) if !p.trim().is_empty() => p,
            Ok(_) => return ToolOutput::err("pattern must not be empty"),
            Err(e) => return ToolOutput::err(e),
        };
        let base = ctx.resolve(arg_opt_str(&input, "path").unwrap_or("."));
        match fs::metadata(&base) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return ToolOutput::err(format!("{} is not a directory", base.display())),
            Err(e) => return ToolOutput::err(io_err("search", &base, &e)),
        }
        let mut hits: Vec<(std::time::SystemTime, PathBuf)> = walk(&base)
            .into_iter()
            .filter(|p| glob_match(pattern, &rel_of(&base, p)))
            .map(|p| (fs::metadata(&p).and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH), p))
            .collect();
        if hits.is_empty() {
            let hint = if pattern.contains('/') {
                String::new()
            } else {
                format!(" (pattern has no `/`, so it only matches top-level files; try **/{pattern})")
            };
            return ToolOutput::ok(format!("no files match {pattern}{hint}"));
        }
        hits.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        let total = hits.len();
        let mut out: Vec<String> = hits.iter().take(500).map(|(_, p)| display_path(&ctx.workspace, p)).collect();
        if total > 500 {
            out.push(format!("… {} more (narrow the pattern)", total - 500));
        }
        ToolOutput::ok(out.join("\n"))
    }
}

pub struct Grep;

impl Tool for Grep {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "grep".into(),
            description: "Search file contents with a regex. Output is path:line:text. Respects .gitignore, skips binary files.".into(),
            input_schema: json!({"type":"object","properties":{
                "pattern":{"type":"string","description":"Rust regex syntax"},
                "path":{"type":"string","description":"File or directory (default: workspace)"},
                "glob":{"type":"string","description":"Only search files matching this glob, e.g. *.rs or src/**/*.ts"},
                "case_insensitive":{"type":"boolean"},
                "max_results":{"type":"integer","minimum":1,"maximum":2000}},
                "required":["pattern"]}),
            parallel_safe: true,
            idempotent: true,
            pinned: true,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        vec![Effect::Read { path: ctx.resolve(arg_opt_str(input, "path").unwrap_or(".")) }]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let pattern = match arg_str(&input, "pattern") {
            Ok(p) => p,
            Err(e) => return ToolOutput::err(e),
        };
        let re = match RegexBuilder::new(pattern)
            .case_insensitive(arg_opt_bool(&input, "case_insensitive").unwrap_or(false))
            .size_limit(1 << 22)
            .build()
        {
            Ok(r) => r,
            Err(e) => return ToolOutput::err(format!("invalid regex: {e}")),
        };
        let max = arg_opt_u64(&input, "max_results").unwrap_or(200).clamp(1, 2000) as usize;
        let base = ctx.resolve(arg_opt_str(&input, "path").unwrap_or("."));
        let meta = match fs::metadata(&base) {
            Ok(m) => m,
            Err(e) => return ToolOutput::err(io_err("search", &base, &e)),
        };
        let files = if meta.is_dir() { walk(&base) } else { vec![base.clone()] };
        let filter = arg_opt_str(&input, "glob");
        let mut out = Vec::new();
        let mut truncated = false;
        let mut skipped_binary = 0;
        'files: for f in &files {
            if let Some(g) = filter {
                let rel = rel_of(&base, f);
                let target = if g.contains('/') { rel } else { rel.rsplit('/').next().unwrap_or("").to_string() };
                if !glob_match(g, &target) {
                    continue;
                }
            }
            if fs::metadata(f).map(|m| m.len() > MAX_GREP_FILE).unwrap_or(true) {
                continue;
            }
            let Ok(data) = fs::read(f) else { continue };
            if is_binary(&data) {
                skipped_binary += 1;
                continue;
            }
            let text = String::from_utf8_lossy(&data);
            for (i, line) in text.lines().enumerate() {
                if re.is_match(line) {
                    if out.len() >= max {
                        truncated = true;
                        break 'files;
                    }
                    out.push(format!("{}:{}:{}", display_path(&ctx.workspace, f), i + 1, truncate_str(line, 300)));
                }
            }
        }
        if out.is_empty() {
            return ToolOutput::ok(format!("no matches in {} file(s)", files.len()));
        }
        if truncated {
            out.push(format!("… stopped at {max} results (narrow the pattern or raise max_results)"));
        }
        if skipped_binary > 0 {
            out.push(format!("({skipped_binary} binary file(s) skipped)"));
        }
        ToolOutput::ok(out.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ctx;

    #[test]
    fn glob_semantics() {
        assert!(glob_match("src/**/*.rs", "src/a.rs"));
        assert!(glob_match("src/**/*.rs", "src/x/y/a.rs"));
        assert!(!glob_match("src/**/*.rs", "lib/a.rs"));
        assert!(glob_match("*.{rs,toml}", "Cargo.toml"));
        assert!(!glob_match("*.rs", "src/a.rs"));
        assert!(glob_match("**/*.rs", "a.rs"));
        assert!(glob_match("file[0-9].txt", "file7.txt"));
        assert!(!glob_match("file[!0-9].txt", "file7.txt"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
        assert!(glob_match("weird[", "weird["));
        assert_eq!(expand_braces("a{b,c{d,e}}f"), vec!["abf", "acdf", "acef"]);
        assert_eq!(expand_braces("unclosed{a"), vec!["unclosed{a"]);
    }

    fn tree(c: &ToolCtx) {
        let w = &c.workspace;
        for d in ["src/deep", "target/debug", "node_modules/x", ".git", "build", "logs"] {
            fs::create_dir_all(w.join(d)).unwrap();
        }
        fs::write(w.join(".gitignore"), "# comment\nbuild/\n*.log\n!keep.log\n/root_only.txt\n").unwrap();
        fs::write(w.join("src/a.rs"), "fn main() { todo!() }\n").unwrap();
        fs::write(w.join("src/deep/b.rs"), "// TODO later\nfn b() {}\n").unwrap();
        fs::write(w.join("target/debug/c.rs"), "TODO\n").unwrap();
        fs::write(w.join("node_modules/x/d.rs"), "TODO\n").unwrap();
        fs::write(w.join(".git/config"), "TODO\n").unwrap();
        fs::write(w.join("build/e.rs"), "TODO\n").unwrap();
        fs::write(w.join("logs/run.log"), "TODO\n").unwrap();
        fs::write(w.join("logs/keep.log"), "TODO kept\n").unwrap();
        fs::write(w.join("root_only.txt"), "TODO\n").unwrap();
        fs::write(w.join("src/root_only.txt"), "TODO nested\n").unwrap();
        fs::write(w.join("src/blob.bin"), [b'T', b'O', b'D', b'O', 0, 1]).unwrap();
        fs::write(w.join("src/deep/.gitignore"), "b.rs\n").unwrap();
    }

    #[test]
    fn walker_honors_skip_dirs_and_gitignore() {
        let c = ctx("walk");
        tree(&c);
        let files: Vec<String> = walk(&c.workspace).iter().map(|p| rel_of(&c.workspace, p)).collect();
        assert!(files.contains(&"src/a.rs".to_string()));
        assert!(files.contains(&"logs/keep.log".to_string()), "negation re-includes: {files:?}");
        assert!(files.contains(&"src/root_only.txt".to_string()), "anchored rule only hits root");
        for bad in ["target/debug/c.rs", "node_modules/x/d.rs", ".git/config", "build/e.rs", "logs/run.log", "root_only.txt", "src/deep/b.rs"] {
            assert!(!files.contains(&bad.to_string()), "{bad} should be ignored: {files:?}");
        }
    }

    #[test]
    fn glob_tool() {
        let c = ctx("globt");
        tree(&c);
        let o = Glob.call(&c, json!({"pattern":"**/*.rs"}));
        assert!(!o.is_error);
        assert_eq!(o.content.lines().collect::<Vec<_>>(), vec!["src/a.rs"]);
        let o = Glob.call(&c, json!({"pattern":"*.rs"}));
        assert!(o.content.contains("try **/*.rs"), "{}", o.content);
        assert!(Glob.call(&c, json!({})).is_error);
        assert!(Glob.call(&c, json!({"pattern":"  "})).is_error);
        assert!(Glob.call(&c, json!({"pattern":"*","path":"nope"})).is_error);
        assert!(Glob.call(&c, json!({"pattern":"*","path":"src/a.rs"})).is_error);
    }

    #[test]
    fn symlink_cycles_do_not_hang() {
        let c = ctx("cycle");
        fs::create_dir(c.workspace.join("d")).unwrap();
        std::os::unix::fs::symlink(&c.workspace, c.workspace.join("d/loop")).unwrap();
        fs::write(c.workspace.join("d/f.txt"), "x").unwrap();
        let files = walk(&c.workspace);
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn grep_tool() {
        let c = ctx("grep");
        tree(&c);
        let o = Grep.call(&c, json!({"pattern":"TODO"}));
        assert!(!o.is_error);
        assert!(o.content.contains("logs/keep.log:1:TODO kept"));
        assert!(o.content.contains("src/root_only.txt:1:TODO nested"));
        assert!(!o.content.contains("target/"));
        assert!(o.content.contains("1 binary file(s) skipped"));
        let o = Grep.call(&c, json!({"pattern":"todo","case_insensitive":true,"glob":"*.rs"}));
        assert_eq!(o.content, "src/a.rs:1:fn main() { todo!() }");
        let o = Grep.call(&c, json!({"pattern":"TODO","max_results":1}));
        assert!(o.content.contains("stopped at 1 results"));
        let o = Grep.call(&c, json!({"pattern":"(unclosed"}));
        assert!(o.is_error && o.content.contains("invalid regex"));
        assert!(Grep.call(&c, json!({"pattern":"x","path":"missing"})).is_error);
        assert!(Grep.call(&c, json!({})).is_error);
        let o = Grep.call(&c, json!({"pattern":"zzz_never"}));
        assert!(!o.is_error && o.content.starts_with("no matches"));
        let o = Grep.call(&c, json!({"pattern":"nested","path":"src/root_only.txt"}));
        assert_eq!(o.content, "src/root_only.txt:1:TODO nested");
    }
}
