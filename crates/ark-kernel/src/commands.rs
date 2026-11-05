//! Custom instructions invoked as `/name args`: Markdown files in
//! `.ark/commands/`, `.claude/commands/` (Claude Code compatible) and the
//! user's `commands/` dir. `$ARGUMENTS` and `$1`…`$9` are substituted; a file
//! without placeholders gets the arguments appended. Subdirectories become
//! namespaces (`git/commit.md` → `/git:commit`).

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub struct CommandDef {
    pub name: String,
    pub description: String,
    pub path: PathBuf,
}

pub fn dirs(data: &Path, workspace: &Path) -> Vec<PathBuf> {
    let mut v = vec![workspace.join(".ark/commands"), workspace.join(".claude/commands"), data.join("commands")];
    if let Some(h) = std::env::var_os("HOME") {
        v.push(PathBuf::from(h).join(".claude/commands"));
    }
    v
}

/// First definition of a name wins (project before user).
pub fn discover(dirs: &[PathBuf]) -> Vec<CommandDef> {
    let mut out: Vec<CommandDef> = Vec::new();
    for d in dirs {
        walk(d, d, 0, &mut out);
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn walk(root: &Path, dir: &Path, depth: u32, out: &mut Vec<CommandDef>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        if p.is_dir() && depth < 2 {
            walk(root, &p, depth + 1, out);
        } else if p.extension().is_some_and(|x| x == "md") {
            let rel = p.strip_prefix(root).unwrap_or(&p).with_extension("");
            let name = rel.to_string_lossy().replace('/', ":");
            if out.iter().any(|c| c.name == name) {
                continue;
            }
            let text = std::fs::read_to_string(&p).unwrap_or_default();
            let (fm, body) = split_frontmatter(&text);
            let description = fm.lines().find_map(|l| l.strip_prefix("description:")).map(|d| d.trim().trim_matches('"').to_string()).unwrap_or_else(|| body.lines().find(|l| !l.trim().is_empty()).unwrap_or("").chars().take(80).collect());
            out.push(CommandDef { name, description, path: p });
        }
    }
}

fn split_frontmatter(t: &str) -> (&str, &str) {
    if let Some(rest) = t.strip_prefix("---\n") {
        if let Some(end) = rest.find("\n---") {
            let body = rest[end + 4..].trim_start_matches('\n');
            return (&rest[..end], body);
        }
    }
    ("", t)
}

/// Quote-aware split: `a "b c" d` → [a, b c, d].
pub fn split_args(s: &str) -> Vec<String> {
    let mut v = Vec::new();
    let mut cur = String::new();
    let mut q: Option<char> = None;
    let mut any = false;
    for c in s.chars() {
        match (q, c) {
            (None, '"' | '\'') => {
                q = Some(c);
                any = true;
            }
            (Some(x), c) if c == x => q = None,
            (None, c) if c.is_whitespace() => {
                if any || !cur.is_empty() {
                    v.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            (_, c) => cur.push(c),
        }
    }
    if any || !cur.is_empty() {
        v.push(cur);
    }
    v
}

pub fn render(body: &str, args: &str) -> String {
    let args = args.trim();
    let parts = split_args(args);
    let mut out = body.replace("$ARGUMENTS", args);
    let mut used = out != body;
    for i in (1..=9).rev() {
        let key = format!("${i}");
        if out.contains(&key) {
            out = out.replace(&key, parts.get(i - 1).map(String::as_str).unwrap_or(""));
            used = true;
        }
    }
    if !used && !args.is_empty() {
        out = format!("{}\n\n{args}", out.trim_end());
    }
    out
}

/// Resolves names this module doesn't know (MCP prompts); None = not mine.
pub type ExtraResolver<'a> = &'a dyn Fn(&str, &str) -> Option<Result<String, String>>;

pub enum Expanded {
    /// Not a slash command (or an unknown one): send as-is.
    Plain,
    Text(String),
    Error(String),
}

/// Expand `/name args`. `extra` resolves names this module doesn't know
/// (MCP prompts); it returns None for "not mine".
pub fn expand(input: &str, defs: &[CommandDef], extra: ExtraResolver) -> Expanded {
    let Some(rest) = input.trim_start().strip_prefix('/') else { return Expanded::Plain };
    let (name, args) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
    if name.is_empty() || name.contains('/') {
        return Expanded::Plain; // a path like /etc/hosts, not a command
    }
    if let Some(d) = defs.iter().find(|d| d.name == name) {
        return match std::fs::read_to_string(&d.path) {
            Ok(t) => Expanded::Text(render(split_frontmatter(&t).1, args)),
            Err(e) => Expanded::Error(format!("/{name}: {e}")),
        };
    }
    match extra(name, args) {
        Some(Ok(t)) => Expanded::Text(t),
        Some(Err(e)) => Expanded::Error(format!("/{name}: {e}")),
        None => Expanded::Plain,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_render_and_expand() {
        let root = ark_core::tmp::scratch_path(format!("ark-cmd-{}", crate::util::random_hex(6)));
        let a = root.join("proj");
        let b = root.join("user");
        std::fs::create_dir_all(a.join("git")).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(a.join("review.md"), "---\ndescription: \"Review code\"\n---\nReview $1 focusing on $2.\nAll: $ARGUMENTS").unwrap();
        std::fs::write(a.join("git/commit.md"), "Write a commit message.").unwrap();
        std::fs::write(b.join("review.md"), "user version").unwrap();
        std::fs::write(b.join("notes.txt"), "ignored").unwrap();
        let defs = discover(&[a.clone(), b.clone(), root.join("missing")]);
        let names: Vec<_> = defs.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["git:commit", "review"]);
        assert_eq!(defs[1].description, "Review code");
        assert_eq!(defs[0].description, "Write a commit message.");
        let none = |_: &str, _: &str| None;
        match expand("/review src/main.rs \"error handling\"", &defs, &none) {
            Expanded::Text(t) => assert_eq!(t, "Review src/main.rs focusing on error handling.\nAll: src/main.rs \"error handling\""),
            _ => panic!(),
        }
        match expand("/git:commit fix typo", &defs, &none) {
            Expanded::Text(t) => assert_eq!(t, "Write a commit message.\n\nfix typo"),
            _ => panic!(),
        }
        assert!(matches!(expand("/etc/hosts is broken", &defs, &none), Expanded::Plain));
        assert!(matches!(expand("/unknown x", &defs, &none), Expanded::Plain));
        assert!(matches!(expand("hello /review", &defs, &none), Expanded::Plain));
        assert!(matches!(expand("/", &defs, &none), Expanded::Plain));
        let mcp = |n: &str, a: &str| (n == "mcp__s__p").then(|| if a.is_empty() { Err("missing argument `topic`".to_string()) } else { Ok(format!("prompt {a}")) });
        assert!(matches!(expand("/mcp__s__p x", &defs, &mcp), Expanded::Text(t) if t == "prompt x"));
        assert!(matches!(expand("/mcp__s__p", &defs, &mcp), Expanded::Error(e) if e.contains("topic")));
        std::fs::remove_file(a.join("review.md")).unwrap();
        assert!(matches!(expand("/review x", &defs, &none), Expanded::Error(_)), "vanished file is an error, not silence");
    }

    #[test]
    fn args_and_placeholders() {
        assert_eq!(split_args(r#"a "b c" 'd e' f"#), ["a", "b c", "d e", "f"]);
        assert_eq!(split_args(r#""" x"#), ["", "x"]);
        assert_eq!(render("do $1 and $3", "one"), "do one and ");
        assert_eq!(render("plain", ""), "plain");
    }
}
