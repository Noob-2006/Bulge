//! @-references in user prompts (Hermes `agent/context_references.py`, MIT):
//! `@file:path[:a-b]`, `@folder:dir`, `@diff`, `@staged`, `@git:N`, `@url:https://…`.
//! The typed token stays where it was; expansions go below an `--- Attached Context ---`
//! footer. Budgets: one file never inlines past 50% of the window, the whole message is
//! refused past 50% and warned past 25%; at most 16 references per message. Paths must stay
//! inside the workspace and never name credential files.

use seagent_core::estimate_tokens;
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub const MAX_REFERENCES: usize = 16;
const TRAILING_PUNCTUATION: &[char] = &[',', '.', ';', '!', '?'];
const SENSITIVE_HOME_FILES: &[&str] = &[".ssh/authorized_keys", ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/config", ".bashrc", ".zshrc", ".profile", ".bash_profile", ".zprofile", ".netrc", ".pgpass", ".npmrc", ".pypirc"];
/// Hermes `file_safety.HOME_CREDENTIAL_DIRS`.
pub const HOME_CREDENTIAL_DIRS: &[&str] = &[".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure", ".config/gh", ".config/gcloud"];
const TEXT_EXTENSIONS: &[&str] = &["py", "md", "txt", "json", "yaml", "yml", "toml", "js", "ts"];
const BINARY_EXTENSIONS: &[&str] = &["png", "jpg", "jpeg", "gif", "webp", "bmp", "ico", "tiff", "pdf", "zip", "gz", "tgz", "bz2", "xz", "7z", "rar", "tar", "jar", "class", "so", "dylib", "dll", "exe", "bin", "o", "a", "wasm", "mp3", "mp4", "mov", "avi", "mkv", "wav", "flac", "ogg", "woff", "woff2", "ttf", "otf", "sqlite", "db", "doc", "docx", "xls", "xlsx", "ppt", "pptx"];
const FOLDER_LIMIT: usize = 200;
const LINE_COUNT_MAX_BYTES: u64 = 4 * 1024 * 1024;
const MAX_QUIET_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const CHARS_PER_TOKEN: usize = 4;

#[derive(Debug, Clone, PartialEq)]
pub struct Reference {
    pub raw: String,
    pub kind: String,
    pub target: String,
    pub start: usize,
    pub end: usize,
    pub line_start: Option<usize>,
    pub line_end: Option<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct Expanded {
    pub message: String,
    pub references: Vec<Reference>,
    pub warnings: Vec<String>,
    pub injected_tokens: u64,
    pub expanded: bool,
    pub blocked: bool,
}

/// How the expander fetches a URL it is asked to attach.
pub type FetchFn = dyn Fn(&str) -> Result<String, String> + Sync;

/// What the expander may touch.
pub struct Env<'a> {
    pub cwd: &'a Path,
    /// Paths must stay under this root (default: the workspace).
    pub allowed_root: &'a Path,
    pub context_length: u64,
    pub home: Option<PathBuf>,
    /// Extra files that must never be attached (seagent's secrets file, …).
    pub deny: Vec<PathBuf>,
    pub fetch: Option<&'a FetchFn>,
}

fn pattern() -> &'static regex::Regex {
    static P: OnceLock<regex::Regex> = OnceLock::new();
    P.get_or_init(|| regex::Regex::new(r#"@(?:(diff|staged)\b|(file|folder|git|url):((?:`[^`\n]+`|"[^"\n]+"|'[^'\n]+')(?::\d+(?:-\d+)?)?|\S+))"#).unwrap())
}

/// `(?<![\w/])`: the `@` must not continue a word or a path (emails, `a/@b`).
fn boundary_ok(msg: &str, at: usize) -> bool {
    msg[..at].chars().next_back().is_none_or(|c| !(c.is_alphanumeric() || c == '_' || c == '/'))
}

pub fn parse(message: &str) -> Vec<Reference> {
    let mut out = Vec::new();
    for c in pattern().captures_iter(message) {
        let m = c.get(0).unwrap();
        if !boundary_ok(message, m.start()) {
            continue;
        }
        if let Some(s) = c.get(1) {
            out.push(Reference { raw: m.as_str().into(), kind: s.as_str().into(), target: String::new(), start: m.start(), end: m.end(), line_start: None, line_end: None });
            continue;
        }
        let kind = c.get(2).unwrap().as_str().to_string();
        let value = strip_trailing_punctuation(c.get(3).map(|v| v.as_str()).unwrap_or(""));
        let (target, a, b) = if kind == "file" { parse_file_value(&value) } else { (strip_wrappers(&value), None, None) };
        // The raw token loses the stripped punctuation too.
        let end = m.start() + 1 + kind.len() + 1 + value.len();
        out.push(Reference { raw: message[m.start()..end].to_string(), kind, target, start: m.start(), end, line_start: a, line_end: b });
    }
    out
}

fn strip_trailing_punctuation(v: &str) -> String {
    let mut s = v.trim_end_matches(TRAILING_PUNCTUATION).to_string();
    // Drop unbalanced closers so "(see @file:x.py)" does not swallow the ")".
    while let Some(last) = s.chars().last() {
        let open = match last {
            ')' => '(',
            ']' => '[',
            '}' => '{',
            _ => break,
        };
        if s.matches(last).count() > s.matches(open).count() {
            s.pop();
        } else {
            break;
        }
    }
    s
}

fn strip_wrappers(v: &str) -> String {
    let b = v.as_bytes();
    if b.len() >= 2 && b[0] == b[b.len() - 1] && matches!(b[0], b'`' | b'"' | b'\'') {
        v[1..v.len() - 1].to_string()
    } else {
        v.to_string()
    }
}

/// `path`, `path:10`, `path:10-20`, or a quoted path with an optional range.
fn parse_file_value(v: &str) -> (String, Option<usize>, Option<usize>) {
    static BARE: OnceLock<regex::Regex> = OnceLock::new();
    static RANGE: OnceLock<regex::Regex> = OnceLock::new();
    let range = RANGE.get_or_init(|| regex::Regex::new(r"^:(\d+)(?:-(\d+))?$").unwrap());
    let nums = |c: regex::Captures| {
        let a: usize = c[1].parse().unwrap_or(1);
        let b = c.get(2).and_then(|b| b.as_str().parse().ok()).unwrap_or(a);
        (Some(a), Some(b))
    };
    if let Some(q) = v.chars().next().filter(|q| matches!(q, '`' | '"' | '\'')) {
        if let Some(close) = v[1..].find(q) {
            let path = v[1..1 + close].to_string();
            let rest = &v[2 + close..];
            if rest.is_empty() {
                return (path, None, None);
            }
            if let Some(c) = range.captures(rest) {
                let (a, b) = nums(c);
                return (path, a, b);
            }
        }
        return (strip_wrappers(v), None, None);
    }
    let bare = BARE.get_or_init(|| regex::Regex::new(r"^(.+?)(?::(\d+)(?:-(\d+))?)?$").unwrap());
    match bare.captures(v) {
        Some(c) if c.get(2).is_some() => {
            let a: usize = c[2].parse().unwrap_or(1);
            let b = c.get(3).and_then(|b| b.as_str().parse().ok()).unwrap_or(a);
            (c[1].to_string(), Some(a), Some(b))
        }
        _ => (v.to_string(), None, None),
    }
}

/// Expand every reference in `message`. Never fails: problems become warnings.
pub fn expand(message: &str, env: &Env) -> Expanded {
    let refs = parse(message);
    if refs.is_empty() {
        return Expanded { message: message.into(), ..Default::default() };
    }
    let hard = (env.context_length / 2).max(1);
    let soft = (env.context_length / 4).max(1);
    let mut warnings = Vec::new();
    let mut blocks = Vec::new();
    for r in refs.iter().take(MAX_REFERENCES) {
        match expand_one(r, env, hard) {
            Ok(b) => blocks.push(b),
            Err(w) => warnings.push(w),
        }
    }
    for r in refs.iter().skip(MAX_REFERENCES) {
        warnings.push(format!("{}: not expanded (maximum {MAX_REFERENCES} @-references per message)", r.raw));
    }
    let injected: u64 = blocks.iter().map(|b| estimate_tokens(b)).sum();
    let mut out = Expanded { message: message.into(), references: refs, injected_tokens: injected, ..Default::default() };
    if injected > hard {
        warnings.push(format!("@ context injection refused: {injected} tokens exceeds the 50% hard limit ({hard})."));
        out.warnings = warnings;
        out.blocked = true;
        return out;
    }
    if injected > soft {
        warnings.push(format!("@ context injection warning: {injected} tokens exceeds the 25% soft limit ({soft})."));
    }
    let mut fin = message.to_string();
    if !warnings.is_empty() {
        fin.push_str("\n\n--- Context Warnings ---\n");
        fin.push_str(&warnings.iter().map(|w| format!("- {w}")).collect::<Vec<_>>().join("\n"));
    }
    if !blocks.is_empty() {
        fin.push_str("\n\n--- Attached Context ---\n\n");
        fin.push_str(&blocks.join("\n\n"));
    }
    out.message = fin.trim().to_string();
    out.expanded = !blocks.is_empty() || !warnings.is_empty();
    out.warnings = warnings;
    out
}

fn expand_one(r: &Reference, env: &Env, max_inline: u64) -> Result<String, String> {
    match r.kind.as_str() {
        "file" | "folder" => expand_path(r, env, max_inline),
        "diff" => git(r, env.cwd, &["diff"]),
        "staged" => git(r, env.cwd, &["diff", "--staged"]),
        "git" => {
            let n = r.target.parse::<u32>().unwrap_or(1).clamp(1, 10);
            git(r, env.cwd, &["log", &format!("-{n}"), "-p"])
        }
        "url" => {
            let Some(f) = env.fetch else { return Err(format!("{}: no URL fetcher available", r.raw)) };
            let content = f(&r.target).map_err(|e| format!("{}: {e}", r.raw))?;
            let content = content.trim();
            if content.is_empty() {
                return Err(format!("{}: no content extracted", r.raw));
            }
            Ok(format!("🌐 {} ({} tokens)\n{content}", r.raw, estimate_tokens(content)))
        }
        _ => Err(format!("{}: unsupported reference type", r.raw)),
    }
}

fn lexical_clean(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            c => out.push(c),
        }
    }
    out
}

/// Resolve against `cwd` (symlinks followed when the path exists) and enforce the root.
fn resolve(env: &Env, target: &str) -> Result<PathBuf, String> {
    let expanded = match (target.strip_prefix("~/"), &env.home) {
        (Some(rest), Some(h)) => h.join(rest),
        _ => PathBuf::from(target),
    };
    let joined = env.cwd.join(expanded);
    let resolved = joined.canonicalize().unwrap_or_else(|_| lexical_clean(&joined));
    let root = env.allowed_root.canonicalize().unwrap_or_else(|_| env.allowed_root.to_path_buf());
    if !resolved.starts_with(&root) {
        return Err("path is outside the allowed workspace".into());
    }
    Ok(resolved)
}

/// Credential / internal paths never attach (fails closed).
pub fn sensitive(path: &Path, home: Option<&Path>, deny: &[PathBuf]) -> Option<&'static str> {
    if deny.iter().any(|d| path == d || d.canonicalize().is_ok_and(|d| path == d)) {
        return Some("path is a sensitive credential or internal seagent path and cannot be attached");
    }
    if let Some(h) = home {
        let h = h.canonicalize().unwrap_or_else(|_| h.to_path_buf());
        if SENSITIVE_HOME_FILES.iter().any(|f| path == h.join(f)) {
            return Some("path is a sensitive credential file and cannot be attached");
        }
        if HOME_CREDENTIAL_DIRS.iter().any(|d| path.starts_with(h.join(d))) {
            return Some("path is a sensitive credential or internal seagent path and cannot be attached");
        }
    }
    // Project-local `.env` files anywhere (`.env.example` is the documented substitute).
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name == ".env" || (name.starts_with(".env.") && !matches!(name, ".env.example" | ".env.sample" | ".env.template")) {
        return Some("path is a sensitive credential or internal seagent path and cannot be attached");
    }
    None
}

fn expand_path(r: &Reference, env: &Env, max_inline: u64) -> Result<String, String> {
    let folder = r.kind == "folder";
    let path = resolve(env, &r.target).map_err(|e| format!("{}: {e}", r.raw))?;
    if let Some(e) = sensitive(&path, env.home.as_deref(), &env.deny) {
        return Err(format!("{}: {e}", r.raw));
    }
    if !path.exists() {
        return Err(format!("{}: {} not found", r.raw, r.kind));
    }
    if (folder && !path.is_dir()) || (!folder && !path.is_file()) {
        return Err(format!("{}: path is not a {}", r.raw, r.kind));
    }
    if folder {
        let listing = folder_listing(&path, env.cwd, env.allowed_root);
        return Ok(format!("📁 {} ({} tokens)\n{listing}", r.raw, estimate_tokens(&listing)));
    }
    if is_binary(&path) {
        return Ok(on_disk(r, &path, mime(&path), "binary file, not inlined as text.", "Use your tools to work with it (read or convert it, extract its text, or view/render it as needed); do not tell the user the file type is unsupported."));
    }
    let budget = max_inline as usize * CHARS_PER_TOKEN;
    let text = if let Some(a) = r.line_start {
        let b = r.line_end.unwrap_or(a).max(a);
        let f = std::fs::File::open(&path).map_err(|e| format!("{}: {e}", r.raw))?;
        let mut rd = std::io::BufReader::new(f);
        let mut out = String::new();
        let mut line = Vec::new();
        let mut n = 0usize;
        loop {
            line.clear();
            // Bounded read: a single giant line can't be materialised past the budget.
            let got = (&mut rd).take((budget + 1) as u64).read_until(b'\n', &mut line).map_err(|e| format!("{}: {e}", r.raw))?;
            if got == 0 {
                break;
            }
            if !line.ends_with(b"\n") && got > budget {
                return Ok(oversized(r, &path, (out.len() + got) / CHARS_PER_TOKEN));
            }
            n += 1;
            if n >= a && n <= b {
                out.push_str(&String::from_utf8_lossy(&line));
                if out.len() > budget {
                    return Ok(oversized(r, &path, out.len() / CHARS_PER_TOKEN));
                }
            }
            if n >= b {
                break;
            }
        }
        out
    } else {
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if size as usize > budget {
            return Ok(oversized(r, &path, size as usize / CHARS_PER_TOKEN));
        }
        let t = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", r.raw))?;
        t.strip_prefix('\u{feff}').map(str::to_string).unwrap_or(t)
    };
    let tokens = estimate_tokens(&text);
    if tokens > max_inline {
        return Ok(oversized(r, &path, tokens as usize));
    }
    let lang = match path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase().as_str() {
        "py" => "python",
        "js" => "javascript",
        "ts" => "typescript",
        "tsx" => "tsx",
        "jsx" => "jsx",
        "json" => "json",
        "md" => "markdown",
        "sh" => "bash",
        "yml" | "yaml" => "yaml",
        "toml" => "toml",
        "rs" => "rust",
        _ => "",
    };
    Ok(format!("📄 {} ({tokens} tokens)\n```{lang}\n{text}\n```", r.raw))
}

fn mime(p: &Path) -> &'static str {
    match p.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase().as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        "mp3" => "audio/mpeg",
        "mp4" => "video/mp4",
        _ => "application/octet-stream",
    }
}

fn is_binary(p: &Path) -> bool {
    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    if BINARY_EXTENSIONS.contains(&ext.as_str()) && !TEXT_EXTENSIONS.contains(&ext.as_str()) {
        return true;
    }
    let mut buf = [0u8; 4096];
    std::fs::File::open(p).and_then(|mut f| f.read(&mut buf)).map(|n| buf[..n].contains(&0)).unwrap_or(false)
}

fn fmt_bytes(n: u64) -> String {
    match n {
        n if n >= 1 << 30 => format!("{:.1} GB", n as f64 / (1u64 << 30) as f64),
        n if n >= 1 << 20 => format!("{:.1} MB", n as f64 / (1u64 << 20) as f64),
        n if n >= 1 << 10 => format!("{:.1} KB", n as f64 / 1024.0),
        n => format!("{n} B"),
    }
}

/// The file was not inlined, but it IS on disk where the agent's tools run.
fn on_disk(r: &Reference, path: &Path, descriptor: &str, reason: &str, guidance: &str) -> String {
    let size = std::fs::metadata(path).map(|m| fmt_bytes(m.len())).unwrap_or_else(|_| "unknown size".into());
    format!("📎 {} ({descriptor}, {size}) — {reason} It is available on disk at `{}`. {guidance}", r.raw, path.display())
}

fn oversized(r: &Reference, path: &Path, tokens: usize) -> String {
    on_disk(r, path, &format!("text file, approximately {tokens} tokens"), "too large to inline safely.", "Use read with a narrow line range, grep, or shell tools to inspect only the relevant parts; do not load the entire file into context.")
}

fn file_meta(p: &Path) -> String {
    let Ok(m) = std::fs::metadata(p) else { return "unknown size".into() };
    if is_binary(p) || m.len() > LINE_COUNT_MAX_BYTES {
        return format!("{} bytes", m.len());
    }
    match std::fs::read(p) {
        Ok(b) => format!("{} lines", b.iter().filter(|c| **c == b'\n').count() + 1),
        Err(_) => format!("{} bytes", m.len()),
    }
}

fn folder_listing(path: &Path, cwd: &Path, root: &Path) -> String {
    let shown = path.strip_prefix(cwd).or_else(|_| path.strip_prefix(root)).map(|p| format!("{}/", p.display())).unwrap_or_else(|_| format!("{}/", path.display()));
    let shown = if shown == "/" { "./".to_string() } else { shown };
    let mut lines = vec![shown];
    let entries = visible_entries(path, cwd);
    for e in &entries {
        let depth = e.strip_prefix(path).map(|r| r.components().count()).unwrap_or(1);
        let indent = "  ".repeat(depth.saturating_sub(1));
        let name = e.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        lines.push(if e.is_dir() { format!("{indent}- {name}/") } else { format!("{indent}- {name} ({})", file_meta(e)) });
    }
    if entries.len() >= FOLDER_LIMIT {
        lines.push("- ...".into());
    }
    lines.join("\n")
}

/// Files via `rg --files` (honours ignore files), else a walk skipping dot-entries.
fn visible_entries(path: &Path, cwd: &Path) -> Vec<PathBuf> {
    if let Ok((0, out, _)) = run_capped("rg", &["--files".to_string(), path.to_string_lossy().to_string()], cwd, &[], Duration::from_secs(10)) {
        let mut set = std::collections::BTreeSet::new();
        for line in out.lines().map(str::trim).filter(|l| !l.is_empty()).take(FOLDER_LIMIT) {
            let full = cwd.join(line);
            let mut p = full.parent();
            while let Some(d) = p {
                if !d.starts_with(path) || d == path {
                    break;
                }
                set.insert((false, d.to_path_buf()));
                p = d.parent();
            }
            set.insert((true, full));
        }
        return set.into_iter().filter(|(_, p)| p.exists()).map(|(_, p)| p).collect();
    }
    let mut out = Vec::new();
    let mut stack = vec![path.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        let mut es: Vec<_> = rd.flatten().filter(|e| !e.file_name().to_string_lossy().starts_with('.') && e.file_name() != "__pycache__").collect();
        es.sort_by_key(|e| (e.path().is_file(), e.file_name()));
        let mut dirs = Vec::new();
        for e in es {
            if out.len() >= FOLDER_LIMIT {
                return out;
            }
            if e.path().is_dir() {
                dirs.push(e.path());
            }
            out.push(e.path());
        }
        stack.extend(dirs.into_iter().rev());
    }
    out
}

/// Environment for internal git calls: never prompt, never run repo-supplied programs
/// (Hermes `noninteractive_git_env` + `harden_git_argv`).
pub fn git_env() -> Vec<(String, String)> {
    let overrides = [
        ("credential.helper", ""),
        ("core.askPass", ""),
        ("core.fsmonitor", "false"),
        ("core.untrackedCache", "false"),
        ("core.hooksPath", "/dev/null"),
        ("core.pager", "cat"),
        ("core.editor", "true"),
        ("sequence.editor", "true"),
        ("diff.external", ""),
        ("core.sshCommand", "ssh -o BatchMode=yes"),
    ];
    let mut v: Vec<(String, String)> = [("GIT_TERMINAL_PROMPT", "0"), ("GCM_INTERACTIVE", "Never"), ("GIT_CONFIG_GLOBAL", "/dev/null"), ("GIT_CONFIG_SYSTEM", "/dev/null"), ("GIT_CONFIG_NOSYSTEM", "1"), ("GIT_PAGER", "cat"), ("PAGER", "cat"), ("GIT_EDITOR", "true")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    v.push(("GIT_CONFIG_COUNT".into(), overrides.len().to_string()));
    for (i, (k, val)) in overrides.iter().enumerate() {
        v.push((format!("GIT_CONFIG_KEY_{i}"), k.to_string()));
        v.push((format!("GIT_CONFIG_VALUE_{i}"), val.to_string()));
    }
    v
}

/// `--no-ext-diff --no-textconv` right after a diff-rendering subcommand.
pub fn harden_git_args(args: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    if let Some(i) = out.iter().position(|a| !a.starts_with('-')) {
        if matches!(out[i].as_str(), "diff" | "show" | "log" | "blame") {
            out.splice(i + 1..i + 1, ["--no-ext-diff".to_string(), "--no-textconv".to_string()]);
        }
    }
    out
}

fn git(r: &Reference, cwd: &Path, args: &[&str]) -> Result<String, String> {
    let label = format!("git {}", args.join(" "));
    match run_capped("git", &harden_git_args(args), cwd, &git_env(), Duration::from_secs(30)) {
        Ok((0, out, _)) => {
            let content = if out.trim().is_empty() { "(no output)".to_string() } else { out.trim().to_string() };
            Ok(format!("🧾 {label} ({} tokens)\n```diff\n{content}\n```", estimate_tokens(&content)))
        }
        Ok((_, _, err)) => Err(format!("{}: {}", r.raw, if err.trim().is_empty() { "git command failed".into() } else { err.trim().to_string() })),
        Err(e) if e == "timeout" => Err(format!("{}: git command timed out (30s)", r.raw)),
        Err(e) => Err(format!("{}: {e}", r.raw)),
    }
}

/// Run with no stdin, bounded output (past the cap the child is killed: exit 137) and a timeout.
pub fn run_capped(cmd: &str, args: &[String], cwd: &Path, env: &[(String, String)], timeout: Duration) -> Result<(i32, String, String), String> {
    let mut c = Command::new(cmd);
    c.args(args).current_dir(cwd).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    for (k, v) in env {
        c.env(k, v);
    }
    for k in std::env::vars().map(|(k, _)| k).filter(|k| k == "GIT_CONFIG_PARAMETERS" || k.starts_with("GIT_CONFIG_KEY_") || k.starts_with("GIT_CONFIG_VALUE_")) {
        if !env.iter().any(|(e, _)| *e == k) {
            c.env_remove(k);
        }
    }
    let mut child = c.spawn().map_err(|e| e.to_string())?;
    let drain = |s: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let over = s.map(|s| s.take(MAX_QUIET_OUTPUT_BYTES as u64 + 1).read_to_end(&mut buf).is_ok() && buf.len() > MAX_QUIET_OUTPUT_BYTES).unwrap_or(false);
            buf.truncate(MAX_QUIET_OUTPUT_BYTES);
            (String::from_utf8_lossy(&buf).into_owned(), over)
        })
    };
    let out = drain(child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>));
    let err = drain(child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>));
    let until = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("timeout".into());
            }
        }
    };
    let (o, over) = out.join().unwrap_or_default();
    let (e, _) = err.join().unwrap_or_default();
    let code = if over { 137 } else { status.code().unwrap_or(-1) };
    Ok((code, o, e))
}

/// Plain GET for `@url:` when the host injected no fetcher: text, HTML stripped, 2 MB cap.
pub fn default_fetch(url: &str) -> Result<String, String> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err("only http(s) URLs can be attached".into());
    }
    let agent: ureq::Agent = seagent_net::http::builder().timeout_global(Some(Duration::from_secs(20))).http_status_as_error(false).max_redirects(5).build().into();
    let mut resp = agent.get(url).header("accept", "text/html,text/plain,application/json;q=0.9,*/*;q=0.5").call().map_err(|e| format!("request failed: {e}"))?;
    let status = resp.status().as_u16();
    let ctype = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
    let mut raw = Vec::new();
    resp.body_mut().with_config().limit(u64::MAX).reader().take(2 << 20).read_to_end(&mut raw).map_err(|e| format!("reading body: {e}"))?;
    if status >= 400 {
        return Err(format!("HTTP {status}"));
    }
    if !ctype.is_empty() && !(ctype.starts_with("text/") || ctype.contains("json") || ctype.contains("xml")) {
        return Err(format!("content-type {ctype} is not text"));
    }
    let text = String::from_utf8_lossy(&raw).into_owned();
    Ok(if ctype.contains("html") || text.trim_start().starts_with('<') { html_text(&text) } else { text })
}

pub fn html_text(html: &str) -> String {
    static RES: OnceLock<[regex::Regex; 4]> = OnceLock::new();
    let [blocks, breaks, tags, spaces] = RES.get_or_init(|| {
        [
            regex::Regex::new(r"(?is)<(script|style|noscript|svg|head)\b.*?</(script|style|noscript|svg|head)\s*>|<!--.*?-->").unwrap(),
            regex::Regex::new(r"(?i)<(br|/p|/div|/li|/h[1-6]|/tr|/section|/article)\b[^>]*>").unwrap(),
            regex::Regex::new(r"(?s)<[^>]*>").unwrap(),
            regex::Regex::new(r"[ \t\r\f]+").unwrap(),
        ]
    });
    let s = blocks.replace_all(html, " ");
    let s = breaks.replace_all(&s, "\n");
    let s = tags.replace_all(&s, " ");
    let s = s.replace("&nbsp;", " ").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&#39;", "'").replace("&amp;", "&");
    let s = spaces.replace_all(&s, " ");
    s.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn ws() -> PathBuf {
        let d = seagent_core::tmp::scratch_path(format!("seagent-refs-{}", crate::util::random_hex(8)));
        fs::create_dir_all(d.join("src/sub")).unwrap();
        d.canonicalize().unwrap()
    }
    fn env<'a>(ws: &'a Path, ctx: u64) -> Env<'a> {
        Env { cwd: ws, allowed_root: ws, context_length: ctx, home: Some(ws.join("home")), deny: vec![ws.join("secrets.toml")], fetch: None }
    }

    #[test]
    fn parsing_handles_ranges_quotes_punctuation_and_emails() {
        let r = parse("look at @file:src/a.rs:10-20, and (see @file:b.py) then @diff and @git:3 mail me@diff.com @staged.");
        let kinds: Vec<_> = r.iter().map(|r| (r.kind.as_str(), r.target.as_str(), r.line_start, r.line_end)).collect();
        assert_eq!(kinds, vec![("file", "src/a.rs", Some(10), Some(20)), ("file", "b.py", None, None), ("diff", "", None, None), ("git", "3", None, None), ("staged", "", None, None)]);
        assert_eq!(r[0].raw, "@file:src/a.rs:10-20");
        assert_eq!(r[1].raw, "@file:b.py");
        let q = parse("@file:`my file.txt`:5 and @folder:\"a dir\" and @url:https://x.test/p?q=1.");
        assert_eq!((q[0].target.as_str(), q[0].line_start, q[0].line_end), ("my file.txt", Some(5), Some(5)));
        assert_eq!(q[1].target, "a dir");
        assert_eq!(q[2].target, "https://x.test/p?q=1");
        assert!(parse("path/@file:x").is_empty() && parse("no refs here").is_empty());
    }

    #[test]
    fn files_inline_with_fences_and_line_ranges() {
        let d = ws();
        fs::write(d.join("src/a.py"), "l1\nl2\nl3\nl4\n").unwrap();
        fs::write(d.join("src/sub/b.txt"), "b").unwrap();
        let e = expand("check @file:src/a.py:2-3 please", &env(&d, 100_000));
        assert!(!e.blocked && e.expanded);
        assert!(e.message.starts_with("check @file:src/a.py:2-3 please\n\n--- Attached Context ---"), "{}", e.message);
        assert!(e.message.contains("```python\nl2\nl3\n\n```"), "{}", e.message);
        let e = expand("@file:src/a.py", &env(&d, 100_000));
        assert!(e.message.contains("l1\nl2\nl3\nl4"));
        let e = expand("@folder:src", &env(&d, 100_000));
        assert!(e.message.contains("📁 @folder:src") && e.message.contains("a.py (5 lines)") && e.message.contains("sub/"), "{}", e.message);
    }

    #[test]
    fn guards_outside_sensitive_binary_missing_and_budgets() {
        let d = ws();
        fs::create_dir_all(d.join("home/.ssh")).unwrap();
        fs::write(d.join("home/.ssh/id_rsa"), "KEY").unwrap();
        fs::write(d.join(".env"), "A=1").unwrap();
        fs::write(d.join("secrets.toml"), "x").unwrap();
        fs::write(d.join("img.png"), [0u8, 1, 2]).unwrap();
        fs::write(d.join("big.txt"), "word ".repeat(4000)).unwrap();
        let e = expand("@file:../../etc/passwd @file:home/.ssh/id_rsa @file:.env @file:secrets.toml @file:nope.txt @folder:img.png", &env(&d, 100_000));
        let w = e.warnings.join("\n");
        assert!(w.contains("outside the allowed workspace") && w.contains("sensitive credential") && w.contains("nope.txt: file not found") && w.contains("path is not a folder"), "{w}");
        assert_eq!(e.warnings.len(), 6);
        assert!(!e.message.contains("KEY") && e.message.contains("--- Context Warnings ---"));
        let e = expand("@file:img.png", &env(&d, 100_000));
        assert!(e.message.contains("📎 @file:img.png (image/png") && e.message.contains("binary file"));
        // One oversized file becomes a pointer, not a refusal.
        let e = expand("@file:big.txt", &env(&d, 4_000));
        assert!(!e.blocked && e.message.contains("too large to inline safely"), "{}", e.message);
        // Several mid-size files: the aggregate trips the hard limit.
        for i in 0..4 {
            fs::write(d.join(format!("m{i}.txt")), "abcd ".repeat(900)).unwrap();
        }
        let e = expand("@file:m0.txt @file:m1.txt @file:m2.txt @file:m3.txt", &env(&d, 4_000));
        assert!(e.blocked && e.warnings.last().unwrap().contains("50% hard limit"), "{:?}", e.warnings);
        let many: String = (0..18).map(|_| "@file:m0.txt ").collect();
        let e = expand(&many, &env(&d, 10_000_000));
        assert!(e.warnings.iter().filter(|w| w.contains("maximum 16")).count() == 2);
    }

    #[test]
    fn git_references_run_hardened_git() {
        let d = ws();
        let g = |args: &[&str]| run_capped("git", &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(), &d, &git_env(), Duration::from_secs(10));
        if g(&["init", "-q"]).is_err() {
            return; // no git on this machine
        }
        g(&["-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "--allow-empty", "-m", "first commit"]).unwrap();
        fs::write(d.join("f.txt"), "x\n").unwrap();
        g(&["add", "f.txt"]).unwrap();
        let e = expand("@staged and @git:1 and @diff", &env(&d, 100_000));
        assert!(e.message.contains("🧾 git diff --staged") && e.message.contains("+x"), "{}", e.message);
        assert!(e.message.contains("first commit") && e.message.contains("🧾 git diff (") && e.message.contains("(no output)"));
        assert_eq!(harden_git_args(&["log", "-1"]), ["log", "--no-ext-diff", "--no-textconv", "-1"]);
        assert_eq!(harden_git_args(&["status"]), ["status"]);
    }

    #[test]
    fn urls_use_the_fetcher_and_the_default_get() {
        let d = ws();
        let f = |u: &str| if u.ends_with("/empty") { Ok(String::new()) } else { Ok(format!("page {u}")) };
        let mut en = env(&d, 100_000);
        en.fetch = Some(&f);
        let e = expand("read @url:https://e.test/a and @url:https://e.test/empty", &en);
        assert!(e.message.contains("🌐 @url:https://e.test/a") && e.message.contains("page https://e.test/a"));
        assert!(e.warnings[0].contains("no content extracted"));
        // Default fetcher against a local fake server.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::Write;
            let (mut s, _) = l.accept().unwrap();
            let mut b = [0u8; 2048];
            let _ = s.read(&mut b);
            let body = "<html><head><title>t</title></head><body><script>x()</script><p>Hello &amp; welcome</p></body></html>";
            let _ = write!(s, "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
        });
        assert_eq!(default_fetch(&format!("http://{addr}/")).unwrap(), "Hello & welcome");
        assert!(default_fetch("file:///etc/passwd").is_err());
    }
}
