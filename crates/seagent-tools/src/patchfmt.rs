//! Patch-text formats.
//! - V4A (Hermes `tools/patch_parser.py`, MIT): `*** Begin Patch` / `*** Update File:` /
//!   `*** Add File:` / `*** Delete File:` / `*** Move File: a -> b`, hunks applied with the
//!   fuzzy matcher, validated in full before anything is written.
//! - OpenAI/Codex `apply_patch` envelopes (OpenClaw `src/agents/apply-patch*.ts`, MIT):
//!   strict boundaries, `*** Move to:`, `@@` context anchors, `*** End of File`, tolerant
//!   line matching that keeps the file's own bytes (line endings, BOM) outside the change.

use crate::fuzzy::{self, Matcher};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

// ───────────────────── unified diff ─────────────────────

/// difflib.unified_diff(a, b, fromfile, tofile) with n=3 context lines.
pub fn unified_diff(from: &str, to: &str, old: &str, new: &str) -> String {
    let a: Vec<&str> = old.split_inclusive('\n').collect();
    let b: Vec<&str> = new.split_inclusive('\n').collect();
    let mut codes = Matcher::new(&a, &b).opcodes();
    if codes.is_empty() {
        codes.push(("equal", 0, 1, 0, 1));
    }
    if codes.iter().all(|c| c.0 == "equal") {
        return String::new();
    }
    let n = 3;
    // get_grouped_opcodes
    if codes[0].0 == "equal" {
        let (t, i1, i2, j1, j2) = codes[0];
        codes[0] = (t, i1.max(i2.saturating_sub(n)), i2, j1.max(j2.saturating_sub(n)), j2);
    }
    let last = codes.len() - 1;
    if codes[last].0 == "equal" {
        let (t, i1, i2, j1, j2) = codes[last];
        codes[last] = (t, i1, i2.min(i1 + n), j1, j2.min(j1 + n));
    }
    let mut groups = Vec::new();
    let mut group = Vec::new();
    for (t, i1, i2, j1, j2) in codes {
        if t == "equal" && i2 - i1 > 2 * n {
            group.push((t, i1, i1 + n, j1, j1 + n));
            groups.push(std::mem::take(&mut group));
            group.push((t, i2 - n, i2, j2 - n, j2));
            continue;
        }
        group.push((t, i1, i2, j1, j2));
    }
    if !group.is_empty() && !(group.len() == 1 && group[0].0 == "equal") {
        groups.push(group);
    }
    let range = |s: usize, e: usize| {
        let len = e - s;
        let beg = if len == 0 { s } else { s + 1 };
        if len == 1 {
            format!("{beg}")
        } else {
            format!("{beg},{len}")
        }
    };
    let mut out = format!("--- {from}\n+++ {to}\n");
    let line = |out: &mut String, p: char, l: &str| {
        out.push(p);
        out.push_str(l);
        if !l.ends_with('\n') {
            out.push_str("\n\\ No newline at end of file\n");
        }
    };
    for g in groups {
        let (f, l) = (g[0], g[g.len() - 1]);
        out.push_str(&format!("@@ -{} +{} @@\n", range(f.1, l.2), range(f.3, l.4)));
        for (t, i1, i2, j1, j2) in g {
            if t == "equal" {
                for x in &a[i1..i2] {
                    line(&mut out, ' ', x);
                }
                continue;
            }
            if t == "replace" || t == "delete" {
                for x in &a[i1..i2] {
                    line(&mut out, '-', x);
                }
            }
            if t == "replace" || t == "insert" {
                for x in &b[j1..j2] {
                    line(&mut out, '+', x);
                }
            }
        }
    }
    out
}

// ───────────────────── shared file access ─────────────────────

/// Read state of a path as the patch engines see it.
enum Probe {
    Text(String),
    Missing,
    Unreadable(String),
}

fn probe(p: &Path) -> Probe {
    match fs::read(p) {
        Ok(d) if crate::util::is_binary(&d) => Probe::Unreadable(format!("{} is a binary file", p.display())),
        Ok(d) => match String::from_utf8(d) {
            Ok(s) => Probe::Text(s),
            Err(_) => Probe::Unreadable(format!("{} is not valid UTF-8", p.display())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Probe::Missing,
        Err(e) if p.is_dir() => Probe::Unreadable(format!("{} is a directory ({e})", p.display())),
        Err(e) => Probe::Unreadable(e.to_string()),
    }
}

/// Planned change of one path: Some(text) = write, None = remove.
pub type Plan = Vec<(PathBuf, Option<String>, Option<String>)>;

/// Write a plan (path, before, after) transactionally: on any failure, undo what was done.
pub fn commit(plan: &Plan) -> Result<(), String> {
    for (i, (p, _, after)) in plan.iter().enumerate() {
        let r = match after {
            Some(t) => {
                if let Some(d) = p.parent() {
                    let _ = fs::create_dir_all(d);
                }
                crate::util::atomic_write(p, t.as_bytes())
            }
            None => fs::remove_file(p),
        };
        if let Err(e) = r {
            let mut failed = Vec::new();
            for (q, before, _) in plan[..i].iter().rev() {
                let undo = match before {
                    Some(t) => crate::util::atomic_write(q, t.as_bytes()),
                    None => fs::remove_file(q),
                };
                if undo.is_err() {
                    failed.push(q.display().to_string());
                }
            }
            let mut msg = format!("cannot write {}: {e}; earlier changes rolled back", p.display());
            if !failed.is_empty() {
                msg.push_str(&format!("; WARNING rollback also failed for: {}", failed.join(", ")));
            }
            return Err(msg);
        }
    }
    Ok(())
}

/// Collapse a plan so each path appears once (first `before`, last `after`).
fn collapse(steps: Vec<(PathBuf, Option<String>, Option<String>)>) -> Plan {
    let mut order: Vec<PathBuf> = Vec::new();
    let mut map: HashMap<PathBuf, (Option<String>, Option<String>)> = HashMap::new();
    for (p, before, after) in steps {
        match map.get_mut(&p) {
            Some(e) => e.1 = after,
            None => {
                order.push(p.clone());
                map.insert(p, (before, after));
            }
        }
    }
    order.into_iter().filter_map(|p| map.remove(&p).map(|(b, a)| (p, b, a))).filter(|(_, b, a)| b != a).collect()
}

// ───────────────────── V4A (Hermes) ─────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum V4aKind {
    Add,
    Update,
    Delete,
    Move,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct V4aHunk {
    pub hint: Option<String>,
    /// (prefix, content); prefix is ' ', '-' or '+'.
    pub lines: Vec<(char, String)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct V4aOp {
    pub kind: V4aKind,
    pub path: String,
    pub new_path: Option<String>,
    pub hunks: Vec<V4aHunk>,
}

fn marker(line: &str, words: &[&str]) -> bool {
    // `^\*\*\*\s*Begin\s+Patch\s*$`
    let Some(rest) = line.strip_prefix("***") else { return false };
    let toks: Vec<&str> = rest.split_whitespace().collect();
    toks == words && !rest.is_empty()
}

fn op_marker(line: &str) -> Option<(V4aKind, String, Option<String>)> {
    let rest = line.strip_prefix("***")?.trim_start();
    for (kind, word) in [(V4aKind::Update, "Update"), (V4aKind::Add, "Add"), (V4aKind::Delete, "Delete"), (V4aKind::Move, "Move")] {
        let Some(r) = rest.strip_prefix(word) else { continue };
        if !r.starts_with(char::is_whitespace) {
            continue;
        }
        let Some(r) = r.trim_start().strip_prefix("File:") else { continue };
        let arg = r.trim();
        if kind == V4aKind::Move {
            let (a, b) = arg.split_once("->")?;
            return Some((kind, a.trim().to_string(), Some(b.trim().to_string())));
        }
        return Some((kind, arg.to_string(), None));
    }
    None
}

pub fn looks_like_v4a(s: &str) -> bool {
    s.lines().any(|l| marker(l, &["Begin", "Patch"]) || op_marker(l).is_some())
}

pub fn parse_v4a(text: &str) -> Result<Vec<V4aOp>, String> {
    let lines: Vec<&str> = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l)).collect();
    let mut start: isize = -1;
    let mut end = lines.len();
    for (i, l) in lines.iter().enumerate() {
        if marker(l, &["Begin", "Patch"]) {
            start = i as isize;
        } else if marker(l, &["End", "Patch"]) {
            end = i;
            break;
        }
    }
    let mut ops: Vec<V4aOp> = Vec::new();
    let mut cur: Option<V4aOp> = None;
    let mut hunk: Option<V4aHunk> = None;
    fn flush_hunk(cur: &mut Option<V4aOp>, hunk: &mut Option<V4aHunk>) {
        if let (Some(op), Some(h)) = (cur.as_mut(), hunk.take()) {
            if !h.lines.is_empty() {
                op.hunks.push(h);
            }
        }
    }
    let from = (start + 1) as usize;
    for line in lines.iter().take(end).skip(from) {
        if let Some((kind, path, new_path)) = op_marker(line) {
            flush_hunk(&mut cur, &mut hunk);
            if let Some(op) = cur.take() {
                ops.push(op);
            }
            let op = V4aOp { kind: kind.clone(), path, new_path, hunks: vec![] };
            hunk = (kind == V4aKind::Add).then(V4aHunk::default);
            if matches!(kind, V4aKind::Delete | V4aKind::Move) {
                ops.push(op);
            } else {
                cur = Some(op);
            }
        } else if let Some(after) = line.strip_prefix("@@") {
            if cur.is_some() {
                flush_hunk(&mut cur, &mut hunk);
                let inner = after.trim_start();
                let hint = inner.find("@@").map(|e| inner[..e].trim().to_string()).filter(|h| !h.is_empty());
                hunk = Some(V4aHunk { hint, lines: vec![] });
            }
        } else if cur.is_some() && !line.is_empty() {
            let h = hunk.get_or_insert_with(V4aHunk::default);
            let first = line.chars().next().unwrap();
            if matches!(first, '+' | '-' | ' ') {
                h.lines.push((first, line[1..].to_string()));
            } else if first != '\\' {
                h.lines.push((' ', line.to_string()));
            }
        }
    }
    flush_hunk(&mut cur, &mut hunk);
    if let Some(op) = cur.take() {
        ops.push(op);
    }
    let mut errs = Vec::new();
    for op in &ops {
        if op.path.is_empty() {
            errs.push("Operation with empty file path".to_string());
        }
        if op.kind == V4aKind::Update && op.hunks.is_empty() {
            errs.push(format!("UPDATE {:?}: no hunks found", op.path));
        }
        if op.kind == V4aKind::Move && op.new_path.as_deref().unwrap_or("").is_empty() {
            errs.push(format!("MOVE {:?}: missing destination path (expected 'src -> dst')", op.path));
        }
    }
    if errs.is_empty() {
        Ok(ops)
    } else {
        Err(format!("Parse error: {}", errs.join("; ")))
    }
}

fn split_hunk(h: &V4aHunk) -> (Vec<&str>, Vec<&str>) {
    (h.lines.iter().filter(|l| l.0 != '+').map(|l| l.1.as_str()).collect(), h.lines.iter().filter(|l| l.0 != '-').map(|l| l.1.as_str()).collect())
}

fn count_overlapping(text: &str, pat: &str) -> usize {
    if pat.is_empty() {
        return text.len() + 1;
    }
    (0..=text.len()).filter(|&i| text.is_char_boundary(i) && text[i..].starts_with(pat)).count()
}

fn insert_addition_only(content: &str, hint: Option<&str>, insert: &str) -> Result<String, String> {
    if let Some(h) = hint {
        let n = count_overlapping(content, h);
        if n > 1 {
            return Err(format!("Addition-only hunk: context hint '{h}' is ambiguous ({n} occurrences) — provide a more unique hint"));
        }
        if n == 1 {
            let at = content.find(h).unwrap();
            return Ok(match content[at..].find('\n') {
                None => format!("{content}\n{insert}"),
                Some(e) => {
                    let eol = at + e;
                    format!("{}{insert}\n{}", &content[..=eol], &content[eol + 1..])
                }
            });
        }
    }
    Ok(format!("{}\n{insert}\n", content.trim_end_matches('\n')))
}

/// Apply one UPDATE's hunks to `content`. Returns (new content, strategies, notes).
fn v4a_update(path: &str, content: &str, hunks: &[V4aHunk]) -> Result<(String, Vec<&'static str>, Vec<String>), String> {
    let mut text = content.to_string();
    let mut strategies = Vec::new();
    let mut notes = Vec::new();
    for (i, h) in hunks.iter().enumerate() {
        let (s, r) = split_hunk(h);
        if s == r {
            continue;
        }
        let (search, repl) = (s.join("\n"), r.join("\n"));
        if s.is_empty() {
            text = insert_addition_only(&text, h.hint.as_deref(), &repl)?;
            continue;
        }
        let label = h.hint.as_ref().map(|x| format!("'{x}'")).unwrap_or("(no hint)".into());
        match fuzzy::fuzzy_replace(&text, &search, &repl, false) {
            Ok(rp) => {
                text = rp.content;
                strategies.push(rp.strategy);
                notes.extend(rp.note);
            }
            Err(err) => {
                // Retry inside a window around the context hint.
                let hint_pos = h.hint.as_deref().and_then(|x| text.find(x));
                let mut done = false;
                if let Some(hp) = hint_pos {
                    let mut ws = hp.saturating_sub(500);
                    while !text.is_char_boundary(ws) {
                        ws -= 1;
                    }
                    let mut we = (hp + 2000).min(text.len());
                    while !text.is_char_boundary(we) {
                        we += 1;
                    }
                    if let Ok(rp) = fuzzy::fuzzy_replace(&text[ws..we], &search, &repl, false) {
                        text = format!("{}{}{}", &text[..ws], rp.content, &text[we..]);
                        strategies.push(rp.strategy);
                        notes.extend(rp.note);
                        done = true;
                    }
                }
                if !done && !fuzzy::is_already_applied(&text, &search, &repl) {
                    return Err(format!("{path}: hunk {} {label} not found — {err}{}", i + 1, fuzzy::no_match_hint(&err, &search, &text)));
                }
            }
        }
    }
    Ok((text, strategies, notes))
}

/// Result text of an applied patch.
#[derive(Debug, Default)]
pub struct Applied {
    pub created: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
    pub diff: String,
    pub notes: Vec<String>,
    pub plan: Plan,
}

/// Validate every V4A operation against the current files (with an overlay so later ops
/// see earlier ones), build the full plan, and only then write it.
pub fn apply_v4a(ops: &[V4aOp], resolve: &dyn Fn(&str) -> PathBuf, write: bool) -> Result<Applied, String> {
    let mut overlay: HashMap<PathBuf, Option<String>> = HashMap::new();
    let mut steps = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut real = 0;
    let mut out = Applied::default();
    let read = |overlay: &HashMap<PathBuf, Option<String>>, p: &Path| -> Probe {
        match overlay.get(p) {
            Some(Some(t)) => Probe::Text(t.clone()),
            Some(None) => Probe::Missing,
            None => probe(p),
        }
    };
    for op in ops {
        let p = resolve(&op.path);
        match op.kind {
            V4aKind::Update => {
                let cur = match read(&overlay, &p) {
                    Probe::Text(t) => t,
                    Probe::Missing => {
                        errors.push(format!("{}: file not found", op.path));
                        continue;
                    }
                    Probe::Unreadable(e) => {
                        errors.push(format!("{}: {e}", op.path));
                        continue;
                    }
                };
                for h in &op.hunks {
                    let (s, r) = split_hunk(h);
                    if s != r || h.lines.iter().any(|l| l.0 != ' ') {
                        real += 1;
                    }
                    if s.is_empty() && s != r {
                        if let Some(hint) = &h.hint {
                            let n = count_overlapping(&cur, hint);
                            if n == 0 {
                                errors.push(format!("{}: addition-only hunk context hint '{hint}' not found", op.path));
                            } else if n > 1 {
                                errors.push(format!("{}: addition-only hunk context hint '{hint}' is ambiguous ({n} occurrences)", op.path));
                            }
                        }
                    }
                }
                match v4a_update(&op.path, &cur, &op.hunks) {
                    Ok((new, strategies, notes)) => {
                        out.notes.extend(notes);
                        out.notes.extend(fuzzy::boundary_note(strategies.iter().copied(), "the hunk's", &format!(" in {}", op.path)));
                        out.diff.push_str(&unified_diff(&format!("a/{}", op.path), &format!("b/{}", op.path), &cur, &new));
                        steps.push((p.clone(), Some(cur), Some(new.clone())));
                        overlay.insert(p, Some(new));
                        out.modified.push(op.path.clone());
                    }
                    Err(e) => errors.push(e),
                }
            }
            V4aKind::Delete => {
                real += 1;
                match read(&overlay, &p) {
                    Probe::Text(t) => {
                        out.diff.push_str(&unified_diff(&format!("a/{}", op.path), "/dev/null", &t, ""));
                        steps.push((p.clone(), Some(t), None));
                        overlay.insert(p, None);
                        out.deleted.push(op.path.clone());
                    }
                    _ => errors.push(format!("{}: file not found for deletion", op.path)),
                }
            }
            V4aKind::Move => {
                real += 1;
                let np = op.new_path.clone().unwrap_or_default();
                let dst = resolve(&np);
                let src = read(&overlay, &p);
                if !matches!(src, Probe::Text(_)) {
                    errors.push(format!("{}: source file not found for move", op.path));
                }
                match read(&overlay, &dst) {
                    Probe::Text(_) => errors.push(format!("{np}: destination already exists — move would overwrite")),
                    Probe::Unreadable(e) => errors.push(format!("{np}: could not confirm the path is free — {e}")),
                    Probe::Missing => {
                        if let Probe::Text(t) = src {
                            steps.push((dst.clone(), None, Some(t.clone())));
                            steps.push((p.clone(), Some(t.clone()), None));
                            overlay.insert(dst, Some(t));
                            overlay.insert(p, None);
                            out.diff.push_str(&format!("# Moved: {} -> {np}\n", op.path));
                            out.modified.push(format!("{} -> {np}", op.path));
                        }
                    }
                }
            }
            V4aKind::Add => {
                real += 1;
                match read(&overlay, &p) {
                    Probe::Text(_) => errors.push(format!("{}: file already exists — use Update File, not Add File", op.path)),
                    Probe::Unreadable(e) => errors.push(format!("{}: could not confirm the path is free — {e}", op.path)),
                    Probe::Missing => {
                        let body: Vec<&str> = op.hunks.iter().flat_map(|h| h.lines.iter().filter(|l| l.0 == '+').map(|l| l.1.as_str())).collect();
                        let text = body.join("\n");
                        out.diff.push_str(&format!("--- /dev/null\n+++ b/{}\n{}\n", op.path, body.iter().map(|l| format!("+{l}")).collect::<Vec<_>>().join("\n")));
                        steps.push((p.clone(), None, Some(text.clone())));
                        overlay.insert(p, Some(text));
                        out.created.push(op.path.clone());
                    }
                }
            }
        }
    }
    if errors.is_empty() && real == 0 {
        errors.push("Patch contains no changes (only context lines were provided)".into());
    }
    if !errors.is_empty() {
        return Err(format!("Patch validation failed (no files were modified):\n{}", errors.iter().map(|e| format!("  • {e}")).collect::<Vec<_>>().join("\n")));
    }
    out.plan = collapse(steps);
    if write {
        commit(&out.plan).map_err(|e| format!("Apply phase failed: {e}"))?;
    }
    let mut seen = HashSet::new();
    out.notes.retain(|n| seen.insert(n.clone()));
    Ok(out)
}

// ───────────────────── apply_patch (OpenClaw / Codex) ─────────────────────

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Chunk {
    pub context: Option<String>,
    pub old: Vec<String>,
    pub new: Vec<String>,
    /// For each new line: the index of the old (context) line it repeats, if any.
    pub context_old: Vec<Option<usize>>,
    pub eof: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Hunk {
    Add { path: String, contents: String },
    Delete { path: String },
    Update { path: String, move_to: Option<String>, chunks: Vec<Chunk> },
}

pub fn parse_apply_patch(input: &str) -> Result<Vec<Hunk>, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Invalid patch: input is empty.".into());
    }
    let mut lines: Vec<&str> = trimmed.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l)).collect();
    if lines.len() >= 4 && matches!(lines[0], "<<EOF" | "<<'EOF'" | "<<\"EOF\"") && lines[lines.len() - 1].ends_with("EOF") {
        lines = lines[1..lines.len() - 1].to_vec();
    }
    if lines.first().map(|l| l.trim()) != Some("*** Begin Patch") {
        return Err("The first line of the patch must be '*** Begin Patch'".into());
    }
    if lines.last().map(|l| l.trim()) != Some("*** End Patch") || lines.len() < 2 {
        return Err("The last line of the patch must be '*** End Patch'".into());
    }
    let body = &lines[1..lines.len() - 1];
    let mut hunks = Vec::new();
    let mut off = 0;
    while off < body.len() {
        let (h, used) = parse_one(&body[off..], off + 2)?;
        hunks.push(h);
        off += used;
    }
    Ok(hunks)
}

fn parse_one(lines: &[&str], line_no: usize) -> Result<(Hunk, usize), String> {
    let first = lines[0].trim();
    if let Some(p) = first.strip_prefix("*** Add File: ") {
        let mut contents = String::new();
        let mut used = 1;
        for l in &lines[1..] {
            match l.strip_prefix('+') {
                Some(t) => {
                    contents.push_str(t);
                    contents.push('\n');
                    used += 1;
                }
                None => break,
            }
        }
        return Ok((Hunk::Add { path: p.to_string(), contents }, used));
    }
    if let Some(p) = first.strip_prefix("*** Delete File: ") {
        return Ok((Hunk::Delete { path: p.to_string() }, 1));
    }
    if let Some(p) = first.strip_prefix("*** Update File: ") {
        let mut used = 1;
        let mut move_to = None;
        if let Some(m) = lines.get(used).map(|l| l.trim()).and_then(|l| l.strip_prefix("*** Move to: ")) {
            move_to = Some(m.to_string());
            used += 1;
        }
        let mut chunks = Vec::new();
        while used < lines.len() {
            let l = lines[used];
            if l.trim().is_empty() {
                used += 1;
                continue;
            }
            if l.starts_with("***") {
                break;
            }
            let (c, n) = parse_chunk(&lines[used..], line_no + used, chunks.is_empty())?;
            chunks.push(c);
            used += n;
        }
        if chunks.is_empty() {
            return Err(format!("Invalid patch hunk at line {line_no}: Update file hunk for path '{p}' is empty"));
        }
        return Ok((Hunk::Update { path: p.to_string(), move_to, chunks }, used));
    }
    Err(format!("Invalid patch hunk at line {line_no}: '{}' is not a valid hunk header. Valid hunk headers: '*** Add File: {{path}}', '*** Delete File: {{path}}', '*** Update File: {{path}}'", lines[0]))
}

fn parse_chunk(lines: &[&str], line_no: usize, allow_missing: bool) -> Result<(Chunk, usize), String> {
    let mut c = Chunk::default();
    let mut start = 0;
    match lines.first() {
        Some(&"@@") => start = 1,
        Some(l) if l.starts_with("@@ ") => {
            c.context = Some(l[3..].to_string());
            start = 1;
        }
        Some(l) if !allow_missing => return Err(format!("Invalid patch hunk at line {line_no}: Expected update hunk to start with a @@ context marker, got: '{l}'")),
        _ => {}
    }
    if start >= lines.len() || lines[start] == "*** End of File" {
        return Err(format!("Invalid patch hunk at line {}: Update hunk does not contain any lines", line_no + 1));
    }
    let mut parsed = 0;
    for l in &lines[start..] {
        if *l == "*** End of File" {
            c.eof = true;
            parsed += 1;
            break;
        }
        let m = l.chars().next();
        if matches!(m, None | Some(' ') | Some('+') | Some('-')) {
            let content = if l.is_empty() { "" } else { &l[1..] };
            if m != Some('-') {
                c.context_old.push(if m == Some('+') { None } else { Some(c.old.len()) });
                c.new.push(content.to_string());
            }
            if m != Some('+') {
                c.old.push(content.to_string());
            }
            parsed += 1;
            continue;
        }
        if parsed == 0 {
            return Err(format!("Invalid patch hunk at line {}: Unexpected line found in update hunk: '{l}'. Every line should start with ' ' (context line), '+' (added line), or '-' (removed line)", line_no + 1));
        }
        break;
    }
    Ok((c, parsed + start))
}

#[derive(Clone, Debug, PartialEq)]
struct SrcLine {
    text: String,
    ending: &'static str,
}

fn parse_source(contents: &str) -> (String, Vec<SrcLine>, &'static str, bool) {
    let (bom, text) = match contents.strip_prefix('\u{feff}') {
        Some(t) => ("\u{feff}".to_string(), t),
        None => (String::new(), contents),
    };
    let mut lines = Vec::new();
    let b = text.as_bytes();
    let mut s = 0;
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\r' || b[i] == b'\n' {
            let ending = if b[i] == b'\r' && b.get(i + 1) == Some(&b'\n') {
                "\r\n"
            } else if b[i] == b'\r' {
                "\r"
            } else {
                "\n"
            };
            lines.push(SrcLine { text: text[s..i].to_string(), ending });
            i += ending.len();
            s = i;
        } else {
            i += 1;
        }
    }
    if s < b.len() {
        lines.push(SrcLine { text: text[s..].to_string(), ending: "" });
    }
    let pref = lines.iter().map(|l| l.ending).find(|e| !e.is_empty()).unwrap_or("\n");
    let missing_final = lines.last().is_some_and(|l| l.ending.is_empty());
    (bom, lines, pref, missing_final)
}

fn norm_punct(v: &str) -> String {
    v.chars()
        .map(|c| match c {
            '\u{2010}'..='\u{2015}' | '\u{2212}' => '-',
            '\u{2018}'..='\u{201b}' => '\'',
            '\u{201c}'..='\u{201f}' => '"',
            '\u{a0}' | '\u{2000}'..='\u{200a}' | '\u{202f}' | '\u{205f}' | '\u{3000}' => ' ',
            c => c,
        })
        .collect()
}

enum Seek {
    Found(usize),
    Ambiguous(usize),
    Missing,
}

fn seek(lines: &[String], pat: &[String], start: usize, eof: bool) -> Seek {
    if pat.is_empty() {
        return Seek::Found(start);
    }
    if pat.len() > lines.len() {
        return Seek::Missing;
    }
    let max = lines.len() - pat.len();
    let from = if eof { start.max(max) } else { start };
    if from > max {
        return Seek::Missing;
    }
    let norms: [fn(&str) -> String; 4] = [|v| v.to_string(), |v| v.trim_end().to_string(), |v| v.trim().to_string(), |v| norm_punct(v.trim())];
    for n in norms {
        let mut first = None;
        let mut count = 0;
        for i in from..=max {
            if pat.iter().enumerate().all(|(k, p)| n(&lines[i + k]) == n(p)) {
                first.get_or_insert(i);
                count += 1;
            }
        }
        if let Some(i) = first {
            return if count == 1 { Seek::Found(i) } else { Seek::Ambiguous(count) };
        }
    }
    Seek::Missing
}

fn changed_lines(src: &[SrcLine], start: usize, old_count: usize, new: &[String], pref: &'static str) -> Vec<SrcLine> {
    let replaced = &src[start.min(src.len())..(start + old_count).min(src.len())];
    let nearby = replaced.iter().map(|l| l.ending).find(|e| !e.is_empty()).or_else(|| src.get(start).map(|l| l.ending).filter(|e| !e.is_empty())).or_else(|| start.checked_sub(1).and_then(|s| src.get(s)).map(|l| l.ending).filter(|e| !e.is_empty())).unwrap_or(pref);
    new.iter()
        .enumerate()
        .map(|(i, t)| {
            let ending = if replaced.len() == new.len() {
                replaced.get(i).map(|l| l.ending).unwrap_or(nearby)
            } else if i == new.len() - 1 && !replaced.is_empty() {
                replaced.last().map(|l| l.ending).unwrap_or(nearby)
            } else if i + 1 < replaced.len() {
                replaced[i].ending
            } else {
                nearby
            };
            SrcLine { text: t.clone(), ending }
        })
        .collect()
}

/// Apply update chunks to file contents (OpenClaw `applyUpdateHunk`).
pub fn apply_update(path: &str, contents: &str, chunks: &[Chunk]) -> Result<String, String> {
    let (bom, src, pref, missing_final) = parse_source(contents);
    let orig: Vec<String> = src.iter().map(|l| l.text.clone()).collect();
    let mut reps: Vec<(usize, usize, Vec<SrcLine>)> = Vec::new();
    let mut idx = 0;
    for c in chunks {
        if let Some(ctx) = &c.context {
            match seek(&orig, std::slice::from_ref(ctx), idx, false) {
                Seek::Ambiguous(n) => return Err(format!("Found {n} occurrences of context '{ctx}' in {path}. The context must be unique; use a more specific @@ context line.")),
                Seek::Missing => return Err(format!("Failed to find context '{ctx}' in {path}")),
                Seek::Found(i) => idx = i + 1,
            }
        }
        if c.old.is_empty() {
            let at = if c.context.is_some() && !c.eof { idx } else { src.len() };
            let mut ins = changed_lines(&src, at, 0, &c.new, pref);
            if missing_final && at == src.len() {
                if let Some(l) = ins.last_mut() {
                    l.ending = "";
                }
            }
            reps.push((at, 0, ins));
            idx = at;
            continue;
        }
        let mut pat = c.old.clone();
        let mut new = c.new.clone();
        let mut r = seek(&orig, &pat, idx, c.eof);
        if matches!(r, Seek::Missing) && pat.last().is_some_and(|l| l.is_empty()) {
            pat.pop();
            if new.last().is_some_and(|l| l.is_empty()) {
                new.pop();
            }
            r = seek(&orig, &pat, idx, c.eof);
        }
        let found = match r {
            Seek::Ambiguous(n) => return Err(format!("Found {n} occurrences of these lines in {path}. The lines must be unique; include more surrounding lines in the hunk:\n{}", c.old.join("\n"))),
            Seek::Missing => return Err(format!("Failed to find expected lines in {path}:\n{}", c.old.join("\n"))),
            Seek::Found(i) => i,
        };
        // Keep matched context records so bytes outside each explicit change stay untouched.
        let mut out = Vec::new();
        let (mut os, mut ns) = (0, 0);
        for (nc, oc) in c.context_old.iter().enumerate() {
            let Some(oc) = *oc else { continue };
            if oc >= pat.len() || nc >= new.len() {
                continue;
            }
            out.extend(changed_lines(&src, found + os, oc.saturating_sub(os), &new[ns.min(nc)..nc], pref));
            out.push(src[found + oc].clone());
            os = oc + 1;
            ns = nc + 1;
        }
        out.extend(changed_lines(&src, found + os, pat.len().saturating_sub(os), &new[ns.min(new.len())..], pref));
        reps.push((found, pat.len(), out));
        idx = found + pat.len();
    }
    reps.sort_by_key(|r| r.0);
    let mut lines = src;
    for (s, n, new) in reps.into_iter().rev() {
        lines.splice(s..s + n, new);
    }
    let len = lines.len();
    for l in lines.iter_mut().take(len.saturating_sub(1)) {
        if l.ending.is_empty() {
            l.ending = pref;
        }
    }
    Ok(bom + &lines.iter().map(|l| format!("{}{}", l.text, l.ending)).collect::<String>())
}

/// Plan an apply_patch envelope: (plan, summary text).
/// Resolves a patch path to (absolute path, display name), or refuses it.
pub type Resolve<'a> = &'a dyn Fn(&str) -> Result<(PathBuf, String), String>;

pub fn plan_apply_patch(hunks: &[Hunk], resolve: Resolve) -> Result<(Plan, String), String> {
    if hunks.is_empty() {
        return Err("No files were modified.".into());
    }
    let mut overlay: HashMap<PathBuf, Option<String>> = HashMap::new();
    let mut steps = Vec::new();
    let (mut added, mut modified, mut deleted, mut noop): (Vec<String>, Vec<String>, Vec<String>, Vec<String>) = Default::default();
    let read = |overlay: &HashMap<PathBuf, Option<String>>, p: &Path| match overlay.get(p) {
        Some(Some(t)) => Probe::Text(t.clone()),
        Some(None) => Probe::Missing,
        None => probe(p),
    };
    let push = |v: &mut Vec<String>, s: &str| {
        if !v.iter().any(|x| x == s) {
            v.push(s.to_string());
        }
    };
    for h in hunks {
        match h {
            Hunk::Add { path, contents } => {
                let (p, disp) = resolve(path)?;
                if !matches!(read(&overlay, &p), Probe::Missing) {
                    return Err(format!("{disp} already exists. Use \"*** Update File: {disp}\" to change it, or delete it earlier in the same patch."));
                }
                steps.push((p.clone(), None, Some(contents.clone())));
                overlay.insert(p, Some(contents.clone()));
                push(&mut added, &disp);
            }
            Hunk::Delete { path } => {
                let (p, disp) = resolve(path)?;
                match read(&overlay, &p) {
                    Probe::Text(t) => {
                        steps.push((p.clone(), Some(t), None));
                        overlay.insert(p, None);
                        push(&mut deleted, &disp);
                    }
                    Probe::Missing => return Err(format!("Failed to delete file {disp}: file does not exist")),
                    Probe::Unreadable(e) => return Err(format!("Failed to delete file {disp}: {e}")),
                }
            }
            Hunk::Update { path, move_to, chunks } => {
                let (p, disp) = resolve(path)?;
                let cur = match read(&overlay, &p) {
                    Probe::Text(t) => t,
                    Probe::Missing => return Err(format!("Failed to read file to update {disp}: file does not exist")),
                    Probe::Unreadable(e) => return Err(format!("Failed to read file to update {disp}: {e}")),
                };
                let applied = apply_update(&disp, &cur, chunks)?;
                if let Some(m) = move_to {
                    let (mp, mdisp) = resolve(m)?;
                    if mp != p {
                        if !matches!(read(&overlay, &mp), Probe::Missing) {
                            return Err(format!("{mdisp} already exists. Delete it earlier in the same patch to replace it."));
                        }
                        noop.retain(|x| x != &disp);
                        steps.push((mp.clone(), None, Some(applied.clone())));
                        steps.push((p.clone(), Some(cur), None));
                        overlay.insert(mp, Some(applied));
                        overlay.insert(p, None);
                        push(&mut modified, &mdisp);
                        continue;
                    }
                }
                if applied.replace("\r\n", "\n") == cur.replace("\r\n", "\n") {
                    push(&mut noop, &disp);
                } else {
                    noop.retain(|x| x != &disp);
                    steps.push((p.clone(), Some(cur), Some(applied.clone())));
                    overlay.insert(p, Some(applied));
                    push(&mut modified, &disp);
                }
            }
        }
    }
    let text = if !noop.is_empty() && added.is_empty() && modified.is_empty() && deleted.is_empty() {
        format!("No changes made to {}.", noop.join(", "))
    } else {
        let mut l = vec!["Success. Updated the following files:".to_string()];
        l.extend(added.iter().map(|f| format!("A {f}")));
        l.extend(modified.iter().map(|f| format!("M {f}")));
        l.extend(deleted.iter().map(|f| format!("D {f}")));
        l.join("\n")
    };
    Ok((collapse(steps), text))
}

/// Target paths an apply_patch envelope or V4A patch touches (for the gates).
pub fn target_paths(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for l in text.lines() {
        let t = l.trim();
        for pre in ["*** Add File: ", "*** Delete File: ", "*** Update File: ", "*** Move to: "] {
            if let Some(p) = t.strip_prefix(pre) {
                out.push(p.trim().to_string());
            }
        }
        if let Some((_, a, b)) = op_marker(t).and_then(|(k, a, b)| (k == V4aKind::Move).then_some((k, a, b))) {
            out.push(a);
            out.extend(b);
        } else if let Some((_, a, _)) = op_marker(t) {
            if !out.contains(&a) {
                out.push(a);
            }
        }
    }
    let mut seen = HashSet::new();
    out.retain(|p| !p.is_empty() && seen.insert(p.clone()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::tmpdir;

    #[test]
    fn unified_diff_like_difflib() {
        let d = unified_diff("a/x", "b/x", "1\n2\n3\n", "1\nTWO\n3\n");
        assert_eq!(d, "--- a/x\n+++ b/x\n@@ -1,3 +1,3 @@\n 1\n-2\n+TWO\n 3\n");
        assert_eq!(unified_diff("a", "b", "same\n", "same\n"), "");
    }

    #[test]
    fn v4a_parse_and_apply_all_ops() {
        let d = tmpdir("v4a");
        fs::write(d.join("a.py"), "def f():\n    return 1\n\ndef g():\n    return 2\n").unwrap();
        fs::write(d.join("old.txt"), "moving\n").unwrap();
        fs::write(d.join("gone.txt"), "bye\n").unwrap();
        let patch = "*** Begin Patch\n*** Update File: a.py\n@@ def g @@\n def g():\n-    return 2\n+    return 3\n*** Add File: new.txt\n+hello\n+world\n*** Delete File: gone.txt\n*** Move File: old.txt -> sub/moved.txt\n*** End Patch\n";
        let ops = parse_v4a(patch).unwrap();
        assert_eq!(ops.len(), 4);
        assert_eq!(ops[0].hunks[0].hint.as_deref(), Some("def g"));
        let r = |p: &str| d.join(p);
        let a = apply_v4a(&ops, &r, true).unwrap();
        assert_eq!(fs::read_to_string(d.join("a.py")).unwrap(), "def f():\n    return 1\n\ndef g():\n    return 3\n");
        assert_eq!(fs::read_to_string(d.join("new.txt")).unwrap(), "hello\nworld");
        assert!(!d.join("gone.txt").exists() && !d.join("old.txt").exists());
        assert_eq!(fs::read_to_string(d.join("sub/moved.txt")).unwrap(), "moving\n");
        assert!(a.diff.contains("-    return 2\n+    return 3"), "{}", a.diff);
        assert_eq!((a.created.len(), a.deleted.len(), a.modified.len()), (1, 1, 2));
    }

    #[test]
    fn v4a_validation_is_all_or_nothing() {
        let d = tmpdir("v4a2");
        fs::write(d.join("a.txt"), "one\n").unwrap();
        fs::write(d.join("b.txt"), "two\n").unwrap();
        let patch = "*** Begin Patch\n*** Update File: a.txt\n-one\n+ONE\n*** Update File: b.txt\n-zzz\n+q\n*** Add File: b.txt\n+x\n*** End Patch";
        let e = apply_v4a(&parse_v4a(patch).unwrap(), &|p| d.join(p), true).unwrap_err();
        assert!(e.contains("no files were modified") && e.contains("b.txt: hunk 1") && e.contains("already exists"), "{e}");
        assert_eq!(fs::read_to_string(d.join("a.txt")).unwrap(), "one\n");
        assert!(parse_v4a("*** Begin Patch\n*** Update File: x\n*** End Patch").unwrap_err().contains("no hunks"));
        assert!(parse_v4a("*** Move File: a\n").unwrap().is_empty(), "no `->`: not a move marker");
        let e = apply_v4a(&parse_v4a("*** Update File: a.txt\n one\n").unwrap(), &|p| d.join(p), false).unwrap_err();
        assert!(e.contains("no changes"), "{e}");
        // Fuzzy: indentation drift still applies; addition-only with hint.
        fs::write(d.join("c.txt"), "header\n    body\nfooter\n").unwrap();
        let a = apply_v4a(&parse_v4a("*** Update File: c.txt\n-body\n+BODY\n@@ header @@\n+inserted\n").unwrap(), &|p| d.join(p), true).unwrap();
        assert!(a.notes.is_empty());
        assert_eq!(fs::read_to_string(d.join("c.txt")).unwrap(), "header\ninserted\n    BODY\nfooter\n");
    }

    fn env(d: &Path) -> impl Fn(&str) -> Result<(PathBuf, String), String> + '_ {
        move |p: &str| Ok((d.join(p), p.to_string()))
    }

    #[test]
    fn apply_patch_add_update_delete_move() {
        let d = tmpdir("ap");
        fs::write(d.join("m.rs"), "fn a() {}\r\nfn b() {\r\n    1\r\n}\r\n").unwrap();
        fs::write(d.join("del.txt"), "x\n").unwrap();
        fs::write(d.join("mv.txt"), "keep\nchange\n").unwrap();
        let p = "*** Begin Patch\n*** Add File: n/new.txt\n+line1\n+line2\n*** Update File: m.rs\n@@ fn b() {\n-    1\n+    2\n*** Delete File: del.txt\n*** Update File: mv.txt\n*** Move to: moved.txt\n keep\n-change\n+changed\n*** End Patch";
        let hunks = parse_apply_patch(p).unwrap();
        let (plan, text) = plan_apply_patch(&hunks, &env(&d)).unwrap();
        commit(&plan).unwrap();
        assert_eq!(text, "Success. Updated the following files:\nA n/new.txt\nM m.rs\nM moved.txt\nD del.txt");
        assert_eq!(fs::read_to_string(d.join("m.rs")).unwrap(), "fn a() {}\r\nfn b() {\r\n    2\r\n}\r\n", "CRLF kept");
        assert_eq!(fs::read_to_string(d.join("n/new.txt")).unwrap(), "line1\nline2\n");
        assert_eq!(fs::read_to_string(d.join("moved.txt")).unwrap(), "keep\nchanged\n");
        assert!(!d.join("mv.txt").exists() && !d.join("del.txt").exists());
    }

    #[test]
    fn apply_patch_errors_eof_and_ambiguity() {
        assert_eq!(parse_apply_patch("").unwrap_err(), "Invalid patch: input is empty.");
        assert!(parse_apply_patch("*** Update File: x\n").unwrap_err().contains("first line"));
        assert!(parse_apply_patch("*** Begin Patch\n*** Update File: x\n").unwrap_err().contains("last line"));
        assert!(parse_apply_patch("*** Begin Patch\nbogus\n*** End Patch").unwrap_err().contains("not a valid hunk header"));
        assert!(parse_apply_patch("*** Begin Patch\n*** Update File: x\n*** End Patch").unwrap_err().contains("is empty"));
        assert!(parse_apply_patch("<<'EOF'\n*** Begin Patch\n*** Delete File: x\n*** End Patch\nEOF").is_ok());
        // Ambiguous lines.
        let c = vec![Chunk { old: vec!["x".into()], new: vec!["y".into()], context_old: vec![None], ..Default::default() }];
        assert!(apply_update("f", "x\nx\n", &c).unwrap_err().contains("Found 2 occurrences"));
        // EOF anchors to the last occurrence.
        let h = parse_apply_patch("*** Begin Patch\n*** Update File: f\n@@\n-x\n+y\n*** End of File\n*** End Patch").unwrap();
        let Hunk::Update { chunks, .. } = &h[0] else { panic!() };
        assert_eq!(apply_update("f", "x\nmid\nx\n", chunks).unwrap(), "x\nmid\ny\n");
        // Tolerant punctuation / trailing whitespace; no-final-newline append.
        let c = vec![Chunk { old: vec!["say \"hi\"".into()], new: vec!["say \"bye\"".into()], context_old: vec![None], ..Default::default() }];
        assert_eq!(apply_update("f", "say \u{201c}hi\u{201d}  \n", &c).unwrap(), "say \"bye\"\n");
        let c = vec![Chunk { new: vec!["tail".into()], context_old: vec![None], ..Default::default() }];
        assert_eq!(apply_update("f", "a\nb", &c).unwrap(), "a\nb\ntail");
        // Add over an existing file, delete missing.
        let d = tmpdir("ap2");
        fs::write(d.join("e.txt"), "x").unwrap();
        let h = parse_apply_patch("*** Begin Patch\n*** Add File: e.txt\n+y\n*** End Patch").unwrap();
        assert!(plan_apply_patch(&h, &env(&d)).unwrap_err().contains("already exists"));
        let h = parse_apply_patch("*** Begin Patch\n*** Delete File: none.txt\n*** End Patch").unwrap();
        assert!(plan_apply_patch(&h, &env(&d)).unwrap_err().contains("does not exist"));
        let h = parse_apply_patch("*** Begin Patch\n*** Update File: e.txt\n@@\n-x\n+x\n*** End Patch").unwrap();
        assert_eq!(plan_apply_patch(&h, &env(&d)).unwrap().1, "No changes made to e.txt.");
    }

    #[test]
    fn target_paths_cover_both_formats() {
        let t = target_paths("*** Begin Patch\n*** Update File: a\n*** Move to: b\n*** Move File: c -> d\n*** Add File: e\n*** End Patch");
        assert_eq!(t, vec!["a", "b", "c", "d", "e"]);
    }
}
