use crate::util::{atomic_write, display_path, io_err, is_binary, truncate_str};
use ark_core::tool::{arg_opt_bool, arg_opt_u64, arg_str};
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

const MAX_LINE: usize = 2000;
const DEFAULT_LIMIT: u64 = 2000;
const MAX_DIR_ENTRIES: usize = 1000;

fn path_effect(ctx: &ToolCtx, input: &Value, write: bool) -> Vec<Effect> {
    // Same aliases the tools accept, so the gate judges what will really run.
    let mut input = input.clone();
    crate::util::alias(&mut input, "path", &["file", "file_path", "filename"]);
    match arg_str(&input, "path") {
        Ok(p) if write => vec![Effect::Write { path: ctx.resolve(p) }],
        Ok(p) => vec![Effect::Read { path: ctx.resolve(p) }],
        Err(_) => vec![],
    }
}

pub struct Read;

impl Tool for Read {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "read".into(),
            description: "Read a text file with line numbers, or list a directory. Use offset/limit for large files.".into(),
            input_schema: json!({"type":"object","properties":{
                "path":{"type":"string","description":"File or directory, relative to the workspace or absolute"},
                "offset":{"type":"integer","minimum":1,"description":"First line to show (1-based)"},
                "limit":{"type":"integer","minimum":1,"description":"Max lines (default 2000)"}},
                "required":["path"]}),
            parallel_safe: true,
            idempotent: true,
            pinned: true,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        path_effect(ctx, input, false)
    }
    fn call(&self, ctx: &ToolCtx, mut input: Value) -> ToolOutput {
        crate::util::alias(&mut input, "path", &["file", "file_path", "filename"]);
        let p = match arg_str(&input, "path") {
            Ok(p) => ctx.resolve(p),
            Err(e) => return ToolOutput::err(e),
        };
        let meta = match fs::metadata(&p) {
            Ok(m) => m,
            Err(e) => return ToolOutput::err(io_err("read", &p, &e)),
        };
        if meta.is_dir() {
            return list_dir(&p);
        }
        let data = match fs::read(&p) {
            Ok(d) => d,
            Err(e) => return ToolOutput::err(io_err("read", &p, &e)),
        };
        if is_binary(&data) {
            return ToolOutput::err(format!(
                "{} looks like a binary file ({} bytes); refusing to read it as text",
                p.display(),
                data.len()
            ));
        }
        let text = String::from_utf8_lossy(&data);
        let offset = arg_opt_u64(&input, "offset").unwrap_or(1).max(1) as usize;
        let limit = arg_opt_u64(&input, "limit").unwrap_or(DEFAULT_LIMIT).max(1) as usize;
        let total = text.lines().count();
        if total == 0 {
            return ToolOutput::ok("(empty file)");
        }
        if offset > total {
            return ToolOutput::err(format!("offset {offset} is past the end of the file ({total} lines)"));
        }
        let mut out = String::new();
        for (i, line) in text.lines().enumerate().skip(offset - 1).take(limit) {
            let l = truncate_str(line, MAX_LINE);
            out.push_str(&format!("{:>6}\t{}{}\n", i + 1, l, if l.len() < line.len() { " …[line truncated]" } else { "" }));
        }
        let shown_end = (offset - 1 + limit).min(total);
        if shown_end < total {
            out.push_str(&format!("… {} more lines (use offset={} to continue)\n", total - shown_end, shown_end + 1));
        }
        ToolOutput::ok(out)
    }
}

fn list_dir(p: &PathBuf) -> ToolOutput {
    let rd = match fs::read_dir(p) {
        Ok(r) => r,
        Err(e) => return ToolOutput::err(io_err("list", p, &e)),
    };
    let mut names: Vec<String> = rd
        .filter_map(|e| e.ok())
        .map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                n + "/"
            } else {
                n
            }
        })
        .collect();
    names.sort();
    let total = names.len();
    names.truncate(MAX_DIR_ENTRIES);
    let mut out = names.join("\n");
    if total > MAX_DIR_ENTRIES {
        out.push_str(&format!("\n… {} more entries", total - MAX_DIR_ENTRIES));
    }
    if total == 0 {
        out = "(empty directory)".into();
    }
    ToolOutput::ok(out)
}

pub struct Write;

impl Tool for Write {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "write".into(),
            description: "Create or overwrite a file with the given content. Parent directories are created.".into(),
            input_schema: json!({"type":"object","properties":{
                "path":{"type":"string"},"content":{"type":"string"}},"required":["path","content"]}),
            parallel_safe: false,
            idempotent: true,
            pinned: true,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        path_effect(ctx, input, true)
    }
    fn call(&self, ctx: &ToolCtx, mut input: Value) -> ToolOutput {
        crate::util::alias(&mut input, "path", &["file", "file_path", "filename"]);
        crate::util::alias(&mut input, "content", &["text", "contents", "data"]);
        let (p, content) = match (arg_str(&input, "path"), arg_str(&input, "content")) {
            (Ok(p), Ok(c)) => (ctx.resolve(p), c),
            (Err(e), _) | (_, Err(e)) => return ToolOutput::err(e),
        };
        if p.is_dir() {
            return ToolOutput::err(format!("{} is a directory", p.display()));
        }
        if let Some(parent) = p.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                return ToolOutput::err(io_err("create directory", parent, &e));
            }
        }
        let existed = p.exists();
        match atomic_write(&p, content.as_bytes()) {
            Ok(()) => ToolOutput::ok(format!(
                "{} {} ({} bytes)",
                if existed { "overwrote" } else { "created" },
                display_path(&ctx.workspace, &p),
                content.len()
            )),
            Err(e) => ToolOutput::err(io_err("write", &p, &e)),
        }
    }
}

/// Apply one exact-match replacement to `text`.
fn apply_edit(text: &str, old: &str, new: &str, all: bool) -> Result<(String, usize), String> {
    if old.is_empty() {
        return Err("old_string must not be empty (use write to create files)".into());
    }
    if old == new {
        return Err("old_string and new_string are identical; nothing to change".into());
    }
    let n = text.matches(old).count();
    if n == 0 {
        // Models sometimes double-escape: a literal backslash-n where a newline was meant.
        if let (Some(o), Some(nw)) = (unescape(old), unescape(new).or_else(|| Some(new.to_string()))) {
            if text.contains(&o) {
                return apply_edit(text, &o, &nw, all);
            }
        }
    }
    match n {
        0 => Err("old_string not found; read the file again and copy the text exactly (including whitespace)".into()),
        n if n > 1 && !all => Err(format!(
            "old_string occurs {n} times; add surrounding context to make it unique, or set replace_all"
        )),
        n => Ok((text.replace(old, new), n)),
    }
}

/// `a\\nb` → `a\nb` (also \\t and \\\"); None if there was nothing to unescape.
fn unescape(s: &str) -> Option<String> {
    if !s.contains("\\n") && !s.contains("\\t") {
        return None;
    }
    Some(s.replace("\\n", "\n").replace("\\t", "\t").replace("\\\"", "\""))
}

fn read_text(p: &PathBuf) -> Result<String, String> {
    let data = fs::read(p).map_err(|e| io_err("read", p, &e))?;
    if is_binary(&data) {
        return Err(format!("{} is a binary file; it cannot be edited as text", p.display()));
    }
    String::from_utf8(data).map_err(|_| format!("{} is not valid UTF-8; refusing to edit", p.display()))
}

pub struct Edit;

fn edit_aliases(e: &mut Value) {
    crate::util::alias(e, "old_string", &["old", "old_str", "search", "find"]);
    crate::util::alias(e, "new_string", &["new", "new_str", "replace", "replacement"]);
    crate::util::alias(e, "path", &["file", "file_path", "filename"]);
}

impl Tool for Edit {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "edit".into(),
            description: "Replace an exact string in a file. old_string must match exactly once unless replace_all is set.".into(),
            input_schema: json!({"type":"object","properties":{
                "path":{"type":"string"},"old_string":{"type":"string"},"new_string":{"type":"string"},
                "replace_all":{"type":"boolean","default":false}},
                "required":["path","old_string","new_string"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: true,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        path_effect(ctx, input, true)
    }
    fn call(&self, ctx: &ToolCtx, mut input: Value) -> ToolOutput {
        edit_aliases(&mut input);
        let path = arg_str(&input, "path").and_then(|p| if p.trim().is_empty() { Err("`path` is empty; name the file to edit".to_string()) } else { Ok(p) });
        let args = (path, arg_str(&input, "old_string"), arg_str(&input, "new_string"));
        let (p, old, new) = match args {
            (Ok(p), Ok(o), Ok(n)) => (ctx.resolve(p), o, n),
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => return ToolOutput::err(e),
        };
        if old.is_empty() && !p.exists() {
            if let Some(d) = p.parent() {
                let _ = fs::create_dir_all(d);
            }
            return match atomic_write(&p, new.as_bytes()) {
                Ok(()) => ToolOutput::ok(format!("created {}", display_path(&ctx.workspace, &p))),
                Err(e) => ToolOutput::err(io_err("write", &p, &e)),
            };
        }
        let text = match read_text(&p) {
            Ok(t) => t,
            Err(e) => return ToolOutput::err(e),
        };
        let all = arg_opt_bool(&input, "replace_all").unwrap_or(false);
        let (out, n) = match apply_edit(&text, old, new, all) {
            Ok(r) => r,
            Err(e) => return ToolOutput::err(format!("{}: {e}", display_path(&ctx.workspace, &p))),
        };
        match atomic_write(&p, out.as_bytes()) {
            Ok(()) => ToolOutput::ok(format!("edited {} ({n} replacement{})", display_path(&ctx.workspace, &p), if n == 1 { "" } else { "s" })),
            Err(e) => ToolOutput::err(io_err("write", &p, &e)),
        }
    }
}

pub struct Patch;

fn resolve_in(ws: &Path, p: &str) -> PathBuf {
    let p = ark_core::tool::expand_home(p);
    if p.is_absolute() {
        p
    } else {
        ws.join(p)
    }
}

/// What a `write` / `edit` / `patch` call would change, without writing anything:
/// (path, current text — None for a new file, text after the call).
pub fn preview(ws: &Path, tool: &str, input: &Value) -> Result<Vec<(PathBuf, Option<String>, String)>, String> {
    let mut input = input.clone();
    match tool {
        "write" => {
            crate::util::alias(&mut input, "path", &["file", "file_path", "filename"]);
            let p = resolve_in(ws, arg_str(&input, "path")?);
            let old = if p.exists() { Some(read_text(&p)?) } else { None };
            Ok(vec![(p, old, arg_str(&input, "content")?.to_string())])
        }
        "edit" => {
            edit_aliases(&mut input);
            let (p, old, new) = (resolve_in(ws, arg_str(&input, "path")?), arg_str(&input, "old_string")?, arg_str(&input, "new_string")?);
            if old.is_empty() && !p.exists() {
                return Ok(vec![(p, None, new.to_string())]);
            }
            let text = read_text(&p)?;
            let (out, _) = apply_edit(&text, old, new, arg_opt_bool(&input, "replace_all").unwrap_or(false))?;
            Ok(vec![(p, Some(text), out)])
        }
        "patch" => Ok(Patch::plan(ws, &input)?.into_iter().map(|f| (f.path, (!f.created).then_some(f.original), f.updated)).collect()),
        t => Err(format!("`{t}` does not edit files")),
    }
}

struct PlannedFile {
    path: PathBuf,
    original: String,
    updated: String,
    /// Did not exist before: rollback removes it.
    created: bool,
}

/// The edit list of a patch call, normalised: alternative key names, per-edit aliases, and a
/// top-level `path` applied to edits that name none (a common single-file shape).
fn patch_edits(input: &Value) -> Option<Vec<Value>> {
    let mut input = input.clone();
    crate::util::rename(&mut input, "edits", &["patch", "changes", "patches", "files", "input"]);
    edit_aliases(&mut input);
    let shared = input.get("path").and_then(Value::as_str).filter(|p| !p.is_empty()).map(str::to_string);
    let edits = input.get("edits")?.as_array()?;
    Some(
        edits
            .iter()
            .map(|e| {
                let mut e = e.clone();
                edit_aliases(&mut e);
                if let (Some(p), Some(o)) = (&shared, e.as_object_mut()) {
                    o.entry("path").or_insert_with(|| Value::String(p.clone()));
                }
                e
            })
            .collect(),
    )
}

impl Patch {
    fn plan(ws: &Path, input: &Value) -> Result<Vec<PlannedFile>, String> {
        let edits = patch_edits(input).ok_or("missing array argument `edits`")?;
        if edits.is_empty() {
            return Err("`edits` is empty".into());
        }
        let mut files: Vec<PlannedFile> = Vec::new();
        for (i, e) in edits.iter().enumerate() {
            let (p, old, new) = match (arg_str(e, "path"), arg_str(e, "old_string"), arg_str(e, "new_string")) {
                (Ok(p), Ok(o), Ok(n)) => (resolve_in(ws, p), o, n),
                (Err(err), _, _) | (_, Err(err), _) | (_, _, Err(err)) => return Err(format!("edit #{}: {err}", i + 1)),
            };
            let idx = match files.iter().position(|f| f.path == p) {
                Some(idx) => idx,
                // New file: old_string "" on a path that doesn't exist yet.
                None if old.is_empty() && !p.exists() => {
                    files.push(PlannedFile { path: p.clone(), original: String::new(), updated: new.to_string(), created: true });
                    continue;
                }
                None => {
                    let original = read_text(&p).map_err(|err| {
                        // Seen with Haiku: old_string "placeholder" for a file that should be created.
                        let hint = if p.exists() { "" } else { "; to create a new file, set its old_string to \"\"" };
                        format!("edit #{}: {err}{hint}", i + 1)
                    })?;
                    files.push(PlannedFile { path: p.clone(), updated: original.clone(), original, created: false });
                    files.len() - 1
                }
            };
            let f = &mut files[idx];
            f.updated = apply_edit(&f.updated, old, new, false)
                .map_err(|err| format!("edit #{} ({}): {err}", i + 1, display_path(ws, &p)))?
                .0;
        }
        Ok(files)
    }
}

impl Tool for Patch {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "patch".into(),
            description: "Apply several exact-string edits across one or more files atomically: either every edit applies or none does. To create a file, use old_string \"\" on a path that does not exist.".into(),
            input_schema: json!({"type":"object","properties":{"edits":{"type":"array","items":{
                "type":"object","properties":{"path":{"type":"string"},"old_string":{"type":"string"},"new_string":{"type":"string"}},
                "required":["path","old_string","new_string"]}}},"required":["edits"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let mut out: Vec<Effect> = Vec::new();
        for e in patch_edits(input).into_iter().flatten() {
            if let Ok(p) = arg_str(&e, "path") {
                let eff = Effect::Write { path: ctx.resolve(p) };
                if !out.contains(&eff) {
                    out.push(eff);
                }
            }
        }
        out
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let files = match Self::plan(&ctx.workspace, &input) {
            Ok(f) => f,
            Err(e) => return ToolOutput::err(format!("patch rejected, no files changed: {e}")),
        };
        for (i, f) in files.iter().enumerate() {
            if f.created {
                if let Some(d) = f.path.parent() {
                    let _ = fs::create_dir_all(d);
                }
            }
            if let Err(e) = atomic_write(&f.path, f.updated.as_bytes()) {
                let mut failed_rollback = Vec::new();
                for done in &files[..i] {
                    let undo = if done.created { fs::remove_file(&done.path) } else { atomic_write(&done.path, done.original.as_bytes()) };
                    if undo.is_err() {
                        failed_rollback.push(done.path.display().to_string());
                    }
                }
                let mut msg = format!("patch failed, rolled back: {}", io_err("write", &f.path, &e));
                if !failed_rollback.is_empty() {
                    msg.push_str(&format!("; WARNING rollback also failed for: {}", failed_rollback.join(", ")));
                }
                return ToolOutput::err(msg);
            }
        }
        let names: Vec<_> = files.iter().map(|f| display_path(&ctx.workspace, &f.path)).collect();
        ToolOutput::ok(format!("patched {} file(s): {}", files.len(), names.join(", ")))
    }
}

#[cfg(test)]
mod preview_tests {
    use super::*;

    #[test]
    fn previews_edits_without_writing() {
        let d = std::env::temp_dir().join(format!("ark-preview-{}", std::process::id()));
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("a.txt"), "one two one").unwrap();
        let p = preview(&d, "edit", &json!({"path": "a.txt", "old_string": "two", "new_string": "2"})).unwrap();
        assert_eq!((p[0].1.as_deref(), p[0].2.as_str()), (Some("one two one"), "one 2 one"));
        let p = preview(&d, "patch", &json!({"edits": [{"path": "a.txt", "old": "one", "new": "1"}, {"path": "b.txt", "old_string": "", "new_string": "new"}]}));
        assert!(p.is_err(), "`one` is ambiguous");
        let p = preview(&d, "patch", &json!({"edits": [{"path": "a.txt", "old": "two", "new": "2"}, {"path": "b.txt", "old_string": "", "new_string": "new"}]})).unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p[1].1, None);
        let p = preview(&d, "write", &json!({"path": "a.txt", "content": "x"})).unwrap();
        assert_eq!(p[0].1.as_deref(), Some("one two one"));
        assert_eq!(fs::read_to_string(d.join("a.txt")).unwrap(), "one two one", "nothing written");
        let _ = fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ctx;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn lenient_argument_names_and_patch_creates_files() {
        let c = ctx("lenient");
        assert!(!Write.call(&c, json!({"file":"a.txt","text":"one two"})).is_error);
        assert!(!Edit.call(&c, json!({"file_path":"a.txt","old":"two","new":"2"})).is_error);
        assert_eq!(fs::read_to_string(c.workspace.join("a.txt")).unwrap(), "one 2");
        // Aliased paths are judged by the gate too.
        assert_eq!(Write.effects(&c, &json!({"file":"/etc/x","text":"y"})), vec![Effect::Write { path: "/etc/x".into() }]);
        assert_eq!(Patch.effects(&c, &json!({"edits":[{"file":"/etc/y","old":"a","new":"b"}]})), vec![Effect::Write { path: "/etc/y".into() }]);
        let o = Patch.call(&c, json!({"edits":[{"path":"a.txt","old":"one","new":"1"},{"path":"new/dir/b.txt","old_string":"","new_string":"fresh"}]}));
        assert!(!o.is_error, "{}", o.content);
        assert_eq!(fs::read_to_string(c.workspace.join("new/dir/b.txt")).unwrap(), "fresh");
        // Creating then failing later rolls back: the new file must vanish.
        let o = Patch.call(&c, json!({"edits":[{"path":"c.txt","old_string":"","new_string":"x"},{"path":"a.txt","old_string":"zzz","new_string":"q"}]}));
        assert!(o.is_error && !c.workspace.join("c.txt").exists());
        let o = Patch.call(&c, json!({"patch":"[{\"path\":\"a.txt\",\"old_string\":\"1\",\"new_string\":\"I\"}]"}));
        assert!(!o.is_error, "stringified `patch` accepted: {}", o.content);
        assert_eq!(Patch.effects(&c, &json!({"changes":[{"path":"/etc/z","old":"a","new":"b"}]})), vec![Effect::Write { path: "/etc/z".into() }]);
        fs::write(c.workspace.join("m.py"), "def f():\n    return 1\n").unwrap();
        let o = Edit.call(&c, json!({"path":"m.py","old_string":"def f():\\n    return 1","new_string":"def f():\\n    return 2"}));
        assert!(!o.is_error, "double-escaped newlines tolerated: {}", o.content);
        assert_eq!(fs::read_to_string(c.workspace.join("m.py")).unwrap(), "def f():\n    return 2\n");
        assert!(!Edit.call(&c, json!({"path":"fresh/new.txt","old_string":"","new_string":"hi"})).is_error);
        assert!(Edit.call(&c, json!({"path":"m.py","old_string":"","new_string":"x"})).is_error, "empty old on existing file still refused");
        assert!(!Patch.call(&c, json!({"input":[{"path":"m.py","old":"2","new":"3"}]})).is_error);
        // "" on an existing file is not a create.
        assert!(Patch.call(&c, json!({"edits":[{"path":"a.txt","old_string":"","new_string":"x"}]})).is_error);
    }

    #[test]
    fn read_numbers_lines_and_paginates() {
        let c = ctx("read");
        fs::write(c.workspace.join("a.txt"), "one\ntwo\nthree\n").unwrap();
        let o = Read.call(&c, json!({"path":"a.txt","offset":2,"limit":1}));
        assert!(!o.is_error);
        assert!(o.content.contains("     2\ttwo"));
        assert!(!o.content.contains("one"));
        assert!(o.content.contains("1 more lines (use offset=3"));
    }

    #[test]
    fn read_failures() {
        let c = ctx("readf");
        assert!(Read.call(&c, json!({})).is_error);
        assert!(Read.call(&c, json!({"path": 5})).is_error);
        let o = Read.call(&c, json!({"path":"nope.txt"}));
        assert!(o.is_error && o.content.contains("does not exist"), "{}", o.content);
        fs::write(c.workspace.join("bin"), [0u8, 1, 2, 0, 255]).unwrap();
        let o = Read.call(&c, json!({"path":"bin"}));
        assert!(o.is_error && o.content.contains("binary"));
        fs::write(c.workspace.join("x"), "a\n").unwrap();
        assert!(Read.call(&c, json!({"path":"x","offset":10})).is_error);
        let locked = c.workspace.join("locked");
        fs::write(&locked, "secret").unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let o = Read.call(&c, json!({"path":"locked"}));
        assert!(o.is_error && o.content.contains("permission denied"), "{}", o.content);
    }

    #[test]
    fn read_dir_and_empty_and_non_utf8() {
        let c = ctx("readd");
        fs::create_dir(c.workspace.join("sub")).unwrap();
        fs::write(c.workspace.join("e"), "").unwrap();
        fs::write(c.workspace.join("latin"), [b'c', b'a', b'f', 0xe9, b'\n']).unwrap();
        let o = Read.call(&c, json!({"path":"."}));
        assert!(o.content.contains("sub/") && o.content.contains("latin"));
        assert_eq!(Read.call(&c, json!({"path":"e"})).content, "(empty file)");
        let o = Read.call(&c, json!({"path":"latin"}));
        assert!(!o.is_error && o.content.contains("caf"));
    }

    #[test]
    fn write_creates_dirs_and_reports_effects() {
        let c = ctx("write");
        let o = Write.call(&c, json!({"path":"d/e/f.txt","content":"hi"}));
        assert!(!o.is_error, "{}", o.content);
        assert_eq!(fs::read_to_string(c.workspace.join("d/e/f.txt")).unwrap(), "hi");
        assert_eq!(Write.effects(&c, &json!({"path":"d/e/f.txt"})), vec![Effect::Write { path: c.workspace.join("d/e/f.txt") }]);
        let o = Write.call(&c, json!({"path":"d/e/f.txt","content":"bye"}));
        assert!(o.content.starts_with("overwrote"));
    }

    #[test]
    fn write_failures() {
        let c = ctx("writef");
        assert!(Write.call(&c, json!({"path":"a"})).is_error);
        assert!(Write.call(&c, json!({"path":".","content":"x"})).is_error);
        let ro = c.workspace.join("ro");
        fs::create_dir(&ro).unwrap();
        fs::set_permissions(&ro, fs::Permissions::from_mode(0o555)).unwrap();
        let o = Write.call(&c, json!({"path":"ro/f","content":"x"}));
        assert!(o.is_error && o.content.contains("permission denied"), "{}", o.content);
        assert!(fs::read_dir(&ro).unwrap().next().is_none(), "no temp file left behind");
        fs::set_permissions(&ro, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn edit_paths() {
        let c = ctx("edit");
        let f = c.workspace.join("f.rs");
        fs::write(&f, "let a = 1;\nlet b = 1;\n").unwrap();
        let o = Edit.call(&c, json!({"path":"f.rs","old_string":"= 1","new_string":"= 2"}));
        assert!(o.is_error && o.content.contains("occurs 2 times"));
        let o = Edit.call(&c, json!({"path":"f.rs","old_string":"zzz","new_string":"y"}));
        assert!(o.is_error && o.content.contains("not found"));
        assert!(Edit.call(&c, json!({"path":"f.rs","old_string":"","new_string":"y"})).is_error);
        assert!(Edit.call(&c, json!({"path":"f.rs","old_string":"a","new_string":"a"})).is_error);
        assert!(Edit.call(&c, json!({"path":"missing.rs","old_string":"a","new_string":"b"})).is_error);
        assert!(Edit.call(&c, json!({"path":"f.rs","old_string":"a"})).is_error);
        assert_eq!(fs::read_to_string(&f).unwrap(), "let a = 1;\nlet b = 1;\n", "failed edits must not touch the file");
        let o = Edit.call(&c, json!({"path":"f.rs","old_string":"= 1","new_string":"= 2","replace_all":true}));
        assert!(!o.is_error && o.content.contains("2 replacements"));
        assert!(Edit.call(&c, json!({"path":"f.rs","old_string":"a = 2","new_string":"a = 3"})).content.contains("1 replacement"));
        assert_eq!(fs::read_to_string(&f).unwrap(), "let a = 3;\nlet b = 2;\n");
        fs::write(c.workspace.join("b"), [0u8, 9]).unwrap();
        assert!(Edit.call(&c, json!({"path":"b","old_string":"\t","new_string":"x"})).content.contains("binary"));
    }

    #[test]
    fn patch_applies_across_files_and_same_file_sequentially() {
        let c = ctx("patch");
        fs::write(c.workspace.join("a"), "alpha beta").unwrap();
        fs::write(c.workspace.join("b"), "gamma").unwrap();
        let input = json!({"edits":[
            {"path":"a","old_string":"alpha","new_string":"ALPHA"},
            {"path":"a","old_string":"ALPHA beta","new_string":"done"},
            {"path":"b","old_string":"gamma","new_string":"GAMMA"}]});
        assert_eq!(Patch.effects(&c, &input).len(), 2);
        let o = Patch.call(&c, input);
        assert!(!o.is_error, "{}", o.content);
        assert_eq!(fs::read_to_string(c.workspace.join("a")).unwrap(), "done");
        assert_eq!(fs::read_to_string(c.workspace.join("b")).unwrap(), "GAMMA");
    }

    #[test]
    fn patch_validation_failure_changes_nothing() {
        let c = ctx("patchv");
        fs::write(c.workspace.join("a"), "one").unwrap();
        fs::write(c.workspace.join("b"), "two").unwrap();
        let o = Patch.call(&c, json!({"edits":[
            {"path":"a","old_string":"one","new_string":"1"},
            {"path":"b","old_string":"missing","new_string":"2"}]}));
        assert!(o.is_error && o.content.contains("edit #2"), "{}", o.content);
        assert_eq!(fs::read_to_string(c.workspace.join("a")).unwrap(), "one");
        assert!(Patch.call(&c, json!({"edits":[]})).is_error);
        assert!(Patch.call(&c, json!({})).is_error);
        assert!(Patch.call(&c, json!({"edits":[{"path":"a"}]})).is_error);
        let o = Patch.call(&c, json!({"edits":[{"path":"nofile","old_string":"x","new_string":"y"}]}));
        assert!(o.is_error && o.content.contains("old_string to \"\""), "{}", o.content);
    }

    #[test]
    fn patch_inherits_top_level_path_and_edit_rejects_empty_path() {
        let c = ctx("patchtop");
        fs::write(c.workspace.join("a"), "one two").unwrap();
        // Seen with Haiku: one shared `path` beside the edit list; per-edit paths still win.
        let input = json!({"path":"a","edits":[{"old_string":"one","new_string":"1"},{"path":"b","old_string":"","new_string":"new"}]});
        assert_eq!(Patch.effects(&c, &input), vec![Effect::Write { path: c.workspace.join("a") }, Effect::Write { path: c.workspace.join("b") }]);
        let o = Patch.call(&c, input);
        assert!(!o.is_error, "{}", o.content);
        assert_eq!(fs::read_to_string(c.workspace.join("a")).unwrap(), "1 two");
        assert_eq!(fs::read_to_string(c.workspace.join("b")).unwrap(), "new");
        // Seen with gpt-5-nano: path "" used to resolve to the workspace directory.
        let o = Edit.call(&c, json!({"path":"","old_string":"","new_string":""}));
        assert!(o.is_error && o.content.contains("`path` is empty"), "{}", o.content);
    }

    #[test]
    fn patch_rolls_back_when_second_write_fails() {
        let c = ctx("patchr");
        fs::write(c.workspace.join("a"), "one").unwrap();
        let ro = c.workspace.join("ro");
        fs::create_dir(&ro).unwrap();
        fs::write(ro.join("b"), "two").unwrap();
        fs::set_permissions(&ro, fs::Permissions::from_mode(0o555)).unwrap();
        let o = Patch.call(&c, json!({"edits":[
            {"path":"a","old_string":"one","new_string":"1"},
            {"path":"ro/b","old_string":"two","new_string":"2"}]}));
        fs::set_permissions(&ro, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(o.is_error && o.content.contains("rolled back"), "{}", o.content);
        assert_eq!(fs::read_to_string(c.workspace.join("a")).unwrap(), "one");
        assert_eq!(fs::read_to_string(ro.join("b")).unwrap(), "two");
    }
}
