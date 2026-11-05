//! read / write / edit / patch / apply_patch. Behavior follows Hermes `read_file` /
//! `write_file` / `patch` and OpenClaw `read` / `apply_patch` (see fuzzy.rs, patchfmt.rs,
//! extract.rs, filestate.rs, lint.rs for the ported pieces).

use crate::filestate as st;
use crate::lint;
use crate::util::{atomic_write, display_path, io_err, is_binary, truncate_str};
use seagent_core::tool::{arg_opt_bool, arg_opt_str, arg_opt_u64, arg_str};
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

const MAX_LINE: usize = 2000;
const DEFAULT_LIMIT: u64 = 2000;
const MAX_DIR_ENTRIES: usize = 1000;
const LARGE_FILE_HINT_BYTES: u64 = 512_000;

fn protected_effect(p: &Path) -> Option<Effect> {
    (st::cfg().protected_instructions && st::is_protected_instruction(p)).then(|| Effect::Remote {
        dest: p.display().to_string(),
        reason: format!("writes agent-instruction file {} (steers future agent runs; a prompt-injection persistence vector)", p.display()),
    })
}

fn path_effect(ctx: &ToolCtx, input: &Value, write: bool) -> Vec<Effect> {
    // Same aliases the tools accept, so the gate judges what will really run.
    let mut input = input.clone();
    crate::util::alias(&mut input, "path", &["file", "file_path", "filename"]);
    match arg_str(&input, "path") {
        Ok(p) if write => {
            let p = ctx.resolve(p);
            let mut v = vec![Effect::Write { path: p.clone() }];
            v.extend(protected_effect(&p));
            v
        }
        Ok(p) => vec![Effect::Read { path: ctx.resolve(p) }],
        Err(_) => vec![],
    }
}

/// `[files] workspace_only`: refuse paths outside the workspace.
pub(crate) fn contained(ctx: &ToolCtx, p: &Path) -> Result<(), String> {
    if st::cfg().workspace_only {
        st::contain(&ctx.workspace, p).map_err(|e| format!("{e}\nFile tools are workspace-contained by configuration (files.workspace_only = true); keep paths within the workspace."))?;
    }
    Ok(())
}

pub struct Read;

impl Tool for Read {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "read".into(),
            description: "Read a text file with line numbers, or list a directory. Use offset/limit for large files. Documents (.ipynb, .docx, .xlsx, .pptx, .odt/.ods/.odp, .epub, .rtf, .pdf, SQLite) are converted to text; images (PNG/JPEG/GIF/WebP) are shown to you as pictures.".into(),
            input_schema: json!({"type":"object","properties":{
                "path":{"type":"string","description":"File or directory, relative to the workspace or absolute"},
                "offset":{"type":"integer","minimum":1,"description":"First line to show (1-based)"},
                "limit":{"type":"integer","minimum":1,"description":"Max lines (default 2000)"},
                "fresh":{"type":"boolean","description":"Return the content even if it is unchanged since your last identical read"}},
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
        let raw = match arg_str(&input, "path") {
            Ok(p) => p.to_string(),
            Err(e) => return ToolOutput::err(e),
        };
        let p = ctx.resolve(&raw);
        if let Err(e) = contained(ctx, &p) {
            return ToolOutput::err(e);
        }
        if st::blocked_device(&p) {
            return ToolOutput::err(format!("Cannot read '{raw}': this is a device file that would block or produce infinite output."));
        }
        let meta = match fs::metadata(&p) {
            Ok(m) => m,
            Err(e) => {
                let mut msg = io_err("read", &p, &e);
                if e.kind() == std::io::ErrorKind::NotFound {
                    let similar = st::similar_files(&p);
                    if !similar.is_empty() {
                        msg.push_str(&format!("\nSimilar files: {}", similar.iter().map(|s| display_path(&ctx.workspace, Path::new(s))).collect::<Vec<_>>().join(", ")));
                    }
                }
                return ToolOutput::err(msg);
            }
        };
        if meta.is_dir() {
            st::note_other_call(&ctx.session_id);
            return list_dir(&p);
        }
        if let Some(kind) = st::special_file_kind(&p) {
            return ToolOutput::err(format!("'{raw}' is {kind}, not a regular file — reading it would block indefinitely, so no read was attempted. Use the shell tool if you need to interact with it."));
        }
        if let Some(e) = st::read_block_error(&p) {
            return ToolOutput::err(e);
        }
        let offset = arg_opt_u64(&input, "offset").unwrap_or(1).max(1) as usize;
        let limit = arg_opt_u64(&input, "limit").unwrap_or(DEFAULT_LIMIT).max(1) as usize;
        if crate::extract::is_extractable(&p) {
            return read_document(ctx, &raw, &p, offset, limit);
        }
        if let Some(out) = read_image(&p, meta.len()) {
            return out;
        }
        if st::has_binary_extension(&p) {
            let ext = p.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
            return ToolOutput::err(format!("Cannot read binary file '{raw}' (.{ext}). Use the shell tool to inspect binary files."));
        }
        let fresh = arg_opt_bool(&input, "fresh").unwrap_or(false);
        if !fresh {
            match st::dedup_check(&ctx.session_id, &p, offset, limit) {
                Some(Ok(stub)) => return ToolOutput::ok(stub),
                Some(Err(block)) => return ToolOutput::err(block),
                None => {}
            }
        }
        let before = st::version(&p);
        let data = match fs::read(&p) {
            Ok(d) => d,
            Err(e) => return ToolOutput::err(io_err("read", &p, &e)),
        };
        if is_binary(&data) {
            return ToolOutput::err(format!("{} looks like a binary file ({} bytes); refusing to read it as text", p.display(), data.len()));
        }
        let text = String::from_utf8_lossy(&data);
        paginate(ctx, &p, &text, offset, limit, meta.len(), before, false)
    }
}

/// Line-numbered page of `text` with the char budget, hints and read tracking.
#[allow(clippy::too_many_arguments)]
fn paginate(ctx: &ToolCtx, p: &Path, text: &str, offset: usize, limit: usize, size: u64, before: Option<st::Version>, document: bool) -> ToolOutput {
    let total = text.lines().count();
    if total == 0 {
        st::record_read(&ctx.session_id, p, offset, limit, 0, 0, false, before);
        return ToolOutput::ok("(empty file)");
    }
    if offset > total {
        return ToolOutput::err(format!("offset {offset} is past the end of the file ({total} lines)"));
    }
    let mut out = String::new();
    let mut clamped_line = false;
    for (i, line) in text.lines().enumerate().skip(offset - 1).take(limit) {
        let l = truncate_str(line, MAX_LINE);
        clamped_line |= l.len() < line.len();
        out.push_str(&format!("{:>6}\t{}{}\n", i + 1, l, if l.len() < line.len() { " …[line truncated]" } else { "" }));
    }
    let mut shown_end = (offset - 1 + limit).min(total);
    let max_chars = st::cfg().read_max_chars;
    let mut budget_note = String::new();
    if out.chars().count() > max_chars {
        let (kept, n, _) = st::char_budget(&out, max_chars);
        let next = offset + n;
        shown_end = next - 1;
        budget_note = format!("… output truncated at the {max_chars}-char read budget after {n} line(s) (showing lines {offset}-{shown_end} of {total}). Use offset={next} to continue.\n");
        out = kept;
        if !out.ends_with('\n') {
            out.push('\n');
        }
    }
    let conflicts = st::conflict_blocks(&out);
    if !budget_note.is_empty() {
        out.push_str(&budget_note);
    } else if shown_end < total {
        out.push_str(&format!("… {} more lines (use offset={} to continue)\n", total - shown_end, shown_end + 1));
    }
    if conflicts > 0 {
        out.push_str(&format!("[hint] {conflicts} unresolved git merge-conflict block(s) (<<<<<<< / ======= / >>>>>>>) in this range. Resolve them (keep one side or combine, delete the markers) before editing around them.\n"));
    }
    if size > LARGE_FILE_HINT_BYTES && limit > 200 && shown_end < total {
        out.push_str(&format!("[hint] This file is large ({size} bytes). Consider reading only the section you need with offset and limit to keep context usage efficient.\n"));
    }
    let partial = offset > 1 || shown_end < total || clamped_line;
    if document && partial {
        // Extracted text is not the file's bytes: never a whole-file write baseline.
        return ToolOutput::ok(out);
    }
    let count = st::record_read(&ctx.session_id, p, offset, limit, shown_end, total, partial, before);
    if count >= 4 {
        return ToolOutput::err(format!("BLOCKED: You have read this exact file region {count} times in a row. The content has NOT changed. You already have this information. STOP re-reading and proceed with your task."));
    }
    if count >= 3 {
        out.push_str(&format!("[warning] You have read this exact file region {count} times consecutively. The content has not changed since your last read. Use the information you already have. If you are stuck in a loop, stop reading and proceed with writing or responding.\n"));
    }
    ToolOutput::ok(out)
}

fn read_document(ctx: &ToolCtx, raw: &str, p: &Path, offset: usize, limit: usize) -> ToolOutput {
    let data = match fs::read(p) {
        Ok(d) => d,
        Err(e) => return ToolOutput::err(io_err("read", p, &e)),
    };
    let ext = crate::extract::ext_of(p);
    match crate::extract::extract(p, &data) {
        Ok(text) => {
            let mut o = paginate(ctx, p, &text, offset, limit, data.len() as u64, st::version(p), ext != "ipynb");
            if !o.is_error && ext != "ipynb" {
                o.content.push_str("[extracted document text — not the file's bytes; edit the original with a document library via the shell tool]\n");
            }
            o
        }
        // .ipynb that is not valid JSON etc.: fall back to plain text.
        Err(_) if ext == "ipynb" && !is_binary(&data) => paginate(ctx, p, &String::from_utf8_lossy(&data), offset, limit, data.len() as u64, st::version(p), false),
        Err(e) => ToolOutput::err(format!("Cannot read '{raw}' (.{ext}): document extraction failed — {e}. Use the shell tool to inspect or convert the file.")),
    }
}

fn read_image(p: &Path, size: u64) -> Option<ToolOutput> {
    let ext = p.extension()?.to_string_lossy().to_lowercase();
    if !matches!(ext.as_str(), "png" | "jpg" | "jpeg" | "gif" | "webp") {
        return None;
    }
    let mut head = [0u8; 16];
    let n = fs::File::open(p).and_then(|mut f| std::io::Read::read(&mut f, &mut head)).ok()?;
    let mt = seagent_core::tool::image_media_type(&head[..n])?;
    if size > seagent_core::tool::MAX_IMAGE_BYTES {
        return Some(ToolOutput::err(format!("{} is a {mt} image of {size} bytes, over the {} byte limit for showing it to the model. Downscale it first (e.g. `convert in.png -resize 1600x1600 out.png` via the shell tool).", p.display(), seagent_core::tool::MAX_IMAGE_BYTES)));
    }
    Some(ToolOutput::ok(format!("Read image file [{mt}, {size} bytes]: {}\n{}", p.display(), seagent_core::tool::image_marker(mt, p))))
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

/// Guards every writing tool shares (system paths, binary documents, containment).
fn write_guards(ctx: &ToolCtx, p: &Path) -> Result<(), String> {
    contained(ctx, p)?;
    if let Some(e) = st::sensitive_write_error(p) {
        return Err(e);
    }
    if let Some(e) = st::binary_document_write_error(p) {
        return Err(e);
    }
    Ok(())
}

/// Post-write lint suffix (non-blocking report).
fn lint_after(p: &Path, pre: Option<&str>, post: &str) -> String {
    let c = st::cfg();
    if !c.lint {
        return String::new();
    }
    lint::suffix(&lint::check_delta(p, pre, Some(post), c.lint_project_toolchains))
}

/// Security-guidance suffix (Hermes `plugins/security-guidance`): a non-blocking warning for
/// dangerous constructs in the new content, attached the same way the lint report is.
fn guidance_after(ctx: &ToolCtx, p: &Path, new_text: &str) -> String {
    if !st::cfg().security_guidance {
        return String::new();
    }
    seagent_security::guidance::suffix(&ctx.session_id, &p.to_string_lossy(), new_text)
}

/// `SECURITY_GUIDANCE_BLOCK=1`: refuse the write instead of warning.
fn guidance_refusal(ctx: &ToolCtx, p: &Path, new_text: &str) -> Option<String> {
    if !st::cfg().security_guidance {
        return None;
    }
    seagent_security::guidance::refusal(&ctx.session_id, &p.to_string_lossy(), new_text)
}

pub struct Write;

impl Tool for Write {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "write".into(),
            description: "Create or overwrite a file with the given content. Parent directories are created. Overwriting an existing file requires having read its full current content first; for changes to part of a file use edit.".into(),
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
        if let Err(e) = write_guards(ctx, &p) {
            return ToolOutput::err(e);
        }
        if let Some(e) = st::internal_content_error(content) {
            return ToolOutput::err(e);
        }
        let ext = p.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
        if st::cfg().lint && lint::FAIL_CLOSED.contains(&ext.as_str()) {
            if let lint::Lint::Failed(e) = lint::check_content(&p, content) {
                return ToolOutput::err(format!("Refusing to write {}: the content does not parse as .{ext} ({e}). The file was NOT modified; fix the syntax and write again.", display_path(&ctx.workspace, &p)));
            }
        }
        st::note_other_call(&ctx.session_id);
        let _lock = st::lock_path(&p);
        if let Some(why) = guidance_refusal(ctx, &p, content) {
            return ToolOutput::err(why);
        }
        if let Some(reason) = st::stale_overwrite_blocker(&ctx.session_id, &p) {
            return ToolOutput::err(format!("Refusing to overwrite {}: {reason} The file was NOT modified. Reload the current contents with read (every page, for a file that needs offset/limit), merge the requested change, then call write again. For small edits, prefer edit so existing unrelated changes are preserved.", display_path(&ctx.workspace, &p)));
        }
        let warning = st::edit_warning(&ctx.session_id, &p);
        if let Some(parent) = p.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                return ToolOutput::err(io_err("create directory", parent, &e));
            }
        }
        let old = fs::read_to_string(&p).ok();
        let existed = p.exists();
        match atomic_write(&p, content.as_bytes()) {
            Ok(()) => {
                st::note_edited(&ctx.session_id, &p, true);
                let mut msg = format!("{} {} ({} bytes)", if existed { "overwrote" } else { "created" }, display_path(&ctx.workspace, &p), content.len());
                if let Some(w) = warning {
                    msg.push_str(&format!("\n[warning] {w}"));
                }
                if let Some(h) = old.as_deref().and_then(|o| st::rewrite_hint(o, content)) {
                    msg.push_str(&format!("\n[hint] {h}"));
                }
                msg.push_str(&lint_after(&p, old.as_deref(), content));
                msg.push_str(&guidance_after(ctx, &p, content));
                msg.push_str(&crate::lsp::after_write(&ctx.workspace, &p, old.as_deref(), content));
                ToolOutput::ok(msg)
            }
            Err(e) => ToolOutput::err(io_err("write", &p, &e)),
        }
    }
}

/// One replacement through the fuzzy matcher: (new text, count, notes).
fn apply_edit(text: &str, old: &str, new: &str, all: bool) -> Result<(String, usize, Vec<String>), String> {
    if old.is_empty() {
        return Err("old_string must not be empty (use write to create files)".into());
    }
    if old == new {
        return Err("old_string and new_string are identical; nothing to change".into());
    }
    // Both strings double-escaped (a literal backslash-n where a newline was meant):
    // seagent has always unescaped both when that makes old_string match exactly.
    if !text.contains(old) {
        if let (Some(o), Some(nw)) = (unescape(old), unescape(new).or_else(|| Some(new.to_string()))) {
            if text.contains(&o) && o != nw {
                return apply_edit(text, &o, &nw, all);
            }
        }
    }
    match crate::fuzzy::fuzzy_replace(text, old, new, all) {
        Ok(r) => {
            let mut notes: Vec<String> = r.note.into_iter().collect();
            notes.extend(crate::fuzzy::boundary_note([r.strategy], "old_string's", ""));
            if r.strategy != "exact" && !crate::fuzzy::is_similarity_strategy(r.strategy) {
                notes.push(format!("matched with the {} strategy (whitespace/indentation/escaping/Unicode differed from the file)", r.strategy));
            }
            Ok((r.content, r.count, notes))
        }
        Err(e) => Err(format!("{e}{}", crate::fuzzy::no_match_hint(&e, old, text))),
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

fn notes_suffix(notes: &[String]) -> String {
    notes.iter().map(|n| format!("\n[note] {n}")).collect()
}

impl Tool for Edit {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "edit".into(),
            description: "Replace a string in a file. old_string must match exactly once unless replace_all is set; small whitespace, indentation, escaping and Unicode-punctuation differences are tolerated.".into(),
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
        if let Err(e) = write_guards(ctx, &p) {
            return ToolOutput::err(e);
        }
        let _lock = st::lock_path(&p);
        if let Some(why) = guidance_refusal(ctx, &p, new) {
            return ToolOutput::err(why);
        }
        if old.is_empty() && !p.exists() {
            if let Some(d) = p.parent() {
                let _ = fs::create_dir_all(d);
            }
            return match atomic_write(&p, new.as_bytes()) {
                Ok(()) => {
                    st::note_edited(&ctx.session_id, &p, true);
                    ToolOutput::ok(format!("created {}{}{}{}", display_path(&ctx.workspace, &p), lint_after(&p, None, new), guidance_after(ctx, &p, new), crate::lsp::after_write(&ctx.workspace, &p, None, new)))
                }
                Err(e) => ToolOutput::err(io_err("write", &p, &e)),
            };
        }
        let text = match read_text(&p) {
            Ok(t) => t,
            Err(e) => return ToolOutput::err(e),
        };
        let warning = st::edit_warning(&ctx.session_id, &p);
        let all = arg_opt_bool(&input, "replace_all").unwrap_or(false);
        let (out, n, notes) = match apply_edit(&text, old, new, all) {
            Ok(r) => r,
            Err(e) => return ToolOutput::err(format!("{}: {e}", display_path(&ctx.workspace, &p))),
        };
        match atomic_write(&p, out.as_bytes()) {
            Ok(()) => {
                st::note_edited(&ctx.session_id, &p, false);
                let mut msg = format!("edited {} ({n} replacement{})", display_path(&ctx.workspace, &p), if n == 1 { "" } else { "s" });
                if let Some(w) = warning {
                    msg.push_str(&format!("\n[warning] {w}"));
                }
                msg.push_str(&notes_suffix(&notes));
                msg.push_str(&lint_after(&p, Some(&text), &out));
                msg.push_str(&guidance_after(ctx, &p, new));
                msg.push_str(&crate::lsp::after_write(&ctx.workspace, &p, Some(&text), &out));
                ToolOutput::ok(msg)
            }
            Err(e) => ToolOutput::err(io_err("write", &p, &e)),
        }
    }
}

pub struct Patch;

fn resolve_in(ws: &Path, p: &str) -> PathBuf {
    let p = seagent_core::tool::expand_home(p);
    if p.is_absolute() {
        p
    } else {
        ws.join(p)
    }
}

/// What a `write` / `edit` / `patch` / `apply_patch` call would change, without writing anything:
/// (path, current text — None for a new file, text after the call — "" for a deletion).
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
            let (out, _, _) = apply_edit(&text, old, new, arg_opt_bool(&input, "replace_all").unwrap_or(false))?;
            Ok(vec![(p, Some(text), out)])
        }
        "patch" => Ok(Patch::plan(ws, &input)?.into_iter().map(|(p, b, a)| (p, b, a.unwrap_or_default())).collect()),
        "apply_patch" => {
            let text = arg_str(&input, "input")?;
            let hunks = crate::patchfmt::parse_apply_patch(text)?;
            let (plan, _) = crate::patchfmt::plan_apply_patch(&hunks, &|r| Ok((resolve_in(ws, r), r.to_string())))?;
            Ok(plan.into_iter().map(|(p, b, a)| (p, b, a.unwrap_or_default())).collect())
        }
        t => Err(format!("`{t}` does not edit files")),
    }
}

/// The edit list of a patch call, normalised: alternative key names, per-edit aliases, and a
/// top-level `path` applied to edits that name none (a common single-file shape).
fn patch_edits(input: &Value) -> Option<Vec<Value>> {
    let mut input = input.clone();
    if v4a_text(&input).is_some() {
        return None;
    }
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

/// A V4A patch text given as `patch` (or `edits`/`input`) instead of an edit list.
fn v4a_text(input: &Value) -> Option<&str> {
    ["patch", "edits", "input"].iter().filter_map(|k| input.get(*k).and_then(Value::as_str)).find(|s| {
        let t = s.trim_start();
        !t.starts_with('[') && !t.starts_with('{') && crate::patchfmt::looks_like_v4a(s)
    })
}

impl Patch {
    /// (path, before — None if new, after — None if deleted).
    fn plan(ws: &Path, input: &Value) -> Result<crate::patchfmt::Plan, String> {
        if let Some(text) = v4a_text(input) {
            let ops = crate::patchfmt::parse_v4a(text)?;
            if ops.is_empty() {
                return Err("the patch text contains no operations (*** Update File: / *** Add File: / *** Delete File: / *** Move File: a -> b)".into());
            }
            return Ok(crate::patchfmt::apply_v4a(&ops, &|p| resolve_in(ws, p), false)?.plan);
        }
        Ok(Self::plan_edits(ws, input)?.0)
    }

    fn plan_edits(ws: &Path, input: &Value) -> Result<(crate::patchfmt::Plan, Vec<String>), String> {
        let edits = patch_edits(input).ok_or("missing array argument `edits` (or a V4A patch text in `patch`)")?;
        if edits.is_empty() {
            return Err("`edits` is empty".into());
        }
        let mut files: Vec<(PathBuf, Option<String>, String)> = Vec::new();
        let mut notes = Vec::new();
        for (i, e) in edits.iter().enumerate() {
            let (p, old, new) = match (arg_str(e, "path"), arg_str(e, "old_string"), arg_str(e, "new_string")) {
                (Ok(p), Ok(o), Ok(n)) => (resolve_in(ws, p), o, n),
                (Err(err), _, _) | (_, Err(err), _) | (_, _, Err(err)) => return Err(format!("edit #{}: {err}", i + 1)),
            };
            let idx = match files.iter().position(|f| f.0 == p) {
                Some(idx) => idx,
                // New file: old_string "" on a path that doesn't exist yet.
                None if old.is_empty() && !p.exists() => {
                    files.push((p.clone(), None, new.to_string()));
                    continue;
                }
                None => {
                    let original = read_text(&p).map_err(|err| {
                        // Seen with Haiku: old_string "placeholder" for a file that should be created.
                        let hint = if p.exists() { "" } else { "; to create a new file, set its old_string to \"\"" };
                        format!("edit #{}: {err}{hint}", i + 1)
                    })?;
                    files.push((p.clone(), Some(original.clone()), original));
                    files.len() - 1
                }
            };
            let f = &mut files[idx];
            let (out, _, n) = apply_edit(&f.2, old, new, false).map_err(|err| format!("edit #{} ({}): {err}", i + 1, display_path(ws, &p)))?;
            f.2 = out;
            notes.extend(n.into_iter().map(|x| format!("edit #{}: {x}", i + 1)));
        }
        Ok((files.into_iter().map(|(p, b, a)| (p, b, Some(a))).collect(), notes))
    }
}

fn plan_effects(ctx: &ToolCtx, paths: impl IntoIterator<Item = PathBuf>) -> Vec<Effect> {
    let mut out: Vec<Effect> = Vec::new();
    for p in paths {
        for eff in std::iter::once(Effect::Write { path: p.clone() }).chain(protected_effect(&p)) {
            if !out.contains(&eff) {
                out.push(eff);
            }
        }
    }
    let _ = ctx;
    out
}

/// Write a plan with locks, guards and file-state bookkeeping; returns lint suffixes.
fn commit_plan(ctx: &ToolCtx, plan: &crate::patchfmt::Plan) -> Result<String, String> {
    for (p, _, _) in plan {
        write_guards(ctx, p)?;
    }
    for (p, before, after) in plan {
        if let Some(a) = after {
            if let Some(why) = guidance_refusal(ctx, p, &seagent_security::guidance::added_text(before.as_deref(), a)) {
                return Err(format!("{} nothing was written: {why}", display_path(&ctx.workspace, p)));
            }
        }
    }
    let mut paths: Vec<&PathBuf> = plan.iter().map(|x| &x.0).collect();
    paths.sort();
    let _locks: Vec<st::PathLock> = paths.iter().map(|p| st::lock_path(p)).collect();
    // The plan was computed from disk moments ago; re-check nothing moved underneath.
    for (p, before, _) in plan {
        let now = if p.exists() { read_text(p).ok() } else { None };
        if now != *before {
            return Err(format!("{} changed while the patch was being prepared; nothing was written — re-read it and retry", display_path(&ctx.workspace, p)));
        }
    }
    crate::patchfmt::commit(plan).map_err(|e| e.replace("cannot write", "patch failed, rolled back: cannot write"))?;
    let mut tail = String::new();
    for (p, before, after) in plan {
        match after {
            Some(a) => {
                st::note_edited(&ctx.session_id, p, before.is_none());
                tail.push_str(&lint_after(p, before.as_deref(), a));
                tail.push_str(&guidance_after(ctx, p, &seagent_security::guidance::added_text(before.as_deref(), a)));
                tail.push_str(&crate::lsp::after_write(&ctx.workspace, p, before.as_deref(), a));
            }
            None => st::note_edited(&ctx.session_id, p, true),
        }
    }
    Ok(tail)
}

impl Tool for Patch {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "patch".into(),
            description: "Apply several edits across one or more files atomically: either every edit applies or none does. Give `edits` (list of {path, old_string, new_string}; old_string \"\" on a path that does not exist creates it) or `patch`: a V4A patch text (*** Begin Patch / *** Update File: p / @@ hint @@ / ' ctx' '-old' '+new' / *** Add File: p / *** Delete File: p / *** Move File: a -> b / *** End Patch). Matching tolerates whitespace/indentation drift.".into(),
            input_schema: json!({"type":"object","properties":{
                "edits":{"type":"array","items":{
                    "type":"object","properties":{"path":{"type":"string"},"old_string":{"type":"string"},"new_string":{"type":"string"}},
                    "required":["path","old_string","new_string"]}},
                "patch":{"type":"string","description":"V4A patch text (alternative to edits)"}}}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        if let Some(text) = v4a_text(input) {
            return plan_effects(ctx, crate::patchfmt::target_paths(text).iter().map(|p| ctx.resolve(p)));
        }
        plan_effects(ctx, patch_edits(input).into_iter().flatten().filter_map(|e| arg_str(&e, "path").ok().map(|p| ctx.resolve(p))))
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        if let Some(text) = v4a_text(&input) {
            let applied = match crate::patchfmt::parse_v4a(text).and_then(|ops| {
                if ops.is_empty() {
                    Err("the patch text contains no operations".to_string())
                } else {
                    crate::patchfmt::apply_v4a(&ops, &|p| ctx.resolve(p), false)
                }
            }) {
                Ok(a) => a,
                Err(e) => return ToolOutput::err(format!("patch rejected, no files changed: {e}")),
            };
            let tail = match commit_plan(ctx, &applied.plan) {
                Ok(t) => t,
                Err(e) => return ToolOutput::err(e),
            };
            let mut msg = String::from("patched:");
            for (k, v) in [("created", &applied.created), ("modified", &applied.modified), ("deleted", &applied.deleted)] {
                if !v.is_empty() {
                    msg.push_str(&format!(" {k} {}", v.join(", ")));
                }
            }
            msg.push_str(&notes_suffix(&applied.notes));
            msg.push('\n');
            msg.push_str(truncate_str(&applied.diff, 8000));
            msg.push_str(&tail);
            return ToolOutput::ok(msg);
        }
        let (plan, notes) = match Self::plan_edits(&ctx.workspace, &input) {
            Ok(f) => f,
            Err(e) => return ToolOutput::err(format!("patch rejected, no files changed: {e}")),
        };
        let tail = match commit_plan(ctx, &plan) {
            Ok(t) => t,
            Err(e) => return ToolOutput::err(e),
        };
        let names: Vec<_> = plan.iter().map(|f| display_path(&ctx.workspace, &f.0)).collect();
        ToolOutput::ok(format!("patched {} file(s): {}{}{tail}", plan.len(), names.join(", "), notes_suffix(&notes)))
    }
}

/// OpenClaw/Codex `apply_patch`: `*** Begin Patch` envelopes, workspace-contained by default.
pub struct ApplyPatch;

const CONTAINMENT_HINT: &str = "apply_patch is workspace-contained by configuration (files.apply_patch_workspace_only, default true; files.workspace_only imposes the same independently). Keep patch paths within the workspace, or use the patch/edit tools, which the gates judge per path.";

impl ApplyPatch {
    fn resolver(ctx: &ToolCtx) -> impl Fn(&str) -> Result<(PathBuf, String), String> + '_ {
        let c = st::cfg();
        move |raw: &str| {
            let raw = raw.trim();
            if raw.is_empty() {
                return Err("Invalid patch: empty file path".into());
            }
            // Literal-@ file references ("@src/x.rs") mean the path itself unless such a file exists.
            let lit = ctx.resolve(raw);
            let p = match raw.strip_prefix('@') {
                Some(r) if !lit.exists() => ctx.resolve(r),
                _ => lit,
            };
            let p = st::normalize(&p);
            if c.apply_patch_workspace_only || c.workspace_only {
                st::contain(&ctx.workspace, &p).map_err(|e| format!("{e}\n{CONTAINMENT_HINT}"))?;
            }
            Ok((p.clone(), display_path(&ctx.workspace, &p)))
        }
    }
}

impl Tool for ApplyPatch {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "apply_patch".into(),
            description: "Patch one/many files. Input requires *** Begin Patch and *** End Patch. Hunks: '*** Add File: path' + '+' lines; '*** Delete File: path'; '*** Update File: path' (optional '*** Move to: new') + chunks starting with '@@' or '@@ <context line>', lines prefixed ' ', '-', '+', optional '*** End of File'.".into(),
            input_schema: json!({"type":"object","properties":{
                "input":{"type":"string","description":"Patch content using the *** Begin Patch/End Patch format."}},"required":["input"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let mut input = input.clone();
        crate::util::alias(&mut input, "input", &["patch", "text", "diff"]);
        let text = arg_opt_str(&input, "input").unwrap_or("");
        plan_effects(ctx, crate::patchfmt::target_paths(text).iter().map(|p| ctx.resolve(p.strip_prefix('@').filter(|_| !ctx.resolve(p).exists()).unwrap_or(p))))
    }
    fn call(&self, ctx: &ToolCtx, mut input: Value) -> ToolOutput {
        crate::util::alias(&mut input, "input", &["patch", "text", "diff"]);
        let text = arg_opt_str(&input, "input").unwrap_or("");
        if text.trim().is_empty() {
            return ToolOutput::err("Provide a patch input.");
        }
        let res = crate::patchfmt::parse_apply_patch(text).and_then(|h| crate::patchfmt::plan_apply_patch(&h, &Self::resolver(ctx)));
        let (plan, summary) = match res {
            Ok(r) => r,
            Err(e) => return ToolOutput::err(e),
        };
        match commit_plan(ctx, &plan) {
            Ok(tail) => ToolOutput::ok(format!("{summary}{tail}")),
            Err(e) => ToolOutput::err(e),
        }
    }
}

#[cfg(test)]
mod preview_tests {
    use super::*;

    #[test]
    fn previews_edits_without_writing() {
        let d = seagent_core::tmp::scratch_path(format!("seagent-preview-{}", std::process::id()));
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
        let p = preview(&d, "patch", &json!({"patch": "*** Begin Patch\n*** Update File: a.txt\n-one two one\n+uno\n*** End Patch"})).unwrap();
        assert_eq!(p[0].2, "uno");
        let p = preview(&d, "apply_patch", &json!({"input": "*** Begin Patch\n*** Delete File: a.txt\n*** End Patch"})).unwrap();
        assert_eq!((p[0].1.as_deref(), p[0].2.as_str()), (Some("one two one"), ""));
        assert_eq!(fs::read_to_string(d.join("a.txt")).unwrap(), "one two one", "nothing written");
        let _ = fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ctx;
    use std::os::unix::fs::PermissionsExt;

    /// Read a file in full so this session may overwrite it.
    fn seen(c: &ToolCtx, p: &str) {
        let o = Read.call(c, json!({"path": p, "fresh": true}));
        assert!(!o.is_error, "{}", o.content);
    }

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
    fn read_guards_suggestions_dedup_and_loops() {
        let c = ctx("readg");
        fs::write(c.workspace.join("config.yaml"), "a: 1\n").unwrap();
        let o = Read.call(&c, json!({"path":"config.yml"}));
        assert!(o.is_error && o.content.contains("Similar files: config.yaml"), "{}", o.content);
        assert!(Read.call(&c, json!({"path":"/dev/zero"})).content.contains("device file"));
        fs::write(c.workspace.join(".env"), "KEY=v").unwrap();
        assert!(Read.call(&c, json!({"path":".env"})).content.contains("secret-bearing"));
        fs::write(c.workspace.join("song.mp3"), "ID3").unwrap();
        assert!(Read.call(&c, json!({"path":"song.mp3"})).content.contains("binary file"));
        // Identical re-read: stub, then block; `fresh` bypasses; a change resets.
        let first = Read.call(&c, json!({"path":"config.yaml"}));
        assert!(first.content.contains("a: 1"));
        assert_eq!(Read.call(&c, json!({"path":"config.yaml"})).content, st::DEDUP_STATUS);
        assert!(Read.call(&c, json!({"path":"config.yaml"})).content.starts_with("BLOCKED"));
        assert!(Read.call(&c, json!({"path":"config.yaml","fresh":true})).content.contains("a: 1"));
        let o = Read.call(&c, json!({"path":"config.yaml","fresh":true}));
        assert!(o.content.contains("3 times consecutively"), "{}", o.content);
        assert!(Read.call(&c, json!({"path":"config.yaml","fresh":true})).content.contains("BLOCKED"));
        fs::write(c.workspace.join("c.txt"), "<<<<<<< HEAD\na\n=======\nb\n>>>>>>> x\n").unwrap();
        assert!(Read.call(&c, json!({"path":"c.txt"})).content.contains("merge-conflict"));
    }

    #[test]
    fn read_char_budget_and_documents_and_images() {
        let c = ctx("readb");
        let long: String = (0..30_000).map(|i| format!("line {i}\n")).collect();
        fs::write(c.workspace.join("big.txt"), &long).unwrap();
        let o = Read.call(&c, json!({"path":"big.txt","limit":30000}));
        assert!(o.content.contains("read budget") && o.content.contains("Use offset="), "{}", &o.content[o.content.len() - 300..]);
        let nb = json!({"cells":[{"cell_type":"code","source":"x = 1","outputs":[]}]});
        fs::write(c.workspace.join("n.ipynb"), nb.to_string()).unwrap();
        let o = Read.call(&c, json!({"path":"n.ipynb"}));
        assert!(o.content.contains("# ── Code cell 1 ──") && o.content.contains("x = 1"), "{}", o.content);
        fs::write(c.workspace.join("bad.docx"), "nope").unwrap();
        assert!(Read.call(&c, json!({"path":"bad.docx"})).content.contains("document extraction failed"));
        fs::write(c.workspace.join("p.png"), b"\x89PNG\r\n\x1a\n0000").unwrap();
        let o = Read.call(&c, json!({"path":"p.png"}));
        assert!(!o.is_error && o.content.contains("image/png"), "{}", o.content);
        let (text, imgs) = seagent_core::tool::take_images(&o.content);
        assert_eq!(imgs.len(), 1);
        assert!(!text.contains("[[seagent:image"));
    }

    #[test]
    fn write_creates_dirs_and_reports_effects() {
        let c = ctx("write");
        let o = Write.call(&c, json!({"path":"d/e/f.txt","content":"hi"}));
        assert!(!o.is_error, "{}", o.content);
        assert_eq!(fs::read_to_string(c.workspace.join("d/e/f.txt")).unwrap(), "hi");
        assert_eq!(Write.effects(&c, &json!({"path":"d/e/f.txt"})), vec![Effect::Write { path: c.workspace.join("d/e/f.txt") }]);
        let o = Write.call(&c, json!({"path":"d/e/f.txt","content":"bye"}));
        assert!(o.content.starts_with("overwrote"), "own write is a full-content baseline: {}", o.content);
    }

    #[test]
    fn write_emits_security_guidance_once_per_file() {
        let c = ctx("guidance");
        // Hermes `plugins/security-guidance`: the write goes through, a warning rides back.
        let o = Write.call(&c, json!({"path":"g.py","content":"import os\nos.system(cmd)\n"}));
        assert!(!o.is_error, "{}", o.content);
        assert_eq!(o.content.matches("⚠️ Security guidance").count(), 1, "{}", o.content);
        assert!(o.content.contains("1 pattern matched (os_system_injection)"), "{}", o.content);
        assert_eq!(fs::read_to_string(c.workspace.join("g.py")).unwrap(), "import os\nos.system(cmd)\n", "not a blocker");
        // Same file, same session: already told, so the second write stays quiet.
        let o = Write.call(&c, json!({"path":"g.py","content":"import os\nos.system(cmd)\n# same\n"}));
        assert!(!o.is_error && !o.content.contains("Security guidance"), "{}", o.content);
        // Another file warns again; clean content never does.
        let o = Edit.call(&c, json!({"path":"h.js","old_string":"","new_string":"el.innerHTML = x;"}));
        assert!(!o.is_error && o.content.contains("innerHTML_xss"), "{}", o.content);
        let o = Write.call(&c, json!({"path":"clean.py","content":"x = 1\n"}));
        assert!(!o.content.contains("Security guidance"), "{}", o.content);
        // Patches scan what they add: a new dangerous line warns, a removal does not.
        let o = Patch.call(&c, json!({"edits":[{"path":"clean.py","old_string":"x = 1","new_string":"x = 1\nresult = eval(raw)"}]}));
        assert!(!o.is_error && o.content.contains("eval_injection"), "{}", o.content);
        let o = Patch.call(&c, json!({"edits":[{"path":"clean.py","old_string":"result = eval(raw)","new_string":"result = parse(raw)"}]}));
        assert!(!o.is_error && !o.content.contains("Security guidance"), "{}", o.content);
        // files.security_guidance = false silences the whole thing.
        st::configure_files(&json!({"security_guidance": false}));
        let off = Write.call(&c, json!({"path":"off.py","content":"eval(x)\n"}));
        st::configure_files(&json!({}));
        assert!(!off.is_error && !off.content.contains("Security guidance"), "{}", off.content);
        // SECURITY_GUIDANCE_BLOCK=1 refuses the write instead (env switch, as upstream).
        std::env::set_var("SECURITY_GUIDANCE_BLOCK", "1");
        let blocked = Write.call(&c, json!({"path":"blocked.py","content":"eval(x)\n"}));
        std::env::remove_var("SECURITY_GUIDANCE_BLOCK");
        assert!(blocked.is_error && blocked.content.contains("security-guidance refused this write"), "{}", blocked.content);
        assert!(!c.workspace.join("blocked.py").exists(), "blocked write left nothing behind");
    }

    #[test]
    fn write_guards_stale_and_lint() {
        let c = ctx("writeg");
        let f = c.workspace.join("x.txt");
        fs::write(&f, "on disk").unwrap();
        let o = Write.call(&c, json!({"path":"x.txt","content":"new"}));
        assert!(o.is_error && o.content.contains("has not seen its full current content"), "{}", o.content);
        seen(&c, "x.txt");
        assert!(!Write.call(&c, json!({"path":"x.txt","content":"new"})).is_error);
        std::thread::sleep(std::time::Duration::from_millis(10));
        fs::write(&f, "external change").unwrap();
        assert!(Write.call(&c, json!({"path":"x.txt","content":"mine"})).content.contains("modified since you last read it"));
        assert!(Write.call(&c, json!({"path":"/etc/seagent-test","content":"x"})).content.contains("sensitive system path"));
        assert!(Write.call(&c, json!({"path":"r.docx","content":"x"})).content.contains("binary document"));
        assert!(Write.call(&c, json!({"path":"y.txt","content":"     1\tfoo\n     2\tbar"})).content.contains("line-number"));
        assert!(Write.call(&c, json!({"path":"c.json","content":"{oops"})).content.contains("does not parse as .json"));
        assert!(!Write.call(&c, json!({"path":"c.json","content":"{\"ok\":1}"})).is_error);
        assert!(Write.effects(&c, &json!({"path":"AGENTS.md","content":"x"})).iter().any(|e| matches!(e, Effect::Remote { reason, .. } if reason.contains("agent-instruction"))));
        if lint::check_content(Path::new("a.py"), "x=1") == lint::Lint::Ok {
            let o = Write.call(&c, json!({"path":"s.py","content":"def f(:\n"}));
            assert!(!o.is_error && o.content.contains("lint failed"), "py is report-only: {}", o.content);
        }
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
        assert!(o.is_error && o.content.contains("Found 2 matches"), "{}", o.content);
        let o = Edit.call(&c, json!({"path":"f.rs","old_string":"zzz","new_string":"y"}));
        assert!(o.is_error && o.content.contains("Could not find a match"));
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
    fn edit_fuzzy_and_hints() {
        let c = ctx("editz");
        fs::write(c.workspace.join("g.py"), "def f():\n    if x:\n        return 1\n").unwrap();
        let o = Edit.call(&c, json!({"path":"g.py","old_string":"if x:\n    return 1","new_string":"if x:\n    return 2"}));
        assert!(!o.is_error && o.content.contains("line_trimmed"), "{}", o.content);
        assert_eq!(fs::read_to_string(c.workspace.join("g.py")).unwrap(), "def f():\n    if x:\n        return 2\n");
        let o = Edit.call(&c, json!({"path":"g.py","old_string":"\tif x:","new_string":"if y:"}));
        assert!(!o.is_error, "{}", o.content);
        let o = Edit.call(&c, json!({"path":"g.py","old_string":"if xx_value:","new_string":"if z:"}));
        assert!(o.is_error && o.content.contains("Did you mean"), "{}", o.content);
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
    fn patch_v4a_text() {
        let c = ctx("patch4");
        fs::write(c.workspace.join("a.py"), "def f():\n    return 1\n").unwrap();
        let text = "*** Begin Patch\n*** Update File: a.py\n@@ def f @@\n def f():\n-    return 1\n+    return 2\n*** Add File: b.txt\n+hi\n*** End Patch";
        assert_eq!(Patch.effects(&c, &json!({"patch": text})), vec![Effect::Write { path: c.workspace.join("a.py") }, Effect::Write { path: c.workspace.join("b.txt") }]);
        let o = Patch.call(&c, json!({"patch": text}));
        assert!(!o.is_error && o.content.contains("+    return 2"), "{}", o.content);
        assert_eq!(fs::read_to_string(c.workspace.join("b.txt")).unwrap(), "hi");
        let o = Patch.call(&c, json!({"patch": "*** Begin Patch\n*** Update File: a.py\n-nope\n+x\n*** End Patch"}));
        assert!(o.is_error && o.content.contains("no files were modified"), "{}", o.content);
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

    #[test]
    fn apply_patch_tool_and_containment() {
        let c = ctx("applyp");
        fs::write(c.workspace.join("m.txt"), "a\nb\nc\n").unwrap();
        let text = "*** Begin Patch\n*** Update File: m.txt\n@@ a\n-b\n+B\n*** Add File: d/n.txt\n+new\n*** End Patch";
        assert_eq!(ApplyPatch.effects(&c, &json!({"input": text})).len(), 2);
        let o = ApplyPatch.call(&c, json!({"input": text}));
        assert_eq!(o.content, "Success. Updated the following files:\nA d/n.txt\nM m.txt");
        assert_eq!(fs::read_to_string(c.workspace.join("m.txt")).unwrap(), "a\nB\nc\n");
        let o = ApplyPatch.call(&c, json!({"input": "*** Begin Patch\n*** Add File: ../escape.txt\n+x\n*** End Patch"}));
        assert!(o.is_error && o.content.contains("escapes workspace root") && o.content.contains("workspace-contained"), "{}", o.content);
        assert!(ApplyPatch.call(&c, json!({"input": " "})).content.contains("Provide a patch input"));
        let o = ApplyPatch.call(&c, json!({"patch": "*** Begin Patch\n*** Update File: m.txt\n@@\n-zzz\n+y\n*** End Patch"}));
        assert!(o.is_error && o.content.contains("Failed to find expected lines"), "{}", o.content);
    }

    /// Row 6 (OpenClaw `src/agents/agent-tools.read.ts`): a PDF is converted to text the model
    /// can read, pictures are handed over as image blocks (never as base64-as-text), and an
    /// image over the attachment cap is refused with a downscale hint.
    #[test]
    fn read_converts_pdfs_to_text_and_images_to_blocks() {
        let c = ctx("readdocs");
        let pdf = b"%PDF-1.4\n1 0 obj\n<< /Length 60 >>\nstream\nBT /F1 12 Tf 72 700 Td (Quarterly report) Tj ET\nendstream\nendobj\n%%EOF".to_vec();
        fs::write(c.workspace.join("report.pdf"), &pdf).unwrap();
        let o = Read.call(&c, json!({"path":"report.pdf"}));
        assert!(!o.is_error, "{}", o.content);
        assert!(o.content.contains("Quarterly report"), "{}", o.content);
        assert!(o.content.contains("[extracted document text — not the file's bytes"), "{}", o.content);
        fs::write(c.workspace.join("shot.png"), b"\x89PNG\r\n\x1a\n0000").unwrap();
        let o = Read.call(&c, json!({"path":"shot.png"}));
        assert!(!o.is_error && o.content.contains("Read image file [image/png"), "{}", o.content);
        let (text, imgs) = seagent_core::tool::take_images(&o.content);
        assert_eq!(imgs.len(), 1, "one picture block for the model");
        assert!(text.contains("shot.png") && !text.contains("iVBOR"), "the bytes are not inlined as text: {text}");
        fs::write(c.workspace.join("cam.jpg"), [b"\xff\xd8\xff\xe0".as_slice(), &[0u8; 32]].concat()).unwrap();
        assert!(Read.call(&c, json!({"path":"cam.jpg"})).content.contains("image/jpeg"));
        fs::write(c.workspace.join("huge.png"), [b"\x89PNG\r\n\x1a\n".as_slice(), &vec![0u8; 5 * 1024 * 1024]].concat()).unwrap();
        let o = Read.call(&c, json!({"path":"huge.png"}));
        assert!(o.is_error && o.content.contains("Downscale"), "{}", o.content);
    }
}
