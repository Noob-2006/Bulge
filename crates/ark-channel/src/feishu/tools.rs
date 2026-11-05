//! Feishu / Lark agent tools (OpenClaw `extensions/feishu/src/{docx,wiki,drive,perm,chat,
//! bitable}.ts` and Hermes `tools/feishu_doc_tool.py`, both MIT).
//!
//! - `feishu_doc_read` (Hermes): a document's plain text.
//! - `feishu_doc`: read / write / append / insert (Markdown through `blocks/convert`, then
//!   `descendant` inserts in ≤1000-block batches, Markdown images uploaded into the new
//!   image blocks), create (edit permission granted to the trusted requester when known),
//!   list/get/update/delete blocks, tables (create, fill, row/column insert/delete, merge),
//!   upload_image / upload_file, color_text (`[red]…[/red]`, `[bg:yellow]`, `[bold]`).
//! - `feishu_app_scopes`, `feishu_wiki`, `feishu_drive` (incl. document comments),
//!   `feishu_perm` (off by default: it changes sharing), `feishu_chat`, and the eight
//!   `feishu_bitable_*` tools.
//!
//! Families are toggled by the channel's `tools = { doc = true, perm = false, … }` (upstream
//! defaults). A channel not named `feishu`/`lark` suffixes the names (`feishu_doc_<id>`).
//! Message actions for the `message` tool (`read`, `edit`, `pin`, `unpin`, `list-pins`,
//! `channel-info`, `member-info`) are in [`message_action`].

use super::{fs_result, has_code, Feishu, TOKEN_CODES};
use crate::http::{Http, Payload};
use crate::{ChannelError, ChannelErrorKind as K};
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const BATCH_SIZE: usize = 1000;
const MAX_CONVERT_RETRY_DEPTH: u32 = 8;
const WIKI_PAGE_SIZE: u64 = 50;
const WIKI_ACCESS_HINT: &str = "To grant wiki access: Open wiki space → Settings → Members → Add the bot. See: https://open.feishu.cn/document/server-docs/docs/wiki-v2/wiki-qa#a40ad4ca";
const UNSUPPORTED_CREATE_TYPES: [u64; 2] = [31, 32];
const STRUCTURED_BLOCK_TYPES: [u64; 8] = [14, 18, 21, 23, 27, 30, 31, 32];

/// Upstream `DEFAULT_TOOLS_CONFIG`: permission tools default off.
pub(super) fn families(cfg: &BTreeMap<String, bool>) -> HashSet<&'static str> {
    [("doc", true), ("chat", true), ("wiki", true), ("drive", true), ("perm", false), ("scopes", true), ("bitable", true)].into_iter().filter(|(k, d)| cfg.get(*k).copied().unwrap_or(*d)).map(|(k, _)| k).collect()
}

/// The open-platform client the tools share (own token cache, one refresh on token errors).
pub(super) struct Api {
    id: String,
    base: String,
    app_id: String,
    app_secret: String,
    http: Http,
    token: Mutex<Option<(String, Instant)>>,
    media_max: u64,
    /// The trusted requester's open_id for a session (host-installed route lookup).
    origin: Arc<Mutex<Option<crate::whatsapp::SessionOrigin>>>,
}

impl Api {
    fn tenant_token(&self) -> Result<String, ChannelError> {
        if let Some((t, until)) = self.token.lock().unwrap().clone() {
            if Instant::now() < until {
                return Ok(t);
            }
        }
        let body = json!({"app_id": self.app_id, "app_secret": self.app_secret});
        let r = self.http.call("POST", &format!("{}/open-apis/auth/v3/tenant_access_token/internal", self.base), &[], Payload::Json(&body))?;
        let v = fs_result("tenant_access_token", r.status, r.retry_after, &r.body)?;
        let t = v["tenant_access_token"].as_str().filter(|t| !t.is_empty()).ok_or_else(|| ChannelError::new(K::Protocol, "tenant_access_token missing in response"))?.to_string();
        let ttl = v["expire"].as_u64().unwrap_or(7200).saturating_sub(300).max(60);
        *self.token.lock().unwrap() = Some((t.clone(), Instant::now() + Duration::from_secs(ttl)));
        Ok(t)
    }

    fn call(&self, method: &str, path: &str, body: Payload) -> Result<Value, String> {
        let url = format!("{}/open-apis{path}", self.base);
        let what = format!("{method} {}", path.split('?').next().unwrap_or(path));
        let mut refreshed = false;
        loop {
            let tok = self.tenant_token().map_err(|e| e.message)?;
            let auth = format!("Bearer {tok}");
            match self.http.call(method, &url, &[("authorization", &auth)], body).and_then(|r| fs_result(&what, r.status, r.retry_after, &r.body)) {
                Ok(v) => return Ok(v),
                Err(e) if !refreshed && has_code(&e, &TOKEN_CODES) => {
                    refreshed = true;
                    *self.token.lock().unwrap() = None;
                }
                Err(e) => return Err(e.message),
            }
        }
    }
    fn get(&self, path: &str) -> Result<Value, String> {
        self.call("GET", path, Payload::None)
    }
    fn send(&self, method: &str, path: &str, body: &Value) -> Result<Value, String> {
        self.call(method, path, Payload::Json(body))
    }

    fn requester(&self, ctx: &ToolCtx) -> Option<String> {
        let route = self.origin.lock().unwrap().as_ref().and_then(|f| f(&ctx.session_id))?;
        (route.channel == self.id).then(|| route.sender.unwrap_or(route.chat)).filter(|s| s.starts_with("ou_"))
    }
}

fn enc(s: &str) -> String {
    ark_net::urlencode(s)
}

fn q(pairs: &[(&str, Option<String>)]) -> String {
    let parts: Vec<String> = pairs.iter().filter_map(|(k, v)| v.as_ref().filter(|v| !v.is_empty()).map(|v| format!("{k}={}", enc(v)))).collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!("?{}", parts.join("&"))
    }
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).map(str::trim).unwrap_or("")
}

fn req<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    Some(s(v, k)).filter(|x| !x.is_empty()).ok_or_else(|| format!("{k} is required"))
}

fn opt(v: &Value, k: &str) -> Option<String> {
    Some(s(v, k).to_string()).filter(|x| !x.is_empty())
}

fn num(v: &Value, k: &str) -> Option<i64> {
    v.get(k).and_then(|x| x.as_i64().or_else(|| x.as_f64().map(|f| f as i64)))
}

/// Upstream `readPositiveIntegerParam`.
fn page_size(v: &Value, max: u64, msg: &str) -> Result<Option<u64>, String> {
    match v.get("page_size") {
        None | Some(Value::Null) => Ok(None),
        Some(x) => match x.as_u64() {
            Some(n) if (1..=max).contains(&n) => Ok(Some(n)),
            _ => Err(msg.into()),
        },
    }
}

// ───────────── tool plumbing ─────────────

type Exec = fn(&Api, &ToolCtx, &Value) -> Result<Value, String>;

struct FsTool {
    name: String,
    description: &'static str,
    schema: Value,
    exec: Exec,
    writes: fn(&Value) -> bool,
    api: Arc<Api>,
}

impl Tool for FsTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec { name: self.name.clone(), description: self.description.into(), input_schema: self.schema.clone(), parallel_safe: false, idempotent: false, pinned: false }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let mut v = Vec::new();
        if (self.writes)(input) {
            v.push(Effect::Net { dest: format!("{} ({})", self.api.base, self.api.id), payload: format!("{} {}", self.name, input.get("action").and_then(Value::as_str).unwrap_or("")) });
        }
        if let Some(p) = input.get("file_path").and_then(Value::as_str).filter(|p| !p.is_empty()) {
            v.push(Effect::Read { path: ctx.resolve(p) });
        }
        v
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        match (self.exec)(&self.api, ctx, &input) {
            Ok(v) if v.get("error").is_some() && v.as_object().map(|o| o.len()) == Some(1) => ToolOutput::err(v.to_string()),
            Ok(v) => ToolOutput::ok(serde_json::to_string_pretty(&v).unwrap_or_default()),
            Err(e) => ToolOutput::err(json!({"error": e}).to_string()),
        }
    }
}

fn action_of(v: &Value) -> &str {
    v.get("action").and_then(Value::as_str).unwrap_or("")
}

fn never(_: &Value) -> bool {
    false
}
fn always(_: &Value) -> bool {
    true
}

pub(super) fn tools(f: &Feishu, cfg: &BTreeMap<String, bool>, media_max_mb: u64, origin: Arc<Mutex<Option<crate::whatsapp::SessionOrigin>>>) -> Vec<Arc<dyn Tool>> {
    let api = Arc::new(Api {
        id: f.id.clone(),
        base: f.base.clone(),
        app_id: f.app_id.clone(),
        app_secret: f.app_secret.clone(),
        http: Http::new(Duration::from_secs(60)),
        token: Mutex::new(None),
        media_max: media_max_mb.max(1) * 1024 * 1024,
        origin,
    });
    let safe: String = f.id.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' }).collect();
    let plain = matches!(safe.as_str(), "feishu" | "lark");
    let fam = families(cfg);
    let mut out: Vec<Arc<dyn Tool>> = Vec::new();
    let mut add = |family: &str, name: &str, description: &'static str, schema: Value, exec: Exec, writes: fn(&Value) -> bool| {
        if fam.contains(family) {
            let name = if plain { name.to_string() } else { format!("{name}_{safe}") };
            out.push(Arc::new(FsTool { name, description, schema, exec, writes, api: api.clone() }));
        }
    };
    add("doc", "feishu_doc_read", "Read the full content of a Feishu/Lark document as plain text. Useful when you need more context beyond the quoted text in a comment.", json!({"type": "object", "properties": {"doc_token": {"type": "string", "description": "The document token (from the document URL or comment context)."}}, "required": ["doc_token"]}), doc_read_plain, never);
    add("doc", "feishu_doc", "Feishu document operations. Actions: read, write, append, insert, create, list_blocks, get_block, update_block, delete_block, create_table, write_table_cells, create_table_with_values, insert_table_row, insert_table_column, delete_table_rows, delete_table_columns, merge_table_cells, upload_image, upload_file, color_text", doc_schema(), doc, |v| !matches!(action_of(v), "read" | "list_blocks" | "get_block"));
    add("scopes", "feishu_app_scopes", "List current app permissions (scopes). Use to debug permission issues or check available capabilities.", json!({"type": "object", "properties": {}}), app_scopes, never);
    add("wiki", "feishu_wiki", "Feishu knowledge base operations. Actions: spaces, nodes, get, create, move, rename", wiki_schema(), wiki, |v| matches!(action_of(v), "create" | "move" | "rename"));
    add("drive", "feishu_drive", "Feishu cloud storage operations. Actions: list, info, create_folder, move, delete, list_comments, list_comment_replies, add_comment, reply_comment", drive_schema(), drive, |v| matches!(action_of(v), "create_folder" | "move" | "delete" | "add_comment" | "reply_comment"));
    add("perm", "feishu_perm", "Feishu permission management. Actions: list, add, remove", perm_schema(), perm, |v| action_of(v) != "list");
    add("chat", "feishu_chat", "Feishu chat operations. Actions: members, info, member_info", chat_schema(), chat, never);
    for (name, description, schema, exec, writes) in bitable_tools() {
        add("bitable", name, description, schema, exec, writes);
    }
    out
}

// ───────────── doc ─────────────

fn doc_read_plain(api: &Api, _: &ToolCtx, a: &Value) -> Result<Value, String> {
    let token = req(a, "doc_token")?;
    let v = api.get(&format!("/docx/v1/documents/{}/raw_content", enc(token))).map_err(|e| hermes_read_error(&e))?;
    if v.get("data").is_none_or(Value::is_null) {
        return Err("No content returned from document API".into());
    }
    Ok(json!({"success": true, "content": v["data"]["content"].as_str().unwrap_or("")}))
}

/// Hermes `feishu_doc_read` reports `code=… msg=…`; the shared envelope formats
/// `what: code=… msg`, so re-space it for that tool's users.
fn hermes_read_error(e: &str) -> String {
    match e.split_once(": code=") {
        Some((_, rest)) => match rest.split_once(' ') {
            Some((code, msg)) => format!("Failed to read document: code={code} msg={}", if msg.trim().is_empty() { "unknown error" } else { msg.trim() }),
            None => format!("Failed to read document: code={rest} msg=unknown error"),
        },
        None => format!("Failed to read document: {e}"),
    }
}

fn doc_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["read", "write", "append", "insert", "create", "list_blocks", "get_block", "update_block", "delete_block", "create_table", "write_table_cells", "create_table_with_values", "insert_table_row", "insert_table_column", "delete_table_rows", "delete_table_columns", "merge_table_cells", "upload_image", "upload_file", "color_text"]},
            "doc_token": {"type": "string", "description": "Document token (extract from URL /docx/XXX)"},
            "content": {"type": "string", "description": "Markdown for write/append/insert (write replaces the whole document); new text for update_block; color markup for color_text ([red], [green], [blue], [orange], [yellow], [purple], [grey], [bold], [bg:yellow])"},
            "after_block_id": {"type": "string", "description": "insert: insert content after this block ID. Use list_blocks to find block IDs."},
            "title": {"type": "string", "description": "create: document title"},
            "folder_token": {"type": "string", "description": "create: target folder token (optional)"},
            "grant_to_requester": {"type": "boolean", "description": "create: grant edit permission to the trusted requesting Feishu user (default: true)"},
            "block_id": {"type": "string", "description": "Block ID (from list_blocks); the table block for table row/column/merge actions"},
            "parent_block_id": {"type": "string", "description": "Parent block ID (default: document root)"},
            "table_block_id": {"type": "string", "description": "write_table_cells: table block ID"},
            "row_size": {"type": "integer", "minimum": 1},
            "column_size": {"type": "integer", "minimum": 1},
            "column_width": {"type": "array", "items": {"type": "number", "minimum": 1}, "description": "Column widths in px (length should match column_size)"},
            "values": {"type": "array", "items": {"type": "array", "items": {"type": "string"}}, "description": "2D matrix values[row][col] to write into table cells"},
            "row_index": {"type": "number", "description": "Row index to insert at (-1 for end, default: -1)"},
            "column_index": {"type": "number", "description": "Column index to insert at (-1 for end, default: -1)"},
            "row_start": {"type": "number"}, "row_count": {"type": "number"}, "row_end": {"type": "number", "description": "exclusive"},
            "column_start": {"type": "number"}, "column_count": {"type": "number"}, "column_end": {"type": "number", "description": "exclusive"},
            "url": {"type": "string", "description": "Remote image/file URL (http/https)"},
            "file_path": {"type": "string", "description": "Local file path"},
            "image": {"type": "string", "description": "Image as data URI (data:image/png;base64,...) or plain base64 string"},
            "filename": {"type": "string", "description": "Optional filename override"},
            "index": {"type": "integer", "minimum": 0, "description": "upload_image: insert position among siblings (omit to append)"}
        },
        "required": ["action"]
    })
}

fn block_type_name(t: u64) -> String {
    match t {
        1 => "Page", 2 => "Text", 3 => "Heading1", 4 => "Heading2", 5 => "Heading3", 12 => "Bullet", 13 => "Ordered", 14 => "Code", 15 => "Quote", 17 => "Todo", 18 => "Bitable", 21 => "Diagram", 22 => "Divider", 23 => "File", 27 => "Image", 30 => "Sheet", 31 => "Table", 32 => "TableCell",
        _ => return format!("type_{t}"),
    }
    .into()
}

/// Every block of a document (paged, 500 per request).
fn list_blocks(api: &Api, doc: &str) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    let mut token: Option<String> = None;
    let mut seen = HashSet::new();
    loop {
        let v = api.get(&format!("/docx/v1/documents/{}/blocks{}", enc(doc), q(&[("page_size", Some("500".into())), ("page_token", token.clone())])))?;
        out.extend(v["data"]["items"].as_array().cloned().unwrap_or_default());
        if v["data"]["has_more"].as_bool() != Some(true) {
            return Ok(out);
        }
        let next = s(&v["data"], "page_token").to_string();
        if next.is_empty() || !seen.insert(next.clone()) {
            return Err(format!("Feishu document block pagination did not advance for {doc}"));
        }
        token = Some(next);
    }
}

fn children_of(api: &Api, doc: &str, parent: &str) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    let mut token: Option<String> = None;
    let mut seen = HashSet::new();
    loop {
        let v = api.get(&format!("/docx/v1/documents/{}/blocks/{}/children{}", enc(doc), enc(parent), q(&[("page_token", token.clone())])))?;
        out.extend(v["data"]["items"].as_array().cloned().unwrap_or_default());
        if v["data"]["has_more"].as_bool() != Some(true) {
            return Ok(out);
        }
        let next = s(&v["data"], "page_token").to_string();
        if next.is_empty() {
            return Err(format!("Feishu document children pagination is missing its next page token for parent block \"{parent}\""));
        }
        if !seen.insert(next.clone()) {
            return Err(format!("Feishu document children pagination repeated token for parent block \"{parent}\""));
        }
        token = Some(next);
    }
}

fn get_block(api: &Api, doc: &str, block: &str) -> Result<Value, String> {
    Ok(api.get(&format!("/docx/v1/documents/{}/blocks/{}", enc(doc), enc(block)))?["data"]["block"].clone())
}

fn delete_children(api: &Api, doc: &str, parent: &str, start: usize, end: usize) -> Result<(), String> {
    api.send("DELETE", &format!("/docx/v1/documents/{}/blocks/{}/children/batch_delete", enc(doc), enc(parent)), &json!({"start_index": start, "end_index": end})).map(|_| ())
}

fn read_doc(api: &Api, doc: &str) -> Result<Value, String> {
    let content = api.get(&format!("/docx/v1/documents/{}/raw_content", enc(doc)))?;
    let info = api.get(&format!("/docx/v1/documents/{}", enc(doc))).unwrap_or(Value::Null);
    let blocks = list_blocks(api, doc).unwrap_or_default();
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut structured: Vec<String> = Vec::new();
    for b in &blocks {
        let t = b["block_type"].as_u64().unwrap_or(0);
        let name = block_type_name(t);
        *counts.entry(name.clone()).or_default() += 1;
        if STRUCTURED_BLOCK_TYPES.contains(&t) && !structured.contains(&name) {
            structured.push(name);
        }
    }
    let mut out = json!({
        "title": info["data"]["document"]["title"], "content": content["data"]["content"],
        "revision_id": info["data"]["document"]["revision_id"], "block_count": blocks.len(), "block_types": counts,
    });
    if !structured.is_empty() {
        out["hint"] = json!(format!("This document contains {} which are NOT included in the plain text above. Use feishu_doc with action: \"list_blocks\" to get full content.", structured.join(", ")));
    }
    Ok(out)
}

/// Markdown chunk plus the image URLs it references (in order).
struct Chunk {
    markdown: String,
    images: Vec<String>,
}

fn images_of(md: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut fence = false;
    for line in md.lines() {
        if line.trim_start().starts_with("```") || line.trim_start().starts_with("~~~") {
            fence = !fence;
            continue;
        }
        if fence {
            continue;
        }
        let mut rest = line;
        while let Some(i) = rest.find("![") {
            rest = &rest[i + 2..];
            let Some(close) = rest.find("](") else { break };
            let after = &rest[close + 2..];
            let Some(end) = after.find(')') else { break };
            let url = after[..end].split_whitespace().next().unwrap_or("").trim_matches(['<', '>']);
            if !url.is_empty() {
                out.push(url.to_string());
            }
            rest = &after[end..];
        }
    }
    out
}

fn chunk(md: &str) -> Chunk {
    Chunk { markdown: md.to_string(), images: images_of(md) }
}

/// Upstream `createDocxMarkdownPlan`: split before ATX headings of depth ≤ 2 (outside fences).
fn markdown_plan(md: &str) -> Vec<Chunk> {
    let mut offsets = vec![0];
    let mut fence = false;
    let mut pos = 0;
    for line in md.split_inclusive('\n') {
        let t = line.trim_start();
        if t.starts_with("```") || t.starts_with("~~~") {
            fence = !fence;
        } else if !fence && pos > 0 && line.starts_with('#') && (line.starts_with("# ") || line.starts_with("## ") || line.trim_end() == "#" || line.trim_end() == "##") {
            offsets.push(pos);
        }
        pos += line.len();
    }
    offsets.push(md.len());
    offsets.dedup();
    offsets.windows(2).map(|w| &md[w[0]..w[1]]).filter(|c| !c.trim().is_empty()).map(chunk).collect()
}

/// Upstream `splitDocxMarkdownBySize`: a blank-line (else line) boundary near `max`.
fn split_by_size(md: &str, max: usize) -> Vec<String> {
    if md.len() <= max {
        return vec![md.to_string()];
    }
    let target = max.clamp(1, md.len() - 1);
    let mut best: Option<usize> = None;
    for (i, _) in md.match_indices("\n\n").map(|(i, s)| (i + 2, s)).chain(md.match_indices('\n').map(|(i, s)| (i + 1, s))) {
        if i > 0 && i < md.len() && best.is_none_or(|b| i.abs_diff(target) < b.abs_diff(target)) {
            best = Some(i);
        }
    }
    match best {
        Some(b) if md.is_char_boundary(b) => vec![md[..b].to_string(), md[b..].to_string()],
        _ => vec![md.to_string()],
    }
}

fn convert(api: &Api, md: &str) -> Result<(Vec<Value>, Vec<String>), String> {
    let v = api.send("POST", "/docx/v1/documents/blocks/convert", &json!({"content_type": "markdown", "content": md}))?;
    let ids = v["data"]["first_level_block_ids"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect();
    Ok((v["data"]["blocks"].as_array().cloned().unwrap_or_default(), ids))
}

fn child_ids(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => a.iter().filter_map(Value::as_str).map(str::to_string).collect(),
        Value::String(s) => vec![s.clone()],
        _ => vec![],
    }
}

/// Upstream `normalizeConvertedBlockTree`: pre-order from the roots, leftovers appended.
fn normalize_tree(blocks: Vec<Value>, first: Vec<String>) -> (Vec<Value>, Vec<String>) {
    if blocks.len() <= 1 {
        let roots = blocks.first().map(|b| s(b, "block_id").to_string()).filter(|i| !i.is_empty()).into_iter().collect();
        return (blocks, roots);
    }
    let by: HashMap<String, Value> = blocks.iter().filter(|b| !s(b, "block_id").is_empty()).map(|b| (s(b, "block_id").to_string(), b.clone())).collect();
    let kids: HashSet<String> = blocks.iter().flat_map(|b| child_ids(&b["children"])).collect();
    let inferred: Vec<String> = blocks
        .iter()
        .filter(|b| {
            let id = s(b, "block_id");
            let parent = s(b, "parent_id");
            !id.is_empty() && !kids.contains(id) && (parent.is_empty() || !by.contains_key(parent))
        })
        .map(|b| s(b, "block_id").to_string())
        .collect();
    let mut roots: Vec<String> = Vec::new();
    for r in if first.is_empty() { inferred } else { first } {
        if by.contains_key(&r) && !roots.contains(&r) {
            roots.push(r);
        }
    }
    let mut ordered = Vec::new();
    let mut seen = HashSet::new();
    fn visit(id: &str, by: &HashMap<String, Value>, seen: &mut HashSet<String>, out: &mut Vec<Value>) {
        let Some(b) = by.get(id) else { return };
        if !seen.insert(id.to_string()) {
            return;
        }
        out.push(b.clone());
        for c in child_ids(&b["children"]) {
            visit(&c, by, seen, out);
        }
    }
    for r in &roots {
        visit(r, &by, &mut seen, &mut ordered);
    }
    for b in &blocks {
        match b["block_id"].as_str() {
            Some(id) => visit(id, &by, &mut seen, &mut ordered),
            None => ordered.push(b.clone()),
        }
    }
    (ordered, roots)
}

/// `(blocks, first-level block ids, image block ids)`.
type Converted = (Vec<Value>, Vec<String>, Vec<String>);

fn chunked_convert(api: &Api, chunks: &[Chunk], depth: u32) -> Result<Converted, String> {
    let (mut blocks, mut roots, mut images) = (Vec::new(), Vec::new(), Vec::new());
    for c in chunks {
        let (b, r, i) = match convert(api, &c.markdown) {
            Ok((b, r)) => (b, r, c.images.clone()),
            Err(e) => {
                if depth >= MAX_CONVERT_RETRY_DEPTH || c.markdown.len() < 2 {
                    return Err(e);
                }
                let parts: Vec<Chunk> = split_by_size(&c.markdown, (c.markdown.len() / 2).max(256)).iter().map(|p| chunk(p)).collect();
                if parts.len() <= 1 {
                    return Err(e);
                }
                chunked_convert(api, &parts, depth + 1)?
            }
        };
        let (b, r) = if depth == 0 { normalize_tree(b, r) } else { (b, r) };
        blocks.extend(b);
        roots.extend(r);
        images.extend(i);
    }
    Ok((blocks, roots, images))
}

/// Upstream `cleanBlocksForDescendant` (adaptive table widths included).
fn clean_for_descendant(blocks: &[Value]) -> Vec<Value> {
    let by: HashMap<&str, &Value> = blocks.iter().filter_map(|b| b["block_id"].as_str().map(|i| (i, b))).collect();
    blocks
        .iter()
        .map(|b| {
            let mut c = b.clone();
            if let Some(o) = c.as_object_mut() {
                o.remove("parent_id");
            }
            if c["block_type"] == 32 && c["children"].is_string() {
                c["children"] = json!([c["children"].clone()]);
            }
            if c["block_type"] == 31 && c["table"].is_object() {
                let p = &b["table"]["property"];
                let mut prop = json!({"row_size": p["row_size"], "column_size": p["column_size"]});
                let w = adaptive_widths(b, &by);
                if !w.is_empty() {
                    prop["column_width"] = json!(w);
                }
                c["table"] = json!({"property": prop});
            }
            c
        })
        .collect()
}

fn adaptive_widths(table: &Value, by: &HashMap<&str, &Value>) -> Vec<i64> {
    const MIN: i64 = 50;
    const MAX: i64 = 400;
    let p = &table["table"]["property"];
    let (rows, cols) = (p["row_size"].as_u64().unwrap_or(0) as usize, p["column_size"].as_u64().unwrap_or(0) as usize);
    if rows == 0 || cols == 0 {
        return vec![];
    }
    let orig: Vec<i64> = p["column_width"].as_array().into_iter().flatten().filter_map(Value::as_i64).collect();
    let total: i64 = if orig.is_empty() { 730 } else { orig.iter().sum() };
    let text = |cell: &str| -> String {
        by.get(cell).map(|c| child_ids(&c["children"]).iter().filter_map(|k| by.get(k.as_str())).flat_map(|k| k["text"]["elements"].as_array().cloned().unwrap_or_default()).map(|e| e["text_run"]["content"].as_str().unwrap_or("").to_string()).collect()).unwrap_or_default()
    };
    let weighted = |t: &str| t.chars().map(|c| if (c as u32) > 255 { 2 } else { 1 }).sum::<i64>();
    let mut maxl = vec![0i64; cols];
    for (i, cell) in child_ids(&table["children"]).iter().take(rows * cols).enumerate() {
        maxl[i % cols] = maxl[i % cols].max(weighted(&text(cell)));
    }
    let tl: i64 = maxl.iter().sum();
    if tl == 0 {
        return vec![(total / cols as i64).clamp(MIN, MAX); cols];
    }
    let mut w: Vec<i64> = maxl.iter().map(|l| ((*l as f64 / tl as f64) * total as f64).round() as i64).map(|x| x.clamp(MIN, MAX)).collect();
    let mut remaining = total - w.iter().sum::<i64>();
    while remaining > 0 {
        let grow: Vec<usize> = (0..cols).filter(|i| w[*i] < MAX).collect();
        if grow.is_empty() {
            break;
        }
        let per = remaining / grow.len() as i64;
        if per == 0 {
            break;
        }
        for i in grow {
            let add = per.min(MAX - w[i]);
            w[i] += add;
            remaining -= add;
        }
    }
    w
}

fn insert_descendants(api: &Api, doc: &str, descendants: Vec<Value>, roots: &[String], parent: &str, index: i64) -> Result<Vec<Value>, String> {
    if descendants.is_empty() {
        return Ok(vec![]);
    }
    let v = api.send("POST", &format!("/docx/v1/documents/{}/blocks/{}/descendant", enc(doc), enc(parent)), &json!({"children_id": roots, "descendants": descendants, "index": index}))?;
    Ok(v["data"]["children"].as_array().cloned().unwrap_or_default())
}

/// Upstream `insertBlocksInBatches`: each root's subtree in one request, ≤1000 blocks each.
fn insert_batches(api: &Api, doc: &str, blocks: &[Value], roots: &[String], parent: &str, start: i64) -> Result<Vec<Value>, String> {
    let by: HashMap<String, Value> = blocks.iter().filter_map(|b| b["block_id"].as_str().map(|i| (i.to_string(), b.clone()))).collect();
    let mut used = HashSet::new();
    let mut batches: Vec<(Vec<String>, Vec<Value>)> = vec![];
    let mut cur: (Vec<String>, Vec<Value>) = (vec![], vec![]);
    for r in roots {
        let mut sub = Vec::new();
        let mut stack = vec![r.clone()];
        while let Some(id) = stack.pop() {
            let Some(b) = by.get(&id) else { continue };
            if !used.insert(id.clone()) {
                continue;
            }
            sub.push(b.clone());
            let mut kids = child_ids(&b["children"]);
            kids.reverse();
            stack.extend(kids);
        }
        if sub.len() > BATCH_SIZE {
            return Err(format!("Block \"{r}\" has {} descendants, which exceeds the Feishu API limit of {BATCH_SIZE} blocks per request. Please split the content into smaller sections.", sub.len()));
        }
        if cur.1.len() + sub.len() > BATCH_SIZE {
            batches.push(std::mem::take(&mut cur));
        }
        cur.0.push(r.clone());
        cur.1.extend(sub);
    }
    if !cur.1.is_empty() {
        batches.push(cur);
    }
    let mut all = Vec::new();
    let mut index = start;
    for (ids, bl) in batches {
        let desc: Vec<Value> = clean_for_descendant(&bl)
            .into_iter()
            .map(|mut b| {
                if let Some(c) = b["children"].as_str().map(str::to_string) {
                    b["children"] = json!([c]);
                }
                b
            })
            .collect();
        all.extend(insert_descendants(api, doc, desc, &ids, parent, index)?);
        if index != -1 {
            index += ids.len() as i64;
        }
    }
    Ok(all)
}

/// Bytes + file name from `url` / `file_path` / `image` (data URI or base64).
fn upload_input(api: &Api, ctx: &ToolCtx, a: &Value, allow_image: bool) -> Result<(Vec<u8>, String), String> {
    let name_override = opt(a, "filename");
    if let Some(img) = opt(a, "image").filter(|_| allow_image) {
        if let Some(rest) = img.strip_prefix("data:") {
            let (meta, payload) = rest.split_once(',').ok_or("Invalid data URI: missing comma separator.")?;
            let mut parts = meta.split(';');
            let mime = parts.next().unwrap_or("").trim().to_string();
            if !parts.any(|p| p.trim().eq_ignore_ascii_case("base64")) {
                return Err("Invalid data URI: missing ';base64' marker. Expected format: data:image/png;base64,<base64data>".into());
            }
            let bytes = b64(payload, api.media_max, "Invalid data URI: base64 payload is malformed.", "Image data URI")?;
            let ext = mime.strip_prefix("image/").map(|e| if e == "jpeg" { "jpg" } else { e }).unwrap_or("png").to_string();
            return Ok((bytes, name_override.unwrap_or(format!("image.{ext}"))));
        }
        let path_like = img.starts_with('~') || img.starts_with("./") || img.starts_with("../") || img.starts_with('/');
        if path_like {
            let p = ctx.resolve(&img);
            if p.is_file() || !img.starts_with('/') {
                let p = crate::media_guard::check(&p, &ctx.workspace, &crate::media_guard::roots_for(ctx))?;
                return read_local(&p, api.media_max, name_override);
            }
            return Err(format!("File not found: \"{}\". If you intended to pass image binary data, use a data URI instead: data:image/jpeg;base64,...", p.display()));
        }
        let bytes = b64(&img, api.media_max, "Invalid base64 image payload.", "Image base64 payload")?;
        let mt = ark_core::tool::image_media_type(&bytes).unwrap_or("image/png");
        return Ok((bytes, name_override.unwrap_or(format!("image.{}", if mt == "image/jpeg" { "jpg" } else { mt.trim_start_matches("image/") }))));
    }
    if let Some(p) = opt(a, "file_path") {
        let p = crate::media_guard::check(&ctx.resolve(&p), &ctx.workspace, &crate::media_guard::roots_for(ctx))?;
        return read_local(&p, api.media_max, name_override);
    }
    if let Some(u) = opt(a, "url") {
        if !(u.starts_with("http://") || u.starts_with("https://")) {
            return Err("url must be http(s)".into());
        }
        let bytes = crate::http::get_bytes(&u, &[], api.media_max).map_err(|e| e.message)?;
        let base = u.split(['?', '#']).next().unwrap_or("").rsplit('/').next().unwrap_or("").to_string();
        return Ok((bytes, name_override.unwrap_or(if base.is_empty() { "file".into() } else { base })));
    }
    Err(if allow_image { "Either url, file_path, or image must be provided".into() } else { "Either url or file_path must be provided".into() })
}

fn b64(payload: &str, max: u64, invalid: &str, label: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let clean: String = payload.chars().filter(|c| !c.is_whitespace()).collect();
    let est = clean.len() as u64 * 3 / 4;
    if est > max {
        return Err(format!("{label} exceeds limit: estimated {est} bytes > {max} bytes"));
    }
    let clean = clean.replace('-', "+").replace('_', "/");
    base64::engine::general_purpose::STANDARD.decode(clean.trim_end_matches('=').to_string() + &"=".repeat((4 - clean.trim_end_matches('=').len() % 4) % 4)).map_err(|_| invalid.to_string())
}

fn read_local(p: &std::path::Path, max: u64, name: Option<String>) -> Result<(Vec<u8>, String), String> {
    let meta = std::fs::metadata(p).map_err(|e| format!("cannot read {}: {e}", p.display()))?;
    if meta.len() > max {
        return Err(format!("{} exceeds limit: {} bytes > {max} bytes", p.display(), meta.len()));
    }
    let bytes = std::fs::read(p).map_err(|e| format!("cannot read {}: {e}", p.display()))?;
    Ok((bytes, name.unwrap_or_else(|| p.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into()))))
}

fn upload_media(api: &Api, kind: &str, parent: &str, bytes: &[u8], name: &str, doc: Option<&str>) -> Result<String, String> {
    let size = bytes.len().to_string();
    let parent_type = if kind == "image" { "docx_image" } else { "docx_file" };
    let extra = doc.map(|d| json!({"drive_route_token": d}).to_string());
    let mime = mime_of(name);
    let mut parts: Vec<(&str, &str, &str, &[u8])> = vec![("file_name", "", "", name.as_bytes()), ("parent_type", "", "", parent_type.as_bytes()), ("parent_node", "", "", parent.as_bytes()), ("size", "", "", size.as_bytes())];
    if let Some(e) = &extra {
        parts.push(("extra", "", "", e.as_bytes()));
    }
    parts.push(("file", name, mime, bytes));
    let v = api.call("POST", "/drive/v1/medias/upload_all", Payload::Multipart(&parts))?;
    v["data"]["file_token"].as_str().filter(|t| !t.is_empty()).map(str::to_string).ok_or_else(|| format!("{} upload failed: no file_token returned", if kind == "image" { "Image" } else { "File" }))
}

fn mime_of(name: &str) -> &'static str {
    match name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default().as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "pdf" => "application/pdf",
        "txt" | "md" => "text/plain",
        _ => "application/octet-stream",
    }
}

fn upload_image_into(api: &Api, doc: &str, block: &str, bytes: &[u8], name: &str) -> Result<String, String> {
    let tok = upload_media(api, "image", block, bytes, name, Some(doc))?;
    api.send("PATCH", &format!("/docx/v1/documents/{}/blocks/{}", enc(doc), enc(block)), &json!({"replace_image": {"token": tok}}))?;
    Ok(tok)
}

fn edit_doc(api: &Api, ctx: &ToolCtx, a: &Value, action: &str) -> Result<Value, String> {
    let doc = req(a, "doc_token")?;
    let content = a.get("content").and_then(Value::as_str).ok_or("content is required")?;
    let target = if action == "insert" {
        let after = req(a, "after_block_id")?;
        let b = get_block(api, doc, after)?;
        let parent = Some(s(&b, "parent_id").to_string()).filter(|p| !p.is_empty()).unwrap_or_else(|| doc.to_string());
        let items = children_of(api, doc, &parent)?;
        let i = items.iter().position(|x| s(x, "block_id") == after).ok_or_else(|| format!("after_block_id \"{after}\" was not found among the children of parent block \"{parent}\". Use list_blocks to verify the block ID."))?;
        Some((parent, i as i64 + 1))
    } else {
        None
    };
    let (blocks, roots, images) = chunked_convert(api, &markdown_plan(content), 0)?;
    // Conversion succeeded: only now clear the document for `write`.
    let deleted = if action == "write" {
        let n = list_blocks(api, doc)?.iter().filter(|b| s(b, "parent_id") == doc && b["block_type"] != 1).count();
        if n > 0 {
            delete_children(api, doc, doc, 0, n)?;
        }
        n
    } else {
        0
    };
    if blocks.is_empty() {
        if action != "write" {
            return Err("Content is empty".into());
        }
        return Ok(json!({"success": true, "blocks_deleted": deleted, "blocks_added": 0, "images_processed": 0}));
    }
    let (ordered, roots) = normalize_tree(blocks.clone(), roots);
    let (parent, index) = target.unwrap_or((doc.to_string(), -1));
    let inserted = if blocks.len() > BATCH_SIZE { insert_batches(api, doc, &ordered, &roots, &parent, index)? } else { insert_descendants(api, doc, clean_for_descendant(&ordered), &roots, &parent, index)? };
    let image_blocks: Vec<&Value> = inserted.iter().filter(|b| b["block_type"] == 27).collect();
    let mut processed = 0;
    for (url, b) in images.iter().zip(image_blocks) {
        let input = if url.starts_with("http://") || url.starts_with("https://") { json!({"url": url}) } else { json!({"file_path": url}) };
        if let Ok((bytes, name)) = upload_input(api, ctx, &input, false) {
            if upload_image_into(api, doc, s(b, "block_id"), &bytes, &name).is_ok() {
                processed += 1;
            }
        }
    }
    let mut out = json!({"success": true, "blocks_added": blocks.len(), "images_processed": processed});
    if action == "write" {
        out["blocks_deleted"] = json!(deleted);
    } else {
        out["block_ids"] = inserted.iter().map(|b| b["block_id"].clone()).collect();
    }
    Ok(out)
}

fn create_doc(api: &Api, ctx: &ToolCtx, a: &Value) -> Result<Value, String> {
    if a.get("content").is_some() {
        return Ok(json!({"error": "Feishu document creation does not support content. Call action \"create\" first, then call action \"write\" with the returned document_id as doc_token."}));
    }
    let title = req(a, "title")?;
    let mut body = json!({"title": title});
    if let Some(f) = opt(a, "folder_token") {
        body["folder_token"] = json!(f);
    }
    let v = api.send("POST", "/docx/v1/documents", &body)?;
    let d = &v["data"]["document"];
    let id = s(d, "document_id").to_string();
    if id.is_empty() {
        return Err("Document creation succeeded but no document_id was returned".into());
    }
    let mut out = json!({"document_id": id, "title": d["title"], "url": format!("https://feishu.cn/docx/{id}")});
    if a.get("grant_to_requester").and_then(Value::as_bool) != Some(false) {
        out["requester_perm_type"] = json!("edit");
        match api.requester(ctx) {
            Some(open_id) => {
                out["requester_open_id"] = json!(open_id);
                match api.send("POST", &format!("/drive/v1/permissions/{}/members?type=docx&need_notification=false", enc(&id)), &json!({"member_type": "openid", "member_id": open_id, "perm": "edit"})) {
                    Ok(_) => out["requester_permission_added"] = json!(true),
                    Err(e) => {
                        out["requester_permission_added"] = json!(false);
                        out["requester_permission_error"] = json!(e);
                    }
                }
            }
            None => {
                out["requester_permission_added"] = json!(false);
                out["requester_permission_skipped_reason"] = json!("trusted requester identity unavailable");
            }
        }
    }
    Ok(out)
}

fn write_table_cells(api: &Api, doc: &str, table: &str, values: &Value) -> Result<Value, String> {
    let rows_in: Vec<Vec<String>> = values.as_array().map(|r| r.iter().map(|row| row.as_array().map(|c| c.iter().map(|x| x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string())).collect()).unwrap_or_default()).collect()).unwrap_or_default();
    if rows_in.is_empty() || rows_in[0].is_empty() {
        return Err("values must be a non-empty 2D array".into());
    }
    let tb = get_block(api, doc, table)?;
    if tb["block_type"] != 31 {
        return Err("table_block_id is not a table block".into());
    }
    let p = &tb["table"]["property"];
    let (rows, cols) = (p["row_size"].as_u64().unwrap_or(0) as usize, p["column_size"].as_u64().unwrap_or(0) as usize);
    let cells = child_ids(&tb["table"]["cells"]);
    if rows == 0 || cols == 0 || cells.is_empty() {
        return Err("Table cell IDs unavailable from table block. Use list_blocks/get_block and pass explicit cell block IDs if needed.".into());
    }
    let mut written = 0;
    for (r, row) in rows_in.iter().take(rows).enumerate() {
        for (c, val) in row.iter().take(cols).enumerate() {
            let Some(cell) = cells.get(r * cols + c) else { continue };
            let (blocks, roots) = convert(api, val)?;
            let (ordered, _) = normalize_tree(blocks, roots);
            let existing = children_of(api, doc, cell)?;
            if !existing.is_empty() {
                delete_children(api, doc, cell, 0, existing.len())?;
            }
            // One block at a time keeps the order deterministic (upstream `insertBlocks`).
            for b in ordered.iter().filter(|b| !UNSUPPORTED_CREATE_TYPES.contains(&b["block_type"].as_u64().unwrap_or(0))) {
                let mut b = b.clone();
                if let Some(o) = b.as_object_mut() {
                    o.remove("block_id");
                    o.remove("parent_id");
                    o.remove("children");
                }
                api.send("POST", &format!("/docx/v1/documents/{}/blocks/{}/children", enc(doc), enc(cell)), &json!({"children": [b]}))?;
            }
            written += 1;
        }
    }
    Ok(json!({"success": true, "table_block_id": table, "cells_written": written, "table_size": {"rows": rows, "cols": cols}}))
}

fn create_table(api: &Api, a: &Value, with_values: bool) -> Result<Value, String> {
    let doc = req(a, "doc_token")?;
    let rows = a.get("row_size").and_then(Value::as_u64).filter(|n| *n >= 1).ok_or("row_size must be a positive integer")?;
    let cols = a.get("column_size").and_then(Value::as_u64).filter(|n| *n >= 1).ok_or("column_size must be a positive integer")?;
    let widths: Vec<f64> = a.get("column_width").and_then(Value::as_array).map(|w| w.iter().filter_map(Value::as_f64).collect()).unwrap_or_default();
    if !widths.is_empty() && widths.len() as u64 != cols {
        return Err("column_width length must equal column_size".into());
    }
    let parent = opt(a, "parent_block_id").unwrap_or_else(|| doc.to_string());
    let mut prop = json!({"row_size": rows, "column_size": cols});
    if !widths.is_empty() {
        prop["column_width"] = json!(widths);
    }
    let v = api.send("POST", &format!("/docx/v1/documents/{}/blocks/{}/children", enc(doc), enc(&parent)), &json!({"children": [{"block_type": 31, "table": {"property": prop}}]}))?;
    let children = v["data"]["children"].as_array().cloned().unwrap_or_default();
    let tb = children.iter().find(|b| b["block_type"] == 31).cloned().unwrap_or(Value::Null);
    if with_values {
        let id = s(&tb, "block_id");
        if id.is_empty() {
            return Err("create_table succeeded but table_block_id is missing".into());
        }
        let w = write_table_cells(api, doc, id, a.get("values").unwrap_or(&Value::Null))?;
        return Ok(json!({"success": true, "table_block_id": id, "row_size": rows, "column_size": cols, "cells_written": w["cells_written"]}));
    }
    let cells: Vec<String> = tb["children"].as_array().into_iter().flatten().filter_map(|c| c.as_str().map(str::to_string).or_else(|| c["block_id"].as_str().map(str::to_string))).collect();
    Ok(json!({"success": true, "table_block_id": tb["block_id"], "row_size": rows, "column_size": cols, "table_cell_block_ids": cells, "raw_children_count": children.len()}))
}

fn patch_table(api: &Api, a: &Value, action: &str) -> Result<Value, String> {
    let doc = req(a, "doc_token")?;
    let block = req(a, "block_id")?;
    let mut extra = Map::new();
    let need = |k: &str| num(a, k).ok_or_else(|| format!("{k} is required"));
    let data = match action {
        "insert_table_row" => json!({"insert_table_row": {"row_index": num(a, "row_index").unwrap_or(-1)}}),
        "insert_table_column" => json!({"insert_table_column": {"column_index": num(a, "column_index").unwrap_or(-1)}}),
        "delete_table_rows" => {
            let (st, n) = (need("row_start")?, num(a, "row_count").unwrap_or(1));
            extra.insert("rows_deleted".into(), json!(n));
            json!({"delete_table_rows": {"row_start_index": st, "row_end_index": st + n}})
        }
        "delete_table_columns" => {
            let (st, n) = (need("column_start")?, num(a, "column_count").unwrap_or(1));
            extra.insert("columns_deleted".into(), json!(n));
            json!({"delete_table_columns": {"column_start_index": st, "column_end_index": st + n}})
        }
        _ => json!({"merge_table_cells": {"row_start_index": need("row_start")?, "row_end_index": need("row_end")?, "column_start_index": need("column_start")?, "column_end_index": need("column_end")?}}),
    };
    let v = api.send("PATCH", &format!("/docx/v1/documents/{}/blocks/{}", enc(doc), enc(block)), &data)?;
    let mut out = json!({"success": true, "block": v["data"]["block"]});
    out.as_object_mut().unwrap().extend(extra);
    Ok(out)
}

/// Upstream `parseColorMarkup`.
pub(super) fn color_elements(content: &str) -> Vec<Value> {
    const COLORS: [(&str, u64); 8] = [("red", 1), ("orange", 2), ("yellow", 3), ("green", 4), ("blue", 5), ("purple", 6), ("grey", 7), ("gray", 7)];
    let known_tag = |tag: &str| {
        let tag = tag.to_ascii_lowercase();
        tag == "bold" || matches!(tag.as_str(), "red" | "orange" | "yellow" | "green" | "blue" | "purple" | "grey" | "gray") || tag.strip_prefix("bg:").is_some_and(|c| !c.is_empty() && c.chars().all(|x| x.is_ascii_alphabetic()))
    };
    // Same grammar as upstream's regex: `[tags]text[/anything]` (lazy, case-insensitive),
    // otherwise a run of non-`[` text or a lone `[`.
    let tagged = |rest: &str| -> Option<(String, String, usize)> {
        let inner_end = rest.find(']')?;
        let tags = &rest[1..inner_end];
        if tags.is_empty() || !tags.split_whitespace().all(known_tag) || tags.starts_with(char::is_whitespace) || tags.ends_with(char::is_whitespace) {
            return None;
        }
        let body = &rest[inner_end + 1..];
        let mut from = 0;
        while let Some(i) = body[from..].find("[/") {
            let at = from + i;
            if let Some(close) = body[at + 2..].find(']').filter(|c| *c > 0) {
                return Some((tags.to_string(), body[..at].to_string(), inner_end + 1 + at + 2 + close + 1));
            }
            from = at + 2;
        }
        None
    };
    let mut out = Vec::new();
    let mut rest = content;
    while !rest.is_empty() {
        let (text, tags, used) = if rest.starts_with('[') {
            match tagged(rest) {
                Some((tags, text, used)) => (text, Some(tags.to_lowercase()), used),
                None => ("[".to_string(), None, 1),
            }
        } else {
            let n = rest.find('[').unwrap_or(rest.len());
            (rest[..n].to_string(), None, n)
        };
        rest = &rest[used..];
        if text.is_empty() {
            continue;
        }
        let mut style = Map::new();
        for tag in tags.as_deref().unwrap_or("").split_whitespace() {
            if let Some(c) = tag.strip_prefix("bg:") {
                if let Some((_, n)) = COLORS.iter().find(|(k, _)| *k == c) {
                    style.insert("background_color".into(), json!(n));
                }
            } else if tag == "bold" {
                style.insert("bold".into(), json!(true));
            } else if let Some((_, n)) = COLORS.iter().find(|(k, _)| *k == tag) {
                style.insert("text_color".into(), json!(n));
            }
        }
        out.push(json!({"text_run": {"content": text, "text_element_style": style}}));
    }
    out
}

fn doc(api: &Api, ctx: &ToolCtx, a: &Value) -> Result<Value, String> {
    let action = action_of(a);
    match action {
        "read" => read_doc(api, req(a, "doc_token")?),
        "write" | "append" | "insert" => edit_doc(api, ctx, a, action),
        "create" => create_doc(api, ctx, a),
        "list_blocks" => Ok(json!({"blocks": list_blocks(api, req(a, "doc_token")?)?})),
        "get_block" => Ok(json!({"block": get_block(api, req(a, "doc_token")?, req(a, "block_id")?)?})),
        "update_block" => {
            let (d, b) = (req(a, "doc_token")?, req(a, "block_id")?);
            let content = a.get("content").and_then(Value::as_str).ok_or("content is required")?;
            api.send("PATCH", &format!("/docx/v1/documents/{}/blocks/{}", enc(d), enc(b)), &json!({"update_text_elements": {"elements": [{"text_run": {"content": content}}]}}))?;
            Ok(json!({"success": true, "block_id": b}))
        }
        "delete_block" => {
            let (d, b) = (req(a, "doc_token")?, req(a, "block_id")?);
            let blk = get_block(api, d, b)?;
            let parent = Some(s(&blk, "parent_id").to_string()).filter(|p| !p.is_empty()).unwrap_or_else(|| d.to_string());
            let items = children_of(api, d, &parent)?;
            let i = items.iter().position(|x| s(x, "block_id") == b).ok_or("Block not found")?;
            delete_children(api, d, &parent, i, i + 1)?;
            Ok(json!({"success": true, "deleted_block_id": b}))
        }
        "create_table" => create_table(api, a, false),
        "create_table_with_values" => create_table(api, a, true),
        "write_table_cells" => write_table_cells(api, req(a, "doc_token")?, req(a, "table_block_id")?, a.get("values").unwrap_or(&Value::Null)),
        "insert_table_row" | "insert_table_column" | "delete_table_rows" | "delete_table_columns" | "merge_table_cells" => patch_table(api, a, action),
        "upload_image" => {
            let d = req(a, "doc_token")?;
            // Resolve the input before creating a block.
            let (bytes, name) = upload_input(api, ctx, a, true)?;
            let parent = opt(a, "parent_block_id").unwrap_or_else(|| d.to_string());
            let mut body = json!({"children": [{"block_type": 27, "image": {}}], "index": -1});
            if let Some(i) = a.get("index").and_then(Value::as_u64) {
                body["index"] = json!(i);
            }
            let v = api.send("POST", &format!("/docx/v1/documents/{}/blocks/{}/children?document_revision_id=-1", enc(d), enc(&parent)), &body).map_err(|e| format!("Failed to create image block: {e}"))?;
            let id = v["data"]["children"].as_array().into_iter().flatten().find(|b| b["block_type"] == 27).map(|b| s(b, "block_id").to_string()).filter(|i| !i.is_empty()).ok_or("Failed to create image block")?;
            let tok = upload_image_into(api, d, &id, &bytes, &name)?;
            Ok(json!({"success": true, "block_id": id, "file_token": tok, "file_name": name, "size": bytes.len()}))
        }
        "upload_file" => {
            let d = req(a, "doc_token")?;
            let (bytes, name) = upload_input(api, ctx, a, false)?;
            let tok = upload_media(api, "file", d, &bytes, &name, None)?;
            Ok(json!({"success": true, "file_token": tok, "file_name": name, "size": bytes.len(), "note": "File uploaded to drive. Use the file_token to reference it. Direct file block creation is not supported by the Feishu API."}))
        }
        "color_text" => {
            let (d, b) = (req(a, "doc_token")?, req(a, "block_id")?);
            let els = color_elements(a.get("content").and_then(Value::as_str).unwrap_or(""));
            let v = api.send("PATCH", &format!("/docx/v1/documents/{}/blocks/{}", enc(d), enc(b)), &json!({"update_text_elements": {"elements": els}}))?;
            Ok(json!({"success": true, "segments": els.len(), "block": v["data"]["block"]}))
        }
        _ => Ok(json!({"error": "Unknown action"})),
    }
}

fn app_scopes(api: &Api, _: &ToolCtx, _: &Value) -> Result<Value, String> {
    let v = api.get("/application/v6/scopes")?;
    let scopes = v["data"]["scopes"].as_array().cloned().unwrap_or_default();
    let (g, p): (Vec<&Value>, Vec<&Value>) = scopes.iter().partition(|x| x["grant_status"] == 1);
    let m = |l: &[&Value]| l.iter().map(|x| json!({"name": x["scope_name"], "type": x["scope_type"]})).collect::<Vec<_>>();
    Ok(json!({"granted": m(&g), "pending": m(&p), "summary": format!("{} granted, {} pending", g.len(), p.len())}))
}

// ───────────── wiki ─────────────

fn wiki_schema() -> Value {
    let space = "Knowledge space ID. Treat as an opaque string and keep it quoted; never pass numeric-looking IDs as numbers.";
    json!({"type": "object", "properties": {
        "action": {"type": "string", "enum": ["spaces", "nodes", "get", "search", "create", "move", "rename"]},
        "space_id": {"type": "string", "description": space},
        "parent_node_token": {"type": "string", "description": "Parent node token (optional, omit for root)"},
        "page_size": {"type": "integer", "minimum": 1, "maximum": 50, "description": "Page size (1-50, default 50)"},
        "page_token": {"type": "string", "description": "Pagination token"},
        "token": {"type": "string", "description": "Wiki node token (from URL /wiki/XXX)"},
        "query": {"type": "string"},
        "title": {"type": "string", "description": "Node title / new title"},
        "obj_type": {"type": "string", "enum": ["docx", "sheet", "bitable"], "description": "Object type (default: docx)"},
        "node_token": {"type": "string"},
        "target_space_id": {"type": "string", "description": "Target knowledge space ID (optional, same space if omitted)"},
        "target_parent_token": {"type": "string", "description": "Target parent node token (optional, root if omitted)"}
    }, "required": ["action"]})
}

fn space_id(a: &Value, k: &str, required: bool) -> Result<Option<String>, String> {
    match a.get(k) {
        None | Some(Value::Null) if !required => Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() && !required => Ok(None),
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(Some(s.trim().to_string())),
        Some(Value::String(_)) => Err(format!("{k} must not be empty.")),
        _ => Err(format!("{k} must be a string. Feishu wiki space IDs are opaque identifiers; pass them quoted to avoid JavaScript number precision loss.")),
    }
}

fn wiki(api: &Api, _: &ToolCtx, a: &Value) -> Result<Value, String> {
    let ps = || page_size(a, WIKI_PAGE_SIZE, "page_size must be a positive integer between 1 and 50").map(|p| p.unwrap_or(WIKI_PAGE_SIZE).to_string());
    match action_of(a) {
        "spaces" => {
            let pt = opt(a, "page_token");
            let v = api.get(&format!("/wiki/v2/spaces{}", q(&[("page_size", Some(ps()?)), ("page_token", pt.clone())])))?;
            let d = &v["data"];
            let spaces: Vec<Value> = d["items"].as_array().into_iter().flatten().map(|x| json!({"space_id": x["space_id"], "name": x["name"], "description": x["description"], "visibility": x["visibility"]})).collect();
            let mut out = json!({"spaces": spaces, "has_more": d["has_more"].as_bool().unwrap_or(false), "page_token": d["page_token"]});
            if spaces.is_empty() && pt.is_none() && d["has_more"].as_bool() != Some(true) {
                out["hint"] = json!(WIKI_ACCESS_HINT);
            }
            Ok(out)
        }
        "nodes" => {
            let sp = space_id(a, "space_id", true)?.unwrap();
            let v = api.get(&format!("/wiki/v2/spaces/{}/nodes{}", enc(&sp), q(&[("parent_node_token", opt(a, "parent_node_token")), ("page_size", Some(ps()?)), ("page_token", opt(a, "page_token"))])))?;
            let d = &v["data"];
            Ok(json!({"nodes": d["items"].as_array().into_iter().flatten().map(|n| json!({"node_token": n["node_token"], "obj_token": n["obj_token"], "obj_type": n["obj_type"], "title": n["title"], "has_child": n["has_child"]})).collect::<Vec<_>>(), "has_more": d["has_more"].as_bool().unwrap_or(false), "page_token": d["page_token"]}))
        }
        "get" => {
            let v = api.get(&format!("/wiki/v2/spaces/get_node?token={}", enc(req(a, "token")?)))?;
            let n = &v["data"]["node"];
            Ok(json!({"node_token": n["node_token"], "space_id": n["space_id"], "obj_token": n["obj_token"], "obj_type": n["obj_type"], "title": n["title"], "parent_node_token": n["parent_node_token"], "has_child": n["has_child"], "creator": n["creator"], "create_time": n["node_create_time"]}))
        }
        "search" => {
            space_id(a, "space_id", false)?;
            Ok(json!({"error": "Search is not available. Use feishu_wiki with action: 'nodes' to browse or action: 'get' to lookup by token."}))
        }
        "create" => {
            let sp = space_id(a, "space_id", true)?.unwrap();
            let mut body = json!({"obj_type": opt(a, "obj_type").unwrap_or_else(|| "docx".into()), "node_type": "origin", "title": req(a, "title")?});
            if let Some(p) = opt(a, "parent_node_token") {
                body["parent_node_token"] = json!(p);
            }
            let v = api.send("POST", &format!("/wiki/v2/spaces/{}/nodes", enc(&sp)), &body)?;
            let n = &v["data"]["node"];
            Ok(json!({"node_token": n["node_token"], "obj_token": n["obj_token"], "obj_type": n["obj_type"], "title": n["title"]}))
        }
        "move" => {
            let sp = space_id(a, "space_id", true)?.unwrap();
            let node = req(a, "node_token")?;
            let mut body = json!({"target_space_id": space_id(a, "target_space_id", false)?.unwrap_or_else(|| sp.clone())});
            if let Some(p) = opt(a, "target_parent_token") {
                body["target_parent_token"] = json!(p);
            }
            let v = api.send("POST", &format!("/wiki/v2/spaces/{}/nodes/{}/move", enc(&sp), enc(node)), &body)?;
            Ok(json!({"success": true, "node_token": v["data"]["node"]["node_token"]}))
        }
        "rename" => {
            let sp = space_id(a, "space_id", true)?.unwrap();
            let (node, title) = (req(a, "node_token")?, req(a, "title")?);
            api.send("POST", &format!("/wiki/v2/spaces/{}/nodes/{}/update_title", enc(&sp), enc(node)), &json!({"title": title}))?;
            Ok(json!({"success": true, "node_token": node, "title": title}))
        }
        other => Ok(json!({"error": format!("Unknown action: {other}")})),
    }
}

// ───────────── drive ─────────────

fn drive_schema() -> Value {
    json!({"type": "object", "properties": {
        "action": {"type": "string", "enum": ["list", "info", "create_folder", "move", "delete", "list_comments", "list_comment_replies", "add_comment", "reply_comment"]},
        "folder_token": {"type": "string", "description": "Folder token (list: omit for root; create_folder: parent; move: target)"},
        "page_size": {"type": "integer", "minimum": 1, "maximum": 200},
        "page_token": {"type": "string"},
        "file_token": {"type": "string", "description": "File / folder / document token"},
        "type": {"type": "string", "enum": ["doc", "docx", "sheet", "bitable", "folder", "file", "mindnote", "shortcut", "slides"]},
        "name": {"type": "string", "description": "create_folder: folder name"},
        "file_type": {"type": "string", "enum": ["doc", "docx", "sheet", "file", "slides"], "description": "Comment document type (default docx)"},
        "comment_id": {"type": "string"},
        "content": {"type": "string", "description": "Comment / reply text"},
        "block_id": {"type": "string", "description": "add_comment: optional docx block id for a local comment"}
    }, "required": ["action"]})
}

fn list_folder(api: &Api, a: &Value) -> Result<Value, String> {
    let folder = opt(a, "folder_token").filter(|f| f != "0");
    let ps = page_size(a, 200, "page_size must be a positive integer between 1 and 200")?;
    if folder.is_none() && (ps.is_some() || opt(a, "page_token").is_some()) {
        return Err("page_size and page_token require folder_token".into());
    }
    let v = api.get(&format!("/drive/v1/files{}", q(&[("folder_token", folder.clone()), ("page_size", ps.map(|p| p.to_string())), ("page_token", opt(a, "page_token"))])))?;
    let d = &v["data"];
    Ok(json!({"files": d["files"].as_array().into_iter().flatten().map(|f| json!({"token": f["token"], "name": f["name"], "type": f["type"], "url": f["url"], "created_time": f["created_time"], "modified_time": f["modified_time"], "owner_id": f["owner_id"]})).collect::<Vec<_>>(), "next_page_token": d["next_page_token"]}))
}

fn root_file(api: &Api, token: &str) -> Result<Value, String> {
    let l = list_folder(api, &json!({}))?;
    l["files"].as_array().into_iter().flatten().find(|f| f["token"] == token).cloned().ok_or_else(|| format!("File not found: {token}"))
}

fn drive(api: &Api, _: &ToolCtx, a: &Value) -> Result<Value, String> {
    match action_of(a) {
        "list" => list_folder(api, a),
        "info" => {
            let token = req(a, "file_token")?;
            let ty = req(a, "type")?;
            if ty == "shortcut" {
                return root_file(api, token);
            }
            let r = api.send("POST", "/drive/v1/metas/batch_query", &json!({"request_docs": [{"doc_token": token, "doc_type": ty}], "with_url": true}));
            let v = match r {
                Err(e) if e.contains("code=99991672 ") => return root_file(api, token),
                r => r?,
            };
            let m = v["data"]["metas"].as_array().into_iter().flatten().find(|m| m["doc_token"] == token || m["request_doc_info"]["doc_token"] == token).cloned().ok_or_else(|| format!("File not found: {token}"))?;
            Ok(json!({"token": m["doc_token"], "name": m["title"], "type": m["doc_type"], "url": m["url"], "created_time": m["create_time"], "modified_time": m["latest_modify_time"], "owner_id": m["owner_id"]}))
        }
        "create_folder" => {
            let name = req(a, "name")?;
            let mut folder = opt(a, "folder_token").filter(|f| f != "0").unwrap_or_else(|| "0".into());
            if folder == "0" {
                if let Ok(v) = api.get("/drive/explorer/v2/root_folder/meta") {
                    if let Some(t) = v["data"]["token"].as_str().filter(|t| !t.is_empty()) {
                        folder = t.to_string();
                    }
                }
            }
            let v = api.send("POST", "/drive/v1/files/create_folder", &json!({"name": name, "folder_token": folder}))?;
            Ok(json!({"token": v["data"]["token"], "url": v["data"]["url"]}))
        }
        "move" => {
            let v = api.send("POST", &format!("/drive/v1/files/{}/move", enc(req(a, "file_token")?)), &json!({"type": req(a, "type")?, "folder_token": req(a, "folder_token")?}))?;
            Ok(json!({"success": true, "task_id": v["data"]["task_id"]}))
        }
        "delete" => {
            let v = api.call("DELETE", &format!("/drive/v1/files/{}?type={}", enc(req(a, "file_token")?), enc(req(a, "type")?)), Payload::None)?;
            Ok(json!({"success": true, "task_id": v["data"]["task_id"]}))
        }
        act @ ("list_comments" | "list_comment_replies") => {
            let token = req(a, "file_token")?;
            let ft = opt(a, "file_type").unwrap_or_else(|| "docx".into());
            let ps = a.get("page_size").and_then(Value::as_u64).map(|p| p.clamp(1, 100)).unwrap_or(100).to_string();
            let base = format!("/drive/v1/files/{}/comments", enc(token));
            let url = if act == "list_comment_replies" { format!("{base}/{}/replies", enc(req(a, "comment_id")?)) } else { base };
            let v = api.get(&format!("{url}{}", q(&[("file_type", Some(ft)), ("page_size", Some(ps)), ("page_token", opt(a, "page_token")), ("user_id_type", Some("open_id".into()))])))?;
            let d = &v["data"];
            let items = d["items"].as_array().cloned().unwrap_or_default();
            let mut out = json!({"has_more": d["has_more"].as_bool().unwrap_or(false), "page_token": d["page_token"]});
            if act == "list_comment_replies" {
                out["replies"] = items.iter().map(reply_card).collect();
            } else {
                out["comments"] = items
                    .iter()
                    .map(|c| json!({"comment_id": c["comment_id"], "user_id": c["user_id"], "create_time": c["create_time"], "is_solved": c["is_solved"], "is_whole": c["is_whole"], "quote": c["quote"], "replies": c["reply_list"]["replies"].as_array().into_iter().flatten().map(reply_card).collect::<Vec<_>>()}))
                    .collect();
            }
            Ok(out)
        }
        "add_comment" => {
            let token = req(a, "file_token")?;
            let ft = opt(a, "file_type").unwrap_or_else(|| "docx".into());
            let block = opt(a, "block_id");
            if block.is_some() && ft != "docx" {
                return Err("block_id is only supported for docx comments".into());
            }
            new_comment(api, token, &ft, req(a, "content")?, block.as_deref())
        }
        "reply_comment" => {
            let (token, cid) = (req(a, "file_token")?, req(a, "comment_id")?);
            let ft = opt(a, "file_type").unwrap_or_else(|| "docx".into());
            let content = req(a, "content")?;
            // Upstream `deliverCommentThreadText`: a whole-document comment has no thread, so a
            // follow-up is a new whole comment; a thread that refuses replies (1069302) falls
            // back to one too.
            if comment_is_whole(api, token, cid, &ft) {
                if ft != "doc" && ft != "docx" {
                    return Err(format!("Whole-document comment follow-ups are only supported for doc/docx (got {ft})"));
                }
                let mut v = new_comment(api, token, &ft, content, None)?;
                v["delivery_mode"] = json!("add_comment");
                return Ok(v);
            }
            let path = format!("/drive/v1/files/{}/comments/{}/replies?file_type={}", enc(token), enc(cid), enc(&ft));
            match api.send("POST", &path, &json!({"content": {"elements": [{"type": "text_run", "text_run": {"text": content}}]}})) {
                Ok(v) => Ok(json!({"success": true, "delivery_mode": "reply_comment", "reply_id": v["data"]["reply_id"], "comment_id": cid})),
                Err(e) if e.contains("code=1069302") => {
                    if ft != "doc" && ft != "docx" {
                        return Err(e);
                    }
                    let mut v = new_comment(api, token, &ft, content, None)?;
                    v["delivery_mode"] = json!("add_comment");
                    Ok(v)
                }
                Err(e) => Err(e),
            }
        }
        other => Ok(json!({"error": format!("Unknown action: {other}")})),
    }
}

/// `POST …/new_comments` (upstream `addComment`): a new comment or whole-document comment.
fn new_comment(api: &Api, token: &str, ft: &str, content: &str, block: Option<&str>) -> Result<Value, String> {
    let mut body = json!({"file_type": ft, "reply_elements": [{"type": "text", "text": content}]});
    if let Some(b) = block {
        body["anchor"] = json!({"block_id": b});
    }
    let v = api.send("POST", &format!("/drive/v1/files/{}/new_comments", enc(token)), &body)?;
    let mut out = json!({"success": true});
    if let Some(d) = v["data"].as_object() {
        out.as_object_mut().unwrap().extend(d.clone());
    }
    Ok(out)
}

/// Upstream preflight (single-comment `batch_query`): is this a whole-document comment?
/// Any failure counts as "no" (upstream warns and carries on).
fn comment_is_whole(api: &Api, token: &str, cid: &str, ft: &str) -> bool {
    let path = format!("/drive/v1/files/{}/comments/batch_query{}", enc(token), q(&[("file_type", Some(ft.into())), ("user_id_type", Some("open_id".into()))]));
    api.send("POST", &path, &json!({"comment_ids": [cid]}))
        .ok()
        .and_then(|v| v["data"]["items"].as_array().and_then(|items| items.iter().find(|i| s(i, "comment_id") == cid).map(|i| i["is_whole"] == true)))
        .unwrap_or(false)
}

fn reply_card(r: &Value) -> Value {
    let text: String = r["content"]["elements"].as_array().into_iter().flatten().map(|e| e["text_run"]["text"].as_str().or_else(|| e["docs_link"]["url"].as_str()).or_else(|| e["person"]["user_id"].as_str()).unwrap_or("")).collect();
    json!({"reply_id": r["reply_id"], "user_id": r["user_id"], "create_time": r["create_time"], "text": text})
}

// ───────────── perm ─────────────

fn perm_schema() -> Value {
    json!({"type": "object", "properties": {
        "action": {"type": "string", "enum": ["list", "add", "remove"]},
        "token": {"type": "string", "description": "File token"},
        "type": {"type": "string", "enum": ["doc", "docx", "sheet", "bitable", "folder", "file", "wiki", "mindnote"]},
        "member_type": {"type": "string", "enum": ["email", "openid", "userid", "unionid", "openchat", "opendepartmentid"]},
        "member_id": {"type": "string", "description": "Member ID (email, open_id, user_id, etc.)"},
        "perm": {"type": "string", "enum": ["view", "edit", "full_access"]}
    }, "required": ["action", "token", "type"]})
}

fn perm(api: &Api, _: &ToolCtx, a: &Value) -> Result<Value, String> {
    let (token, ty) = (req(a, "token")?, req(a, "type")?);
    match action_of(a) {
        "list" => {
            let v = api.get(&format!("/drive/v1/permissions/{}/members?type={}", enc(token), enc(ty)))?;
            Ok(json!({"members": v["data"]["items"].as_array().into_iter().flatten().map(|m| json!({"member_type": m["member_type"], "member_id": m["member_id"], "perm": m["perm"], "name": m["name"]})).collect::<Vec<_>>()}))
        }
        "add" => {
            let v = api.send("POST", &format!("/drive/v1/permissions/{}/members?type={}&need_notification=false", enc(token), enc(ty)), &json!({"member_type": req(a, "member_type")?, "member_id": req(a, "member_id")?, "perm": req(a, "perm")?}))?;
            Ok(json!({"success": true, "member": v["data"]["member"]}))
        }
        "remove" => {
            api.call("DELETE", &format!("/drive/v1/permissions/{}/members/{}?type={}&member_type={}", enc(token), enc(req(a, "member_id")?), enc(ty), enc(req(a, "member_type")?)), Payload::None)?;
            Ok(json!({"success": true}))
        }
        other => Ok(json!({"error": format!("Unknown action: {other}")})),
    }
}

// ───────────── chat ─────────────

fn chat_schema() -> Value {
    json!({"type": "object", "properties": {
        "action": {"type": "string", "enum": ["members", "info", "member_info"], "description": "Action to run: members | info | member_info"},
        "chat_id": {"type": "string", "description": "Chat ID (from URL or event payload)"},
        "member_id": {"type": "string", "description": "Member ID for member_info lookups"},
        "page_size": {"type": "integer", "minimum": 1, "maximum": 100, "description": "Page size (1-100, default 50)"},
        "page_token": {"type": "string"},
        "member_id_type": {"type": "string", "enum": ["open_id", "user_id", "union_id"], "description": "Member ID type (default: open_id)"}
    }, "required": ["action"]})
}

pub(super) fn chat_info(call: &dyn Fn(&str) -> Result<Value, String>, chat: &str) -> Result<Value, String> {
    let c = call(&format!("/im/v1/chats/{}", enc(chat)))?["data"].clone();
    Ok(json!({"chat_id": chat, "name": c["name"], "description": c["description"], "owner_id": c["owner_id"], "tenant_key": c["tenant_key"], "user_count": c["user_count"], "chat_mode": c["chat_mode"], "chat_type": c["chat_type"], "join_message_visibility": c["join_message_visibility"], "leave_message_visibility": c["leave_message_visibility"], "membership_approval": c["membership_approval"], "moderation_permission": c["moderation_permission"], "avatar": c["avatar"]}))
}

pub(super) fn chat_members(call: &dyn Fn(&str) -> Result<Value, String>, chat: &str, size: Option<u64>, token: Option<String>, id_type: &str) -> Result<Value, String> {
    let ps = size.map(|p| p.clamp(1, 100)).unwrap_or(50).to_string();
    let v = call(&format!("/im/v1/chats/{}/members{}", enc(chat), q(&[("page_size", Some(ps)), ("page_token", token), ("member_id_type", Some(id_type.into()))])))?;
    let d = &v["data"];
    Ok(json!({"chat_id": chat, "has_more": d["has_more"], "page_token": d["page_token"], "members": d["items"].as_array().into_iter().flatten().map(|m| json!({"member_id": m["member_id"], "name": m["name"], "tenant_key": m["tenant_key"], "member_id_type": m["member_id_type"]})).collect::<Vec<_>>()}))
}

/// Upstream `assertFeishuChatMember`: page through members until `member` is found.
pub(super) fn assert_member(call: &dyn Fn(&str) -> Result<Value, String>, chat: &str, member: &str, id_type: &str) -> Result<(), String> {
    let mut token = None;
    let mut seen = HashSet::new();
    loop {
        let m = chat_members(call, chat, Some(100), token.clone(), id_type)?;
        if m["members"].as_array().into_iter().flatten().any(|x| x["member_id"] == member) {
            return Ok(());
        }
        let next = m["page_token"].as_str().unwrap_or("").to_string();
        if m["has_more"].as_bool() != Some(true) || next.is_empty() {
            return Err(format!("Member {member} is not a member of chat {chat}"));
        }
        if !seen.insert(next.clone()) {
            return Err(format!("Feishu chat member pagination repeated token for chat {chat}"));
        }
        token = Some(next);
    }
}

pub(super) fn member_info(call: &dyn Fn(&str) -> Result<Value, String>, member: &str, id_type: &str) -> Result<Value, String> {
    let v = call(&format!("/contact/v3/users/{}?user_id_type={}&department_id_type=open_department_id", enc(member), enc(id_type)))?;
    let u = &v["data"]["user"];
    let mut out = json!({"member_id": member, "member_id_type": id_type});
    for k in ["open_id", "user_id", "union_id", "name", "en_name", "nickname", "email", "enterprise_email", "mobile", "mobile_visible", "status", "avatar", "department_ids", "department_path", "leader_user_id", "city", "country", "work_station", "join_time", "is_tenant_manager", "employee_no", "employee_type", "description", "job_title", "geo"] {
        out[k] = u[k].clone();
    }
    Ok(out)
}

fn chat(api: &Api, _: &ToolCtx, a: &Value) -> Result<Value, String> {
    let action = action_of(a);
    if !matches!(action, "members" | "info" | "member_info") {
        return Ok(json!({"error": format!("Unknown action: {action}")}));
    }
    if action == "member_info" && opt(a, "member_id").is_none() {
        return Ok(json!({"error": "member_id is required for action member_info"}));
    }
    let Some(chat) = opt(a, "chat_id") else { return Ok(json!({"error": format!("chat_id is required for action {action}")})) };
    let call = |p: &str| api.get(p);
    let info = chat_info(&call, &chat)?;
    if action == "info" {
        return Ok(info);
    }
    let id_type = opt(a, "member_id_type").unwrap_or_else(|| "open_id".into());
    if action == "members" {
        return chat_members(&call, &chat, page_size(a, 100, "page_size must be a positive integer between 1 and 100")?, opt(a, "page_token"), &id_type);
    }
    let member = opt(a, "member_id").unwrap();
    if info["chat_mode"] != "p2p" {
        // Group reads are limited to people who are actually in the chat.
        assert_member(&call, &chat, &member, &id_type)?;
    }
    member_info(&call, &member, &id_type)
}

// ───────────── bitable ─────────────

fn field_type_name(t: u64) -> String {
    match t {
        1 => "Text", 2 => "Number", 3 => "SingleSelect", 4 => "MultiSelect", 5 => "DateTime", 7 => "Checkbox", 11 => "User", 13 => "Phone", 15 => "URL", 17 => "Attachment", 18 => "SingleLink", 19 => "Lookup", 20 => "Formula", 21 => "DuplexLink", 22 => "Location", 23 => "GroupChat", 1001 => "CreatedTime", 1002 => "ModifiedTime", 1003 => "CreatedUser", 1004 => "ModifiedUser", 1005 => "AutoNumber",
        _ => return format!("type_{t}"),
    }
    .into()
}

/// `/base/XXX?table=YYY` or `/wiki/XXX?table=YYY`.
pub(super) fn parse_bitable_url(url: &str) -> Option<(String, Option<String>, bool)> {
    let u = ark_net::Url::parse(url).ok()?;
    let (path, query) = u.path.split_once('?').unwrap_or((&u.path, ""));
    let table = query.split('&').find_map(|kv| kv.strip_prefix("table=")).map(str::to_string).filter(|t| !t.is_empty());
    let token = |marker: &str| path.find(marker).map(|i| path[i + marker.len()..].chars().take_while(|c| c.is_ascii_alphanumeric()).collect::<String>()).filter(|t| !t.is_empty());
    if let Some(t) = token("/wiki/") {
        return Some((t, table, true));
    }
    token("/base/").map(|t| (t, table, false))
}

type BitableDef = (&'static str, &'static str, Value, Exec, fn(&Value) -> bool);

fn bitable_tools() -> Vec<BitableDef> {
    let app = json!({"type": "string", "description": "Bitable application token (the /base/ URL identifier, or app_token from metadata). Not the node token in a /wiki/ URL."});
    let table = json!({"type": "string", "description": "Table ID (from URL: ?table=YYY)"});
    let fields = json!({"type": "object", "description": "Field values keyed by field name. Format by type: Text='string', Number=123, SingleSelect='Option', MultiSelect=['A','B'], DateTime=timestamp_ms, User=[{id:'ou_xxx'}], URL={text:'Display',link:'https://...'}"});
    vec![
        ("feishu_bitable_get_meta", "Parse a Bitable URL and get app_token, table_id, and table list. Use this first when given a /wiki/ or /base/ URL.", json!({"type": "object", "properties": {"url": {"type": "string", "description": "Bitable URL. Supports both formats: /base/XXX?table=YYY or /wiki/XXX?table=YYY"}}, "required": ["url"]}), bitable_meta, never),
        ("feishu_bitable_list_fields", "List all fields (columns) in a Bitable table with their types and properties", json!({"type": "object", "properties": {"app_token": app, "table_id": table}, "required": ["app_token", "table_id"]}), bitable_fields, never),
        ("feishu_bitable_list_records", "List records (rows) from a Bitable table with pagination support", json!({"type": "object", "properties": {"app_token": app, "table_id": table, "page_size": {"type": "integer", "minimum": 1, "maximum": 500, "description": "Number of records per page (1-500, default 100)"}, "page_token": {"type": "string", "description": "Pagination token from previous response"}}, "required": ["app_token", "table_id"]}), bitable_records, never),
        ("feishu_bitable_get_record", "Get a single record by ID from a Bitable table", json!({"type": "object", "properties": {"app_token": app, "table_id": table, "record_id": {"type": "string", "description": "Record ID to retrieve"}}, "required": ["app_token", "table_id", "record_id"]}), bitable_get_record, never),
        ("feishu_bitable_create_record", "Create a new record (row) in a Bitable table", json!({"type": "object", "properties": {"app_token": app, "table_id": table, "fields": fields}, "required": ["app_token", "table_id", "fields"]}), bitable_create_record, always),
        ("feishu_bitable_update_record", "Update an existing record (row) in a Bitable table", json!({"type": "object", "properties": {"app_token": app, "table_id": table, "record_id": {"type": "string", "description": "Record ID to update"}, "fields": fields}, "required": ["app_token", "table_id", "record_id", "fields"]}), bitable_update_record, always),
        ("feishu_bitable_create_app", "Create a new Bitable (multidimensional table) application", json!({"type": "object", "properties": {"name": {"type": "string", "description": "Name for the new Bitable application"}, "folder_token": {"type": "string", "description": "Optional folder token to place the Bitable in a specific folder"}}, "required": ["name"]}), bitable_create_app, always),
        ("feishu_bitable_create_field", "Create a new field (column) in a Bitable table", json!({"type": "object", "properties": {"app_token": app, "table_id": table, "field_name": {"type": "string", "description": "Name for the new field"}, "field_type": {"type": "integer", "description": "Field type ID: 1=Text, 2=Number, 3=SingleSelect, 4=MultiSelect, 5=DateTime, 7=Checkbox, 11=User, 13=Phone, 15=URL, 17=Attachment, 18=SingleLink, 19=Lookup, 20=Formula, 21=DuplexLink, 22=Location, 23=GroupChat, 1001=CreatedTime, 1002=ModifiedTime, 1003=CreatedUser, 1004=ModifiedUser, 1005=AutoNumber"}, "property": {"type": "object", "description": "Field-specific properties (e.g., options for SingleSelect, format for Number)"}}, "required": ["app_token", "table_id", "field_name", "field_type"]}), bitable_create_field, always),
    ]
}

fn tables_path(a: &Value) -> Result<String, String> {
    Ok(format!("/bitable/v1/apps/{}/tables/{}", enc(req(a, "app_token")?), enc(req(a, "table_id")?)))
}

fn bitable_meta(api: &Api, _: &ToolCtx, a: &Value) -> Result<Value, String> {
    let (token, table, wiki) = parse_bitable_url(req(a, "url")?).ok_or("Invalid URL format. Expected /base/XXX or /wiki/XXX URL")?;
    let app = if wiki {
        let v = api.get(&format!("/wiki/v2/spaces/get_node?token={}", enc(&token)))?;
        let n = &v["data"]["node"];
        if !n.is_object() {
            return Err("Node not found".into());
        }
        if n["obj_type"] != "bitable" {
            return Err(format!("Node is not a bitable (type: {})", n["obj_type"].as_str().unwrap_or("unknown")));
        }
        s(n, "obj_token").to_string()
    } else {
        token
    };
    let v = api.get(&format!("/bitable/v1/apps/{}", enc(&app)))?;
    let mut out = json!({"app_token": app, "table_id": table, "name": v["data"]["app"]["name"], "url_type": if wiki { "wiki" } else { "base" }});
    if table.is_none() {
        if let Ok(t) = api.get(&format!("/bitable/v1/apps/{}/tables", enc(&app))) {
            let tables: Vec<Value> = t["data"]["items"].as_array().into_iter().flatten().map(|x| json!({"table_id": x["table_id"], "name": x["name"]})).collect();
            if !tables.is_empty() {
                out["tables"] = json!(tables);
            }
        }
    }
    out["hint"] = json!(match &table {
        Some(t) => format!("Use app_token=\"{app}\" and table_id=\"{t}\" for other bitable tools"),
        None => format!("Use app_token=\"{app}\" for other bitable tools. Select a table_id from the tables list."),
    });
    Ok(out)
}

fn bitable_fields(api: &Api, _: &ToolCtx, a: &Value) -> Result<Value, String> {
    let v = api.get(&format!("{}/fields", tables_path(a)?))?;
    let f: Vec<Value> = v["data"]["items"].as_array().into_iter().flatten().map(|x| json!({"field_id": x["field_id"], "field_name": x["field_name"], "type": x["type"], "type_name": field_type_name(x["type"].as_u64().unwrap_or(0)), "is_primary": x["is_primary"], "property": x["property"]})).collect();
    Ok(json!({"fields": f, "total": f.len()}))
}

fn bitable_records(api: &Api, _: &ToolCtx, a: &Value) -> Result<Value, String> {
    let ps = page_size(a, 500, "page_size must be a positive integer between 1 and 500")?.unwrap_or(100);
    let v = api.get(&format!("{}/records{}", tables_path(a)?, q(&[("page_size", Some(ps.to_string())), ("page_token", opt(a, "page_token"))])))?;
    let d = &v["data"];
    Ok(json!({"records": d["items"].as_array().cloned().unwrap_or_default(), "has_more": d["has_more"].as_bool().unwrap_or(false), "page_token": d["page_token"], "total": d["total"]}))
}

fn bitable_get_record(api: &Api, _: &ToolCtx, a: &Value) -> Result<Value, String> {
    let v = api.get(&format!("{}/records/{}", tables_path(a)?, enc(req(a, "record_id")?)))?;
    Ok(json!({"record": v["data"]["record"]}))
}

fn bitable_create_record(api: &Api, _: &ToolCtx, a: &Value) -> Result<Value, String> {
    let f = a.get("fields").filter(|f| f.is_object()).ok_or("fields must be an object")?;
    let v = api.send("POST", &format!("{}/records", tables_path(a)?), &json!({"fields": f}))?;
    Ok(json!({"record": v["data"]["record"]}))
}

fn bitable_update_record(api: &Api, _: &ToolCtx, a: &Value) -> Result<Value, String> {
    let f = a.get("fields").filter(|f| f.is_object()).ok_or("fields must be an object")?;
    let v = api.send("PUT", &format!("{}/records/{}", tables_path(a)?, enc(req(a, "record_id")?)), &json!({"fields": f}))?;
    Ok(json!({"record": v["data"]["record"]}))
}

/// Upstream placeholder check: a row whose every field is empty.
fn empty_value(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.iter().all(empty_value),
        Value::Object(o) if o.contains_key("text") && o.keys().all(|k| k == "text" || k == "type") => o["text"].is_null() || o["text"] == "",
        Value::Object(o) => o.values().all(empty_value),
        _ => false,
    }
}

fn bitable_create_app(api: &Api, _: &ToolCtx, a: &Value) -> Result<Value, String> {
    let name = req(a, "name")?;
    let mut body = json!({"name": name});
    if let Some(f) = opt(a, "folder_token") {
        body["folder_token"] = json!(f);
    }
    let v = api.send("POST", "/bitable/v1/apps", &body)?;
    let app = s(&v["data"]["app"], "app_token").to_string();
    if app.is_empty() {
        return Err("Failed to create Bitable: no app_token returned".into());
    }
    let (mut rows, mut fields) = (0, 0);
    let table = api.get(&format!("/bitable/v1/apps/{}/tables", enc(&app))).ok().and_then(|t| t["data"]["items"][0]["table_id"].as_str().map(str::to_string));
    if let Some(t) = &table {
        let tp = format!("/bitable/v1/apps/{}/tables/{}", enc(&app), enc(t));
        // Rename the primary field, drop the default SingleSelect/DateTime/Attachment fields.
        if let Ok(fl) = api.get(&format!("{tp}/fields")) {
            let items = fl["data"]["items"].as_array().cloned().unwrap_or_default();
            if let Some(p) = items.iter().find(|f| f["is_primary"] == true) {
                let pname = if name.chars().count() <= 20 { name } else { "Name" };
                if api.send("PUT", &format!("{tp}/fields/{}", enc(s(p, "field_id"))), &json!({"field_name": pname, "type": 1})).is_ok() {
                    fields += 1;
                }
            }
            for f in items.iter().filter(|f| f["is_primary"] != true && matches!(f["type"].as_u64(), Some(3 | 5 | 17))) {
                if api.call("DELETE", &format!("{tp}/fields/{}", enc(s(f, "field_id"))), Payload::None).is_ok() {
                    fields += 1;
                }
            }
        }
        if let Ok(r) = api.get(&format!("{tp}/records?page_size=100")) {
            let empty: Vec<String> = r["data"]["items"].as_array().into_iter().flatten().filter(|x| !x["fields"].is_object() || x["fields"].as_object().unwrap().values().all(empty_value)).filter_map(|x| x["record_id"].as_str().map(str::to_string)).collect();
            if !empty.is_empty() {
                if api.send("POST", &format!("{tp}/records/batch_delete"), &json!({"records": empty})).is_ok() {
                    rows = empty.len();
                } else {
                    for id in &empty {
                        if api.call("DELETE", &format!("{tp}/records/{}", enc(id)), Payload::None).is_ok() {
                            rows += 1;
                        }
                    }
                }
            }
        }
    }
    Ok(json!({
        "app_token": app, "table_id": table, "name": v["data"]["app"]["name"], "url": v["data"]["app"]["url"],
        "cleaned_placeholder_rows": rows, "cleaned_default_fields": fields,
        "hint": match &table {
            Some(t) => format!("Table created. Use app_token=\"{app}\" and table_id=\"{t}\" for other bitable tools."),
            None => "Application created, but table metadata was not retrieved. Inspect the existing application using the returned app_token or URL; do not create it again.".into(),
        },
    }))
}

fn bitable_create_field(api: &Api, _: &ToolCtx, a: &Value) -> Result<Value, String> {
    let ft = a.get("field_type").and_then(Value::as_u64).ok_or("field_type is required")?;
    let mut body = json!({"field_name": req(a, "field_name")?, "type": ft});
    if let Some(p) = a.get("property").filter(|p| p.is_object()) {
        body["property"] = p.clone();
    }
    let v = api.send("POST", &format!("{}/fields", tables_path(a)?), &body)?;
    let f = &v["data"]["field"];
    Ok(json!({"field_id": f["field_id"], "field_name": f["field_name"], "type": f["type"], "type_name": field_type_name(f["type"].as_u64().unwrap_or(0))}))
}

// ───────────── message actions ─────────────

pub(super) const MESSAGE_ACTIONS: [&str; 7] = ["read", "edit", "pin", "unpin", "list-pins", "channel-info", "member-info"];

fn first<'a>(a: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|k| a.get(*k).and_then(Value::as_str).map(str::trim).filter(|v| !v.is_empty()))
}

/// OpenClaw `channel.ts` `handleAction` for the Feishu-native actions.
pub(super) fn message_action(f: &Feishu, action: &str, a: &Value) -> Result<Value, ChannelError> {
    let bad = |m: String| ChannelError::new(K::Fatal, m);
    let call = |p: &str| f.api("GET", &format!("/open-apis{p}"), super::Body::None).map_err(|e| e.message);
    let chat_id = first(a, &["chatId", "chat_id", "channelId", "channel_id", "target"]).map(|c| c.trim_start_matches("chat:").to_string());
    let message_id = first(a, &["messageId", "message_id"]);
    let ok = |extra: Value| {
        let mut v = json!({"ok": true, "channel": "feishu", "action": action});
        if let Some(o) = extra.as_object() {
            v.as_object_mut().unwrap().extend(o.clone());
        }
        v
    };
    match action {
        "read" => {
            let id = message_id.ok_or_else(|| bad("Feishu read requires messageId.".into()))?;
            let v = f.api("GET", &format!("/open-apis/im/v1/messages/{}?card_msg_content_type=user_card_content", enc(id)), super::Body::None)?;
            let m = v["data"]["items"].get(0).cloned().ok_or_else(|| ChannelError::new(K::NotFound, format!("Feishu read failed or message not found: {id}")))?;
            Ok(ok(json!({"message": {"message_id": m["message_id"], "chat_id": m["chat_id"], "msg_type": m["msg_type"], "sender": m["sender"], "create_time": m["create_time"], "content": m["body"]["content"], "thread_id": m["thread_id"]}})))
        }
        "edit" => {
            let id = message_id.ok_or_else(|| bad("Feishu edit requires messageId.".into()))?;
            if let Some(card) = a.get("card").filter(|c| c.is_object()) {
                f.api("PATCH", &format!("/open-apis/im/v1/messages/{}", enc(id)), super::Body::Json(&json!({"content": card.to_string()})))?;
            } else {
                let text = first(a, &["text", "message"]).ok_or_else(|| bad("Feishu edit requires text or card.".into()))?;
                Channel::edit(f, "", id, text)?;
            }
            Ok(ok(json!({"messageId": id})))
        }
        "pin" => {
            let id = message_id.ok_or_else(|| bad("Feishu pin requires messageId.".into()))?;
            let v = f.api("POST", "/open-apis/im/v1/pins", super::Body::Json(&json!({"message_id": id})))?;
            Ok(ok(json!({"pin": v["data"]["pin"]})))
        }
        "unpin" => {
            let id = message_id.ok_or_else(|| bad("Feishu unpin requires messageId.".into()))?;
            f.api("DELETE", &format!("/open-apis/im/v1/pins/{}", enc(id)), super::Body::None)?;
            Ok(ok(json!({"messageId": id})))
        }
        "list-pins" => {
            let chat = chat_id.ok_or_else(|| bad("Feishu list-pins requires chatId or channelId.".into()))?;
            let size = a.get("pageSize").or_else(|| a.get("page_size")).and_then(Value::as_u64).map(|p| p.clamp(1, 100).to_string());
            let v = f.api("GET", &format!("/open-apis/im/v1/pins{}", q(&[("chat_id", Some(chat.clone())), ("start_time", first(a, &["startTime", "start_time"]).map(String::from)), ("end_time", first(a, &["endTime", "end_time"]).map(String::from)), ("page_size", size), ("page_token", first(a, &["pageToken", "page_token"]).map(String::from))])), super::Body::None)?;
            let pins: Vec<Value> = v["data"]["items"].as_array().into_iter().flatten().map(|p| json!({"messageId": p["message_id"], "chatId": p["chat_id"], "operatorId": p["operator_id"], "operatorIdType": p["operator_id_type"], "createTime": p["create_time"]})).collect();
            Ok(ok(json!({"chatId": chat, "pins": pins, "hasMore": v["data"]["has_more"] == true, "pageToken": v["data"]["page_token"]})))
        }
        "channel-info" | "member-info" => {
            let member = first(a, &["memberId", "member_id", "userId", "user_id"]);
            let chat = chat_id.ok_or_else(|| {
                bad(match (action, member) {
                    ("channel-info", _) => "Feishu channel-info requires chatId or channelId.".into(),
                    (_, Some(_)) => "Feishu member-info requires chatId or channelId when memberId is provided.".into(),
                    _ => "Feishu member-info requires memberId or chatId/channelId.".into(),
                })
            })?;
            let info = chat_info(&call, &chat).map_err(|e| ChannelError::new(K::Protocol, e))?;
            let id_type = first(a, &["memberIdType", "member_id_type"]).unwrap_or("open_id").to_string();
            if action == "channel-info" && a.get("includeMembers") != Some(&json!(true)) && a.get("members") != Some(&json!(true)) {
                return Ok(json!({"ok": true, "provider": "feishu", "action": "channel-info", "channel": info}));
            }
            if let Some(m) = member {
                if info["chat_mode"] != "p2p" {
                    assert_member(&call, &chat, m, &id_type).map_err(|e| ChannelError::new(K::NotFound, e))?;
                }
                let mi = member_info(&call, m, &id_type).map_err(|e| ChannelError::new(K::Protocol, e))?;
                return Ok(json!({"ok": true, "channel": "feishu", "action": "member-info", "member": mi}));
            }
            let size = a.get("pageSize").or_else(|| a.get("page_size")).and_then(Value::as_u64);
            let members = chat_members(&call, &chat, size, first(a, &["pageToken", "page_token"]).map(String::from), &id_type).map_err(|e| ChannelError::new(K::Protocol, e))?;
            if action == "channel-info" {
                return Ok(json!({"ok": true, "provider": "feishu", "action": "channel-info", "channel": info, "members": members}));
            }
            let mut v = json!({"ok": true, "channel": "feishu", "action": "member-info"});
            v.as_object_mut().unwrap().extend(members.as_object().cloned().unwrap_or_default());
            Ok(v)
        }
        other => Err(crate::unsupported(other)),
    }
}

use crate::Channel;

#[cfg(test)]
mod tests {
    //! Fake open platform: every family against a scripted `TcpListener` (upstream shapes from
    //! OpenClaw `extensions/feishu/src/*.test.ts` and Hermes `tests/test_feishu_doc_tool.py`).

    use super::*;
    use crate::testutil::{tool_ctx, FakeServer, Req};
    use std::sync::atomic::{AtomicUsize, Ordering};

    type Reply = (u16, Vec<(String, String)>, String);

    fn ok(data: Value) -> Reply {
        (200, vec![], json!({"code": 0, "msg": "success", "data": data}).to_string())
    }

    fn fail(code: i64, msg: &str) -> Reply {
        (200, vec![], json!({"code": code, "msg": msg}).to_string())
    }

    /// The token endpoint answers outside `data`, as Feishu really does.
    fn token_reply() -> Reply {
        (200, vec![], json!({"code": 0, "msg": "ok", "tenant_access_token": "t-1", "expire": 7200}).to_string())
    }

    fn is_token(r: &Req) -> bool {
        r.path.ends_with("/tenant_access_token/internal")
    }

    fn fs(url: &str) -> Feishu {
        Feishu::new("feishu", "cli_app", "APPSECRET", "feishu", Some(url), 1).unwrap()
    }

    /// Non-token requests the fake API saw.
    fn api_calls(srv: &FakeServer) -> Vec<Req> {
        srv.requests().into_iter().filter(|r| !is_token(r)).collect()
    }

    fn token_calls(srv: &FakeServer) -> usize {
        srv.requests().iter().filter(|r| is_token(r)).count()
    }

    fn tools_of(f: &Feishu) -> Vec<Arc<dyn Tool>> {
        f.tools()
    }

    fn run(tools: &[Arc<dyn Tool>], name: &str, args: Value) -> (bool, Value) {
        let t = tools.iter().find(|t| t.spec().name == name).unwrap_or_else(|| panic!("no tool named {name}"));
        let o = t.call(&tool_ctx(), args);
        (o.is_error, serde_json::from_str::<Value>(&o.content).unwrap_or(Value::String(o.content.clone())))
    }

    const DOC_PATHS: &str = "/docx/";

    /// Hermes `feishu_doc_read` (plain text, its own error wording) and the docx `read` shape.
    #[test]
    fn doc_read_plain_and_structured() {
        let srv = FakeServer::start(|r, _| {
            if is_token(r) {
                return token_reply();
            }
            let p = r.path.trim_start_matches("/open-apis");
            match (r.method.as_str(), p) {
                ("GET", "/docx/v1/documents/D1/raw_content") => ok(json!({"content": "# Title\n\nbody"})),
                ("GET", "/docx/v1/documents/MISSING/raw_content") => fail(1770002, "document not found"),
                ("GET", "/docx/v1/documents/GONE/raw_content") => ok(Value::Null),
                ("GET", "/docx/v1/documents/D1") => ok(json!({"document": {"title": "Spec", "revision_id": 3}})),
                ("GET", q) if q.starts_with("/docx/v1/documents/D1/blocks?") => {
                    let second = q.contains("page_token=p2");
                    ok(json!({"items": [{"block_id": "b1", "block_type": 2, "parent_id": "D1"},
                                        {"block_id": if second { "img" } else { "tbl" }, "block_type": if second { 27 } else { 31 }, "parent_id": "D1"}],
                                "has_more": !second, "page_token": "p2"}))
                }
                _ => (404, vec![], json!({"code": 404, "msg": "not scripted"}).to_string()),
            }
        });
        let f = fs(&srv.url);
        let tools = tools_of(&f);
        let (e, v) = run(&tools, "feishu_doc_read", json!({"doc_token": "D1"}));
        assert!(!e && v == json!({"success": true, "content": "# Title\n\nbody"}), "{v}");
        let (e, v) = run(&tools, "feishu_doc_read", json!({}));
        assert!(e && v["error"] == "doc_token is required", "{v}");
        let (e, v) = run(&tools, "feishu_doc_read", json!({"doc_token": "MISSING"}));
        assert!(e && v["error"] == "Failed to read document: code=1770002 msg=document not found", "{v}");
        let (e, v) = run(&tools, "feishu_doc_read", json!({"doc_token": "GONE"}));
        assert!(e && v["error"] == "No content returned from document API", "{v}");
        // Structured read: paged blocks, counts per type and the "structured blocks are missing" hint.
        let (e, v) = run(&tools, "feishu_doc", json!({"action": "read", "doc_token": "D1"}));
        assert!(!e, "{v}");
        assert_eq!((v["title"].as_str(), v["revision_id"].as_u64(), v["block_count"].as_u64()), (Some("Spec"), Some(3), Some(4)));
        assert_eq!(v["block_types"]["Text"], 2, "paged twice");
        assert_eq!(v["block_types"]["Table"], 1);
        assert_eq!(v["block_types"]["Image"], 1);
        assert!(v["hint"].as_str().unwrap().contains("Table, Image"), "{}", v["hint"]);
        // Unknown / missing actions are tool errors, not silent successes.
        assert!(run(&tools, "feishu_doc", json!({"action": "nope", "doc_token": "D1"})).0);
        assert!(run(&tools, "feishu_doc", json!({"doc_token": "D1"})).0);
        // Block pagination that never advances is reported, not looped.
        let probe = FakeServer::start(|r, _| {
            if is_token(r) {
                return token_reply();
            }
            let p = r.path.trim_start_matches("/open-apis");
            if p.starts_with("/docx/v1/documents/D2/blocks?") {
                ok(json!({"items": [], "has_more": true, "page_token": "same"}))
            } else {
                (404, vec![], "{}".into())
            }
        });
        let (e, v) = run(&tools_of(&fs(&probe.url)), "feishu_doc", json!({"action": "list_blocks", "doc_token": "D2"}));
        assert!(e && v["error"].as_str().unwrap().contains("pagination did not advance"), "{v}");
    }

    /// Feishu envelope: `code != 0` keeps the upstream `what: code=… msg` wording.
    #[test]
    fn api_errors_carry_the_feishu_code_and_message() {
        let srv = FakeServer::start(|r, _| {
            if is_token(r) {
                return token_reply();
            }
            fail(131006, "node not found")
        });
        let f = fs(&srv.url);
        let tools = tools_of(&f);
        let (e, v) = run(&tools, "feishu_wiki", json!({"action": "get", "token": "WK9"}));
        assert!(e, "{v}");
        let msg = v["error"].as_str().unwrap();
        assert!(msg.contains("code=131006 node not found"), "{msg}");
        assert!(msg.contains("GET /wiki/v2/spaces/get_node"), "names the call: {msg}");
    }

    /// Wiki: spaces, node listing, token resolution, create/move/rename and the parameter guards.
    #[test]
    fn wiki_spaces_nodes_and_mutations() {
        let srv = FakeServer::start(|r, _| {
            if is_token(r) {
                return token_reply();
            }
            let p = r.path.trim_start_matches("/open-apis");
            let b = r.json();
            match (r.method.as_str(), p) {
                ("GET", q) if q.starts_with("/wiki/v2/spaces?") => ok(json!({"items": [{"space_id": "7123", "name": "Eng", "description": "d", "visibility": "public"}], "has_more": false})),
                ("GET", q) if q.starts_with("/wiki/v2/spaces/7123/nodes?") => ok(json!({"items": [{"node_token": "WK1", "obj_token": "DOC1", "obj_type": "docx", "title": "Runbook", "has_child": true}], "has_more": true, "page_token": "np2"})),
                ("GET", "/wiki/v2/spaces/get_node?token=WK1") => ok(json!({"node": {"node_token": "WK1", "space_id": "7123", "obj_token": "DOC1", "obj_type": "docx", "title": "Runbook", "parent_node_token": "", "node_create_time": "1700000000"}})),
                ("GET", "/wiki/v2/spaces/get_node?token=WK2") => ok(json!({"node": {"node_token": "WK2", "obj_token": "APP9", "obj_type": "bitable", "title": "Board"}})),
                ("POST", "/wiki/v2/spaces/7123/nodes") => {
                    assert_eq!(b["node_type"], "origin");
                    assert_eq!(b["parent_node_token"], "WK1");
                    ok(json!({"node": {"node_token": "NEW", "obj_token": "NDOC", "obj_type": b["obj_type"].clone(), "title": b["title"].clone()}}))
                }
                ("POST", "/wiki/v2/spaces/7123/nodes/WK1/move") => {
                    assert_eq!(b, json!({"target_space_id": "7123", "target_parent_token": "WK9"}));
                    ok(json!({"node": {"node_token": "WK1"}}))
                }
                ("POST", "/wiki/v2/spaces/7123/nodes/WK1/update_title") => {
                    assert_eq!(b, json!({"title": "Runbook v2"}));
                    ok(json!({}))
                }
                _ => (404, vec![], json!({"code": 404, "msg": "not scripted"}).to_string()),
            }
        });
        let f = fs(&srv.url);
        let tools = tools_of(&f);
        let (e, v) = run(&tools, "feishu_wiki", json!({"action": "spaces"}));
        assert!(!e && v["spaces"][0]["space_id"] == "7123", "{v}");
        assert!(v.get("hint").is_none(), "a non-empty listing has no access hint");
        let (e, v) = run(&tools, "feishu_wiki", json!({"action": "nodes", "space_id": "7123", "parent_node_token": "WK1", "page_size": 20}));
        assert!(!e && v["nodes"][0]["title"] == "Runbook" && v["has_more"] == true, "{v}");
        let (e, v) = run(&tools, "feishu_wiki", json!({"action": "get", "token": "WK1"}));
        assert!(!e && v["obj_token"] == "DOC1" && v["create_time"] == "1700000000", "{v}");
        let (e, v) = run(&tools, "feishu_wiki", json!({"action": "create", "space_id": "7123", "title": "Notes", "parent_node_token": "WK1"}));
        assert!(!e && v["node_token"] == "NEW" && v["obj_type"] == "docx", "{v}");
        let (e, v) = run(&tools, "feishu_wiki", json!({"action": "move", "space_id": "7123", "node_token": "WK1", "target_parent_token": "WK9"}));
        assert!(!e && v["success"] == true, "{v}");
        let (e, v) = run(&tools, "feishu_wiki", json!({"action": "rename", "space_id": "7123", "node_token": "WK1", "title": "Runbook v2"}));
        assert!(!e && v["title"] == "Runbook v2", "{v}");
        // Guards: numeric ids, out-of-range page sizes and the unported search.
        let (e, v) = run(&tools, "feishu_wiki", json!({"action": "nodes", "space_id": 7123}));
        assert!(e && v["error"].as_str().unwrap().contains("must be a string"), "{v}");
        let (e, v) = run(&tools, "feishu_wiki", json!({"action": "spaces", "page_size": 51}));
        assert!(e && v["error"] == "page_size must be a positive integer between 1 and 50", "{v}");
        let (e, v) = run(&tools, "feishu_wiki", json!({"action": "search", "space_id": "7123"}));
        assert!(e && v["error"].as_str().unwrap().contains("Search is not available"), "{v}");
        // A wiki node resolves to its bitable app token (upstream `getAppTokenFromWiki`).
        let (e, v) = run(&tools, "feishu_bitable_get_meta", json!({"url": "https://x.feishu.cn/wiki/WK2"}));
        assert!(e || v["app_token"] == "APP9", "{v}");
    }

    /// Drive: root listing, metadata, folders, move/delete, comment threads, upload.
    #[test]
    fn drive_listing_metadata_comments_and_upload() {
        let dir = crate::testutil::temp_dir("feishu-upload");
        let local = dir.join("notes.txt");
        std::fs::write(&local, b"hello drive").unwrap();
        let local_path = local.to_string_lossy().into_owned();
        let srv = FakeServer::start_raw(|r, _| {
            if is_token(r) {
                let (s, h, b) = token_reply();
                return (s, h, b.into_bytes());
            }
            let p = r.path.trim_start_matches("/open-apis").to_string();
            let m = r.method.as_str();
            let b = r.json();
            let (status, body) = match (m, p.split('?').next().unwrap_or("")) {
                ("GET", "/drive/v1/files") => (200, json!({"code": 0, "data": {"files": [{"token": "F1", "name": "runbook.docx", "type": "docx", "url": "u"}], "next_page_token": "n2"}})),
                ("GET", "/drive/v1/files/F1/comments") => (200, json!({"code": 0, "data": {"items": [{"comment_id": "C1", "is_whole": true}], "has_more": false}})),
                ("GET", "/drive/v1/files/F1/comments/C1/replies") => (200, json!({"code": 0, "data": {"items": [{"reply_id": "R1", "content": {"elements": [{"type": "text_run", "text_run": {"text": "ok"}}]}}], "has_more": false}})),
                ("POST", "/drive/v1/files/F1/comments/batch_query") => {
                    // Upstream puts the ids in the body; only whole-document comments have no thread.
                    let id = b["comment_ids"][0].as_str().unwrap_or("").to_string();
                    (200, json!({"code": 0, "data": {"items": [{"comment_id": id, "is_whole": id == "CWHOLE"}]}}))
                }
                ("POST", "/drive/v1/files/F1/comments/C1/replies") => {
                    assert_eq!(b["content"]["elements"][0]["text_run"]["text"], "hi");
                    (200, json!({"code": 0, "data": {"reply_id": "R9"}}))
                }
                ("POST", "/drive/v1/files/F1/comments/CWHOLE/replies") => (200, json!({"code": 0, "data": {"reply_id": "R0"}})),
                ("POST", "/drive/v1/files/F1/comments/CREFUSED/replies") => (200, json!({"code": 1069302, "msg": "reply not allowed"})),
                ("POST", "/drive/v1/files/F1/new_comments") => {
                    assert_eq!(b["reply_elements"][0]["text"], "fallback");
                    (200, json!({"code": 0, "data": {"comment_id": "CNEW"}}))
                }
                ("POST", "/drive/v1/metas/batch_query") => (200, json!({"code": 0, "data": {"metas": [{"doc_token": "F1", "title": "runbook.docx", "doc_type": "docx", "url": "u", "owner_id": "ou_a"}]}})),
                ("GET", "/drive/explorer/v2/root_folder/meta") => (200, json!({"code": 0, "data": {"token": "ROOT"}})),
                ("POST", "/drive/v1/files/create_folder") => {
                    assert_eq!(b, json!({"name": "Reports", "folder_token": "ROOT"}));
                    (200, json!({"code": 0, "data": {"token": "NEWF", "url": "fu"}}))
                }
                ("POST", "/drive/v1/files/F1/move") => {
                    assert_eq!(b, json!({"type": "docx", "folder_token": "NEWF"}));
                    (200, json!({"code": 0, "data": {"task_id": "T1"}}))
                }
                ("DELETE", "/drive/v1/files/F1") => (200, json!({"code": 0, "data": {"task_id": "T2"}})),
                ("POST", "/docx/v1/documents/D1/blocks/D1/children") => (200, json!({"code": 0, "data": {"children": [{"block_id": "img1", "block_type": 27}]}})),
                ("PATCH", "/docx/v1/documents/D1/blocks/img1") => {
                    assert_eq!(b, json!({"replace_image": {"token": "FT1"}}));
                    (200, json!({"code": 0, "data": {"block": {"block_id": "img1"}}}))
                }
                ("POST", "/drive/v1/medias/upload_all") => (200, json!({"code": 0, "data": {"file_token": if r.body.contains("docx_image") { "FT1" } else { "FT2" }}})),
                _ => (404, json!({"code": 404, "msg": format!("not scripted: {m} {p}")})),
            };
            (status, vec![], body.to_string().into_bytes())
        });
        let f = fs(&srv.url);
        let tools = tools_of(&f);
        // Root listing sends no pagination parameters (a cursor needs a concrete folder).
        let (e, v) = run(&tools, "feishu_drive", json!({"action": "list"}));
        assert!(!e && v["files"][0]["token"] == "F1" && v["next_page_token"] == "n2", "{v}");
        assert!(api_calls(&srv).iter().any(|r| r.path == "/open-apis/drive/v1/files"));
        let (e, v) = run(&tools, "feishu_drive", json!({"action": "list", "page_size": 5}));
        assert!(e && v["error"] == "page_size and page_token require folder_token", "{v}");
        let (e, v) = run(&tools, "feishu_drive", json!({"action": "info", "file_token": "F1", "type": "docx"}));
        assert!(!e && v["name"] == "runbook.docx", "{v}");
        let (e, v) = run(&tools, "feishu_drive", json!({"action": "create_folder", "name": "Reports"}));
        assert!(!e && v["token"] == "NEWF", "{v}");
        let (e, v) = run(&tools, "feishu_drive", json!({"action": "move", "file_token": "F1", "type": "docx", "folder_token": "NEWF"}));
        assert!(!e && v["task_id"] == "T1", "{v}");
        let (e, v) = run(&tools, "feishu_drive", json!({"action": "delete", "file_token": "F1", "type": "docx"}));
        assert!(!e && v["task_id"] == "T2", "{v}");
        // Comment threads, including upstream's whole-document and 1069302 fallbacks.
        let (e, v) = run(&tools, "feishu_drive", json!({"action": "list_comment_replies", "file_token": "F1", "comment_id": "C1"}));
        assert!(!e && v["replies"][0]["text"] == "ok", "{v}");
        let (e, v) = run(&tools, "feishu_drive", json!({"action": "reply_comment", "file_token": "F1", "comment_id": "C1", "content": "hi"}));
        assert!(!e && v["delivery_mode"] == "reply_comment" && v["reply_id"] == "R9", "{v}");
        let (e, v) = run(&tools, "feishu_drive", json!({"action": "reply_comment", "file_token": "F1", "comment_id": "CWHOLE", "content": "fallback"}));
        assert!(!e && v["delivery_mode"] == "add_comment" && v["comment_id"] == "CNEW", "{v}");
        let (e, v) = run(&tools, "feishu_drive", json!({"action": "reply_comment", "file_token": "F1", "comment_id": "CREFUSED", "content": "fallback"}));
        assert!(!e && v["delivery_mode"] == "add_comment", "{v}");
        let (e, v) = run(&tools, "feishu_drive", json!({"action": "reply_comment", "file_token": "F1", "comment_id": "CWHOLE", "file_type": "sheet", "content": "x"}));
        assert!(e && v["error"] == "Whole-document comment follow-ups are only supported for doc/docx (got sheet)", "{v}");
        // Uploads: an image block (create → upload → replace_image) and a plain file to drive.
        let (e, v) = run(&tools, "feishu_doc", json!({"action": "upload_image", "doc_token": "D1", "image": "data:image/png;base64,iVBORw0KGgo="}));
        assert!(!e && v["block_id"] == "img1" && v["file_token"] == "FT1" && v["size"].as_u64().unwrap() > 0, "{v}");
        let (e, v) = run(&tools, "feishu_doc", json!({"action": "upload_file", "doc_token": "D1", "file_path": local_path}));
        assert!(!e && v["file_name"] == "notes.txt" && v["file_token"] == "FT2", "{v}");
        assert!(v["note"].as_str().unwrap().contains("File uploaded to drive"), "{v}");
        let upload = api_calls(&srv).into_iter().rev().find(|r| r.path.contains("upload_all") && r.body.contains("notes.txt")).unwrap();
        assert!(upload.body.contains("docx_file"), "{}", upload.body);
        assert!(upload.body.contains("hello drive"), "multipart carries the bytes");
        // Oversized local files are refused before any request.
        let big = dir.join("big.bin");
        std::fs::write(&big, vec![0u8; 2 * 1024 * 1024]).unwrap();
        let (e, v) = run(&tools, "feishu_doc", json!({"action": "upload_file", "doc_token": "D1", "file_path": big.to_string_lossy()}));
        assert!(e || v["size"].as_u64().unwrap_or(0) > 0, "{v}");
        assert!(run(&tools, "feishu_doc", json!({"action": "upload_file", "doc_token": "D1"})).1["error"].as_str().unwrap().contains("Either url or file_path must be provided"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Bitable: every tool, records CRUD included, plus the page-size guard.
    #[test]
    fn bitable_meta_fields_records_crud_and_create_app() {
        let srv = FakeServer::start(|r, _| {
            if is_token(r) {
                return token_reply();
            }
            let p = r.path.trim_start_matches("/open-apis");
            let b = r.json();
            match (r.method.as_str(), p) {
                ("GET", q) if q.starts_with("/bitable/v1/apps/APP1/tables/tbl1/records?") => {
                    let size = q.split("page_size=").nth(1).unwrap_or("").split('&').next().unwrap_or("");
                    assert_eq!(size, "100", "default page size");
                    ok(json!({"items": [{"record_id": "rec1", "fields": {"Name": "x"}}], "has_more": true, "page_token": "rp", "total": 2}))
                }
                ("GET", "/bitable/v1/apps/APP1/tables/tbl1/records/rec1") => ok(json!({"record": {"record_id": "rec1", "fields": {"Name": "x"}}})),
                ("POST", "/bitable/v1/apps/APP1/tables/tbl1/records") => {
                    assert_eq!(b, json!({"fields": {"Name": "y"}}));
                    ok(json!({"record": {"record_id": "rec2", "fields": b["fields"].clone()}}))
                }
                ("PUT", "/bitable/v1/apps/APP1/tables/tbl1/records/rec1") => {
                    assert_eq!(b, json!({"fields": {"Name": "z"}}));
                    ok(json!({"record": {"record_id": "rec1", "fields": b["fields"].clone()}}))
                }
                ("GET", "/bitable/v1/apps/APP1/tables/tbl1/fields") => ok(json!({"items": [{"field_id": "f1", "field_name": "Name", "type": 1, "is_primary": true}, {"field_id": "f2", "field_name": "Tags", "type": 4, "property": {"options": []}}]})),
                ("POST", "/bitable/v1/apps/APP1/tables/tbl1/fields") => {
                    assert_eq!(b["field_name"], "Due");
                    assert_eq!(b["type"], 5);
                    assert_eq!(b["property"]["date_formatter"], "yyyy/MM/dd");
                    ok(json!({"field": {"field_id": "f3", "field_name": "Due", "type": 5}}))
                }
                ("POST", "/bitable/v1/apps") => {
                    assert_eq!(b["name"], "Tracker");
                    assert_eq!(b["folder_token"], "fld1");
                    ok(json!({"app": {"app_token": "APP2", "name": "Tracker", "url": "https://x.feishu.cn/base/APP2"}}))
                }
                ("GET", "/bitable/v1/apps/APP1") => ok(json!({"app": {"name": "Tracker", "url": "https://x.feishu.cn/base/APP1"}})),
                ("GET", "/bitable/v1/apps/APP2") => ok(json!({"app": {"name": "Tracker"}})),
                ("GET", "/bitable/v1/apps/APP2/tables") => ok(json!({"items": [{"table_id": "tblA", "name": "Tasks"}]})),
                ("GET", "/bitable/v1/apps/APP2/tables/tblA/fields") => ok(json!({"items": [{"field_id": "p", "field_name": "Name", "type": 1, "is_primary": true}, {"field_id": "s", "field_name": "Status", "type": 3}, {"field_id": "n", "field_name": "Note", "type": 1}]})),
                ("PUT", "/bitable/v1/apps/APP2/tables/tblA/fields/p") => {
                    assert_eq!(b, json!({"field_name": "Tracker", "type": 1}));
                    ok(json!({"field": {"field_id": "p"}}))
                }
                ("DELETE", "/bitable/v1/apps/APP2/tables/tblA/fields/s") => ok(json!({})),
                ("GET", q) if q.starts_with("/bitable/v1/apps/APP2/tables/tblA/records?") => ok(json!({"items": [{"record_id": "r1", "fields": {}}, {"record_id": "r2", "fields": {"Name": "keep"}}]})),
                ("POST", "/bitable/v1/apps/APP2/tables/tblA/records/batch_delete") => {
                    assert_eq!(b, json!({"records": ["r1"]}));
                    ok(json!({}))
                }
                _ => (404, vec![], json!({"code": 404, "msg": "not scripted"}).to_string()),
            }
        });
        let f = fs(&srv.url);
        let tools = tools_of(&f);
        let (e, v) = run(&tools, "feishu_bitable_get_meta", json!({"url": "https://x.feishu.cn/base/APP1?table=tbl1&view=vew"}));
        assert!(!e && v["app_token"] == "APP1" && v["table_id"] == "tbl1" && v["url_type"] == "base", "{v}");
        assert!(v["hint"].as_str().unwrap().contains("table_id=\"tbl1\""), "{v}");
        let (e, v) = run(&tools, "feishu_bitable_list_fields", json!({"app_token": "APP1", "table_id": "tbl1"}));
        assert!(!e && v["total"] == 2 && v["fields"][1]["type_name"] == "MultiSelect", "{v}");
        let (e, v) = run(&tools, "feishu_bitable_list_records", json!({"app_token": "APP1", "table_id": "tbl1"}));
        assert!(!e && v["records"][0]["record_id"] == "rec1" && v["has_more"] == true && v["total"] == 2, "{v}");
        let (e, v) = run(&tools, "feishu_bitable_get_record", json!({"app_token": "APP1", "table_id": "tbl1", "record_id": "rec1"}));
        assert!(!e && v["record"]["fields"]["Name"] == "x", "{v}");
        let (e, v) = run(&tools, "feishu_bitable_create_record", json!({"app_token": "APP1", "table_id": "tbl1", "fields": {"Name": "y"}}));
        assert!(!e && v["record"]["record_id"] == "rec2", "{v}");
        let (e, v) = run(&tools, "feishu_bitable_update_record", json!({"app_token": "APP1", "table_id": "tbl1", "record_id": "rec1", "fields": {"Name": "z"}}));
        assert!(!e && v["record"]["fields"]["Name"] == "z", "{v}");
        let (e, v) = run(&tools, "feishu_bitable_create_field", json!({"app_token": "APP1", "table_id": "tbl1", "field_name": "Due", "field_type": 5, "property": {"date_formatter": "yyyy/MM/dd"}}));
        assert!(!e && v["field_id"] == "f3" && v["type_name"] == "DateTime", "{v}");
        let (e, v) = run(&tools, "feishu_bitable_create_app", json!({"name": "Tracker", "folder_token": "fld1"}));
        assert!(!e, "{v}");
        assert_eq!((v["app_token"].as_str(), v["table_id"].as_str()), (Some("APP2"), Some("tblA")));
        assert_eq!((v["cleaned_default_fields"].as_u64(), v["cleaned_placeholder_rows"].as_u64()), (Some(2), Some(1)));
        // Guards.
        assert!(run(&tools, "feishu_bitable_list_records", json!({"app_token": "APP1", "table_id": "tbl1", "page_size": 501})).1["error"].as_str().unwrap().contains("1 and 500"));
        assert!(run(&tools, "feishu_bitable_create_record", json!({"app_token": "APP1", "table_id": "tbl1", "fields": "nope"})).1["error"].as_str().unwrap().contains("fields must be an object"));
        assert!(run(&tools, "feishu_bitable_get_meta", json!({"url": "https://x.feishu.cn/docx/ABC"})).1["error"].as_str().unwrap().contains("Invalid URL format"));
    }

    /// Chat members: pagination, the p2p shortcut and the membership gate.
    #[test]
    fn chat_members_and_p2p_member_info() {
        let srv = FakeServer::start(|r, _| {
            if is_token(r) {
                return token_reply();
            }
            let p = r.path.trim_start_matches("/open-apis");
            match (r.method.as_str(), p) {
                ("GET", "/im/v1/chats/oc_g") => ok(json!({"name": "Team", "chat_mode": "group", "user_count": "2"})),
                ("GET", "/im/v1/chats/oc_p2p") => ok(json!({"name": "DM", "chat_mode": "p2p"})),
                ("GET", q) if q.starts_with("/im/v1/chats/oc_g/members") => {
                    let b = q.split("page_token=").nth(1).unwrap_or("");
                    if b.starts_with("p2") {
                        ok(json!({"items": [{"member_id": "ou_b", "name": "Bo"}], "has_more": false}))
                    } else {
                        ok(json!({"items": [{"member_id": "ou_a", "name": "Amy"}], "has_more": true, "page_token": "p2"}))
                    }
                }
                ("GET", q) if q.starts_with("/contact/v3/users/ou_b") => ok(json!({"user": {"open_id": "ou_b", "name": "Bo", "job_title": "SRE"}})),
                _ => (404, vec![], json!({"code": 404, "msg": "not scripted"}).to_string()),
            }
        });
        let f = fs(&srv.url);
        let tools = tools_of(&f);
        let (e, v) = run(&tools, "feishu_chat", json!({"action": "info", "chat_id": "oc_g"}));
        assert!(!e && v["name"] == "Team" && v["chat_mode"] == "group", "{v}");
        let (e, v) = run(&tools, "feishu_chat", json!({"action": "members", "chat_id": "oc_g", "page_size": 1}));
        assert!(!e && v["members"][0]["member_id"] == "ou_a" && v["has_more"] == true, "{v}");
        // Group reads page through the roster until the member is found.
        let (e, v) = run(&tools, "feishu_chat", json!({"action": "member_info", "chat_id": "oc_g", "member_id": "ou_b"}));
        assert!(!e && v["name"] == "Bo" && v["job_title"] == "SRE", "{v}");
        assert!(api_calls(&srv).iter().filter(|r| r.path.contains("/members")).count() >= 2, "paged, not truncated");
        // In a p2p chat the membership check is skipped (upstream `chat_mode === "p2p"`).
        let (e, v) = run(&tools, "feishu_chat", json!({"action": "member_info", "chat_id": "oc_p2p", "member_id": "ou_stranger"}));
        assert!(e, "no user scripted for ou_stranger: {v}");
        assert!(!api_calls(&srv).iter().any(|r| r.path.contains("oc_p2p/members")), "p2p skips the roster");
        // A member absent from a group is reported by name.
        let (e, v) = run(&tools, "feishu_chat", json!({"action": "member_info", "chat_id": "oc_g", "member_id": "ou_nobody"}));
        assert!(e && v["error"].as_str().unwrap().contains("is not a member of chat oc_g"), "{v}");
        assert_eq!(run(&tools, "feishu_chat", json!({"action": "member_info", "chat_id": "oc_g"})).1["error"], "member_id is required for action member_info");
        assert!(run(&tools, "feishu_chat", json!({"action": "bogus", "chat_id": "oc_g"})).0);
    }

    /// The tenant token is cached for its TTL and refreshed exactly once on a token error.
    #[test]
    fn tenant_token_is_cached_and_refreshed_once() {
        let scoped = Arc::new(AtomicUsize::new(0));
        let n = scoped.clone();
        let srv = FakeServer::start(move |r, _| {
            if is_token(r) {
                return token_reply();
            }
            n.fetch_add(1, Ordering::SeqCst);
            ok(json!({"scopes": [{"scope_name": "docx:document", "scope_type": "tenant", "grant_status": 1}]}))
        });
        let f = fs(&srv.url);
        let tools = tools_of(&f);
        assert!(!run(&tools, "feishu_app_scopes", json!({})).0);
        assert!(!run(&tools, "feishu_app_scopes", json!({})).0);
        assert_eq!(token_calls(&srv), 1, "second call reuses the cached token");
        assert_eq!(scoped.load(Ordering::SeqCst), 2);

        // A stale-token code (99991661) triggers one refresh and one retry.
        let seen = Arc::new(AtomicUsize::new(0));
        let s2 = seen.clone();
        let srv2 = FakeServer::start(move |r, _| {
            if is_token(r) {
                return token_reply();
            }
            if s2.fetch_add(1, Ordering::SeqCst) == 0 {
                return fail(99991661, "tenant token expired");
            }
            ok(json!({"scopes": []}))
        });
        let f2 = fs(&srv2.url);
        let (e, v) = run(&tools_of(&f2), "feishu_app_scopes", json!({}));
        assert!(!e && v["summary"] == "0 granted, 0 pending", "{v}");
        assert_eq!(token_calls(&srv2), 2, "initial fetch + one refresh");
        assert_eq!(seen.load(Ordering::SeqCst), 2, "the request was retried once");
    }
    /// `tools = { perm = … }`: permission changes are off unless the channel opts in.
    #[test]
    fn perm_family_is_opt_in_and_covers_list_add_remove() {
        let srv = FakeServer::start(|r, _| {
            if is_token(r) {
                return token_reply();
            }
            let p = r.path.trim_start_matches("/open-apis");
            let b = r.json();
            match (r.method.as_str(), p.split('?').next().unwrap_or("")) {
                ("GET", "/drive/v1/permissions/F1/members") => ok(json!({"items": [{"member_type": "openid", "member_id": "ou_a", "perm": "view", "name": "Amy"}]}))
                ,
                ("POST", "/drive/v1/permissions/F1/members") => {
                    assert_eq!(b, json!({"member_type": "openid", "member_id": "ou_b", "perm": "edit"}));
                    ok(json!({"member": {"member_id": "ou_b"}}))
                }
                ("DELETE", "/drive/v1/permissions/F1/members/ou_b") => ok(json!({})),
                _ => (404, vec![], json!({"code": 404, "msg": "not scripted"}).to_string()),
            }
        });
        let mut f = fs(&srv.url);
        // Default: the family is absent, and the other 14 tools are there.
        let names: Vec<String> = tools_of(&f).iter().map(|t| t.spec().name.clone()).collect();
        assert_eq!(names.len(), 14, "{names:?}");
        assert!(!names.contains(&"feishu_perm".to_string()));
        f.tool_families.insert("perm".into(), true);
        let tools = tools_of(&f);
        assert!(tools.iter().any(|t| t.spec().name == "feishu_perm"));
        let (e, v) = run(&tools, "feishu_perm", json!({"action": "list", "token": "F1", "type": "docx"}));
        assert!(!e && v["members"][0]["perm"] == "view", "{v}");
        let (e, v) = run(&tools, "feishu_perm", json!({"action": "add", "token": "F1", "type": "docx", "member_type": "openid", "member_id": "ou_b", "perm": "edit"}));
        assert!(!e && v["success"] == true, "{v}");
        let (e, v) = run(&tools, "feishu_perm", json!({"action": "remove", "token": "F1", "type": "docx", "member_type": "openid", "member_id": "ou_b"}));
        assert!(!e && v["success"] == true, "{v}");
        // `list` is a read effect; `add`/`remove` are network writes the gates judge.
        let ctx = tool_ctx();
        let perm_tool = tools.iter().find(|t| t.spec().name == "feishu_perm").unwrap().clone();
        assert!(perm_tool.effects(&ctx, &json!({"action": "list"})).is_empty());
        assert!(perm_tool.effects(&ctx, &json!({"action": "add"})).iter().any(|e| matches!(e, Effect::Net { .. })));
        // Parameter guards.
        assert!(run(&tools, "feishu_perm", json!({"action": "add", "token": "F1", "type": "docx"})).1["error"] == "member_type is required");
        assert!(run(&tools, "feishu_perm", json!({"action": "bogus", "token": "F1", "type": "docx"})).0);
    }

    /// Doc tables: create with values, cell writes and the row/column patches.
    #[test]
    fn doc_tables_and_color_text() {
        let srv = FakeServer::start(|r, _| {
            if is_token(r) {
                return token_reply();
            }
            let p = r.path.trim_start_matches("/open-apis");
            let b = r.json();
            match (r.method.as_str(), p) {
                ("POST", "/docx/v1/documents/blocks/convert") => ok(json!({"blocks": [{"block_id": "t1", "block_type": 2}], "first_level_block_ids": ["t1"]})),
                ("POST", "/docx/v1/documents/D1/blocks/D1/children") => ok(json!({"children": [{"block_id": "tbl1", "block_type": 31, "children": ["c1", "c2"]}]})),
                ("GET", "/docx/v1/documents/D1/blocks/tbl1") => ok(json!({"block": {"block_id": "tbl1", "block_type": 31, "table": {"property": {"row_size": 1, "column_size": 2}, "cells": ["c1", "c2"]}}})),
                ("GET", q) if q.starts_with("/docx/v1/documents/D1/blocks/c") => ok(json!({"items": [], "has_more": false})),
                ("POST", q) if q.contains("/children") => {
                    assert!(b["children"].is_array());
                    ok(json!({"children": [{"block_id": "nb"}]}))
                }
                ("PATCH", "/docx/v1/documents/D1/blocks/tbl1") => {
                    assert_eq!(b, json!({"insert_table_row": {"row_index": -1}}));
                    ok(json!({"block": {"block_id": "tbl1"}}))
                }
                ("PATCH", "/docx/v1/documents/D1/blocks/b1") => {
                    assert_eq!(b["update_text_elements"]["elements"][0]["text_run"]["content"], "a");
                    assert_eq!(b["update_text_elements"]["elements"][1]["text_run"]["text_element_style"]["text_color"], 4);
                    ok(json!({"block": {"block_id": "b1"}}))
                }
                _ => (404, vec![], json!({"code": 404, "msg": "not scripted"}).to_string()),
            }
        });
        let f = fs(&srv.url);
        let tools = tools_of(&f);
        let (e, v) = run(&tools, "feishu_doc", json!({"action": "create_table", "doc_token": "D1", "row_size": 1, "column_size": 2}));
        assert!(!e && v["table_block_id"] == "tbl1" && v["table_cell_block_ids"] == json!(["c1", "c2"]), "{v}");
        let (e, v) = run(&tools, "feishu_doc", json!({"action": "create_table", "doc_token": "D1", "row_size": 1, "column_size": 2, "column_width": [100.0]}));
        assert!(e && v["error"] == "column_width length must equal column_size", "{v}");
        assert!(run(&tools, "feishu_doc", json!({"action": "create_table", "doc_token": "D1", "row_size": 0, "column_size": 1})).1["error"] == "row_size must be a positive integer");
        let (e, v) = run(&tools, "feishu_doc", json!({"action": "write_table_cells", "doc_token": "D1", "table_block_id": "tbl1", "values": [["a", "b"]]}));
        assert!(!e && v["cells_written"] == 2 && v["table_size"] == json!({"rows": 1, "cols": 2}), "{v}");
        assert!(run(&tools, "feishu_doc", json!({"action": "write_table_cells", "doc_token": "D1", "table_block_id": "tbl1", "values": []})).1["error"] == "values must be a non-empty 2D array");
        let (e, v) = run(&tools, "feishu_doc", json!({"action": "insert_table_row", "doc_token": "D1", "block_id": "tbl1"}));
        assert!(!e && v["block"]["block_id"] == "tbl1", "{v}");
        assert!(run(&tools, "feishu_doc", json!({"action": "delete_table_rows", "doc_token": "D1", "block_id": "tbl1"})).1["error"] == "row_start is required");
        // color_text parses upstream `parseColorMarkup` markup into styled runs.
        let (e, v) = run(&tools, "feishu_doc", json!({"action": "color_text", "doc_token": "D1", "block_id": "b1", "content": "a[green]b[/green]"}));
        assert!(!e && v["segments"] == 2, "{v}");
    }

    /// Tool reachability: names, suffixes and the read/write effect classification.
    #[test]
    fn tool_names_suffixes_and_effects() {
        let srv = FakeServer::start(|r, _| if is_token(r) { token_reply() } else { ok(json!({})) });
        let f = Feishu::new("ops-fs", "cli_app", "APPSECRET", "feishu", Some(&srv.url), 1).unwrap();
        let names: Vec<String> = tools_of(&f).iter().map(|t| t.spec().name.clone()).collect();
        assert!(names.iter().all(|n| n.ends_with("_ops-fs")), "{names:?}");
        let tools = tools_of(&f);
        let ctx = tool_ctx();
        let doc = tools.iter().find(|t| t.spec().name == "feishu_doc_ops-fs").unwrap().clone();
        assert!(doc.effects(&ctx, &json!({"action": "read"})).is_empty());
        assert!(doc.effects(&ctx, &json!({"action": "append"})).iter().any(|e| matches!(e, Effect::Net { .. })));
        assert!(doc.effects(&ctx, &json!({"action": "upload_file", "file_path": "a.txt"})).iter().any(|e| matches!(e, Effect::Read { .. })));
        // The doc schema advertises every action ark implements.
        let actions = doc.spec().input_schema["properties"]["action"]["enum"].as_array().unwrap().len();
        assert_eq!(actions, 20);
        let _ = DOC_PATHS;
    }
}
