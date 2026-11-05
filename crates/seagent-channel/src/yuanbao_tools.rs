//! Yuanbao agent tools (Hermes `tools/yuanbao_tools.py`, MIT): `yb_query_group_info`,
//! `yb_query_group_members`, `yb_send_dm`, `yb_search_sticker`, `yb_send_sticker`.
//! Every result is the upstream JSON envelope (`{"success": …}`); failures come back as
//! `{"success": false, "error": …}` (plus `candidates` when a DM recipient is ambiguous).
//! A channel named something other than `yuanbao` suffixes the names (`yb_send_dm_<id>`).

use super::{proto, sticker, Inner};
use crate::{Media, MediaKind};
use seagent_core::tool::arg_opt_str;
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::sync::Arc;

const USER_TYPE_LABEL: [&str; 4] = ["unknown", "user", "yuanbao_ai", "bot"];
const MENTION_HINT: &str = "To @mention a user, you MUST use the format: space + @ + nickname + space (e.g. \" @Alice \").";
const IMAGE_EXTS: [&str; 6] = ["jpg", "jpeg", "png", "gif", "webp", "bmp"];
/// Upstream `YuanbaoAdapter.DM_MAX_CHARS`: a proactive DM longer than this is cut and marked.
const DM_MAX_CHARS: usize = 10_000;
/// Hermes `platform.shared.truncated_suffix`.
const TRUNCATED_SUFFIX: &str = "\n...(truncated)";

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    GroupInfo,
    Members,
    SendDm,
    SearchSticker,
    SendSticker,
}

const KINDS: [(Kind, &str); 5] = [
    (Kind::GroupInfo, "yb_query_group_info"),
    (Kind::Members, "yb_query_group_members"),
    (Kind::SendDm, "yb_send_dm"),
    (Kind::SearchSticker, "yb_search_sticker"),
    (Kind::SendSticker, "yb_send_sticker"),
];

pub(super) struct YbTool {
    kind: Kind,
    name: String,
    inner: Arc<Inner>,
}

pub(super) fn tools(inner: &Arc<Inner>) -> Vec<Arc<dyn Tool>> {
    let safe: String = inner.id.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' }).collect();
    KINDS
        .iter()
        .map(|(kind, base)| {
            let name = if safe == "yuanbao" { base.to_string() } else { format!("{base}_{safe}") };
            Arc::new(YbTool { kind: *kind, name, inner: inner.clone() }) as Arc<dyn Tool>
        })
        .collect()
}

struct YbError(Value);

fn fail(msg: impl Into<String>) -> YbError {
    YbError(json!({"success": false, "error": msg.into()}))
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).map(str::trim).unwrap_or("")
}

/// `(user_id, nickname, role label)` for every member of `group`.
fn members(inner: &Arc<Inner>, group: &str) -> Result<Vec<(String, String, &'static str)>, YbError> {
    inner.ensure_started();
    let (frame, id) = proto::encode_get_group_member_list(group, 0, 200);
    let (_, data) = inner.request(frame, &id).map_err(|e| fail(e.message))?;
    let list = proto::decode_get_group_member_list_rsp(&data).ok_or_else(|| fail("get_group_member_list returned None"))?;
    Ok(list
        .members
        .into_iter()
        .map(|m| {
            // Upstream reads `user_type` (0 unknown, 1 user, 2 yuanbao_ai, 3 bot) into the role field.
            let role = USER_TYPE_LABEL.get(m.role as usize).copied().unwrap_or("unknown");
            (m.user_id, m.nickname, role)
        })
        .collect())
}

fn group_info(inner: &Arc<Inner>, a: &Value) -> Result<Value, YbError> {
    let group = s(a, "group_code");
    if group.is_empty() {
        return Err(fail("group_code is required"));
    }
    inner.ensure_started();
    let (frame, id) = proto::encode_query_group_info(group);
    let (_, data) = inner.request(frame, &id).map_err(|e| fail(e.message))?;
    let gi = proto::decode_query_group_info_rsp(&data).ok_or_else(|| fail("query_group_info returned None"))?;
    Ok(json!({
        "success": true, "group_code": group, "group_name": gi.group_name, "member_count": gi.member_count,
        "owner": {"user_id": gi.owner_id, "nickname": gi.owner_nickname},
        "note": "The group is called \"派 (Pai)\" in the app.",
    }))
}

fn query_members(inner: &Arc<Inner>, a: &Value) -> Result<Value, YbError> {
    let group = s(a, "group_code");
    if group.is_empty() {
        return Err(fail("group_code is required"));
    }
    let name = s(a, "name");
    let action = Some(s(a, "action")).filter(|x| !x.is_empty()).unwrap_or("list_all");
    let all: Vec<Value> = members(inner, group)?.into_iter().map(|(u, n, r)| json!({"user_id": u, "nickname": n, "role": r})).collect();
    if all.is_empty() {
        return Err(fail("No members found in this group."));
    }
    let hint = a.get("mention").and_then(Value::as_bool).unwrap_or(false);
    let listing = |ok: bool, msg: String, m: Vec<Value>| {
        let mut v = json!({"success": ok, "msg": msg, "members": m});
        if hint {
            v["mention_hint"] = json!(MENTION_HINT);
        }
        v
    };
    if action == "list_bots" {
        let bots: Vec<Value> = all.iter().filter(|m| matches!(m["role"].as_str(), Some("yuanbao_ai" | "bot"))).cloned().collect();
        if bots.is_empty() {
            return Err(fail("No bots found in this group."));
        }
        return Ok(listing(true, format!("Found {} bot(s).", bots.len()), bots));
    }
    if action == "find" && !name.is_empty() {
        let f = name.to_lowercase();
        let hit: Vec<Value> = all.iter().filter(|m| m["nickname"].as_str().unwrap_or("").to_lowercase().contains(&f)).cloned().collect();
        if !hit.is_empty() {
            return Ok(listing(true, format!("Found {} member(s) matching \"{name}\".", hit.len()), hit));
        }
        return Ok(listing(false, format!("No match for \"{name}\". All members listed below."), all));
    }
    Ok(listing(true, format!("Found {} member(s).", all.len()), all))
}

fn search_sticker(a: &Value) -> Result<Value, YbError> {
    let q = s(a, "query");
    let limit = limit_arg(a);
    let hits = sticker::search(q, limit);
    Ok(json!({
        "success": true, "query": q, "count": hits.len(),
        "results": hits.iter().map(|h| json!({"sticker_id": h.id, "name": h.name, "description": h.description, "package_id": sticker::PACKAGE_ID})).collect::<Vec<_>>(),
    }))
}

/// Upstream `search_sticker`'s `safe_limit = max(1, min(50, int(limit) if limit else 10))`, with a
/// `TypeError`/`ValueError` falling back to 10 — so falsy values (0, "", false, null, absent) and
/// non-integer strings use the default, floats truncate, and everything clamps to 1..=50.
fn limit_arg(a: &Value) -> usize {
    let n = match a.get("limit") {
        None | Some(Value::Null) => return 10,
        // Python `bool` is an `int`; `False` is falsy.
        Some(Value::Bool(true)) => 1.0,
        Some(Value::Bool(false)) => return 10,
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        // `int("7")` works, `int("7.9")` raises ValueError → default.
        Some(Value::String(t)) => match t.trim().parse::<i64>() {
            Ok(v) => v as f64,
            Err(_) => return 10,
        },
        _ => return 10,
    };
    if n == 0.0 {
        return 10;
    }
    (n.trunc() as i64).clamp(1, 50) as usize
}

/// The session's chat on this channel (Hermes `HERMES_SESSION_CHAT_ID`).
fn session_chat(inner: &Arc<Inner>, session: &str) -> String {
    let route = inner.origin.lock().unwrap().as_ref().and_then(|f| f(session));
    route.filter(|r| r.channel == inner.id).map(|r| r.chat).unwrap_or_default()
}

fn send_sticker(inner: &Arc<Inner>, a: &Value, session: &str) -> Result<Value, YbError> {
    let chat = Some(s(a, "chat_id").to_string()).filter(|c| !c.is_empty()).unwrap_or_else(|| session_chat(inner, session));
    let target = chat.as_str();
    if target.is_empty() {
        return Err(fail("chat_id is required (no active yuanbao session detected)"));
    }
    let raw = s(a, "sticker");
    let st = if raw.is_empty() {
        random_sticker()
    } else {
        raw.chars().all(|c| c.is_ascii_digit()).then(|| sticker::by_id(raw)).flatten().or_else(|| sticker::by_name(raw))
    };
    let st = st.ok_or_else(|| fail(format!("Sticker not found: {raw:?}. Use search_sticker first to discover available stickers.")))?;
    inner.ensure_started();
    let reply = Some(s(a, "reply_to")).filter(|r| !r.is_empty());
    let id = inner.send_body(target, vec![sticker::elem(st)], reply).map_err(|e| fail(e.message))?;
    Ok(json!({
        "success": true, "chat_id": target, "sticker": {"sticker_id": st.id, "name": st.name}, "message_id": id,
        "note": "Sticker delivered to the chat. If you have additional text to say, reply now; otherwise end your turn without generating text.",
    }))
}

/// Upstream `get_random_sticker` (no category).
fn random_sticker() -> Option<&'static sticker::Sticker> {
    let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos() as usize).unwrap_or(0);
    sticker::STICKERS.get(n % sticker::STICKERS.len().max(1))
}

/// `MEDIA:<path>` lines are attachments (Hermes `BasePlatformAdapter.extract_media`).
fn extract_media(text: &str) -> (Vec<String>, String) {
    let mut media = Vec::new();
    let mut keep = Vec::new();
    for line in text.lines() {
        match line.trim().strip_prefix("MEDIA:") {
            Some(p) if !p.trim().is_empty() => media.push(p.trim().trim_matches(['"', '\'', '`']).to_string()),
            _ => keep.push(line),
        }
    }
    (media, keep.join("\n").trim().to_string())
}

fn resolve_recipient(inner: &Arc<Inner>, group: &str, name: &str) -> Result<(String, String), YbError> {
    if group.is_empty() {
        return Err(fail("group_code is required when user_id is not provided"));
    }
    if name.is_empty() {
        return Err(fail("name is required when user_id is not provided"));
    }
    let f = name.to_lowercase();
    let hit: Vec<_> = members(inner, group)?.into_iter().filter(|(_, n, _)| n.to_lowercase().contains(&f)).collect();
    match hit.len() {
        0 => Err(fail(format!("No member matching \"{name}\" found in group {group}."))),
        1 => {
            let (u, n, _) = hit.into_iter().next().unwrap();
            Ok((u, if n.is_empty() { name.to_string() } else { n }))
        }
        _ => {
            let mut e = fail(format!("Multiple members match \"{name}\". Please specify which one."));
            e.0["candidates"] = hit.iter().map(|(u, n, _)| json!({"user_id": u, "nickname": n})).collect();
            Err(e)
        }
    }
}

fn send_dm(inner: &Arc<Inner>, a: &Value, session: &str) -> Result<Value, YbError> {
    let mut group = s(a, "group_code").trim_start_matches("group:").to_string();
    if group.is_empty() {
        group = session_chat(inner, session).strip_prefix("group:").unwrap_or("").to_string();
    }
    let mut files: Vec<String> = Vec::new();
    for item in a.get("media_files").and_then(Value::as_array).into_iter().flatten() {
        match item {
            Value::Object(_) => files.push(s(item, "path").to_string()),
            Value::Array(p) if p.len() >= 2 => files.push(p[0].as_str().unwrap_or("").to_string()),
            _ => {}
        }
    }
    let (embedded, mut message) = extract_media(arg_opt_str(a, "message").unwrap_or(""));
    files.extend(embedded);
    // Upstream `YuanbaoAdapter.send_dm` cuts proactive DM text at `DM_MAX_CHARS`.
    if message.chars().count() > DM_MAX_CHARS {
        message = message.chars().take(DM_MAX_CHARS).collect::<String>() + TRUNCATED_SUFFIX;
    }
    // Hermes `filter_media_delivery_paths`: only existing regular files go out.
    files.retain(|p| !p.is_empty() && std::path::Path::new(p).is_file());
    // srv-012: attachments leave the host only from the workspace / sandbox output area.
    for p in files.iter_mut() {
        *p = crate::media_guard::check_current(std::path::Path::new(p)).map_err(fail)?.display().to_string();
    }
    if message.is_empty() && files.is_empty() {
        return Err(fail("message or media_files is required"));
    }
    let name = s(a, "name");
    let (uid, nick) = match s(a, "user_id") {
        "" => resolve_recipient(inner, &group, name)?,
        u => (u.to_string(), name.to_string()),
    };
    if uid.is_empty() {
        return Err(fail("Could not resolve user_id"));
    }
    if !group.is_empty() {
        // C2C messages started from a group carry its code (upstream `group_code=` on send).
        inner.dm_group.lock().unwrap().insert(uid.clone(), group.clone());
    }
    inner.ensure_started();
    let chat = format!("direct:{uid}");
    let mut last: Option<Result<String, String>> = None;
    let mut errors = Vec::new();
    if !message.is_empty() {
        // Upstream's sender splits long text on the platform limit (4000 chars here).
        let mut pieces = crate::chunk::split(&message, super::MAX_MESSAGE, crate::LenUnit::Chars);
        if pieces.is_empty() {
            pieces.push(message.clone());
        }
        for piece in pieces {
            let r = inner.send_text_chunk(&chat, &piece, None).map_err(|e| e.message);
            if let Err(e) = &r {
                errors.push(e.clone());
            }
            last = Some(r);
        }
    }
    for p in &files {
        let ext = std::path::Path::new(p).extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
        let kind = if IMAGE_EXTS.contains(&ext.as_str()) { MediaKind::Image } else { MediaKind::Document };
        let m = Media { kind, path: Some(p.clone()), ..Default::default() };
        let r = inner.media_body(&m).and_then(|body| inner.send_body(&chat, body, None)).map_err(|e| e.message);
        if let Err(e) = &r {
            errors.push(e.clone());
        }
        last = Some(r);
    }
    let last = last.ok_or_else(|| fail("No deliverable text or media remained"))?;
    let id = match last {
        Ok(id) => id,
        Err(_) => return Err(fail(errors.join("; "))),
    };
    let mut note = format!("DM sent to \"{nick}\" successfully.");
    if !errors.is_empty() {
        note.push_str(&format!(" (partial failure: {})", errors.join("; ")));
    }
    Ok(json!({"success": true, "user_id": uid, "nickname": nick, "message_id": id, "note": note}))
}

fn schema(kind: Kind) -> (String, Value) {
    let group_code = json!({"type": "string", "description": "The unique group identifier (group_code)."});
    match kind {
        Kind::GroupInfo => (
            "Query basic info about a group (called '派/Pai' in the app), including group name, owner, and member count.".into(),
            json!({"type": "object", "properties": {"group_code": group_code}, "required": ["group_code"]}),
        ),
        Kind::Members => (
            "Query members of a group (called '派/Pai' in the app). Use this tool when you need to @mention someone, find a user by name, list bots (including Yuanbao AI), or list all members. IMPORTANT: You MUST call this tool before @mentioning any user, because you need the exact nickname to construct the @mention format.".into(),
            json!({"type": "object", "properties": {
                "group_code": group_code,
                "action": {"type": "string", "enum": ["find", "list_bots", "list_all"], "description": "find — search a user by name (use when you need to @mention or look up someone); list_bots — list bots and Yuanbao AI assistants; list_all — list all members."},
                "name": {"type": "string", "description": "User name to search (partial match, case-insensitive). Required for 'find'. Use the name the user mentioned in the conversation."},
                "mention": {"type": "boolean", "description": "Set to true when you need to @mention/at someone in your reply. The response will include the exact @mention format to use."}
            }, "required": ["group_code", "action"]}),
        ),
        Kind::SendDm => (
            "Send a private/direct message (DM) to a user in a group, with optional media files. This tool automatically looks up the user by name in the group member list and sends the message. Use this when someone asks to privately message / 私信 / DM a user. Supports text, images, and file attachments. You can also provide user_id directly if already known.".into(),
            json!({"type": "object", "properties": {
                "group_code": {"type": "string", "description": "The group where the target user belongs. Extract from chat_id: 'group:328306697' → '328306697'. Required when user_id is not provided."},
                "name": {"type": "string", "description": "Target user's display name (partial match, case-insensitive). Required when user_id is not provided."},
                "message": {"type": "string", "description": "The message text to send as a DM. Can be empty if only sending media."},
                "user_id": {"type": "string", "description": "Target user's account ID. If provided, skips the member lookup. Usually obtained from a previous yb_query_group_members call."},
                "media_files": {"type": "array", "description": "Optional list of media files to send along with the DM. Images (.jpg/.png/.gif/.webp/.bmp) are sent as image messages; other files are sent as document attachments.", "items": {"type": "object", "properties": {
                    "path": {"type": "string", "description": "Absolute local file path of the media to send."},
                    "is_voice": {"type": "boolean", "description": "Whether the file is a voice message (default false)."}
                }, "required": ["path"]}}
            }}),
        ),
        Kind::SearchSticker => (
            "Search the built-in Yuanbao sticker (表情包/贴纸) catalogue by keyword (Chinese or English, fuzzy). Returns sticker_id candidates for yb_send_sticker. Prefer stickers over bare Unicode emoji in Yuanbao chats.".into(),
            json!({"type": "object", "properties": {
                "query": {"type": "string", "description": "Keyword, e.g. '666', '比心', 'thanks'. Empty returns the first stickers."},
                "limit": {"type": "integer", "description": "Max results (1-50, default 10)."}
            }}),
        ),
        Kind::SendSticker => (
            "Send a built-in sticker (TIMFaceElem) to a Yuanbao chat. Use yb_search_sticker first to find a sticker_id, or pass the Chinese name directly. Never send bare Unicode emoji as a sticker substitute.".into(),
            json!({"type": "object", "properties": {
                "sticker": {"type": "string", "description": "Sticker name (e.g. '六六六') or sticker_id (e.g. '278'). Empty sends a random sticker."},
                "chat_id": {"type": "string", "description": "Target chat: 'direct:<account_id>', 'group:<group_code>' or a bare account id (default: the current conversation)."},
                "reply_to": {"type": "string", "description": "Optional message id to quote."}
            }}),
        ),
    }
}

impl Tool for YbTool {
    fn spec(&self) -> ToolSpec {
        let (description, input_schema) = schema(self.kind);
        let read = matches!(self.kind, Kind::GroupInfo | Kind::Members | Kind::SearchSticker);
        ToolSpec { name: self.name.clone(), description, input_schema, parallel_safe: read, idempotent: read, pinned: false }
    }

    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        match self.kind {
            Kind::SendDm => {
                let to = match s(input, "user_id") {
                    "" => format!("{}:{}", s(input, "group_code"), s(input, "name")),
                    u => u.to_string(),
                };
                let mut v = vec![Effect::Send { channel: self.inner.id.clone(), payload: format!("DM {to}: {}", s(input, "message")) }];
                for p in input.get("media_files").and_then(Value::as_array).into_iter().flatten() {
                    let path = p.get("path").and_then(Value::as_str).or_else(|| p.get(0).and_then(Value::as_str)).unwrap_or("");
                    if !path.is_empty() {
                        v.push(Effect::Read { path: path.into() });
                    }
                }
                v
            }
            Kind::SendSticker => vec![Effect::Send { channel: self.inner.id.clone(), payload: format!("sticker {} → {}", s(input, "sticker"), s(input, "chat_id")) }],
            _ => vec![],
        }
    }

    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let r = match self.kind {
            Kind::GroupInfo => group_info(&self.inner, &input),
            Kind::Members => query_members(&self.inner, &input),
            Kind::SendDm => crate::media_guard::scoped(crate::media_guard::roots_for(ctx), || send_dm(&self.inner, &input, &ctx.session_id)),
            Kind::SearchSticker => search_sticker(&input),
            Kind::SendSticker => send_sticker(&self.inner, &input, &ctx.session_id),
        };
        match r {
            Ok(v) => ToolOutput::ok(v.to_string()),
            Err(YbError(v)) => ToolOutput { content: v.to_string(), is_error: true, ui_resource: None },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Config, Timing, Yuanbao, TOKEN_PATH, UPLOAD_INFO_PATH};
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};
    use crate::Channel;
    use seagent_net::ws::{Message, WebSocket};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    type Ws = WebSocket<TcpStream>;
    type Log = Arc<Mutex<Vec<(proto::Head, Vec<u8>)>>>;

    fn fast() -> Timing {
        Timing {
            heartbeat: Duration::from_secs(60),
            pong_timeout: Duration::from_secs(10),
            auth_timeout: Duration::from_secs(3),
            send_timeout: Duration::from_secs(5),
            reconnect_base: Duration::from_millis(20),
            sign_retry_delay: Duration::from_millis(5),
            debounce: Duration::from_millis(50),
            connect_wait: Duration::from_secs(5),
        }
    }

    /// A channel that never connects (tools are built without I/O).
    fn yb(id: &str) -> Yuanbao {
        Yuanbao::new(
            id,
            Config { app_key: "AK".into(), app_secret: "SK".into(), ws_url: Some("ws://127.0.0.1:9/wss/connection".into()), api_domain: Some("http://127.0.0.1:9".into()), ..Default::default() },
        )
        .unwrap()
    }

    fn token_ok() -> (u16, Vec<(String, String)>, String) {
        (200, vec![], json!({"code": 0, "data": {"token": "TOK", "bot_id": "bot1", "duration": 3600, "source": "bot"}}).to_string())
    }

    /// sign-token, genUploadInfo and the signed COS PUT that media sends need.
    fn api_server() -> FakeServer {
        FakeServer::start(|req, _| {
            if req.path.starts_with(TOKEN_PATH) {
                return token_ok();
            }
            if req.path.starts_with(UPLOAD_INFO_PATH) {
                return (200, vec![], json!({"code": 0, "data": {"bucketName": "bkt", "region": "ap-guangzhou", "location": "/up/a.png", "encryptTmpSecretId": "SID", "encryptTmpSecretKey": "SKEY", "encryptToken": "STOK", "startTime": 1700000000, "expiredTime": 4100000000u64, "resourceUrl": "https://res.example/a.png"}}).to_string());
            }
            (200, vec![], String::new())
        })
    }

    fn mem(user_id: &str, nickname: &str, role: u64) -> (String, String, u64) {
        (user_id.into(), nickname.into(), role)
    }

    /// What the fake gateway answers: the roster, the group card and an optional send failure.
    struct Gw {
        members: Vec<(String, String, u64)>,
        info: (String, String, String, u64),
        send_error: Option<(u64, String)>,
    }

    impl Default for Gw {
        fn default() -> Self {
            Gw {
                // roles as the protocol numbers them: 0 member, 1 admin, 2 owner, 3 bot.
                members: vec![mem("u-bob", "Bob", 1), mem("u-ai", "元宝", 2), mem("u-bot", "Botty", 3), mem("u-amy", "Amy", 0)],
                info: ("派 Group".into(), "u-amy".into(), "Amy".into(), 4),
                send_error: None,
            }
        }
    }

    fn members_rsp(members: &[(String, String, u64)]) -> Vec<u8> {
        let mut r = Vec::new();
        for (uid, nick, role) in members {
            let mut m = Vec::new();
            proto::s(&mut m, 1, uid);
            proto::s(&mut m, 2, nick);
            proto::v(&mut m, 3, *role);
            proto::m(&mut r, 3, &m);
        }
        r
    }

    fn info_rsp(info: &(String, String, String, u64)) -> Vec<u8> {
        let mut gi = Vec::new();
        proto::s(&mut gi, 1, &info.0);
        proto::s(&mut gi, 2, &info.1);
        proto::s(&mut gi, 3, &info.2);
        proto::v(&mut gi, 4, info.3);
        let mut r = Vec::new();
        proto::m(&mut r, 3, &gi);
        r
    }

    fn recv(ws: &mut Ws, within: Duration) -> Option<(proto::Head, Vec<u8>)> {
        let until = Instant::now() + within;
        while Instant::now() < until {
            match ws.recv() {
                Ok(Some(Message::Binary(b))) => return proto::decode_conn_msg(&b),
                Ok(Some(Message::Close(_))) | Err(_) => return None,
                _ => {}
            }
        }
        None
    }

    fn reply(ws: &mut Ws, h: &proto::Head, data: &[u8]) {
        let _ = ws.send(&Message::Binary(proto::encode_conn_msg_full(proto::CMD_RESPONSE, &h.cmd, 0, &h.msg_id, &h.module, data, false)));
    }

    fn serve(ws: &mut Ws, gw: &Gw, log: &Log, until: Instant) {
        while Instant::now() < until {
            match ws.recv() {
                Ok(Some(Message::Binary(b))) => {
                    let Some((h, data)) = proto::decode_conn_msg(&b) else { continue };
                    log.lock().unwrap().push((h.clone(), data.clone()));
                    if h.cmd_type != proto::CMD_REQUEST {
                        continue;
                    }
                    let rsp = match h.cmd.as_str() {
                        "query_group_info" => info_rsp(&gw.info),
                        "get_group_member_list" => members_rsp(&gw.members),
                        "send_c2c_message" | "send_group_message" => match &gw.send_error {
                            Some((code, msg)) => {
                                let mut r = Vec::new();
                                proto::v(&mut r, 1, *code);
                                proto::s(&mut r, 2, msg);
                                r
                            }
                            None => Vec::new(),
                        },
                        _ => Vec::new(),
                    };
                    reply(ws, &h, &rsp);
                }
                Ok(Some(Message::Close(_))) | Err(_) => return,
                _ => {}
            }
        }
    }

    /// A scripted Yuanbao gateway: auth-bind, then the tool requests.
    fn gateway(gw: Gw) -> (String, Log) {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let l = log.clone();
        let gw = Arc::new(gw);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}/wss/connection", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for s in listener.incoming() {
                let Ok(mut s) = s else { continue };
                let (l, gw) = (l.clone(), gw.clone());
                std::thread::spawn(move || {
                    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    let Ok((head, rest)) = seagent_net::ws::read_head(&mut s, 65536) else { return };
                    s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
                    let Ok(mut ws) = WebSocket::accept(s, &head, rest) else { return };
                    let Some((h, _)) = recv(&mut ws, Duration::from_secs(5)) else { return };
                    let mut rsp = Vec::new();
                    proto::s(&mut rsp, 3, "conn-1");
                    reply(&mut ws, &h, &rsp);
                    serve(&mut ws, &gw, &l, Instant::now() + Duration::from_secs(15));
                });
            }
        });
        (url, log)
    }

    struct Fixture {
        y: Yuanbao,
        log: Log,
        api: FakeServer,
    }

    fn fixture(gw: Gw) -> Fixture {
        let api = api_server();
        let (ws_url, log) = gateway(gw);
        let y = Yuanbao::new(
            "yuanbao",
            Config {
                app_key: "AK".into(),
                app_secret: "SK".into(),
                ws_url: Some(ws_url),
                api_domain: Some(api.url.clone()),
                cos_base: Some(api.url.clone()),
                poll_timeout_secs: 1,
                timing: fast(),
                ..Default::default()
            },
        )
        .unwrap();
        Fixture { y, log, api }
    }

    fn tool(f: &Fixture, name: &str) -> Arc<dyn Tool> {
        f.y.tools().into_iter().find(|t| t.spec().name == name).unwrap_or_else(|| panic!("no tool {name}"))
    }

    fn call(f: &Fixture, name: &str, input: Value) -> ToolOutput {
        tool(f, name).call(&crate::testutil::tool_ctx(), input)
    }

    fn body(r: &ToolOutput) -> Value {
        serde_json::from_str(&r.content).unwrap_or_else(|e| panic!("not a JSON envelope ({e}): {}", r.content))
    }

    /// Request frames with `cmd`, decoded.
    fn frames(f: &Fixture, cmd: &str) -> Vec<proto::Fields> {
        f.log.lock().unwrap().iter().filter(|(h, _)| h.cmd == cmd).map(|(_, d)| proto::Fields::parse(d).unwrap_or_default()).collect()
    }

    /// The channel connects lazily; a read round-trip makes sure the socket (and the bot id used
    /// as the sender on sends) is up before a send is inspected.
    fn connected(f: &Fixture) {
        let r = call(f, "yb_query_group_info", json!({"group_code": "g1"}));
        assert!(!r.is_error, "{}", r.content);
    }

    fn route(f: &Fixture, chat: &str) {
        let chat = chat.to_string();
        *f.y.inner.origin.lock().unwrap() = Some(Arc::new(move |s: &str| (s == "s").then(|| crate::router::RouteKey { channel: "yuanbao".into(), chat: chat.clone(), sender: None })));
    }

    #[test]
    fn tools_use_the_upstream_names_and_schemas() {
        let y = yb("yuanbao");
        let tools = y.tools();
        let names: Vec<String> = tools.iter().map(|t| t.spec().name).collect();
        assert_eq!(names, ["yb_query_group_info", "yb_query_group_members", "yb_send_dm", "yb_search_sticker", "yb_send_sticker"]);
        let spec = |n: &str| tools.iter().find(|t| t.spec().name == n).unwrap().spec();
        let info = spec("yb_query_group_info");
        assert_eq!(info.input_schema["required"], json!(["group_code"]));
        assert_eq!(info.input_schema["properties"]["group_code"]["type"], json!("string"));
        let members = spec("yb_query_group_members");
        assert_eq!(members.input_schema["required"], json!(["group_code", "action"]));
        assert_eq!(members.input_schema["properties"]["action"]["enum"], json!(["find", "list_bots", "list_all"]));
        assert_eq!(members.input_schema["properties"]["mention"]["type"], json!("boolean"));
        assert_eq!(members.input_schema["properties"]["name"]["type"], json!("string"));
        let dm = spec("yb_send_dm");
        assert_eq!(dm.input_schema["properties"]["media_files"]["type"], json!("array"));
        assert_eq!(dm.input_schema["properties"]["media_files"]["items"]["required"], json!(["path"]));
        assert_eq!(dm.input_schema["properties"]["user_id"]["type"], json!("string"));
        assert_eq!(spec("yb_search_sticker").input_schema["properties"]["limit"]["type"], json!("integer"));
        let st = spec("yb_send_sticker");
        assert_eq!(st.input_schema["properties"]["chat_id"]["type"], json!("string"));
        assert_eq!(st.input_schema["properties"]["reply_to"]["type"], json!("string"));
        for t in &tools {
            let s = t.spec();
            assert_eq!(s.input_schema["type"], json!("object"), "{}", s.name);
            assert!(!s.description.is_empty(), "{}", s.name);
        }
        // The three lookups are side-effect free; the senders are not.
        let flags: Vec<(String, bool)> = tools.iter().map(|t| (t.spec().name, t.spec().parallel_safe)).collect();
        assert_eq!(flags, [("yb_query_group_info".into(), true), ("yb_query_group_members".into(), true), ("yb_send_dm".into(), false), ("yb_search_sticker".into(), true), ("yb_send_sticker".into(), false)]);
        // Another bot id suffixes every name (Hermes registers the toolset once per adapter).
        let other: Vec<String> = yb("yb-team").tools().iter().map(|t| t.spec().name).collect();
        assert!(other.contains(&"yb_send_dm_yb-team".to_string()), "{other:?}");
    }

    #[test]
    fn group_info_returns_the_upstream_envelope() {
        let f = fixture(Gw::default());
        let r = call(&f, "yb_query_group_info", json!({"group_code": "g1"}));
        assert!(!r.is_error, "{}", r.content);
        let v = body(&r);
        assert_eq!((v["success"].as_bool(), v["group_code"].as_str(), v["group_name"].as_str()), (Some(true), Some("g1"), Some("派 Group")));
        assert_eq!((v["member_count"].as_u64(), v["owner"]["user_id"].as_str(), v["owner"]["nickname"].as_str()), (Some(4), Some("u-amy"), Some("Amy")));
        assert!(v["note"].as_str().unwrap().contains("派 (Pai)"));
        let sent = frames(&f, "query_group_info");
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].str(1), "g1");
        // A missing group_code never reaches the gateway.
        let before = f.log.lock().unwrap().len();
        let r = call(&f, "yb_query_group_info", json!({"group_code": "  "}));
        assert!(r.is_error);
        assert_eq!(body(&r), json!({"success": false, "error": "group_code is required"}));
        assert_eq!(f.log.lock().unwrap().len(), before);
    }

    #[test]
    fn members_list_find_bots_and_the_mention_hint() {
        let f = fixture(Gw::default());
        let v = body(&call(&f, "yb_query_group_members", json!({"group_code": "g1", "action": "list_all", "mention": true})));
        assert_eq!((v["success"].as_bool(), v["msg"].as_str()), (Some(true), Some("Found 4 member(s).")));
        assert_eq!(v["mention_hint"].as_str(), Some(MENTION_HINT));
        let all = v["members"].as_array().unwrap().clone();
        // member / admin / owner / bot as the protocol numbers them, labelled like upstream.
        assert_eq!(all.iter().map(|m| m["role"].as_str().unwrap()).collect::<Vec<_>>(), ["user", "yuanbao_ai", "bot", "unknown"]);
        assert_eq!(v["members"][0], json!({"user_id": "u-bob", "nickname": "Bob", "role": "user"}));
        // `action` defaults to list_all and no hint is added unless asked for.
        let v = body(&call(&f, "yb_query_group_members", json!({"group_code": "g1"})));
        assert_eq!(v["msg"], json!("Found 4 member(s)."));
        assert!(v.get("mention_hint").is_none());
        let sent = frames(&f, "get_group_member_list");
        assert_eq!((sent[0].str(1), sent[0].var(2), sent[0].var(3)), ("g1".to_string(), 0, 200));
        // Partial, case-insensitive find.
        let v = body(&call(&f, "yb_query_group_members", json!({"group_code": "g1", "action": "find", "name": "AMY"})));
        assert_eq!((v["success"].as_bool(), v["msg"].as_str()), (Some(true), Some("Found 1 member(s) matching \"AMY\".")));
        assert_eq!(v["members"].as_array().unwrap().len(), 1);
        // No match: success false but the whole roster is returned.
        let v = body(&call(&f, "yb_query_group_members", json!({"group_code": "g1", "action": "find", "name": "zzz"})));
        assert_eq!((v["success"].as_bool(), v["msg"].as_str()), (Some(false), Some("No match for \"zzz\". All members listed below.")));
        assert_eq!(v["members"].as_array().unwrap().len(), 4);
        // list_bots keeps the AI assistant and the bot.
        let v = body(&call(&f, "yb_query_group_members", json!({"group_code": "g1", "action": "list_bots"})));
        assert_eq!((v["msg"].as_str(), v["members"].as_array().unwrap().len()), (Some("Found 2 bot(s)."), 2));

        let empty = fixture(Gw { members: vec![], ..Default::default() });
        let r = call(&empty, "yb_query_group_members", json!({"group_code": "g1", "action": "list_all"}));
        assert!(r.is_error);
        assert_eq!(body(&r)["error"], json!("No members found in this group."));
        let humans = fixture(Gw { members: vec![mem("u-amy", "Amy", 0)], ..Default::default() });
        let r = call(&humans, "yb_query_group_members", json!({"group_code": "g1", "action": "list_bots"}));
        assert!(r.is_error);
        assert_eq!(body(&r)["error"], json!("No bots found in this group."));
    }

    #[test]
    fn send_dm_by_user_id_echoes_the_group_and_caps_long_text() {
        let f = fixture(Gw::default());
        connected(&f);
        let r = call(&f, "yb_send_dm", json!({"group_code": "group:g1", "user_id": "u-bob", "name": "Bob", "message": " hi there "}));
        assert!(!r.is_error, "{}", r.content);
        let v = body(&r);
        assert_eq!((v["success"].as_bool(), v["user_id"].as_str(), v["nickname"].as_str()), (Some(true), Some("u-bob"), Some("Bob")));
        assert_eq!(v["note"], json!("DM sent to \"Bob\" successfully."));
        assert!(v["message_id"].as_str().unwrap().starts_with("c2c_"));
        let c = frames(&f, "send_c2c_message");
        assert_eq!(c.len(), 1);
        // `group:` prefixes are tolerated on input; the group code is echoed on the C2C frame.
        assert_eq!((c[0].str(2), c[0].str(3), c[0].str(6)), ("u-bob".to_string(), "bot1".to_string(), "g1".to_string()));
        assert_eq!(proto::decode_elem(&c[0].bytes(5)), proto::Elem::text("hi there"));
        // Upstream `send_dm` cuts at DM_MAX_CHARS, then the sender splits on the 4000-char limit.
        let long = "x".repeat(DM_MAX_CHARS + 5);
        let r = call(&f, "yb_send_dm", json!({"group_code": "g1", "user_id": "u-bob", "message": long}));
        assert!(!r.is_error, "{}", r.content);
        let sent: Vec<String> = frames(&f, "send_c2c_message")[1..].iter().map(|m| proto::decode_elem(&m.bytes(5)).content.text).collect();
        assert!(sent.len() >= 3, "split into platform-sized pieces: {}", sent.len());
        assert!(sent.iter().all(|s| s.chars().count() <= 4000), "{:?}", sent.iter().map(|s| s.chars().count()).collect::<Vec<_>>());
        assert!(sent.last().unwrap().ends_with("...(truncated)"));
        let total: usize = sent.iter().map(|s| s.chars().count()).sum();
        assert_eq!(total, DM_MAX_CHARS + TRUNCATED_SUFFIX.chars().count());
        // Nothing to send.
        let before = f.log.lock().unwrap().len();
        for empty in [json!({"group_code": "g1", "user_id": "u-bob"}), json!({"group_code": "g1", "user_id": "u-bob", "message": "   \n  "})] {
            let r = call(&f, "yb_send_dm", empty);
            assert!(r.is_error);
            assert_eq!(body(&r)["error"], json!("message or media_files is required"));
        }
        assert_eq!(f.log.lock().unwrap().len(), before, "no frame for an empty DM");
    }

    #[test]
    fn send_dm_resolves_a_name_against_the_group_roster() {
        let f = fixture(Gw::default());
        let r = call(&f, "yb_send_dm", json!({"group_code": "g1", "name": "AMY", "message": "yo"}));
        assert!(!r.is_error, "{}", r.content);
        assert_eq!(body(&r)["nickname"], json!("Amy"));
        assert_eq!(frames(&f, "send_c2c_message")[0].str(2), "u-amy");
        assert_eq!(frames(&f, "send_c2c_message")[0].str(6), "g1");
        // No match names the group it searched.
        let r = call(&f, "yb_send_dm", json!({"group_code": "g1", "name": "nobody", "message": "yo"}));
        assert!(r.is_error);
        assert_eq!(body(&r)["error"], json!("No member matching \"nobody\" found in group g1."));
        // Ambiguous names come back as candidates instead of a guess.
        let r = call(&f, "yb_send_dm", json!({"group_code": "g1", "name": "bo", "message": "yo"}));
        assert!(r.is_error);
        let v = body(&r);
        assert_eq!(v["error"], json!("Multiple members match \"bo\". Please specify which one."));
        let c = v["candidates"].as_array().unwrap().clone();
        assert_eq!(c.len(), 2, "{c:?}");
        assert!(c.contains(&json!({"user_id": "u-bob", "nickname": "Bob"})));
        // Without user_id, a group is required …
        let r = call(&f, "yb_send_dm", json!({"name": "Bob", "message": "yo"}));
        assert!(r.is_error);
        assert_eq!(body(&r)["error"], json!("group_code is required when user_id is not provided"));
        let r = call(&f, "yb_send_dm", json!({"group_code": "g1", "message": "yo"}));
        assert!(r.is_error);
        assert_eq!(body(&r)["error"], json!("name is required when user_id is not provided"));
        // … and defaults to the session's `group:<code>` chat when the session came from a group.
        route(&f, "group:g9");
        let r = call(&f, "yb_send_dm", json!({"name": "Bob", "message": "yo"}));
        assert!(!r.is_error, "{}", r.content);
        let sent = frames(&f, "get_group_member_list");
        assert_eq!(sent.last().unwrap().str(1), "g9", "looked Bob up in the session's group");
        let c = frames(&f, "send_c2c_message");
        assert_eq!(c.last().unwrap().str(6), "g9", "the session's group code is echoed");
    }

    #[test]
    fn send_dm_attaches_media_and_drops_missing_files() {
        let dir = temp_dir("yb-dm");
        let png = dir.join("pic.png");
        std::fs::write(&png, b"\x89PNG\r\n\x1a\n\x00\x00\x00\x00").unwrap();
        let pdf = dir.join("doc.pdf");
        std::fs::write(&pdf, b"%PDF-1.4").unwrap();
        let gone = dir.join("gone.png");
        let f = fixture(Gw::default());
        connected(&f);
        let r = call(
            &f,
            "yb_send_dm",
            json!({"group_code": "g1", "user_id": "u-bob", "media_files": [
                {"path": png.display().to_string()},
                [pdf.display().to_string(), false],
                {"path": gone.display().to_string()}
            ]}),
        );
        assert!(!r.is_error, "{}", r.content);
        let sent: Vec<String> = frames(&f, "send_c2c_message").iter().map(|m| proto::decode_elem(&m.bytes(5)).msg_type).collect();
        assert_eq!(sent, ["TIMImageElem", "TIMFileElem"], "image by extension, everything else as a document");
        assert!(f.api.requests().iter().any(|q| q.path.starts_with(UPLOAD_INFO_PATH)), "media is uploaded first");
        assert!(f.api.requests().len() >= 3, "genUploadInfo + COS PUT per file");
        // `MEDIA:` lines in the text are attachments, and the tag leaves the message.
        let r = call(&f, "yb_send_dm", json!({"group_code": "g1", "user_id": "u-bob", "message": format!("look\nMEDIA: {}", pdf.display())}));
        assert!(!r.is_error, "{}", r.content);
        let text = frames(&f, "send_c2c_message").iter().map(|m| proto::decode_elem(&m.bytes(5))).find(|e| e.msg_type == "TIMTextElem").unwrap();
        assert_eq!(text, proto::Elem::text("look"));
        // Only an undeliverable path → nothing left to send.
        let r = call(&f, "yb_send_dm", json!({"group_code": "g1", "user_id": "u-bob", "media_files": [{"path": gone.display().to_string()}]}));
        assert!(r.is_error);
        assert_eq!(body(&r)["error"], json!("message or media_files is required"));
    }

    #[test]
    fn search_sticker_matches_upstream_limits() {
        let case = |v: Value| search_sticker(&v).unwrap_or_else(|_| panic!());
        let v = case(json!({"query": "六六六", "limit": 99}));
        assert_eq!(v["results"][0]["sticker_id"], json!("278"));
        assert_eq!(v["results"][0]["package_id"], json!(sticker::PACKAGE_ID));
        assert!(v["count"].as_u64().unwrap() <= 50, "clamped to 50: {v}");
        assert_eq!(v["query"], json!("六六六"));
        // `int(limit)`: floats truncate, integer strings parse.
        assert_eq!(case(json!({"limit": 2.9}))["count"], json!(2));
        assert_eq!(case(json!({"limit": "2"}))["count"], json!(2));
        // Falsy / unparsable / missing → default 10.
        for q in [json!({"limit": 0}), json!({"limit": -4}), json!({"limit": "abc"}), json!({"limit": "7.9"}), json!({"limit": false}), json!({"limit": null}), json!({})] {
            assert!(case(q.clone())["count"].as_u64().unwrap() <= 10, "{q}");
        }
        assert_eq!(case(json!({}))["count"], json!(10));
        // The fuzzy matcher never returns more than the limit for an unknown keyword.
        assert!(case(json!({"query": "絕不存在的貼紙關鍵字", "limit": 3}))["count"].as_u64().unwrap() <= 3);
    }

    #[test]
    fn send_sticker_by_name_id_random_and_session_default() {
        let f = fixture(Gw::default());
        connected(&f);
        let v = body(&call(&f, "yb_send_sticker", json!({"sticker": "六六六", "chat_id": "group:g1", "reply_to": "m-prev"})));
        assert_eq!((v["success"].as_bool(), v["chat_id"].as_str()), (Some(true), Some("group:g1")));
        assert!(v["message_id"].as_str().unwrap().starts_with("grp_"));
        assert!(v["note"].as_str().unwrap().starts_with("Sticker delivered to the chat."));
        let g = frames(&f, "send_group_message");
        assert_eq!((g[0].str(2), g[0].str(7)), ("g1".to_string(), "m-prev".to_string()));
        let e = proto::decode_elem(&g[0].bytes(6));
        assert_eq!(e.msg_type, "TIMFaceElem");
        assert!(e.content.data.contains(v["sticker"]["sticker_id"].as_str().unwrap()), "{}", e.content.data);
        // By numeric id.
        let v = body(&call(&f, "yb_send_sticker", json!({"sticker": "278", "chat_id": "direct:u-bob"})));
        assert_eq!((v["sticker"]["sticker_id"].as_str(), v["sticker"]["name"].as_str()), (Some("278"), Some("六六六")));
        assert!(frames(&f, "send_c2c_message")[0].str(2) == "u-bob");
        // Upstream `get_sticker_by_name` ends in `search_stickers(q, 1)[0]`, so an unknown name still
        // resolves to a catalogue entry instead of failing.
        let v = body(&call(&f, "yb_send_sticker", json!({"sticker": "no-such-sticker", "chat_id": "group:g1"})));
        let id = v["sticker"]["sticker_id"].as_str().unwrap();
        assert!(sticker::STICKERS.iter().any(|s| s.id == id), "fuzzy fallback picked {id}");
        // Empty sticker → a random catalogue entry.
        let v = body(&call(&f, "yb_send_sticker", json!({"chat_id": "group:g1"})));
        let id = v["sticker"]["sticker_id"].as_str().unwrap();
        assert!(sticker::STICKERS.iter().any(|s| s.id == id), "random pick {id} is in the catalogue");
        // Without chat_id the session's chat is used …
        let r = call(&f, "yb_send_sticker", json!({"sticker": "六六六"}));
        assert!(r.is_error);
        assert_eq!(body(&r)["error"], json!("chat_id is required (no active yuanbao session detected)"));
        route(&f, "group:g2");
        let v = body(&call(&f, "yb_send_sticker", json!({"sticker": "六六六"})));
        assert_eq!(v["chat_id"], json!("group:g2"));
        assert_eq!(frames(&f, "send_group_message").last().unwrap().str(2), "g2");
    }

    #[test]
    fn send_dm_connects_the_channel_on_first_use() {
        // A DM sent before the channel ever polled still reaches the gateway (upstream's adapter
        // singleton is always connected; here the tool has to start the socket itself).
        let f = fixture(Gw::default());
        let started = Instant::now();
        let r = call(&f, "yb_send_dm", json!({"group_code": "g1", "user_id": "u-bob", "message": "first"}));
        assert!(!r.is_error, "{}", r.content);
        assert_eq!(frames(&f, "send_c2c_message")[0].str(2), "u-bob");
        assert!(started.elapsed() < Duration::from_secs(3), "no connect_wait timeout: {:?}", started.elapsed());
    }

    #[test]
    fn send_failures_surface_the_gateway_error() {
        let f = fixture(Gw { send_error: Some((5, "boom".into())), ..Default::default() });
        let r = call(&f, "yb_send_dm", json!({"group_code": "g1", "user_id": "u-bob", "message": "hi"}));
        assert!(r.is_error, "{}", r.content);
        assert!(r.content.contains("code=5") && r.content.contains("boom"), "{}", r.content);
        let r = call(&f, "yb_send_sticker", json!({"sticker": "六六六", "chat_id": "direct:u-bob"}));
        assert!(r.is_error);
        assert!(r.content.contains("boom"), "{}", r.content);
    }

    #[test]
    fn effects_describe_dms_stickers_and_reads() {
        let f = fixture(Gw::default());
        let ctx = crate::testutil::tool_ctx();
        let dm = tool(&f, "yb_send_dm");
        let e = dm.effects(&ctx, &json!({"group_code": "g1", "user_id": "u-bob", "message": "hi", "media_files": [{"path": "/a/b.png"}]}));
        assert!(matches!(&e[0], Effect::Send { channel, payload } if channel == "yuanbao" && payload.contains("u-bob") && payload.ends_with("hi")), "{e:?}");
        assert!(matches!(&e[1], Effect::Read { path } if path.to_string_lossy() == "/a/b.png"), "{e:?}");
        let e = dm.effects(&ctx, &json!({"group_code": "g1", "name": "Bob", "message": "hi"}));
        assert!(matches!(&e[0], Effect::Send { payload, .. } if payload.contains("g1:Bob")), "{e:?}");
        let st = tool(&f, "yb_send_sticker");
        assert!(matches!(&st.effects(&ctx, &json!({"sticker": "666", "chat_id": "group:g1"}))[0], Effect::Send { channel, .. } if channel == "yuanbao"));
        assert!(tool(&f, "yb_query_group_members").effects(&ctx, &json!({"group_code": "g1"})).is_empty());
        assert!(tool(&f, "yb_search_sticker").effects(&ctx, &json!({"query": "666"})).is_empty());
    }

    #[test]
    fn extract_media_takes_tag_lines_and_leaves_the_rest() {
        let (m, t) = extract_media("hi\nMEDIA: /a/b.png\nbye");
        assert_eq!((m, t.as_str()), (vec!["/a/b.png".to_string()], "hi\nbye"));
        let (m, t) = extract_media("MEDIA: \"/x y/z.pdf\"\n\nplain");
        assert_eq!((m, t.as_str()), (vec!["/x y/z.pdf".to_string()], "plain"));
        assert!(extract_media("MEDIA:   \nnot a tag").0.is_empty(), "an empty tag is not an attachment");
    }
}
