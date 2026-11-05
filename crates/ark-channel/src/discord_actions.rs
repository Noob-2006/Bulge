//! Discord `message` tool actions (ported from OpenClaw `extensions/discord`, MIT:
//! `src/channel-actions.ts`, `src/actions/handle-action*.ts`, `runtime.*.ts` and the
//! `send.*.ts` REST helpers they call). Params use OpenClaw's camelCase names
//! (`message-tool-schema.ts`); `target` is the ark chat id (channel id or `user:<id>`).
//! Results mirror the upstream `jsonResult` payloads.
//!
//! Not ported: per-account action gates (`actions.roles` etc.; ark has no equivalent
//! config) and the requester-permission pre-checks (they need the trusted sender
//! identity of the turn, which raw tool args never carry); Discord itself still
//! enforces the bot's permissions. `sticker-search` is not implemented by the
//! Discord extension. send/reply/react/edit/delete are handled by the generic tool.

use super::{poll_json, Body, Discord, Poll, PollAnswer, PollMeta, MAX_MESSAGE, SUPPRESS_NOTIFICATIONS};
use crate::{ChannelError, ChannelErrorKind as K, LenUnit};
use base64::Engine;
use serde_json::{json, Map, Value};

/// Every action `Discord::action` implements (advertised by `message_actions`).
pub(super) const ACTIONS: &[&str] = &[
    "poll",
    "reactions",
    "read",
    "upload-file",
    "pin",
    "unpin",
    "list-pins",
    "permissions",
    "thread-create",
    "thread-list",
    "thread-reply",
    "search",
    "sticker",
    "member-info",
    "role-info",
    "emoji-list",
    "emoji-upload",
    "sticker-upload",
    "role-add",
    "role-remove",
    "channel-info",
    "channel-list",
    "channel-create",
    "channel-edit",
    "channel-delete",
    "channel-move",
    "category-create",
    "category-edit",
    "category-delete",
    "voice-status",
    "event-list",
    "event-create",
    "timeout",
    "kick",
    "ban",
    "set-presence",
];

const MAX_EMOJI_BYTES: usize = 256 * 1024;
const MAX_STICKER_BYTES: usize = 512 * 1024;
const MAX_EVENT_COVER_BYTES: usize = 8 * 1024 * 1024;
const MAX_UPLOAD_BYTES: usize = 100 * 1024 * 1024;
const MAX_STICKERS: usize = 3;
const POLL_MAX_ANSWERS: usize = 10;
const POLL_MAX_HOURS: u64 = 32 * 24;
const AUTO_ARCHIVE_MINUTES: [u64; 4] = [60, 1440, 4320, 10080];
const UNKNOWN_VOICE_STATE: u64 = 10065;
const ACTIVITY_TYPES: [(&str, u64); 6] = [("playing", 0), ("streaming", 1), ("listening", 2), ("watching", 3), ("custom", 4), ("competing", 5)];
const IMAGE_TYPES: [&str; 4] = ["image/png", "image/jpeg", "image/jpg", "image/gif"];

/// `PermissionFlagsBits` (discord-api-types v10), name → bit.
const PERMISSIONS: [(&str, u32); 53] = [
    ("CreateInstantInvite", 0),
    ("KickMembers", 1),
    ("BanMembers", 2),
    ("Administrator", 3),
    ("ManageChannels", 4),
    ("ManageGuild", 5),
    ("AddReactions", 6),
    ("ViewAuditLog", 7),
    ("PrioritySpeaker", 8),
    ("Stream", 9),
    ("ViewChannel", 10),
    ("SendMessages", 11),
    ("SendTTSMessages", 12),
    ("ManageMessages", 13),
    ("EmbedLinks", 14),
    ("AttachFiles", 15),
    ("ReadMessageHistory", 16),
    ("MentionEveryone", 17),
    ("UseExternalEmojis", 18),
    ("ViewGuildInsights", 19),
    ("Connect", 20),
    ("Speak", 21),
    ("MuteMembers", 22),
    ("DeafenMembers", 23),
    ("MoveMembers", 24),
    ("UseVAD", 25),
    ("ChangeNickname", 26),
    ("ManageNicknames", 27),
    ("ManageRoles", 28),
    ("ManageWebhooks", 29),
    ("ManageEmojisAndStickers", 30),
    ("ManageGuildExpressions", 30),
    ("UseApplicationCommands", 31),
    ("RequestToSpeak", 32),
    ("ManageEvents", 33),
    ("ManageThreads", 34),
    ("CreatePublicThreads", 35),
    ("CreatePrivateThreads", 36),
    ("UseExternalStickers", 37),
    ("SendMessagesInThreads", 38),
    ("UseEmbeddedActivities", 39),
    ("ModerateMembers", 40),
    ("ViewCreatorMonetizationAnalytics", 41),
    ("UseSoundboard", 42),
    ("CreateGuildExpressions", 43),
    ("CreateEvents", 44),
    ("UseExternalSounds", 45),
    ("SendVoiceMessages", 46),
    ("SetVoiceChannelStatus", 48),
    ("SendPolls", 49),
    ("UseExternalApps", 50),
    ("PinMessages", 51),
    ("BypassSlowmode", 52),
];
const ADMINISTRATOR: u64 = 1 << 3;

type Files = Vec<(String, String, Vec<u8>)>;

fn bad(msg: impl Into<String>) -> ChannelError {
    ChannelError::new(K::Fatal, msg)
}

// ---------------------------------------------------------------- params (OpenClaw param-readers)

fn snake(k: &str) -> String {
    let mut s = String::new();
    for c in k.chars() {
        if c.is_ascii_uppercase() {
            s.push('_');
            s.push(c.to_ascii_lowercase());
        } else {
            s.push(c);
        }
    }
    s
}

/// The value under `k` or its snake_case alias.
fn raw<'a>(a: &'a Value, k: &str) -> Option<&'a Value> {
    a.get(k).filter(|v| !v.is_null()).or_else(|| a.get(snake(k)).filter(|v| !v.is_null()))
}

/// Trimmed non-empty string (numbers are stringified).
fn opt(a: &Value, k: &str) -> Option<String> {
    match raw(a, k)? {
        Value::String(s) => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Untrimmed string, empty allowed.
fn text(a: &Value, k: &str) -> Option<String> {
    raw(a, k)?.as_str().map(str::to_string)
}

fn req(a: &Value, k: &str) -> Result<String, ChannelError> {
    opt(a, k).ok_or_else(|| bad(format!("{k} required")))
}

/// Non-negative integer (number or numeric string); blank = absent; `max` inclusive.
fn int(a: &Value, k: &str, max: Option<u64>, message: Option<&str>) -> Result<Option<u64>, ChannelError> {
    let msg = || bad(message.map(str::to_string).unwrap_or_else(|| format!("{k} must be a non-negative integer")));
    let v = match raw(a, k) {
        None => return Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() => return Ok(None),
        Some(Value::String(s)) => s.trim().parse::<u64>().map_err(|_| msg())?,
        Some(Value::Number(n)) => match (n.as_u64(), n.as_f64()) {
            (Some(u), _) => u,
            (None, Some(f)) if f >= 0.0 && f.fract() == 0.0 && f < 9.0e15 => f as u64,
            _ => return Err(msg()),
        },
        Some(_) => return Err(msg()),
    };
    if max.is_some_and(|m| v > m) {
        return Err(msg());
    }
    Ok(Some(v))
}

fn pos_int(a: &Value, k: &str) -> Result<Option<u64>, ChannelError> {
    let m = format!("{k} must be a positive integer");
    match int(a, k, None, Some(&m))? {
        Some(0) => Err(bad(m)),
        v => Ok(v),
    }
}

fn flag(a: &Value, k: &str) -> Option<bool> {
    match raw(a, k)? {
        Value::Bool(b) => Some(*b),
        Value::String(s) if s.trim().eq_ignore_ascii_case("true") => Some(true),
        Value::String(s) if s.trim().eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

/// A string list (one string counts as a list of one); None when empty.
fn list(a: &Value, k: &str) -> Option<Vec<String>> {
    let one = |v: &Value| match v {
        Value::String(s) => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    };
    let out: Vec<String> = match raw(a, k)? {
        Value::Array(xs) => xs.iter().filter_map(one).collect(),
        v => one(v).into_iter().collect(),
    };
    (!out.is_empty()).then_some(out)
}

fn auto_archive(a: &Value, k: &str) -> Result<Option<u64>, ChannelError> {
    match pos_int(a, k)? {
        Some(v) if !AUTO_ARCHIVE_MINUTES.contains(&v) => Err(bad(format!("{k} must be one of 60, 1440, 4320, or 10080 minutes"))),
        v => Ok(v),
    }
}

/// `clearParent: true` / `parentId: null` → Some(None) (clear); a string → Some(Some(id)).
fn parent(a: &Value) -> Option<Option<String>> {
    if a.get("clearParent") == Some(&Value::Bool(true)) || a.get("parentId") == Some(&Value::Null) {
        return Some(None);
    }
    opt(a, "parentId").map(Some)
}

/// Discord forum tags (`parseAvailableTags`): objects with a string `name`.
fn available_tags(a: &Value) -> Option<Value> {
    let tags: Vec<Value> = a
        .get("availableTags")?
        .as_array()?
        .iter()
        .filter(|t| t["name"].is_string())
        .map(|t| {
            let mut o = Map::new();
            if t["id"].is_string() {
                o.insert("id".into(), t["id"].clone());
            }
            o.insert("name".into(), t["name"].clone());
            if t["moderated"].is_boolean() {
                o.insert("moderated".into(), t["moderated"].clone());
            }
            for k in ["emoji_id", "emoji_name"] {
                if t[k].is_string() || t.get(k) == Some(&Value::Null) {
                    o.insert(k.into(), t[k].clone());
                }
            }
            Value::Object(o)
        })
        .collect();
    (!tags.is_empty()).then_some(Value::Array(tags))
}

/// Insert only the `Some` values (`stripUndefinedFields`).
fn object(fields: Vec<(&str, Option<Value>)>) -> Value {
    Value::Object(fields.into_iter().filter_map(|(k, v)| v.map(|v| (k.to_string(), v))).collect())
}

fn qs(pairs: &[(&str, String)]) -> String {
    if pairs.is_empty() {
        return String::new();
    }
    format!("?{}", pairs.iter().map(|(k, v)| format!("{k}={}", ark_net::urlencode(v))).collect::<Vec<_>>().join("&"))
}

fn nonce() -> String {
    let b = ark_net::crypto::random_bytes(8);
    (u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]) >> 2).to_string()
}

// ---------------------------------------------------------------- time

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { yoe + era * 400 + 1 } else { yoe + era * 400 }, m, d)
}

/// RFC 3339 (`2024-01-02T03:04:05.123+00:00`) → Unix milliseconds.
pub(super) fn parse_ts(s: &str) -> Option<i64> {
    let s = s.trim();
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    if s.len() < 19 || !matches!(s.as_bytes()[10], b'T' | b't' | b' ') {
        return None;
    }
    let (y, mo, d, h, mi, se) = (num(0..4)?, num(5..7)?, num(8..10)?, num(11..13)?, num(14..16)?, num(17..19)?);
    let mut rest = &s[19..];
    let mut ms = 0;
    if let Some(f) = rest.strip_prefix('.') {
        let digits = f.chars().take_while(char::is_ascii_digit).count();
        let frac = &f[..digits];
        ms = format!("{frac:0<3}")[..3].parse::<i64>().ok()?;
        rest = &f[digits..];
    }
    let offset = match rest {
        "" | "Z" | "z" => 0,
        o if o.len() == 6 && (o.starts_with('+') || o.starts_with('-')) => {
            let v = o[1..3].parse::<i64>().ok()? * 60 + o[4..6].parse::<i64>().ok()?;
            if o.starts_with('-') {
                -v
            } else {
                v
            }
        }
        _ => return None,
    };
    Some(((days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se - offset * 60) * 1000) + ms)
}

/// Unix milliseconds → `YYYY-MM-DDTHH:MM:SS.mmmZ` (JS `toISOString`).
pub(super) fn iso(ms: i64) -> String {
    let (days, rem) = (ms.div_euclid(86_400_000), ms.rem_euclid(86_400_000));
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z", rem / 3_600_000, rem / 60_000 % 60, rem / 1000 % 60, rem % 1000)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// `withNormalizedTimestamp`: add `timestampMs` / `timestampUtc` from `timestamp`.
fn norm_msg(mut m: Value) -> Value {
    if let Some(ms) = m["timestamp"].as_str().and_then(parse_ts) {
        if let Some(o) = m.as_object_mut() {
            o.entry("timestampMs").or_insert(json!(ms));
            o.entry("timestampUtc").or_insert(json!(iso(ms)));
        }
    }
    m
}

fn norm_list(v: Value) -> Value {
    match v {
        Value::Array(xs) => Value::Array(xs.into_iter().map(norm_msg).collect()),
        v => v,
    }
}

// ---------------------------------------------------------------- media

/// Content type from magic bytes (PNG/APNG, JPEG, GIF, WebP, Lottie JSON, PDF, audio/video basics).
fn sniff(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        // APNG: an acTL chunk before the first IDAT.
        let idat = b.windows(4).position(|w| w == b"IDAT").unwrap_or(b.len());
        return Some(if b[..idat].windows(4).any(|w| w == b"acTL") { "image/apng" } else { "image/png" });
    }
    if b.starts_with(&[0xff, 0xd8, 0xff]) {
        return Some("image/jpeg");
    }
    if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
        return Some("image/gif");
    }
    if b.len() > 12 && &b[..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    if b.starts_with(b"%PDF-") {
        return Some("application/pdf");
    }
    if b.starts_with(b"OggS") {
        return Some("audio/ogg");
    }
    if b.starts_with(b"ID3") || b.starts_with(&[0xff, 0xfb]) {
        return Some("audio/mpeg");
    }
    if b.len() > 8 && &b[4..8] == b"ftyp" {
        return Some("video/mp4");
    }
    let first = b.iter().find(|c| !c.is_ascii_whitespace());
    if matches!(first, Some(b'{')) && serde_json::from_slice::<Value>(b).is_ok() {
        return Some("application/json");
    }
    None
}

/// A media reference (http(s) URL, `data:` URL, `file://` or local path) → (file name, content type, bytes).
pub(super) fn load_media(src: &str, max: usize) -> Result<(String, String, Vec<u8>), ChannelError> {
    let src = src.trim();
    let base = |s: &str| s.split(['?', '#']).next().unwrap_or(s).rsplit('/').next().filter(|n| !n.is_empty()).unwrap_or("file").to_string();
    let (name, declared, bytes) = if let Some(d) = src.strip_prefix("data:") {
        let (meta, data) = d.split_once(',').ok_or_else(|| bad("invalid data: URL"))?;
        let mime = meta.split(';').next().unwrap_or("").to_string();
        let bytes = if meta.ends_with(";base64") {
            base64::engine::general_purpose::STANDARD.decode(data.trim()).map_err(|e| bad(format!("invalid data: URL: {e}")))?
        } else {
            ark_net::urldecode(data).into_bytes()
        };
        ("file".to_string(), mime, bytes)
    } else if src.starts_with("http://") || src.starts_with("https://") {
        (base(src), String::new(), crate::http::get_bytes(src, &[], max as u64)?)
    } else {
        let p = ark_core::tool::expand_home(src.strip_prefix("file://").unwrap_or(src));
        // srv-012: only workspace / sandbox-output files leave the host.
        let p = crate::media_guard::check_current(&p).map_err(bad)?;
        let meta = std::fs::metadata(&p).map_err(|e| bad(format!("cannot read media {}: {e}", p.display())))?;
        if meta.len() as usize > max {
            return Err(bad(format!("media {} is larger than {max} bytes", p.display())));
        }
        let bytes = std::fs::read(&p).map_err(|e| bad(format!("cannot read media {}: {e}", p.display())))?;
        (p.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into()), String::new(), bytes)
    };
    if bytes.len() > max {
        return Err(bad(format!("media is larger than {max} bytes")));
    }
    let ct = sniff(&bytes).map(str::to_string).or_else(|| Some(declared.to_ascii_lowercase()).filter(|d| !d.is_empty())).unwrap_or_else(|| "application/octet-stream".into());
    Ok((name, ct, bytes))
}

fn data_uri(ct: &str, bytes: &[u8]) -> String {
    format!("data:{ct};base64,{}", base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// multipart/form-data with plain fields and one file (`multipartStyle: "form"`).
fn form(fields: &[(&str, &str)], file: (&str, &str, &str, &[u8])) -> (String, Vec<u8>) {
    let boundary = format!("arkdc{}", ark_net::crypto::hex(&ark_net::crypto::random_bytes(12)));
    let mut b = Vec::new();
    for (k, v) in fields {
        b.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n").as_bytes());
    }
    let (field, name, ct, data) = file;
    b.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{}\"\r\nContent-Type: {ct}\r\n\r\n", name.replace(['"', '\r', '\n'], "")).as_bytes());
    b.extend_from_slice(data);
    b.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), b)
}

fn reaction_identifier(e: &Value) -> Option<String> {
    match (e["id"].as_str(), e["name"].as_str()) {
        (Some(id), Some(name)) => Some(format!("{name}:{id}")),
        (_, Some(name)) if !name.is_empty() => Some(name.to_string()),
        _ => None,
    }
}

fn permission_names(bits: u64) -> Vec<&'static str> {
    let mut v: Vec<&str> = PERMISSIONS.iter().filter(|(_, b)| bits & (1u64 << b) != 0).map(|(n, _)| *n).collect();
    v.sort_unstable();
    v
}

fn perm(v: &Value) -> u64 {
    v.as_str().and_then(|s| s.parse().ok()).or_else(|| v.as_u64()).unwrap_or(0)
}

/// Base role permissions + channel overwrites (`resolveMemberChannelPermissionBits`).
fn channel_permissions(guild_id: &str, user_id: &str, guild: &Value, member: &Value, channel: &Value) -> u64 {
    let roles = guild["roles"].as_array().cloned().unwrap_or_default();
    let role_perm = |id: &str| roles.iter().find(|r| r["id"] == id).map(|r| perm(&r["permissions"])).unwrap_or(0);
    let member_roles: Vec<&str> = member["roles"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    let mut p = role_perm(guild_id);
    for r in &member_roles {
        p |= role_perm(r);
    }
    if p & ADMINISTRATOR != 0 {
        return PERMISSIONS.iter().fold(0, |acc, (_, b)| acc | (1u64 << b));
    }
    let ows = channel["permission_overwrites"].as_array().cloned().unwrap_or_default();
    for o in ows.iter().filter(|o| o["id"] == guild_id) {
        p = (p & !perm(&o["deny"])) | perm(&o["allow"]);
    }
    let (mut deny, mut allow) = (0, 0);
    for o in ows.iter().filter(|o| o["id"].as_str().is_some_and(|id| member_roles.contains(&id))) {
        deny |= perm(&o["deny"]);
        allow |= perm(&o["allow"]);
    }
    p = (p & !deny) | allow;
    for o in ows.iter().filter(|o| o["id"] == user_id) {
        p = (p & !perm(&o["deny"])) | perm(&o["allow"]);
    }
    p
}

fn is_thread(kind: Option<u64>) -> bool {
    matches!(kind, Some(10..=12))
}

// ---------------------------------------------------------------- actions

impl Discord {
    /// `channel:<id>`, `<#id>`, a bare id, or `user:<id>` (opens the DM) → channel id.
    fn act_channel(&self, raw: &str) -> Result<String, ChannelError> {
        let r = raw.trim();
        let r = r.strip_prefix("discord:").unwrap_or(r);
        let r = r.strip_prefix("channel:").unwrap_or(r);
        let r = r.strip_prefix("<#").and_then(|x| x.strip_suffix('>')).unwrap_or(r);
        if r.is_empty() {
            return Err(bad("Discord channel target is required (use channel:<id>)."));
        }
        self.target(r, None)
    }

    /// `channelId`, then `target` (the ark chat), then `to`.
    fn read_target(&self, a: &Value) -> Result<String, ChannelError> {
        let t = opt(a, "channelId").or_else(|| opt(a, "target")).or_else(|| opt(a, "to")).ok_or_else(|| bad("Discord channel target is required (use channel:<id>)."))?;
        self.act_channel(&t)
    }

    fn get(&self, path: &str) -> Result<Value, ChannelError> {
        self.inner.rest("GET", path, Body::None)
    }

    fn guild_of(&self, channel: &str) -> Option<String> {
        self.get(&format!("/channels/{channel}")).ok().and_then(|c| c["guild_id"].as_str().map(str::to_string))
    }

    /// Text in ≤2000-char pieces; reply reference and files on the first. Returns message ids.
    fn send_parts(&self, channel: &str, text: &str, reply_to: Option<&str>, silent: bool, files: Files) -> Result<Vec<String>, ChannelError> {
        let text = self.rewrite_roles(channel, text);
        let mut pieces = crate::chunk::split(&text, MAX_MESSAGE, LenUnit::Chars);
        if pieces.is_empty() {
            pieces.push(String::new());
        }
        let mut files = Some(files);
        let mut ids = Vec::new();
        for (i, piece) in pieces.into_iter().enumerate() {
            let mut body = json!({"content": piece, "allowed_mentions": self.inner.cfg.mentions.allowed()});
            if silent {
                body["flags"] = json!(SUPPRESS_NOTIFICATIONS);
            }
            if let (0, Some(r)) = (i, reply_to) {
                body["message_reference"] = json!({"message_id": r, "fail_if_not_exists": false});
            }
            let f = files.take().unwrap_or_default();
            if !f.is_empty() {
                body["attachments"] = Value::Array(f.iter().enumerate().map(|(k, (name, _, _))| json!({"id": k, "filename": name})).collect());
            }
            ids.push(self.post_message(channel, &body, f)?);
        }
        Ok(ids)
    }

    fn sent(channel: &str, ids: &[String]) -> Value {
        json!({"ok": true, "result": {"messageId": ids.first().cloned().unwrap_or_default(), "channelId": channel, "messageIds": ids}})
    }

    pub(super) fn action(&self, action: &str, a: &Value) -> Result<Value, ChannelError> {
        match action {
            "poll" => self.act_poll(a),
            "reactions" => {
                let channel = self.read_target(a)?;
                let m = req(a, "messageId")?;
                let limit = pos_int(a, "limit")?.map_or(100, |l| l.clamp(1, 100));
                let msg = self.get(&format!("/channels/{channel}/messages/{m}"))?;
                let mut out = Vec::new();
                for r in msg["reactions"].as_array().into_iter().flatten() {
                    let Some(id) = reaction_identifier(&r["emoji"]) else { continue };
                    let users = self.get(&format!("/channels/{channel}/messages/{m}/reactions/{}?limit={limit}", ark_net::urlencode(&id)))?;
                    let users: Vec<Value> = users
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(|u| {
                            let name = u["username"].as_str();
                            let tag = match (name, u["discriminator"].as_str()) {
                                (Some(n), Some(d)) if !n.is_empty() && !d.is_empty() => json!(format!("{n}#{d}")),
                                _ => u["username"].clone(),
                            };
                            json!({"id": u["id"], "username": u["username"], "tag": tag})
                        })
                        .collect();
                    out.push(json!({"emoji": {"id": r["emoji"]["id"], "name": r["emoji"]["name"], "raw": id}, "count": r["count"], "users": users}));
                }
                Ok(json!({"ok": true, "reactions": out}))
            }
            "read" => {
                let channel = self.read_target(a)?;
                let messages = match opt(a, "messageId") {
                    Some(m) => vec![self.get(&format!("/channels/{channel}/messages/{m}"))?],
                    None => {
                        let mut q = Vec::new();
                        if let Some(l) = pos_int(a, "limit")? {
                            q.push(("limit", l.clamp(1, 100).to_string()));
                        }
                        for k in ["before", "after", "around"] {
                            if let Some(v) = opt(a, k) {
                                q.push((k, v));
                            }
                        }
                        let v = self.get(&format!("/channels/{channel}/messages{}", qs(&q)))?;
                        v.as_array().cloned().ok_or_else(|| ChannelError::new(K::Protocol, "Unexpected Discord response for message read: expected array."))?
                    }
                };
                Ok(json!({"ok": true, "channelId": channel, "messages": messages.into_iter().map(norm_msg).collect::<Vec<_>>()}))
            }
            "upload-file" => {
                let channel = self.act_channel(&opt(a, "target").or_else(|| opt(a, "to")).ok_or_else(|| bad("Discord channel target is required (use channel:<id>)."))?)?;
                let src = text(a, "filePath").or_else(|| text(a, "path")).or_else(|| text(a, "media")).filter(|s| !s.trim().is_empty());
                let Some(src) = src else {
                    if text(a, "buffer").is_some() {
                        return Err(bad("Use action: \"send\" for base64 buffer attachments; upload-file requires filePath, path, or media."));
                    }
                    return Err(bad("upload-file requires filePath, path, or media."));
                };
                let content = text(a, "message").or_else(|| text(a, "content")).or_else(|| text(a, "caption")).unwrap_or_default();
                let (name, ct, bytes) = load_media(&src, MAX_UPLOAD_BYTES)?;
                let name = opt(a, "filename").unwrap_or(name);
                let ids = self.send_parts(&channel, &content, opt(a, "replyTo").as_deref(), flag(a, "silent") == Some(true), vec![(name, ct, bytes)])?;
                Ok(Self::sent(&channel, &ids))
            }
            "pin" | "unpin" => {
                let channel = self.read_target(a)?;
                let m = req(a, "messageId")?;
                self.inner.rest(if action == "pin" { "PUT" } else { "DELETE" }, &format!("/channels/{channel}/pins/{m}"), Body::None)?;
                Ok(json!({"ok": true}))
            }
            "list-pins" => {
                let channel = self.read_target(a)?;
                Ok(json!({"ok": true, "pins": norm_list(self.get(&format!("/channels/{channel}/pins"))?)}))
            }
            "permissions" => {
                let channel = self.read_target(a)?;
                Ok(json!({"ok": true, "permissions": self.act_permissions(&channel)?}))
            }
            "thread-create" => self.act_thread_create(a),
            "thread-list" => self.act_thread_list(a),
            "thread-reply" => {
                let channel = match opt(a, "threadId") {
                    Some(t) => self.act_channel(&t)?,
                    None => self.read_target(a)?,
                };
                let content = text(a, "message").filter(|m| !m.trim().is_empty()).ok_or_else(|| bad("message required"))?;
                let media = text(a, "media").or_else(|| text(a, "path")).or_else(|| text(a, "filePath")).filter(|s| !s.trim().is_empty());
                let files = match media {
                    Some(m) => vec![load_media(&m, MAX_UPLOAD_BYTES)?],
                    None => vec![],
                };
                let ids = self.send_parts(&channel, &content, opt(a, "replyTo").as_deref(), flag(a, "silent") == Some(true), files)?;
                Ok(Self::sent(&channel, &ids))
            }
            "search" => self.act_search(a),
            "sticker" => {
                let to = opt(a, "target").or_else(|| opt(a, "to")).ok_or_else(|| bad("to required"))?;
                let ids = list(a, "stickerId").or_else(|| list(a, "stickerIds")).ok_or_else(|| bad("sticker-id required"))?;
                if ids.len() > MAX_STICKERS {
                    return Err(bad("Discord supports up to 3 stickers per message"));
                }
                let channel = self.act_channel(&to)?;
                let content = text(a, "message").filter(|c| !c.trim().is_empty()).map(|c| self.rewrite_roles(&channel, &c));
                let mut body = object(vec![("content", content.map(Value::from)), ("sticker_ids", Some(json!(ids))), ("nonce", Some(json!(nonce()))), ("enforce_nonce", Some(json!(true)))]);
                if flag(a, "silent") == Some(true) {
                    body["flags"] = json!(SUPPRESS_NOTIFICATIONS);
                }
                let id = self.post_message(&channel, &body, vec![])?;
                Ok(Self::sent(&channel, &[id]))
            }
            "member-info" => {
                let (u, g) = (req(a, "userId")?, req(a, "guildId")?);
                Ok(json!({"ok": true, "member": self.get(&format!("/guilds/{g}/members/{u}"))?}))
            }
            "role-info" => {
                let g = req(a, "guildId")?;
                Ok(json!({"ok": true, "roles": self.get(&format!("/guilds/{g}/roles"))?}))
            }
            "emoji-list" => {
                let guild = match opt(a, "guildId") {
                    Some(g) => Some(g),
                    None => {
                        let c = self.read_target(a)?;
                        self.guild_of(&c)
                    }
                };
                let g = guild.ok_or_else(|| bad("Discord emoji listing requires guildId or a server channel."))?;
                let limit = pos_int(a, "limit")?.unwrap_or(100).min(100) as usize;
                let mut emojis: Vec<(String, String, bool)> = self
                    .get(&format!("/guilds/{g}/emojis"))?
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|e| Some((e["name"].as_str().filter(|n| !n.is_empty())?.to_string(), e["id"].as_str()?.to_string(), e["animated"] == true)))
                    .map(|(n, id, anim)| (n.clone(), format!("{n}:{id}"), anim))
                    .collect();
                emojis.sort();
                let out: Vec<Value> = emojis
                    .into_iter()
                    .take(limit)
                    .map(|(name, identifier, animated)| {
                        let mut e = json!({"name": name, "identifier": identifier});
                        if animated {
                            e["animated"] = json!(true);
                        }
                        e
                    })
                    .collect();
                Ok(json!({"ok": true, "emojis": out}))
            }
            "emoji-upload" => {
                let g = req(a, "guildId")?;
                let name = req(a, "emojiName")?;
                let media = text(a, "media").filter(|m| !m.trim().is_empty()).ok_or_else(|| bad("media required"))?;
                let roles = list(a, "roleIds");
                let (_, ct, bytes) = load_media(&media, MAX_EMOJI_BYTES)?;
                if !IMAGE_TYPES.contains(&ct.as_str()) {
                    return Err(bad("Discord emoji uploads require a PNG, JPG, or GIF image"));
                }
                let body = object(vec![("name", Some(json!(name))), ("image", Some(json!(data_uri(&ct, &bytes)))), ("roles", roles.map(|r| json!(r)))]);
                Ok(json!({"ok": true, "emoji": self.inner.rest("POST", &format!("/guilds/{g}/emojis"), Body::Json(&body))?}))
            }
            "sticker-upload" => {
                let g = req(a, "guildId")?;
                let (name, desc, tags) = (req(a, "stickerName")?, req(a, "stickerDesc")?, req(a, "stickerTags")?);
                let media = text(a, "media").filter(|m| !m.trim().is_empty()).ok_or_else(|| bad("media required"))?;
                let (file, ct, bytes) = load_media(&media, MAX_STICKER_BYTES)?;
                if !["image/png", "image/apng", "application/json"].contains(&ct.as_str()) {
                    return Err(bad("Discord sticker uploads require a PNG, APNG, or Lottie JSON file"));
                }
                let file = if file == "file" { "sticker".to_string() } else { file };
                let (ctype, body) = form(&[("name", &name), ("description", &desc), ("tags", &tags)], ("file", &file, &ct, &bytes));
                Ok(json!({"ok": true, "sticker": self.inner.rest("POST", &format!("/guilds/{g}/stickers"), Body::Raw(ctype, body))?}))
            }
            "role-add" | "role-remove" => {
                let (g, u, r) = (req(a, "guildId")?, req(a, "userId")?, req(a, "roleId")?);
                self.inner.rest(if action == "role-add" { "PUT" } else { "DELETE" }, &format!("/guilds/{g}/members/{u}/roles/{r}"), Body::None)?;
                Ok(json!({"ok": true}))
            }
            "channel-info" => {
                let c = match opt(a, "channelId") {
                    Some(c) => self.act_channel(&c)?,
                    None => self.read_target(a).map_err(|_| bad("channelId required"))?,
                };
                Ok(json!({"ok": true, "channel": self.get(&format!("/channels/{c}"))?}))
            }
            "channel-list" => {
                let g = req(a, "guildId")?;
                Ok(json!({"ok": true, "channels": self.get(&format!("/guilds/{g}/channels"))?}))
            }
            "channel-create" | "category-create" => {
                let g = req(a, "guildId")?;
                let name = req(a, "name")?;
                let position = int(a, "position", None, None)?;
                let body = if action == "category-create" {
                    object(vec![("name", Some(json!(name))), ("type", Some(json!(4))), ("position", position.map(Value::from))])
                } else {
                    let kind = match int(a, "channelType", None, None)? {
                        Some(t) => Some(t),
                        None => int(a, "type", None, None)?,
                    };
                    object(vec![
                        ("name", Some(json!(name))),
                        ("type", kind.map(Value::from)),
                        ("parent_id", parent(a).flatten().map(Value::from)),
                        ("topic", opt(a, "topic").map(Value::from)),
                        ("position", position.map(Value::from)),
                        ("nsfw", flag(a, "nsfw").map(Value::from)),
                    ])
                };
                let v = self.inner.rest("POST", &format!("/guilds/{g}/channels"), Body::Json(&body))?;
                let mut out = json!({"ok": true});
                out[if action == "category-create" { "category" } else { "channel" }] = v;
                Ok(out)
            }
            "channel-edit" | "category-edit" => {
                let (c, body) = if action == "category-edit" {
                    (req(a, "categoryId")?, object(vec![("name", opt(a, "name").map(Value::from)), ("position", int(a, "position", None, None)?.map(Value::from))]))
                } else {
                    let body = object(vec![
                        ("name", opt(a, "name").map(Value::from)),
                        ("topic", opt(a, "topic").map(Value::from)),
                        ("position", int(a, "position", None, None)?.map(Value::from)),
                        ("parent_id", parent(a).map(|p| p.map_or(Value::Null, Value::from))),
                        ("nsfw", flag(a, "nsfw").map(Value::from)),
                        ("rate_limit_per_user", int(a, "rateLimitPerUser", None, None)?.map(Value::from)),
                        ("archived", flag(a, "archived").map(Value::from)),
                        ("locked", flag(a, "locked").map(Value::from)),
                        ("auto_archive_duration", auto_archive(a, "autoArchiveDuration")?.map(Value::from)),
                        ("available_tags", available_tags(a)),
                    ]);
                    (req(a, "channelId")?, body)
                };
                let v = self.inner.rest("PATCH", &format!("/channels/{c}"), Body::Json(&body))?;
                let mut out = json!({"ok": true});
                out[if action == "category-edit" { "category" } else { "channel" }] = v;
                Ok(out)
            }
            "channel-delete" | "category-delete" => {
                let c = req(a, if action == "category-delete" { "categoryId" } else { "channelId" })?;
                self.inner.rest("DELETE", &format!("/channels/{c}"), Body::None)?;
                Ok(json!({"ok": true, "channelId": c}))
            }
            "channel-move" => {
                let (g, c) = (req(a, "guildId")?, req(a, "channelId")?);
                let mut entry = json!({"id": c});
                if let Some(p) = parent(a) {
                    entry["parent_id"] = p.map_or(Value::Null, Value::from);
                }
                if let Some(pos) = int(a, "position", None, None)? {
                    entry["position"] = json!(pos);
                }
                self.inner.rest("PATCH", &format!("/guilds/{g}/channels"), Body::Json(&json!([entry])))?;
                Ok(json!({"ok": true}))
            }
            "voice-status" => {
                let (g, u) = (req(a, "guildId")?, req(a, "userId")?);
                let voice = match self.get(&format!("/guilds/{g}/voice-states/{u}")) {
                    Ok(v) => v,
                    Err(e) if e.message.contains(&format!("(code {UNKNOWN_VOICE_STATE})")) || e.message.to_ascii_lowercase().contains("unknown voice state") => {
                        json!({"guild_id": g, "user_id": u, "channel_id": null, "connected": false, "absent": true, "reason": "unknown_voice_state"})
                    }
                    Err(e) => return Err(e),
                };
                Ok(json!({"ok": true, "voice": voice}))
            }
            "event-list" => {
                let g = req(a, "guildId")?;
                Ok(json!({"ok": true, "events": self.get(&format!("/guilds/{g}/scheduled-events"))?}))
            }
            "event-create" => {
                let g = req(a, "guildId")?;
                let (name, start) = (req(a, "eventName")?, req(a, "startTime")?);
                let entity_type = match opt(a, "eventType").as_deref() {
                    Some("stage") => 1,
                    Some("external") => 3,
                    _ => 2,
                };
                let image = match text(a, "image").filter(|i| !i.trim().is_empty()) {
                    Some(src) => {
                        let (_, ct, bytes) = load_media(&src, MAX_EVENT_COVER_BYTES)?;
                        if !IMAGE_TYPES.contains(&ct.as_str()) {
                            return Err(bad(format!("Discord event cover images must be PNG, JPG, or GIF (got {ct})")));
                        }
                        Some(json!(data_uri(&ct, &bytes)))
                    }
                    None => None,
                };
                let location = opt(a, "location");
                let body = object(vec![
                    ("name", Some(json!(name))),
                    ("description", opt(a, "desc").map(Value::from)),
                    ("scheduled_start_time", Some(json!(start))),
                    ("scheduled_end_time", opt(a, "endTime").map(Value::from)),
                    ("entity_type", Some(json!(entity_type))),
                    ("channel_id", opt(a, "channelId").map(Value::from)),
                    ("entity_metadata", location.filter(|_| entity_type == 3).map(|l| json!({"location": l}))),
                    ("image", image),
                    ("privacy_level", Some(json!(2))),
                ]);
                Ok(json!({"ok": true, "event": self.inner.rest("POST", &format!("/guilds/{g}/scheduled-events"), Body::Json(&body))?}))
            }
            "timeout" | "kick" | "ban" => self.act_moderation(action, a),
            "set-presence" => self.act_presence(a),
            _ => Err(crate::unsupported(action)),
        }
    }

    fn act_poll(&self, a: &Value) -> Result<Value, ChannelError> {
        // Shared validation (`message::normalize_poll`); Discord's own limits (whole hours, 10
        // answers) still apply below.
        let a = &crate::message_tool::normalize_poll_args(a, POLL_MAX_ANSWERS)?;
        let question = opt(a, "question").ok_or_else(|| bad("Poll question is required"))?;
        let options: Vec<String> = a["options"].as_array().into_iter().flatten().filter_map(|o| o.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect();
        if options.len() < 2 {
            return Err(bad("Poll requires at least 2 options"));
        }
        if options.len() > POLL_MAX_ANSWERS {
            return Err(bad(format!("Poll supports at most {POLL_MAX_ANSWERS} options")));
        }
        let max_sel = a["maxSelections"].as_f64().map(|f| f.floor() as i64).unwrap_or(1);
        if max_sel < 1 {
            return Err(bad("maxSelections must be at least 1"));
        }
        if max_sel as usize > options.len() {
            return Err(bad("maxSelections cannot exceed option count"));
        }
        let hours = a["durationHours"].as_f64().map(f64::floor);
        // Discord polls run for whole hours (`sendPollDiscord`).
        if hours.is_none() && a["durationSeconds"].is_number() {
            return Err(bad("Discord polls do not support durationSeconds; use durationHours"));
        }
        if hours.is_some_and(|h| h < 1.0) {
            return Err(bad("durationHours must be at least 1"));
        }
        let hours = hours.map_or(24, |h| (h as u64).clamp(1, POLL_MAX_HOURS));
        let channel = match opt(a, "threadId") {
            Some(t) => self.act_channel(&t)?,
            None => self.read_target(a)?,
        };
        let poll = Poll { question: question.clone(), answers: options.iter().map(|o| PollAnswer { text: o.clone(), ..Default::default() }).collect(), duration_hours: hours as u32, multiselect: max_sel > 1 };
        let content = text(a, "message").filter(|c| !c.trim().is_empty()).map(|c| self.rewrite_roles(&channel, &c));
        let mut body = object(vec![("content", content.map(Value::from)), ("poll", Some(poll_json(&poll))), ("nonce", Some(json!(nonce()))), ("enforce_nonce", Some(json!(true)))]);
        body["allowed_mentions"] = self.inner.cfg.mentions.allowed();
        if flag(a, "silent") == Some(true) {
            body["flags"] = json!(SUPPRESS_NOTIFICATIONS);
        }
        let v = self.inner.rest("POST", &format!("/channels/{channel}/messages"), Body::Json(&body))?;
        let id = v["id"].as_str().unwrap_or("").to_string();
        if !id.is_empty() {
            self.inner.remember(&id, &channel);
            let echoed: Vec<u64> = v["poll"]["answers"].as_array().into_iter().flatten().filter_map(|x| x["answer_id"].as_u64()).collect();
            let answers = options.iter().enumerate().map(|(i, o)| (echoed.get(i).copied().unwrap_or(i as u64 + 1), o.clone(), None)).collect();
            self.inner.polls.lock().unwrap().put(&id, Some(PollMeta { question, answers }));
        }
        Ok(Self::sent(&channel, &[id]))
    }

    /// `fetchChannelPermissionsDiscord`: the bot's effective permissions in a channel.
    fn act_permissions(&self, channel_id: &str) -> Result<Value, ChannelError> {
        let channel = self.get(&format!("/channels/{channel_id}"))?;
        let kind = channel["type"].as_u64();
        let subject = match channel["parent_id"].as_str() {
            Some(p) if is_thread(kind) => self.get(&format!("/channels/{p}"))?,
            _ => channel.clone(),
        };
        let Some(guild_id) = subject["guild_id"].as_str().map(str::to_string) else {
            return Ok(json!({"channelId": channel_id, "permissions": [], "raw": "0", "isDm": true, "channelType": kind}));
        };
        let me = self.get("/users/@me")?;
        let bot = me["id"].as_str().filter(|i| !i.is_empty()).ok_or_else(|| ChannelError::new(K::Protocol, "Failed to resolve bot user id"))?.to_string();
        let guild = self.get(&format!("/guilds/{guild_id}"))?;
        let member = self.get(&format!("/guilds/{guild_id}/members/{bot}"))?;
        let bits = channel_permissions(&guild_id, &bot, &guild, &member, &subject);
        Ok(json!({"channelId": channel_id, "guildId": guild_id, "permissions": permission_names(bits), "raw": bits.to_string(), "isDm": false, "channelType": kind}))
    }

    /// `createThreadDiscord`: standalone (public by default), from a message, or a forum post.
    fn act_thread_create(&self, a: &Value) -> Result<Value, ChannelError> {
        let channel = self.read_target(a)?;
        let name = req(a, "threadName")?;
        let message_id = opt(a, "messageId");
        let content = text(a, "message").unwrap_or_default();
        let auto = auto_archive(a, "autoArchiveMin")?;
        let tags = list(a, "appliedTags");
        let mut body = json!({"name": name});
        let info = if message_id.is_none() { self.get(&format!("/channels/{channel}")).ok() } else { None };
        if let Some(d) = auto.or_else(|| info.as_ref().and_then(|c| c["default_auto_archive_duration"].as_u64())) {
            body["auto_archive_duration"] = json!(d);
        }
        let forum = info.as_ref().is_some_and(|c| matches!(c["type"].as_u64(), Some(15 | 16)));
        let initial = if !content.trim().is_empty() { content } else if forum { name.clone() } else { String::new() };
        let chunks = crate::chunk::split(&initial, MAX_MESSAGE, LenUnit::Chars);
        if forum {
            body["message"] = json!({"content": chunks.first().cloned().unwrap_or_else(|| name.clone())});
            if let Some(t) = &tags {
                body["applied_tags"] = json!(t);
            }
        } else if message_id.is_none() {
            body["type"] = json!(11);
        }
        let path = match &message_id {
            Some(m) => format!("/channels/{channel}/messages/{m}/threads"),
            None => format!("/channels/{channel}/threads"),
        };
        let thread = self.inner.rest("POST", &path, Body::Json(&body))?;
        let tid = thread["id"].as_str().ok_or_else(|| ChannelError::new(K::Protocol, "create thread: no id"))?.to_string();
        self.inner.chans.lock().unwrap().insert(tid.clone(), super::chan_info(&thread));
        let followups: Vec<String> = if forum { chunks.iter().skip(1).cloned().collect() } else { chunks.clone() };
        let mut delivered: Vec<String> = if forum { vec![thread["message"]["id"].as_str().unwrap_or(&tid).to_string()] } else { vec![] };
        let mut count = usize::from(forum);
        let first_followup = usize::from(forum);
        for (i, chunk) in followups.iter().enumerate() {
            let body = json!({"content": self.rewrite_roles(&tid, chunk), "allowed_mentions": self.inner.cfg.mentions.allowed()});
            match self.post_message(&tid, &body, vec![]) {
                Ok(id) => {
                    delivered.push(id);
                    count += 1;
                }
                Err(e) => {
                    let unknown = e.is_retryable();
                    let warning = if unknown {
                        if count > 0 {
                            "Discord thread was created, but delivery of the remaining initial content could not be confirmed"
                        } else {
                            "Discord thread was created, but initial message delivery could not be confirmed"
                        }
                    } else if count > 0 {
                        "Discord thread was created, but its initial content was only partially delivered"
                    } else {
                        "Discord thread was created, but sending the initial message failed"
                    };
                    return Ok(json!({
                        "ok": true, "partial": true, "thread": thread, "warning": format!("{warning}."), "initialMessageError": e.message,
                        "initialMessageDelivery": {"starterMessageDelivered": forum, "deliveredChunkCount": count, "deliveredMessageIds": delivered,
                            "failedChunkDelivery": if unknown { "unknown" } else { "not_delivered" }, "failedChunkIndex": first_followup + i, "totalChunkCount": chunks.len()}
                    }));
                }
            }
        }
        let mut out = json!({"ok": true, "thread": thread});
        if count > 0 {
            out["threadSnapshot"] = json!("creation");
            out["initialMessageDelivery"] = json!({"status": "delivered", "starterMessageDelivered": forum, "deliveredChunkCount": count, "deliveredMessageIds": delivered, "totalChunkCount": chunks.len()});
        }
        Ok(out)
    }

    /// Active threads of a guild (filtered to a parent channel) or archived public threads of a channel.
    fn act_thread_list(&self, a: &Value) -> Result<Value, ChannelError> {
        let guild = req(a, "guildId")?;
        let channel = match opt(a, "channelId") {
            Some(c) => Some(self.act_channel(&c)?),
            None => None,
        };
        let archived = a.get("includeArchived").and_then(Value::as_bool) == Some(true);
        let before = opt(a, "before");
        let limit = pos_int(a, "limit")?;
        let value = if archived {
            let c = channel.as_deref().ok_or_else(|| bad("channelId required to list archived threads"))?;
            let mut q = Vec::new();
            if let Some(b) = &before {
                q.push(("before", b.clone()));
            }
            if let Some(l) = limit {
                q.push(("limit", l.to_string()));
            }
            self.get(&format!("/channels/{c}/threads/archived/public{}", qs(&q)))?
        } else {
            let v = self.get(&format!("/guilds/{guild}/threads/active"))?;
            match &channel {
                // The active-thread endpoint is guild-wide: never return sibling threads or members.
                Some(c) => {
                    let (Some(threads), Some(members)) = (v["threads"].as_array(), v["members"].as_array()) else {
                        return Err(ChannelError::new(K::Protocol, "Unexpected Discord response for active thread list."));
                    };
                    let kept: Vec<Value> = threads.iter().filter(|t| t["parent_id"].as_str() == Some(c.as_str()) && t["guild_id"].as_str() == Some(guild.as_str()) && is_thread(t["type"].as_u64())).cloned().collect();
                    let ids: Vec<&str> = kept.iter().filter_map(|t| t["id"].as_str()).collect();
                    let members: Vec<Value> = members.iter().filter(|m| m["id"].as_str().is_some_and(|i| ids.contains(&i))).cloned().collect();
                    json!({"threads": kept, "members": members})
                }
                None => v,
            }
        };
        let items = value["threads"].as_array().cloned().unwrap_or_default();
        let has_more = value["has_more"] == true;
        let mut query = json!({"guildId": guild, "includeArchived": archived});
        if let Some(c) = &channel {
            query["channelId"] = json!(c);
        }
        if let Some(b) = &before {
            query["before"] = json!(b);
        }
        if let Some(l) = limit {
            query["limit"] = json!(l);
        }
        let mut out = json!({
            "ok": true, "threads": value, "complete": !has_more, "hasMore": has_more, "returnedCount": items.len(),
            "source": if archived { "discord.threadList.archived" } else { "discord.threadList.active" }, "query": query,
        });
        if archived && has_more {
            if let Some(ts) = items.last().and_then(|t| t["thread_metadata"]["archive_timestamp"].as_str()).filter(|t| !t.trim().is_empty()) {
                out["nextBefore"] = json!(ts);
            }
        }
        Ok(out)
    }

    /// Guild message search (`/guilds/{id}/messages/search`); the guild comes from a channel when omitted.
    fn act_search(&self, a: &Value) -> Result<Value, ChannelError> {
        let mut guild = opt(a, "guildId");
        let query = opt(a, "query").or_else(|| opt(a, "content")).ok_or_else(|| bad("Discord search requires query text. Provide query or content."))?;
        let channel_ids = list(a, "channelIds").unwrap_or_default();
        // Without filters the current conversation (`target`) scopes the search.
        let channel = opt(a, "channelId").or_else(|| if guild.is_none() && channel_ids.is_empty() { opt(a, "target") } else { None });
        let mut channels = Vec::new();
        for c in channel_ids.iter().chain(channel.iter()) {
            channels.push(self.act_channel(c)?);
        }
        if guild.is_none() {
            guild = channels.last().filter(|_| channel.is_some()).or(channels.first()).and_then(|c| self.guild_of(c));
        }
        let guild = guild.ok_or_else(|| bad("Discord search requires guildId. Provide guildId explicitly, or provide channelId so the guild can be resolved from the channel."))?;
        let mut authors = list(a, "authorIds").unwrap_or_default();
        authors.extend(opt(a, "authorId"));
        let mut q = vec![("content", query)];
        q.extend(channels.iter().map(|c| ("channel_id", c.clone())));
        q.extend(authors.into_iter().map(|u| ("author_id", u)));
        if let Some(l) = pos_int(a, "limit")? {
            q.push(("limit", l.clamp(1, 25).to_string()));
        }
        let mut v = self.get(&format!("/guilds/{guild}/messages/search{}", qs(&q)))?;
        // HTTP 202 + code 110000 while the guild's search index warms up.
        if v["code"] == 110000 {
            let msg = v["message"].as_str().map(str::trim).filter(|m| !m.is_empty()).unwrap_or("Discord search index is not yet available").to_string();
            let hint = v["retry_after"].as_f64().map(|r| format!(" (retry after {r}s)")).unwrap_or_default();
            return Err(ChannelError::new(K::Protocol, format!("Discord message search unavailable: {msg}{hint}")));
        }
        let Some(groups) = v["messages"].as_array().cloned() else {
            return Err(ChannelError::new(K::Protocol, "Unexpected Discord response for message search: expected messages array."));
        };
        v["messages"] = Value::Array(groups.into_iter().map(norm_list).collect());
        Ok(json!({"ok": true, "results": v}))
    }

    fn act_moderation(&self, action: &str, a: &Value) -> Result<Value, ChannelError> {
        let (g, u) = (req(a, "guildId")?, req(a, "userId")?);
        let reason = opt(a, "reason").map(|r| ark_net::urlencode(&r));
        let headers: Vec<(&str, &str)> = reason.as_deref().map(|r| ("x-audit-log-reason", r)).into_iter().collect();
        match action {
            "timeout" => {
                let minutes = match int(a, "durationMin", None, None)? {
                    Some(m) => Some(m),
                    None => int(a, "durationMinutes", None, None)?,
                };
                let until = opt(a, "until").or_else(|| minutes.filter(|m| *m > 0).map(|m| iso(now_ms() + m as i64 * 60_000)));
                let body = json!({"communication_disabled_until": until});
                let member = self.inner.rest_h("PATCH", &format!("/guilds/{g}/members/{u}"), Body::Json(&body), &headers)?;
                Ok(json!({"ok": true, "member": member}))
            }
            "kick" => {
                self.inner.rest_h("DELETE", &format!("/guilds/{g}/members/{u}"), Body::None, &headers)?;
                Ok(json!({"ok": true}))
            }
            _ => {
                let days = match int(a, "deleteDays", Some(7), Some("deleteDays must be an integer from 0 to 7"))? {
                    Some(d) => Some(d),
                    None => int(a, "deleteMessageDays", Some(7), Some("deleteMessageDays must be an integer from 0 to 7"))?,
                };
                let path = format!("/guilds/{g}/bans/{u}");
                match days {
                    Some(d) => self.inner.rest_h("PUT", &path, Body::Json(&json!({"delete_message_days": d})), &headers)?,
                    None => self.inner.rest_h("PUT", &path, Body::None, &headers)?,
                };
                Ok(json!({"ok": true}))
            }
        }
    }

    /// Gateway op 3 on every shard (and in later Identify payloads).
    fn act_presence(&self, a: &Value) -> Result<Value, ChannelError> {
        let id = &self.inner.cfg.id;
        if self.tx.lock().unwrap().is_some() {
            return Err(bad(format!("Discord gateway not available for channel \"{id}\". The bot may not be connected.")));
        }
        if self.inner.me.lock().unwrap().is_none() {
            return Err(bad(format!("Discord gateway is not connected for channel \"{id}\".")));
        }
        let status = opt(a, "status").unwrap_or_else(|| "online".into());
        if !["online", "dnd", "idle", "invisible"].contains(&status.as_str()) {
            return Err(bad(format!("Invalid status \"{status}\". Must be one of: online, dnd, idle, invisible")));
        }
        let names = ACTIVITY_TYPES.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ");
        let (kind, name) = (opt(a, "activityType"), opt(a, "activityName"));
        let mut activities = Vec::new();
        if kind.is_some() || name.is_some() {
            let Some(kind) = kind else {
                return Err(bad(format!("activityType is required when activityName is provided. Valid types: {names}")));
            };
            let t = ACTIVITY_TYPES.iter().find(|(n, _)| n.eq_ignore_ascii_case(&kind)).map(|(_, t)| *t).ok_or_else(|| bad(format!("Invalid activityType \"{kind}\". Must be one of: {names}")))?;
            let mut act = json!({"name": name.unwrap_or_default(), "type": t});
            if t == 1 {
                if let Some(u) = opt(a, "activityUrl") {
                    act["url"] = json!(u);
                }
            }
            if let Some(s) = opt(a, "activityState") {
                act["state"] = json!(s);
            }
            activities.push(act);
        }
        {
            let mut p = self.inner.presence.lock().unwrap();
            *p = (p.0 + 1, Some(json!({"since": null, "activities": activities, "status": status, "afk": false})));
        }
        Ok(json!({"ok": true, "status": status, "activities": activities}))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Config, Discord};
    use super::*;
    use crate::testutil::{temp_dir, FakeServer, Req};
    use crate::Channel;
    use std::time::Duration;

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x01\0\0\0\x01IDAT";

    fn dc(srv: &FakeServer) -> Discord {
        let mut c = Config::new("dc", "TOKEN");
        c.api_base = srv.url.clone();
        c.retry_base = Duration::from_millis(5);
        c.max_retries = 0;
        Discord::new(c).unwrap()
    }

    fn ok(_: &Req, _: usize) -> (u16, Vec<(String, String)>, String) {
        (200, vec![], json!({"id": "M1"}).to_string())
    }

    fn mr(srv: &FakeServer) -> Vec<(String, String)> {
        srv.requests().iter().map(|r| (r.method.clone(), r.path.clone())).collect()
    }

    fn pairs(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
    }

    #[test]
    fn advertises_exactly_the_implemented_actions() {
        let srv = FakeServer::start(ok);
        let d = dc(&srv);
        assert_eq!(d.message_actions().len(), ACTIONS.len());
        for a in ["send", "react", "edit", "delete", "reply", "sticker-search"] {
            assert!(!d.message_actions().contains(&a));
            assert_eq!(d.message_action(a, &json!({})).unwrap_err().kind, K::Unsupported);
        }
    }

    #[test]
    fn poll_validates_and_registers_votes() {
        let srv = FakeServer::start(|_, _| (200, vec![], json!({"id": "P1", "poll": {"answers": [{"answer_id": 1}, {"answer_id": 2}]}}).to_string()));
        let d = dc(&srv);
        let v = d.message_action("poll", &json!({"target": "C1", "question": "Lunch?", "options": ["Pizza", " Sushi "], "maxSelections": 2, "durationHours": 2000, "message": "vote"})).unwrap();
        assert_eq!(v["result"]["messageId"], "P1");
        let r = &srv.requests()[0];
        assert_eq!((r.method.as_str(), r.path.as_str()), ("POST", "/channels/C1/messages"));
        let b = r.json();
        assert_eq!(b["poll"]["question"]["text"], "Lunch?");
        assert_eq!(b["poll"]["answers"][1]["poll_media"]["text"], "Sushi");
        assert_eq!((b["poll"]["allow_multiselect"].as_bool(), b["poll"]["duration"].as_u64(), b["content"].as_str()), (Some(true), Some(768), Some("vote")));
        assert!(b["nonce"].is_string() && b["enforce_nonce"] == true);
        assert!(d.inner.polls.lock().unwrap().get("P1").flatten().is_some());
        for (args, err) in [
            (json!({"target": "C1", "question": "q", "options": ["a"]}), "at least 2"),
            (json!({"target": "C1", "question": "q", "options": ["a", "b"], "durationSeconds": 60}), "durationSeconds"),
            (json!({"target": "C1", "question": "q", "options": ["a", "b"], "maxSelections": 3}), "exceed"),
            (json!({"target": "C1", "options": ["a", "b"]}), "question"),
        ] {
            assert!(d.message_action("poll", &args).unwrap_err().message.contains(err));
        }
        assert_eq!(srv.requests().len(), 1);
    }

    #[test]
    fn read_reactions_and_pins() {
        let srv = FakeServer::start(|r, _| {
            let p = r.path.as_str();
            let body = if p.starts_with("/channels/C1/messages?") {
                json!([{"id": "1", "timestamp": "2024-01-02T03:04:05.123000+00:00"}])
            } else if p == "/channels/C1/messages/9" {
                json!({"id": "9", "reactions": [{"emoji": {"id": null, "name": "👍"}, "count": 2}, {"emoji": {"id": "55", "name": "party"}, "count": 1}]})
            } else if p.contains("/reactions/") {
                json!([{"id": "U1", "username": "amy", "discriminator": "0420"}])
            } else if p == "/channels/C1/pins" {
                json!([{"id": "7", "timestamp": "2024-01-02T03:04:05Z"}])
            } else {
                Value::Null
            };
            if body.is_null() {
                (204, vec![], String::new())
            } else {
                (200, vec![], body.to_string())
            }
        });
        let d = dc(&srv);
        let v = d.message_action("read", &json!({"target": "channel:C1", "limit": 500, "before": "100", "around": ""})).unwrap();
        assert_eq!((v["channelId"].as_str(), v["messages"][0]["timestampMs"].as_i64()), (Some("C1"), Some(1_704_164_645_123)));
        assert_eq!(v["messages"][0]["timestampUtc"], "2024-01-02T03:04:05.123Z");
        let v = d.message_action("read", &json!({"channelId": "C1", "message_id": "9"})).unwrap();
        assert_eq!(v["messages"][0]["id"], "9");
        let v = d.message_action("reactions", &json!({"target": "C1", "messageId": "9", "limit": 5})).unwrap();
        assert_eq!(v["reactions"][1]["emoji"]["raw"], "party:55");
        assert_eq!((v["reactions"][0]["count"].as_u64(), v["reactions"][0]["users"][0]["tag"].as_str()), (Some(2), Some("amy#0420")));
        d.message_action("pin", &json!({"target": "C1", "messageId": "9"})).unwrap();
        d.message_action("unpin", &json!({"target": "C1", "messageId": "9"})).unwrap();
        let v = d.message_action("list-pins", &json!({"target": "C1"})).unwrap();
        assert_eq!(v["pins"][0]["timestampMs"], 1_704_164_645_000i64);
        assert_eq!(
            mr(&srv),
            pairs(&[
                ("GET", "/channels/C1/messages?limit=100&before=100"),
                ("GET", "/channels/C1/messages/9"),
                ("GET", "/channels/C1/messages/9"),
                ("GET", "/channels/C1/messages/9/reactions/%F0%9F%91%8D?limit=5"),
                ("GET", "/channels/C1/messages/9/reactions/party%3A55?limit=5"),
                ("PUT", "/channels/C1/pins/9"),
                ("DELETE", "/channels/C1/pins/9"),
                ("GET", "/channels/C1/pins"),
            ])
        );
        assert!(d.message_action("pin", &json!({"target": "C1"})).unwrap_err().message.contains("messageId required"));
        assert!(d.message_action("read", &json!({"target": "C1", "limit": 0})).unwrap_err().message.contains("positive integer"));
    }

    #[test]
    fn permissions_follow_roles_overwrites_and_threads() {
        let srv = FakeServer::start(|r, _| {
            let v = match r.path.as_str() {
                "/channels/T1" => json!({"id": "T1", "type": 11, "parent_id": "C1", "guild_id": "G"}),
                "/channels/C1" => json!({"id": "C1", "type": 0, "guild_id": "G", "permission_overwrites": [
                    {"id": "G", "type": 0, "allow": "0", "deny": "2048"},
                    {"id": "R1", "type": 0, "allow": "2048", "deny": "0"},
                    {"id": "B", "type": 1, "allow": "0", "deny": "64"}]}),
                "/channels/DM" => json!({"id": "DM", "type": 1}),
                "/users/@me" => json!({"id": "B"}),
                "/guilds/G" => json!({"id": "G", "roles": [{"id": "G", "permissions": "1088"}, {"id": "R1", "permissions": "8192"}]}),
                "/guilds/G/members/B" => json!({"roles": ["R1"]}),
                _ => json!({}),
            };
            (200, vec![], v.to_string())
        });
        let d = dc(&srv);
        let v = d.message_action("permissions", &json!({"target": "T1"})).unwrap();
        let p = &v["permissions"];
        // @everyone: ViewChannel|AddReactions; role: ManageMessages; channel: -SendMessages(@everyone) +SendMessages(role) -AddReactions(member).
        assert_eq!(p["raw"], (1024u64 | 8192 | 2048).to_string());
        assert_eq!(p["permissions"], json!(["ManageMessages", "SendMessages", "ViewChannel"]));
        assert_eq!((p["guildId"].as_str(), p["isDm"].as_bool(), p["channelType"].as_u64()), (Some("G"), Some(false), Some(11)));
        let v = d.message_action("permissions", &json!({"target": "DM"})).unwrap();
        assert_eq!((v["permissions"]["isDm"].as_bool(), v["permissions"]["raw"].as_str()), (Some(true), Some("0")));
        let admin = channel_permissions("G", "B", &json!({"roles": [{"id": "G", "permissions": "8"}]}), &json!({"roles": []}), &json!({}));
        assert!(permission_names(admin).contains(&"Administrator") && permission_names(admin).contains(&"ManageGuildExpressions"));
    }

    #[test]
    fn threads_create_list_and_reply() {
        let srv = FakeServer::start(|r, n| {
            let v = match (r.method.as_str(), r.path.as_str()) {
                ("GET", "/channels/C1") => json!({"id": "C1", "type": 0, "default_auto_archive_duration": 4320}),
                ("GET", "/channels/F1") => json!({"id": "F1", "type": 15}),
                ("POST", "/channels/C1/threads") => json!({"id": "T1", "type": 11, "parent_id": "C1"}),
                ("POST", "/channels/F1/threads") => json!({"id": "T2", "type": 11, "parent_id": "F1", "message": {"id": "S2"}}),
                ("POST", "/channels/C1/messages/9/threads") => json!({"id": "T3", "type": 11}),
                ("GET", "/guilds/G/threads/active") => json!({"threads": [
                    {"id": "T1", "type": 11, "parent_id": "C1", "guild_id": "G"},
                    {"id": "T9", "type": 11, "parent_id": "C2", "guild_id": "G"}],
                    "members": [{"id": "T1", "user_id": "B"}, {"id": "T9", "user_id": "B"}]}),
                ("GET", p) if p.starts_with("/channels/C1/threads/archived/public") => json!({"threads": [{"id": "T5", "thread_metadata": {"archive_timestamp": "2024-01-01T00:00:00Z"}}], "has_more": true}),
                ("POST", "/channels/T4/messages") => return (403, vec![], json!({"message": "Missing Access", "code": 50001}).to_string()),
                _ => json!({"id": format!("M{n}")}),
            };
            (200, vec![], v.to_string())
        });
        let d = dc(&srv);
        let v = d.message_action("thread-create", &json!({"target": "C1", "threadName": "Plan", "message": "hello"})).unwrap();
        assert_eq!((v["thread"]["id"].as_str(), v["initialMessageDelivery"]["deliveredChunkCount"].as_u64()), (Some("T1"), Some(1)));
        let reqs = srv.requests();
        assert_eq!(reqs[1].json(), json!({"name": "Plan", "auto_archive_duration": 4320, "type": 11}));
        assert_eq!((reqs[2].path.as_str(), reqs[2].json()["content"].as_str()), ("/channels/T1/messages", Some("hello")));
        // Forum: the starter message carries the first chunk and the tags.
        let v = d.message_action("thread-create", &json!({"target": "F1", "threadName": "Bug", "appliedTags": ["t1"], "autoArchiveMin": 60})).unwrap();
        let b = srv.requests()[4].json();
        assert_eq!(b, json!({"name": "Bug", "auto_archive_duration": 60, "message": {"content": "Bug"}, "applied_tags": ["t1"]}));
        assert_eq!(v["initialMessageDelivery"]["deliveredMessageIds"], json!(["S2"]));
        // From a message: no channel lookup, no type.
        let v = d.message_action("thread-create", &json!({"target": "C1", "threadName": "Sub", "messageId": "9"})).unwrap();
        assert!(v.get("initialMessageDelivery").is_none());
        assert_eq!(srv.requests().last().unwrap().json(), json!({"name": "Sub"}));
        assert!(d.message_action("thread-create", &json!({"target": "C1", "threadName": "x", "autoArchiveMin": 30})).unwrap_err().message.contains("60, 1440"));
        // Active list filtered to the parent; archived list paginates.
        let v = d.message_action("thread-list", &json!({"guildId": "G", "channelId": "C1"})).unwrap();
        assert_eq!((v["returnedCount"].as_u64(), v["threads"]["members"].as_array().unwrap().len()), (Some(1), 1));
        assert_eq!((v["source"].as_str(), v["complete"].as_bool()), (Some("discord.threadList.active"), Some(true)));
        let v = d.message_action("thread-list", &json!({"guildId": "G", "channelId": "C1", "includeArchived": true, "limit": 2, "before": "2025-01-01T00:00:00Z"})).unwrap();
        assert_eq!((v["hasMore"].as_bool(), v["nextBefore"].as_str()), (Some(true), Some("2024-01-01T00:00:00Z")));
        assert_eq!(srv.requests().last().unwrap().path, "/channels/C1/threads/archived/public?before=2025-01-01T00%3A00%3A00Z&limit=2");
        assert!(d.message_action("thread-list", &json!({"guildId": "G", "includeArchived": true})).unwrap_err().message.contains("channelId required"));
        // Reply prefers threadId, uploads media, keeps the reply reference.
        let f = temp_dir("dca").join("a.png");
        std::fs::write(&f, PNG).unwrap();
        let v = d.message_action("thread-reply", &json!({"target": "C1", "threadId": "T1", "message": "done", "media": f.display().to_string(), "replyTo": "5", "silent": true})).unwrap();
        assert_eq!(v["result"]["channelId"], "T1");
        let r = srv.requests().last().unwrap().clone();
        assert_eq!(r.path, "/channels/T1/messages");
        assert!(r.body.contains("name=\"files[0]\"; filename=\"a.png\"\r\nContent-Type: image/png") && r.body.contains("\"message_reference\"") && r.body.contains("\"flags\":4096"), "{}", r.body);
        // A failing follow-up still reports the created thread.
        let srv2 = FakeServer::start(|r, _| match r.path.as_str() {
            "/channels/C1/messages/9/threads" => (200, vec![], json!({"id": "T4", "type": 11}).to_string()),
            _ => (403, vec![], json!({"message": "Missing Access", "code": 50001}).to_string()),
        });
        let v = dc(&srv2).message_action("thread-create", &json!({"target": "C1", "threadName": "x", "messageId": "9", "message": "hi"})).unwrap();
        assert_eq!((v["partial"].as_bool(), v["initialMessageDelivery"]["failedChunkDelivery"].as_str()), (Some(true), Some("not_delivered")));
    }

    #[test]
    fn search_upload_and_sticker() {
        let srv = FakeServer::start(|r, n| {
            let v = match r.path.as_str() {
                "/channels/C1" => json!({"id": "C1", "guild_id": "G"}),
                p if p.starts_with("/guilds/G/messages/search") && p.contains("warm") => json!({"code": 110000, "message": "Index not yet available", "retry_after": 2}),
                p if p.starts_with("/guilds/G/messages/search") => json!({"total_results": 1, "messages": [[{"id": "1", "timestamp": "2024-01-02T03:04:05Z"}]]}),
                _ => json!({"id": format!("M{n}")}),
            };
            (200, vec![], v.to_string())
        });
        let d = dc(&srv);
        let v = d.message_action("search", &json!({"target": "C1", "query": "deploy", "authorId": "U1", "limit": 50})).unwrap();
        assert_eq!(v["results"]["messages"][0][0]["timestampMs"], 1_704_164_645_000i64);
        assert_eq!(srv.requests()[1].path, "/guilds/G/messages/search?content=deploy&channel_id=C1&author_id=U1&limit=25");
        let v = d.message_action("search", &json!({"guildId": "G", "content": "x", "channelIds": ["A", "B"]})).unwrap();
        assert!(v["ok"] == true);
        assert_eq!(srv.requests()[2].path, "/guilds/G/messages/search?content=x&channel_id=A&channel_id=B");
        assert!(d.message_action("search", &json!({"guildId": "G", "query": "warm"})).unwrap_err().message.contains("unavailable: Index not yet available (retry after 2s)"));
        assert!(d.message_action("search", &json!({"guildId": "G"})).unwrap_err().message.contains("requires query"));
        // upload-file: local file with caption; filename override.
        let f = temp_dir("dcu").join("r.pdf");
        std::fs::write(&f, b"%PDF-1.4").unwrap();
        let v = d.message_action("upload-file", &json!({"target": "C1", "filePath": f.display().to_string(), "message": "report", "filename": "q3.pdf"})).unwrap();
        assert_eq!(v["result"]["channelId"], "C1");
        let r = srv.requests().last().unwrap().clone();
        assert!(r.body.contains("filename=\"q3.pdf\"\r\nContent-Type: application/pdf") && r.body.contains("\"content\":\"report\""), "{}", r.body);
        assert!(d.message_action("upload-file", &json!({"target": "C1"})).unwrap_err().message.contains("requires filePath"));
        // Stickers: up to three ids, optional text, silent flag.
        d.message_action("sticker", &json!({"target": "C1", "stickerId": ["S1", "S2"], "message": "hi", "silent": true})).unwrap();
        let b = srv.requests().last().unwrap().json();
        assert_eq!((b["sticker_ids"].clone(), b["content"].as_str(), b["flags"].as_u64()), (json!(["S1", "S2"]), Some("hi"), Some(4096)));
        assert!(d.message_action("sticker", &json!({"target": "C1", "stickerId": ["1", "2", "3", "4"]})).unwrap_err().message.contains("up to 3"));
    }

    #[test]
    fn guild_reads_emojis_and_uploads() {
        let srv = FakeServer::start(|r, _| {
            let v = match (r.method.as_str(), r.path.as_str()) {
                ("GET", "/channels/C1") => json!({"id": "C1", "guild_id": "G"}),
                ("GET", "/guilds/G/emojis") => json!([{"id": "2", "name": "zeta"}, {"id": "1", "name": "alpha", "animated": true}, {"id": null, "name": "x"}]),
                ("GET", "/guilds/G/voice-states/U2") => return (404, vec![], json!({"message": "Unknown Voice State", "code": 10065}).to_string()),
                (_, p) => json!({"path": p}),
            };
            (200, vec![], v.to_string())
        });
        let d = dc(&srv);
        assert_eq!(d.message_action("member-info", &json!({"guildId": "G", "userId": "U1"})).unwrap()["member"]["path"], "/guilds/G/members/U1");
        assert_eq!(d.message_action("role-info", &json!({"guildId": "G"})).unwrap()["roles"]["path"], "/guilds/G/roles");
        assert_eq!(d.message_action("channel-info", &json!({"channelId": "channel:C9"})).unwrap()["channel"]["path"], "/channels/C9");
        assert_eq!(d.message_action("channel-list", &json!({"guildId": "G"})).unwrap()["channels"]["path"], "/guilds/G/channels");
        assert_eq!(d.message_action("event-list", &json!({"guildId": "G"})).unwrap()["events"]["path"], "/guilds/G/scheduled-events");
        assert_eq!(d.message_action("voice-status", &json!({"guildId": "G", "userId": "U1"})).unwrap()["voice"]["path"], "/guilds/G/voice-states/U1");
        let v = d.message_action("voice-status", &json!({"guildId": "G", "userId": "U2"})).unwrap();
        assert_eq!((v["voice"]["connected"].as_bool(), v["voice"]["reason"].as_str()), (Some(false), Some("unknown_voice_state")));
        assert!(d.message_action("member-info", &json!({"guildId": "G"})).unwrap_err().message.contains("userId required"));
        // emoji-list resolves the guild from the target channel, sorts, limits.
        let v = d.message_action("emoji-list", &json!({"target": "C1", "limit": 1})).unwrap();
        assert_eq!(v["emojis"], json!([{"name": "alpha", "identifier": "alpha:1", "animated": true}]));
        // Uploads: image type check, data URI, sticker multipart form.
        let png = temp_dir("dce").join("e.png");
        std::fs::write(&png, PNG).unwrap();
        d.message_action("emoji-upload", &json!({"guildId": "G", "emojiName": "ok", "media": png.display().to_string(), "roleIds": ["R1"]})).unwrap();
        let b = srv.requests().last().unwrap().json();
        assert_eq!((b["name"].as_str(), b["roles"].clone()), (Some("ok"), json!(["R1"])));
        assert!(b["image"].as_str().unwrap().starts_with("data:image/png;base64,iVBOR"));
        d.message_action("sticker-upload", &json!({"guildId": "G", "stickerName": "wave", "stickerDesc": "hi", "stickerTags": "wave", "media": png.display().to_string()})).unwrap();
        let r = srv.requests().last().unwrap().clone();
        assert_eq!(r.path, "/guilds/G/stickers");
        assert!(r.header("content-type").unwrap().starts_with("multipart/form-data"));
        assert!(r.body.contains("name=\"name\"\r\n\r\nwave\r\n") && r.body.contains("name=\"tags\"\r\n\r\nwave") && r.body.contains("name=\"file\"; filename=\"e.png\"\r\nContent-Type: image/png"), "{}", r.body);
        let txt = temp_dir("dce").join("e.txt");
        std::fs::write(&txt, b"plain").unwrap();
        assert!(d.message_action("emoji-upload", &json!({"guildId": "G", "emojiName": "x", "media": txt.display().to_string()})).unwrap_err().message.contains("PNG, JPG, or GIF"));
        let big = temp_dir("dce").join("big.png");
        std::fs::write(&big, vec![0u8; MAX_EMOJI_BYTES + 1]).unwrap();
        assert!(d.message_action("emoji-upload", &json!({"guildId": "G", "emojiName": "x", "media": big.display().to_string()})).unwrap_err().message.contains("larger than"));
        // role-add / role-remove.
        d.message_action("role-add", &json!({"guildId": "G", "userId": "U1", "roleId": "R1"})).unwrap();
        d.message_action("role-remove", &json!({"guildId": "G", "userId": "U1", "roleId": "R1"})).unwrap();
        let tail: Vec<(String, String)> = mr(&srv).into_iter().rev().take(2).collect();
        assert_eq!(tail, pairs(&[("DELETE", "/guilds/G/members/U1/roles/R1"), ("PUT", "/guilds/G/members/U1/roles/R1")]));
    }

    #[test]
    fn channel_and_category_management() {
        let srv = FakeServer::start(|r, _| if r.method == "DELETE" { (204, vec![], String::new()) } else { (200, vec![], json!({"id": "N1", "name": "x"}).to_string()) });
        let d = dc(&srv);
        let v = d.message_action("channel-create", &json!({"guildId": "G", "name": "news", "channelType": 5, "parentId": "CAT", "topic": "t", "position": 2, "nsfw": false})).unwrap();
        assert_eq!(v["channel"]["id"], "N1");
        d.message_action("channel-edit", &json!({"channelId": "C1", "name": "n", "clearParent": true, "rateLimitPerUser": 5, "archived": false, "autoArchiveDuration": 1440, "availableTags": [{"name": "bug", "moderated": true, "junk": 1}, {"x": 1}]})).unwrap();
        d.message_action("channel-move", &json!({"guildId": "G", "channelId": "C1", "parentId": "CAT", "position": 0})).unwrap();
        let v = d.message_action("channel-delete", &json!({"channelId": "C1"})).unwrap();
        assert_eq!(v, json!({"ok": true, "channelId": "C1"}));
        let v = d.message_action("category-create", &json!({"guildId": "G", "name": "Ops", "position": 1})).unwrap();
        assert!(v.get("category").is_some());
        d.message_action("category-edit", &json!({"categoryId": "CAT", "name": "Ops2"})).unwrap();
        d.message_action("category-delete", &json!({"categoryId": "CAT"})).unwrap();
        assert_eq!(
            mr(&srv),
            pairs(&[
                ("POST", "/guilds/G/channels"),
                ("PATCH", "/channels/C1"),
                ("PATCH", "/guilds/G/channels"),
                ("DELETE", "/channels/C1"),
                ("POST", "/guilds/G/channels"),
                ("PATCH", "/channels/CAT"),
                ("DELETE", "/channels/CAT"),
            ])
        );
        let rq = srv.requests();
        assert_eq!(rq[0].json(), json!({"name": "news", "type": 5, "parent_id": "CAT", "topic": "t", "position": 2, "nsfw": false}));
        assert_eq!(rq[1].json(), json!({"name": "n", "parent_id": null, "rate_limit_per_user": 5, "archived": false, "auto_archive_duration": 1440, "available_tags": [{"name": "bug", "moderated": true}]}));
        assert_eq!(rq[2].json(), json!([{"id": "C1", "parent_id": "CAT", "position": 0}]));
        assert_eq!(rq[4].json(), json!({"name": "Ops", "type": 4, "position": 1}));
        assert_eq!(rq[5].json(), json!({"name": "Ops2"}));
        assert!(d.message_action("channel-create", &json!({"guildId": "G"})).unwrap_err().message.contains("name required"));
        assert!(d.message_action("channel-edit", &json!({"channelId": "C1", "position": -1})).unwrap_err().message.contains("non-negative"));
    }

    #[test]
    fn events_and_moderation() {
        let srv = FakeServer::start(|r, _| if r.method == "DELETE" || r.method == "PUT" { (204, vec![], String::new()) } else { (200, vec![], json!({"id": "E1"}).to_string()) });
        let d = dc(&srv);
        let img = temp_dir("dcv").join("c.gif");
        std::fs::write(&img, b"GIF89a....").unwrap();
        let v = d.message_action("event-create", &json!({"guildId": "G", "eventName": "Launch", "startTime": "2030-01-01T10:00:00Z", "eventType": "external", "location": "HQ", "desc": "party", "image": img.display().to_string()})).unwrap();
        assert_eq!(v["event"]["id"], "E1");
        let b = srv.requests()[0].json();
        assert_eq!((b["entity_type"].as_u64(), b["entity_metadata"]["location"].as_str(), b["privacy_level"].as_u64()), (Some(3), Some("HQ"), Some(2)));
        assert!(b["image"].as_str().unwrap().starts_with("data:image/gif;base64,"));
        d.message_action("event-create", &json!({"guildId": "G", "eventName": "Talk", "startTime": "2030-01-01T10:00:00Z", "channelId": "V1", "location": "ignored"})).unwrap();
        let b = srv.requests()[1].json();
        assert_eq!((b["entity_type"].as_u64(), b.get("entity_metadata").is_none(), b["channel_id"].as_str()), (Some(2), true, Some("V1")));
        // timeout: duration → ISO until, audit reason header (URL-encoded).
        let before = now_ms();
        d.message_action("timeout", &json!({"guildId": "G", "userId": "U1", "durationMin": 10, "reason": "spam & abuse"})).unwrap();
        let r = &srv.requests()[2];
        assert_eq!((r.method.as_str(), r.path.as_str(), r.header("x-audit-log-reason")), ("PATCH", "/guilds/G/members/U1", Some("spam%20%26%20abuse")));
        let until = parse_ts(r.json()["communication_disabled_until"].as_str().unwrap()).unwrap();
        assert!((until - before - 600_000).abs() < 5_000);
        d.message_action("timeout", &json!({"guildId": "G", "userId": "U1"})).unwrap();
        assert_eq!(srv.requests()[3].json(), json!({"communication_disabled_until": null}));
        d.message_action("kick", &json!({"guildId": "G", "userId": "U1"})).unwrap();
        d.message_action("ban", &json!({"guildId": "G", "userId": "U1", "deleteDays": 7})).unwrap();
        let rq = srv.requests();
        assert_eq!((rq[4].method.as_str(), rq[4].path.as_str(), rq[4].header("x-audit-log-reason")), ("DELETE", "/guilds/G/members/U1", None));
        assert_eq!((rq[5].path.as_str(), rq[5].json()), ("/guilds/G/bans/U1", json!({"delete_message_days": 7})));
        assert!(d.message_action("ban", &json!({"guildId": "G", "userId": "U1", "deleteDays": 8})).unwrap_err().message.contains("0 to 7"));
    }

    #[test]
    fn presence_needs_a_gateway_and_validates() {
        let srv = FakeServer::start(ok);
        let d = dc(&srv);
        assert!(d.message_action("set-presence", &json!({"status": "idle"})).unwrap_err().message.contains("not available"));
        d.tx.lock().unwrap().take();
        assert!(d.message_action("set-presence", &json!({})).unwrap_err().message.contains("not connected"));
        *d.inner.me.lock().unwrap() = Some(Default::default());
        let v = d.message_action("set-presence", &json!({"status": "dnd", "activityType": "Streaming", "activityName": "ark", "activityUrl": "https://twitch.tv/x", "activityState": "live"})).unwrap();
        assert_eq!(v["activities"], json!([{"name": "ark", "type": 1, "url": "https://twitch.tv/x", "state": "live"}]));
        let p = d.inner.presence.lock().unwrap().clone();
        assert_eq!((p.0, p.1.unwrap()["status"].as_str().map(str::to_string)), (1, Some("dnd".into())));
        for (args, err) in [(json!({"status": "away"}), "Invalid status"), (json!({"activityName": "x"}), "activityType is required"), (json!({"activityType": "dancing"}), "Invalid activityType")] {
            assert!(d.message_action("set-presence", &args).unwrap_err().message.contains(err));
        }
    }

    /// A gateway that records every client payload: Hello, then READY after Identify.
    fn gateway(seen: std::sync::Arc<std::sync::Mutex<Vec<Value>>>) -> String {
        use ark_net::ws::{read_head, Message, WebSocket};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let seen = seen.clone();
                std::thread::spawn(move || {
                    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    let Ok((head, rest)) = read_head(&mut s, 65536) else { return };
                    let mut ws = WebSocket::accept(s, &head, rest).unwrap();
                    ws.send_text(&json!({"op": 10, "d": {"heartbeat_interval": 30000}}).to_string()).unwrap();
                    while let Ok(m) = ws.recv_blocking() {
                        let Message::Text(t) = m else { break };
                        let v: Value = serde_json::from_str(&t).unwrap();
                        if v["op"] == 2 {
                            let ready = json!({"op": 0, "s": 1, "t": "READY", "d": {"session_id": "S", "user": {"id": "B", "username": "ark"}, "application": {"id": "APP"}}});
                            ws.send_text(&ready.to_string()).unwrap();
                        }
                        seen.lock().unwrap().push(v);
                    }
                });
            }
        });
        url
    }

    #[test]
    fn presence_goes_out_over_the_gateway_and_in_identify() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let srv = FakeServer::start(ok);
        let mut c = Config::new("dc", "TOKEN");
        c.api_base = srv.url.clone();
        c.gateway_url = Some(gateway(seen.clone()));
        c.poll_timeout_secs = 1;
        c.identify_interval = Duration::from_millis(10);
        let d = std::sync::Arc::new(Discord::new(c.clone()).unwrap());
        let d2 = d.clone();
        std::thread::spawn(move || {
            for _ in 0..8 {
                let _ = d2.poll(&ark_core::Cancel::new());
            }
        });
        let wait = |f: &dyn Fn(&[Value]) -> bool| {
            let until = std::time::Instant::now() + Duration::from_secs(5);
            while !f(&seen.lock().unwrap()) && std::time::Instant::now() < until {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(f(&seen.lock().unwrap()), "{:?}", seen.lock().unwrap());
        };
        let until = std::time::Instant::now() + Duration::from_secs(5);
        while d.inner.me.lock().unwrap().is_none() && std::time::Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
        d.message_action("set-presence", &json!({"status": "idle", "activityType": "watching", "activityName": "logs"})).unwrap();
        wait(&|s| s.iter().any(|v| v["op"] == 3));
        let op3 = seen.lock().unwrap().iter().find(|v| v["op"] == 3).cloned().unwrap();
        assert_eq!(op3["d"], json!({"since": null, "activities": [{"name": "logs", "type": 3}], "status": "idle", "afk": false}));
        d.stop();
        // A fresh Identify carries the stored presence.
        seen.lock().unwrap().clear();
        let d3 = Discord::new(c).unwrap();
        *d3.inner.presence.lock().unwrap() = (1, Some(json!({"status": "dnd", "activities": [], "since": null, "afk": false})));
        let _ = d3.poll(&ark_core::Cancel::new());
        wait(&|s| s.iter().any(|v| v["op"] == 2));
        let id = seen.lock().unwrap().iter().find(|v| v["op"] == 2).cloned().unwrap();
        assert_eq!(id["d"]["presence"]["status"], "dnd");
        std::thread::sleep(Duration::from_millis(100));
        assert!(!seen.lock().unwrap().iter().any(|v| v["op"] == 3), "presence sent twice");
        d3.stop();
    }

    #[test]
    fn time_and_media_helpers() {
        assert_eq!(parse_ts("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_ts("2024-01-02T05:04:05.5+02:00"), Some(1_704_164_645_500));
        assert_eq!(iso(1_704_164_645_500), "2024-01-02T03:04:05.500Z");
        assert_eq!(parse_ts("nope"), None);
        assert_eq!(sniff(b"\x89PNG\r\n\x1a\n....acTL....IDAT"), Some("image/apng"));
        assert_eq!(sniff(b" {\"v\":\"5.5\"}"), Some("application/json"));
        let (_, ct, b) = load_media("data:text/plain;base64,aGk=", 10).unwrap();
        assert_eq!((ct.as_str(), b.as_slice()), ("text/plain", &b"hi"[..]));
    }

    #[test]
    fn load_media_refuses_host_paths_outside_the_send_roots() {
        // srv-012 second layer: even a path that reached the loader directly is checked.
        let ws = ark_core::tmp::TempDir::new("dc-ws");
        let host = ark_core::tmp::TempDir::new("dc-host");
        std::fs::write(ws.join("a.png"), PNG).unwrap();
        std::fs::write(host.join("secret.txt"), b"s").unwrap();
        crate::media_guard::scoped(vec![ws.to_path_buf()], || {
            assert!(load_media(&ws.join("a.png").display().to_string(), 1 << 20).is_ok());
            let e = load_media(&format!("file://{}", host.join("secret.txt").display()), 1 << 20).unwrap_err();
            assert!(e.message.contains("refusing to send"), "{}", e.message);
        });
    }
}
