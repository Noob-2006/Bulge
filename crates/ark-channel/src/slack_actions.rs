//! Slack `message` tool actions (ported from OpenClaw `extensions/slack`, MIT:
//! `message-actions.ts`, `message-action-dispatch.ts`, `action-runtime.ts`, `actions.ts`,
//! `conversation-open.ts`). Web API: `reactions.get`, `conversations.history/replies`,
//! `pins.add/remove/list`, `users.info`, `emoji.list`, `files.info` + private download,
//! files upload v2, `conversations.open`. Results mirror the upstream `jsonResult` payloads.
//!
//! Not ported: per-account action gates (`actions.pins` etc.; ark has no such config),
//! the requester / read-target admission checks (raw tool args carry no trusted turn
//! context), multi-workspace client selection by `teamId` (ark holds one bot token; a
//! `teamId` only qualifies the returned target), and re-rendering of table blocks in
//! `read`. `download-file` returns the saved path instead of inlining images.
//! send/reply/react/edit/delete are handled by the generic tool.

use super::Slack;
use crate::action_args::{self as a, bad};
use crate::http::Payload;
use crate::{ChannelError, Media};
use serde_json::{json, Value};

/// Every action `Slack::action` implements (advertised by `message_actions`).
pub(super) const ACTIONS: &[&str] = &["reactions", "read", "conversation-open", "download-file", "upload-file", "pin", "unpin", "list-pins", "member-info", "emoji-list"];

/// `SLACK_REACTION_RESULT_LIMIT`: reaction users and emoji-list entries.
const RESULT_LIMIT: u64 = 100;
/// `mediaMaxMb` default for downloads.
const DOWNLOAD_MAX: u64 = 20 * 1024 * 1024;
const UPLOAD_MAX: u64 = 1024 * 1024 * 1024;
const DOWNLOAD_FAILED: &str = "File could not be downloaded. Confirm the fileId came from the requested Slack channel or explicit thread and that the file is accessible and within the size limit.";

fn is_id(s: &str, first: &[char]) -> bool {
    s.len() > 1 && s.starts_with(first) && s[1..].chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// `resolveSlackChannelId`: `C1`, `channel:C1`, `slack:C1`, `#C1`, `<#C1|name>`, `team:T:channel:C1`.
fn channel_id(raw: &str) -> String {
    let mut t = raw.trim();
    if let Some(inner) = t.strip_prefix("<#").and_then(|x| x.strip_suffix('>')) {
        t = inner.split('|').next().unwrap_or(inner);
    }
    if t.len() > 5 && t[..5].eq_ignore_ascii_case("team:") {
        t = t.splitn(3, ':').nth(2).unwrap_or(t);
    }
    for p in ["slack:", "channel:", "#"] {
        if t.len() > p.len() && t[..p.len()].eq_ignore_ascii_case(p) {
            t = &t[p.len()..];
        }
    }
    t.to_string()
}

fn need_channel(args: &Value, action: &str) -> Result<String, ChannelError> {
    a::s(args, &["channelId", "target", "to"]).map(|t| channel_id(&t)).ok_or_else(|| bad(format!("{action} requires target (the Slack channel id)")))
}

// ---------------------------------------------------------------- timestamps (withNormalizedTimestamp)

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

fn iso(ms: i64) -> String {
    let (days, rem) = (ms.div_euclid(86_400_000), ms.rem_euclid(86_400_000));
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z", rem / 3_600_000, rem / 60_000 % 60, rem / 1000 % 60, rem % 1000)
}

/// Slack `ts` (seconds with a fraction) → milliseconds.
fn ts_ms(ts: &str) -> Option<i64> {
    let t = ts.trim();
    if t.is_empty() || !t.chars().all(|c| c.is_ascii_digit() || c == '.') || t.matches('.').count() > 1 {
        return None;
    }
    let n: f64 = t.parse().ok()?;
    Some((n * if t.contains('.') || t.len() < 13 { 1000.0 } else { 1.0 }).round() as i64)
}

fn with_ts(mut m: Value) -> Value {
    if let Some(ms) = m["ts"].as_str().and_then(ts_ms) {
        m["timestampMs"] = json!(ms);
        m["timestampUtc"] = json!(iso(ms));
    }
    m
}

/// `normalizeSlackReadTimestamp`: a Slack ts, or an ISO-8601 date with offset → epoch seconds.
fn read_ts(raw: Option<String>, field: &str) -> Result<Option<String>, ChannelError> {
    let Some(t) = raw.map(|t| t.trim().to_string()).filter(|t| !t.is_empty()) else { return Ok(None) };
    if t.split_once('.').map_or(t.chars().all(|c| c.is_ascii_digit()), |(a, b)| !a.is_empty() && !b.is_empty() && a.chars().chain(b.chars()).all(|c| c.is_ascii_digit())) {
        return Ok(Some(t));
    }
    let ms = parse_iso(&t).ok_or_else(|| bad(format!("Invalid Slack read {field} timestamp \"{t}\": expected a Slack timestamp or ISO-8601 date string")))?;
    let s = if ms % 1000 == 0 { (ms / 1000).to_string() } else { format!("{:.3}", ms as f64 / 1000.0).trim_end_matches('0').to_string() };
    Ok(Some(s))
}

/// `YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)` → epoch ms.
fn parse_iso(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r).filter(|x| x.bytes().all(|c| c.is_ascii_digit())).and_then(|x| x.parse::<i64>().ok());
    let (y, mo, d, h, mi, se) = (num(0..4)?, num(5..7)?, num(8..10)?, num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let mut rest = &s[19..];
    let mut frac = 0;
    if let Some(r) = rest.strip_prefix('.') {
        let n = r.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 {
            return None;
        }
        frac = format!("{:0<3}", &r[..n.min(3)]).parse().ok()?;
        rest = &r[n..];
    }
    let off = match rest {
        "Z" | "z" => 0,
        o if o.len() == 6 && matches!(&o[..1], "+" | "-") && &o[3..4] == ":" => {
            let v = o[1..3].parse::<i64>().ok()? * 60 + o[4..6].parse::<i64>().ok()?;
            if o.starts_with('-') {
                -v
            } else {
                v
            }
        }
        _ => return None,
    };
    Some(((days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se) - off * 60) * 1000 + frac)
}

// ---------------------------------------------------------------- download scope (hasSlackScopeProof)

fn has_scope_proof(file: &Value, channel: &str, thread: Option<&str>) -> bool {
    if thread.is_none() && ["channels", "groups", "ims"].iter().any(|k| file[*k].as_array().is_some_and(|xs| xs.iter().any(|x| x.as_str().map(str::trim) == Some(channel)))) {
        return true;
    }
    ["public", "private"].iter().any(|k| {
        file["shares"][*k].as_object().is_some_and(|m| {
            m.iter().any(|(cid, entries)| {
                cid.trim() == channel
                    && entries.as_array().is_some_and(|es| {
                        es.iter().any(|e| {
                            let (ts, tts) = (e["ts"].as_str().map(str::trim).filter(|x| !x.is_empty()), e["thread_ts"].as_str().map(str::trim).filter(|x| !x.is_empty()));
                            match thread {
                                Some(t) => ts == Some(t) || tts == Some(t),
                                None => ts.is_some() || tts.is_some(),
                            }
                        })
                    })
            })
        })
    })
}

fn file_reference(f: &Value, name: &str) -> String {
    let meta: Vec<String> = [f["mimetype"].as_str().map(str::to_string), f["id"].as_str().map(|i| format!("fileId: {i}"))].into_iter().flatten().filter(|s| !s.trim().is_empty()).collect();
    if meta.is_empty() {
        name.to_string()
    } else {
        format!("{name} ({})", meta.join(", "))
    }
}

fn safe_name(n: &str) -> String {
    let s: String = n.chars().map(|c| if c.is_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' }).collect();
    let s = s.trim_start_matches('.').to_string();
    if s.is_empty() {
        "file".into()
    } else {
        s.chars().take(120).collect()
    }
}

impl Slack {
    fn form(&self, method: &str, form: &[(&str, &str)]) -> Result<Value, ChannelError> {
        self.inner.call(method, Payload::Form(form), None)
    }

    pub(super) fn action(&self, action: &str, args: &Value) -> Result<Value, ChannelError> {
        match action {
            "reactions" => {
                let ch = need_channel(args, action)?;
                let m = a::req(args, &["messageId"])?;
                let limit = a::pos(args, &["limit"]).map_err(|_| bad("limit must be a positive integer."))?.unwrap_or(RESULT_LIMIT).min(RESULT_LIMIT) as usize;
                let v = self.form("reactions.get", &[("channel", &ch), ("timestamp", &m), ("full", "true")])?;
                let rs: Vec<Value> = v["message"]["reactions"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|mut r| {
                        if let Some(u) = r["users"].as_array() {
                            r["users"] = json!(u.iter().take(limit).cloned().collect::<Vec<_>>());
                        }
                        r
                    })
                    .collect();
                Ok(json!({"ok": true, "reactions": rs}))
            }
            "read" => self.act_read(args),
            "pin" | "unpin" => {
                let ch = need_channel(args, action)?;
                let m = a::req(args, &["messageId"])?;
                self.inner.api(if action == "pin" { "pins.add" } else { "pins.remove" }, &json!({"channel": ch, "timestamp": m}))?;
                Ok(json!({"ok": true}))
            }
            "list-pins" => {
                let ch = need_channel(args, action)?;
                let v = self.form("pins.list", &[("channel", &ch)])?;
                let pins: Vec<Value> = v["items"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|mut p| {
                        if p["message"].is_object() {
                            p["message"] = with_ts(p["message"].take());
                        }
                        p
                    })
                    .collect();
                Ok(json!({"ok": true, "pins": pins}))
            }
            "member-info" => {
                let user = a::s(args, &["userId"]).ok_or_else(|| bad("member-info requires a userId outside a current Slack conversation."))?;
                let info = self.form("users.info", &[("user", &user)])?;
                Ok(json!({"ok": true, "info": info}))
            }
            "emoji-list" => {
                let limit = a::pos(args, &["limit"]).map_err(|_| bad("limit must be a positive integer."))?.unwrap_or(RESULT_LIMIT).min(RESULT_LIMIT) as usize;
                let v = self.form("emoji.list", &[])?;
                let mut names: Vec<(&String, &Value)> = v["emoji"].as_object().map(|m| m.iter().collect()).unwrap_or_default();
                names.sort_by(|x, y| x.0.cmp(y.0));
                let emojis: Vec<Value> = names
                    .into_iter()
                    .take(limit)
                    .map(|(n, val)| match val.as_str().and_then(|s| s.strip_prefix("alias:")) {
                        Some(of) => json!({"name": n, "identifier": n, "aliasOf": of}),
                        None => json!({"name": n, "identifier": n}),
                    })
                    .collect();
                Ok(json!({"ok": true, "emojis": emojis}))
            }
            "conversation-open" => {
                let users = a::list(args, &["userIds"]);
                if users.is_empty() || users.len() > 8 || !users.iter().all(|u| is_id(u, &['U', 'W'])) {
                    return Err(bad("conversation-open requires userIds: 1-8 Slack user ids (U… / W…)."));
                }
                if users.iter().enumerate().any(|(i, u)| users[..i].contains(u)) {
                    return Err(bad("Slack conversation-open requires distinct userIds."));
                }
                let team = a::s(args, &["teamId"]);
                if team.as_deref().is_some_and(|t| !is_id(&t.to_ascii_uppercase(), &['T'])) {
                    return Err(bad("teamId must be a Slack workspace id (T…)."));
                }
                let v = self.inner.api("conversations.open", &json!({"users": users.join(",")}))?;
                let id = v["channel"]["id"].as_str().map(str::trim).filter(|i| is_id(&i.to_ascii_uppercase(), &['C', 'D', 'G'])).ok_or_else(|| ChannelError::new(crate::ChannelErrorKind::Protocol, "Slack conversations.open did not return a valid conversation ID."))?;
                let target = match &team {
                    Some(t) => format!("team:{}:channel:{}", ark_net::urlencode(t), ark_net::urlencode(id)),
                    None => format!("channel:{id}"),
                };
                Ok(json!({"ok": true, "channelId": id, "target": target}))
            }
            "download-file" => self.act_download(args),
            "upload-file" => self.act_upload(args),
            _ => Err(a::unknown("slack", action)),
        }
    }

    /// `readSlackMessages`: history or thread replies, or one exact message.
    fn act_read(&self, args: &Value) -> Result<Value, ChannelError> {
        let ch = need_channel(args, "read")?;
        let limit = a::pos(args, &["limit"]).map_err(|_| bad("limit must be a positive integer."))?;
        let thread = a::s(args, &["threadId"]);
        let exact = a::s(args, &["messageId"]);
        let (latest, oldest) = match &exact {
            Some(m) => (Some(m.clone()), Some(m.clone())),
            None => (read_ts(a::s(args, &["before"]), "before")?, read_ts(a::s(args, &["after"]), "after")?),
        };
        let limit = if exact.is_some() { Some(1) } else { limit }.map(|l| l.to_string());
        let mut form: Vec<(&str, String)> = vec![("channel", ch.clone())];
        if let Some(l) = limit {
            form.push(("limit", l));
        }
        if exact.is_some() {
            form.push(("inclusive", "true".into()));
        }
        if let Some(l) = latest {
            form.push(("latest", l));
        }
        let method = match &thread {
            Some(t) => {
                // Exclude the root before it consumes the replies-only page limit.
                let num = |s: &str| s.parse::<f64>().unwrap_or(0.0);
                let o = match (&exact, &oldest) {
                    (Some(m), _) => m.clone(),
                    (None, Some(o)) if num(o) > num(t) => o.clone(),
                    _ => t.clone(),
                };
                form.push(("ts", t.clone()));
                form.push(("oldest", o));
                "conversations.replies"
            }
            None => {
                if let Some(o) = oldest {
                    form.push(("oldest", o));
                }
                "conversations.history"
            }
        };
        let pairs: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let v = self.form(method, &pairs)?;
        let messages: Vec<Value> = v["messages"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|m| match (&exact, &thread) {
                (Some(e), _) => m["ts"].as_str() == Some(e),
                (None, Some(t)) => m["ts"].as_str() != Some(t),
                _ => true,
            })
            .map(with_ts)
            .collect();
        let mut out = json!({"ok": true, "channelId": ch, "messages": messages, "hasMore": exact.is_none() && v["has_more"] == true});
        if let Some(t) = thread {
            out["threadId"] = json!(t);
        }
        Ok(out)
    }

    /// `downloadSlackFile`: `files.info`, the channel / thread scope proof, then the private URL.
    fn act_download(&self, args: &Value) -> Result<Value, ChannelError> {
        let file_id = a::s(args, &["fileId"]);
        if file_id.is_none() && a::s(args, &["messageId", "message_id"]).is_some() {
            return Err(bad("download-file requires fileId (the Slack file id, for example F0B0LTT8M36 from event.files[].id), not messageId. Did you mean to pass fileId? messageId is the Slack message timestamp and is used by react / reactions / edit / delete / pin / unpin actions, not download-file."));
        }
        let file_id = file_id.ok_or_else(|| bad("fileId required"))?;
        let ch = a::s(args, &["channelId", "to", "target"]).map(|c| channel_id(&c)).ok_or_else(|| bad("Slack file download requires channelId or to so the read target can be authorized."))?;
        let thread = a::s(args, &["threadId", "replyTo"]);
        let failed = || Ok(json!({"ok": false, "error": DOWNLOAD_FAILED}));
        let v = self.form("files.info", &[("file", &file_id)])?;
        let f = &v["file"];
        let Some(url) = f["url_private_download"].as_str().or_else(|| f["url_private"].as_str()) else { return failed() };
        if !has_scope_proof(f, &ch, thread.as_deref()) {
            return failed();
        }
        let auth = format!("Bearer {}", self.inner.cfg.bot_token);
        let Ok(data) = crate::http::get_bytes(url, &[("authorization", &auth)], DOWNLOAD_MAX) else { return failed() };
        let name = f["name"].as_str().filter(|n| !n.trim().is_empty()).unwrap_or("file");
        let mime = f["mimetype"].as_str().unwrap_or("").to_ascii_lowercase();
        let lname = name.to_ascii_lowercase();
        // Guard against auth / login HTML pages served instead of the file.
        let head = String::from_utf8_lossy(&data[..data.len().min(512)]).trim_start().to_ascii_lowercase();
        if mime != "text/html" && !lname.ends_with(".html") && !lname.ends_with(".htm") && (head.starts_with("<!doctype html") || head.starts_with("<html")) {
            return failed();
        }
        let dir = std::env::temp_dir().join("ark-slack-files");
        std::fs::create_dir_all(&dir).map_err(|e| bad(format!("cannot create {}: {e}", dir.display())))?;
        let path = dir.join(format!("{}-{}", safe_name(&file_id), safe_name(name)));
        std::fs::write(&path, &data).map_err(|e| bad(format!("cannot write {}: {e}", path.display())))?;
        let path = path.to_string_lossy().into_owned();
        let mut media = json!({"mediaUrl": path, "outbound": false});
        let mut out = json!({"ok": true, "fileId": file_id, "path": path, "placeholder": format!("[Slack file: {}]", file_reference(f, name))});
        if !mime.is_empty() {
            media["contentType"] = json!(mime);
            out["contentType"] = json!(mime);
        }
        out["media"] = media;
        Ok(out)
    }

    /// `uploadFile`: files upload v2 into the channel (or a DM opened for `user:<id>`).
    fn act_upload(&self, args: &Value) -> Result<Value, ChannelError> {
        if a::flag(args, "replyBroadcast") == Some(true) {
            return Err(bad("Slack replyBroadcast is only supported for text or block thread replies."));
        }
        let raw = a::s(args, &["to", "target", "channelId"]).ok_or_else(|| bad("upload-file requires target (the Slack channel id)"))?;
        let src = a::text(args, &["filePath"]).or_else(|| a::text(args, &["path"])).or_else(|| a::text(args, &["media"])).filter(|s| !s.trim().is_empty()).ok_or_else(|| bad("upload-file requires filePath, path, or media"))?;
        let comment = a::text(args, &["initialComment"]).or_else(|| a::text(args, &["message"])).or_else(|| a::text(args, &["caption"])).unwrap_or_default();
        let top = a::flag(args, "topLevel") == Some(true) || args.get("threadId") == Some(&Value::Null);
        let thread = if top { None } else { a::s(args, &["threadId", "replyTo"]) };
        let user = raw.trim().strip_prefix("user:").map(str::to_string).or_else(|| is_id(raw.trim(), &['U', 'W']).then(|| raw.trim().to_string()));
        let ch = match user {
            Some(u) => self.inner.api("conversations.open", &json!({"users": u}))?["channel"]["id"].as_str().map(str::to_string).ok_or_else(|| ChannelError::new(crate::ChannelErrorKind::Protocol, "Slack conversations.open did not return a conversation ID."))?,
            None => channel_id(&raw),
        };
        let src = src.trim();
        let (path, base, _tmp) = if src.starts_with("http://") || src.starts_with("https://") {
            let data = crate::http::get_bytes(src, &[], UPLOAD_MAX)?;
            let base = src.split(['?', '#']).next().unwrap_or(src).rsplit('/').next().filter(|n| !n.is_empty()).unwrap_or("file").to_string();
            let p = std::env::temp_dir().join(format!("ark-slack-up-{}-{}", std::process::id(), ark_net::crypto::hex(&ark_net::crypto::random_bytes(6))));
            std::fs::write(&p, data).map_err(|e| bad(format!("cannot write {}: {e}", p.display())))?;
            (p.to_string_lossy().into_owned(), base, Some(TempFile(p)))
        } else {
            let p = ark_core::tool::expand_home(src.strip_prefix("file://").unwrap_or(src));
            let p = crate::media_guard::check_current(&p).map_err(bad)?;
            let base = p.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
            (p.to_string_lossy().into_owned(), base, None)
        };
        let m = Media { path: Some(path), name: a::s(args, &["filename"]).unwrap_or(base), caption: a::s(args, &["title"]), ..Default::default() };
        let fid = self.upload(&ch, thread.as_deref(), &m, Some(comment.as_str()).filter(|c| !c.is_empty()))?;
        Ok(json!({"ok": true, "result": {"channelId": ch, "fileId": fid}}))
    }
}

/// Removes a downloaded upload source once the upload is done.
struct TempFile(std::path::PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::super::Config;
    use super::*;
    use crate::testutil::{temp_dir, FakeServer, Req};
    use crate::{Channel, ChannelErrorKind as K};
    use std::time::Duration;

    fn sl(srv: &FakeServer) -> Slack {
        let mut c = Config::new("sl", "xoxb-SECRET");
        c.api_base = srv.url.clone();
        c.retry_base = Duration::from_millis(5);
        c.max_retries = 0;
        Slack::new(c).unwrap()
    }

    fn ok(v: Value) -> (u16, Vec<(String, String)>, String) {
        let mut v = v;
        v["ok"] = json!(true);
        (200, vec![], v.to_string())
    }

    fn form(r: &Req) -> Vec<(String, String)> {
        r.body.split('&').filter(|p| !p.is_empty()).map(|p| p.split_once('=').unwrap_or((p, ""))).map(|(k, v)| (ark_net::urldecode(k), ark_net::urldecode(&v.replace('+', " ")))).collect()
    }

    fn pairs(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
    }

    #[test]
    fn advertises_exactly_the_implemented_actions() {
        let srv = FakeServer::start(|_, _| ok(json!({})));
        let s = sl(&srv);
        assert_eq!(s.message_actions(), ACTIONS.to_vec());
        for x in ["send", "react", "edit", "delete", "reply", "poll", "sticker"] {
            assert_eq!(s.message_action(x, &json!({})).unwrap_err().kind, K::Unsupported);
        }
    }

    #[test]
    fn time_helpers() {
        assert_eq!(iso(1_700_000_000_123), "2023-11-14T22:13:20.123Z");
        assert_eq!(ts_ms("1700000000.123456"), Some(1_700_000_000_123));
        assert_eq!(read_ts(Some("2023-11-14T22:13:20Z".into()), "before").unwrap().as_deref(), Some("1700000000"));
        assert_eq!(read_ts(Some("2023-11-15T00:13:20.5+02:00".into()), "after").unwrap().as_deref(), Some("1700000000.5"));
        assert_eq!(read_ts(Some("1700000000.000100".into()), "after").unwrap().as_deref(), Some("1700000000.000100"));
        assert!(read_ts(Some("yesterday".into()), "before").unwrap_err().message.contains("Invalid Slack read before timestamp"));
        assert_eq!(channel_id("<#C1|general>"), "C1");
        assert_eq!(channel_id("team:T1:channel:C2"), "C2");
        assert_eq!(channel_id("channel:C3"), "C3");
    }

    #[test]
    fn reactions_read_and_pins() {
        let srv = FakeServer::start(|r, _| match r.path.as_str() {
            "/reactions.get" => ok(json!({"message": {"reactions": [{"name": "thumbsup", "count": 3, "users": ["U1", "U2", "U3"]}]}})),
            "/conversations.history" => ok(json!({"messages": [{"ts": "1700000000.123456", "text": "hi"}], "has_more": true})),
            "/conversations.replies" => ok(json!({"messages": [{"ts": "1700000000.000001", "text": "root"}, {"ts": "1700000005.000002", "text": "reply"}], "has_more": false})),
            "/pins.list" => ok(json!({"items": [{"type": "message", "message": {"ts": "1700000000.5", "text": "pinned"}}, {"type": "file", "file": {"id": "F1"}}]})),
            _ => ok(json!({})),
        });
        let s = sl(&srv);
        let v = s.message_action("reactions", &json!({"target": "channel:C1", "messageId": "1.2", "limit": 2})).unwrap();
        assert_eq!(v["reactions"][0], json!({"name": "thumbsup", "count": 3, "users": ["U1", "U2"]}));
        let v = s.message_action("read", &json!({"target": "C1", "limit": 10, "before": "2023-11-14T22:13:20Z", "after": "1690000000"})).unwrap();
        assert_eq!((v["channelId"].as_str(), v["hasMore"].as_bool(), v["messages"][0]["timestampMs"].as_i64()), (Some("C1"), Some(true), Some(1_700_000_000_123)));
        assert_eq!(v["messages"][0]["timestampUtc"], "2023-11-14T22:13:20.123Z");
        let v = s.message_action("read", &json!({"channelId": "C1", "threadId": "1700000000.000001"})).unwrap();
        assert_eq!((v["messages"].as_array().unwrap().len(), v["messages"][0]["text"].as_str(), v["threadId"].as_str()), (1, Some("reply"), Some("1700000000.000001")), "thread root excluded");
        let v = s.message_action("read", &json!({"channelId": "C1", "messageId": "1700000000.123456"})).unwrap();
        assert_eq!((v["messages"].as_array().unwrap().len(), v["hasMore"].as_bool()), (1, Some(false)));
        s.message_action("pin", &json!({"target": "C1", "messageId": "1.2"})).unwrap();
        s.message_action("unpin", &json!({"target": "C1", "messageId": "1.2"})).unwrap();
        let v = s.message_action("list-pins", &json!({"target": "C1"})).unwrap();
        assert_eq!((v["pins"][0]["message"]["timestampMs"].as_i64(), v["pins"][1]["file"]["id"].as_str()), (Some(1_700_000_000_500), Some("F1")));
        let r = srv.requests();
        assert_eq!((r[0].path.as_str(), form(&r[0])), ("/reactions.get", pairs(&[("channel", "C1"), ("timestamp", "1.2"), ("full", "true")])));
        assert_eq!((r[1].path.as_str(), form(&r[1])), ("/conversations.history", pairs(&[("channel", "C1"), ("limit", "10"), ("latest", "1700000000"), ("oldest", "1690000000")])));
        assert_eq!((r[2].path.as_str(), form(&r[2])), ("/conversations.replies", pairs(&[("channel", "C1"), ("ts", "1700000000.000001"), ("oldest", "1700000000.000001")])));
        assert_eq!(form(&r[3]), pairs(&[("channel", "C1"), ("limit", "1"), ("inclusive", "true"), ("latest", "1700000000.123456"), ("oldest", "1700000000.123456")]));
        assert_eq!((r[4].path.as_str(), r[4].json()), ("/pins.add", json!({"channel": "C1", "timestamp": "1.2"})));
        assert_eq!((r[5].path.as_str(), r[5].json()), ("/pins.remove", json!({"channel": "C1", "timestamp": "1.2"})));
        assert_eq!((r[6].path.as_str(), form(&r[6])), ("/pins.list", pairs(&[("channel", "C1")])));
        assert_eq!(r[0].header("authorization"), Some("Bearer xoxb-SECRET"));
        assert!(s.message_action("pin", &json!({"target": "C1"})).unwrap_err().message.contains("messageId required"));
        assert!(s.message_action("read", &json!({"target": "C1", "limit": 0})).unwrap_err().message.contains("positive integer"));
        assert!(s.message_action("reactions", &json!({"messageId": "1"})).unwrap_err().message.contains("requires target"));
        assert_eq!(srv.requests().len(), 7);
    }

    #[test]
    fn member_info_emoji_list_and_conversation_open() {
        let srv = FakeServer::start(|r, _| match r.path.as_str() {
            "/users.info" => ok(json!({"user": {"id": "U1", "name": "amy"}})),
            "/emoji.list" => ok(json!({"emoji": {"zebra": "https://e/z.png", "party": "https://e/p.gif", "yay": "alias:party"}})),
            "/conversations.open" => ok(json!({"channel": {"id": "D123"}})),
            _ => ok(json!({})),
        });
        let s = sl(&srv);
        let v = s.message_action("member-info", &json!({"userId": "U1"})).unwrap();
        assert_eq!(v["info"]["user"]["name"], "amy");
        let v = s.message_action("emoji-list", &json!({"limit": 2})).unwrap();
        assert_eq!(v["emojis"], json!([{"name": "party", "identifier": "party"}, {"name": "yay", "identifier": "yay", "aliasOf": "party"}]));
        let v = s.message_action("conversation-open", &json!({"userIds": ["U1", "W2"], "teamId": "T9"})).unwrap();
        assert_eq!(v, json!({"ok": true, "channelId": "D123", "target": "team:T9:channel:D123"}));
        assert_eq!(s.message_action("conversation-open", &json!({"userIds": "U1"})).unwrap()["target"], "channel:D123");
        let r = srv.requests();
        assert_eq!((r[0].path.as_str(), form(&r[0])), ("/users.info", pairs(&[("user", "U1")])));
        assert_eq!(r[1].path, "/emoji.list");
        assert_eq!((r[2].path.as_str(), r[2].json()), ("/conversations.open", json!({"users": "U1,W2"})));
        for (action, args, err) in [
            ("member-info", json!({}), "requires a userId"),
            ("emoji-list", json!({"limit": -1}), "positive integer"),
            ("conversation-open", json!({"userIds": ["U1", "U1"]}), "distinct"),
            ("conversation-open", json!({"userIds": ["C1"]}), "1-8 Slack user ids"),
            ("conversation-open", json!({"userIds": ["U1", "U2", "U3", "U4", "U5", "U6", "U7", "U8", "U9"]}), "1-8"),
            ("conversation-open", json!({"userIds": ["U1"], "teamId": "X1"}), "teamId"),
        ] {
            assert!(s.message_action(action, &args).unwrap_err().message.contains(err), "{action} {args}");
        }
        assert_eq!(srv.requests().len(), 4);
    }

    #[test]
    fn download_file_checks_scope_and_saves() {
        let srv = FakeServer::start(|r, _| {
            let base = r.header("host").map(|h| format!("http://{h}")).unwrap_or_default();
            match (r.path.as_str(), form(r).first().map(|(_, v)| v.clone()).unwrap_or_default().as_str()) {
                ("/files.info", "F1") => ok(json!({"file": {"id": "F1", "name": "report.pdf", "mimetype": "application/pdf", "url_private_download": format!("{base}/dl/F1"), "channels": ["C1"]}})),
                ("/files.info", "F2") => ok(json!({"file": {"id": "F2", "name": "x.png", "url_private": format!("{base}/dl/F2"), "shares": {"public": {"C1": [{"ts": "5.5", "thread_ts": "1.1"}]}}}})),
                ("/files.info", "F3") => ok(json!({"file": {"id": "F3", "name": "login.png", "url_private": format!("{base}/dl/F3"), "channels": ["C1"]}})),
                ("/files.info", _) => ok(json!({"file": {"id": "F4"}})),
                ("/dl/F3", _) => (200, vec![], "<!DOCTYPE html><html>login</html>".into()),
                _ => (200, vec![], "PDFBYTES".into()),
            }
        });
        let s = sl(&srv);
        let v = s.message_action("download-file", &json!({"fileId": "F1", "target": "C1"})).unwrap();
        assert_eq!((v["ok"].as_bool(), v["contentType"].as_str(), v["placeholder"].as_str()), (Some(true), Some("application/pdf"), Some("[Slack file: report.pdf (application/pdf, fileId: F1)]")));
        assert_eq!(std::fs::read(v["path"].as_str().unwrap()).unwrap(), b"PDFBYTES");
        assert_eq!(v["media"]["mediaUrl"], v["path"]);
        let dl = srv.requests().into_iter().find(|r| r.path == "/dl/F1").unwrap();
        assert_eq!(dl.header("authorization"), Some("Bearer xoxb-SECRET"));
        assert_eq!(s.message_action("download-file", &json!({"fileId": "F2", "channelId": "C1", "threadId": "1.1"})).unwrap()["ok"], true, "thread share proves scope");
        for args in [json!({"fileId": "F2", "channelId": "C1", "threadId": "9.9"}), json!({"fileId": "F1", "to": "C2"}), json!({"fileId": "F3", "to": "C1"}), json!({"fileId": "F4", "to": "C1"})] {
            assert_eq!(s.message_action("download-file", &args).unwrap(), json!({"ok": false, "error": DOWNLOAD_FAILED}), "{args}");
        }
        assert!(s.message_action("download-file", &json!({"messageId": "1.2", "to": "C1"})).unwrap_err().message.contains("not messageId"));
        assert!(s.message_action("download-file", &json!({"fileId": "F1"})).unwrap_err().message.contains("requires channelId or to"));
        assert_eq!(form(&srv.requests()[0]), pairs(&[("file", "F1")]));
    }

    #[test]
    fn upload_file_goes_through_upload_v2() {
        let srv = FakeServer::start(|r, _| {
            let base = r.header("host").map(|h| format!("http://{h}")).unwrap_or_default();
            match r.path.as_str() {
                "/files.getUploadURLExternal" => ok(json!({"upload_url": format!("{base}/upload"), "file_id": "F9"})),
                "/conversations.open" => ok(json!({"channel": {"id": "D7"}})),
                "/src/notes.txt" => (200, vec![], "REMOTE".into()),
                "/upload" => (200, vec![], "OK".into()),
                _ => ok(json!({})),
            }
        });
        let s = sl(&srv);
        let p = temp_dir("slup").join("a.txt");
        std::fs::write(&p, "LOCAL").unwrap();
        let v = s.message_action("upload-file", &json!({"target": "C1", "filePath": p.to_string_lossy(), "message": "here", "title": "Notes", "threadId": "1.1"})).unwrap();
        assert_eq!(v, json!({"ok": true, "result": {"channelId": "C1", "fileId": "F9"}}));
        let v = s.message_action("upload-file", &json!({"to": "user:U5", "media": format!("{}/src/notes.txt", srv.url), "filename": "n.txt", "replyTo": "2.2", "topLevel": true})).unwrap();
        assert_eq!(v["result"]["channelId"], "D7");
        let r = srv.requests();
        let paths: Vec<&str> = r.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(paths, ["/files.getUploadURLExternal", "/upload", "/files.completeUploadExternal", "/conversations.open", "/src/notes.txt", "/files.getUploadURLExternal", "/upload", "/files.completeUploadExternal"]);
        assert_eq!(form(&r[0]), pairs(&[("filename", "a.txt"), ("length", "5")]));
        assert_eq!(r[1].body, "LOCAL");
        let done = form(&r[2]);
        assert!(done.contains(&("channel_id".into(), "C1".into())) && done.contains(&("thread_ts".into(), "1.1".into())) && done.contains(&("initial_comment".into(), "here".into())));
        assert!(done[0].1.contains("\"title\":\"Notes\""));
        assert_eq!(form(&r[5]), pairs(&[("filename", "n.txt"), ("length", "6")]));
        assert_eq!(r[6].body, "REMOTE");
        let done = form(&r[7]);
        assert!(done.contains(&("channel_id".into(), "D7".into())) && !done.iter().any(|(k, _)| k == "thread_ts" || k == "initial_comment"), "topLevel drops the thread");
        assert!(s.message_action("upload-file", &json!({"target": "C1"})).unwrap_err().message.contains("filePath, path, or media"));
        assert!(s.message_action("upload-file", &json!({"target": "C1", "filePath": "/x", "replyBroadcast": true})).unwrap_err().message.contains("replyBroadcast"));
    }
}
