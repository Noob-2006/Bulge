//! Cloud-document comments (Hermes `feishu_comment.py`, MIT): `drive.notice.comment_add_v1`
//! addressed to the bot becomes an Inbound in chat `doc:<file_type>:<file_token>` whose
//! thread names the comment (`l:<comment_id>` quoted-text thread, `w:<comment_id>` whole
//! document). The text is upstream's prompt: document title/link, the quoted text, the
//! thread timeline (≤ 20 local / 12 whole entries around the current one, own replies
//! marked) and the reply rules (plain text, `NO_REPLY` to stay silent). An "OK" reaction
//! marks the comment while the agent works. Replies go to the thread
//! (`…/comments/{id}/replies`), whole-document comments get a new whole comment, and a
//! thread that refuses replies (1069302) falls back to a whole comment. Simplification:
//! wiki links in the thread are listed as found, not resolved to their underlying docs.

use super::{has_code, Body, Feishu};
use crate::{ChannelError, ChatType, Inbound, Sent};
use serde_json::{json, Value};

const LOCAL_TIMELINE: usize = 20;
const WHOLE_TIMELINE: usize = 12;
const PROMPT_TEXT: usize = 220;
const MAX_PAGES: usize = 5;
pub const NO_REPLY: &str = "NO_REPLY";
const REPLY_NOT_ALLOWED: i64 = 1069302;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Event {
    pub event_id: String,
    pub comment_id: String,
    pub reply_id: String,
    pub file_token: String,
    pub file_type: String,
    pub notice_type: String,
    pub from: String,
    pub to: String,
}

pub(super) fn parse(v: &Value) -> Option<Event> {
    let e = &v["event"];
    if !e.is_object() {
        return None;
    }
    let s = |x: &Value| x.as_str().map(str::to_string).or_else(|| x.as_i64().map(|n| n.to_string())).unwrap_or_default();
    let m = &e["notice_meta"];
    Some(Event {
        event_id: s(&v["header"]["event_id"]),
        comment_id: s(&e["comment_id"]),
        reply_id: s(&e["reply_id"]),
        file_token: s(&m["file_token"]),
        file_type: s(&m["file_type"]),
        notice_type: s(&m["notice_type"]),
        from: s(&m["from_user_id"]["open_id"]),
        to: s(&m["to_user_id"]["open_id"]),
    })
}

/// Upstream's early-exit filters; `None` = handle it.
pub(super) fn skip_reason(e: &Event, me: &str) -> Option<&'static str> {
    if !me.is_empty() && e.from == me {
        return Some("self-authored");
    }
    if e.to.is_empty() || (!me.is_empty() && e.to != me) {
        return Some("not addressed to the bot");
    }
    if !e.notice_type.is_empty() && !matches!(e.notice_type.as_str(), "add_comment" | "add_reply") {
        return Some("notice type");
    }
    if e.file_token.is_empty() || e.file_type.is_empty() || e.comment_id.is_empty() {
        return Some("missing fields");
    }
    None
}

fn maybe_json(v: &Value) -> Value {
    match v {
        Value::String(s) => serde_json::from_str(s).unwrap_or(Value::Null),
        v => v.clone(),
    }
}

/// Plain text of a reply's `content.elements` (text_run, docs_link, person). `semantic`
/// (the prompt's "current text") drops our own @mention and collapses whitespace.
pub(super) fn reply_text(r: &Value, semantic: bool, me: &str) -> String {
    let c = maybe_json(&r["content"]);
    let mut out = String::new();
    for el in c["elements"].as_array().into_iter().flatten() {
        match el["type"].as_str().unwrap_or("") {
            "text_run" => out.push_str(el["text_run"]["text"].as_str().unwrap_or("")),
            "docs_link" => out.push_str(el["docs_link"]["url"].as_str().unwrap_or("")),
            "person" => {
                let uid = el["person"]["user_id"].as_str().unwrap_or(if semantic { "" } else { "unknown" });
                if !(semantic && !me.is_empty() && uid == me) {
                    out.push('@');
                    out.push_str(uid);
                }
            }
            _ => {}
        }
    }
    if semantic {
        out.split_whitespace().collect::<Vec<_>>().join(" ")
    } else {
        out
    }
}

fn reply_user(r: &Value) -> String {
    match &r["user_id"] {
        Value::Object(o) => o.get("open_id").or_else(|| o.get("user_id")).and_then(Value::as_str).unwrap_or("").to_string(),
        v => v.as_str().unwrap_or("").to_string(),
    }
}

/// (user, text, is us)
type Timeline = Vec<(String, String, bool)>;

fn timeline(replies: &[Value], me: &str) -> Timeline {
    replies
        .iter()
        .map(|r| {
            let u = reply_user(r);
            let own = !me.is_empty() && u == me;
            (u, reply_text(r, false, ""), own)
        })
        .collect()
}

/// Up to `limit` entries: `pinned` + `center`, widening around `center`.
pub(super) fn select(t: &Timeline, limit: usize, center: isize, pinned: &[isize]) -> Timeline {
    let n = t.len() as isize;
    if t.len() <= limit {
        return t.clone();
    }
    let mut sel: std::collections::BTreeSet<isize> = pinned.iter().chain([center].iter()).copied().filter(|i| (0..n).contains(i)).collect();
    let (mut lo, mut hi) = (center - 1, center + 1);
    while sel.len() < limit && (lo >= 0 || hi < n) {
        if lo >= 0 {
            sel.insert(lo);
        }
        if sel.len() < limit && hi < n {
            sel.insert(hi);
        }
        lo -= 1;
        hi += 1;
    }
    if sel.is_empty() {
        return t[t.len() - limit..].to_vec();
    }
    sel.into_iter().map(|i| t[i as usize].clone()).collect()
}

fn trunc(s: &str, limit: usize) -> String {
    if s.chars().count() <= limit {
        s.to_string()
    } else {
        format!("{}...", s.chars().take(limit).collect::<String>())
    }
}

/// Feishu document links (`…/docx/<token>` etc.) found in the replies, deduplicated.
fn doc_links(replies: &[Value], current: &str) -> String {
    let mut seen = std::collections::HashSet::new();
    let mut lines = vec![];
    for r in replies {
        let c = maybe_json(&r["content"]);
        for el in c["elements"].as_array().into_iter().flatten() {
            let url = el["docs_link"]["url"].as_str().or_else(|| el["link"]["url"].as_str()).unwrap_or("");
            let Some(host) = ["feishu.cn/", "larkoffice.com/", "larksuite.com/", "lark.suite.com/"].iter().find_map(|h| url.find(h).map(|i| &url[i + h.len()..])) else { continue };
            let mut parts = host.split(['/', '?', '#']);
            let (Some(ty), Some(tok)) = (parts.next(), parts.next()) else { continue };
            let ok_ty = matches!(ty, "wiki" | "doc" | "docx" | "sheet" | "sheets" | "slides" | "mindnote" | "bitable" | "base" | "file");
            if !ok_ty || !(10..=40).contains(&tok.len()) || !tok.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') || !seen.insert(tok.to_string()) {
                continue;
            }
            let same = if tok == current { " (same as current document)" } else { "" };
            lines.push(format!("- {ty}:{tok}{same} ({})", url.chars().take(80).collect::<String>()));
        }
    }
    if lines.is_empty() {
        String::new()
    } else {
        format!("\nReferenced documents in comments:\n{}", lines.join("\n"))
    }
}

const COMMON: &str = "This is a Feishu document comment thread, not an IM chat.
Your reply will be posted automatically. Just output the reply text.
Use the thread timeline above as the main context.
The quoted content is your primary anchor — insert/summarize/explain requests are about it.
Do not guess document content you haven't read.
Reply in the same language as the user's comment unless they request otherwise.
Use plain text only. Do not use Markdown, headings, bullet lists, tables, or code blocks.
Do not show your reasoning process. Do not start with \"I will\", \"Let me\", or \"I'll first\".
Output only the final user-facing reply.
If no reply is needed, output exactly NO_REPLY.";

pub(super) struct Doc<'a> {
    pub title: &'a str,
    pub url: &'a str,
    pub file_type: &'a str,
    pub file_token: &'a str,
}

fn build(intro: Vec<String>, d: &Doc, ids: Vec<String>, label: &str, all: usize, sel: &Timeline, refs: &str) -> String {
    let mut lines = intro;
    lines.push("This comment mentioned you (@mention is for routing, not task content).".into());
    lines.push(format!("Document link: {}", d.url));
    lines.push("Current commented document:".into());
    lines.push(format!("- file_type={}", d.file_type));
    lines.push(format!("- file_token={}", d.file_token));
    lines.extend(ids);
    lines.push(String::new());
    lines.push(format!("{label} ({}/{all} entries):", sel.len()));
    for (u, t, own) in sel {
        lines.push(format!("[{u}] {}{}", trunc(t, PROMPT_TEXT), if *own { " <-- YOU" } else { "" }));
    }
    if !refs.is_empty() {
        lines.push(refs.to_string());
    }
    lines.push(String::new());
    lines.push(COMMON.into());
    lines.join("\n")
}

/// Prompt for a comment on quoted text, from its thread replies.
pub(super) fn local_prompt(d: &Doc, comment_id: &str, quote: &str, replies: &[Value], reply_id: &str, from: &str, me: &str) -> String {
    let t = timeline(replies, me);
    let root = replies.first().map(|r| reply_text(r, true, me)).unwrap_or_default();
    let mut target = replies.iter().enumerate().rfind(|(_, r)| !reply_id.is_empty() && r["reply_id"].as_str() == Some(reply_id)).map(|(i, r)| (reply_text(r, true, me), i as isize));
    if target.as_ref().is_none_or(|(x, _)| x.is_empty()) {
        if let Some(i) = t.iter().rposition(|e| e.0 == from) {
            target = Some((t[i].1.clone(), i as isize));
        }
    }
    let (text, idx) = target.unwrap_or((String::new(), -1));
    let intro = vec![
        format!("The user added a reply in \"{}\".", d.title),
        format!("Current user comment text: \"{}\"", trunc(&text, PROMPT_TEXT)),
        format!("Original comment text: \"{}\"", trunc(&root, PROMPT_TEXT)),
        format!("Quoted content: \"{}\"", trunc(quote, 500)),
    ];
    let sel = select(&t, LOCAL_TIMELINE, idx, &[0, t.len() as isize - 1]);
    build(intro, d, vec![format!("- comment_id={comment_id}")], "Current comment card timeline", t.len(), &sel, &doc_links(replies, d.file_token))
}

/// Prompt for a whole-document comment, from every whole comment's replies.
pub(super) fn whole_prompt(d: &Doc, replies: &[Value], from: &str, me: &str) -> String {
    let t = timeline(replies, me);
    let (mut text, mut idx, mut own) = (String::new(), -1isize, -1isize);
    for (i, r) in replies.iter().enumerate() {
        if t[i].0 == from {
            text = reply_text(r, true, me);
            idx = i as isize;
        }
        if t[i].2 {
            own = i as isize;
        }
    }
    if text.is_empty() {
        if let Some(i) = t.iter().rposition(|e| !e.2) {
            text = t[i].1.clone();
            idx = i as isize;
        }
    }
    let intro = vec![format!("The user added a comment in \"{}\".", d.title), format!("Current user comment text: \"{}\"", trunc(&text, PROMPT_TEXT)), "This is a whole-document comment.".into()];
    let sel = select(&t, WHOLE_TIMELINE, idx, &[own]);
    build(intro, d, vec![], "Whole-document comment timeline", t.len(), &sel, &doc_links(replies, d.file_token))
}

fn sanitize(t: &str) -> String {
    t.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

impl Feishu {
    fn drive(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, ChannelError> {
        self.api(method, path, body.map(Body::Json).unwrap_or(Body::None))
    }

    fn comment_reaction(&self, e: &Event, add: bool) {
        if e.reply_id.is_empty() {
            return;
        }
        let path = format!("/open-apis/drive/v2/files/{}/comments/reaction?file_type={}", ark_net::urlencode(&e.file_token), ark_net::urlencode(&e.file_type));
        let _ = self.drive("POST", &path, Some(&json!({"action": if add { "add" } else { "delete" }, "reply_id": e.reply_id, "reaction_type": "OK"})));
    }

    /// GET up to `MAX_PAGES` pages of `data.items`.
    fn pages(&self, path: &str) -> Vec<Value> {
        let mut out = vec![];
        let mut token = String::new();
        for _ in 0..MAX_PAGES {
            let p = if token.is_empty() { path.to_string() } else { format!("{path}&page_token={}", ark_net::urlencode(&token)) };
            let Ok(v) = self.drive("GET", &p, None) else { break };
            out.extend(v["data"]["items"].as_array().cloned().unwrap_or_default());
            token = if v["data"]["has_more"] == true { v["data"]["page_token"].as_str().unwrap_or("").to_string() } else { String::new() };
            if token.is_empty() {
                break;
            }
        }
        out
    }

    /// The new comment / reply may not be queryable yet when the notice arrives: retry.
    fn retrying<T>(&self, mut f: impl FnMut() -> Option<T>) -> Option<T> {
        for i in 0..self.comment_retries.max(1) {
            if let Some(x) = f() {
                return Some(x);
            }
            if i + 1 < self.comment_retries {
                std::thread::sleep(self.comment_retry_delay);
            }
        }
        None
    }

    /// `drive.notice.comment_add_v1` → Inbound (or None when filtered / disabled).
    pub(super) fn comment_inbound(&self, v: &Value) -> Option<Inbound> {
        let e = parse(v)?;
        if !self.comments {
            return None;
        }
        let me = self.bot().open_id;
        if skip_reason(&e, &me).is_some() {
            return None;
        }
        let doc_key = format!("{}:{}", e.file_type, e.file_token);
        if !self.comment_docs.is_empty() && !self.comment_docs.iter().any(|d| d == "*" || *d == doc_key || *d == e.file_token) {
            return None;
        }
        self.comment_reaction(&e, true);
        let (ft, tok) = (ark_net::urlencode(&e.file_type), ark_net::urlencode(&e.file_token));
        let meta = self.drive("POST", "/open-apis/drive/v1/metas/batch_query", Some(&json!({"request_docs": [{"doc_token": e.file_token, "doc_type": e.file_type}], "with_url": true}))).ok();
        let m = meta.as_ref().map(|v| if v["data"]["metas"].is_array() { v["data"]["metas"][0].clone() } else { v["data"]["metas"][&e.file_token].clone() }).unwrap_or(Value::Null);
        let title = m["title"].as_str().filter(|t| !t.is_empty()).unwrap_or("Untitled").to_string();
        let url = m["url"].as_str().unwrap_or("").to_string();
        let q = format!("/open-apis/drive/v1/files/{tok}/comments/batch_query?file_type={ft}&user_id_type=open_id");
        let detail = self.retrying(|| self.drive("POST", &q, Some(&json!({"comment_ids": [e.comment_id]}))).ok().and_then(|v| v["data"]["items"].get(0).cloned())).unwrap_or(Value::Null);
        let whole = detail["is_whole"] == true;
        let d = Doc { title: &title, url: &url, file_type: &e.file_type, file_token: &e.file_token };
        let text = if whole {
            let comments = self.pages(&format!("/open-apis/drive/v1/files/{tok}/comments?file_type={ft}&is_whole=true&page_size=100&user_id_type=open_id"));
            let replies: Vec<Value> = comments.iter().flat_map(|c| maybe_json(&c["reply_list"])["replies"].as_array().cloned().unwrap_or_default()).collect();
            whole_prompt(&d, &replies, &e.from, &me)
        } else {
            let path = format!("/open-apis/drive/v1/files/{tok}/comments/{}/replies?file_type={ft}&page_size=100&user_id_type=open_id", ark_net::urlencode(&e.comment_id));
            let mut replies = vec![];
            let _ = self.retrying(|| {
                replies = self.pages(&path);
                (e.reply_id.is_empty() || replies.iter().any(|r| r["reply_id"].as_str() == Some(e.reply_id.as_str()))).then_some(())
            });
            local_prompt(&d, &e.comment_id, detail["quote"].as_str().unwrap_or(""), &replies, &e.reply_id, &e.from, &me)
        };
        let id = if e.reply_id.is_empty() { e.comment_id.clone() } else { e.reply_id.clone() };
        Some(Inbound {
            channel: self.id.clone(),
            chat: format!("doc:{doc_key}"),
            chat_type: ChatType::Thread,
            chat_name: title,
            thread: Some(format!("{}:{}:{}", if whole { "w" } else { "l" }, e.comment_id, e.reply_id)),
            sender: e.from.clone(),
            text,
            message_id: format!("cm:{id}"),
            ts: super::now_secs(),
            mentioned: true,
            ..Default::default()
        })
    }

    /// Reply into a comment thread (`chat = doc:<type>:<token>`, `thread = w|l:<comment>:<reply>`).
    pub(super) fn comment_send(&self, chat: &str, thread: Option<&str>, text: &str) -> Result<Sent, ChannelError> {
        let bad = || ChannelError::new(crate::ChannelErrorKind::Fatal, format!("feishu: comment reply needs chat doc:<type>:<token> and a comment thread, got {chat} / {thread:?}"));
        let (ft, tok) = chat.strip_prefix("doc:").and_then(|r| r.split_once(':')).ok_or_else(bad)?;
        let mut th = thread.ok_or_else(bad)?.splitn(3, ':');
        let (kind, cid, rid) = (th.next().unwrap_or(""), th.next().unwrap_or(""), th.next().unwrap_or(""));
        if cid.is_empty() {
            return Err(bad());
        }
        let ev = Event { file_type: ft.into(), file_token: tok.into(), reply_id: rid.into(), ..Default::default() };
        let text = crate::markup::convert(text.trim(), crate::Markup::Plain);
        let mut sent = Sent::default();
        if text.is_empty() || text.contains(NO_REPLY) {
            self.comment_reaction(&ev, false);
            return Ok(sent);
        }
        let (fte, toke) = (ark_net::urlencode(ft), ark_net::urlencode(tok));
        let mut whole = kind == "w";
        for chunk in crate::chunk::split(&text, super::MAX_MESSAGE, crate::LenUnit::Chars) {
            let body = sanitize(&chunk);
            if !whole {
                let path = format!("/open-apis/drive/v1/files/{toke}/comments/{}/replies?file_type={fte}", ark_net::urlencode(cid));
                match self.drive("POST", &path, Some(&json!({"content": {"elements": [{"type": "text_run", "text_run": {"text": body}}]}}))) {
                    Ok(v) => {
                        sent.ids.push(v["data"]["reply_id"].as_str().unwrap_or("").to_string());
                        continue;
                    }
                    // This thread takes no replies: this and later chunks become whole comments.
                    Err(e) if has_code(&e, &[REPLY_NOT_ALLOWED]) => whole = true,
                    Err(e) => return Err(e),
                }
            }
            let v = self.drive("POST", &format!("/open-apis/drive/v1/files/{toke}/new_comments"), Some(&json!({"file_type": ft, "reply_elements": [{"type": "text", "text": body}]})))?;
            sent.ids.push(v["data"]["comment_id"].as_str().unwrap_or("").to_string());
        }
        self.comment_reaction(&ev, false);
        Ok(sent)
    }
}
