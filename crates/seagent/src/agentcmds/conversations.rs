//! `conversations_list`, `conversations_send`, `conversations_turn` (OpenClaw
//! `src/agents/tools/conversation-tools.ts`, gateway `conversations.*`, `routing/conversation-ref.ts`).
//!
//! External conversations get stable opaque addresses `conv_<32 hex>` = the first 32 hex of
//! sha256(JSON `[channel, accountId, kind, peerId, parentConversationRef, threadId]`), built from
//! transport identity only. Every channel inbound updates the directory
//! `<data>/conversations.json` (first/last seen, label). `conversations_send` delivers text
//! through the channel without running the local agent; `conversations_turn` sends and waits
//! (1–300 s, default 30) for the correlated inbound reply, which [`claim`] hands to the waiter
//! instead of starting a second local turn.

use seagent_channel::{Channel, ChatType, Inbound, Outbound};
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use seagent_kernel::config::Paths;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub conversation_ref: String,
    pub channel: String,
    pub account_id: String,
    pub kind: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub first_seen_at: u64,
    pub last_seen_at: u64,
}

/// Upstream `normalizeConversationPeerId`.
pub fn normalize_peer(channel: &str, v: &str) -> String {
    let mut n = v.trim().to_string();
    let pre = format!("{}:", channel.trim().to_lowercase());
    if n.to_lowercase().starts_with(&pre) {
        n = n[pre.len()..].trim().to_string();
    }
    for p in ["user:", "channel:", "group:", "conversation:", "room:", "dm:", "thread:"] {
        if n.to_lowercase().starts_with(p) {
            n = n[p.len()..].to_string();
            break;
        }
    }
    n.trim().to_string()
}

/// Upstream `buildConversationRef`.
pub fn conversation_ref(channel: &str, account: &str, kind: &str, peer: &str, parent: &str, thread: &str) -> String {
    let id = serde_json::to_string(&json!([channel, account, kind, peer, parent, thread])).unwrap_or_default();
    format!("conv_{}", &seagent_net::crypto::hex(&seagent_net::crypto::sha256(id.as_bytes()))[..32])
}

fn kind_of(t: ChatType) -> &'static str {
    match t {
        ChatType::Direct => "direct",
        ChatType::Group | ChatType::Thread => "group",
        ChatType::Channel => "channel",
    }
}

fn account(m: &Inbound) -> String {
    if m.account.is_empty() { "default".into() } else { m.account.clone() }
}

/// (ref, kind, peer, parent ref) of an inbound's conversation.
fn ref_of(m: &Inbound) -> (String, String, String, String) {
    let kind = kind_of(m.chat_type).to_string();
    let peer = normalize_peer(&m.channel, &m.chat);
    match &m.thread {
        Some(t) => {
            let parent = conversation_ref(&m.channel, &account(m), &kind, &peer, "", "");
            (conversation_ref(&m.channel, &account(m), &kind, &peer, &parent, t), kind, peer, parent)
        }
        None => (conversation_ref(&m.channel, &account(m), &kind, &peer, "", ""), kind, peer, String::new()),
    }
}

static DIR_LOCK: Mutex<()> = Mutex::new(());

fn file(paths: &Paths) -> std::path::PathBuf {
    paths.data.join("conversations.json")
}

pub fn load(paths: &Paths) -> BTreeMap<String, Entry> {
    std::fs::read_to_string(file(paths)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

/// Record (or refresh) the conversation an inbound came from.
pub fn observe(paths: &Paths, m: &Inbound) {
    if m.channel.is_empty() || m.chat.is_empty() {
        return;
    }
    let _g = DIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut all = load(paths);
    let (r, kind, peer, _) = ref_of(m);
    let now = super::now_ms();
    let label = Some(if !m.chat_name.is_empty() { m.chat_name.clone() } else { m.sender_name.clone() }).filter(|s| !s.trim().is_empty());
    let e = all.entry(r.clone()).or_insert_with(|| Entry { conversation_ref: r.clone(), channel: m.channel.clone(), account_id: account(m), kind, target: peer, thread_id: m.thread.clone(), label: None, first_seen_at: now, last_seen_at: now });
    e.last_seen_at = now;
    if label.is_some() {
        e.label = label;
    }
    let _ = std::fs::create_dir_all(&paths.data);
    let _ = seagent_kernel::util::atomic_write(&file(paths), serde_json::to_string_pretty(&all).unwrap_or_default().as_bytes());
}

/// Upstream `conversations.list`: newest first, optional channel / text filter, limit ≤ 100.
pub fn list(paths: &Paths, channel: Option<&str>, query: Option<&str>, limit: usize) -> Vec<Entry> {
    let q = query.map(str::to_lowercase);
    let mut v: Vec<Entry> = load(paths).into_values().filter(|e| channel.is_none_or(|c| e.channel == c)).filter(|e| q.as_ref().is_none_or(|q| e.target.to_lowercase().contains(q) || e.label.as_deref().is_some_and(|l| l.to_lowercase().contains(q)) || e.conversation_ref.contains(q))).collect();
    v.sort_by(|a, b| b.last_seen_at.cmp(&a.last_seen_at).then(a.conversation_ref.cmp(&b.conversation_ref)));
    v.truncate(limit.clamp(1, 100));
    v
}

type Waiters = Mutex<HashMap<String, mpsc::Sender<Value>>>;
fn waiters() -> &'static Waiters {
    static W: std::sync::OnceLock<Waiters> = std::sync::OnceLock::new();
    W.get_or_init(Default::default)
}

/// An inbound that answers a pending `conversations_turn` goes to the waiter (true = consumed).
pub fn claim(m: &Inbound) -> bool {
    let (r, ..) = ref_of(m);
    let parent = m.thread.as_ref().map(|_| ref_of(&Inbound { thread: None, ..m.clone() }).0);
    let mut w = waiters().lock().unwrap_or_else(|e| e.into_inner());
    let key = if w.contains_key(&r) { r.clone() } else if let Some(p) = parent.filter(|p| w.contains_key(p)) { p } else { return false };
    let tx = w.remove(&key).unwrap();
    let reply = json!({"conversationRef": key, "messageId": if m.message_id.is_empty() { format!("in_{}", super::now_ms()) } else { m.message_id.clone() }, "replyToId": m.reply.as_ref().map(|r| r.id.clone()), "threadId": m.thread, "text": m.text, "timestamp": if m.ts > 0 { m.ts as u64 * 1000 } else { super::now_ms() }});
    tx.send(reply).is_ok()
}

pub struct Conversations {
    name: &'static str,
    paths: Paths,
    channels: BTreeMap<String, Arc<dyn Channel>>,
}

fn valid_ref(r: &str) -> bool {
    r.len() == 37 && r.starts_with("conv_") && r[5..].chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

impl Conversations {
    fn entry(&self, input: &Value) -> Result<Entry, String> {
        let raw = input["conversationRef"].as_str().ok_or("missing string argument `conversationRef`")?;
        let r = raw.to_lowercase();
        if !valid_ref(&r) {
            return Err(format!("Invalid conversationRef: {raw}"));
        }
        load(&self.paths).remove(&r).ok_or_else(|| format!("Unknown conversationRef: {raw} (see conversations_list)"))
    }

    fn send(&self, e: &Entry, message: &str) -> Result<Value, String> {
        let ch = self.channels.get(&e.channel).ok_or_else(|| format!("channel `{}` is not running in this host", e.channel))?;
        let out = Outbound { chat: e.target.clone(), thread: e.thread_id.clone(), text: message.to_string(), format: seagent_channel::TextFormat::Markdown, ..Default::default() };
        let sent = ch.send(&out).map_err(|x| x.message)?;
        Ok(json!({"status": "sent", "conversationRef": e.conversation_ref, "channel": e.channel, "messageId": sent.ids.last()}))
    }
}

impl Tool for Conversations {
    fn spec(&self) -> ToolSpec {
        let (d, s) = match self.name {
            "conversations_list" => ("List external conversations as stable conversationRef values. Sessions hold local model context; conversationRef selects an exact external channel destination.", json!({"type": "object", "additionalProperties": false, "properties": {"channel": {"type": "string", "minLength": 1}, "query": {"type": "string", "minLength": 1}, "limit": {"type": "integer", "minimum": 1}}})),
            "conversations_send" => ("Send directly through a conversationRef. This performs channel delivery; it does not run the local agent in the backing session.", json!({"type": "object", "additionalProperties": false, "properties": {"conversationRef": {"type": "string", "pattern": "^conv_[a-f0-9]{32}$"}, "message": {"type": "string", "minLength": 1}}, "required": ["conversationRef", "message"]})),
            _ => ("Send through a conversationRef and wait for its correlated inbound reply. The reply returns here instead of starting a second local agent turn; unsolicited messages still start normal turns.", json!({"type": "object", "additionalProperties": false, "properties": {"conversationRef": {"type": "string", "pattern": "^conv_[a-f0-9]{32}$"}, "message": {"type": "string", "minLength": 1}, "timeoutSeconds": {"type": "integer", "minimum": 1, "maximum": 300}}, "required": ["conversationRef", "message"]})),
        };
        ToolSpec { name: self.name.into(), description: d.into(), input_schema: s, parallel_safe: self.name == "conversations_list", idempotent: false, pinned: false }
    }
    fn effects(&self, _: &ToolCtx, input: &Value) -> Vec<Effect> {
        if self.name == "conversations_list" {
            return vec![];
        }
        let ch = self.entry(input).map(|e| format!("{}:{}", e.channel, e.target)).unwrap_or_else(|_| "conversation".into());
        vec![Effect::Send { channel: ch, payload: input["message"].as_str().unwrap_or("").to_string() }]
    }
    fn call(&self, _: &ToolCtx, input: Value) -> ToolOutput {
        let r: Result<Value, String> = (|| match self.name {
            "conversations_list" => {
                let limit = input["limit"].as_u64().unwrap_or(50).min(100) as usize;
                Ok(json!({"conversations": list(&self.paths, input["channel"].as_str(), input["query"].as_str(), limit)}))
            }
            name => {
                let e = self.entry(&input)?;
                let message = input["message"].as_str().filter(|m| !m.is_empty()).ok_or("missing string argument `message`")?;
                if name == "conversations_send" {
                    return self.send(&e, message);
                }
                let secs = input["timeoutSeconds"].as_u64().unwrap_or(30).clamp(1, 300);
                let (tx, rx) = mpsc::channel();
                waiters().lock().unwrap_or_else(|x| x.into_inner()).insert(e.conversation_ref.clone(), tx);
                let sent = match self.send(&e, message) {
                    Ok(s) => s,
                    Err(err) => {
                        waiters().lock().unwrap_or_else(|x| x.into_inner()).remove(&e.conversation_ref);
                        return Ok(json!({"conversationRef": e.conversation_ref, "channel": e.channel, "correlationPersisted": false, "status": "unknown", "error": err}));
                    }
                };
                let base = json!({"conversationRef": e.conversation_ref, "channel": e.channel, "messageId": sent["messageId"], "correlationPersisted": false});
                match rx.recv_timeout(Duration::from_secs(secs)) {
                    Ok(reply) => {
                        let mut v = base;
                        v["status"] = json!("replied");
                        v["reply"] = reply;
                        Ok(v)
                    }
                    Err(_) => {
                        waiters().lock().unwrap_or_else(|x| x.into_inner()).remove(&e.conversation_ref);
                        let mut v = base;
                        v["status"] = json!("timeout");
                        Ok(v)
                    }
                }
            }
        })();
        match r {
            Ok(v) => ToolOutput::ok(serde_json::to_string_pretty(&v).unwrap_or_default()),
            Err(e) => ToolOutput::err(e),
        }
    }
}

pub fn tools(paths: Paths, channels: BTreeMap<String, Arc<dyn Channel>>) -> Vec<Arc<dyn Tool>> {
    ["conversations_list", "conversations_send", "conversations_turn"].into_iter().map(|n| Arc::new(Conversations { name: n, paths: paths.clone(), channels: channels.clone() }) as Arc<dyn Tool>).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_channel::{ChannelError, Sent};

    struct Fake {
        sent: Mutex<Vec<Outbound>>,
    }
    impl Channel for Fake {
        fn id(&self) -> &str {
            "fake"
        }
        fn poll(&self, _: &seagent_core::Cancel) -> Result<Vec<Inbound>, ChannelError> {
            Ok(vec![])
        }
        fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
            self.sent.lock().unwrap().push(out.clone());
            Ok(Sent::one("m1"))
        }
    }

    fn ctx(paths: &Paths) -> ToolCtx {
        ToolCtx { workspace: paths.data.clone(), session_id: "s".into(), artifacts: paths.data.clone(), home: paths.data.clone(), cancel: seagent_core::Cancel::new(), host: Arc::new(super::super::tests::NoHost), secrets: Arc::new(|s: &str| s.to_string()) }
    }

    #[test]
    fn refs_directory_send_and_turn_capture() {
        assert_eq!(normalize_peer("telegram", "telegram:user:42"), "42");
        let r = conversation_ref("telegram", "default", "direct", "42", "", "");
        assert!(valid_ref(&r), "{r}");
        assert_eq!(r, conversation_ref("telegram", "default", "direct", "42", "", ""), "stable");
        assert_ne!(r, conversation_ref("telegram", "default", "group", "42", "", ""));
        let root = seagent_core::tmp::scratch_path(format!("seagent-conv-{}", seagent_kernel::util::random_hex(6)));
        let paths = Paths { data: root.join("data"), config_dir: root.join("c"), runtime: root.join("r"), ..Default::default() };
        let m = Inbound { channel: "fake".into(), chat: "42".into(), sender: "u".into(), sender_name: "Dana".into(), text: "hi".into(), ..Default::default() };
        observe(&paths, &m);
        observe(&paths, &Inbound { channel: "fake".into(), chat: "g1".into(), chat_type: ChatType::Group, chat_name: "Team".into(), ..Default::default() });
        let fake = Arc::new(Fake { sent: Mutex::new(vec![]) });
        let mut chans: BTreeMap<String, Arc<dyn Channel>> = BTreeMap::new();
        chans.insert("fake".into(), fake.clone());
        let ts = tools(paths.clone(), chans);
        let c = ctx(&paths);
        let l: Value = serde_json::from_str(&ts[0].call(&c, json!({"query": "dana"})).content).unwrap();
        let convs = l["conversations"].as_array().unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0]["kind"], "direct");
        assert_eq!(convs[0]["label"], "Dana");
        let cref = convs[0]["conversationRef"].as_str().unwrap().to_string();
        let all: Value = serde_json::from_str(&ts[0].call(&c, json!({})).content).unwrap();
        assert_eq!(all["conversations"].as_array().unwrap().len(), 2);
        let s: Value = serde_json::from_str(&ts[1].call(&c, json!({"conversationRef": cref, "message": "ping"})).content).unwrap();
        assert_eq!(s["status"], "sent");
        assert_eq!(fake.sent.lock().unwrap()[0].chat, "42");
        assert!(ts[1].call(&c, json!({"conversationRef": "conv_xyz", "message": "x"})).content.contains("Invalid conversationRef"));
        assert!(matches!(ts[1].effects(&c, &json!({"conversationRef": cref, "message": "ping"}))[0], Effect::Send { .. }));
        // A turn: the next inbound from that chat is the reply and is consumed.
        let t2 = ts[2].clone();
        let (c2, cref2) = (ctx(&paths), cref.clone());
        let h = std::thread::spawn(move || t2.call(&c2, json!({"conversationRef": cref2, "message": "are you there?", "timeoutSeconds": 5})));
        let mut taken = false;
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(20));
            if claim(&Inbound { channel: "fake".into(), chat: "42".into(), text: "yes!".into(), message_id: "r9".into(), ..Default::default() }) {
                taken = true;
                break;
            }
        }
        assert!(taken, "reply consumed by the waiter");
        let v: Value = serde_json::from_str(&h.join().unwrap().content).unwrap();
        assert_eq!(v["status"], "replied");
        assert_eq!(v["reply"]["text"], "yes!");
        assert!(!claim(&m), "no waiter: normal turn");
        let v: Value = serde_json::from_str(&ts[2].call(&c, json!({"conversationRef": cref, "message": "again", "timeoutSeconds": 1})).content).unwrap();
        assert_eq!(v["status"], "timeout");
        let _ = std::fs::remove_dir_all(&root);
    }
}
