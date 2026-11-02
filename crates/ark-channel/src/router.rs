//! Inbound routing, independent of the kernel: who may talk, which session a
//! chat maps to, slash commands, and redelivery dedup. State persists in one
//! JSON file so restarts keep conversations and never double-submit.

use crate::access::{Pairing, Policy, Verdict};
use crate::{write_atomic, Inbound};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Message ids remembered for dedup.
pub const SEEN_MAX: usize = 512;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionPer {
    /// One session per chat (a group shares it).
    #[default]
    Chat,
    /// One session per sender within a chat.
    Sender,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterConfig {
    #[serde(default)]
    pub policy: Policy,
    #[serde(default)]
    pub session_per: SessionPer,
    #[serde(default)]
    pub privacy_notice: Option<String>,
    #[serde(default)]
    pub ai_label: Option<String>,
}

impl RouterConfig {
    /// Deny-by-default allow list, the common case in tests and simple configs.
    pub fn allow(allow: &[&str], session_per: SessionPer) -> RouterConfig {
        RouterConfig { policy: Policy { allow: allow.iter().map(|s| s.to_string()).collect(), ..Policy::default() }, session_per, ..Default::default() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteKey {
    pub channel: String,
    pub chat: String,
    pub sender: Option<String>,
}

impl RouteKey {
    pub fn chat(channel: &str, chat: &str) -> Self {
        RouteKey { channel: channel.into(), chat: chat.into(), sender: None }
    }
    fn encode(&self) -> String {
        match &self.sender {
            Some(s) => format!("{}\u{1f}{}\u{1f}{s}", self.channel, self.chat),
            None => format!("{}\u{1f}{}", self.channel, self.chat),
        }
    }
    fn decode(s: &str) -> Option<Self> {
        let mut p = s.split('\u{1f}');
        Some(RouteKey { channel: p.next()?.into(), chat: p.next()?.into(), sender: p.next().map(str::to_string) })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Start a fresh session (the binding is already cleared).
    New,
    Stop,
    Status,
    Help,
    /// Delete this sender's sessions and attachments (`ark data delete` for one person).
    Forget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Ignore { reason: String },
    Command { cmd: Command, key: RouteKey, session: Option<String> },
    /// `session: None` → create one, then `bind` it. `notice`: send this first (privacy notice).
    Submit { key: RouteKey, session: Option<String>, text: String, notice: Option<String> },
    /// Unknown sender under pairing: reply with this text and do nothing else.
    Pair { key: RouteKey, reply: String },
    /// A button press on an earlier message.
    Callback { key: RouteKey, session: Option<String>, callback: crate::Callback },
}

/// One persisted binding, for listings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub key: RouteKey,
    pub session: String,
}

#[derive(Default)]
struct State {
    routes: BTreeMap<String, String>,
    seen: VecDeque<String>,
    seen_set: HashSet<String>,
    /// Senders that already got the privacy notice ("channel\u{1f}sender").
    noticed: BTreeSet<String>,
}

pub struct Router {
    path: PathBuf,
    configs: HashMap<String, RouterConfig>,
    pairing: Option<Arc<Pairing>>,
    state: Mutex<State>,
    /// Set when the state file was unreadable and has been moved aside.
    pub load_warning: Option<String>,
}

pub const HELP: &str = "Commands: /new (fresh session), /stop (interrupt), /status, /forget (delete what you sent here), /help. Anything else goes to the agent.";

impl Router {
    pub fn open(path: PathBuf, configs: HashMap<String, RouterConfig>) -> Router {
        let mut warning = None;
        let state = match std::fs::read_to_string(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => {
                warning = Some(format!("cannot read {}: {e}; starting with no routes", path.display()));
                State::default()
            }
            Ok(s) => match parse_state(&s) {
                Some(st) => st,
                None => {
                    let aside = path.with_extension(format!("corrupt-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)));
                    let _ = std::fs::rename(&path, &aside);
                    warning = Some(format!("{} was corrupt; moved to {} and started with no routes", path.display(), aside.display()));
                    State::default()
                }
            },
        };
        Router { path, configs, pairing: None, state: Mutex::new(state), load_warning: warning }
    }

    pub fn with_pairing(mut self, p: Arc<Pairing>) -> Router {
        self.pairing = Some(p);
        self
    }

    pub fn pairing(&self) -> Option<&Arc<Pairing>> {
        self.pairing.as_ref()
    }

    pub fn config(&self, channel: &str) -> Option<&RouterConfig> {
        self.configs.get(channel)
    }

    pub fn key_for(&self, m: &Inbound) -> RouteKey {
        let per = self.configs.get(&m.channel).map(|c| c.session_per).unwrap_or_default();
        // Threads get their own session: `chat` + thread id.
        let chat = match &m.thread {
            Some(t) => format!("{}:thread:{t}", m.chat),
            None => m.chat.clone(),
        };
        RouteKey { channel: m.channel.clone(), chat, sender: (per == SessionPer::Sender).then(|| m.sender.clone()) }
    }

    pub fn route(&self, m: &Inbound) -> Action {
        let ignore = |r: &str| Action::Ignore { reason: r.to_string() };
        let Some(cfg) = self.configs.get(&m.channel) else { return ignore("unknown channel") };
        let approved = |s: &str| self.pairing.as_ref().is_some_and(|p| p.is_approved(&m.channel, s));
        let key = self.key_for(m);
        match cfg.policy.check(m, &approved, self.pairing.as_deref()) {
            Verdict::Allow => {}
            Verdict::Deny(reason) => return Action::Ignore { reason },
            Verdict::NotAddressed => return ignore("group message not addressed to the bot"),
            Verdict::Pair(reply) => return Action::Pair { key, reply },
        }
        let mut st = self.state.lock().unwrap();
        if !m.message_id.is_empty() {
            let id = format!("{}\u{1f}{}\u{1f}{}", m.channel, m.chat, m.message_id);
            if st.seen_set.contains(&id) {
                return ignore("duplicate delivery");
            }
            st.seen_set.insert(id.clone());
            st.seen.push_back(id);
            while st.seen.len() > SEEN_MAX {
                if let Some(old) = st.seen.pop_front() {
                    st.seen_set.remove(&old);
                }
            }
        }
        if let Some(cb) = &m.callback {
            let session = st.routes.get(&key.encode()).cloned();
            self.save(&st);
            return Action::Callback { key, session, callback: cb.clone() };
        }
        let text = m.text.trim();
        if text.is_empty() && m.media.is_empty() {
            self.save(&st);
            return ignore("empty message");
        }
        let cmd = text.strip_prefix('/').map(|c| c.split_whitespace().next().unwrap_or("").split('@').next().unwrap_or("").to_ascii_lowercase());
        let cmd = match cmd.as_deref() {
            Some("new") | Some("reset") => Some(Command::New),
            Some("stop") => Some(Command::Stop),
            Some("status") => Some(Command::Status),
            Some("help") | Some("start") => Some(Command::Help),
            Some("forget") => Some(Command::Forget),
            _ => None,
        };
        let enc = key.encode();
        if cmd == Some(Command::New) {
            st.routes.remove(&enc);
        }
        let session = st.routes.get(&enc).cloned();
        let notice = match (&cfg.privacy_notice, cmd) {
            (Some(n), None) if st.noticed.insert(format!("{}\u{1f}{}", m.channel, m.sender)) => Some(n.clone()),
            _ => None,
        };
        self.save(&st);
        match cmd {
            Some(cmd) => Action::Command { cmd, key, session },
            None => Action::Submit { key, session, text: text.to_string(), notice },
        }
    }

    pub fn bind(&self, key: &RouteKey, session: &str) {
        let mut st = self.state.lock().unwrap();
        st.routes.insert(key.encode(), session.to_string());
        self.save(&st);
    }

    pub fn reset(&self, key: &RouteKey) {
        let mut st = self.state.lock().unwrap();
        if st.routes.remove(&key.encode()).is_some() {
            self.save(&st);
        }
    }

    pub fn session_for(&self, key: &RouteKey) -> Option<String> {
        self.state.lock().unwrap().routes.get(&key.encode()).cloned()
    }

    pub fn routes(&self) -> Vec<Route> {
        self.state.lock().unwrap().routes.iter().filter_map(|(k, s)| Some(Route { key: RouteKey::decode(k)?, session: s.clone() })).collect()
    }

    /// Best effort: a failed write costs at most a redelivery after restart.
    fn save(&self, st: &State) {
        let v = json!({ "version": 1, "routes": st.routes, "seen": st.seen, "noticed": st.noticed });
        let _ = write_atomic(&self.path, v.to_string().as_bytes());
    }
}

fn parse_state(s: &str) -> Option<State> {
    let v: Value = serde_json::from_str(s).ok()?;
    let routes: BTreeMap<String, String> = serde_json::from_value(v.get("routes")?.clone()).ok()?;
    let seen: VecDeque<String> = serde_json::from_value(v.get("seen").cloned().unwrap_or(json!([]))).ok()?;
    let seen_set = seen.iter().cloned().collect();
    let noticed: BTreeSet<String> = serde_json::from_value(v.get("noticed").cloned().unwrap_or(json!([]))).ok()?;
    Some(State { routes, seen, seen_set, noticed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;

    fn msg(chat: &str, sender: &str, id: &str, text: &str) -> Inbound {
        Inbound { channel: "tg".into(), chat: chat.into(), sender: sender.into(), sender_name: "amy".into(), text: text.into(), message_id: id.into(), ts: 0, ..Default::default() }
    }

    fn router(path: PathBuf, allow: &[&str], per: SessionPer) -> Router {
        let mut c = HashMap::new();
        c.insert("tg".to_string(), RouterConfig::allow(allow, per));
        Router::open(path, c)
    }

    #[test]
    fn deny_by_default_and_allow_by_id_name_or_star() {
        let d = temp_dir("rt");
        let r = router(d.join("r.json"), &[], SessionPer::Chat);
        assert!(matches!(r.route(&msg("c", "1", "a", "hi")), Action::Ignore { reason } if reason.contains("allow")));
        let mut other = msg("c", "1", "b", "hi");
        other.channel = "nope".into();
        assert!(matches!(r.route(&other), Action::Ignore { .. }), "unconfigured channel");
        let r = router(d.join("r2.json"), &["1"], SessionPer::Chat);
        assert!(matches!(r.route(&msg("c", "1", "a", "hi")), Action::Submit { .. }));
        let mut m = msg("c", "2", "b", "hi");
        assert!(matches!(r.route(&m), Action::Ignore { .. }));
        m.sender_name = String::new();
        let r = router(d.join("r3.json"), &["@AMY"], SessionPer::Chat);
        assert!(matches!(r.route(&msg("c", "9", "a", "hi")), Action::Submit { .. }), "name match is case-insensitive");
        assert!(matches!(r.route(&m), Action::Ignore { .. }), "empty name never matches");
        let r = router(d.join("r4.json"), &["*"], SessionPer::Chat);
        assert!(matches!(r.route(&m), Action::Submit { .. }));
    }

    #[test]
    fn dedup_commands_and_binding() {
        let d = temp_dir("rt");
        let r = router(d.join("r.json"), &["*"], SessionPer::Chat);
        let Action::Submit { key, session: None, text, .. } = r.route(&msg("c", "1", "m1", "  do it ")) else { panic!() };
        assert_eq!(text, "do it");
        r.bind(&key, "S1");
        assert!(matches!(r.route(&msg("c", "1", "m1", "do it")), Action::Ignore { reason } if reason.contains("duplicate")));
        assert!(matches!(r.route(&msg("c", "1", "m2", "more")), Action::Submit { session: Some(s), .. } if s == "S1"));
        assert!(matches!(r.route(&msg("c", "1", "", "no id")), Action::Submit { .. }));
        assert!(matches!(r.route(&msg("c", "1", "", "no id")), Action::Submit { .. }), "no id → no dedup");
        assert!(matches!(r.route(&msg("c", "1", "m3", "/status@ArkBot")), Action::Command { cmd: Command::Status, session: Some(_), .. }));
        assert!(matches!(r.route(&msg("c", "1", "m4", "/STOP now")), Action::Command { cmd: Command::Stop, .. }));
        assert!(matches!(r.route(&msg("c", "1", "m5", "/help")), Action::Command { cmd: Command::Help, .. }));
        assert!(matches!(r.route(&msg("c", "1", "m5b", "/forget")), Action::Command { cmd: Command::Forget, session: Some(_), .. }));
        assert!(matches!(r.route(&msg("c", "1", "m6", "/deploy prod")), Action::Submit { .. }), "unknown slash text goes to the agent");
        assert!(matches!(r.route(&msg("c", "1", "m7", "   ")), Action::Ignore { .. }));
        assert!(matches!(r.route(&msg("c", "1", "m8", "/new")), Action::Command { cmd: Command::New, session: None, .. }));
        assert!(matches!(r.route(&msg("c", "1", "m9", "hi")), Action::Submit { session: None, .. }), "/new cleared the binding");
        // LRU bound.
        for i in 0..SEEN_MAX + 10 {
            r.route(&msg("c", "1", &format!("x{i}"), "/help"));
        }
        assert!(matches!(r.route(&msg("c", "1", "m2", "again")), Action::Submit { .. }), "oldest ids evicted");
    }

    #[test]
    fn per_chat_vs_per_sender() {
        let d = temp_dir("rt");
        let chat = router(d.join("a.json"), &["*"], SessionPer::Chat);
        let sender = router(d.join("b.json"), &["*"], SessionPer::Sender);
        for r in [&chat, &sender] {
            let Action::Submit { key, .. } = r.route(&msg("g", "1", "a", "x")) else { panic!() };
            r.bind(&key, "S-amy");
        }
        assert!(matches!(chat.route(&msg("g", "2", "b", "x")), Action::Submit { session: Some(s), .. } if s == "S-amy"), "group shares");
        assert!(matches!(sender.route(&msg("g", "2", "b", "x")), Action::Submit { session: None, .. }), "each sender separate");
        assert!(matches!(sender.route(&msg("other", "1", "c", "x")), Action::Submit { session: None, .. }), "per chat too");
    }

    #[test]
    fn state_survives_restart_and_corruption_is_recovered() {
        let d = temp_dir("rt");
        let p = d.join("routes.json");
        {
            let r = router(p.clone(), &["*"], SessionPer::Sender);
            let Action::Submit { key, .. } = r.route(&msg("c", "1", "m1", "x")) else { panic!() };
            r.bind(&key, "S1");
            r.bind(&RouteKey::chat("tg", "z"), "S2");
            r.reset(&RouteKey::chat("tg", "z"));
        }
        let r = router(p.clone(), &["*"], SessionPer::Sender);
        assert!(r.load_warning.is_none());
        assert!(matches!(r.route(&msg("c", "1", "m1", "x")), Action::Ignore { .. }), "dedup persisted");
        assert!(matches!(r.route(&msg("c", "1", "m2", "x")), Action::Submit { session: Some(s), .. } if s == "S1"));
        let routes = r.routes();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].key.sender.as_deref(), Some("1"));
        drop(r);

        std::fs::write(&p, "{\"routes\": [garbage").unwrap();
        let r = router(p.clone(), &["*"], SessionPer::Sender);
        assert!(r.load_warning.as_deref().unwrap().contains("corrupt"));
        assert!(r.routes().is_empty());
        assert!(std::fs::read_dir(&d).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().contains("corrupt-")), "kept for inspection");
        assert!(matches!(r.route(&msg("c", "1", "m3", "x")), Action::Submit { session: None, .. }));
        assert!(std::fs::read_to_string(&p).unwrap().contains("m3"), "rewritten cleanly");
        // Wrong shape (valid JSON) is also corruption.
        std::fs::write(&p, "{\"routes\": {\"k\": 5}}").unwrap();
        assert!(router(p, &["*"], SessionPer::Chat).load_warning.is_some());
    }
}
