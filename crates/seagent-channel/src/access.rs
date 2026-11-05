//! Who may talk to the agent through a channel.
//!
//! DM policy (OpenClaw/Hermes compatible): `allowlist` (seagent default: only
//! `allow` entries), `pairing` (unknown senders get a one-time code the
//! operator approves), `open` (anyone, but only when `allow` contains `"*"`),
//! `disabled`. Group policy: `allowlist` (only listed `groups`), `open`,
//! `disabled`, plus mention gating: in groups the bot answers only when
//! mentioned or replied to, unless `require_mention = false`.
//!
//! Pairing codes: 8 characters from an alphabet without 0/O/1/I, valid 1 h,
//! at most 3 pending per channel, one request per sender per 10 min, 5 wrong
//! approvals lock approval for 1 h. Only a salted SHA-256 of each code is stored.

use crate::{write_atomic, ChatType, Inbound};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DmPolicy {
    #[default]
    Allowlist,
    Pairing,
    Open,
    Disabled,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupPolicy {
    #[default]
    Allowlist,
    Open,
    Disabled,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Sender ids or @names; `"*"` = anyone.
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub dm_policy: DmPolicy,
    #[serde(default)]
    pub group_policy: GroupPolicy,
    /// Chat ids allowed under `group_policy = "allowlist"`; `"*"` = all.
    #[serde(default)]
    pub groups: Vec<String>,
    /// In groups, members must also pass `allow` unless this is set.
    #[serde(default)]
    pub group_allow_all_members: bool,
    #[serde(default = "yes")]
    pub require_mention: bool,
    #[serde(default)]
    pub allow_bots: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Policy { allow: vec![], dm_policy: DmPolicy::default(), group_policy: GroupPolicy::default(), groups: vec![], group_allow_all_members: false, require_mention: true, allow_bots: false }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// Silently ignore, with a reason for logs.
    Deny(String),
    /// Group message not addressed to the bot.
    NotAddressed,
    /// Unknown DM sender under pairing: reply with this text (contains the code).
    Pair(String),
}

fn listed(list: &[String], id: &str, name: &str) -> bool {
    let name = name.trim_start_matches('@');
    list.iter().any(|a| a == "*" || (!id.is_empty() && a == id) || (!name.is_empty() && a.trim_start_matches('@').eq_ignore_ascii_case(name)))
}

impl Policy {
    /// `approved` = senders approved through pairing for this channel.
    pub fn check(&self, m: &Inbound, approved: &dyn Fn(&str) -> bool, pairing: Option<&Pairing>) -> Verdict {
        if m.is_bot && !self.allow_bots {
            return Verdict::Deny("message from a bot".into());
        }
        let sender_ok = listed(&self.allow, &m.sender, &m.sender_name) || approved(&m.sender);
        match m.chat_type {
            ChatType::Direct => match self.dm_policy {
                DmPolicy::Disabled => Verdict::Deny("direct messages disabled".into()),
                DmPolicy::Open if self.allow.iter().any(|a| a == "*") => Verdict::Allow,
                _ if sender_ok => Verdict::Allow,
                DmPolicy::Pairing => match pairing {
                    Some(p) => match p.request(&m.channel, &m.sender, &m.sender_name) {
                        Ok(code) => Verdict::Pair(format!("你還沒有使用權限。請把這組配對碼交給管理員核准：{code}\n（seagent pairing approve {} {code}，1 小時內有效）", m.channel)),
                        Err(why) => Verdict::Deny(why),
                    },
                    None => Verdict::Deny("pairing not available".into()),
                },
                _ => Verdict::Deny(format!("sender {} ({}) is not in allow list", m.sender, m.sender_name)),
            },
            _ => {
                let group_ok = match self.group_policy {
                    GroupPolicy::Disabled => return Verdict::Deny("group messages disabled".into()),
                    GroupPolicy::Open => true,
                    GroupPolicy::Allowlist => self.groups.iter().any(|g| g == "*" || g == &m.chat),
                };
                if !group_ok {
                    return Verdict::Deny(format!("group {} is not allowed", m.chat));
                }
                if !self.group_allow_all_members && !sender_ok {
                    return Verdict::Deny(format!("sender {} is not in allow list", m.sender));
                }
                if self.require_mention && !m.addressed() && m.callback.is_none() {
                    return Verdict::NotAddressed;
                }
                Verdict::Allow
            }
        }
    }
}

const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const TTL: i64 = 3600;
const MAX_PENDING: usize = 3;
const REQUEST_COOLDOWN: i64 = 600;
const MAX_FAILURES: u32 = 5;
const LOCKOUT: i64 = 3600;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingReq {
    pub channel: String,
    pub sender: String,
    pub sender_name: String,
    pub salt: String,
    pub hash: String,
    pub created: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Approved {
    pub sender_name: String,
    pub approved_at: i64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PairState {
    #[serde(default)]
    pending: BTreeMap<String, PendingReq>,
    /// channel → sender → info
    #[serde(default)]
    approved: BTreeMap<String, BTreeMap<String, Approved>>,
    #[serde(default)]
    last_request: BTreeMap<String, i64>,
    #[serde(default)]
    failures: u32,
    #[serde(default)]
    locked_until: i64,
}

/// File-backed pairing store, mode 0600.
pub struct Pairing {
    path: PathBuf,
    st: Mutex<PairState>,
    clock: Box<dyn Fn() -> i64 + Send + Sync>,
    /// mtime of the file we last read or wrote; another process (CLI, daemon) may change it.
    seen: Mutex<Option<std::time::SystemTime>>,
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn digest(salt: &str, code: &str) -> String {
    seagent_net::crypto::hex(&seagent_net::crypto::sha256(format!("{salt}:{}", code.trim().to_ascii_uppercase()).as_bytes()))
}

impl Pairing {
    pub fn open(path: PathBuf) -> Pairing {
        let st = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        let seen = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        Pairing { path, st: Mutex::new(st), clock: Box::new(now), seen: Mutex::new(seen) }
    }

    /// Pick up changes written by another process.
    fn lock(&self) -> std::sync::MutexGuard<'_, PairState> {
        let mut st = self.st.lock().unwrap();
        let m = std::fs::metadata(&self.path).and_then(|m| m.modified()).ok();
        let mut seen = self.seen.lock().unwrap();
        if m.is_some() && m != *seen {
            if let Some(fresh) = std::fs::read_to_string(&self.path).ok().and_then(|s| serde_json::from_str(&s).ok()) {
                *st = fresh;
            }
            *seen = m;
        }
        st
    }

        #[cfg(test)]
    fn with_clock(mut self, f: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = Box::new(f);
        self
    }

    fn save(&self, st: &PairState) {
        if write_atomic(&self.path, serde_json::to_string(st).unwrap_or_default().as_bytes()).is_ok() {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
            *self.seen.lock().unwrap() = std::fs::metadata(&self.path).and_then(|m| m.modified()).ok();
        }
    }

    fn expire(st: &mut PairState, t: i64) {
        st.pending.retain(|_, p| t - p.created < TTL);
    }

    /// New code for an unknown sender, or why not.
    pub fn request(&self, channel: &str, sender: &str, name: &str) -> Result<String, String> {
        let t = (self.clock)();
        let mut st = self.lock();
        Self::expire(&mut st, t);
        let k = format!("{channel}\u{1f}{sender}");
        if st.last_request.get(&k).is_some_and(|&last| t - last < REQUEST_COOLDOWN) {
            return Err("pairing requested recently; ignoring".into());
        }
        if st.pending.values().filter(|p| p.channel == channel).count() >= MAX_PENDING {
            return Err(format!("too many pending pairing requests on {channel}"));
        }
        let raw = seagent_net::crypto::random_bytes(8);
        let code: String = raw.iter().map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char).collect();
        let salt = seagent_net::crypto::random_token(12);
        let id = seagent_net::crypto::hex(&seagent_net::crypto::random_bytes(8));
        st.pending.insert(id, PendingReq { channel: channel.into(), sender: sender.into(), sender_name: name.into(), hash: digest(&salt, &code), salt, created: t });
        st.last_request.insert(k, t);
        self.save(&st);
        Ok(code)
    }

    /// Approve by code. Returns the approved (sender, name).
    pub fn approve(&self, channel: &str, code: &str) -> Result<(String, String), String> {
        let t = (self.clock)();
        let mut st = self.lock();
        if st.locked_until > t {
            return Err(format!("too many wrong codes; approval locked for {} more seconds", st.locked_until - t));
        }
        Self::expire(&mut st, t);
        let hit = st.pending.iter().find(|(_, p)| p.channel == channel && seagent_net::crypto::ct_eq(digest(&p.salt, code).as_bytes(), p.hash.as_bytes())).map(|(k, _)| k.clone());
        let Some(id) = hit else {
            st.failures += 1;
            if st.failures >= MAX_FAILURES {
                st.failures = 0;
                st.locked_until = t + LOCKOUT;
            }
            self.save(&st);
            return Err("no pending request with that code (expired or wrong)".into());
        };
        let p = st.pending.remove(&id).expect("present");
        st.failures = 0;
        st.approved.entry(channel.into()).or_default().insert(p.sender.clone(), Approved { sender_name: p.sender_name.clone(), approved_at: t });
        self.save(&st);
        Ok((p.sender, p.sender_name))
    }

    pub fn is_approved(&self, channel: &str, sender: &str) -> bool {
        self.lock().approved.get(channel).is_some_and(|m| m.contains_key(sender))
    }

    pub fn revoke(&self, channel: &str, sender: &str) -> bool {
        let mut st = self.lock();
        let hit = st.approved.get_mut(channel).is_some_and(|m| m.remove(sender).is_some());
        if hit {
            self.save(&st);
        }
        hit
    }

    pub fn pending(&self) -> Vec<PendingReq> {
        let t = (self.clock)();
        let mut st = self.lock();
        Self::expire(&mut st, t);
        st.pending.values().cloned().map(|mut p| {
            p.salt.clear();
            p.hash.clear();
            p
        }).collect()
    }

    pub fn approved(&self) -> Vec<(String, String, Approved)> {
        self.lock().approved.iter().flat_map(|(c, m)| m.iter().map(move |(s, a)| (c.clone(), s.clone(), a.clone()))).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;
    use crate::ReplyRef;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::Arc;

    fn dm(sender: &str) -> Inbound {
        Inbound { channel: "tg".into(), chat: sender.into(), sender: sender.into(), text: "hi".into(), ..Default::default() }
    }

    fn group(chat: &str, sender: &str) -> Inbound {
        Inbound { chat_type: ChatType::Group, chat: chat.into(), ..dm(sender) }
    }

    #[test]
    fn dm_policies() {
        let none = |_: &str| false;
        let p = Policy { allow: vec!["1".into()], ..Default::default() };
        assert_eq!(p.check(&dm("1"), &none, None), Verdict::Allow);
        assert!(matches!(p.check(&dm("2"), &none, None), Verdict::Deny(_)), "allowlist is the default");
        let open_no_star = Policy { dm_policy: DmPolicy::Open, ..Default::default() };
        assert!(matches!(open_no_star.check(&dm("2"), &none, None), Verdict::Deny(_)), "open needs \"*\"");
        let open = Policy { dm_policy: DmPolicy::Open, allow: vec!["*".into()], ..Default::default() };
        assert_eq!(open.check(&dm("2"), &none, None), Verdict::Allow);
        let off = Policy { dm_policy: DmPolicy::Disabled, allow: vec!["*".into()], ..Default::default() };
        assert!(matches!(off.check(&dm("1"), &none, None), Verdict::Deny(_)));
        let mut bot = dm("1");
        bot.is_bot = true;
        assert!(matches!(p.check(&bot, &none, None), Verdict::Deny(r) if r.contains("bot")));
        assert_eq!(p.check(&dm("9"), &|s| s == "9", None), Verdict::Allow, "paired senders pass");
    }

    #[test]
    fn group_policy_and_mention_gating() {
        let none = |_: &str| false;
        let p = Policy { allow: vec!["1".into()], groups: vec!["g".into()], ..Default::default() };
        assert!(matches!(p.check(&group("other", "1"), &none, None), Verdict::Deny(_)));
        assert_eq!(p.check(&group("g", "1"), &none, None), Verdict::NotAddressed);
        let mut m = group("g", "1");
        m.mentioned = true;
        assert_eq!(p.check(&m, &none, None), Verdict::Allow);
        let mut r = group("g", "1");
        r.reply = Some(ReplyRef { id: "5".into(), is_own: true, ..Default::default() });
        assert_eq!(p.check(&r, &none, None), Verdict::Allow, "reply to the bot is an implicit mention");
        let mut stranger = group("g", "2");
        stranger.mentioned = true;
        assert!(matches!(p.check(&stranger, &none, None), Verdict::Deny(_)));
        let all = Policy { group_allow_all_members: true, require_mention: false, ..p.clone() };
        assert_eq!(all.check(&group("g", "2"), &none, None), Verdict::Allow);
        let off = Policy { group_policy: GroupPolicy::Disabled, ..p };
        assert!(matches!(off.check(&m, &none, None), Verdict::Deny(_)));
    }

    #[test]
    fn pairing_codes_limits_hashing_and_lockout() {
        let d = temp_dir("pair");
        let t = Arc::new(AtomicI64::new(1_000_000));
        let tc = t.clone();
        let pr = Pairing::open(d.join("pairing.json")).with_clock(move || tc.load(Ordering::SeqCst));
        let p = Policy { dm_policy: DmPolicy::Pairing, ..Default::default() };
        let approved = |s: &str| pr.is_approved("tg", s);
        let Verdict::Pair(msg) = p.check(&dm("7"), &approved, Some(&pr)) else { panic!() };
        let code = msg.split('：').nth(1).unwrap().split_whitespace().next().unwrap().to_string();
        assert_eq!(code.len(), 8);
        assert!(code.bytes().all(|b| ALPHABET.contains(&b)));
        let file = std::fs::read_to_string(d.join("pairing.json")).unwrap();
        assert!(!file.contains(&code), "only a hash is stored");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(d.join("pairing.json")).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(matches!(p.check(&dm("7"), &approved, Some(&pr)), Verdict::Deny(r) if r.contains("recently")), "cooldown");
        assert!(pr.approve("other", &code).is_err(), "codes are per channel");
        assert_eq!(pr.approve("tg", &code.to_lowercase()).unwrap().0, "7");
        assert_eq!(p.check(&dm("7"), &|s| pr.is_approved("tg", s), Some(&pr)), Verdict::Allow);
        assert!(pr.approve("tg", &code).is_err(), "single use");
        // Pending cap and expiry.
        for s in ["a", "b", "c"] {
            pr.request("tg", s, "").unwrap();
        }
        assert!(pr.request("tg", "d", "").unwrap_err().contains("too many"));
        t.fetch_add(TTL + 1, Ordering::SeqCst);
        assert!(pr.pending().is_empty(), "expired after 1h");
        assert!(pr.request("tg", "d", "").is_ok());
        // Lockout after repeated wrong codes.
        for _ in 0..MAX_FAILURES {
            assert!(pr.approve("tg", "WRONGWRG").is_err());
        }
        let code = pr.request("tg", "e", "").unwrap();
        assert!(pr.approve("tg", &code).unwrap_err().contains("locked"));
        // Survives restart; revoke works.
        let again = Pairing::open(d.join("pairing.json"));
        assert!(again.is_approved("tg", "7"));
        assert!(again.revoke("tg", "7") && !again.is_approved("tg", "7"));
        // A second instance (CLI vs daemon) sees changes made by the first.
        let a = Pairing::open(d.join("shared.json"));
        let b = Pairing::open(d.join("shared.json"));
        let code = a.request("tg", "z", "").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        b.approve("tg", &code).unwrap();
        assert!(a.is_approved("tg", "z"), "approval written by another process is picked up");
    }
}
