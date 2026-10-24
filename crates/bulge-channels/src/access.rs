//! Who may command bulge through a chat app.
//!
//! The owner's own ids go in `allow_from`. Anyone else who messages the bot
//! in a direct chat gets a one-time pairing code (default policy) and nothing
//! else; the owner approves the code on the computer (`bulge channels approve
//! <code>`), which adds that sender for good. Group chats are ignored unless
//! enabled, and even then only allowed senders who address the bot are heard.
//! There is deliberately no "open to anyone" mode: whoever can message the bot
//! would command an agent with the owner's workspace and model budget.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::Inbound;

/// Codes use an alphabet without look-alike characters (no 0/O, 1/I/L).
const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const CODE_LEN: usize = 8;
/// A pairing code is valid this long.
pub const PAIRING_TTL_SECS: u64 = 3600;
/// At most this many codes wait for approval at once per channel, so a
/// stranger cannot flood the owner with requests.
pub const MAX_PENDING: usize = 3;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DmPolicy {
    /// Unknown senders get a pairing code for the owner to approve.
    #[default]
    Pairing,
    /// Only `allow_from` (and earlier approvals); others are ignored silently.
    Allowlist,
    /// Direct messages are ignored.
    Disabled,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AccessConfig {
    pub dm_policy: DmPolicy,
    /// Sender ids always allowed (the owner's accounts on this app).
    pub allow_from: Vec<String>,
    /// Listen in group chats (to allowed senders who address the bot).
    pub groups: bool,
    /// Group ids where ANYONE who addresses the bot is admitted. Such senders
    /// are guests: bulge runs their requests in a space of their own.
    pub open_groups: Vec<String>,
}

impl AccessConfig {
    /// Whether bulge listens in this group at all (for its chat history).
    pub fn listens_in(&self, chat_id: &str) -> bool {
        self.groups || self.open_groups.iter().any(|g| g == chat_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Admit,
    /// Reply with this text (the pairing instructions) and do nothing else.
    Challenge(String),
    Ignore(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub channel: String,
    pub sender_id: String,
    pub sender_name: String,
    pub code: String,
    pub expires_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PairingData {
    /// channel name → approved sender ids.
    #[serde(default)]
    approved: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pending: Vec<Pending>,
}

/// Approved senders and outstanding pairing codes, persisted as JSON.
///
/// The file is the only copy: `bulge channels serve` and `bulge channels
/// approve` are separate processes, so every operation takes an exclusive
/// lock on `<file>.lock`, reads the file afresh, and writes it back before
/// releasing the lock. Nothing is cached between operations, so an approval
/// takes effect on the next message and is never overwritten by stale state.
pub struct PairingStore {
    path: PathBuf,
}

pub use bulge_util::now_secs;

fn new_code() -> Result<String, String> {
    let mut bytes = [0u8; CODE_LEN];
    getrandom::fill(&mut bytes).map_err(|e| format!("random: {e}"))?;
    Ok(bytes.iter().map(|b| CODE_ALPHABET[usize::from(*b) % CODE_ALPHABET.len()] as char).collect())
}

/// Write `bytes` atomically, mode 600 (pairing and state files name who
/// may command bulge).
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    bulge_util::fs::write_private(path, bytes)
}

fn decide(data: &mut PairingData, config: &AccessConfig, message: &Inbound, now: u64) -> Result<(Decision, bool), String> {
    let allowed = config.allow_from.iter().any(|id| id == &message.sender_id) || data.approved.get(&message.channel).is_some_and(|ids| ids.contains(&message.sender_id));
    if message.is_group {
        if config.open_groups.iter().any(|g| g == &message.chat_id) {
            return Ok((if message.mentioned { Decision::Admit } else { Decision::Ignore("the bot was not addressed") }, false));
        }
        return Ok((match (config.groups, allowed, message.mentioned) {
            (false, _, _) => Decision::Ignore("group chats are off for this channel"),
            (true, false, _) => Decision::Ignore("sender is not allowed"),
            (true, true, false) => Decision::Ignore("the bot was not addressed"),
            (true, true, true) => Decision::Admit,
        }, false));
    }
    if config.dm_policy == DmPolicy::Disabled {
        return Ok((Decision::Ignore("direct messages are off for this channel"), false));
    }
    if allowed {
        return Ok((Decision::Admit, false));
    }
    match config.dm_policy {
        DmPolicy::Disabled => unreachable!("handled above"),
        DmPolicy::Allowlist => Ok((Decision::Ignore("sender is not allowed"), false)),
        DmPolicy::Pairing => {
            data.pending.retain(|p| p.expires_at > now);
            let existing = data.pending.iter().find(|p| p.channel == message.channel && p.sender_id == message.sender_id).map(|p| p.code.clone());
            let code = match existing {
                Some(code) => code,
                None => {
                    // Per channel, so strangers on one app cannot block pairing on another.
                    if data.pending.iter().filter(|p| p.channel == message.channel).count() >= MAX_PENDING {
                        return Ok((Decision::Ignore("too many pairing requests are waiting"), true));
                    }
                    let code = new_code()?;
                    data.pending.push(Pending {
                        channel: message.channel.clone(),
                        sender_id: message.sender_id.clone(),
                        sender_name: message.sender_name.clone(),
                        code: code.clone(),
                        expires_at: now + PAIRING_TTL_SECS,
                    });
                    code
                }
            };
            Ok((Decision::Challenge(format!(
                "這個 bulge 還不認識你。請把配對碼 {code} 交給它的主人，主人在電腦上執行 `bulge channels approve {code}` 後你就能使用（1 小時內有效）。\n\
                 This bulge does not know you yet. Give the pairing code {code} to its owner; once they run `bulge channels approve {code}`, you can use it (valid for 1 hour)."
            )), true))
        }
    }
}

impl PairingStore {
    /// Open the store at `path` (missing = empty; malformed = error).
    pub fn load(path: &Path) -> Result<Self, String> {
        let store = Self { path: path.to_path_buf() };
        store.transact(|_| Ok(((), false)))?;
        Ok(store)
    }

    /// Run `f` on the current file contents under the lock; `f` returns its
    /// result and whether it changed the data (then the file is rewritten).
    fn transact<T>(&self, f: impl FnOnce(&mut PairingData) -> Result<(T, bool), String>) -> Result<T, String> {
        let lock_path = self.path.with_extension("lock");
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&lock_path).map_err(|e| format!("open {}: {e}", lock_path.display()))?;
        lock.lock().map_err(|e| format!("lock {}: {e}", lock_path.display()))?;
        let mut data: PairingData = match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", self.path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => PairingData::default(),
            Err(e) => return Err(format!("read {}: {e}", self.path.display())),
        };
        let (out, changed) = f(&mut data)?;
        if changed {
            let json = serde_json::to_vec_pretty(&data).map_err(|e| e.to_string())?;
            write_atomic(&self.path, &json)?;
        }
        Ok(out)
    }

    /// Decide what to do with `message` under `config`.
    pub fn decide(&mut self, config: &AccessConfig, message: &Inbound, now: u64) -> Result<Decision, String> {
        self.transact(|data| decide(data, config, message, now))
    }
    /// Approve a pending code: its sender is allowed on its channel from now on.
    pub fn approve(&mut self, code: &str, now: u64) -> Result<Pending, String> {
        let code = code.trim().to_ascii_uppercase();
        self.transact(|data| {
            data.pending.retain(|p| p.expires_at > now);
            let at = data.pending.iter().position(|p| p.code == code).ok_or_else(|| format!("no pending pairing code {code} (expired codes are dropped)"))?;
            let pending = data.pending.remove(at);
            let ids = data.approved.entry(pending.channel.clone()).or_default();
            if !ids.contains(&pending.sender_id) {
                ids.push(pending.sender_id.clone());
            }
            Ok((pending, true))
        })
    }

    /// Withdraw an approval.
    pub fn revoke(&mut self, channel: &str, sender_id: &str) -> Result<bool, String> {
        self.transact(|data| {
            let removed = data.approved.get_mut(channel).is_some_and(|ids| {
                let before = ids.len();
                ids.retain(|id| id != sender_id);
                ids.len() != before
            });
            Ok((removed, removed))
        })
    }

    pub fn pending(&self, now: u64) -> Result<Vec<Pending>, String> {
        self.transact(|data| Ok((data.pending.iter().filter(|p| p.expires_at > now).cloned().collect(), false)))
    }

    pub fn approved_senders(&self) -> Result<BTreeMap<String, Vec<String>>, String> {
        self.transact(|data| Ok((data.approved.clone(), false)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(sender: &str, group: bool, mentioned: bool) -> Inbound {
        Inbound {
            channel: "telegram:main".into(),
            chat_id: format!("chat-{sender}"),
            sender_id: sender.into(),
            sender_name: "Someone".into(),
            is_group: group,
            mentioned,
            text: "hi".into(),
            message_id: "1".into(),
            attachments: Vec::new(),
        }
    }

    fn store(tag: &str) -> PairingStore {
        let path = std::env::temp_dir().join(format!("bulge-pairing-{tag}-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        PairingStore::load(&path).unwrap()
    }

    #[test]
    fn owner_is_admitted_and_strangers_get_one_code() {
        let mut s = store("owner");
        let cfg = AccessConfig { allow_from: vec!["owner".into()], ..Default::default() };
        assert_eq!(s.decide(&cfg, &message("owner", false, false), 0).unwrap(), Decision::Admit);
        let Decision::Challenge(first) = s.decide(&cfg, &message("stranger", false, false), 0).unwrap() else { panic!() };
        let Decision::Challenge(again) = s.decide(&cfg, &message("stranger", false, false), 10).unwrap() else { panic!() };
        assert_eq!(first, again, "the same sender keeps the same code");
        assert_eq!(s.pending(10).unwrap().len(), 1);
    }

    #[test]
    fn approving_a_code_admits_that_sender_for_good() {
        let mut s = store("approve");
        let cfg = AccessConfig::default();
        s.decide(&cfg, &message("friend", false, false), 0).unwrap();
        let code = s.pending(0).unwrap()[0].code.clone();
        assert!(s.approve("WRONG123", 0).is_err());
        let approved = s.approve(&code.to_lowercase(), 1).unwrap();
        assert_eq!(approved.sender_id, "friend");
        assert_eq!(s.decide(&cfg, &message("friend", false, false), 2).unwrap(), Decision::Admit);
        // Persisted.
        let reloaded = PairingStore::load(&s.path).unwrap();
        assert_eq!(reloaded.approved_senders().unwrap()["telegram:main"], ["friend"]);
        assert!(s.revoke("telegram:main", "friend").unwrap());
        assert!(matches!(s.decide(&cfg, &message("friend", false, false), 3).unwrap(), Decision::Challenge(_)));
    }

    #[test]
    fn an_approval_from_another_process_is_seen_and_kept() {
        // `serve` holds one store; `bulge channels approve` opens another.
        let mut daemon = store("two-process");
        let cfg = AccessConfig::default();
        assert!(matches!(daemon.decide(&cfg, &message("owner", false, false), 0).unwrap(), Decision::Challenge(_)));
        let mut cli = PairingStore::load(&daemon.path).unwrap();
        let code = cli.pending(0).unwrap()[0].code.clone();
        cli.approve(&code, 1).unwrap();
        assert_eq!(daemon.decide(&cfg, &message("owner", false, false), 2).unwrap(), Decision::Admit);
        // A stranger's later code does not resurrect stale data over the approval.
        assert!(matches!(daemon.decide(&cfg, &message("stranger", false, false), 3).unwrap(), Decision::Challenge(_)));
        assert_eq!(cli.approved_senders().unwrap()["telegram:main"], ["owner"]);
    }

    #[test]
    fn codes_expire_and_pending_requests_are_capped() {
        let mut s = store("cap");
        let cfg = AccessConfig::default();
        for i in 0..MAX_PENDING {
            assert!(matches!(s.decide(&cfg, &message(&format!("s{i}"), false, false), 0).unwrap(), Decision::Challenge(_)));
        }
        assert!(matches!(s.decide(&cfg, &message("one-too-many", false, false), 0).unwrap(), Decision::Ignore(_)));
        let code = s.pending(0).unwrap()[0].code.clone();
        assert!(s.approve(&code, PAIRING_TTL_SECS + 1).is_err(), "expired");
        assert!(matches!(s.decide(&cfg, &message("one-too-many", false, false), PAIRING_TTL_SECS + 1).unwrap(), Decision::Challenge(_)));
    }

    #[test]
    fn groups_need_opt_in_an_allowed_sender_and_a_mention() {
        let mut s = store("groups");
        let off = AccessConfig { allow_from: vec!["owner".into()], ..Default::default() };
        assert!(matches!(s.decide(&off, &message("owner", true, true), 0).unwrap(), Decision::Ignore(_)));
        let on = AccessConfig { groups: true, ..off };
        assert!(matches!(s.decide(&on, &message("owner", true, false), 0).unwrap(), Decision::Ignore(_)));
        assert!(matches!(s.decide(&on, &message("stranger", true, true), 0).unwrap(), Decision::Ignore(_)));
        assert_eq!(s.decide(&on, &message("owner", true, true), 0).unwrap(), Decision::Admit);
        assert!(s.pending(0).unwrap().is_empty(), "group strangers never get codes");
    }

    #[test]
    fn open_groups_admit_anyone_who_addresses_the_bot_there_only() {
        let mut s = store("open");
        let cfg = AccessConfig { open_groups: vec!["Cgroup".into()], ..Default::default() };
        let mut m = message("stranger", true, true);
        m.chat_id = "Cgroup".into();
        assert_eq!(s.decide(&cfg, &m, 0).unwrap(), Decision::Admit);
        m.mentioned = false;
        assert!(matches!(s.decide(&cfg, &m, 0).unwrap(), Decision::Ignore(_)));
        let mut other = message("stranger", true, true);
        other.chat_id = "Cother".into();
        assert!(matches!(s.decide(&cfg, &other, 0).unwrap(), Decision::Ignore(_)), "other groups stay closed");
        assert!(cfg.listens_in("Cgroup") && !cfg.listens_in("Cother"));
        assert!(s.pending(0).unwrap().is_empty());
    }

    #[test]
    fn allowlist_and_disabled_policies_are_silent() {
        let mut s = store("silent");
        let allow = AccessConfig { dm_policy: DmPolicy::Allowlist, ..Default::default() };
        assert!(matches!(s.decide(&allow, &message("x", false, false), 0).unwrap(), Decision::Ignore(_)));
        let off = AccessConfig { dm_policy: DmPolicy::Disabled, allow_from: vec!["owner".into()], groups: true, ..Default::default() };
        assert!(matches!(s.decide(&off, &message("owner", false, false), 0).unwrap(), Decision::Ignore(_)));
        assert_eq!(s.decide(&off, &message("owner", true, true), 0).unwrap(), Decision::Admit, "groups still work");
        assert!(s.pending(0).unwrap().is_empty());
    }
}
