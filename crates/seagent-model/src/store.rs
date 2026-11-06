//! The credential store (`<config>/auth.json`, mode 0600): pooled API keys and OAuth
//! logins per provider, with pool status (cooldowns, request counts) so every process —
//! CLI, daemon — sees the same rotation state. Hermes `auth.json` credential pool /
//! OpenClaw auth profiles.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

pub const VERSION: u32 = 1;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Entry {
    pub id: String,
    pub label: String,
    /// `api_key` | `oauth` | `token` (long-lived bearer such as an Anthropic setup-token).
    pub kind: String,
    /// API key, setup token, or OAuth access token.
    pub key: Option<String>,
    pub refresh: Option<String>,
    pub expires_at_ms: Option<u64>,
    /// Login flow that minted it (refresh uses the same flow).
    pub flow: Option<String>,
    /// Endpoint this credential belongs to (Copilot Enterprise, Qwen resource URL, MiniMax region).
    pub base_url: Option<String>,
    /// Flow-specific data: id_token, account ids, Google project, client id…
    pub extra: BTreeMap<String, Value>,
    /// Lower = tried first under `fill_first`.
    pub priority: u32,
    /// `""` ok | `exhausted` | `dead` (revoked / refresh rejected — never rotated to).
    pub status: String,
    pub exhausted_until_ms: Option<u64>,
    /// Model-scoped cooldowns (`model → until ms`) from rate limits on one model.
    pub model_cooldowns: BTreeMap<String, u64>,
    pub last_error: Option<String>,
    pub request_count: u64,
    pub created_ms: u64,
}

impl Entry {
    pub fn new(kind: &str, label: &str, key: Option<String>) -> Entry {
        Entry {
            id: random_id(),
            label: label.to_string(),
            kind: kind.to_string(),
            key,
            created_ms: crate::ratelimit::now_ms(),
            ..Default::default()
        }
    }
    /// Cooling down (for `model`, or at all) right now.
    pub fn blocked(&self, model: Option<&str>, now: u64) -> Option<u64> {
        if self.status == "dead" {
            return Some(u64::MAX);
        }
        if let Some(u) = self.exhausted_until_ms.filter(|u| *u > now) {
            return Some(u);
        }
        model
            .and_then(|m| self.model_cooldowns.get(m).copied())
            .filter(|u| *u > now)
    }
    /// Redacted key for listings.
    pub fn masked(&self) -> String {
        mask(self.key.as_deref().unwrap_or(""))
    }
}

pub fn mask(k: &str) -> String {
    let n = k.chars().count();
    if n <= 8 {
        return "*".repeat(n);
    }
    let head: String = k.chars().take(4).collect();
    let tail: String = k.chars().skip(n - 4).collect();
    format!("{head}…{tail}")
}

fn random_id() -> String {
    let mut b = [0u8; 6];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut b);
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthFile {
    pub version: u32,
    pub providers: BTreeMap<String, Vec<Entry>>,
    /// Pool selection strategy per provider.
    pub strategies: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct Store {
    path: PathBuf,
    /// Agent-scoped view: reads merge this store (the agent's own profiles) over the shared base
    /// (OpenClaw `agents/<agent>/agent/auth-profiles.json` shadowing the shared store); writes
    /// stay in the agent's own file.
    base: Option<Box<Store>>,
}

fn default_path() -> &'static Mutex<Option<(PathBuf, Option<String>)>> {
    static P: OnceLock<Mutex<Option<(PathBuf, Option<String>)>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(None))
}

/// Where the process keeps its store (set once by the binary from its config dir).
pub fn set_default(path: PathBuf) {
    *default_path().lock().unwrap() = Some((path, None));
}

/// Keep the process store in agent `agent`'s profile (`$SEAGENT_AGENT`): reads merge the agent's own
/// profiles over the shared pool, writes stay in `<root>/agents/<agent>/auth.json`.
pub fn set_default_agent(root: &Path, agent: &str) {
    *default_path().lock().unwrap() = Some((root.to_path_buf(), Some(agent.to_string())));
}

pub fn default_store() -> Option<Store> {
    default_path()
        .lock()
        .unwrap()
        .clone()
        .map(|(p, agent)| match agent {
            Some(a) => Store::for_agent(&p, &a),
            None => Store::new(p),
        })
}

impl Store {
    pub fn new(path: PathBuf) -> Store {
        Store { path, base: None }
    }
    /// The shared pool store (`<config>/auth.json`).
    pub fn shared(root: &Path) -> Store {
        Store::new(root.join("auth.json"))
    }
    /// Per-agent credential profile store: `<root>/agents/<agent>/auth.json`. Its entries are
    /// tried before the shared pool's, and the runtime selects it with `$SEAGENT_AGENT`
    /// (OpenClaw: agent-local auth profiles override the shared read-through base).
    pub fn for_agent(root: &Path, agent: &str) -> Store {
        Store {
            path: root.join("agents").join(agent).join("auth.json"),
            base: Some(Box::new(Store::shared(root))),
        }
    }
    /// This store plus everything inherited from the shared base, agent-local entries first.
    pub fn merged(&self) -> AuthFile {
        let mut f = self.load();
        let Some(base) = &self.base else {
            return f;
        };
        let b = base.load();
        for (p, entries) in b.providers {
            let own = f.providers.entry(p).or_default();
            let ids: Vec<String> = own.iter().map(|e| e.id.clone()).collect();
            for e in entries {
                if !ids.contains(&e.id) {
                    own.push(e);
                }
            }
        }
        for (p, st) in b.strategies {
            f.strategies.entry(p).or_insert(st);
        }
        f
    }
    /// Whether this store is an agent-scoped view.
    pub fn is_agent_scoped(&self) -> bool {
        self.base.is_some()
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn load(&self) -> AuthFile {
        match std::fs::read_to_string(&self.path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
                eprintln!(
                    "seagent: warning: {}: unreadable ({e}); treating as empty",
                    self.path.display()
                );
                AuthFile {
                    version: VERSION,
                    ..Default::default()
                }
            }),
            Err(_) => AuthFile {
                version: VERSION,
                ..Default::default()
            },
        }
    }
    pub fn entries(&self, provider: &str) -> Vec<Entry> {
        let mut v = self.merged().providers.remove(provider).unwrap_or_default();
        v.sort_by_key(|e| e.priority);
        v
    }
    pub fn entry(&self, provider: &str, id: &str) -> Option<Entry> {
        self.entries(provider).into_iter().find(|e| e.id == id)
    }
    /// Read-modify-write under an exclusive lock; the file is replaced atomically, 0600.
    pub fn update<T>(&self, f: impl FnOnce(&mut AuthFile) -> T) -> Result<T, String> {
        if let Some(d) = self.path.parent() {
            std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        }
        let _lock = Lock::acquire(&self.path.with_extension("lock"));
        let mut file = self.load();
        file.version = VERSION;
        let out = f(&mut file);
        file.providers.retain(|_, v| !v.is_empty());
        let data = serde_json::to_vec_pretty(&file).map_err(|e| e.to_string())?;
        write_private(&self.path, &data).map_err(|e| format!("{}: {e}", self.path.display()))?;
        Ok(out)
    }
    /// Add an entry (priority = last unless given); returns its id.
    pub fn add(
        &self,
        provider: &str,
        mut e: Entry,
        priority: Option<u32>,
    ) -> Result<String, String> {
        let id = e.id.clone();
        self.update(|f| {
            let v = f.providers.entry(provider.to_string()).or_default();
            v.sort_by_key(|x| x.priority);
            let at = priority
                .map(|p| (p as usize).min(v.len()))
                .unwrap_or(v.len());
            e.priority = at as u32;
            v.insert(at, e);
            for (i, x) in v.iter_mut().enumerate() {
                x.priority = i as u32;
            }
        })?;
        Ok(id)
    }
    /// Replace an OAuth login of the same flow (re-login) or add it.
    pub fn upsert_login(&self, provider: &str, e: Entry) -> Result<String, String> {
        let existing = self
            .entries(provider)
            .into_iter()
            .find(|x| x.kind == e.kind && x.flow == e.flow && x.label == e.label)
            .map(|x| x.id);
        match existing {
            Some(id) => {
                self.update(|f| {
                    if let Some(x) = f
                        .providers
                        .get_mut(provider)
                        .and_then(|v| v.iter_mut().find(|x| x.id == id))
                    {
                        let prio = x.priority;
                        *x = Entry {
                            id: id.clone(),
                            priority: prio,
                            ..e
                        };
                    }
                })?;
                Ok(id)
            }
            None => self.add(provider, e, None),
        }
    }
    pub fn modify(
        &self,
        provider: &str,
        id: &str,
        f: impl FnOnce(&mut Entry),
    ) -> Result<bool, String> {
        self.update(|file| {
            match file
                .providers
                .get_mut(provider)
                .and_then(|v| v.iter_mut().find(|x| x.id == id))
            {
                Some(x) => {
                    f(x);
                    true
                }
                None => false,
            }
        })
    }
    /// Resolve an index (0-based as listed), id, or exact label.
    pub fn find(&self, provider: &str, target: &str) -> Result<Entry, String> {
        let v = self.entries(provider);
        if let Ok(i) = target.parse::<usize>() {
            if let Some(e) = v.get(i) {
                return Ok(e.clone());
            }
        }
        let m: Vec<&Entry> = v
            .iter()
            .filter(|e| e.id == target || e.label == target)
            .collect();
        match m.len() {
            1 => Ok(m[0].clone()),
            0 => Err(format!(
                "no credential `{target}` for {provider} (see `seagent auth list {provider}`)"
            )),
            n => Err(format!(
                "`{target}` matches {n} credentials for {provider}; use the id"
            )),
        }
    }
    pub fn remove(&self, provider: &str, id: &str) -> Result<bool, String> {
        self.update(|f| {
            let Some(v) = f.providers.get_mut(provider) else {
                return false;
            };
            let n = v.len();
            v.retain(|e| e.id != id);
            for (i, x) in v.iter_mut().enumerate() {
                x.priority = i as u32;
            }
            n != v.len()
        })
    }
    pub fn set_priority(&self, provider: &str, id: &str, prio: u32) -> Result<(), String> {
        self.update(|f| {
            if let Some(v) = f.providers.get_mut(provider) {
                v.sort_by_key(|x| x.priority);
                if let Some(i) = v.iter().position(|e| e.id == id) {
                    let e = v.remove(i);
                    let at = (prio as usize).min(v.len());
                    v.insert(at, e);
                }
                for (i, x) in v.iter_mut().enumerate() {
                    x.priority = i as u32;
                }
            }
        })
    }
    /// Clear cooldowns (one entry or all of a provider's). Dead entries stay dead.
    pub fn reset(&self, provider: &str, id: Option<&str>) -> Result<usize, String> {
        self.update(|f| {
            let mut n = 0;
            for e in f.providers.get_mut(provider).into_iter().flatten() {
                if id.is_none_or(|i| i == e.id) {
                    if e.status == "exhausted" {
                        e.status.clear();
                    }
                    e.exhausted_until_ms = None;
                    e.model_cooldowns.clear();
                    e.last_error = None;
                    n += 1;
                }
            }
            n
        })
    }
    pub fn clear_provider(&self, provider: &str) -> Result<usize, String> {
        self.update(|f| f.providers.remove(provider).map(|v| v.len()).unwrap_or(0))
    }
    pub fn strategy(&self, provider: &str) -> Option<String> {
        self.merged().strategies.get(provider).cloned()
    }
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// `flock`-based exclusive lock held for the read-modify-write.
struct Lock(Option<std::fs::File>);

impl Lock {
    fn acquire(path: &Path) -> Lock {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .ok();
        if let Some(f) = &f {
            unsafe {
                libc::flock(f.as_raw_fd(), libc::LOCK_EX);
            }
        }
        Lock(f)
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        if let Some(f) = &self.0 {
            unsafe {
                libc::flock(f.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn temp_store(tag: &str) -> Store {
    let d = seagent_core::tmp::scratch_path(format!(
        "seagent-authstore-{tag}-{}-{}",
        std::process::id(),
        random_id()
    ));
    Store::new(d.join("auth.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_list_priority_remove_reset() {
        let s = temp_store("crud");
        let a = s
            .add(
                "openai",
                Entry::new("api_key", "work", Some("sk-aaaaaaaaaaaa1111".into())),
                None,
            )
            .unwrap();
        let b = s
            .add(
                "openai",
                Entry::new("api_key", "home", Some("sk-bbbbbbbbbbbb2222".into())),
                None,
            )
            .unwrap();
        let c = s
            .add(
                "openai",
                Entry::new("api_key", "first", Some("sk-c".into())),
                Some(0),
            )
            .unwrap();
        let ids: Vec<String> = s.entries("openai").into_iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![c.clone(), a.clone(), b.clone()]);
        s.set_priority("openai", &b, 0).unwrap();
        assert_eq!(s.entries("openai")[0].id, b);
        assert_eq!(s.find("openai", "home").unwrap().id, b);
        assert_eq!(s.find("openai", "2").unwrap().id, a);
        assert!(s.find("openai", "nope").is_err());
        s.modify("openai", &a, |e| {
            e.status = "exhausted".into();
            e.exhausted_until_ms = Some(u64::MAX - 1);
            e.model_cooldowns.insert("m".into(), u64::MAX - 1);
        })
        .unwrap();
        assert!(s.entry("openai", &a).unwrap().blocked(None, 0).is_some());
        assert_eq!(s.reset("openai", Some(&a)).unwrap(), 1);
        let e = s.entry("openai", &a).unwrap();
        assert!(e.blocked(Some("m"), 0).is_none() && e.status.is_empty());
        assert!(s.remove("openai", &c).unwrap());
        assert_eq!(s.entries("openai").len(), 2);
        assert_eq!(e.masked(), "sk-a…1111");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(s.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(s.clear_provider("openai").unwrap(), 2);
        assert!(s.load().providers.is_empty());
    }

    #[test]
    fn relogin_replaces_same_flow() {
        let s = temp_store("upsert");
        let mut e = Entry::new("oauth", "default", Some("a1".into()));
        e.flow = Some("openai-codex".into());
        let id1 = s.upsert_login("openai-codex", e.clone()).unwrap();
        let mut e2 = Entry::new("oauth", "default", Some("a2".into()));
        e2.flow = Some("openai-codex".into());
        let id2 = s.upsert_login("openai-codex", e2).unwrap();
        assert_eq!(id1, id2);
        let v = s.entries("openai-codex");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].key.as_deref(), Some("a2"));
    }

    #[test]
    fn dead_entries_stay_blocked() {
        let e = Entry {
            status: "dead".into(),
            ..Default::default()
        };
        assert!(e.blocked(None, 0).is_some());
    }

    #[test]
    fn setup_token_does_not_collide_with_an_api_key_profile() {
        // OpenClaw e72b356459b: a setup-token profile must not replace an API-key
        // profile that happens to share its label. Our upsert keys on kind + flow +
        // label, so the API key stays usable and a re-login only replaces the token.
        let s = temp_store("anthropic-profiles");
        let key = Entry::new("api_key", "default", Some("sk-ant-api".into()));
        let key_id = s.add("anthropic", key.clone(), None).unwrap();
        let mut token = Entry::new("token", "setup-token", Some("sk-ant-oat01-a".into()));
        token.flow = Some("anthropic-setup-token".into());
        let token_id = s.upsert_login("anthropic", token).unwrap();
        assert_ne!(key_id, token_id);
        let e = s.entries("anthropic");
        assert_eq!(e.len(), 2);
        assert_eq!(e.iter().find(|x| x.id == key_id).unwrap().key.as_deref(), Some("sk-ant-api"));
        let mut again = Entry::new("token", "setup-token", Some("sk-ant-oat01-b".into()));
        again.flow = Some("anthropic-setup-token".into());
        assert_eq!(s.upsert_login("anthropic", again).unwrap(), token_id, "a token re-login replaces the token");
        let e = s.entries("anthropic");
        assert_eq!(e.len(), 2, "the API key is still there");
        assert_eq!(e.iter().find(|x| x.id == key_id).unwrap().key.as_deref(), Some("sk-ant-api"));
        assert_eq!(e.iter().find(|x| x.id == token_id).unwrap().key.as_deref(), Some("sk-ant-oat01-b"));
    }
}
