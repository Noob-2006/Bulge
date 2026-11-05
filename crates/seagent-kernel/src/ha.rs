//! Daemon high availability (ent-095 / ent-096): leader lease with a fencing token over shared
//! storage. Design and failure analysis: docs/ARCHITECTURE.md §7.
//!
//! Several `seagentd` processes point at one data directory (NFS, a shared disk, or `data/`
//! symlinked onto a mount). Exactly one of them holds the lease (`<ha_dir>/term-<epoch>.json`) and
//! acts as **leader**; the rest are **standby**. No upstream has this — the shape is the classic
//! lease + fencing-token pattern (Chubby / ZooKeeper "sequencer"), adapted to a dumb file store:
//!
//! - **CAS without a lock.** [`LeaseStore::swap`] replaces the record only if it still equals
//!   what the caller read. [`FsLease`] keeps one file per term and claims a new term with an
//!   exclusive `link()` (no lock file a paused holder could sit on); see its docs. An object
//!   store (S3 `If-Match` / `If-None-Match`, GCS generation) implements the same trait.
//! - **No cross-host clock.** A standby never trusts the expiry another machine wrote. It watches
//!   `(node, epoch, renewed)` on its own monotonic clock and only takes over after the record
//!   has stood still for `lease_secs`. The leader self-fences — stops writing — once its *own*
//!   monotonic clock says it has not renewed for `lease_secs`, which is never later than the
//!   moment a standby may take over.
//! - **Fencing token.** Every takeover bumps `epoch`. [`Ha::fence`] re-reads the record and
//!   refuses unless it still names this node and epoch; the session store calls it before every
//!   append (`Store::set_fence`), so a leader that was paused and wakes up with a model reply in
//!   hand cannot write into a log its successor owns. Workers inherit the token through
//!   [`ENV_NODE`] / [`ENV_EPOCH`] / [`ENV_DIR`] and install [`external_fence`].

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Worker processes inherit the leader's identity through these, so they fence too.
pub const ENV_NODE: &str = "SEAGENT_HA_NODE";
pub const ENV_EPOCH: &str = "SEAGENT_HA_EPOCH";
pub const ENV_DIR: &str = "SEAGENT_HA_DIR";

/// `[ha]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HaConfig {
    pub enabled: bool,
    /// Stable name of this node. "" = the host name.
    pub node_id: String,
    /// How long a silent leader keeps the lease (and how long a standby waits) in seconds.
    pub lease_secs: u64,
    /// Renewal period; 0 = `lease_secs / 3`.
    pub renew_secs: u64,
    /// Lease directory (`term-*.json`) on shared storage; "" = `<data>/ha`.
    pub dir: String,
    /// How clients reach this node (shown to callers redirected by a standby). "" = its socket.
    pub advertise: String,
    /// Node-local directory for the SQLite index (`index.db` must not live on NFS). "" = data dir.
    pub index_dir: String,
}

impl Default for HaConfig {
    fn default() -> Self {
        HaConfig { enabled: false, node_id: String::new(), lease_secs: 10, renew_secs: 0, dir: String::new(), advertise: String::new(), index_dir: String::new() }
    }
}

impl HaConfig {
    pub fn node(&self) -> String {
        if self.node_id.trim().is_empty() {
            crate::kanban::hostname()
        } else {
            self.node_id.trim().to_string()
        }
    }
    pub fn lease(&self) -> Duration {
        Duration::from_millis(self.lease_secs.max(1) * 1000)
    }
    pub fn renew(&self) -> Duration {
        if self.renew_secs > 0 {
            Duration::from_secs(self.renew_secs).min(self.lease() / 2)
        } else {
            self.lease() / 3
        }
    }
    pub fn lease_dir(&self, data: &Path) -> PathBuf {
        if self.dir.trim().is_empty() {
            data.join("ha")
        } else {
            PathBuf::from(self.dir.trim())
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled && self.lease_secs < 2 {
            return Err("ha.lease_secs must be at least 2".into());
        }
        if self.renew_secs > 0 && self.renew_secs >= self.lease_secs {
            return Err("ha.renew_secs must be shorter than ha.lease_secs".into());
        }
        if !self.node_id.is_empty() && !self.node_id.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) {
            return Err(format!("ha.node_id `{}` may only use letters, digits, `-`, `_` and `.`", self.node_id));
        }
        Ok(())
    }
}

/// The lease record (one `term-<epoch>.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Lease {
    pub node: String,
    /// The fencing token: strictly increases with every change of leader.
    pub epoch: u64,
    /// Renewal counter; a standby watches it move.
    pub renewed: u64,
    pub renewed_ms: u64,
    pub lease_ms: u64,
    #[serde(default)]
    pub advertise: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub pid: u32,
    /// Set by a graceful step-down: any standby may take over at once.
    #[serde(default)]
    pub released: bool,
}

impl Lease {
    fn same_term(&self, o: &Lease) -> bool {
        self.node == o.node && self.epoch == o.epoch
    }
}

/// Compare-and-swap storage for the lease record.
pub trait LeaseStore: Send + Sync {
    fn read(&self) -> Result<Option<Lease>, String>;
    /// Replace the record with `new` iff it still equals `expect` (`None` = no record yet).
    /// `Ok(false)` = somebody else changed it first.
    fn swap(&self, expect: Option<&Lease>, new: &Lease) -> Result<bool, String>;
    fn describe(&self) -> String;
}

/// One file per term in a (shared) directory: `term-<epoch>.json`.
///
/// There is deliberately **no lock file**: a holder that is paused (SIGSTOP, a long GC, a
/// partition) while holding a lock would block every standby forever. Instead:
/// - taking a new term is `link(tmp, term-<N>)`, which fails with `EEXIST` if anyone else
///   created that term first — the classic NFS-safe exclusive create, and a true CAS on N;
/// - the current lease is the highest-numbered term file;
/// - only the holder of term N ever rewrites `term-<N>.json` (renewal, release), via tmp +
///   rename. A deposed holder rewriting its old term is harmless: readers look at the highest.
pub struct FsLease {
    dir: PathBuf,
}

impl FsLease {
    pub fn new(dir: impl Into<PathBuf>) -> FsLease {
        FsLease { dir: dir.into() }
    }
    fn term(&self, epoch: u64) -> PathBuf {
        self.dir.join(format!("term-{epoch:012}.json"))
    }
    fn terms(&self) -> Vec<u64> {
        let mut v: Vec<u64> = fs::read_dir(&self.dir)
            .map(|rd| rd.flatten().filter_map(|e| e.file_name().to_str().and_then(|n| n.strip_prefix("term-")).and_then(|n| n.strip_suffix(".json")).and_then(|n| n.parse().ok())).collect())
            .unwrap_or_default();
        v.sort_unstable();
        v
    }
    fn write_tmp(&self, l: &Lease) -> Result<PathBuf, String> {
        fs::create_dir_all(&self.dir).map_err(|e| format!("{}: {e}", self.dir.display()))?;
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let tmp = self.dir.join(format!(".tmp-{}-{}-{}", l.node, std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
        let mut f = File::create(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.write_all(&serde_json::to_vec(l).map_err(|e| e.to_string())?).and_then(|_| f.sync_all()).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            e.to_string()
        })?;
        Ok(tmp)
    }
    fn sync_dir(&self) {
        if let Ok(d) = File::open(&self.dir) {
            let _ = d.sync_all();
        }
    }
}

impl LeaseStore for FsLease {
    fn read(&self) -> Result<Option<Lease>, String> {
        // A term file appears complete (link of a synced file), but tolerate a vanished one.
        for epoch in self.terms().into_iter().rev() {
            match fs::read(self.term(epoch)) {
                Ok(b) => return serde_json::from_slice(&b).map(Some).map_err(|e| format!("term-{epoch}: {e}")),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("term-{epoch}: {e}")),
            }
        }
        Ok(None)
    }
    fn swap(&self, expect: Option<&Lease>, new: &Lease) -> Result<bool, String> {
        if self.read()?.as_ref() != expect {
            return Ok(false);
        }
        let tmp = self.write_tmp(new)?;
        let same_term = expect.is_some_and(|e| e.epoch == new.epoch && e.node == new.node);
        let r = if same_term {
            // Renewal / release by the holder of this term: only it writes this file.
            fs::rename(&tmp, self.term(new.epoch)).map(|_| true).map_err(|e| format!("term-{}: {e}", new.epoch))
        } else if new.epoch > expect.map(|e| e.epoch).unwrap_or(0) {
            // A new term: exclusive create. EEXIST = another node won this epoch.
            let r = match fs::hard_link(&tmp, self.term(new.epoch)) {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
                Err(e) => Err(format!("term-{}: {e}", new.epoch)),
            };
            let _ = fs::remove_file(&tmp);
            r
        } else {
            let _ = fs::remove_file(&tmp);
            Err(format!("refusing to move the lease from epoch {} to {}", expect.map(|e| e.epoch).unwrap_or(0), new.epoch))
        };
        self.sync_dir();
        if r == Ok(true) && !same_term {
            // Keep a short history for `ha.status` / post-mortems; drop the rest.
            for old in self.terms().into_iter().filter(|e| *e + 8 < new.epoch) {
                let _ = fs::remove_file(self.term(old));
            }
        }
        r
    }
    fn describe(&self) -> String {
        self.dir.join("term-*.json").display().to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Standby,
    Leader,
}

/// What a [`Ha::tick`] changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    None,
    BecameLeader { epoch: u64, from: Option<String> },
    Lost { reason: String },
}

struct State {
    role: Role,
    held: Option<Lease>,
    last_renew: Instant,
    /// What a standby last saw, and when (its own clock).
    seen: Option<(String, u64, u64, bool)>,
    seen_at: Instant,
    last_error: Option<String>,
    takeovers: u64,
}

/// One node's view of the lease.
pub struct Ha {
    pub cfg: HaConfig,
    pub node: String,
    store: Box<dyn LeaseStore>,
    /// The epoch this node leads under; 0 = not leader. Read lock-free by the fence.
    epoch: AtomicU64,
    state: Mutex<State>,
}

fn pid_alive(pid: u32) -> bool {
    crate::kanban::pid_alive(pid)
}

impl Ha {
    pub fn new(cfg: HaConfig, store: Box<dyn LeaseStore>) -> Ha {
        let node = cfg.node();
        let now = Instant::now();
        Ha { cfg, node, store, epoch: AtomicU64::new(0), state: Mutex::new(State { role: Role::Standby, held: None, last_renew: now, seen: None, seen_at: now, last_error: None, takeovers: 0 }) }
    }

    /// The file-backed elector for a daemon whose data directory is `data`.
    pub fn for_data(cfg: &HaConfig, data: &Path) -> Ha {
        let dir = cfg.lease_dir(data);
        Ha::new(cfg.clone(), Box::new(FsLease::new(dir)))
    }

    pub fn is_leader(&self) -> bool {
        self.epoch.load(Ordering::SeqCst) != 0
    }
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }
    pub fn role(&self) -> Role {
        self.state.lock().unwrap().role
    }

    fn record(&self, epoch: u64, renewed: u64) -> Lease {
        Lease {
            node: self.node.clone(),
            epoch,
            renewed,
            renewed_ms: crate::event::now_ms(),
            lease_ms: self.cfg.lease().as_millis() as u64,
            advertise: self.cfg.advertise.clone(),
            host: crate::kanban::hostname(),
            pid: std::process::id(),
            released: false,
        }
    }

    /// Advance the state machine once. Call it at least every `renew()/2`.
    pub fn tick(&self) -> Transition {
        let mut st = self.state.lock().unwrap();
        let now = Instant::now();
        let lease = self.cfg.lease();
        match st.role {
            Role::Leader => {
                // Self-fence on our own clock first: past this point a standby may own it.
                if now.duration_since(st.last_renew) >= lease {
                    return self.lose(&mut st, format!("lease not renewed for {}s (shared storage unreachable or process paused)", lease.as_secs()));
                }
                if now.duration_since(st.last_renew) < self.cfg.renew() {
                    return Transition::None;
                }
                let held = st.held.clone().unwrap_or_default();
                let cur = match self.store.read() {
                    Ok(c) => c,
                    Err(e) => {
                        st.last_error = Some(e);
                        return Transition::None;
                    }
                };
                match cur {
                    Some(c) if c.same_term(&held) && !c.released => {
                        let next = Lease { renewed: c.renewed + 1, ..self.record(c.epoch, 0) };
                        match self.store.swap(Some(&c), &next) {
                            Ok(true) => {
                                st.held = Some(next);
                                st.last_renew = now;
                                st.last_error = None;
                                Transition::None
                            }
                            Ok(false) => self.lose(&mut st, "the lease changed while renewing".into()),
                            Err(e) => {
                                st.last_error = Some(e);
                                Transition::None
                            }
                        }
                    }
                    Some(c) => self.lose(&mut st, format!("node {} now holds the lease (epoch {})", c.node, c.epoch)),
                    None => self.lose(&mut st, "the lease record disappeared".into()),
                }
            }
            Role::Standby => {
                let cur = match self.store.read() {
                    Ok(c) => c,
                    Err(e) => {
                        st.last_error = Some(e);
                        return Transition::None;
                    }
                };
                st.last_error = None;
                let take = match &cur {
                    None => true,
                    // Released by somebody else; one we released ourselves waits like any lease.
                    Some(c) if c.released && c.node != self.node => true,
                    // Our own previous incarnation on this host, now dead: no need to wait.
                    Some(c) if c.node == self.node && c.host == crate::kanban::hostname() && c.pid != std::process::id() && !pid_alive(c.pid) => true,
                    Some(c) => {
                        let key = (c.node.clone(), c.epoch, c.renewed, c.released);
                        if st.seen.as_ref() != Some(&key) {
                            st.seen = Some(key);
                            st.seen_at = now;
                            false
                        } else {
                            // Wait the longer of our lease and the one the holder announced.
                            let wait = lease.max(Duration::from_millis(c.lease_ms));
                            now.duration_since(st.seen_at) >= wait
                        }
                    }
                };
                if !take {
                    return Transition::None;
                }
                let epoch = cur.as_ref().map(|c| c.epoch).unwrap_or(0) + 1;
                let new = self.record(epoch, 0);
                match self.store.swap(cur.as_ref(), &new) {
                    Ok(true) => {
                        st.role = Role::Leader;
                        st.held = Some(new);
                        st.last_renew = now;
                        st.seen = None;
                        st.takeovers += 1;
                        self.epoch.store(epoch, Ordering::SeqCst);
                        Transition::BecameLeader { epoch, from: cur.map(|c| c.node).filter(|n| !n.is_empty()) }
                    }
                    Ok(false) => Transition::None,
                    Err(e) => {
                        st.last_error = Some(e);
                        Transition::None
                    }
                }
            }
        }
    }

    fn lose(&self, st: &mut State, reason: String) -> Transition {
        self.epoch.store(0, Ordering::SeqCst);
        st.role = Role::Standby;
        st.held = None;
        st.seen = None;
        st.seen_at = Instant::now();
        Transition::Lost { reason }
    }

    /// Give the lease up (planned maintenance): the record is marked released, so a standby
    /// takes over on its next tick instead of waiting a full lease.
    pub fn step_down(&self) -> Result<bool, String> {
        let mut st = self.state.lock().unwrap();
        if st.role != Role::Leader {
            return Ok(false);
        }
        let held = st.held.clone().unwrap_or_default();
        self.epoch.store(0, Ordering::SeqCst);
        let cur = self.store.read()?;
        if let Some(c) = cur.filter(|c| c.same_term(&held)) {
            let rel = Lease { released: true, ..c.clone() };
            self.store.swap(Some(&c), &rel)?;
        }
        st.role = Role::Standby;
        st.held = None;
        // Do not grab it straight back: wait a full lease like any other standby would.
        st.seen = None;
        st.seen_at = Instant::now();
        Ok(true)
    }

    /// The write guard: `Ok` only while this node leads under the epoch on shared storage.
    pub fn fence(&self) -> Result<(), String> {
        let e = self.epoch();
        if e == 0 {
            return Err(format!("node {} is a standby, not the HA leader", self.node));
        }
        {
            let st = self.state.lock().unwrap();
            if st.last_renew.elapsed() >= self.cfg.lease() {
                return Err(format!("node {}'s lease (epoch {e}) expired locally", self.node));
            }
        }
        check_record(self.store.as_ref(), &self.node, e)
    }

    pub fn leader(&self) -> Option<Lease> {
        self.store.read().ok().flatten()
    }

    pub fn status(&self) -> Value {
        let st = self.state.lock().unwrap();
        let cur = self.store.read();
        json!({
            "enabled": true,
            "node": self.node,
            "role": match st.role { Role::Leader => "leader", Role::Standby => "standby" },
            "epoch": self.epoch(),
            "lease_secs": self.cfg.lease().as_secs(),
            "renew_ms": self.cfg.renew().as_millis() as u64,
            "store": self.store.describe(),
            "leader": cur.as_ref().ok().cloned().flatten(),
            "last_renew_ms_ago": (st.role == Role::Leader).then(|| st.last_renew.elapsed().as_millis() as u64),
            "takeovers": st.takeovers,
            "error": st.last_error.clone().or_else(|| cur.err()),
        })
    }

    /// The fence closure for `Store::set_fence`.
    pub fn store_fence(self: &Arc<Self>) -> crate::store::Fence {
        let me = self.clone();
        Arc::new(move || me.fence())
    }

    /// Environment for worker processes this leader starts.
    pub fn worker_env(&self, data: &Path) -> Vec<(String, String)> {
        vec![(ENV_NODE.into(), self.node.clone()), (ENV_EPOCH.into(), self.epoch().to_string()), (ENV_DIR.into(), self.cfg.lease_dir(data).display().to_string())]
    }
}

fn check_record(store: &dyn LeaseStore, node: &str, epoch: u64) -> Result<(), String> {
    match store.read()? {
        Some(l) if l.node == node && l.epoch == epoch && !l.released => Ok(()),
        Some(l) if l.released => Err(format!("the lease of node {} (epoch {}) was released", l.node, l.epoch)),
        Some(l) => Err(format!("fenced: node {} holds the lease at epoch {} (this writer has epoch {epoch})", l.node, l.epoch)),
        None => Err("no HA lease record on shared storage".into()),
    }
}

/// A fence for a process that does not elect (a worker): valid while the lease still names
/// `node`/`epoch`. Built from the inherited [`ENV_NODE`] / [`ENV_EPOCH`] / [`ENV_DIR`].
pub fn external_fence(dir: PathBuf, node: String, epoch: u64) -> crate::store::Fence {
    let store = FsLease::new(dir);
    Arc::new(move || check_record(&store, &node, epoch))
}

/// The inherited worker fence, if this process was started by an HA leader.
pub fn fence_from_env() -> Option<crate::store::Fence> {
    let node = std::env::var(ENV_NODE).ok().filter(|s| !s.is_empty())?;
    let epoch: u64 = std::env::var(ENV_EPOCH).ok()?.parse().ok()?;
    let dir = std::env::var_os(ENV_DIR).map(PathBuf::from)?;
    Some(external_fence(dir, node, epoch))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(node: &str, lease: u64) -> HaConfig {
        HaConfig { enabled: true, node_id: node.into(), lease_secs: lease, ..Default::default() }
    }

    /// Fast-forward a standby's observation (instead of sleeping a full lease in unit tests).
    fn age_observation(h: &Ha, by: Duration) {
        let mut st = h.state.lock().unwrap();
        st.seen_at -= by;
    }
    fn age_renewal(h: &Ha, by: Duration) {
        let mut st = h.state.lock().unwrap();
        st.last_renew -= by;
    }

    #[test]
    fn one_leader_takeover_bumps_the_epoch_and_fences_the_old_one() {
        let d = seagent_core::tmp::TempDir::new("seagent-ha");
        let a = Ha::new(cfg("a", 10), Box::new(FsLease::new(d.path())));
        let b = Ha::new(cfg("b", 10), Box::new(FsLease::new(d.path())));
        assert_eq!(a.tick(), Transition::BecameLeader { epoch: 1, from: None });
        assert!(a.fence().is_ok());
        // b sees a live leader and waits.
        assert_eq!(b.tick(), Transition::None);
        assert_eq!(b.tick(), Transition::None);
        assert!(b.fence().unwrap_err().contains("standby"));
        // a renews: the counter moves, b's observation restarts.
        age_renewal(&a, Duration::from_secs(4));
        assert_eq!(a.tick(), Transition::None);
        assert_eq!(a.leader().unwrap().renewed, 1);
        age_observation(&b, Duration::from_secs(9));
        assert_eq!(b.tick(), Transition::None, "a renewed: b must start its wait over");
        // a goes silent (paused): after a full lease of no movement b takes over at epoch 2.
        age_observation(&b, Duration::from_secs(10));
        assert_eq!(b.tick(), Transition::BecameLeader { epoch: 2, from: Some("a".into()) });
        assert!(b.fence().is_ok());
        // a still believes it leads (its clock was frozen) — the fence re-reads shared storage.
        assert!(a.is_leader());
        assert!(a.fence().unwrap_err().contains("node b holds the lease at epoch 2"));
        // ... and the next tick demotes it.
        age_renewal(&a, Duration::from_secs(4));
        assert!(matches!(a.tick(), Transition::Lost { reason } if reason.contains("node b")));
        assert!(!a.is_leader());
    }

    #[test]
    fn leader_self_fences_when_it_cannot_renew_in_time() {
        let d = seagent_core::tmp::TempDir::new("seagent-ha");
        let a = Ha::new(cfg("a", 5), Box::new(FsLease::new(d.path())));
        assert!(matches!(a.tick(), Transition::BecameLeader { .. }));
        age_renewal(&a, Duration::from_secs(6));
        assert!(a.fence().unwrap_err().contains("expired locally"), "the fence does not wait for the next tick");
        assert!(matches!(a.tick(), Transition::Lost { reason } if reason.contains("not renewed")));
    }

    #[test]
    fn step_down_hands_over_at_once_and_worker_fence_follows_the_epoch() {
        let d = seagent_core::tmp::TempDir::new("seagent-ha");
        let a = Ha::new(cfg("a", 30), Box::new(FsLease::new(d.path())));
        let b = Ha::new(cfg("b", 30), Box::new(FsLease::new(d.path())));
        a.tick();
        let wf = external_fence(d.path().to_path_buf(), "a".into(), 1);
        assert!(wf().is_ok());
        assert_eq!(b.tick(), Transition::None);
        assert!(a.step_down().unwrap());
        assert!(wf().is_err(), "a worker of a stepped-down leader is fenced immediately");
        assert_eq!(b.tick(), Transition::BecameLeader { epoch: 2, from: Some("a".into()) }, "released lease: no full wait");
        assert_eq!(a.tick(), Transition::None, "the old leader does not grab it straight back");
        assert!(wf().unwrap_err().contains("epoch 2"));
        let s = b.status();
        assert_eq!((s["role"].as_str(), s["epoch"].as_u64()), (Some("leader"), Some(2)));
    }

    #[test]
    fn concurrent_electors_never_both_lead() {
        let d = seagent_core::tmp::TempDir::new("seagent-ha");
        let nodes: Vec<Arc<Ha>> = (0..6).map(|i| Arc::new(Ha::new(cfg(&format!("n{i}"), 10), Box::new(FsLease::new(d.path()))))).collect();
        let hs: Vec<_> = nodes.iter().cloned().map(|h| std::thread::spawn(move || (0..20).filter(|_| matches!(h.tick(), Transition::BecameLeader { .. })).count())).collect();
        let wins: usize = hs.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(wins, 1, "exactly one CAS wins the empty lease");
        assert_eq!(nodes.iter().filter(|n| n.fence().is_ok()).count(), 1);
    }

    #[test]
    fn config_validation() {
        assert!(cfg("a", 1).validate().is_err());
        assert!(HaConfig { renew_secs: 10, ..cfg("a", 10) }.validate().is_err());
        assert!(cfg("bad node", 10).validate().is_err());
        assert!(cfg("seagentd-a.corp", 10).validate().is_ok());
        assert_eq!(cfg("a", 9).renew(), Duration::from_secs(3));
    }
}
