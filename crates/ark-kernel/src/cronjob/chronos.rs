//! External cron provider "chronos" (Hermes `plugins/cron_providers/chronos`): instead of the
//! built-in ticker, ask a NAS-style `agent-cron` service to arm ONE one-shot per job at its next
//! fire time; the service calls the agent back (`POST <callback_url>`, a short-lived JWT with
//! `purpose = "cron_fire"`, verified by the host's HTTP mount) and the job re-arms after it runs.
//! Lets an idle daemon scale to zero and still fire on time.
//!
//! Config (inert unless `provider = "chronos"`):
//! ```toml
//! [automation]
//! provider = "chronos"
//! [automation.chronos]
//! portal_url = "https://portal.example"     # agent-cron endpoints live under /api/agent-cron/
//! callback_url = "https://me.example/plugins/cron/fire"
//! token = "{{secret:CHRONOS_TOKEN}}"         # bearer for provision/cancel/list
//! jwks = "https://portal.example/.well-known/jwks.json"   # or an inline JWKS JSON
//! audience = "ark-agent"                     # expected `aud` of fire tokens
//! issuer = "https://portal.example"          # optional `iss` check
//! ```
//! Wire contract (Hermes `_nas_client.py`): `POST /api/agent-cron/provision`
//! `{job_id, fire_at, agent_callback_url, dedup_key}`, `POST /api/agent-cron/cancel {job_id}`,
//! `GET /api/agent-cron/list` → `{armed: [{job_id, fire_at}]}`. A 403 with
//! `{"error":"invalid_client"}` is a deterministic identity rejection: the provider stops
//! talking to the service and the built-in ticker takes over for this process.

use super::schedule::iso_utc;
use crate::automation::{jobs_path, read_list, with_list, Job};
use crate::config::Config;
use crate::cron::Cron;
use crate::kernel::Kernel;
use crate::util::unix_now;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

pub const PROVISION_PATH: &str = "/api/agent-cron/provision";
pub const CANCEL_PATH: &str = "/api/agent-cron/cancel";
pub const LIST_PATH: &str = "/api/agent-cron/list";
/// Fire tokens must carry this `purpose` claim (a general agent JWT must not replay here).
pub const FIRE_PURPOSE: &str = "cron_fire";
/// A fire may arrive a little early or late; outside this window it is refused as stale.
pub const FIRE_GRACE_SECS: i64 = 15 * 60;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ChronosConfig {
    pub portal_url: String,
    pub callback_url: String,
    /// Bearer for the agent-cron endpoints (vault-substituted).
    pub token: String,
    /// JWKS URL or inline JWKS JSON for fire-token verification.
    pub jwks: String,
    pub audience: String,
    pub issuer: Option<String>,
}

impl ChronosConfig {
    /// `Some` only when `[automation] provider = "chronos"` and portal + callback are set
    /// (Hermes `is_available`: config presence only, no network).
    pub fn from_config(cfg: &Config) -> Option<ChronosConfig> {
        let a = &cfg.automation;
        if a.get("provider").and_then(|v| v.as_str()) != Some("chronos") {
            return None;
        }
        let c = a.get("chronos")?.as_table()?;
        let g = |k: &str| c.get(k).and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
        let out = ChronosConfig { portal_url: g("portal_url").trim_end_matches('/').to_string(), callback_url: g("callback_url"), token: g("token"), jwks: g("jwks"), audience: g("audience"), issuer: Some(g("issuer")).filter(|s| !s.is_empty()) };
        (!out.portal_url.is_empty() && !out.callback_url.is_empty()).then_some(out)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientError {
    pub message: String,
    pub status: Option<u16>,
    pub error_code: String,
}

impl ClientError {
    /// The service refused the bearer as not a provisioned agent (never transient).
    pub fn identity_rejected(&self) -> bool {
        self.status == Some(403) && self.error_code == "invalid_client"
    }
}

/// Thin client for the agent → service endpoints.
pub struct Client {
    pub portal_url: String,
    pub token: String,
    agent: ureq::Agent,
}

impl Client {
    pub fn new(portal_url: &str, token: &str) -> Client {
        let agent: ureq::Agent = ark_net::http::builder().timeout_global(Some(Duration::from_secs(15))).http_status_as_error(false).build().into();
        Client { portal_url: portal_url.trim_end_matches('/').to_string(), token: token.to_string(), agent }
    }

    fn request(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value, ClientError> {
        let url = format!("{}{path}", self.portal_url);
        let transport = |e: ureq::Error| ClientError { message: format!("{method} {path} failed: {e}"), status: None, error_code: String::new() };
        let mut resp = if method == "GET" {
            self.agent.get(&url).header("Authorization", &format!("Bearer {}", self.token)).call().map_err(transport)?
        } else {
            self.agent.post(&url).header("Authorization", &format!("Bearer {}", self.token)).header("Content-Type", "application/json").send(body.unwrap_or(json!({})).to_string().as_bytes()).map_err(transport)?
        };
        let status = resp.status().as_u16();
        let text = resp.body_mut().read_to_string().unwrap_or_default();
        if status / 100 != 2 {
            let code = serde_json::from_str::<Value>(&text).ok().and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from)).unwrap_or_default();
            return Err(ClientError { message: format!("{method} {path} returned {status}: {}", text.chars().take(200).collect::<String>()), status: Some(status), error_code: code });
        }
        Ok(if text.trim().is_empty() { json!({}) } else { serde_json::from_str(&text).unwrap_or(json!({})) })
    }

    /// Arm a one-shot for `job_id` at `fire_at` (ISO 8601); `dedup_key` makes re-arming idempotent.
    pub fn provision(&self, job_id: &str, fire_at: &str, callback: &str, dedup_key: &str) -> Result<Value, ClientError> {
        self.request("POST", PROVISION_PATH, Some(json!({"job_id": job_id, "fire_at": fire_at, "agent_callback_url": callback, "dedup_key": dedup_key})))
    }
    pub fn cancel(&self, job_id: &str) -> Result<Value, ClientError> {
        self.request("POST", CANCEL_PATH, Some(json!({"job_id": job_id})))
    }
    /// `{job_id → fire_at}`; an odd shape is empty.
    pub fn list_armed(&self) -> Result<BTreeMap<String, String>, ClientError> {
        let v = self.request("GET", LIST_PATH, None)?;
        Ok(v.get("armed").and_then(|a| a.as_array()).map(|a| a.iter().filter_map(|i| Some((i.get("job_id")?.as_str()?.to_string(), i.get("fire_at").and_then(|f| f.as_str()).unwrap_or("").to_string()))).collect()).unwrap_or_default())
    }
}

// ───────────────────────── provider state ─────────────────────────

struct Installed {
    cfg: ChronosConfig,
    data: PathBuf,
    token: String,
}

static INSTALLED: RwLock<Option<Arc<Installed>>> = RwLock::new(None);

fn state_path(data: &Path) -> PathBuf {
    data.join("chronos_state.json")
}

fn load_state(data: &Path) -> Value {
    std::fs::read_to_string(state_path(data)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(json!({"armed": {}, "identity_rejected": false}))
}

fn save_state(data: &Path, v: &Value) {
    let _ = crate::util::atomic_write(&state_path(data), serde_json::to_string_pretty(v).unwrap_or_default().as_bytes());
}

pub fn identity_rejected(data: &Path) -> bool {
    load_state(data)["identity_rejected"].as_bool().unwrap_or(false)
}

/// Install the provider for this process (from the host after the kernel exists). Returns
/// true when chronos is active; arms all enabled jobs once (Hermes `start()`).
///
/// This is also the cron subsystem's host-attach point (`wire::attach` calls it on every entry
/// path): it registers the runtime the job mutations report `cron_changed` through and announces
/// the loaded job set with `cron_reconciled` (`reason = "startup"`), whether or not chronos is
/// the configured provider.
pub fn install(k: &Kernel) -> bool {
    super::attach(k);
    super::reconciled(k, "startup");
    let Some(cfg) = ChronosConfig::from_config(&k.cfg) else {
        *INSTALLED.write().unwrap() = None;
        return false;
    };
    let token = k.vault.substitute(&cfg.token);
    let inst = Arc::new(Installed { cfg, data: k.paths.data.clone(), token });
    *INSTALLED.write().unwrap() = Some(inst.clone());
    std::thread::spawn(move || {
        let _ = reconcile_with(&inst);
    });
    true
}

pub fn config() -> Option<ChronosConfig> {
    INSTALLED.read().unwrap().as_ref().map(|i| i.cfg.clone())
}

/// `chronos` when the provider owns firing in this process, else `builtin`.
pub fn provider_name(data: &Path) -> &'static str {
    if owns_ticks(data) {
        "chronos"
    } else {
        "builtin"
    }
}

/// When true the daemon's built-in ticker must not claim jobs (the service fires them).
pub fn owns_ticks(data: &Path) -> bool {
    INSTALLED.read().unwrap().as_ref().is_some_and(|i| i.data == data) && !identity_rejected(data)
}

/// The job set changed: converge armed one-shots (best effort, off-thread).
pub fn jobs_changed(data: &Path) {
    let inst = INSTALLED.read().unwrap().clone();
    if let Some(i) = inst.filter(|i| i.data == data) {
        std::thread::spawn(move || {
            let _ = reconcile_with(&i);
        });
    }
}

fn reconcile_with(i: &Installed) -> Result<(usize, usize), String> {
    let client = Client::new(&i.cfg.portal_url, &i.token);
    reconcile(&i.data, &client, &i.cfg.callback_url)
}

/// Converge service one-shots toward `schedules.json`: arm missing/changed, cancel orphans.
/// Returns (armed, cancelled).
pub fn reconcile(data: &Path, client: &Client, callback: &str) -> Result<(usize, usize), String> {
    let mut st = load_state(data);
    if st["identity_rejected"].as_bool().unwrap_or(false) {
        return Ok((0, 0));
    }
    let desired: BTreeMap<String, String> = read_list::<Job>(&jobs_path(data))?.iter().filter(|j| j.enabled).map(|j| (j.id.clone(), iso_utc(j.next_run))).collect();
    let mut observed: BTreeMap<String, String> = st["armed"].as_object().map(|o| o.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string())).collect()).unwrap_or_default();
    if observed.is_empty() {
        observed = client.list_armed().unwrap_or_default();
    }
    let (mut armed, mut cancelled) = (0, 0);
    let mut err = None;
    for (id, fire_at) in &desired {
        if observed.get(id) == Some(fire_at) {
            continue;
        }
        match client.provision(id, fire_at, callback, &format!("{id}:{fire_at}")) {
            Ok(_) => {
                observed.insert(id.clone(), fire_at.clone());
                armed += 1;
            }
            Err(e) if e.identity_rejected() => {
                eprintln!("arkd: chronos: the service rejected this agent's credential (403 invalid_client); falling back to the built-in cron ticker for this process");
                st["identity_rejected"] = json!(true);
                save_state(data, &st);
                return Err(e.message);
            }
            Err(e) => err = Some(e.message),
        }
    }
    let orphans: Vec<String> = observed.keys().filter(|k| !desired.contains_key(*k)).cloned().collect();
    for id in orphans {
        if client.cancel(&id).is_ok() {
            cancelled += 1;
        }
        observed.remove(&id);
    }
    st["armed"] = json!(observed);
    st["last_reconcile"] = json!(unix_now());
    save_state(data, &st);
    match err {
        Some(e) => Err(e),
        None => Ok((armed, cancelled)),
    }
}

/// Claim `id` for an external fire: it must be enabled and due within the grace window.
/// Advances `next_run` like the ticker does (a duplicate fire is a no-op).
pub fn claim(data: &Path, id: &str, now: i64, offset: i32) -> Result<Job, String> {
    with_list(&jobs_path(data), |v: &mut Vec<Job>| -> Result<Job, String> {
        let j = v.iter_mut().find(|j| j.id == id).ok_or_else(|| format!("unknown job {id}"))?;
        if !j.enabled {
            return Err(format!("job {id} is disabled"));
        }
        if j.next_run > now + 60 {
            return Err(format!("job {id} is not due yet (already fired or re-armed)"));
        }
        if now - j.next_run > FIRE_GRACE_SECS {
            // Too late: skip this occurrence, re-arm the next one.
            match Cron::parse(&j.cron).ok().and_then(|c| c.next_after(now, offset)) {
                Some(n) => j.next_run = n,
                None => j.enabled = false,
            }
            return Err(format!("job {id} fire is stale (missed by more than {}m); re-armed", FIRE_GRACE_SECS / 60));
        }
        match Cron::parse(&j.cron).ok().and_then(|c| c.next_after(now, offset)) {
            Some(n) => j.next_run = n,
            None => j.enabled = false,
        }
        j.ext.runs += 1;
        if j.ext.repeat.is_some_and(|r| j.ext.runs >= r) {
            j.enabled = false;
        }
        j.last_run = Some(now);
        Ok(j.clone())
    })?
}

/// Handle a verified fire for `job_id`: claim, run in the background, re-arm afterwards.
pub fn fire(k: &Kernel, job_id: &str) -> Result<String, String> {
    let job = claim(&k.paths.data, job_id, unix_now(), k.cfg.schedule.utc_offset_minutes)?;
    let k2 = k.clone();
    std::thread::spawn(move || {
        let _ = crate::automation::run_job(&k2, &job);
        jobs_changed(&k2.paths.data);
    });
    Ok(format!("fired {job_id}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;

    /// Requests recorded by [`fake`]: `(method, path, body, reply)`.
    type Seen = Arc<Mutex<Vec<(String, String, Value, String)>>>;

    /// Fake agent-cron service: records requests, answers from `reply`.
    fn fake(reply: impl Fn(&str, &str, &Value) -> (u16, String) + Send + 'static) -> (String, Seen) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let mut r = BufReader::new(c.try_clone().unwrap());
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                let mut it = line.split_whitespace();
                let (m, p) = (it.next().unwrap_or("").to_string(), it.next().unwrap_or("").to_string());
                let (mut len, mut auth) = (0usize, String::new());
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).unwrap();
                    if h.trim().is_empty() {
                        break;
                    }
                    let lower = h.to_ascii_lowercase();
                    if let Some(v) = lower.strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                    if lower.starts_with("authorization:") {
                        auth = h["authorization:".len()..].trim().to_string();
                    }
                }
                let mut b = vec![0; len];
                r.read_exact(&mut b).unwrap();
                let body: Value = serde_json::from_slice(&b).unwrap_or(Value::Null);
                let (st, out) = reply(&m, &p, &body);
                s2.lock().unwrap().push((m, p, body, auth));
                let mut c = c;
                let _ = write!(c, "HTTP/1.1 {st} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}", out.len());
            }
        });
        (url, seen)
    }

    fn data_with_jobs() -> (PathBuf, Vec<Job>) {
        let d = std::env::temp_dir().join(format!("ark-chronos-{}", crate::util::random_hex(8)));
        std::fs::create_dir_all(&d).unwrap();
        let a = crate::automation::add_job(&d, "@hourly", "a", &d, None, false, 0).unwrap();
        let b = crate::automation::add_job(&d, "@daily", "b", &d, None, false, 0).unwrap();
        (d, vec![a, b])
    }

    #[test]
    fn reconcile_arms_cancels_and_is_idempotent() {
        let (d, jobs) = data_with_jobs();
        let (url, seen) = fake(|m, p, _| match (m, p) {
            ("GET", LIST_PATH) => (200, json!({"armed": [{"job_id": "orphan", "fire_at": "2026-01-01T00:00:00Z"}]}).to_string()),
            _ => (200, "{}".into()),
        });
        let c = Client::new(&url, "tok-1");
        assert_eq!(reconcile(&d, &c, "https://me/cb").unwrap(), (2, 1));
        {
            let s = seen.lock().unwrap();
            let prov: Vec<_> = s.iter().filter(|r| r.1 == PROVISION_PATH).collect();
            assert_eq!(prov.len(), 2);
            assert_eq!(prov[0].2["agent_callback_url"], "https://me/cb");
            assert_eq!(prov[0].2["dedup_key"], format!("{}:{}", prov[0].2["job_id"].as_str().unwrap(), prov[0].2["fire_at"].as_str().unwrap()));
            assert!(s.iter().any(|r| r.1 == CANCEL_PATH && r.2["job_id"] == "orphan"));
            assert!(s.iter().all(|r| r.3 == "Bearer tok-1"));
        }
        let n = seen.lock().unwrap().len();
        assert_eq!(reconcile(&d, &c, "https://me/cb").unwrap(), (0, 0), "warm state: nothing to re-arm");
        assert_eq!(seen.lock().unwrap().len(), n);
        // Removing a job cancels its one-shot.
        crate::automation::remove_job(&d, &jobs[0].id).unwrap();
        assert_eq!(reconcile(&d, &c, "https://me/cb").unwrap(), (0, 1));
    }

    #[test]
    fn identity_rejection_hands_back_to_the_ticker() {
        let (d, _) = data_with_jobs();
        let (url, _) = fake(|m, _, _| if m == "GET" { (200, json!({"armed": []}).to_string()) } else { (403, json!({"error": "invalid_client"}).to_string()) });
        let c = Client::new(&url, "bad");
        assert!(reconcile(&d, &c, "cb").is_err());
        assert!(identity_rejected(&d));
        assert_eq!(reconcile(&d, &c, "cb").unwrap(), (0, 0), "no more calls once rejected");
        let (url, _) = fake(|_, _, _| (500, "oops".into()));
        let e = Client::new(&url, "x").cancel("j").unwrap_err();
        assert_eq!((e.status, e.identity_rejected()), (Some(500), false));
    }

    #[test]
    fn claim_respects_due_window_and_dedups() {
        let (d, jobs) = data_with_jobs();
        let j = &jobs[0];
        let early = j.next_run - 3600;
        assert!(claim(&d, &j.id, early, 0).unwrap_err().contains("not due"));
        let got = claim(&d, &j.id, j.next_run, 0).unwrap();
        assert_eq!(got.ext.runs, 1);
        assert!(claim(&d, &j.id, j.next_run, 0).unwrap_err().contains("not due"), "duplicate fire is a no-op");
        let late = jobs[1].next_run + FIRE_GRACE_SECS + 10;
        assert!(claim(&d, &jobs[1].id, late, 0).unwrap_err().contains("stale"));
        assert!(claim(&d, "nope", 0, 0).is_err());
    }

    #[test]
    fn config_is_inert_unless_selected() {
        let mut cfg = Config::default();
        assert!(ChronosConfig::from_config(&cfg).is_none());
        cfg.automation = toml::from_str("provider = \"chronos\"\n[chronos]\nportal_url = \"https://p/\"\ncallback_url = \"https://cb\"\naudience = \"ark\"").unwrap();
        let c = ChronosConfig::from_config(&cfg).unwrap();
        assert_eq!((c.portal_url.as_str(), c.audience.as_str(), c.issuer), ("https://p", "ark", None));
        cfg.automation = toml::from_str("provider = \"chronos\"\n[chronos]\nportal_url = \"https://p\"").unwrap();
        assert!(ChronosConfig::from_config(&cfg).is_none(), "callback required");
    }
}
