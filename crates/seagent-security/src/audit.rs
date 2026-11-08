//! Unified, tamper-evident audit stream (ent-072 / ent-073 / ent-061).
//!
//! Every security-relevant fact — app-server requests and their principal, logins, token
//! issue/rotate/revoke, configuration changes, approval answers (with *who* answered),
//! broker requests and gate decisions — becomes one [`Event`] in one file:
//!
//! ```text
//! <data>/audit/events.jsonl                    the live segment
//! <data>/audit/head.json                       {seq, hash} of the last record
//! <data>/audit/archive/events-<a>-<b>.jsonl    rotated, read-only segments
//! <data>/audit/archive/events-<a>-<b>.seal     {first_seq, last_seq, first_prev, last_hash, sha256}
//! ```
//!
//! Records are **hash-chained**: `hash = sha256(prev ‖ canonical(record without hash))`, and
//! the chain continues across rotated segments, so editing, deleting or reordering any line
//! breaks `verify` from that point on. A local process running as the same user can still
//! rewrite the whole chain; the defence for that is the external copy — every record (with its
//! hash) is forwarded to syslog / Splunk HEC / OTLP by [`crate::audit_export`], so the SIEM
//! holds an independent anchor that `seagent audit verify --anchor <hash>` can be checked against.
//!
//! Records are metadata only: method names, principals, verdicts, ids — never message text,
//! tool input or secret values. Free-text fields are capped and PII-masked before writing.
//!
//! Writers in several processes (daemon, CLI, app server) serialise through `flock` on
//! `<data>/audit/.lock`; nothing here ever blocks on a human.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Who did it. `kind`: `token` (a named `[app] tokens` entry), `service` (an issued service
/// account), `sso` (an OIDC login), `basic` (dashboard password), `local` (the unix socket /
/// a terminal: the OS user), `channel` (a chat sender), `system` (the daemon itself).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Actor {
    pub kind: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub role: String,
    /// Client address (after trusted-proxy resolution), when the action came over the network.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ip: String,
}

impl Actor {
    pub fn new(kind: &str, name: &str) -> Actor {
        Actor { kind: kind.into(), name: name.into(), ..Default::default() }
    }
    pub fn system() -> Actor {
        Actor::new("system", "seagentd")
    }
    /// The OS user running this process (the owner of the unix socket).
    pub fn local() -> Actor {
        let name = crate::os::user_name();
        Actor { kind: "local".into(), name, role: "admin".into(), ip: String::new() }
    }
    pub fn channel(channel: &str, sender: &str) -> Actor {
        Actor::new("channel", &format!("{channel}:{sender}"))
    }
    pub fn with_role(mut self, role: &str) -> Actor {
        self.role = role.into();
        self
    }
    pub fn with_ip(mut self, ip: &str) -> Actor {
        self.ip = ip.into();
        self
    }
    /// `kind:name`, the compact form used in logs and `approved_by`.
    pub fn label(&self) -> String {
        format!("{}:{}", self.kind, self.name)
    }
    /// Parse the compact `kind:name` form back (unknown → `local`).
    pub fn parse_label(s: &str) -> Actor {
        match s.split_once(':') {
            Some((k, n)) if !k.is_empty() => Actor::new(k, n),
            _ => Actor::new("local", s),
        }
    }
}

/// One audit record before it is chained.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// Dotted kind: `app.request`, `auth.login`, `auth.denied`, `token.issue`,
    /// `config.change`, `approval.answer`, `broker.request`, `gate.decision`, `audit.*`,
    /// `retention.*`, `ediscovery.export`, `quota.*`, `budget.alert`.
    pub kind: String,
    pub actor: Actor,
    /// What was acted on (a method, a session id, a config key, a host …).
    pub target: String,
    /// `allow`, `deny`, `ok`, `error`, or a gate verdict.
    pub outcome: String,
    pub session: String,
    pub detail: Value,
    /// Organization / team the record belongs to (ent-050); empty = the default organization.
    pub org: String,
    pub team: String,
}

impl Event {
    pub fn new(kind: &str, actor: Actor, target: &str, outcome: &str) -> Event {
        Event { kind: kind.into(), actor, target: target.into(), outcome: outcome.into(), session: String::new(), detail: Value::Null, org: String::new(), team: String::new() }
    }
    /// Tag the record with its tenant (ent-050).
    pub fn tenant(mut self, org: &str, team: &str) -> Event {
        self.org = org.into();
        self.team = team.into();
        self
    }
    pub fn session(mut self, s: &str) -> Event {
        self.session = s.into();
        self
    }
    pub fn detail(mut self, d: Value) -> Event {
        self.detail = d;
        self
    }
}

const MAX_FIELD: usize = 500;
/// Detail keys that carry a principal and are exempt from PII masking.
pub const IDENTITY_KEYS: &[&str] = &["approved_by", "answered_by", "principal", "user", "subject", "issued_to", "custodian", "requester", "approvals", "approvers", "owner", "reviewer"];
static MAX_BYTES: AtomicU64 = AtomicU64::new(64 * 1024 * 1024);

/// Rotate the live segment once it grows past `bytes` (`[audit] rotate_mb`).
pub fn set_rotate_bytes(bytes: u64) {
    MAX_BYTES.store(bytes.max(4096), Ordering::Relaxed);
}

pub fn dir(data: &Path) -> PathBuf {
    data.join("audit")
}
fn live(data: &Path) -> PathBuf {
    dir(data).join("events.jsonl")
}
fn head_path(data: &Path) -> PathBuf {
    dir(data).join("head.json")
}
pub fn archive_dir(data: &Path) -> PathBuf {
    dir(data).join("archive")
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
pub fn sha256_hex(b: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, b).as_ref())
}

/// Keys sorted at every level, no whitespace: the bytes the hash covers.
pub fn canonical(v: &Value) -> String {
    fn sort(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                let mut out = Map::new();
                for k in keys {
                    out.insert(k.clone(), sort(&m[k]));
                }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(sort).collect()),
            o => o.clone(),
        }
    }
    // serde_json's map keeps insertion order only with `preserve_order`; sorting by hand makes
    // the encoding independent of that feature.
    let s = sort(v);
    let mut out = String::new();
    write_canon(&s, &mut out);
    out
}

fn write_canon(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            out.push('{');
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String((*k).clone()).to_string());
                out.push(':');
                write_canon(&m[*k], out);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canon(x, out);
            }
            out.push(']');
        }
        o => out.push_str(&o.to_string()),
    }
}

fn chain_hash(prev: &str, body: &Value) -> String {
    let mut m = prev.as_bytes().to_vec();
    m.push(b'\n');
    m.extend_from_slice(canonical(body).as_bytes());
    sha256_hex(&m)
}

/// Cap and mask a free-text field (ent-078: nothing personal lands in the stream by accident).
fn clean(s: &str) -> String {
    let s: String = s.chars().take(MAX_FIELD).collect();
    crate::pii::mask(&s)
}

/// Detail keys that carry an identifier (session / approval / request ids): capped, never
/// masked — an auditor joins audit records to sessions on them, so they must stay exact.
pub const ID_KEYS: &[&str] = &["session", "session_id", "id", "approval_id", "request_id", "tool_use_id", "seq"];

fn cap(s: &str) -> String {
    s.chars().take(MAX_FIELD).collect()
}

/// An identifier rather than free text: one token of `[A-Za-z0-9._:/-]` that contains a
/// letter and no `@`. Session ids (`20261105-091234-fac35b`) and approval ids have long digit
/// runs that the card mask's Luhn check passes one time in ten; a bare card number (digits
/// and separators only) is not id-shaped and is still masked.
fn id_shaped(s: &str) -> bool {
    !s.is_empty() && s.chars().any(|c| c.is_ascii_alphabetic()) && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '-'))
}

fn clean_target(s: &str) -> String {
    if id_shaped(s) {
        cap(s)
    } else {
        clean(s)
    }
}

fn clean_value(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(clean(s)),
        Value::Array(a) => Value::Array(a.iter().take(64).map(clean_value).collect()),
        // Identity fields name *who* acted: capped, never masked.
        Value::Object(m) => Value::Object(m.iter().take(64).map(|(k, v)| (k.clone(), if IDENTITY_KEYS.contains(&k.as_str()) || ID_KEYS.contains(&k.as_str()) { cap_value(v) } else { clean_value(v) })).collect()),
        o => o.clone(),
    }
}

fn cap_value(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(s.chars().take(MAX_FIELD).collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, v)| (k.clone(), cap_value(v))).collect()),
        o => o.clone(),
    }
}

struct Lock(File);
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

/// `File::lock` is `flock(LOCK_EX)` on unix and `LockFileEx` on Windows.
fn lock(data: &Path) -> Result<Lock, String> {
    // Never resurrect a removed home: the data dir may be created, but its parent must exist.
    if !data.exists() && !data.parent().is_some_and(Path::exists) {
        return Err(format!("audit: {} does not exist", data.display()));
    }
    fs::create_dir_all(dir(data)).map_err(|e| format!("audit: {e}"))?;
    let f = crate::os::with_mode(OpenOptions::new().create(true).truncate(false).write(true), 0o600).open(dir(data).join(".lock")).map_err(|e| format!("audit: {e}"))?;
    if f.lock().is_err() {
        return Err("audit: cannot lock".into());
    }
    Ok(Lock(f))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Head {
    pub seq: u64,
    pub hash: String,
}

/// The last record's seq and hash (from `head.json`, recovered from the files if missing).
pub fn head(data: &Path) -> Head {
    if let Some(h) = fs::read_to_string(head_path(data)).ok().and_then(|s| serde_json::from_str::<Head>(&s).ok()) {
        return h;
    }
    // Recover from the newest record on disk.
    let mut h = Head::default();
    for p in segments(data) {
        if let Some(last) = read_lines(&p).last() {
            h = Head { seq: last["seq"].as_u64().unwrap_or(0), hash: last["hash"].as_str().unwrap_or("").into() };
        }
    }
    h
}

/// Append one record. Returns its sequence number.
pub fn emit(data: &Path, ev: Event) -> Result<u64, String> {
    let _l = lock(data)?;
    let h = head(data);
    let seq = h.seq + 1;
    let mut body = json!({
        "v": 1,
        "seq": seq,
        "ts": now_ms(),
        "kind": ev.kind,
        // The actor is the point of the record: capped, never masked.
        "actor": cap_value(&serde_json::to_value(&ev.actor).unwrap_or(Value::Null)),
        "target": clean_target(&ev.target),
        "outcome": clean(&ev.outcome),
        "prev": h.hash,
    });
    if !ev.session.is_empty() {
        body["session"] = Value::String(cap(&ev.session));
    }
    if !ev.detail.is_null() {
        body["detail"] = clean_value(&ev.detail);
    }
    // Tenant tags are written only when set, so single-tenant records keep their exact shape.
    if !ev.org.is_empty() && ev.org != "default" {
        body["org"] = Value::String(clean(&ev.org));
    }
    if !ev.team.is_empty() {
        body["team"] = Value::String(clean(&ev.team));
    }
    let hash = chain_hash(&h.hash, &body);
    body["hash"] = Value::String(hash.clone());
    let p = live(data);
    let mut f = crate::os::with_mode(OpenOptions::new().create(true).append(true), 0o600).open(&p).map_err(|e| format!("audit: {e}"))?;
    writeln!(f, "{}", canonical(&body)).map_err(|e| format!("audit: {e}"))?;
    let _ = f.sync_data();
    let tmp = head_path(data).with_extension("tmp");
    fs::write(&tmp, serde_json::to_string(&Head { seq, hash }).unwrap_or_default()).map_err(|e| format!("audit: {e}"))?;
    fs::rename(&tmp, head_path(data)).map_err(|e| format!("audit: {e}"))?;
    if f.metadata().map(|m| m.len()).unwrap_or(0) >= MAX_BYTES.load(Ordering::Relaxed) {
        rotate_locked(data)?;
    }
    Ok(seq)
}

/// Best effort: an audit failure is reported on stderr, never turned into a request failure
/// (the request itself already happened or was refused).
pub fn record(data: &Path, ev: Event) {
    if let Err(e) = emit(data, ev) {
        note_error(&e);
    }
}

static WRITE_ERRORS: AtomicU64 = AtomicU64::new(0);
static LAST_ERROR: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

/// Remember a failure (audit write or SIEM export) for `/metrics` and `/ready`; libraries do
/// not print.
pub fn note_error(e: &str) {
    WRITE_ERRORS.fetch_add(1, Ordering::Relaxed);
    *LAST_ERROR.lock().unwrap_or_else(|p| p.into_inner()) = e.to_string();
}

/// `(failures so far, last message)`.
pub fn errors() -> (u64, String) {
    (WRITE_ERRORS.load(Ordering::Relaxed), LAST_ERROR.lock().unwrap_or_else(|p| p.into_inner()).clone())
}

/// Close the live segment: move it into `archive/` read-only and write its seal.
pub fn rotate(data: &Path) -> Result<Option<PathBuf>, String> {
    let _l = lock(data)?;
    rotate_locked(data)
}

fn rotate_locked(data: &Path) -> Result<Option<PathBuf>, String> {
    let p = live(data);
    let lines = read_lines(&p);
    let (Some(first), Some(last)) = (lines.first(), lines.last()) else { return Ok(None) };
    let (a, b) = (first["seq"].as_u64().unwrap_or(0), last["seq"].as_u64().unwrap_or(0));
    fs::create_dir_all(archive_dir(data)).map_err(|e| format!("audit: {e}"))?;
    let dest = archive_dir(data).join(format!("events-{a:012}-{b:012}.jsonl"));
    let bytes = fs::read(&p).map_err(|e| format!("audit: {e}"))?;
    let seal = json!({
        "first_seq": a, "last_seq": b,
        "first_ts": first["ts"], "last_ts": last["ts"],
        "first_prev": first["prev"], "last_hash": last["hash"],
        "sha256": sha256_hex(&bytes), "sealed_at": now_ms(),
    });
    fs::rename(&p, &dest).map_err(|e| format!("audit: {e}"))?;
    let _ = crate::os::set_mode(&dest, 0o400);
    let sp = dest.with_extension("seal");
    fs::write(&sp, serde_json::to_string_pretty(&seal).unwrap_or_default()).map_err(|e| format!("audit: {e}"))?;
    let _ = crate::os::set_mode(&sp, 0o400);
    Ok(Some(dest))
}

/// Archived segments oldest first, then the live one.
pub fn segments(data: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(archive_dir(data)).map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "jsonl")).collect()).unwrap_or_default();
    v.sort();
    let l = live(data);
    if l.exists() {
        v.push(l);
    }
    v
}

fn read_lines(p: &Path) -> Vec<Value> {
    let Ok(f) = File::open(p) else { return vec![] };
    BufReader::new(f).lines().map_while(Result::ok).filter(|l| !l.trim().is_empty()).map(|l| serde_json::from_str(&l).unwrap_or(Value::Null)).collect()
}

/// Every record in order (archived then live).
pub fn all(data: &Path) -> Vec<Value> {
    segments(data).iter().flat_map(|p| read_lines(p)).collect()
}

/// `seagent audit events` filter.
#[derive(Debug, Clone, Default)]
pub struct Query {
    pub kind: Option<String>,
    pub actor: Option<String>,
    pub session: Option<String>,
    pub outcome: Option<String>,
    pub after_ms: Option<u64>,
    pub before_ms: Option<u64>,
    pub limit: usize,
    /// Only this organization's records (`default` also matches untagged ones).
    pub org: Option<String>,
    /// Only this team's records plus the organization-wide ones.
    pub team: Option<String>,
}

impl Query {
    pub fn matches(&self, r: &Value) -> bool {
        let s = |k: &str| r[k].as_str().unwrap_or("");
        self.kind.as_deref().is_none_or(|k| s("kind") == k || s("kind").starts_with(&format!("{k}.")))
            && self.actor.as_deref().is_none_or(|a| r["actor"]["name"].as_str() == Some(a) || format!("{}:{}", r["actor"]["kind"].as_str().unwrap_or(""), r["actor"]["name"].as_str().unwrap_or("")) == a)
            && self.session.as_deref().is_none_or(|x| s("session") == x)
            && self.outcome.as_deref().is_none_or(|x| s("outcome") == x)
            && self.after_ms.is_none_or(|t| r["ts"].as_u64().unwrap_or(0) >= t)
            && self.before_ms.is_none_or(|t| r["ts"].as_u64().unwrap_or(0) < t)
            && self.org.as_deref().is_none_or(|o| r["org"].as_str().unwrap_or("default") == o)
            && self.team.as_deref().is_none_or(|t| r["team"].as_str().is_none_or(|x| x.is_empty() || x == t))
    }
}

/// Newest-last matching records, at most `limit` (the newest ones).
pub fn query(data: &Path, q: &Query) -> Vec<Value> {
    let mut v: Vec<Value> = all(data).into_iter().filter(|r| q.matches(r)).collect();
    let lim = if q.limit == 0 { 100 } else { q.limit };
    if v.len() > lim {
        v.drain(..v.len() - lim);
    }
    v
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct Verify {
    pub ok: bool,
    pub segments: usize,
    pub events: u64,
    pub first_seq: u64,
    pub last_seq: u64,
    /// `prev` of the oldest remaining record: empty when the chain starts at genesis, the hash
    /// of the last pruned record after retention removed older segments.
    pub anchor: String,
    pub head: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Walk every segment: seq continuity, prev links, record hashes, seals and `head.json`.
/// `anchor`: a hash previously exported elsewhere (SIEM) that must appear in the chain.
pub fn verify(data: &Path, anchor: Option<&str>) -> Verify {
    let segs = segments(data);
    let mut r = Verify { ok: true, segments: segs.len(), ..Default::default() };
    let mut prev: Option<String> = None;
    let mut expect_seq: Option<u64> = None;
    let mut anchor_seen = anchor.is_none();
    let fail = |r: &mut Verify, e: String| {
        r.ok = false;
        r.error = Some(e);
    };
    for p in &segs {
        let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        if p.extension().is_some_and(|x| x == "jsonl") && p.parent() == Some(&archive_dir(data)) {
            let seal: Option<Value> = fs::read_to_string(p.with_extension("seal")).ok().and_then(|s| serde_json::from_str(&s).ok());
            match seal {
                None => {
                    fail(&mut r, format!("{name}: seal missing"));
                    return r;
                }
                Some(s) => {
                    let bytes = fs::read(p).unwrap_or_default();
                    if s["sha256"].as_str() != Some(sha256_hex(&bytes).as_str()) {
                        fail(&mut r, format!("{name}: contents differ from the seal"));
                        return r;
                    }
                }
            }
        }
        let text = fs::read_to_string(p).unwrap_or_default();
        for (i, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(mut rec) = serde_json::from_str::<Value>(line) else {
                fail(&mut r, format!("{name}:{}: not JSON", i + 1));
                return r;
            };
            let seq = rec["seq"].as_u64().unwrap_or(0);
            let given = rec["hash"].as_str().unwrap_or("").to_string();
            let p_link = rec["prev"].as_str().unwrap_or("").to_string();
            if let Some(e) = expect_seq {
                if seq != e {
                    fail(&mut r, format!("{name}:{}: seq {seq}, expected {e} (a record was removed or reordered)", i + 1));
                    return r;
                }
            } else {
                r.first_seq = seq;
                r.anchor = p_link.clone();
            }
            if let Some(pv) = &prev {
                if *pv != p_link {
                    fail(&mut r, format!("{name}:{}: seq {seq} does not link to the previous record", i + 1));
                    return r;
                }
            }
            if let Some(o) = rec.as_object_mut() {
                o.remove("hash");
            }
            if chain_hash(&p_link, &rec) != given {
                fail(&mut r, format!("{name}:{}: seq {seq} was modified (hash mismatch)", i + 1));
                return r;
            }
            if anchor == Some(given.as_str()) {
                anchor_seen = true;
            }
            prev = Some(given);
            expect_seq = Some(seq + 1);
            r.events += 1;
            r.last_seq = seq;
        }
    }
    r.head = prev.clone().unwrap_or_default();
    let h = head(data);
    if r.events > 0 && (h.seq != r.last_seq || h.hash != r.head) {
        let msg = format!("head.json says seq {} but the chain ends at {} (records were truncated)", h.seq, r.last_seq);
        fail(&mut r, msg);
        return r;
    }
    if !anchor_seen {
        fail(&mut r, format!("anchor {} is not in the chain", anchor.unwrap_or("")));
    }
    r
}

/// Retention (ent-077): delete archived segments whose newest record is older than
/// `cutoff_ms`. Never touches the live segment, and does nothing while a legal hold covers
/// audit data. The deletion itself is recorded (with the hash it leaves as the new anchor).
pub fn prune(data: &Path, cutoff_ms: u64, held: bool) -> Result<usize, String> {
    if held {
        return Ok(0);
    }
    let mut removed = vec![];
    {
        let _l = lock(data)?;
        let segs: Vec<PathBuf> = segments(data).into_iter().filter(|p| p.parent() == Some(&archive_dir(data))).collect();
        // Only a prefix may go: the chain must stay contiguous.
        for p in segs {
            let seal: Value = fs::read_to_string(p.with_extension("seal")).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null);
            if seal["last_ts"].as_u64().is_none_or(|t| t >= cutoff_ms) {
                break;
            }
            let _ = crate::os::set_mode(&p, 0o600);
            fs::remove_file(&p).map_err(|e| format!("audit: {e}"))?;
            let _ = fs::remove_file(p.with_extension("seal"));
            removed.push(json!({"segment": p.file_name().map(|n| n.to_string_lossy().to_string()), "last_seq": seal["last_seq"], "last_hash": seal["last_hash"]}));
        }
    }
    let n = removed.len();
    if n > 0 {
        emit(data, Event::new("retention.audit_pruned", Actor::system(), "audit", "ok").detail(json!({"segments": removed, "cutoff_ms": cutoff_ms})))?;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let base = std::env::var_os("TMPDIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        let d = base.join(format!("seagent-audit-{}-{}", std::process::id(), now_ms() ^ (rand_u64() & 0xffff_ffff)));
        fs::create_dir_all(&d).unwrap();
        d
    }
    fn rand_u64() -> u64 {
        let mut b = [0u8; 8];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b).unwrap();
        u64::from_le_bytes(b)
    }
    struct G(PathBuf);
    impl Drop for G {
        fn drop(&mut self) {
            for p in segments(&self.0) {
                let _ = crate::os::set_mode(&p, 0o600);
            }
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn chain_appends_verifies_and_detects_edits() {
        let g = G(tmp());
        let d = &g.0;
        for i in 0..5 {
            emit(d, Event::new("app.request", Actor::new("token", "bot").with_role("user"), &format!("m{i}"), "allow")).unwrap();
        }
        let v = verify(d, None);
        assert!(v.ok, "{v:?}");
        assert_eq!((v.events, v.first_seq, v.last_seq), (5, 1, 5));
        let anchor = all(d)[2]["hash"].as_str().unwrap().to_string();
        assert!(verify(d, Some(&anchor)).ok);
        assert!(!verify(d, Some("deadbeef")).ok);
        // Edit one field of record 3.
        let p = live(d);
        let text = fs::read_to_string(&p).unwrap().replace("\"target\":\"m2\"", "\"target\":\"mX\"");
        fs::write(&p, text).unwrap();
        let v = verify(d, None);
        assert!(!v.ok && v.error.as_deref().unwrap().contains("seq 3"), "{v:?}");
    }

    #[test]
    fn deleting_a_line_or_truncating_is_detected() {
        let g = G(tmp());
        let d = &g.0;
        for i in 0..4 {
            emit(d, Event::new("x", Actor::system(), &i.to_string(), "ok")).unwrap();
        }
        let p = live(d);
        let lines: Vec<String> = fs::read_to_string(&p).unwrap().lines().map(String::from).collect();
        fs::write(&p, format!("{}\n{}\n{}\n", lines[0], lines[2], lines[3])).unwrap();
        assert!(verify(d, None).error.unwrap().contains("expected 2"));
        fs::write(&p, format!("{}\n{}\n", lines[0], lines[1])).unwrap();
        assert!(verify(d, None).error.unwrap().contains("truncated"));
    }

    #[test]
    fn rotation_seals_segments_and_the_chain_spans_them() {
        let g = G(tmp());
        let d = &g.0;
        for i in 0..3 {
            emit(d, Event::new("x", Actor::system(), &i.to_string(), "ok")).unwrap();
        }
        let seg = rotate(d).unwrap().unwrap();
        assert!(seg.with_extension("seal").exists());
        for i in 3..6 {
            emit(d, Event::new("x", Actor::system(), &i.to_string(), "ok")).unwrap();
        }
        let v = verify(d, None);
        assert!(v.ok && v.events == 6 && v.segments == 2, "{v:?}");
        assert_eq!(all(d)[3]["prev"], all(d)[2]["hash"]);
        // Tamper with the archived segment.
        crate::os::set_mode(&seg, 0o600).unwrap();
        let t = fs::read_to_string(&seg).unwrap().replace("\"target\":\"1\"", "\"target\":\"9\"");
        fs::write(&seg, t).unwrap();
        assert!(verify(d, None).error.unwrap().contains("seal"));
    }

    #[test]
    fn prune_removes_old_segments_keeps_the_chain_verifiable_and_respects_holds() {
        let g = G(tmp());
        let d = &g.0;
        emit(d, Event::new("x", Actor::system(), "a", "ok")).unwrap();
        rotate(d).unwrap();
        emit(d, Event::new("x", Actor::system(), "b", "ok")).unwrap();
        rotate(d).unwrap();
        emit(d, Event::new("x", Actor::system(), "c", "ok")).unwrap();
        assert_eq!(prune(d, now_ms() + 1000, true).unwrap(), 0, "a legal hold keeps everything");
        assert_eq!(prune(d, now_ms() + 1000, false).unwrap(), 2);
        let v = verify(d, None);
        assert!(v.ok && v.first_seq == 3 && !v.anchor.is_empty(), "{v:?}");
        assert!(query(d, &Query { kind: Some("retention".into()), ..Default::default() }).len() == 1);
    }

    #[test]
    fn records_are_masked_capped_and_filterable() {
        let g = G(tmp());
        let d = &g.0;
        emit(d, Event::new("auth.login", Actor::new("sso", "alice@example.com").with_ip("10.0.0.5"), &"y ".repeat(2000), "ok").detail(json!({"note": "call 555-123-4567"}))).unwrap();
        emit(d, Event::new("approval.answer", Actor::channel("slack", "U1"), "gate-1", "once").session("s1")).unwrap();
        let all = all(d);
        assert!(all[0]["target"].as_str().unwrap().chars().count() <= MAX_FIELD);
        assert_eq!(all[0]["actor"]["name"], "alice@example.com", "who did it is never masked");
        assert!(!all[0]["detail"]["note"].as_str().unwrap().contains("555-123-4567"));
        let q = Query { kind: Some("approval".into()), session: Some("s1".into()), ..Default::default() };
        assert_eq!(query(d, &q).len(), 1);
        assert_eq!(query(d, &Query { actor: Some("channel:slack:U1".into()), ..Default::default() }).len(), 1);
        assert_eq!(Actor::parse_label("sso:bob"), Actor::new("sso", "bob"));
    }

    /// Regression: session / approval ids with long digit runs used to come out as
    /// `[card]-fac35b` because the digits happened to pass the Luhn check.
    #[test]
    fn ids_are_never_masked() {
        let g = G(tmp());
        let d = &g.0;
        // "20261105091239" passes Luhn: exactly the shape that was being masked.
        assert!(crate::pii::mask("20261105-091239").contains("[card]"), "precondition: the digit run alone is card-like");
        let sid = "20261105-091239-fac35b";
        let aid = "20261105-091239-3a1c9e";
        emit(d, Event::new("approval.answer", Actor::new("sso", "ann"), aid, "once").session(sid).detail(json!({"session": sid, "id": aid, "note": "card 4111 1111 1111 1111"}))).unwrap();
        emit(d, Event::new("x", Actor::system(), "4111-1111-1111-1111", "ok")).unwrap();
        let all = all(d);
        assert_eq!(all[0]["target"], aid);
        assert_eq!(all[0]["session"], sid);
        assert_eq!(all[0]["detail"]["session"], sid);
        assert_eq!(all[0]["detail"]["id"], aid);
        assert!(all[0]["detail"]["note"].as_str().unwrap().contains("[card]"), "free text is still masked");
        assert_eq!(all[1]["target"], "[card]", "a bare card number is not an id");
        assert_eq!(query(d, &Query { session: Some(sid.into()), ..Default::default() }).len(), 1);
        assert!(verify(d, None).ok);
    }

    #[test]
    fn records_carry_their_tenant_and_queries_stay_inside_it() {
        let g = G(tmp());
        let d = &g.0;
        emit(d, Event::new("x", Actor::system(), "legacy", "ok")).unwrap();
        emit(d, Event::new("x", Actor::system(), "eng", "ok").tenant("acme", "eng")).unwrap();
        emit(d, Event::new("x", Actor::system(), "ops", "ok").tenant("acme", "ops")).unwrap();
        emit(d, Event::new("x", Actor::system(), "acme-wide", "ok").tenant("acme", "")).unwrap();
        assert!(all(d)[0].get("org").is_none(), "untagged records keep their shape");
        let targets = |q: Query| query(d, &q).iter().map(|r| r["target"].as_str().unwrap().to_string()).collect::<Vec<_>>();
        assert_eq!(targets(Query { org: Some("default".into()), ..Default::default() }), vec!["legacy"]);
        assert_eq!(targets(Query { org: Some("acme".into()), ..Default::default() }), vec!["eng", "ops", "acme-wide"]);
        assert_eq!(targets(Query { org: Some("acme".into()), team: Some("eng".into()), ..Default::default() }), vec!["eng", "acme-wide"]);
        assert!(verify(d, None).ok);
    }
}
