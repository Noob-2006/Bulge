//! Enterprise governance that the kernel enforces itself, so every entry point (CLI, app
//! server, channels, cron) is covered the same way:
//!
//! * `[audit]` — the unified audit stream's rotation and SIEM export (ent-072…076);
//! * `[compliance.retention]` + legal holds — one retention policy for sessions, audit,
//!   broker log, daemon logs and exports (ent-077);
//! * session ownership → per-user / per-team usage (ent-070) and `[quotas]` (ent-071);
//! * `[alerts]` — spend/quota alerts pushed to a channel or webhook (ent-094);
//! * `[compliance] data_class` + `classes` — which models a data class may use (ent-093).

use crate::event::{Event, EventKind};
use crate::kernel::Runtime;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ───────────────────────── config ─────────────────────────

/// `[audit]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    /// Rotate (seal + archive) the live segment past this size.
    pub rotate_mb: u64,
    /// Also record read-only app-server requests that do not expose content (`*.list` …).
    /// Content reads (`session.history`, live views) and every write are always recorded.
    pub log_reads: bool,
    /// Seconds between SIEM export pumps in the daemon.
    pub export_secs: u64,
    pub export: ark_security::audit_export::ExportConfig,
    /// Ed25519 seed (base64, 32 bytes) that signs rotated segment seals: a file path, a
    /// `{{secret:NAME}}` reference, or empty (seals stay unsigned). See `ark audit seal-key`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub seal_key: String,
    /// The matching public key (`ed25519:<base64>`) `ark audit verify` checks seals against;
    /// empty = derived from `seal_key` when that is readable.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub seal_pubkey: String,
    /// RFC 3161 Time-Stamping Authority URL; each signed seal is also timestamped there.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tsa_url: String,
    /// `ark audit verify` fails while any archived seal is unsigned.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub require_signed_seals: bool,
}

impl AuditConfig {
    /// The seal-signing seed, resolved (`subst` resolves `{{secret:…}}`), if configured.
    pub fn seal_seed(&self, subst: &dyn Fn(&str) -> String) -> Option<String> {
        let k = self.seal_key.trim();
        if k.is_empty() {
            return None;
        }
        let v = if k.contains("{{secret:") { subst(k) } else { std::fs::read_to_string(ark_core::tool::expand_home(k)).ok()? };
        let v = v.trim().to_string();
        (!v.is_empty() && !v.contains("{{secret:")).then_some(v)
    }

    /// The public key seals are verified against: `seal_pubkey`, else derived from the seed.
    pub fn seal_public(&self, subst: &dyn Fn(&str) -> String) -> Option<String> {
        if !self.seal_pubkey.trim().is_empty() {
            return Some(self.seal_pubkey.trim().to_string());
        }
        self.seal_seed(subst).and_then(|s| ark_security::signing::public_of(&s).ok())
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        AuditConfig { rotate_mb: 64, log_reads: false, export_secs: 10, export: Default::default(), seal_key: String::new(), seal_pubkey: String::new(), tsa_url: String::new(), require_signed_seals: false }
    }
}

/// `[compliance.retention]` — days to keep each class of data; unset = keep.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RetentionConfig {
    /// Same as the older `compliance.retention_days` (which still works).
    pub sessions_days: Option<u32>,
    /// Archived (sealed) audit segments.
    pub audit_days: Option<u32>,
    /// `<data>/audit/broker.jsonl` lines.
    pub broker_days: Option<u32>,
    /// `<data>/logs/*` files.
    pub logs_days: Option<u32>,
    /// eDiscovery bundles under `<data>/exports/`.
    pub exports_days: Option<u32>,
}

/// `[quotas]` — spend per user / team per period (ent-071). 0 / absent = no quota.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct QuotaConfig {
    /// `month` (calendar month, UTC) or `day`.
    pub period: String,
    /// Default per-user quota in USD.
    pub user_usd: f64,
    /// Per-user overrides, by registry name / id or principal label.
    pub users: BTreeMap<String, f64>,
    /// Per-team quotas (sum of the team's members).
    pub teams: BTreeMap<String, f64>,
    /// Warn (and alert) from this fraction on.
    pub warn_at: f64,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        QuotaConfig { period: "month".into(), user_usd: 0.0, users: BTreeMap::new(), teams: BTreeMap::new(), warn_at: 0.8 }
    }
}

impl QuotaConfig {
    pub fn enabled(&self) -> bool {
        self.user_usd > 0.0 || self.users.values().any(|v| *v > 0.0) || self.teams.values().any(|v| *v > 0.0)
    }
}

/// `[alerts]` — where spend / quota / cap alerts go (ent-094).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AlertsConfig {
    /// Delivery targets (`slack:C0123`, `telegram:42`, `https://hooks.example/x`).
    pub targets: Vec<String>,
    /// Signing secret for webhook targets (`{{secret:NAME}}`).
    pub secret: Option<String>,
    /// The Net-SNMP `snmptrap` binary for `snmp://community@host[:port]` targets (SNMPv2c
    /// traps to a legacy NMS). Default: `snmptrap` on PATH.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snmptrap: Option<String>,
}

/// Enterprise OID ark's traps use (32473 is the IANA example enterprise number, RFC 5612;
/// map it in the NMS, or load the varbinds by OID).
pub const SNMP_TRAP_OID: &str = "1.3.6.1.4.1.32473.1.0.1";

/// Send one SNMPv2c trap through `snmptrap`: `target` is `snmp://community@host[:port]`.
/// Varbinds: `.1.1` the alert key, `.1.2` the text (both strings).
pub fn snmp_trap(bin: &str, target: &str, key: &str, text: &str) -> Result<String, String> {
    let rest = target.strip_prefix("snmp://").ok_or("not an snmp:// target")?;
    let (community, host) = rest.rsplit_once('@').unwrap_or(("public", rest));
    let host = host.trim_end_matches('/');
    if host.is_empty() || host.starts_with('-') || community.starts_with('-') {
        return Err(format!("{target}: bad host or community"));
    }
    let host = if host.contains(':') { host.to_string() } else { format!("{host}:162") };
    let mut cmd = std::process::Command::new(bin);
    cmd.args(["-v", "2c", "-c", community, &host, "", SNMP_TRAP_OID]).args([format!("{SNMP_TRAP_OID}.1.1"), "s".into(), key.into(), format!("{SNMP_TRAP_OID}.1.2"), "s".into(), text.chars().take(255).collect()]);
    let mut tries = 0;
    let out = loop {
        match cmd.output() {
            // A just-written binary can be briefly busy (another thread's fork); retry.
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && tries < 20 => {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            r => break r.map_err(|e| format!("snmp: cannot run `{bin}`: {e} (install net-snmp-utils / snmp, or set [alerts] snmptrap)"))?,
        }
    };
    if out.status.success() {
        Ok(format!("snmp trap to {host}"))
    } else {
        Err(format!("snmp: {}", String::from_utf8_lossy(&out.stderr).trim().chars().take(300).collect::<String>()))
    }
}

// ───────────────────────── legal holds ─────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hold {
    pub id: String,
    /// `all`, `audit`, `session:<id>` or `user:<name>`.
    pub scope: String,
    pub reason: String,
    pub by: String,
    pub created_ms: u64,
}

fn holds_path(data: &Path) -> PathBuf {
    data.join("compliance").join("holds.json")
}

pub fn holds(data: &Path) -> Vec<Hold> {
    std::fs::read_to_string(holds_path(data)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn save_holds(data: &Path, h: &[Hold]) -> Result<(), String> {
    let p = holds_path(data);
    std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
    crate::util::atomic_write(&p, serde_json::to_string_pretty(h).unwrap_or_default().as_bytes()).map_err(|e| e.to_string())
}

pub fn hold_add(data: &Path, scope: &str, reason: &str, by: &str) -> Result<Hold, String> {
    let scope = scope.trim();
    let ok = scope == "all" || scope == "audit" || scope.strip_prefix("session:").is_some_and(|s| !s.is_empty()) || scope.strip_prefix("user:").is_some_and(|s| !s.is_empty());
    if !ok {
        return Err(format!("hold scope `{scope}`: use all, audit, session:<id> or user:<name>"));
    }
    if reason.trim().is_empty() {
        return Err("a legal hold needs a reason (case or matter number)".into());
    }
    let h = Hold { id: format!("hold-{}", crate::util::random_hex(6)), scope: scope.into(), reason: reason.trim().into(), by: by.into(), created_ms: crate::event::now_ms() };
    let mut all = holds(data);
    all.push(h.clone());
    save_holds(data, &all)?;
    ark_security::audit::record(data, ark_security::audit::Event::new("retention.hold_added", ark_security::audit::Actor::parse_label(by), &h.scope, "ok").detail(json!({"hold": h.id, "reason": h.reason})));
    Ok(h)
}

pub fn hold_release(data: &Path, id: &str, by: &str) -> Result<(), String> {
    let mut all = holds(data);
    let n = all.len();
    all.retain(|h| h.id != id);
    if all.len() == n {
        return Err(format!("no hold `{id}`"));
    }
    save_holds(data, &all)?;
    ark_security::audit::record(data, ark_security::audit::Event::new("retention.hold_released", ark_security::audit::Actor::parse_label(by), id, "ok"));
    Ok(())
}

fn held(hs: &[Hold], scope: &str) -> bool {
    hs.iter().any(|h| h.scope == "all" || h.scope == scope)
}

// ───────────────────────── ownership & usage ─────────────────────────

fn owners_path(data: &Path) -> PathBuf {
    data.join("usage").join("owners.json")
}

fn owners(data: &Path) -> BTreeMap<String, String> {
    std::fs::read_to_string(owners_path(data)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

/// Record who started / drives a session (`kind:name` principal label). First writer wins:
/// a session belongs to whoever created it.
pub fn note_owner(data: &Path, session: &str, principal: &str) {
    if session.is_empty() || principal.is_empty() {
        return;
    }
    let mut o = owners(data);
    if o.contains_key(session) {
        return;
    }
    o.insert(session.into(), principal.into());
    let p = owners_path(data);
    let _ = std::fs::create_dir_all(p.parent().unwrap());
    let _ = crate::util::atomic_write(&p, serde_json::to_string(&o).unwrap_or_default().as_bytes());
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Owner {
    /// Registry name when the principal maps to a registered user, else the principal label.
    pub user: String,
    pub team: String,
}

fn registry_owner(paths: &crate::config::Paths, label: &str) -> Owner {
    let (kind, name) = label.split_once(':').unwrap_or(("local", label));
    let u = match kind {
        "channel" => name.split_once(':').and_then(|(c, s)| crate::agents::find_user(paths, c, s)),
        "sso" | "saml" | "basic" | "plugin" => crate::agents::find_login(paths, name, name),
        _ => crate::agents::users(paths).into_iter().find(|u| u.name == name || u.id == name || u.identities.iter().any(|i| i.channel == kind && i.sender == name)),
    };
    match u {
        Some(u) => Owner { user: u.name, team: u.team },
        None => Owner { user: label.into(), team: String::new() },
    }
}

/// Who a session is charged to: the recorded owner, else its channel sender, else the parent
/// session's owner (sub-agents), else the local OS user.
pub fn owner_of(rt: &Runtime, session: &str) -> Owner {
    owner_in(&rt.paths, &rt.store, session)
}

/// [`owner_of`] without a runtime (the CLI opens the store itself).
pub fn owner_in(paths: &crate::config::Paths, store: &crate::store::Store, session: &str) -> Owner {
    registry_owner(paths, &owner_label_in(paths, store, session))
}

/// The principal label (`kind:name`) a session belongs to, resolved like [`owner_in`] but
/// without mapping it onto the user registry (dual control compares principals).
pub fn owner_label_in(paths: &crate::config::Paths, store: &crate::store::Store, session: &str) -> String {
    let o = owners(&paths.data);
    let mut cur = session.to_string();
    for _ in 0..8 {
        if let Some(l) = o.get(&cur) {
            return l.clone();
        }
        let evs = store.read(&cur).unwrap_or_default();
        if let Some(src) = evs.iter().find_map(|e| match &e.kind {
            EventKind::Inbox { source, .. } if source.starts_with("channel:") => Some(source.clone()),
            _ => None,
        }) {
            return src;
        }
        match store.list().into_iter().find(|s| s.id == cur).and_then(|s| s.parent) {
            Some(p) => cur = p,
            None => break,
        }
    }
    ark_security::audit::Actor::local().label()
}

/// The registered user (`ark users`) a principal label belongs to, if any: an SSO login, a
/// linked chat identity or a registry name all resolve to the same person.
pub fn registered_person(data: &Path, label: &str) -> Option<crate::agents::User> {
    let paths = crate::config::Paths { data: data.to_path_buf(), config_dir: PathBuf::new(), runtime: PathBuf::new(), ..Default::default() };
    let (kind, name) = label.split_once(':').unwrap_or(("local", label));
    match kind {
        "channel" => name.split_once(':').and_then(|(c, s)| crate::agents::find_user(&paths, c, s)),
        "sso" | "saml" | "basic" | "plugin" | "header" => crate::agents::find_login(&paths, name, name).or_else(|| crate::agents::users(&paths).into_iter().find(|u| u.name == name)),
        _ => crate::agents::users(&paths).into_iter().find(|u| u.name == name || u.id == name || u.identities.iter().any(|i| i.channel == kind && i.sender == name)),
    }
}

/// Are two principal labels the same person (equal, or one registered user)?
pub fn same_person(data: &Path, a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    match (registered_person(data, a), registered_person(data, b)) {
        (Some(x), Some(y)) => x.id == y.id,
        _ => false,
    }
}

/// The sessions among `sessions` that belong to the registered user `user` (ent-049: whose
/// running turns stop when the user is deactivated).
pub fn sessions_of_user(paths: &crate::config::Paths, store: &crate::store::Store, sessions: &[String], user: &crate::agents::User) -> Vec<String> {
    sessions.iter().filter(|s| owner_in(paths, store, s).user == user.name).cloned().collect()
}

/// Start of the current quota period (UTC), Unix ms.
pub fn period_start(period: &str, now_ms: u64) -> u64 {
    let day = now_ms / 86_400_000 * 86_400_000;
    if period == "day" {
        return day;
    }
    // First of the month: walk back by day-of-month.
    let date = ark_security::audit_export::rfc3339(now_ms);
    let dom: u64 = date[8..10].parse().unwrap_or(1);
    day - (dom - 1) * 86_400_000
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct UsageRow {
    pub key: String,
    pub usd: f64,
    pub tokens: u64,
    pub sessions: usize,
}

fn session_usage(rt: &Runtime, evs: &[Event], model_hint: &str, since: u64) -> (f64, u64) {
    let model = if model_hint.is_empty() { crate::limits::session_model(evs) } else { model_hint.to_string() };
    let mut usd = 0.0;
    let mut tok = 0;
    for e in evs.iter().filter(|e| e.ts >= since) {
        if let Some(c) = crate::limits::event_cost(&rt.cfg, &model, &e.kind) {
            usd += c;
        }
        if let EventKind::Message { usage: Some(u), .. } | EventKind::AuxUsage { usage: u, .. } = &e.kind {
            tok += u.input_tokens + u.output_tokens + u.cache_read_tokens + u.cache_write_tokens;
        }
    }
    (usd, tok)
}

/// Spend grouped by `user` or `team` since `since_ms` (ent-070).
pub fn usage_by(rt: &Runtime, by: &str, since_ms: u64) -> Vec<UsageRow> {
    let mut m: BTreeMap<String, UsageRow> = BTreeMap::new();
    for info in rt.store.list() {
        let evs = rt.store.read(&info.id).unwrap_or_default();
        let (usd, tokens) = session_usage(rt, &evs, &info.model, since_ms);
        if usd == 0.0 && tokens == 0 {
            continue;
        }
        let o = owner_of(rt, &info.id);
        let key = if by == "team" { if o.team.is_empty() { "(no team)".to_string() } else { o.team } } else { o.user };
        let r = m.entry(key.clone()).or_insert_with(|| UsageRow { key, ..Default::default() });
        r.usd += usd;
        r.tokens += tokens;
        r.sessions += 1;
    }
    let mut v: Vec<UsageRow> = m.into_values().collect();
    v.sort_by(|a, b| b.usd.partial_cmp(&a.usd).unwrap_or(std::cmp::Ordering::Equal));
    v
}

#[derive(Debug, Clone, PartialEq)]
pub enum QuotaVerdict {
    Ok,
    Warn(String),
    Over(String),
}

/// Is the owner of `session` (or their team) over quota this period?
pub fn quota_check(rt: &Runtime, session: &str) -> QuotaVerdict {
    let q = &rt.cfg.quotas;
    if !q.enabled() {
        return QuotaVerdict::Ok;
    }
    let since = period_start(&q.period, crate::event::now_ms());
    let o = owner_of(rt, session);
    let rows = usage_by(rt, "user", since);
    let user_used = rows.iter().find(|r| r.key == o.user).map(|r| r.usd).unwrap_or(0.0);
    let user_cap = q.users.get(&o.user).copied().unwrap_or(q.user_usd);
    let mut worst: Option<(f64, String)> = None;
    if user_cap > 0.0 {
        worst = Some((user_used / user_cap, format!("user `{}` spent ${user_used:.2} of ${user_cap:.2} this {}", o.user, q.period)));
    }
    if let Some(cap) = q.teams.get(&o.team).copied().filter(|c| *c > 0.0) {
        let t = usage_by(rt, "team", since).into_iter().find(|r| r.key == o.team).map(|r| r.usd).unwrap_or(0.0);
        let r = t / cap;
        if worst.as_ref().is_none_or(|(w, _)| r > *w) {
            worst = Some((r, format!("team `{}` spent ${t:.2} of ${cap:.2} this {}", o.team, q.period)));
        }
    }
    match worst {
        Some((r, t)) if r >= 1.0 => QuotaVerdict::Over(format!("quota reached: {t}")),
        Some((r, t)) if r >= q.warn_at => QuotaVerdict::Warn(format!("approaching quota ({:.0} %): {t}", r * 100.0)),
        _ => QuotaVerdict::Ok,
    }
}

// ───────────────────────── alerts ─────────────────────────

fn alerts_state(data: &Path) -> PathBuf {
    data.join("compliance").join("alerts-sent.json")
}

/// Push an alert to every `[alerts] targets` entry once per `key` (e.g. `quota:alice:2026-11:warn`).
/// Always recorded in the audit stream. Returns the delivery receipts (empty when deduplicated).
pub fn alert(rt: &Runtime, key: &str, text: &str) -> Vec<String> {
    let data = &rt.paths.data;
    let mut sent: BTreeMap<String, u64> = std::fs::read_to_string(alerts_state(data)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    if sent.contains_key(key) {
        return vec![];
    }
    sent.insert(key.into(), crate::event::now_ms());
    if sent.len() > 2000 {
        let cut = sent.values().copied().min().unwrap_or(0);
        sent.retain(|_, v| *v > cut);
    }
    let _ = std::fs::create_dir_all(data.join("compliance"));
    let _ = crate::util::atomic_write(&alerts_state(data), serde_json::to_string(&sent).unwrap_or_default().as_bytes());
    let mut receipts = vec![];
    for t in &rt.cfg.alerts.targets {
        if t.starts_with("snmp://") {
            let bin = rt.cfg.alerts.snmptrap.as_deref().unwrap_or("snmptrap");
            receipts.push(snmp_trap(bin, t, key, text).unwrap_or_else(|e| e));
            continue;
        }
        let target = match crate::outbound::Target::parse(t) {
            Ok(crate::outbound::Target::Webhook { url, .. }) => crate::outbound::Target::Webhook { url, secret: rt.cfg.alerts.secret.clone() },
            Ok(t) => t,
            Err(e) => {
                receipts.push(format!("{t}: {e}"));
                continue;
            }
        };
        let payload = crate::outbound::Payload::new("budget.alert", format!("⚠ ark: {text}")).with_data(json!({"key": key}));
        receipts.push(match crate::outbound::deliver(&target, &payload) {
            Ok(r) => r,
            Err(e) => format!("{t}: {e}"),
        });
    }
    ark_security::audit::record(data, ark_security::audit::Event::new("budget.alert", ark_security::audit::Actor::system(), key, "ok").detail(json!({"text": text, "delivered": receipts})));
    receipts
}

/// Turn a cap / quota verdict into an alert key and fire it (deduplicated per period).
pub fn alert_on(rt: &Runtime, scope: &str, level: &str, text: &str) {
    let period = ark_security::audit_export::rfc3339(crate::event::now_ms());
    let tag = if rt.cfg.quotas.period == "day" { &period[..10] } else { &period[..7] };
    alert(rt, &format!("{scope}:{tag}:{level}"), text);
}

// ───────────────────────── data classification ─────────────────────────

fn pattern_matches(p: &str, model: &str) -> bool {
    p == "*" || p == model || p.strip_suffix("/*").is_some_and(|pre| model.split('/').next() == Some(pre))
}

/// `Err(reason)` when the configured data class forbids `model` (ent-093).
pub fn class_allows(c: &crate::config::ComplianceConfig, model: &str) -> Result<(), String> {
    let class = c.data_class.trim();
    if class.is_empty() {
        return Ok(());
    }
    let Some(allowed) = c.classes.get(class) else {
        return Err(format!("compliance.data_class `{class}` has no entry in [compliance.classes] (fail closed)"));
    };
    if allowed.iter().any(|p| pattern_matches(p, model)) {
        Ok(())
    } else {
        Err(format!("model `{model}` is not approved for `{class}` data (compliance.classes.{class})"))
    }
}

// ───────────────────────── retention ─────────────────────────

const DAY: u64 = 86_400_000;

/// One retention pass over every data class (ent-077). Returns `(class, removed)` pairs.
pub fn enforce_retention(rt: &Runtime) -> Vec<(&'static str, usize)> {
    let data = &rt.paths.data;
    let c = &rt.cfg.compliance;
    let hs = holds(data);
    let now = crate::event::now_ms();
    let mut out = vec![];
    if held(&hs, "all") {
        return out;
    }
    if let Some(days) = c.retention.sessions_days.or(c.retention_days).filter(|d| *d > 0) {
        let cutoff = now.saturating_sub(days as u64 * DAY);
        let mut n = 0;
        for s in rt.store.list().into_iter().filter(|s| s.updated_ms < cutoff && !rt.is_running(&s.id)) {
            if held(&hs, &format!("session:{}", s.id)) || hs.iter().any(|h| h.scope.strip_prefix("user:").is_some_and(|u| owner_of(rt, &s.id).user == u)) {
                continue;
            }
            rt.end_session(&s.id, "retention");
            if rt.store.remove(&s.id).is_ok() {
                n += 1;
            }
        }
        out.push(("sessions", n));
    }
    if let Some(days) = c.retention.audit_days.filter(|d| *d > 0) {
        let n = ark_security::audit::prune(data, now.saturating_sub(days as u64 * DAY), held(&hs, "audit")).unwrap_or(0);
        out.push(("audit", n));
    }
    if let Some(days) = c.retention.broker_days.filter(|d| *d > 0) {
        out.push(("broker", prune_jsonl(&data.join("audit").join("broker.jsonl"), "ts_ms", now.saturating_sub(days as u64 * DAY))));
    }
    if let Some(days) = c.retention.logs_days.filter(|d| *d > 0) {
        out.push(("logs", prune_files(&data.join("logs"), now.saturating_sub(days as u64 * DAY))));
    }
    if let Some(days) = c.retention.exports_days.filter(|d| *d > 0) {
        out.push(("exports", prune_files(&data.join("exports"), now.saturating_sub(days as u64 * DAY))));
    }
    let total: usize = out.iter().map(|(_, n)| n).sum();
    if total > 0 {
        let detail: Value = out.iter().map(|(k, n)| (k.to_string(), json!(n))).collect::<serde_json::Map<_, _>>().into();
        ark_security::audit::record(data, ark_security::audit::Event::new("retention.run", ark_security::audit::Actor::system(), "retention", "ok").detail(detail));
    }
    out
}

fn prune_jsonl(p: &Path, ts_key: &str, cutoff: u64) -> usize {
    let Ok(text) = std::fs::read_to_string(p) else { return 0 };
    let mut keep = String::new();
    let mut n = 0;
    for l in text.lines() {
        let ts = serde_json::from_str::<Value>(l).ok().and_then(|v| v[ts_key].as_u64()).unwrap_or(u64::MAX);
        if ts < cutoff {
            n += 1;
        } else {
            keep.push_str(l);
            keep.push('\n');
        }
    }
    if n > 0 {
        let _ = crate::util::atomic_write(p, keep.as_bytes());
    }
    n
}

fn prune_files(dir: &Path, cutoff: u64) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else { return 0 };
    let mut n = 0;
    for e in rd.flatten() {
        let old = e.metadata().ok().and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).is_some_and(|d| (d.as_millis() as u64) < cutoff);
        if !old {
            continue;
        }
        let p = e.path();
        let ok = if p.is_dir() { std::fs::remove_dir_all(&p).is_ok() } else { std::fs::remove_file(&p).is_ok() };
        if ok {
            n += 1;
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn period_start_is_day_or_first_of_month() {
        let t = 1_709_210_096_789; // 2024-02-29T12:34:56Z
        assert_eq!(ark_security::audit_export::rfc3339(period_start("day", t)), "2024-02-29T00:00:00.000Z");
        assert_eq!(ark_security::audit_export::rfc3339(period_start("month", t)), "2024-02-01T00:00:00.000Z");
    }

    #[test]
    fn data_class_limits_models() {
        let mut c = crate::config::ComplianceConfig::default();
        assert!(class_allows(&c, "x/y").is_ok());
        c.data_class = "secret".into();
        assert!(class_allows(&c, "anthropic/m").unwrap_err().contains("fail closed"));
        c.classes.insert("secret".into(), vec!["local/*".into()]);
        c.classes.insert("internal".into(), vec!["*".into()]);
        assert!(class_allows(&c, "local/llama").is_ok());
        assert!(class_allows(&c, "anthropic/m").unwrap_err().contains("not approved for `secret`"));
        c.data_class = "internal".into();
        assert!(class_allows(&c, "anthropic/m").is_ok());
    }

    #[test]
    fn holds_validate_scope_and_reason() {
        let d = ark_core::tmp::TempDir::new("ark-holds");
        assert!(hold_add(d.path(), "everything", "x", "local:a").is_err());
        assert!(hold_add(d.path(), "all", " ", "local:a").is_err());
        let h = hold_add(d.path(), "user:alice", "case 42", "local:a").unwrap();
        assert!(held(&holds(d.path()), "user:alice"));
        hold_release(d.path(), &h.id, "local:a").unwrap();
        assert!(holds(d.path()).is_empty());
        assert!(ark_security::audit::all(d.path()).iter().any(|r| r["kind"] == "retention.hold_added"));
    }

    #[test]
    fn prune_jsonl_keeps_new_lines() {
        let d = ark_core::tmp::TempDir::new("ark-prunejsonl");
        let p = d.path().join("b.jsonl");
        std::fs::write(&p, "{\"ts_ms\":1}\n{\"ts_ms\":5000}\n").unwrap();
        assert_eq!(prune_jsonl(&p, "ts_ms", 100), 1);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{\"ts_ms\":5000}\n");
    }

    struct NoModels;
    impl crate::kernel::Resolver for NoModels {
        fn provider(&self, id: &str) -> Result<std::sync::Arc<dyn ark_core::Provider>, String> {
            Err(format!("no provider {id}"))
        }
    }

    fn kernel(tmp: &ark_core::tmp::TempDir, mutate: impl FnOnce(&mut crate::config::Config)) -> crate::kernel::Kernel {
        let root = tmp.path();
        let paths = crate::config::Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run"), ..Default::default() };
        std::fs::create_dir_all(&paths.data).unwrap();
        let mut cfg = crate::config::Config::default();
        cfg.model.default = "fake/m".into();
        cfg.checkpoint.enabled = false;
        cfg.prices.insert("fake/m".into(), crate::ledger::Price { input: 1000.0, output: 1000.0, cache_read: 0.0, cache_write: 0.0 });
        mutate(&mut cfg);
        crate::kernel::new_kernel(cfg, paths, std::sync::Arc::new(NoModels), vec![], std::sync::Arc::new(crate::vault::Vault::empty()), std::sync::Arc::new(crate::approver::Policy { allow_privilege: false, allow_egress: false }))
    }

    fn spend(k: &crate::kernel::Kernel, id: &str, tokens: u64, source: Option<&str>) {
        let header = EventKind::Header { version: crate::event::LOG_VERSION, session_id: id.into(), workspace: "/w".into(), model: "fake/m".into(), parent: None, title: None };
        let mut log = k.store.create(header).unwrap();
        if let Some(src) = source {
            log.append(EventKind::Inbox { id: "i1".into(), text: "hi".into(), source: src.into(), attachments: vec![] }).unwrap();
        }
        let usage = ark_core::Usage { input_tokens: tokens, ..Default::default() };
        log.append(EventKind::Message { message: ark_core::Message::assistant("ok"), usage: Some(usage), model: Some("fake/m".into()), inbox: None }).unwrap();
    }

    #[test]
    fn usage_is_attributed_to_users_and_teams_and_quotas_stop_the_owner() {
        let tmp = ark_core::tmp::TempDir::new("ark-gov-quota");
        let k = kernel(&tmp, |c| {
            c.quotas.user_usd = 10.0;
            c.quotas.teams.insert("eng".into(), 12.0);
        });
        let ann = crate::agents::user_add(&k.paths, "ann").unwrap();
        crate::agents::user_link(&k.paths, &ann.id, "slack", "U1").unwrap();
        crate::agents::user_update(&k.paths, &ann.id, |u| {
            u.team = "eng".into();
            Ok(())
        })
        .unwrap();
        let bob = crate::agents::user_add(&k.paths, "bob").unwrap();
        crate::agents::user_link_email(&k.paths, &bob.id, "bob@corp.example").unwrap();
        crate::agents::user_update(&k.paths, &bob.id, |u| {
            u.team = "eng".into();
            Ok(())
        })
        .unwrap();
        spend(&k, "s-ann", 5_000, Some("channel:slack:U1")); // $5 via a chat
        spend(&k, "s-bob", 7_000, None); // $7 through the app server as an SSO user
        note_owner(&k.paths.data, "s-bob", "sso:bob@corp.example");
        let by_user = usage_by(&k, "user", 0);
        assert_eq!(by_user.iter().map(|r| (r.key.as_str(), (r.usd * 100.0).round() as i64)).collect::<Vec<_>>(), vec![("bob", 700), ("ann", 500)]);
        let by_team = usage_by(&k, "team", 0);
        assert_eq!(by_team.len(), 1);
        assert_eq!((by_team[0].key.as_str(), by_team[0].sessions), ("eng", 2));
        // Team cap $12 is reached by the two of them together.
        match quota_check(&k, "s-ann") {
            QuotaVerdict::Over(r) => assert!(r.contains("team `eng`"), "{r}"),
            other => panic!("{other:?}"),
        }
        // Alerts are deduplicated and audited even without a delivery host.
        alert_on(&k, "quota:ann", "over", "quota reached");
        alert_on(&k, "quota:ann", "over", "quota reached");
        let alerts = ark_security::audit::query(&k.paths.data, &ark_security::audit::Query { kind: Some("budget".into()), ..Default::default() });
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn retention_skips_held_sessions_and_users() {
        let tmp = ark_core::tmp::TempDir::new("ark-gov-ret");
        let k = kernel(&tmp, |c| c.compliance.retention.sessions_days = Some(1));
        spend(&k, "s-old", 1, None);
        spend(&k, "s-held", 1, None);
        // Age both logs by three days (rewrite the event timestamps on disk).
        let old = crate::event::now_ms() - 3 * 86_400_000;
        let re = regex::Regex::new(r#""ts":\d+"#).unwrap();
        for id in ["s-old", "s-held"] {
            for e in std::fs::read_dir(k.store.dir(id)).unwrap().flatten() {
                let t = std::fs::read_to_string(e.path()).unwrap_or_default();
                let _ = std::fs::write(e.path(), re.replace_all(&t, format!("\"ts\":{old}").as_str()).as_bytes());
            }
        }
        hold_add(&k.paths.data, "session:s-held", "matter 7", "local:t").unwrap();
        assert_eq!(enforce_retention(&k), vec![("sessions", 1)]);
        let left: Vec<String> = k.store.list().into_iter().map(|s| s.id).collect();
        assert_eq!(left, vec!["s-held".to_string()], "a held session survives");
        hold_add(&k.paths.data, "all", "freeze", "local:t").unwrap();
        assert!(enforce_retention(&k).is_empty(), "a global hold stops every deletion");
    }

    /// Legacy NMS: an `snmp://community@host` alert target sends an SNMPv2c trap through
    /// `snmptrap` (a fake binary here) with the key and text as string varbinds.
    #[test]
    fn alerts_reach_a_legacy_nms_as_snmp_traps() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = ark_core::tmp::TempDir::new("ark-gov-snmp");
        let fake = tmp.path().join("snmptrap");
        let argv = tmp.path().join("argv.txt");
        std::fs::write(&fake, format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n", argv.display())).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let bin = fake.display().to_string();
        let k = kernel(&tmp, |c| {
            c.alerts.targets = vec!["snmp://n0c-ro@nms.corp.example".into()];
            c.alerts.snmptrap = Some(bin.clone());
        });
        let mut r = alert(&k, "quota:ann:2026-11", "ann used 90% of the monthly quota");
        for _ in 0..50 {
            if argv.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(r.pop().unwrap(), "snmp trap to nms.corp.example:162");
        let a = std::fs::read_to_string(&argv).unwrap();
        assert_eq!(a, format!("-v\n2c\n-c\nn0c-ro\nnms.corp.example:162\n\n{SNMP_TRAP_OID}\n{SNMP_TRAP_OID}.1.1\ns\nquota:ann:2026-11\n{SNMP_TRAP_OID}.1.2\ns\nann used 90% of the monthly quota\n"));
        assert!(snmp_trap(&bin, "snmp://-x@h", "k", "t").is_err(), "no option injection through the target");
        assert!(snmp_trap("/nonexistent/snmptrap", "snmp://c@h", "k", "t").unwrap_err().contains("install"));
    }

    #[test]
    fn answers_record_the_approver() {
        let tmp = ark_core::tmp::TempDir::new("ark-gov-appr");
        let data = tmp.path();
        let p = std::sync::Arc::new(crate::approver::Pending::new(std::time::Duration::from_secs(5), Box::new(|_| {})));
        let req = crate::approver::ApprovalRequest { id: "a1".into(), tool_use_id: "t".into(), session: "s1".into(), tool: "bash".into(), summary: "rm".into(), input: serde_json::Value::Null, gate: crate::gate::GateKind::Exec, reason: "risky [tier 3: delete]".into(), tier: 3 };
        let p2 = p.clone();
        let h = std::thread::spawn(move || crate::approver::Approver::approve(&*p2, &req));
        while crate::approver::Approver::pending(&*p).is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let who = ark_security::audit::Actor::new("sso", "alice@corp.example").with_role("user");
        assert!(crate::approver::answer_by(&*p, data, "a1", "once", &who, "arp"));
        assert_eq!(h.join().unwrap(), crate::approver::Approval::Once);
        let recs = ark_security::audit::all(data);
        let r = recs.iter().find(|r| r["kind"] == "approval.answer").unwrap();
        assert_eq!(r["actor"]["name"], "alice@corp.example");
        assert_eq!(r["detail"]["tier"], 3);
        assert_eq!(r["detail"]["approved_by"], "sso:alice@corp.example");
        assert_eq!(r["session"], "s1");
        assert!(!crate::approver::answer_by(&*p, data, "a1", "once", &who, "arp"), "already answered");
    }

    #[test]
    fn pii_at_rest_masks_stored_input_ent078() {
        let tmp = ark_core::tmp::TempDir::new("ark-gov-pii");
        let k = kernel(&tmp, |c| c.compliance.pii.at_rest = true);
        let ws = tmp.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let id = k.create_session(&ws, None, None, None).unwrap();
        k.submit(&id, "mail bob@corp.example or call +1 415-555-0100", "cli").unwrap();
        let stored = serde_json::to_string(&k.store.read(&id).unwrap()).unwrap();
        assert!(!stored.contains("bob@corp.example") && !stored.contains("415-555-0100") && stored.contains("[email]"), "{stored}");
        let off = ark_core::tmp::TempDir::new("ark-gov-pii-off");
        let k = kernel(&off, |_| {});
        let ws = off.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let id = k.create_session(&ws, None, None, None).unwrap();
        k.submit(&id, "mail bob@corp.example", "cli").unwrap();
        assert!(serde_json::to_string(&k.store.read(&id).unwrap()).unwrap().contains("bob@corp.example"), "off by default");
    }

    /// ent-086: the model call of a session owned by a team member resolves its provider with
    /// that team in scope (so the resolver can pick the team's own key); others resolve without.
    #[test]
    fn model_calls_carry_the_owners_team() {
        struct Rec(std::sync::Mutex<Vec<Option<String>>>);
        impl crate::kernel::Resolver for Rec {
            fn provider(&self, id: &str) -> Result<std::sync::Arc<dyn ark_core::Provider>, String> {
                self.0.lock().unwrap().push(ark_core::team::current());
                Err(format!("no provider {id}"))
            }
        }
        let tmp = ark_core::tmp::TempDir::new("ark-gov-team");
        let root = tmp.path();
        let paths = crate::config::Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run"), ..Default::default() };
        std::fs::create_dir_all(&paths.data).unwrap();
        let mut cfg = crate::config::Config::default();
        cfg.model.default = "fake/m".into();
        cfg.checkpoint.enabled = false;
        let rec = std::sync::Arc::new(Rec(Default::default()));
        let k = crate::kernel::new_kernel(cfg, paths, rec.clone(), vec![], std::sync::Arc::new(crate::vault::Vault::empty()), std::sync::Arc::new(crate::approver::Policy { allow_privilege: false, allow_egress: false }));
        let ann = crate::agents::user_add(&k.paths, "ann").unwrap();
        crate::agents::user_update(&k.paths, &ann.id, |u| {
            u.team = "eng".into();
            Ok(())
        })
        .unwrap();
        crate::agents::user_link_email(&k.paths, &ann.id, "ann@corp.example").unwrap();
        let ws = root.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let id = k.create_session(&ws, None, None, None).unwrap();
        note_owner(&k.paths.data, &id, "sso:ann@corp.example");
        k.submit(&id, "hi", "cli").unwrap();
        let _ = k.run(&id, crate::kernel::RunOpts::default());
        let other = k.create_session(&ws, None, None, None).unwrap();
        k.submit(&other, "hi", "cli").unwrap();
        let _ = k.run(&other, crate::kernel::RunOpts::default());
        let seen = rec.0.lock().unwrap().clone();
        assert!(seen.contains(&Some("eng".to_string())), "{seen:?}");
        assert!(seen.contains(&None), "{seen:?}");
    }
}
