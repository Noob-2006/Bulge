//! DevOps / SRE tools (BATCH-next §三 pro-015/017/071, ent-105/106/107): read-only queries
//! against self-hosted monitoring (Prometheus, Loki, Alertmanager, Elastic, Grafana), the
//! controlled `deploy` tool (plan → approve → apply → prepared rollback), and native ticket /
//! incident integrations (Jira incl. JSM, ServiceNow, PagerDuty).
//!
//! Configuration lives under `[integrations.<id>]` (the kernel keeps that table opaque and
//! hands it here unparsed), for example:
//!
//! ```toml
//! [integrations.prometheus]
//! url = "http://prometheus.internal:9090"
//! token = "{{secret:PROM_TOKEN}}"          # optional; `user` + `password` for basic auth
//! [integrations.loki]
//! via_grafana = "loki-uid"                  # query through Grafana's datasource proxy
//! [integrations.grafana]
//! url = "https://grafana.internal"
//! token = "{{secret:GRAFANA_SA_TOKEN}}"
//! [integrations.jira]
//! url = "https://jira.example.com"
//! email = "bot@example.com"                 # Cloud: email + API token (basic); DC: token only (bearer)
//! token = "{{secret:JIRA_TOKEN}}"
//! ```
//!
//! Credentials are only ever `{{secret:NAME}}` references resolved at call time through the
//! vault (`ToolCtx::secrets`); a literal credential works but `seagent doctor`-style review should
//! flag it. HTTP goes through [`client`] (ureq, the same stack as `web::http`; seagent-net has no
//! shared outbound client builder yet, so `[network]` proxy / CA settings are not applied here).

pub mod client;
pub mod deploy;
pub mod observe;
pub mod run;
pub mod tickets;

use seagent_core::Tool;
use serde_json::{Map, Value};
use std::sync::Arc;

/// The `[integrations]` table as JSON. Each tool reads its own section.
#[derive(Debug, Clone, Default)]
pub struct Integrations(pub Value);

impl Integrations {
    pub fn new(v: Value) -> Integrations {
        Integrations(if v.is_object() { v } else { Value::Object(Map::new()) })
    }
    pub fn section(&self, id: &str) -> Option<&Map<String, Value>> {
        self.0.get(id).and_then(Value::as_object)
    }
    /// A string (or number / bool) key of a section, trimmed; `None` when empty.
    pub fn str(&self, id: &str, key: &str) -> Option<String> {
        let v = self.section(id)?.get(key)?;
        let s = match v {
            Value::String(s) => s.trim().to_string(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            _ => return None,
        };
        (!s.is_empty()).then_some(s)
    }
    pub fn u64(&self, id: &str, key: &str) -> Option<u64> {
        let v = self.section(id)?.get(key)?;
        v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
    }
    pub fn bool(&self, id: &str, key: &str) -> Option<bool> {
        self.section(id)?.get(key)?.as_bool()
    }
    pub fn list(&self, id: &str, key: &str) -> Vec<String> {
        match self.section(id).and_then(|s| s.get(key)) {
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            Some(Value::String(s)) => s.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            _ => vec![],
        }
    }
    /// `enabled = false` switches a configured section off without deleting it.
    pub fn enabled(&self, id: &str) -> bool {
        self.section(id).is_some() && self.bool(id, "enabled") != Some(false)
    }
    /// A section with an endpoint (`url` / `base_url`, or `via_grafana` for Prometheus / Loki).
    pub fn has_endpoint(&self, id: &str) -> bool {
        self.enabled(id) && (self.str(id, "url").is_some() || self.str(id, "base_url").is_some() || self.str(id, "via_grafana").is_some())
    }
}

/// The DevOps tools for one `[integrations]` table. Query and ticket tools appear only when
/// their section names an endpoint; `deploy` is always present (it drives local CLIs and
/// is useless without an approval anyway).
pub fn tools(cfg: Arc<Integrations>) -> Vec<Arc<dyn Tool>> {
    let mut out: Vec<Arc<dyn Tool>> = observe::tools(&cfg);
    if cfg.bool("deploy", "enabled") != Some(false) {
        out.push(Arc::new(deploy::Deploy { cfg: cfg.clone() }));
    }
    out.extend(tickets::tools(&cfg));
    out
}

/// [`tools`] plus the security-operations set ([`crate::secops`]) from the raw table.
pub fn tools_from_value(integrations: Value) -> Vec<Arc<dyn Tool>> {
    let cfg = Arc::new(Integrations::new(integrations));
    let mut out = tools(cfg.clone());
    out.extend(crate::secops::tools(cfg));
    out
}

// ───────────────────────────── shared helpers ─────────────────────────────

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Unix seconds → `YYYY-MM-DDTHH:MM:SSZ`.
pub fn rfc3339(t: i64) -> String {
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", secs / 3600, secs % 3600 / 60, secs % 60)
}

/// `15s` / `5m` / `2h` / `7d` / `1w` → seconds.
pub fn duration_secs(s: &str) -> Option<i64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: i64 = num.parse().ok()?;
    let mul = match unit.trim() {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        "w" => 604_800,
        _ => return None,
    };
    Some(n * mul)
}

/// A time argument as unix seconds: `now`, `now-1h`, `-15m`, `1h` (= ago), unix seconds,
/// or an RFC 3339 timestamp (`2026-01-02T03:04:05Z`, offsets allowed).
pub fn parse_time(s: &str, now: i64) -> Result<i64, String> {
    let t = s.trim();
    if t.is_empty() || t == "now" {
        return Ok(now);
    }
    if let Some(rest) = t.strip_prefix("now-").or_else(|| t.strip_prefix('-')) {
        return duration_secs(rest).map(|d| now - d).ok_or_else(|| format!("bad relative time `{s}`"));
    }
    if let Ok(n) = t.parse::<f64>() {
        // Milliseconds are common in copied URLs.
        return Ok(if n > 1e11 { (n / 1000.0) as i64 } else { n as i64 });
    }
    if let Some(d) = duration_secs(t) {
        return Ok(now - d);
    }
    parse_rfc3339(t).ok_or_else(|| format!("bad time `{s}` (use now-1h, -15m, unix seconds or RFC 3339)"))
}

pub fn parse_rfc3339(t: &str) -> Option<i64> {
    let b = t.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || !(b[10] == b'T' || b[10] == b' ') {
        return None;
    }
    let n = |r: std::ops::Range<usize>| t.get(r)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, s) = (n(0..4)?, n(5..7)?, n(8..10)?, n(11..13)?, n(14..16)?, n(17..19)?);
    let mut rest = &t[19..];
    if let Some(r) = rest.strip_prefix('.') {
        rest = r.trim_start_matches(|c: char| c.is_ascii_digit());
    }
    let off = match rest {
        "" | "Z" | "z" => 0,
        o if o.len() == 6 && (o.starts_with('+') || o.starts_with('-')) => {
            let v = o[1..3].parse::<i64>().ok()? * 3600 + o[4..6].parse::<i64>().ok()? * 60;
            if o.starts_with('-') { -v } else { v }
        }
        _ => return None,
    };
    let (y2, m2) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * m2 + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + s - off)
}

/// Cap model-facing text at `max` bytes. When it is cut, the whole text is spilled under
/// `<artifacts>/ops/` and the note names the file so the model can page through it.
pub(crate) fn cap_output(ctx: &seagent_core::ToolCtx, tool: &str, text: String, max: usize) -> String {
    if text.len() <= max {
        return text;
    }
    let dir = ctx.artifacts.join("ops");
    let file = dir.join(format!("{tool}-{}.txt", seagent_net::crypto::hex(&seagent_net::crypto::random_bytes(4))));
    let saved = std::fs::create_dir_all(&dir).and_then(|_| std::fs::write(&file, &text)).is_ok();
    let head = crate::util::truncate_str(&text, max);
    if saved {
        format!("{head}\n\n[truncated: {} of {} bytes shown; full output saved to {} — read it in parts]", head.len(), text.len(), file.display())
    } else {
        format!("{head}\n\n[truncated: {} of {} bytes shown]", head.len(), text.len())
    }
}

pub(crate) fn arg<'a>(input: &'a Value, key: &str) -> Option<&'a str> {
    input.get(key).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty())
}

pub(crate) fn arg_u64(input: &Value, key: &str) -> Option<u64> {
    input.get(key).and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())))
}

pub(crate) fn arg_list(input: &Value, key: &str) -> Vec<String> {
    match input.get(key) {
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect(),
        Some(Value::String(s)) if !s.trim().is_empty() => vec![s.trim().to_string()],
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn times_parse_relative_absolute_and_round_trip() {
        let now = 1_800_000_000;
        assert_eq!(parse_time("now", now).unwrap(), now);
        assert_eq!(parse_time("now-1h", now).unwrap(), now - 3600);
        assert_eq!(parse_time("-15m", now).unwrap(), now - 900);
        assert_eq!(parse_time("2d", now).unwrap(), now - 172_800);
        assert_eq!(parse_time("1700000000000", now).unwrap(), 1_700_000_000);
        assert_eq!(parse_time("2026-11-05T10:00:00Z", now).unwrap(), parse_rfc3339("2026-11-05T18:00:00+08:00").unwrap());
        assert_eq!(rfc3339(parse_rfc3339("2024-02-29T23:59:58Z").unwrap()), "2024-02-29T23:59:58Z");
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert!(parse_time("yesterday", now).is_err());
    }

    #[test]
    fn registration_follows_the_integrations_table() {
        let names = |v: Value| tools_from_value(v).iter().map(|t| t.spec().name).collect::<Vec<_>>();
        let base = names(json!({}));
        assert!(base.contains(&"deploy".to_string()) && base.contains(&"scan_report".to_string()) && base.contains(&"compliance_check".to_string()) && base.contains(&"osv_query".to_string()));
        assert!(!base.iter().any(|n| n == "prometheus_query" || n == "jira" || n == "siem_alerts"), "{base:?}");
        let all = names(json!({
            "prometheus": {"url": "http://p:9090"}, "loki": {"via_grafana": "loki"}, "alertmanager": {"url": "http://am"},
            "elastic": {"url": "http://es:9200"}, "grafana": {"url": "http://g"}, "jira": {"url": "http://j"},
            "servicenow": {"url": "http://sn"}, "pagerduty": {"token": "{{secret:PD}}"}, "wazuh": {"url": "http://w"},
            "deploy": {"enabled": false}
        }));
        for n in ["prometheus_query", "loki_query", "alertmanager_alerts", "elastic_search", "grafana_query", "jira", "servicenow", "pagerduty", "siem_alerts"] {
            assert!(all.contains(&n.to_string()), "{n} in {all:?}");
        }
        assert!(!all.contains(&"deploy".to_string()));
        let off = names(json!({"prometheus": {"url": "http://p", "enabled": false}}));
        assert!(!off.contains(&"prometheus_query".to_string()));
        for t in tools_from_value(json!({"prometheus": {"url": "http://p"}, "jira": {"url": "http://j"}})) {
            let s = t.spec();
            assert_eq!(s.input_schema["type"], "object", "{}", s.name);
            assert!(!s.description.is_empty());
        }
    }
}
