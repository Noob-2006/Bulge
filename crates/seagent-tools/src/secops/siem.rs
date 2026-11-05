//! `siem_alerts` (pro-030): read open security alerts from Wazuh (its indexer), Elastic
//! Security, Splunk (Enterprise Security notables or any search) and Semgrep (AppSec platform
//! findings), normalised to one shape — time, severity, rule, asset — de-duplicated by rule ×
//! asset with a count, most severe first. Read-only: Splunk searches that write
//! (`| delete`, `| outputlookup`, `| collect`, `| sendemail`, scripts, …) are refused.

use crate::ops::client::Endpoint;
use crate::ops::observe::{elastic_search_raw, valid_index};
use crate::ops::{arg, arg_u64, cap_output, now_unix, parse_time, rfc3339, Integrations};
use crate::secops::report::Sev;
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

pub const SOURCES: &[&str] = &["wazuh", "elastic", "splunk", "semgrep"];

pub struct SiemAlerts {
    pub cfg: Arc<Integrations>,
}

impl SiemAlerts {
    pub fn configured(cfg: &Integrations) -> Vec<&'static str> {
        SOURCES.iter().copied().filter(|s| cfg.has_endpoint(s) || (*s == "semgrep" && cfg.enabled("semgrep") && cfg.str("semgrep", "token").is_some())).collect()
    }
}

#[derive(Debug, Clone)]
struct Alert {
    source: &'static str,
    time: String,
    severity: Sev,
    rule: String,
    title: String,
    asset: String,
    id: String,
    count: usize,
}

fn wazuh_sev(level: u64) -> Sev {
    match level {
        13.. => Sev::Critical,
        10..=12 => Sev::High,
        7..=9 => Sev::Medium,
        4..=6 => Sev::Low,
        _ => Sev::Info,
    }
}

/// Splunk commands that write, send or execute: refused anywhere in the pipeline.
const SPL_DENY: &[&str] = &["delete", "outputlookup", "outputcsv", "outputtext", "collect", "mcollect", "meventcollect", "tscollect", "sendemail", "sendalert", "script", "run", "runshellscript", "dump", "map", "sendmail", "rest"];

/// A read-only SPL search, or why it is not.
pub fn spl_read_only(q: &str) -> Result<String, String> {
    let t = q.trim();
    if t.is_empty() {
        return Err("empty search".into());
    }
    for seg in t.split('|').skip(1) {
        let cmd = seg.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
        if SPL_DENY.contains(&cmd.as_str()) {
            return Err(format!("`| {cmd}` is not allowed: siem_alerts only runs read-only searches"));
        }
    }
    Ok(if t.starts_with('|') || t.to_ascii_lowercase().starts_with("search ") { t.to_string() } else { format!("search {t}") })
}

fn str_of<'a>(v: &'a Value, path: &str) -> &'a str {
    v.pointer(path).and_then(Value::as_str).unwrap_or("")
}

fn fetch(src: &'static str, ep: &Endpoint, cfg: &Integrations, input: &Value, limit: usize) -> Result<Vec<Alert>, String> {
    let now = now_unix();
    let since = arg(input, "since").unwrap_or("now-24h");
    match src {
        "wazuh" => {
            let index = cfg.str("wazuh", "index").unwrap_or_else(|| "wazuh-alerts-*".into());
            let min = arg_u64(input, "min_level").or_else(|| cfg.u64("wazuh", "min_level")).unwrap_or(7);
            let mut q = json!({"since": since, "time_field": "timestamp", "size": limit, "dsl": {"range": {"rule.level": {"gte": min}}}});
            if let Some(t) = arg(input, "query") {
                q["query"] = json!(t);
            }
            let v = elastic_search_raw(ep, &index, &q, limit)?;
            Ok(v["hits"].as_array().into_iter().flatten().map(|h| {
                let s = &h["source"];
                Alert { source: "wazuh", time: str_of(s, "/timestamp").into(), severity: wazuh_sev(s.pointer("/rule/level").and_then(Value::as_u64).unwrap_or(0)), rule: str_of(s, "/rule/id").into(), title: str_of(s, "/rule/description").into(), asset: str_of(s, "/agent/name").into(), id: h["_id"].as_str().unwrap_or("").into(), count: 1 }
            }).collect())
        }
        "elastic" => {
            let index = cfg.str("elastic", "siem_index").unwrap_or_else(|| ".alerts-security.alerts-*".into());
            if !index.split(',').all(|i| i.trim().starts_with(".alerts-") || valid_index(i.trim())) {
                return Err(format!("bad siem_index `{index}`"));
            }
            let mut q = json!({"since": since, "size": limit, "dsl": {"term": {"kibana.alert.workflow_status": "open"}}});
            if let Some(t) = arg(input, "query") {
                q["query"] = json!(t);
            }
            let v = elastic_search_raw(ep, &index, &q, limit)?;
            Ok(v["hits"].as_array().into_iter().flatten().map(|h| {
                let s = &h["source"];
                let flat = |k: &str| s.get(k).and_then(Value::as_str).unwrap_or_else(|| str_of(s, &format!("/{}", k.replace('.', "/")))).to_string();
                Alert { source: "elastic", time: flat("@timestamp"), severity: Sev::parse(&flat("kibana.alert.severity")), rule: flat("kibana.alert.rule.uuid"), title: flat("kibana.alert.rule.name"), asset: flat("host.name"), id: h["_id"].as_str().unwrap_or("").into(), count: 1 }
            }).collect())
        }
        "splunk" => {
            let search = spl_read_only(arg(input, "query").map(String::from).or_else(|| cfg.str("splunk", "search")).as_deref().unwrap_or("search index=notable"))?;
            let earliest = rfc3339(parse_time(since, now)?);
            let r = ep.post_form("/services/search/jobs/export", &[("search", format!("{search} | head {limit}")), ("earliest_time", earliest), ("latest_time", "now".into()), ("output_mode", "json".to_string())])?;
            if !(200..300).contains(&r.status) {
                return Err(format!("splunk API error ({}): {}", r.status, crate::util::truncate_str(&ep.redact(&r.body), 1000)));
            }
            Ok(r.body.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter_map(|v| v.get("result").cloned()).take(limit).map(|x| {
                let g = |ks: &[&str]| ks.iter().find_map(|k| x[k].as_str()).unwrap_or("").to_string();
                Alert { source: "splunk", time: g(&["_time"]), severity: Sev::parse(&g(&["urgency", "severity"])), rule: g(&["search_name", "rule_name", "source"]), title: g(&["rule_title", "rule_name", "search_name", "_raw"]).chars().take(200).collect(), asset: g(&["dest", "host", "src"]), id: g(&["event_id", "_cd"]), count: 1 }
            }).collect())
        }
        "semgrep" => {
            let slug = cfg.str("semgrep", "deployment").ok_or("[integrations.semgrep] deployment (the deployment slug) is required")?;
            if !slug.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return Err(format!("bad deployment slug `{slug}`"));
            }
            let v = ep.json(ep.get(&format!("/api/v1/deployments/{slug}/findings"), &[("issue_type", arg(input, "issue_type").unwrap_or("sast").into()), ("status", "open".into()), ("page_size", limit.to_string())])?)?;
            Ok(v["findings"].as_array().into_iter().flatten().map(|f| Alert {
                source: "semgrep",
                time: str_of(f, "/relevant_since").into(),
                severity: Sev::parse(str_of(f, "/severity")),
                rule: str_of(f, "/rule_name").into(),
                title: f.pointer("/rule_message").or(f.pointer("/rule/message")).and_then(Value::as_str).unwrap_or("").chars().take(200).collect(),
                asset: format!("{}:{}:{}", str_of(f, "/repository/name"), str_of(f, "/location/file_path"), f.pointer("/location/line").and_then(Value::as_u64).unwrap_or(0)),
                id: f["id"].to_string(),
                count: 1,
            }).collect())
        }
        _ => Err(format!("unknown source `{src}`")),
    }
}

impl Tool for SiemAlerts {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "siem_alerts".into(),
            description: format!("Read open security alerts from the configured SIEM / AppSec sources ({}) normalised to time, severity, rule, asset; duplicates (same rule on the same asset) are merged with a count, most severe first. `source` picks one (default: all configured), `since` (default now-24h), `query` narrows (Lucene for Wazuh/Elastic, SPL for Splunk; read-only), `min_level` for Wazuh. Read-only.", Self::configured(&self.cfg).join(", ")),
            input_schema: json!({"type":"object","properties":{
                "source":{"type":"string","enum":SOURCES},"since":{"type":"string"},"query":{"type":"string"},"min_level":{"type":"integer"},
                "min_severity":{"type":"string","enum":["info","low","medium","high","critical"]},"issue_type":{"type":"string","enum":["sast","sca","secrets"]},"limit":{"type":"integer"}}}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let srcs: Vec<&str> = match arg(input, "source") {
            Some(s) => vec![s],
            None => Self::configured(&self.cfg),
        };
        srcs.into_iter().filter_map(|s| Endpoint::from_config(&self.cfg, s, (s == "semgrep").then_some("https://semgrep.dev"), ctx).ok()).map(|e| Effect::Net { dest: e.base, payload: String::new() }).collect()
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let configured = Self::configured(&self.cfg);
        let srcs: Vec<&'static str> = match arg(&input, "source") {
            Some(s) => match configured.iter().find(|c| **c == s) {
                Some(c) => vec![*c],
                None => return ToolOutput::err(format!("source `{s}` is not configured (configured: {})", configured.join(", "))),
            },
            None => configured,
        };
        let limit = arg_u64(&input, "limit").unwrap_or(100).clamp(1, 1000) as usize;
        let mut alerts: Vec<Alert> = vec![];
        let mut errors = BTreeMap::new();
        for s in &srcs {
            let r = Endpoint::from_config(&self.cfg, s, (*s == "semgrep").then_some("https://semgrep.dev"), ctx).and_then(|ep| fetch(s, &ep, &self.cfg, &input, limit));
            match r {
                Ok(a) => alerts.extend(a),
                Err(e) => {
                    errors.insert(*s, e);
                }
            }
        }
        if alerts.is_empty() && !errors.is_empty() {
            return ToolOutput::err(errors.values().cloned().collect::<Vec<_>>().join("\n"));
        }
        let min = arg(&input, "min_severity").map(Sev::parse).unwrap_or(Sev::Unknown);
        let raw = alerts.len();
        let mut merged: BTreeMap<(String, String, String), Alert> = BTreeMap::new();
        for a in alerts.into_iter().filter(|a| a.severity >= min) {
            match merged.get_mut(&(a.source.to_string(), a.rule.clone(), a.asset.clone())) {
                Some(m) => {
                    m.count += 1;
                    if a.time > m.time {
                        m.time = a.time;
                    }
                    m.severity = m.severity.max(a.severity);
                }
                None => {
                    merged.insert((a.source.to_string(), a.rule.clone(), a.asset.clone()), a);
                }
            }
        }
        let mut list: Vec<Alert> = merged.into_values().collect();
        list.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.time.cmp(&a.time)));
        let out = json!({"sources": srcs, "raw_alerts": raw, "unique": list.len(), "errors": errors,
                         "alerts": list.iter().map(|a| json!({"source": a.source, "severity": a.severity.as_str(), "time": a.time, "rule": a.rule, "title": a.title, "asset": a.asset, "count": a.count, "id": a.id})).collect::<Vec<_>>()});
        ToolOutput::ok(cap_output(ctx, "siem_alerts", serde_json::to_string_pretty(&out).unwrap_or_default(), 30_000))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::FakeServer;

    #[test]
    fn splunk_searches_are_read_only() {
        assert_eq!(spl_read_only("index=notable urgency=high").unwrap(), "search index=notable urgency=high");
        assert_eq!(spl_read_only("| tstats count where index=x").unwrap(), "| tstats count where index=x");
        assert!(spl_read_only("index=x | delete").is_err());
        assert!(spl_read_only("index=x | stats count | outputlookup evil.csv").is_err());
        assert!(spl_read_only("index=x | sendemail to=a@b").is_err());
        assert!(spl_read_only("   ").is_err());
    }

    #[test]
    fn all_sources_normalise_dedup_and_rank() {
        let ctx = crate::testutil::ctx("secops-siem");
        let wazuh = json!({"hits":{"total":{"value":3},"hits":[
            {"_id":"w1","_source":{"timestamp":"2026-11-05T10:00:00Z","rule":{"id":"5712","level":10,"description":"sshd brute force"},"agent":{"name":"web-1"}}},
            {"_id":"w2","_source":{"timestamp":"2026-11-05T10:05:00Z","rule":{"id":"5712","level":10,"description":"sshd brute force"},"agent":{"name":"web-1"}}},
            {"_id":"w3","_source":{"timestamp":"2026-11-05T09:00:00Z","rule":{"id":"550","level":7,"description":"Integrity checksum changed"},"agent":{"name":"db-1"}}}]}});
        let elastic = json!({"hits":{"hits":[{"_id":"e1","_source":{"@timestamp":"2026-11-05T11:00:00Z","kibana.alert.severity":"critical","kibana.alert.rule.name":"Mimikatz","kibana.alert.rule.uuid":"r1","host":{"name":"win-7"}}}]}});
        let splunk = format!("{}\n{}\n", json!({"result":{"_time":"2026-11-05T08:00:00Z","urgency":"medium","search_name":"Excessive logins","dest":"vpn-1"}}), json!({"preview":false,"lastrow":true}));
        let semgrep = json!({"findings":[{"id":11,"rule_name":"python.sqli","severity":"high","rule_message":"SQL injection","repository":{"name":"api"},"location":{"file_path":"db.py","line":12}}]});
        let srv = FakeServer::start(vec![
            ("POST /wazuh-alerts-*/_search", 200, "application/json", wazuh.to_string()),
            ("POST /.alerts-security.alerts-*/_search", 200, "application/json", elastic.to_string()),
            ("POST /services/search/jobs/export", 200, "application/json", splunk),
            ("GET /api/v1/deployments/acme/findings", 200, "application/json", semgrep.to_string()),
        ]);
        let cfg = json!({"wazuh": {"url": srv.url, "user": "ro", "password": "{{secret:TOKEN}}"}, "elastic": {"url": srv.url}, "splunk": {"url": srv.url, "token": "{{secret:TOKEN}}"}, "semgrep": {"url": srv.url, "token": "{{secret:TOKEN}}", "deployment": "acme"}});
        let t = SiemAlerts { cfg: Arc::new(Integrations::new(cfg)) };
        assert_eq!(t.effects(&ctx, &json!({})).len(), 4);
        let o = t.call(&ctx, json!({}));
        assert!(!o.is_error, "{}", o.content);
        let v: Value = serde_json::from_str(&o.content).unwrap();
        assert_eq!(v["raw_alerts"], 6);
        assert_eq!(v["unique"], 5);
        assert_eq!(v["alerts"][0]["title"], "Mimikatz");
        let brute = v["alerts"].as_array().unwrap().iter().find(|a| a["rule"] == "5712").unwrap();
        assert_eq!((brute["count"].as_u64(), brute["severity"].as_str(), brute["time"].as_str()), (Some(2), Some("high"), Some("2026-11-05T10:05:00Z")));
        let reqs = srv.requests();
        let wz = reqs.iter().find(|r| r.path.starts_with("/wazuh")).unwrap();
        assert_eq!(wz.json()["query"]["bool"]["must"][0]["range"]["rule.level"]["gte"], 7);
        let sp = reqs.iter().find(|r| r.path.contains("export")).unwrap();
        assert!(sp.body.contains("search=search%20index%3Dnotable%20%7C%20head%20100") && sp.body.contains("output_mode=json"), "{}", sp.body);
        assert!(t.call(&ctx, json!({"source": "splunk", "query": "index=x | delete"})).content.contains("not allowed"));
        let o = t.call(&ctx, json!({"source": "wazuh", "min_severity": "high"}));
        assert!(!o.content.contains("Integrity"), "{}", o.content);
        assert!(t.call(&ctx, json!({"source": "qradar"})).is_error);
    }
}
