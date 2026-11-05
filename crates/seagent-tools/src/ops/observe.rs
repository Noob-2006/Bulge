//! Read-only monitoring queries (pro-015 / pro-017): `prometheus_query` (PromQL),
//! `loki_query` (LogQL), `alertmanager_alerts`, `elastic_search` and `grafana_query`.
//!
//! Read-only by construction: the tools only issue GETs (and the two read POSTs, Elastic
//! `_search` and Grafana `/api/ds/query`) to paths they build themselves — no method, path or
//! admin endpoint comes from the model. Every answer is summarised (series → min / max / last
//! plus a downsample; log streams → newest lines) and capped; the full text spills under
//! `<artifacts>/ops/` when it is cut. Self-hosted endpoints are the default; Prometheus / Loki
//! can also be reached through Grafana's datasource proxy (`via_grafana = "<uid>"`).

use super::client::Endpoint;
use super::{arg, arg_list, arg_u64, cap_output, now_unix, parse_time, rfc3339, Integrations};
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Map, Value};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Prometheus,
    Loki,
    Alertmanager,
    Elastic,
    Grafana,
}

impl Kind {
    fn id(self) -> &'static str {
        match self {
            Kind::Prometheus => "prometheus",
            Kind::Loki => "loki",
            Kind::Alertmanager => "alertmanager",
            Kind::Elastic => "elastic",
            Kind::Grafana => "grafana",
        }
    }
    fn tool(self) -> &'static str {
        match self {
            Kind::Prometheus => "prometheus_query",
            Kind::Loki => "loki_query",
            Kind::Alertmanager => "alertmanager_alerts",
            Kind::Elastic => "elastic_search",
            Kind::Grafana => "grafana_query",
        }
    }
}

pub struct Query {
    pub cfg: Arc<Integrations>,
    pub kind: Kind,
}

pub fn tools(cfg: &Arc<Integrations>) -> Vec<Arc<dyn Tool>> {
    [Kind::Prometheus, Kind::Loki, Kind::Alertmanager, Kind::Elastic, Kind::Grafana]
        .into_iter()
        .filter(|k| cfg.has_endpoint(k.id()))
        .map(|kind| Arc::new(Query { cfg: cfg.clone(), kind }) as Arc<dyn Tool>)
        .collect()
}

const TIME_HELP: &str = "now, now-1h, -15m, unix seconds or RFC 3339";

impl Tool for Query {
    fn spec(&self) -> ToolSpec {
        let (description, schema) = match self.kind {
            Kind::Prometheus => (
                "Read-only PromQL against the configured Prometheus (or a Grafana Prometheus datasource). kind=instant (default) evaluates `query` at `time`; kind=range over start..end with step (series are summarised: min/max/last + downsample); kind=series|labels|label_values|alerts|rules|targets for metadata. Never writes.",
                json!({"type":"object","properties":{
                    "query":{"type":"string","description":"PromQL expression (instant/range) or series selector (series)"},
                    "kind":{"type":"string","enum":["instant","range","series","labels","label_values","alerts","rules","targets"]},
                    "time":{"type":"string","description":TIME_HELP},"start":{"type":"string","description":format!("{TIME_HELP}; default now-1h")},"end":{"type":"string"},
                    "step":{"type":"string","description":"e.g. 30s, 5m; default ~250 points"},"label":{"type":"string","description":"label name for label_values"},
                    "limit":{"type":"integer","description":"max series shown (default 30)"}}}),
            ),
            Kind::Loki => (
                "Read-only LogQL against the configured Loki (or a Grafana Loki datasource). kind=logs (default) returns the newest matching lines between start and end (default last 1h, limit 100, max 1000); metric queries are summarised like Prometheus series; kind=labels|label_values|series for metadata.",
                json!({"type":"object","properties":{
                    "query":{"type":"string","description":"LogQL, e.g. {app=\"api\"} |= \"error\""},
                    "kind":{"type":"string","enum":["logs","labels","label_values","series"]},
                    "start":{"type":"string","description":TIME_HELP},"end":{"type":"string"},"limit":{"type":"integer"},
                    "direction":{"type":"string","enum":["backward","forward"]},"label":{"type":"string"}}}),
            ),
            Kind::Alertmanager => (
                "Read-only view of the configured Alertmanager: kind=alerts (default; firing alerts with labels, summary, start time), silences, groups or status. `filter` takes matchers like alertname=\"HighLatency\" or severity=~\"critical|page\". Cannot create silences or change anything.",
                json!({"type":"object","properties":{
                    "kind":{"type":"string","enum":["alerts","silences","groups","status"]},
                    "filter":{"type":"array","items":{"type":"string"}},"active":{"type":"boolean"},"silenced":{"type":"boolean"},"inhibited":{"type":"boolean"},
                    "receiver":{"type":"string"},"limit":{"type":"integer"}}}),
            ),
            Kind::Elastic => (
                "Read-only search of the configured Elasticsearch / OpenSearch: `index` (pattern, e.g. logs-*), `query` (Lucene query_string) and/or `dsl` (a query clause object), `since`/`until` on time_field (default @timestamp), `size` (default 20, capped), optional `fields` and `aggs`. Only _search / _count are ever called.",
                json!({"type":"object","properties":{
                    "index":{"type":"string"},"query":{"type":"string"},"dsl":{"type":"object"},"since":{"type":"string","description":TIME_HELP},"until":{"type":"string"},
                    "time_field":{"type":"string"},"size":{"type":"integer"},"fields":{"type":"array","items":{"type":"string"}},"aggs":{"type":"object"},
                    "count_only":{"type":"boolean"},"sort":{"type":"string","enum":["desc","asc"]}}}),
            ),
            Kind::Grafana => (
                "Read-only Grafana (self-hosted or Cloud): action=search (dashboards by text/tag), dashboard (panels and their queries by uid), datasources, alerts (Grafana-managed alert state), annotations (from..to), query (run a datasource query: datasource_uid + expr, from..to). Never edits dashboards or alert rules.",
                json!({"type":"object","properties":{
                    "action":{"type":"string","enum":["search","dashboard","datasources","alerts","annotations","query"]},
                    "query":{"type":"string","description":"search text (search)"},"uid":{"type":"string","description":"dashboard uid"},
                    "datasource_uid":{"type":"string"},"expr":{"type":"string","description":"PromQL/LogQL for action=query"},
                    "from":{"type":"string","description":TIME_HELP},"to":{"type":"string"},"tags":{"type":"array","items":{"type":"string"}},"limit":{"type":"integer"}},
                    "required":["action"]}),
            ),
        };
        ToolSpec { name: self.kind.tool().into(), description: description.into(), input_schema: schema, parallel_safe: true, idempotent: true, pinned: false }
    }

    fn effects(&self, ctx: &ToolCtx, _input: &Value) -> Vec<Effect> {
        // A read: data comes in, nothing is sent but the query itself (as with web_fetch).
        let dest = match Endpoint::from_config(&self.cfg, self.kind.id(), None, ctx) {
            Ok(e) => e.base,
            Err(_) => self.cfg.str(self.kind.id(), "url").unwrap_or_else(|| self.kind.id().to_string()),
        };
        vec![Effect::Net { dest, payload: String::new() }]
    }

    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let ep = match Endpoint::from_config(&self.cfg, self.kind.id(), None, ctx) {
            Ok(e) => e,
            Err(e) => return ToolOutput::err(e),
        };
        let r = match self.kind {
            Kind::Prometheus => prometheus(&ep, &input),
            Kind::Loki => loki(&ep, &input),
            Kind::Alertmanager => alertmanager(&ep, &input),
            Kind::Elastic => elastic(&ep, &self.cfg, &input),
            Kind::Grafana => grafana(&ep, &input),
        };
        match r {
            Ok(v) => ToolOutput::ok(cap_output(ctx, self.kind.tool(), serde_json::to_string_pretty(&v).unwrap_or_default(), ep.max_output)),
            Err(e) => ToolOutput::err(e),
        }
    }
}

fn time_arg(input: &Value, key: &str, default: i64) -> Result<i64, String> {
    match arg(input, key) {
        Some(t) => parse_time(t, now_unix()),
        None => Ok(default),
    }
}

/// `{__name__="x", a="b"}` → `x{a="b"}`.
fn series_name(metric: &Value) -> String {
    let Some(m) = metric.as_object() else { return "{}".into() };
    let name = m.get("__name__").and_then(Value::as_str).unwrap_or("");
    let labels: Vec<String> = m.iter().filter(|(k, _)| *k != "__name__").map(|(k, v)| format!("{k}=\"{}\"", v.as_str().unwrap_or(""))).collect();
    format!("{name}{{{}}}", labels.join(","))
}

fn num(v: &Value) -> Option<f64> {
    v.as_str().and_then(|s| s.parse().ok()).or_else(|| v.as_f64())
}

/// Prometheus-shaped `data` (`vector` / `matrix` / `scalar` / `streams`) → a compact summary.
fn summarise_series(data: &Value, limit: usize) -> Value {
    let rt = data["resultType"].as_str().unwrap_or("");
    let result = data["result"].as_array().cloned().unwrap_or_default();
    let total = result.len();
    let series: Vec<Value> = match rt {
        "vector" => result.iter().take(limit).map(|s| json!({"series": series_name(&s["metric"]), "value": s["value"][1], "at": s["value"][0].as_f64().map(|t| rfc3339(t as i64))})).collect(),
        "matrix" => result
            .iter()
            .take(limit)
            .map(|s| {
                let pts: Vec<(f64, f64)> = s["values"].as_array().map(|a| a.iter().filter_map(|p| Some((p[0].as_f64()?, num(&p[1])?))).collect()).unwrap_or_default();
                let vals: Vec<f64> = pts.iter().map(|p| p.1).filter(|v| v.is_finite()).collect();
                let (min, max) = vals.iter().fold((f64::INFINITY, f64::NEG_INFINITY), |(a, b), v| (a.min(*v), b.max(*v)));
                let stride = pts.len().div_ceil(20).max(1);
                let sample: Vec<Value> = pts.iter().step_by(stride).map(|(t, v)| json!([rfc3339(*t as i64), v])).collect();
                json!({"series": series_name(&s["metric"]), "points": pts.len(), "min": if vals.is_empty() { Value::Null } else { json!(min) }, "max": if vals.is_empty() { Value::Null } else { json!(max) },
                       "last": pts.last().map(|p| json!(p.1)), "from": pts.first().map(|p| rfc3339(p.0 as i64)), "to": pts.last().map(|p| rfc3339(p.0 as i64)), "sample": sample})
            })
            .collect(),
        "scalar" | "string" => return json!({"type": rt, "value": data["result"][1], "at": data["result"][0].as_f64().map(|t| rfc3339(t as i64))}),
        _ => return data.clone(),
    };
    let mut out = json!({"type": rt, "series_total": total, "series": series});
    if total > limit {
        out["note"] = json!(format!("{} more series not shown; narrow the selector or aggregate (sum by …)", total - limit));
    }
    out
}

fn prom_data(ep: &Endpoint, path: &str, q: &[(&str, String)]) -> Result<Value, String> {
    let v = ep.json(ep.get(path, q)?)?;
    if v["status"].as_str() == Some("error") {
        return Err(format!("{} query error ({}): {}", ep.id, v["errorType"].as_str().unwrap_or(""), v["error"].as_str().unwrap_or("")));
    }
    let mut d = v["data"].clone();
    if let Some(w) = v["warnings"].as_array().filter(|w| !w.is_empty()) {
        if let Some(o) = d.as_object_mut() {
            o.insert("warnings".into(), Value::Array(w.clone()));
        }
    }
    Ok(d)
}

/// Bounded step: at most ~250 points per series unless the caller asks for a step.
fn step_for(input: &Value, start: i64, end: i64) -> Result<String, String> {
    if let Some(s) = arg(input, "step") {
        let secs = super::duration_secs(s).ok_or_else(|| format!("bad step `{s}`"))?;
        if secs <= 0 || (end - start) / secs > 11_000 {
            return Err("step too small for this range (over 11,000 points per series)".into());
        }
        return Ok(format!("{secs}s"));
    }
    Ok(format!("{}s", ((end - start) / 250).max(15)))
}

fn prometheus(ep: &Endpoint, input: &Value) -> Result<Value, String> {
    let kind = arg(input, "kind").unwrap_or("instant");
    let limit = arg_u64(input, "limit").unwrap_or(30).clamp(1, 500) as usize;
    let now = now_unix();
    let query = arg(input, "query");
    let need_q = || query.map(String::from).ok_or_else(|| format!("`query` is required for kind={kind}"));
    match kind {
        "instant" => {
            let t = time_arg(input, "time", now)?;
            Ok(summarise_series(&prom_data(ep, "/api/v1/query", &[("query", need_q()?), ("time", t.to_string())])?, limit))
        }
        "range" => {
            let end = time_arg(input, "end", now)?;
            let start = time_arg(input, "start", end - 3600)?;
            if start >= end {
                return Err("start must be before end".into());
            }
            let step = step_for(input, start, end)?;
            Ok(summarise_series(&prom_data(ep, "/api/v1/query_range", &[("query", need_q()?), ("start", start.to_string()), ("end", end.to_string()), ("step", step)])?, limit))
        }
        "series" => {
            let end = time_arg(input, "end", now)?;
            let start = time_arg(input, "start", end - 3600)?;
            let d = prom_data(ep, "/api/v1/series", &[("match[]", need_q()?), ("start", start.to_string()), ("end", end.to_string()), ("limit", limit.to_string())])?;
            let all = d.as_array().cloned().unwrap_or_default();
            Ok(json!({"series_total": all.len(), "series": all.iter().take(limit).map(series_name).collect::<Vec<_>>()}))
        }
        "labels" => prom_data(ep, "/api/v1/labels", &[]),
        "label_values" => {
            let l = arg(input, "label").ok_or("`label` is required for kind=label_values")?;
            if !l.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(format!("bad label name `{l}`"));
            }
            let d = prom_data(ep, &format!("/api/v1/label/{l}/values"), &[])?;
            let all = d.as_array().cloned().unwrap_or_default();
            Ok(json!({"total": all.len(), "values": all.into_iter().take(limit * 10).collect::<Vec<_>>()}))
        }
        "alerts" => {
            let d = prom_data(ep, "/api/v1/alerts", &[])?;
            let a = d["alerts"].as_array().cloned().unwrap_or_default();
            Ok(json!({"total": a.len(), "alerts": a.iter().take(limit).map(|x| json!({"labels": x["labels"], "state": x["state"], "activeAt": x["activeAt"], "summary": x["annotations"]["summary"], "value": x["value"]})).collect::<Vec<_>>()}))
        }
        "rules" => {
            let d = prom_data(ep, "/api/v1/rules", &[])?;
            let mut rules = vec![];
            for g in d["groups"].as_array().into_iter().flatten() {
                for r in g["rules"].as_array().into_iter().flatten() {
                    rules.push(json!({"group": g["name"], "name": r["name"], "type": r["type"], "state": r["state"], "health": r["health"], "query": r["query"]}));
                }
            }
            Ok(json!({"total": rules.len(), "rules": rules.into_iter().take(limit * 4).collect::<Vec<_>>()}))
        }
        "targets" => {
            let d = prom_data(ep, "/api/v1/targets", &[("state", "active".into())])?;
            let t = d["activeTargets"].as_array().cloned().unwrap_or_default();
            let down: Vec<Value> = t.iter().filter(|x| x["health"].as_str() != Some("up")).map(|x| json!({"job": x["labels"]["job"], "instance": x["labels"]["instance"], "health": x["health"], "lastError": x["lastError"]})).collect();
            Ok(json!({"active": t.len(), "unhealthy": down.len(), "unhealthy_targets": down.into_iter().take(limit).collect::<Vec<_>>()}))
        }
        other => Err(format!("unknown kind `{other}`")),
    }
}

fn loki(ep: &Endpoint, input: &Value) -> Result<Value, String> {
    let kind = arg(input, "kind").unwrap_or("logs");
    let now = now_unix();
    let end = time_arg(input, "end", now)?;
    let start = time_arg(input, "start", end - 3600)?;
    let ns = |t: i64| format!("{t}000000000");
    match kind {
        "logs" => {
            let q = arg(input, "query").ok_or("`query` (LogQL) is required")?;
            let limit = arg_u64(input, "limit").unwrap_or(100).clamp(1, 1000) as usize;
            let dir = if arg(input, "direction") == Some("forward") { "forward" } else { "backward" };
            let d = prom_data(ep, "/loki/api/v1/query_range", &[("query", q.into()), ("start", ns(start)), ("end", ns(end)), ("limit", limit.to_string()), ("direction", dir.into())])?;
            if d["resultType"].as_str() != Some("streams") {
                return Ok(summarise_series(&d, 30));
            }
            let mut lines: Vec<(i128, String, String)> = vec![];
            for s in d["result"].as_array().into_iter().flatten() {
                let labels = series_name(&s["stream"]);
                for e in s["values"].as_array().into_iter().flatten() {
                    let ts: i128 = e[0].as_str().and_then(|t| t.parse().ok()).unwrap_or(0);
                    let line = e[1].as_str().unwrap_or("");
                    lines.push((ts, labels.clone(), crate::util::truncate_str(line, 2000).to_string()));
                }
            }
            lines.sort_by(|a, b| if dir == "forward" { a.0.cmp(&b.0) } else { b.0.cmp(&a.0) });
            lines.truncate(limit);
            let total = lines.len();
            Ok(json!({"lines": total, "range": [rfc3339(start), rfc3339(end)], "entries": lines.into_iter().map(|(ts, l, line)| json!({"t": rfc3339((ts / 1_000_000_000) as i64), "stream": l, "line": line})).collect::<Vec<_>>(),
                      "stats": d["stats"]["summary"].clone()}))
        }
        "labels" => prom_data(ep, "/loki/api/v1/labels", &[("start", ns(start)), ("end", ns(end))]),
        "label_values" => {
            let l = arg(input, "label").ok_or("`label` is required for kind=label_values")?;
            if !l.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(format!("bad label name `{l}`"));
            }
            prom_data(ep, &format!("/loki/api/v1/label/{l}/values"), &[("start", ns(start)), ("end", ns(end))])
        }
        "series" => {
            let q = arg(input, "query").ok_or("`query` (stream selector) is required")?;
            let d = prom_data(ep, "/loki/api/v1/series", &[("match[]", q.into()), ("start", ns(start)), ("end", ns(end))])?;
            let all = d.as_array().cloned().unwrap_or_default();
            Ok(json!({"total": all.len(), "series": all.iter().take(100).map(series_name).collect::<Vec<_>>()}))
        }
        other => Err(format!("unknown kind `{other}`")),
    }
}

fn alertmanager(ep: &Endpoint, input: &Value) -> Result<Value, String> {
    let kind = arg(input, "kind").unwrap_or("alerts");
    let limit = arg_u64(input, "limit").unwrap_or(50).clamp(1, 500) as usize;
    let mut q: Vec<(&str, String)> = arg_list(input, "filter").into_iter().map(|f| ("filter", f)).collect();
    for k in ["active", "silenced", "inhibited"] {
        if let Some(b) = input.get(k).and_then(Value::as_bool) {
            q.push((k, b.to_string()));
        }
    }
    if let Some(r) = arg(input, "receiver") {
        q.push(("receiver", r.into()));
    }
    let brief = |a: &Value| json!({"alertname": a["labels"]["alertname"], "severity": a["labels"]["severity"], "state": a["status"]["state"], "startsAt": a["startsAt"], "labels": a["labels"],
                                   "summary": a["annotations"]["summary"].as_str().or(a["annotations"]["description"].as_str()), "runbook": a["annotations"]["runbook_url"], "fingerprint": a["fingerprint"], "generatorURL": a["generatorURL"]});
    match kind {
        "alerts" => {
            let v = ep.json(ep.get("/api/v2/alerts", &q)?)?;
            let mut all = v.as_array().cloned().unwrap_or_default();
            // Oldest first: the earliest firing alert is usually closest to the cause.
            all.sort_by(|a, b| a["startsAt"].as_str().cmp(&b["startsAt"].as_str()));
            Ok(json!({"total": all.len(), "alerts": all.iter().take(limit).map(brief).collect::<Vec<_>>()}))
        }
        "groups" => {
            let v = ep.json(ep.get("/api/v2/alerts/groups", &q)?)?;
            let g: Vec<Value> = v.as_array().into_iter().flatten().take(limit).map(|g| json!({"labels": g["labels"], "receiver": g["receiver"]["name"], "alerts": g["alerts"].as_array().map(|a| a.len()).unwrap_or(0)})).collect();
            Ok(json!({"groups": g}))
        }
        "silences" => {
            let v = ep.json(ep.get("/api/v2/silences", &q.into_iter().filter(|(k, _)| *k == "filter").collect::<Vec<_>>())?)?;
            let s: Vec<Value> = v.as_array().into_iter().flatten().filter(|s| s["status"]["state"].as_str() != Some("expired")).take(limit).map(|s| json!({"id": s["id"], "state": s["status"]["state"], "matchers": s["matchers"], "endsAt": s["endsAt"], "createdBy": s["createdBy"], "comment": s["comment"]})).collect();
            Ok(json!({"silences": s}))
        }
        "status" => {
            let v = ep.json(ep.get("/api/v2/status", &[])?)?;
            Ok(json!({"cluster": v["cluster"]["status"], "peers": v["cluster"]["peers"].as_array().map(|p| p.len()), "version": v["versionInfo"]["version"], "uptime": v["uptime"]}))
        }
        other => Err(format!("unknown kind `{other}`")),
    }
}

/// Index names / patterns the tool will search: letters, digits and `.-_*,:` — never a
/// leading `_` (that would be an API endpoint such as `_delete_by_query`).
pub fn valid_index(i: &str) -> bool {
    !i.is_empty() && i.len() <= 255 && !i.starts_with('_') && !i.contains("..") && i.split(',').all(|p| !p.trim().starts_with('_')) && i.chars().all(|c| c.is_ascii_alphanumeric() || ".-_*,:".contains(c))
}

/// The `_search` body for one call (pure, unit-tested).
pub fn elastic_body(input: &Value, now: i64, max_hits: usize) -> Result<Value, String> {
    let mut must: Vec<Value> = vec![];
    if let Some(q) = arg(input, "query") {
        must.push(json!({"query_string": {"query": q, "default_operator": "AND"}}));
    }
    if let Some(d) = input.get("dsl").filter(|d| d.is_object()) {
        must.push(d.clone());
    }
    let mut filter: Vec<Value> = vec![];
    let tf = arg(input, "time_field").unwrap_or("@timestamp");
    if arg(input, "since").is_some() || arg(input, "until").is_some() {
        let mut r = Map::new();
        if let Some(s) = arg(input, "since") {
            r.insert("gte".into(), json!(rfc3339(parse_time(s, now)?)));
        }
        if let Some(u) = arg(input, "until") {
            r.insert("lte".into(), json!(rfc3339(parse_time(u, now)?)));
        }
        filter.push(json!({"range": {tf: r}}));
    }
    let query = if must.is_empty() && filter.is_empty() { json!({"match_all": {}}) } else { json!({"bool": {"must": must, "filter": filter}}) };
    if input.get("count_only").and_then(Value::as_bool) == Some(true) {
        return Ok(json!({"query": query}));
    }
    let size = arg_u64(input, "size").unwrap_or(20).min(max_hits as u64);
    let mut body = json!({"query": query, "size": size, "track_total_hits": true, "sort": [{tf: {"order": if arg(input, "sort") == Some("asc") { "asc" } else { "desc" }, "unmapped_type": "date"}}]});
    let fields = arg_list(input, "fields");
    if !fields.is_empty() {
        body["_source"] = json!(fields);
    }
    if let Some(a) = input.get("aggs").filter(|a| a.is_object()) {
        body["aggs"] = a.clone();
    }
    Ok(body)
}

fn elastic(ep: &Endpoint, cfg: &Integrations, input: &Value) -> Result<Value, String> {
    let index = arg(input, "index").map(String::from).or_else(|| cfg.str("elastic", "default_index")).ok_or("`index` is required (or set [integrations.elastic] default_index)")?;
    if !valid_index(&index) {
        return Err(format!("`{index}` is not an index name or pattern"));
    }
    let allowed = cfg.list("elastic", "allow_indices");
    if !allowed.is_empty() && !index.split(',').all(|i| allowed.iter().any(|a| seagent_security::glob::fnmatch(a, i.trim()))) {
        return Err(format!("index `{index}` is outside [integrations.elastic] allow_indices"));
    }
    elastic_search_raw(ep, &index, input, cfg.u64("elastic", "max_hits").unwrap_or(100) as usize)
}

/// `_search` / `_count` on `index` and the compact hit list; shared with `siem_alerts`.
pub fn elastic_search_raw(ep: &Endpoint, index: &str, input: &Value, max_hits: usize) -> Result<Value, String> {
    let body = elastic_body(input, now_unix(), max_hits)?;
    let count_only = input.get("count_only").and_then(Value::as_bool) == Some(true);
    let path = format!("/{}/{}", crate::web::http::enc(index).replace("%2A", "*").replace("%2C", ","), if count_only { "_count" } else { "_search" });
    let v = ep.json(ep.send("POST", &path, &[], Some(&body))?)?;
    if count_only {
        return Ok(json!({"index": index, "count": v["count"]}));
    }
    let hits: Vec<Value> = v["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|h| {
            let src = h["_source"].to_string();
            let src = if src.len() > 2000 { Value::String(format!("{}…", crate::util::truncate_str(&src, 2000))) } else { h["_source"].clone() };
            json!({"_index": h["_index"], "_id": h["_id"], "source": src})
        })
        .collect();
    let mut out = json!({"index": index, "total": v["hits"]["total"]["value"].as_u64().or(v["hits"]["total"].as_u64()), "took_ms": v["took"], "hits": hits});
    if let Some(a) = v.get("aggregations") {
        out["aggregations"] = a.clone();
    }
    Ok(out)
}

fn grafana(ep: &Endpoint, input: &Value) -> Result<Value, String> {
    let action = arg(input, "action").ok_or("`action` is required")?;
    let limit = arg_u64(input, "limit").unwrap_or(30).clamp(1, 500) as usize;
    let now = now_unix();
    let uid_ok = |u: &str| !u.is_empty() && u.len() <= 128 && u.chars().all(|c| c.is_ascii_alphanumeric() || "-_".contains(c));
    match action {
        "search" => {
            let mut q = vec![("type", "dash-db".to_string()), ("limit", limit.to_string())];
            if let Some(t) = arg(input, "query") {
                q.push(("query", t.into()));
            }
            for t in arg_list(input, "tags") {
                q.push(("tag", t));
            }
            let v = ep.json(ep.get("/api/search", &q)?)?;
            Ok(json!({"dashboards": v.as_array().into_iter().flatten().map(|d| json!({"uid": d["uid"], "title": d["title"], "folder": d["folderTitle"], "tags": d["tags"], "url": d["url"]})).collect::<Vec<_>>()}))
        }
        "dashboard" => {
            let uid = arg(input, "uid").filter(|u| uid_ok(u)).ok_or("`uid` (dashboard uid) is required")?;
            let v = ep.json(ep.get(&format!("/api/dashboards/uid/{uid}"), &[])?)?;
            let mut panels = vec![];
            let mut walk = vec![v["dashboard"]["panels"].clone()];
            while let Some(Value::Array(ps)) = walk.pop() {
                for p in ps {
                    if p["type"].as_str() == Some("row") {
                        walk.push(p["panels"].clone());
                    }
                    let targets: Vec<Value> = p["targets"].as_array().into_iter().flatten().map(|t| json!({"datasource": t["datasource"]["uid"], "expr": t["expr"].as_str().or(t["query"].as_str()).or(t["rawSql"].as_str())})).collect();
                    panels.push(json!({"id": p["id"], "title": p["title"], "type": p["type"], "targets": targets}));
                }
            }
            Ok(json!({"uid": uid, "title": v["dashboard"]["title"], "variables": v["dashboard"]["templating"]["list"].as_array().map(|l| l.iter().map(|x| x["name"].clone()).collect::<Vec<_>>()), "panels": panels}))
        }
        "datasources" => {
            let v = ep.json(ep.get("/api/datasources", &[])?)?;
            Ok(json!({"datasources": v.as_array().into_iter().flatten().map(|d| json!({"uid": d["uid"], "name": d["name"], "type": d["type"], "default": d["isDefault"]})).collect::<Vec<_>>()}))
        }
        "alerts" => {
            let v = ep.json(ep.get("/api/prometheus/grafana/api/v1/alerts", &[])?)?;
            let a = v["data"]["alerts"].as_array().cloned().unwrap_or_default();
            Ok(json!({"total": a.len(), "alerts": a.iter().take(limit).map(|x| json!({"labels": x["labels"], "state": x["state"], "activeAt": x["activeAt"], "summary": x["annotations"]["summary"]})).collect::<Vec<_>>()}))
        }
        "annotations" => {
            let to = time_arg(input, "to", now)?;
            let from = time_arg(input, "from", to - 86_400)?;
            let mut q = vec![("from", format!("{from}000")), ("to", format!("{to}000")), ("limit", limit.to_string())];
            for t in arg_list(input, "tags") {
                q.push(("tags", t));
            }
            let v = ep.json(ep.get("/api/annotations", &q)?)?;
            Ok(json!({"annotations": v.as_array().into_iter().flatten().map(|a| json!({"time": a["time"].as_i64().map(|t| rfc3339(t / 1000)), "text": a["text"], "tags": a["tags"], "dashboardUID": a["dashboardUID"]})).collect::<Vec<_>>()}))
        }
        "query" => {
            let ds = arg(input, "datasource_uid").filter(|u| uid_ok(u)).ok_or("`datasource_uid` is required for action=query")?;
            let expr = arg(input, "expr").ok_or("`expr` is required for action=query")?;
            let to = time_arg(input, "to", now)?;
            let from = time_arg(input, "from", to - 3600)?;
            let body = json!({"queries": [{"refId": "A", "datasource": {"uid": ds}, "expr": expr, "maxDataPoints": 250, "intervalMs": (((to - from) / 250).max(15)) * 1000}], "from": format!("{from}000"), "to": format!("{to}000")});
            let v = ep.json(ep.post("/api/ds/query", &body)?)?;
            let r = &v["results"]["A"];
            if let Some(e) = r["error"].as_str() {
                return Err(format!("grafana query error: {e}"));
            }
            let frames: Vec<Value> = r["frames"]
                .as_array()
                .into_iter()
                .flatten()
                .take(limit)
                .map(|f| {
                    let fields: Vec<Value> = f["schema"]["fields"].as_array().into_iter().flatten().map(|x| json!({"name": x["name"], "labels": x["labels"]})).collect();
                    let cols = f["data"]["values"].as_array().cloned().unwrap_or_default();
                    let rows = cols.first().and_then(Value::as_array).map(|c| c.len()).unwrap_or(0);
                    let last: Vec<Value> = cols.iter().map(|c| c.as_array().and_then(|a| a.last().cloned()).unwrap_or(Value::Null)).collect();
                    json!({"name": f["schema"]["name"], "fields": fields, "rows": rows, "last_row": last})
                })
                .collect();
            Ok(json!({"frames": frames}))
        }
        other => Err(format!("unknown action `{other}`")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::FakeServer;

    fn tool(cfg: Value, kind: Kind) -> Query {
        Query { cfg: Arc::new(Integrations::new(cfg)), kind }
    }

    #[test]
    fn prometheus_instant_range_and_metadata_are_read_only_and_summarised() {
        let ctx = crate::testutil::ctx("ops-prom");
        let vector = json!({"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"up","job":"api"},"value":[1700000000.0,"1"]}]}});
        let pts: Vec<Value> = (0..100).map(|i| json!([1700000000.0 + i as f64 * 15.0, format!("{}", i)])).collect();
        let matrix = json!({"status":"success","data":{"resultType":"matrix","result":[{"metric":{"__name__":"rate","pod":"a"},"values":pts},{"metric":{"pod":"b"},"values":[]}]}});
        let srv = FakeServer::start(vec![
            ("GET /api/v1/query", 200, "application/json", vector.to_string()),
            ("GET /api/v1/query_range", 200, "application/json", matrix.to_string()),
            ("GET /api/v1/targets", 200, "application/json", json!({"status":"success","data":{"activeTargets":[{"labels":{"job":"api","instance":"a:1"},"health":"down","lastError":"refused"},{"labels":{},"health":"up"}]}}).to_string()),
        ]);
        let t = tool(json!({"prometheus": {"url": srv.url, "token": "{{secret:TOKEN}}"}}), Kind::Prometheus);
        assert_eq!(t.effects(&ctx, &json!({})), vec![Effect::Net { dest: srv.url.clone(), payload: String::new() }]);
        let o = t.call(&ctx, json!({"query": "up"}));
        assert!(!o.is_error && o.content.contains("up{job=\\\"api\\\"}"), "{}", o.content);
        let o = t.call(&ctx, json!({"query": "rate(x[5m])", "kind": "range", "start": "now-2h", "limit": 1}));
        assert!(!o.is_error, "{}", o.content);
        let v: Value = serde_json::from_str(&o.content).unwrap();
        assert_eq!(v["series"][0]["points"], 100);
        assert_eq!(v["series"][0]["max"], 99.0);
        assert!(v["series"][0]["sample"].as_array().unwrap().len() <= 20);
        assert!(v["note"].as_str().unwrap().contains("1 more series"));
        let r = srv.requests();
        assert!(r.iter().all(|x| x.method == "GET"));
        assert_eq!(r[1].query("step").as_deref(), Some("28s"));
        let o = t.call(&ctx, json!({"kind": "targets"}));
        assert!(o.content.contains("\"unhealthy\": 1") && o.content.contains("refused"), "{}", o.content);
        assert!(t.call(&ctx, json!({"kind": "range", "query": "x", "step": "1s", "start": "now-30d"})).is_error);
    }

    #[test]
    fn loki_streams_through_the_grafana_proxy_newest_first_and_capped() {
        let ctx = crate::testutil::ctx("ops-loki");
        let streams = json!({"status":"success","data":{"resultType":"streams","result":[
            {"stream":{"app":"api"},"values":[["1700000001000000000","old error"],["1700000003000000000","new error"]]},
            {"stream":{"app":"web"},"values":[["1700000002000000000","mid error"]]}]}});
        let srv = FakeServer::start(vec![("GET /api/datasources/proxy/uid/lk/loki/api/v1/query_range", 200, "application/json", streams.to_string())]);
        let t = tool(json!({"grafana": {"url": srv.url, "token": "{{secret:TOKEN}}"}, "loki": {"via_grafana": "lk", "max_output_chars": 1000}}), Kind::Loki);
        let o = t.call(&ctx, json!({"query": "{app=~\".+\"} |= \"error\"", "limit": 2}));
        assert!(!o.is_error, "{}", o.content);
        let v: Value = serde_json::from_str(&o.content).unwrap();
        assert_eq!(v["lines"], 2);
        assert_eq!(v["entries"][0]["line"], "new error");
        assert_eq!(v["entries"][1]["line"], "mid error");
        let req = srv.last();
        assert_eq!(req.header("authorization").as_deref(), Some("Bearer s3cr3t"));
        assert_eq!(req.query("direction").as_deref(), Some("backward"));
        assert!(req.query("start").unwrap().ends_with("000000000"));
    }

    #[test]
    fn alertmanager_filters_and_output_cap_spills() {
        let ctx = crate::testutil::ctx("ops-am");
        let alerts: Vec<Value> = (0..200).map(|i| json!({"labels":{"alertname":format!("A{i}"),"severity":"page"},"annotations":{"summary":"x".repeat(100)},"status":{"state":"active"},"startsAt":format!("2026-11-05T10:{:02}:00Z", i % 60),"fingerprint":format!("f{i}")})).collect();
        let srv = FakeServer::start(vec![("GET /api/v2/alerts", 200, "application/json", Value::Array(alerts).to_string())]);
        let t = tool(json!({"alertmanager": {"url": srv.url, "max_output_chars": 2000}}), Kind::Alertmanager);
        let o = t.call(&ctx, json!({"filter": ["severity=\"page\""], "active": true, "limit": 100}));
        assert!(!o.is_error);
        assert!(o.content.contains("[truncated:") && o.content.contains("/ops/alertmanager_alerts-"), "{}", &o.content[o.content.len() - 300..]);
        let req = srv.last();
        assert_eq!(req.query("filter").as_deref(), Some("severity=\"page\""));
        assert_eq!(req.query("active").as_deref(), Some("true"));
    }

    #[test]
    fn elastic_builds_a_bounded_search_and_refuses_api_paths() {
        let b = elastic_body(&json!({"query": "level:error", "since": "now-1h", "size": 5000, "fields": ["message"]}), 1_800_000_000, 100).unwrap();
        assert_eq!(b["size"], 100);
        assert_eq!(b["query"]["bool"]["must"][0]["query_string"]["query"], "level:error");
        assert_eq!(b["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"], rfc3339(1_800_000_000 - 3600));
        assert_eq!(b["_source"][0], "message");
        assert!(valid_index("logs-*,metrics-app") && valid_index(".alerts-security.alerts-default"));
        assert!(!valid_index("_all") && !valid_index("logs/_delete_by_query") && !valid_index("a,_cluster") && !valid_index(""));
        let ctx = crate::testutil::ctx("ops-es");
        let srv = FakeServer::start(vec![("POST /logs-*/_search", 200, "application/json", json!({"took":3,"hits":{"total":{"value":1},"hits":[{"_index":"logs-1","_id":"x","_source":{"message":"boom"}}]}}).to_string())]);
        let t = tool(json!({"elastic": {"url": srv.url, "user": "ro", "password": "{{secret:TOKEN}}", "allow_indices": ["logs-*"]}}), Kind::Elastic);
        let o = t.call(&ctx, json!({"index": "logs-*", "query": "boom"}));
        assert!(!o.is_error && o.content.contains("boom"), "{}", o.content);
        assert!(srv.last().header("authorization").unwrap().starts_with("Basic "));
        assert!(t.call(&ctx, json!({"index": "secrets"})).content.contains("allow_indices"));
        assert!(t.call(&ctx, json!({"index": "_security"})).is_error);
    }

    #[test]
    fn grafana_search_dashboard_and_datasource_query() {
        let ctx = crate::testutil::ctx("ops-grafana");
        let srv = FakeServer::start(vec![
            ("GET /api/search", 200, "application/json", json!([{"uid":"d1","title":"API","folderTitle":"Prod","tags":["api"]}]).to_string()),
            ("GET /api/dashboards/uid/d1", 200, "application/json", json!({"dashboard":{"title":"API","panels":[{"id":1,"type":"row","panels":[{"id":2,"title":"Latency","type":"timeseries","targets":[{"datasource":{"uid":"prom"},"expr":"histogram_quantile(0.99, x)"}]}]}]}}).to_string()),
            ("POST /api/ds/query", 200, "application/json", json!({"results":{"A":{"frames":[{"schema":{"name":"up","fields":[{"name":"Time"},{"name":"Value","labels":{"job":"api"}}]},"data":{"values":[[1,2],[0,1]]}}]}}}).to_string()),
        ]);
        let t = tool(json!({"grafana": {"url": srv.url, "token": "{{secret:TOKEN}}", "org_id": "2"}}), Kind::Grafana);
        assert!(t.call(&ctx, json!({"action": "search", "query": "api"})).content.contains("\"uid\": \"d1\""));
        let o = t.call(&ctx, json!({"action": "dashboard", "uid": "d1"}));
        assert!(o.content.contains("histogram_quantile") && o.content.contains("Latency"), "{}", o.content);
        let o = t.call(&ctx, json!({"action": "query", "datasource_uid": "prom", "expr": "up"}));
        assert!(o.content.contains("\"rows\": 2"), "{}", o.content);
        assert_eq!(srv.last().header("x-grafana-org-id").as_deref(), Some("2"));
        assert!(t.call(&ctx, json!({"action": "dashboard", "uid": "../admin"})).is_error);
    }
}
