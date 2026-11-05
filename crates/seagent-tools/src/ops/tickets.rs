//! Native ticket / incident integrations (ent-105 Jira incl. Jira Service Management, ent-106
//! ServiceNow, ent-107 PagerDuty).
//!
//! * `jira` — search (JQL), get, create, comment, transitions / transition, and JSM customer
//!   requests (`jsm_create`, `jsm_get`). Cloud (`email` + API token, basic) and Data Center
//!   (personal access token, bearer); `api_version = 3` sends Atlassian Document Format.
//! * `servicenow` — Table API search (encoded query) / get / create / update / comment on an
//!   allowlisted set of tables (`tables`, writes limited to `write_tables`).
//! * `pagerduty` — REST incidents list / get / create / acknowledge / resolve (`token`, `from`)
//!   and Events API v2 trigger / acknowledge / resolve by `dedup_key` (`routing_key`).
//!
//! Credentials are vault references (`token = "{{secret:JIRA_TOKEN}}"`). Reads declare a
//! network read; writes declare the text they send, so the kernel's tiers treat a ticket
//! write to a host that is not allowlisted as tier 2 (add the host to `[gate] egress_allow`
//! to make it tier 1, run-and-audit). Inbound PagerDuty / Jira webhooks are verified by the
//! webhook channel (`scheme = "pagerduty"` / `"jira"`).

use super::client::{secret, Auth, Endpoint};
use super::{arg, arg_list, arg_u64, cap_output, now_unix, parse_time, rfc3339, Integrations};
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::sync::Arc;

pub fn tools(cfg: &Arc<Integrations>) -> Vec<Arc<dyn Tool>> {
    let mut out: Vec<Arc<dyn Tool>> = vec![];
    if cfg.has_endpoint("jira") {
        out.push(Arc::new(Jira { cfg: cfg.clone() }));
    }
    if cfg.has_endpoint("servicenow") {
        out.push(Arc::new(ServiceNow { cfg: cfg.clone() }));
    }
    if cfg.enabled("pagerduty") && (cfg.str("pagerduty", "token").is_some() || cfg.str("pagerduty", "routing_key").is_some()) {
        out.push(Arc::new(PagerDuty { cfg: cfg.clone() }));
    }
    out
}

fn net(dest: String, payload: String) -> Vec<Effect> {
    vec![Effect::Net { dest, payload }]
}

fn base_of(cfg: &Integrations, id: &str, default: &str) -> String {
    cfg.str(id, "url").or_else(|| cfg.str(id, "base_url")).unwrap_or_else(|| default.to_string())
}

fn done(ctx: &ToolCtx, tool: &str, max: usize, r: Result<Value, String>) -> ToolOutput {
    match r {
        Ok(v) => ToolOutput::ok(cap_output(ctx, tool, serde_json::to_string_pretty(&v).unwrap_or_default(), max)),
        Err(e) => ToolOutput::err(e),
    }
}

/// Every write leaves a record in the audit stream (who, what, where), success or not.
fn audit_write(ctx: &ToolCtx, kind: &str, target: &str, ok: bool, detail: Value) {
    let ev = seagent_security::audit::Event::new(kind, seagent_security::audit::Actor::new("agent", &ctx.session_id), target, if ok { "ok" } else { "error" }).session(&ctx.session_id).detail(detail);
    seagent_security::audit::record(&ctx.home, ev);
}

// ───────────────────────────── Jira ─────────────────────────────

pub struct Jira {
    pub cfg: Arc<Integrations>,
}

pub fn jira_key_ok(k: &str) -> bool {
    let Some((p, n)) = k.split_once('-') else { return false };
    p.len() >= 2 && p.len() <= 30 && p.starts_with(|c: char| c.is_ascii_uppercase()) && p.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') && !n.is_empty() && n.len() <= 10 && n.chars().all(|c| c.is_ascii_digit())
}

/// Plain text → Atlassian Document Format (one paragraph per blank-line-separated block).
pub fn adf(text: &str) -> Value {
    let paras: Vec<Value> = text.split("\n\n").filter(|p| !p.trim().is_empty()).map(|p| json!({"type": "paragraph", "content": [{"type": "text", "text": p.trim()}]})).collect();
    json!({"type": "doc", "version": 1, "content": paras})
}

const JIRA_WRITES: &[&str] = &["create", "comment", "transition", "jsm_create"];

impl Jira {
    fn v3(&self) -> bool {
        self.cfg.str("jira", "api_version").as_deref() == Some("3")
    }
    fn text(&self, s: &str) -> Value {
        if self.v3() { adf(s) } else { json!(s) }
    }
    fn api(&self) -> &'static str {
        if self.v3() { "/rest/api/3" } else { "/rest/api/2" }
    }
    fn brief(issue: &Value) -> Value {
        let f = &issue["fields"];
        json!({"key": issue["key"], "summary": f["summary"], "status": f["status"]["name"], "priority": f["priority"]["name"], "assignee": f["assignee"]["displayName"], "type": f["issuetype"]["name"], "updated": f["updated"], "labels": f["labels"]})
    }
    fn key(input: &Value) -> Result<&str, String> {
        arg(input, "key").filter(|k| jira_key_ok(k)).ok_or_else(|| "`key` must be an issue key like OPS-123".to_string())
    }
    fn run(&self, ep: &Endpoint, input: &Value, ctx: &ToolCtx) -> Result<Value, String> {
        let action = arg(input, "action").ok_or("`action` is required")?;
        let api = self.api();
        match action {
            "search" => {
                let jql = arg(input, "jql").ok_or("`jql` is required")?;
                let limit = arg_u64(input, "limit").unwrap_or(20).clamp(1, 100);
                let path = if self.v3() { format!("{api}/search/jql") } else { format!("{api}/search") };
                let v = ep.json(ep.get(&path, &[("jql", jql.into()), ("maxResults", limit.to_string()), ("fields", "summary,status,priority,assignee,issuetype,updated,labels".into())])?)?;
                Ok(json!({"total": v["total"], "issues": v["issues"].as_array().into_iter().flatten().map(Self::brief).collect::<Vec<_>>()}))
            }
            "get" => {
                let key = Self::key(input)?;
                let v = ep.json(ep.get(&format!("{api}/issue/{key}"), &[("fields", "summary,status,priority,assignee,issuetype,updated,labels,description,comment,created,reporter".into())])?)?;
                let mut b = Self::brief(&v);
                let desc = &v["fields"]["description"];
                b["description"] = if desc.is_string() { desc.clone() } else { json!(adf_text(desc)) };
                b["comments"] = json!(v["fields"]["comment"]["comments"].as_array().into_iter().flatten().rev().take(10).map(|c| json!({"author": c["author"]["displayName"], "created": c["created"], "body": if c["body"].is_string() { c["body"].clone() } else { json!(adf_text(&c["body"])) }})).collect::<Vec<_>>());
                Ok(b)
            }
            "create" => {
                let project = arg(input, "project").map(String::from).or_else(|| self.cfg.str("jira", "default_project")).ok_or("`project` is required (or set [integrations.jira] default_project)")?;
                let allow = self.cfg.list("jira", "allow_projects");
                if !allow.is_empty() && !allow.contains(&project) {
                    return Err(format!("project `{project}` is not in [integrations.jira] allow_projects"));
                }
                let summary = arg(input, "summary").ok_or("`summary` is required")?;
                let mut fields = json!({"project": {"key": project}, "summary": summary, "issuetype": {"name": arg(input, "issuetype").unwrap_or("Task")}});
                if let Some(d) = arg(input, "description") {
                    fields["description"] = self.text(d);
                }
                let labels = arg_list(input, "labels");
                if !labels.is_empty() {
                    fields["labels"] = json!(labels);
                }
                if let Some(p) = arg(input, "priority") {
                    fields["priority"] = json!({"name": p});
                }
                let r = ep.post(&format!("{api}/issue"), &json!({"fields": fields})).and_then(|r| ep.json(r));
                audit_write(ctx, "ticket.create", &format!("jira:{project}"), r.is_ok(), json!({"summary": summary, "key": r.as_ref().ok().map(|v| v["key"].clone())}));
                let v = r?;
                Ok(json!({"created": v["key"], "url": format!("{}/browse/{}", ep.base, v["key"].as_str().unwrap_or(""))}))
            }
            "comment" => {
                let key = Self::key(input)?;
                let body = arg(input, "body").ok_or("`body` is required")?;
                let r = ep.post(&format!("{api}/issue/{key}/comment"), &json!({"body": self.text(body)})).and_then(|r| ep.json(r));
                audit_write(ctx, "ticket.comment", &format!("jira:{key}"), r.is_ok(), json!({"chars": body.len()}));
                Ok(json!({"commented": key, "id": r?["id"]}))
            }
            "transitions" => {
                let key = Self::key(input)?;
                let v = ep.json(ep.get(&format!("{api}/issue/{key}/transitions"), &[])?)?;
                Ok(json!({"key": key, "transitions": v["transitions"].as_array().into_iter().flatten().map(|t| json!({"id": t["id"], "name": t["name"], "to": t["to"]["name"]})).collect::<Vec<_>>()}))
            }
            "transition" => {
                let key = Self::key(input)?;
                let want = arg(input, "transition").ok_or("`transition` (name or id) is required")?;
                let v = ep.json(ep.get(&format!("{api}/issue/{key}/transitions"), &[])?)?;
                let t = v["transitions"].as_array().into_iter().flatten().find(|t| t["id"].as_str() == Some(want) || t["name"].as_str().is_some_and(|n| n.eq_ignore_ascii_case(want)) || t["to"]["name"].as_str().is_some_and(|n| n.eq_ignore_ascii_case(want))).cloned();
                let Some(t) = t else {
                    let names: Vec<&str> = v["transitions"].as_array().into_iter().flatten().filter_map(|t| t["name"].as_str()).collect();
                    return Err(format!("no transition `{want}` on {key}; available: {}", names.join(", ")));
                };
                let mut body = json!({"transition": {"id": t["id"]}});
                if let Some(c) = arg(input, "body") {
                    body["update"] = json!({"comment": [{"add": {"body": self.text(c)}}]});
                }
                let r = ep.send("POST", &format!("{api}/issue/{key}/transitions"), &[], Some(&body)).and_then(|r| ep.json(r));
                audit_write(ctx, "ticket.transition", &format!("jira:{key}"), r.is_ok(), json!({"to": t["to"]["name"]}));
                r?;
                Ok(json!({"key": key, "transitioned_to": t["to"]["name"]}))
            }
            "jsm_create" => {
                let sd = arg(input, "service_desk_id").ok_or("`service_desk_id` is required")?;
                let rt = arg(input, "request_type_id").ok_or("`request_type_id` is required")?;
                let summary = arg(input, "summary").ok_or("`summary` is required")?;
                let body = json!({"serviceDeskId": sd, "requestTypeId": rt, "requestFieldValues": {"summary": summary, "description": arg(input, "description").unwrap_or("")}});
                let r = ep.post("/rest/servicedeskapi/request", &body).and_then(|r| ep.json(r));
                audit_write(ctx, "ticket.create", &format!("jsm:{sd}"), r.is_ok(), json!({"summary": summary}));
                let v = r?;
                Ok(json!({"created": v["issueKey"], "status": v["currentStatus"]["status"], "portal": v["_links"]["web"]}))
            }
            "jsm_get" => {
                let key = Self::key(input)?;
                let v = ep.json(ep.get(&format!("/rest/servicedeskapi/request/{key}"), &[])?)?;
                Ok(json!({"key": v["issueKey"], "status": v["currentStatus"]["status"], "reporter": v["reporter"]["displayName"], "created": v["createdDate"]["iso8601"], "fields": v["requestFieldValues"].as_array().map(|a| a.iter().map(|f| json!({"field": f["label"], "value": f["value"]})).collect::<Vec<_>>())}))
            }
            other => Err(format!("unknown action `{other}`")),
        }
    }
}

/// The plain text of an ADF document.
pub fn adf_text(v: &Value) -> String {
    let mut out = String::new();
    fn walk(v: &Value, out: &mut String) {
        if let Some(t) = v["text"].as_str() {
            out.push_str(t);
        }
        for c in v["content"].as_array().into_iter().flatten() {
            walk(c, out);
        }
        if v["type"].as_str() == Some("paragraph") {
            out.push('\n');
        }
    }
    walk(v, &mut out);
    out.trim().to_string()
}

impl Tool for Jira {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "jira".into(),
            description: "Jira / Jira Service Management. Reads: action=search (jql), get (key), transitions (key), jsm_get (key). Writes (audited, approval tiers apply): create (project, summary, description, issuetype, labels, priority), comment (key, body), transition (key, transition name/id, optional body), jsm_create (service_desk_id, request_type_id, summary, description).".into(),
            input_schema: json!({"type":"object","properties":{
                "action":{"type":"string","enum":["search","get","create","comment","transitions","transition","jsm_create","jsm_get"]},
                "jql":{"type":"string"},"key":{"type":"string"},"limit":{"type":"integer"},"project":{"type":"string"},"summary":{"type":"string"},"description":{"type":"string"},
                "issuetype":{"type":"string"},"labels":{"type":"array","items":{"type":"string"}},"priority":{"type":"string"},"body":{"type":"string"},"transition":{"type":"string"},
                "service_desk_id":{"type":"string"},"request_type_id":{"type":"string"}},"required":["action"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let action = arg(input, "action").unwrap_or("");
        let payload = if JIRA_WRITES.contains(&action) { ["summary", "description", "body", "transition"].iter().filter_map(|k| arg(input, k)).collect::<Vec<_>>().join("\n") } else { String::new() };
        net(base_of(&self.cfg, "jira", ""), payload)
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let ep = match Endpoint::from_config(&self.cfg, "jira", None, ctx) {
            Ok(e) => e,
            Err(e) => return ToolOutput::err(e),
        };
        done(ctx, "jira", ep.max_output, self.run(&ep, &input, ctx))
    }
}

// ───────────────────────────── ServiceNow ─────────────────────────────

pub struct ServiceNow {
    pub cfg: Arc<Integrations>,
}

const SN_READ: &[&str] = &["incident", "problem", "change_request", "sc_request", "sc_req_item", "task", "cmdb_ci", "sys_user_group", "kb_knowledge"];
const SN_WRITE: &[&str] = &["incident", "problem", "change_request"];

fn sys_id_ok(s: &str) -> bool {
    s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
}

impl ServiceNow {
    fn tables(&self, key: &str, default: &[&str]) -> Vec<String> {
        let l = self.cfg.list("servicenow", key);
        if l.is_empty() { default.iter().map(|s| s.to_string()).collect() } else { l }
    }
    fn table(&self, input: &Value, write: bool) -> Result<String, String> {
        let t = arg(input, "table").unwrap_or("incident").to_string();
        let allow = if write { self.tables("write_tables", SN_WRITE) } else { self.tables("tables", SN_READ) };
        if !allow.contains(&t) {
            return Err(format!("table `{t}` is not allowed for {} ([integrations.servicenow] {}: {})", if write { "writes" } else { "reads" }, if write { "write_tables" } else { "tables" }, allow.join(", ")));
        }
        Ok(t)
    }
    fn brief(r: &Value) -> Value {
        let mut o = json!({});
        for k in ["number", "sys_id", "short_description", "state", "priority", "urgency", "impact", "assignment_group", "assigned_to", "opened_at", "sys_updated_on", "cmdb_ci", "category"] {
            if let Some(v) = r.get(k).filter(|v| !v.is_null() && v.as_str() != Some("")) {
                o[k] = v.clone();
            }
        }
        o
    }
    fn run(&self, ep: &Endpoint, input: &Value, ctx: &ToolCtx) -> Result<Value, String> {
        let action = arg(input, "action").ok_or("`action` is required")?;
        let common = [("sysparm_display_value", "true".to_string()), ("sysparm_exclude_reference_link", "true".to_string())];
        let fields_obj = || input.get("fields").filter(|f| f.is_object()).cloned().ok_or("`fields` (object of column → value) is required");
        match action {
            "search" => {
                let t = self.table(input, false)?;
                let limit = arg_u64(input, "limit").unwrap_or(20).clamp(1, 200);
                let mut q: Vec<(&str, String)> = common.to_vec();
                q.push(("sysparm_limit", limit.to_string()));
                q.push(("sysparm_query", arg(input, "query").unwrap_or("active=true^ORDERBYDESCsys_updated_on").to_string()));
                let v = ep.json(ep.get(&format!("/api/now/table/{t}"), &q)?)?;
                Ok(json!({"table": t, "records": v["result"].as_array().into_iter().flatten().map(Self::brief).collect::<Vec<_>>()}))
            }
            "get" => {
                let t = self.table(input, false)?;
                let v = if let Some(id) = arg(input, "sys_id") {
                    if !sys_id_ok(id) {
                        return Err("`sys_id` must be 32 hex characters".into());
                    }
                    ep.json(ep.get(&format!("/api/now/table/{t}/{id}"), &common)?)?["result"].clone()
                } else {
                    let n = arg(input, "number").filter(|n| n.chars().all(|c| c.is_ascii_alphanumeric())).ok_or("`sys_id` or `number` is required")?;
                    let mut q = common.to_vec();
                    q.push(("sysparm_query", format!("number={n}")));
                    q.push(("sysparm_limit", "1".into()));
                    ep.json(ep.get(&format!("/api/now/table/{t}"), &q)?)?["result"][0].clone()
                };
                if v.is_null() {
                    return Err("record not found".into());
                }
                let mut b = Self::brief(&v);
                for k in ["description", "close_notes", "work_notes", "comments"] {
                    if let Some(x) = v.get(k).and_then(Value::as_str).filter(|s| !s.is_empty()) {
                        b[k] = json!(crate::util::truncate_str(x, 4000));
                    }
                }
                Ok(b)
            }
            "create" => {
                let t = self.table(input, true)?;
                let f = fields_obj()?;
                let r = ep.post(&format!("/api/now/table/{t}"), &f).and_then(|r| ep.json(r));
                audit_write(ctx, "ticket.create", &format!("servicenow:{t}"), r.is_ok(), json!({"short_description": f["short_description"]}));
                let v = r?;
                Ok(json!({"created": v["result"]["number"], "sys_id": v["result"]["sys_id"]}))
            }
            "update" | "comment" => {
                let t = self.table(input, true)?;
                let id = arg(input, "sys_id").filter(|s| sys_id_ok(s)).ok_or("`sys_id` (32 hex) is required")?;
                let body = if action == "comment" {
                    let text = arg(input, "text").ok_or("`text` is required")?;
                    let col = if input.get("work_note").and_then(Value::as_bool) == Some(true) { "work_notes" } else { "comments" };
                    json!({col: text})
                } else {
                    fields_obj()?
                };
                let r = ep.send("PATCH", &format!("/api/now/table/{t}/{id}"), &[], Some(&body)).and_then(|r| ep.json(r));
                audit_write(ctx, &format!("ticket.{action}"), &format!("servicenow:{t}/{id}"), r.is_ok(), json!({"columns": body.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>())}));
                let v = r?;
                Ok(json!({"updated": v["result"]["number"], "state": v["result"]["state"]}))
            }
            other => Err(format!("unknown action `{other}`")),
        }
    }
}

impl Tool for ServiceNow {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "servicenow".into(),
            description: "ServiceNow Table API. Reads: action=search (table, encoded `query`, limit), get (table, sys_id or number). Writes (audited, approval tiers apply; only allowlisted tables): create (table, fields), update (table, sys_id, fields), comment (table, sys_id, text, work_note=true for an internal note). Default table: incident.".into(),
            input_schema: json!({"type":"object","properties":{
                "action":{"type":"string","enum":["search","get","create","update","comment"]},
                "table":{"type":"string"},"query":{"type":"string","description":"encoded query, e.g. active=true^priority=1"},"limit":{"type":"integer"},
                "sys_id":{"type":"string"},"number":{"type":"string"},"fields":{"type":"object"},"text":{"type":"string"},"work_note":{"type":"boolean"}},"required":["action"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let action = arg(input, "action").unwrap_or("");
        let payload = match action {
            "create" | "update" => input.get("fields").map(|f| f.to_string()).unwrap_or_default(),
            "comment" => arg(input, "text").unwrap_or("").to_string(),
            _ => String::new(),
        };
        net(base_of(&self.cfg, "servicenow", ""), payload)
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let ep = match Endpoint::from_config(&self.cfg, "servicenow", None, ctx) {
            Ok(e) => e,
            Err(e) => return ToolOutput::err(e),
        };
        done(ctx, "servicenow", ep.max_output, self.run(&ep, &input, ctx))
    }
}

// ───────────────────────────── PagerDuty ─────────────────────────────

pub struct PagerDuty {
    pub cfg: Arc<Integrations>,
}

const PD_API: &str = "https://api.pagerduty.com";
const PD_EVENTS: &str = "https://events.pagerduty.com";

fn pd_id_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.chars().all(|c| c.is_ascii_alphanumeric())
}

impl PagerDuty {
    fn rest(&self, ctx: &ToolCtx) -> Result<Endpoint, String> {
        let mut c = (*self.cfg).clone();
        // The REST key goes in `Authorization: Token token=…`, not as a bearer.
        if let Some(Value::Object(s)) = c.0.get_mut("pagerduty") {
            s.remove("token");
            s.insert("auth".into(), json!("none"));
            if !s.contains_key("url") {
                s.insert("url".into(), json!(self.cfg.str("pagerduty", "api_url").unwrap_or_else(|| PD_API.into())));
            }
        }
        let mut ep = Endpoint::from_config(&c, "pagerduty", Some(PD_API), ctx)?;
        let tok = self.cfg.str("pagerduty", "token").ok_or("[integrations.pagerduty] token is required for REST actions")?;
        ep.auth = Auth::Header("Authorization".into(), format!("Token token={}", secret(ctx, &tok)?));
        if let Some(f) = self.cfg.str("pagerduty", "from") {
            ep.headers.push(("From".into(), f));
        }
        Ok(ep)
    }
    fn events(&self, ctx: &ToolCtx) -> Result<(Endpoint, String), String> {
        let mut c = (*self.cfg).clone();
        if let Some(Value::Object(s)) = c.0.get_mut("pagerduty") {
            s.remove("token");
            s.insert("auth".into(), json!("none"));
            s.insert("url".into(), json!(self.cfg.str("pagerduty", "events_url").unwrap_or_else(|| PD_EVENTS.into())));
        }
        let ep = Endpoint::from_config(&c, "pagerduty", Some(PD_EVENTS), ctx)?;
        let rk = self.cfg.str("pagerduty", "routing_key").ok_or("[integrations.pagerduty] routing_key (an Events API v2 integration key) is required for events")?;
        Ok((ep, secret(ctx, &rk)?))
    }
    fn brief(i: &Value) -> Value {
        json!({"id": i["id"], "number": i["incident_number"], "title": i["title"], "status": i["status"], "urgency": i["urgency"], "service": i["service"]["summary"], "created_at": i["created_at"], "assignees": i["assignments"].as_array().map(|a| a.iter().map(|x| x["assignee"]["summary"].clone()).collect::<Vec<_>>()), "url": i["html_url"]})
    }
    fn run(&self, ctx: &ToolCtx, input: &Value) -> Result<Value, String> {
        let action = arg(input, "action").ok_or("`action` is required")?;
        match action {
            "incidents" => {
                let ep = self.rest(ctx)?;
                let mut q: Vec<(&str, String)> = vec![("limit", arg_u64(input, "limit").unwrap_or(25).clamp(1, 100).to_string())];
                let statuses = arg_list(input, "statuses");
                for s in if statuses.is_empty() { vec!["triggered".to_string(), "acknowledged".to_string()] } else { statuses } {
                    q.push(("statuses[]", s));
                }
                for s in arg_list(input, "service_ids") {
                    q.push(("service_ids[]", s));
                }
                if let Some(s) = arg(input, "since") {
                    q.push(("since", rfc3339(parse_time(s, now_unix())?)));
                }
                let v = ep.json(ep.get("/incidents", &q)?)?;
                Ok(json!({"incidents": v["incidents"].as_array().into_iter().flatten().map(Self::brief).collect::<Vec<_>>(), "more": v["more"]}))
            }
            "incident" => {
                let ep = self.rest(ctx)?;
                let id = arg(input, "incident_id").filter(|i| pd_id_ok(i)).ok_or("`incident_id` is required")?;
                let v = ep.json(ep.get(&format!("/incidents/{id}"), &[])?)?;
                let log = ep.json(ep.get(&format!("/incidents/{id}/log_entries"), &[("limit", "25".into()), ("is_overview", "true".into())])?)?;
                let mut b = Self::brief(&v["incident"]);
                b["timeline"] = json!(log["log_entries"].as_array().into_iter().flatten().map(|e| json!({"at": e["created_at"], "type": e["type"], "summary": e["summary"]})).collect::<Vec<_>>());
                Ok(b)
            }
            "create_incident" => {
                let ep = self.rest(ctx)?;
                if !ep.headers.iter().any(|(k, _)| k == "From") {
                    return Err("[integrations.pagerduty] from (the PagerDuty user's email) is required to create or update incidents".into());
                }
                let title = arg(input, "title").or(arg(input, "summary")).ok_or("`title` is required")?;
                let svc = arg(input, "service_id").map(String::from).or_else(|| self.cfg.str("pagerduty", "service_id")).filter(|s| pd_id_ok(s)).ok_or("`service_id` is required")?;
                let mut inc = json!({"type": "incident", "title": title, "service": {"id": svc, "type": "service_reference"}, "urgency": arg(input, "urgency").unwrap_or("high")});
                if let Some(d) = arg(input, "details") {
                    inc["body"] = json!({"type": "incident_body", "details": d});
                }
                if let Some(k) = arg(input, "dedup_key") {
                    inc["incident_key"] = json!(k);
                }
                let r = ep.post("/incidents", &json!({"incident": inc})).and_then(|r| ep.json(r));
                audit_write(ctx, "incident.create", &format!("pagerduty:{svc}"), r.is_ok(), json!({"title": title}));
                Ok(Self::brief(&r?["incident"]))
            }
            "acknowledge" | "resolve" | "trigger" if action == "trigger" || arg(input, "incident_id").is_none() => {
                let (ep, rk) = self.events(ctx)?;
                let mut ev = json!({"routing_key": rk, "event_action": action});
                if let Some(k) = arg(input, "dedup_key") {
                    ev["dedup_key"] = json!(k);
                } else if action != "trigger" {
                    return Err("`dedup_key` (or `incident_id`) is required to acknowledge / resolve".into());
                }
                if action == "trigger" {
                    let summary = arg(input, "summary").or(arg(input, "title")).ok_or("`summary` is required")?;
                    let sev = arg(input, "severity").unwrap_or("error");
                    if !["critical", "error", "warning", "info"].contains(&sev) {
                        return Err("severity: critical, error, warning or info".into());
                    }
                    ev["payload"] = json!({"summary": crate::util::truncate_str(summary, 1024), "source": arg(input, "source").unwrap_or("seagent"), "severity": sev, "component": arg(input, "component"), "group": arg(input, "group"), "class": arg(input, "class"), "custom_details": input.get("custom_details").cloned().unwrap_or(Value::Null)});
                }
                let r = ep.post("/v2/enqueue", &ev).and_then(|r| ep.json(r));
                let r = r.map_err(|e| e.replace(&rk, "***"));
                audit_write(ctx, &format!("incident.{action}"), "pagerduty:events", r.is_ok(), json!({"dedup_key": ev["dedup_key"], "summary": ev["payload"]["summary"]}));
                let v = r?;
                Ok(json!({"status": v["status"], "dedup_key": v["dedup_key"], "message": v["message"]}))
            }
            "acknowledge" | "resolve" => {
                let ep = self.rest(ctx)?;
                if !ep.headers.iter().any(|(k, _)| k == "From") {
                    return Err("[integrations.pagerduty] from (the PagerDuty user's email) is required to update incidents".into());
                }
                let id = arg(input, "incident_id").filter(|i| pd_id_ok(i)).ok_or("bad `incident_id`")?;
                let status = if action == "acknowledge" { "acknowledged" } else { "resolved" };
                let mut body = json!({"incident": {"type": "incident_reference", "status": status}});
                if let Some(n) = arg(input, "resolution").filter(|_| status == "resolved") {
                    body["incident"]["resolution"] = json!(n);
                }
                let r = ep.send("PUT", &format!("/incidents/{id}"), &[], Some(&body)).and_then(|r| ep.json(r));
                audit_write(ctx, &format!("incident.{action}"), &format!("pagerduty:{id}"), r.is_ok(), json!({}));
                Ok(Self::brief(&r?["incident"]))
            }
            other => Err(format!("unknown action `{other}`")),
        }
    }
}

impl Tool for PagerDuty {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "pagerduty".into(),
            description: "PagerDuty. Reads: action=incidents (open incidents; statuses, service_ids, since), incident (incident_id: details + timeline). Writes (audited, approval tiers apply): trigger (Events v2: summary, source, severity, dedup_key, custom_details), acknowledge / resolve (dedup_key via Events v2, or incident_id via REST), create_incident (title, service_id, urgency, details).".into(),
            input_schema: json!({"type":"object","properties":{
                "action":{"type":"string","enum":["incidents","incident","trigger","acknowledge","resolve","create_incident"]},
                "incident_id":{"type":"string"},"dedup_key":{"type":"string"},"summary":{"type":"string"},"title":{"type":"string"},"source":{"type":"string"},
                "severity":{"type":"string","enum":["critical","error","warning","info"]},"component":{"type":"string"},"group":{"type":"string"},"class":{"type":"string"},
                "custom_details":{"type":"object"},"service_id":{"type":"string"},"urgency":{"type":"string","enum":["high","low"]},"details":{"type":"string"},"resolution":{"type":"string"},
                "statuses":{"type":"array","items":{"type":"string"}},"service_ids":{"type":"array","items":{"type":"string"}},"since":{"type":"string"},"limit":{"type":"integer"}},"required":["action"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let action = arg(input, "action").unwrap_or("");
        let events = matches!(action, "trigger") || (matches!(action, "acknowledge" | "resolve") && arg(input, "incident_id").is_none());
        let dest = if events { self.cfg.str("pagerduty", "events_url").unwrap_or_else(|| PD_EVENTS.into()) } else { base_of(&self.cfg, "pagerduty", &self.cfg.str("pagerduty", "api_url").unwrap_or_else(|| PD_API.into())) };
        let payload = match action {
            "incidents" | "incident" => String::new(),
            _ => ["summary", "title", "details", "resolution", "dedup_key", "incident_id"].iter().filter_map(|k| arg(input, k)).collect::<Vec<_>>().join("\n") + &format!(" ({action})"),
        };
        net(dest, payload)
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        done(ctx, "pagerduty", self.cfg.u64("pagerduty", "max_output_chars").map(|m| m as usize).unwrap_or(super::client::DEFAULT_MAX_OUTPUT), self.run(ctx, &input))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::FakeServer;

    #[test]
    fn jira_search_create_transition_against_a_fake_server() {
        let ctx = crate::testutil::ctx("tickets-jira");
        let srv = FakeServer::start(vec![
            ("GET /rest/api/2/search", 200, "application/json", json!({"total":1,"issues":[{"key":"OPS-1","fields":{"summary":"disk full","status":{"name":"Open"},"priority":{"name":"High"}}}]}).to_string()),
            ("POST /rest/api/2/issue", 201, "application/json", json!({"key":"OPS-2","id":"10"}).to_string()),
            ("GET /rest/api/2/issue/OPS-2/transitions", 200, "application/json", json!({"transitions":[{"id":"31","name":"Resolve","to":{"name":"Done"}}]}).to_string()),
            ("POST /rest/api/2/issue/OPS-2/transitions", 204, "application/json", String::new()),
            ("POST /rest/servicedeskapi/request", 201, "application/json", json!({"issueKey":"HD-9","currentStatus":{"status":"Waiting for support"}}).to_string()),
        ]);
        let t = Jira { cfg: Arc::new(Integrations::new(json!({"jira": {"url": srv.url, "email": "bot@example.com", "token": "{{secret:TOKEN}}", "allow_projects": ["OPS"]}}))) };
        let o = t.call(&ctx, json!({"action": "search", "jql": "project = OPS AND status = Open"}));
        assert!(o.content.contains("disk full"), "{}", o.content);
        let req = srv.last();
        assert!(req.header("authorization").unwrap().starts_with("Basic "));
        assert_eq!(req.query("jql").as_deref(), Some("project = OPS AND status = Open"));
        assert!(t.effects(&ctx, &json!({"action": "search", "jql": "x"})).iter().all(|e| matches!(e, Effect::Net { payload, .. } if payload.is_empty())));
        let fx = t.effects(&ctx, &json!({"action": "create", "summary": "Patch CVE-2026-1"}));
        assert!(matches!(&fx[0], Effect::Net { payload, .. } if payload.contains("CVE-2026-1")));
        assert!(t.call(&ctx, json!({"action": "create", "project": "HR", "summary": "x"})).content.contains("allow_projects"));
        let o = t.call(&ctx, json!({"action": "create", "project": "OPS", "summary": "Patch CVE-2026-1", "description": "a\n\nb", "labels": ["security"]}));
        assert!(o.content.contains("OPS-2") && o.content.contains("/browse/OPS-2"), "{}", o.content);
        assert_eq!(srv.last().json()["fields"]["labels"][0], "security");
        let o = t.call(&ctx, json!({"action": "transition", "key": "OPS-2", "transition": "done", "body": "fixed"}));
        assert!(!o.is_error && o.content.contains("Done"), "{}", o.content);
        assert_eq!(srv.last().json()["transition"]["id"], "31");
        assert!(t.call(&ctx, json!({"action": "get", "key": "ops-2; drop"})).is_error);
        assert!(t.call(&ctx, json!({"action": "jsm_create", "service_desk_id": "1", "request_type_id": "2", "summary": "VPN down"})).content.contains("HD-9"));
        let kinds: Vec<String> = seagent_security::audit::all(&ctx.home).iter().map(|e| format!("{} {}", e["kind"].as_str().unwrap_or(""), e["outcome"].as_str().unwrap_or(""))).collect();
        assert_eq!(kinds, ["ticket.create ok", "ticket.transition ok", "ticket.create ok"], "{kinds:?}");
        let v3 = Jira { cfg: Arc::new(Integrations::new(json!({"jira": {"url": "http://x", "api_version": 3}}))) };
        assert_eq!(v3.text("p1\n\np2")["content"].as_array().unwrap().len(), 2);
        assert_eq!(adf_text(&adf("hello\n\nworld")), "hello\nworld");
    }

    #[test]
    fn servicenow_tables_are_allowlisted_and_updates_patch() {
        let ctx = crate::testutil::ctx("tickets-sn");
        let id = "0123456789abcdef0123456789abcdef";
        let patch = format!("PATCH /api/now/table/incident/{id}");
        let srv = FakeServer::start(vec![
            ("GET /api/now/table/incident", 200, "application/json", json!({"result":[{"number":"INC001","sys_id":id,"short_description":"db slow","state":"New","priority":"1 - Critical"}]}).to_string()),
            ("POST /api/now/table/incident", 201, "application/json", json!({"result":{"number":"INC002","sys_id":id}}).to_string()),
            (patch.as_str(), 200, "application/json", json!({"result":{"number":"INC002","state":"In Progress"}}).to_string()),
        ]);
        let t = ServiceNow { cfg: Arc::new(Integrations::new(json!({"servicenow": {"url": srv.url, "user": "svc", "password": "{{secret:TOKEN}}"}}))) };
        let o = t.call(&ctx, json!({"action": "search", "query": "active=true^priority=1"}));
        assert!(o.content.contains("INC001") && o.content.contains("db slow"), "{}", o.content);
        assert_eq!(srv.last().query("sysparm_query").as_deref(), Some("active=true^priority=1"));
        assert!(t.call(&ctx, json!({"action": "search", "table": "sys_user"})).content.contains("not allowed"));
        assert!(t.call(&ctx, json!({"action": "create", "table": "cmdb_ci", "fields": {}})).content.contains("not allowed for writes"));
        assert!(t.call(&ctx, json!({"action": "create", "fields": {"short_description": "API 5xx", "urgency": "1"}})).content.contains("INC002"));
        let o = t.call(&ctx, json!({"action": "comment", "sys_id": id, "text": "rolled back", "work_note": true}));
        assert!(!o.is_error, "{}", o.content);
        let last = srv.last();
        assert_eq!(last.method, "PATCH");
        assert_eq!(last.json()["work_notes"], "rolled back");
    }

    #[test]
    fn pagerduty_events_and_rest_use_their_own_credentials() {
        let ctx = crate::testutil::ctx("tickets-pd");
        let srv = FakeServer::start(vec![
            ("POST /v2/enqueue", 202, "application/json", json!({"status":"success","dedup_key":"k1","message":"Event processed"}).to_string()),
            ("GET /incidents", 200, "application/json", json!({"incidents":[{"id":"P1","incident_number":5,"title":"API down","status":"triggered","service":{"summary":"api"}}],"more":false}).to_string()),
            ("PUT /incidents/P1", 200, "application/json", json!({"incident":{"id":"P1","status":"acknowledged"}}).to_string()),
        ]);
        let t = PagerDuty { cfg: Arc::new(Integrations::new(json!({"pagerduty": {"api_url": srv.url, "events_url": srv.url, "token": "{{secret:TOKEN}}", "routing_key": "{{secret:TOKEN}}", "from": "oncall@example.com"}}))) };
        let o = t.call(&ctx, json!({"action": "trigger", "summary": "error rate 12%", "severity": "critical", "dedup_key": "k1"}));
        assert!(o.content.contains("success"), "{}", o.content);
        let ev = srv.last().json();
        assert_eq!(ev["routing_key"], "s3cr3t");
        assert_eq!(ev["payload"]["severity"], "critical");
        assert!(t.call(&ctx, json!({"action": "resolve", "dedup_key": "k1"})).content.contains("success"));
        assert_eq!(srv.last().json()["event_action"], "resolve");
        let o = t.call(&ctx, json!({"action": "incidents"}));
        assert!(o.content.contains("API down"), "{}", o.content);
        let req = srv.last();
        assert_eq!(req.header("authorization").as_deref(), Some("Token token=s3cr3t"));
        assert!(req.path.contains("statuses%5B%5D=triggered"), "{}", req.path);
        let o = t.call(&ctx, json!({"action": "acknowledge", "incident_id": "P1"}));
        assert!(o.content.contains("acknowledged"), "{}", o.content);
        assert_eq!(srv.last().header("from").as_deref(), Some("oncall@example.com"));
        let fx = t.effects(&ctx, &json!({"action": "trigger", "summary": "x"}));
        assert!(matches!(&fx[0], Effect::Net { dest, payload } if dest == &srv.url && payload.contains("trigger")));
        assert!(t.call(&ctx, json!({"action": "trigger", "summary": "x", "severity": "fatal"})).is_error);
    }
}
