//! Hermes' `kanban_*` tool surface (same names and parameters). One implementation
//! serves orchestrator sessions and dispatcher-spawned workers: a worker is
//! recognised by its session id (the dispatcher's registry, or the durable run
//! record), which plays the role of `HERMES_KANBAN_TASK` / `HERMES_KANBAN_RUN_ID`.

use super::dispatch::{self, Live};
use super::ops::{self, Completion, NewTask, Refusal, ReviewRequest};
use super::store::{self, BoardData, Subscription};
use super::{board_dir, now, resolve_board, tool_error, KanbanConfig, ATTACHMENT_MAX_BYTES};
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Map, Value};
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub const LIST_DEFAULT_LIMIT: u64 = 50;
pub const LIST_MAX_LIMIT: u64 = 200;
const ORCHESTRATOR: &[&str] = &["kanban_list", "kanban_unblock"];
const DESC_TASK_ID: &str = "Task id. If omitted, defaults to the task the dispatcher spawned you to work on. That default only exists for a dispatcher-spawned worker; any other caller has no default and must pass an explicit task_id (use kanban_list to discover ids).";
const DESC_BOARD: &str = "Kanban board slug to target. When omitted, the call resolves the active board ($SEAGENT_KANBAN_BOARD → the 'current' pointer → 'default'). Pass an explicit slug only to override the active board for this one call.";

/// Who is calling: a dispatcher worker (bound to one task) or an orchestrator.
pub struct Caller {
    pub data: std::path::PathBuf,
    pub scope: Option<Live>,
    pub delegated_child: bool,
    pub session: String,
}

impl Caller {
    pub fn of(ctx: &ToolCtx) -> Caller {
        let data = ctx.home.clone();
        let scope = dispatch::scope_for_session(&data, &ctx.session_id);
        let delegated_child = scope.is_none() && delegated_from_worker(&data, &ctx.session_id);
        Caller { data, scope, delegated_child, session: ctx.session_id.clone() }
    }
    /// Profile name persisted as author/creator — never taken from tool args.
    pub fn identity(&self, cfg: &KanbanConfig) -> String {
        self.scope.as_ref().and_then(|s| s.profile.clone()).unwrap_or_else(|| cfg.identity.clone())
    }
}

/// A sub-agent spawned (directly or transitively) by a worker session shares its
/// task but is not the run owner: it may report findings, never mutate.
fn delegated_from_worker(data: &Path, session: &str) -> bool {
    let st = crate::store::Store::new(data.join("sessions"));
    let mut cur = session.to_string();
    for _ in 0..8 {
        let parent = st.open(&cur).ok().and_then(|l| match l.events().first().map(|e| &e.kind) {
            Some(crate::event::EventKind::Header { parent, .. }) => parent.clone(),
            _ => None,
        });
        let Some(p) = parent else { return false };
        if dispatch::scope_for_session(data, &p).is_some() {
            return true;
        }
        cur = p;
    }
    false
}

pub struct Reject(pub String);
type R<T> = Result<T, Reject>;
fn rej<T>(m: impl Into<String>) -> R<T> {
    Err(Reject(m.into()))
}
fn check(c: bool, m: impl Into<String>) -> R<()> {
    if c {
        Ok(())
    } else {
        rej(m)
    }
}
impl From<String> for Reject {
    fn from(s: String) -> Self {
        Reject(s)
    }
}

fn s<'a>(a: &'a Value, k: &str) -> Option<&'a str> {
    a.get(k).and_then(|v| v.as_str())
}
fn text(a: &Value, k: &str, msg: Option<&str>) -> R<String> {
    match s(a, k).map(str::trim).filter(|x| !x.is_empty()) {
        Some(x) => Ok(x.to_string()),
        None => rej(msg.map(String::from).unwrap_or_else(|| format!("{k} is required"))),
    }
}
fn boolarg(a: &Value, k: &str) -> R<bool> {
    match a.get(k) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(v) => match v.as_str().map(|x| x.trim().to_lowercase()).as_deref() {
            Some("true" | "1" | "yes") => Ok(true),
            Some("false" | "0" | "no") => Ok(false),
            _ => rej(format!("{k} must be a boolean or 'true'/'false'")),
        },
    }
}
fn int(a: &Value, k: &str) -> R<Option<i64>> {
    match a.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v.as_i64().or_else(|| v.as_str().and_then(|x| x.trim().parse().ok())).map(Some).ok_or_else(|| Reject(format!("{k} must be an integer"))),
    }
}
/// A single string is accepted as a one-item list.
fn str_list(a: &Value, k: &str, what: &str) -> R<Option<Vec<String>>> {
    match a.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(x)) => Ok(Some(vec![x.trim().to_string()].into_iter().filter(|x| !x.is_empty()).collect())),
        Some(Value::Array(v)) => Ok(Some(v.iter().map(|x| x.as_str().map(String::from).unwrap_or_else(|| x.to_string())).map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect())),
        Some(o) => rej(format!("{k} must be a list of {what}, got {}", type_name(o))),
    }
}
fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}
fn ok(fields: Value) -> String {
    let mut m = Map::new();
    m.insert("ok".into(), true.into());
    if let Value::Object(f) = fields {
        m.extend(f);
    }
    Value::Object(m).to_string()
}

impl Caller {
    fn reject_delegated(&self, tool: &str) -> R<()> {
        check(!self.delegated_child, format!("{tool} refused: delegated sub-agents are not Kanban run owners. Return findings to the parent agent; the dispatcher worker or an explicitly configured Kanban orchestrator must perform board mutations."))
    }
    fn default_task(&self, a: &Value) -> Option<String> {
        if let Some(t) = a.get("task_id").and_then(|v| v.as_str().map(String::from).or_else(|| (!v.is_null()).then(|| v.to_string()))).map(|t| t.trim().to_string()).filter(|t| !t.is_empty()) {
            return Some(t);
        }
        if self.delegated_child {
            return None;
        }
        self.scope.as_ref().map(|s| s.task.clone())
    }
    fn require_task(&self, a: &Value) -> R<String> {
        if let Some(t) = self.default_task(a) {
            return Ok(t);
        }
        if self.delegated_child {
            return rej("task_id is required: this session does not own the parent worker's task, so it is not a valid default. Pass an explicit task_id.");
        }
        rej("task_id is required: this session has no dispatcher-assigned task to default to. Pass an explicit task_id; discover task ids with kanban_list.")
    }
    fn enforce_ownership(&self, tid: &str) -> R<()> {
        match &self.scope {
            Some(s) if s.task != tid => rej(format!("worker is scoped to task {}; refusing to mutate {tid}. Use kanban_comment to hand off information to other tasks, or kanban_create to spawn follow-up work.", s.task)),
            _ => Ok(()),
        }
    }
    /// Worker preamble: delegated-child rejection, task resolution, task scope.
    fn guard(&self, tool: &str, a: &Value) -> R<String> {
        self.reject_delegated(tool)?;
        let t = self.require_task(a)?;
        self.enforce_ownership(&t)?;
        Ok(t)
    }
    /// The worker's run id when it is scoped to `tid` (the run-ownership CAS).
    fn run_for(&self, tid: &str) -> Option<u64> {
        self.scope.as_ref().filter(|s| s.task == tid).map(|s| s.run)
    }
    fn orchestrator_only(&self, tool: &str) -> R<()> {
        check(self.scope.is_none(), format!("{tool} is orchestrator-only; dispatcher-spawned workers must use kanban_complete, kanban_request_review, kanban_request_changes, kanban_block, kanban_heartbeat, or kanban_comment for their assigned task."))
    }
}

/// Goal-mode handoff gate: a reachable judge must agree before complete / review.
fn goal_gate(tool: &str, b: &BoardData, tid: &str, evidence: &str) -> R<()> {
    let Some(t) = b.task(tid).filter(|t| t.goal_mode) else { return Ok(()) };
    let Some(k) = super::kernel() else { return Ok(()) };
    let goal = format!("{}\n\n{}", t.title, t.body.clone().unwrap_or_default());
    let Ok((v, reason)) = super::llm::judge_goal(&k, goal.trim(), evidence.trim()) else { return Ok(()) };
    match (tool, v.as_str()) {
        (_, "done") => Ok(()),
        ("kanban_complete", "blocked") => rej(format!("Goal completion rejected: judge ruled the goal unachievable — {reason}. The task will NOT complete silently. Either re-scope the task, or record the block with kanban_block and hand the decision to a human / reviewer.")),
        ("kanban_complete", _) => rej(format!("Goal completion rejected by judge: {reason}. To proceed, either: (1) provide explicit acceptance evidence in your summary matching the task's criteria, or (2) create continuation tasks with parents=[{tid}] and keep this task alive.")),
        (_, "blocked") => rej(format!("Goal review handoff rejected: judge ruled the goal unachievable — {reason}. Record the block with kanban_block instead of requesting review.")),
        _ => rej(format!("Goal review handoff rejected by judge: {reason}. Provide acceptance evidence matching the card before requesting review.")),
    }
}

fn fields(t: &super::store::Task, names: &[&str]) -> Value {
    let full = serde_json::to_value(t).unwrap_or_default();
    let mut m = Map::new();
    for n in names {
        let v = match *n {
            "model_override" | "provider_override" | "tenant" | "body" | "assignee" | "workspace_path" | "result" | "last_failure_error" | "created_by" | "completion_contract" => full[*n].clone(),
            _ => full.get(*n).cloned().unwrap_or(Value::Null),
        };
        m.insert((*n).into(), v);
    }
    Value::Object(m)
}
const TASK_FIELDS: &[&str] = &["id", "title", "body", "assignee", "status", "tenant", "priority", "workspace_kind", "workspace_path", "created_by", "created_at", "started_at", "completed_at", "result", "current_run_id", "model_override", "provider_override", "completion_contract", "last_failure_error"];
const SUMMARY_FIELDS: &[&str] = &["id", "title", "assignee", "status", "priority", "tenant", "workspace_kind", "workspace_path", "created_by", "created_at", "started_at", "completed_at", "current_run_id", "model_override", "provider_override"];

fn run_json(r: &super::store::Run) -> Value {
    json!({"id": r.id, "profile": r.profile, "status": r.status, "outcome": r.outcome, "summary": r.summary, "error": r.error, "metadata": r.metadata, "started_at": r.started_at, "ended_at": r.ended_at})
}
pub fn attachment_json(a: &super::store::Attachment) -> Value {
    json!({"id": a.id, "filename": a.filename, "content_type": a.content_type, "size": a.size, "uploaded_by": a.uploaded_by, "stored_path": a.stored_path, "created_at": a.created_at})
}

/// The canonical `[security]` URL policy for board attachment fetches — the same decider
/// the web tools use (`seagent_security::url_safety`), plus the `[kanban]
/// attach_url_allow_private` escape hatch for LAN / test targets.
#[derive(Clone, Default)]
pub struct FetchPolicy {
    /// SSRF policy: `[security] allow_private_urls` / `fake_ip_ranges`.
    pub url: seagent_security::url_safety::UrlPolicy,
    /// `[security.website_blocklist]`.
    pub blocklist: seagent_security::url_safety::WebsiteBlocklist,
    /// Resolves relative `website_blocklist.shared_files`.
    pub config_dir: std::path::PathBuf,
}

impl FetchPolicy {
    /// The process-wide `[security]` policy the kernel installed
    /// (`SecurityConfig::activate_at`), with `[kanban] attach_url_allow_private` folded in.
    /// The web tools read the same global policy, so an operator's `allow_private_urls` /
    /// `fake_ip_ranges` / website blocklist applies here too.
    pub fn from_config(allow_private: bool) -> FetchPolicy {
        let mut url = seagent_security::url_safety::global_policy();
        url.allow_private_urls |= allow_private;
        FetchPolicy { url, ..Default::default() }
    }
    /// Blocked by the user's website blocklist (this board's list, then the process-wide one).
    fn website_block(&self, url: &str) -> Option<String> {
        seagent_security::url_safety::check_website_access(url, &self.blocklist, &self.config_dir).or_else(|| seagent_security::url_safety::check_website_global(url))
    }
    /// One hop's verdict (initial URL and every redirect): the website blocklist, then the
    /// SSRF rules over every DNS answer, so a refused target is never dialled.
    fn allow_hop(&self, url: &str) -> Result<(), String> {
        if let Some(m) = self.website_block(url) {
            return Err(format!("URL blocked by website policy: {m}. Do not retry this URL."));
        }
        seagent_security::url_safety::resolve_safe(url, &self.url, &seagent_security::url_safety::system_resolve)
            .map(|_| ())
            .map_err(|e| format!("URL blocked by SSRF protection: {}", seagent_security::url_safety::ssrf_message(&e)))
    }
}

/// Connect-time guard: every dial re-checks the host and each resolved address and hands back
/// only those addresses, so the answer that was vetted is the one dialled (a second DNS answer
/// cannot swap in a private target between the check and the connect).
#[derive(Debug)]
struct HopResolver {
    url: seagent_security::url_safety::UrlPolicy,
}

impl ureq::unversioned::resolver::Resolver for HopResolver {
    fn resolve(&self, uri: &ureq::http::Uri, config: &ureq::config::Config, timeout: ureq::unversioned::transport::NextTimeout) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        let hosts = seagent_security::url_safety::HostPolicy { url: &self.url, allowed_hostnames: &[], hostname_allowlist: &[], blocked_hostnames: &[] };
        let host = seagent_security::url_safety::normalize_host(uri.host().unwrap_or(""));
        let scheme = if uri.scheme_str() == Some("https") { "https" } else { "http" };
        seagent_security::url_safety::check_host(&host, scheme, &hosts).map_err(blocked)?;
        let addrs = ureq::unversioned::resolver::DefaultResolver::default().resolve(uri, config, timeout)?;
        let ips: Vec<std::net::IpAddr> = addrs.iter().map(|a| a.ip()).collect();
        seagent_security::url_safety::check_resolved(&host, &ips, scheme, &hosts).map_err(blocked)?;
        Ok(addrs)
    }
}

fn blocked(msg: String) -> ureq::Error {
    ureq::Error::Io(std::io::Error::new(std::io::ErrorKind::PermissionDenied, msg))
}

fn fetch_err(url: &str, e: ureq::Error) -> String {
    match e {
        ureq::Error::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied => format!("URL blocked by SSRF protection: {url}: {io}"),
        other => format!("failed to fetch {url}: {other}"),
    }
}

/// Fetch an http(s) URL capped at `max`. Every hop — the first request and each redirect —
/// is decided by `seagent_security::url_safety` (SSRF ranges, cloud-metadata floor, website
/// blocklist) and the connection dials only the vetted addresses. Returns (bytes, content-type).
pub fn download_capped(url: &str, max: u64, policy: &FetchPolicy) -> Result<(Vec<u8>, Option<String>), String> {
    let cfg = seagent_net::http::builder().http_status_as_error(false).max_redirects(0).timeout_global(Some(Duration::from_secs(30))).build();
    let agent = ureq::Agent::with_parts(cfg, ureq::unversioned::transport::DefaultConnector::default(), HopResolver { url: policy.url.clone() });
    let mut cur = url.to_string();
    for _ in 0..6 {
        let scheme = cur.split("://").next().unwrap_or("").to_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(format!("unsupported URL scheme {scheme:?}; only http/https are allowed"));
        }
        policy.allow_hop(&cur)?;
        let mut r = agent.get(&cur).header("user-agent", "seagent-kanban/attach").call().map_err(|e| fetch_err(&cur, e))?;
        let st = r.status().as_u16();
        if (300..400).contains(&st) {
            let loc = r.headers().get("location").and_then(|v| v.to_str().ok()).ok_or_else(|| format!("redirect without Location header from {cur}"))?.to_string();
            cur = join_url(&cur, &loc);
            continue;
        }
        if !(200..300).contains(&st) {
            return Err(format!("failed to fetch {cur}: HTTP {st}"));
        }
        let ct = r.headers().get("content-type").and_then(|v| v.to_str().ok()).map(|v| v.split(';').next().unwrap_or("").trim().to_string()).filter(|v| !v.is_empty());
        let mut buf = vec![];
        r.body_mut().with_config().limit(u64::MAX).reader().take(max + 1).read_to_end(&mut buf).map_err(|e| e.to_string())?;
        if buf.len() as u64 > max {
            return Err(format!("attachment exceeds {} MB limit", max / (1024 * 1024)));
        }
        return Ok((buf, ct));
    }
    Err(format!("too many redirects fetching {url}"))
}

fn join_url(base: &str, loc: &str) -> String {
    if loc.contains("://") {
        return loc.into();
    }
    let (scheme, rest) = base.split_once("://").unwrap_or(("http", base));
    let host = rest.split('/').next().unwrap_or("");
    if loc.starts_with('/') {
        format!("{scheme}://{host}{loc}")
    } else {
        let dir = base.rsplit_once('/').map(|(d, _)| d).unwrap_or(base);
        format!("{dir}/{loc}")
    }
}

pub fn gh_token(cfg: &KanbanConfig) -> Option<String> {
    let t = cfg.github_token.trim();
    let t = if t.is_empty() { String::new() } else { super::kernel().map(|k| k.vault.substitute(t)).unwrap_or_else(|| t.to_string()) };
    Some(t).filter(|t| !t.is_empty() && !t.contains("{{secret:")).or_else(|| std::env::var("GH_TOKEN").ok()).or_else(|| std::env::var("GITHUB_TOKEN").ok()).filter(|t| !t.is_empty())
}

/// The full completion path: PR acceptance outside the lock, then the atomic write.
pub fn complete_task(data: &Path, slug: &str, cfg: &KanbanConfig, tid: &str, mut c: Completion) -> Result<u64, (Refusal, Option<String>)> {
    let prepared = store::with_board(data, slug, |b| Ok(super::pr::prepare(b, tid, c.expected_run, c.metadata.as_ref()))).map_err(|e| (Refusal::No, Some(e)))?;
    match prepared {
        Err(()) => return Err((Refusal::No, None)),
        Ok(Some((snap, contract, published))) => {
            let gh = super::pr::Gh::new(&cfg.github_api, gh_token(cfg));
            let receipt = super::pr::collect(&gh, &contract, published.as_deref());
            c.acceptance = Some((snap, receipt));
        }
        Ok(None) => {}
    }
    store::with_board(data, slug, |b| {
        if let Some(t) = b.task(tid) {
            c.claim_live = dispatch::claim_is_live(b, t);
        }
        Ok(ops::complete(b, data, slug, tid, c, cfg.failure_limit))
    })
    .map_err(|e| (Refusal::No, Some(e)))?
    .map_err(|r| (r, None))
}

pub struct KanbanTool {
    pub name: &'static str,
    pub cfg: KanbanConfig,
}

fn p(t: &str, d: &str) -> Value {
    json!({"type": t, "description": d})
}

pub fn schema(name: &str) -> (String, Value, Vec<&'static str>) {
    let tid = p("string", DESC_TASK_ID);
    let strs = |d: &str| json!({"type": "array", "items": {"type": "string"}, "description": d});
    let mut statuses: Vec<&str> = super::workflow::HERMES_STATUSES.to_vec();
    statuses.push("archived");
    let (desc, props, req): (&str, Value, Vec<&'static str>) = match name {
        "kanban_show" => ("Read a task's full state — title, body, assignee, parent task handoffs, your prior attempts on this task if any, comments, and recent events. Use this to (re)orient yourself before starting work, especially on retries. The response includes a pre-formatted ``worker_context`` string suitable for inclusion verbatim in your reasoning. Outside a dispatcher-spawned worker there is no default task: a bare call returns a pointer to ``kanban_list`` instead of task state.", json!({"task_id": tid}), vec![]),
        "kanban_list" => ("List Kanban task summaries so an orchestrator can discover work to route. Supports the same core filters as the CLI: assignee, status, tenant, include_archived, and limit. Returns compact rows with ids, title, status, assignee, priority, parent/child ids, and counts. Bounded to 50 rows by default, 200 max, with truncation metadata. Also recomputes ready tasks before listing. Orchestrator-only — dispatcher-spawned task workers cannot use this tool.", json!({"assignee": p("string", "Optional assignee/profile filter."), "status": {"type": "string", "enum": statuses, "description": "Optional task status filter."}, "tenant": p("string", "Optional tenant/project namespace filter."), "include_archived": p("boolean", "Include archived tasks. Defaults to false."), "limit": p("integer", "Optional maximum rows to return (default 50, max 200).")}), vec![]),
        "kanban_complete" => ("Mark your current task done with a structured handoff for downstream workers and humans. Prefer ``summary`` for a human-readable 1-3 sentence description of what you did; put machine-readable facts in ``metadata`` (changed_files, tests_run, decisions, findings, etc). At least one of ``summary`` or ``result`` is required. If you created new tasks via ``kanban_create`` during this run, list their ids in ``created_cards`` — the kernel verifies them so phantom references are caught. If you produced deliverable files, list their absolute paths in ``artifacts`` — they are attached to the task and delivered with the completion notification.", json!({"task_id": tid, "summary": p("string", "Human-readable handoff, 1-3 sentences. Appears in Run History and in downstream workers' context."), "metadata": p("object", "Free-form dict of structured facts about this attempt — {\"changed_files\": [...], \"tests_run\": 12, \"findings\": [...]}. Surfaced to downstream workers alongside ``summary``."), "result": p("string", "Short result log line (legacy field, maps to task.result). Use ``summary`` instead when possible."), "created_cards": strs("Optional structured manifest of task ids you created via ``kanban_create`` during this run. The kernel verifies each id exists and was created by this worker's profile; any phantom id blocks the completion with an error listing what went wrong. Only list ids you got back from a successful ``kanban_create`` call. Omit the field if you did not create any cards."), "artifacts": strs("Optional list of absolute paths to deliverable files you produced during this run — generated charts, PDFs, spreadsheets, images, archives. The path must exist on disk at completion. Files inside a managed scratch workspace are copied to durable task attachments before cleanup; a missing declared scratch artifact keeps the task in-flight so you can fix the path and retry.")}), vec![]),
        "kanban_block" => ("Stop work on this task and route it according to WHY you're stuck. Set ``kind`` to say which: 'dependency' (waiting on another task — goes to todo and auto-resumes when that task finishes, no human needed), 'needs_input' (you need a human decision/answer), 'capability' (a hard wall: no access, missing credentials, an action no agent can do), or 'transient' (a flaky failure that may clear). ``reason`` is shown to the human on the board. If a task keeps getting unblocked and re-blocked for the same reason, it is auto-escalated to triage. Use for genuine blockers only — don't block on things you can resolve yourself.", json!({"task_id": tid, "reason": p("string", "What you need answered or what stopped you, in one or two sentences. Don't paste the whole conversation; the human has the board and can ask follow-ups via comments."), "kind": {"type": "string", "enum": ["dependency", "needs_input", "capability", "transient"], "description": "Why you're blocked. 'dependency' waits in todo and resumes automatically when an incomplete parent finishes; if no parent is open it is recorded as needs_input instead. The others surface to a human. Omit only if none apply."}}), vec!["reason"]),
        "kanban_schedule" => ("Park your current task in the 'scheduled' state while it waits for time or an external event. This ends the current run and makes the task non-dispatchable until an orchestrator unblocks it; it does not create a timer. Put any wake-up marker such as ``SCHEDULED_UNTIL=<ISO8601>`` in ``reason``.", json!({"task_id": tid, "reason": p("string", "Optional reason or machine-readable wake-up marker recorded on the completed run and scheduled event.")}), vec![]),
        "kanban_request_review" => ("Hand the task off for review: implementation, self-review, and verification are complete and you want a human (or reviewer) to look before it is marked done. Moves the task to the 'review' column and notifies the subscriber. Unlike ``kanban_block`` this is NOT a blocker — it never counts toward unblock-loop detection. Use this instead of blocking with a free-form 'review-required:' reason.", json!({"task_id": tid, "summary": p("string", "What was implemented and how it was verified, in one or two sentences — shown to the reviewer."), "reviewer": p("string", "Optional reviewer profile. When provided, the task is reassigned to that profile before review dispatch."), "metadata": {"type": "object", "description": "Optional structured handoff facts for the reviewer, such as changed_files, tests_run, commit, or decisions.", "additionalProperties": true}, "artifacts": strs("Optional list of absolute paths to deliverable files this handoff names. They are copied into the task's durable attachments before the reviewer's completion cleans the scratch workspace up. A missing declared scratch artifact keeps the task in place so you can fix the path and retry.")}), vec!["summary"]),
        "kanban_request_changes" => ("Reviewer verdict: return the current review run to the original implementer with concrete required changes. This closes the review run, reapplies parent dependency gating, and requeues the task without using block-loop accounting. Only use from a task claimed from the review column; use kanban_block only for a genuine external blocker.", json!({"task_id": tid, "reason": p("string", "Specific, actionable changes the implementer must make before requesting another review.")}), vec!["reason"]),
        "kanban_heartbeat" => ("Signal that you're still alive during a long operation (training, encoding, large crawls). Call every few minutes so humans see liveness separately from process checks. Pure side effect — no work changes.", json!({"task_id": tid, "note": p("string", "Optional short note describing current progress. Shown in the event log.")}), vec![]),
        "kanban_comment" => ("Append a comment to a task's thread. Use for durable notes that should outlive this run (questions for the next worker, partial findings, rationale). Ephemeral reasoning doesn't belong here — use your normal response instead.", json!({"task_id": p("string", "Task id. Required (may be your own task or another's — comment threads are per-task). Outside a dispatcher-spawned worker there is no default; use kanban_list to discover ids."), "body": p("string", "Markdown-supported comment body.")}), vec!["task_id", "body"]),
        "kanban_attach" => ("Attach a file to a task by passing its bytes inline (base64). Use for genuine file artifacts the next worker or a human should be able to download — generated reports, images, exports. The file is stored as a real attachment under the task's attachments dir, capped at 25 MB. Prefer kanban_attach_url when you only have a URL.", json!({"task_id": tid, "filename": p("string", "File name to store it under (e.g. 'report.pdf'). Directory components are stripped; only the leaf is kept."), "content_base64": p("string", "The file contents, base64-encoded. Max 25 MB decoded."), "content_type": p("string", "Optional MIME type (e.g. 'application/pdf').")}), vec!["filename", "content_base64"]),
        "kanban_attach_url" => ("Attach a file to a task by URL — seagent downloads it server-side and stores it as a real attachment (capped at 25 MB). Use when you have a link rather than the bytes. Only http/https URLs are accepted.", json!({"task_id": tid, "url": p("string", "http(s) URL to fetch and store."), "filename": p("string", "Optional name to store it under. Defaults to the URL path's leaf component."), "content_type": p("string", "Optional MIME type override. Defaults to the Content-Type the server returns.")}), vec!["url"]),
        "kanban_attachments" => ("List the files attached to a task: id, filename, content_type, size, who uploaded it, and the absolute on-disk path you can read.", json!({"task_id": tid}), vec![]),
        "kanban_create" => ("Create a new kanban task, optionally as a child of the current one (pass the current task id in ``parents``). Used by orchestrators to fan out — decompose work into child tasks with specific assignees, link them into a pipeline, then complete your own task. The dispatcher picks up the new tasks on its next tick and spawns the assigned profiles.", json!({
            "title": p("string", "Short task title (required)."),
            "assignee": p("string", "Profile name that should execute this task (e.g. 'researcher-a', 'reviewer', 'writer'). Required — tasks without an assignee are never dispatched."),
            "body": p("string", "Opening post: full spec, acceptance criteria, links. The assigned worker reads this as part of its context."),
            "parents": strs("Parent task ids. The new task stays in 'todo' until every parent reaches 'done'; then it auto-promotes to 'ready'. Typical fan-in: list all the researcher task ids when creating a synthesizer task."),
            "tenant": p("string", "Optional namespace for multi-project isolation."),
            "priority": p("integer", "Dispatcher tiebreaker. Higher = picked sooner when multiple ready tasks share an assignee."),
            "workspace_kind": {"type": "string", "enum": ["scratch", "dir", "worktree"], "description": "Workspace flavor: 'scratch' (fresh tmp dir, default), 'dir' (shared directory, requires absolute workspace_path), 'worktree' (git worktree)."},
            "workspace_path": p("string", "Absolute path for 'dir' or 'worktree' workspace. Relative paths are rejected at dispatch."),
            "project": p("string", "Optional project id or slug to link the task to (recorded on the task; seagent resolves worktrees from the board's default workdir)."),
            "triage": p("boolean", "If true, task lands in 'triage' instead of 'todo' — a specifier is expected to flesh out the body before work starts."),
            "idempotency_key": p("string", "If a non-archived task with this key already exists, return that task's id instead of creating a duplicate. Useful for retry-safe automation."),
            "max_runtime_seconds": p("integer", "Per-task runtime cap. When exceeded, the dispatcher interrupts the worker and re-queues the task with outcome='timed_out'."),
            "initial_status": {"type": "string", "enum": ["running", "blocked"], "description": "Initial card status. Use 'blocked' for tasks that require immediate human ops to skip the brief running-to-blocked transition. Defaults to 'running', which preserves the usual dispatch path."},
            "skills": strs("Skill names to force-load into the dispatched worker. The kanban lifecycle is already injected automatically; use this to pin a task to a specialist context."),
            "goal_mode": p("boolean", "Run the dispatched worker in a goal loop: after each turn an auxiliary judge checks the worker's response against this card's title/body; if the work isn't done and budget remains, the worker keeps going in the same session until the judge agrees it's complete (or the goal-turn budget is exhausted, which blocks the task for human review). Defaults to false."),
            "completion_contract": p("string", "Declare at creation: local-only (default), OWNER/REPO for PR publication, or an exact GitHub PR URL. PR tasks cannot complete until repository-required exact-head CI passes. On publication pass metadata.published_pr."),
            "goal_max_turns": p("integer", "Turn budget for goal_mode workers. Ignored unless goal_mode is true. Defaults to 20."),
            "model": p("string", "Pin the dispatched worker to this model instead of the assignee profile's configured model."),
            "provider": p("string", "Provider the 'model' belongs to. Requires 'model'.")
        }), vec!["title", "assignee"]),
        "kanban_unblock" => ("Unblock a Kanban task. It moves to ready when all parents are done, or todo while any parent remains open. Orchestrator-only — dispatcher-spawned task workers cannot use this tool.", json!({"task_id": p("string", "Blocked task id to move to ready or parent-gated todo.")}), vec!["task_id"]),
        "kanban_link" => ("Add a parent→child dependency edge after both tasks already exist. The child won't promote to 'ready' until all parents are 'done'. Cycles and self-links are rejected. A running child is rejected unless the active owning worker is linking its own card for a dependency handoff.", json!({"parent_id": p("string", "Parent task id."), "child_id": p("string", "Child task id.")}), vec!["parent_id", "child_id"]),
        _ => ("", json!({}), vec![]),
    };
    let mut props = props;
    props["board"] = p("string", DESC_BOARD);
    (desc.into(), props, req)
}

pub const NAMES: &[&str] = &["kanban_show", "kanban_list", "kanban_complete", "kanban_block", "kanban_schedule", "kanban_request_review", "kanban_request_changes", "kanban_heartbeat", "kanban_comment", "kanban_attach", "kanban_attach_url", "kanban_attachments", "kanban_create", "kanban_unblock", "kanban_link"];

/// Tools bound to a dispatcher-spawned worker's session (no board-routing tools).
pub fn worker_tools(cfg: &KanbanConfig) -> Vec<Arc<dyn Tool>> {
    let mut v: Vec<Arc<dyn Tool>> = NAMES.iter().filter(|n| !ORCHESTRATOR.contains(n)).map(|n| Arc::new(KanbanTool { name: n, cfg: cfg.clone() }) as Arc<dyn Tool>).collect();
    v.extend(super::workboard::worker_tools(cfg));
    v
}

/// Every board tool for ordinary sessions (`[kanban] enabled`): both vocabularies.
pub fn orchestrator_tools(cfg: &KanbanConfig) -> Vec<Arc<dyn Tool>> {
    let mut v: Vec<Arc<dyn Tool>> = NAMES.iter().map(|n| Arc::new(KanbanTool { name: n, cfg: cfg.clone() }) as Arc<dyn Tool>).collect();
    v.extend(super::workboard::all_tools(cfg));
    v
}

/// What a normal (non-dispatcher) session gets from `[kanban]`: the orchestrator tools
/// of both vocabularies, or nothing at all when the board is off. Hermes' opt-in
/// (`toolsets: [kanban]`) maps onto `enabled`; the config layer already drops the whole
/// `[kanban]` section for a project config that is not trusted, so a repository cannot
/// opt itself in (`config::PROJECT_GATED`).
pub fn session_tools(cfg: &KanbanConfig) -> Vec<Arc<dyn Tool>> {
    if cfg.enabled {
        orchestrator_tools(cfg)
    } else {
        Vec::new()
    }
}

impl Tool for KanbanTool {
    fn spec(&self) -> ToolSpec {
        let (description, props, req) = schema(self.name);
        ToolSpec { name: self.name.into(), description, input_schema: json!({"type": "object", "properties": props, "required": req}), parallel_safe: matches!(self.name, "kanban_show" | "kanban_list" | "kanban_attachments"), idempotent: matches!(self.name, "kanban_show" | "kanban_list" | "kanban_attachments" | "kanban_heartbeat"), pinned: false }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let caller = Caller::of(ctx);
        let slug = Self::board_of(&caller, input).unwrap_or_default();
        let path = board_dir(&ctx.home, &slug);
        match self.name {
            "kanban_show" | "kanban_list" | "kanban_attachments" => vec![Effect::Read { path }],
            "kanban_attach_url" => vec![Effect::Net { dest: s(input, "url").unwrap_or("").into(), payload: String::new() }, Effect::Write { path }],
            "kanban_complete" => {
                let mut v = vec![Effect::Write { path }];
                if let Some(tid) = caller.default_task(input) {
                    if store::read_board(&ctx.home, &slug).ok().and_then(|b| b.task(&tid).and_then(|t| t.completion_contract.clone())).is_some_and(|c| c != "local-only") {
                        v.push(Effect::Net { dest: self.cfg.github_api.clone(), payload: String::new() });
                    }
                }
                v
            }
            _ => vec![Effect::Write { path }],
        }
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let props = schema(self.name).1;
        let mut allowed: Vec<String> = props.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
        allowed.sort();
        if let Some(o) = input.as_object() {
            let extra = if self.name == "kanban_create" { &["session_id", "project_id"][..] } else if self.name == "kanban_attach_url" { &["title"][..] } else { &[][..] };
            let mut unknown: Vec<&String> = o.keys().filter(|k| !allowed.contains(k) && !extra.contains(&k.as_str())).collect();
            unknown.sort();
            if !unknown.is_empty() {
                return ToolOutput::err(tool_error(format!("{}: unknown parameter(s): {}. Valid parameters: {}. Nothing changed.", self.name, unknown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "), allowed.join(", "))));
            }
        }
        let caller = Caller::of(ctx);
        match self.handle(&caller, &input) {
            Ok(s) => ToolOutput::ok(s),
            Err(Reject(m)) => ToolOutput::err(tool_error(if m.starts_with(self.name) || m.contains(" refused") || m.starts_with("worker is scoped") || m.starts_with("task_id is required") { m } else { format!("{}: {m}", self.name) })),
        }
    }
}

impl KanbanTool {
    /// The board this call targets: an explicit `board` argument wins, then the board a
    /// dispatcher spawned this worker on (`Live.slug`, upstream `HERMES_KANBAN_BOARD`),
    /// then the current pointer. The daemon dispatches every board, so a worker must not
    /// fall back to the current pointer of an unrelated board.
    fn board_of(c: &Caller, a: &Value) -> R<String> {
        if s(a, "board").is_some() {
            return resolve_board(&c.data, s(a, "board")).map_err(Reject);
        }
        match c.scope.as_ref().map(|x| x.slug.clone()).filter(|x| !x.is_empty()) {
            Some(slug) => Ok(super::normalize_slug(Some(&slug)).map_err(Reject)?.unwrap_or(slug)),
            None => resolve_board(&c.data, None).map_err(Reject),
        }
    }

    fn handle(&self, c: &Caller, a: &Value) -> R<String> {
        let cfg = &self.cfg;
        let data = c.data.as_path();
        let slug = Self::board_of(c, a)?;
        let slug = slug.as_str();
        let lim = cfg.failure_limit;
        match self.name {
            "kanban_show" => {
                let Some(tid) = c.default_task(a) else {
                    return Ok(json!({"current_task": null, "hint": "No dispatcher-assigned task in this session, so there is no task to show by default. Call kanban_list to see task ids on the board, then kanban_show(task_id=<id>) for full state."}).to_string());
                };
                let b = store::read_board(data, slug)?;
                let t = b.task(&tid).ok_or_else(|| Reject(format!("task {tid} not found")))?;
                let ev = b.events_for(&tid);
                let skip = ev.len().saturating_sub(50);
                Ok(json!({
                    "task": fields(t, TASK_FIELDS),
                    "parents": b.parent_ids(&tid),
                    "unsatisfied_parents": ops::unsatisfied_parents(&b, &tid).into_iter().map(|(i, s)| json!({"id": i, "status": s})).collect::<Vec<_>>(),
                    "children": b.child_ids(&tid),
                    "comments": b.comments_for(&tid).iter().map(|c| json!({"author": c.author, "body": c.body, "created_at": c.created_at})).collect::<Vec<_>>(),
                    "events": ev.iter().skip(skip).map(|e| json!({"kind": e.kind, "payload": e.payload, "created_at": e.created_at, "run_id": e.run_id})).collect::<Vec<_>>(),
                    "runs": b.runs_for(&tid).into_iter().map(run_json).collect::<Vec<_>>(),
                    "worker_context": super::context::build_worker_context(&b, &tid, now())?,
                })
                .to_string())
            }
            "kanban_list" => {
                c.orchestrator_only(self.name)?;
                let inc = boolarg(a, "include_archived")?;
                let limit = int(a, "limit").map_err(|_| Reject("limit must be an integer".into()))?.unwrap_or(LIST_DEFAULT_LIMIT as i64);
                check(limit >= 1, "limit must be >= 1")?;
                check(limit <= LIST_MAX_LIMIT as i64, format!("limit must be <= {LIST_MAX_LIMIT}"))?;
                let limit = limit as usize;
                let (promoted, b) = store::with_board(data, slug, |b| Ok((ops::recompute_ready(b, lim), b.clone())))?;
                let mut rows: Vec<&super::store::Task> = b.tasks.iter().filter(|t| (inc || t.status != "archived") && s(a, "assignee").is_none_or(|x| t.assignee.as_deref() == Some(x)) && s(a, "status").is_none_or(|x| t.status == x) && s(a, "tenant").is_none_or(|x| t.tenant.as_deref() == Some(x))).collect();
                rows.sort_by_key(|t| (std::cmp::Reverse(t.priority), t.created_at));
                let truncated = rows.len() > limit;
                let tasks: Vec<Value> = rows.into_iter().take(limit).map(|t| {
                    let mut v = fields(t, SUMMARY_FIELDS);
                    let (ps, cs) = (b.parent_ids(&t.id), b.child_ids(&t.id));
                    v["parent_count"] = ps.len().into();
                    v["child_count"] = cs.len().into();
                    v["parents"] = json!(ps);
                    v["children"] = json!(cs);
                    v
                }).collect();
                let next = (truncated && limit < LIST_MAX_LIMIT as usize).then(|| (limit * 2).min(LIST_MAX_LIMIT as usize));
                Ok(json!({"tasks": tasks, "count": tasks.len(), "limit": limit, "truncated": truncated, "next_limit": next, "promoted": promoted}).to_string())
            }
            "kanban_complete" => {
                let tid = c.guard(self.name, a)?;
                let summary = s(a, "summary").filter(|x| !x.trim().is_empty()).map(ops::redact);
                let result = s(a, "result").filter(|x| !x.trim().is_empty()).map(ops::redact);
                let mut metadata = match a.get("metadata") {
                    None | Some(Value::Null) => None,
                    Some(m @ Value::Object(_)) => Some(ops::redact_value(m)),
                    Some(o) => return rej(format!("metadata must be an object/dict, got {}", type_name(o))),
                };
                let created = str_list(a, "created_cards", "task ids")?;
                let artifacts = str_list(a, "artifacts", "file paths")?;
                if let Some(arts) = artifacts.filter(|v| !v.is_empty()) {
                    let m = metadata.get_or_insert_with(|| json!({}));
                    let mut merged: Vec<String> = m["artifacts"].as_array().map(|x| x.iter().filter_map(|v| v.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect()).unwrap_or_default();
                    for x in arts {
                        if !merged.contains(&x) {
                            merged.push(x);
                        }
                    }
                    m["artifacts"] = json!(merged);
                }
                check(summary.is_some() || result.is_some(), "provide at least one of: summary (preferred), result")?;
                if c.scope.is_some() {
                    metadata.get_or_insert_with(|| json!({}))["worker_session_id"] = c.session.clone().into();
                }
                let b = store::read_board(data, slug)?;
                goal_gate(self.name, &b, &tid, summary.as_deref().or(result.as_deref()).unwrap_or(""))?;
                let comp = Completion { result, summary, metadata, created_cards: created, expected_run: c.run_for(&tid), ..Default::default() };
                match complete_task(data, slug, cfg, &tid, comp) {
                    Ok(rid) => {
                        let b = store::read_board(data, slug)?;
                        Ok(ok(json!({"task_id": tid, "run_id": (rid != 0).then_some(rid), "attachments": b.attachments_for(&tid).into_iter().map(attachment_json).collect::<Vec<_>>()})))
                    }
                    Err((Refusal::Artifact(e), _)) => rej(format!("kanban_complete could not preserve the declared artifacts: {e}. Your task is still in-flight and its scratch workspace was kept. Fix the artifact path or storage error, then retry kanban_complete with the same handoff.")),
                    Err((Refusal::LiveClaim, _)) => rej(format!("kanban_complete refused: {tid} is running under a live worker claim; pass expected_run_id (worker ownership) or force=True (explicit operator override) instead of closing the live run. Nothing changed. Wait for the worker to finish, or an operator can run `seagent kanban complete --force {tid}`.")),
                    Err((Refusal::Hallucinated(ph), _)) => rej(format!("kanban_complete blocked: the following created_cards do not exist or were not created by this worker: {}. Your task is still in-flight (no state change). Retry kanban_complete with the same summary/metadata and either drop these ids from created_cards, or pass created_cards=[] to skip the card-claim check entirely.", ph.join(", "))),
                    Err((Refusal::Empty, _)) => rej(format!("kanban_complete blocked: completion blocked: {tid} has no result or summary evidence. Your task is still in-flight (no state change). Retry kanban_complete with a non-empty summary or result describing what was done.")),
                    Err((Refusal::No, e)) => {
                        if let Some(e) = e {
                            return rej(e);
                        }
                        let b = store::read_board(data, slug)?;
                        let blockers = ops::unsatisfied_parents(&b, &tid);
                        if !blockers.is_empty() {
                            return rej(format!("could not complete {tid}: unsatisfied parent dependencies: {}; complete the parents first (done or archived)", blockers.iter().map(|(p, s)| format!("{p} ({s})")).collect::<Vec<_>>().join(", ")));
                        }
                        rej(b.task(&tid).and_then(|t| t.last_failure_error.clone()).unwrap_or_else(|| format!("could not complete {tid} (unknown id, stale run, or already terminal)")))
                    }
                }
            }
            "kanban_block" => {
                let tid = c.guard(self.name, a)?;
                let reason = ops::redact(&text(a, "reason", Some("reason is required — explain what input you need"))?);
                let kind = s(a, "kind");
                check(kind.is_none_or(|k| super::workflow::VALID_BLOCK_KINDS.contains(&k)), format!("kind must be one of {:?} (or omit it)", super::workflow::VALID_BLOCK_KINDS))?;
                let run = c.run_for(&tid);
                let (okb, landed, status, rid) = store::with_board(data, slug, |b| {
                    if let Some(t) = b.task(&tid) {
                        if t.goal_mode && !matches!(kind, Some("dependency" | "needs_input")) {
                            return Err(format!("goal_mode tasks can only block with kind in [\"dependency\", \"needs_input\"] (got {kind:?}). If the task is actually finished or cannot proceed for another reason, call kanban_complete instead — the completion judge will evaluate it."));
                        }
                    }
                    let okb = ops::block(b, &tid, Some(&reason), kind, run)?;
                    let t = b.task(&tid);
                    Ok((okb, t.and_then(|t| t.block_kind.clone()), t.map(|t| t.status.clone()), b.latest_run(&tid).map(|r| r.id)))
                })?;
                check(okb, format!("could not block {tid} (unknown id or not in running/ready)"))?;
                let mut out = json!({"task_id": tid, "run_id": rid, "status": status, "block_kind": landed});
                if kind == Some("dependency") && landed.as_deref() != kind {
                    out["requested_kind"] = "dependency".into();
                    out["note"] = "kind='dependency' only waits on an incomplete parent; no parent is open, so this was recorded as needs_input (sticky until a human unblocks) instead of parking in todo where the dispatcher would respawn it.".into();
                }
                Ok(ok(out))
            }
            "kanban_schedule" => {
                let tid = c.guard(self.name, a)?;
                check(a.get("reason").is_none_or(|v| v.is_string() || v.is_null()), "reason must be a string")?;
                let reason = s(a, "reason").map(str::trim).filter(|x| !x.is_empty()).map(ops::redact);
                let run = c.run_for(&tid);
                let (okb, st, rid) = store::with_board(data, slug, |b| {
                    if b.task(&tid).is_some_and(|t| t.goal_mode) {
                        return Err("goal_mode tasks cannot be scheduled: use kanban_block with kind in [\"dependency\", \"needs_input\"] for a genuine external blocker, or kanban_complete so the completion judge can evaluate it.".into());
                    }
                    let okb = ops::schedule(b, &tid, reason.as_deref(), run);
                    Ok((okb, b.status_of(&tid).map(String::from), b.latest_run(&tid).map(|r| r.id)))
                })?;
                check(okb, format!("could not schedule {tid} (unknown id or not in todo/ready/running/blocked)"))?;
                Ok(ok(json!({"task_id": tid, "run_id": rid, "status": st, "reason": reason})))
            }
            "kanban_request_review" => {
                let tid = c.guard(self.name, a)?;
                let summary = ops::redact(&text(a, "summary", Some("summary is required — describe what was implemented and how it was verified so the reviewer has context"))?);
                let mut metadata = match a.get("metadata") {
                    None | Some(Value::Null) => None,
                    Some(m @ Value::Object(_)) => Some(m.clone()),
                    Some(o) => return rej(format!("metadata must be an object/dict, got {}", type_name(o))),
                };
                if let Some(arts) = str_list(a, "artifacts", "file paths")?.filter(|v| !v.is_empty()) {
                    metadata.get_or_insert_with(|| json!({}))["artifacts"] = json!(arts);
                }
                if c.scope.is_some() {
                    metadata.get_or_insert_with(|| json!({}))["worker_session_id"] = c.session.clone().into();
                }
                let reviewer = s(a, "reviewer").filter(|x| !x.trim().is_empty()).map(ops::redact);
                if let Some(r) = &reviewer {
                    check(cfg.profile_exists(&r.to_lowercase()), format!("reviewer profile {r:?} is not configured. Configured profiles: {}", cfg.profiles.keys().cloned().collect::<Vec<_>>().join(", ")))?;
                }
                let b = store::read_board(data, slug)?;
                goal_gate(self.name, &b, &tid, &summary)?;
                let run = c.run_for(&tid);
                let r = store::with_board(data, slug, |b| {
                    let live = b.task(&tid).is_some_and(|t| dispatch::claim_is_live(b, t));
                    Ok(ops::request_review(b, data, slug, &tid, ReviewRequest { summary: Some(summary.clone()), metadata: metadata.clone(), reviewer: reviewer.clone(), expected_run: run, force: false, claim_live: live }).map(|_| (b.status_of(&tid).map(String::from), b.latest_run(&tid).map(|r| r.id))))
                })?;
                match r {
                    Ok((st, rid)) => Ok(ok(json!({"task_id": tid, "run_id": rid, "status": st}))),
                    Err(e) if e.contains("artifact") => rej(format!("kanban_request_review could not preserve the declared artifacts: {e}. Your task is still in-flight (no state change) and its scratch workspace was kept. Fix the artifact path or storage error, then retry kanban_request_review with the same handoff.")),
                    Err(e) => rej(format!("could not request review for {tid}: {e}")),
                }
            }
            "kanban_request_changes" => {
                let tid = c.guard(self.name, a)?;
                let reason = ops::redact(&text(a, "reason", Some("reason is required — describe the changes needed"))?);
                let run = c.run_for(&tid);
                let r = store::with_board(data, slug, |b| Ok(ops::request_changes(b, &tid, &reason, run).map(|i| (i, b.status_of(&tid).map(String::from), b.latest_run(&tid).map(|r| r.id)))))?;
                match r {
                    Ok((imp, st, rid)) => Ok(ok(json!({"task_id": tid, "run_id": rid, "status": st, "implementer": imp}))),
                    Err(e) => rej(format!("could not request changes for {tid}: {e}")),
                }
            }
            "kanban_heartbeat" => {
                let tid = c.guard(self.name, a)?;
                let run = c.run_for(&tid);
                let lock = c.scope.as_ref().map(|s| s.lock.clone());
                let okb = store::with_board(data, slug, |b| {
                    ops::heartbeat_claim(b, &tid, lock.as_deref().filter(|l| !l.is_empty()), cfg.claim_ttl_secs);
                    Ok(ops::heartbeat_worker(b, &tid, s(a, "note"), run))
                })?;
                check(okb, format!("could not heartbeat {tid} (unknown id or not running)"))?;
                Ok(ok(json!({"task_id": tid})))
            }
            "kanban_comment" => {
                c.reject_delegated(self.name)?;
                let Some(tid) = s(a, "task_id").filter(|x| !x.trim().is_empty()) else {
                    return rej("task_id is required: comments are per-task and this session has no dispatcher-assigned task to default to. Discover task ids with kanban_list, or pass the task id you mean.");
                };
                let body = ops::redact(&text(a, "body", None)?);
                let author = c.identity(cfg);
                let cid = store::with_board(data, slug, |b| ops::add_comment(b, tid, &author, &body))?;
                Ok(ok(json!({"task_id": tid, "comment_id": cid})))
            }
            "kanban_attach" => {
                let tid = c.guard(self.name, a)?;
                let filename = text(a, "filename", None)?;
                let b64 = text(a, "content_base64", None)?;
                use base64::Engine;
                let bytes = base64::engine::general_purpose::STANDARD.decode(b64.trim()).map_err(|e| Reject(format!("content_base64 is not valid base64: {e}")))?;
                let aid = store::with_board(data, slug, |b| ops::store_attachment(b, data, slug, &tid, &filename, &bytes, s(a, "content_type"), Some("agent"), None))?;
                Ok(ok(json!({"task_id": tid, "attachment_id": aid, "size": bytes.len()})))
            }
            "kanban_attach_url" => {
                let tid = c.guard(self.name, a)?;
                let url = text(a, "url", None)?;
                let filename = s(a, "filename").or(s(a, "title")).map(str::trim).filter(|x| !x.is_empty()).map(String::from).unwrap_or_else(|| {
                    let path = url.split(['?', '#']).next().unwrap_or("");
                    let leaf = path.split("://").nth(1).and_then(|r| r.split_once('/')).map(|(_, p)| p.rsplit('/').next().unwrap_or("")).unwrap_or("");
                    let leaf = pct_decode(leaf);
                    if leaf.trim().is_empty() { "download".into() } else { leaf }
                });
                let (bytes, ct) = download_capped(&url, ATTACHMENT_MAX_BYTES, &FetchPolicy::from_config(cfg.attach_url_allow_private))?;
                let ctype = s(a, "content_type").map(String::from).or(ct);
                let aid = store::with_board(data, slug, |b| ops::store_attachment(b, data, slug, &tid, &filename, &bytes, ctype.as_deref(), Some("agent"), None))?;
                Ok(ok(json!({"task_id": tid, "attachment_id": aid, "size": bytes.len()})))
            }
            "kanban_attachments" => {
                let tid = c.require_task(a)?;
                let b = store::read_board(data, slug)?;
                check(b.task(&tid).is_some(), format!("task {tid} not found"))?;
                Ok(json!({"ok": true, "task_id": tid, "attachments": b.attachments_for(&tid).into_iter().map(attachment_json).collect::<Vec<_>>()}).to_string())
            }
            "kanban_create" => {
                c.reject_delegated(self.name)?;
                let title = text(a, "title", None)?;
                let Some(assignee) = s(a, "assignee").filter(|x| !x.trim().is_empty()) else {
                    return rej("assignee is required — name the profile that should execute this task (the dispatcher will only spawn tasks with an assignee)");
                };
                let triage = boolarg(a, "triage")?;
                let goal_mode = boolarg(a, "goal_mode")?;
                let skills = str_list(a, "skills", "skill names")?;
                let parents = str_list(a, "parents", "task ids")?.unwrap_or_default();
                check(s(a, "model").is_some() || s(a, "provider").is_none(), "'provider' requires 'model' to be set as well")?;
                let meta = super::boards::read_meta(data, slug);
                if meta.kind == "sessions" {
                    return rej(format!("board {slug:?} is a Sessions board; it does not hold cards"));
                }
                let self_task = c.scope.as_ref().map(|s| s.task.clone());
                let identity = c.identity(cfg);
                let session = if c.scope.is_some() { None } else { Some(c.session.clone()).filter(|s| !s.is_empty()) };
                let n = NewTask {
                    title,
                    body: s(a, "body").map(String::from),
                    assignee: Some(assignee.into()),
                    parents,
                    tenant: s(a, "tenant").map(String::from).or_else(|| std::env::var("SEAGENT_TENANT").ok().filter(|t| !t.is_empty())),
                    priority: int(a, "priority")?.unwrap_or(0),
                    workspace_kind: s(a, "workspace_kind").map(String::from),
                    workspace_path: s(a, "workspace_path").map(String::from),
                    triage,
                    idempotency_key: s(a, "idempotency_key").map(String::from),
                    max_runtime_seconds: int(a, "max_runtime_seconds")?,
                    skills,
                    model_override: s(a, "model").map(String::from),
                    provider_override: s(a, "provider").map(String::from),
                    goal_mode,
                    goal_max_turns: int(a, "goal_max_turns")?.map(|x| x.max(1) as u32),
                    completion_contract: s(a, "completion_contract").map(String::from),
                    initial_status: Some(s(a, "initial_status").unwrap_or("running").into()),
                    created_by: Some(identity),
                    creator_task_id: self_task,
                    session_id: s(a, "session_id").map(String::from).or(session.clone()),
                    default_workdir: meta.default_workdir.clone(),
                    ..Default::default()
                };
                let auto_sub = cfg.auto_subscribe_on_create && session.is_some();
                let (id, landed, gate, subscribed) = store::with_board(data, slug, |b| {
                    let id = ops::create_task(b, n)?;
                    let t = b.task(&id).unwrap();
                    let landed = json!({"status": t.status, "workspace_kind": t.workspace_kind, "workspace_path": t.workspace_path, "project_id": s(a, "project").or(s(a, "project_id"))});
                    let wait = b.events_for(&id).into_iter().rev().find(|e| e.kind == "dependency_wait").and_then(|e| e.payload.as_ref().map(|p| p["parent"].clone()));
                    let gate = match wait {
                        Some(p) => json!({"gated": true, "gated_by": p}),
                        None => json!({"gated": false}),
                    };
                    let mut subscribed = false;
                    if auto_sub {
                        subscribed = super::notify::subscribe(b, Subscription { task_id: Some(id.clone()), session_key: session.clone(), delivery_mode: "wake".into(), ..Default::default() }).is_ok();
                    }
                    Ok((id, landed, gate, subscribed))
                })?;
                let mut out = json!({"task_id": id, "subscribed": subscribed});
                out.as_object_mut().unwrap().extend(landed.as_object().unwrap().clone());
                out.as_object_mut().unwrap().extend(gate.as_object().unwrap().clone());
                Ok(ok(out))
            }
            "kanban_unblock" => {
                c.reject_delegated(self.name)?;
                c.orchestrator_only(self.name)?;
                let tid = text(a, "task_id", Some("task_id is required"))?;
                c.enforce_ownership(&tid)?;
                let (okb, st) = store::with_board(data, slug, |b| Ok((ops::unblock(b, &tid), b.status_of(&tid).map(String::from))))?;
                check(okb, format!("could not unblock {tid} (not blocked or unknown)"))?;
                Ok(ok(json!({"task_id": tid, "status": st})))
            }
            "kanban_link" => {
                c.reject_delegated(self.name)?;
                let (Some(p), Some(ch)) = (s(a, "parent_id").filter(|x| !x.is_empty()), s(a, "child_id").filter(|x| !x.is_empty())) else { return rej("both parent_id and child_id are required") };
                let run = c.run_for(ch);
                let gated = store::with_board(data, slug, |b| ops::link(b, p, ch, run))?;
                let mut out = json!({"parent_id": p, "child_id": ch, "gated": gated});
                if gated {
                    out["gated_by"] = p.into();
                }
                Ok(ok(out))
            }
            other => rej(format!("unknown kanban tool {other}")),
        }
    }
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests;
