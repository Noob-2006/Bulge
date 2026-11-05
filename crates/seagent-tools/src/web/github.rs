//! `github_read` / `github_search`: public GitHub issues, pull requests, commits and Actions
//! workflow-job logs, plus issue/PR search inside one repository. Ported from OpenClaw
//! `extensions/github`:
//!
//! * `index.ts` — both tools' descriptions and parameter schemas (1–4096-char `url` with
//!   `refresh`; `repository` + `kind` + `state` + `page`, 256-char plain-text `query`) and the
//!   "Provide a public …" validation messages. The descriptions drop upstream's "the Gateway
//!   reads GitHub; the sandbox needs no credentials" sentence, which is not true of this port.
//! * `src/targets.ts` — owner/repo/commit-SHA validation, the issue/pull/commit and
//!   `actions/runs/{run}/job/{job}` URL shapes, canonical target URLs.
//! * `src/search-params.ts` — keyword quoting (every word becomes a literal phrase, so caller
//!   text can never be a qualifier or Boolean operator), the 256-char bounds, page 1–50.
//! * `src/search.ts` — repository visibility check before and after the search, the fixed
//!   `repo:` / `is:public` / `is:issue|is:pull-request` / `is:<state>` query, `sort=updated`,
//!   20 per page, the 1 000-result limit, `nextPage` / `incomplete` / `limited` and the
//!   "item outside the requested scope" rejection.
//! * `src/detail.ts`, `src/detail-checks.ts`, `src/job-logs.ts`, `src/preview*.ts`,
//!   `src/view-model.ts` — the reader document: 32 KiB body, 20 comments at 4 KiB each, review
//!   comments with diff and line context, file changes (30 files, 16 KiB patch each, 96 KiB
//!   total), PR checks (runs + legacy statuses, 100 items, failure > pending > success) and the
//!   last 64 KiB of a completed job log with its run and commit identity.
//! * `src/github-api.ts` — `Accept: application/vnd.github+json`, `X-GitHub-Api-Version`,
//!   `User-Agent`, bearer token, 256 KiB / 1 MiB response caps and the normalised error text
//!   (401 / 403 / rate limit / 404 / 5xx) with the anonymous retry for an unusable credential.
//!
//! Public reads work without a credential at GitHub's lower anonymous rate limit
//! (`GITHUB_TOKEN`, `GH_TOKEN` or `[web.providers.github] api_key` raise it). HTTP goes through
//! `web::http`, so a `[web.providers.github] base_url` (GitHub Enterprise) keeps the loopback
//! guard of `web::ssrf`. Deliberate deviations: no document cache (`refresh` is accepted and
//! always fetches), no avatar / co-author decoration (upstream's extra commits request plus image
//! bytes), and the job log is fetched in one GET and then tailed, because `http::Resp` exposes no
//! response headers for a `HEAD`/`Range` pair. Response headers are unavailable in general, so
//! `Link`-based pagination flags come from the JSON counts, a rate limit is recognised from a 429
//! or a 403 whose body names the limit (not from `Retry-After` / `X-RateLimit-*`), and the
//! `User-Agent` names seagent rather than the Control UI. Byte-based caps (`truncate_str`) bound the
//! body and patch text by bytes where upstream counts UTF-16 units.
//!
//! OpenClaw is MIT-licensed; see `THIRD_PARTY_NOTICES.md`.

use crate::web::content::wrap_web;
use crate::web::http::{self, EnvFn, WebCtx};
use crate::web::ssrf;
use crate::web::WebConfig;
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::sync::Arc;

const API: &str = "https://api.github.com";
const API_VERSION: &str = "2022-11-28";
/// OpenClaw `GITHUB_REQUEST_TIMEOUT_MS`.
const REQUEST_TIMEOUT: u64 = 8;
/// OpenClaw `GITHUB_JSON_MAX_BYTES` and `DETAIL_JSON_MAX_BYTES`.
const JSON_MAX: usize = 256 * 1024;
const DETAIL_JSON_MAX: usize = 1024 * 1024;
const SEARCH_PAGE_SIZE: usize = 20;
const SEARCH_RESULT_LIMIT: usize = 1_000;
const QUERY_MAX_CHARS: usize = 256;
const BODY_MAX_CHARS: usize = 32 * 1024;
const COMMENT_LIMIT: usize = 20;
const COMMENT_MAX_CHARS: usize = 4 * 1024;
const FILE_LIMIT: usize = 30;
const PATCH_MAX_CHARS: usize = 16 * 1024;
const PATCH_TOTAL_MAX_CHARS: usize = 96 * 1024;
const CHECK_LIMIT: usize = 100;
const LABEL_MAX_CHARS: usize = 256;
/// OpenClaw `LOG_MAX_BYTES`.
const LOG_MAX_BYTES: usize = 64 * 1024;

const ENV: &[&str] = &["GITHUB_TOKEN", "GH_TOKEN"];

/// The two upstream validation messages, verbatim.
const READ_HINT: &str = "Provide a public github.com issue, pull request, commit, or Actions workflow-job URL.";
const SEARCH_HINT: &str = "Provide a public owner/repo repository, shorter plain-text keywords without search syntax, valid kind/state filters, and a page from 1 to 50.";
/// Upstream's only 404 text: a private or vanished repository must not be distinguishable.
const NOT_PUBLIC_404: &str = "GitHub item is unavailable or not public (HTTP 404). Open the link on GitHub to check access.";

// ───────────────────────────── target parsing ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Issue { owner: String, repo: String, number: u64 },
    Pull { owner: String, repo: String, number: u64 },
    Commit { owner: String, repo: String, sha: String },
    Job { owner: String, repo: String, run_id: u64, job_id: u64 },
}

impl Target {
    fn owner(&self) -> &str {
        match self {
            Target::Issue { owner, .. } | Target::Pull { owner, .. } | Target::Commit { owner, .. } | Target::Job { owner, .. } => owner,
        }
    }
    fn repo(&self) -> &str {
        match self {
            Target::Issue { repo, .. } | Target::Pull { repo, .. } | Target::Commit { repo, .. } | Target::Job { repo, .. } => repo,
        }
    }
    fn kind(&self) -> &'static str {
        match self {
            Target::Issue { .. } => "issue",
            Target::Pull { .. } => "pull",
            Target::Commit { .. } => "commit",
            Target::Job { .. } => "job",
        }
    }
    /// `https://github.com/<owner>/<repo>/<surface>/<id>` (OpenClaw `githubTargetUrl`).
    fn url(&self) -> String {
        match self {
            Target::Issue { owner, repo, number } => format!("https://github.com/{owner}/{repo}/issues/{number}"),
            Target::Pull { owner, repo, number } => format!("https://github.com/{owner}/{repo}/pull/{number}"),
            Target::Commit { owner, repo, sha } => format!("https://github.com/{owner}/{repo}/commit/{sha}"),
            Target::Job { owner, repo, run_id, job_id } => format!("https://github.com/{owner}/{repo}/actions/runs/{run_id}/job/{job_id}"),
        }
    }
    /// REST collection for this target (`issues` / `pulls` / `commits` / `actions/jobs`).
    fn collection(&self) -> &'static str {
        match self {
            Target::Issue { .. } => "issues",
            Target::Pull { .. } => "pulls",
            Target::Commit { .. } => "commits",
            Target::Job { .. } => "actions/jobs",
        }
    }
    fn id(&self) -> String {
        match self {
            Target::Issue { number, .. } | Target::Pull { number, .. } => number.to_string(),
            Target::Commit { sha, .. } => sha.clone(),
            Target::Job { job_id, .. } => job_id.to_string(),
        }
    }
}

/// OpenClaw `isValidOwner`.
pub fn valid_owner(v: &str) -> bool {
    let b = v.as_bytes();
    if b.is_empty() || b.len() > 39 || !b[0].is_ascii_alphanumeric() || !b[b.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
}

/// OpenClaw `isValidRepo`: dot/underscore/hyphen edges are allowed, `.git`/`.atom` are not.
pub fn valid_repo(v: &str) -> bool {
    if v.is_empty() || v.len() > 100 {
        return false;
    }
    let lower = v.to_ascii_lowercase();
    if lower == "." || lower == ".." || lower.ends_with(".git") || lower.ends_with(".atom") {
        return false;
    }
    v.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// OpenClaw `validGitHubSearchRepository`: exactly `owner/repo`.
pub fn valid_repository(v: &str) -> bool {
    let parts: Vec<&str> = v.split('/').collect();
    parts.len() == 2 && valid_owner(parts[0]) && valid_repo(parts[1])
}

fn sha_ok(v: &str) -> bool {
    (7..=40).contains(&v.len()) && v.bytes().all(|c| c.is_ascii_hexdigit())
}

/// `/{owner}/{repo}/(issues/N|pull/N[/files]|commit/SHA)`.
fn parse_item_path(path: &str) -> Option<Target> {
    let seg: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if seg.len() == 4 {
        let (owner, repo, surface, id) = (seg[0], seg[1], seg[2], seg[3]);
        if !valid_owner(owner) || !valid_repo(repo) {
            return None;
        }
        let number = || -> Option<u64> {
            if id.is_empty() || id.len() > 10 || !id.bytes().all(|c| c.is_ascii_digit()) || id.starts_with('0') {
                return None;
            }
            id.parse().ok().filter(|n| (1..=9_999_999_999).contains(n))
        };
        return match surface {
            "issues" => number().map(|number| Target::Issue { owner: owner.into(), repo: repo.into(), number }),
            "pull" => number().map(|number| Target::Pull { owner: owner.into(), repo: repo.into(), number }),
            "commit" if sha_ok(id) => Some(Target::Commit { owner: owner.into(), repo: repo.into(), sha: id.to_ascii_lowercase() }),
            _ => None,
        };
    }
    if seg.len() == 5 && seg[2] == "pull" && seg[4] == "files" {
        let (owner, repo, id) = (seg[0], seg[1], seg[3]);
        let number: u64 = id.parse().ok().filter(|n| (1..=9_999_999_999).contains(n) && !id.starts_with('0'))?;
        return (valid_owner(owner) && valid_repo(repo)).then(|| Target::Pull { owner: owner.into(), repo: repo.into(), number });
    }
    None
}

/// `/{owner}/{repo}/actions/runs/{run}/job/{job}`.
fn parse_job_path(path: &str) -> Option<Target> {
    let seg: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if seg.len() != 7 || seg[2] != "actions" || seg[3] != "runs" || seg[5] != "job" {
        return None;
    }
    let num = |s: &str| -> Option<u64> { (!s.is_empty() && s.len() <= 16 && !s.starts_with('0') && s.bytes().all(|c| c.is_ascii_digit())).then(|| s.parse().ok()).flatten() };
    let (owner, repo) = (seg[0], seg[1]);
    if !valid_owner(owner) || !valid_repo(repo) {
        return None;
    }
    Some(Target::Job { owner: owner.into(), repo: repo.into(), run_id: num(seg[4])?, job_id: num(seg[6])? })
}

/// An authority carrying a username or password (`url.username || url.password` upstream).
fn has_userinfo(url: &str) -> bool {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    authority.contains('@')
}

/// A public `github.com` document URL (OpenClaw `parseGitHubReadParams`), or the tool's hint.
pub fn parse_read_url(url: &str) -> Result<Target, String> {
    if url.len() > 4096 {
        return Err(READ_HINT.into());
    }
    let u = ssrf::parse_url(url).map_err(|_| READ_HINT.to_string())?;
    if u.scheme != "https" || u.host != "github.com" || u.port != 443 || has_userinfo(url) {
        return Err(READ_HINT.into());
    }
    let path = u.path.split('?').next().unwrap_or("").trim_end_matches('/');
    parse_job_path(path).or_else(|| parse_item_path(path)).ok_or_else(|| READ_HINT.to_string())
}

/// `(owner, repo, number)` of an item permalink inside `owner/repo` (search result validation).
fn parse_item_url(v: &Value) -> Option<Target> {
    let s = v.as_str()?;
    let u = ssrf::parse_url(s).ok()?;
    (u.scheme == "https" && u.host == "github.com" && u.port == 443 && !has_userinfo(s)).then_some(())?;
    parse_item_path(u.path.split('?').next().unwrap_or(""))
}

// ───────────────────────────── search parameters ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchParams {
    pub repository: String,
    pub query: String,
    /// `issue` | `pull`.
    pub kind: &'static str,
    /// `all` | `open` | `closed`.
    pub state: &'static str,
    pub page: u64,
}

/// Every whitespace-separated word becomes a literal phrase (OpenClaw `quoteGitHubSearchKeywords`).
pub fn quote_keywords(query: &str) -> String {
    let t = query.trim();
    if t.is_empty() {
        return String::new();
    }
    t.split_whitespace().map(|w| format!("\"{w}\"")).collect::<Vec<_>>().join(" ")
}

/// OpenClaw `parseGitHubSearchParams`; unknown keys and search syntax are rejected.
pub fn parse_search_params(v: &Value) -> Result<SearchParams, String> {
    let e = || SEARCH_HINT.to_string();
    let Some(obj) = v.as_object() else { return Err(e()) };
    if obj.keys().any(|k| !["repository", "query", "kind", "state", "page"].contains(&k.as_str())) {
        return Err(e());
    }
    let repository = obj.get("repository").and_then(|x| x.as_str()).filter(|s| valid_repository(s)).ok_or_else(e)?;
    let query = obj.get("query").map(|q| q.as_str().unwrap_or("\u{0}")).unwrap_or("");
    if query.contains('\u{0}') {
        return Err(e());
    }
    if query.chars().count() > QUERY_MAX_CHARS || query.chars().any(|c| matches!(c, '"' | '\\' | ':' | '(' | ')') || c.is_control()) {
        return Err(e());
    }
    if quote_keywords(query).chars().count() > QUERY_MAX_CHARS {
        return Err(e());
    }
    let kind = match obj.get("kind").and_then(|x| x.as_str()) {
        Some("issue") => "issue",
        Some("pull") => "pull",
        _ => return Err(e()),
    };
    let state = match obj.get("state") {
        None => "all",
        Some(Value::String(s)) => match s.as_str() {
            "all" => "all",
            "open" => "open",
            "closed" => "closed",
            _ => return Err(e()),
        },
        // Upstream compares the raw value: only a missing key defaults to `all`.
        Some(_) => return Err(e()),
    };
    let page = match obj.get("page") {
        None => 1,
        Some(x) => x.as_u64().filter(|p| (1..=50).contains(p)).ok_or_else(e)?,
    };
    Ok(SearchParams { repository: repository.to_string(), query: query.trim().to_string(), kind, state, page })
}

/// The fixed search query (OpenClaw `searchWithIdentity`).
pub fn search_query(p: &SearchParams, canonical: &str) -> String {
    let mut parts = vec![format!("repo:{canonical}"), "is:public".into(), format!("is:{}", if p.kind == "pull" { "pull-request" } else { "issue" })];
    if p.state != "all" {
        parts.push(format!("is:{}", p.state));
    }
    let kw = quote_keywords(&p.query);
    if !kw.is_empty() {
        parts.push(kw);
    }
    parts.join(" ")
}

// ───────────────────────────── HTTP ─────────────────────────────

/// One normalised GitHub failure: `status` drives the anonymous retry, `message` reaches the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhError {
    pub status: u16,
    pub message: String,
}

impl GhError {
    fn new(status: u16, message: impl Into<String>) -> GhError {
        GhError { status, message: message.into() }
    }
    /// Upstream `formatControlUiGitHubPreviewError`: a 502 is the retryable transport/document
    /// failure and carries the retry hint; every other status keeps its own text.
    fn text(&self) -> String {
        if self.status == 502 {
            format!("{}. Retry or check GitHub availability.", crate::util::truncate_str(&self.message, 256))
        } else {
            self.message.clone()
        }
    }
    fn tool(&self) -> ToolOutput {
        ToolOutput::err(self.text())
    }
}

type R<T> = Result<T, GhError>;

/// `[web.providers.github] base_url`, `GITHUB_API_URL`, else the public API.
fn base(c: &WebCtx) -> String {
    c.base_url("github", Some("GITHUB_API_URL"), API)
}

/// OpenClaw `resolveGitHubApiBaseUrl`: HTTPS only, no query/hash, path `/` or `/api/v3`; a
/// self-hosted instance on a loopback address may use plain HTTP (needed for local tests).
pub fn validate_base(b: &str) -> Result<(), String> {
    let u = ssrf::parse_url(b).map_err(|_| "GitHub API base URL must use http:// or https://".to_string())?;
    if u.path.contains('?') || u.path.contains('#') {
        return Err("GitHub API base URL must not carry a query string or fragment".into());
    }
    let clean = matches!(u.path.trim_end_matches('/'), "" | "/api/v3");
    if u.scheme == "https" && clean {
        return Ok(());
    }
    // A self-hosted / local instance may be plain HTTP, but only on a loopback or private address.
    if u.scheme == "http" && clean && is_local_host(&u.host) {
        return Ok(());
    }
    Err(format!("GitHub API base URL {b} is not allowed: use an HTTPS GitHub API base URL (plain HTTP only for a local/private instance)"))
}

/// `localhost` or a loopback / private / link-local IP literal.
fn is_local_host(host: &str) -> bool {
    let h = ssrf::normalize_host(host);
    h == "localhost" || h.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback() || ssrf::is_private_ip(ip)).unwrap_or(false)
}

fn headers(token: Option<&str>) -> Vec<(&'static str, String)> {
    let mut h = vec![
        ("Accept", "application/vnd.github+json".to_string()),
        ("User-Agent", "seagent".to_string()),
        ("X-GitHub-Api-Version", API_VERSION.to_string()),
    ];
    if let Some(t) = token.filter(|t| !t.trim().is_empty()) {
        h.push(("Authorization", format!("Bearer {t}")));
    }
    h
}

/// Status → upstream's normalised error text (`formatControlUiGitHubPreviewError`).
pub fn status_error(status: u16, body: &str) -> GhError {
    let msg = serde_json::from_str::<Value>(body).ok().and_then(|v| v.get("message").and_then(|m| m.as_str()).map(|s| s.to_string())).unwrap_or_default();
    let rate_limited = status == 429 || (status == 403 && {
        let m = msg.to_ascii_lowercase();
        m.contains("rate limit") || m.contains("abuse detection")
    });
    if rate_limited {
        return GhError::new(429, "GitHub API rate limit exceeded (HTTP 429). Wait and retry. An unauthenticated request is limited to 60 calls per hour, so set GITHUB_TOKEN to raise it.");
    }
    match status {
        401 => GhError::new(401, "GitHub authentication failed (HTTP 401). Check GITHUB_TOKEN in the environment, or [web.providers.github] api_key."),
        403 => GhError::new(403, "GitHub access denied (HTTP 403). Check the configured GitHub credential's repository access."),
        404 => GhError::new(404, NOT_PUBLIC_404),
        // Every other status is a retryable 502 upstream, with the upstream status in the text.
        s => GhError::new(502, format!("GitHub request failed (HTTP {s})")),
    }
}

/// Upstream `ControlUiGitHubTransportError`: a fixed text, never the raw transport diagnostic.
fn transport(e: &str) -> String {
    let l = e.to_ascii_lowercase();
    if l.contains("timeout") || l.contains("timed out") {
        "GitHub request timed out".into()
    } else {
        "Could not reach GitHub".into()
    }
}

/// One GET against the fixed API origin with a bounded body.
fn get_json(c: &WebCtx, url: &str, token: Option<&str>, max_bytes: usize) -> R<Value> {
    validate_base(&base(c)).map_err(|e| GhError::new(502, e))?;
    let timeout = c.opt_u64("github", "timeout_seconds").unwrap_or(REQUEST_TIMEOUT).clamp(1, 120);
    let r = http::get(url, &[], &headers(token), timeout).map_err(|e| GhError::new(502, transport(&e)))?;
    if !r.ok() {
        return Err(status_error(r.status, &r.body));
    }
    if r.body.len() > max_bytes {
        return Err(GhError::new(502, "GitHub response exceeded the size limit"));
    }
    serde_json::from_str(&r.body).map_err(|_| GhError::new(502, "GitHub response was not valid JSON"))
}

/// A credential that an unusable token must not disable: retry anonymously on 401/403/429
/// (OpenClaw `withOptionalGitHubAuth`).
fn optional_auth<T>(token: Option<&str>, f: impl Fn(Option<&str>) -> R<T>) -> R<T> {
    match f(token) {
        Err(e) if token.is_some() && matches!(e.status, 401 | 403 | 429) => f(None),
        r => r,
    }
}

fn repo_url(c: &WebCtx, owner: &str, repo: &str) -> String {
    format!("{}/repos/{owner}/{repo}", base(c))
}

fn required_str(v: &Value, k: &str) -> R<String> {
    v.get(k).and_then(|x| x.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).ok_or_else(|| GhError::new(502, format!("GitHub response omitted {k}")))
}

fn optional_str(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn non_negative(v: &Value, k: &str) -> R<u64> {
    v.get(k).and_then(|x| x.as_u64()).ok_or_else(|| GhError::new(502, format!("GitHub response omitted {k}")))
}

/// OpenClaw `isPublicGitHubRepository`.
pub fn is_public_repo(v: &Value) -> bool {
    v.get("private").and_then(|p| p.as_bool()) == Some(false) && v.get("visibility").and_then(|x| x.as_str()) == Some("public")
}

/// `/repos/{owner}/{repo}` — visibility and identity, before any item is read.
fn public_repo(c: &WebCtx, token: Option<&str>, owner: &str, repo: &str) -> R<(String, u64)> {
    let v = get_json(c, &repo_url(c, owner, repo), token, JSON_MAX)?;
    if !is_public_repo(&v) {
        return Err(GhError::new(404, NOT_PUBLIC_404));
    }
    let full = required_str(&v, "full_name")?;
    let id = v.get("id").and_then(|x| x.as_u64()).filter(|n| *n > 0).ok_or_else(|| GhError::new(502, "GitHub returned invalid repository metadata"))?;
    Ok((full, id))
}

// ───────────────────────────── reader document ─────────────────────────────

fn markdown_body(v: Option<&Value>, max_chars: usize) -> (String, bool) {
    let body = v.and_then(|b| b.as_str()).unwrap_or("");
    let cut = crate::util::truncate_str(body, max_chars).to_string();
    let truncated = cut.len() < body.len();
    (cut, truncated)
}

/// Upstream `githubPreviewView`'s badge: a merged PR wins over its state, a closed issue reads as
/// "Closed" in the accent tone unless it was closed as not planned, and the timestamp is the
/// merge time (or the close time of a closed item).
fn badge(kind: &str, state: &str, draft: bool, merged: Option<&str>, state_reason: Option<&str>, closed: Option<&str>) -> Value {
    let (label, tone) = if merged.is_some() {
        ("Merged", "accent")
    } else if draft && state == "open" {
        ("Draft", "neutral")
    } else if state == "open" {
        ("Open", "positive")
    } else if kind == "issue" && state_reason != Some("not_planned") {
        ("Closed", "accent")
    } else {
        ("Closed", "negative")
    };
    let mut v = json!({"label": label, "tone": tone});
    if let Some(ts) = merged.or_else(|| (state == "closed").then_some(closed).flatten()) {
        v["timestamp"] = json!(ts);
    }
    v
}

/// Upstream `commentUrl`: a permalink must be an `https://github.com` URL without userinfo.
fn comment_url(v: &Value) -> R<String> {
    let s = required_str(v, "html_url")?;
    let u = ssrf::parse_url(&s).map_err(|_| GhError::new(502, "GitHub comment returned an unsafe permalink"))?;
    if u.scheme != "https" || u.host != "github.com" || u.port != 443 || has_userinfo(&s) {
        return Err(GhError::new(502, "GitHub comment returned an unsafe permalink"));
    }
    Ok(s)
}

/// One comment, with a permalink-derived id and the source context review / commit comments carry.
/// The flag says a delivered body or diff was cut (which makes the document partial, but does not
/// mean comments are missing).
fn parse_comment(v: &Value, kind: &str) -> R<(Value, bool)> {
    let id = non_negative(v, "id")?;
    let url = comment_url(v)?;
    let user = v.get("user").cloned().unwrap_or(Value::Null);
    let (body, body_cut) = markdown_body(v.get("body"), COMMENT_MAX_CHARS);
    let mut cut = body_cut;
    // Upstream uses the permalink anchor (`#issuecomment-1`, `#discussion_r5`) as the id.
    let id = url.split('#').nth(1).filter(|a| !a.is_empty()).map(str::to_string).unwrap_or_else(|| {
        let prefix = match kind {
            "review" => "discussion_r",
            "commit" => "commitcomment-",
            _ => "issuecomment-",
        };
        format!("{prefix}{id}")
    });
    let mut c = json!({
        "id": id,
        "url": url,
        "author": optional_str(&user, "login").unwrap_or_else(|| "ghost".into()),
        "createdAt": required_str(v, "created_at")?,
        "body": body,
        "bodyTruncated": body_cut,
    });
    if kind != "discussion" {
        if kind == "review" {
            c["label"] = json!("Review comment");
        }
        let line = v.get("line").and_then(|x| x.as_u64()).or_else(|| v.get("original_line").and_then(|x| x.as_u64()));
        let start = v.get("start_line").and_then(|x| x.as_u64()).or_else(|| v.get("original_start_line").and_then(|x| x.as_u64()));
        let line_label = line.map(|l| match start {
            Some(s) if s != l => format!("{s}–{l}"),
            _ => l.to_string(),
        });
        let side = match v.get("side").and_then(|s| s.as_str()) {
            Some("LEFT") => Some("Before change"),
            Some("RIGHT") => Some("After change"),
            _ => None,
        };
        let outdated = v.get("line").and_then(|x| x.as_u64()).is_none() && v.get("original_line").and_then(|x| x.as_u64()).is_some();
        let labels: Vec<&str> = [side, outdated.then_some("Outdated")].into_iter().flatten().collect();
        let mut context = json!({
            "path": optional_str(v, "path"),
            "lineLabel": line_label,
            "label": (!labels.is_empty()).then(|| labels.join(" · ")),
        });
        if kind == "review" {
            let (diff, diff_cut) = markdown_body(v.get("diff_hunk"), COMMENT_MAX_CHARS);
            // A review comment without a diff hunk is incomplete, exactly as upstream.
            cut |= diff_cut || v.get("diff_hunk").and_then(|d| d.as_str()).is_none();
            context["diff"] = json!(diff);
            context["diffTruncated"] = json!(diff_cut);
            if let Some(reply) = v.get("in_reply_to_id").and_then(|x| x.as_u64()).filter(|n| *n > 0) {
                context["replyUrl"] = json!(format!("{}#discussion_r{reply}", url.split('#').next().unwrap_or("")));
                context["replyLabel"] = json!(format!("In reply to #{reply}"));
            }
        }
        c["context"] = context;
    }
    Ok((c, cut))
}

/// One comment page. `truncated` means comments are missing; `content_truncated` only means a
/// delivered comment was cut.
struct CommentPage {
    items: Vec<Value>,
    total: u64,
    truncated: bool,
    content_truncated: bool,
}

/// A comment page pair; a failing optional collection only marks the document partial, exactly as
/// upstream (`fetchComments` swallows everything but an access error).
fn comments(c: &WebCtx, token: Option<&str>, url: &str, kind: &str, total: u64) -> CommentPage {
    let empty = CommentPage { items: vec![], total, truncated: false, content_truncated: false };
    if total == 0 {
        return CommentPage { total: 0, ..empty };
    }
    match get_json(c, url, token, DETAIL_JSON_MAX) {
        Ok(Value::Array(rows)) => {
            let mut page = CommentPage { items: vec![], truncated: rows.len() > COMMENT_LIMIT, ..empty };
            for r in rows.iter().take(COMMENT_LIMIT) {
                match parse_comment(r, kind) {
                    Ok((v, cut)) => {
                        page.content_truncated |= cut;
                        page.items.push(v);
                    }
                    // An unparsable comment (upstream: an unsafe permalink) drops the page.
                    Err(_) => page.truncated = true,
                }
            }
            page.truncated |= page.total > page.items.len() as u64;
            page
        }
        Ok(_) | Err(_) => CommentPage { truncated: true, ..empty },
    }
}

fn parse_files(v: &Value) -> R<(Vec<Value>, bool)> {
    let rows = v.as_array().ok_or_else(|| GhError::new(502, "GitHub files were not an array"))?;
    let mut budget = PATCH_TOTAL_MAX_CHARS;
    let mut truncated = rows.len() > FILE_LIMIT;
    let mut out = vec![];
    for f in rows.iter().take(FILE_LIMIT) {
        let patch_raw = f.get("patch").and_then(|p| p.as_str());
        let (patch, cut) = match patch_raw {
            Some(p) => {
                let t = crate::util::truncate_str(p, PATCH_MAX_CHARS.min(budget)).to_string();
                budget -= t.len();
                (Some(t.clone()), t.len() < p.len())
            }
            None => (None, true),
        };
        truncated |= cut;
        out.push(json!({
            "path": required_str(f, "filename")?,
            "previousPath": optional_str(f, "previous_filename"),
            "status": required_str(f, "status")?,
            "additions": non_negative(f, "additions")?,
            "deletions": non_negative(f, "deletions")?,
            "patch": patch,
            // GitHub omits binary / oversized patches: never imply a complete diff.
            "patchTruncated": cut,
        }));
    }
    Ok((out, truncated))
}

// ── PR checks ──

fn check_state(entry: &Value, kind: &str) -> R<(&'static str, &'static str)> {
    let s = |v: Option<&Value>| v.and_then(|x| x.as_str()).unwrap_or("").to_string();
    let (state, detail): (&'static str, &'static str) = match kind {
        "statuses" => match s(entry.get("state")).as_str() {
            "success" => ("success", "Passed"),
            "pending" => ("pending", "Pending"),
            "failure" => ("failure", "Failed"),
            "error" => ("failure", "Error"),
            _ => return Err(GhError::new(502, "GitHub commit status returned an unknown state")),
        },
        _ => {
            if s(entry.get("status")) == "completed" {
                match s(entry.get("conclusion")).as_str() {
                    "success" => ("success", "Passed"),
                    "neutral" => ("neutral", "Neutral"),
                    "skipped" => ("neutral", "Skipped"),
                    "failure" => ("failure", "Failed"),
                    "cancelled" => ("failure", "Canceled"),
                    "timed_out" => ("failure", "Timed out"),
                    "action_required" => ("failure", "Action required"),
                    "stale" => ("failure", "Stale"),
                    "startup_failure" => ("failure", "Could not start"),
                    _ => return Err(GhError::new(502, "GitHub check returned an unknown state")),
                }
            } else {
                match s(entry.get("status")).as_str() {
                    "queued" => ("pending", "Queued"),
                    "in_progress" => ("pending", "In progress"),
                    "waiting" | "requested" | "pending" => ("pending", "Waiting"),
                    _ => return Err(GhError::new(502, "GitHub check returned an unknown state")),
                }
            }
        }
    };
    Ok((state, detail))
}

fn https_url(v: Option<&Value>) -> Option<String> {
    let s = v.and_then(|x| x.as_str()).filter(|s| s.len() <= 4096)?;
    let u = ssrf::parse_url(s).ok()?;
    (u.scheme == "https").then(|| s.to_string())
}

fn parse_check_page(page: &Value, commit: &str, kind: &str) -> R<(Vec<Value>, u64, bool)> {
    let entries = page.get(if kind == "runs" { "check_runs" } else { "statuses" }).and_then(|x| x.as_array()).ok_or_else(|| GhError::new(502, "GitHub checks returned a different revision or invalid list"))?;
    if kind == "statuses" && page.get("sha").and_then(|s| s.as_str()) != Some(commit) {
        return Err(GhError::new(502, "GitHub checks returned a different revision or invalid list"));
    }
    let total = non_negative(page, "total_count").map_err(|_| GhError::new(502, "GitHub checks returned an invalid count"))?;
    let mut latest: std::collections::BTreeMap<String, (u64, Value)> = Default::default();
    for e in entries.iter().take(CHECK_LIMIT) {
        if e.get("head_sha").and_then(|s| s.as_str()) != Some(commit) && kind == "runs" {
            return Err(GhError::new(502, "GitHub check returned a different revision or invalid item"));
        }
        let id = e.get("id").and_then(|x| x.as_u64()).ok_or_else(|| GhError::new(502, "GitHub checks returned an invalid count"))?;
        let name = required_str(e, if kind == "runs" { "name" } else { "context" })?;
        let (state, detail) = check_state(e, kind)?;
        // Runs are identified by id, legacy statuses by case-insensitive context.
        let key = if kind == "runs" { id.to_string() } else { name.to_ascii_lowercase() };
        if latest.get(&key).map(|(prev, _)| *prev).is_some_and(|prev| prev >= id) {
            continue;
        }
        let item = json!({
            "name": crate::util::truncate_str(&name, LABEL_MAX_CHARS),
            "state": state,
            "detail": detail,
            "url": https_url(if kind == "runs" { e.get("html_url") } else { e.get("target_url") }),
        });
        latest.insert(key, (id, item));
    }
    let missing = total.saturating_sub(entries.len().min(CHECK_LIMIT) as u64);
    let count = latest.len() as u64;
    Ok((latest.into_values().map(|(_, v)| v).collect(), count + missing, entries.len() > CHECK_LIMIT || missing > 0))
}

const STATE_ORDER: [&str; 4] = ["failure", "pending", "success", "neutral"];

fn pull_checks(c: &WebCtx, token: Option<&str>, repo: &str, head: &str, url: &str) -> Value {
    if head.len() != 40 || !head.bytes().all(|b| b.is_ascii_hexdigit()) {
        return json!({"state":"unavailable","summary":"Checks unavailable","total":0,"items":[],"truncated":true,"url":url});
    }
    let commit = format!("{repo}/commits/{head}");
    let mut items: Vec<Value> = vec![];
    let mut total = 0u64;
    let mut truncated = false;
    for kind in ["runs", "statuses"] {
        let suffix = if kind == "runs" { "/check-runs?filter=latest&per_page=" } else { "/status?per_page=" };
        match get_json(c, &format!("{commit}{suffix}{CHECK_LIMIT}"), token, DETAIL_JSON_MAX) {
            Ok(page) => match parse_check_page(&page, head, kind) {
                Ok((mut got, n, cut)) => {
                    total += n;
                    truncated |= cut;
                    items.append(&mut got);
                }
                // Optional CI never hides the PR body.
                Err(_) => truncated = true,
            },
            Err(_) => truncated = true,
        }
    }
    items.sort_by(|a, b| {
        let rank = |v: &Value| STATE_ORDER.iter().position(|s| Some(*s) == v["state"].as_str()).unwrap_or(9);
        rank(a).cmp(&rank(b)).then_with(|| a["name"].as_str().unwrap_or("").cmp(b["name"].as_str().unwrap_or("")))
    });
    truncated |= items.len() > CHECK_LIMIT;
    let count = |s: &str| items.iter().filter(|i| i["state"] == s).count();
    let state = if count("failure") > 0 {
        "failure"
    } else if count("pending") > 0 {
        "pending"
    } else if truncated {
        "unavailable"
    } else if count("success") > 0 {
        "success"
    } else {
        "neutral"
    };
    let summary = [
        truncated.then(|| if items.is_empty() { "Checks unavailable".to_string() } else { "Checks incomplete".to_string() }),
        (count("failure") > 0).then(|| format!("{} failed", count("failure"))),
        (count("pending") > 0).then(|| format!("{} pending", count("pending"))),
        (count("success") > 0).then(|| format!("{} passed", count("success"))),
        (count("neutral") > 0).then(|| format!("{} skipped or neutral", count("neutral"))),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<String>>();
    items.truncate(CHECK_LIMIT);
    json!({
        "state": state,
        "summary": if summary.is_empty() { "No checks reported".to_string() } else { summary.join(" · ") },
        "total": total,
        "items": items,
        "truncated": truncated,
        "url": url,
        "commit": head,
    })
}

// ── job logs ──

fn job_log(c: &WebCtx, token: Option<&str>, job_url: &str) -> R<(String, u64, usize)> {
    let timeout = c.opt_u64("github", "timeout_seconds").unwrap_or(REQUEST_TIMEOUT).clamp(1, 120);
    let r = http::get(&format!("{job_url}/logs"), &[], &headers(token), timeout).map_err(|e| GhError::new(502, transport(&e)))?;
    if !r.ok() {
        return Err(GhError::new(502, "GitHub job logs are unavailable; open the job on GitHub"));
    }
    let total = r.body.len();
    let start = total.saturating_sub(LOG_MAX_BYTES);
    let mut text = r.body[start..].to_string();
    // A byte window can begin inside UTF-8 or a credential: deliver complete lines only.
    if start > 0 {
        text = text.find('\n').map(|i| text[i + 1..].to_string()).unwrap_or_default();
    }
    // Never hand a signed download URL or the configured credential to the model (upstream
    // `redactToolPayloadText` masks credential-shaped strings; the credential we know is ours).
    let text = crate::web::content::strip_invisible(&text);
    let text = match token.filter(|t| t.len() >= 8) {
        Some(t) => text.replace(t, "***"),
        None => text,
    };
    Ok((text, total as u64, start))
}

fn job_document(c: &WebCtx, token: Option<&str>, t: &Target) -> R<Value> {
    let (owner, repo, run_id, job_id) = match t {
        Target::Job { owner, repo, run_id, job_id } => (owner, repo, *run_id, *job_id),
        _ => return Err(GhError::new(400, "Invalid GitHub workflow job target")),
    };
    let repo_url = repo_url(c, owner, repo);
    let job_url = format!("{repo_url}/actions/jobs/{job_id}");
    let job = get_json(c, &job_url, token, JSON_MAX)?;
    let same = |k: &str, want: &str| job.get(k).and_then(|x| x.as_str()).is_some_and(|v| v.eq_ignore_ascii_case(want));
    if job.get("id").and_then(|x| x.as_u64()) != Some(job_id)
        || job.get("run_id").and_then(|x| x.as_u64()) != Some(run_id)
        || !same("url", &job_url)
        || !same("run_url", &format!("{repo_url}/actions/runs/{run_id}"))
        || !job.get("head_sha").and_then(|x| x.as_str()).is_some_and(|s| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(GhError::new(502, "GitHub returned a different or incomplete workflow job"));
    }
    let name = required_str(&job, "name")?;
    let status = required_str(&job, "status")?;
    if status != "completed" {
        return Err(GhError::new(502, "GitHub job is still running; read its logs after it completes"));
    }
    let conclusion = required_str(&job, "conclusion")?;
    let (log, total_bytes, start) = job_log(c, token, &job_url)?;
    let partial = start > 0;
    let summary = if partial {
        format!("Partial log: complete lines from the last {LOG_MAX_BYTES} bytes of {total_bytes} bytes. Earlier output is omitted.")
    } else {
        format!("Complete available job log ({total_bytes} bytes).")
    };
    let body = format!("{summary}\n\n{}", log.split('\n').map(|l| format!("    {l}")).collect::<Vec<_>>().join("\n"));
    Ok(json!({
        "url": t.url(),
        "title": name,
        "subtitle": format!("{owner}/{repo} · job {job_id}"),
        "revision": job["head_sha"],
        "metadata": [
            {"label": "Run", "value": run_id.to_string()},
            {"label": "Job", "value": job_id.to_string()},
            {"label": "Status", "value": status},
            {"label": "Conclusion", "value": conclusion},
        ],
        "body": body,
        "bodyTruncated": partial,
        "partial": partial,
    }))
}

// ── issue / pull / commit ──

fn item_document(c: &WebCtx, token: Option<&str>, t: &Target) -> R<Value> {
    let repo_url = repo_url(c, t.owner(), t.repo());
    let item_url = format!("{repo_url}/{}/{}", t.collection(), t.id());
    // Commits carry their file list inline, so the first page already asks for it.
    let first = if t.kind() == "commit" { format!("{item_url}?per_page={FILE_LIMIT}") } else { item_url.clone() };
    let v = get_json(c, &first, token, DETAIL_JSON_MAX)?;
    if !v.is_object() {
        return Err(GhError::new(502, "GitHub response was not an object"));
    }
    let mut partial = false;
    if t.kind() == "commit" {
        let commit = v.get("commit").cloned().unwrap_or(Value::Null);
        let message = commit.get("message").and_then(|m| m.as_str()).unwrap_or("");
        let (body, cut) = markdown_body(Some(&Value::String(message.into())), BODY_MAX_CHARS);
        partial |= cut;
        let author = v.get("author").cloned().unwrap_or(Value::Null);
        let commit_author = commit.get("author").cloned().unwrap_or(Value::Null);
        let stats = v.get("stats").cloned().unwrap_or(Value::Null);
        let sha = required_str(&v, "sha")?;
        let page = comments(c, token, &format!("{item_url}/comments?per_page={COMMENT_LIMIT}"), "commit", non_negative(&commit, "comment_count")?);
        let CommentPage { items: mut list, total: comments_total, truncated: comments_truncated, content_truncated } = page;
        partial |= content_truncated || comments_truncated;
        list.sort_by(|a, b| a["createdAt"].as_str().unwrap_or("").cmp(b["createdAt"].as_str().unwrap_or("")).then_with(|| a["id"].as_str().unwrap_or("").cmp(b["id"].as_str().unwrap_or(""))));
        let (files, ft) = match v.get("files") {
            Some(f) => parse_files(f)?,
            None => (vec![], true),
        };
        partial |= ft;
        let mut meta = vec![];
        if let Some(a) = stats.get("additions").and_then(|x| x.as_u64()) {
            meta.push(json!({"label":"Additions","value":format!("+{a}"),"tone":"positive"}));
        }
        if let Some(d) = stats.get("deletions").and_then(|x| x.as_u64()) {
            meta.push(json!({"label":"Deletions","value":format!("−{d}"),"tone":"negative"}));
        }
        return Ok(json!({
            "url": t.url(),
            "revision": sha,
            "subtitle": format!("{}/{} · {}", t.owner(), t.repo(), crate::util::truncate_str(&sha, 12)),
            "badge": {"label": "Commit", "tone": "neutral"},
            "title": body.split('\n').next().unwrap_or(""),
            "author": optional_str(&author, "login").or_else(|| optional_str(&commit_author, "name")).unwrap_or_else(|| "ghost".into()),
            "createdAt": optional_str(&commit_author, "date"),
            "metadata": meta,
            "body": body,
            "bodyTruncated": cut,
            "comments": list,
            "commentsTotal": comments_total,
            "commentsTruncated": comments_truncated,
            "files": files,
            "filesTotal": files.len(),
            "filesTruncated": ft,
            "partial": partial,
        }));
    }

    // issue / pull
    let number = match t {
        Target::Issue { number, .. } | Target::Pull { number, .. } => *number,
        _ => unreachable!(),
    };
    let title = required_str(&v, "title")?;
    let state = required_str(&v, "state")?;
    let user = v.get("user").cloned().unwrap_or(Value::Null);
    let (body, cut) = markdown_body(v.get("body"), BODY_MAX_CHARS);
    partial |= cut;
    let merged = optional_str(&v, "merged_at");
    let draft = v.get("draft").and_then(|d| d.as_bool()).unwrap_or(false);
    let mut meta = vec![];
    if let Some(a) = v.get("additions").and_then(|x| x.as_u64()) {
        meta.push(json!({"label":"Additions","value":format!("+{a}"),"tone":"positive"}));
    }
    if let Some(d) = v.get("deletions").and_then(|x| x.as_u64()) {
        meta.push(json!({"label":"Deletions","value":format!("−{d}"),"tone":"negative"}));
    }
    if let Some(f) = v.get("changed_files").and_then(|x| x.as_u64()) {
        meta.push(json!({"label":"Files","value":f.to_string()}));
    }
    if let Some(cm) = v.get("comments").and_then(|x| x.as_u64()) {
        meta.push(json!({"label":"Comments","value":cm.to_string()}));
    }
    let head = v.get("head").cloned().unwrap_or(Value::Null);
    let base_ref = v.get("base").cloned().unwrap_or(Value::Null);
    if t.kind() == "pull" {
        if let (Some(h), Some(b)) = (optional_str(&head, "ref"), optional_str(&base_ref, "ref")) {
            meta.push(json!({"label":"Branch","value":format!("{} → {}", crate::util::truncate_str(&h, 256), crate::util::truncate_str(&b, 256))}));
        }
    }
    let discussion_total = non_negative(&v, "comments")?;
    let discussion = comments(c, token, &format!("{repo_url}/issues/{number}/comments?per_page={COMMENT_LIMIT}"), "discussion", discussion_total);
    let CommentPage { items: mut list, total: mut comments_total, truncated: mut comments_truncated, content_truncated: mut content_cut } = discussion;
    if t.kind() == "pull" {
        let review = comments(c, token, &format!("{item_url}/comments?per_page={COMMENT_LIMIT}&sort=created&direction=asc"), "review", non_negative(&v, "review_comments")?);
        comments_total += review.total;
        comments_truncated |= review.truncated;
        content_cut |= review.content_truncated;
        list.extend(review.items);
    }
    partial |= comments_truncated || content_cut;
    let numeric = |s: &str| s.trim_start_matches(|c: char| !c.is_ascii_digit()).parse::<u64>().unwrap_or(0);
    list.sort_by(|a, b| a["createdAt"].as_str().unwrap_or("").cmp(b["createdAt"].as_str().unwrap_or("")).then_with(|| numeric(a["id"].as_str().unwrap_or("")).cmp(&numeric(b["id"].as_str().unwrap_or("")))));
    let files_total = if t.kind() == "pull" { non_negative(&v, "changed_files")? } else { 0 };
    let (mut files, mut files_truncated) = (vec![], false);
    if t.kind() == "pull" && files_total > 0 {
        match get_json(c, &format!("{item_url}/files?per_page={FILE_LIMIT}"), token, DETAIL_JSON_MAX) {
            Ok(page) => {
                let (f, cut) = parse_files(&page)?;
                files_truncated = cut || files_total > f.len() as u64;
                files = f;
            }
            // A missing diff must not hide the discussion.
            Err(_) => files_truncated = true,
        }
    }
    let checks = if t.kind() == "pull" { Some(pull_checks(c, token, &repo_url, head.get("sha").and_then(|s| s.as_str()).unwrap_or(""), &format!("{}/checks", t.url()))) } else { None };
    partial |= files_truncated || checks.as_ref().is_some_and(|ch| ch["truncated"].as_bool() == Some(true) || ch["state"] == "unavailable");
    let mut doc = json!({
        "url": t.url(),
        "revision": if t.kind() == "pull" { head.get("sha").cloned().unwrap_or(Value::Null) } else { v.get("updated_at").cloned().unwrap_or(Value::Null) },
        "subtitle": format!("{}/{} #{number}", t.owner(), t.repo()),
        "badge": badge(t.kind(), &state, draft, merged.as_deref(), optional_str(&v, "state_reason").as_deref(), optional_str(&v, "closed_at").as_deref()),
        "title": title,
        "author": optional_str(&user, "login").unwrap_or_else(|| "ghost".into()),
        "authorUrl": format!("https://github.com/{}", optional_str(&user, "login").unwrap_or_else(|| "ghost".into())),
        "createdAt": required_str(&v, "created_at")?,
        "updatedAt": required_str(&v, "updated_at")?,
        "metadata": meta,
        "body": body,
        "bodyTruncated": cut,
        "comments": list,
        "commentsTotal": comments_total,
        "commentsTruncated": comments_truncated,
        "files": files,
        "filesTotal": files_total,
        "filesTruncated": files_truncated,
        "partial": partial,
    });
    if let Some(ch) = checks {
        doc["checks"] = ch;
    }
    Ok(doc)
}

/// The whole reader for one target: repository visibility first, then the document.
fn read_document(c: &WebCtx, token: Option<&str>, t: &Target) -> R<Value> {
    let (_, id) = public_repo(c, token, t.owner(), t.repo())?;
    if t.kind() == "job" {
        let doc = job_document(c, token, t)?;
        // The log came from a signed storage URL: re-check visibility before delivering it.
        if public_repo(c, token, t.owner(), t.repo())?.1 != id {
            return Err(GhError::new(404, NOT_PUBLIC_404));
        }
        return Ok(doc);
    }
    item_document(c, token, t)
}

// ───────────────────────────── search ─────────────────────────────

fn search_items(c: &WebCtx, token: Option<&str>, p: &SearchParams) -> R<Value> {
    let (canonical, id) = public_repo(c, token, &owner_of(&p.repository), &repo_of(&p.repository))?;
    if !valid_repository(&canonical) {
        return Err(GhError::new(502, "GitHub returned invalid repository metadata"));
    }
    let q = search_query(p, &canonical);
    let url = format!(
        "{}/search/issues?q={}&sort=updated&order=desc&per_page={SEARCH_PAGE_SIZE}&page={}",
        base(c),
        http::enc(&q),
        p.page
    );
    let v = get_json(c, &url, token, DETAIL_JSON_MAX)?;
    let total = v.get("total_count").and_then(|x| x.as_i64()).filter(|n| *n >= 0).ok_or_else(|| GhError::new(502, "GitHub returned an invalid search page"))? as u64;
    let incomplete = v.get("incomplete_results").and_then(|x| x.as_bool()).ok_or_else(|| GhError::new(502, "GitHub returned an invalid search page"))?;
    let rows = v.get("items").and_then(|x| x.as_array()).filter(|a| a.len() <= SEARCH_PAGE_SIZE).ok_or_else(|| GhError::new(502, "GitHub returned an invalid search page"))?;
    let mut items = vec![];
    for it in rows {
        let target = parse_item_url(it.get("html_url").unwrap_or(&Value::Null));
        let Some(target) = target else { return Err(GhError::new(502, "GitHub search returned an item outside the requested scope")) };
        let (owner, repo, number) = match &target {
            Target::Issue { owner, repo, number } | Target::Pull { owner, repo, number } => (owner, repo, *number),
            _ => return Err(GhError::new(502, "GitHub search returned an item outside the requested scope")),
        };
        // Upstream tests truthiness: an absent or null `pull_request` is an issue.
        let item_kind = if it.get("pull_request").is_some_and(|v| !v.is_null() && v.as_bool() != Some(false)) { "pull" } else { "issue" };
        let state = it.get("state").and_then(|s| s.as_str()).unwrap_or("");
        let repo_matches = format!("{owner}/{repo}").eq_ignore_ascii_case(&canonical)
            && it.get("repository_url").and_then(|x| x.as_str()).is_some_and(|u| u.eq_ignore_ascii_case(&format!("{}/repos/{canonical}", base(c))));
        if !repo_matches
            || it.get("number").and_then(|x| x.as_u64()) != Some(number)
            || item_kind != p.kind
            || target.kind() != p.kind
            || !matches!(state, "open" | "closed")
            || (p.state != "all" && state != p.state)
        {
            return Err(GhError::new(502, "GitHub search returned an item outside the requested scope"));
        }
        items.push(json!({
            "url": target.url(),
            "number": number,
            "kind": item_kind,
            "title": crate::util::truncate_str(&required_str(it, "title")?, 512),
            "state": state,
            "updatedAt": required_str(it, "updated_at")?,
        }));
    }
    // Visibility can change while the search is in flight: never disclose that page.
    let current = public_repo(c, token, &owner_of(&canonical), &repo_of(&canonical))?;
    if current.1 != id {
        return Err(GhError::new(404, NOT_PUBLIC_404));
    }
    let capped = total.min(SEARCH_RESULT_LIMIT as u64);
    let next_page = (p.page * SEARCH_PAGE_SIZE as u64) < capped;
    Ok(json!({
        "repository": canonical,
        "kind": p.kind,
        "page": p.page,
        "pageSize": SEARCH_PAGE_SIZE,
        "totalCount": total,
        "incomplete": incomplete,
        "resultLimit": SEARCH_RESULT_LIMIT,
        "limited": total > SEARCH_RESULT_LIMIT as u64,
        "nextPage": next_page.then(|| p.page + 1),
        "items": items,
    }))
}

fn owner_of(repo: &str) -> String {
    repo.split_once('/').map(|x| x.0.to_string()).unwrap_or_default()
}

fn repo_of(repo: &str) -> String {
    repo.split_once('/').map(|x| x.1.to_string()).unwrap_or_default()
}

// ───────────────────────────── tools ─────────────────────────────

pub struct GitHubRead {
    pub cfg: Arc<WebConfig>,
    pub env: EnvFn,
}

impl GitHubRead {
    fn ctx(&self, t: &ToolCtx) -> WebCtx {
        WebCtx::from_tool(self.cfg.clone(), self.env.clone(), t)
    }
    fn token(&self, c: &WebCtx) -> Option<String> {
        c.key("github", ENV)
    }
}

impl Tool for GitHubRead {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "github_read".into(),
            description: "Read a known public GitHub issue, pull request, commit, or Actions workflow-job URL. Returns the description, bounded discussion and review comments, file changes, PR checks, or the bounded end of a completed job log with its run and commit identity. Inspect partial and truncation flags before treating the result as complete. Does not search or modify GitHub.".into(),
            input_schema: json!({"type":"object","required":["url"],"additionalProperties":false,"properties":{
                "url":{"type":"string","minLength":1,"maxLength":4096,"description":"Public github.com issue, pull request, commit, or Actions workflow-job URL."},
                "refresh":{"type":"boolean","description":"Fetch current content instead of cached content."}}}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let c = self.ctx(ctx);
        vec![Effect::Net { dest: http::host_of(&base(&c)), payload: input.get("url").and_then(|u| u.as_str()).unwrap_or("").to_string() }]
    }
    fn call(&self, t: &ToolCtx, input: Value) -> ToolOutput {
        let c = self.ctx(t);
        let Some(url) = input.get("url").and_then(|u| u.as_str()).map(str::trim).filter(|u| !u.is_empty()) else { return ToolOutput::err(READ_HINT) };
        let target = match parse_read_url(url) {
            Ok(t) => t,
            Err(e) => return ToolOutput::err(e),
        };
        // Upstream requires `refresh` to be a boolean when present (it only gates the cache).
        if input.get("refresh").is_some_and(|r| r.as_bool().is_none()) {
            return ToolOutput::err(READ_HINT);
        }
        // `refresh` only matters for the (unported) document cache: every call is fresh here.
        let token = self.token(&c);
        match optional_auth(token.as_deref(), |tok| read_document(&c, tok, &target)) {
            Ok(doc) => ToolOutput::ok(wrap_web(&serde_json::to_string_pretty(&doc).unwrap_or_default(), "web_fetch")),
            Err(e) => e.tool(),
        }
    }
}

pub struct GitHubSearch {
    pub cfg: Arc<WebConfig>,
    pub env: EnvFn,
}

impl Tool for GitHubSearch {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "github_search".into(),
            description: "Find public issues or pull requests in one chosen GitHub repository. Choose kind=issue or kind=pull; search each separately when you need both. Returns up to 20 matches, newest updated first, and nextPage, incomplete, and limited flags. Returns item URLs for further reading. Does not search private repositories or modify GitHub.".into(),
            input_schema: json!({"type":"object","required":["repository","kind"],"additionalProperties":false,"properties":{
                "repository":{"type":"string","description":"Public github.com repository as owner/repo."},
                "query":{"type":"string","maxLength":256,"description":"Plain-text keywords; up to 256 characters after each word is quoted. No qualifiers, quotes, backslashes, or parentheses. Omit to list matches for the filters."},
                "kind":{"type":"string","enum":["issue","pull"]},
                "state":{"type":"string","enum":["all","open","closed"],"default":"all"},
                "page":{"type":"integer","minimum":1,"maximum":50,"default":1}}}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let c = GitHubRead { cfg: self.cfg.clone(), env: self.env.clone() }.ctx(ctx);
        let repo = input.get("repository").and_then(|r| r.as_str()).unwrap_or("");
        vec![Effect::Net { dest: http::host_of(&base(&c)), payload: format!("{repo} {}", input.get("query").and_then(|q| q.as_str()).unwrap_or("")) }]
    }
    fn call(&self, t: &ToolCtx, input: Value) -> ToolOutput {
        let c = GitHubRead { cfg: self.cfg.clone(), env: self.env.clone() }.ctx(t);
        let p = match parse_search_params(&input) {
            Ok(p) => p,
            Err(e) => return ToolOutput::err(e),
        };
        let token = c.key("github", ENV);
        match optional_auth(token.as_deref(), |tok| search_items(&c, tok, &p)) {
            Ok(v) => ToolOutput::ok(wrap_web(&serde_json::to_string_pretty(&v).unwrap_or_default(), "web_search")),
            Err(e) => e.tool(),
        }
    }
}

/// Both GitHub tools. Upstream enables the plugin by default and needs no credential for
/// public reads, so they are always registered.
pub fn tools(cfg: Arc<WebConfig>, env: EnvFn) -> Vec<Arc<dyn Tool>> {
    vec![Arc::new(GitHubRead { cfg: cfg.clone(), env: env.clone() }), Arc::new(GitHubSearch { cfg, env })]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ctx;
    use crate::web::testutil::{env_of, FakeServer, Reply, Req};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    fn repo(cfg: &FakeServer) -> String {
        format!(r#"{{"providers":{{"github":{{"base_url":"{}"}}}}}}"#, cfg.url)
    }

    fn wc(cfg: &str) -> WebCtx {
        crate::web::testutil::wctx(serde_json::from_str(cfg).unwrap(), &[])
    }

    fn tool_output_json(out: &ToolOutput) -> Value {
        assert!(!out.is_error, "{}", out.content);
        let start = out.content.find("---\n").expect("envelope");
        let body = &out.content[start + 4..out.content.rfind("\n<<<END").expect("envelope end")];
        serde_json::from_str(body.trim()).expect("document json")
    }

    /// A fake server whose `BASE` placeholders expand to its own URL (the document carries
    /// absolute `url` / `run_url` / `repository_url` values that GitHub would return).
    fn dynamic(routes: Vec<(&'static str, u16, &'static str, String)>) -> FakeServer {
        FakeServer::with(move |r: &Req| -> Reply {
            let base = format!("http://{}", r.header("host").unwrap_or_default());
            let key = format!("{} {}", r.method, r.path.split('?').next().unwrap_or(""));
            match routes.iter().find(|(k, ..)| *k == key) {
                Some((_, st, ct, body)) => (*st, ct.to_string(), body.replace("BASE", &base).into_bytes(), vec![]),
                None => (404, "text/plain".into(), format!("no route {key}").into_bytes(), vec![]),
            }
        })
    }

    fn routes() -> Vec<(&'static str, u16, &'static str, String)> {
        vec![
            ("GET /repos/o/r", 200, "application/json", json!({"id":123,"full_name":"o/r","private":false,"visibility":"public"}).to_string()),
            (
                "GET /repos/o/r/issues/7",
                200,
                "application/json",
                json!({
                    "number":7,"title":"Crash on start","state":"open","created_at":"2025-01-02T03:04:05Z","updated_at":"2025-02-03T04:05:06Z",
                    "user":{"login":"octo"},"body":"Steps to reproduce\nsecond line","comments":2,"repository_url":"x"
                })
                .to_string(),
            ),
            (
                "GET /repos/o/r/issues/7/comments",
                200,
                "application/json",
                json!([
                    {"id":9007199254740993u64,"html_url":"https://github.com/o/r/issues/7#issuecomment-1","created_at":"2025-01-03T00:00:00Z","user":{"login":"alice"},"body":"me too"},
                    {"id":2,"html_url":"https://github.com/o/r/issues/7#issuecomment-2","created_at":"2025-01-04T00:00:00Z","user":{},"body":"no author"}
                ])
                .to_string(),
            ),
            (
                "GET /repos/o/r/issues/8/comments",
                200,
                "application/json",
                json!([{"id":4,"html_url":"https://github.com/o/r/pull/8#issuecomment-4","created_at":"2025-03-01T12:00:00Z","user":{"login":"carol"},"body":"looks good"}]).to_string(),
            ),
            (
                "GET /repos/o/r/pulls/8",
                200,
                "application/json",
                json!({
                    "number":8,"title":"Add feature","state":"open","draft":false,"merged_at":null,
                    "created_at":"2025-03-01T00:00:00Z","updated_at":"2025-03-02T00:00:00Z","user":{"login":"octo"},
                    "body":"Implements it","comments":1,"review_comments":1,"changed_files":2,"additions":12,"deletions":3,
                    "head":{"ref":"feature","sha":SHA},"base":{"ref":"main"}
                })
                .to_string(),
            ),
            (
                "GET /repos/o/r/pulls/8/comments",
                200,
                "application/json",
                json!([{
                    "id":5,"html_url":"https://github.com/o/r/pull/8#discussion_r5","created_at":"2025-03-02T00:00:00Z",
                    "user":{"login":"bob"},"body":"nit","path":"src/lib.rs","line":12,"start_line":10,"side":"RIGHT","diff_hunk":"@@ -1 +1 @@"
                }])
                .to_string(),
            ),
            (
                "GET /repos/o/r/pulls/8/files",
                200,
                "application/json",
                json!([
                    {"filename":"src/lib.rs","status":"modified","additions":10,"deletions":2,"patch":"@@ -1 +1 @@\n-a\n+b"},
                    {"filename":"assets/logo.png","status":"added","additions":0,"deletions":0}
                ])
                .to_string(),
            ),
            (
                "GET /repos/o/r/commits/0123456789abcdef0123456789abcdef01234567/check-runs",
                200,
                "application/json",
                json!({"total_count":2,"check_runs":[
                    {"id":1,"name":"build","status":"completed","conclusion":"failure","head_sha":SHA,"html_url":"https://github.com/o/r/runs/1"},
                    {"id":2,"name":"lint","status":"in_progress","head_sha":SHA,"html_url":"https://github.com/o/r/runs/2"}
                ]})
                .to_string(),
            ),
            (
                "GET /repos/o/r/commits/0123456789abcdef0123456789abcdef01234567/status",
                200,
                "application/json",
                json!({"state":"failure","total_count":1,"sha":SHA,"statuses":[
                    {"id":3,"context":"ci/legacy","state":"success","target_url":"https://ci.example/3"}
                ]})
                .to_string(),
            ),
            (
                "GET /repos/o/r/commits/abcdef1",
                200,
                "application/json",
                json!({
                    "sha":"abcdef1234567890","commit":{"message":"Fix the bug\n\nlonger explanation","comment_count":1,"author":{"name":"Ada","date":"2025-04-01T00:00:00Z"}},
                    "author":{"login":"ada"},"stats":{"additions":5,"deletions":1},
                    "files":[{"filename":"a.rs","status":"modified","additions":5,"deletions":1,"patch":"@@ -1 +1 @@"}]
                })
                .to_string(),
            ),
            (
                "GET /repos/o/r/commits/abcdef1/comments",
                200,
                "application/json",
                json!([{"id":7,"html_url":"https://github.com/o/r/commit/abcdef1#commitcomment-7","created_at":"2025-04-02T00:00:00Z","user":{"login":"ada"},"body":"note","path":"a.rs","line":3}]).to_string(),
            ),
            (
                "GET /search/issues",
                200,
                "application/json",
                json!({"total_count":42,"incomplete_results":false,"items":[
                    {"html_url":"https://github.com/o/r/issues/7","repository_url":"BASE/repos/o/r","number":7,"title":"Crash on start","state":"open","updated_at":"2025-02-03T04:05:06Z"},
                    {"html_url":"https://github.com/o/r/issues/9","repository_url":"BASE/repos/o/r","number":9,"title":"Old one","state":"closed","updated_at":"2025-01-01T00:00:00Z"}
                ]})
                .to_string(),
            ),
            (
                "GET /repos/o/r/actions/jobs/55",
                200,
                "application/json",
                json!({
                    "id":55,"run_id":44,"name":"test (ubuntu)","status":"completed","conclusion":"success","head_sha":SHA,
                    "url":"BASE/repos/o/r/actions/jobs/55","run_url":"BASE/repos/o/r/actions/runs/44"
                })
                .to_string(),
            ),
            ("GET /repos/o/r/actions/jobs/55/logs", 200, "text/plain", format!("{}\nlast line of the log\n", "filler".repeat(20_000))),
        ]
    }

    #[test]
    fn target_parsing_follows_upstream_url_shapes() {
        assert_eq!(parse_read_url("https://github.com/o/r/issues/7").unwrap(), Target::Issue { owner: "o".into(), repo: "r".into(), number: 7 });
        assert_eq!(parse_read_url("https://github.com/o/r/pull/8/files").unwrap(), Target::Pull { owner: "o".into(), repo: "r".into(), number: 8 });
        assert_eq!(parse_read_url("https://github.com/o/r/commit/ABCDEF1").unwrap(), Target::Commit { owner: "o".into(), repo: "r".into(), sha: "abcdef1".into() });
        assert!(matches!(
            parse_read_url("https://github.com/o/r/actions/runs/44/job/55/").unwrap(),
            Target::Job { run_id: 44, job_id: 55, .. }
        ));
        // Upstream's refusals: other hosts, plain http, userinfo, source/download/check pages, bad ids.
        for bad in [
            "http://github.com/o/r/issues/7",
            "https://gitlab.com/o/r/issues/7",
            "https://user:secret@github.com/o/r/issues/1",
            "https://github.com:8443/o/r/issues/7",
            "https://github.com/o/r/issues/0",
            "https://github.com/o/r/issues/12345678901",
            "https://github.com/o/r/pull/8/commits",
            "https://github.com/o/r/commit/zzz",
            "https://github.com/o/r/commit/abcdef",
            "https://github.com/o/r",
            "https://github.com/o/r/actions/runs/0/job/55",
        ] {
            assert_eq!(parse_read_url(bad).unwrap_err(), READ_HINT, "{bad}");
        }
        assert_eq!(parse_read_url(&format!("https://github.com/o/r/issues/7?x={}", "a".repeat(4100))).unwrap_err(), READ_HINT);
        assert!(valid_owner("octocat") && !valid_owner("-octo") && !valid_owner(&"a".repeat(40)));
        assert!(valid_repo("my.repo_x-1") && !valid_repo(".git") && !valid_repo("repo.git") && !valid_repo("repo.atom"));
        assert!(valid_repository("o/r") && !valid_repository("o") && !valid_repository("o/r/extra"));
    }

    #[test]
    fn search_params_quote_keywords_and_reject_syntax() {
        let p = parse_search_params(&json!({"repository":"o/r","query":"segfault on start","kind":"pull","state":"open","page":3})).unwrap();
        assert_eq!((p.kind, p.state, p.page), ("pull", "open", 3));
        assert_eq!(quote_keywords(" a  b\tc "), "\"a\" \"b\" \"c\"");
        assert_eq!(quote_keywords(""), "");
        assert_eq!(
            search_query(&p, "o/r"),
            "repo:o/r is:public is:pull-request is:open \"segfault\" \"on\" \"start\""
        );
        let all = SearchParams { repository: "o/r".into(), query: String::new(), kind: "issue", state: "all", page: 1 };
        assert_eq!(search_query(&all, "o/r"), "repo:o/r is:public is:issue");
        for bad in [
            json!({"repository":"o/r","kind":"issue","query":"label:bug"}),
            json!({"repository":"o/r","kind":"issue","query":"\"quoted\""}),
            json!({"repository":"o/r","kind":"issue","query":"back\\slash"}),
            json!({"repository":"o/r","kind":"issue","query":"fn(x)"}),
            json!({"repository":"o/r","kind":"issue","query":"a\u{7}"}),
            json!({"repository":"o/r","kind":"issue","query":"x".repeat(257)}),
            json!({"repository":"o/r","kind":"pr"}),
            json!({"repository":"o/r","kind":"issue","state":"merged"}),
            json!({"repository":"o/r","kind":"issue","state":null}),
            json!({"repository":"o/r","kind":"issue","state":5}),
            json!({"repository":"o/r","kind":"issue","page":0}),
            json!({"repository":"o/r","kind":"issue","page":51}),
            json!({"repository":"o/r","kind":"issue","page":1.5}),
            json!({"repository":"nope","kind":"issue"}),
            json!({"repository":"o/r","kind":"issue","bogus":1}),
            json!({"kind":"issue"}),
        ] {
            assert_eq!(parse_search_params(&bad).unwrap_err(), SEARCH_HINT, "{bad}");
        }
        assert_eq!(parse_search_params(&json!({"repository":"o/r","kind":"issue"})).unwrap().state, "all");
    }

    /// The issue reader: no credential is required for a public repository.
    #[test]
    fn read_issue_document_and_comments() {
        let s = dynamic(routes());
        let c = wc(&repo(&s));
        let t = GitHubRead { cfg: c.cfg.clone(), env: env_of(&[]) };
        let out = t.call(&ctx("gh-issue"), json!({"url":"https://github.com/o/r/issues/7"}));
        assert!(out.content.contains("<<<EXTERNAL_UNTRUSTED_CONTENT"), "untrusted envelope");
        let d = tool_output_json(&out);
        assert_eq!((d["url"].as_str(), d["title"].as_str(), d["author"].as_str()), (Some("https://github.com/o/r/issues/7"), Some("Crash on start"), Some("octo")));
        assert_eq!((d["badge"]["label"].as_str(), d["subtitle"].as_str()), (Some("Open"), Some("o/r #7")));
        assert_eq!(d["body"].as_str(), Some("Steps to reproduce\nsecond line"));
        assert_eq!((d["bodyTruncated"].as_bool(), d["partial"].as_bool()), (Some(false), Some(false)));
        assert_eq!(d["comments"].as_array().unwrap().len(), 2);
        assert_eq!(d["comments"][0]["author"].as_str(), Some("alice"));
        assert_eq!(d["comments"][1]["author"].as_str(), Some("ghost"), "a missing user is ghost, as upstream");
        assert_eq!(d["commentsTotal"].as_u64(), Some(2));
        assert_eq!(d["commentsTruncated"].as_bool(), Some(false));
        // The API headers are the ones GitHub documents; anonymous reads carry no Authorization.
        let q = s.requests()[0].clone();
        assert_eq!(q.header("accept").as_deref(), Some("application/vnd.github+json"));
        assert_eq!(q.header("x-github-api-version").as_deref(), Some("2022-11-28"));
        assert_eq!(q.header("user-agent").as_deref(), Some("seagent"));
        assert!(s.requests().iter().all(|r| r.header("authorization").is_none()));
    }

    #[test]
    fn read_pull_document_with_files_and_checks() {
        let s = dynamic(routes());
        let c = wc(&repo(&s));
        let t = GitHubRead { cfg: c.cfg.clone(), env: env_of(&[("GITHUB_TOKEN", "ghp_secret")]) };
        let d = tool_output_json(&t.call(&ctx("gh-pull"), json!({"url":"https://github.com/o/r/pull/8","refresh":true})));
        assert_eq!((d["title"].as_str(), d["revision"].as_str()), (Some("Add feature"), Some(SHA)));
        assert_eq!(d["metadata"][0]["value"].as_str(), Some("+12"));
        assert_eq!(d["metadata"][1]["value"].as_str(), Some("−3"));
        assert_eq!(d["metadata"][3]["label"].as_str(), Some("Comments"));
        assert_eq!(d["metadata"][4]["label"].as_str(), Some("Branch"));
        assert_eq!(d["metadata"][4]["value"].as_str(), Some("feature → main"));
        // Discussion + review comments merged in time order; a review comment keeps its context.
        assert_eq!(d["comments"].as_array().unwrap().len(), 2);
        assert_eq!(d["comments"][0]["label"].as_str(), None);
        assert_eq!(d["comments"][1]["label"].as_str(), Some("Review comment"));
        assert_eq!(d["comments"][1]["context"]["path"].as_str(), Some("src/lib.rs"));
        assert_eq!(d["comments"][1]["context"]["lineLabel"].as_str(), Some("10–12"));
        assert_eq!(d["comments"][1]["context"]["label"].as_str(), Some("After change"));
        // Files: 30-file cap, binary diffs flagged as incomplete rather than empty.
        assert_eq!(d["files"].as_array().unwrap().len(), 2);
        assert_eq!(d["files"][0]["path"].as_str(), Some("src/lib.rs"));
        assert_eq!(d["files"][0]["patchTruncated"].as_bool(), Some(false));
        assert_eq!(d["files"][1]["patchTruncated"].as_bool(), Some(true));
        assert_eq!(d["filesTotal"].as_u64(), Some(2));
        // Checks: runs and legacy statuses merged, failures first, summary counts, state failure.
        assert_eq!(d["checks"]["state"].as_str(), Some("failure"));
        assert_eq!(d["checks"]["summary"].as_str(), Some("1 failed · 1 pending · 1 passed"));
        assert_eq!(d["checks"]["total"].as_u64(), Some(3));
        assert_eq!(d["checks"]["items"][0]["name"].as_str(), Some("build"));
        assert_eq!(d["checks"]["items"][0]["detail"].as_str(), Some("Failed"));
        assert_eq!(d["checks"]["items"][1]["detail"].as_str(), Some("In progress"));
        assert_eq!(d["checks"]["items"][2]["url"].as_str(), Some("https://ci.example/3"));
        assert_eq!(d["checks"]["commit"].as_str(), Some(SHA));
        assert!(s.requests().iter().all(|r| r.header("authorization").as_deref() == Some("Bearer ghp_secret")), "the token is used when set");
    }

    #[test]
    fn read_commit_document() {
        let s = dynamic(routes());
        let c = wc(&repo(&s));
        let t = GitHubRead { cfg: c.cfg.clone(), env: env_of(&[]) };
        let d = tool_output_json(&t.call(&ctx("gh-commit"), json!({"url":"https://github.com/o/r/commit/abcdef1"})));
        assert_eq!((d["badge"]["label"].as_str(), d["title"].as_str()), (Some("Commit"), Some("Fix the bug")));
        assert_eq!(d["body"].as_str(), Some("Fix the bug\n\nlonger explanation"));
        assert_eq!((d["author"].as_str(), d["createdAt"].as_str()), (Some("ada"), Some("2025-04-01T00:00:00Z")));
        assert_eq!(d["metadata"][0]["value"].as_str(), Some("+5"));
        assert_eq!(d["files"][0]["path"].as_str(), Some("a.rs"));
        assert_eq!(d["comments"][0]["body"].as_str(), Some("note"));
        assert_eq!(d["comments"][0]["id"].as_str(), Some("commitcomment-7"), "the permalink anchor is the id");
        assert_eq!(d["comments"][0]["context"]["path"].as_str(), Some("a.rs"), "commit comments keep their file location");
        assert_eq!(d["comments"][0]["context"]["lineLabel"].as_str(), Some("3"));
        assert_eq!(d["comments"][0]["label"].as_str(), None, "only review comments are labelled");
        assert_eq!(d["commentsTruncated"].as_bool(), Some(false));
        assert_eq!(d["revision"].as_str(), Some("abcdef1234567890"));
        assert!(s.requests().iter().any(|r| r.path.contains("/commits/abcdef1")), "the inline file list is requested");
    }

    #[test]
    fn read_job_log_tails_a_completed_job() {
        let s = dynamic(routes());
        let c = wc(&repo(&s));
        let t = GitHubRead { cfg: c.cfg.clone(), env: env_of(&[]) };
        let d = tool_output_json(&t.call(&ctx("gh-job"), json!({"url":"https://github.com/o/r/actions/runs/44/job/55"})));
        assert_eq!(d["title"].as_str(), Some("test (ubuntu)"));
        assert_eq!(d["subtitle"].as_str(), Some("o/r · job 55"));
        assert_eq!(d["revision"].as_str(), Some(SHA));
        assert_eq!(d["metadata"][3]["value"].as_str(), Some("success"));
        let body = d["body"].as_str().unwrap();
        assert!(body.starts_with("Partial log:"), "{body}");
        assert!(body.contains("last line of the log"), "the tail keeps the end of the log");
        assert_eq!(d["partial"].as_bool(), Some(true));
        assert_eq!(d["bodyTruncated"].as_bool(), Some(true));
    }

    #[test]
    fn read_job_rejects_a_mismatched_or_running_job() {
        let s = dynamic(vec![
            ("GET /repos/o/r", 200, "application/json", json!({"id":1,"full_name":"o/r","private":false,"visibility":"public"}).to_string()),
            ("GET /repos/o/r/actions/jobs/55", 200, "application/json", json!({"id":56,"run_id":44,"name":"x","status":"completed","conclusion":"success","head_sha":SHA,"url":"u","run_url":"v"}).to_string()),
        ]);
        let c = wc(&repo(&s));
        let t = GitHubRead { cfg: c.cfg.clone(), env: env_of(&[]) };
        let o = t.call(&ctx("gh-job-bad"), json!({"url":"https://github.com/o/r/actions/runs/44/job/55"}));
        assert!(o.is_error);
        assert!(o.content.contains("different or incomplete workflow job"), "{}", o.content);
        let s = dynamic(vec![
            ("GET /repos/o/r", 200, "application/json", json!({"id":1,"full_name":"o/r","private":false,"visibility":"public"}).to_string()),
            ("GET /repos/o/r/actions/jobs/55", 200, "application/json", json!({"id":55,"run_id":44,"name":"x","status":"queued","conclusion":null,"head_sha":SHA,"url":"BASE/repos/o/r/actions/jobs/55","run_url":"BASE/repos/o/r/actions/runs/44"}).to_string()),
        ]);
        let c = wc(&repo(&s));
        let t = GitHubRead { cfg: c.cfg.clone(), env: env_of(&[]) };
        let o = t.call(&ctx("gh-job-running"), json!({"url":"https://github.com/o/r/actions/runs/44/job/55"}));
        assert!(o.content.contains("still running"), "{}", o.content);
    }

    /// A private repository and a missing one are indistinguishable, exactly as upstream.
    #[test]
    fn read_refuses_private_or_missing_repositories() {
        let s = FakeServer::start(vec![("GET /repos/o/r", 200, "application/json", json!({"id":1,"full_name":"o/r","private":true,"visibility":"private"}).to_string())]);
        let c = wc(&repo(&s));
        let t = GitHubRead { cfg: c.cfg.clone(), env: env_of(&[]) };
        let o = t.call(&ctx("gh-private"), json!({"url":"https://github.com/o/r/issues/7"}));
        assert!(o.is_error);
        assert_eq!(o.content, NOT_PUBLIC_404);
        assert_eq!(s.requests().len(), 1, "the item is never requested");
        let s = FakeServer::start(vec![("GET /repos/o/r", 404, "application/json", json!({"message":"Not Found"}).to_string())]);
        let c = wc(&repo(&s));
        let t = GitHubRead { cfg: c.cfg.clone(), env: env_of(&[]) };
        let o = t.call(&ctx("gh-404"), json!({"url":"https://github.com/o/r/issues/7"}));
        assert_eq!(o.content, NOT_PUBLIC_404);
    }

    #[test]
    fn search_scopes_paginates_and_rechecks_visibility() {
        let s = dynamic(routes());
        let c = wc(&repo(&s));
        let t = GitHubSearch { cfg: c.cfg.clone(), env: env_of(&[]) };
        let v = tool_output_json(&t.call(&ctx("gh-search"), json!({"repository":"o/r","query":"crash start","kind":"issue","page":1})));
        assert_eq!((v["repository"].as_str(), v["kind"].as_str()), (Some("o/r"), Some("issue")));
        assert_eq!((v["page"].as_u64(), v["pageSize"].as_u64()), (Some(1), Some(20)));
        assert_eq!((v["totalCount"].as_u64(), v["incomplete"].as_bool()), (Some(42), Some(false)));
        assert_eq!((v["limited"].as_bool(), v["nextPage"].as_u64()), (Some(false), Some(2)));
        assert_eq!(v["items"][0]["url"].as_str(), Some("https://github.com/o/r/issues/7"));
        assert_eq!(v["items"][1]["state"].as_str(), Some("closed"));
        assert_eq!(v["items"][0]["kind"].as_str(), Some("issue"));
        let reqs = s.requests();
        let q = reqs.iter().find(|r| r.path.starts_with("/search/issues")).expect("search request");
        let sent = q.query("q").expect("q parameter");
        assert_eq!(sent, "repo:o/r is:public is:issue \"crash\" \"start\"");
        assert_eq!((q.query("sort").as_deref(), q.query("order").as_deref()), (Some("updated"), Some("desc")));
        assert_eq!((q.query("per_page").as_deref(), q.query("page").as_deref()), (Some("20"), Some("1")));
        // The repository is read before and after the search.
        assert_eq!(s.requests().iter().filter(|r| r.path == "/repos/o/r").count(), 2);
    }

    #[test]
    fn search_rejects_items_outside_the_requested_scope() {
        let s = FakeServer::start(vec![
            ("GET /repos/o/r", 200, "application/json", json!({"id":1,"full_name":"o/r","private":false,"visibility":"public"}).to_string()),
            (
                "GET /search/issues",
                200,
                "application/json",
                json!({"total_count":1,"incomplete_results":false,"items":[
                    {"html_url":"https://github.com/other/repo/issues/7","repository_url":"BASE/repos/o/r","number":7,"title":"x","state":"open","updated_at":"2025-01-01T00:00:00Z"}
                ]})
                .to_string(),
            ),
        ]);
        let c = wc(&repo(&s));
        let t = GitHubSearch { cfg: c.cfg.clone(), env: env_of(&[]) };
        let o = t.call(&ctx("gh-scope"), json!({"repository":"o/r","kind":"issue"}));
        assert!(o.is_error);
        assert!(o.content.contains("outside the requested scope"), "{}", o.content);
    }

    #[test]
    fn search_marks_the_thousand_result_limit() {
        let s = FakeServer::start(vec![
            ("GET /repos/o/r", 200, "application/json", json!({"id":1,"full_name":"o/r","private":false,"visibility":"public"}).to_string()),
            ("GET /search/issues", 200, "application/json", json!({"total_count":5000,"incomplete_results":true,"items":[]}).to_string()),
        ]);
        let c = wc(&repo(&s));
        let t = GitHubSearch { cfg: c.cfg.clone(), env: env_of(&[]) };
        let v = tool_output_json(&t.call(&ctx("gh-limit"), json!({"repository":"o/r","kind":"pull","page":50})));
        assert_eq!((v["limited"].as_bool(), v["incomplete"].as_bool()), (Some(true), Some(true)));
        assert!(v["nextPage"].is_null(), "search results stop at 1000");
        assert_eq!(v["resultLimit"].as_u64(), Some(1000));
    }

    #[test]
    fn status_errors_map_to_upstream_messages() {
        assert!(status_error(403, r#"{"message":"API rate limit exceeded for 1.2.3.4."}"#).message.starts_with("GitHub API rate limit exceeded (HTTP 429)"));
        assert!(status_error(429, "").message.contains("rate limit"));
        assert!(status_error(403, r#"{"message":"Resource not accessible by integration"}"#).message.starts_with("GitHub access denied (HTTP 403)"));
        assert!(status_error(401, "").message.starts_with("GitHub authentication failed (HTTP 401)"));
        assert_eq!(status_error(404, "").status, 404);
        assert!(status_error(503, "").message.starts_with("GitHub request failed (HTTP 503)"));
        // Only a transport-grade 502 carries upstream's retry hint; 401/403/404/429 do not.
        assert_eq!(status_error(503, "").text(), "GitHub request failed (HTTP 503). Retry or check GitHub availability.");
        assert_eq!(status_error(422, "").text(), "GitHub request failed (HTTP 422). Retry or check GitHub availability.");
        assert_eq!(status_error(404, "").text(), NOT_PUBLIC_404);
        assert_eq!(status_error(429, "").text(), status_error(429, "").message);
        let s = FakeServer::start(vec![("GET /repos/o/r", 403, "application/json", r#"{"message":"API rate limit exceeded"}"#.into())]);
        let c = wc(&repo(&s));
        let t = GitHubRead { cfg: c.cfg.clone(), env: env_of(&[]) };
        let o = t.call(&ctx("gh-rate"), json!({"url":"https://github.com/o/r/issues/7"}));
        assert!(o.content.contains("set GITHUB_TOKEN"), "{}", o.content);
        assert!(!o.content.contains("Retry or check GitHub availability"), "{}", o.content);
    }

    /// A malformed document is a retryable 502 and reads exactly like upstream's formatted error.
    #[test]
    fn a_transport_grade_failure_carries_the_retry_hint() {
        let s = FakeServer::start(vec![("GET /repos/o/r", 200, "application/json", "not json".into())]);
        let c = wc(&repo(&s));
        let t = GitHubRead { cfg: c.cfg.clone(), env: env_of(&[("GITHUB_TOKEN", "ghp_secret")]) };
        let o = t.call(&ctx("gh-badjson"), json!({"url":"https://github.com/o/r/issues/7"}));
        assert!(o.is_error);
        assert_eq!(o.content, "GitHub response was not valid JSON. Retry or check GitHub availability.");
        assert!(!o.content.contains("ghp_secret"), "no credential is echoed");
    }

    /// An unusable credential must not disable public reads (OpenClaw `withOptionalGitHubAuth`).
    #[test]
    fn a_rejected_token_retries_anonymously() {
        let seen = std::sync::Arc::new(AtomicUsize::new(0));
        let s = FakeServer::with(move |r: &Req| -> Reply {
            if r.path != "/repos/o/r" {
                return (404, "application/json".into(), br#"{"message":"Not Found"}"#.to_vec(), vec![]);
            }
            seen.fetch_add(1, Ordering::SeqCst);
            if r.header("authorization").is_some() {
                (401, "application/json".into(), br#"{"message":"Bad credentials"}"#.to_vec(), vec![])
            } else {
                (200, "application/json".into(), br#"{"id":1,"full_name":"o/r","private":false,"visibility":"public"}"#.to_vec(), vec![])
            }
        });
        let c = wc(&repo(&s));
        let t = GitHubSearch { cfg: c.cfg.clone(), env: env_of(&[("GITHUB_TOKEN", "expired")]) };
        let o = t.call(&ctx("gh-anon"), json!({"repository":"o/r","kind":"issue"}));
        // The retry succeeds at the repository read, then fails on the search (404 here).
        assert!(o.is_error);
        assert!(o.content.contains("HTTP 404"), "{}", o.content);
        assert!(s.requests().len() >= 3);
        assert!(s.requests().last().unwrap().header("authorization").is_none(), "the retry is anonymous");
    }

    #[test]
    fn base_url_must_be_an_api_root() {
        assert!(validate_base("https://api.github.com").is_ok());
        assert!(validate_base("https://ghe.example.com/api/v3/").is_ok());
        assert!(validate_base("http://127.0.0.1:8080").is_ok());
        assert!(validate_base("ftp://api.github.com").is_err());
        assert!(validate_base("https://api.github.com/?token=1").is_err());
        assert!(validate_base("https://api.github.com/repos").is_err());
        assert!(validate_base("http://example.com").is_err(), "public plain HTTP is refused");
    }

    #[test]
    fn tools_are_always_registered() {
        let cfg = Arc::new(WebConfig::default());
        let names: Vec<String> = tools(cfg, env_of(&[])).iter().map(|t| t.spec().name).collect();
        assert_eq!(names, vec!["github_read", "github_search"]);
        for t in tools(Arc::new(WebConfig::default()), env_of(&[])) {
            let s = t.spec();
            assert_eq!(s.input_schema["type"], "object");
            assert_eq!(s.input_schema["additionalProperties"], false);
            assert!(!s.description.is_empty());
        }
        let read = GitHubRead { cfg: Arc::new(WebConfig::default()), env: env_of(&[]) };
        let spec = read.spec();
        assert_eq!(spec.input_schema["required"], json!(["url"]));
        assert_eq!(spec.input_schema["properties"]["url"]["maxLength"].as_u64(), Some(4096));
        let search = GitHubSearch { cfg: Arc::new(WebConfig::default()), env: env_of(&[]) };
        let spec = search.spec();
        assert_eq!(spec.input_schema["required"], json!(["repository", "kind"]));
        assert_eq!(spec.input_schema["properties"]["query"]["maxLength"].as_u64(), Some(256));
        assert_eq!(spec.input_schema["properties"]["page"]["maximum"].as_u64(), Some(50));
    }

    #[test]
    fn body_and_comment_truncation_is_flagged() {
        let long_body = "x".repeat(BODY_MAX_CHARS + 100);
        let long_comment = "y".repeat(COMMENT_MAX_CHARS + 100);
        let s = FakeServer::start(vec![
            ("GET /repos/o/r", 200, "application/json", json!({"id":1,"full_name":"o/r","private":false,"visibility":"public"}).to_string()),
            (
                "GET /repos/o/r/issues/7",
                200,
                "application/json",
                json!({"number":7,"title":"t","state":"closed","created_at":"2025-01-01T00:00:00Z","updated_at":"2025-01-01T00:00:00Z","user":{"login":"a"},"body":long_body,"comments":1}).to_string(),
            ),
            (
                "GET /repos/o/r/issues/7/comments",
                200,
                "application/json",
                json!([{"id":1,"html_url":"https://github.com/o/r/issues/7#issuecomment-1","created_at":"2025-01-01T00:00:00Z","user":{"login":"b"},"body":long_comment}]).to_string(),
            ),
        ]);
        let c = wc(&repo(&s));
        let t = GitHubRead { cfg: c.cfg.clone(), env: env_of(&[]) };
        let d = tool_output_json(&t.call(&ctx("gh-long"), json!({"url":"https://github.com/o/r/issues/7"})));
        assert_eq!(d["bodyTruncated"].as_bool(), Some(true));
        assert_eq!(d["body"].as_str().unwrap().len(), BODY_MAX_CHARS);
        assert_eq!(d["comments"][0]["bodyTruncated"].as_bool(), Some(true));
        assert_eq!(d["comments"][0]["body"].as_str().unwrap().len(), COMMENT_MAX_CHARS);
        assert_eq!(d["partial"].as_bool(), Some(true));
        assert_eq!(d["commentsTruncated"].as_bool(), Some(false), "a cut body is not a missing comment");
        assert_eq!(d["badge"]["label"].as_str(), Some("Closed"));
    }

    #[test]
    fn bad_arguments_return_the_upstream_hint() {
        let c = wc(r#"{"providers":{"github":{"base_url":"https://api.github.com"}}}"#);
        let read = GitHubRead { cfg: c.cfg.clone(), env: env_of(&[]) };
        let ct = ctx("gh-args");
        assert_eq!(read.call(&ct, json!({})).content, READ_HINT);
        assert_eq!(read.call(&ct, json!({"url":"https://example.com/o/r/issues/1"})).content, READ_HINT);
        assert_eq!(read.call(&ct, json!({"url":"https://github.com/o/r/issues/1","refresh":"yes"})).content, READ_HINT);
        assert_eq!(read.call(&ct, json!({"url":"https://github.com/o/r/issues/1","refresh":null})).content, READ_HINT, "upstream rejects a null refresh");
        assert_eq!(read.call(&ct, json!({"url":"https://user@github.com/o/r/issues/1"})).content, READ_HINT);
        let search = GitHubSearch { cfg: c.cfg.clone(), env: env_of(&[]) };
        assert_eq!(search.call(&ct, json!({"repository":"o/r"})).content, SEARCH_HINT);
    }

    /// Upstream keys a comment by its permalink anchor and keeps the source context on review and
    /// commit comments, including the reply link.
    #[test]
    fn comment_ids_come_from_permalinks_and_review_context_keeps_replies() {
        let s = dynamic(vec![
            ("GET /repos/o/r", 200, "application/json", json!({"id":1,"full_name":"o/r","private":false,"visibility":"public"}).to_string()),
            (
                "GET /repos/o/r/pulls/8",
                200,
                "application/json",
                json!({
                    "number":8,"title":"Add feature","state":"open","draft":false,"merged_at":null,
                    "created_at":"2025-03-01T00:00:00Z","updated_at":"2025-03-02T00:00:00Z","user":{"login":"octo"},
                    "body":"b","comments":1,"review_comments":1,"changed_files":0,
                    "head":{"ref":"feature","sha":SHA},"base":{"ref":"main"}
                })
                .to_string(),
            ),
            (
                "GET /repos/o/r/issues/8/comments",
                200,
                "application/json",
                json!([{"id":11,"html_url":"https://github.com/o/r/issues/8#issuecomment-11","created_at":"2025-03-01T00:00:00Z","user":{"login":"a"},"body":"first"}]).to_string(),
            ),
            (
                "GET /repos/o/r/pulls/8/comments",
                200,
                "application/json",
                json!([{
                    "id":12,"html_url":"https://github.com/o/r/pull/8#discussion_r12","created_at":"2025-03-01T01:00:00Z",
                    "user":{"login":"b"},"body":"nit","path":"src/lib.rs","line":14,"start_line":12,"side":"LEFT",
                    "diff_hunk":"@@ -1 +1 @@","in_reply_to_id":7
                }])
                .to_string(),
            ),
            (
                "GET /repos/o/r/commits/0123456789abcdef0123456789abcdef01234567/check-runs",
                200,
                "application/json",
                json!({"total_count":0,"check_runs":[]}).to_string(),
            ),
            (
                "GET /repos/o/r/commits/0123456789abcdef0123456789abcdef01234567/status",
                200,
                "application/json",
                json!({"total_count":0,"sha":SHA,"statuses":[]}).to_string(),
            ),
        ]);
        let c = wc(&repo(&s));
        let t = GitHubRead { cfg: c.cfg.clone(), env: env_of(&[]) };
        let d = tool_output_json(&t.call(&ctx("gh-ids"), json!({"url":"https://github.com/o/r/pull/8"})));
        assert_eq!(d["comments"][0]["id"].as_str(), Some("issuecomment-11"), "the discussion anchor is the id");
        assert_eq!(d["comments"][1]["id"].as_str(), Some("discussion_r12"), "the review anchor is the id");
        // Every comment carries its permalink verbatim.
        assert_eq!(d["comments"][1]["url"].as_str(), Some("https://github.com/o/r/pull/8#discussion_r12"));
        assert_eq!(d["comments"][1]["context"]["lineLabel"].as_str(), Some("12–14"));
        assert_eq!(d["comments"][1]["context"]["label"].as_str(), Some("Before change"));
        assert_eq!(d["comments"][1]["context"]["replyUrl"].as_str(), Some("https://github.com/o/r/pull/8#discussion_r7"));
        assert_eq!(d["comments"][1]["context"]["replyLabel"].as_str(), Some("In reply to #7"));
        assert!(d["comments"][0]["context"].is_null(), "a discussion comment has no source context");
        assert_eq!((d["commentsTruncated"].as_bool(), d["partial"].as_bool()), (Some(false), Some(false)));
    }

    /// A comment that is not a github.com permalink is dropped and reported, never echoed.
    #[test]
    fn unsafe_comment_permalinks_drop_the_page() {
        for bad in ["https://example.com/steal", "https://user:secret@github.com/o/r/issues/7#issuecomment-1"] {
            let s = FakeServer::start(vec![
                ("GET /repos/o/r", 200, "application/json", json!({"id":1,"full_name":"o/r","private":false,"visibility":"public"}).to_string()),
                (
                    "GET /repos/o/r/issues/7",
                    200,
                    "application/json",
                    json!({"number":7,"title":"t","state":"open","created_at":"2025-01-01T00:00:00Z","updated_at":"2025-01-01T00:00:00Z","user":{"login":"a"},"body":"b","comments":1}).to_string(),
                ),
                (
                    "GET /repos/o/r/issues/7/comments",
                    200,
                    "application/json",
                    json!([{"id":1,"html_url":bad,"created_at":"2025-01-01T00:00:00Z","user":{"login":"b"},"body":"x"}]).to_string(),
                ),
            ]);
            let c = wc(&repo(&s));
            let t = GitHubRead { cfg: c.cfg.clone(), env: env_of(&[]) };
            let o = t.call(&ctx("gh-permalink"), json!({"url":"https://github.com/o/r/issues/7"}));
            let d = tool_output_json(&o);
            assert_eq!(d["title"].as_str(), Some("t"), "the item survives: {bad}");
            assert_eq!(d["comments"].as_array().unwrap().len(), 0, "{bad}");
            assert_eq!((d["commentsTruncated"].as_bool(), d["partial"].as_bool()), (Some(true), Some(true)), "{bad}");
            assert!(!o.content.contains("steal") && !o.content.contains("secret"), "the permalink is not echoed: {}", o.content);
        }
    }

    /// `commentsTruncated` reports missing comments only — a cut body is a partial document.
    #[test]
    fn commit_comment_bodies_are_partial_but_not_missing_comments() {
        let long = "y".repeat(COMMENT_MAX_CHARS + 100);
        let s = FakeServer::start(vec![
            ("GET /repos/o/r", 200, "application/json", json!({"id":1,"full_name":"o/r","private":false,"visibility":"public"}).to_string()),
            (
                "GET /repos/o/r/commits/abcdef1",
                200,
                "application/json",
                json!({
                    "sha":"abcdef1234567890","commit":{"message":"Fix","comment_count":1,"author":{"name":"Ada","date":"2025-04-01T00:00:00Z"}},
                    "author":{"login":"ada"},"stats":{"additions":1,"deletions":0},"files":[]
                })
                .to_string(),
            ),
            (
                "GET /repos/o/r/commits/abcdef1/comments",
                200,
                "application/json",
                json!([{"id":7,"html_url":"https://github.com/o/r/commit/abcdef1#commitcomment-7","created_at":"2025-04-02T00:00:00Z","user":{"login":"ada"},"body":long}]).to_string(),
            ),
        ]);
        let c = wc(&repo(&s));
        let t = GitHubRead { cfg: c.cfg.clone(), env: env_of(&[]) };
        let d = tool_output_json(&t.call(&ctx("gh-commit-long"), json!({"url":"https://github.com/o/r/commit/abcdef1"})));
        assert_eq!(d["comments"][0]["bodyTruncated"].as_bool(), Some(true));
        assert_eq!(d["commentsTruncated"].as_bool(), Some(false), "the comment is present, only cut");
        assert_eq!(d["commentsTotal"].as_u64(), Some(1));
        assert_eq!(d["partial"].as_bool(), Some(true));
    }

    /// A closed issue reads as accent unless it was closed as not planned; the badge carries the
    /// close time, as upstream's `githubPreviewView` does.
    #[test]
    fn closed_issue_badge_uses_the_completion_tone() {
        let doc = |number: u64, kind_state: &str, reason: &str| {
            json!({
                "number":number,"title":"t","state":"closed","state_reason":reason,"closed_at":"2025-05-01T00:00:00Z",
                "created_at":"2025-01-01T00:00:00Z","updated_at":"2025-05-01T00:00:00Z","user":{"login":"a"},"body":"b",
                "comments":0,"review_comments":0,"changed_files":0,"merged_at":null,"kind":kind_state
            })
            .to_string()
        };
        let s = dynamic(vec![
            ("GET /repos/o/r", 200, "application/json", json!({"id":1,"full_name":"o/r","private":false,"visibility":"public"}).to_string()),
            ("GET /repos/o/r/issues/1", 200, "application/json", doc(1, "issue", "completed")),
            ("GET /repos/o/r/issues/2", 200, "application/json", doc(2, "issue", "not_planned")),
            ("GET /repos/o/r/pulls/3", 200, "application/json", doc(3, "pull", "completed")),
        ]);
        let c = wc(&repo(&s));
        let t = GitHubRead { cfg: c.cfg.clone(), env: env_of(&[]) };
        let done = tool_output_json(&t.call(&ctx("gh-closed"), json!({"url":"https://github.com/o/r/issues/1"})));
        assert_eq!((done["badge"]["label"].as_str(), done["badge"]["tone"].as_str()), (Some("Closed"), Some("accent")));
        assert_eq!(done["badge"]["timestamp"].as_str(), Some("2025-05-01T00:00:00Z"));
        let dropped = tool_output_json(&t.call(&ctx("gh-notplanned"), json!({"url":"https://github.com/o/r/issues/2"})));
        assert_eq!(dropped["badge"]["tone"].as_str(), Some("negative"));
        let unmerged = tool_output_json(&t.call(&ctx("gh-closed-pr"), json!({"url":"https://github.com/o/r/pull/3"})));
        assert_eq!((unmerged["badge"]["label"].as_str(), unmerged["badge"]["tone"].as_str()), (Some("Closed"), Some("negative")));
    }

    /// Upstream validates the canonical repository name a search is scoped to.
    #[test]
    fn search_rejects_invalid_repository_metadata() {
        let s = FakeServer::start(vec![("GET /repos/o/r", 200, "application/json", json!({"id":1,"full_name":"not a repo","private":false,"visibility":"public"}).to_string())]);
        let c = wc(&repo(&s));
        let t = GitHubSearch { cfg: c.cfg.clone(), env: env_of(&[]) };
        let o = t.call(&ctx("gh-badmeta"), json!({"repository":"o/r","kind":"issue"}));
        assert!(o.is_error);
        assert!(o.content.starts_with("GitHub returned invalid repository metadata"), "{}", o.content);
    }

    /// `[web.providers.github] api_key` wins over the environment, resolves a `{{secret:NAME}}`
    /// placeholder, and never reaches the model.
    #[test]
    fn a_config_api_key_secret_authenticates_without_being_echoed() {
        let s = dynamic(routes());
        let cfg = json!({"providers":{"github":{"base_url":s.url,"api_key":"{{secret:TOKEN}}"}}});
        let c = crate::web::testutil::wctx(cfg, &[]);
        let t = GitHubRead { cfg: c.cfg.clone(), env: env_of(&[("GITHUB_TOKEN", "ghp_from_env")]) };
        let o = t.call(&ctx("gh-key"), json!({"url":"https://github.com/o/r/issues/7"}));
        assert!(!o.is_error, "{}", o.content);
        assert!(s.requests().iter().all(|r| r.header("authorization").as_deref() == Some("Bearer s3cr3t")), "the configured key is used");
        assert!(!o.content.contains("s3cr3t") && !o.content.contains("ghp_from_env"), "no credential is echoed");

        // `GH_TOKEN` is the second environment name, as upstream's CLI convention.
        let s = dynamic(routes());
        let c = wc(&repo(&s));
        let t = GitHubSearch { cfg: c.cfg.clone(), env: env_of(&[("GH_TOKEN", "gho_env")]) };
        assert!(!t.call(&ctx("gh-ghtoken"), json!({"repository":"o/r","kind":"issue"})).is_error);
        assert!(s.requests().iter().all(|r| r.header("authorization").as_deref() == Some("Bearer gho_env")));
    }

    /// A repository that turns private while the log is read must not disclose the log.
    #[test]
    fn a_job_document_is_refused_when_visibility_changes_mid_read() {
        let reads = Arc::new(AtomicUsize::new(0));
        let seen = reads.clone();
        let s = FakeServer::with(move |r: &Req| -> Reply {
            let base = format!("http://{}", r.header("host").unwrap_or_default());
            match r.path.split('?').next().unwrap_or("") {
                "/repos/o/r" => {
                    let private = seen.fetch_add(1, Ordering::SeqCst) > 0;
                    let body = if private { r#"{"id":1,"full_name":"o/r","private":true,"visibility":"private"}"# } else { r#"{"id":1,"full_name":"o/r","private":false,"visibility":"public"}"# };
                    (200, "application/json".into(), body.as_bytes().to_vec(), vec![])
                }
                "/repos/o/r/actions/jobs/55" => {
                    let body = json!({
                        "id":55,"run_id":44,"name":"test","status":"completed","conclusion":"success","head_sha":SHA,
                        "url":"BASE/repos/o/r/actions/jobs/55","run_url":"BASE/repos/o/r/actions/runs/44"
                    })
                    .to_string()
                    .replace("BASE", &base);
                    (200, "application/json".into(), body.into_bytes(), vec![])
                }
                "/repos/o/r/actions/jobs/55/logs" => (200, "text/plain".into(), b"tail\n".to_vec(), vec![]),
                _ => (404, "text/plain".into(), b"{}".to_vec(), vec![]),
            }
        });
        let c = wc(&repo(&s));
        let t = GitHubRead { cfg: c.cfg.clone(), env: env_of(&[]) };
        let o = t.call(&ctx("gh-job-private"), json!({"url":"https://github.com/o/r/actions/runs/44/job/55"}));
        assert!(o.is_error);
        assert_eq!(o.content, NOT_PUBLIC_404);
        assert_eq!(s.requests().iter().filter(|r| r.path == "/repos/o/r").count(), 2, "visibility is re-checked");
    }

    /// A job log is delivered to the model, so the credential that fetched it must be masked in it.
    #[test]
    fn a_job_log_never_echoes_the_configured_credential() {
        let s = dynamic(vec![
            ("GET /repos/o/r", 200, "application/json", json!({"id":1,"full_name":"o/r","private":false,"visibility":"public"}).to_string()),
            (
                "GET /repos/o/r/actions/jobs/55",
                200,
                "application/json",
                json!({
                    "id":55,"run_id":44,"name":"test","status":"completed","conclusion":"success","head_sha":SHA,
                    "url":"BASE/repos/o/r/actions/jobs/55","run_url":"BASE/repos/o/r/actions/runs/44"
                })
                .to_string(),
            ),
            ("GET /repos/o/r/actions/jobs/55/logs", 200, "text/plain", "step 1\nusing token ghp_abcdefghijklmnop\nstep 3\n".to_string()),
        ]);
        let c = wc(&repo(&s));
        let t = GitHubRead { cfg: c.cfg.clone(), env: env_of(&[("GITHUB_TOKEN", "ghp_abcdefghijklmnop")]) };
        let o = t.call(&ctx("gh-log-token"), json!({"url":"https://github.com/o/r/actions/runs/44/job/55"}));
        let d = tool_output_json(&o);
        let body = d["body"].as_str().unwrap();
        assert!(!o.content.contains("ghp_abcdefghijklmnop"), "{}", o.content);
        assert!(body.contains("using token ***") && body.contains("step 3"), "the rest of the log survives: {body}");
        assert_eq!(d["partial"].as_bool(), Some(false), "the whole (small) log is delivered");
    }
}
