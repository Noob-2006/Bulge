//! Code-forge tools for software-development roles (BATCH-next §3, pro-023/024):
//! `forge_read` and `forge_write` over GitHub (github.com and Enterprise Server, token or
//! GitHub App identity) and GitLab (gitlab.com and self-managed, API base configurable).
//!
//! ```toml
//! [integrations.forge.hosts.github]
//! kind = "github"
//! api_base = "https://api.github.com"       # GHES: https://ghe.example.com/api/v3
//! token = "{{secret:GITHUB_TOKEN}}"         # PAT, fine-grained token, or an App installation token
//! [integrations.forge.hosts.ghapp]          # …or let ark mint App installation tokens itself
//! kind = "github"
//! app_id = "123456"
//! installation_id = "7890123"
//! private_key = "{{secret:GITHUB_APP_KEY}}"  # the App's PEM
//! [integrations.forge.hosts.gitlab]
//! kind = "gitlab"
//! api_base = "https://gitlab.example.com/api/v4"
//! token = "{{secret:GITLAB_TOKEN}}"         # PRIVATE-TOKEN: personal / project / group access token
//! ```
//!
//! With no `[integrations.forge]` at all, `GITHUB_TOKEN` / `GH_TOKEN` and `GITLAB_TOKEN` in the
//! environment (or the vault) are enough: `github` and `gitlab` (gitlab.com) hosts appear.
//!
//! * `forge_read`: issue, pull/merge request, changed files, comments (with inline review
//!   comments), checks / pipelines, and open-issue / open-PR lists. Nothing to approve.
//! * `forge_write`: comment, review (with inline comments), create a pull/merge request,
//!   create or update (close/reopen/relabel) an issue. Every call is **tier 2**: the effect it
//!   declares is "acts on a remote system" with the request text as the outgoing payload (so
//!   the egress scan sees secrets in it), which the approval flow asks about unless an
//!   envelope already covers it. There is deliberately **no merge**, no branch or tag
//!   deletion and no force-push here: those stay with `git`/`gh` where the existing risk
//!   tiers (force-push, deleting a remote branch) apply.
//!
//! The model names a `host` from the config and a repository; URLs and tokens are never model
//! input. Results are wrapped as untrusted external content (issue text is attacker-controlled).

pub mod app;
pub mod github;
pub mod gitlab;

use crate::pro_http;
use ark_core::tool::{arg_opt_str, arg_opt_u64, arg_str};
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

pub type EnvFn = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HostCfg {
    pub kind: String,
    pub description: String,
    pub api_base: Option<String>,
    pub token: Option<String>,
    pub token_env: Option<String>,
    // GitHub App identity
    pub app_id: Option<String>,
    pub installation_id: Option<String>,
    pub private_key: Option<String>,
    pub private_key_file: Option<String>,
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ForgeConfig {
    pub enabled: Option<bool>,
    pub hosts: BTreeMap<String, HostCfg>,
}

impl ForgeConfig {
    pub fn from_value(v: Value, env: &EnvFn) -> Result<ForgeConfig, String> {
        let mut cfg: ForgeConfig = if v.is_null() { ForgeConfig::default() } else { serde_json::from_value(v).map_err(|e| format!("[integrations.forge]: {e}"))? };
        for (n, h) in &cfg.hosts {
            if !matches!(h.kind.as_str(), "github" | "gitlab") {
                return Err(format!("[integrations.forge.hosts.{n}]: kind `{}` is not github or gitlab", h.kind));
            }
            if h.kind == "gitlab" && h.app_id.is_some() {
                return Err(format!("[integrations.forge.hosts.{n}]: App identity is a GitHub feature"));
            }
            if h.app_id.is_some() && (h.installation_id.is_none() || (h.private_key.is_none() && h.private_key_file.is_none())) {
                return Err(format!("[integrations.forge.hosts.{n}]: app_id needs installation_id and private_key (or private_key_file)"));
            }
            if let Some(b) = &h.api_base {
                if !(b.starts_with("https://") || b.starts_with("http://")) {
                    return Err(format!("[integrations.forge.hosts.{n}]: api_base must be an http(s) URL"));
                }
            }
        }
        if cfg.hosts.is_empty() && cfg.enabled != Some(false) {
            if ["GITHUB_TOKEN", "GH_TOKEN"].iter().any(|k| env(k).is_some()) {
                cfg.hosts.insert("github".into(), HostCfg { kind: "github".into(), ..Default::default() });
            }
            if env("GITLAB_TOKEN").is_some() {
                cfg.hosts.insert("gitlab".into(), HostCfg { kind: "gitlab".into(), ..Default::default() });
            }
        }
        Ok(cfg)
    }
}

pub fn tools(cfg: Value, env: EnvFn) -> Result<Vec<Arc<dyn Tool>>, String> {
    let cfg = Arc::new(ForgeConfig::from_value(cfg, &env)?);
    if cfg.enabled == Some(false) || cfg.hosts.is_empty() {
        return Ok(vec![]);
    }
    Ok(vec![Arc::new(ForgeRead { cfg: cfg.clone(), env: env.clone() }), Arc::new(ForgeWrite { cfg, env })])
}

pub(crate) fn clip(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    let mut end = n;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…[cut]", &s[..end])
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Inline {
    pub path: String,
    pub line: u64,
    pub body: String,
    #[serde(default)]
    pub side: Option<String>,
}

/// The arguments of `forge_write`.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Write {
    pub action: String,
    pub number: Option<u64>,
    pub target: Option<String>,
    pub title: String,
    pub body: String,
    pub labels: Vec<String>,
    pub verdict: String,
    pub comments: Vec<Inline>,
    pub head: Option<String>,
    pub base: Option<String>,
    pub draft: bool,
    pub state: Option<String>,
    pub commit_id: Option<String>,
    pub maintainer_can_modify: Option<bool>,
}

const MAX_TEXT: usize = 60_000;

impl Write {
    fn check(&self) -> Result<(), String> {
        if !matches!(self.action.as_str(), "comment" | "review" | "create_pr" | "create_issue" | "update_issue") {
            return Err(format!("action must be comment, review, create_pr, create_issue or update_issue (got `{}`); merging and deleting are not offered", self.action));
        }
        let total = self.title.len() + self.body.len() + self.comments.iter().map(|c| c.body.len() + c.path.len()).sum::<usize>();
        if total > MAX_TEXT {
            return Err(format!("the text is {total} bytes; at most {MAX_TEXT} per call"));
        }
        if self.comments.len() > 50 {
            return Err("at most 50 inline comments per review".into());
        }
        if matches!(self.action.as_str(), "comment") && self.body.trim().is_empty() {
            return Err("`comment` needs a body".into());
        }
        if matches!(self.action.as_str(), "create_pr" | "create_issue") && self.title.trim().is_empty() {
            return Err(format!("`{}` needs a title", self.action));
        }
        if self.labels.len() > 20 || self.labels.iter().any(|l| l.is_empty() || l.len() > 100) {
            return Err("labels: at most 20, 1-100 characters each".into());
        }
        for c in &self.comments {
            if c.path.is_empty() || c.line == 0 || c.body.trim().is_empty() {
                return Err("every inline comment needs path, line (>= 1) and body".into());
            }
        }
        for b in [&self.head, &self.base].into_iter().flatten() {
            if b.is_empty() || b.len() > 255 || b.chars().any(|c| c.is_control() || c.is_whitespace()) || b.starts_with('-') {
                return Err(format!("`{b}` is not a usable branch name"));
            }
        }
        Ok(())
    }
}

/// A resolved host: base URL, headers and credential for one call.
pub struct Api {
    pub kind: String,
    pub base: String,
    token: Option<String>,
    timeout: u64,
}

impl Api {
    fn headers(&self) -> Vec<(&'static str, String)> {
        let mut h: Vec<(&'static str, String)> = vec![("Accept", "application/json".into()), ("User-Agent", "ark".into())];
        if self.kind == "github" {
            h.push(("Accept", "application/vnd.github+json".into()));
            h.push(("X-GitHub-Api-Version", "2022-11-28".into()));
            if let Some(t) = &self.token {
                h.push(("Authorization", format!("Bearer {t}")));
            }
        } else if let Some(t) = &self.token {
            h.push(("PRIVATE-TOKEN", t.clone()));
        }
        h
    }
    fn secrets(&self) -> Vec<&str> {
        self.token.iter().map(String::as_str).collect()
    }
    pub fn get(&self, path: &str) -> Result<Value, String> {
        let r = pro_http::get(&format!("{}{path}", self.base), &self.headers(), self.timeout, &self.secrets())?;
        if !r.ok() {
            return Err(pro_http::api_error(&format!("{} GET {}", self.kind, path.split('?').next().unwrap_or(path)), &r, &self.secrets()));
        }
        r.json()
    }
    pub fn send(&self, method: &str, path: &str, body: &Value) -> Result<Value, String> {
        if self.token.is_none() {
            return Err(format!("no credential for this {} host: set `token` (or GITHUB_TOKEN / GITLAB_TOKEN) before writing", self.kind));
        }
        let r = pro_http::send(method, &format!("{}{path}", self.base), &self.headers(), Some(body), self.timeout, &self.secrets())?;
        if !r.ok() {
            return Err(pro_http::api_error(&format!("{} {method} {}", self.kind, path), &r, &self.secrets()));
        }
        Ok(if r.body.trim().is_empty() { json!({}) } else { r.json().unwrap_or_else(|_| json!({})) })
    }
}

fn secret(ctx: &ToolCtx, raw: &str) -> Result<String, String> {
    let v = (ctx.secrets)(raw.trim());
    if let Some(i) = v.find("{{secret:") {
        let name: String = v[i + 9..].chars().take_while(|c| *c != '}').collect();
        return Err(format!("secret `{name}` is not set; store it in the vault ({{{{secret:{name}}}}})"));
    }
    Ok(v)
}

fn default_base(kind: &str) -> &'static str {
    if kind == "github" {
        "https://api.github.com"
    } else {
        "https://gitlab.com/api/v4"
    }
}

fn base_of(h: &HostCfg) -> String {
    h.api_base.clone().unwrap_or_else(|| default_base(&h.kind).into()).trim_end_matches('/').to_string()
}

fn pick<'a>(cfg: &'a ForgeConfig, input: &Value) -> Result<(&'a str, &'a HostCfg), String> {
    match arg_opt_str(input, "host") {
        Some(n) => cfg.hosts.get_key_value(n).map(|(k, v)| (k.as_str(), v)).ok_or_else(|| format!("unknown host `{n}`; configured: {}", cfg.hosts.keys().cloned().collect::<Vec<_>>().join(", "))),
        None if cfg.hosts.len() == 1 => cfg.hosts.iter().next().map(|(k, v)| (k.as_str(), v)).ok_or_else(|| "no hosts".into()),
        None => Err(format!("name a `host`: {}", cfg.hosts.keys().cloned().collect::<Vec<_>>().join(", "))),
    }
}

fn repo_ok(kind: &str, repo: &str) -> Result<(), String> {
    let ok = if kind == "github" { github::valid_repo(repo) } else { gitlab::valid_project(repo) };
    if ok {
        Ok(())
    } else if kind == "github" {
        Err(format!("`{repo}` is not a GitHub repository (use owner/repo)"))
    } else {
        Err(format!("`{repo}` is not a GitLab project path (use group/project or group/subgroup/project)"))
    }
}

fn resolve(ctx: &ToolCtx, env: &EnvFn, h: &HostCfg, need_token: bool) -> Result<Api, String> {
    let timeout = h.timeout_seconds.unwrap_or(20).clamp(1, 120);
    let base = base_of(h);
    let from_env = |names: &[&str]| -> Option<String> {
        names.iter().find_map(|n| {
            env(n).or_else(|| {
                let ph = format!("{{{{secret:{n}}}}}");
                let v = (ctx.secrets)(&ph);
                (v != ph && !v.trim().is_empty()).then_some(v)
            })
        })
    };
    let token = if let (Some(app_id), Some(inst)) = (&h.app_id, &h.installation_id) {
        let pem = match (&h.private_key, &h.private_key_file) {
            (Some(k), _) => secret(ctx, k)?,
            (_, Some(f)) => std::fs::read_to_string(ctx.resolve(f)).map_err(|e| format!("cannot read private_key_file: {e}"))?,
            _ => return Err("GitHub App needs private_key".into()),
        };
        Some(app::installation_token(&base, app_id, inst, &pem, timeout)?)
    } else if let Some(t) = h.token.as_deref().filter(|t| !t.trim().is_empty()) {
        Some(secret(ctx, t)?)
    } else if let Some(e) = &h.token_env {
        from_env(&[e.as_str()])
    } else if h.kind == "github" {
        from_env(&["GITHUB_TOKEN", "GH_TOKEN"])
    } else {
        from_env(&["GITLAB_TOKEN"])
    };
    if need_token && token.is_none() {
        return Err(format!("no credential for this {} host: set `token = \"{{{{secret:NAME}}}}\"` (or GITHUB_TOKEN / GITLAB_TOKEN)", h.kind));
    }
    Ok(Api { kind: h.kind.clone(), base, token, timeout })
}

fn describe(cfg: &ForgeConfig) -> String {
    cfg.hosts.iter().map(|(n, h)| format!("{n} ({}{}{})", h.kind, h.api_base.as_deref().map(|b| format!(" {b}")).unwrap_or_default(), if h.description.is_empty() { String::new() } else { format!(": {}", h.description) })).collect::<Vec<_>>().join("; ")
}

pub struct ForgeRead {
    cfg: Arc<ForgeConfig>,
    env: EnvFn,
}

impl Tool for ForgeRead {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "forge_read".into(),
            description: format!("Read from a code forge (GitHub or GitLab, including self-hosted, private repositories with the configured token): an issue, a pull/merge request (GitLab MR = pr, number = iid), its changed files with diffs, its comments including inline review comments, its checks or pipelines, or a list of open issues / PRs. Hosts: {}.", describe(&self.cfg)),
            input_schema: json!({"type":"object","properties":{
                "host":{"type":"string","description":"Configured host (optional when only one exists)"},
                "repo":{"type":"string","description":"GitHub owner/repo, or GitLab group/subgroup/project"},
                "kind":{"type":"string","enum":["issue","pr","pr_files","comments","checks","issues","prs"]},
                "number":{"type":"integer","minimum":1,"description":"Issue number / PR number / MR iid (not for lists)"},
                "state":{"type":"string","enum":["open","closed","all"],"description":"For lists (default open)"},
                "limit":{"type":"integer","minimum":1,"description":"List/comment page size (default 20, at most 100)"}},"required":["repo","kind"]}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        match pick(&self.cfg, input) {
            Ok((_, h)) => vec![Effect::Net { dest: pro_http::dest_of(&base_of(h)), payload: String::new() }],
            Err(_) => vec![],
        }
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let run = || -> Result<String, String> {
            let (name, h) = pick(&self.cfg, &input)?;
            let repo = arg_str(&input, "repo")?.trim();
            repo_ok(&h.kind, repo)?;
            let kind = arg_str(&input, "kind")?;
            let state = arg_opt_str(&input, "state").unwrap_or("open");
            if !matches!(state, "open" | "closed" | "all") {
                return Err("state must be open, closed or all".into());
            }
            let limit = arg_opt_u64(&input, "limit").map(|l| l as usize).unwrap_or(20).clamp(1, 100);
            let number = arg_opt_u64(&input, "number").filter(|n| *n >= 1);
            let api = resolve(ctx, &self.env, h, false)?;
            let mut v = if h.kind == "github" { github::read(&api, repo, kind, number, state, limit)? } else { gitlab::read(&api, repo, kind, number, state, limit)? };
            v["host"] = json!(name);
            v["repo"] = json!(repo);
            Ok(crate::web::content::wrap(&serde_json::to_string_pretty(&v).unwrap_or_default(), "forge_read", true))
        };
        match run() {
            Ok(t) => ToolOutput::ok(t),
            Err(e) => ToolOutput::err(e),
        }
    }
}

pub struct ForgeWrite {
    cfg: Arc<ForgeConfig>,
    env: EnvFn,
}

impl Tool for ForgeWrite {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "forge_write".into(),
            description: format!("Write to a code forge (GitHub or GitLab): comment on an issue/PR/MR, submit a review (verdict comment/approve/request_changes, optional inline comments on file lines), create a pull/merge request from an already-pushed branch, create an issue, or update one (close/reopen, title, body, labels). Needs approval every time. Does not merge, delete or force-push. Hosts: {}.", describe(&self.cfg)),
            input_schema: json!({"type":"object","properties":{
                "host":{"type":"string"},
                "repo":{"type":"string","description":"GitHub owner/repo, or GitLab group/subgroup/project"},
                "action":{"type":"string","enum":["comment","review","create_pr","create_issue","update_issue"]},
                "number":{"type":"integer","minimum":1,"description":"Issue / PR / MR number (comment, review, update_issue)"},
                "target":{"type":"string","enum":["issue","pr"],"description":"GitLab only: whether `number` is an issue or a merge request (required for comment; update_issue defaults to issue)"},
                "title":{"type":"string"},
                "body":{"type":"string","description":"Markdown text"},
                "labels":{"type":"array","items":{"type":"string"}},
                "verdict":{"type":"string","enum":["comment","approve","request_changes"],"description":"review"},
                "comments":{"type":"array","description":"review: inline comments","items":{"type":"object","properties":{"path":{"type":"string"},"line":{"type":"integer","minimum":1},"body":{"type":"string"},"side":{"type":"string","enum":["RIGHT","LEFT"]}},"required":["path","line","body"]}},
                "commit_id":{"type":"string","description":"review (GitHub): the commit the review refers to"},
                "head":{"type":"string","description":"create_pr: source branch (owner:branch for a GitHub fork)"},
                "base":{"type":"string","description":"create_pr: target branch"},
                "draft":{"type":"boolean"},
                "state":{"type":"string","enum":["open","closed"],"description":"update_issue"}},"required":["repo","action"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let Ok((name, h)) = pick(&self.cfg, input) else { return vec![] };
        let repo = arg_opt_str(input, "repo").unwrap_or("");
        let action = arg_opt_str(input, "action").unwrap_or("write");
        let n = arg_opt_u64(input, "number").map(|n| format!("#{n}")).unwrap_or_default();
        // A pseudo-destination without a host: the risk classifier then reads the call as
        // "acts on a remote system" (tier 2) even when the forge's own host is on the
        // development allowlist, and the request text rides along as the outgoing payload
        // for the secret / PII scan.
        let dest = format!("/forge/{name}/{repo}");
        let text = format!("{action} {repo}{n} on {}\n{}\n{}", base_of(h), arg_opt_str(input, "title").unwrap_or(""), arg_opt_str(input, "body").unwrap_or(""));
        let inline = input["comments"].as_array().map(|a| a.iter().filter_map(|c| c["body"].as_str()).collect::<Vec<_>>().join("\n")).unwrap_or_default();
        vec![Effect::Remote { dest: dest.clone(), reason: format!("{} {action} {repo}{n} ({})", h.kind, base_of(h)) }, Effect::Net { dest, payload: format!("{text}\n{inline}") }]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let run = || -> Result<String, String> {
            let (name, h) = pick(&self.cfg, &input)?;
            let repo = arg_str(&input, "repo")?.trim();
            repo_ok(&h.kind, repo)?;
            let w: Write = serde_json::from_value(input.clone()).map_err(|e| format!("bad arguments: {e}"))?;
            w.check()?;
            let api = resolve(ctx, &self.env, h, true)?;
            let mut v = if h.kind == "github" { github::write(&api, repo, &w)? } else { gitlab::write(&api, repo, &w)? };
            v["host"] = json!(name);
            v["repo"] = json!(repo);
            Ok(serde_json::to_string_pretty(&v).unwrap_or_default())
        };
        match run() {
            Ok(t) => ToolOutput::ok(t),
            Err(e) => ToolOutput::err(e),
        }
    }
}

#[cfg(test)]
mod tests;
