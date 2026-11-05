//! Team activity reports from GitHub and Discord (OpenClaw extensions/team-reports, MIT).
//!
//! A UTC day is collected from the GitHub REST API (search: PRs opened / merged, issues
//! opened / closed, commits per org) and the Discord REST API (messages per configured
//! channel), aggregated per person (roster mapping GitHub logins and Discord ids), optionally
//! summarized by the model, and stored under `<surfaces>/team-reports/<period>/<key>.{json,md}`.
//! Weeks (ISO, `2026-W45`) and months (`2026-11`) roll up stored days. The daemon generates
//! the closed day on schedule; the `team_reports` tool, ARP methods and the web page
//! (`/surfaces/team-reports/`) read them.

use super::{complete, days_from_civil, esc_html, iso, now_ms, read_json, write_atomic, write_json, Completion, Env};
use ark_core::{Cancel, Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use ark_net::httpd::Response;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn d_github_base() -> String {
    "https://api.github.com".into()
}
fn d_discord_base() -> String {
    "https://discord.com/api/v10".into()
}
fn d_excerpt() -> usize {
    260
}
fn yes() -> bool {
    true
}
fn d_closed() -> String {
    "00:05".into()
}
fn d_intraday() -> u64 {
    4
}
fn d_retention() -> u64 {
    400
}

/// `[surfaces.team_reports]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamReportsConfig {
    pub github: GithubConfig,
    #[serde(default)]
    pub discord: Option<DiscordConfig>,
    /// Roster: who is who across GitHub and Discord.
    #[serde(default)]
    pub people: Vec<Person>,
    #[serde(default)]
    pub summaries: SummaryConfig,
    #[serde(default)]
    pub schedule: ScheduleConfig,
    /// Days of stored reports to keep. Default 400 (0 = keep everything).
    #[serde(default = "d_retention")]
    pub retention_days: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubConfig {
    /// Usually `{{secret:GITHUB_TOKEN}}`.
    pub token: String,
    pub orgs: Vec<String>,
    #[serde(default)]
    pub exclude_repos: Vec<String>,
    /// Default https://api.github.com (GitHub Enterprise: https://host/api/v3).
    #[serde(default = "d_github_base")]
    pub api_base_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscordConfig {
    /// Bot token, usually `{{secret:DISCORD_BOT_TOKEN}}`.
    pub token: String,
    pub guild_id: String,
    pub channels: Vec<DiscordChannel>,
    /// Characters kept per message excerpt. Default 260.
    #[serde(default = "d_excerpt")]
    pub excerpt_max_chars: usize,
    /// Default https://discord.com/api/v10.
    #[serde(default = "d_discord_base")]
    pub api_base_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscordChannel {
    pub id: String,
    /// Keep short message excerpts in the report. Default false.
    #[serde(default)]
    pub excerpts: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Person {
    /// First login is the display login; the rest are aliases.
    pub github: Vec<String>,
    #[serde(default)]
    pub display: Option<String>,
    #[serde(default)]
    pub discord_user_id: Option<String>,
    #[serde(default)]
    pub discord_username: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SummaryConfig {
    /// Model-written summary on each report. Default true.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// `provider/model`; empty = the aux model.
    pub model: String,
}

impl Default for SummaryConfig {
    fn default() -> Self {
        SummaryConfig { enabled: true, model: String::new() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScheduleConfig {
    /// Generate the closed UTC day automatically in the daemon. Default true.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// UTC time of day the previous day is generated. Default "00:05".
    #[serde(default = "d_closed")]
    pub closed_day_utc: String,
    /// Refresh today's intraday report every N hours (0 = off). Default 4.
    #[serde(default = "d_intraday")]
    pub intraday_every_hours: u64,
    #[serde(default = "yes")]
    pub weekly: bool,
    #[serde(default = "yes")]
    pub monthly: bool,
}

impl Default for ScheduleConfig {
    fn default() -> Self {
        ScheduleConfig { enabled: true, closed_day_utc: d_closed(), intraday_every_hours: d_intraday(), weekly: true, monthly: true }
    }
}

// ───────────────────────── periods ─────────────────────────

/// Parse `YYYY-MM-DD` → days since epoch.
fn day_num(key: &str) -> Result<i64, String> {
    let p: Vec<&str> = key.split('-').collect();
    let bad = || format!("invalid date `{key}` (expected YYYY-MM-DD)");
    if p.len() != 3 || p[0].len() != 4 || p[1].len() != 2 || p[2].len() != 2 {
        return Err(bad());
    }
    let (y, m, d): (i64, u32, u32) = (p[0].parse().map_err(|_| bad())?, p[1].parse().map_err(|_| bad())?, p[2].parse().map_err(|_| bad())?);
    if !(1..=12).contains(&m) || d == 0 || d > 31 || super::civil(days_from_civil(y, m, d)) != (y, m, d) {
        return Err(bad());
    }
    Ok(days_from_civil(y, m, d))
}

fn day_key(n: i64) -> String {
    let (y, m, d) = super::civil(n);
    format!("{y:04}-{m:02}-{d:02}")
}

/// ISO week key (`2026-W45`) of a day.
pub fn week_key(n: i64) -> String {
    let wd = (n + 3).rem_euclid(7); // Monday = 0
    let thursday = n - wd + 3;
    let (y, _, _) = super::civil(thursday);
    let week = (thursday - days_from_civil(y, 1, 1)) / 7 + 1;
    format!("{y:04}-W{week:02}")
}

fn month_key(n: i64) -> String {
    let (y, m, _) = super::civil(n);
    format!("{y:04}-{m:02}")
}

/// Days of a week or month key.
fn days_of(period: &str, key: &str) -> Result<Vec<i64>, String> {
    match period {
        "day" => Ok(vec![day_num(key)?]),
        "week" => {
            let (y, w) = key.split_once("-W").ok_or_else(|| format!("invalid week `{key}` (expected YYYY-Www)"))?;
            let (y, w): (i64, i64) = (y.parse().map_err(|_| "bad week year")?, w.parse().map_err(|_| "bad week number")?);
            if !(1..=53).contains(&w) {
                return Err(format!("invalid week `{key}`"));
            }
            let jan4 = days_from_civil(y, 1, 4);
            let monday = jan4 - (jan4 + 3).rem_euclid(7) + (w - 1) * 7;
            let days: Vec<i64> = (monday..monday + 7).collect();
            if week_key(monday) != key {
                return Err(format!("invalid week `{key}`"));
            }
            Ok(days)
        }
        "month" => {
            let (y, m) = key.split_once('-').ok_or_else(|| format!("invalid month `{key}` (expected YYYY-MM)"))?;
            let (y, m): (i64, u32) = (y.parse().map_err(|_| "bad month")?, m.parse().map_err(|_| "bad month")?);
            if !(1..=12).contains(&m) {
                return Err(format!("invalid month `{key}`"));
            }
            let start = days_from_civil(y, m, 1);
            let end = if m == 12 { days_from_civil(y + 1, 1, 1) } else { days_from_civil(y, m + 1, 1) };
            Ok((start..end).collect())
        }
        p => Err(format!("period must be day, week or month, got {p}")),
    }
}

// ───────────────────────── HTTP ─────────────────────────

/// HTTPS without credentials, query or fragment (plain http only for loopback test servers).
fn check_base(base: &str, what: &str) -> Result<String, String> {
    let b = base.trim().trim_end_matches('/');
    let rest = b.strip_prefix("https://").or_else(|| b.strip_prefix("http://").filter(|r| r.starts_with("127.0.0.1") || r.starts_with("localhost")));
    match rest {
        Some(r) if !r.is_empty() && !r.contains(['?', '#', '@']) => Ok(b.to_string()),
        _ => Err(format!("{what} API base URL must be HTTPS without credentials, query, or fragment")),
    }
}

struct Http {
    agent: ureq::Agent,
    base: String,
    headers: Vec<(String, String)>,
    token: String,
    calls: u64,
    /// Max seconds to wait for a rate limit (tests use 0).
    max_wait: u64,
}

impl Http {
    fn new(base: &str, what: &str, headers: Vec<(String, String)>, token: String) -> Result<Http, String> {
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(30))).build().into();
        Ok(Http { agent, base: check_base(base, what)?, headers, token, calls: 0, max_wait: 60 })
    }

    fn url(&self, path: &str) -> Result<String, String> {
        let u = if path.starts_with("http://") || path.starts_with("https://") { path.to_string() } else { format!("{}{}", self.base, path) };
        if !u.starts_with(&format!("{}/", self.base)) {
            return Err("Refused API pagination outside the configured base URL".into());
        }
        Ok(u)
    }

    /// GET with retry on 5xx and rate limits; returns (json, next page url).
    fn get(&mut self, path: &str) -> Result<(Value, Option<String>), String> {
        let url = self.url(path)?;
        let mut fails = 0;
        loop {
            self.calls += 1;
            let mut req = self.agent.get(&url);
            for (k, v) in &self.headers {
                req = req.header(k, v);
            }
            let mut r = req.call().map_err(|e| format!("Request failed; check API access and connectivity ({})", e.to_string().replace(&self.token, "[redacted]")))?;
            let status = r.status().as_u16();
            let h = |k: &str| r.headers().get(k).and_then(|v| v.to_str().ok()).map(str::to_string);
            let (retry_after, remaining, link) = (h("retry-after"), h("x-ratelimit-remaining"), h("link"));
            let body = r.body_mut().read_to_string().unwrap_or_default();
            if status == 429 || (status == 403 && (remaining.as_deref() == Some("0") || retry_after.is_some() || body.to_lowercase().contains("rate limit"))) {
                let wait = retry_after.and_then(|s| s.parse::<u64>().ok()).unwrap_or(60).max(1);
                if fails >= 2 || wait > self.max_wait {
                    return Err(format!("HTTP {status}: rate limited (retry after {wait}s)"));
                }
                fails += 1;
                std::thread::sleep(Duration::from_secs(wait));
                continue;
            }
            if status >= 500 && fails < 3 {
                fails += 1;
                std::thread::sleep(Duration::from_millis(if self.max_wait == 0 { 1 } else { 1000 << (fails - 1) }));
                continue;
            }
            if !(200..300).contains(&status) {
                return Err(format!("HTTP {status}; check token permissions and access"));
            }
            let v: Value = serde_json::from_str(&body).map_err(|_| "Invalid JSON API response".to_string())?;
            let next = link.and_then(|l| l.split(',').find(|p| p.contains("rel=\"next\"")).and_then(|p| p.split('<').nth(1)).and_then(|p| p.split('>').next()).map(str::to_string));
            return Ok((v, next));
        }
    }
}

// ───────────────────────── collection ─────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub kind: String,
    pub author: String,
    pub repo: String,
    pub title: String,
    pub url: String,
}

#[derive(Debug, Default)]
struct Collected {
    items: Vec<Item>,
    /// (channel, author id, author name, excerpt?)
    messages: Vec<(String, String, String, Option<String>)>,
    warnings: Vec<String>,
    api_calls: u64,
}

fn secret(env: &Env, s: &str) -> String {
    env.kernel().map(|k| k.vault.substitute(s)).unwrap_or_else(|_| s.to_string())
}

const SEARCHES: &[(&str, &str, &str)] = &[("pr_opened", "is:pr", "created"), ("pr_merged", "is:pr is:merged", "merged"), ("issue_opened", "is:issue", "created"), ("issue_closed", "is:issue", "closed")];

fn collect_github(env: &Env, cfg: &GithubConfig, start: u64, end: u64, out: &mut Collected, max_wait: u64) {
    let token = secret(env, &cfg.token);
    let mut http = match Http::new(&cfg.api_base_url, "GitHub", vec![("accept".into(), "application/vnd.github+json".into()), ("x-github-api-version".into(), "2022-11-28".into()), ("authorization".into(), format!("Bearer {token}")), ("user-agent".into(), "ark-team-reports".into())], token.clone()) {
        Ok(h) => h,
        Err(e) => return out.warnings.push(e),
    };
    http.max_wait = max_wait;
    let range = format!("{}..{}", iso(start), iso(end.saturating_sub(1000)));
    let excluded = |repo: &str| cfg.exclude_repos.iter().any(|x| x.eq_ignore_ascii_case(repo));
    for org in &cfg.orgs {
        for (kind, qual, field) in SEARCHES {
            let q = format!("org:{org} {qual} {field}:{range}");
            let mut next = Some(format!("/search/issues?q={}&per_page=100", ark_net::urlencode(&q)));
            let mut pages = 0;
            while let Some(path) = next.take() {
                pages += 1;
                match http.get(&path) {
                    Ok((v, n)) => {
                        if v["incomplete_results"] == true {
                            out.warnings.push(format!("{kind} search for {org}: GitHub returned incomplete search results"));
                        }
                        for it in v["items"].as_array().into_iter().flatten() {
                            let repo = it["repository_url"].as_str().and_then(|u| u.split("/repos/").nth(1)).unwrap_or("").to_string();
                            if excluded(&repo) {
                                continue;
                            }
                            out.items.push(Item { kind: kind.to_string(), author: it["user"]["login"].as_str().unwrap_or("").into(), repo, title: it["title"].as_str().unwrap_or("").into(), url: it["html_url"].as_str().unwrap_or("").into() });
                        }
                        next = n.filter(|_| pages < 10);
                    }
                    Err(e) => out.warnings.push(format!("{kind} search for {org}: {e}")),
                }
            }
        }
        let q = format!("org:{org} committer-date:{range}");
        let mut next = Some(format!("/search/commits?q={}&per_page=100", ark_net::urlencode(&q)));
        let mut pages = 0;
        while let Some(path) = next.take() {
            pages += 1;
            match http.get(&path) {
                Ok((v, n)) => {
                    for it in v["items"].as_array().into_iter().flatten() {
                        let repo = it["repository"]["full_name"].as_str().unwrap_or("").to_string();
                        if excluded(&repo) {
                            continue;
                        }
                        let author = it["author"]["login"].as_str().or(it["commit"]["author"]["name"].as_str()).unwrap_or("").to_string();
                        out.items.push(Item { kind: "commit".into(), author, repo, title: it["commit"]["message"].as_str().unwrap_or("").lines().next().unwrap_or("").into(), url: it["html_url"].as_str().unwrap_or("").into() });
                    }
                    next = n.filter(|_| pages < 10);
                }
                Err(e) => out.warnings.push(format!("Commit search for {org}: {e}")),
            }
        }
    }
    out.api_calls += http.calls;
}

const DISCORD_EPOCH: u64 = 1_420_070_400_000;

fn collect_discord(env: &Env, cfg: &DiscordConfig, start: u64, end: u64, out: &mut Collected, max_wait: u64) {
    let token = secret(env, &cfg.token);
    let mut http = match Http::new(&cfg.api_base_url, "Discord", vec![("authorization".into(), format!("Bot {token}")), ("user-agent".into(), "DiscordBot (https://github.com/ark, 1) ark-team-reports".into())], token.clone()) {
        Ok(h) => h,
        Err(e) => return out.warnings.push(e),
    };
    http.max_wait = max_wait;
    for ch in &cfg.channels {
        let mut after = (start.saturating_sub(DISCORD_EPOCH)) << 22;
        for _ in 0..200 {
            match http.get(&format!("/channels/{}/messages?limit=100&after={after}", ch.id)) {
                Ok((v, _)) => {
                    let msgs = v.as_array().cloned().unwrap_or_default();
                    if msgs.is_empty() {
                        break;
                    }
                    let mut max_id = after;
                    let mut past_end = false;
                    for m in &msgs {
                        let id: u64 = m["id"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0);
                        max_id = max_id.max(id);
                        let ts = (id >> 22) + DISCORD_EPOCH;
                        if ts >= end {
                            past_end = true;
                            continue;
                        }
                        if ts < start || m["author"]["bot"] == true {
                            continue;
                        }
                        let excerpt = ch.excerpts.then(|| m["content"].as_str().unwrap_or("").chars().take(cfg.excerpt_max_chars).collect::<String>()).filter(|s| !s.is_empty());
                        out.messages.push((ch.id.clone(), m["author"]["id"].as_str().unwrap_or("").into(), m["author"]["global_name"].as_str().or(m["author"]["username"].as_str()).unwrap_or("").into(), excerpt));
                    }
                    if past_end || msgs.len() < 100 || max_id == after {
                        break;
                    }
                    after = max_id;
                }
                Err(e) => {
                    out.warnings.push(format!("Discord channel {}: {e}", ch.id));
                    break;
                }
            }
        }
    }
    out.api_calls += http.calls;
}

// ───────────────────────── aggregation ─────────────────────────

const COUNTS: &[&str] = &["prsOpened", "prsMerged", "issuesOpened", "issuesClosed", "commits", "discordMessages"];

fn count_key(kind: &str) -> &'static str {
    match kind {
        "pr_opened" => "prsOpened",
        "pr_merged" => "prsMerged",
        "issue_opened" => "issuesOpened",
        "issue_closed" => "issuesClosed",
        _ => "commits",
    }
}

fn aggregate(cfg: &TeamReportsConfig, c: &Collected) -> (Map<String, Value>, Vec<Value>, Vec<Value>) {
    let who_gh = |login: &str| -> String {
        cfg.people.iter().find(|p| p.github.iter().any(|g| g.eq_ignore_ascii_case(login))).map(|p| p.display.clone().unwrap_or_else(|| p.github[0].clone())).unwrap_or_else(|| login.to_string())
    };
    let who_dc = |id: &str, name: &str| -> String {
        cfg.people.iter().find(|p| p.discord_user_id.as_deref() == Some(id) || p.discord_username.as_deref().is_some_and(|u| u.eq_ignore_ascii_case(name))).map(|p| p.display.clone().unwrap_or_else(|| p.github[0].clone())).unwrap_or_else(|| name.to_string())
    };
    let mut totals: Map<String, Value> = COUNTS.iter().map(|k| (k.to_string(), json!(0))).collect();
    let mut people: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    let mut repos: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    let bump = |m: &mut Map<String, Value>, k: &str| {
        let n = m.get(k).and_then(|v| v.as_u64()).unwrap_or(0) + 1;
        m.insert(k.into(), json!(n));
    };
    for it in &c.items {
        let k = count_key(&it.kind);
        bump(&mut totals, k);
        if !it.author.is_empty() {
            bump(people.entry(who_gh(&it.author)).or_default(), k);
        }
        if !it.repo.is_empty() {
            bump(repos.entry(it.repo.clone()).or_default(), k);
        }
    }
    for (_, id, name, _) in &c.messages {
        bump(&mut totals, "discordMessages");
        bump(people.entry(who_dc(id, name)).or_default(), "discordMessages");
    }
    let mut people: Vec<Value> = people.into_iter().map(|(n, mut m)| {
        m.insert("name".into(), n.into());
        Value::Object(m)
    }).collect();
    let score = |v: &Value| COUNTS.iter().map(|k| v[*k].as_u64().unwrap_or(0)).sum::<u64>();
    people.sort_by_key(|v| std::cmp::Reverse(score(v)));
    let mut repos: Vec<Value> = repos.into_iter().map(|(n, mut m)| {
        m.insert("repo".into(), n.into());
        Value::Object(m)
    }).collect();
    repos.sort_by_key(|v| std::cmp::Reverse(score(v)));
    (totals, people, repos)
}

/// Add up stored reports (week / month rollups).
fn rollup(reports: &[Value]) -> (Map<String, Value>, Vec<Value>, Vec<Value>) {
    let mut totals: Map<String, Value> = COUNTS.iter().map(|k| (k.to_string(), json!(0))).collect();
    let mut people: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    let mut repos: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    let add = |m: &mut Map<String, Value>, src: &Value| {
        for k in COUNTS {
            let n = m.get(*k).and_then(|v| v.as_u64()).unwrap_or(0) + src[*k].as_u64().unwrap_or(0);
            if n > 0 {
                m.insert(k.to_string(), json!(n));
            }
        }
    };
    for r in reports {
        add(&mut totals, &r["totals"]);
        for p in r["people"].as_array().into_iter().flatten() {
            add(people.entry(p["name"].as_str().unwrap_or("").into()).or_default(), p);
        }
        for p in r["repos"].as_array().into_iter().flatten() {
            add(repos.entry(p["repo"].as_str().unwrap_or("").into()).or_default(), p);
        }
    }
    let score = |v: &Value| COUNTS.iter().map(|k| v[*k].as_u64().unwrap_or(0)).sum::<u64>();
    let mut p: Vec<Value> = people.into_iter().map(|(n, mut m)| {
        m.insert("name".into(), n.into());
        Value::Object(m)
    }).collect();
    p.sort_by_key(|v| std::cmp::Reverse(score(v)));
    let mut r: Vec<Value> = repos.into_iter().map(|(n, mut m)| {
        m.insert("repo".into(), n.into());
        Value::Object(m)
    }).collect();
    r.sort_by_key(|v| std::cmp::Reverse(score(v)));
    (totals, p, r)
}

fn markdown(r: &Value) -> String {
    let t = &r["totals"];
    let mut s = format!("# Team report · {} {}\n\n", r["period"].as_str().unwrap_or(""), r["key"].as_str().unwrap_or(""));
    if r["intraday"] == true {
        s.push_str(&format!("_Intraday, as of {}_\n\n", r["generatedAt"].as_str().unwrap_or("")));
    }
    if let Some(sum) = r["summary"].as_str() {
        s.push_str(&format!("{sum}\n\n"));
    }
    s.push_str(&format!("- PRs opened: {}\n- PRs merged: {}\n- Issues opened: {}\n- Issues closed: {}\n- Commits: {}\n- Discord messages: {}\n", t["prsOpened"], t["prsMerged"], t["issuesOpened"], t["issuesClosed"], t["commits"], t["discordMessages"]));
    if r["workSessions"].as_u64().unwrap_or(0) > 0 {
        s.push_str(&format!("- Agent work sessions: {}\n", r["workSessions"]));
    }
    s.push_str("\n## People\n\n| Person | PRs opened | PRs merged | Issues | Commits | Messages |\n|---|---|---|---|---|---|\n");
    for p in r["people"].as_array().into_iter().flatten() {
        let n = |k: &str| p[k].as_u64().unwrap_or(0);
        s.push_str(&format!("| {} | {} | {} | {} | {} | {} |\n", p["name"].as_str().unwrap_or(""), n("prsOpened"), n("prsMerged"), n("issuesOpened") + n("issuesClosed"), n("commits"), n("discordMessages")));
    }
    if let Some(items) = r["items"].as_array().filter(|i| !i.is_empty()) {
        s.push_str("\n## Merged and opened\n\n");
        for it in items.iter().filter(|i| i["kind"] != "commit").take(50) {
            s.push_str(&format!("- [{}]({}) — {} ({}, {})\n", it["title"].as_str().unwrap_or(""), it["url"].as_str().unwrap_or(""), it["author"].as_str().unwrap_or(""), it["repo"].as_str().unwrap_or(""), it["kind"].as_str().unwrap_or("").replace('_', " ")));
        }
    }
    if let Some(w) = r["warnings"].as_array().filter(|w| !w.is_empty()) {
        s.push_str("\n## Warnings\n\n");
        for x in w {
            s.push_str(&format!("- {}\n", x.as_str().unwrap_or("")));
        }
    }
    s
}

fn report_dir(env: &Env) -> PathBuf {
    env.dir.join("team-reports")
}

fn store(env: &Env, r: &Value) -> Result<(), String> {
    let (p, k) = (r["period"].as_str().unwrap_or("day"), r["key"].as_str().unwrap_or(""));
    let base = report_dir(env).join(p);
    write_json(&base.join(format!("{k}.json")), r)?;
    write_atomic(&base.join(format!("{k}.md")), markdown(r).as_bytes())
}

pub fn load(env: &Env, period: &str, key: &str) -> Option<Value> {
    if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') || !matches!(period, "day" | "week" | "month") {
        return None;
    }
    read_json(&report_dir(env).join(period).join(format!("{key}.json")))
}

static RUN: Mutex<()> = Mutex::new(());

/// Collect, aggregate, summarize and store one UTC day (intraday = up to now).
pub fn generate_day(env: &Env, date: Option<&str>, intraday: bool, cancel: &Cancel) -> Result<Value, String> {
    generate_day_with(env, date, intraday, cancel, 60)
}

fn generate_day_with(env: &Env, date: Option<&str>, intraday: bool, cancel: &Cancel, max_wait: u64) -> Result<Value, String> {
    let cfg = env.cfg.team_reports.as_ref().ok_or("team reports are not configured ([surfaces.team_reports])")?;
    let _g = RUN.lock().unwrap();
    let today = (now_ms() / 86_400_000) as i64;
    let day = match date {
        Some(d) => day_num(d)?,
        None if intraday => today,
        None => today - 1,
    };
    if day > today || (day == today && !intraday) {
        return Err("only closed UTC days can be generated; pass intraday=true for today".into());
    }
    let start = day as u64 * 86_400_000;
    let end = if intraday && day == today { now_ms() } else { start + 86_400_000 };
    let mut c = Collected::default();
    collect_github(env, &cfg.github, start, end, &mut c, max_wait);
    if let Some(d) = &cfg.discord {
        collect_discord(env, d, start, end, &mut c, max_wait);
    }
    let (totals, people, repos) = aggregate(cfg, &c);
    let work = env.kernel().map(|k| k.store.list().into_iter().filter(|s| s.parent.is_none() && s.updated_ms >= start && s.updated_ms < end).count()).unwrap_or(0);
    let mut channels: BTreeMap<String, (u64, Vec<String>)> = BTreeMap::new();
    for (ch, _, name, ex) in &c.messages {
        let e = channels.entry(ch.clone()).or_default();
        e.0 += 1;
        if let Some(x) = ex.as_ref().filter(|_| e.1.len() < 20) {
            e.1.push(format!("{name}: {x}"));
        }
    }
    let mut r = json!({
        "period": "day", "key": day_key(day), "intraday": intraday && day == today,
        "window": {"start": iso(start), "end": iso(end)}, "generatedAt": iso(now_ms()),
        "totals": totals, "people": people, "repos": repos,
        "items": c.items.iter().take(500).collect::<Vec<_>>(),
        "discord": channels.iter().map(|(id, (n, ex))| json!({"channel": id, "messages": n, "excerpts": ex})).collect::<Vec<_>>(),
        "workSessions": work, "warnings": c.warnings, "stats": {"apiCalls": c.api_calls},
    });
    summarize(env, cfg, &mut r, cancel);
    store(env, &r)?;
    prune(env, cfg);
    Ok(r)
}

fn summarize(env: &Env, cfg: &TeamReportsConfig, r: &mut Value, cancel: &Cancel) {
    if !cfg.summaries.enabled {
        return;
    }
    let Ok(k) = env.kernel() else { return };
    let top: Vec<String> = r["items"].as_array().into_iter().flatten().filter(|i| i["kind"] != "commit").take(40).map(|i| format!("{} {} by {} in {}", i["kind"].as_str().unwrap_or(""), i["title"].as_str().unwrap_or(""), i["author"].as_str().unwrap_or(""), i["repo"].as_str().unwrap_or(""))).collect();
    let input = format!("Period: {} {}\nTotals: {}\nPeople: {}\nRepos: {}\nNotable items:\n{}", r["period"], r["key"], r["totals"], r["people"], r["repos"], top.join("\n"));
    let c = Completion { model: Some(cfg.summaries.model.as_str()).filter(|m| !m.is_empty()), system: "You write short, factual team activity summaries (3-6 sentences) from the data given. Do not invent facts, names or numbers. Plain prose, no headings.", user: input, max_tokens: 600, temperature: None, reasoning: None, timeout: Duration::from_secs(60) };
    match complete(k, c, cancel) {
        Ok((t, _)) if !t.trim().is_empty() => r["summary"] = t.trim().into(),
        Ok(_) => {}
        Err(e) => {
            if let Some(w) = r["warnings"].as_array_mut() {
                w.push(format!("summary: {e}").into());
            }
        }
    }
}

/// Week or month from stored days.
pub fn generate_rollup(env: &Env, period: &str, key: &str, cancel: &Cancel) -> Result<Value, String> {
    let cfg = env.cfg.team_reports.as_ref().ok_or("team reports are not configured ([surfaces.team_reports])")?;
    let days = days_of(period, key)?;
    let reports: Vec<Value> = days.iter().filter_map(|d| load(env, "day", &day_key(*d))).collect();
    if reports.is_empty() {
        return Err(format!("no stored days for {period} {key}; generate the days first"));
    }
    let (totals, people, repos) = rollup(&reports);
    let mut r = json!({"period": period, "key": key, "days": reports.iter().map(|r| r["key"].clone()).collect::<Vec<_>>(), "window": {"start": iso(days[0] as u64 * 86_400_000), "end": iso((*days.last().unwrap() as u64 + 1) * 86_400_000)}, "generatedAt": iso(now_ms()), "totals": totals, "people": people, "repos": repos, "workSessions": reports.iter().map(|r| r["workSessions"].as_u64().unwrap_or(0)).sum::<u64>(), "warnings": reports.iter().flat_map(|r| r["warnings"].as_array().cloned().unwrap_or_default()).collect::<Vec<_>>()});
    summarize(env, cfg, &mut r, cancel);
    store(env, &r)?;
    Ok(r)
}

fn prune(env: &Env, cfg: &TeamReportsConfig) {
    if cfg.retention_days == 0 {
        return;
    }
    let cutoff = (now_ms() / 86_400_000) as i64 - cfg.retention_days as i64;
    for e in std::fs::read_dir(report_dir(env).join("day")).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if let Some(d) = name.split('.').next().and_then(|k| day_num(k).ok()) {
            if d < cutoff {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

pub fn list(env: &Env, period: Option<&str>) -> Value {
    let mut out = Map::new();
    for p in ["day", "week", "month"].into_iter().filter(|p| period.is_none_or(|x| x == *p)) {
        let mut keys: Vec<String> = std::fs::read_dir(report_dir(env).join(p)).into_iter().flatten().flatten().filter_map(|e| e.file_name().to_string_lossy().strip_suffix(".json").map(str::to_string)).collect();
        keys.sort();
        keys.reverse();
        out.insert(p.into(), json!(keys));
    }
    Value::Object(out)
}

// ───────────────────────── ARP / HTTP / tool / scheduler ─────────────────────────

pub fn rpc_list(env: &Env, p: &Value) -> Result<Value, String> {
    Ok(json!({"periods": list(env, p["period"].as_str())}))
}

pub fn rpc_get(env: &Env, p: &Value) -> Result<Value, String> {
    let (period, key) = (p["period"].as_str().unwrap_or("day"), p["key"].as_str().unwrap_or(""));
    days_of(period, key)?;
    let r = load(env, period, key).ok_or("Report not found; generate the requested UTC day first")?;
    Ok(if p["format"] == "markdown" { json!({"markdown": markdown(&r)}) } else { r })
}

pub fn rpc_generate(env: &Env, p: &Value) -> Result<Value, String> {
    let period = p["period"].as_str().unwrap_or("day");
    match period {
        "day" => generate_day(env, p["date"].as_str(), p["intraday"] == true, &Cancel::new()).map(|r| json!({"key": r["key"], "totals": r["totals"]})),
        _ => generate_rollup(env, period, p["key"].as_str().unwrap_or(""), &Cancel::new()).map(|r| json!({"key": r["key"], "totals": r["totals"]})),
    }
}

pub fn serve(env: &Env, rest: &str) -> Response {
    let parts: Vec<&str> = rest.split(['?', '#']).next().unwrap_or("").split('/').filter(|s| !s.is_empty()).collect();
    let page = |title: &str, body: &str| Response::html(&format!("<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{}</title><style>body{{font:14px/1.5 system-ui,sans-serif;max-width:960px;margin:24px auto;padding:0 16px}}table{{border-collapse:collapse}}td,th{{border-bottom:1px solid #8884;padding:4px 10px;text-align:left}}.m{{display:inline-block;margin:0 16px 8px 0}}.m b{{display:block;font-size:22px}}</style></head><body>{body}</body></html>", esc_html(title))).with_header("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'");
    match parts.as_slice() {
        [] => {
            let l = list(env, None);
            let mut b = String::from("<h1>Team reports</h1>");
            for p in ["day", "week", "month"] {
                b.push_str(&format!("<h2>{p}</h2><ul>"));
                for k in l[p].as_array().into_iter().flatten().take(60) {
                    let k = k.as_str().unwrap_or("");
                    b.push_str(&format!("<li><a href=\"{p}/{}\">{}</a></li>", esc_html(k), esc_html(k)));
                }
                b.push_str("</ul>");
            }
            page("Team reports", &b)
        }
        [period, key] => match load(env, period, key) {
            Some(r) => {
                let t = &r["totals"];
                let mut b = format!("<p><a href=\"../\">← all reports</a></p><h1>{} {}</h1>", esc_html(period), esc_html(key));
                if let Some(s) = r["summary"].as_str() {
                    b.push_str(&format!("<p>{}</p>", esc_html(s)));
                }
                for (label, k) in [("PRs opened", "prsOpened"), ("PRs merged", "prsMerged"), ("Issues opened", "issuesOpened"), ("Issues closed", "issuesClosed"), ("Commits", "commits"), ("Messages", "discordMessages")] {
                    b.push_str(&format!("<span class=\"m\"><b>{}</b>{label}</span>", t[k].as_u64().unwrap_or(0)));
                }
                b.push_str("<h2>People</h2><table><tr><th>Person</th><th>PRs opened</th><th>PRs merged</th><th>Issues</th><th>Commits</th><th>Messages</th></tr>");
                for p in r["people"].as_array().into_iter().flatten() {
                    let n = |k: &str| p[k].as_u64().unwrap_or(0);
                    b.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>", esc_html(p["name"].as_str().unwrap_or("")), n("prsOpened"), n("prsMerged"), n("issuesOpened") + n("issuesClosed"), n("commits"), n("discordMessages")));
                }
                b.push_str("</table>");
                if let Some(items) = r["items"].as_array() {
                    b.push_str("<h2>Items</h2><ul>");
                    for it in items.iter().filter(|i| i["kind"] != "commit").take(100) {
                        let url = it["url"].as_str().unwrap_or("");
                        let link = if url.starts_with("https://") { format!("<a href=\"{}\" rel=\"noopener noreferrer\">{}</a>", esc_html(url), esc_html(it["title"].as_str().unwrap_or(""))) } else { esc_html(it["title"].as_str().unwrap_or("")) };
                        b.push_str(&format!("<li>{link} — {} ({})</li>", esc_html(it["author"].as_str().unwrap_or("")), esc_html(it["repo"].as_str().unwrap_or(""))));
                    }
                    b.push_str("</ul>");
                }
                page(&format!("Team report {key}"), &b)
            }
            None => Response::text(404, "Report not found; generate the requested UTC day first"),
        },
        _ => Response::text(404, "not found"),
    }
}

pub struct TeamReportsTool(pub Arc<Env>);

impl Tool for TeamReportsTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "team_reports".into(),
            description: "Daily, weekly and monthly team activity reports from GitHub and Discord with model-written summaries. action=status | list {period?} | get {period: day|week|month, key, format: json|markdown} | generate {date? (YYYY-MM-DD, default yesterday UTC), intraday?} | rollup {period: week|month, key} (from stored days).".into(),
            input_schema: json!({"type": "object", "properties": {
                "action": {"type": "string", "enum": ["status", "list", "get", "generate", "rollup"]},
                "period": {"type": "string", "enum": ["day", "week", "month"]},
                "key": {"type": "string", "description": "2026-11-02, 2026-W45 or 2026-11"},
                "format": {"type": "string", "enum": ["json", "markdown"]},
                "date": {"type": "string"},
                "intraday": {"type": "boolean"}
            }, "required": ["action"]}),
            parallel_safe: false,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let Some(cfg) = &self.0.cfg.team_reports else { return vec![] };
        if input["action"] != "generate" {
            return vec![];
        }
        let host = |u: &str| u.split("://").nth(1).and_then(|r| r.split('/').next()).unwrap_or("").to_string();
        let mut e = vec![Effect::Net { dest: host(&cfg.github.api_base_url), payload: format!("search orgs {}", cfg.github.orgs.join(", ")) }];
        if let Some(d) = &cfg.discord {
            e.push(Effect::Net { dest: host(&d.api_base_url), payload: format!("read messages of channels {}", d.channels.iter().map(|c| c.id.as_str()).collect::<Vec<_>>().join(", ")) });
        }
        e
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let env = &self.0;
        let r = match input["action"].as_str().unwrap_or("") {
            "status" => Ok(json!({"configured": true, "stored": list(env, None), "schedule": env.cfg.team_reports.as_ref().map(|c| json!(c.schedule))}).to_string()),
            "list" => rpc_list(env, &input).map(|v| v.to_string()),
            "get" => rpc_get(env, &input).map(|v| if input["format"] == "markdown" { v["markdown"].as_str().unwrap_or("").to_string() } else { v.to_string() }),
            "generate" => generate_day(env, input["date"].as_str(), input["intraday"] == true, &ctx.cancel).map(|r| markdown(&r)),
            "rollup" => generate_rollup(env, input["period"].as_str().unwrap_or("week"), input["key"].as_str().unwrap_or(""), &ctx.cancel).map(|r| markdown(&r)),
            a => Err(format!("unknown action `{a}`")),
        };
        match r {
            Ok(t) => ToolOutput::ok(t),
            Err(e) => ToolOutput::err(e),
        }
    }
}

/// What the schedule wants done at `now` given what is stored: (day, intraday) and rollups.
/// (day key, intraday) to generate, and (period, key) rollups.
type Due = (Option<(String, bool)>, Vec<(String, String)>);

fn due(cfg: &ScheduleConfig, now: u64, have: &dyn Fn(&str, &str) -> Option<u64>) -> Due {
    let today = (now / 86_400_000) as i64;
    let (h, m) = cfg.closed_day_utc.split_once(':').and_then(|(h, m)| Some((h.parse::<u64>().ok()?, m.parse::<u64>().ok()?))).unwrap_or((0, 5));
    let after_close = now % 86_400_000 >= (h * 3600 + m * 60) * 1000;
    let yesterday = day_key(today - 1);
    let mut rollups = Vec::new();
    let mut day = None;
    if after_close && have("day", &yesterday).is_none() {
        day = Some((yesterday.clone(), false));
    } else if cfg.intraday_every_hours > 0 {
        let fresh = have("day", &day_key(today)).is_some_and(|t| now.saturating_sub(t) < cfg.intraday_every_hours * 3_600_000);
        if !fresh {
            day = Some((day_key(today), true));
        }
    }
    if have("day", &yesterday).is_some() {
        // Yesterday closed a week (Sunday) or a month (last day).
        if cfg.weekly && (today - 1 + 3).rem_euclid(7) == 6 && have("week", &week_key(today - 1)).is_none() {
            rollups.push(("week".into(), week_key(today - 1)));
        }
        if cfg.monthly && month_key(today) != month_key(today - 1) && have("month", &month_key(today - 1)).is_none() {
            rollups.push(("month".into(), month_key(today - 1)));
        }
    }
    (day, rollups)
}

pub fn spawn_scheduler(env: Arc<Env>, cancel: Cancel) -> Option<std::thread::JoinHandle<()>> {
    let cfg = env.cfg.team_reports.clone()?;
    if !cfg.schedule.enabled {
        return None;
    }
    Some(std::thread::spawn(move || {
        while !cancel.is_cancelled() {
            let have = |p: &str, k: &str| load(&env, p, k).map(|r| r["generatedAt"].as_str().and_then(super::parse_iso).unwrap_or(1));
            let (day, rollups) = due(&cfg.schedule, now_ms(), &have);
            if let Some((d, intraday)) = day {
                if let Err(e) = generate_day(&env, Some(&d), intraday, &cancel) {
                    eprintln!("arkd: team-reports: {d}: {e}");
                }
            }
            for (p, k) in rollups {
                if let Err(e) = generate_rollup(&env, &p, &k, &cancel) {
                    eprintln!("arkd: team-reports: {p} {k}: {e}");
                }
            }
            for _ in 0..60 {
                if cancel.is_cancelled() {
                    return;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::super::testkit;
    use super::*;

    #[test]
    fn periods() {
        assert_eq!(week_key(day_num("2026-11-02").unwrap()), "2026-W45");
        assert_eq!(week_key(day_num("2021-01-03").unwrap()), "2020-W53");
        assert_eq!(days_of("week", "2026-W45").unwrap()[0], day_num("2026-11-02").unwrap());
        assert_eq!(days_of("month", "2026-02").unwrap().len(), 28);
        assert!(day_num("2026-02-30").is_err());
        assert!(days_of("week", "2026-W60").is_err());
    }

    #[test]
    fn schedule_decides_what_is_due() {
        let cfg = ScheduleConfig::default();
        let now = day_num("2026-11-02").unwrap() as u64 * 86_400_000 + 600_000; // Monday 00:10
        let none = |_: &str, _: &str| None;
        let (d, r) = due(&cfg, now, &none);
        assert_eq!(d, Some(("2026-11-01".into(), false)));
        assert!(r.is_empty());
        let have_day = |p: &str, k: &str| (p == "day" && k == "2026-11-01").then_some(1);
        let (d, r) = due(&cfg, now, &have_day);
        assert_eq!(d, Some(("2026-11-02".into(), true)));
        assert_eq!(r, vec![("week".to_string(), "2026-W44".to_string())]);
        let early = day_num("2026-11-02").unwrap() as u64 * 86_400_000 + 60_000;
        assert_eq!(due(&ScheduleConfig { intraday_every_hours: 0, ..cfg.clone() }, early, &none).0, None);
    }

    #[test]
    fn generates_reports_from_fake_github_and_discord() {
        let day = day_num("2026-11-01").unwrap() as u64 * 86_400_000;
        let msg_id = |ms: u64| ((ms - DISCORD_EPOCH) << 22).to_string();
        let (m1, m2, late) = (msg_id(day + 3_600_000), msg_id(day + 7_200_000), msg_id(day + 90_000_000));
        let (url, seen) = testkit::server(Box::new(move |r| {
            let p = r.path.clone();
            let body = if p.starts_with("/search/issues") && p.contains("is%3Amerged") {
                json!({"items": [{"user": {"login": "AliceGH"}, "title": "Fix crash", "html_url": "https://github.com/acme/app/pull/7", "repository_url": "https://api.github.com/repos/acme/app"}]})
            } else if p.starts_with("/search/issues") && p.contains("is%3Apr") && !p.contains("page=2") {
                return (200, vec![("link".into(), format!("<{}?page=2>; rel=\"next\"", "http://127.0.0.1:1/evil"))], json!({"items": [{"user": {"login": "bob"}, "title": "Add API", "html_url": "https://github.com/acme/app/pull/8", "repository_url": "https://api.github.com/repos/acme/app"}, {"user": {"login": "bob"}, "title": "Skip", "html_url": "x", "repository_url": "https://api.github.com/repos/acme/secret"}]}).to_string());
            } else if p.starts_with("/search/issues") && p.contains("closed%3A") {
                return (500, vec![], "oops".into());
            } else if p.starts_with("/search/issues") {
                json!({"items": []})
            } else if p.starts_with("/search/commits") {
                json!({"items": [{"author": {"login": "alice"}, "repository": {"full_name": "acme/app"}, "commit": {"message": "wip\n\nbody"}, "html_url": "https://github.com/acme/app/commit/1"}]})
            } else if p.starts_with("/channels/42/messages") {
                json!([{"id": late, "author": {"id": "9", "username": "al"}, "content": "tomorrow"}, {"id": m2, "author": {"id": "9", "username": "al"}, "content": "shipping it"}, {"id": m1, "author": {"id": "5", "username": "bot", "bot": true}, "content": "beep"}])
            } else {
                return (404, vec![], "{}".into());
            };
            (200, vec![], body.to_string())
        }));
        let cfg = format!(
            "[team_reports]\nretention_days = 0\n[team_reports.github]\ntoken = \"ghs_test\"\norgs = [\"acme\"]\nexclude_repos = [\"acme/secret\"]\napi_base_url = \"{url}\"\n[team_reports.discord]\ntoken = \"bot_test\"\nguild_id = \"1\"\napi_base_url = \"{url}\"\nchannels = [{{id = \"42\", excerpts = true}}]\n[[team_reports.people]]\ngithub = [\"alice\", \"AliceGH\"]\ndisplay = \"Alice\"\ndiscord_user_id = \"9\"\n"
        );
        let (env, fake) = testkit::env("tr", &["A calm day: Alice merged a fix."], &cfg);
        let r = generate_day_with(&env, Some("2026-11-01"), false, &Cancel::new(), 0).unwrap();
        assert_eq!(r["totals"]["prsMerged"], 1);
        assert_eq!(r["totals"]["prsOpened"], 1, "excluded repo dropped");
        assert_eq!(r["totals"]["commits"], 1);
        assert_eq!(r["totals"]["discordMessages"], 1, "bot and out-of-window messages dropped");
        let alice = r["people"].as_array().unwrap().iter().find(|p| p["name"] == "Alice").unwrap();
        assert_eq!((alice["prsMerged"].as_u64(), alice["commits"].as_u64(), alice["discordMessages"].as_u64()), (Some(1), Some(1), Some(1)));
        assert_eq!(r["summary"], "A calm day: Alice merged a fix.");
        assert!(r["warnings"].to_string().contains("pagination outside the configured base URL"), "{}", r["warnings"]);
        assert!(r["warnings"].to_string().contains("HTTP 500"));
        assert_eq!(r["discord"][0]["excerpts"][0], "al: shipping it");
        let reqs = seen.lock().unwrap().clone();
        assert!(reqs.iter().any(|q| q.path.contains("created%3A2026-11-01T00%3A00%3A00Z..2026-11-01T23%3A59%3A59Z")), "{:?}", reqs.iter().map(|r| r.path.clone()).collect::<Vec<_>>());
        let gh = reqs.iter().find(|q| q.path.starts_with("/search")).unwrap();
        assert!(gh.headers.iter().any(|(k, v)| k == "authorization" && v == "Bearer ghs_test"));
        assert!(gh.headers.iter().any(|(k, v)| k == "x-github-api-version" && v == "2022-11-28"));
        let dc = reqs.iter().find(|q| q.path.starts_with("/channels")).unwrap();
        assert!(dc.headers.iter().any(|(k, v)| k == "authorization" && v == "Bot bot_test"));
        assert!(dc.path.contains(&format!("after={}", (day - DISCORD_EPOCH) << 22)));
        assert!(fake.seen.lock().unwrap()[0].messages[0].text().contains("Totals"));
        // Stored, listed, served, rolled up.
        assert_eq!(list(&env, Some("day"))["day"][0], "2026-11-01");
        assert!(rpc_get(&env, &json!({"period": "day", "key": "2026-11-01", "format": "markdown"})).unwrap()["markdown"].as_str().unwrap().contains("| Alice | 0 | 1 | 0 | 1 | 1 |"));
        let page = serve(&env, "/day/2026-11-01");
        assert_eq!(page.status, 200);
        let w = generate_rollup(&env, "week", "2026-W44", &Cancel::new()).unwrap();
        assert_eq!(w["totals"]["commits"], 1);
        assert!(generate_rollup(&env, "month", "2026-10", &Cancel::new()).unwrap_err().contains("no stored days"));
        assert!(generate_day(&env, Some("2999-01-01"), false, &Cancel::new()).is_err());
        let t = TeamReportsTool(env.clone());
        let ws = testkit::temp("tr-ws");
        assert!(t.call(&testkit::ctx(&env, &ws), json!({"action": "get", "period": "day", "key": "2026-11-01", "format": "markdown"})).content.starts_with("# Team report · day 2026-11-01"));
        assert!(check_base("http://evil.example", "GitHub").is_err());
    }
}
