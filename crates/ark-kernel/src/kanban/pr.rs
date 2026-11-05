//! Exact-head GitHub acceptance for tasks declared with a PR completion contract
//! (`OWNER/REPO` or an exact PR URL). Completion is refused until every
//! repository-required check passes on the PR's *current* head. Network work happens
//! outside the board lock; the receipt only counts if the task's run/status/contract
//! snapshot is unchanged when it is recorded.

use super::store::BoardData;
use serde_json::{json, Value};
use std::io::Read;
use std::time::Duration;

/// `(current_run_id, status, completion_contract)` captured before the network reads.
pub type Snapshot = (Option<u64>, String, String);

fn repo_re() -> &'static regex::Regex {
    static R: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    R.get_or_init(|| regex::Regex::new(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$").unwrap())
}
fn pr_re() -> &'static regex::Regex {
    static R: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    R.get_or_init(|| regex::Regex::new(r"^https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/pull/([1-9][0-9]*)$").unwrap())
}

pub fn validate_contract(v: Option<&str>) -> Result<String, String> {
    match v {
        None | Some("local-only") | Some("") => Ok("local-only".into()),
        Some(s) if repo_re().is_match(s) || pr_re().is_match(s) => Ok(s.into()),
        Some(_) => Err("completion_contract must be local-only, OWNER/REPO, or an exact GitHub PR URL".into()),
    }
}

/// Under the lock: refuse (Err) a stale caller, bind `metadata.published_pr` once to an
/// `OWNER/REPO` contract, and return what to collect. Ok(None) = no gate (local-only).
/// `Err` is the only failure mode (`stale caller`), so `()` carries all the information and
/// every caller only checks `is_err()`.
#[allow(clippy::result_unit_err)]
pub fn prepare(b: &mut BoardData, id: &str, expected_run: Option<u64>, metadata: Option<&Value>) -> Result<Option<(Snapshot, String, Option<String>)>, ()> {
    let t = b.task(id).ok_or(())?;
    let contract = t.completion_contract.clone().unwrap_or_else(|| "local-only".into());
    if contract == "local-only" {
        return Ok(None);
    }
    if !matches!(t.status.as_str(), "running" | "ready" | "blocked" | "review") || (expected_run.is_some() && t.current_run_id != expected_run) {
        return Err(());
    }
    let published = metadata.and_then(|m| m["published_pr"].as_str()).map(String::from);
    let mut contract = contract;
    if let Some(p) = published.as_deref() {
        // Publication binds once: a retry cannot swap the task's PR for a green sibling.
        if pr_re().captures(p).is_some_and(|c| c[1] == contract) {
            b.task_mut(id).unwrap().completion_contract = Some(p.into());
            contract = p.into();
        }
    }
    let t = b.task(id).unwrap();
    Ok(Some(((t.current_run_id, t.status.clone(), contract.clone()), contract, published)))
}

/// Under complete's lock, before its terminal write: append the receipt; false blocks.
pub fn record_acceptance(b: &mut BoardData, id: &str, snap: &Snapshot, receipt: &Value) -> bool {
    let Some(t) = b.task(id) else { return false };
    let now_snap = (t.current_run_id, t.status.clone(), t.completion_contract.clone().unwrap_or_else(|| "local-only".into()));
    if &now_snap != snap {
        return false;
    }
    b.append_event(id, "pr_acceptance", Some(receipt.clone()), snap.0);
    if receipt["ok"] != true {
        let detail = format!("PR acceptance {}: {} {}", receipt["classification"].as_str().unwrap_or(""), receipt["detail"].as_str().unwrap_or(""), receipt["recovery"].as_str().unwrap_or(""));
        b.task_mut(id).unwrap().last_failure_error = Some(detail);
        return false;
    }
    true
}

pub struct Gh {
    pub api: String,
    pub token: Option<String>,
    agent: ureq::Agent,
}

enum GhErr {
    Auth(String),
    /// Message kept for debugging only; never persisted (may echo host details).
    #[allow(dead_code)]
    Infra(String),
}

impl Gh {
    pub fn new(api: &str, token: Option<String>) -> Gh {
        let agent = ark_net::http::builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(30))).build().into();
        Gh { api: api.trim_end_matches('/').to_string(), token: token.filter(|t| !t.is_empty()), agent }
    }

    fn send(&self, method: &str, url: &str, body: Option<&Value>) -> Result<(Value, Option<String>), GhErr> {
        let endpoint = url.split('?').next().unwrap_or(url).to_string();
        let mut r = match method {
            "POST" => {
                let mut q = self.agent.post(url).header("accept", "application/vnd.github+json").header("user-agent", "ark-kanban").header("x-github-api-version", "2022-11-28");
                if let Some(t) = &self.token {
                    q = q.header("authorization", &format!("Bearer {t}"));
                }
                q.header("content-type", "application/json").send(body.map(|b| b.to_string()).unwrap_or_default().as_bytes())
            }
            _ => {
                let mut q = self.agent.get(url).header("accept", "application/vnd.github+json").header("user-agent", "ark-kanban").header("x-github-api-version", "2022-11-28");
                if let Some(t) = &self.token {
                    q = q.header("authorization", &format!("Bearer {t}"));
                }
                q.call()
            }
        }
        .map_err(|e| GhErr::Infra(format!("request failed: {e}")))?;
        let status = r.status().as_u16();
        let link = r.headers().get("link").and_then(|v| v.to_str().ok()).map(String::from);
        let mut raw = Vec::new();
        r.body_mut().with_config().limit(u64::MAX).reader().take(16 * 1024 * 1024).read_to_end(&mut raw).map_err(|e| GhErr::Infra(e.to_string()))?;
        if matches!(status, 401 | 403 | 404) {
            // Persist only the code + endpoint, never the response body.
            return Err(GhErr::Auth(format!("HTTP {status} on {}", endpoint.trim_start_matches(&self.api))));
        }
        if !(200..300).contains(&status) {
            return Err(GhErr::Infra(format!("HTTP {status}")));
        }
        let v: Value = serde_json::from_slice(&raw).map_err(|e| GhErr::Infra(e.to_string()))?;
        if v.get("errors").is_some_and(|e| !e.is_null()) {
            return Err(GhErr::Infra("GitHub returned incomplete GraphQL evidence".into()));
        }
        Ok((v, link))
    }

    fn get(&self, path: &str) -> Result<Value, GhErr> {
        self.send("GET", &format!("{}/{path}", self.api), None).map(|(v, _)| v)
    }

    /// Every page (following `Link: rel="next"`), like `gh api --paginate --slurp`.
    fn pages(&self, path: &str) -> Result<Vec<Value>, GhErr> {
        let mut url = format!("{}/{path}", self.api);
        let mut out = vec![];
        for _ in 0..50 {
            let (v, link) = self.send("GET", &url, None)?;
            out.push(v);
            match link.as_deref().and_then(next_link) {
                Some(n) => url = n,
                None => return Ok(out),
            }
        }
        Err(GhErr::Infra("too many pages".into()))
    }
}

fn next_link(h: &str) -> Option<String> {
    h.split(',').find(|p| p.contains("rel=\"next\"")).and_then(|p| p.split(';').next()).map(|u| u.trim().trim_start_matches('<').trim_end_matches('>').to_string())
}

fn classify(check: &Value, sha: &str, outcome: Option<&str>, is_run: bool) -> &'static str {
    let head = check.get("head_sha").or_else(|| check.get("sha")).and_then(|v| v.as_str());
    if head != Some(sha) {
        return "stale";
    }
    if is_run && check["status"].as_str() != Some("completed") {
        return "pending";
    }
    match outcome {
        Some("success") => "success",
        Some("failure") => "failure",
        Some("pending") => "pending",
        _ => "infra",
    }
}

/// Read the PR's current head and every required check on it; never panics.
pub fn collect(gh: &Gh, contract: &str, published: Option<&str>) -> Value {
    let mut receipt = json!({"ok": false, "classification": "missing", "head_sha": null, "pr_url": published, "checks": [],
        "recovery": "Fix required failures, rerun infrastructure checks or wait, then retry completion. Use kanban_block if human input is needed; receipts remain on the task event log."});
    match collect_inner(gh, contract, published, &mut receipt) {
        Ok(()) => {}
        Err(GhErr::Auth(e)) => {
            receipt["classification"] = "auth".into();
            receipt["detail"] = format!("GitHub refused the acceptance read ({e}); fix the GitHub token's access to the repository, then retry completion.").into();
        }
        Err(GhErr::Infra(_)) => {
            receipt["classification"] = "infra".into();
            receipt["detail"] = "GitHub acceptance evidence unavailable or incomplete; check GitHub authentication/API access and retry.".into();
        }
    }
    receipt
}

fn collect_inner(gh: &Gh, contract: &str, published: Option<&str>, receipt: &mut Value) -> Result<(), GhErr> {
    let declared = pr_re().is_match(contract);
    let url = if declared { Some(contract) } else { published };
    let cap = url.and_then(|u| pr_re().captures(u));
    let Some(cap) = cap.filter(|c| (declared || &c[1] == contract) && !(declared && published.is_some_and(|p| p != contract))) else {
        receipt["detail"] = "Supply metadata.published_pr matching the persisted completion contract.".into();
        return Ok(());
    };
    let (repo, number) = (cap[1].to_string(), cap[2].parse::<u64>().unwrap_or(0));
    receipt["pr_url"] = url.into();
    let (owner, name) = repo.split_once('/').unwrap();
    let query = format!("{{repository(owner:{},name:{}){{pullRequest(number:{number}){{headRefOid baseRefName state baseRef{{branchProtectionRule{{requiredStatusChecks{{context app{{databaseId}}}}}}}}}}}}}}", json!(owner), json!(name));
    let (g, _) = gh.send("POST", &format!("{}/graphql", gh.api), Some(&json!({"query": query})))?;
    let repository = &g["data"]["repository"];
    if repository.is_null() {
        // A private repo the token cannot read resolves to null, not an error.
        return Err(GhErr::Auth(format!("HTTP 404 on graphql {repo}")));
    }
    let pr = &repository["pullRequest"];
    let sha = pr["headRefOid"].as_str().unwrap_or("").to_string();
    let branch = pr["baseRefName"].as_str().unwrap_or("").to_string();
    receipt["head_sha"] = sha.clone().into();
    let hex40 = sha.len() == 40 && sha.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
    if !hex40 || !matches!(pr["state"].as_str(), Some("OPEN" | "MERGED")) {
        return Err(GhErr::Infra("PR is closed or current head is unavailable".into()));
    }
    let mut required: std::collections::BTreeSet<(String, Option<i64>)> = std::collections::BTreeSet::new();
    for r in pr["baseRef"]["branchProtectionRule"]["requiredStatusChecks"].as_array().into_iter().flatten() {
        required.insert((r["context"].as_str().unwrap_or("").to_string(), r["app"]["databaseId"].as_i64()));
    }
    let enc: String = branch.bytes().map(|c| if c.is_ascii_alphanumeric() || b"-_.~".contains(&c) { (c as char).to_string() } else { format!("%{c:02X}") }).collect();
    for page in gh.pages(&format!("repos/{repo}/rules/branches/{enc}?per_page=100"))? {
        for rule in page.as_array().into_iter().flatten().filter(|r| r["type"] == "required_status_checks") {
            for c in rule["parameters"]["required_status_checks"].as_array().into_iter().flatten() {
                required.insert((c["context"].as_str().unwrap_or("").to_string(), c["integration_id"].as_i64()));
            }
        }
    }
    receipt["required"] = json!(required.iter().map(|(c, a)| json!({"context": c, "app_id": a})).collect::<Vec<_>>());
    if required.is_empty() {
        receipt["detail"] = "No repository-required checks are configured; explicitly use a local-only contract for non-CI tasks.".into();
        return Ok(());
    }
    let pages = gh.pages(&format!("repos/{repo}/commits/{sha}/check-runs?per_page=100&filter=latest"))?;
    let runs: Vec<Value> = pages.iter().flat_map(|p| p["check_runs"].as_array().cloned().unwrap_or_default()).collect();
    let ids: std::collections::HashSet<i64> = runs.iter().filter_map(|r| r["id"].as_i64()).collect();
    if Some(ids.len() as u64) != pages.first().and_then(|p| p["total_count"].as_u64()) {
        return Err(GhErr::Infra("Incomplete check-run pagination".into()));
    }
    let statuses: Vec<Value> = gh.pages(&format!("repos/{repo}/commits/{sha}/statuses?per_page=100"))?.into_iter().flat_map(|p| p.as_array().cloned().unwrap_or_default()).map(|mut s| {
        s["sha"] = sha.clone().into();
        s
    }).collect();
    let mut outcomes: Vec<&'static str> = vec![];
    let mut checks = vec![];
    for (context, app) in &required {
        let unpinned = app.is_none_or(|a| a == -1);
        let mut selected: Vec<(&Value, bool)> = runs.iter().filter(|r| r["name"].as_str() == Some(context) && (unpinned || r["app"]["id"].as_i64() == *app)).map(|r| (r, true)).collect();
        // A legacy status can satisfy an unpinned context, never an app-pinned one.
        if unpinned {
            if let Some(s) = statuses.iter().filter(|s| s["context"].as_str() == Some(context)).max_by_key(|s| s["id"].as_i64()) {
                selected.push((s, false));
            }
        }
        if selected.is_empty() {
            outcomes.push("missing");
            checks.push(json!({"name": context, "classification": "missing", "head_sha": sha}));
        }
        for (c, is_run) in selected {
            let outcome = if is_run { c["conclusion"].as_str() } else { c["state"].as_str() };
            let class = classify(c, &sha, outcome, is_run);
            outcomes.push(class);
            checks.push(json!({"name": context, "id": c["id"], "url": c.get("html_url").or_else(|| c.get("target_url")), "head_sha": c.get("head_sha").or_else(|| c.get("sha")), "classification": class, "conclusion": outcome}));
        }
    }
    receipt["checks"] = json!(checks);
    // Re-read: an old head's successes are never transferable.
    let cur = gh.get(&format!("repos/{repo}/pulls/{number}"))?;
    if cur["head"]["sha"].as_str() != Some(sha.as_str()) || cur["base"]["ref"].as_str() != Some(branch.as_str()) || (cur["state"] == "closed" && cur["merged"] != true) {
        receipt["classification"] = "stale".into();
        receipt["detail"] = "PR head/base changed while collecting evidence; retry.".into();
        return Ok(());
    }
    let class = outcomes.iter().find(|o| **o != "success").copied().unwrap_or(if outcomes.is_empty() { "missing" } else { "success" });
    receipt["classification"] = class.into();
    receipt["ok"] = (class == "success").into();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// Minimal GitHub fake: routes by path prefix, records requests.
    fn fake(routes: Vec<(&'static str, String, Option<&'static str>)>) -> (String, Arc<Mutex<Vec<String>>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("http://{}", l.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(vec![]));
        let s2 = seen.clone();
        let base = addr.clone();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let mut r = BufReader::new(c.try_clone().unwrap());
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                let mut len = 0;
                let mut auth = String::new();
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).unwrap();
                    if h.trim().is_empty() {
                        break;
                    }
                    let lower = h.to_lowercase();
                    if let Some(v) = lower.strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap();
                    }
                    if lower.starts_with("authorization:") {
                        auth = h.trim().to_string();
                    }
                }
                let mut body = vec![0; len];
                std::io::Read::read_exact(&mut r, &mut body).unwrap();
                s2.lock().unwrap().push(format!("{path} {auth}"));
                let (status, text, link) = routes.iter().find(|(p, _, _)| path.starts_with(p)).map(|(_, b, l)| (if b == "404" { 404 } else { 200 }, b.clone(), *l)).unwrap_or((404, "{}".into(), None));
                let link = link.map(|l| format!("link: <{base}{l}>; rel=\"next\"\r\n")).unwrap_or_default();
                let mut w = c;
                let _ = write!(w, "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{link}connection: close\r\n\r\n{text}", text.len());
            }
        });
        (addr, seen)
    }

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    fn graphql(state: &str) -> String {
        json!({"data": {"repository": {"pullRequest": {"headRefOid": SHA, "baseRefName": "main", "state": state, "baseRef": {"branchProtectionRule": {"requiredStatusChecks": [{"context": "ci", "app": {"databaseId": 15368}}]}}}}}}).to_string()
    }

    #[test]
    fn green_exact_head_passes_and_pagination_is_followed() {
        let runs1 = json!({"total_count": 2, "check_runs": [{"id": 1, "name": "ci", "app": {"id": 15368}, "head_sha": SHA, "status": "completed", "conclusion": "success", "html_url": "https://x/1"}]}).to_string();
        let runs2 = json!({"total_count": 2, "check_runs": [{"id": 2, "name": "lint", "app": {"id": 1}, "head_sha": SHA, "status": "completed", "conclusion": "success"}]}).to_string();
        let rules = json!([{"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": "lint", "integration_id": null}]}}]).to_string();
        let pull = json!({"head": {"sha": SHA}, "base": {"ref": "main"}, "state": "open"}).to_string();
        let (api, seen) = fake(vec![
            ("/graphql", graphql("OPEN"), None),
            ("/repos/o/r/rules/branches/main", rules, None),
            ("/repos/o/r/commits/0123456789abcdef0123456789abcdef01234567/check-runs?per_page=100&filter=latest&page=2", runs2, None),
            ("/repos/o/r/commits/0123456789abcdef0123456789abcdef01234567/check-runs", runs1, Some("/repos/o/r/commits/0123456789abcdef0123456789abcdef01234567/check-runs?per_page=100&filter=latest&page=2")),
            ("/repos/o/r/commits/0123456789abcdef0123456789abcdef01234567/statuses", "[]".into(), None),
            ("/repos/o/r/pulls/7", pull, None),
        ]);
        let gh = Gh::new(&api, Some("tok".into()));
        let r = collect(&gh, "o/r", Some("https://github.com/o/r/pull/7"));
        assert_eq!(r["classification"], "success", "{r}");
        assert_eq!(r["ok"], true);
        assert_eq!(r["checks"].as_array().unwrap().len(), 2);
        let s = seen.lock().unwrap();
        assert!(s.iter().all(|l| l.contains("Bearer tok")));
        assert!(s.iter().any(|l| l.contains("page=2")), "{s:?}");
    }

    #[test]
    fn failures_stale_heads_missing_publication_and_auth() {
        let runs = json!({"total_count": 1, "check_runs": [{"id": 1, "name": "ci", "app": {"id": 15368}, "head_sha": SHA, "status": "completed", "conclusion": "failure"}]}).to_string();
        let pull = json!({"head": {"sha": SHA}, "base": {"ref": "main"}, "state": "open"}).to_string();
        let (api, _) = fake(vec![
            ("/graphql", graphql("OPEN"), None),
            ("/repos/o/r/rules/branches/main", "[]".into(), None),
            ("/repos/o/r/commits/0123456789abcdef0123456789abcdef01234567/check-runs", runs, None),
            ("/repos/o/r/commits/0123456789abcdef0123456789abcdef01234567/statuses", "[]".into(), None),
            ("/repos/o/r/pulls/7", pull, None),
        ]);
        let gh = Gh::new(&api, None);
        let r = collect(&gh, "https://github.com/o/r/pull/7", None);
        assert_eq!(r["classification"], "failure");
        assert_eq!(r["ok"], false);
        // OWNER/REPO contract without a published PR: actionable "missing".
        let r = collect(&gh, "o/r", None);
        assert_eq!(r["classification"], "missing");
        assert!(r["detail"].as_str().unwrap().contains("published_pr"));
        // A PR in another repo never satisfies the contract.
        assert_eq!(collect(&gh, "o/r", Some("https://github.com/x/y/pull/1"))["classification"], "missing");
        let (api404, _) = fake(vec![("/graphql", "404".into(), None)]);
        let r = collect(&Gh::new(&api404, None), "https://github.com/o/r/pull/7", None);
        assert_eq!(r["classification"], "auth");
        assert!(!r["detail"].as_str().unwrap().contains("{}"), "never persists response bodies");
        let stale_pull = json!({"head": {"sha": "f".repeat(40)}, "base": {"ref": "main"}, "state": "open"}).to_string();
        let ok_runs = json!({"total_count": 1, "check_runs": [{"id": 1, "name": "ci", "app": {"id": 15368}, "head_sha": SHA, "status": "completed", "conclusion": "success"}]}).to_string();
        let (api2, _) = fake(vec![
            ("/graphql", graphql("OPEN"), None),
            ("/repos/o/r/rules/branches/main", "[]".into(), None),
            ("/repos/o/r/commits/0123456789abcdef0123456789abcdef01234567/check-runs", ok_runs, None),
            ("/repos/o/r/commits/0123456789abcdef0123456789abcdef01234567/statuses", "[]".into(), None),
            ("/repos/o/r/pulls/7", stale_pull, None),
        ]);
        assert_eq!(collect(&Gh::new(&api2, None), "https://github.com/o/r/pull/7", None)["classification"], "stale");
    }

    #[test]
    fn contract_validation_binding_and_snapshot_fence() {
        assert_eq!(validate_contract(None).unwrap(), "local-only");
        assert!(validate_contract(Some("o/r")).is_ok());
        assert!(validate_contract(Some("https://github.com/o/r/pull/3")).is_ok());
        assert!(validate_contract(Some("https://evil.com/o/r/pull/3")).is_err());
        let mut b = BoardData::default();
        let id = crate::kanban::ops::create_task(&mut b, crate::kanban::ops::NewTask { title: "pr".into(), completion_contract: Some("o/r".into()), ..Default::default() }).unwrap();
        let (snap, contract, _) = prepare(&mut b, &id, None, Some(&json!({"published_pr": "https://github.com/o/r/pull/9"}))).unwrap().unwrap();
        assert_eq!(contract, "https://github.com/o/r/pull/9");
        assert_eq!(b.task(&id).unwrap().completion_contract.as_deref(), Some("https://github.com/o/r/pull/9"), "binds once");
        // Snapshot changed (status moved) → receipt is not recorded.
        b.task_mut(&id).unwrap().status = "blocked".into();
        assert!(!record_acceptance(&mut b, &id, &snap, &json!({"ok": true})));
        b.task_mut(&id).unwrap().status = "ready".into();
        assert!(!record_acceptance(&mut b, &id, &snap, &json!({"ok": false, "classification": "failure", "detail": "ci red", "recovery": "fix"})));
        assert!(b.task(&id).unwrap().last_failure_error.as_deref().unwrap().contains("ci red"));
        assert!(record_acceptance(&mut b, &id, &snap, &json!({"ok": true})));
        assert_eq!(next_link("<http://a/x?page=2>; rel=\"next\", <http://a/x?page=5>; rel=\"last\"").as_deref(), Some("http://a/x?page=2"));
    }
}
