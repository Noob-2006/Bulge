//! GitHub (github.com and Enterprise Server) REST calls for `forge_read` / `forge_write`.

use super::{clip, Api, Write};
use serde_json::{json, Value};

pub fn valid_repo(r: &str) -> bool {
    crate::web::github::valid_repository(r)
}

fn user(v: &Value) -> Value {
    v["user"]["login"].clone()
}

fn labels(v: &Value) -> Vec<Value> {
    v["labels"].as_array().map(|a| a.iter().map(|l| l["name"].clone()).collect()).unwrap_or_default()
}

fn issue(v: &Value) -> Value {
    json!({"number": v["number"], "title": v["title"], "state": v["state"], "author": user(v), "labels": labels(v), "assignees": v["assignees"].as_array().map(|a| a.iter().map(|x| x["login"].clone()).collect::<Vec<_>>()),
        "body": clip(v["body"].as_str().unwrap_or(""), 8000), "url": v["html_url"], "comments": v["comments"], "created_at": v["created_at"], "updated_at": v["updated_at"], "is_pull_request": v.get("pull_request").is_some()})
}

fn pull(v: &Value) -> Value {
    let mut o = issue(v);
    o["head"] = json!({"ref": v["head"]["ref"], "sha": v["head"]["sha"], "repo": v["head"]["repo"]["full_name"]});
    o["base"] = json!({"ref": v["base"]["ref"], "sha": v["base"]["sha"]});
    for k in ["draft", "merged", "mergeable", "mergeable_state", "additions", "deletions", "changed_files", "review_comments", "commits"] {
        o[k] = v[k].clone();
    }
    o["is_pull_request"] = json!(true);
    o
}

pub fn read(api: &Api, repo: &str, kind: &str, number: Option<u64>, state: &str, limit: usize) -> Result<Value, String> {
    let need = || number.ok_or_else(|| format!("`{kind}` needs a number"));
    match kind {
        "issue" => Ok(issue(&api.get(&format!("/repos/{repo}/issues/{}", need()?))?)),
        "pr" => Ok(pull(&api.get(&format!("/repos/{repo}/pulls/{}", need()?))?)),
        "pr_files" => {
            let v = api.get(&format!("/repos/{repo}/pulls/{}/files?per_page=30", need()?))?;
            let mut total = 0usize;
            let files: Vec<Value> = v
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|f| {
                    let patch = f["patch"].as_str().unwrap_or("");
                    let room = (96 * 1024usize).saturating_sub(total);
                    let p = clip(patch, (16 * 1024).min(room));
                    total += p.len();
                    json!({"path": f["filename"], "status": f["status"], "additions": f["additions"], "deletions": f["deletions"], "patch": p})
                })
                .collect();
            Ok(json!({"files": files}))
        }
        "comments" => {
            let n = need()?;
            let issue_c = api.get(&format!("/repos/{repo}/issues/{n}/comments?per_page={limit}"))?;
            let mut out: Vec<Value> = issue_c.as_array().cloned().unwrap_or_default().iter().map(|c| json!({"id": c["id"], "author": user(c), "body": clip(c["body"].as_str().unwrap_or(""), 4000), "created_at": c["created_at"], "url": c["html_url"]})).collect();
            // Review comments exist only for pull requests; an issue answers 404.
            if let Ok(rc) = api.get(&format!("/repos/{repo}/pulls/{n}/comments?per_page={limit}")) {
                out.extend(rc.as_array().cloned().unwrap_or_default().iter().map(|c| json!({"id": c["id"], "author": user(c), "body": clip(c["body"].as_str().unwrap_or(""), 4000), "path": c["path"], "line": c["line"], "diff_hunk": clip(c["diff_hunk"].as_str().unwrap_or(""), 800), "created_at": c["created_at"], "url": c["html_url"]})));
            }
            Ok(json!({"comments": out}))
        }
        "checks" => {
            let pr = api.get(&format!("/repos/{repo}/pulls/{}", need()?))?;
            let sha = pr["head"]["sha"].as_str().ok_or("pull request has no head sha")?.to_string();
            let runs = api.get(&format!("/repos/{repo}/commits/{sha}/check-runs?per_page=50"))?;
            let status = api.get(&format!("/repos/{repo}/commits/{sha}/status"))?;
            Ok(json!({"sha": sha,
                "check_runs": runs["check_runs"].as_array().map(|a| a.iter().map(|r| json!({"name": r["name"], "status": r["status"], "conclusion": r["conclusion"], "url": r["html_url"], "summary": clip(r["output"]["summary"].as_str().unwrap_or(""), 600)})).collect::<Vec<_>>()),
                "combined_status": status["state"]}))
        }
        "issues" => {
            let v = api.get(&format!("/repos/{repo}/issues?state={state}&per_page={limit}"))?;
            Ok(json!({"issues": v.as_array().cloned().unwrap_or_default().iter().filter(|i| i.get("pull_request").is_none()).map(issue).collect::<Vec<_>>()}))
        }
        "prs" => {
            let v = api.get(&format!("/repos/{repo}/pulls?state={state}&per_page={limit}"))?;
            Ok(json!({"pull_requests": v.as_array().cloned().unwrap_or_default().iter().map(pull).collect::<Vec<_>>()}))
        }
        k => Err(format!("unknown kind `{k}`")),
    }
}

fn created(v: &Value) -> Value {
    json!({"ok": true, "number": v["number"], "id": v["id"], "url": v["html_url"]})
}

pub fn write(api: &Api, repo: &str, w: &Write) -> Result<Value, String> {
    match w.action.as_str() {
        "comment" => {
            let n = w.number.ok_or("`comment` needs a number (issue or pull request)")?;
            // Pull requests are issues for the purpose of conversation comments.
            Ok(created(&api.send("POST", &format!("/repos/{repo}/issues/{n}/comments"), &json!({"body": w.body}))?))
        }
        "review" => {
            let n = w.number.ok_or("`review` needs the pull request number")?;
            let event = match w.verdict.as_str() {
                "approve" => "APPROVE",
                "request_changes" => "REQUEST_CHANGES",
                "comment" | "" => "COMMENT",
                v => return Err(format!("verdict must be comment, approve or request_changes (got `{v}`)")),
            };
            if event == "REQUEST_CHANGES" && w.body.trim().is_empty() {
                return Err("request_changes needs a body that says what to change".into());
            }
            if event == "COMMENT" && w.body.trim().is_empty() && w.comments.is_empty() {
                return Err("a comment review needs a body or inline comments".into());
            }
            let mut body = json!({"event": event});
            if !w.body.is_empty() {
                body["body"] = json!(w.body);
            }
            if !w.comments.is_empty() {
                body["comments"] = json!(w.comments.iter().map(|c| json!({"path": c.path, "line": c.line, "side": c.side.as_deref().unwrap_or("RIGHT"), "body": c.body})).collect::<Vec<_>>());
            }
            if let Some(sha) = &w.commit_id {
                body["commit_id"] = json!(sha);
            }
            Ok(created(&api.send("POST", &format!("/repos/{repo}/pulls/{n}/reviews"), &body)?))
        }
        "create_pr" => {
            let (head, base) = (w.head.as_deref().ok_or("`create_pr` needs `head` (the branch with the changes; `owner:branch` for a fork)")?, w.base.as_deref().ok_or("`create_pr` needs `base`")?);
            let mut b = json!({"title": w.title, "head": head, "base": base, "body": w.body, "draft": w.draft});
            if let Some(m) = w.maintainer_can_modify {
                b["maintainer_can_modify"] = json!(m);
            }
            let r = api.send("POST", &format!("/repos/{repo}/pulls"), &b)?;
            if !w.labels.is_empty() {
                // Labels are set through the issues endpoint; a failure here must not hide the PR.
                let _ = api.send("POST", &format!("/repos/{repo}/issues/{}/labels", r["number"]), &json!({"labels": w.labels}));
            }
            Ok(created(&r))
        }
        "create_issue" => {
            let mut b = json!({"title": w.title, "body": w.body});
            if !w.labels.is_empty() {
                b["labels"] = json!(w.labels);
            }
            Ok(created(&api.send("POST", &format!("/repos/{repo}/issues"), &b)?))
        }
        "update_issue" => {
            let n = w.number.ok_or("`update_issue` needs a number")?;
            let mut b = json!({});
            match w.state.as_deref() {
                Some("open") => b["state"] = json!("open"),
                Some("closed") => b["state"] = json!("closed"),
                Some(s) => return Err(format!("state must be open or closed (got `{s}`)")),
                None => {}
            }
            if !w.title.is_empty() {
                b["title"] = json!(w.title);
            }
            if !w.body.is_empty() {
                b["body"] = json!(w.body);
            }
            if !w.labels.is_empty() {
                b["labels"] = json!(w.labels);
            }
            if b.as_object().is_some_and(|o| o.is_empty()) {
                return Err("nothing to update: give state, title, body or labels".into());
            }
            Ok(created(&api.send("PATCH", &format!("/repos/{repo}/issues/{n}"), &b)?))
        }
        a => Err(format!("unknown action `{a}`")),
    }
}
