//! GitLab (gitlab.com and self-managed, any `api_base`) REST calls for `forge_read` / `forge_write`.
//! A merge request is "pr" and its `iid` is the "number".

use super::{clip, Api, Write};
use crate::web::http::enc;
use serde_json::{json, Value};

/// `group/subgroup/project`: 2-10 segments of `[A-Za-z0-9_.-]`, none starting with `.` or `-`.
pub fn valid_project(p: &str) -> bool {
    let seg: Vec<&str> = p.split('/').collect();
    (2..=10).contains(&seg.len()) && seg.iter().all(|s| !s.is_empty() && s.len() <= 255 && !s.starts_with(['.', '-']) && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')))
}

fn pid(project: &str) -> String {
    enc(project)
}

fn issue(v: &Value) -> Value {
    json!({"number": v["iid"], "title": v["title"], "state": v["state"], "author": v["author"]["username"], "labels": v["labels"], "assignees": v["assignees"].as_array().map(|a| a.iter().map(|x| x["username"].clone()).collect::<Vec<_>>()),
        "body": clip(v["description"].as_str().unwrap_or(""), 8000), "url": v["web_url"], "comments": v["user_notes_count"], "created_at": v["created_at"], "updated_at": v["updated_at"]})
}

fn mr(v: &Value) -> Value {
    let mut o = issue(v);
    o["head"] = json!({"ref": v["source_branch"], "sha": v["sha"]});
    o["base"] = json!({"ref": v["target_branch"]});
    for k in ["draft", "merge_status", "detailed_merge_status", "has_conflicts", "changes_count", "merged_at"] {
        o[k] = v[k].clone();
    }
    o["pipeline"] = json!({"status": v["head_pipeline"]["status"], "url": v["head_pipeline"]["web_url"]});
    o["is_pull_request"] = json!(true);
    o
}

fn state(s: &str) -> &str {
    match s {
        "open" => "opened",
        "all" => "all",
        o => o,
    }
}

pub fn read(api: &Api, project: &str, kind: &str, number: Option<u64>, st: &str, limit: usize) -> Result<Value, String> {
    let p = pid(project);
    let need = || number.ok_or_else(|| format!("`{kind}` needs a number"));
    match kind {
        "issue" => Ok(issue(&api.get(&format!("/projects/{p}/issues/{}", need()?))?)),
        "pr" => Ok(mr(&api.get(&format!("/projects/{p}/merge_requests/{}", need()?))?)),
        "pr_files" => {
            let v = api.get(&format!("/projects/{p}/merge_requests/{}/changes", need()?))?;
            let mut total = 0usize;
            let files: Vec<Value> = v["changes"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .take(30)
                .map(|f| {
                    let room = (96 * 1024usize).saturating_sub(total);
                    let d = clip(f["diff"].as_str().unwrap_or(""), (16 * 1024).min(room));
                    total += d.len();
                    json!({"path": f["new_path"], "old_path": f["old_path"], "new_file": f["new_file"], "deleted": f["deleted_file"], "renamed": f["renamed_file"], "patch": d})
                })
                .collect();
            Ok(json!({"files": files}))
        }
        "comments" => {
            let n = need()?;
            // Issues and merge requests both have notes; discussions add the inline positions.
            let path = match api.get(&format!("/projects/{p}/merge_requests/{n}/discussions?per_page={limit}")) {
                Ok(v) => v,
                Err(_) => api.get(&format!("/projects/{p}/issues/{n}/discussions?per_page={limit}"))?,
            };
            let mut out = vec![];
            for d in path.as_array().cloned().unwrap_or_default() {
                for note in d["notes"].as_array().cloned().unwrap_or_default() {
                    if note["system"] == json!(true) {
                        continue;
                    }
                    out.push(json!({"id": note["id"], "discussion": d["id"], "author": note["author"]["username"], "body": clip(note["body"].as_str().unwrap_or(""), 4000), "path": note["position"]["new_path"], "line": note["position"]["new_line"], "resolved": note["resolved"], "created_at": note["created_at"]}));
                }
            }
            Ok(json!({"comments": out}))
        }
        "checks" => {
            let v = api.get(&format!("/projects/{p}/merge_requests/{}/pipelines", need()?))?;
            Ok(json!({"pipelines": v.as_array().cloned().unwrap_or_default().iter().take(10).map(|x| json!({"id": x["id"], "status": x["status"], "ref": x["ref"], "sha": x["sha"], "url": x["web_url"]})).collect::<Vec<_>>()}))
        }
        "issues" => {
            let v = api.get(&format!("/projects/{p}/issues?state={}&per_page={limit}", state(st)))?;
            Ok(json!({"issues": v.as_array().cloned().unwrap_or_default().iter().map(issue).collect::<Vec<_>>()}))
        }
        "prs" => {
            let v = api.get(&format!("/projects/{p}/merge_requests?state={}&per_page={limit}", state(st)))?;
            Ok(json!({"pull_requests": v.as_array().cloned().unwrap_or_default().iter().map(mr).collect::<Vec<_>>()}))
        }
        k => Err(format!("unknown kind `{k}`")),
    }
}

fn created(v: &Value) -> Value {
    json!({"ok": true, "number": v["iid"], "id": v["id"], "url": v["web_url"]})
}

pub fn write(api: &Api, project: &str, w: &Write) -> Result<Value, String> {
    let p = pid(project);
    match w.action.as_str() {
        "comment" => {
            let n = w.number.ok_or("`comment` needs a number")?;
            let target = match w.target.as_deref() {
                Some("issue") => "issues",
                Some("pr") => "merge_requests",
                _ => return Err("GitLab needs `target`: \"issue\" or \"pr\" (merge request) for a comment".into()),
            };
            let r = api.send("POST", &format!("/projects/{p}/{target}/{n}/notes"), &json!({"body": w.body}))?;
            Ok(json!({"ok": true, "id": r["id"], "url": null}))
        }
        "review" => {
            let n = w.number.ok_or("`review` needs the merge request number")?;
            if !matches!(w.verdict.as_str(), "comment" | "approve" | "request_changes" | "") {
                return Err(format!("verdict must be comment, approve or request_changes (got `{}`)", w.verdict));
            }
            if w.verdict == "request_changes" && w.body.trim().is_empty() {
                return Err("request_changes needs a body that says what to change".into());
            }
            if w.body.trim().is_empty() && w.comments.is_empty() && w.verdict != "approve" {
                return Err("a review needs a body or inline comments".into());
            }
            let mut posted = vec![];
            if !w.comments.is_empty() {
                let m = api.get(&format!("/projects/{p}/merge_requests/{n}"))?;
                let refs = &m["diff_refs"];
                if refs["head_sha"].is_null() {
                    return Err("the merge request has no diff_refs yet (no diff to comment on)".into());
                }
                for (i, c) in w.comments.iter().enumerate() {
                    let pos = json!({"position_type": "text", "base_sha": refs["base_sha"], "start_sha": refs["start_sha"], "head_sha": refs["head_sha"], "new_path": c.path, "old_path": c.path, "new_line": c.line});
                    match api.send("POST", &format!("/projects/{p}/merge_requests/{n}/discussions"), &json!({"body": c.body, "position": pos})) {
                        Ok(d) => posted.push(d["id"].clone()),
                        Err(e) => return Err(format!("inline comment {} of {} ({}:{}) failed after {} were posted: {e}", i + 1, w.comments.len(), c.path, c.line, posted.len())),
                    }
                }
            }
            if !w.body.trim().is_empty() {
                let body = if w.verdict == "request_changes" { format!("**Changes requested**\n\n{}", w.body) } else { w.body.clone() };
                api.send("POST", &format!("/projects/{p}/merge_requests/{n}/notes"), &json!({"body": body}))?;
            }
            if w.verdict == "approve" {
                api.send("POST", &format!("/projects/{p}/merge_requests/{n}/approve"), &json!({}))?;
            }
            Ok(json!({"ok": true, "inline_comments": posted.len(), "verdict": w.verdict}))
        }
        "create_pr" => {
            let (head, base) = (w.head.as_deref().ok_or("`create_pr` needs `head` (the source branch)")?, w.base.as_deref().ok_or("`create_pr` needs `base` (the target branch)")?);
            let title = if w.draft && !w.title.starts_with("Draft:") { format!("Draft: {}", w.title) } else { w.title.clone() };
            let mut b = json!({"source_branch": head, "target_branch": base, "title": title, "description": w.body});
            if !w.labels.is_empty() {
                b["labels"] = json!(w.labels.join(","));
            }
            Ok(created(&api.send("POST", &format!("/projects/{p}/merge_requests"), &b)?))
        }
        "create_issue" => {
            let mut b = json!({"title": w.title, "description": w.body});
            if !w.labels.is_empty() {
                b["labels"] = json!(w.labels.join(","));
            }
            Ok(created(&api.send("POST", &format!("/projects/{p}/issues"), &b)?))
        }
        "update_issue" => {
            let n = w.number.ok_or("`update_issue` needs a number")?;
            let target = match w.target.as_deref() {
                Some("issue") | None => "issues",
                Some("pr") => "merge_requests",
                Some(t) => return Err(format!("target must be issue or pr (got `{t}`)")),
            };
            let mut b = json!({});
            match w.state.as_deref() {
                Some("open") => b["state_event"] = json!("reopen"),
                Some("closed") => b["state_event"] = json!("close"),
                Some(s) => return Err(format!("state must be open or closed (got `{s}`)")),
                None => {}
            }
            if !w.title.is_empty() {
                b["title"] = json!(w.title);
            }
            if !w.body.is_empty() {
                b["description"] = json!(w.body);
            }
            if !w.labels.is_empty() {
                b["labels"] = json!(w.labels.join(","));
            }
            if b.as_object().is_some_and(|o| o.is_empty()) {
                return Err("nothing to update: give state, title, body or labels".into());
            }
            Ok(created(&api.send("PUT", &format!("/projects/{p}/{target}/{n}"), &b)?))
        }
        a => Err(format!("unknown action `{a}`")),
    }
}
