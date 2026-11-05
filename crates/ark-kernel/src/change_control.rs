//! Change control through the on-prem ticketing system (`[approvals.dual_control.change_control]`).
//!
//! When a dual-controlled action is requested, a change request is opened in ServiceNow
//! (`change_request` table) or Jira Server / Data Center (an issue in the change project), and
//! a poller watches it: an approved ticket counts as one vote (principal
//! `change:<system>:<number>`, i.e. the change advisory board), a rejected one denies the
//! action. The ticket never replaces the quorum: with `min_approvals = 2`, the CAB plus one
//! person approves; with 1, the CAB alone. Every step is in the audit stream
//! (`change.request`, then the vote recorded by [`crate::approver::answer_as`]).
//!
//! The poller stops when the request is decided by anyone, expires, or the ticket is closed.

use crate::approver::{answer_as, Approver};
use ark_security::audit::{record, Actor, Event};
use ark_security::dual_control::ChangeControlConfig;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub struct Ticket {
    pub system: String,
    /// Human number (`CHG0031337`, `CHG-42`).
    pub number: String,
    /// Record id to poll (ServiceNow `sys_id`; the Jira key).
    pub id: String,
}

impl Ticket {
    /// The principal its decision is recorded under.
    pub fn principal(&self) -> String {
        format!("change:{}:{}", self.system, self.number)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum State {
    Pending,
    Approved,
    Rejected,
}

fn agent() -> ureq::Agent {
    ark_net::http::builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(20)))
        .build()
        .into()
}

fn auth(c: &ChangeControlConfig, subst: &dyn Fn(&str) -> String) -> Result<String, String> {
    let token = subst(&c.token);
    if token.contains("{{secret:") {
        return Err("change_control token: the secret does not resolve".into());
    }
    Ok(if c.user.is_empty() {
        format!("Bearer {token}")
    } else {
        format!(
            "Basic {}",
            ark_net::crypto::b64(format!("{}:{token}", c.user).as_bytes())
        )
    })
}

fn call(
    c: &ChangeControlConfig,
    subst: &dyn Fn(&str) -> String,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<Value, String> {
    let url = format!("{}{path}", c.url.trim_end_matches('/'));
    let a = auth(c, subst)?;
    let resp = match body {
        Some(b) => agent()
            .post(&url)
            .header("Authorization", &a)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .send(b.to_string()),
        None if method == "GET" => agent()
            .get(&url)
            .header("Authorization", &a)
            .header("Accept", "application/json")
            .call(),
        None => return Err("bad request".into()),
    };
    let mut resp = resp.map_err(|e| format!("{}: {e}", c.system))?;
    let st = resp.status().as_u16();
    let text = resp
        .body_mut()
        .with_config()
        .limit(1 << 20)
        .read_to_string()
        .unwrap_or_default();
    if !(200..300).contains(&st) {
        return Err(format!("{}: HTTP {st}", c.system));
    }
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", c.system))
}

/// Open the change request.
pub fn create(
    c: &ChangeControlConfig,
    subst: &dyn Fn(&str) -> String,
    summary: &str,
    description: &str,
) -> Result<Ticket, String> {
    match c.system.as_str() {
        "jira" => {
            let v = call(
                c,
                subst,
                "POST",
                "/rest/api/2/issue",
                Some(
                    json!({"fields": {"project": {"key": c.project}, "summary": summary, "description": description, "issuetype": {"name": c.issue_type}}}),
                ),
            )?;
            let key = v["key"]
                .as_str()
                .ok_or("jira: no issue key in the reply")?
                .to_string();
            Ok(Ticket {
                system: "jira".into(),
                number: key.clone(),
                id: key,
            })
        }
        _ => {
            let v = call(
                c,
                subst,
                "POST",
                "/api/now/table/change_request",
                Some(
                    json!({"short_description": summary, "description": description, "type": "normal"}),
                ),
            )?;
            let r = &v["result"];
            let (Some(id), Some(n)) = (r["sys_id"].as_str(), r["number"].as_str()) else {
                return Err("servicenow: no sys_id / number in the reply".into());
            };
            Ok(Ticket {
                system: "servicenow".into(),
                number: n.into(),
                id: id.into(),
            })
        }
    }
}

/// Where the ticket stands.
pub fn state(
    c: &ChangeControlConfig,
    subst: &dyn Fn(&str) -> String,
    t: &Ticket,
) -> Result<State, String> {
    let has = |l: &[String], s: &str| l.iter().any(|x| x.eq_ignore_ascii_case(s));
    match t.system.as_str() {
        "jira" => {
            let v = call(
                c,
                subst,
                "GET",
                &format!(
                    "/rest/api/2/issue/{}?fields=status",
                    ark_net::urlencode(&t.id)
                ),
                None,
            )?;
            let s = v["fields"]["status"]["name"].as_str().unwrap_or("");
            Ok(if has(&c.approved, s) {
                State::Approved
            } else if has(&c.rejected, s) {
                State::Rejected
            } else {
                State::Pending
            })
        }
        _ => {
            let v = call(
                c,
                subst,
                "GET",
                &format!(
                    "/api/now/table/change_request/{}?sysparm_fields=approval,state,number",
                    ark_net::urlencode(&t.id)
                ),
                None,
            )?;
            let a = v["result"]["approval"].as_str().unwrap_or("");
            let approved = if c.approved.is_empty() {
                a == "approved"
            } else {
                has(&c.approved, a)
            };
            let rejected = if c.rejected.is_empty() {
                a == "rejected"
            } else {
                has(&c.rejected, a)
            };
            Ok(if approved {
                State::Approved
            } else if rejected {
                State::Rejected
            } else {
                State::Pending
            })
        }
    }
}

/// Poll `t` until approval `id` is decided (by the ticket or anyone else) or it expires.
pub fn watch(
    approver: Arc<dyn Approver>,
    data: PathBuf,
    c: ChangeControlConfig,
    subst: Arc<dyn Fn(&str) -> String + Send + Sync>,
    t: Ticket,
    id: String,
) {
    let every = Duration::from_millis((c.poll_secs.max(1) * 1000).min(3_600_000));
    let _ = std::thread::Builder::new()
        .name(format!("change-{}", t.number))
        .spawn(move || {
            let mut errors = 0u32;
            while let Some(q) = crate::approver::quorum(&id) {
                if ark_security::audit::now_ms() >= q.expires_ms {
                    return;
                }
                match state(&c, &*subst, &t) {
                    Ok(State::Pending) => errors = 0,
                    Ok(s) => {
                        let who = Actor::new("change", &format!("{}:{}", t.system, t.number))
                            .with_role("cab");
                        let _ = answer_as(
                            &*approver,
                            &data,
                            &id,
                            if s == State::Approved {
                                "once"
                            } else {
                                "deny rejected in the change ticket"
                            },
                            &who,
                            "change_control",
                        );
                        return;
                    }
                    Err(e) => {
                        errors += 1;
                        // Reported once per streak; the poll keeps going until the request expires.
                        if errors == 1 {
                            record(
                                &data,
                                Event::new("change.poll", Actor::system(), &t.principal(), "error")
                                    .detail(json!({"approval": id, "error": e})),
                            );
                        }
                    }
                }
                std::thread::sleep(every);
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::sync::Mutex;

    /// A fake ITSM: answers POST with a new record and GET with the next state in `states`.
    type Seen = Arc<Mutex<Vec<(String, String)>>>;

    fn fake_itsm(states: Vec<&'static str>, jira: bool) -> (String, Seen) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(vec![]));
        let s2 = seen.clone();
        std::thread::spawn(move || {
            let mut states = states.into_iter();
            let mut last = "";
            for s in l.incoming().flatten() {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut first = String::new();
                r.read_line(&mut first).unwrap();
                let mut len = 0usize;
                let mut authz = String::new();
                loop {
                    let mut h = String::new();
                    if r.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                        break;
                    }
                    let low = h.to_ascii_lowercase();
                    if let Some(v) = low.strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap();
                    }
                    if low.starts_with("authorization:") {
                        authz = h.trim().to_string();
                    }
                }
                let mut body = vec![0u8; len];
                r.read_exact(&mut body).unwrap();
                s2.lock().unwrap().push((
                    first.trim().to_string(),
                    format!("{authz}\n{}", String::from_utf8_lossy(&body)),
                ));
                let reply = if first.starts_with("POST") {
                    if jira {
                        json!({"key": "CHG-7"})
                    } else {
                        json!({"result": {"sys_id": "abc123", "number": "CHG0040001"}})
                    }
                } else {
                    last = states.next().unwrap_or(last);
                    if jira {
                        json!({"fields": {"status": {"name": last}}})
                    } else {
                        json!({"result": {"approval": last, "number": "CHG0040001"}})
                    }
                }
                .to_string();
                let mut s = s;
                let _ = write!(s, "HTTP/1.1 201 Created\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}", reply.len());
            }
        });
        (url, seen)
    }

    #[test]
    fn servicenow_change_requests_are_opened_and_read() {
        let (url, seen) = fake_itsm(vec!["requested", "approved"], false);
        let c = ChangeControlConfig {
            url,
            user: "ark".into(),
            token: "{{secret:SN}}".into(),
            ..Default::default()
        };
        let subst = |s: &str| s.replace("{{secret:SN}}", "pw");
        let t = create(
            &c,
            &subst,
            "ark: sudo reboot on web01",
            "requested by sso:ann",
        )
        .unwrap();
        assert_eq!(
            (t.number.as_str(), t.id.as_str(), t.principal().as_str()),
            ("CHG0040001", "abc123", "change:servicenow:CHG0040001")
        );
        assert_eq!(state(&c, &subst, &t).unwrap(), State::Pending);
        assert_eq!(state(&c, &subst, &t).unwrap(), State::Approved);
        let seen = seen.lock().unwrap();
        assert!(
            seen[0].0.starts_with("POST /api/now/table/change_request ")
                && seen[0].1.contains("Basic YXJrOnB3")
                && seen[0].1.contains("sudo reboot"),
            "{seen:?}"
        );
        assert!(
            seen[1]
                .0
                .starts_with("GET /api/now/table/change_request/abc123?sysparm_fields=approval"),
            "{seen:?}"
        );
        let bad = ChangeControlConfig {
            token: "{{secret:NOPE}}".into(),
            ..c
        };
        assert!(create(&bad, &|s: &str| s.to_string(), "x", "y")
            .unwrap_err()
            .contains("secret"));
    }

    #[test]
    fn jira_statuses_decide() {
        let (url, _seen) = fake_itsm(vec!["Open", "Declined"], true);
        let c = ChangeControlConfig {
            system: "jira".into(),
            url,
            token: "pat".into(),
            project: "CHG".into(),
            approved: vec!["Approved".into()],
            rejected: vec!["Declined".into()],
            ..Default::default()
        };
        let t = create(&c, &|s: &str| s.to_string(), "x", "y").unwrap();
        assert_eq!(t.principal(), "change:jira:CHG-7");
        assert_eq!(
            state(&c, &|s: &str| s.to_string(), &t).unwrap(),
            State::Pending
        );
        assert_eq!(
            state(&c, &|s: &str| s.to_string(), &t).unwrap(),
            State::Rejected
        );
    }

    /// End to end: the ticket's approval is the CAB's vote; with one human approval the
    /// dual-controlled request completes, and the ticket number is in the audit stream.
    #[test]
    fn an_approved_ticket_counts_as_one_approver() {
        use crate::approver::{Answered, Pending};
        let tmp = ark_core::tmp::TempDir::new("ark-change");
        let data = tmp.path().to_path_buf();
        let (url, _seen) = fake_itsm(vec!["requested", "approved"], false);
        let cc = ChangeControlConfig {
            url,
            token: "t".into(),
            poll_secs: 1,
            ..Default::default()
        };
        let dc = ark_security::dual_control::DualControlConfig {
            enabled: true,
            tools: vec!["sh".into()],
            change_control: Some(cc.clone()),
            ..Default::default()
        };
        let p: Arc<Pending> = Arc::new(Pending::new(Duration::from_secs(10), Box::new(|_| {})));
        let subst: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(|s: &str| s.to_string());
        let t = create(&cc, &*subst, "x", "y").unwrap();
        let mut q = ark_security::dual_control::Quorum::new(
            &dc,
            "cc-1",
            "s1",
            "sh",
            "sso:req",
            ark_security::audit::now_ms(),
        );
        q.change_ticket = Some(t.principal());
        crate::approver::open_quorum(q);
        let req = crate::approver::ApprovalRequest {
            id: "cc-1".into(),
            tool_use_id: String::new(),
            session: "s1".into(),
            tool: "sh".into(),
            summary: String::new(),
            input: Value::Null,
            gate: crate::gate::GateKind::Privilege,
            reason: "x".into(),
            tier: 2,
        };
        let p2 = p.clone();
        let h = std::thread::spawn(move || p2.approve_within(&req, Duration::from_secs(10)));
        while p.list().is_empty() {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            answer_as(
                &*p,
                &data,
                "cc-1",
                "once",
                &Actor::new("sso", "ann").with_role("admin"),
                "app"
            )
            .unwrap(),
            Answered::Counted { have: 1, need: 2 }
        );
        watch(p.clone(), data.clone(), cc, subst, t, "cc-1".into());
        assert_eq!(h.join().unwrap(), crate::approver::Approval::Once);
        let ans = ark_security::audit::all(&data)
            .into_iter()
            .find(|r| r["kind"] == "approval.answer")
            .unwrap();
        assert_eq!(
            ans["detail"]["approvals"],
            json!(["sso:ann", "change:servicenow:CHG0040001"])
        );
        assert_eq!(ans["detail"]["via"], "change_control");
    }
}
