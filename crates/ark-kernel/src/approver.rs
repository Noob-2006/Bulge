//! Who answers gate questions and `ask_user`. Fail-closed: no answer = deny.

use crate::gate::GateKind;
use std::collections::HashMap;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalRequest {
    pub id: String,
    /// The tool call being judged (empty for nested code-mode calls).
    pub tool_use_id: String,
    pub session: String,
    pub tool: String,
    pub summary: String,
    /// The call's input, secrets redacted (lets UIs render diffs of edits).
    pub input: serde_json::Value,
    pub gate: GateKind,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    Once,
    /// Same gate + reason allowed for the rest of the session.
    Always,
    Deny,
}

pub trait Approver: Send + Sync {
    fn approve(&self, req: &ApprovalRequest) -> Approval;
    fn ask(&self, session: &str, question: &str) -> Result<String, String>;
}

/// Headless policy: fixed answers, no human.
pub struct Policy {
    pub allow_privilege: bool,
    pub allow_egress: bool,
}

impl Approver for Policy {
    fn approve(&self, req: &ApprovalRequest) -> Approval {
        let ok = match req.gate {
            GateKind::Privilege => self.allow_privilege,
            GateKind::Egress => self.allow_egress,
        };
        if ok {
            Approval::Once
        } else {
            Approval::Deny
        }
    }
    fn ask(&self, _: &str, _: &str) -> Result<String, String> {
        Err("no human is attached to this session (headless). Proceed with your best judgement and state your assumptions.".into())
    }
}

/// Approvals answered asynchronously over the daemon protocol, with a timeout.
pub struct Pending {
    timeout: Duration,
    state: Mutex<PendingState>,
    cv: Condvar,
    notify: Box<dyn Fn(PendingItem) + Send + Sync>,
}

#[derive(Debug, Clone)]
pub enum PendingItem {
    Approval(ApprovalRequest),
    Question { id: String, session: String, question: String },
}

#[derive(Default)]
struct PendingState {
    open: HashMap<String, PendingItem>,
    answers: HashMap<String, String>,
}

impl Pending {
    pub fn new(timeout: Duration, notify: Box<dyn Fn(PendingItem) + Send + Sync>) -> Self {
        Pending { timeout, state: Mutex::new(PendingState::default()), cv: Condvar::new(), notify }
    }

    pub fn list(&self) -> Vec<PendingItem> {
        self.state.lock().unwrap().open.values().cloned().collect()
    }

    /// Returns false when the id is unknown (already answered / timed out).
    pub fn answer(&self, id: &str, answer: &str) -> bool {
        let mut s = self.state.lock().unwrap();
        if s.open.remove(id).is_none() {
            return false;
        }
        s.answers.insert(id.to_string(), answer.to_string());
        self.cv.notify_all();
        true
    }

    fn wait(&self, id: String, item: PendingItem) -> Option<String> {
        {
            let mut s = self.state.lock().unwrap();
            s.open.insert(id.clone(), item.clone());
        }
        (self.notify)(item);
        let s = self.state.lock().unwrap();
        let (mut s, _) = self.cv.wait_timeout_while(s, self.timeout, |s| !s.answers.contains_key(&id)).unwrap();
        s.open.remove(&id);
        s.answers.remove(&id)
    }
}

impl Approver for Pending {
    fn approve(&self, req: &ApprovalRequest) -> Approval {
        match self.wait(req.id.clone(), PendingItem::Approval(req.clone())).as_deref() {
            Some("once") | Some("allow") | Some("yes") => Approval::Once,
            Some("always") => Approval::Always,
            _ => Approval::Deny,
        }
    }
    fn ask(&self, session: &str, question: &str) -> Result<String, String> {
        let id = crate::util::new_id();
        self.wait(id.clone(), PendingItem::Question { id, session: session.into(), question: question.into() })
            .ok_or_else(|| "the user did not answer in time; continue with your best judgement".into())
    }
}

/// Remembers "always" answers per session.
#[derive(Default)]
pub struct Remembered(Mutex<HashMap<String, Vec<(GateKind, String)>>>);

impl Remembered {
    pub fn contains(&self, session: &str, gate: GateKind, reason: &str) -> bool {
        self.0.lock().unwrap().get(session).is_some_and(|v| v.iter().any(|(g, r)| *g == gate && r == reason))
    }
    pub fn insert(&self, session: &str, gate: GateKind, reason: &str) {
        self.0.lock().unwrap().entry(session.into()).or_default().push((gate, reason.into()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn req(id: &str) -> ApprovalRequest {
        ApprovalRequest { id: id.into(), tool_use_id: String::new(), session: "s".into(), tool: "shell".into(), summary: "sudo x".into(), input: serde_json::Value::Null, gate: GateKind::Privilege, reason: "sudo".into() }
    }

    #[test]
    fn policy_is_fixed_and_cannot_ask() {
        let p = Policy { allow_privilege: false, allow_egress: true };
        assert_eq!(p.approve(&req("1")), Approval::Deny);
        let mut r = req("2");
        r.gate = GateKind::Egress;
        assert_eq!(p.approve(&r), Approval::Once);
        assert!(p.ask("s", "?").is_err());
    }

    #[test]
    fn pending_answer_and_timeout() {
        let p = Arc::new(Pending::new(Duration::from_millis(200), Box::new(|_| {})));
        let p2 = p.clone();
        let h = std::thread::spawn(move || p2.approve(&req("a")));
        // Wait until it is listed, then answer.
        for _ in 0..100 {
            if !p.list().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(p.answer("a", "always"));
        assert_eq!(h.join().unwrap(), Approval::Always);
        assert!(!p.answer("a", "once"), "already answered");
        // Nobody answers → deny after timeout, and the item is gone.
        assert_eq!(p.approve(&req("b")), Approval::Deny);
        assert!(p.list().is_empty());
        assert!(p.ask("s", "q").is_err());
        // Garbage answer is a deny.
        let p3 = p.clone();
        let h = std::thread::spawn(move || p3.approve(&req("c")));
        while p.list().is_empty() {
            std::thread::sleep(Duration::from_millis(2));
        }
        p.answer("c", "maybe");
        assert_eq!(h.join().unwrap(), Approval::Deny);
    }

    #[test]
    fn remembered_is_per_session_and_reason() {
        let r = Remembered::default();
        r.insert("s1", GateKind::Egress, "x");
        assert!(r.contains("s1", GateKind::Egress, "x"));
        assert!(!r.contains("s2", GateKind::Egress, "x"));
        assert!(!r.contains("s1", GateKind::Privilege, "x"));
        assert!(!r.contains("s1", GateKind::Egress, "y"));
    }
}
