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
    /// Risk tier (§0-1) of the call, 0 when the request is not tiered. Tier 3 is the hard
    /// floor: surfaces offer no "always" and only the owner may answer it (srv-017/018).
    pub tier: u8,
}

impl ApprovalRequest {
    /// Tier 3: irreversible and outside the sandbox.
    pub fn irreversible(&self) -> bool {
        self.tier >= 3
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    Once,
    /// Same gate + reason allowed for the rest of the session.
    Always,
    /// Durable grant (OpenClaw allow-always / Hermes permanent allowlist).
    Permanent,
    Deny,
}

pub trait Approver: Send + Sync {
    fn approve(&self, req: &ApprovalRequest) -> Approval;
    fn ask(&self, session: &str, question: &str) -> Result<String, String>;
    /// Can a human answer at all? Headless policies cannot (exec `ask_fallback` applies).
    fn interactive(&self) -> bool {
        true
    }
    /// Approvals waiting for an answer (asynchronous approvers only).
    fn pending(&self) -> Vec<PendingItem> {
        vec![]
    }
    /// Answer a pending approval/question by id (`/approve`, chat buttons). False if unknown.
    fn answer(&self, _id: &str, _answer: &str) -> bool {
        false
    }
    /// Did approval `id` end because nobody answered in time (not an explicit deny)?
    fn expired(&self, _id: &str) -> bool {
        false
    }
    /// Structured questions (Hermes `clarify`). Default: one `ask` per question with
    /// the choices rendered as a numbered list, answers parsed back.
    fn clarify(&self, session: &str, questions: &[ClarifyQuestion]) -> ClarifyReply {
        let mut answers = std::collections::BTreeMap::new();
        for q in questions {
            match self.ask(session, &render_question(q)) {
                Ok(a) => {
                    answers.insert(q.qid.clone(), parse_answer(q, &a));
                }
                Err(e) => {
                    let outcome = if e.contains("in time") { "timed_out" } else if e.contains("headless") { "undelivered" } else { "cancelled" };
                    return ClarifyReply { answers, outcome: outcome.into(), notice: Some(e) };
                }
            }
        }
        ClarifyReply { answers, outcome: "submitted".into(), notice: None }
    }
}

/// One `clarify` question as the UI shows it (`choices` already carry the
/// "(Recommended)" label on the first one).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ClarifyQuestion {
    pub qid: String,
    pub question: String,
    #[serde(default)]
    pub choices: Vec<String>,
    #[serde(default)]
    pub multi_select: bool,
}

/// How a clarify wait ended: `answers` maps qid → answer (None = skipped);
/// `outcome` is submitted | cancelled | timed_out | undelivered.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ClarifyReply {
    pub answers: std::collections::BTreeMap<String, Option<serde_json::Value>>,
    pub outcome: String,
    pub notice: Option<String>,
}

pub const RECOMMENDED: &str = "(Recommended)";
pub const SKIP_WORD: &str = "skip";

pub fn strip_recommended(s: &str) -> String {
    let t = s.trim();
    if t.to_lowercase().ends_with(&RECOMMENDED.to_lowercase()) {
        t[..t.len() - RECOMMENDED.len()].trim().to_string()
    } else {
        t.to_string()
    }
}

/// Text form of a question for surfaces without native choice cards.
pub fn render_question(q: &ClarifyQuestion) -> String {
    if q.choices.is_empty() {
        return q.question.clone();
    }
    let mut s = format!("{}\n", q.question);
    for (i, c) in q.choices.iter().enumerate() {
        s.push_str(&format!("  {}. {c}\n", i + 1));
    }
    s.push_str(&format!("  {}. Other (type your answer)\n", q.choices.len() + 1));
    s.push_str(if q.multi_select { "Reply with one or more numbers (e.g. 1,3), or type your own answer; `skip` to skip." } else { "Reply with a number, or type your own answer; `skip` to skip." });
    s
}

/// Map a typed reply onto a question: numbers / labels pick choices, `skip`
/// skips, anything else is a free-text ("Other") answer.
pub fn parse_answer(q: &ClarifyQuestion, raw: &str) -> Option<serde_json::Value> {
    use serde_json::Value;
    let t = raw.trim();
    if t.is_empty() || t.eq_ignore_ascii_case(SKIP_WORD) {
        return None;
    }
    let pick = |tok: &str| -> Option<String> {
        let tok = tok.trim();
        if let Ok(n) = tok.trim_end_matches('.').parse::<usize>() {
            return q.choices.get(n.wrapping_sub(1)).map(|c| strip_recommended(c));
        }
        q.choices.iter().find(|c| strip_recommended(c).eq_ignore_ascii_case(&strip_recommended(tok))).map(|c| strip_recommended(c))
    };
    if q.choices.is_empty() {
        return Some(Value::String(t.into()));
    }
    if q.multi_select {
        if let Ok(Value::Array(a)) = serde_json::from_str::<Value>(t) {
            let v: Vec<Value> = a.iter().filter_map(|x| x.as_str()).map(|x| Value::String(pick(x).unwrap_or_else(|| strip_recommended(x)))).collect();
            return (!v.is_empty()).then_some(Value::Array(v));
        }
        let parts: Vec<Option<String>> = t.split(',').map(pick).collect();
        if parts.iter().all(Option::is_some) {
            return Some(Value::Array(parts.into_iter().flatten().map(Value::String).collect()));
        }
        return Some(Value::Array(vec![Value::String(t.into())]));
    }
    Some(Value::String(pick(t).unwrap_or_else(|| strip_recommended(t))))
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
            // Exec-policy and write approvals need a human (or an explicit allowlist).
            GateKind::Exec | GateKind::Write => self.allow_privilege && self.allow_egress,
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
    fn interactive(&self) -> bool {
        false
    }
}

/// Approvals answered asynchronously over the daemon protocol, with a timeout.
pub struct Pending {
    timeout_ms: std::sync::atomic::AtomicU64,
    state: Mutex<PendingState>,
    cv: Condvar,
    notify: Box<dyn Fn(PendingItem) + Send + Sync>,
}

#[derive(Debug, Clone)]
pub enum PendingItem {
    Approval(ApprovalRequest),
    Question {
        id: String,
        session: String,
        question: String,
        /// Pickable choices (clarify); empty = open-ended.
        choices: Vec<String>,
        multi: bool,
    },
}

#[derive(Default)]
struct PendingState {
    open: HashMap<String, PendingItem>,
    answers: HashMap<String, String>,
    /// Ids whose wait ran out (bounded; read once by the gate).
    expired: std::collections::HashSet<String>,
}

impl Pending {
    pub fn new(timeout: Duration, notify: Box<dyn Fn(PendingItem) + Send + Sync>) -> Self {
        Pending { timeout_ms: std::sync::atomic::AtomicU64::new(timeout.as_millis() as u64), state: Mutex::new(PendingState::default()), cv: Condvar::new(), notify }
    }

    /// `approvals.timeout_secs` once the config is loaded.
    pub fn set_timeout(&self, t: Duration) {
        self.timeout_ms.store(t.as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
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
        let timeout = Duration::from_millis(self.timeout_ms.load(std::sync::atomic::Ordering::Relaxed));
        let (mut s, _) = self.cv.wait_timeout_while(s, timeout, |s| !s.answers.contains_key(&id)).unwrap();
        s.open.remove(&id);
        let a = s.answers.remove(&id);
        if a.is_none() {
            if s.expired.len() > 1024 {
                s.expired.clear();
            }
            s.expired.insert(id);
        }
        a
    }

    /// The configured wait (`approvals.timeout_secs`).
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.load(std::sync::atomic::Ordering::Relaxed))
    }
}

impl Approver for Pending {
    fn approve(&self, req: &ApprovalRequest) -> Approval {
        let Some(answer) = self.wait(req.id.clone(), PendingItem::Approval(req.clone())) else { return Approval::Deny };
        match ark_security::approvals::parse_answer(&answer) {
            ("once", _) => Approval::Once,
            ("session", _) => Approval::Always,
            ("permanent", _) => Approval::Permanent,
            (_, reason) => {
                if let Some(r) = reason {
                    ark_security::approvals::set_deny_reason(&req.id, &r);
                }
                Approval::Deny
            }
        }
    }
    fn pending(&self) -> Vec<PendingItem> {
        self.list()
    }
    fn answer(&self, id: &str, answer: &str) -> bool {
        Pending::answer(self, id, answer)
    }
    fn expired(&self, id: &str) -> bool {
        self.state.lock().unwrap().expired.remove(id)
    }
    fn ask(&self, session: &str, question: &str) -> Result<String, String> {
        let id = crate::util::new_id();
        self.wait(id.clone(), PendingItem::Question { id, session: session.into(), question: question.into(), choices: vec![], multi: false })
            .ok_or_else(|| "the user did not answer in time; continue with your best judgement".into())
    }
    /// One pending question per clarify entry, in order, each with its choices so
    /// surfaces render pickable rows (web UI, channel buttons).
    fn clarify(&self, session: &str, questions: &[ClarifyQuestion]) -> ClarifyReply {
        let mut answers = std::collections::BTreeMap::new();
        for q in questions {
            let id = crate::util::new_id();
            match self.wait(id.clone(), PendingItem::Question { id, session: session.into(), question: q.question.clone(), choices: q.choices.clone(), multi: q.multi_select }) {
                Some(a) if a == "\u{0}cancel" => return ClarifyReply { answers, outcome: "cancelled".into(), notice: Some("the user cancelled the questions".into()) },
                Some(a) => {
                    answers.insert(q.qid.clone(), parse_answer(q, &a));
                }
                None => return ClarifyReply { answers, outcome: "timed_out".into(), notice: Some("the user did not answer in time".into()) },
            }
        }
        ClarifyReply { answers, outcome: "submitted".into(), notice: None }
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
        ApprovalRequest { id: id.into(), tool_use_id: String::new(), session: "s".into(), tool: "shell".into(), summary: "sudo x".into(), input: serde_json::Value::Null, gate: GateKind::Privilege, reason: "sudo".into(), tier: 0 }
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
        assert!(p.expired("b"), "a timeout is told apart from an explicit deny");
        assert!(!p.expired("b"), "read once");
        assert!(!p.expired("a"), "an answered approval did not expire");
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

#[cfg(test)]
mod clarify_tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;

    fn q(choices: &[&str], multi: bool) -> ClarifyQuestion {
        ClarifyQuestion { qid: "q0".into(), question: "Which DB?".into(), choices: choices.iter().map(|s| s.to_string()).collect(), multi_select: multi }
    }

    #[test]
    fn answers_map_onto_choices() {
        let one = q(&["Postgres (Recommended)", "SQLite"], false);
        assert_eq!(parse_answer(&one, "1"), Some(json!("Postgres")));
        assert_eq!(parse_answer(&one, "sqlite"), Some(json!("SQLite")));
        assert_eq!(parse_answer(&one, "MySQL please"), Some(json!("MySQL please")), "Other = free text");
        assert_eq!(parse_answer(&one, "skip"), None);
        let many = q(&["a", "b", "c"], true);
        assert_eq!(parse_answer(&many, "1, 3"), Some(json!(["a", "c"])));
        assert_eq!(parse_answer(&many, "[\"b\"]"), Some(json!(["b"])));
        assert_eq!(parse_answer(&many, "none of these"), Some(json!(["none of these"])));
        assert_eq!(parse_answer(&q(&[], false), "  free  "), Some(json!("free")));
        let r = render_question(&one);
        assert!(r.contains("1. Postgres (Recommended)") && r.contains("3. Other"));
        assert_eq!(strip_recommended("x (recommended)"), "x");
    }

    #[test]
    fn pending_clarify_publishes_choices_and_times_out() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        let p = Arc::new(Pending::new(Duration::from_millis(300), Box::new(move |i| s2.lock().unwrap().push(i))));
        let p2 = p.clone();
        let qs = vec![q(&["A", "B"], false), ClarifyQuestion { qid: "q1".into(), question: "Name?".into(), choices: vec![], multi_select: false }];
        let qs2 = qs.clone();
        let h = std::thread::spawn(move || p2.clarify("s", &qs2));
        let wait_item = |n: usize| loop {
            if let Some(PendingItem::Question { id, choices, .. }) = seen.lock().unwrap().get(n).cloned() {
                break (id, choices);
            }
            std::thread::sleep(Duration::from_millis(2));
        };
        let (id, choices) = wait_item(0);
        assert_eq!(choices, ["A", "B"]);
        assert!(Approver::answer(p.as_ref(), &id, "2"));
        let (id, _) = wait_item(1);
        assert!(Approver::answer(p.as_ref(), &id, "Ada"));
        let r = h.join().unwrap();
        assert_eq!(r.outcome, "submitted");
        assert_eq!(r.answers["q0"], Some(json!("B")));
        assert_eq!(r.answers["q1"], Some(json!("Ada")));
        let r = p.clarify("s", &qs);
        assert_eq!(r.outcome, "timed_out");
        assert!(r.answers.is_empty());
        // Headless policy: undelivered.
        let r = Policy { allow_privilege: false, allow_egress: false }.clarify("s", &qs);
        assert_eq!(r.outcome, "undelivered");
    }
}
