//! Task notifications: terminal transitions append a sequenced notification; each
//! subscription keeps a durable cursor. Delivery (seagentd's dispatcher tick) wakes the
//! subscribed seagent session and/or hands chat targets to a host-registered sink;
//! `pull` subscriptions are read with `workboard_notify_events` / `_advance`.

use super::store::{BoardData, Notification, Subscription};
use super::{now, store};
use crate::util::random_hex;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::{Arc, RwLock};

pub const DELIVERY_MODES: &[&str] = &["notify", "notify+wake", "wake", "pull"];
/// Default kinds when a subscription lists none.
const DEFAULT_KINDS: &[&str] = &["completed", "failed", "blocked"];

/// Append a notification for `task` (kinds: completed, failed, blocked, review, stale).
pub fn push(b: &mut BoardData, task: &str, kind: &str, message: &str, run_id: Option<u64>, artifacts: Vec<String>) -> u64 {
    b.next_notification += 1;
    let seq = b.next_notification;
    let session_key = b.task(task).and_then(|t| t.session_key.clone());
    b.notifications.push(Notification { seq, task_id: task.into(), kind: kind.into(), message: message.into(), run_id, session_key, artifacts, created_at: now() });
    // Bounded history: keep the newest 2000.
    let n = b.notifications.len();
    if n > 2000 {
        b.notifications.drain(..n - 2000);
    }
    seq
}

/// A new task inherits the delivery targets of its parents / creator.
pub fn inherit_subscriptions(b: &mut BoardData, task: &str, sources: &[String]) {
    let inherited: Vec<Subscription> = b.subscriptions.iter().filter(|s| s.task_id.as_deref().is_some_and(|t| sources.iter().any(|x| x == t))).cloned().collect();
    for mut s in inherited {
        if b.subscriptions.iter().any(|x| x.task_id.as_deref() == Some(task) && x.platform == s.platform && x.chat_id == s.chat_id && x.thread_id == s.thread_id && x.session_key == s.session_key) {
            continue;
        }
        s.id = format!("sub_{}", random_hex(10));
        s.task_id = Some(task.into());
        s.cursor = b.next_notification;
        s.created_at = now();
        b.subscriptions.push(s);
    }
}

fn matches(s: &Subscription, n: &Notification) -> bool {
    s.task_id.as_deref().is_none_or(|t| t == n.task_id)
        && s.run_id.as_deref().is_none_or(|r| n.run_id.map(|x| x.to_string()).as_deref() == Some(r))
        && if s.event_kinds.is_empty() { DEFAULT_KINDS.contains(&n.kind.as_str()) } else { s.event_kinds.iter().any(|k| k == &n.kind) }
}

/// Create (or return the identical existing) subscription.
pub fn subscribe(b: &mut BoardData, mut s: Subscription) -> Result<Subscription, String> {
    if let Some(t) = &s.task_id {
        if b.task(t).is_none() {
            return Err(format!("task {t} not found"));
        }
    }
    if s.delivery_mode.is_empty() {
        s.delivery_mode = if s.platform.is_some() { "notify".into() } else if s.session_key.is_some() { "wake".into() } else { "pull".into() };
    }
    if !DELIVERY_MODES.contains(&s.delivery_mode.as_str()) {
        return Err(format!("delivery_mode must be one of {DELIVERY_MODES:?}"));
    }
    for k in &s.event_kinds {
        if !["completed", "failed", "stale", "blocked", "review"].contains(&k.as_str()) {
            return Err(format!("unknown event kind {k:?} (completed, failed, stale, blocked, review)"));
        }
    }
    if let Some(e) = b.subscriptions.iter_mut().find(|x| x.task_id == s.task_id && x.platform == s.platform && x.chat_id == s.chat_id && x.thread_id == s.thread_id && x.session_key == s.session_key && x.run_id == s.run_id) {
        e.delivery_mode = s.delivery_mode;
        if !s.event_kinds.is_empty() {
            e.event_kinds = s.event_kinds;
        }
        return Ok(e.clone());
    }
    s.id = format!("sub_{}", random_hex(10));
    // Only events after subscribing are delivered.
    s.cursor = b.next_notification;
    s.created_at = now();
    b.subscriptions.push(s.clone());
    Ok(s)
}

pub fn unsubscribe(b: &mut BoardData, id: &str) -> bool {
    let n = b.subscriptions.len();
    b.subscriptions.retain(|s| s.id != id);
    n != b.subscriptions.len()
}

/// Unread notifications for a subscription (replay-safe: the cursor does not move).
pub fn pending(b: &BoardData, sub: &Subscription, limit: usize) -> Vec<Notification> {
    b.notifications.iter().filter(|n| n.seq > sub.cursor && matches(sub, n)).take(limit).cloned().collect()
}

/// Read and advance the cursor past what was returned.
pub fn advance(b: &mut BoardData, sub_id: &str, limit: usize) -> Result<(Vec<Notification>, u64), String> {
    let s = b.subscriptions.iter().find(|s| s.id == sub_id).cloned().ok_or_else(|| format!("subscription not found: {sub_id}"))?;
    let evs = pending(b, &s, limit);
    let cursor = evs.last().map(|n| n.seq).unwrap_or(s.cursor);
    if let Some(x) = b.subscriptions.iter_mut().find(|x| x.id == sub_id) {
        x.cursor = cursor;
    }
    Ok((evs, cursor))
}

// ───────────────────────── delivery ─────────────────────────

/// A chat delivery target for `platform`/`chat_id` subscriptions (registered by the host).
pub type Sink = Arc<dyn Fn(&Subscription, &str) -> Result<(), String> + Send + Sync>;
static SINK: RwLock<Option<Sink>> = RwLock::new(None);

pub fn set_sink(s: Sink) {
    *SINK.write().unwrap() = Some(s);
}

pub fn render(slug: &str, b: &BoardData, n: &Notification) -> String {
    let title = b.task(&n.task_id).map(|t| t.title.as_str()).unwrap_or("");
    let verb = match n.kind.as_str() {
        "completed" => "completed",
        "failed" => "failed",
        "blocked" => "is blocked",
        "review" => "is ready for review",
        "stale" => "went stale",
        k => k,
    };
    let mut s = format!("Kanban [{slug}] {} {verb}: {title}\n{}", n.task_id, n.message);
    if !n.artifacts.is_empty() {
        s.push_str(&format!("\nArtifacts: {}", n.artifacts.join(", ")));
    }
    s
}

/// Deliver unread notifications for every push subscription on the board. Wakes
/// subscribed seagent sessions (`wake` / `notify+wake`); chat targets go to the sink. A
/// failed delivery leaves the cursor so the next tick retries.
pub fn deliver(data: &Path, slug: &str, wake: &dyn Fn(&str, &str) -> Result<(), String>) -> Result<usize, String> {
    let b = store::read_board(data, slug)?;
    let sink = SINK.read().unwrap().clone();
    let mut advanced: Vec<(String, u64)> = vec![];
    let mut sent = 0;
    for s in b.subscriptions.iter().filter(|s| s.delivery_mode != "pull") {
        let evs = pending(&b, s, 20);
        let mut cursor = s.cursor;
        for n in &evs {
            let text = render(slug, &b, n);
            let mut ok = true;
            if s.platform.is_some() && s.delivery_mode != "wake" {
                ok &= match &sink {
                    Some(f) => f(s, &text).is_ok(),
                    None => false,
                };
            }
            if let Some(sess) = s.session_key.as_deref().filter(|_| s.delivery_mode != "notify" || s.platform.is_none()) {
                ok &= wake(sess, &text).is_ok();
            }
            if !ok {
                break;
            }
            cursor = n.seq;
            sent += 1;
        }
        if cursor != s.cursor {
            advanced.push((s.id.clone(), cursor));
        }
    }
    if !advanced.is_empty() {
        store::with_board(data, slug, |b| {
            for (id, c) in &advanced {
                if let Some(s) = b.subscriptions.iter_mut().find(|s| &s.id == id) {
                    s.cursor = s.cursor.max(*c);
                }
            }
            Ok(())
        })?;
    }
    Ok(sent)
}

pub fn sub_json(s: &Subscription) -> Value {
    json!({"id": s.id, "task_id": s.task_id, "platform": s.platform, "chat_id": s.chat_id, "thread_id": s.thread_id, "session_key": s.session_key, "run_id": s.run_id, "target": s.target, "event_kinds": s.event_kinds, "delivery_mode": s.delivery_mode, "cursor": s.cursor, "created_at": s.created_at})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kanban::ops::{self, NewTask};
    use std::sync::Mutex;

    #[test]
    fn cursors_inheritance_and_delivery() {
        let d = crate::kanban::testutil::data();
        let (parent, child) = store::with_board(&d, "default", |b| {
            let p = ops::create_task(b, NewTask { title: "p".into(), assignee: Some("a".into()), ..Default::default() })?;
            subscribe(b, Subscription { task_id: Some(p.clone()), session_key: Some("sess-1".into()), ..Default::default() })?;
            let pull = subscribe(b, Subscription { event_kinds: vec!["completed".into()], ..Default::default() })?;
            assert_eq!(pull.delivery_mode, "pull");
            let c = ops::create_task(b, NewTask { title: "c".into(), parents: vec![p.clone()], ..Default::default() })?;
            assert_eq!(b.subscriptions.iter().filter(|s| s.task_id.as_deref() == Some(&c)).count(), 1, "child inherits the parent's session");
            assert!(subscribe(b, Subscription { event_kinds: vec!["bogus".into()], ..Default::default() }).is_err());
            Ok((p, c))
        })
        .unwrap();
        store::with_board(&d, "default", |b| {
            ops::complete(b, &d, "default", &parent, ops::Completion { summary: Some("did it".into()), ..Default::default() }, 2).unwrap();
            ops::block(b, &child, Some("need input"), Some("needs_input"), None)?;
            Ok(())
        })
        .unwrap();
        let woke = Mutex::new(vec![]);
        let n = deliver(&d, "default", &|s, t| {
            woke.lock().unwrap().push((s.to_string(), t.to_string()));
            Ok(())
        })
        .unwrap();
        assert_eq!(n, 2);
        let w = woke.lock().unwrap().clone();
        assert!(w[0].1.contains("completed") && w[0].1.contains("did it"));
        assert!(w[1].1.contains("is blocked"));
        assert_eq!(deliver(&d, "default", &|_, _| Ok(())).unwrap(), 0, "cursor advanced");
        // Pull cursor: replay-safe read, then advance.
        let b = store::read_board(&d, "default").unwrap();
        let pull = b.subscriptions.iter().find(|s| s.delivery_mode == "pull").unwrap().clone();
        assert_eq!(pending(&b, &pull, 50).len(), 1, "only completed events");
        assert_eq!(pending(&b, &pull, 50).len(), 1, "reads do not advance");
        let (evs, _) = store::with_board(&d, "default", |b| advance(b, &pull.id, 50)).unwrap();
        assert_eq!(evs.len(), 1);
        let b = store::read_board(&d, "default").unwrap();
        assert!(pending(&b, b.subscriptions.iter().find(|s| s.id == pull.id).unwrap(), 50).is_empty());
        // A failing wake keeps the notification for the next tick.
        store::with_board(&d, "default", |b| {
            push(b, &child, "blocked", "again", None, vec![]);
            Ok(())
        })
        .unwrap();
        assert_eq!(deliver(&d, "default", &|_, _| Err("down".into())).unwrap(), 0);
        assert_eq!(deliver(&d, "default", &|_, _| Ok(())).unwrap(), 1);
    }
}
