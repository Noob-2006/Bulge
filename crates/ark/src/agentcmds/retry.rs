//! `/retry` (Hermes `gateway/slash_commands_session.py::_handle_retry_command`, cli `_cmd_retry`):
//! rewind the conversation to just before the last user-originated turn and send that
//! message again. The rewind is a `Rewind` event (the log stays append-only); a turn whose
//! message carried attachments (images, files) is refused with the session untouched,
//! because a re-send cannot reconstruct them.

use super::{sid, text};
use crate::slash::{Ctx, Reply};
use ark_core::Block;
use ark_kernel::event::EventKind;
use ark_kernel::projection::project;

pub fn cmd_retry(c: &Ctx, _: &str) -> Result<Reply, String> {
    let id = sid(c)?;
    if c.k.is_running(id) {
        return text("A turn is still running — /stop it first, then /retry.");
    }
    let events = c.k.store.read(id).map_err(|e| e.to_string())?;
    let v = project(&events);
    let Some(&seq) = v.user_turns.last() else { return text("No previous message to retry.") };
    let msg = events.iter().find(|e| e.seq == seq).and_then(|e| match &e.kind {
        EventKind::Message { message, .. } => Some(message.clone()),
        _ => None,
    });
    let Some(msg) = msg else { return text("No previous message to retry.") };
    if msg.content.iter().any(|b| !matches!(b, Block::Text { .. })) {
        return text("Can't retry: the last message had attachments that can't be re-sent. Send it again yourself.");
    }
    let last = msg.text();
    if last.trim().is_empty() {
        return text("No previous message to retry.");
    }
    c.k.record(id, EventKind::Rewind { from_seq: seq, turns: 1 }).map_err(|e| e.to_string())?;
    Ok(Reply { text: Some(format!("retrying: {}", super::one_line(&last, 80))), prompt: Some(last), action: None })
}

#[cfg(test)]
mod tests {
    use super::super::tests::ctx;
    use crate::slash;
    use crate::testkit::kit;
    use ark_kernel::kernel::RunOpts;
    use ark_kernel::projection::project;

    #[test]
    fn retry_rewinds_the_last_turn_and_resends_it() {
        let t = kit();
        let id = t.k.create_session(&t.ws, None, None, None).unwrap();
        let c = ctx(&t.k, &t.ws, Some(id.clone()));
        assert_eq!(slash::run(&c, "/retry").unwrap().text.as_deref(), Some("No previous message to retry."));
        for m in ["first question", "second question"] {
            t.k.submit(&id, m, "cli").unwrap();
            t.k.run(&id, RunOpts::default()).unwrap();
        }
        let before = project(&t.k.store.read(&id).unwrap()).messages.len();
        assert_eq!(before, 4);
        let r = slash::run(&c, "/retry").unwrap();
        assert_eq!(r.prompt.as_deref(), Some("second question"));
        let v = project(&t.k.store.read(&id).unwrap());
        assert_eq!(v.messages.len(), 2, "last exchange rewound");
        assert!(v.messages[1].text().contains("first question"));
        // Re-sending produces a fresh answer at the end.
        t.k.submit(&id, r.prompt.as_deref().unwrap(), "cli").unwrap();
        t.k.run(&id, RunOpts::default()).unwrap();
        let v = project(&t.k.store.read(&id).unwrap());
        assert_eq!(v.messages.len(), 4);
        assert!(v.messages[3].text().contains("second question"));
    }
}
