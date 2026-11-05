//! Memory flush before compaction (OpenClaw flush-plan.ts / agent-tools.memory-flush.ts,
//! MIT): when compaction is about to drop messages, the aux model extracts durable notes
//! from them and they are appended (never overwriting) to today's daily note
//! `<data>/memory/daily/YYYY-MM-DD.md`. Bootstrap files (MEMORY.md, DREAMS.md) stay untouched.

use crate::util::{self, clip};
use crate::Host;
use ark_core::{Message, Role};
use ark_kernel::lifecycle::Lifecycle;
use std::sync::Arc;

pub const SILENT: &str = "NO_REPLY";

pub fn system_prompt(day: &str) -> String {
    format!("Pre-compaction memory flush turn. The session is near auto-compaction; capture durable memories before the older messages are dropped. Your notes are appended to memory/daily/{day}.md. Treat MEMORY.md, DREAMS.md, SOUL.md and AGENTS.md as read-only. Usually {SILENT} is correct.")
}

pub fn user_prompt(day: &str, transcript: &str) -> String {
    format!("Pre-compaction memory flush. Extract only durable facts worth keeping beyond this session from the messages below: decisions, user preferences, environment facts, open commitments, lessons from mistakes. Write them as short Markdown bullet points (one fact each). Never include secrets or credentials. If nothing is worth storing, reply with {SILENT}.\nDate: {day}\n\nMessages about to be compacted:\n{transcript}")
}

pub fn render(dropped: &[Message], max_chars: usize) -> String {
    let lines: Vec<String> = dropped
        .iter()
        .map(|m| (m.role, ark_kernel::lifecycle::strip_fences(&m.text())))
        .filter(|(_, t)| !t.trim().is_empty())
        .map(|(r, t)| format!("{}: {}", if r == Role::User { "user" } else { "assistant" }, util::compact_ws(&t)))
        .collect();
    let all = lines.join("\n");
    let n = all.chars().count();
    if n <= max_chars {
        all
    } else {
        all.chars().skip(n - max_chars).collect()
    }
}

/// Run one flush; returns the notes written (None when nothing was stored).
pub fn flush(h: &Host, dropped: &[Message]) -> Result<Option<String>, String> {
    let s = &h.settings.flush;
    let transcript = render(dropped, s.max_chars);
    if !s.enabled || transcript.trim().is_empty() {
        return Ok(None);
    }
    let now = util::now_ms();
    let day = util::day_stamp(now, h.utc_offset_minutes);
    let out = h.sample(&s.model, &system_prompt(&day), &user_prompt(&day, &transcript), 1024)?;
    let notes = crate::fence::sanitize_context(out.trim()).trim().to_string();
    if notes.is_empty() || notes.trim_matches(|c: char| !c.is_alphanumeric() && c != '_') == SILENT {
        return Ok(None);
    }
    let notes = clip(&notes, 4000);
    let p = h.memory_dir().join("daily").join(format!("{day}.md"));
    let mut cur = std::fs::read_to_string(&p).unwrap_or_default();
    if cur.is_empty() {
        cur = format!("# {day}\n");
    }
    let hm = util::iso((now as i64 + h.utc_offset_minutes as i64 * 60_000).max(0) as u64)[11..16].to_string();
    let next = format!("{}\n\n## Pre-compaction flush ({hm})\n{notes}\n", cur.trim_end());
    util::write_atomic(&p, next.as_bytes())?;
    Ok(Some(notes))
}

pub struct Flush(pub Arc<Host>);

impl Lifecycle for Flush {
    fn name(&self) -> String {
        "memory-flush".into()
    }
    fn pre_compress(&self, _session: &str, _ws: &str, dropped: &[Message]) {
        if self.0.has_sampler() {
            if let Err(e) = flush(&self.0, dropped) {
                eprintln!("ark: memory flush failed: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_notes_or_stays_silent() {
        let reply = Arc::new(std::sync::Mutex::new("- User decided to deploy on Fridays only".to_string()));
        let r2 = reply.clone();
        let h = crate::test_host_with("flush", |_| {}, Arc::new(move |_, sys: &str, u: &str, _| {
            assert!(sys.contains("Pre-compaction") && u.contains("user: we deploy on fridays"));
            Ok(r2.lock().unwrap().clone())
        }));
        let msgs = vec![Message::user("we deploy on fridays from now on"), Message::assistant("ok")];
        Flush(h.clone()).pre_compress("s", "/w", &msgs);
        let day = util::day_stamp(util::now_ms(), h.utc_offset_minutes);
        let p = h.memory_dir().join(format!("daily/{day}.md"));
        let t = std::fs::read_to_string(&p).unwrap();
        assert!(t.starts_with(&format!("# {day}")) && t.contains("## Pre-compaction flush") && t.contains("Fridays only"));
        *reply.lock().unwrap() = "NO_REPLY".into();
        assert_eq!(flush(&h, &msgs).unwrap(), None);
        *reply.lock().unwrap() = "- second note".into();
        flush(&h, &msgs).unwrap();
        let t2 = std::fs::read_to_string(&p).unwrap();
        assert!(t2.contains("Fridays only") && t2.contains("second note"), "append-only");
        assert_eq!(render(&msgs, 10).chars().count(), 10);
    }
}
