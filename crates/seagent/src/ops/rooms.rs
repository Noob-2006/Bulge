//! Hosted rooms / group chats (Hermes `gateway/hosted_room_discussion.py` +
//! `tui_gateway/hosted_room_service.py`, same-gateway Discussions): a room seats 2–6
//! agents (each with its own session, optional model and optional seagent profile) that
//! discuss the user's message in bounded rounds.
//!
//! Policy (ported): the user's message opens a Discussion; round 0 goes to the members it
//! @mentions (none = everyone), rotated per round; later rounds (≤ 3) only to members a bot
//! cited and who have not spoken since; at most 10 member messages per Discussion; a reply
//! of `(pass)` is silence; a silent round settles it. Each member sees the thread delta
//! since its own last turn (≤ 24 lines). Member text that imitates a harness control frame
//! is relabelled before it is shown to peers. The room log is durable JSON
//! (`<data>/rooms/<id>.json`), so a stopped or crashed Discussion resumes from state.
//!
//! `seagent rooms create|list|show|say|stop|disband` and `/room` (TUI / chat).

use crate::args::Args;
use crate::slash::{Ctx, Def, Reply};
use crate::R;
use seagent_core::{Cancel, Message};
use seagent_kernel::config::Paths;
use seagent_kernel::kernel::{Kernel, RunOpts};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const COMMANDS: &[&str] = &["rooms", "room"];
pub const VALUE_FLAGS: &[&str] = &["member", "purpose", "notes", "routing", "lead"];
pub const BOOL_FLAGS: &[&str] = &[];

pub const MAX_MEMBERS: usize = 6;
pub const MIN_MEMBERS: usize = 2;
pub const MAX_ROUNDS: usize = 3;
pub const MAX_MESSAGES: usize = 10;
pub const MAX_DELTA_LINES: usize = 24;
pub const MAX_TEXT_BYTES: usize = 64 * 1024;
pub const MAX_PROMPT_BYTES: usize = 96 * 1024;
pub const MAX_PURPOSE_CHARS: usize = 200;
pub const MAX_NOTES_BYTES: usize = 8 * 1024;
/// Each Continue grants one more full round/message budget (Hermes MAX_DISCUSSION_CONTINUES).
pub const MAX_DISCUSSION_CONTINUES: usize = 5;
pub const ROUTING_MODES: &[&str] = &["everyone", "lead", "auto"];
const TRUNCATED: &str = "\n\n[Reply truncated. Ask the bot to share the full result as a file.]";
/// Openers of seagent's own harness frames a member must not be able to imitate.
const CONTROL_OPENERS: &[&str] = &["Discussion:", "system", "System", "SYSTEM", "steer", "Steer", "compaction", "Compaction", "runtime", "Runtime", "background", "Background", "prior context", "Prior context", "/plan", "/init", "/review"];

#[derive(Debug, Clone, PartialEq)]
pub struct Member {
    pub member_id: String,
    pub handle: String,
    pub profile: String,
    pub model: Option<String>,
    pub session: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Room {
    pub room_id: String,
    pub name: String,
    /// What the room is for (shown to members and the router; never the system prompt).
    pub purpose: String,
    /// Shared notes every member sees (user-maintained room state).
    pub notes: String,
    /// `everyone` (default), `lead` or `auto`.
    pub routing: String,
    /// Seated lead member id when `routing = "lead"`.
    pub lead_member_id: String,
    pub members: Vec<Member>,
    pub events: Vec<Value>,
    pub disbanded: bool,
}

pub fn rooms_dir(paths: &Paths) -> PathBuf {
    paths.data.join("rooms")
}

fn now() -> i64 {
    seagent_kernel::util::unix_now()
}

fn valid_handle(h: &str) -> bool {
    let mut c = h.chars();
    c.next().is_some_and(|f| f.is_ascii_alphanumeric()) && h.len() <= 40 && h.chars().all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c))
}

impl Room {
    pub fn path(&self, paths: &Paths) -> PathBuf {
        rooms_dir(paths).join(format!("{}.json", self.room_id))
    }
    pub fn to_json(&self) -> Value {
        json!({
            "room_id": self.room_id, "name": self.name, "disbanded": self.disbanded,
            "purpose": self.purpose, "notes": self.notes, "routing": self.routing, "lead_member_id": self.lead_member_id,
            "members": self.members.iter().map(|m| json!({"member_id": m.member_id, "handle": m.handle, "profile": m.profile, "model": m.model, "session": m.session})).collect::<Vec<_>>(),
            "events": self.events,
        })
    }
    pub fn from_json(v: &Value) -> Result<Room, String> {
        let members = v["members"].as_array().ok_or("room has no members")?.iter().map(|m| Member {
            member_id: m["member_id"].as_str().unwrap_or("").into(),
            handle: m["handle"].as_str().unwrap_or("").into(),
            profile: m["profile"].as_str().unwrap_or("").into(),
            model: m["model"].as_str().map(str::to_string),
            session: m["session"].as_str().map(str::to_string),
        }).collect();
        let routing = v["routing"].as_str().unwrap_or("everyone").trim().to_ascii_lowercase();
        Ok(Room {
            room_id: v["room_id"].as_str().ok_or("room_id")?.into(),
            name: v["name"].as_str().unwrap_or("").into(),
            purpose: v["purpose"].as_str().unwrap_or("").into(),
            notes: v["notes"].as_str().unwrap_or("").into(),
            routing: if ROUTING_MODES.contains(&routing.as_str()) { routing } else { "everyone".into() },
            lead_member_id: v["lead_member_id"].as_str().unwrap_or("").into(),
            members,
            events: v["events"].as_array().cloned().unwrap_or_default(),
            disbanded: v["disbanded"] == true,
        })
    }
    pub fn save(&self, paths: &Paths) -> Result<(), String> {
        std::fs::create_dir_all(rooms_dir(paths)).map_err(|e| e.to_string())?;
        seagent_kernel::util::atomic_write(&self.path(paths), serde_json::to_string_pretty(&self.to_json()).unwrap_or_default().as_bytes()).map_err(|e| e.to_string())
    }
    fn next_seq(&self) -> u64 {
        self.events.last().and_then(|e| e["seq"].as_u64()).unwrap_or(0) + 1
    }
    pub fn append(&mut self, kind: &str, actor: Value, payload: Value) -> u64 {
        let seq = self.next_seq();
        self.events.push(json!({"seq": seq, "event_id": format!("e{seq}"), "kind": kind, "actor": actor, "payload": payload, "ts": now()}));
        seq
    }
    pub fn member(&self, id: &str) -> Option<&Member> {
        self.members.iter().find(|m| m.member_id == id)
    }
}

/// `profile[:handle][@provider/model]` specs → members.
pub fn parse_members(specs: &[String]) -> Result<Vec<Member>, String> {
    let mut out: Vec<Member> = vec![];
    for (i, s) in specs.iter().enumerate() {
        let (left, model) = match s.split_once('@') {
            Some((l, m)) => (l, Some(m.trim().to_string()).filter(|m| !m.is_empty())),
            None => (s.as_str(), None),
        };
        let (profile, handle) = match left.split_once(':') {
            Some((p, h)) => (p.trim().to_string(), h.trim().to_string()),
            None => (left.trim().to_string(), left.trim().to_string()),
        };
        if !valid_handle(&handle) {
            return Err(format!("member {}: invalid handle {handle:?} (letters, digits, . _ : -)", i + 1));
        }
        if out.iter().any(|m| m.handle.eq_ignore_ascii_case(&handle)) {
            return Err(format!("duplicate handle @{handle}"));
        }
        if matches!(handle.to_lowercase().as_str(), "all" | "everyone" | "user") {
            return Err(format!("@{handle} is reserved"));
        }
        out.push(Member { member_id: format!("m{}", seagent_kernel::util::random_hex(6)), handle, profile, model, session: None });
    }
    if out.len() < MIN_MEMBERS || out.len() > MAX_MEMBERS {
        return Err(format!("a room seats {MIN_MEMBERS}–{MAX_MEMBERS} members (got {})", out.len()));
    }
    Ok(out)
}

/// Cron delivery (`deliver: room:<id>`): append one labelled gateway message to the room's log.
/// It names the @mentions the job included so a room worker can start a round for those members;
/// it never starts a round itself (a feed of scheduled results must not make every bot answer).
pub fn post_message(data: &Path, id_or_name: &str, text: &str) -> Result<String, String> {
    let paths = Paths { data: data.to_path_buf(), ..Default::default() };
    let mut r = load(&paths, id_or_name)?;
    if r.disbanded {
        return Err(format!("room `{id_or_name}` is disbanded"));
    }
    let mentioned: Vec<String> = resolve_mentions(&[text], &r.members, false).iter().map(|m| m.handle.clone()).collect();
    r.append("message.gateway", json!({"kind": "gateway", "source": "cron"}), json!({"text": text, "thread_id": "main", "mentions": mentioned, "scheduled": true}));
    r.save(&paths)?;
    Ok(format!("posted to room {} ({})", r.room_id, r.name))
}

pub fn create(paths: &Paths, name: &str, members: Vec<Member>) -> Result<Room, String> {
    create_with(paths, name, members, "", "", "everyone", "")
}

/// `create` plus room settings (purpose, shared notes and lead/auto routing).
pub fn create_with(paths: &Paths, name: &str, members: Vec<Member>, purpose: &str, notes: &str, routing: &str, lead: &str) -> Result<Room, String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return Err("room name must be 1–80 characters".into());
    }
    let (purpose, notes, routing, lead_member_id) = resolve_settings(&members, purpose, notes, routing, lead)?;
    let r = Room { room_id: format!("room-{}", seagent_kernel::util::random_hex(4)), name: name.into(), purpose, notes, routing, lead_member_id, members, events: vec![], disbanded: false };
    r.save(paths)?;
    Ok(r)
}

/// Normalize and validate room settings. `lead` is a handle or member id; `lead` routing
/// needs one, `everyone`/`auto` clear it.
pub fn resolve_settings(members: &[Member], purpose: &str, notes: &str, routing: &str, lead: &str) -> Result<(String, String, String, String), String> {
    let purpose = purpose.split_whitespace().collect::<Vec<_>>().join(" ");
    if purpose.chars().count() > MAX_PURPOSE_CHARS {
        return Err(format!("purpose must be at most {MAX_PURPOSE_CHARS} characters"));
    }
    let notes = notes.trim().to_string();
    if notes.len() > MAX_NOTES_BYTES {
        return Err(format!("notes must be at most {MAX_NOTES_BYTES} bytes"));
    }
    let routing = if routing.trim().is_empty() { "everyone".into() } else { routing.trim().to_ascii_lowercase() };
    if !ROUTING_MODES.contains(&routing.as_str()) {
        return Err(format!("routing must be one of {}", ROUTING_MODES.join(", ")));
    }
    let lead = lead.trim().trim_start_matches('@');
    let lead_member_id = if routing == "lead" {
        let m = members.iter().find(|m| m.member_id == lead || m.handle.eq_ignore_ascii_case(lead)).ok_or("lead routing needs a seated --lead <handle>")?;
        m.member_id.clone()
    } else {
        String::new()
    };
    Ok((purpose, notes, routing, lead_member_id))
}

/// Change room settings; a field passed as `None` keeps its current value.
pub fn set_context(paths: &Paths, room: &mut Room, purpose: Option<&str>, notes: Option<&str>, routing: Option<&str>, lead: Option<&str>) -> Result<(), String> {
    let lead_handle = lead.unwrap_or_else(|| room.members.iter().find(|m| m.member_id == room.lead_member_id).map(|m| m.handle.as_str()).unwrap_or(""));
    let (p, n, r, lid) = resolve_settings(
        &room.members,
        purpose.unwrap_or(&room.purpose),
        notes.unwrap_or(&room.notes),
        routing.unwrap_or(&room.routing),
        lead_handle,
    )?;
    room.purpose = p;
    room.notes = n;
    room.routing = r;
    room.lead_member_id = lid;
    room.save(paths)
}

pub fn load(paths: &Paths, id_or_name: &str) -> Result<Room, String> {
    let direct = rooms_dir(paths).join(format!("{id_or_name}.json"));
    let read = |p: &PathBuf| std::fs::read_to_string(p).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()).and_then(|v| Room::from_json(&v).ok());
    if let Some(r) = read(&direct) {
        return Ok(r);
    }
    list(paths).into_iter().find(|r| r.name.eq_ignore_ascii_case(id_or_name)).ok_or_else(|| format!("no room `{id_or_name}` (see `seagent rooms list`)"))
}

pub fn list(paths: &Paths) -> Vec<Room> {
    let mut v: Vec<Room> = std::fs::read_dir(rooms_dir(paths)).map(|rd| rd.flatten().filter_map(|e| std::fs::read_to_string(e.path()).ok()).filter_map(|s| serde_json::from_str::<Value>(&s).ok()).filter_map(|v| Room::from_json(&v).ok()).filter(|r| !r.disbanded).collect()).unwrap_or_default();
    v.sort_by(|a, b| a.room_id.cmp(&b.room_id));
    v
}

// ───────────── policy ─────────────

pub fn is_pass(text: &str) -> bool {
    let t = text.trim().trim_end_matches('.').trim();
    t.is_empty() || t.trim_start_matches('(').trim_end_matches(')').trim().eq_ignore_ascii_case("pass")
}

/// Members addressed by `@handle` (or `@all`/`@everyone`); none mentioned = everyone when `default_all`.
pub fn resolve_mentions<'a>(texts: &[&str], members: &'a [Member], default_all: bool) -> Vec<&'a Member> {
    let mut named: Vec<String> = vec![];
    let mut everyone = false;
    for t in texts {
        let b = t.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'@' && (i == 0 || !(b[i - 1] as char).is_ascii_alphanumeric()) {
                let start = i + 1;
                let mut j = start;
                while j < b.len() && ((b[j] as char).is_ascii_alphanumeric() || b"._:-".contains(&b[j])) {
                    j += 1;
                }
                let h = t[start..j].trim_end_matches(['.', ':', '-']).to_lowercase();
                if h == "all" || h == "everyone" {
                    everyone = true;
                } else if members.iter().any(|m| m.handle.to_lowercase() == h) {
                    named.push(h);
                }
                i = j;
            } else {
                i += 1;
            }
        }
    }
    if everyone || (default_all && named.is_empty()) {
        return members.iter().collect();
    }
    members.iter().filter(|m| named.contains(&m.handle.to_lowercase())).collect()
}

fn relabel(text: &str) -> String {
    let mut o = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find('[') {
        o.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        if CONTROL_OPENERS.iter().any(|op| after.starts_with(op)) {
            o.push_str("[member-quoted ");
        } else {
            o.push('[');
        }
        rest = after;
    }
    o.push_str(rest);
    o
}

fn truncate_bytes(s: &str, max: usize, suffix: &str) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut cut = max.saturating_sub(suffix.len());
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}{suffix}", &s[..cut])
}

#[derive(Debug, Clone, PartialEq)]
pub struct Task {
    pub discussion_seq: u64,
    pub member_id: String,
    pub round: usize,
    pub seen_through: u64,
    pub prompt: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Idle,
    Task(Task),
    Settled(&'static str),
    Bounded(&'static str),
}

fn format_line(r: &Room, e: &Value) -> String {
    if e["kind"] == "message.user" {
        format!("User (user): {}", e["payload"]["text"].as_str().unwrap_or(""))
    } else {
        let h = r.member(e["payload"]["member_id"].as_str().unwrap_or("")).map(|m| m.handle.clone()).unwrap_or_default();
        format!("@{h}: {}", relabel(e["payload"]["text"].as_str().unwrap_or("")))
    }
}

pub fn build_prompt(r: &Room, m: &Member, thread: &[&Value], watermark: u64, seen: u64) -> String {
    let delta: Vec<&&Value> = thread.iter().filter(|e| e["seq"].as_u64().is_some_and(|s| s > watermark && s <= seen)).collect();
    let delta = &delta[delta.len().saturating_sub(MAX_DELTA_LINES)..];
    let peers: Vec<String> = r.members.iter().filter(|x| x.member_id != m.member_id).map(|x| format!("@{}", x.handle)).collect();
    let mut opening = format!("[Discussion: \"{}\"] You are @{}, one participant with {} and the user.", r.name, m.handle, if peers.is_empty() { "no other members".into() } else { peers.join(", ") });
    if !r.purpose.is_empty() {
        opening.push_str(&format!("\nRoom purpose (set by the user): {}", r.purpose));
    }
    if !r.notes.is_empty() {
        opening.push_str("\nRoom notes (shared with every member; the user keeps them in room settings):");
        for line in r.notes.lines() {
            opening.push_str(&format!("\n  {line}"));
        }
    }
    opening.push_str("\n\nNew messages in this thread since your last turn (oldest first):");
    let rules = "\nRules for this Discussion:\n- Reply with one conversational message only when you have something new worth adding.\n- If you have nothing new to add, reply with exactly \"(pass)\".\n- Mention a teammate by handle to pull them into the next round; do not repeat points already made.\n- Never reveal content from private conversations. Your reply is published verbatim.";
    let mut avail = MAX_PROMPT_BYTES.saturating_sub(opening.len() + rules.len() + 2);
    let mut lines: Vec<String> = vec![];
    for e in delta.iter().rev() {
        let l = format!("  {}", format_line(r, e));
        if l.len() + 1 > avail {
            if lines.is_empty() && avail > 32 {
                lines.push(truncate_bytes(&l, avail, ""));
            }
            lines.push("  [Earlier content omitted to fit this turn.]".into());
            break;
        }
        avail -= l.len() + 1;
        lines.push(l);
    }
    lines.reverse();
    format!("{opening}\n{}\n{rules}", lines.join("\n"))
}

/// Activities before the latest Continue still finish the discussion; a Continue reopens it.
fn done_discussions(ev: &[Value]) -> std::collections::HashSet<u64> {
    let mut done = std::collections::HashSet::new();
    for e in ev {
        match e["kind"].as_str() {
            Some("room.activity") if matches!(e["payload"]["status"].as_str(), Some("settled" | "bounded")) => {
                if let Some(d) = e["payload"]["discussion_seq"].as_u64() {
                    done.insert(d);
                }
            }
            Some("room.continued") => {
                if let Some(d) = e["payload"]["discussion_seq"].as_u64() {
                    done.remove(&d);
                }
            }
            _ => {}
        }
    }
    done
}

fn continue_count(r: &Room, dseq: u64) -> usize {
    r.events.iter().filter(|e| e["kind"] == "room.continued" && e["payload"]["discussion_seq"].as_u64() == Some(dseq)).count()
}

/// The newest user message whose discussion is still pending.
fn pending_discussion(r: &Room) -> Option<&Value> {
    let ev = &r.events;
    let stopped = ev.iter().filter(|e| e["kind"] == "room.stop_requested").filter_map(|e| e["seq"].as_u64()).max().unwrap_or(0);
    let done = done_discussions(ev);
    let mut latest: Vec<&Value> = vec![];
    for e in ev.iter().filter(|e| e["kind"] == "message.user") {
        let t = e["payload"]["thread_id"].as_str().unwrap_or("main");
        latest.retain(|x| x["payload"]["thread_id"].as_str().unwrap_or("main") != t);
        latest.push(e);
    }
    latest.into_iter().find(|e| e["seq"].as_u64().unwrap_or(0) > stopped && !done.contains(&e["seq"].as_u64().unwrap_or(0)))
}

/// The assignment the lead/router recorded for a discussion: (member ids, everyone).
fn assignment_for(r: &Room, dseq: u64) -> Option<(Vec<String>, bool)> {
    r.events.iter().rev().find(|e| e["kind"] == "room.assignment" && e["payload"]["discussion_seq"].as_u64() == Some(dseq)).map(|e| {
        let ids = e["payload"]["member_ids"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
        (ids, e["payload"]["everyone"].as_bool().unwrap_or(false))
    })
}

/// Replay the room log and decide the next member turn (at most one).
pub fn plan_next(r: &Room) -> Decision {
    let ev = &r.events;
    let Some(disc) = pending_discussion(r) else { return Decision::Idle };
    let dseq = disc["seq"].as_u64().unwrap_or(0);
    let thread_id = disc["payload"]["thread_id"].as_str().unwrap_or("main").to_string();
    let continues = continue_count(r, dseq);
    let max_messages = MAX_MESSAGES.saturating_mul(1 + continues);
    let max_rounds = MAX_ROUNDS.saturating_mul(1 + continues);
    let committed: Vec<u64> = ev.iter().filter(|e| e["kind"] == "turn.settled").filter_map(|e| e["payload"]["message_seq"].as_u64()).collect();
    let thread: Vec<&Value> = ev.iter().filter(|e| e["payload"]["thread_id"].as_str().unwrap_or("main") == thread_id && (e["kind"] == "message.user" || (e["kind"] == "message.member" && committed.contains(&e["seq"].as_u64().unwrap_or(0))))).collect();
    let since: Vec<&Value> = thread.iter().copied().filter(|e| e["seq"].as_u64().unwrap_or(0) >= dseq).collect();
    let member_msgs: Vec<&Value> = since.iter().copied().filter(|e| e["kind"] == "message.member" && e["payload"]["discussion_seq"].as_u64() == Some(dseq)).collect();
    if member_msgs.len() >= max_messages {
        return Decision::Bounded("max_messages");
    }
    let terminals: Vec<(usize, String)> = ev.iter().filter(|e| e["kind"].as_str().is_some_and(|k| k.starts_with("turn.")) && e["payload"]["discussion_seq"].as_u64() == Some(dseq)).map(|e| (e["payload"]["round"].as_u64().unwrap_or(0) as usize, e["payload"]["member_id"].as_str().unwrap_or("").to_string())).collect();
    // Watermark: the last seq each member has seen in this thread.
    // (Hermes `_derive_member_watermarks`: every terminal counts; a published reply also
    // covers the member's own message.)
    let watermark = |mid: &str| ev.iter().filter(|e| e["kind"].as_str().is_some_and(|k| k.starts_with("turn.")) && e["payload"]["member_id"] == mid && e["payload"]["thread_id"].as_str().unwrap_or("main") == thread_id).map(|e| e["payload"]["seen_through"].as_u64().unwrap_or(0).max(e["payload"]["message_seq"].as_u64().unwrap_or(0))).max().unwrap_or(0);
    for round in 0..max_rounds {
        let responders: Vec<&Member> = if round == 0 {
            let named = resolve_mentions(&[disc["payload"]["text"].as_str().unwrap_or("")], &r.members, false);
            if !named.is_empty() {
                named
            } else if let Some((ids, everyone)) = assignment_for(r, dseq) {
                if everyone {
                    r.members.iter().collect()
                } else {
                    r.members.iter().filter(|m| ids.contains(&m.member_id)).collect()
                }
            } else {
                resolve_mentions(&[disc["payload"]["text"].as_str().unwrap_or("")], &r.members, true)
            }
        } else {
            // Peers a bot cited and who have not posted since.
            let mut cited: Vec<(&Member, u64)> = vec![];
            let mut last_post: std::collections::HashMap<&str, u64> = Default::default();
            for e in &member_msgs {
                let speaker = e["payload"]["member_id"].as_str().unwrap_or("");
                let seq = e["seq"].as_u64().unwrap_or(0);
                last_post.insert(speaker, seq);
                for m in resolve_mentions(&[e["payload"]["text"].as_str().unwrap_or("")], &r.members, false) {
                    if m.member_id != speaker {
                        cited.retain(|(c, _)| c.member_id != m.member_id);
                        cited.push((m, seq));
                    }
                }
            }
            r.members.iter().filter(|m| cited.iter().any(|(c, at)| c.member_id == m.member_id && last_post.get(m.member_id.as_str()).copied().unwrap_or(0) <= *at)).collect()
        };
        let shift = if responders.is_empty() { 0 } else { round % responders.len() };
        let rotated: Vec<&Member> = responders[shift..].iter().chain(responders[..shift].iter()).copied().collect();
        for m in rotated {
            let wm = watermark(&m.member_id);
            let delta: Vec<&&Value> = thread.iter().filter(|e| e["seq"].as_u64().unwrap_or(0) > wm).collect();
            if delta.is_empty() || terminals.contains(&(round, m.member_id.clone())) {
                continue;
            }
            let seen = delta.last().and_then(|e| e["seq"].as_u64()).unwrap_or(0);
            return Decision::Task(Task { discussion_seq: dseq, member_id: m.member_id.clone(), round, seen_through: seen, prompt: build_prompt(r, m, &thread, wm, seen) });
        }
        if !member_msgs.iter().any(|e| e["payload"]["round"].as_u64() == Some(round as u64)) {
            return Decision::Settled("silent_round");
        }
        if round == max_rounds - 1 {
            return Decision::Bounded("max_rounds");
        }
    }
    Decision::Bounded("max_rounds")
}

/// The latest bounded discussion that may take another Continue, if any.
fn paused_discussion(r: &Room) -> Option<(u64, String)> {
    let bounded = r.events.iter().rev().find(|e| e["kind"] == "room.activity" && e["payload"]["status"] == "bounded")?;
    let dseq = bounded["payload"]["discussion_seq"].as_u64()?;
    let seq = bounded["seq"].as_u64().unwrap_or(0);
    let thread_id = bounded["payload"]["thread_id"].as_str().unwrap_or("main").to_string();
    if r.events.iter().any(|e| e["seq"].as_u64().unwrap_or(0) > seq && (e["kind"] == "room.stop_requested" || (e["kind"] == "message.user" && e["payload"]["thread_id"].as_str().unwrap_or("main") == thread_id))) {
        return None;
    }
    if continue_count(r, dseq) >= MAX_DISCUSSION_CONTINUES {
        return None;
    }
    // The latest Continue must not already have reopened this cap.
    let last_continue = r.events.iter().filter(|e| e["kind"] == "room.continued" && e["payload"]["discussion_seq"].as_u64() == Some(dseq)).filter_map(|e| e["seq"].as_u64()).max().unwrap_or(0);
    if last_continue > seq {
        return None;
    }
    Some((dseq, thread_id))
}

/// `Continue` on a discussion that hit its cap: grants one more full round/message budget.
pub fn continue_room(paths: &Paths, room: &mut Room) -> Result<usize, String> {
    if room.disbanded {
        return Err("room is disbanded".into());
    }
    let (dseq, thread_id) = paused_discussion(room).ok_or("no bounded discussion to continue (or the Continue limit was reached)")?;
    let grant = continue_count(room, dseq) + 1;
    room.append("room.continued", json!({"kind": "user"}), json!({"discussion_seq": dseq, "thread_id": thread_id, "grant": grant}));
    room.save(paths)?;
    Ok(grant)
}

/// Runs one member turn and returns its reply text.
pub trait Runner {
    fn run(&self, room: &Room, member: &mut Member, prompt: &str) -> Result<String, String>;

    /// `routing = "auto"`: a cheap router picks round-0 responders. `Ok(Some(ids))`
    /// with an empty vec means everyone; `Ok(None)`/`Err` falls back to everyone.
    fn route(&self, _room: &Room, _message: &str, _recent: &[(String, String)]) -> Result<Option<Vec<String>>, String> {
        Ok(None)
    }
}

const ROUTER_SYSTEM_PROMPT: &str = "You route messages in a group chat between a user and several AI assistants. Decide which members the user's new message is for: pick each member whose role or area the request touches, and only those. Pick everyone only when the message is clearly for the whole group. Never pick a member only to acknowledge or repeat another. Reply with only a JSON object and nothing else: {\"members\": [\"handle\", ...]} or {\"members\": \"everyone\"}.";

fn router_prompt(room: &Room, message: &str, recent: &[(String, String)]) -> String {
    let mut lines = vec![format!("Room: {}", room.name)];
    if !room.purpose.is_empty() {
        lines.push(format!("Purpose: {}", room.purpose));
    }
    if !room.notes.is_empty() {
        lines.push(format!("Notes: {}", room.notes.chars().take(2000).collect::<String>()));
    }
    lines.push(String::new());
    lines.push("Members:".into());
    for m in &room.members {
        let role = if m.profile.is_empty() { "".to_string() } else { format!(": {}", m.profile) };
        lines.push(format!("- @{}{role}", m.handle));
    }
    if !recent.is_empty() {
        lines.push(String::new());
        lines.push("Recent messages (oldest first):".into());
        for (who, text) in recent {
            let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
            lines.push(format!("  {who}: {}", flat.chars().take(600).collect::<String>()));
        }
    }
    lines.push(String::new());
    lines.push("The user's new message:".into());
    lines.push(format!("  {}", message.chars().take(20_000).collect::<String>()));
    lines.join("\n")
}

fn parse_router_answer(text: &str, members: &[Member]) -> Option<Vec<String>> {
    let raw = text.trim().trim_start_matches("```json").trim_start_matches("```").trim_end_matches("```").trim();
    let v: Value = serde_json::from_str(raw).ok()?;
    if v.as_object().is_none_or(|o| o.len() != 1 || !o.contains_key("members")) {
        return None;
    }
    let picked = &v["members"];
    if picked.as_str() == Some("everyone") {
        return Some(vec![]);
    }
    let arr = picked.as_array()?;
    if arr.is_empty() {
        return None;
    }
    let mut ids = vec![];
    for item in arr {
        let h = item.as_str()?.trim().trim_start_matches('@');
        let m = members.iter().find(|m| m.handle.eq_ignore_ascii_case(h))?;
        if !ids.contains(&m.member_id) {
            ids.push(m.member_id.clone());
        }
    }
    Some(ids)
}

/// The lead's routing turn: a lead that names nobody (or fails) gets the message itself.
fn lead_routing_prompt(room: &Room, lead: &Member, message: &str, recent: &[(String, String)]) -> String {
    let mut lines = vec![format!("[Discussion: \"{}\"] You are @{}, the lead of this room.", room.name, lead.handle)];
    if !room.purpose.is_empty() {
        lines.push(format!("Room purpose (set by the user): {}", room.purpose));
    }
    if !room.notes.is_empty() {
        lines.push(format!("Room notes:\n{}", room.notes));
    }
    lines.push(String::new());
    lines.push("Members:".into());
    for m in &room.members {
        lines.push(format!("- @{}{}", m.handle, if m.member_id == lead.member_id { " (you)" } else { "" }));
    }
    if !recent.is_empty() {
        lines.push(String::new());
        lines.push("Recent messages (oldest first):".into());
        for (who, text) in recent {
            lines.push(format!("  {who}: {}", text.split_whitespace().collect::<Vec<_>>().join(" ")));
        }
    }
    lines.push(String::new());
    lines.push("The message (from the user):".into());
    lines.push(format!("  {message}"));
    lines.push(String::new());
    lines.push("You are the lead: decide who takes it, not answer it yourself here. Pick the member(s) whose role the request touches (yourself included when it is yours). Reply with only a JSON object and nothing else, for example {\"assign\": [\"handle\"]}.".into());
    lines.join("\n")
}

fn parse_lead_assignment(text: &str, members: &[Member], lead: &Member) -> (Vec<String>, bool) {
    let candidate = seagent_kernel::jsonschema::extract_json_candidate(text);
    if let Ok(v) = serde_json::from_str::<Value>(&candidate) {
        if let Some(arr) = v.get("assign").and_then(Value::as_array) {
            let mut ids = vec![];
            for item in arr {
                if let Some(h) = item.as_str() {
                    let h = h.trim().trim_start_matches('@');
                    if let Some(m) = members.iter().find(|m| m.handle.eq_ignore_ascii_case(h)) {
                        if !ids.contains(&m.member_id) {
                            ids.push(m.member_id.clone());
                        }
                    }
                }
            }
            if !ids.is_empty() {
                return (ids, false);
            }
        }
    }
    (vec![lead.member_id.clone()], true)
}

fn recent_messages(room: &Room, before_seq: u64) -> Vec<(String, String)> {
    let mut rows: Vec<(String, String)> = room
        .events
        .iter()
        .filter(|e| e["seq"].as_u64().is_some_and(|s| s < before_seq) && (e["kind"] == "message.user" || e["kind"] == "message.member"))
        .map(|e| {
            let who = if e["kind"] == "message.user" {
                "user".to_string()
            } else {
                room.member(e["payload"]["member_id"].as_str().unwrap_or("")).map(|m| m.handle.clone()).unwrap_or_else(|| "member".into())
            };
            (who, e["payload"]["text"].as_str().unwrap_or("").to_string())
        })
        .collect();
    if rows.len() > 5 {
        rows = rows.split_off(rows.len() - 5);
    }
    rows
}

/// Record the lead/auto assignment for a new, unaddressed discussion. Best-effort: a
/// failed router falls back to everyone, a failed lead to the lead alone.
fn ensure_routing(paths: &Paths, room: &mut Room, runner: &dyn Runner) -> Result<(), String> {
    if room.routing == "everyone" {
        return Ok(());
    }
    let Some(disc) = pending_discussion(room) else { return Ok(()) };
    let dseq = disc["seq"].as_u64().unwrap_or(0);
    let thread_id = disc["payload"]["thread_id"].as_str().unwrap_or("main").to_string();
    let text = disc["payload"]["text"].as_str().unwrap_or("").to_string();
    if assignment_for(room, dseq).is_some() {
        return Ok(());
    }
    // Explicit mentions (and @all) always win; only a new thread is routable.
    if !resolve_mentions(&[text.as_str()], &room.members, false).is_empty() {
        return Ok(());
    }
    if room.events.iter().any(|e| e["seq"].as_u64().is_some_and(|s| s < dseq) && e["payload"]["thread_id"].as_str().unwrap_or("main") == thread_id && (e["kind"] == "message.user" || e["kind"] == "message.member")) {
        return Ok(());
    }
    let recent = recent_messages(room, dseq);
    let (ids, everyone, fallback, source) = if room.routing == "lead" {
        let Some(lead) = room.member(&room.lead_member_id).cloned() else {
            return Ok(());
        };
        let prompt = lead_routing_prompt(room, &lead, &text, &recent);
        let mut m = lead.clone();
        let answer = runner.run(room, &mut m, &prompt);
        if let Some(slot) = room.members.iter_mut().find(|x| x.member_id == lead.member_id) {
            *slot = m;
        }
        let (ids, fallback) = match answer {
            Ok(a) => parse_lead_assignment(&a, &room.members, &lead),
            Err(_) => (vec![lead.member_id.clone()], true),
        };
        (ids, false, fallback, "lead")
    } else {
        match runner.route(room, &text, &recent) {
            Ok(Some(ids)) if ids.is_empty() => (vec![], true, false, "router"),
            Ok(Some(ids)) => (ids, false, false, "router"),
            _ => (vec![], true, true, "router"),
        }
    };
    room.append("room.assignment", json!({"kind": "gateway"}), json!({
        "discussion_seq": dseq, "thread_id": thread_id, "member_ids": ids,
        "everyone": everyone, "fallback": fallback, "routing": room.routing, "source": source,
    }));
    room.save(paths)
}

/// Members run as sessions of this kernel (their own session per room, optional model);
/// a member naming another seagent profile runs through `seagent -p <profile> run`.
pub struct KernelRunner {
    pub k: Kernel,
    pub workspace: PathBuf,
}

impl Runner for KernelRunner {
    fn run(&self, room: &Room, m: &mut Member, prompt: &str) -> Result<String, String> {
        let current = crate::ops::profile::current();
        if !m.profile.is_empty() && m.profile != current && m.profile != m.handle && crate::ops::profile::list().contains(&m.profile) {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let mut cmd = std::process::Command::new(exe);
            cmd.args(["-p", &m.profile, "run", "--quiet"]);
            if let Some(model) = &m.model {
                cmd.args(["-m", model]);
            }
            let out = cmd.arg(prompt).stdin(std::process::Stdio::null()).output().map_err(|e| e.to_string())?;
            if !out.status.success() {
                return Err(String::from_utf8_lossy(&out.stderr).lines().last().unwrap_or("member run failed").to_string());
            }
            return Ok(String::from_utf8_lossy(&out.stdout).trim().to_string());
        }
        let sid = match m.session.clone().filter(|s| self.k.store.read(s).is_ok()) {
            Some(s) => s,
            None => {
                let s = self.k.create_session(&self.workspace, m.model.as_deref(), None, Some(&format!("room {} · @{}", room.name, m.handle))).map_err(|e| e.to_string())?;
                m.session = Some(s.clone());
                s
            }
        };
        // The discussion frame already says where this turn comes from; a "room" source
        // would prefix the prompt with "[from room] " and blur it.
        self.k.submit(&sid, prompt, "user").map_err(|e| e.to_string())?;
        let out = self.k.run(&sid, RunOpts::default()).map_err(|e| e.to_string())?;
        Ok(out.text)
    }

    fn route(&self, room: &Room, message: &str, recent: &[(String, String)]) -> Result<Option<Vec<String>>, String> {
        let model = self.k.cfg.task_model("group_router");
        let prompt = router_prompt(room, message, recent);
        let (reply, _used, _stop) = self.k.sample(Some(&model), ROUTER_SYSTEM_PROMPT, vec![Message::user(prompt)], vec![], 200, &Cancel::new())?;
        Ok(parse_router_answer(&reply.text(), &room.members))
    }
}

/// Post a user message and drive the Discussion to completion; `on_msg` sees each
/// published member message (`@handle: text`). Returns the final status.
pub fn say(paths: &Paths, room: &mut Room, text: &str, runner: &dyn Runner, on_msg: &mut dyn FnMut(&str)) -> Result<&'static str, String> {
    if room.disbanded {
        return Err("room is disbanded".into());
    }
    if text.trim().is_empty() {
        return Err("empty message".into());
    }
    let text = truncate_bytes(text, MAX_TEXT_BYTES, "");
    room.append("message.user", json!({"kind": "user"}), json!({"text": text, "thread_id": "main"}));
    room.save(paths)?;
    drive(paths, room, runner, on_msg)
}

pub fn drive(paths: &Paths, room: &mut Room, runner: &dyn Runner, on_msg: &mut dyn FnMut(&str)) -> Result<&'static str, String> {
    for _ in 0..(MAX_ROUNDS * (MAX_DISCUSSION_CONTINUES + 1) * MAX_MEMBERS + 2) {
        // Re-read: a `stop` from another terminal lands in the file.
        if let Ok(fresh) = load(paths, &room.room_id) {
            room.events = fresh.events;
            room.disbanded = fresh.disbanded;
        }
        if ensure_routing(paths, room, runner).is_err() {
            // A router/lead call is advisory: fall through to the normal round.
        }
        match plan_next(room) {
            Decision::Idle => return Ok("idle"),
            Decision::Settled(why) | Decision::Bounded(why) => {
                let status = if why == "silent_round" { "settled" } else { "bounded" };
                let dseq = room.events.iter().rev().find(|e| e["kind"] == "message.user").and_then(|e| e["seq"].as_u64()).unwrap_or(0);
                room.append("room.activity", json!({"kind": "gateway"}), json!({"status": status, "reason_code": why, "discussion_seq": dseq, "thread_id": "main"}));
                room.save(paths)?;
                return Ok(status);
            }
            Decision::Task(t) => {
                let idx = room.members.iter().position(|m| m.member_id == t.member_id).ok_or("member vanished")?;
                let mut m = room.members[idx].clone();
                let res = runner.run(room, &mut m, &t.prompt);
                room.members[idx] = m.clone();
                let coords = json!({"discussion_seq": t.discussion_seq, "member_id": t.member_id, "round": t.round, "thread_id": "main", "seen_through": t.seen_through});
                match res {
                    Ok(reply) if is_pass(&reply) => {
                        let mut p = coords;
                        p["passed"] = json!(true);
                        room.append("turn.settled", json!({"kind": "gateway"}), p);
                    }
                    Ok(reply) => {
                        let reply = truncate_bytes(reply.trim(), MAX_TEXT_BYTES, TRUNCATED);
                        let mut mp = coords.clone();
                        mp["text"] = json!(reply);
                        let mseq = room.append("message.member", json!({"kind": "member", "id": t.member_id}), mp);
                        let mut p = coords;
                        p["passed"] = json!(false);
                        p["message_seq"] = json!(mseq);
                        room.append("turn.settled", json!({"kind": "gateway"}), p);
                        on_msg(&format!("@{}: {reply}", m.handle));
                    }
                    Err(e) => {
                        let mut p = coords;
                        p["error"] = json!(e);
                        room.append("turn.failed", json!({"kind": "gateway"}), p);
                        on_msg(&format!("@{} failed: {e}", m.handle));
                    }
                }
                room.save(paths)?;
            }
        }
    }
    Ok("bounded")
}

pub fn stop(paths: &Paths, room: &mut Room) -> Result<(), String> {
    room.append("room.stop_requested", json!({"kind": "user"}), json!({"cancel_id": seagent_kernel::util::random_hex(6)}));
    room.save(paths)
}

pub fn transcript(r: &Room, last: usize) -> String {
    let msgs: Vec<String> = r.events.iter().filter(|e| e["kind"] == "message.user" || e["kind"] == "message.member").map(|e| format_line(r, e)).collect();
    msgs[msgs.len().saturating_sub(last)..].join("\n")
}

fn summary(r: &Room) -> String {
    let routing = match r.routing.as_str() {
        "lead" => format!(" · lead @{}", r.members.iter().find(|m| m.member_id == r.lead_member_id).map(|m| m.handle.as_str()).unwrap_or("?")),
        "auto" => " · auto-routed".to_string(),
        _ => String::new(),
    };
    let purpose = if r.purpose.is_empty() { String::new() } else { format!(" — {}", r.purpose) };
    format!("{}  {}{purpose}  [{}]{routing}", r.room_id, r.name, r.members.iter().map(|m| format!("@{}{}", m.handle, m.model.as_ref().map(|x| format!("[{x}]")).unwrap_or_default())).collect::<Vec<_>>().join(" "))
}

// ───────────── CLI / slash ─────────────

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if !COMMANDS.contains(&cmd) {
        return None;
    }
    Some(cli(a))
}

fn cli(a: &Args) -> R {
    let paths = Paths::from_env();
    let one = |key: &str| a.vals(key).into_iter().next().unwrap_or_default();
    match a.pos(0).unwrap_or("list") {
        "create" => {
            let members = parse_members(&a.vals("member"))?;
            let (purpose, notes, routing, lead) = (one("purpose"), one("notes"), one("routing"), one("lead"));
            let r = if purpose.is_empty() && notes.is_empty() && routing.is_empty() && lead.is_empty() {
                create(&paths, &a.rest(1), members)?
            } else {
                create_with(&paths, &a.rest(1), members, &purpose, &notes, &routing, &lead)?
            };
            println!("✓ created {}", summary(&r));
        }
        "update" | "set" => {
            let mut r = load(&paths, a.need(1, "room")?)?;
            let purpose = a.vals("purpose").into_iter().next();
            let notes = a.vals("notes").into_iter().next();
            let routing = a.vals("routing").into_iter().next();
            let lead = a.vals("lead").into_iter().next();
            if purpose.is_none() && notes.is_none() && routing.is_none() && lead.is_none() {
                return Err("rooms update needs at least one of --purpose, --notes, --routing, --lead".into());
            }
            set_context(&paths, &mut r, purpose.as_deref(), notes.as_deref(), routing.as_deref(), lead.as_deref())?;
            println!("✓ updated {}", summary(&r));
        }
        "list" => {
            let l = list(&paths);
            if l.is_empty() {
                println!("no rooms — seagent rooms create <name> --member coder --member critic:crit@openai/gpt-5");
            }
            for r in l {
                println!("{}", summary(&r));
            }
        }
        "show" => {
            let r = load(&paths, a.need(1, "room")?)?;
            println!("{}\n{}", summary(&r), transcript(&r, a.num::<usize>("limit")?.unwrap_or(40)));
        }
        "say" => {
            let mut r = load(&paths, a.need(1, "room")?)?;
            let text = a.rest(2);
            let c = crate::build_agent(a, crate::approver_for(a, true), false)?;
            let runner = KernelRunner { k: c.k.clone(), workspace: c.workspace.clone() };
            let status = say(&paths, &mut r, &text, &runner, &mut |m| println!("{m}\n"))?;
            eprintln!("· discussion {status}");
        }
        "continue" => {
            let mut r = load(&paths, a.need(1, "room")?)?;
            let grant = continue_room(&paths, &mut r)?;
            let c = crate::build_agent(a, crate::approver_for(a, true), false)?;
            let runner = KernelRunner { k: c.k.clone(), workspace: c.workspace.clone() };
            let status = drive(&paths, &mut r, &runner, &mut |m| println!("{m}\n"))?;
            eprintln!("· discussion continued (grant {grant}): {status}");
        }
        "stop" => {
            let mut r = load(&paths, a.need(1, "room")?)?;
            stop(&paths, &mut r)?;
            println!("✓ stop requested");
        }
        "disband" => {
            let mut r = load(&paths, a.need(1, "room")?)?;
            r.disbanded = true;
            r.save(&paths)?;
            println!("✓ disbanded {}", r.room_id);
        }
        other => return Err(format!("unknown `seagent rooms {other}` (create <name> --member profile[:handle][@model]… [--purpose … --notes … --routing everyone|lead|auto --lead <handle>] | update <room> … | list | show | say <room> <text> | continue <room> | stop | disband)").into()),
    }
    Ok(0)
}

pub const SLASH: &[Def] = &[Def { name: "room", aliases: &["group"], args: "[list|<room> <message>|continue <room>|stop <room>]", help: "Group chat: several agents discuss your message in turns", category: "Session", admin: true, local: true, run: slash_room }];

fn slash_room(c: &Ctx, a: &str) -> Result<Reply, String> {
    let paths = c.k.paths.clone();
    let text = |t: String| Ok(Reply { text: Some(t), ..Default::default() });
    let mut w = a.splitn(2, char::is_whitespace);
    match (w.next().unwrap_or(""), w.next().unwrap_or("").trim()) {
        ("" | "list", _) => text(list(&paths).iter().map(summary).collect::<Vec<_>>().join("\n")).map(|mut r| {
            if r.text.as_deref() == Some("") {
                r.text = Some("no rooms — create one with `seagent rooms create <name> --member a --member b`".into());
            }
            r
        }),
        ("stop", id) => {
            let mut r = load(&paths, id)?;
            stop(&paths, &mut r)?;
            text("stop requested".into())
        }
        ("continue", id) => {
            let mut r = load(&paths, id)?;
            let grant = continue_room(&paths, &mut r)?;
            let runner = KernelRunner { k: c.k.clone(), workspace: c.workspace.clone() };
            match c.notify.clone() {
                Some(n) => {
                    let paths = paths.clone();
                    std::thread::spawn(move || {
                        let n2 = n.clone();
                        let res = drive(&paths, &mut r, &runner, &mut |m| n2(m.to_string()));
                        n(match res {
                            Ok(s) => format!("· discussion continued (grant {grant}): {s}"),
                            Err(e) => format!("✗ room: {e}"),
                        });
                    });
                    text(format!("continued {} — members reply below", r_name(id)))
                }
                None => {
                    let mut out = vec![];
                    let s = drive(&paths, &mut r, &runner, &mut |m| out.push(m.to_string()))?;
                    out.push(format!("· discussion continued (grant {grant}): {s}"));
                    text(out.join("\n\n"))
                }
            }
        }
        (id, "") => {
            let r = load(&paths, id)?;
            text(format!("{}\n{}", summary(&r), transcript(&r, 20)))
        }
        (id, msg) => {
            let mut r = load(&paths, id)?;
            let runner = KernelRunner { k: c.k.clone(), workspace: c.workspace.clone() };
            let msg = msg.to_string();
            match c.notify.clone() {
                Some(n) => {
                    std::thread::spawn(move || {
                        let n2 = n.clone();
                        let res = say(&paths, &mut r, &msg, &runner, &mut |m| n2(m.to_string()));
                        n(match res {
                            Ok(s) => format!("· discussion {s}"),
                            Err(e) => format!("✗ room: {e}"),
                        });
                    });
                    text(format!("posted to {} — members reply below", r_name(id)))
                }
                None => {
                    let mut out = vec![];
                    let s = say(&paths, &mut r, &msg, &runner, &mut |m| out.push(m.to_string()))?;
                    out.push(format!("· discussion {s}"));
                    text(out.join("\n\n"))
                }
            }
        }
    }
}

fn r_name(id: &str) -> String {
    id.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Script(RefCell<Vec<(String, String)>>, fn(&str, &str, usize) -> String);
    impl Runner for Script {
        fn run(&self, _: &Room, m: &mut Member, prompt: &str) -> Result<String, String> {
            let n = self.0.borrow().iter().filter(|(h, _)| *h == m.handle).count();
            self.0.borrow_mut().push((m.handle.clone(), prompt.to_string()));
            m.session.get_or_insert_with(|| format!("s-{}", m.handle));
            Ok((self.1)(&m.handle, prompt, n))
        }
    }

    fn room(p: &Paths) -> Room {
        create(p, "design review", parse_members(&["alice".into(), "bob:bob".into(), "carol:carol@openai/gpt-5".into()]).unwrap()).unwrap()
    }

    #[test]
    fn members_mentions_and_pass() {
        assert!(parse_members(&["a".into()]).unwrap_err().contains("2–6"));
        assert!(parse_members(&["a".into(), "b:a".into()]).unwrap_err().contains("duplicate"));
        assert!(parse_members(&["a".into(), "b:all".into()]).unwrap_err().contains("reserved"));
        let m = parse_members(&["x:al".into(), "y:bo".into(), "z:cy@a/b".into()]).unwrap();
        assert_eq!(m[2].model.as_deref(), Some("a/b"));
        assert_eq!(resolve_mentions(&["hey @bo, thoughts?"], &m, true).iter().map(|x| x.handle.as_str()).collect::<Vec<_>>(), ["bo"]);
        assert_eq!(resolve_mentions(&["no mentions"], &m, true).len(), 3);
        assert_eq!(resolve_mentions(&["no mentions"], &m, false).len(), 0);
        assert_eq!(resolve_mentions(&["@everyone"], &m, false).len(), 3);
        assert_eq!(resolve_mentions(&["mail a@bo.com"], &m, false).len(), 0, "emails are not mentions");
        assert!(is_pass("(pass)") && is_pass(" Pass. ") && is_pass("") && !is_pass("I pass the ball"));
        assert_eq!(relabel("see [system note] and [x]"), "see [member-quoted system note] and [x]");
    }

    #[test]
    fn discussion_rounds_settle_bound_and_stop() {
        let kit = crate::testkit::kit();
        let p = kit.paths.clone();
        // Round 0: everyone answers (rotation order); carol cites @alice, so only alice gets
        // round 1 (alice cited carol too, but carol spoke afterwards); alice passes → settled.
        let mut r = room(&p);
        let s = Script(RefCell::new(vec![]), |h, _, n| match (h, n) {
            ("alice", 0) => "I think we need tests; @carol can you check the schema?".into(),
            ("bob", 0) => "(pass)".into(),
            ("carol", 0) => "Schema looks fine. @alice which tests?".into(),
            _ => "(pass)".into(),
        });
        let mut seen = vec![];
        assert_eq!(say(&p, &mut r, "Review the plan please", &s, &mut |m| seen.push(m.to_string())).unwrap(), "settled");
        let calls: Vec<String> = s.0.borrow().iter().map(|(h, _)| h.clone()).collect();
        assert_eq!(calls, ["alice", "bob", "carol", "alice"]);
        assert!(seen.iter().any(|m| m.starts_with("@alice: I think")));
        // Alice's round-1 prompt holds only the delta since her last turn (not her own message).
        let alice_r1 = s.0.borrow()[3].1.clone();
        assert!(alice_r1.contains("@carol: Schema looks fine"), "{alice_r1}");
        assert!(!alice_r1.contains("User (user): Review the plan please"), "already seen");
        assert!(!alice_r1.contains("@alice: I think"), "own message is covered by the watermark");
        assert!(alice_r1.contains("reply with exactly \"(pass)\""));
        assert!(r.members.iter().all(|m| m.session.is_some()));
        // Persisted and reloadable; the transcript has the user line and the replies.
        let back = load(&p, "design review").unwrap();
        assert!(transcript(&back, 10).starts_with("User (user): Review the plan please"));
        assert_eq!(plan_next(&back), Decision::Idle);
        // A mention addresses only that member in round 0.
        let s2 = Script(RefCell::new(vec![]), |_, _, _| "(pass)".into());
        assert_eq!(say(&p, &mut r, "@bob just you", &s2, &mut |_| {}).unwrap(), "settled");
        assert_eq!(s2.0.borrow().iter().map(|(h, _)| h.as_str()).collect::<Vec<_>>(), ["bob"]);
        // Members that keep citing each other are bounded (rounds/messages).
        let s3 = Script(RefCell::new(vec![]), |h, _, _| if h == "alice" { "@bob again".into() } else { "@alice again".into() });
        let mut r3 = room(&p);
        assert_eq!(say(&p, &mut r3, "@alice @bob debate", &s3, &mut |_| {}).unwrap(), "bounded");
        assert!(s3.0.borrow().len() <= MAX_MESSAGES);
        // A stop request makes the pending discussion idle.
        let mut r4 = room(&p);
        r4.append("message.user", json!({"kind": "user"}), json!({"text": "hi", "thread_id": "main"}));
        stop(&p, &mut r4).unwrap();
        assert_eq!(plan_next(&r4), Decision::Idle);
        assert_eq!(list(&p).len(), 3);
    }

    #[test]
    fn prompt_caps_rotation_truncation_and_disband() {
        let kit = crate::testkit::kit();
        let p = kit.paths.clone();
        // Delta cap: 30 user lines in the thread, each member sees only the last 24.
        let mut r = create(&p, "cap", parse_members(&["a:a".into(), "b:b".into(), "c:c".into()]).unwrap()).unwrap();
        for i in 0..30 {
            r.append("message.user", json!({"kind": "user"}), json!({"text": format!("line {i}"), "thread_id": "main"}));
        }
        let task = match plan_next(&r) {
            Decision::Task(t) => t,
            d => panic!("expected a task, got {d:?}"),
        };
        assert_eq!(task.member_id, r.members[0].member_id, "round 0 starts with the first member");
        let delta: Vec<&str> = task.prompt.lines().filter(|l| l.starts_with("  User (user): ")).collect();
        assert_eq!(delta.len(), MAX_DELTA_LINES, "only the newest {MAX_DELTA_LINES} lines are shown");
        assert!(delta.last().unwrap().ends_with("line 29"), "{}", delta.last().unwrap());
        assert!(!task.prompt.contains("line 5\n") && !task.prompt.contains("line 0\n"), "older lines are dropped");

        // Round rotation: two members who spoke before the citing message are pulled in and
        // the round starts from `round % responders` (here bob, then alice).
        let mut r2 = create(&p, "rotate", parse_members(&["alice".into(), "bob".into(), "carol".into(), "dave".into()]).unwrap()).unwrap();
        let s = Script(RefCell::new(vec![]), |h, _, _| match h {
            "alice" | "bob" => "starting".into(),
            "carol" => "@alice @bob please check this".into(),
            _ => "(pass)".into(),
        });
        assert_eq!(say(&p, &mut r2, "kick off", &s, &mut |_| {}).unwrap(), "settled");
        let order: Vec<String> = s.0.borrow().iter().map(|(h, _)| h.clone()).collect();
        assert_eq!(order, ["alice", "bob", "carol", "dave", "bob", "alice"], "round 1 rotates the two cited peers");

        // Message cap: after MAX_MESSAGES published replies the Discussion stops planning, and
        // `drive` records the reason instead of leaving it pending.
        let mut r3 = create(&p, "cap10", parse_members(&["a".into(), "b".into()]).unwrap()).unwrap();
        r3.append("message.user", json!({"kind": "user"}), json!({"text": "go", "thread_id": "main"}));
        for i in 0..MAX_MESSAGES {
            let mid = r3.members[i % 2].member_id.clone();
            let seq = r3.append("message.member", json!({"kind": "member", "id": mid}), json!({"text": format!("reply {i}"), "member_id": mid, "discussion_seq": 1, "round": 0, "thread_id": "main"}));
            r3.append("turn.settled", json!({"kind": "gateway"}), json!({"discussion_seq": 1, "member_id": mid, "round": 0, "thread_id": "main", "seen_through": seq, "passed": false, "message_seq": seq}));
        }
        assert_eq!(plan_next(&r3), Decision::Bounded("max_messages"));
        r3.save(&p).unwrap();
        assert_eq!(drive(&p, &mut r3, &Script(RefCell::new(vec![]), |_, _, _| panic!("no member turn after the cap")), &mut |_| {}).unwrap(), "bounded");
        let last = r3.events.iter().rev().find(|e| e["kind"] == "room.activity").unwrap();
        assert_eq!((last["payload"]["status"].as_str(), last["payload"]["reason_code"].as_str()), (Some("bounded"), Some("max_messages")));

        // Oversized user text is cut to 64 KiB before it is stored.
        let mut r4 = create(&p, "cut", parse_members(&["a:a".into(), "b:b".into()]).unwrap()).unwrap();
        let quiet = Script(RefCell::new(vec![]), |_, _, _| "(pass)".into());
        say(&p, &mut r4, &"x".repeat(MAX_TEXT_BYTES + 4096), &quiet, &mut |_| {}).unwrap();
        let stored = load(&p, &r4.room_id).unwrap();
        let text = stored.events.iter().find(|e| e["kind"] == "message.user").unwrap()["payload"]["text"].as_str().unwrap().to_string();
        assert_eq!(text.len(), MAX_TEXT_BYTES);

        // Disband: hidden from `list`, and no new messages can be posted.
        r4.disbanded = true;
        r4.save(&p).unwrap();
        assert!(list(&p).iter().all(|x| x.room_id != r4.room_id), "disbanded rooms drop out of the list");
        assert!(say(&p, &mut r4, "hello?", &quiet, &mut |_| {}).unwrap_err().contains("disbanded"));
    }

    #[test]
    fn kernel_runner_and_slash() {
        let kit = crate::testkit::kit();
        let p = kit.paths.clone();
        let c = crate::slash::Ctx { k: &kit.k, ext: None, session: None, workspace: kit.ws.clone(), surface: crate::slash::Surface::Cli, sender: None, notify: None };
        // Empty-state hint and the `/group` alias share the `/room` row.
        assert!(crate::slash::run(&c, "/room").unwrap().text.unwrap().contains("no rooms"));
        assert!(crate::slash::find("group").is_some_and(|d| d.name == "room"));
        let r = create(&p, "pair", parse_members(&["one".into(), "two".into()]).unwrap()).unwrap();
        let out = crate::slash::run(&c, &format!("/room {} hello team", r.room_id)).unwrap().text.unwrap();
        // The echo provider answers with the prompt it got: neither member passes on round 0.
        assert!(out.contains("@one: reply: [Discussion: \"pair\"] You are @one"), "{out}");
        assert!(out.contains("@two: reply:"));
        assert!(out.contains("· discussion"));
        let back = load(&p, &r.room_id).unwrap();
        assert!(back.members.iter().all(|m| m.session.as_ref().is_some_and(|s| kit.k.store.read(s).is_ok())));
        assert!(crate::slash::run(&c, "/room").unwrap().text.unwrap().contains("pair"));
        assert!(crate::slash::run(&c, &format!("/room {}", r.room_id)).unwrap().text.unwrap().contains("User (user): hello team"));
        assert!(crate::slash::run(&c, &format!("/group {}", r.room_id)).unwrap().text.unwrap().contains("User (user): hello team"));
        assert_eq!(crate::slash::run(&c, &format!("/room stop {}", r.room_id)).unwrap().text.unwrap(), "stop requested");
        assert!(load(&p, &r.room_id).unwrap().events.iter().any(|e| e["kind"] == "room.stop_requested"));
    }
    #[test]
    fn cron_post_appends_a_labelled_message_and_mentions() {
        let d = seagent_core::tmp::scratch_path(format!("seagent-room-post-{}", seagent_kernel::util::random_hex(6)));
        let p = Paths { data: d.clone(), ..Default::default() };
        let r = room(&p);
        let receipt = post_message(&d, &r.room_id, "nightly digest @bob").unwrap();
        assert!(receipt.contains(&r.room_id), "{receipt}");
        let got = load(&p, &r.room_id).unwrap();
        let ev = got.events.last().unwrap();
        assert_eq!((ev["kind"].as_str(), ev["actor"]["source"].as_str()), (Some("message.gateway"), Some("cron")));
        assert_eq!(ev["payload"]["text"], "nightly digest @bob");
        assert_eq!(ev["payload"]["mentions"], json!(["bob"]), "only mentioned members are named");
        assert!(post_message(&d, "no-such-room", "x").unwrap_err().contains("no room"));
    }

    #[test]
    fn room_settings_lead_auto_routing_and_continue() {
        let kit = crate::testkit::kit();
        let p = kit.paths.clone();
        let members = parse_members(&["alice".into(), "bob".into()]).unwrap();
        assert!(resolve_settings(&members, "", "", "bogus", "").unwrap_err().contains("routing"));
        assert!(resolve_settings(&members, "", "", "lead", "").unwrap_err().contains("--lead"));
        assert!(resolve_settings(&members, &"x".repeat(MAX_PURPOSE_CHARS + 1), "", "", "").unwrap_err().contains("purpose"));
        assert!(resolve_settings(&members, "", &"x".repeat(MAX_NOTES_BYTES + 1), "", "").unwrap_err().contains("notes"));

        // Lead routing: an unaddressed new message goes to the lead as a routing turn, which names bob.
        let mut r = create_with(&p, "lead room", members, "Review APIs", "Shared: run fmt", "lead", "alice").unwrap();
        assert_eq!(r.lead_member_id, r.members[0].member_id);
        assert!(summary(&r).contains("lead @alice") && summary(&r).contains("Review APIs"));
        let s = Script(RefCell::new(vec![]), |h, prompt, _n| {
            if prompt.contains("the lead of this room") {
                "{\"assign\":[\"bob\"]}".into()
            } else if h == "bob" {
                "I reviewed the API.".into()
            } else {
                "(pass)".into()
            }
        });
        let mut seen = vec![];
        assert_eq!(say(&p, &mut r, "please look at the API", &s, &mut |m| seen.push(m.to_string())).unwrap(), "settled");
        assert_eq!(s.0.borrow().iter().map(|(h, _)| h.as_str()).collect::<Vec<_>>(), ["alice", "bob"], "lead routes, bob answers");
        assert!(seen.iter().any(|m| m.starts_with("@bob: I reviewed")));
        let assignment = r.events.iter().find(|e| e["kind"] == "room.assignment").unwrap();
        assert_eq!(assignment["payload"]["source"], "lead");
        assert_eq!(assignment["payload"]["member_ids"], json!([r.members[1].member_id.clone()]));
        let bob_prompt = s.0.borrow().iter().find(|(h, _)| h == "bob").unwrap().1.clone();
        assert!(bob_prompt.contains("Room purpose (set by the user): Review APIs"), "{bob_prompt}");
        assert!(bob_prompt.contains("Shared: run fmt"), "{bob_prompt}");

        // Auto routing: the cheap router picks carol, and nobody else takes round 0.
        let mut a = create_with(&p, "auto room", parse_members(&["alice".into(), "bob".into(), "carol".into()]).unwrap(), "Triage", "", "auto", "").unwrap();
        struct Routed {
            calls: RefCell<Vec<String>>,
            pick: usize,
        }
        impl Runner for Routed {
            fn run(&self, _: &Room, m: &mut Member, _: &str) -> Result<String, String> {
                self.calls.borrow_mut().push(m.handle.clone());
                Ok("(pass)".into())
            }
            fn route(&self, room: &Room, _: &str, _: &[(String, String)]) -> Result<Option<Vec<String>>, String> {
                Ok(Some(vec![room.members[self.pick].member_id.clone()]))
            }
        }
        let routed = Routed { calls: RefCell::new(vec![]), pick: 2 };
        say(&p, &mut a, "please triage this", &routed, &mut |_| {}).unwrap();
        assert_eq!(routed.calls.borrow().as_slice(), ["carol"]);
        let assignment = a.events.iter().find(|e| e["kind"] == "room.assignment").unwrap();
        assert_eq!(assignment["payload"]["source"], "router");
        assert_eq!(assignment["payload"]["member_ids"], json!([a.members[2].member_id.clone()]));

        // Continue past the message cap: one grant reopens the same discussion; a second
        // Continue without another cap is refused.
        let mut c = create(&p, "bounded", parse_members(&["a".into(), "b".into()]).unwrap()).unwrap();
        c.append("message.user", json!({"kind": "user"}), json!({"text": "go", "thread_id": "main"}));
        for i in 0..MAX_MESSAGES {
            let mid = c.members[i % 2].member_id.clone();
            let seq = c.append("message.member", json!({"kind": "member", "id": mid}), json!({"text": format!("reply {i}"), "member_id": mid, "discussion_seq": 1, "round": 0, "thread_id": "main"}));
            c.append("turn.settled", json!({"kind": "gateway"}), json!({"discussion_seq": 1, "member_id": mid, "round": 0, "thread_id": "main", "seen_through": seq, "passed": false, "message_seq": seq}));
        }
        assert_eq!(plan_next(&c), Decision::Bounded("max_messages"));
        c.append("room.activity", json!({"kind": "gateway"}), json!({"status": "bounded", "reason_code": "max_messages", "discussion_seq": 1, "thread_id": "main"}));
        assert_eq!(continue_room(&p, &mut c).unwrap(), 1);
        assert!(!matches!(plan_next(&c), Decision::Bounded(_)), "a Continue grants another budget");
        assert!(continue_room(&p, &mut c).is_err(), "no second Continue until the reopened discussion caps again");

        // Old room files (before purpose/routing existed) load with safe defaults.
        let legacy = json!({"room_id": "room-legacy", "name": "Legacy", "members": [{"member_id": "m1", "handle": "a", "profile": "a"}], "events": []});
        std::fs::create_dir_all(rooms_dir(&p)).unwrap();
        std::fs::write(rooms_dir(&p).join("room-legacy.json"), serde_json::to_string(&legacy).unwrap()).unwrap();
        let old = load(&p, "room-legacy").unwrap();
        assert_eq!((old.routing.as_str(), old.purpose.as_str(), old.notes.as_str()), ("everyone", "", ""));
        assert!(old.lead_member_id.is_empty());
    }
}
