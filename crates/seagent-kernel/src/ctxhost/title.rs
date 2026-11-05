//! Automatic session titles (Hermes `agent/title_generator.py`, `agent/session_store.py` provenance).
//!
//! After the first successful turn of a session that still has no title, one cheap aux-model call
//! names the conversation from the user's opening message plus the start of the reply. It runs on a
//! thread of its own — the turn never waits — and only ever fills an empty title: a name the person
//! typed is never overwritten. `[context] title_generation` / `title_model_upgrade` switch it off and
//! `title_language` pins the output language.
//!
//! The model call sits behind [`Titler`] so tests drive the prompt/parse/guard logic without a network.

use super::Host;
use crate::kernel::Kernel;
use crate::lifecycle::Lifecycle;
use crate::projection::project;
use seagent_core::{Cancel, Message};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

/// Stored titles are capped like the kernel's `set_title` (80 chars).
pub const MAX_TITLE_CHARS: usize = 80;
/// Characters of the opening message shown to the model (Claude Code/OpenClaw converge on 1000).
pub const MAX_INPUT_CHARS: usize = 1000;
/// Characters of the reply excerpt appended as context.
pub const MAX_REPLY_CHARS: usize = 400;
/// Titling is a 3–7 word task; a longer "title" is the model answering instead of naming.
pub const MAX_TITLE_WORDS: usize = 12;
pub const TITLE_MAX_TOKENS: u32 = 512;
/// How long the background thread retries a busy session log before giving up (never blocks a turn).
const PERSIST_BUDGET: Duration = Duration::from_secs(20);

/// Opening messages that are machinery, not a request (Hermes `_MACHINE_PREFIXES`).
const MACHINE_PREFIXES: &[&str] = &["[Summary of earlier conversation]", "[CONTEXT COMPACTION", "[Runtime note:", "[System note:", "[SYSTEM]", "[System: The active model"];

/// Control wrappers a `/command` turn carries around the prose the user typed (Codex CLI list).
const CONTROL_WRAPPERS: &[&str] = &[
    "command-message", "command-name", "command-args", "local-command-caveat", "local-command-stderr", "local-command-stdout",
    "task-notification", "system-reminder", "ide_opened_file", "ide_selection",
];

/// Prompt-example echoes: a small model sometimes parrots the prompt's own examples back
/// (Hermes `_EXAMPLE_ECHO_REJECT`; "Friendly greeting" is a legitimate answer for a bare hello).
const EXAMPLE_ECHO: &[&str] = &["fix login button on mobile", "postgres connection pool exhaustion", "code changes"];

pub type Titler = Arc<dyn Fn(&str) -> Result<String, String> + Send + Sync>;

/// The titling prompt; `language` ("" = the user's language) pins the output language.
pub fn prompt(language: &str) -> String {
    let lang = if language.trim().is_empty() {
        "- Write the title in the same language as the user's message.".to_string()
    } else {
        format!("- Write the title in {}.", language.trim())
    };
    format!(
        "You name chat sessions. Given the opening of a conversation, write a title that lets the user find it again in a list.\n\n\
Rules:\n\
- 3 to 7 words, sentence case (capitalize only the first word and proper nouns).\n\
- Name what the user wants DONE, not that they asked a question.\n\
- Keep technical terms, filenames, numbers and error codes exact.\n\
- Drop filler words: the, this, my, a, an.\n\
- No trailing punctuation, no quotes, no tool names, no 'Title:' prefix.\n\
- Never answer the message. Name it.\n\
- Always produce something, even for a bare greeting.\n\
{lang}\n\
Good: {{\"title\": \"Fix login button on mobile\"}}\n\
Good: {{\"title\": \"Postgres connection pool exhaustion\"}}\n\
Too vague: {{\"title\": \"Code changes\"}}\n\n\
Reply with JSON only: {{\"title\": \"...\"}}"
    )
}

/// Remove leading control wrappers (nested too) so a `/skill` turn reduces to the prose typed.
pub fn strip_wrappers(text: &str) -> String {
    let mut current = text.trim().to_string();
    for _ in 0..CONTROL_WRAPPERS.len() * 2 {
        let lower = current.to_lowercase();
        let Some((open, close)) = CONTROL_WRAPPERS.iter().find_map(|tag| {
            let open = format!("<{tag}>");
            lower.starts_with(&open).then(|| (open, format!("</{tag}>")))
        }) else {
            break;
        };
        let next = match lower.find(&close) {
            Some(end) => {
                let after = current[end + close.len()..].trim().to_string();
                if after.is_empty() {
                    current[open.len()..end].trim().to_string()
                } else {
                    after
                }
            }
            None => current[open.len()..].trim().to_string(),
        };
        if next == current {
            break;
        }
        current = next;
    }
    current
}

/// First non-empty line of `text`, whitespace-collapsed.
fn first_line(text: &str) -> String {
    text.lines().map(str::trim).find(|l| !l.is_empty()).map(|l| l.split_whitespace().collect::<Vec<_>>().join(" ")).unwrap_or_default()
}

/// Whether this opening message is worth titling at all.
pub fn is_titleable(user: &str) -> bool {
    let t = user.trim();
    !t.is_empty() && !MACHINE_PREFIXES.iter().any(|p| t.starts_with(p)) && !strip_wrappers(t).trim().is_empty()
}

/// Instant title: the first meaningful line trimmed at a word boundary (no model, never fails).
pub fn derive_title(user: &str) -> Option<String> {
    if !is_titleable(user) {
        return None;
    }
    let line = first_line(&strip_wrappers(user));
    if line.is_empty() {
        return None;
    }
    let mut title: String = line.chars().take(MAX_TITLE_CHARS).collect();
    if line.chars().count() > MAX_TITLE_CHARS {
        let cut = title.rfind(' ').filter(|i| *i > MAX_TITLE_CHARS / 2).unwrap_or(title.len());
        title.truncate(cut);
        title = title.trim_end_matches([' ', ',', '.', ';', ':', '—', '-']).to_string();
        title.push('…');
    }
    Some(title).filter(|t| !t.trim().is_empty())
}

/// What the model sees: the opening message (bounded) plus the start of the first reply.
pub fn build_input(user: &str, assistant: &str) -> String {
    let user = strip_wrappers(user);
    let mut out: String = user.chars().take(MAX_INPUT_CHARS).collect();
    let reply = first_line(assistant);
    if !reply.is_empty() {
        out.push_str("\n\nAssistant replied:\n");
        out.push_str(&reply.chars().take(MAX_REPLY_CHARS).collect::<String>());
    }
    out
}

fn strip_title_prefix(text: &str) -> &str {
    text.strip_prefix("title:").or_else(|| text.strip_prefix("Title:")).unwrap_or(text).trim()
}

/// `{"title": "..."}` (strict, then a loose scan) else the first line as prose.
pub fn parse_title(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let fenced = raw.strip_prefix("```").map(|r| r.trim_start_matches("json").trim_start()).map(|r| r.strip_suffix("```").unwrap_or(r).trim()).filter(|r| !r.is_empty());
    let body = fenced.unwrap_or(raw);
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(t) = v.get("title").and_then(|t| t.as_str()) {
            return clean_title(t);
        }
    }
    // Loose scan: a fenced or prefixed JSON payload a strict parse rejected.
    if let Some(i) = body.find("\"title\"") {
        let rest = &body[i + 7..];
        if let Some(start) = rest.find(':') {
            let after = rest[start + 1..].trim_start();
            if let Some(inner) = after.strip_prefix('"') {
                if let Some(end) = inner.find('"') {
                    let tok = inner[..end].replace("\\\"", "\"").replace("\\\\", "\\");
                    return clean_title(&tok);
                }
                return None; // truncated structured output: not a title
            }
        }
    }
    // Truncated JSON is never a title even as prose (`{"title` / an unclosed fence).
    if body.starts_with("{\"") || body.starts_with("[\"") || body.starts_with("[{") {
        return None;
    }
    clean_title(&first_line(strip_title_prefix(body)))
}

/// Normalise a model-produced title (strip quotes/prefix/trailing punctuation, cap the length).
pub fn clean_title(raw: &str) -> Option<String> {
    let collapsed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let t = strip_title_prefix(&collapsed).trim_matches(['"', '\'', '`']).trim_end_matches(['.', '!', ',', ';', ':']).trim();
    if t.is_empty() {
        return None;
    }
    let t: String = t.chars().take(MAX_TITLE_CHARS).collect();
    Some(t).filter(|t| !t.is_empty())
}

/// Reject a title that ignores the task: an answer-shaped blob or one of the prompt's examples.
pub fn plausible(title: &str) -> bool {
    let words = title.split_whitespace().count();
    if words == 0 || words > MAX_TITLE_WORDS {
        return false;
    }
    let normalized = title.trim_matches(|c: char| !c.is_alphanumeric()).to_lowercase();
    !EXAMPLE_ECHO.contains(&normalized.as_str())
}

/// Model call + parse + guards in one place: the usable title, or an error worth ignoring.
pub fn from_reply(raw: &str) -> Result<String, String> {
    let title = parse_title(raw).ok_or("the model returned no usable title")?;
    if !plausible(&title) {
        return Err(format!("rejected title `{title}` (answer-shaped or one of the prompt's examples)"));
    }
    Ok(title)
}

/// The title seam plus the in-flight guard: one generation per session at a time.
pub struct Titles {
    kernel: Weak<crate::kernel::Runtime>,
    seam: RwLock<Option<Titler>>,
    busy: Mutex<std::collections::HashSet<String>>,
}

impl Titles {
    pub fn new(kernel: Weak<crate::kernel::Runtime>, seam: Option<Titler>) -> Titles {
        Titles { kernel, seam: RwLock::new(seam), busy: Mutex::new(Default::default()) }
    }

    /// Replace the generator (tests, custom hosts).
    pub fn set_titler(&self, t: Option<Titler>) {
        *self.seam.write().unwrap() = t;
    }

    /// Ask for a title. Uses the injected seam when there is one (it receives the built input),
    /// else `Kernel::sample` on `[model.tasks] title_generation` (aux model).
    pub fn generate(&self, user: &str, assistant: &str, language: &str) -> Result<String, String> {
        if !is_titleable(user) {
            return Err("nothing to title".into());
        }
        let input = build_input(user, assistant);
        let system = prompt(language);
        if let Some(f) = self.seam.read().unwrap().clone() {
            return f(&input);
        }
        let k = self.kernel.upgrade().ok_or("kernel is gone")?;
        let model = k.cfg_now().task_model("title_generation").to_string();
        let (m, _, _) = k.sample(Some(&model), &system, vec![Message::user(input)], vec![], TITLE_MAX_TOKENS, &Cancel::new())?;
        Ok(m.text())
    }

    fn claim(&self, session: &str) -> bool {
        self.busy.lock().unwrap().insert(session.to_string())
    }
    fn release(&self, session: &str) {
        self.busy.lock().unwrap().remove(session);
    }
}

/// The title a session carries right now, if any.
fn current_title(k: &Kernel, session: &str) -> Option<String> {
    k.store.read(session).ok().map(|e| project(&e).title).unwrap_or_default().filter(|t| !t.trim().is_empty())
}

fn titled(k: &Kernel, session: &str) -> bool {
    current_title(k, session).is_some()
}

/// Write `title` unless the session carries a name of its own, retrying while a running turn holds
/// the log (the store's write lock has a 1.5 s deadline). `replace` lists the titles this call may
/// overwrite ("" = the empty title): anything else means a person named the session, and we stop.
/// Never blocks the turn — this always runs on the background thread.
fn write_title(k: &Kernel, session: &str, title: &str, replace: &[&str]) -> bool {
    let deadline = Instant::now() + PERSIST_BUDGET;
    loop {
        match current_title(k, session) {
            Some(cur) if cur == title => return true,
            Some(cur) if !replace.contains(&cur.as_str()) => return false,
            _ => {}
        }
        let _ = k.set_title(session, title);
        if current_title(k, session).as_deref() == Some(title) {
            return true; // the write landed now; no need to wait out the lock window
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The `turn_end` body. Naming happens on its own thread, so the turn never waits on it:
/// the instant title (a slice of the user's words, cannot fail) lands first and the aux-model
/// title replaces it a moment later (Hermes stages 1 and 2, with `derived < llm < user`).
pub fn after_turn(host: &Host, session: &str, user: &str, assistant: &str, ok: bool) {
    if !ok || session.trim().is_empty() || !is_titleable(user) {
        return;
    }
    let Some(k) = host.kernel() else { return };
    let cfg = k.cfg_now();
    if !cfg.context.title_generation {
        return;
    }
    // Everything after the instant title is an upgrade of it.
    let upgrade = cfg.context.title_model_upgrade;
    if titled(&k, session) || !host.titles.claim(session) {
        return;
    }
    let (titles, weak) = (host.titles.clone(), host.kernel_weak());
    let (session, user, assistant) = (session.to_string(), user.to_string(), assistant.to_string());
    let language = cfg.context.title_language.clone();
    std::thread::spawn(move || {
        let Some(k) = weak.upgrade() else {
            titles.release(&session);
            return;
        };
        let derived = derive_title(&user);
        if let Some(d) = &derived {
            write_title(&k, &session, d, &[""]);
        }
        if upgrade {
            if let Ok(raw) = titles.generate(&user, &assistant, &language) {
                if let Ok(title) = from_reply(&raw) {
                    // Replace only our own placeholder: a name the person typed meanwhile wins.
                    let replace: Vec<&str> = match derived.as_deref() {
                        Some(d) => vec![d],
                        None => vec![""],
                    };
                    write_title(&k, &session, &title, &replace);
                }
            }
        }
        titles.release(&session);
    });
}

/// `Lifecycle::turn_end` entry point.
pub struct AutoTitle(pub Arc<Host>);

impl Lifecycle for AutoTitle {
    fn name(&self) -> String {
        "ctxhost:titles".into()
    }
    fn turn_end(&self, session: &str, _workspace: &str, user: &str, assistant: &str, ok: bool) {
        after_turn(&self.0, session, user, assistant, ok);
    }
}

/// `/title` with no argument on an untitled session: name it now.
pub fn generate_now(k: &Kernel, titles: &Titles, session: &str, language: &str) -> Result<String, String> {
    let events = k.store.read(session).map_err(|e| e.to_string())?;
    let view = project(&events);
    if let Some(t) = view.title.filter(|t| !t.trim().is_empty()) {
        return Ok(t);
    }
    let user = view.messages.iter().find(|m| m.role == seagent_core::Role::User).map(|m| m.text()).unwrap_or_default();
    if !is_titleable(&user) {
        return Err("this session has no title yet and nothing to name it after".into());
    }
    let assistant = view.messages.iter().rev().filter(|m| m.role == seagent_core::Role::Assistant).map(|m| m.text()).next().unwrap_or_default();
    let title = titles.generate(&user, &assistant, language).and_then(|raw| from_reply(&raw)).or_else(|_| derive_title(&user).ok_or_else(|| "could not name this session".to_string()))?;
    k.set_title(session, &title).map_err(|e| e.to_string())?;
    Ok(title)
}
