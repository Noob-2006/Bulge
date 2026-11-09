//! `/tts` and `/voice`, plus the channel auto voice reply.
//!
//! `/tts` merges OpenClaw `src/auto-reply/reply/commands-tts.ts` (on/off/status,
//! provider, persona, limit, summary, audio, help) with Hermes' per-profile TTS
//! settings: `voice`, `voices`, `speed` and `auto` (off/always/inbound/tagged).
//! Everything mutable is persisted through [`super::prefs`] (`[media.tts] prefs_path`),
//! never by rewriting the config file, so a chat command can change the profile's
//! choices without a config write.
//!
//! `/voice` merges Hermes' `CommandDef("voice", … [on|off|tts|status])` with
//! OpenClaw's talk-voice command (status/list/set) and points at `seagent voice` for the
//! CLI voice loop.
//!
//! [`auto_reply`] is what an inbound channel calls for every reply: it honours
//! `[media.tts] auto` (persisted `/tts auto`, per-chat override in `extra`), the
//! `[[tts…]]` reply directives, the Talk/voice-message voice-bubble rules and the
//! character cap before synthesizing anything.

use super::{prefs, tool as tts_tool};
use crate::Media;
use seagent_core::Cancel;
use std::path::PathBuf;

/// The surface that runs the command. `chat` (`<channel>:<chat>`, as in `slash::Sender`) is
/// what `/tts chat` and `/voice tts` scope their per-chat override to; `None` = a local
/// surface with no chat behind it (CLI / TUI), where only the profile default applies.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CommandCtx {
    pub chat: Option<String>,
}

impl CommandCtx {
    /// A context scoped to one channel chat.
    pub fn chat(channel: &str, chat: &str) -> Self {
        let c = format!("{}:{}", channel.trim(), chat.trim());
        CommandCtx { chat: (!c.trim_matches(':').is_empty()).then_some(c) }
    }
}

const USAGE: &str = "🔊 TTS commands
- /tts status — show the current settings
- /tts on | off — enable or disable automatic spoken replies
- /tts auto [off|always|inbound|tagged] — when replies are spoken
- /tts provider [id] — show or set the provider (/tts providers lists them)
- /tts voice [id|default] — show or set this provider's voice
- /tts voices [limit] — list the provider's voices
- /tts persona [id|off] — show or set the persona
- /tts personas — list the configured personas
- /tts set <provider> [voice] — set provider and voice at once
- /tts speed [0.25-4.0] — show or set the speaking speed
- /tts limit [100-4096] — auto-reply character limit before summary/truncation
- /tts summary [on|off] — summarize long replies instead of truncating
- /tts audio <text> — speak this text now
- /tts help — this list";

const VOICE_USAGE: &str = "🎙 Voice commands
- /voice status — voice mode, Talk voice and provider
- /voice on | off — arm or disarm voice mode for this profile
- /voice tts [on|off] — read replies aloud
- /voice list [limit] — list the Talk provider's voices
- /voice set <voice> — set the Talk voice
Start the CLI voice loop with `seagent voice` (push-to-talk, `--continuous` for hands-free).";

/// Split `args` into the lowercased action and the untouched remainder.
fn split(args: &str) -> (String, &str) {
    let args = args.trim();
    match args.split_once(char::is_whitespace) {
        Some((a, rest)) => (a.to_ascii_lowercase(), rest.trim()),
        None => (args.to_ascii_lowercase(), ""),
    }
}

fn saved(r: Result<PathBuf, String>, ok: &str) -> String {
    match r {
        Ok(_) => ok.to_string(),
        Err(e) => format!("⚠️ Couldn't update TTS preferences: {e}"),
    }
}

fn provider_label(m: &Media, id: &str) -> String {
    match super::find(m, id) {
        Some(p) if p.configured(m) => format!("{id} (✅ configured)"),
        Some(_) => format!("{id} (❌ not configured)"),
        None => format!("{id} (❌ unknown)"),
    }
}

fn tts_status(m: &Media) -> String {
    let p = prefs::load(m);
    let provider = super::configured_provider(m);
    let auto = prefs::auto_mode(m);
    let voice = p.voice.clone().or_else(|| super::opt(m, &provider, "voice")).unwrap_or_else(|| "(provider default)".into());
    let speed = p.speed.map(|s| format!("{s:.2}")).or_else(|| m.cfg.get("tts.speed").and_then(|v| v.as_float()).map(|f| format!("{f:.2}"))).unwrap_or_else(|| "1.0".into());
    let mut lines = vec![
        "📊 TTS status".to_string(),
        format!("State: {}", if p.enabled(m) { "✅ enabled" } else { "❌ disabled" }),
        format!("Provider: {}", provider_label(m, &provider)),
        format!("Chain: {}", super::chain(m).join(" → ")),
        format!("Voice: {voice}"),
        format!("Persona: {}", p.persona.clone().unwrap_or_else(|| "none".into())),
        format!("Talk voice: {}", super::talk_voice(m).unwrap_or_else(|| "(unset)".into())),
        format!("Auto replies: {auto}"),
        format!("Text limit: {} chars (hard cap {})", prefs::max_length(m), prefs::MAX_LIMIT),
        format!("Auto-summary: {}", if prefs::summarize(m) { "on" } else { "off" }),
        format!("Speed: {speed}"),
    ];
    if let Some(last) = super::last_attempt() {
        let age = super::unix_now().saturating_sub(last.at);
        let attempts: Vec<String> = last.attempts.iter().map(|a| format!("{}:{}{}", a.provider, if a.ok { "ok" } else { "failed" }, a.error.as_ref().map(|e| format!(" ({e})")).unwrap_or_default())).collect();
        lines.push(format!("Last attempt: {age}s ago, {} chars{}", last.text_len, if attempts.is_empty() { String::new() } else { format!(" — {}", attempts.join(", ")) }));
    }
    lines.join("\n")
}

fn provider_list(m: &Media) -> String {
    let active = super::configured_provider(m);
    let mut lines = vec!["🎙️ TTS providers".to_string()];
    for p in super::providers() {
        let mark = if p.id() == active { " →" } else { "" };
        lines.push(format!("- {}{mark} {}", p.id(), if p.configured(m) { "✅ configured" } else { "❌ not configured" }));
    }
    lines.push(format!("Primary: {active}"));
    lines.push("Usage: /tts provider <id>".into());
    lines.join("\n")
}

fn voices_list(m: &Media, provider: &str, limit: usize) -> String {
    let Some(p) = super::find(m, provider) else {
        return format!("❌ Unknown TTS provider: {provider}.\nUse /tts providers to list the registered providers.");
    };
    match p.voices(m, &Cancel::new()) {
        Ok(v) if v.is_empty() => format!("{provider} has no voice catalog; set any voice id with /tts voice <id>."),
        Ok(v) => {
            let limit = limit.clamp(1, 200);
            let mut lines = vec![format!("🎙️ {provider} voices: {}", v.len())];
            lines.extend(v.iter().take(limit).map(|x| format!("- {x}")));
            if v.len() > limit {
                lines.push(format!("(showing first {limit} of {})", v.len()));
            }
            lines.push("Use /tts voice <id>.".into());
            lines.join("\n")
        }
        Err(e) => format!("⚠️ Couldn't list {provider} voices: {e}"),
    }
}

fn persona_list(m: &Media) -> String {
    let active = prefs::load(m).persona;
    let ps = tts_tool::personas(m);
    if ps.is_empty() {
        return "🎭 No personas configured ([media.tts.personas.<id>] label/provider/voice/prompt).".into();
    }
    let mut lines = vec![format!("🎭 TTS personas (active: {})", active.clone().unwrap_or_else(|| "none".into()))];
    for (id, t) in ps {
        let label = t.get("label").and_then(|v| v.as_str()).map(|l| format!(" ({l})")).unwrap_or_default();
        let provider = t.get("provider").and_then(|v| v.as_str()).map(|p| format!(" provider={p}")).unwrap_or_default();
        let voice = t.get("voice").and_then(|v| v.as_str()).map(|v| format!(" voice={v}")).unwrap_or_default();
        let mark = if active.as_deref() == Some(id.as_str()) { " →" } else { "" };
        lines.push(format!("- {id}{label}{provider}{voice}{mark}"));
    }
    lines.push("Usage: /tts persona <id> | off".into());
    lines.join("\n")
}

fn tts_audio(m: &Media, text: &str) -> String {
    if text.trim().is_empty() {
        return "🎤 Generate audio from text.\n\nUsage: /tts audio <text>\nExample: /tts audio Hello, this is a test!".into();
    }
    let v = tts_tool::resolve_voice(m, None, None, None, None);
    let want = tts_tool::want_voice_note(m, None, None);
    let dir = tts_tool::fallback_out_dir(m, "audio");
    match tts_tool::speak_chunks(m, text, &v, None, want, &dir, &crate::store::stem("tts"), &Cancel::new()) {
        Ok(s) if !s.paths.is_empty() => format!("🔊 Spoken via {}.", s.provider).to_string() + "\n" + &crate::store::media_tags(&s.paths, s.voice_compatible),
        Ok(_) => "⚠️ TTS produced no audio.".into(),
        Err(e) => format!("⚠️ Couldn't create the audio: {e}"),
    }
}

/// `/tts chat [on|off|voice|default|status]` — this chat's override (OpenClaw
/// commands-tts `chat on|off`; Hermes `_auto_tts_enabled_chats` /
/// `_auto_tts_disabled_chats`). Without a chat surface only the profile default exists.
fn tts_chat(m: &Media, rest: &str, c: &CommandCtx) -> String {
    let Some(chat) = c.chat.as_deref() else {
        return format!(
            "🔇 Per-chat TTS overrides need a chat surface (the gateway). This profile speaks: {}.\nChange the default with /tts auto off|always|inbound|tagged.",
            prefs::auto_mode(m)
        );
    };
    let label = match prefs::chat_mode(m, chat).as_deref() {
        Some("off") => "text only",
        Some("voice_only") => "spoken for voice notes only",
        Some(_) => "spoken",
        None => "the profile default",
    };
    match rest.trim().to_ascii_lowercase().as_str() {
        "" | "status" => format!("🔊 TTS in this chat ({chat}): {label}.\nChange with /tts chat on|off|voice|default."),
        "on" | "true" | "yes" => saved(prefs::set_chat_mode(m, chat, Some("all")), &format!("🔊 TTS enabled for this chat ({chat}).")),
        "off" | "false" | "no" => saved(prefs::set_chat_mode(m, chat, Some("off")), &format!("🔇 TTS disabled for this chat ({chat}).")),
        "voice" | "voice_only" => saved(prefs::set_chat_mode(m, chat, Some("voice_only")), &format!("🔊 TTS speaks replies to voice notes in this chat ({chat}).")),
        "default" | "clear" | "reset" => saved(prefs::set_chat_mode(m, chat, None), "✅ Per-chat TTS override cleared; the profile default applies."),
        _ => "Usage: /tts chat [on|off|voice|default|status]".into(),
    }
}

/// `/tts …` — every mutation goes to the persisted preferences.
pub fn tts_command(m: &Media, args: &str, c: &CommandCtx) -> String {
    let (action, rest) = split(args);
    match action.as_str() {
        "" | "status" => tts_status(m),
        "on" => saved(prefs::set_auto(m, "always"), "🔊 TTS enabled."),
        "off" => saved(prefs::set_auto(m, "off"), "🔇 TTS disabled."),
        "help" | "?" | "h" | "-h" | "--help" => USAGE.into(),
        "provider" | "providers" => {
            if rest.is_empty() {
                return provider_list(m);
            }
            let id = rest.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
            if id == "auto" || super::find(m, &id).is_some() {
                saved(prefs::set_provider(m, Some(&id)), &format!("✅ TTS provider set to {id}."))
            } else {
                format!("❌ Unknown TTS provider: {id}.\nUse /tts providers to list the registered providers.")
            }
        }
        "voice" => {
            let id = rest.strip_prefix("set ").unwrap_or(rest).trim();
            if id.is_empty() {
                let provider = super::configured_provider(m);
                let current = prefs::load(m).voice.or_else(|| super::opt(m, &provider, "voice")).unwrap_or_else(|| "(provider default)".into());
                return format!("🎙️ Voice for {provider}: {current}\nList them with /tts voices; set one with /tts voice <id>; clear with /tts voice default.");
            }
            if matches!(id.to_ascii_lowercase().as_str(), "off" | "none" | "default" | "clear") {
                return saved(prefs::set_voice(m, None), "✅ Voice reset to the provider/default voice.");
            }
            saved(prefs::set_voice(m, Some(id)), &format!("✅ TTS voice set to {id}."))
        }
        "voices" => {
            let limit = rest.split_whitespace().next().and_then(|n| n.parse::<usize>().ok()).unwrap_or(20);
            let provider = prefs::load(m).provider.filter(|p| p != "auto").unwrap_or_else(|| super::configured_provider(m));
            voices_list(m, &provider, limit)
        }
        "persona" | "personas" => {
            if rest.is_empty() {
                return persona_list(m);
            }
            let id = rest.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
            if matches!(id.as_str(), "off" | "none" | "default" | "clear") {
                return saved(prefs::set_persona(m, None), "✅ TTS persona disabled.");
            }
            if tts_tool::persona(m, &id).is_none() {
                return format!("❌ Unknown TTS persona: {id}.\nUse /tts personas to list the configured personas.");
            }
            saved(prefs::set_persona(m, Some(&id)), &format!("✅ TTS persona set to {id}."))
        }
        "set" => {
            let mut it = rest.split_whitespace();
            let Some(id) = it.next() else {
                return "Usage: /tts set <provider> [voice]".into();
            };
            let id = id.to_ascii_lowercase();
            if super::find(m, &id).is_none() && id != "auto" {
                return format!("❌ Unknown TTS provider: {id}.\nUse /tts providers to list the registered providers.");
            }
            if let Err(e) = prefs::set_provider(m, Some(&id)) {
                return format!("⚠️ Couldn't update TTS preferences: {e}");
            }
            match it.next() {
                Some(voice) => saved(prefs::set_voice(m, Some(voice)), &format!("✅ TTS provider set to {id}, voice {voice}.")),
                None => format!("✅ TTS provider set to {id}."),
            }
        }
        "speed" => {
            if rest.is_empty() {
                let speed = prefs::load(m).speed.or_else(|| m.cfg.get("tts.speed").and_then(|v| v.as_float()).map(|f| f as f32)).unwrap_or(1.0);
                return format!("⏩ TTS speed: {speed:.2}.\nRange 0.25-4.0; change with /tts speed <value>.");
            }
            match rest.split_whitespace().next().unwrap_or("").parse::<f32>() {
                Ok(s) => saved(prefs::set_speed(m, s), &format!("✅ TTS speed set to {s:.2}.")),
                Err(_) => "❌ Speed must be a number between 0.25 and 4.0.".into(),
            }
        }
        "auto" => {
            if rest.is_empty() {
                return format!(
                    "🔁 TTS auto replies: {}.\n- off: never speak replies\n- always: speak every reply\n- inbound: speak only replies to voice messages\n- tagged: speak only replies carrying a [[tts]] directive\nChange with /tts auto <mode>.",
                    prefs::auto_mode(m)
                );
            }
            let mode = rest.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
            saved(prefs::set_auto(m, &mode), &format!("✅ TTS auto mode set to {mode}."))
        }
        "limit" => {
            if rest.is_empty() {
                return format!(
                    "📏 TTS limit: {} characters.\nText longer than this is summarized (when /tts summary is on) or truncated.\nRange: {}-{}.\nChange with /tts limit <number>.",
                    prefs::max_length(m),
                    prefs::MIN_LIMIT,
                    prefs::MAX_LIMIT
                );
            }
            match rest.split_whitespace().next().unwrap_or("").parse::<usize>() {
                Ok(n) => saved(prefs::set_max_length(m, n), &format!("✅ TTS limit set to {n} characters.")),
                Err(_) => format!("❌ Limit must be a number between {} and {} characters.", prefs::MIN_LIMIT, prefs::MAX_LIMIT),
            }
        }
        "summary" | "summarize" => match rest.to_ascii_lowercase().as_str() {
            "" => format!(
                "📝 TTS auto-summary: {}.\nWhen text exceeds {} chars: on = summarized then spoken, off = truncated then spoken.\nChange with /tts summary on|off.",
                if prefs::summarize(m) { "on" } else { "off" },
                prefs::max_length(m)
            ),
            "on" | "true" | "yes" => saved(prefs::set_summarize(m, true), "✅ TTS auto-summary enabled."),
            "off" | "false" | "no" => saved(prefs::set_summarize(m, false), "❌ TTS auto-summary disabled."),
            _ => USAGE.into(),
        },
        "audio" | "say" => tts_audio(m, rest),
        "chat" => tts_chat(m, rest, c),
        "latest" | "read" => "🎤 /tts latest needs the session transcript (gateway surface only); use /tts audio <text>.".into(),
        _ => USAGE.into(),
    }
}

fn voice_status(m: &Media, c: &CommandCtx) -> String {
    let p = prefs::load(m);
    let provider = tts_tool::talk_provider(m);
    let voice = p.talk_voice.clone().or_else(|| m.cfg.str("talk.voice"));
    #[cfg(feature = "personal")]
    let wake = if m.cfg.bool_or("voice.wake_word", false) { crate::voice::wake::phrase(m) } else { "off".into() };
    #[cfg(not(feature = "personal"))]
    let wake = if m.cfg.bool_or("voice.wake_word", false) { "unavailable (build with --features personal)".to_string() } else { "off".into() };
    let mut lines = vec![
        "🎙 Voice status".to_string(),
        format!("Voice mode: {} (start it with `seagent voice`)", if prefs::voice_mode(m) { "✅ enabled" } else { "❌ disabled" }),
        format!("Speak replies: {}", if prefs::voice_tts(m) { "✅ on" } else { "❌ off" }),
    ];
    if let Some(chat) = c.chat.as_deref() {
        let label = match prefs::chat_mode(m, chat).as_deref() {
            Some("off") => "text only",
            Some("voice_only") => "spoken for voice notes only",
            Some(_) => "spoken",
            None => "the profile default",
        };
        lines.push(format!("This chat ({chat}): {label}"));
    }
    lines.push(format!("Talk provider: {provider}"));
    lines.push(format!("Talk voice: {}", voice.clone().unwrap_or_else(|| "(unset — /voice set <id>)".into())));
    lines.push(format!("Wake word: {wake}"));
    lines.push(format!("Listen: {} (stt)", crate::stt::resolve_provider(m)));
    if let Some(t) = m.cfg.get("tts.streaming.min_len").and_then(|v| v.as_integer()) {
        lines.push(format!("Streaming: sentences from {t} chars"));
    }
    lines.push("/voice on|off, /voice tts on|off, /voice list [n], /voice set <voice>".into());
    lines.join("\n")
}

/// `/voice tts on|off`: the profile default plus, on a chat surface, that chat's Hermes
/// `_VOICE_MODES` entry (`all` / `off`).
fn voice_tts_toggle(m: &Media, on: bool, c: &CommandCtx) -> String {
    let mut out = saved(
        prefs::set_voice_tts(m, on),
        if on { "🔊 Voice replies will be spoken." } else { "🔇 Voice replies will be text only." },
    );
    if let Some(chat) = c.chat.as_deref() {
        match prefs::set_chat_mode(m, chat, Some(if on { "all" } else { "off" })) {
            Ok(_) => out.push_str(&format!("\n🔊 Applies to this chat ({chat}).")),
            Err(e) => out.push_str(&format!("\n⚠️ {e}")),
        }
    }
    out
}

fn talk_set(m: &Media, wanted: &str) -> String {
    let provider = tts_tool::talk_provider(m);
    let catalog = super::find(m, &provider).map(|p| p.voices(m, &Cancel::new())).transpose();
    let chosen = match catalog {
        Ok(Some(v)) if !v.is_empty() => tts_tool::pick_voice(&v, wanted),
        _ => Some(wanted.to_string()),
    };
    let Some(voice) = chosen else {
        return format!("❌ No voice found for \"{wanted}\". Try: /voice list");
    };
    saved(prefs::set_talk_voice(m, Some(&voice)), &format!("✅ Talk voice set to {voice}.")) + "\nIt applies from the next spoken turn."
}

/// `/voice …` — Hermes voice-mode toggles merged with OpenClaw talk-voice.
pub fn voice_command(m: &Media, args: &str, c: &CommandCtx) -> String {
    let (action, rest) = split(args);
    match action.as_str() {
        "" | "status" => voice_status(m, c),
        "on" => saved(prefs::set_voice_mode(m, true), "🎙 Voice mode enabled.\nRun `seagent voice` to talk (push-to-talk; `seagent voice --continuous` for hands-free)."),
        "off" => saved(prefs::set_voice_mode(m, false), "🔇 Voice mode disabled."),
        "tts" => match rest.to_ascii_lowercase().as_str() {
            "" => format!("🔊 Voice replies: {}.\nChange with /voice tts on|off.", if prefs::voice_tts(m) { "spoken" } else { "text only" }),
            "on" | "true" | "yes" => voice_tts_toggle(m, true, c),
            "off" | "false" | "no" => voice_tts_toggle(m, false, c),
            _ => VOICE_USAGE.into(),
        },
        "list" | "voices" => {
            let limit = rest.split_whitespace().next().and_then(|n| n.parse::<usize>().ok()).unwrap_or(12);
            let provider = tts_tool::talk_provider(m);
            let Some(p) = super::find(m, &provider) else {
                return format!("❌ Unknown Talk provider: {provider}.\nSet [media.talk] provider.");
            };
            match p.voices(m, &Cancel::new()) {
                Ok(v) if v.is_empty() => format!("{provider} has no voice catalog; set any voice id with /voice set <id>."),
                Ok(v) => {
                    let limit = limit.clamp(1, 200);
                    let mut lines = vec![format!("🎙️ {provider} voices: {}", v.len()), String::new()];
                    lines.extend(v.iter().take(limit).map(|x| format!("- {x}")));
                    if v.len() > limit {
                        lines.push(format!("(showing first {limit})"));
                    }
                    lines.push(String::new());
                    lines.push("Use /voice set <voice>.".into());
                    lines.join("\n")
                }
                Err(e) => format!("⚠️ {provider} voice list failed: {e}"),
            }
        }
        "set" => {
            let wanted = rest.trim();
            if wanted.is_empty() {
                return "Usage: /voice set <voiceId|name>".into();
            }
            talk_set(m, wanted)
        }
        "help" | "?" | "h" | "--help" => VOICE_USAGE.into(),
        _ => VOICE_USAGE.into(),
    }
}

/// Shorten a long reply before synthesis (`/tts summary on`): the agent's own model when
/// one is installed, otherwise the caller falls back to plain truncation.
pub(crate) type Summarizer = fn(&Media, &str, usize, &Cancel) -> Option<String>;

fn configured_summarizer() -> Summarizer {
    summary_hook().lock().unwrap().unwrap_or(default_summarizer)
}

fn summary_hook() -> &'static std::sync::Mutex<Option<Summarizer>> {
    static H: std::sync::OnceLock<std::sync::Mutex<Option<Summarizer>>> = std::sync::OnceLock::new();
    H.get_or_init(|| std::sync::Mutex::new(None))
}

/// Replace the summarizer (tests; the binary leaves the default installed).
#[cfg(test)]
pub(crate) fn set_summarizer(f: Summarizer) {
    *summary_hook().lock().unwrap() = Some(f);
}

/// `[media.tts] summarize` with the agent's model: a spoken-length digest of the reply.
fn default_summarizer(_m: &Media, text: &str, cap: usize, cancel: &Cancel) -> Option<String> {
    let llm = crate::llm()?;
    let system = format!("Rewrite this assistant reply as spoken text of at most {cap} characters: keep the meaning, names and numbers, drop code, lists, links and Markdown, and add no preamble. Reply with the spoken text only.");
    let out = llm.complete(None, &system, vec![seagent_core::Message::user(text)], 400, cancel).ok()?;
    let out = out.trim().to_string();
    (!out.is_empty()).then_some(out)
}

/// The text to speak for a long auto reply: summarized when enabled, else cut.
fn shorten(m: &Media, spoken: &str, cap: usize, cancel: &Cancel) -> String {
    if spoken.chars().count() > cap && prefs::summarize(m) {
        if let Some(s) = configured_summarizer()(m, spoken, cap, cancel) {
            let s = super::normalize(&s);
            if !s.trim().is_empty() {
                return clamp_text(&s, cap);
            }
        }
    }
    clamp_text(spoken, cap)
}

/// Cut `text` to at most `max` characters, preferring a sentence boundary.
fn clamp_text(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let head: String = text.chars().take(max).collect();
    match head.rfind(['.', '!', '?', ';', ':']) {
        Some(i) if i >= max / 2 => head[..=i].trim().to_string(),
        _ => head.trim_end().to_string(),
    }
}

/// Spoken reply for a channel: `None` when this reply stays text-only.
///
/// `chat` is the chat key (`<channel>:<chat>`) whose `/tts chat` / `/voice tts` override
/// wins over the profile's `[media.tts] auto` (Hermes `_voice_mode`); a `[[tts…]]`
/// directive in `text` chooses the provider/voice and the spoken text, and forces speech
/// unless auto is off. Returns the audio file and whether to send it as a voice bubble.
pub(crate) fn auto_reply(m: &Media, text: &str, inbound_voice: bool, channel: &str, chat: Option<&str>, cancel: &Cancel) -> Option<(PathBuf, bool)> {
    if text.trim().is_empty() {
        return None;
    }
    let d = super::normalize::parse_directives(text);
    let mode = chat.and_then(|c| prefs::auto_for_chat(m, c)).unwrap_or_else(|| prefs::auto_mode(m));
    let forced = d.has_directive || d.tts_text.is_some();
    let should = match mode.as_str() {
        "off" => false,
        "always" => true,
        "inbound" => inbound_voice,
        "tagged" => forced,
        _ => false,
    };
    if !should {
        return None;
    }
    let body = d.tts_text.clone().filter(|t| !t.trim().is_empty()).unwrap_or_else(|| d.cleaned.clone());
    let spoken = super::normalize(&body);
    if spoken.trim().is_empty() {
        return None;
    }
    let v = tts_tool::resolve_voice(m, d.provider.as_deref(), d.voice.as_deref(), None, d.speed);
    let cap = prefs::max_length(m).min(super::max_text_length(m, &v.provider)).max(1);
    let capped = shorten(m, &spoken, cap, cancel);
    let channel = channel.trim().to_ascii_lowercase();
    let want_voice = inbound_voice || super::OPUS_VOICE_PLATFORMS.contains(&channel.as_str()) || m.cfg.bool_or("tts.voice_notes", false);
    let dir = tts_tool::fallback_out_dir(m, "audio");
    match tts_tool::speak_chunks(m, &capped, &v, None, want_voice, &dir, &crate::store::stem("reply"), cancel) {
        Ok(s) => s.paths.first().map(|p| (p.clone(), s.voice_compatible)),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeServer};
    use serde_json::Value;

    /// A `Media` whose output dir and prefs file live in a fresh temp dir; `base` is the
    /// fake server for the provider `id` (`[providers.<id>] api_key/base_url`).
    fn media_for(id: &str, base: &str, tag: &str, extra: &str) -> Media {
        let dir = temp_dir(tag);
        // TOML literal strings: a Windows path's `\` is not an escape there.
        let cfg = format!("output_dir = '{}'\n[tts]\nprefs_path = '{}'\n{extra}", dir.join("media").display(), dir.join("p.json").display());
        Media { cfg: crate::testutil::cfg_for(id, base, &cfg), http: Default::default() }
    }

    fn media_at(base: &str, tag: &str, extra: &str) -> Media {
        media_for("openai", base, tag, extra)
    }

    fn cfg(tag: &str, extra: &str) -> Media {
        media_at("http://127.0.0.1:1", tag, extra)
    }

    fn opus() -> Vec<u8> {
        let mut v = b"OggS".to_vec();
        v.resize(28, 0);
        v.extend_from_slice(b"OpusHead");
        v.extend_from_slice(b"\x01\x02fake-opus");
        v
    }

    #[test]
    fn status_on_off_and_auto() {
        let m = cfg("cmd-status", "provider = \"openai\"\n[talk]\nprovider = \"openai\"\nvoice = \"nova\"");
        let c = CommandCtx::default();
        let s = tts_command(&m, "", &c);
        assert!(s.contains("📊 TTS status"), "{s}");
        assert!(s.contains("Provider: openai (✅ configured)"), "{s}");
        assert!(s.contains("State: ❌ disabled"), "{s}");
        assert!(s.contains("Text limit: 1500"), "{s}");

        assert!(tts_command(&m, "on", &c).contains("TTS enabled"));
        assert_eq!(prefs::auto_mode(&m), "always");
        assert!(tts_command(&m, "status", &c).contains("State: ✅ enabled"));
        assert!(tts_command(&m, "off", &c).contains("TTS disabled"));
        assert_eq!(prefs::auto_mode(&m), "off");

        assert!(tts_command(&m, "auto inbound", &c).contains("auto mode set to inbound"));
        assert_eq!(prefs::auto_mode(&m), "inbound");
        assert!(tts_command(&m, "auto", &c).contains("inbound: speak only replies to voice messages"));
        let bad = tts_command(&m, "auto loudly", &c);
        assert!(bad.contains("Couldn't update TTS preferences") && bad.contains("unknown TTS auto mode"), "{bad}");
        assert_eq!(prefs::auto_mode(&m), "inbound", "a rejected mode changes nothing");
    }

    #[test]
    fn provider_voice_and_voices() {
        let m = cfg("cmd-provider", "provider = \"openai\"");
        let c = CommandCtx::default();
        let list = tts_command(&m, "providers", &c);
        assert!(list.contains("Primary: openai") && list.contains("edge"), "{list}");
        assert!(list.contains("- openai → ✅ configured"), "the active provider is marked: {list}");

        let unknown = tts_command(&m, "provider nope", &c);
        assert!(unknown.contains("Unknown TTS provider: nope"), "{unknown}");
        assert_eq!(prefs::load(&m).provider, None);

        assert!(tts_command(&m, "provider edge", &c).contains("provider set to edge"));
        assert_eq!(prefs::load(&m).provider.as_deref(), Some("edge"));
        assert!(tts_command(&m, "status", &c).contains("Provider: edge"));
        // Auto-detection is spelled like OpenClaw's.
        assert!(tts_command(&m, "provider auto", &c).contains("provider set to auto"));

        assert!(tts_command(&m, "voice nova", &c).contains("voice set to nova"));
        assert_eq!(prefs::load(&m).voice.as_deref(), Some("nova"));
        assert!(tts_command(&m, "voice", &c).contains("Voice for"));
        assert!(tts_command(&m, "voice default", &c).contains("reset"));
        assert_eq!(prefs::load(&m).voice, None);

        let voices = tts_command(&m, "voices", &c);
        assert!(voices.contains("alloy") && voices.contains("voices:"), "{voices}");
        assert!(tts_command(&m, "voices 2", &c).contains("showing first 2"));

        assert!(tts_command(&m, "set openai onyx", &c).contains("provider set to openai, voice onyx"));
        let p = prefs::load(&m);
        assert_eq!((p.provider.as_deref(), p.voice.as_deref()), (Some("openai"), Some("onyx")));
        assert!(tts_command(&m, "set", &c).contains("Usage: /tts set"));
    }

    #[test]
    fn persona_speed_limit_and_summary() {
        let m = cfg("cmd-persona", "provider = \"openai\"\n[tts.personas.narrator]\nlabel = \"Narrator\"\nprovider = \"openai\"\nvoice = \"onyx\"\nprompt = \"Calm.\"\n[tts.personas.coach]\nlabel = \"Coach\"");
        let c = CommandCtx::default();
        let list = tts_command(&m, "personas", &c);
        assert!(list.contains("narrator (Narrator) provider=openai voice=onyx"), "{list}");
        assert!(list.contains("coach"), "{list}");
        assert!(tts_command(&m, "persona narrator", &c).contains("persona set to narrator"));
        assert_eq!(prefs::load(&m).persona.as_deref(), Some("narrator"));
        assert!(tts_command(&m, "personas", &c).contains("narrator (Narrator) provider=openai voice=onyx →"), "active persona marked");
        assert!(tts_command(&m, "persona nobody", &c).contains("Unknown TTS persona: nobody"));
        assert!(tts_command(&m, "persona off", &c).contains("persona disabled"));
        assert_eq!(prefs::load(&m).persona, None);

        assert!(tts_command(&m, "speed 1.5", &c).contains("speed set to 1.50"));
        assert_eq!(prefs::load(&m).speed, Some(1.5));
        assert!(tts_command(&m, "speed", &c).contains("TTS speed: 1.50"));
        assert!(tts_command(&m, "speed 9", &c).contains("Couldn't update"));
        assert!(tts_command(&m, "speed fast", &c).contains("Speed must be a number"));

        assert!(tts_command(&m, "limit 800", &c).contains("limit set to 800"));
        assert_eq!(prefs::max_length(&m), 800);
        assert!(tts_command(&m, "limit 5", &c).contains("Couldn't update"));
        assert!(tts_command(&m, "summary off", &c).contains("auto-summary disabled"));
        assert!(!prefs::summarize(&m));
        assert!(tts_command(&m, "summary on", &c).contains("auto-summary enabled"));
    }

    #[test]
    fn audio_command_speaks_into_a_media_tag() {
        let srv = FakeServer::start_raw(|r, _| match r.path.as_str() {
            "/audio/speech" => (200, vec![("content-type".into(), "audio/mpeg".into())], b"ID3\x04cmd-audio".to_vec()),
            _ => (404, vec![], b"{}".to_vec()),
        });
        let m = media_at(&srv.url, "cmd-audio", "provider = \"openai\"");
        let out = tts_command(&m, "audio Hello from the slash command.", &CommandCtx::default());
        assert!(out.contains("MEDIA:"), "{out}");
        let path = PathBuf::from(out.lines().find_map(|l| l.strip_prefix("MEDIA:")).unwrap());
        assert!(path.is_file());
        assert_eq!(std::fs::read(&path).unwrap(), b"ID3\x04cmd-audio");
        assert_eq!(srv.requests()[0].json()["input"], "Hello from the slash command.");

        assert!(tts_command(&m, "audio", &CommandCtx::default()).contains("Usage: /tts audio <text>"));
    }

    #[test]
    fn unknown_tts_arguments_show_usage() {
        let m = cfg("cmd-usage", "provider = \"openai\"");
        let out = tts_command(&m, "frobnicate loudly", &CommandCtx::default());
        assert!(out.contains("TTS commands") && out.contains("/tts provider [id]"), "{out}");
        assert!(tts_command(&m, "help", &CommandCtx::default()).contains("TTS commands"));
        assert!(tts_command(&m, "chat on", &CommandCtx::default()).contains("need a chat surface"), "a CLI surface cannot scope a per-chat override");
        // On a chat surface `/tts chat` really sets the per-chat mode.
        let cc = CommandCtx { chat: Some("slack:C1".into()) };
        assert!(tts_command(&m, "chat on", &cc).contains("enabled for this chat"));
        assert_eq!(prefs::chat_mode(&m, "slack:C1").as_deref(), Some("all"));
        assert_eq!(prefs::auto_for_chat(&m, "slack:C1").as_deref(), Some("always"));
        assert!(tts_command(&m, "chat off", &cc).contains("disabled for this chat"));
        assert_eq!(prefs::auto_for_chat(&m, "slack:C1").as_deref(), Some("off"));
        assert!(tts_command(&m, "chat voice", &cc).contains("voice notes"));
        assert_eq!(prefs::auto_for_chat(&m, "slack:C1").as_deref(), Some("inbound"));
        assert!(tts_command(&m, "chat status", &cc).contains("slack:C1"));
        assert!(tts_command(&m, "chat default", &cc).contains("profile default"));
        assert_eq!(prefs::chat_mode(&m, "slack:C1"), None);
    }

    /// ElevenLabs over a fake server: the Talk voice catalog plus echo audio.
    fn catalog_server() -> FakeServer {
        FakeServer::start_raw(|r, _| match r.path.as_str() {
            "/v1/voices" => (200, vec![("content-type".into(), "application/json".into())], br#"{"voices":[{"voice_id":"v1","name":"One"},{"voice_id":"v2","name":"Two"},{"voice_id":"speaker-three","name":"Three"}]}"#.to_vec()),
            p if p.starts_with("/v1/text-to-speech/") => (200, vec![("content-type".into(), "audio/mpeg".into())], b"ID3\x04talk".to_vec()),
            _ => (404, vec![], b"{}".to_vec()),
        })
    }

    #[test]
    fn voice_status_toggles_and_talk_voice() {
        let srv = catalog_server();
        let m = media_for("elevenlabs", &srv.url, "cmd-voice", "provider = \"elevenlabs\"\n[talk]\nprovider = \"elevenlabs\"\nvoice = \"v1\"");
        let c = CommandCtx::default();
        let s = voice_command(&m, "", &c);
        assert!(s.contains("Voice status") && s.contains("Talk provider: elevenlabs"), "{s}");
        assert!(s.contains("Talk voice: v1"), "{s}");
        assert!(s.contains("`seagent voice`"), "points at the CLI loop: {s}");

        assert!(voice_command(&m, "on", &c).contains("Voice mode enabled"));
        assert!(prefs::voice_mode(&m));
        assert!(voice_command(&m, "status", &c).contains("Voice mode: ✅ enabled"));
        assert!(voice_command(&m, "off", &c).contains("Voice mode disabled"));
        assert!(!prefs::voice_mode(&m));

        assert!(voice_command(&m, "tts", &c).contains("Voice replies: spoken"));
        assert!(voice_command(&m, "tts off", &c).contains("text only"));
        assert!(!prefs::voice_tts(&m));
        assert!(voice_command(&m, "tts", &c).contains("Voice replies: text only"));
        assert!(voice_command(&m, "tts maybe", &c).contains("Voice commands"));

        // On a chat surface `/voice tts on|off` also scopes this chat (Hermes `_VOICE_MODES`).
        let cc = CommandCtx { chat: Some("discord:1234".into()) };
        assert!(voice_command(&m, "tts on", &cc).contains("Applies to this chat (discord:1234)"));
        assert_eq!(prefs::chat_mode(&m, "discord:1234").as_deref(), Some("all"));
        assert!(voice_command(&m, "status", &cc).contains("This chat (discord:1234): spoken"));
        assert!(voice_command(&m, "tts off", &cc).contains("Applies to this chat"));
        assert_eq!(prefs::chat_mode(&m, "discord:1234").as_deref(), Some("off"));
        assert!(voice_command(&m, "status", &cc).contains("text only"));

        let list = voice_command(&m, "list 2", &c);
        assert!(list.contains("v1") && list.contains("v2") && list.contains("showing first 2"), "{list}");
        assert!(voice_command(&m, "set v2", &c).contains("Talk voice set to v2"));
        assert_eq!(prefs::load(&m).talk_voice.as_deref(), Some("v2"));
        assert!(voice_command(&m, "set Speaker-Three", &c).contains("Talk voice set to speaker-three"));
        assert_eq!(prefs::load(&m).talk_voice.as_deref(), Some("speaker-three"));
        assert!(voice_command(&m, "set zzz", &c).contains("No voice found"));
        assert!(voice_command(&m, "set", &c).contains("Usage: /voice set"));
        assert!(voice_command(&m, "dance", &c).contains("Voice commands"));
    }

    fn reply_server() -> FakeServer {
        FakeServer::start_raw(|r, _| match r.path.as_str() {
            "/audio/speech" => (200, vec![("content-type".into(), "audio/ogg".into())], opus()),
            _ => (404, vec![], b"{}".to_vec()),
        })
    }

    #[test]
    fn auto_reply_off_inbound_always_and_override() {
        let srv = reply_server();
        let mk = |tag: &str, auto: &str| media_at(&srv.url, tag, &format!("provider = \"openai\"\nauto = \"{auto}\""));

        let cancel = Cancel::new();

        let off = mk("reply-off", "off");
        assert_eq!(auto_reply(&off, "Hello there.", false, "telegram", None, &cancel), None);
        assert_eq!(auto_reply(&off, "Hello there.", true, "telegram", None, &cancel), None);

        let inbound = mk("reply-inbound", "inbound");
        assert!(auto_reply(&inbound, "Text reply.", false, "telegram", None, &cancel).is_none(), "text messages stay text");
        let (path, voice) = auto_reply(&inbound, "Voice reply.", true, "telegram", None, &cancel).expect("inbound voice is spoken");
        assert!(path.is_file());
        assert!(voice, "Ogg/Opus audio is a voice bubble");

        let always = mk("reply-always", "always");
        let (path, _) = auto_reply(&always, "Always spoken.", false, "slack", None, &cancel).expect("always speaks");
        assert!(path.is_file());
        assert_eq!(auto_reply(&always, "   ", false, "slack", None, &cancel), None, "nothing to say");
        // Per-chat override wins over the profile (`/tts chat off`, persisted in prefs).
        prefs::set_chat_mode(&always, "slack:C1", Some("off")).unwrap();
        assert_eq!(auto_reply(&always, "Muted here.", false, "slack", Some("slack:C1"), &cancel), None);
        assert!(auto_reply(&always, "Another chat.", false, "slack", Some("slack:C2"), &cancel).is_some(), "other chats keep the profile mode");
        // `/voice tts on` alone speaks even when no `[media.tts] auto` is configured.
        let bare = media_at(&srv.url, "reply-voice-tts", "provider = \"openai\"");
        prefs::set_voice_tts(&bare, true).unwrap();
        assert!(auto_reply(&bare, "Voice replies on.", false, "slack", None, &cancel).is_some(), "an explicit /voice tts on beats the default off");
        prefs::set_voice_tts(&bare, false).unwrap();
        assert_eq!(auto_reply(&bare, "Voice replies off.", false, "slack", None, &cancel), None);

        // Tagged mode only speaks directives, and a directive forces speech.
        let tagged = mk("reply-tagged", "tagged");
        assert!(auto_reply(&tagged, "Just text.", false, "slack", None, &cancel).is_none());
        let (path, _) = auto_reply(&tagged, "Visible reply [[tts:text]]spoken instead[[/tts:text]]", false, "slack", None, &cancel).expect("directive speaks");
        assert!(path.is_file());
    }

    #[test]
    fn auto_reply_caps_long_text() {
        let srv = reply_server();
        let m = media_at(&srv.url, "reply-cap", "provider = \"openai\"\nauto = \"always\"\nmax_length = 120");
        let long = "This is the first sentence of a rather long reply. This is the second sentence, also long. And here comes a third sentence with even more words in it. Finally a fourth sentence closes the whole thing off properly.";
        let (path, _) = auto_reply(&m, long, false, "slack", None, &Cancel::new()).expect("spoken");
        assert!(path.is_file());
        let reqs = srv.requests();
        assert!(!reqs.is_empty());
        let spoken = reqs[0].json()["input"].as_str().unwrap().to_string();
        assert!(spoken.chars().count() <= 120, "cap respected: {spoken:?} ({} chars)", spoken.chars().count());
        assert!(spoken.ends_with('.'), "cuts at a sentence boundary: {spoken:?}");
        assert_eq!(reqs.len(), 1, "the cap keeps it a single chunk");
    }

    #[test]
    fn auto_reply_respects_directives() {
        let srv = reply_server();
        let m = media_at(&srv.url, "reply-directives", "provider = \"openai\"\nauto = \"always\"");
        let text = "Here is the short version. [[tts:voice=onyx speed=1.5]][[tts:text]]The full spoken version is much longer[[/tts:text]]";
        let (path, _) = auto_reply(&m, text, false, "slack", None, &Cancel::new()).expect("spoken");
        assert!(path.is_file());
        let body: Value = srv.requests()[0].json();
        assert_eq!(body["input"], "The full spoken version is much longer");
        assert_eq!(body["voice"], "onyx");
        assert_eq!(body["speed"], 1.5);
    }

    /// A summarizer that only answers for texts carrying a marker, so the other auto-reply
    /// tests keep the default truncation behaviour even when they run in parallel.
    fn marker_summarizer(_m: &Media, text: &str, cap: usize, _c: &Cancel) -> Option<String> {
        text.contains("SUMMARIZE-ME").then(|| format!("Short version in under {cap} characters."))
    }

    #[test]
    fn auto_reply_summarizes_long_replies_when_enabled() {
        set_summarizer(marker_summarizer);
        let srv = reply_server();
        let long = format!("SUMMARIZE-ME. {} This reply is far too long to speak in full.", "Padding words that go on and on. ".repeat(12));
        let m = media_at(&srv.url, "reply-summary", "provider = \"openai\"\nauto = \"always\"\nmax_length = 120\nsummarize = true");
        let (path, _) = auto_reply(&m, &long, false, "slack", None, &Cancel::new()).expect("spoken");
        assert!(path.is_file());
        let spoken = srv.requests()[0].json()["input"].as_str().unwrap().to_string();
        assert!(spoken.starts_with("Short version in under 120 characters."), "the model summary is spoken: {spoken:?}");
        assert!(spoken.chars().count() <= 120);

        // Summary off: the same reply is truncated instead of summarized.
        let srv2 = reply_server();
        let m2 = media_at(&srv2.url, "reply-no-summary", "provider = \"openai\"\nauto = \"always\"\nmax_length = 120\nsummarize = false");
        auto_reply(&m2, &long, false, "slack", None, &Cancel::new()).expect("spoken");
        let spoken2 = srv2.requests()[0].json()["input"].as_str().unwrap().to_string();
        assert!(!spoken2.starts_with("Short version"), "{spoken2:?}");
        assert!(spoken2.len() <= 120 * 4);
    }

    #[test]
    fn auto_reply_survives_provider_failure() {
        let m = media_at("http://127.0.0.1:1", "reply-fail", "provider = \"openai\"\nauto = \"always\"");
        assert_eq!(auto_reply(&m, "Nobody is listening.", false, "slack", None, &Cancel::new()), None, "a failed synthesis never panics or sends text");
    }

}
