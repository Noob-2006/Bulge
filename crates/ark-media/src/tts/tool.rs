//! The `text_to_speech` tool (Hermes `tools/tts_tool.py` + OpenClaw
//! `src/agents/tools/tts-tool.ts`) and the `talk_voice` tool (OpenClaw
//! `extensions/talk-voice/tool.ts`).
//!
//! `text_to_speech` normalizes the text (Markdown, code, URLs, emoji — [`super::normalize`]),
//! resolves provider/voice/persona (call argument → persona → persisted prefs →
//! `[media.tts]`), splits it under the provider's per-request cap without dropping
//! words ([`super::split_text`]), synthesizes every chunk through the provider chain,
//! saves the audio under `output_dir/audio` (or the caller's `output_path`) and returns
//! the `[[audio_as_voice]]` + `MEDIA:<path>` tags the channels turn into an attachment
//! plus the JSON envelope Hermes returns (`success`, `file_path`, `file_paths`,
//! `media_tag`, `provider`, `voice_compatible`, `chunk_count`, …).
//!
//! `talk_voice` is `list`/`set` for the Talk voice (the one `/voice set` and voice mode
//! use); it does not reconnect a live call — the next call picks the voice up.

use super::{prefs, find, max_text_length, split_text, synthesize_chain, TtsRequest};
use crate::store;
use crate::Media;
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Provider/voice/style actually used for one call.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Voice {
    pub provider: String,
    pub voice: Option<String>,
    pub instructions: Option<String>,
    pub speed: Option<f32>,
    /// Persona id that supplied provider/voice/prompt, when any.
    pub persona: Option<String>,
}

/// Audio written by one call.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Spoken {
    pub provider: String,
    pub paths: Vec<PathBuf>,
    pub chunks: usize,
    /// Every chunk came out as a real Ogg/Opus voice note.
    pub voice_compatible: bool,
}

/// The data root used when no tool workspace is available (`/tts audio`, auto replies):
/// `$ARK_HOME`, else `$HOME`, else the temp dir.
pub(crate) fn fallback_workspace() -> PathBuf {
    if let Some(h) = std::env::var_os("ARK_HOME").filter(|h| !h.is_empty()) {
        return PathBuf::from(h);
    }
    if let Some(h) = std::env::var_os("HOME").filter(|h| !h.is_empty()) {
        return PathBuf::from(h);
    }
    std::env::temp_dir()
}

/// `<output_dir>/<kind>` outside a tool call.
pub(crate) fn fallback_out_dir(m: &Media, kind: &str) -> PathBuf {
    m.cfg.output_dir(&fallback_workspace()).join(kind)
}

/// `[media.tts.personas.<id>]` as a table.
pub(crate) fn persona(m: &Media, id: &str) -> Option<toml::Table> {
    m.cfg.get(&format!("tts.personas.{id}")).and_then(|v| v.as_table()).cloned()
}

/// Every configured persona, in config order.
pub(crate) fn personas(m: &Media) -> Vec<(String, toml::Table)> {
    m.cfg.table("tts.personas").into_iter().filter_map(|(id, v)| v.as_table().map(|t| (id, t.clone()))).collect()
}

fn table_str(t: &toml::Table, k: &str) -> Option<String> {
    t.get(k).and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

/// Provider, voice, style and speed for a call: explicit argument, then the active
/// persona, then the persisted preferences, then `[media.tts]`.
pub(crate) fn resolve_voice(m: &Media, provider: Option<&str>, voice: Option<&str>, instructions: Option<&str>, speed: Option<f32>) -> Voice {
    let p = prefs::load(m);
    let persona_id = p.persona.clone();
    let table = persona_id.as_deref().and_then(|id| persona(m, id));
    let pick = |k: &str| table.as_ref().and_then(|t| table_str(t, k));
    let provider = provider
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .or_else(|| pick("provider"))
        .or_else(|| p.provider.clone())
        .unwrap_or_else(|| super::configured_provider(m));
    let provider = if provider == "auto" { super::configured_provider(m) } else { provider };
    Voice {
        provider,
        voice: voice.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).or_else(|| pick("voice")).or_else(|| p.voice.clone()),
        instructions: instructions.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).or_else(|| pick("prompt")),
        speed: speed.or(p.speed),
        persona: table.as_ref().and(persona_id),
    }
}

/// Match a `/voice set` / `talk_voice` query against a provider catalog and return the
/// voice id to store: exact id, then exact id before `" (Name)"`, then name/id contains.
pub(crate) fn pick_voice(catalog: &[String], wanted: &str) -> Option<String> {
    let wanted = wanted.trim();
    if wanted.is_empty() {
        return None;
    }
    let lower = wanted.to_ascii_lowercase();
    let id_of = |entry: &str| entry.split(" (").next().unwrap_or(entry).trim().to_string();
    catalog
        .iter()
        .find(|e| e.as_str() == wanted)
        .or_else(|| catalog.iter().find(|e| id_of(e).eq_ignore_ascii_case(wanted)))
        .or_else(|| catalog.iter().find(|e| e.to_ascii_lowercase().contains(&lower)))
        .map(|e| id_of(e))
}

/// Whether the audio should be delivered as an Ogg/Opus voice bubble.
pub(crate) fn want_voice_note(m: &Media, format: Option<&str>, channel: Option<&str>) -> bool {
    match format.map(|f| f.trim().to_ascii_lowercase()) {
        Some(f) if f == "opus" || f == "ogg" => true,
        Some(_) => false,
        None => match channel.map(|c| c.trim().to_ascii_lowercase()).filter(|c| !c.is_empty()) {
            Some(c) => super::OPUS_VOICE_PLATFORMS.contains(&c.as_str()),
            None => m.cfg.bool_or("tts.voice_notes", false),
        },
    }
}

/// Normalize, chunk under the provider cap, synthesize every chunk and save the audio
/// in `dir` as `stem.<ext>` (or `<stem>-001.<ext>`, … when the text had to be split).
#[allow(clippy::too_many_arguments)]
pub(crate) fn speak_chunks(m: &Media, text: &str, v: &Voice, format: Option<&str>, want_voice: bool, dir: &Path, stem: &str, cancel: &ark_core::Cancel) -> Result<Spoken, String> {
    let spoken = super::normalize(text);
    if spoken.trim().is_empty() {
        return Err("Text is empty after TTS cleanup".into());
    }
    let Some(p) = find(m, &v.provider) else {
        return Err(format!("unknown TTS provider `{}`", v.provider));
    };
    let id = p.id().to_string();
    let chunks = split_text(&spoken, max_text_length(m, &id));
    if chunks.is_empty() {
        return Err("Text is required".into());
    }
    // An explicit provider override opts out of the configured chain, unless it *is* the
    // configured one (then the user's `fallback` list still applies).
    let chain = if id == super::configured_provider(m) { super::chain(m) } else { vec![id.clone()] };
    let mut paths = Vec::new();
    let mut voice_compatible = true;
    for (i, chunk) in chunks.iter().enumerate() {
        let req = TtsRequest { text: chunk.clone(), voice: v.voice.clone(), format: format.map(|f| f.to_ascii_lowercase()), speed: v.speed, instructions: v.instructions.clone(), ..Default::default() };
        let (used, speech) = synthesize_chain(m, &chain, &req, cancel)?;
        let (asset, voice) = super::finalize(m, &used, speech, want_voice, cancel);
        voice_compatible &= voice;
        let name = if chunks.len() > 1 { format!("{stem}-{:03}", i + 1) } else { stem.to_string() };
        paths.push(store::save(dir, &name, &asset)?);
    }
    Ok(Spoken { provider: id, paths, chunks: chunks.len(), voice_compatible })
}

/// `MEDIA:` tag lines plus the JSON envelope (`_media_tag` + the tool result object).
fn envelope(s: &Spoken) -> String {
    let media_tag = store::media_tags(&s.paths, s.voice_compatible);
    let body = serde_json::to_string(&json!({
        "success": true,
        "file_path": s.paths.first().map(|p| p.display().to_string()).unwrap_or_default(),
        "file_paths": s.paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "media_tag": media_tag,
        "provider": s.provider,
        "voice_compatible": s.voice_compatible,
        "chunk_count": s.chunks,
        "delivery_file_count": s.paths.len(),
        "combined_chunks": false,
    }))
    .unwrap_or_else(|_| "{}".into());
    format!("{media_tag}\n{body}")
}

fn failure(e: impl AsRef<str>) -> ToolOutput {
    let e = e.as_ref();
    ToolOutput::err(serde_json::to_string(&json!({"success": false, "error": e})).unwrap_or_else(|_| format!("{{\"success\":false,\"error\":\"{}\"}}", e.replace('"', "'"))))
}

/// Reject `..` components (Hermes `_resolve_output_base`) and control characters.
fn check_output_path(p: &str) -> Result<PathBuf, String> {
    if p.contains('\n') || p.contains('\r') || p.contains('\0') {
        return Err("output_path contains control characters or line separators; use a plain filesystem path".into());
    }
    let path = ark_core::tool::expand_home(p);
    if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Err(format!("output_path contains '..' traversal component: {p}. Use an absolute path or one relative to the workspace without '..'."));
    }
    Ok(path)
}

fn move_file(from: &Path, to: &Path) -> Result<(), String> {
    if let Some(par) = to.parent() {
        std::fs::create_dir_all(par).map_err(|e| format!("{}: {e}", par.display()))?;
    }
    if std::fs::rename(from, to).is_ok() {
        return Ok(());
    }
    std::fs::copy(from, to).map_err(|e| format!("{}: {e}", to.display()))?;
    let _ = std::fs::remove_file(from);
    Ok(())
}

/// `text_to_speech`: speak `text`, save the audio, return the `MEDIA:` tags + JSON.
pub struct TextToSpeech {
    pub m: Arc<Media>,
}

impl TextToSpeech {
    fn output_dir(&self, ctx: &ToolCtx) -> PathBuf {
        self.m.out_dir(ctx, "audio")
    }

    fn run(&self, ctx: &ToolCtx, input: &Value) -> Result<Spoken, String> {
        let text = ark_core::tool::arg_opt_str(input, "text").unwrap_or("");
        if text.trim().is_empty() {
            return Err("Text is required".into());
        }
        let v = resolve_voice(&self.m, ark_core::tool::arg_opt_str(input, "provider"), ark_core::tool::arg_opt_str(input, "voice"), ark_core::tool::arg_opt_str(input, "instructions"), input.get("speed").and_then(|s| s.as_f64()).map(|s| s as f32));
        let format = ark_core::tool::arg_opt_str(input, "format");
        let channel = ark_core::tool::arg_opt_str(input, "channel");
        let explicit = ark_core::tool::arg_opt_str(input, "output_path").map(check_output_path).transpose()?;
        let (dir, stem) = match &explicit {
            Some(p) => (p.parent().filter(|d| !d.as_os_str().is_empty()).map(Path::to_path_buf).unwrap_or_else(|| ctx.workspace.clone()), p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "speech".into())),
            None => (self.output_dir(ctx), store::stem("tts")),
        };
        let want = want_voice_note(&self.m, format, channel);
        let spoken = speak_chunks(&self.m, text, &v, format, want, &dir, &stem, &ctx.cancel)?;
        // A caller path is honoured verbatim for a single chunk; a split keeps numbered files.
        if let (Some(target), 1) = (&explicit, spoken.paths.len()) {
            let mut s = spoken;
            move_file(&s.paths[0], target)?;
            s.paths = vec![target.clone()];
            return Ok(s);
        }
        Ok(spoken)
    }
}

impl Tool for TextToSpeech {
    fn spec(&self) -> ToolSpec {
        let s = |d: &str| json!({"type": "string", "description": d});
        ToolSpec {
            name: "text_to_speech".into(),
            description: "Convert text to speech audio. Returns a MEDIA: path the platform delivers as native audio (a voice bubble on Telegram, Matrix, Feishu, WhatsApp and Signal when the provider can emit Ogg/Opus, a regular attachment otherwise). Text is cleaned of Markdown/code/URLs first, provider-specific per-request caps apply automatically (OpenAI 4096, xAI 15000, MiniMax 10000, ElevenLabs 5k-40k depending on model) and longer input is split into ordered chunks without silent truncation. Voice and provider are user-configured (edge/openai/elevenlabs/… or a command provider under [media.tts.providers.<name>]); only pass provider/voice when the user explicitly asks for one. Use this only for an explicit speak/voice/audio request, never for an ordinary text reply.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "text": s("The text to convert to speech."),
                    "output_path": s("Optional file path for the audio (defaults to <output_dir>/audio/tts-<timestamp>.mp3)."),
                    "speed": {"type": "number", "minimum": 0.25, "maximum": 4.0, "description": "Playback speed multiplier (1.0 = normal). Overrides the configured speed."},
                    "instructions": s("Optional voice-design guidance (tone, emotion, pacing, accent); honoured by OpenAI gpt-4o-mini-tts and compatible servers, ignored elsewhere."),
                    "provider": s("Provider id override (edge, openai, elevenlabs, minimax, gemini, neutts, piper, …). Defaults to the configured provider."),
                    "voice": s("Voice id or name override for this call."),
                    "format": {"type": "string", "enum": ["mp3", "opus", "ogg", "wav", "flac", "aac", "pcm"], "description": "Wanted container; opus/ogg ask for a voice note."},
                    "channel": s("Channel id the audio is for (telegram, matrix, feishu, whatsapp, signal => voice bubble).")
                },
                "required": ["text"]
            }),
            parallel_safe: true,
            idempotent: false,
            pinned: false,
        }
    }

    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let text = ark_core::tool::arg_opt_str(input, "text").unwrap_or("");
        if text.trim().is_empty() {
            return vec![];
        }
        let v = resolve_voice(&self.m, ark_core::tool::arg_opt_str(input, "provider"), ark_core::tool::arg_opt_str(input, "voice"), ark_core::tool::arg_opt_str(input, "instructions"), None);
        let mut fx = Vec::new();
        // Network providers send the text off the machine; local engines and command
        // providers (piper, neutts, kittentts, tts-local-cli, [media.tts.providers.*]) do not.
        if let Some(p) = find(&self.m, &v.provider) {
            if let Some(dest) = p.dest(&self.m) {
                fx.push(Effect::Net { dest, payload: text.to_string() });
            }
        }
        match ark_core::tool::arg_opt_str(input, "output_path").map(check_output_path).transpose() {
            Ok(Some(p)) => fx.push(Effect::Write { path: p }),
            _ => fx.push(Effect::Write { path: self.output_dir(ctx) }),
        }
        fx
    }

    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        match self.run(ctx, &input) {
            Ok(s) => ToolOutput::ok(envelope(&s)),
            Err(e) => failure(e),
        }
    }
}

/// Provider the Talk voice comes from: `[media.talk] provider`, else the persisted
/// `/tts provider`, else the configured TTS provider.
pub(crate) fn talk_provider(m: &Media) -> String {
    m.cfg.str("talk.provider").or_else(|| prefs::load(m).provider).filter(|p| p != "auto").unwrap_or_else(|| super::configured_provider(m))
}

/// The Talk voice in force: persisted `/voice set`, else `[media.talk] voice`.
pub(crate) fn current_talk_voice(m: &Media) -> Option<String> {
    prefs::load(m).talk_voice.or_else(|| m.cfg.str("talk.voice"))
}

/// `talk_voice`: list or set the Talk voice (`/voice set`, voice mode).
pub struct TalkVoice {
    pub m: Arc<Media>,
}

impl TalkVoice {
    /// Provider whose voices the Talk voice is taken from.
    pub(crate) fn provider(&self) -> String {
        talk_provider(&self.m)
    }

    pub(crate) fn current(&self) -> Option<String> {
        current_talk_voice(&self.m)
    }

    fn voices(&self, cancel: &ark_core::Cancel) -> Result<Vec<String>, String> {
        match find(&self.m, &self.provider()) {
            Some(p) => p.voices(&self.m, cancel),
            None => Err(format!("unknown TTS provider `{}`", self.provider())),
        }
    }

    fn run(&self, input: &Value, cancel: &ark_core::Cancel) -> Result<String, String> {
        let action = ark_core::tool::arg_opt_str(input, "action").unwrap_or("").trim().to_ascii_lowercase();
        let provider = self.provider();
        match action.as_str() {
            "list" | "get" | "status" => {
                let listed = self.voices(cancel);
                let (voices, error) = match listed {
                    Ok(v) => (v, Value::Null),
                    Err(e) => (vec![], json!(e)),
                };
                let current = self.current();
                let mut lines = vec![format!("Talk voice: {} ({provider})", current.clone().unwrap_or_else(|| "(unset)".into()))];
                lines.push(format!("- provider: {provider}"));
                lines.push(format!("- voice: {}", current.clone().unwrap_or_else(|| "(unset)".into())));
                for v in voices.iter().take(12) {
                    lines.push(format!("- {v}"));
                }
                if voices.len() > 12 {
                    lines.push(format!("(showing first 12 of {})", voices.len()));
                }
                lines.push("Usage: talk_voice {\"action\":\"set\",\"voice\":\"<id>\"}".into());
                let mut body = json!({
                    "success": true,
                    "provider": provider,
                    "voice": current,
                    "voices": voices,
                    "canChange": true,
                });
                if !error.is_null() {
                    body["error"] = error;
                }
                Ok(format!("{}\n{}", lines.join("\n"), body))
            }
            "set" => {
                let wanted = ark_core::tool::arg_opt_str(input, "voice").map(str::trim).filter(|v| !v.is_empty()).ok_or("voice is required for action=set")?;
                let chosen = match self.voices(cancel) {
                    Ok(v) if !v.is_empty() => pick_voice(&v, wanted),
                    // Offline/unsupported voice lists: accept the id as given.
                    _ => Some(wanted.to_string()),
                };
                let Some(voice) = chosen else {
                    return Err(format!("No voice found for \"{wanted}\". Try: talk_voice {{\"action\":\"list\"}}"));
                };
                prefs::set_talk_voice(&self.m, Some(&voice)).map_err(|e| format!("could not save preferences: {e}"))?;
                Ok(format!("✅ Talk voice set to {voice}\n{}", json!({"success": true, "provider": provider, "voice": voice, "saved": true})))
            }
            "" => Err("missing string argument `action`".into()),
            other => Err(format!("Unknown Talk voice action: {other}")),
        }
    }
}

impl Tool for TalkVoice {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "talk_voice".into(),
            description: "List or change the voice used for spoken Talk sessions and voice mode in this profile. Use list to see the provider, the current voice and the available voice ids; use set with an available voice id to change it. The saved voice applies from the next spoken turn; voice/provider ids are provider-specific.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["list", "set"], "description": "list = show the Talk provider, current voice and voice ids; set = change the Talk voice."},
                    "voice": {"type": "string", "description": "Voice id (or name) from list; required for set."}
                },
                "required": ["action"],
                "additionalProperties": false
            }),
            parallel_safe: true,
            idempotent: false,
            pinned: false,
        }
    }

    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let action = ark_core::tool::arg_opt_str(input, "action").unwrap_or("").to_ascii_lowercase();
        let provider = self.provider();
        let mut fx = Vec::new();
        if matches!(action.as_str(), "list" | "get" | "status" | "set") {
            // `set` verifies the id against the provider's catalog; both may query the vendor.
            if let Some(dest) = find(&self.m, &provider).and_then(|p| p.dest(&self.m)) {
                fx.push(Effect::Net { dest, payload: "tts voice list".into() });
            }
        }
        if action == "set" {
            fx.push(Effect::Write { path: prefs::path(&self.m) });
        }
        fx
    }

    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        match self.run(&input, &ctx.cancel) {
            Ok(text) => ToolOutput::ok(text),
            Err(e) => failure(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{ctx, temp_dir, FakeServer};

    const MP3: &[u8] = b"ID3\x04\x00\x00\x00fake-mp3";

    fn audio_server() -> FakeServer {
        FakeServer::start_raw(|r, _| match r.path.as_str() {
            "/audio/speech" => (200, vec![("content-type".into(), "audio/mpeg".into())], MP3.to_vec()),
            _ => (404, vec![], b"{\"error\":{\"message\":\"nope\"}}".to_vec()),
        })
    }

    fn tool(m: Media) -> TextToSpeech {
        TextToSpeech { m: Arc::new(m) }
    }

    #[test]
    fn speaks_normalizes_and_writes_media_tags() {
        let srv = audio_server();
        let out = temp_dir("tool-speech-out");
        let m = super::super::testkit::media("openai", &srv.url, &format!("provider = \"openai\"\noutput_dir = \"{}\"", out.display()));
        let c = ctx("tool-speech");
        let r = tool(m).call(&c, json!({"text": "# Heading\n\nHello **world**, see https://example.com/x\n\n```rs\nfn main() {}\n```"}));
        assert!(!r.is_error, "{}", r.content);
        let lines: Vec<&str> = r.content.lines().collect();
        let media = lines.iter().find_map(|l| l.strip_prefix("MEDIA:")).expect("MEDIA: line");
        let path = PathBuf::from(media);
        assert!(path.is_file(), "{media}");
        assert_eq!(std::fs::read(&path).unwrap(), MP3);
        assert_eq!(path.extension().unwrap(), "mp3");
        let env: Value = serde_json::from_str(lines.last().unwrap()).unwrap();
        assert_eq!(env["success"], true);
        assert_eq!(env["file_path"].as_str().unwrap(), media);
        assert_eq!(env["provider"], "openai");
        assert_eq!(env["chunk_count"], 1);
        assert_eq!(env["delivery_file_count"], 1);
        assert_eq!(env["voice_compatible"], false);
        // No channel + no voice_notes: a plain attachment, no voice directive.
        assert!(!r.content.contains(crate::store::VOICE_DIRECTIVE));
        let body = srv.requests()[0].json();
        let input = body["input"].as_str().unwrap();
        assert!(input.contains("Hello world"), "{input}");
        assert!(!input.contains('#') && !input.contains("```") && !input.contains("http"), "{input}");
        assert_eq!(body["response_format"], "mp3");
    }

    #[test]
    fn voice_instructions_and_format_reach_the_provider() {
        let srv = audio_server();
        let out = temp_dir("tool-speech-voice");
        let m = super::super::testkit::media("openai", &srv.url, &format!("provider = \"openai\"\noutput_dir = \"{}\"\n[talk]\nprovider = \"openai\"\nvoice = \"nova\"", out.display()));
        let c = ctx("tool-speech-voice");
        let r = tool(m).call(&c, json!({"text": "One short line.", "voice": "onyx", "instructions": "Speak in a cheerful whisper", "speed": 1.5, "format": "wav", "channel": "telegram"}));
        assert!(!r.is_error, "{}", r.content);
        let body = srv.requests()[0].json();
        assert_eq!(body["voice"], "onyx");
        assert_eq!(body["input"], "One short line.");
        assert_eq!(body["instructions"], "Speak in a cheerful whisper");
        assert_eq!(body["speed"], 1.5);
        assert_eq!(body["response_format"], "wav");
    }

    #[test]
    fn long_text_is_chunked_without_losing_words() {
        let srv = audio_server();
        let out = temp_dir("tool-speech-chunks");
        let m = super::super::testkit::media("openai", &srv.url, &format!("provider = \"openai\"\noutput_dir = \"{}\"\n[tts.openai]\nmax_text_length = 40", out.display()));
        let c = ctx("tool-speech-chunks");
        let text = "First sentence here. Second sentence follows. Third one closes the paragraph.";
        let r = tool(m).call(&c, json!({"text": text}));
        assert!(!r.is_error, "{}", r.content);
        let env: Value = serde_json::from_str(r.content.lines().last().unwrap()).unwrap();
        let n = env["chunk_count"].as_u64().unwrap();
        assert!(n >= 3, "{env}");
        let files = env["file_paths"].as_array().unwrap();
        assert_eq!(files.len() as u64, n);
        for f in files {
            assert!(Path::new(f.as_str().unwrap()).is_file());
        }
        let reqs = srv.requests();
        assert_eq!(reqs.len() as u64, n);
        let mut words = Vec::new();
        for req in &reqs {
            let input = req.json()["input"].as_str().unwrap().to_string();
            assert!(input.chars().count() <= 40, "{input}");
            words.extend(input.split_whitespace().map(str::to_string));
        }
        assert_eq!(words, text.split_whitespace().map(str::to_string).collect::<Vec<_>>(), "chunking never drops or reorders words");
        let tags = r.content.lines().filter(|l| l.starts_with("MEDIA:")).count();
        assert_eq!(tags as u64, n, "one MEDIA: line per chunk (the JSON envelope repeats the tag field)");
    }

    #[test]
    fn output_path_is_honoured_and_traversal_rejected() {
        let srv = audio_server();
        let m = super::super::testkit::media("openai", &srv.url, "provider = \"openai\"");
        let c = ctx("tool-speech-path");
        let target = c.workspace.join("voice").join("memo.mp3");
        let r = tool(m).call(&c, json!({"text": "Saved where I asked.", "output_path": target.display().to_string()}));
        assert!(!r.is_error, "{}", r.content);
        assert_eq!(std::fs::read(&target).unwrap(), MP3);
        let env: Value = serde_json::from_str(r.content.lines().last().unwrap()).unwrap();
        assert_eq!(env["file_path"].as_str().unwrap(), target.display().to_string());

        let bad = tool(super::super::testkit::media("openai", &srv.url, "provider = \"openai\"")).call(&c, json!({"text": "hi", "output_path": "../escape.mp3"}));
        assert!(bad.is_error, "{}", bad.content);
        assert!(bad.content.contains("traversal"), "{}", bad.content);
    }

    #[test]
    fn missing_text_and_unknown_provider_are_json_errors() {
        let out = temp_dir("tool-speech-errors");
        let m = super::super::testkit::media("openai", "http://127.0.0.1:1", &format!("provider = \"openai\"\noutput_dir = \"{}\"", out.display()));
        let c = ctx("tool-speech-errors");
        let empty = tool(m).call(&c, json!({"text": "   "}));
        let m = super::super::testkit::media("openai", "http://127.0.0.1:1", &format!("provider = \"openai\"\noutput_dir = \"{}\"", out.display()));
        assert!(empty.is_error);
        let env: Value = serde_json::from_str(&empty.content).unwrap();
        assert_eq!(env["success"], false);
        assert!(env["error"].as_str().unwrap().contains("Text is required"));

        let unknown = tool(m).call(&c, json!({"text": "hello", "provider": "does-not-exist"}));
        assert!(unknown.is_error);
        assert!(unknown.content.contains("unknown TTS provider"), "{}", unknown.content);
    }

    #[test]
    fn effects_net_only_for_network_providers() {
        let out = temp_dir("tool-speech-effects");
        let m = super::super::testkit::media("openai", "https://api.example.test", &format!("provider = \"openai\"\noutput_dir = \"{}\"", out.display()));
        let c = ctx("tool-speech-effects");
        let fx = TextToSpeech { m: Arc::new(m) }.effects(&c, &json!({"text": "say this"}));
        assert!(fx.iter().any(|e| matches!(e, Effect::Net { dest, payload } if dest.as_str() == "api.example.test" && payload == "say this")), "{fx:?}");
        assert!(fx.iter().any(|e| matches!(e, Effect::Write { .. })), "{fx:?}");

        let m2 = super::super::testkit::media("openai", "https://api.example.test", "[providers.mine]\ncommand = \"true {output_path}\"\n[tts.providers.mine]\ncommand = \"true {output_path}\"");
        let fx2 = TextToSpeech { m: Arc::new(m2) }.effects(&c, &json!({"text": "local only", "provider": "mine"}));
        assert!(!fx2.iter().any(|e| matches!(e, Effect::Net { .. })), "command providers stay on this machine: {fx2:?}");
        assert!(fx2.iter().any(|e| matches!(e, Effect::Write { .. })));
    }

    /// ElevenLabs over a fake server: a three-voice catalog and echo audio.
    fn catalog_server() -> FakeServer {
        FakeServer::start_raw(|r, _| match r.path.as_str() {
            "/v1/voices" => (200, vec![("content-type".into(), "application/json".into())], br#"{"voices":[{"voice_id":"v1","name":"One"},{"voice_id":"v2","name":"Two"},{"voice_id":"speaker-three","name":"Three"}]}"#.to_vec()),
            p if p.starts_with("/v1/text-to-speech/") => (200, vec![("content-type".into(), "audio/mpeg".into())], MP3.to_vec()),
            _ => (404, vec![], b"{\"error\":{\"message\":\"nope\"}}".to_vec()),
        })
    }

    #[test]
    fn talk_voice_lists_and_sets() {
        let srv = catalog_server();
        let out = temp_dir("tool-talkvoice");
        let m = Arc::new(super::super::testkit::media("elevenlabs", &srv.url, &format!("provider = \"elevenlabs\"\noutput_dir = \"{}\"\n[talk]\nprovider = \"elevenlabs\"\nvoice = \"v1\"", out.display())));
        let c = ctx("tool-talkvoice");
        let t = TalkVoice { m: m.clone() };

        let listed = t.call(&c, json!({"action": "list"}));
        assert!(!listed.is_error, "{}", listed.content);
        assert!(listed.content.contains("v1") && listed.content.contains("speaker-three"), "{}", listed.content);

        let set = t.call(&c, json!({"action": "set", "voice": "v2"}));
        assert!(!set.is_error, "{}", set.content);
        assert!(set.content.contains("Talk voice set to v2"), "{}", set.content);
        assert_eq!(prefs::load(&m).talk_voice.as_deref(), Some("v2"));
        assert_eq!(super::super::talk_voice(&m).as_deref(), Some("v2"), "voice mode and /voice read the same value");

        // A name match (case-insensitive) stores the bare id; an unknown one is rejected.
        assert!(!t.call(&c, json!({"action": "set", "voice": "Speaker-Three"})).is_error);
        assert_eq!(prefs::load(&m).talk_voice.as_deref(), Some("speaker-three"));
        let bad = t.call(&c, json!({"action": "set", "voice": "zzz"}));
        assert!(bad.is_error);
        assert!(bad.content.contains("No voice found"), "{}", bad.content);
        let unknown_action = t.call(&c, json!({"action": "shout"}));
        assert!(unknown_action.is_error && unknown_action.content.contains("Unknown Talk voice action"));
        assert!(t.call(&c, json!({})).is_error);

        let set_fx = t.effects(&c, &json!({"action": "set", "voice": "v1"}));
        assert!(set_fx.iter().any(|e| matches!(e, Effect::Write { path } if path.ends_with("p.json"))), "{set_fx:?}");
        assert!(set_fx.iter().any(|e| matches!(e, Effect::Net { .. })), "looking the id up queries the provider: {set_fx:?}");
    }
}
