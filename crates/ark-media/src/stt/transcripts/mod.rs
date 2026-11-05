//! Meeting / call transcripts (OpenClaw `src/transcripts/*`,
//! `src/agents/tools/transcripts-tool*.ts`): capture sessions from transcript
//! source providers, a durable store, deterministic (or model-written) notes, and
//! the `transcripts` tool (start, stop, status, import, summarize, list, show).
//!
//! Store: `<ark home>/transcripts/<YYYY-MM-DD>/<session id>/` with `session.json`,
//! `utterances.jsonl`, `summary.json` and `notes.md`. A session's selector is
//! `<date>/<session id>`.
//!
//! Source providers ([`TranscriptSource`]): `manual-transcript` (pasted text, built
//! in), `audio-file` (an audio recording, transcribed with [`crate::stt`]),
//! `microphone` (live local capture: utterances are cut by the voice-mode silence
//! detector and transcribed one by one), `discord-voice` (a Discord voice channel,
//! through the `ark-channel` voice manager installed with
//! [`channel::set_discord_voice`]) and `google-meet` (live Meet captions, read from
//! the meeting bot through [`channel::Captions`]), plus providers registered at
//! runtime with [`register_source`] (Teams, Zoom, phone calls…).
//!
//! ```toml
//! [media.transcripts]
//! enabled = true
//! max_utterances = 2000
//! model_summary = true   # notes written by the agent's model when available (heuristic fallback)
//! ```

pub mod channel;
pub mod sources;
pub mod store;
pub mod summary;
mod tool;

pub use channel::{captions, captions_for, discord_voice, set_captions, set_discord_voice, CaptionLine, CaptionSession, Captions, DiscordVoice};
pub use sources::{register_source, sources, Capture, TranscriptSource};
pub use store::{Session, SourceLocator, Store, Utterance};
pub use tool::list_json;

use crate::Media;
use ark_core::Tool;
use std::sync::Arc;

pub fn enabled(m: &Media) -> bool {
    m.cfg.bool_or("transcripts.enabled", true)
}

pub fn max_utterances(m: &Media) -> usize {
    m.cfg.int_or("transcripts.max_utterances", 2000).max(1) as usize
}

pub fn tools(m: &Arc<Media>) -> Vec<Arc<dyn Tool>> {
    vec![Arc::new(tool::Transcripts { m: m.clone() })]
}

#[cfg(test)]
mod tests;
