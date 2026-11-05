//! Discord voice → the `transcripts` tool: the media layer's `discord-voice` source
//! (OpenClaw `extensions/discord/src/voice/transcripts-source.ts`) installed on the live
//! voice manager.
//!
//! `seagent-media` owns the transcript source, the session store and the `transcripts` tool, but
//! not the Discord transport (gateway, voice socket, Opus decode, per-utterance STT). The
//! source therefore talks to a narrow back-end trait,
//! [`make_discord_voice`](seagent_media::stt::transcripts::channel::DiscordVoice); this module is
//! the implementation that turns the running [`VoiceManager`] into it, and [`install`] puts it
//! in the process-wide slot. [`crate::discord::Discord::new`] calls [`install`] for every bot
//! that has `[channels.<name>.voice]`, so `transcripts start providerId = "discord-voice"`
//! works against a real voice channel — without it the source could only ever answer
//! "Discord voice manager is not available." outside tests.
//!
//! Every recognized line goes to two places, as it does upstream: the agent (an `Inbound` in
//! the bound text channel) and the transcript taps (`media.transcripts` sessions).

use crate::discord_voice::VoiceManager;
use seagent_media::stt::transcripts::channel::{DiscordVoice, HeardSink};
use seagent_media::stt::transcripts::Capture;
use std::sync::Arc;

/// The live manager as the media layer sees it.
struct Bridge(Arc<VoiceManager>);

impl DiscordVoice for Bridge {
    fn connected(&self, account: &str) -> bool {
        self.0.ready_for_account(account)
    }

    fn capture(&self, account: &str, guild: &str, channel: &str, sink: HeardSink) -> Result<Box<dyn Capture>, String> {
        if !self.connected(account) {
            return Err("Discord voice manager is not available.".into());
        }
        let g = guild.trim().parse::<u64>().map_err(|_| format!("`{guild}` is not a Discord guild id"))?;
        let c = channel.trim().parse::<u64>().map_err(|_| format!("`{channel}` is not a Discord channel id"))?;
        // Lines are tapped from now on: they arrive once the bot sits in that voice channel
        // (`/voice join`, or the agent's own join). Joining is not implied — a transcript
        // session must not drag the bot into a call.
        Ok(self.0.open_transcripts(g, c, sink))
    }
}

/// Install `m` as the media layer's Discord voice backend. The slot is process-wide (upstream
/// has one voice manager per process too); the last channel built wins, which is the bot the
/// operator configured last.
pub fn install(m: Arc<VoiceManager>) {
    seagent_media::stt::transcripts::set_discord_voice(Arc::new(Bridge(m)));
}
