//! CLI voice mode (push-to-talk, hands-free, barge-in), microphone capture, wake
//! word and voice transcript filtering. Talk mode lives with realtime voice.
pub mod mode;
pub mod record;
pub mod transcript;
pub mod wake;

pub use mode::{requirements, run_cli, voice_mode, VoiceFlags, VoiceModeOpts, VoiceSummary};

use crate::Media;
use ark_core::Tool;
use std::sync::Arc;

pub fn tools(_m: &Arc<Media>) -> Vec<Arc<dyn Tool>> {
    vec![]
}

#[cfg(test)]
mod tests;
