//! CLI voice mode (push-to-talk, hands-free, barge-in), microphone capture, wake
//! word and voice transcript filtering. Talk mode lives with realtime voice.
//!
//! Voice mode and the wake word are personal-desktop features: built only with
//! `--features personal` (gen1-306). Microphone capture and the transcript filter stay —
//! live transcription and meetings use them.
#[cfg(feature = "personal")]
pub mod mode;
pub mod record;
pub mod transcript;
#[cfg(feature = "personal")]
pub mod wake;

#[cfg(feature = "personal")]
pub use mode::{requirements, run_cli, voice_mode, VoiceFlags, VoiceModeOpts, VoiceSummary};

use crate::Media;
use ark_core::Tool;
use std::sync::Arc;

pub fn tools(_m: &Arc<Media>) -> Vec<Arc<dyn Tool>> {
    vec![]
}

#[cfg(all(test, feature = "personal"))]
mod tests;
