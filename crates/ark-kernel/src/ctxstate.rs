//! `[context]` config and the kernel's per-session state for the context features
//! (@-references, subdirectory hints, persona, coding posture, titles, verify loop,
//! hook output spill, side questions). One field on `Runtime` holds all of it.

use ark_core::Tool;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, RwLock};

/// `[context]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ContextConfig {
    /// Expand `@file:path[:a-b]`, `@folder:`, `@diff`, `@staged`, `@git:N`, `@url:` in prompts (default true).
    pub references: bool,
    /// Append a subdirectory's AGENTS.md / CLAUDE.md / .cursorrules to the first tool result that
    /// touches it (default true).
    pub subdir_hints: bool,
    /// Load `<config dir>/SOUL.md` as the persona, seeding ark's default on first run (default true).
    pub soul: bool,
    /// Personality overlay: a built-in (helpful, concise, technical, creative, teacher, kawaii,
    /// catgirl, pirate, shakespeare, surfer, noir, uwu, philosopher, hype) or a key of
    /// `personalities` ("" = none).
    pub personality: String,
    /// User-defined personalities (name → prompt text), overriding built-ins by name.
    pub personalities: BTreeMap<String, String>,
    /// Coding posture: auto (code workspace on an interactive surface) | on | off | focus (default auto).
    #[serde(deserialize_with = "flex")]
    pub coding_context: String,
    /// Extra workflow rules appended to the coding brief.
    pub coding_instructions: String,
    /// One-line Python toolchain probe in the environment section (default true).
    pub environment_probe: bool,
    /// Instant title from the first message (default true).
    pub title_generation: bool,
    /// Upgrade it with an aux-model title in the background (default true).
    pub title_model_upgrade: bool,
    /// Title language ("" = the user's language).
    pub title_language: String,
    /// Edit → verify-before-finish nudge: off | on | auto (auto = not on messaging channels). Default off.
    #[serde(deserialize_with = "flex")]
    pub verify_on_stop: String,
    /// Bound on pre_verify continue directives per turn (default 3).
    pub max_verify_nudges: u32,
    /// Append the coding clean-up guidance to the verify nudge (default true).
    pub verify_guidance: bool,
    /// `pre_verify` hook commands (Hermes protocol: JSON on stdin; stdout
    /// `{"action":"continue","message":..}` or `{"decision":"block","reason":..}` keeps the turn going).
    pub pre_verify: Vec<String>,
    /// Spill hook-injected context larger than `hook_spill_max_chars` to a file (default true).
    pub hook_spill: bool,
    pub hook_spill_max_chars: usize,
    pub hook_spill_preview_head: usize,
    pub hook_spill_preview_tail: usize,
    /// Spill directory ("" = `<data>/hook_outputs`).
    pub hook_spill_dir: String,
    /// Model for `/btw` ("" = the session's model, main-model-first like Hermes).
    pub side_question_model: String,
}

impl Default for ContextConfig {
    fn default() -> Self {
        ContextConfig {
            references: true,
            subdir_hints: true,
            soul: true,
            personality: String::new(),
            personalities: BTreeMap::new(),
            coding_context: "auto".into(),
            coding_instructions: String::new(),
            environment_probe: true,
            title_generation: true,
            title_model_upgrade: true,
            title_language: String::new(),
            verify_on_stop: "off".into(),
            max_verify_nudges: 3,
            verify_guidance: true,
            pre_verify: vec![],
            hook_spill: true,
            hook_spill_max_chars: 10_000,
            hook_spill_preview_head: 500,
            hook_spill_preview_tail: 500,
            hook_spill_dir: String::new(),
            side_question_model: String::new(),
        }
    }
}

/// Accept `true` / `false` as well as strings for tri-state keys.
fn flex<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum V {
        B(bool),
        S(String),
    }
    Ok(match V::deserialize(d)? {
        V::B(true) => "on".into(),
        V::B(false) => "off".into(),
        V::S(s) => s.trim().to_lowercase(),
    })
}

/// URL fetcher for `@url:` (host-injected; the default does a plain GET).
pub type UrlFetcher = Arc<dyn Fn(&str) -> Result<String, String> + Send + Sync>;

/// A `pre_verify` gate (Hermes plugin hook): after code edits, return a message to keep the
/// turn going one more round. Arguments: (session, workspace, changed paths, attempt, final reply).
pub trait VerifyGate: Send + Sync {
    fn name(&self) -> String;
    fn pre_verify(&self, session: &str, workspace: &str, changed: &[String], attempt: u32, reply: &str) -> Option<String>;
}

#[derive(Default)]
pub struct CtxState {
    pub subdirs: Mutex<HashMap<String, crate::subdir::Tracker>>,
    /// Titles computed off-thread, waiting for the session's writer: (title, source).
    pub titles: Mutex<HashMap<String, (String, String)>>,
    pub url_fetcher: RwLock<Option<UrlFetcher>>,
    pub micro: Mutex<HashMap<String, crate::microcompact::MicroState>>,
    pub verify: Mutex<HashMap<String, crate::verify_loop::TurnState>>,
    pub verify_gates: RwLock<Vec<Arc<dyn VerifyGate>>>,
    /// Tools the active context engine exposes (offered with full schemas while it is active).
    pub engine_tools: RwLock<Vec<Arc<dyn Tool>>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tri_state_keys_accept_bools() {
        let c: ContextConfig = toml::from_str("verify_on_stop = true\ncoding_context = \"OFF\"").unwrap();
        assert_eq!((c.verify_on_stop.as_str(), c.coding_context.as_str()), ("on", "off"));
        let d = ContextConfig::default();
        assert!(d.references && d.subdir_hints && d.title_generation && d.hook_spill);
        assert_eq!((d.hook_spill_max_chars, d.max_verify_nudges, d.verify_on_stop.as_str()), (10_000, 3, "off"));
        assert!(toml::from_str::<ContextConfig>("nope = 1").is_err());
    }
}
