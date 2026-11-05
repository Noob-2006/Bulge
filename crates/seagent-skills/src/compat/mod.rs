//! Ecosystem compatibility (F5/F6): import skills, plugins and MCP servers written for
//! OpenClaw, Hermes or Claude Code into seagent.
//!
//! - [`skill`] — `SKILL.md` frontmatter normalisation (OpenClaw `requires.*` /
//!   `metadata.openclaw.*`, Hermes `platforms` / `metadata.hermes.*`, Claude Code
//!   `allowed-tools` / `disable-model-invocation`) → the keys seagent's
//!   [`crate::skill::Requirements`] reads.
//! - [`cli`] — `seagent skills compat scan|import`, the only writer (it goes through
//!   [`crate::core::confedit`] for config and `<data>/skills|plugins` for files).
//! - plugin and MCP manifests themselves are converted by `seagent_plugin::compat`
//!   (`seagent-plugin/src/compat/`), which this crate calls.

pub mod cli;
pub mod skill;

pub use skill::{normalize, variant, SkillImport};
