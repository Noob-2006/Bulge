//! ark-skills: the skills system (discovery with requirement gating, skills_list / skill_view /
//! skill_manage, preprocessing, env setup, skills as slash commands, bundles, linter, ledger,
//! usage, curator, background review), the skills hub (official / GitHub taps / ClawHub /
//! skills.sh / LobeHub / well-known / URL sources, install, update, Skills Guard, AST audit),
//! bundled-skill sync and the optional-mcps / plugin-catalog catalogs with plugin install.
//! Ports of Hermes `tools/skills_*`, `agent/curator.py` … and OpenClaw `src/skills` (both MIT).

pub mod compat;
pub mod core;
pub mod host;
pub mod hub;
pub mod skill;
pub mod yaml;
