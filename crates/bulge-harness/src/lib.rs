//! bulge-harness: the evolvable harness tree.

pub mod eval;
pub mod improve;
pub mod memory;
pub mod profile;
pub mod tree;
pub mod usage;
pub mod workshop;

pub use eval::{EvalSummary, EvalTask, Judgment, judge_prompt, parse_judgment};
pub use improve::{
    PROPOSE_LESSONS_PROMPT, PROPOSE_PROFILE_PROMPT, ProfileTarget, ProfileUpdate,
    parse_proposed_lessons, parse_proposed_profile,
};
pub use memory::{Lesson, brief, retrieve};
pub use profile::{Profile, Section};
pub use workshop::{PROPOSE_SKILL_PROMPT, SkillDraft, install as install_skill, parse_proposed_skill};
pub use tree::{Problem, Skill, SurfaceSpec, Tree, always_on, materialize, skills, skills_catalog, validate};
pub use usage::{Author, CuratePolicy, Lifecycle, SkillUsage, UsageLedger};
