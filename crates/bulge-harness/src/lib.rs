//! bulge-harness: the evolvable harness tree.

pub mod eval;
pub mod improve;
pub mod memory;
pub mod profile;
pub mod store;
pub mod tree;
pub mod usage;
pub mod workshop;

pub use eval::{EvalSummary, EvalTask, Judgment, judge_prompt, parse_judgment};
pub use improve::{
    Learning, PROPOSE_LEARNING_PROMPT, ProfileTarget, ProfileUpdate, parse_proposed_learning,
    parse_proposed_lessons, parse_proposed_profile,
};
pub use memory::{Lesson, brief};
pub use profile::{Profile, Section};
pub use store::MemoryStore;
pub use workshop::{SkillDraft, install as install_skill, parse_proposed_skill};
pub use tree::{Problem, Skill, SurfaceSpec, Tree, always_on, materialize, skills, skills_catalog, validate};
pub use usage::{Author, CuratePolicy, Lifecycle, SkillUsage, UsageLedger};
