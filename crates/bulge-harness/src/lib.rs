//! bulge-harness: the evolvable harness tree.

pub mod eval;
pub mod improve;
pub mod memory;
pub mod tree;
pub mod workshop;

pub use eval::{EvalSummary, EvalTask, Judgment, judge_prompt, parse_judgment};
pub use improve::{PROPOSE_LESSONS_PROMPT, parse_proposed_lessons};
pub use memory::{Lesson, brief, retrieve};
pub use workshop::{PROPOSE_SKILL_PROMPT, SkillDraft, parse_proposed_skill};
pub use tree::{Problem, Skill, SurfaceSpec, Tree, materialize, skills, validate};
