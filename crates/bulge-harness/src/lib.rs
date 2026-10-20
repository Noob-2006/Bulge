//! bulge-harness: the evolvable harness tree.

pub mod improve;
pub mod memory;
pub mod tree;

pub use improve::{PROPOSE_LESSONS_PROMPT, parse_proposed_lessons};
pub use memory::{Lesson, brief, retrieve};
pub use tree::{Problem, Skill, SurfaceSpec, Tree, materialize, skills, validate};
