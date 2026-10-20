//! bulge-harness: the evolvable harness tree.

pub mod memory;
pub mod tree;

pub use memory::{Lesson, brief, retrieve};
pub use tree::{Problem, Skill, SurfaceSpec, Tree, materialize, skills, validate};
