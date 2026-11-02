//! ark-tools: the builtin tool set. Every tool reports precise effects so the
//! kernel's gates can judge a call without knowing the tool.

mod agent;
mod fs;
mod job;
mod memory;
mod plan;
mod search;
mod shell;
mod util;
mod web;

#[cfg(test)]
mod testutil;

use ark_core::Tool;
use std::sync::Arc;

pub use agent::{AskUser, Spawn};
pub use fs::{preview, Edit, Patch, Read, Write};
pub use job::Job;
pub use memory::Memory;
pub use plan::{Skill, Todo};
pub use search::{Glob, Grep};
pub use shell::Shell;
pub use web::WebFetch;

pub fn builtin_tools() -> Vec<Arc<dyn Tool>> {
    vec![
        Arc::new(Read),
        Arc::new(Write),
        Arc::new(Edit),
        Arc::new(Patch),
        Arc::new(Glob),
        Arc::new(Grep),
        Arc::new(Shell),
        Arc::new(WebFetch),
        Arc::new(Memory),
        Arc::new(Spawn),
        Arc::new(AskUser),
        Arc::new(Todo),
        Arc::new(Skill),
        Arc::new(Job),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn names_unique_and_schemas_are_objects() {
        let tools = builtin_tools();
        let names: HashSet<_> = tools.iter().map(|t| t.spec().name).collect();
        assert_eq!(names.len(), tools.len());
        for t in &tools {
            let s = t.spec();
            assert_eq!(s.input_schema["type"], "object", "{}", s.name);
            assert!(!s.description.is_empty());
        }
    }
}
