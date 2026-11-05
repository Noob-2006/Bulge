//! ark-tools: the builtin tool set. Every tool reports precise effects so the
//! kernel's gates can judge a call without knowing the tool.

mod agent;
pub mod exec;
mod fs;
pub mod fuzzy;
pub mod patchfmt;
mod extract;
/// Document → text converters (PDF, DOCX, PPTX, XLSX, ODT, HTML, RTF, notebooks…), shared with
/// the memory knowledge index.
pub mod documents {
    pub use crate::extract::{extract, html_text, is_extractable};
}
mod zip;
pub mod data;
pub mod directory;
pub mod forge;
pub mod pro_http;
pub mod filestate;
mod lint;
mod job;
pub mod lsp;
mod memory;
/// DevOps / SRE tools: monitoring queries, controlled deploys, tickets and incidents.
pub mod ops;
mod plan;
pub mod proc;
mod search;
/// Security-operations tools: scan reports, OSV, SIEM alerts, compliance checklists.
pub mod secops;
mod shell;
mod terminal;
pub mod tokenjuice;
mod util;
pub mod web;

#[cfg(test)]
mod testutil;

use ark_core::Tool;
use std::sync::Arc;

pub use agent::{AskUser, Spawn};
pub use filestate::configure_files;
pub use fs::{preview, ApplyPatch, Edit, Patch, Read, Write};
pub use job::Job;
pub use memory::Memory;
pub mod memory_store {
    //! The builtin memory store (MEMORY.md / USER.md) for hosts: limits, scanner hook, approval gate, staged replay.
    pub use crate::memory::{apply_batch, apply_staged, cap_of, find_one, load, path_of, session_tainted, set_limits, set_write_approval, staging_dir, write_approval_enabled, CHAR_CAP, SEP, WRITE_SCANNER};
}
pub use plan::{Skill, Todo};
pub use proc::Proc;
pub use search::{Glob, Grep};
pub use shell::Shell;
pub use terminal::{CloseTerminal, ReadTerminal};
pub use web::WebFetch;

pub fn builtin_tools() -> Vec<Arc<dyn Tool>> {
    let mut tools: Vec<Arc<dyn Tool>> = vec![
        Arc::new(Read),
        Arc::new(Write),
        Arc::new(Edit),
        Arc::new(Patch),
        Arc::new(ApplyPatch),
        Arc::new(Glob),
        Arc::new(Grep),
        Arc::new(Shell),
        Arc::new(Memory),
        Arc::new(Spawn),
        Arc::new(AskUser),
        Arc::new(Todo),
        Arc::new(Skill),
        Arc::new(Job),
        Arc::new(Proc),
        Arc::new(ReadTerminal),
        Arc::new(CloseTerminal),
    ];
    // `web_fetch` / `web_search` / `web_extract` (+ `x_search`, Firecrawl) on the `[web]`
    // defaults; a host with a config replaces these with `web::tools` of the same names.
    tools.extend(web::tools(Arc::new(web::WebConfig::default()), web::http::process_env()));
    tools
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
