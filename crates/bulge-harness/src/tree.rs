//! The harness tree: a map of relative path -> file content, plus a surface
//! spec describing how those files become the model's context. Modelled on
//! Google Harness²'s tree, adapted to bulge's own surface.
//! MARK: M20 — transcribed by dsh; see marks/M20-harness-tree.md.

use std::collections::BTreeMap;

/// Relative path -> UTF-8 content.
pub type Tree = BTreeMap<String, String>;

/// Which files are always in context, the budget, and where skills live.
#[derive(Debug, Clone)]
pub struct SurfaceSpec {
    /// Files concatenated into every request's system prompt, in this order.
    pub always_on: Vec<String>,
    /// Max combined chars of the always-on files (validation fails if exceeded).
    pub always_on_max: usize,
    /// Directory prefix holding skills, e.g. "skills/".
    pub skill_dir: String,
}

impl Default for SurfaceSpec {
    fn default() -> Self {
        Self {
            always_on: vec!["systemprompt.md".into(), "guardrails.md".into(), "memory/MEMORY.md".into(), "tool_guidance.md".into()],
            always_on_max: 24_000,
            skill_dir: "skills/".into(),
        }
    }
}

/// One discovered skill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skill {
    /// Directory name under `skill_dir` (also the required frontmatter `name`).
    pub name: String,
    pub description: String,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub path: String,
    pub message: String,
}

/// Parse all skills under the surface's skill dir (`<skill_dir><name>/SKILL.md`).
/// Each SKILL.md starts with a frontmatter block delimited by `---` lines
/// containing `name:` and `description:`.
pub fn skills(tree: &Tree, spec: &SurfaceSpec) -> Result<Vec<Skill>, Problem> {
    let _ = (tree, spec);
    todo!("M20")
}

/// Validate the tree against the surface. Returns every problem found (not just
/// the first): always-on byte budget; each skill's frontmatter present; skill
/// `name` equals its directory; every skill's name appears in some always-on
/// file (otherwise it is dead weight the model can never trigger).
pub fn validate(tree: &Tree, spec: &SurfaceSpec) -> Vec<Problem> {
    let _ = (tree, spec);
    todo!("M20")
}

/// Build the system prompt: the always-on files concatenated, then an
/// `<available_skills>` index of `name: description` lines (bodies load on
/// demand). Missing always-on files are skipped.
pub fn materialize(tree: &Tree, spec: &SurfaceSpec) -> String {
    let _ = (tree, spec);
    todo!("M20")
}
