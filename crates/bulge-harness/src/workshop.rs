//! Skill workshop: turn a repeated, successful procedure into a reusable skill
//! file in the harness tree. Where a lesson (see `memory`) is a one-line cue→do,
//! a skill is a named, multi-step procedure the model loads on demand.
//!
//! Like the improver, this is offline and split logic/I-O: the proposal prompt
//! and the parser live here and produce a candidate skill that is *validated
//! against the real tree* before install; the model call and the write to disk
//! are the caller's. A proposal that would not pass `tree::validate` is rejected
//! here, so the workshop never dirties the surface.

use crate::improve::slug;
use crate::tree::{self, SurfaceSpec, Tree};

/// A proposed skill, already named, before it is written into a tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillDraft {
    pub name: String,
    pub description: String,
    pub body: String,
}

impl SkillDraft {
    /// The on-disk `SKILL.md` source: frontmatter (`name`, `description`) then body.
    pub fn to_source(&self) -> String {
        format!("---\nname: {}\ndescription: {}\n---\n{}\n", self.name, self.description.trim(), self.body.trim())
    }

    /// Its path under a surface's skill dir, e.g. `skills/<name>/SKILL.md`.
    pub fn path(&self, spec: &SurfaceSpec) -> String {
        let dir = spec.skill_dir.trim_end_matches('/');
        if dir.is_empty() {
            format!("{}/SKILL.md", self.name)
        } else {
            format!("{dir}/{}/SKILL.md", self.name)
        }
    }
}

/// Parse the model's reply into a draft. `null`, missing fields, or non-JSON all
/// yield `None`. The name is slugged so it is a valid single directory level.
/// The description is capped at 60 chars (the index truncation point), char-safely.
pub fn parse_proposed_skill(reply: &str) -> Option<SkillDraft> {
    let object = extract_json_object(reply)?;
    let value: serde_json::Value = serde_json::from_str(&object).ok()?;
    let field = |key: &str| value.get(key).and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let name = field("name");
    let description = field("description");
    let body = field("body");
    if name.is_empty() || description.is_empty() || body.is_empty() {
        return None;
    }
    let description = if description.chars().count() > 60 {
        description.chars().take(60).collect()
    } else {
        description
    };
    Some(SkillDraft { name: slug(&name), description, body })
}

/// Install a draft into a copy of `tree`, but only if the result still passes
/// `tree::validate` for `spec` (the skill parses, its name matches its directory,
/// and it is actually referenced by the always-on text). Returns the updated tree
/// and the installed path, or the validation problems that blocked it.
///
/// The caller is responsible for the always-on reference: a skill no always-on
/// file names is dead weight, so the workshop refuses to add it until some
/// always-on file mentions the name. This keeps the surface honest.
pub fn install(tree: &Tree, spec: &SurfaceSpec, draft: &SkillDraft) -> Result<(Tree, String), Vec<tree::Problem>> {
    let path = draft.path(spec);
    let mut candidate = tree.clone();
    candidate.insert(path.clone(), draft.to_source());

    // Only judge problems tied to this skill's own path (others pre-existed).
    let problems: Vec<tree::Problem> = tree::validate(&candidate, spec).into_iter().filter(|p| p.path == path).collect();
    if problems.is_empty() {
        Ok((candidate, path))
    } else {
        Err(problems)
    }
}

/// Extract the first balanced top-level `{...}` from text, honouring strings.
pub(crate) fn extract_json_object(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let start = text.find('{')?;
    let mut depth = 0_i32;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, &byte) in bytes.iter().enumerate().skip(start) {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(text[start..=offset].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface() -> SurfaceSpec {
        SurfaceSpec {
            always_on: vec!["systemprompt.md".into()],
            always_on_max: 10_000,
            skill_dir: "skills/".into(),
        }
    }

    #[test]
    fn parses_and_slugs_a_skill() {
        let reply = r#"{"name": "Release Checklist", "description": "when cutting a release", "body": "1. test\n2. tag"}"#;
        let draft = parse_proposed_skill(reply).expect("parses");
        assert_eq!(draft.name, "release-checklist");
        assert_eq!(draft.path(&surface()), "skills/release-checklist/SKILL.md");
        assert!(draft.to_source().starts_with("---\nname: release-checklist\n"));
    }

    #[test]
    fn null_or_incomplete_proposals_are_rejected() {
        assert!(parse_proposed_skill("null").is_none());
        assert!(parse_proposed_skill(r#"{"name": "x", "description": "y"}"#).is_none());
        assert!(parse_proposed_skill("not json").is_none());
    }

    #[test]
    fn truncates_a_long_description_to_sixty_chars() {
        let long = "é".repeat(61);
        let reply = format!(r#"{{"name": "x", "description": "{long}", "body": "steps"}}"#);
        let draft = parse_proposed_skill(&reply).expect("parses");
        assert_eq!(draft.description.chars().count(), 60);
        assert_eq!(draft.description, "é".repeat(60));
    }

    #[test]
    fn install_succeeds_when_the_skill_is_referenced() {
        let mut tree: Tree = Tree::new();
        tree.insert("systemprompt.md".into(), "Use release-checklist before shipping.".into());
        let draft = SkillDraft { name: "release-checklist".into(), description: "when cutting a release".into(), body: "steps".into() };

        let (updated, path) = install(&tree, &surface(), &draft).expect("installs");
        assert_eq!(path, "skills/release-checklist/SKILL.md");
        assert!(updated.contains_key(&path));
        // It really is a valid skill in the updated tree.
        let skills = tree::skills(&updated, &surface()).unwrap();
        assert_eq!(skills.len(), 1);
        assert_eq!(skills[0].name, "release-checklist");
    }

    #[test]
    fn install_refuses_a_skill_nothing_references() {
        let mut tree: Tree = Tree::new();
        tree.insert("systemprompt.md".into(), "Nothing names it.".into());
        let draft = SkillDraft { name: "orphan".into(), description: "never triggered".into(), body: "steps".into() };

        let problems = install(&tree, &surface(), &draft).expect_err("should be refused");
        assert!(problems.iter().any(|p| p.message.contains("dead weight")));
    }
}
