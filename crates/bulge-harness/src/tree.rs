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
    /// Max combined bytes of the always-on files (validation fails if exceeded).
    pub always_on_max: usize,
    /// Directory prefix holding skills, e.g. "skills/".
    pub skill_dir: String,
}

impl Default for SurfaceSpec {
    fn default() -> Self {
        Self {
            // User-authored files only. The agent-written profile (memory/MEMORY.md,
            // memory/USER.md) is injected per turn by the runner, not here: it
            // changes after jobs, and the always-on text is the cached prefix.
            always_on: vec!["systemprompt.md".into(), "guardrails.md".into(), "tool_guidance.md".into()],
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

/// The directory prefix under which skill directories live, always ending in
/// `/` (unless it is empty).
fn skill_prefix(spec: &SurfaceSpec) -> String {
    let dir = spec.skill_dir.trim_end_matches('/');
    if dir.is_empty() { String::new() } else { format!("{dir}/") }
}

/// Every `<skill_dir><name>/SKILL.md` entry, as `(directory name, source)`,
/// sorted by directory name.
fn skill_entries<'a>(tree: &'a Tree, spec: &SurfaceSpec) -> Vec<(&'a str, &'a str)> {
    let prefix = skill_prefix(spec);
    let mut found = Vec::new();
    for (path, source) in tree {
        let Some(rest) = path.strip_prefix(&prefix) else {
            continue;
        };
        let Some(name) = rest.strip_suffix("/SKILL.md") else {
            continue;
        };
        // Exactly one directory level: no empty names, no nested paths.
        if name.is_empty() || name.contains('/') {
            continue;
        }
        found.push((name, source.as_str()));
    }
    found.sort_by(|a, b| a.0.cmp(b.0));
    found
}

/// A parsed frontmatter block plus the body that follows it.
struct Frontmatter {
    fields: BTreeMap<String, String>,
    body: String,
}

/// Parse the hand-written frontmatter contract: the source starts with a `---`
/// line, ends the block at the next `---` line, and every non-empty line in
/// between is `key: value` (keys and values trimmed).
fn parse_frontmatter(source: &str) -> Result<Frontmatter, String> {
    let mut fields = BTreeMap::new();
    let mut pos = 0usize;
    let mut first = true;
    let mut body_start = None;

    for line in source.split_inclusive('\n') {
        let raw = line.strip_suffix('\n').unwrap_or(line);
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        let trimmed = raw.trim();

        if first {
            if trimmed != "---" {
                return Err("SKILL.md must start with a `---` frontmatter line".into());
            }
            first = false;
        } else if trimmed == "---" {
            body_start = Some(pos + line.len());
            break;
        } else if !trimmed.is_empty() {
            let Some((key, value)) = trimmed.split_once(':') else {
                return Err(format!("frontmatter line is not `key: value`: {trimmed:?}"));
            };
            let key = key.trim();
            if key.is_empty() {
                return Err("frontmatter line has an empty key".into());
            }
            fields.insert(key.to_string(), value.trim().to_string());
        }
        pos += line.len();
    }

    let Some(body_start) = body_start else {
        return Err("SKILL.md frontmatter is not closed by a `---` line".into());
    };
    Ok(Frontmatter { fields, body: source[body_start..].to_string() })
}

/// Parse one skill source. The skill's name is always its directory name; the
/// frontmatter only has to carry a non-empty `name` and `description`.
fn parse_skill(dir_name: &str, source: &str) -> Result<Skill, String> {
    let frontmatter = parse_frontmatter(source)?;
    let name = frontmatter.fields.get("name").map(String::as_str).unwrap_or("");
    if name.trim().is_empty() {
        return Err("frontmatter needs a non-empty `name:` line".into());
    }
    let description = frontmatter.fields.get("description").map(String::as_str).unwrap_or("");
    if description.trim().is_empty() {
        return Err("frontmatter needs a non-empty `description:` line".into());
    }
    Ok(Skill {
        name: dir_name.to_string(),
        description: description.to_string(),
        body: frontmatter.body,
    })
}

/// Concatenate the always-on files that exist, in spec order.
fn always_on_text(tree: &Tree, spec: &SurfaceSpec) -> String {
    let mut out = String::new();
    let mut first = true;
    for path in &spec.always_on {
        let Some(content) = tree.get(path) else {
            continue;
        };
        if !first {
            out.push_str("\n\n");
        }
        out.push_str(content);
        first = false;
    }
    out
}

/// The `<available_skills>` index, one `name: description` line per skill.
fn skills_block(skills: &[Skill]) -> String {
    let mut out = String::from("<available_skills>\n");
    for skill in skills {
        out.push_str(&skill.name);
        out.push_str(": ");
        out.push_str(&skill.description);
        out.push('\n');
    }
    out.push_str("</available_skills>");
    out
}

/// Parse all skills under the surface's skill dir (`<skill_dir><name>/SKILL.md`).
/// Each SKILL.md starts with a frontmatter block delimited by `---` lines
/// containing `name:` and `description:`.
pub fn skills(tree: &Tree, spec: &SurfaceSpec) -> Result<Vec<Skill>, Problem> {
    let prefix = skill_prefix(spec);
    let mut parsed = Vec::new();
    for (dir_name, source) in skill_entries(tree, spec) {
        let path = format!("{prefix}{dir_name}/SKILL.md");
        match parse_skill(dir_name, source) {
            Ok(skill) => parsed.push(skill),
            Err(message) => return Err(Problem { path, message }),
        }
    }
    Ok(parsed)
}

/// Validate the tree against the surface. Returns every problem found (not just
/// the first): always-on byte budget; each skill's frontmatter present; skill
/// `name` equals its directory; every skill's name appears in some always-on
/// file (otherwise it is dead weight the model can never trigger).
pub fn validate(tree: &Tree, spec: &SurfaceSpec) -> Vec<Problem> {
    let mut problems = Vec::new();
    let prefix = skill_prefix(spec);

    let always_on_bytes: usize = spec
        .always_on
        .iter()
        .filter_map(|path| tree.get(path))
        .map(String::len)
        .sum();
    if always_on_bytes > spec.always_on_max {
        problems.push(Problem {
            path: spec.always_on.first().cloned().unwrap_or_default(),
            message: format!(
                "always-on content is {always_on_bytes} bytes, over the {} byte cap",
                spec.always_on_max
            ),
        });
    }

    let always_on = always_on_text(tree, spec);
    for (dir_name, source) in skill_entries(tree, spec) {
        let path = format!("{prefix}{dir_name}/SKILL.md");
        let frontmatter = match parse_frontmatter(source) {
            Ok(frontmatter) => frontmatter,
            Err(message) => {
                problems.push(Problem { path, message });
                continue;
            }
        };

        match frontmatter.fields.get("name") {
            None => problems.push(Problem {
                path: path.clone(),
                message: format!("frontmatter needs a `name: {dir_name}` line"),
            }),
            Some(name) if name != dir_name => problems.push(Problem {
                path: path.clone(),
                message: format!(
                    "frontmatter `name: {name}` does not match its directory `{dir_name}`"
                ),
            }),
            Some(_) => {}
        }

        match frontmatter.fields.get("description") {
            None => problems.push(Problem {
                path: path.clone(),
                message: "frontmatter needs a `description:` line".into(),
            }),
            Some(description) if description.trim().is_empty() => problems.push(Problem {
                path: path.clone(),
                message: "frontmatter `description:` is empty".into(),
            }),
            Some(_) => {}
        }

        if !always_on.contains(dir_name) {
            problems.push(Problem {
                path,
                message: format!(
                    "skill '{dir_name}' is never named in the always-on text, so the agent \
                     will not know to invoke it — an untriggered skill is dead weight"
                ),
            });
        }
    }

    problems
}

/// Build the system prompt: the always-on files concatenated, then an
/// `<available_skills>` index of `name: description` lines (bodies load on
/// demand). Missing always-on files are skipped.
pub fn materialize(tree: &Tree, spec: &SurfaceSpec) -> String {
    let mut out = always_on(tree, spec);
    let catalog = skills_catalog(tree, spec);
    if !catalog.is_empty() {
        if !out.is_empty() {
            out.push_str("\n\n");
        }
        out.push_str(&catalog);
    }
    out
}

/// The always-on files concatenated in surface order (empty if none exist).
/// This part only changes when the user edits those files, so a runner can use
/// it as the stable system prompt.
pub fn always_on(tree: &Tree, spec: &SurfaceSpec) -> String {
    always_on_text(tree, spec)
}

/// The `<available_skills>` catalog (empty when there are no valid skills). It
/// grows as the skill workshop installs skills, so a runner that cares about the
/// provider prefix cache should place it after the stable system prompt.
pub fn skills_catalog(tree: &Tree, spec: &SurfaceSpec) -> String {
    match skills(tree, spec) {
        Ok(found) if !found.is_empty() => skills_block(&found),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface() -> SurfaceSpec {
        SurfaceSpec {
            always_on: vec!["systemprompt.md".into(), "guardrails.md".into()],
            always_on_max: 1_000,
            skill_dir: "skills/".into(),
        }
    }

    fn tree(entries: &[(&str, &str)]) -> Tree {
        entries
            .iter()
            .map(|(path, content)| ((*path).to_string(), (*content).to_string()))
            .collect()
    }

    const ALPHA: &str = "---\nname: alpha\ndescription: Alpha workflow.\n---\n# Alpha\nDo alpha.\n";
    const BETA: &str = "---\nname: beta\ndescription: Beta workflow.\n---\n# Beta\nDo beta.\n";

    #[test]
    fn normal_tree_parses_validates_and_materializes() {
        let tree = tree(&[
            ("systemprompt.md", "Use `alpha` and `beta` when needed."),
            ("guardrails.md", "Be careful."),
            ("skills/alpha/SKILL.md", ALPHA),
            ("skills/beta/SKILL.md", BETA),
        ]);
        let spec = surface();

        let found = skills(&tree, &spec).expect("skills parse");
        assert_eq!(
            found,
            vec![
                Skill {
                    name: "alpha".into(),
                    description: "Alpha workflow.".into(),
                    body: "# Alpha\nDo alpha.\n".into(),
                },
                Skill {
                    name: "beta".into(),
                    description: "Beta workflow.".into(),
                    body: "# Beta\nDo beta.\n".into(),
                },
            ]
        );
        assert_eq!(validate(&tree, &spec), Vec::new());
        assert_eq!(
            materialize(&tree, &spec),
            "Use `alpha` and `beta` when needed.\n\nBe careful.\n\n\
             <available_skills>\nalpha: Alpha workflow.\nbeta: Beta workflow.\n</available_skills>"
        );
    }

    #[test]
    fn skill_dir_without_trailing_slash_is_accepted() {
        let tree = tree(&[
            ("systemprompt.md", "alpha"),
            ("skills/alpha/SKILL.md", ALPHA),
        ]);
        let spec = SurfaceSpec {
            skill_dir: "skills".into(),
            ..surface()
        };
        let found = skills(&tree, &spec).expect("skills parse");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "alpha");
    }

    #[test]
    fn always_on_over_byte_cap_is_one_problem() {
        let tree = tree(&[("systemprompt.md", "012345"), ("guardrails.md", "ok")]);
        let spec = SurfaceSpec {
            always_on_max: 5,
            ..surface()
        };
        let problems = validate(&tree, &spec);
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].path, "systemprompt.md");
        assert!(problems[0].message.contains("8 bytes"));
        assert!(problems[0].message.contains("5 byte cap"));
    }

    #[test]
    fn byte_cap_counts_bytes_not_chars() {
        // Two chars, four UTF-8 bytes: over a three-byte cap.
        let tree = tree(&[("systemprompt.md", "éé")]);
        let spec = SurfaceSpec {
            always_on_max: 3,
            ..surface()
        };
        let problems = validate(&tree, &spec);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].message.contains("4 bytes"));
    }

    #[test]
    fn frontmatter_name_must_match_directory() {
        let tree = tree(&[
            ("systemprompt.md", "Use alpha."),
            (
                "skills/alpha/SKILL.md",
                "---\nname: other\ndescription: Alpha workflow.\n---\nbody",
            ),
        ]);
        let problems = validate(&tree, &surface());
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].path, "skills/alpha/SKILL.md");
        assert!(problems[0].message.contains("does not match"));
    }

    #[test]
    fn untriggered_skill_is_dead_weight() {
        let tree = tree(&[
            ("systemprompt.md", "Nothing to see here."),
            ("skills/alpha/SKILL.md", ALPHA),
        ]);
        let problems = validate(&tree, &surface());
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].path, "skills/alpha/SKILL.md");
        assert!(problems[0].message.contains("dead weight"));
    }

    #[test]
    fn missing_description_is_a_problem() {
        let tree = tree(&[
            ("systemprompt.md", "Use alpha."),
            ("skills/alpha/SKILL.md", "---\nname: alpha\n---\nbody"),
        ]);
        let spec = surface();

        let err = skills(&tree, &spec).expect_err("missing description must not parse");
        assert_eq!(err.path, "skills/alpha/SKILL.md");
        assert!(err.message.contains("description"));

        let problems = validate(&tree, &spec);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].message.contains("description"));
    }

    #[test]
    fn empty_description_is_a_problem() {
        let tree = tree(&[
            ("systemprompt.md", "Use alpha."),
            (
                "skills/alpha/SKILL.md",
                "---\nname: alpha\ndescription:\n---\nbody",
            ),
        ]);
        let problems = validate(&tree, &surface());
        assert_eq!(problems.len(), 1);
        assert!(problems[0].message.contains("description"));
        assert!(problems[0].message.contains("empty"));
    }

    #[test]
    fn malformed_frontmatter_is_a_problem() {
        let tree = tree(&[
            ("systemprompt.md", "Use alpha."),
            ("skills/alpha/SKILL.md", "name: alpha\ndescription: x\n"),
        ]);
        let problems = validate(&tree, &surface());
        assert_eq!(problems.len(), 1);
        assert!(problems[0].message.contains("must start"));
    }

    #[test]
    fn skills_reports_the_first_parse_error_in_name_order() {
        let tree = tree(&[
            ("skills/alpha/SKILL.md", "---\nname: alpha\ndescription: x\n---\nbody"),
            ("skills/beta/SKILL.md", "---\nname: beta\n---\nbody"),
        ]);
        let err = skills(&tree, &surface()).expect_err("beta has no description");
        assert_eq!(err.path, "skills/beta/SKILL.md");
    }

    #[test]
    fn validate_reports_every_problem() {
        let tree = tree(&[
            ("systemprompt.md", "alpha"),
            (
                "skills/alpha/SKILL.md",
                "---\nname: wrong\ndescription: Alpha workflow.\n---\nbody",
            ),
            ("skills/beta/SKILL.md", "---\nname: beta\n---\nbody"),
        ]);
        let spec = SurfaceSpec {
            always_on_max: 4,
            ..surface()
        };
        let problems = validate(&tree, &spec);
        assert_eq!(problems.len(), 4, "{problems:?}");

        assert!(problems.iter().any(|p| p.path == "systemprompt.md"));
        assert!(
            problems
                .iter()
                .any(|p| p.path == "skills/alpha/SKILL.md" && p.message.contains("does not match"))
        );
        assert!(
            problems
                .iter()
                .any(|p| p.path == "skills/beta/SKILL.md" && p.message.contains("description"))
        );
        assert!(
            problems
                .iter()
                .any(|p| p.path == "skills/beta/SKILL.md" && p.message.contains("dead weight"))
        );
    }

    #[test]
    fn materialize_skips_missing_always_on_files() {
        let tree = tree(&[("guardrails.md", "Guardrails only.")]);
        assert_eq!(materialize(&tree, &surface()), "Guardrails only.");
    }

    #[test]
    fn materialize_omits_the_skills_block_when_there_are_no_skills() {
        let tree = tree(&[("systemprompt.md", "Prompt."), ("guardrails.md", "Guard.")]);
        let out = materialize(&tree, &surface());
        assert_eq!(out, "Prompt.\n\nGuard.");
        assert!(!out.contains("<available_skills>"));
    }
}
