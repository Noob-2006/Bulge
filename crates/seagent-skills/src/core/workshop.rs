//! The model-facing skill workshop (`skill action=workshop …`): draft a SKILL.md from a goal,
//! validate/lint a draft, and refine an existing skill into a proposal the model applies with
//! `skill action=update` / `action=patch` (OpenClaw `agents/tools/skill-workshop-tool*.ts`,
//! `skills/workshop/skill-authoring-standards.ts`, `skills/workshop/skill-lint.ts`, MIT).
//!
//! Nothing here writes: a draft/proposal is text the model reviews and then saves through the
//! guarded writer in [`super::manage`] (security scan, lint, ledger, approval gate). The
//! authoring advisories are OpenClaw's, ported rule for rule; only findings a write *introduces*
//! are reported, so an existing skill's standing findings never nag.

use crate::skill::{self, MAX_NAME};
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

pub const MAX_DESCRIPTION_BYTES: usize = 160;
const MAX_BODY_LINES: usize = 250;
const MAX_BODY_BYTES: usize = 12_000;
const MIN_NEGATION_LINES: usize = 3;
const MAX_ADVISORIES: usize = 3;

/// The authoring standard the draft template and the `refine` hints quote (OpenClaw
/// `SKILL_AUTHORING_STANDARDS_PROMPT`).
pub const AUTHORING_STANDARD: &str = "Skill authoring standard:\n- A skill is a procedure, not memory: the method for one class of task this user repeats. Write ordered steps, each with the exact commands, tools, paths and the check that shows it worked.\n- Each rule is an imperative plus one clause of why, attached to the step it affects. One rule per lesson.\n- Fix the misleading sentence in place; leave out update notes, dates, ticket ids, incident stories and quoted user text.\n- description: the trigger situations first, then what the skill produces (aim for ≤160 bytes).\n- Keep in SKILL.md what every run needs; move the rest into references/, templates/ or scripts/ and point at it from the step that needs it.";

fn no_op_words() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)\b(?:powerful|comprehensive|robust|seamless(?:ly)?|cutting-edge|state-of-the-art|be thorough|make sure to)\b").unwrap())
}
fn shouting() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\bIMPORTANT\b").unwrap())
}
fn negation_line() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)^(?:[-*+]|\d+[.)])?\s*(?:\*\*)?(?:never|don['’]t|do not)\b").unwrap())
}
fn narrative_line() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^(?:[-*+]\s*)?(?:\*\*)?(?:UPDATE|NOTE|EDIT)\b|\b20\d\d-\d\d-\d\d\b").unwrap())
}
fn identity() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)^(?:this|a|the) skill\b").unwrap())
}

/// Prose of a SKILL.md body: fenced code and inline code removed, one entry per line.
fn prose_lines(body: &str) -> Vec<String> {
    let mut out = String::new();
    let mut inside = false;
    for line in body.lines() {
        if line.trim_start().starts_with("```") {
            inside = !inside;
            continue;
        }
        if !inside {
            out.push_str(line);
            out.push('\n');
        }
    }
    let inline = Regex::new(r"`[^`\n]*`").unwrap();
    inline.replace_all(&out, "").lines().map(|l| l.trim().to_string()).collect()
}

/// Authoring-convention findings for one SKILL.md, most useful first (OpenClaw
/// `lintSkillMarkdown`); these never block a write.
pub fn advisories_of(content: &str) -> Vec<(String, String)> {
    let (front, body) = crate::yaml::frontmatter(content);
    let description = front.get("description").and_then(|d| d.as_str()).unwrap_or("").trim().to_string();
    let lines = prose_lines(body);
    let bytes = description.len();
    let body_lines = body.lines().count();
    let body_bytes = body.len();
    let joined = format!("{}\n{}", description, lines.join("\n"));
    let mut no_ops: Vec<String> = no_op_words().find_iter(&joined).map(|m| m.as_str().to_string()).collect();
    no_ops.extend(shouting().find_iter(&joined).map(|m| m.as_str().to_string()));
    no_ops.sort();
    no_ops.dedup();
    let negations = lines.iter().filter(|l| negation_line().is_match(l)).count();
    let mut out = Vec::new();
    if bytes > MAX_DESCRIPTION_BYTES {
        out.push(("description-length".to_string(), format!("description is {bytes} bytes; trim it to ≤{MAX_DESCRIPTION_BYTES} with the trigger first.")));
    }
    if identity().is_match(&description) {
        out.push(("description-identity".to_string(), "description opens with \"This skill\"; open with the situation that triggers it.".to_string()));
    }
    if body_lines > MAX_BODY_LINES || body_bytes > MAX_BODY_BYTES {
        out.push(("sprawl".to_string(), format!("SKILL.md body is {body_lines} lines ({body_bytes} bytes); move reference only some runs need into references/ and point to it from its step.")));
    }
    if !no_ops.is_empty() {
        out.push(("no-op".to_string(), format!("cut no-op emphasis ({}); plain steps carry the same weight.", no_ops.iter().take(3).cloned().collect::<Vec<_>>().join(", "))));
    }
    if negations >= MIN_NEGATION_LINES {
        out.push(("negation".to_string(), format!("{negations} lines start with Never/Don't; state the behavior to produce instead.")));
    }
    if lines.iter().any(|l| narrative_line().is_match(l)) {
        out.push(("narrative".to_string(), "found an update note or date; fold the lesson into the step it changes.".to_string()));
    }
    out
}

/// Advisories this write *introduces* (`skillWriteAdvisories`), at most three.
pub fn advisories(before: &str, after: &str) -> Vec<String> {
    let standing: Vec<String> = advisories_of(before).into_iter().map(|(r, _)| r).collect();
    advisories_of(after)
        .into_iter()
        .filter(|(r, _)| !standing.contains(r))
        .take(MAX_ADVISORIES)
        .map(|(_, m)| format!("Advisory (not blocking): {m} Fix with `skill action=patch`."))
        .collect()
}

/// `Name of skill` → `name-of-skill`, within the frontmatter name rules.
pub fn slug(text: &str) -> String {
    let mut out = String::new();
    for c in text.trim().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if (c.is_whitespace() || c == '-' || c == '_') && !out.ends_with('-') {
            out.push('-');
        }
    }
    let mut s: String = out.trim_matches('-').chars().take(MAX_NAME).collect();
    while s.ends_with('-') {
        s.pop();
    }
    s
}

/// A draft SKILL.md: the name it would be saved under and the full text.
#[derive(Debug, Clone)]
pub struct Draft {
    pub name: String,
    pub content: String,
}

/// Draft a SKILL.md from a goal and the steps that worked. The model is told what to change,
/// not handed a finished truth: the draft is a starting point it refines before saving.
pub fn draft(goal: &str, name: Option<&str>, description: Option<&str>, steps: &[String]) -> Result<Draft, String> {
    let goal = goal.trim();
    if goal.is_empty() {
        return Err("`goal` is required for a draft (what class of task this skill is for)".into());
    }
    let name = match name.map(str::trim).filter(|n| !n.is_empty()) {
        Some(n) => n.to_ascii_lowercase(),
        None => slug(goal),
    };
    if !skill::valid_name(&name) {
        return Err(format!("bad skill name `{name}` (lowercase letters, digits, dashes; ≤{} chars); pass `name` with a lowercase-dashed form", skill::MAX_NAME));
    }
    let title = name.split('-').map(|w| {
        let mut c = w.chars();
        c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
    }).collect::<Vec<_>>().join(" ");
    let desc = description.map(str::trim).filter(|d| !d.is_empty()).map(String::from).unwrap_or_else(|| {
        // The goal's first sentence is the honest default description.
        let first = goal.split(['.', '\n']).next().unwrap_or(goal).trim();
        if first.chars().count() > 140 { first.chars().take(140).collect() } else { first.to_string() }
    });
    let steps_block = if steps.is_empty() {
        "1. (add the ordered steps that worked, with the exact command or tool call)\n2. (the check that shows each step worked)".to_string()
    } else {
        steps.iter().enumerate().filter(|(_, s)| !s.trim().is_empty()).map(|(i, s)| format!("{}. {}", i + 1, s.trim())).collect::<Vec<_>>().join("\n")
    };
    let content = format!(
        "---\nname: {name}\ndescription: {}\n---\n\n# {title}\n\n## When to Use\n{goal}\n\n## Procedure\n{steps_block}\n\n## Verification\n- (state the check that proves the task succeeded)\n",
        serde_json::to_string(&desc).unwrap_or_default()
    );
    Ok(Draft { name, content })
}

/// The result of checking a draft: blocking problems, then advisory ones.
#[derive(Debug, Clone, Default)]
pub struct Validation {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub security: Option<String>,
}

impl Validation {
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
    pub fn render(&self, name: &str) -> String {
        let mut out = if self.ok() {
            format!("{name}: draft is valid — no lint errors")
        } else {
            format!("{name}: {} blocking problem(s)", self.errors.len())
        };
        for e in &self.errors {
            out.push_str(&format!("\n  ERROR   {e}"));
        }
        for w in &self.warnings {
            out.push_str(&format!("\n  WARN    {w}"));
        }
        if let Some(s) = &self.security {
            out.push_str(&format!("\n  security: {s}"));
        }
        out
    }
}

/// Check a SKILL.md draft: structure + name rules (blocking), the linter and the authoring
/// advisories (warnings), plus the security scanner's verdict.
pub fn validate(content: &str, name: Option<&str>, dir: Option<&Path>) -> Validation {
    let mut v = Validation::default();
    match crate::yaml::frontmatter_strict(content) {
        Ok((front, body)) => {
            if !front.is_object() {
                v.errors.push("SKILL.md must start with a `---` frontmatter block".into());
            }
            let declared = front.get("name").and_then(|n| n.as_str()).unwrap_or("").trim().to_string();
            let expect = name.map(str::to_string).unwrap_or_else(|| declared.clone());
            if declared.is_empty() {
                v.errors.push("frontmatter is missing `name`".into());
            } else if !skill::valid_name(&declared) {
                v.errors.push(format!("name `{declared}` must be lowercase letters, digits, dashes or underscores (≤{} chars)", skill::MAX_NAME));
            } else if !expect.is_empty() && declared != expect {
                v.errors.push(format!("frontmatter name `{declared}` does not match `{expect}` (they must be identical)"));
            }
            if front.get("description").and_then(|d| d.as_str()).unwrap_or("").trim().is_empty() {
                v.errors.push("frontmatter is missing `description` (the skill index routes on it)".into());
            }
            if body.trim().is_empty() {
                v.errors.push("the body is empty; the procedure belongs in SKILL.md".into());
            }
        }
        Err(e) => v.errors.push(format!("frontmatter does not parse: {e}")),
    }
    for f in super::lint::lint_content(content, dir) {
        if f.severity == "error" {
            v.errors.push(format!("{}: {}", f.rule, f.message));
        } else {
            v.warnings.push(format!("{}: {}", f.rule, f.message));
        }
    }
    for (rule, message) in advisories_of(content) {
        v.warnings.push(format!("{rule}: {message}"));
    }
    let scan = seagent_security::skills_guard::scan_skill_text("draft", content, "agent-created");
    v.security = Some(if scan.findings.is_empty() {
        "clean".to_string()
    } else {
        format!("{} verdict, {} finding(s) — see `seagent skills audit` before sharing", scan.verdict.as_str(), scan.findings.len())
    });
    v
}

/// A refinement of an existing skill: the proposed SKILL.md and what changed.
#[derive(Debug, Clone)]
pub struct Refinement {
    pub name: String,
    pub content: String,
    pub section: String,
    pub advisories: Vec<String>,
}

/// Fold a session's steps (or the model's own) into the skill that governs them. The section is
/// appended as imperative steps, not as an incident report (the authoring standard's rule).
pub fn refine(existing: &str, name: &str, focus: &str, steps: &[String]) -> Result<Refinement, String> {
    if !skill::valid_name(name) {
        return Err(format!("bad skill name `{name}`"));
    }
    let steps: Vec<String> = steps.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    if steps.is_empty() {
        return Err("`refine` needs `steps` (the concrete steps that worked, or the correction the user made)".into());
    }
    // Never append the same lesson twice: only steps the skill does not already carry are added.
    let steps: Vec<String> = steps.into_iter().filter(|s| !existing.contains(s.as_str())).collect();
    if steps.is_empty() {
        return Err(format!("`{name}` already carries this step; patch the sentence it belongs to instead of appending it again"));
    }
    let focus = focus.trim();
    let heading = if focus.is_empty() { "Refined procedure".to_string() } else { focus.chars().take(80).collect::<String>() };
    let section = format!("## {heading}\n{}", steps.iter().enumerate().map(|(i, s)| format!("{}. {s}", i + 1)).collect::<Vec<_>>().join("\n"));
    let content = format!("{}\n{}\n", existing.trim_end(), section);
    let advisories = advisories(existing, &content);
    Ok(Refinement { name: name.to_string(), content, section, advisories })
}

/// A deterministic skill-diet plan: keep the frontmatter and the first sections inside the
/// budget, move the tail into `references/diet-<name>.md` and point at it from a short
/// `## Details` section. No model call: what moved is exactly what was too long.
#[derive(Debug, Clone, PartialEq)]
pub struct Diet {
    pub name: String,
    pub before_bytes: usize,
    pub after_bytes: usize,
    pub reference_path: String,
    pub reference: String,
    pub content: String,
    pub moved_sections: usize,
}

pub fn diet_plan(content: &str, name: &str, max_bytes: usize) -> Option<Diet> {
    let before_bytes = content.len();
    if before_bytes <= max_bytes {
        return None;
    }
    let chunks: Vec<&str> = content.split("\n## ").collect();
    if chunks.len() < 2 {
        return None;
    }
    let mut keep = chunks[0].to_string();
    let mut moved: Vec<&str> = Vec::new();
    for (i, chunk) in chunks.iter().enumerate().skip(1) {
        let section = format!("\n## {chunk}");
        // The first section always stays: a diet must never produce a skill with no procedure.
        if i == 1 || keep.len() + section.len() <= max_bytes {
            keep.push_str(&section);
        } else {
            moved.push(chunk);
        }
    }
    if moved.is_empty() {
        return None;
    }
    let reference_path = format!("references/diet-{name}.md");
    let reference = moved.iter().map(|s| format!("## {s}")).collect::<Vec<_>>().join("\n\n");
    let pointer = format!("## Details\nSee {reference_path} for procedure sections moved out of SKILL.md by `seagent curator diet`.\n");
    let content = format!("{}\n\n{}", keep.trim_end(), pointer);
    Some(Diet { name: name.to_string(), before_bytes, after_bytes: content.len(), reference_path, reference, content, moved_sections: moved.len() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draft_slug_validate_and_refine() {
        let d = draft("Ship the staging release without downtime. Use terraform and the fleet API.", Some("ship-staging"), None, &["Run the release checklist".to_string(), "Watch the fleet dashboard".to_string()]).unwrap();
        assert_eq!(d.name, "ship-staging");
        assert!(d.content.starts_with("---\nname: ship-staging\ndescription: \"Ship the staging release without downtime\""), "{}", d.content);
        assert!(d.content.contains("# Ship Staging") && d.content.contains("## When to Use\nShip the staging release") && d.content.contains("1. Run the release checklist\n2. Watch the fleet dashboard"), "{}", d.content);
        let v = validate(&d.content, Some("ship-staging"), None);
        assert!(v.ok(), "{:?}", v.errors);
        assert!(v.security.as_deref() == Some("clean"));
        // A goal alone still produces a shape the model can fill in.
        let bare = draft("Review a pull request", None, None, &[]).unwrap();
        assert_eq!(bare.name, "review-a-pull-request");
        assert!(bare.content.contains("(add the ordered steps that worked"), "{}", bare.content);
        assert!(draft(" ", None, None, &[]).unwrap_err().contains("goal"));
        assert!(draft("x", Some("Bad Name"), None, &[]).unwrap_err().contains("bad skill name"));
        // Validation blocks structure, warns on authoring conventions.
        let bad = "---\nname: other\ndescription: \"A powerful, comprehensive skill that makes sure to be thorough and IMPORTANT\"\n---\n\n# T\n\nNever guess.\nNever retry.\nDon't skip.\n\n2024-01-02 fixed it\n";
        let v = validate(bad, Some("target"), None);
        assert!(!v.ok() && v.errors.iter().any(|e| e.contains("does not match")), "{v:?}");
        let rules: Vec<&str> = v.warnings.iter().map(|w| w.split(':').next().unwrap_or("")).collect();
        for r in ["no-op", "negation", "narrative"] {
            assert!(rules.contains(&r), "{r} missing from {rules:?}");
        }
        assert!(validate("not frontmatter", None, None).errors.iter().any(|e| e.contains("frontmatter") || e.contains("name")));
        // Refine appends a section and never duplicates a lesson.
        let skill_md = "---\nname: deploy\ndescription: Ship it\n---\n\n# Deploy\n\n## When to Use\nAlways.\n\n1. run tests\n";
        let r = refine(skill_md, "deploy", "Rollback", &["Run `seagent deploy rollback` when the canary fails".to_string()]).unwrap();
        assert!(r.content.starts_with(skill_md.trim_end()) && r.content.contains("## Rollback\n1. Run `seagent deploy rollback`"), "{}", r.content);
        assert!(r.section.contains("## Rollback"));
        assert!(refine(&r.content, "deploy", "Rollback", &["Run `seagent deploy rollback` when the canary fails".to_string()]).unwrap_err().contains("already carries"));
        assert!(refine(skill_md, "deploy", "", &[]).unwrap_err().contains("needs `steps`"));
        // Advisories report only what a write introduces.
        assert!(advisories(skill_md, &r.content).is_empty(), "a clean append adds no advisory");
        let noisy = format!("{skill_md}\nBe thorough and comprehensive.\n");
        assert!(advisories(skill_md, &noisy).iter().any(|a| a.starts_with("Advisory (not blocking): cut no-op emphasis")));
        assert!(AUTHORING_STANDARD.contains("A skill is a procedure, not memory"));
    }

    #[test]
    fn diet_moves_the_tail_into_references_without_losing_it() {
        let body = (0..40).map(|i| format!("## Section {i}\n{}", "step ".repeat(80))).collect::<Vec<_>>().join("\n");
        let md = format!("---\nname: big\ndescription: Big\n---\n\n# Big\n\n{body}");
        let d = diet_plan(&md, "big", 4_000).unwrap();
        assert_eq!(d.reference_path, "references/diet-big.md");
        assert!(d.after_bytes < d.before_bytes && d.after_bytes <= 4_000 + 200, "{} -> {}", d.before_bytes, d.after_bytes);
        assert!(d.content.starts_with("---\nname: big") && d.content.contains("## Details") && d.content.contains("references/diet-big.md"));
        assert!(d.reference.starts_with("## Section ") && d.reference.contains("## Section 39"));
        assert_eq!(d.content.matches("## Section").count() + d.reference.matches("## Section").count(), 40, "every section survives the move");
        assert!(diet_plan(&md, "big", 100_000).is_none(), "a small skill is left alone");
        assert!(diet_plan("---\nname: x\ndescription: x\n---\nno headings", "x", 10).is_none(), "nothing to move");
    }
}
