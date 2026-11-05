//! Advisory SKILL.md linter (Hermes `tools/skill_linter.py`, MIT): the authoring standards a
//! reviewer would otherwise catch. Findings never block by themselves; `ark skills lint`
//! prints them and exits non-zero only on errors.

use regex::Regex;
use serde_json::Value;
use std::fs;
use std::path::Path;

/// Shell utilities the native tools wrap; naming them in prose steers the model to a raw shell call.
const SHELL_UTIL_TO_TOOL: &[(&str, &str)] = &[("grep", "grep"), ("rg", "grep"), ("cat", "read"), ("head", "read"), ("tail", "read"), ("sed", "edit"), ("awk", "edit"), ("find", "glob"), ("ls", "glob")];
const MARKETING_WORDS: &[&str] = &["powerful", "comprehensive", "seamless", "advanced", "cutting-edge", "state-of-the-art", "revolutionary", "robust"];
const POSIX_PRIMITIVES: &[&str] = &["fcntl", "termios", "os.setsid", "signal.SIGKILL", "osascript", "/proc/", "apt-get", "systemctl"];
const FORBIDDEN_FILES: &[&str] = &["README.md", "CHANGELOG.md", "install.sh", ".env", ".env.example", ".gitignore"];
const INCIDENT_REF_MIN: usize = 4;
const INCIDENT_REF_PER_KCHAR: f64 = 0.5;
const MAX_REFERENCE_FILES: usize = 60;
const BODY_SOFT_BUDGET_CHARS: usize = 24_000;
/// The skill index keeps this many description characters.
pub const PROMPT_DESC_LIMIT: usize = 60;

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub severity: &'static str,
    pub rule: &'static str,
    pub message: String,
}

fn err(rule: &'static str, m: String) -> Finding {
    Finding { severity: "error", rule, message: m }
}
fn warn(rule: &'static str, m: String) -> Finding {
    Finding { severity: "warning", rule, message: m }
}

fn strip_code_blocks(body: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    let mut rest = body;
    while let Some(i) = rest.find("```") {
        if !inside {
            out.push_str(&rest[..i]);
        }
        inside = !inside;
        rest = &rest[i + 3..];
    }
    if !inside {
        out.push_str(rest);
    }
    out
}

/// PR / issue references (`#1234`, `PR 1234`, `issue #123`) not preceded by a word char or `/`.
fn incident_refs(prose: &str) -> usize {
    let hash = Regex::new(r"#\d{3,6}\b").unwrap();
    let word = Regex::new(r"\b(?:PR|issue)\s*#?\d{3,6}\b").unwrap();
    let b = prose.as_bytes();
    let mut n = hash.find_iter(prose).filter(|m| m.start() == 0 || !(b[m.start() - 1].is_ascii_alphanumeric() || b[m.start() - 1] == b'_' || b[m.start() - 1] == b'/')).count();
    n += word.find_iter(prose).filter(|m| !prose[m.start()..m.end()].contains('#')).count();
    n
}

fn check_frontmatter(fm: &Value, dir: Option<&Path>, out: &mut Vec<Finding>) {
    let name = fm.get("name").and_then(Value::as_str).unwrap_or("").trim().to_string();
    if !name.is_empty() && !Regex::new(r"^[a-z0-9][a-z0-9_-]*$").unwrap().is_match(&name) {
        out.push(err("name-format", format!("name '{name}' must be lowercase letters, digits, hyphens, and underscores only.")));
    }
    if let Some(d) = dir {
        let dn = d.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
        if !name.is_empty() && name != dn {
            out.push(err("name-dir-mismatch", format!("frontmatter name '{name}' does not match directory '{dn}'; they must be identical.")));
        }
    }
    let desc = fm.get("description").and_then(Value::as_str).unwrap_or("").trim().trim_matches(['\'', '"']).to_string();
    if desc.chars().count() > PROMPT_DESC_LIMIT {
        out.push(warn("description-length", format!("description is {} chars; the skill index truncates past {PROMPT_DESC_LIMIT} chars + '...', losing routing signal. Keep it to one sentence.", desc.chars().count())));
    }
    let lower = desc.to_lowercase();
    let hits: Vec<&str> = MARKETING_WORDS.iter().copied().filter(|w| Regex::new(&format!(r"\b{}\b", regex::escape(w))).unwrap().is_match(&lower)).collect();
    if !hits.is_empty() {
        out.push(warn("description-marketing", format!("description contains marketing words {hits:?}; state the capability, not adjectives.")));
    }
    for key in ["version", "author", "license"] {
        if fm.get(key).is_none() {
            out.push(warn("missing-metadata", format!("frontmatter is missing '{key}'; every peer skill has it.")));
        }
    }
    let author = fm.get("author").and_then(Value::as_str).unwrap_or("");
    if !author.is_empty() && ["hermes", "agent", "hermes agent"].contains(&author.trim().to_lowercase().as_str()) && author != "Hermes Agent" {
        out.push(warn("author-caps", format!("author '{author}' should be 'Hermes Agent' (proper caps) or a real contributor name.")));
    }
    let meta = fm.get("metadata").and_then(|m| m.get("ark").or_else(|| m.get("hermes")));
    match meta {
        Some(Value::Object(m)) if !m.contains_key("tags") => out.push(warn("missing-metadata", "metadata.ark.tags is missing.".into())),
        Some(Value::Object(_)) => {}
        _ => out.push(warn("missing-metadata", "frontmatter is missing metadata.ark.{tags, related_skills}.".into())),
    }
    if let Some(p) = fm.get("platforms") {
        let items: Vec<String> = match p {
            Value::Array(a) => a.iter().map(|v| v.as_str().unwrap_or("").to_string()).collect(),
            Value::String(s) => vec![s.clone()],
            _ => vec![],
        };
        let bad: Vec<&String> = items.iter().filter(|i| !["linux", "macos", "windows", "darwin"].contains(&i.to_lowercase().as_str())).collect();
        if !bad.is_empty() {
            out.push(warn("platforms-value", format!("platforms contains unrecognized value(s) {bad:?}; expected a subset of [\"darwin\", \"linux\", \"macos\", \"windows\"].")));
        }
    }
}

fn check_body(body: &str, dir: Option<&Path>, out: &mut Vec<Finding>) {
    if body.len() > BODY_SOFT_BUDGET_CHARS {
        out.push(warn("oversized-body", format!("SKILL.md body is {} chars (~{} tokens); loading the skill puts all of it in context for the rest of the session. Keep the always-on rules here (~200 lines) and move topic depth into references/<topic>.md.", body.len(), body.len() / 4)));
    }
    let prose = strip_code_blocks(body);
    for (util, tool) in SHELL_UTIL_TO_TOOL {
        if prose.contains(&format!("`{util}`")) {
            out.push(warn("shell-utility-reference", format!("prose references `{util}`; name the native tool `{tool}` instead.")));
        }
    }
    if !Regex::new(r"(?m)^#+\s+When to [Uu]se").unwrap().is_match(body) {
        out.push(warn("missing-section", "no '## When to Use' section found; skills need explicit trigger conditions near the top.".into()));
    }
    let refs = incident_refs(&prose);
    if refs >= INCIDENT_REF_MIN && refs as f64 / prose.len().max(1) as f64 * 1000.0 >= INCIDENT_REF_PER_KCHAR {
        out.push(warn("incident-log-shape", format!("{refs} PR/issue references in prose; write the generalizable rule + why and drop the incident numbers — the rule must stand without the story.")));
    }
    let Some(d) = dir else { return };
    let mut seen = std::collections::HashSet::new();
    for m in Regex::new(r"(references|templates|assets)/[\w./-]+").unwrap().find_iter(body) {
        let rel = m.as_str().trim_end_matches('.');
        if rel.contains('*') || rel.ends_with('/') || !seen.insert(rel.to_string()) {
            continue;
        }
        if !d.join(rel).exists() {
            out.push(warn("dangling-reference", format!("body references '{rel}' but that file does not exist in the skill directory.")));
        }
    }
}

fn files_under(d: &Path, out: &mut Vec<std::path::PathBuf>) {
    for e in fs::read_dir(d).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            files_under(&p, out);
        } else {
            out.push(p);
        }
    }
}

fn check_files(fm: &Value, d: &Path, out: &mut Vec<Finding>) {
    if fm.get("platforms").is_none_or(|p| p.is_null()) {
        let mut scripts = Vec::new();
        files_under(&d.join("scripts"), &mut scripts);
        let mut offenders = Vec::new();
        for s in scripts.iter().filter(|s| matches!(s.extension().and_then(|e| e.to_str()), Some("py" | "sh" | "bash"))) {
            let t = fs::read_to_string(s).unwrap_or_default();
            let hit: Vec<&str> = POSIX_PRIMITIVES.iter().copied().filter(|p| t.contains(p)).collect();
            if !hit.is_empty() {
                offenders.push(format!("{}: {hit:?}", s.file_name().unwrap().to_string_lossy()));
            }
        }
        if !offenders.is_empty() {
            out.push(warn("platforms-gating", format!("scripts use POSIX-only primitives ({}) but no 'platforms:' frontmatter is declared. Fix cross-platform or gate with platforms: [linux, macos].", offenders.join("; "))));
        }
    }
    for f in FORBIDDEN_FILES {
        if d.join(f).exists() {
            out.push(warn("forbidden-file", format!("skill ships '{f}'; skills should not include scaffolding/config files.")));
        }
    }
    let mut refs = Vec::new();
    files_under(&d.join("references"), &mut refs);
    let n = refs.iter().filter(|p| p.extension().is_some_and(|e| e == "md") && !p.components().any(|c| c.as_os_str().to_string_lossy().starts_with('_'))).count();
    if n > MAX_REFERENCE_FILES {
        out.push(warn("references-sprawl", format!("{n} files under references/; that is a per-session log, not topical depth. Merge same-topic files into one rule set and drop incident narration.")));
    }
}

/// Lint raw SKILL.md content; `dir` enables the on-disk checks.
pub fn lint_content(content: &str, dir: Option<&Path>) -> Vec<Finding> {
    let (fm, body) = crate::yaml::frontmatter(content);
    let mut out = Vec::new();
    check_frontmatter(&fm, dir, &mut out);
    check_body(body, dir, &mut out);
    if let Some(d) = dir {
        check_files(&fm, d, &mut out);
    }
    out
}

pub fn lint_skill(skill_md: &Path) -> Result<Vec<Finding>, String> {
    let t = fs::read_to_string(skill_md).map_err(|e| format!("{}: {e}", skill_md.display()))?;
    Ok(lint_content(&t, skill_md.parent()))
}

pub fn format(name: &str, f: &[Finding]) -> String {
    if f.is_empty() {
        return format!("{name}: no lint findings");
    }
    let mut o = format!("{name}: {} finding(s)\n", f.len());
    for x in f {
        o.push_str(&format!("  {:<7} {:<24} {}\n", x.severity.to_uppercase(), x.rule, x.message));
    }
    o.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_fire_and_clean_skill_passes() {
        let d = std::env::temp_dir().join(format!("ark-lint-{}/tool", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("scripts")).unwrap();
        fs::write(d.join("scripts/run.sh"), "systemctl restart x").unwrap();
        fs::write(d.join("README.md"), "x").unwrap();
        let bad = "---\nname: Tool_X\ndescription: A powerful and comprehensive tool that does many many things for everyone everywhere\n---\nUse `grep` to find it. See references/missing.md. Fixed in #1234, #2345, PR 3456 and issue #4567.\n```\n`cat` in code is fine\n```";
        let f = lint_content(bad, Some(&d));
        let rules: Vec<&str> = f.iter().map(|x| x.rule).collect();
        for r in ["name-format", "name-dir-mismatch", "description-length", "description-marketing", "missing-metadata", "shell-utility-reference", "missing-section", "incident-log-shape", "dangling-reference", "platforms-gating", "forbidden-file"] {
            assert!(rules.contains(&r), "{r} missing from {rules:?}");
        }
        assert!(!f.iter().any(|x| x.message.contains("`cat`")), "code blocks are not prose");
        assert_eq!(f.iter().filter(|x| x.severity == "error").count(), 2);
        let good = "---\nname: tool\ndescription: Restart the tool service safely\nversion: 1.0.0\nauthor: Ark\nlicense: MIT\nplatforms: [linux]\nmetadata:\n  ark:\n    tags: [ops]\n---\n## When to Use\nWhen the tool hangs.\n";
        fs::remove_file(d.join("README.md")).unwrap();
        assert_eq!(lint_content(good, Some(&d)), vec![]);
        assert!(format("tool", &[]).contains("no lint findings"));
        let _ = fs::remove_dir_all(d.parent().unwrap());
    }

    #[test]
    fn author_caps_size_and_sprawl_rules() {
        let d = std::env::temp_dir().join(format!("ark-lint-meta-{}/sprawl", std::process::id()));
        let _ = fs::remove_dir_all(d.parent().unwrap());
        fs::create_dir_all(d.join("references")).unwrap();
        for i in 0..61 {
            fs::write(d.join(format!("references/r{i}.md")), "x").unwrap();
        }
        let head = |author: &str| format!("---\nname: sprawl\ndescription: Restart the service safely\nversion: 1.0.0\nauthor: {author}\nlicense: MIT\nplatforms: [linux, solaris]\nmetadata:\n  ark:\n    tags: [ops]\n---\n## When to Use\nWhen it hangs.\n");
        let caps = |f: &[Finding]| f.iter().filter(|x| x.rule == "author-caps").count();
        let f = lint_content(&head("hermes"), Some(&d));
        assert_eq!(caps(&f), 1, "{f:?}");
        assert_eq!(caps(&lint_content(&head("Hermes Agent"), Some(&d))), 0);
        assert_eq!(caps(&lint_content(&head("Jane Doe"), Some(&d))), 0);
        for r in ["author-caps", "platforms-value", "references-sprawl"] {
            let hit: Vec<&Finding> = f.iter().filter(|x| x.rule == r).collect();
            assert_eq!(hit.len(), 1, "{r} missing from {f:?}");
            assert_eq!(hit[0].severity, "warning", "{r}");
        }
        let big = format!("{}## When to Use\n{}", head("Jane Doe"), "x ".repeat(13_000));
        let g = lint_content(&big, None);
        let ob: Vec<&Finding> = g.iter().filter(|x| x.rule == "oversized-body").collect();
        assert_eq!(ob.len(), 1, "{g:?}");
        assert_eq!(ob[0].severity, "warning");
        assert!(g.iter().chain(f.iter()).all(|x| x.severity == "warning" || matches!(x.rule, "name-format" | "name-dir-mismatch")));
        let _ = fs::remove_dir_all(d.parent().unwrap());
    }
}
