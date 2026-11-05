//! Skill normalisation: OpenClaw / Hermes / Claude Code `SKILL.md` variants → the shape
//! ark reads.
//!
//! ark consumes very little frontmatter (`skill::Skill`: `name`, `description`, and
//! `skill::Requirements`: `requires.{bins,anyBins,env,config}`, `os`, plus
//! `metadata.{ark,openclaw,hermes}.{requires,os}` and Hermes' `platforms:`). So the job
//! is to hoist the upstream spellings into those keys, drop what ark would otherwise
//! silently misread, and report both — never to invent a field.
//!
//! Upstreams (read-only): `/home/noob/openclaw/dist/extensions/*/skills/*/SKILL.md`,
//! `/home/noob/openclaw/skills/*/SKILL.md`, `/home/noob/hermes-agent/skills/**/SKILL.md`,
//! `share/skills/**/SKILL.md`.

use crate::yaml;
use serde_json::{json, Map, Value};

#[derive(Debug, Clone)]
pub struct SkillImport {
    pub name: String,
    /// The normalized frontmatter (what gets written back as `SKILL.md`'s block).
    pub front: Value,
    pub body: String,
    /// Fields that now drive ark's behaviour (`requires` hoisted, `platforms` → `os`, …).
    pub mapped: Vec<String>,
    /// Fields removed because ark cannot honour them (with the reason in `warnings`).
    pub dropped: Vec<String>,
    pub warnings: Vec<String>,
}

/// Which upstream flavour a frontmatter block came from.
pub fn variant(front: &Value) -> &'static str {
    let meta = front.get("metadata");
    let has = |ns: &str| meta.and_then(|m| m.get(ns)).is_some();
    if has("openclaw") {
        "openclaw"
    } else if has("hermes") || front.get("platforms").is_some() {
        "hermes"
    } else if front.get("allowed-tools").is_some()
        || front.get("disable-model-invocation").is_some()
        || front.get("user-invocable").is_some()
        || front.get("command-dispatch").is_some()
        || front.get("command-tool").is_some()
        || front.get("command-arg-mode").is_some()
    {
        "claude-code"
    } else if has("ark") || front.get("upstream").is_some() {
        "ark"
    } else {
        "plain"
    }
}

/// The upstream flavour of a whole `SKILL.md` text (frontmatter only, no rewriting).
pub fn variant_of(text: &str) -> Option<&'static str> {
    yaml::frontmatter_strict(text).ok().map(|(front, _)| variant(&front))
}

fn list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect(),
        Some(Value::String(s)) => s.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect(),
        _ => vec![],
    }
}

fn push_unique(into: &mut Vec<String>, items: Vec<String>) {
    for i in items {
        if !into.contains(&i) {
            into.push(i);
        }
    }
}

/// Normalize one `SKILL.md` (or any text with a YAML frontmatter block).
pub fn normalize(text: &str) -> Result<SkillImport, String> {
    let (mut front, body) = yaml::frontmatter_strict(text).map_err(|e| format!("frontmatter: {e}"))?;
    if !front.is_object() {
        return Err("frontmatter is not a mapping".into());
    }
    let mut mapped: Vec<String> = Vec::new();
    let mut dropped: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    let name = front.get("name").and_then(Value::as_str).map(str::trim).unwrap_or_default().to_string();
    if name.is_empty() {
        return Err("frontmatter has no `name`".into());
    }
    if !crate::skill::valid_name(&name) {
        warnings.push(format!("name `{name}`: ark wants lowercase letters, digits, `-`, `_`, `.` (≤ 64); the skill will not be discovered until it is renamed."));
    }
    if front.get("description").and_then(Value::as_str).map(str::trim).unwrap_or("").is_empty() {
        warnings.push("description is missing: ark lists skills by their description, so this one is hard for the model to find.".into());
    }

    // 1. requires: top level plus every namespace ark's Requirements reads.
    let mut req: Map<String, Value> = front.get("requires").and_then(Value::as_object).cloned().unwrap_or_default();
    let mut hoisted: Vec<String> = Vec::new();
    for ns in ["ark", "openclaw", "hermes"] {
        // Copied out first: the namespace table is edited below.
        let block = front.get("metadata").and_then(|m| m.get(ns)).cloned().unwrap_or(Value::Null);
        let Some(b) = block.as_object() else { continue };
        if let Some(r) = b.get("requires").and_then(Value::as_object) {
            for (k, v) in r {
                if !req.contains_key(k) {
                    req.insert(k.clone(), v.clone());
                }
                hoisted.push(format!("metadata.{ns}.requires.{k} → requires.{k}"));
            }
            if let Some(meta) = front.get_mut("metadata").and_then(|m| m.get_mut(ns)).and_then(Value::as_object_mut) {
                meta.remove("requires");
            }
        }
        // `metadata.openclaw.primaryEnv` is the key everything else is gated on upstream.
        if let Some(env) = b.get("primaryEnv").and_then(Value::as_str).filter(|e| !e.trim().is_empty()) {
            let mut cur = list(req.get("env"));
            push_unique(&mut cur, vec![env.trim().to_string()]);
            req.insert("env".into(), json!(cur));
            hoisted.push(format!("metadata.{ns}.primaryEnv → requires.env"));
        }
        let os = list(b.get("os"));
        if !os.is_empty() {
            let mut cur = list(front.get("os"));
            push_unique(&mut cur, os);
            front["os"] = json!(cur);
            mapped.push(format!("metadata.{ns}.os → os"));
        }
    }
    if front.get("requires").is_some() || !req.is_empty() {
        front["requires"] = Value::Object(req);
        if hoisted.is_empty() {
            mapped.push("requires".into());
        }
    }
    mapped.extend(hoisted);

    // 2. OS allowlist: Hermes `platforms:` and OpenClaw's top-level `os:` are the same gate.
    let platforms = list(front.get("platforms"));
    if !platforms.is_empty() {
        let mut cur = list(front.get("os"));
        push_unique(&mut cur, platforms);
        front["os"] = json!(cur);
        front.as_object_mut().map(|m| m.remove("platforms"));
        mapped.push("platforms → os".into());
    }
    if front.get("os").is_some() {
        let os = list(front.get("os"));
        let norm: Vec<String> = os.iter().map(|o| if o == "mac" || o == "macos" { "darwin".to_string() } else { o.to_ascii_lowercase() }).collect();
        front["os"] = json!(norm);
        if !mapped.iter().any(|m| m.ends_with("→ os") || m == "os") {
            mapped.push("os".into());
        }
    }

    // 3. Fields ark has no equivalent for: remove them so nothing downstream misreads them.
    for (key, why) in [
        ("allowed-tools", "ark skills may use every tool the session has; an allowlist is not enforced."),
        ("disable-model-invocation", "ark lists a skill to the model whenever its requirements are met; there is no manual-only flag."),
        ("user-invocable", "ark exposes every skill as `/skill <name>`; the flag is ignored."),
        ("command-dispatch", "ark's slash routing is `/skill`; command dispatch directives are not read."),
        ("command-tool", "ark's slash routing is `/skill`; command dispatch directives are not read."),
        ("command-arg-mode", "ark's slash routing is `/skill`; command dispatch directives are not read."),
    ] {
        if front.get(key).is_some() {
            front.as_object_mut().map(|m| m.remove(key));
            dropped.push(key.to_string());
            warnings.push(format!("`{key}`: {why}"));
        }
    }
    if let Some(install) = front.get("metadata").and_then(|m| m.get("openclaw")).and_then(|o| o.get("install")) {
        if !install.is_null() {
            if let Some(meta) = front.get_mut("metadata").and_then(|m| m.get_mut("openclaw")).and_then(Value::as_object_mut) {
                meta.remove("install");
            }
            dropped.push("metadata.openclaw.install".into());
            warnings.push("`metadata.openclaw.install`: ark never runs brew/go/node installers; install the tool and let `requires.bins` gate the skill.".into());
        }
    }

    // One blank line between the block and the body is the writer's job; drop the
    // separator here so `write` → `normalize` is stable.
    Ok(SkillImport { name, front, body: body.trim_start_matches(['\n', '\r']).to_string(), mapped, dropped, warnings })
}

/// `normalize` for a skill directory, recording where it came from in `upstream`.
pub fn from_dir(dir: &std::path::Path) -> Result<SkillImport, String> {
    let file = dir.join("SKILL.md");
    let text = std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
    let mut imp = normalize(&text)?;
    let src = variant(&imp.front);
    if src != "claude-code" && src != "plain" {
        imp.front["upstream"] = json!(format!("{} ({src})", dir.display()));
    }
    Ok(imp)
}

/// Write `SKILL.md` for `imp` into `dir` (created). Returns the file written.
pub fn write(imp: &SkillImport, dir: &std::path::Path) -> Result<std::path::PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut out = String::from("---\n");
    out.push_str(&yaml::to_yaml(&imp.front));
    out.push_str("---\n\n");
    out.push_str(&imp.body);
    let path = dir.join("SKILL.md");
    std::fs::write(&path, out).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compat_skill_openclaw_variant_hoists_requires_and_drops_the_allowlist() {
        // Shape of openclaw/dist/extensions/discord/skills/discord/SKILL.md.
        let src = "---\nname: discord\ndescription: \"Discord messaging workflows.\"\nmetadata: { \"openclaw\": { \"emoji\": \"🎮\", \"requires\": { \"config\": [\"channels.discord\"] }, \"primaryEnv\": \"DISCORD_TOKEN\", \"install\": [{\"id\": \"brew\", \"kind\": \"brew\"}] } }\nallowed-tools: [\"message\"]\n---\n# Discord\n\nUse `message`.\n";
        let imp = normalize(src).unwrap();
        assert_eq!(imp.name, "discord");
        assert_eq!(variant(&imp.front), "openclaw");
        assert_eq!(imp.front["requires"]["config"][0], "channels.discord");
        assert_eq!(imp.front["requires"]["env"][0], "DISCORD_TOKEN", "primaryEnv becomes a requirement");
        assert!(imp.mapped.iter().any(|m| m.contains("metadata.openclaw.requires.config")), "{:?}", imp.mapped);
        assert_eq!(imp.dropped, vec!["allowed-tools", "metadata.openclaw.install"]);
        assert!(imp.warnings.iter().any(|w| w.contains("allowed-tools")), "{:?}", imp.warnings);
        assert!(imp.front.get("allowed-tools").is_none());
        assert!(imp.front["metadata"]["openclaw"].get("install").is_none());
        assert!(imp.body.starts_with("# Discord"), "{:?}", imp.body);
        // The result round-trips through ark's own reader and its requirement gating.
        let again = normalize(&format!("---\n{}---\n{}", yaml::to_yaml(&imp.front), imp.body)).unwrap();
        assert_eq!(again.front["requires"], imp.front["requires"]);
    }

    #[test]
    fn compat_skill_hermes_variant_maps_platforms_to_os() {
        // Shape of hermes-agent/skills/web/blocked-page-recovery/SKILL.md.
        let src = "---\nname: blocked-page-recovery\ndescription: \"Use when a fetch fails.\"\nversion: 1.0.0\nauthor: Hermes Agent\nlicense: MIT\nplatforms: [linux, macos, windows]\nmetadata:\n  hermes:\n    tags: [Research, Archives]\n---\n# Recovery\n";
        let imp = normalize(src).unwrap();
        assert_eq!(variant(&imp.front), "hermes");
        assert_eq!(imp.front["os"], json!(["linux", "darwin", "windows"]), "macos is spelled darwin for os_satisfied");
        assert!(imp.mapped.iter().any(|m| m == "platforms → os"), "{:?}", imp.mapped);
        assert!(imp.dropped.is_empty(), "{:?}", imp.dropped);
        assert_eq!(imp.front["author"], "Hermes Agent", "unknown keys pass through untouched");
        assert!(imp.front.get("platforms").is_none());
    }

    #[test]
    fn compat_skill_claude_code_variant_drops_invocation_flags() {
        // Shape of a Claude Code plugin skill (also seen in OpenClaw's skills/).
        let src = "---\nname: manual-only\ndescription: \"Run the release checklist.\"\nallowed-tools: Bash, Read\ndisable-model-invocation: true\nuser-invocable: true\n---\n# Release\n";
        let imp = normalize(src).unwrap();
        assert_eq!(variant_of(src), Some("claude-code"));
        assert_eq!(imp.dropped, vec!["allowed-tools", "disable-model-invocation", "user-invocable"]);
        assert_eq!(imp.warnings.len(), 3);
        assert!(imp.mapped.is_empty(), "nothing was hoisted: {:?}", imp.mapped);
        assert_eq!(imp.front["description"], "Run the release checklist.");
    }

    #[test]
    fn compat_skill_rejects_broken_input_without_panicking() {
        assert!(normalize("no frontmatter here").is_err());
        assert!(normalize("---\nname: [unclosed\n---\nbody").is_err());
        assert!(normalize("---\ndescription: x\n---\n").unwrap_err().contains("no `name`"));
        assert!(normalize("---\nname: 7\n---\n").unwrap_err().contains("no `name`"));
        // A name ark would reject is imported with a warning, not silently dropped.
        let imp = normalize("---\nname: Bad Name\ndescription: x\n---\n").unwrap();
        assert_eq!(imp.name, "Bad Name");
        assert!(imp.warnings.iter().any(|w| w.contains("lowercase")));
    }

    #[test]
    fn compat_skill_write_is_readable_by_ark() {
        let d = ark_core::tmp::TempDir::new("ark-compat-skill");
        let imp = normalize("---\nname: notes\ndescription: Keep notes\nmetadata: {\"openclaw\": {\"requires\": {\"bins\": [\"rg\"]}}}\n---\nbody\n").unwrap();
        let p = write(&imp, &d.join("notes")).unwrap();
        let back = normalize(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(back.name, "notes");
        assert_eq!(back.front["requires"]["bins"][0], "rg");
        assert_eq!(back.body, "body\n");
    }

    #[test]
    fn compat_skill_real_corpora_normalize() {
        let dirs: Vec<std::path::PathBuf> = vec![
            "/home/noob/openclaw/dist/extensions".into(),
            "/home/noob/openclaw/skills".into(),
            "/home/noob/hermes-agent/skills".into(),
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../share/skills"),
        ];
        let mut seen = 0usize;
        let mut failures = Vec::new();
        let mut by_variant = std::collections::BTreeMap::new();
        for root in &dirs {
            let mut files = Vec::new();
            walk(root, 6, &mut files);
            for f in files {
                if f.file_name().is_some_and(|n| n == "SKILL.md") {
                    seen += 1;
                    let text = match std::fs::read_to_string(&f) {
                        Ok(t) => t,
                        Err(e) => {
                            failures.push(format!("{}: {e}", f.display()));
                            continue;
                        }
                    };
                    match normalize(&text) {
                        Ok(imp) => *by_variant.entry(variant(&imp.front)).or_insert(0usize) += 1,
                        Err(e) => failures.push(format!("{}: {e}", f.display())),
                    }
                }
            }
        }
        if seen == 0 {
            eprintln!("skipping: no upstream skill corpus");
            return;
        }
        println!("skills: {seen} SKILL.md normalized, {failures:?} failed, variants {by_variant:?}");
        assert!(failures.is_empty(), "{failures:#?}");
    }

    /// 7-6-1: the role packs are ordinary SKILL.md files to every upstream reader. Each one
    /// normalizes as a plain skill with nothing hoisted or dropped (OpenClaw and Hermes read
    /// `name` + `description` and ignore the rest), the layer fields survive a write/read
    /// round trip, and ark's own loader reads them back with `isco` as a string.
    #[test]
    fn compat_skill_role_packs_are_plain_skills_everywhere() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../share/roles");
        let mut files = Vec::new();
        walk(&root, 4, &mut files);
        files.retain(|f| f.file_name().is_some_and(|n| n == "SKILL.md"));
        assert!(files.len() >= 548, "{} packs", files.len());
        for f in &files {
            let text = std::fs::read_to_string(f).unwrap();
            let imp = normalize(&text).unwrap_or_else(|e| panic!("{}: {e}", f.display()));
            assert_eq!(variant(&imp.front), "plain", "{}", f.display());
            assert!(imp.dropped.is_empty() && imp.mapped.is_empty() && imp.warnings.is_empty(), "{}: {:?} {:?} {:?}", f.display(), imp.mapped, imp.dropped, imp.warnings);
            assert!(imp.front["isco"].is_string(), "{}: isco is a YAML string", f.display());
            let dir = f.parent().unwrap();
            let s = crate::skill::Skill::load(dir, &root, crate::skill::Source::Extra).unwrap();
            let r = s.role().unwrap_or_else(|| panic!("{}: role fields", f.display()));
            assert_eq!(s.name, dir.file_name().unwrap().to_string_lossy());
            assert!(!s.description.is_empty());
            assert_eq!(r.extends.is_none(), r.layer == "L0");
        }
        // Round trip through ark's writer keeps the layer fields.
        let d = ark_core::tmp::TempDir::new("ark-compat-role");
        let imp = from_dir(&root.join("L2/software-developer")).unwrap();
        let p = write(&imp, &d.join("software-developer")).unwrap();
        let back = crate::skill::Skill::load(p.parent().unwrap(), &d, crate::skill::Source::Extra).unwrap();
        assert_eq!(back.role().unwrap(), crate::skill::RoleMeta { layer: "L2".into(), isco: "2512".into(), extends: Some("professional-practice".into()), regulated: false });
    }

    /// Bare-integer `isco` (as older packs and other tools write it) still reads as a string,
    /// and a Distilly / colleague-skill style persona file (name + description + body, no
    /// layer) stays an ordinary skill.
    #[test]
    fn compat_skill_role_fields_from_other_writers() {
        let d = ark_core::tmp::TempDir::new("ark-compat-role2");
        for (name, text) in [
            ("bare", "---\nname: bare\ndescription: d\nlayer: L2\nisco: 110\nextends: armed-forces\nregulated: false\n---\nbody\n"),
            ("hermes", "---\nname: hermes\ndescription: d\nlayer: L1\nisco: 2\nextends: professional-core\nplatforms: [linux]\n---\nbody\n"),
            ("colleague", "---\nname: colleague\ndescription: How a teammate reviews code\nmetadata: {\"distilly\": {\"source\": \"team\"}}\n---\n# Review habits\n- read the tests first\n"),
        ] {
            let imp = normalize(text).unwrap();
            write(&imp, &d.join(name)).unwrap();
        }
        let load = |n: &str| crate::skill::Skill::load(&d.join(n), &d, crate::skill::Source::Extra).unwrap();
        assert_eq!(load("bare").role().unwrap().isco, "0110");
        let h = load("hermes");
        assert_eq!((h.role().unwrap().isco.as_str(), h.requirements().os), ("2", vec!["linux".to_string()]));
        let c = load("colleague");
        assert!(c.role().is_none() && c.description.contains("teammate"));
    }

    fn walk(dir: &std::path::Path, depth: usize, out: &mut Vec<std::path::PathBuf>) {
        if depth == 0 {
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            if name == "node_modules" || name == "__pycache__" || name == ".git" || name == "target" {
                continue;
            }
            if p.is_dir() {
                walk(&p, depth - 1, out);
            } else {
                out.push(p);
            }
        }
    }
}
