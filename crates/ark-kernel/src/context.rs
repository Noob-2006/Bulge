//! Cache-first prompt assembly. Segments are ordered most-stable first and are
//! frozen into a `System` event, so the prefix stays byte-identical across steps
//! and the provider's prompt cache keeps hitting.

use crate::config::{Config, Paths};
use crate::projection::View;
use ark_core::{ModelRequest, SystemSegment, ToolSchema, ToolSpec};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

const PROJECT_FILES: &[&str] = &["AGENTS.md", "CLAUDE.md", ".ark/AGENTS.md"];
const MAX_PROJECT_BYTES: usize = 24_000;
const MAX_MEMORY_BYTES: usize = 8_000;

pub const IDENTITY: &str = "You are Ark, an autonomous agent running on the user's machine. Work until the task is done, verifying results with tools rather than guessing. Be concise in prose and precise in actions.

Rules:
- Paths are relative to the workspace unless absolute.
- Never ask the user for secret values. Reference stored secrets as {{secret:NAME}}; the kernel substitutes them at execution time and you never see the value.
- Only two things are gated: commands needing elevated privileges / changing the system, and sending sensitive data off the machine. If a call is blocked, do not retry it; pick another approach or explain what the user must do.
- Large tool outputs are saved to files; read slices of them instead of re-running the tool.
- Tools not listed with a full schema are in the tool index: call `tool_describe` once with all the ones you need, then `tool_call` to use them.";

pub struct ToolView<'a> {
    pub pinned: Vec<&'a ToolSpec>,
    pub unpinned: Vec<&'a ToolSpec>,
}

pub fn split_tools<'a>(specs: &'a [ToolSpec], cfg: &Config) -> ToolView<'a> {
    let mut v = ToolView { pinned: vec![], unpinned: vec![] };
    for s in specs {
        if cfg.tools.disabled.contains(&s.name) {
            continue;
        }
        let pinned = if cfg.tools.pinned.contains(&s.name) {
            true
        } else if cfg.tools.unpinned.contains(&s.name) {
            false
        } else {
            s.pinned
        };
        if pinned {
            v.pinned.push(s)
        } else {
            v.unpinned.push(s)
        }
    }
    v.pinned.sort_by(|a, b| a.name.cmp(&b.name));
    v.unpinned.sort_by(|a, b| a.name.cmp(&b.name));
    v
}

/// Build the frozen system segments for a session.
pub fn system_segments(cfg: &Config, paths: &Paths, workspace: &Path, specs: &[ToolSpec], utc_offset: i32) -> Vec<SystemSegment> {
    let tv = split_tools(specs, cfg);
    let mut segs = Vec::new();
    let mut identity = IDENTITY.to_string();
    if !cfg.identity.trim().is_empty() {
        identity.push_str("\n\n");
        identity.push_str(cfg.identity.trim());
    }
    segs.push(SystemSegment { id: "identity".into(), text: identity, cache: false });

    if !tv.unpinned.is_empty() {
        let mut t = String::from("# Tool index (tool_describe several at once, then tool_call)\n");
        for s in &tv.unpinned {
            t.push_str(&format!("- {}: {}\n", s.name, s.summary()));
        }
        segs.push(SystemSegment { id: "tools".into(), text: t, cache: false });
    }

    let skills = discover_skills(&paths.skills_dirs(workspace));
    if !skills.is_empty() {
        let mut t = String::from("# Skills (read the SKILL.md file before using one)\n");
        for (name, desc, path) in &skills {
            t.push_str(&format!("- {name}: {desc} ({})\n", path.display()));
        }
        segs.push(SystemSegment { id: "skills".into(), text: t, cache: false });
    }

    let mem_dir = paths.data.join("memory");
    let mut mem = String::new();
    for (file, title) in [("USER.md", "About the user"), ("MEMORY.md", "Your notes")] {
        if let Ok(s) = fs::read_to_string(mem_dir.join(file)) {
            if !s.trim().is_empty() {
                mem.push_str(&format!("## {title}\n{}\n", cap(&s, MAX_MEMORY_BYTES)));
            }
        }
    }
    if !mem.is_empty() {
        segs.push(SystemSegment { id: "memory".into(), text: format!("# Memory (snapshot at session start)\n{mem}"), cache: false });
    }

    let mut proj = String::new();
    for f in PROJECT_FILES {
        if let Ok(s) = fs::read_to_string(workspace.join(f)) {
            proj.push_str(&format!("## {f}\n{}\n", cap(&s, MAX_PROJECT_BYTES)));
        }
    }
    let now = crate::util::fmt_time(crate::util::unix_now(), utc_offset);
    proj.push_str(&format!("\n# Environment\nworkspace: {}\nos: {} {}\nsession started: {now} (UTC{:+})\n", workspace.display(), std::env::consts::OS, std::env::consts::ARCH, utc_offset as f64 / 60.0));
    segs.push(SystemSegment { id: "project".into(), text: proj, cache: true });
    segs
}

fn cap(s: &str, max: usize) -> String {
    crate::util::head_tail(s, max).0
}

/// `(name, description, path)` from `*/SKILL.md` YAML frontmatter.
pub fn discover_skills(dirs: &[PathBuf]) -> Vec<(String, String, PathBuf)> {
    let mut out: Vec<(String, String, PathBuf)> = Vec::new();
    for d in dirs {
        let Ok(rd) = fs::read_dir(d) else { continue };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let p = e.path().join("SKILL.md");
            let Ok(text) = fs::read_to_string(&p) else { continue };
            let (name, desc) = frontmatter(&text);
            let name = name.unwrap_or_else(|| e.file_name().to_string_lossy().to_string());
            if out.iter().any(|(n, _, _)| *n == name) {
                continue; // earlier (more specific) dirs win
            }
            out.push((name, desc.unwrap_or_default(), p));
        }
    }
    out
}

fn frontmatter(text: &str) -> (Option<String>, Option<String>) {
    let Some(rest) = text.strip_prefix("---") else { return (None, None) };
    let Some(end) = rest.find("\n---") else { return (None, None) };
    let mut name = None;
    let mut desc = None;
    for line in rest[..end].lines() {
        if let Some((k, v)) = line.split_once(':') {
            let v = v.trim().trim_matches('"').trim_matches('\'').to_string();
            match k.trim() {
                "name" => name = Some(v),
                "description" => desc = Some(v.chars().take(300).collect()),
                _ => {}
            }
        }
    }
    (name, desc)
}

pub fn meta_tools() -> Vec<ToolSchema> {
    vec![
        ToolSchema {
            name: "tool_describe".into(),
            description: "Show the full description and input schema of tools from the tool index. Pass every tool you plan to use in `names` at once.".into(),
            input_schema: json!({"type":"object","properties":{"names":{"type":"array","items":{"type":"string"}},"name":{"type":"string"}}}),
        },
        ToolSchema {
            name: "tool_call".into(),
            description: "Call a tool from the tool index by name with its input object.".into(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"input":{"type":"object"}},"required":["name","input"]}),
        },
    ]
}

pub fn split_model(m: &str) -> (&str, &str) {
    m.split_once('/').unwrap_or(("", m))
}

/// Assemble the request for the next step from the projected view.
pub fn build_request(view: &View, cfg: &Config, specs: &[ToolSpec], kernel_tools: &[ToolSchema], model: &str) -> ModelRequest {
    let tv = split_tools(specs, cfg);
    let mut tools: Vec<ToolSchema> = tv.pinned.iter().map(|s| s.schema()).collect();
    tools.extend(kernel_tools.iter().cloned());
    if !tv.unpinned.is_empty() {
        tools.extend(meta_tools());
    }
    let n = view.messages.len();
    ModelRequest {
        model: split_model(model).1.to_string(),
        system: view.system.clone(),
        messages: view.messages.clone(),
        tools,
        max_tokens: cfg.model.max_tokens,
        temperature: cfg.model.temperature,
        // Cache through the second-to-last message: stable across this step's retries
        // and the next step's prefix.
        cache_after_message: if n >= 2 { Some(n - 2) } else { None },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &str, pinned: bool) -> ToolSpec {
        ToolSpec { name: name.into(), description: format!("{name} does things. More detail."), input_schema: json!({"type":"object"}), parallel_safe: false, idempotent: false, pinned }
    }

    #[test]
    fn pinning_overrides_and_disabled() {
        let mut cfg = Config::default();
        cfg.tools.disabled = vec!["gone".into()];
        cfg.tools.pinned = vec!["b".into()];
        cfg.tools.unpinned = vec!["a".into()];
        let specs = [spec("a", true), spec("b", false), spec("gone", true)];
        let tv = split_tools(&specs, &cfg);
        assert_eq!(tv.pinned.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["b"]);
        assert_eq!(tv.unpinned.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["a"]);
    }

    #[test]
    fn segments_are_deterministic_and_include_project_and_skills() {
        let ws = std::env::temp_dir().join(format!("ark-ctx-{}", crate::util::random_hex(8)));
        fs::create_dir_all(ws.join(".ark/skills/deploy")).unwrap();
        fs::write(ws.join("AGENTS.md"), "Use cargo.").unwrap();
        fs::write(ws.join(".ark/skills/deploy/SKILL.md"), "---\nname: deploy\ndescription: \"Ship it\"\n---\nbody").unwrap();
        fs::create_dir_all(ws.join(".ark/skills/broken")).unwrap();
        fs::write(ws.join(".ark/skills/broken/SKILL.md"), "no frontmatter").unwrap();
        let paths = Paths { data: ws.join("data"), config_dir: ws.join("cfg"), runtime: ws.join("run") };
        let cfg = Config::default();
        let specs = [spec("read", true), spec("web_fetch", false)];
        let a = system_segments(&cfg, &paths, &ws, &specs, 480);
        let ids: Vec<_> = a.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["identity", "tools", "skills", "project"]);
        assert!(a[1].text.contains("web_fetch: web_fetch does things."));
        assert!(a[2].text.contains("deploy: Ship it") && a[2].text.contains("broken"));
        assert!(a[3].text.contains("Use cargo.") && a[3].cache);
        assert_eq!(a.iter().filter(|s| s.cache).count(), 1);
    }

    #[test]
    fn request_includes_meta_tools_only_when_needed() {
        let cfg = Config::default();
        let view = View::default();
        let r = build_request(&view, &cfg, &[spec("read", true)], &[], "anthropic/claude-x");
        assert_eq!(r.model, "claude-x");
        assert!(r.tools.iter().all(|t| t.name != "tool_call"));
        let r = build_request(&view, &cfg, &[spec("read", true), spec("w", false)], &[], "p/m");
        assert!(r.tools.iter().any(|t| t.name == "tool_call"));
        assert_eq!(r.cache_after_message, None);
    }

    #[test]
    fn model_split() {
        assert_eq!(split_model("openrouter/anthropic/claude"), ("openrouter", "anthropic/claude"));
        assert_eq!(split_model("bare"), ("", "bare"));
    }
}
