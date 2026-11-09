//! Loading skills into a turn: the catalog a workspace sees (local roots + plugin-provided
//! `plugin:skill` names), and the user message a `/skill`, a stacked `/a /b do X` or a
//! `/bundle` invocation becomes (Hermes `agent/skill_commands.py`,
//! `tools/skills_tool_plugin.py`, MIT).
//!
//! Plugin skills: every configured plugin whose directory (its command / first absolute
//! argument, as the plugin guard resolves it) has `skills/<name>/SKILL.md`, plus portable
//! packages installed under `<data>/plugins/<name>/skills/`, are served as `<plugin>:<name>`.
//! They are interactive-only (never auto-registered as bare channel commands).

use super::settings::{Settings, Store};
use super::{preprocess, setup, usage};
use crate::skill::{self, Missing, Skill, Source};
use seagent_kernel::config::{Config, Paths};
use seagent_kernel::vault::Vault;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Directory a `[plugins.<name>]` entry runs from (same rule as the plugin guard).
pub fn plugin_dir(t: &toml::Table) -> Option<PathBuf> {
    if let Some(c) = t.get("cwd").and_then(|v| v.as_str()) {
        let p = super::settings::expand(c);
        if p.is_dir() {
            return Some(p);
        }
    }
    let cmd = t.get("command").and_then(|v| v.as_str()).into_iter();
    let args = t.get("args").and_then(|v| v.as_array()).into_iter().flatten().filter_map(|v| v.as_str());
    for cand in cmd.chain(args) {
        let p = super::settings::expand(cand);
        if p.is_absolute() && p.exists() && !["/usr", "/bin", "/sbin", "/lib", "/nix"].iter().any(|s| p.starts_with(s)) {
            return Some(if p.is_dir() { p } else { p.parent().map(Path::to_path_buf).unwrap_or(p) });
        }
    }
    None
}

/// `(plugin, skills dir)` for every plugin that ships skills.
pub fn plugin_skill_roots(cfg: &Config, paths: &Paths) -> Vec<(String, PathBuf)> {
    let mut v = Vec::new();
    for (name, t) in &cfg.plugins {
        if t.get("enabled").and_then(|e| e.as_bool()) == Some(false) {
            continue;
        }
        if let Some(d) = plugin_dir(t) {
            if d.join("skills").is_dir() {
                v.push((name.clone(), d.join("skills")));
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir(paths.data.join("plugins")) {
        let mut es: Vec<_> = rd.flatten().collect();
        es.sort_by_key(|e| e.file_name());
        for e in es {
            let n = e.file_name().to_string_lossy().to_string();
            if e.path().join("skills").is_dir() && !e.path().join(".disabled").exists() && !n.starts_with('.') && !v.iter().any(|(p, _)| *p == n) && !cfg.plugins.get(&n).is_some_and(|t| t.get("enabled").and_then(|x| x.as_bool()) == Some(false)) {
                v.push((n, e.path().join("skills")));
            }
        }
    }
    v
}

/// Skills plugins provide, named `plugin:skill`.
pub fn plugin_skills(cfg: &Config, paths: &Paths) -> Vec<Skill> {
    let mut out = Vec::new();
    for (plugin, root) in plugin_skill_roots(cfg, paths) {
        for mut s in skill::discover(&[(root, Source::Plugin(plugin.clone()))]) {
            s.name = format!("{plugin}:{}", s.name);
            out.push(s);
        }
    }
    out
}

/// Everything the workspace can load: local roots (first definition wins) then plugin skills.
/// Disabled names (`[skills] disabled`) are dropped.
pub fn catalog(cfg: &Config, paths: &Paths, ws: &Path, s: &Settings) -> Vec<Skill> {
    let mut all = catalog_loadable(cfg, paths, ws, s);
    // Requirement gating (OpenClaw `evaluateRequirementsFromMetadata`): a skill whose binaries,
    // env, config or OS requirement is unmet is not offered — not in the index, `skills_list`
    // or `skills_search`. An explicit load (`skill action=view`, `/name`) still reaches it.
    all.retain(|k| k.eligible(cfg));
    all
}

/// The catalog before requirement gating: only `[skills] disabled` is applied. Explicit loads
/// use this (Hermes `skill_view` ignores the platform gate when serving a named skill).
pub fn catalog_loadable(cfg: &Config, paths: &Paths, ws: &Path, s: &Settings) -> Vec<Skill> {
    let mut all = skill::discover(&skill::roots(paths, ws, &s.external_dirs));
    all.extend(plugin_skills(cfg, paths));
    all.retain(|k| !s.is_disabled(&k.name));
    all
}

/// The catalog split into what this host can use and what it cannot, with the reasons
/// (`skill action=list verbose`, `seagent skills list --all`).
pub fn catalog_split(cfg: &Config, paths: &Paths, ws: &Path, s: &Settings) -> (Vec<Skill>, Vec<(Skill, skill::Missing)>) {
    let mut visible = Vec::new();
    let mut hidden = Vec::new();
    for sk in catalog_loadable(cfg, paths, ws, s) {
        let m = sk.missing(cfg);
        if m.is_empty() {
            visible.push(sk);
        } else {
            hidden.push((sk, m));
        }
    }
    (visible, hidden)
}

/// `Foo Bar` → `foo-bar` (the `/command` slug; `+` and `/` dropped).
pub fn slug(name: &str) -> String {
    let mut out = String::new();
    for c in name.trim().chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ':' || c == '.' {
            out.push(c.to_ascii_lowercase());
        } else if c.is_whitespace() && !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

pub const SKILL_DIR_NOTE: &str = "Resolve any relative paths in this skill (e.g. `scripts/foo.js`, `templates/config.yaml`) against that directory, then run them with the shell tool using the absolute path.";
const SINGLE_SKILL_INSTRUCTION: &str = "The user has provided the following instruction alongside the skill invocation: ";

fn supporting_files(dir: &Path) -> Vec<String> {
    let mut v = Vec::new();
    for sub in ["references", "templates", "scripts", "assets", "examples"] {
        let mut files = Vec::new();
        walk_files(&dir.join(sub), dir, &mut files);
        v.extend(files);
    }
    v.sort();
    v.truncate(50);
    v
}

fn walk_files(d: &Path, base: &Path, out: &mut Vec<String>) {
    let Ok(rd) = std::fs::read_dir(d) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk_files(&p, base, out);
        } else if let Ok(r) = p.strip_prefix(base) {
            out.push(r.to_string_lossy().to_string());
        }
    }
}

/// `metadata.seagent.config` / `metadata.hermes.config` values resolved from `[skills.config.<skill>]`:
/// every declared key is listed with the configured value, else the declared `default`, else
/// `(not set)` (upstream `_inject_skill_config` / `resolve_skill_config_values`), so the agent
/// needn't read the config file.
pub fn skill_config_block(sk: &Skill, cfg: &Config) -> Option<String> {
    let decl = sk.meta("metadata.seagent.config").or_else(|| sk.meta("metadata.hermes.config"))?;
    let keys: Vec<(String, Option<String>)> = match decl {
        serde_json::Value::Array(a) => a
            .iter()
            .filter_map(|v| v.get("key").and_then(|k| k.as_str()).or(v.as_str()).map(|k| {
                let default = v.get("default").filter(|d| !d.is_null()).map(|d| d.as_str().map(String::from).unwrap_or_else(|| d.to_string()));
                (k.to_string(), default)
            }))
            .collect(),
        serde_json::Value::Object(o) => o.keys().map(|k| (k.clone(), None)).collect(),
        _ => return None,
    };
    if keys.is_empty() {
        return None;
    }
    let section = cfg.skills.get("config").and_then(|c| c.get(&sk.name)).and_then(|c| c.as_table());
    let lines: Vec<String> = keys
        .iter()
        .map(|(k, default)| match section.and_then(|s| s.get(k)) {
            Some(toml::Value::String(s)) if !s.trim().is_empty() => format!("  {k} = {}", super::settings::expand(s).display()),
            Some(v) => format!("  {k} = {v}"),
            None => match default {
                Some(d) => format!("  {k} = {d}"),
                None => format!("  {k} = (not set)"),
            },
        })
        .collect();
    Some(format!("[Skill config ([skills.config.{}]):\n{}\n]", sk.name, lines.join("\n")))
}

/// The message block for one loaded skill.
pub fn skill_block(sk: &Skill, note: &str, instruction: &str, session: Option<&str>, cfg: &Config, s: &Settings, vault: &Vault) -> Result<String, String> {
    // The skill's declared environment goes in before its body is rendered: inline-shell
    // snippets and every command the model runs for this skill then see it.
    setup::prepare(&sk.front, &sk.name, cfg, vault);
    let content = preprocess::preprocess(&sk.body()?, Some(&sk.dir), session, s);
    let mut parts = vec![note.to_string(), String::new(), content.trim().to_string()];
    // The directory the model will use in shell commands: Git Bash spelling (`C:/…`) on Windows.
    parts.extend([String::new(), format!("[Skill directory: {}]", seagent_core::platform::shell::path_str(&sk.dir)), SKILL_DIR_NOTE.to_string()]);
    if let Some(c) = skill_config_block(sk, cfg) {
        parts.extend([String::new(), c]);
    }
    if let Some(n) = setup::setup_note(&sk.front, &vault.names()) {
        parts.extend([String::new(), format!("[Skill setup note: {n}]")]);
    }
    let sup = supporting_files(&sk.dir);
    if !sup.is_empty() {
        parts.extend([String::new(), "[This skill has supporting files (paths relative to the skill directory above):]".to_string()]);
        parts.extend(sup.iter().map(|f| format!("- {f}")));
        parts.push(format!("\nRead any of these with the read tool, or run scripts directly by absolute path (e.g. `node {}/scripts/foo.js`).", sk.dir.display()));
    }
    if !instruction.trim().is_empty() {
        parts.extend([String::new(), format!("{SINGLE_SKILL_INSTRUCTION}{}", instruction.trim())]);
    }
    Ok(parts.join("\n"))
}

pub struct Loader<'a> {
    pub cfg: &'a Config,
    pub paths: &'a Paths,
    pub ws: &'a Path,
    pub settings: &'a Settings,
    pub vault: Vault,
}

impl<'a> Loader<'a> {
    /// A loader whose vault is this install's `secrets.toml` (unreadable → empty: the setup note
    /// then names what is missing instead of failing the turn).
    pub fn new(cfg: &'a Config, paths: &'a Paths, ws: &'a Path, settings: &'a Settings) -> Loader<'a> {
        Loader { cfg, paths, ws, settings, vault: Vault::load(&paths.secrets()).unwrap_or_else(|_| Vault::empty()) }
    }
}

impl Loader<'_> {
    /// Explicit loads (a named skill, a stacked invocation, a bundle member): requirement gating
    /// does not hide a skill the user or model asked for by name.
    pub fn catalog(&self) -> Vec<Skill> {
        catalog_loadable(self.cfg, self.paths, self.ws, self.settings)
    }

    /// What the index / `skills_list` / `skills_search` offer.
    pub fn offered(&self) -> Vec<Skill> {
        catalog(self.cfg, self.paths, self.ws, self.settings)
    }

    fn track(&self, name: &str) {
        usage::bump_use(&Store::new(self.paths), name);
    }

    /// `/name instruction` → message, or None when `key` is not a loadable skill.
    pub fn invoke(&self, key: &str, instruction: &str, session: Option<&str>) -> Option<Result<String, String>> {
        let cat = self.catalog();
        let sk = resolve(&cat, key)?;
        let note = format!("[IMPORTANT: The user has invoked the \"{}\" skill, indicating they want you to follow its instructions. The full skill content is loaded below.]", sk.name);
        self.track(&sk.name);
        Some(skill_block(sk, &note, instruction, session, self.cfg, self.settings, &self.vault))
    }

    /// `/a /b do X`: further leading `/skill` tokens (up to 5) load together.
    pub fn invoke_stacked(&self, first: &str, rest: &str, session: Option<&str>) -> Option<Result<String, String>> {
        let cat = self.catalog();
        resolve(&cat, first)?;
        let mut keys = vec![first.to_string()];
        let mut tail = rest.trim();
        while keys.len() < 5 {
            let Some(tok) = tail.split_whitespace().next().filter(|t| t.starts_with('/')) else { break };
            let k = tok.trim_start_matches('/');
            if resolve(&cat, k).is_none() || keys.iter().any(|x| x == k) {
                break;
            }
            keys.push(k.to_string());
            tail = tail[tok.len()..].trim_start();
        }
        if keys.len() == 1 {
            return self.invoke(first, rest, session);
        }
        let mut names = Vec::new();
        let mut blocks = Vec::new();
        for k in &keys {
            let sk = resolve(&cat, k).unwrap();
            self.track(&sk.name);
            match skill_block(sk, &format!("[Loaded as part of a stacked skill invocation: {}.]", sk.name), "", session, self.cfg, self.settings, &self.vault) {
                Ok(b) => {
                    names.push(sk.name.clone());
                    blocks.push(b);
                }
                Err(e) => return Some(Err(e)),
            }
        }
        let header = scaffold_header("stacked skill bundle", &names, &[], &[], "", tail);
        Some(Ok(std::iter::once(header).chain(blocks).collect::<Vec<_>>().join("\n\n")))
    }

    /// A bundle's message: every member loaded under one header (missing / disabled members skipped).
    pub fn invoke_bundle(&self, b: &super::bundles::Bundle, instruction: &str, session: Option<&str>) -> Result<String, String> {
        let cat = catalog_loadable(self.cfg, self.paths, self.ws, &Settings { disabled: vec![], ..self.settings.clone() });
        let (mut names, mut missing, mut disabled, mut blocks) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for m in &b.skills {
            match resolve(&cat, m) {
                Some(sk) if self.settings.is_disabled(&sk.name) => disabled.push(m.clone()),
                Some(sk) => {
                    self.track(&sk.name);
                    blocks.push(skill_block(sk, &format!("[Loaded as part of the \"{}\" skill bundle.]", b.name), "", session, self.cfg, self.settings, &self.vault)?);
                    names.push(sk.name.clone());
                }
                None => missing.push(m.clone()),
            }
        }
        if blocks.is_empty() {
            return Err(format!("bundle `{}`: none of its skills are installed ({})", b.name, b.skills.join(", ")));
        }
        let header = scaffold_header(&format!("\"{}\" skill bundle", b.name), &names, &missing, &disabled, &b.instruction, instruction);
        Ok(std::iter::once(header).chain(blocks).collect::<Vec<_>>().join("\n\n"))
    }
}

/// Grouping key a skill is listed under: its category folder, or `plugin <name>`.
pub fn group_of(sk: &Skill) -> String {
    match &sk.source {
        Source::Plugin(p) => format!("plugin {p}"),
        _ => sk.category.clone().unwrap_or_else(|| "general".into()),
    }
}

/// `skills_list`: the offered catalog as one grouped block with each skill's description and
/// SKILL.md path (Hermes `skills_list` returns name/description/category; the path is what
/// upstream renders in the prompt index). `verbose` names the skills this host cannot use and why.
pub fn list_text(cat: &[Skill], hidden: &[(Skill, Missing)], filtered: bool, verbose: bool) -> String {
    let mut groups: BTreeMap<String, Vec<&Skill>> = BTreeMap::new();
    for s in cat {
        groups.entry(group_of(s)).or_default().push(s);
    }
    let cats: Vec<String> = groups.keys().cloned().collect();
    let mut out = if cat.is_empty() {
        if filtered {
            "no skill matches (try `skill action=list` for the whole catalog)".to_string()
        } else {
            "No skills found in the skills directory.".to_string()
        }
    } else {
        format!(
            "{} skill(s) in {} categor{} — load one with `skill action=view name=<name>`:\n",
            cat.len(),
            cats.len(),
            if cats.len() == 1 { "y" } else { "ies" }
        )
    };
    for (g, list) in &groups {
        out.push_str(&format!("{g}:\n"));
        for s in list {
            out.push_str(&format!("  - {}: {} ({})\n", s.name, s.description, s.file.display()));
        }
    }
    if !hidden.is_empty() {
        if verbose {
            out.push_str(&format!("\n{} installed skill(s) cannot run on this host (unmet requirements):\n", hidden.len()));
            for (s, m) in hidden {
                out.push_str(&format!("  - {}: {} ({}) — {}\n", s.name, s.description, s.file.display(), m.describe()));
            }
        } else {
            out.push_str(&format!(
                "\n{} installed skill(s) cannot run on this host (unmet requirements); pass verbose=true to see which and why: {}\n",
                hidden.len(),
                hidden.iter().map(|(s, _)| s.name.clone()).collect::<Vec<_>>().join(", ")
            ));
        }
    }
    out.trim_end().to_string()
}

/// A typed command → skill (`_` ≡ `-` for Telegram, `category/name`, `plugin:name`).
pub fn resolve<'a>(cat: &'a [Skill], key: &str) -> Option<&'a Skill> {
    let k = key.trim().trim_start_matches('/');
    skill::find(cat, k).or_else(|| cat.iter().find(|s| slug(&s.name) == slug(k) || slug(&s.name) == slug(&k.replace('_', "-"))))
}

pub fn scaffold_header(subject: &str, loaded: &[String], missing: &[String], disabled: &[String], extra: &str, user: &str) -> String {
    let mut l = vec![format!("[IMPORTANT: The user has invoked the {subject}, loading {} skills together. Treat every skill below as active guidance for this turn.]", loaded.len()), String::new(), format!("Skills loaded: {}", loaded.join(", "))];
    if !missing.is_empty() {
        l.push(format!("Skills missing (skipped): {}", missing.join(", ")));
    }
    if !disabled.is_empty() {
        l.push(format!("Skills disabled (skipped): {}", disabled.join(", ")));
    }
    if !extra.trim().is_empty() {
        l.extend([String::new(), format!("Bundle instruction: {}", extra.trim())]);
    }
    if !user.trim().is_empty() {
        l.extend([String::new(), format!("User instruction: {}", user.trim())]);
    }
    l.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn fixture(tag: &str) -> (PathBuf, Paths, PathBuf) {
        let d = seagent_core::tmp::scratch_path(format!("seagent-invoke-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let paths = Paths { data: d.join("data"), config_dir: d.join("config"), runtime: d.join("run"), ..Default::default() };
        let ws = d.join("ws");
        std::fs::create_dir_all(ws.join(".seagent/skills/deploy/scripts")).unwrap();
        std::fs::write(ws.join(".seagent/skills/deploy/SKILL.md"), "---\nname: deploy\ndescription: Ship it\nrequired_environment_variables: [DEPLOY_TOKEN_XYZ]\n---\nRun ${SEAGENT_SKILL_DIR}/scripts/go.sh for ${SEAGENT_SESSION_ID}").unwrap();
        std::fs::write(ws.join(".seagent/skills/deploy/scripts/go.sh"), "echo").unwrap();
        std::fs::create_dir_all(ws.join(".seagent/skills/review")).unwrap();
        std::fs::write(ws.join(".seagent/skills/review/SKILL.md"), "---\nname: review\ndescription: Review code\n---\nLook closely.").unwrap();
        (d, paths, ws)
    }

    #[test]
    fn plugin_skills_messages_and_stacking() {
        let (d, paths, ws) = fixture("a");
        let pdir = d.join("myplug");
        std::fs::create_dir_all(pdir.join("skills/lint")).unwrap();
        std::fs::write(pdir.join("plugin.sh"), "#!/bin/sh").unwrap();
        std::fs::write(pdir.join("skills/lint/SKILL.md"), "---\nname: lint\ndescription: Lint stuff\n---\nlint body").unwrap();
        std::fs::create_dir_all(paths.data.join("plugins/portable/skills/fmt")).unwrap();
        std::fs::write(paths.data.join("plugins/portable/skills/fmt/SKILL.md"), "---\nname: fmt\ndescription: Format\n---\nfmt body").unwrap();
        let mut cfg = Config::default();
        cfg.plugins.insert("myplug".into(), toml::from_str(&format!("command = '{}'", pdir.join("plugin.sh").display())).unwrap());
        let s = Settings::from_table(&toml::Table::new());
        let names: Vec<String> = plugin_skills(&cfg, &paths).into_iter().map(|s| s.name).collect();
        assert_eq!(names, ["myplug:lint", "portable:fmt"]);
        let l = Loader { cfg: &cfg, paths: &paths, ws: &ws, settings: &s, vault: Vault::empty() };
        let m = l.invoke("deploy", "to prod", Some("sess1")).unwrap().unwrap();
        assert!(m.starts_with("[IMPORTANT: The user has invoked the \"deploy\" skill"), "{m}");
        assert!(m.contains(&format!("Run {}/scripts/go.sh for sess1", seagent_core::platform::shell::path_str(&ws.join(".seagent").join("skills").join("deploy")))), "{m}");
        assert!(m.contains("[Skill setup note: Setup needed before using this skill: missing env $DEPLOY_TOKEN_XYZ."), "{m}");
        assert!(m.contains("- scripts/go.sh") && m.ends_with("skill invocation: to prod"));
        // Collected secrets reach the skill's environment (vault → this process → its commands).
        let vault = Vault::empty();
        vault.set("DEPLOY_TOKEN_XYZ", "tok-123").unwrap();
        let l = Loader { cfg: &cfg, paths: &paths, ws: &ws, settings: &s, vault };
        let m = l.invoke("deploy", "", None).unwrap().unwrap();
        assert!(!m.contains("Skill setup note"), "ready once the vault has the value: {m}");
        assert_eq!(std::env::var("DEPLOY_TOKEN_XYZ").as_deref(), Ok("tok-123"), "injected for the skill's commands");
        assert!(setup::passthrough_names().contains(&"DEPLOY_TOKEN_XYZ".to_string()), "and forwarded to sandboxes");
        assert!(l.invoke("myplug:lint", "", None).unwrap().unwrap().contains("lint body"));
        assert!(l.invoke("nope", "", None).is_none());
        let st = l.invoke_stacked("deploy", "/review /deploy now please", None).unwrap().unwrap();
        assert!(st.contains("loading 2 skills together") && st.contains("User instruction: /deploy now please") && st.contains("Look closely."), "{st}");
        assert_eq!(usage::get(&Store::new(&paths), "deploy")["use_count"], 3);
        assert_eq!(slug("Foo Bar+"), "foo-bar");
        let _ = std::fs::remove_dir_all(&d);
    }
}
