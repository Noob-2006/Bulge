//! The skills index in the system prompt and its live delta (Hermes `agent/prompt_builder.py`
//! skills block + `agent/skills_index_delta.py`, MIT).
//!
//! The index is part of the frozen system prompt (built at session start and after
//! compaction) so the provider prefix cache stays warm. A skill installed, created, removed or
//! disabled afterwards (hub install, the `skill` tool, the curator, a plugin, another process)
//! would otherwise never reach the model until the next rebuild. Every turn, the index the
//! session would build now is compared with the one its prompt carries (as amended by notes
//! already sent); a difference is delivered on the per-turn channel (`Lifecycle::prefetch`,
//! appended behind the cached prefix). Each note states the full difference against the
//! prompt, and a note is sent only when that difference changes.

use super::invoke;
use super::settings::Settings;
use crate::skill::{Skill, Source};
use seagent_kernel::config::{Config, Paths};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, Weak};

pub const NOTE_PREFIX: &str = "[System: The skills available in this conversation changed after its system prompt was built.";
const ADDED_HEAD: &str = "Now available (load with `skill action=view name=<name>` or read its SKILL.md when relevant, like the skills listed in the system prompt):";
const REMOVED_HEAD: &str = "No longer available:";
const ACCURATE_AGAIN: &str = " The skills listed in the system prompt are accurate again; earlier skill-change notes are superseded.";
/// Index descriptions are cut here (Hermes `SKILL_PROMPT_DESC_LIMIT`).
pub const DESC_LIMIT: usize = 60;

fn short(d: &str) -> String {
    let d = d.split_whitespace().collect::<Vec<_>>().join(" ");
    if d.chars().count() > DESC_LIMIT {
        format!("{}...", d.chars().take(DESC_LIMIT).collect::<String>())
    } else {
        d
    }
}

/// `{name: row}` for a catalog.
pub fn rows(cat: &[Skill]) -> BTreeMap<String, String> {
    cat.iter().map(|s| (s.name.clone(), format!("    - {}: {} ({})", s.name, short(&s.description), s.file.display()))).collect()
}

/// The `skills` system segment: every loadable skill grouped by category.
pub fn render(cat: &[Skill]) -> String {
    if cat.is_empty() {
        return String::new();
    }
    let mut groups: BTreeMap<String, Vec<&Skill>> = BTreeMap::new();
    for s in cat {
        let g = match &s.source {
            Source::Plugin(p) => format!("plugin {p}"),
            _ => s.category.clone().unwrap_or_else(|| "general".into()),
        };
        groups.entry(g).or_default().push(s);
    }
    let mut t = String::from("# Skills\nReusable procedures. Before following one, load it (`skill action=view name=<name>`, or read the SKILL.md path shown); `skill action=search query=<task>` finds one by what you are trying to do. The user can also run one as `/<name>`.\n<available_skills>\n");
    for (g, list) in groups {
        t.push_str(&format!("  {g}:\n"));
        for s in list {
            t.push_str(&format!("    - {}: {} ({})\n", s.name, short(&s.description), s.file.display()));
        }
    }
    t.push_str("</available_skills>\n");
    t
}

/// The note for a difference (`added` rows, `removed` names); empty sets = "accurate again".
pub fn note(added: &BTreeMap<String, String>, removed: &BTreeSet<String>) -> String {
    if added.is_empty() && removed.is_empty() {
        return format!("{NOTE_PREFIX}{ACCURATE_AGAIN}]");
    }
    let mut p = vec![NOTE_PREFIX.to_string()];
    if !added.is_empty() {
        p.push(ADDED_HEAD.to_string());
        p.extend(added.values().cloned());
    }
    if !removed.is_empty() {
        p.push(format!("{REMOVED_HEAD} {}", removed.iter().cloned().collect::<Vec<_>>().join(", ")));
    }
    p.join("\n") + "]"
}

/// Session → (its workspace, baseline the prompt carries, last announced (added, removed)).
type SessionState = (String, BTreeMap<String, String>, (BTreeSet<String>, BTreeSet<String>));

#[derive(Default)]
struct State {
    /// Workspace → names in the most recently built prompt index. Absent: that workspace's prompt
    /// carries no index (no skills), so there is no baseline to compare against (upstream returns
    /// early for a prompt without an `<available_skills>` block).
    built: HashMap<String, BTreeMap<String, String>>,
    /// Session → (its workspace, baseline the prompt carries, last announced (added, removed)).
    sessions: HashMap<String, SessionState>,
}

pub struct SkillsIndex {
    pub cfg: Config,
    pub paths: Paths,
    pub settings: Settings,
    state: Mutex<State>,
}

impl SkillsIndex {
    pub fn new(cfg: &Config, paths: &Paths) -> SkillsIndex {
        SkillsIndex { settings: Settings::load(cfg), cfg: cfg.clone(), paths: paths.clone(), state: Mutex::new(State::default()) }
    }

    fn current(&self, ws: &str) -> BTreeMap<String, String> {
        rows(&invoke::catalog(&self.cfg, &self.paths, Path::new(ws), &self.settings))
    }

    /// The per-turn delta note for `session`, if the model has not been told yet.
    pub fn delta(&self, session: &str, ws: &str) -> Option<String> {
        let current = self.current(ws);
        let mut st = self.state.lock().unwrap();
        let built = st.built.get(ws).cloned()?;
        let entry = st.sessions.entry(session.to_string()).or_insert_with(|| (ws.to_string(), built, Default::default()));
        let (_, base, (told_add, told_rm)) = entry.clone();
        let believed: BTreeSet<String> = base.keys().cloned().chain(told_add.iter().cloned()).filter(|n| !told_rm.contains(n)).collect();
        let now: BTreeSet<String> = current.keys().cloned().collect();
        if believed == now {
            return None;
        }
        let added: BTreeMap<String, String> = current.iter().filter(|(n, _)| !base.contains_key(*n)).map(|(n, r)| (n.clone(), r.clone())).collect();
        let removed: BTreeSet<String> = base.keys().filter(|n| !current.contains_key(*n)).cloned().collect();
        entry.2 = (added.keys().cloned().collect(), removed.clone());
        Some(note(&added, &removed))
    }

    /// `/reload-skills`: rescan and diff against the index this workspace's prompt carries.
    /// Nothing is mutated: the per-turn delta (`prefetch`) announces the same difference on the
    /// next turn, so the frozen prefix stays cache-warm (Hermes `agent/skill_commands.reload_skills`).
    pub fn reload(&self, ws: &str) -> Reload {
        let current = self.current(ws);
        let st = self.state.lock().unwrap();
        let total = current.len();
        let Some(base) = st.built.get(ws) else {
            return Reload { added: current.keys().map(|k| (k.clone(), current[k].clone())).collect(), removed: Vec::new(), updated: Vec::new(), total, baseline: false };
        };
        let mut out = Reload { total, baseline: true, ..Default::default() };
        for (name, row) in &current {
            match base.get(name) {
                None => out.added.push((name.clone(), row.clone())),
                Some(old) if old != row => out.updated.push((name.clone(), row.clone())),
                Some(_) => {}
            }
        }
        out.removed = base.keys().filter(|n| !current.contains_key(*n)).cloned().collect();
        out
    }
}

/// What `/reload-skills` found (`baseline` false: this workspace's prompt carries no index yet).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Reload {
    pub added: Vec<(String, String)>,
    pub removed: Vec<String>,
    pub updated: Vec<(String, String)>,
    pub total: usize,
    pub baseline: bool,
}

impl Reload {
    pub fn empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.updated.is_empty()
    }

    /// The reply, in the upstream shape (`Added Skills:` / `Removed Skills:` / total).
    pub fn render(&self) -> String {
        let row = |r: &str| r.trim().trim_start_matches("- ").to_string();
        let mut lines = vec!["Skills reloaded.".to_string()];
        if !self.baseline {
            lines.push("This session's system prompt carries no skill index yet; the skills below will be listed when it is rebuilt.".into());
        }
        if self.empty() {
            lines.push("No new or removed skills.".into());
        }
        if !self.added.is_empty() {
            lines.push("Added Skills:".into());
            lines.extend(self.added.iter().map(|(_, r)| format!("  - {}", row(r))));
        }
        if !self.removed.is_empty() {
            lines.push("Removed Skills:".into());
            lines.extend(self.removed.iter().map(|n| format!("  - {n}")));
        }
        if !self.updated.is_empty() {
            lines.push("Updated Skills:".into());
            lines.extend(self.updated.iter().map(|(_, r)| format!("  - {}", row(r))));
        }
        lines.push(format!("Total skills: {}", self.total));
        if !self.empty() && self.baseline {
            lines.push("The next turn tells the model what changed (the frozen system prompt is not rebuilt).".into());
        }
        lines.join("\n")
    }
}

/// The process-wide index for a data dir: `core::attach` registers one, and `/reload-skills`
/// reaches the same instance so the diff is against the prompt's actual baseline.
pub fn shared(cfg: &Config, paths: &Paths) -> Arc<SkillsIndex> {
    static REGISTRY: OnceLock<Mutex<Vec<Weak<SkillsIndex>>>> = OnceLock::new();
    let reg = REGISTRY.get_or_init(|| Mutex::new(Vec::new()));
    let mut v = reg.lock().unwrap_or_else(|p| p.into_inner());
    v.retain(|w| w.strong_count() > 0);
    if let Some(ix) = v.iter().filter_map(|w| w.upgrade()).find(|ix| ix.paths.data == paths.data) {
        return ix;
    }
    let ix = Arc::new(SkillsIndex::new(cfg, paths));
    v.push(Arc::downgrade(&ix));
    ix
}


impl seagent_kernel::lifecycle::Lifecycle for SkillsIndex {
    fn name(&self) -> String {
        "skills-index".into()
    }
    fn system_segment(&self, ws: &str) -> Option<seagent_core::SystemSegment> {
        let cat = invoke::catalog(&self.cfg, &self.paths, Path::new(ws), &self.settings);
        let text = render(&cat);
        let mut st = self.state.lock().unwrap();
        if text.trim().is_empty() {
            st.built.remove(ws);
        } else {
            st.built.insert(ws.to_string(), rows(&cat));
        }
        // A rebuilt prompt (new session or compaction) is the new baseline for that workspace's
        // sessions only — one process serves several workspaces (gateway, daemon).
        for (_, base, told) in st.sessions.values_mut().filter(|v| v.0 == ws) {
            *base = rows(&cat);
            *told = Default::default();
        }
        Some(seagent_core::SystemSegment { id: "skills".into(), text, cache: false })
    }
    fn prefetch(&self, session: &str, ws: &str, _prompt: &str) -> Option<String> {
        self.delta(session, ws)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_kernel::lifecycle::Lifecycle;

    #[test]
    fn segment_and_delta_notes() {
        let d = seagent_core::tmp::scratch_path(format!("seagent-index-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let paths = Paths { data: d.join("data"), config_dir: d.join("cfg"), runtime: d.join("run"), ..Default::default() };
        let ws = d.join("ws");
        let mk = |n: &str| {
            std::fs::create_dir_all(ws.join(".seagent/skills").join(n)).unwrap();
            std::fs::write(ws.join(".seagent/skills").join(n).join("SKILL.md"), format!("---\nname: {n}\ndescription: Does {n} things in a very long description that keeps going on and on\n---\n")).unwrap();
        };
        mk("alpha");
        let ix = SkillsIndex::new(&Config::default(), &paths);
        let wss = ws.to_string_lossy().to_string();
        let seg = ix.system_segment(&wss).unwrap();
        assert!(seg.id == "skills" && seg.text.contains("<available_skills>") && seg.text.contains("- alpha: Does alpha things in a very long description that keeps goin..."), "{}", seg.text);
        assert_eq!(ix.prefetch("s1", &wss, "hi"), None, "nothing changed");
        mk("beta");
        let n = ix.prefetch("s1", &wss, "hi").unwrap();
        assert!(n.starts_with(NOTE_PREFIX) && n.contains("- beta:") && !n.contains("No longer"), "{n}");
        assert_eq!(ix.prefetch("s1", &wss, "again"), None, "sent once");
        std::fs::remove_dir_all(ws.join(".seagent/skills/alpha")).unwrap();
        let n = ix.prefetch("s1", &wss, "x").unwrap();
        assert!(n.contains("- beta:") && n.contains("No longer available: alpha"), "full difference each time: {n}");
        std::fs::remove_dir_all(ws.join(".seagent/skills/beta")).unwrap();
        mk("alpha");
        let n = ix.prefetch("s1", &wss, "x").unwrap();
        assert!(n.contains("accurate again"), "{n}");
        // A rebuilt prompt resets the baseline.
        mk("gamma");
        ix.system_segment(&wss);
        assert_eq!(ix.prefetch("s1", &wss, "x"), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn no_index_means_no_baseline_and_rebuilds_stay_per_workspace() {
        let d = seagent_core::tmp::scratch_path(format!("seagent-index-ws-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let paths = Paths { data: d.join("data"), config_dir: d.join("cfg"), runtime: d.join("run"), ..Default::default() };
        let (ws1, ws2) = (d.join("one"), d.join("two"));
        let mk = |ws: &std::path::Path, n: &str| {
            std::fs::create_dir_all(ws.join(".seagent/skills").join(n)).unwrap();
            std::fs::write(ws.join(".seagent/skills").join(n).join("SKILL.md"), format!("---\nname: {n}\ndescription: {n}\n---\n")).unwrap();
        };
        // A build ships bundled skills, so an empty index is reached by disabling what exists.
        let mut cfg = Config::default();
        let all: Vec<toml::Value> = invoke::catalog(&cfg, &paths, &ws1, &Settings::from_table(&toml::Table::new())).into_iter().map(|s| toml::Value::String(s.name)).collect();
        assert!(!all.is_empty(), "the bundled skills are discoverable here");
        cfg.skills.insert("disabled".into(), toml::Value::Array(all));
        let ix = SkillsIndex::new(&cfg, &paths);
        let (w1, w2) = (ws1.to_string_lossy().to_string(), ws2.to_string_lossy().to_string());
        // A prompt without an index is never compared (upstream): no baseline, no note.
        assert!(ix.system_segment(&w2).unwrap().text.is_empty());
        mk(&ws2, "gamma");
        assert_eq!(ix.prefetch("s2", &w2, "x"), None, "no baseline yet");
        // One process serves several workspaces: rebuilding w2's prompt must not reset w1's.
        mk(&ws1, "alpha");
        ix.system_segment(&w1);
        assert_eq!(ix.prefetch("s1", &w1, "x"), None);
        mk(&ws2, "delta");
        ix.system_segment(&w2);
        assert_eq!(ix.prefetch("s1", &w1, "x"), None, "s1's baseline is w1's index, not w2's");
        assert_eq!(ix.prefetch("s2", &w2, "x"), None, "w2's rebuilt prompt carries both skills");
        mk(&ws1, "beta");
        let n = ix.prefetch("s1", &w1, "x").unwrap();
        assert!(n.contains("- beta:") && !n.contains("gamma") && !n.contains("No longer"), "{n}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn plugin_skills_are_indexed_and_announced() {
        // A plugin that ships `skills/lint/SKILL.md` is part of the index, grouped under the
        // plugin and named `plugin:skill` (Hermes `tools/skills_tool_plugin.py`).
        let d = seagent_core::tmp::scratch_path(format!("seagent-index-plugin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let paths = Paths { data: d.join("data"), config_dir: d.join("cfg"), runtime: d.join("run"), ..Default::default() };
        let ws = d.join("ws");
        let plug = d.join("myplug");
        std::fs::create_dir_all(plug.join("skills/lint")).unwrap();
        std::fs::write(plug.join("run.sh"), "#!/bin/sh").unwrap();
        std::fs::write(plug.join("skills/lint/SKILL.md"), "---\nname: lint\ndescription: Lint stuff\n---\nlint body").unwrap();
        let mut cfg = Config::default();
        cfg.plugins.insert("myplug".into(), toml::from_str(&format!("command = '{}'", plug.join("run.sh").display())).unwrap());
        let ix = SkillsIndex::new(&cfg, &paths);
        let wss = ws.to_string_lossy().to_string();
        let seg = ix.system_segment(&wss).unwrap();
        assert!(seg.text.contains("plugin myplug:") && seg.text.contains("- myplug:lint: Lint stuff"), "{}", seg.text);
        // Deleting the plugin is a removal, announced on the next turn.
        std::fs::remove_dir_all(plug.join("skills")).unwrap();
        let n = ix.prefetch("s1", &wss, "x").unwrap();
        assert!(n.starts_with(NOTE_PREFIX) && n.contains("No longer available: myplug:lint"), "{n}");
        assert_eq!(ix.prefetch("s1", &wss, "x"), None, "sent once");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// `/reload-skills`: added / removed / updated names, the total, and the same difference still
    /// arriving as the next turn's note (the prompt baseline is untouched).
    #[test]
    fn reload_reports_the_difference_and_the_delta_still_announces_it() {
        let d = seagent_core::tmp::scratch_path(format!("seagent-index-reload-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let paths = Paths { data: d.join("data"), config_dir: d.join("cfg"), runtime: d.join("run"), ..Default::default() };
        let ws = d.join("ws");
        let mk = |n: &str, desc: &str| {
            std::fs::create_dir_all(ws.join(".seagent/skills").join(n)).unwrap();
            std::fs::write(ws.join(".seagent/skills").join(n).join("SKILL.md"), format!("---\nname: {n}\ndescription: {desc}\n---\n")).unwrap();
        };
        mk("alpha", "first");
        mk("gamma", "old words");
        let ix = shared(&Config::default(), &paths);
        let wss = ws.to_string_lossy().to_string();
        ix.system_segment(&wss);
        // Nothing changed: an explicit reload says so (the bundled corpus is part of the catalog).
        let r = ix.reload(&wss);
        let total = r.total;
        assert!(r.baseline && r.empty(), "{r:?}");
        assert!(total > 2, "the shipped corpus is listed too: {total}");
        assert!(r.render().contains("No new or removed skills.") && r.render().contains(&format!("Total skills: {total}")), "{}", r.render());
        // Add, remove and rewrite a description.
        mk("beta", "second");
        std::fs::remove_dir_all(ws.join(".seagent/skills/alpha")).unwrap();
        mk("gamma", "new words");
        let r = ix.reload(&wss);
        assert_eq!((r.added.len(), r.removed.len(), r.updated.len()), (1, 1, 1), "{r:?}");
        assert!(r.added[0].0 == "beta" && r.added[0].1.contains("beta: second"), "{r:?}");
        assert_eq!(r.removed, ["alpha"]);
        let text = r.render();
        assert!(text.contains("Added Skills:\n  - beta: second ") && text.contains("Removed Skills:\n  - alpha") && text.contains("Updated Skills:\n  - gamma: new words "), "{text}");
        assert!(text.contains(&format!("Total skills: {}", r.total)) && text.contains("The next turn tells the model"), "{text}");
        // The frozen prompt is untouched: the same difference rides the next turn as the delta note.
        let n = ix.prefetch("s1", &wss, "x").unwrap();
        assert!(n.contains("- beta:") && n.contains("No longer available: alpha"), "{n}");
        assert_eq!(ix.prefetch("s1", &wss, "x"), None, "announced once");
        // A workspace whose prompt carries no index has no baseline to diff against.
        let fresh = d.join("other");
        std::fs::create_dir_all(fresh.join(".seagent/skills/only")).unwrap();
        std::fs::write(fresh.join(".seagent/skills/only/SKILL.md"), "---\nname: only\ndescription: d\n---\n").unwrap();
        let r = shared(&Config::default(), &paths).reload(&fresh.to_string_lossy());
        assert!(!r.baseline && r.added.iter().any(|(n, _)| n == "only"), "{r:?}");
        assert!(r.render().contains("carries no skill index yet"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
