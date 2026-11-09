//! The skill model: a directory with `SKILL.md` (YAML frontmatter + Markdown body) and
//! optional supporting files (`references/`, `templates/`, `scripts/`, `assets/`).
//! Discovery walks the skill roots (project → user → bundled → extra), nested category
//! folders included (Hermes `skills/<category>/<name>/SKILL.md`); the first root to define
//! a name wins. Shared by the tools, the hub, the CLI and the prompt index.

use seagent_kernel::config::{Config, Paths};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

/// Where a skill was found. Earlier variants shadow later ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// `<ws>/.seagent/skills`, `<ws>/.claude/skills`, `<ws>/.agents/skills`.
    Project,
    /// `<data>/skills`: agent-created, hub-installed and synced bundled skills.
    User,
    /// Shipped with seagent (`share/skills`), loaded in place when not synced.
    Bundled,
    /// Declared by a plugin (`plugin:skill` names).
    Plugin(String),
    /// Other configured / compatible dirs (`~/.claude/skills`, `[skills] extra_dirs`).
    Extra,
}

impl Source {
    pub fn label(&self) -> String {
        match self {
            Source::Project => "project".into(),
            Source::User => "user".into(),
            Source::Bundled => "bundled".into(),
            Source::Plugin(p) => format!("plugin:{p}"),
            Source::Extra => "extra".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Skill {
    pub name: String,
    pub description: String,
    /// The skill directory.
    pub dir: PathBuf,
    /// Its `SKILL.md`.
    pub file: PathBuf,
    /// Category folder(s) between the root and the skill dir (`devops`, `mlops/training`), if nested.
    pub category: Option<String>,
    pub source: Source,
    /// The parsed frontmatter (a JSON object).
    pub front: Value,
}

/// The role-pack part of a skill's frontmatter ([`Skill::role`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleMeta {
    pub layer: String,
    pub isco: String,
    pub extends: Option<String>,
    pub regulated: bool,
}

/// Maximum description length kept for the index (Hermes `MAX_DESCRIPTION_LENGTH`).
pub const MAX_DESCRIPTION: usize = 1024;
/// Skill names: lowercase letters, digits, `-`, `_`, `.`; ≤ 64 chars (Hermes `MAX_NAME_LENGTH`).
pub const MAX_NAME: usize = 64;

pub fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= MAX_NAME && n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.')) && !n.starts_with(['.', '-'])
}

impl Skill {
    /// Load `<dir>/SKILL.md`. The name defaults to the directory name.
    pub fn load(dir: &Path, root: &Path, source: Source) -> Result<Skill, String> {
        let file = dir.join("SKILL.md");
        let text = fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
        let (front, _) = crate::yaml::frontmatter(&text);
        let dir_name = dir.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
        let name = front.get("name").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(String::from).unwrap_or(dir_name);
        let description = front.get("description").and_then(Value::as_str).unwrap_or("").trim().chars().take(MAX_DESCRIPTION).collect();
        // Category ids use `/` on every OS (`devops/k8s`).
        let category = dir.parent().and_then(|p| p.strip_prefix(root).ok()).map(seagent_core::platform::layout::model_path).filter(|s| !s.is_empty());
        Ok(Skill { name, description, dir: dir.to_path_buf(), file, category, source, front })
    }

    /// The Markdown body (frontmatter removed).
    pub fn body(&self) -> Result<String, String> {
        let text = fs::read_to_string(&self.file).map_err(|e| format!("{}: {e}", self.file.display()))?;
        Ok(crate::yaml::frontmatter(&text).1.to_string())
    }

    /// A frontmatter value by dotted path (`metadata.hermes.tags`).
    pub fn meta(&self, path: &str) -> Option<&Value> {
        path.split('.').try_fold(&self.front, |v, k| v.get(k))
    }

    /// Role-pack fields (`share/roles`, BATCH-next §7-6-1): `layer`, `isco` (always a string —
    /// a bare YAML integer is read back as its digits, a unit group padded to four), `extends`.
    /// `None` for an ordinary skill.
    pub fn role(&self) -> Option<RoleMeta> {
        let layer = self.front.get("layer").and_then(Value::as_str).map(str::trim).filter(|l| !l.is_empty())?.to_string();
        let isco = match self.front.get("isco") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Number(n)) => n.to_string(),
            _ => String::new(),
        };
        Some(RoleMeta {
            isco: seagent_kernel::roles::normalize_isco(&isco, seagent_kernel::roles::Layer::parse(&layer)),
            extends: self.front.get("extends").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(String::from),
            regulated: self.front.get("regulated").and_then(|v| v.as_bool().or_else(|| v.as_str().map(|s| s.eq_ignore_ascii_case("true")))).unwrap_or(false),
            layer,
        })
    }

    /// Runtime requirements the frontmatter declares.
    pub fn requirements(&self) -> Requirements {
        Requirements::of(&self.front)
    }

    /// What this host lacks for this skill; empty means eligible (shown in the index, the
    /// `skills_list` catalog and `skills_search`).
    pub fn missing(&self, cfg: &Config) -> Missing {
        self.missing_on(cfg, host_platform())
    }

    pub fn missing_on(&self, cfg: &Config, platform: &str) -> Missing {
        let req = self.requirements();
        let missing_bins: Vec<String> = req.bins.into_iter().filter(|b| !has_bin(b)).collect();
        // `anyBins` needs one of the alternatives, not all of them.
        let any_missing = if req.any_bins.is_empty() || req.any_bins.iter().any(|b| has_bin(b)) {
            Vec::new()
        } else {
            req.any_bins
        };
        let missing_env: Vec<String> = req.env.into_iter().filter(|e| !env_satisfied(cfg, &self.name, e)).collect();
        let missing_config: Vec<String> = req.config.into_iter().filter(|p| !config_satisfied(cfg, p)).collect();
        let missing_os = if req.os.is_empty() || os_satisfied(&req.os, platform) { Vec::new() } else { req.os };
        Missing { bins: missing_bins, any_bins: any_missing, env: missing_env, config: missing_config, os: missing_os }
    }

    /// No unmet requirement on this host (OpenClaw `eligible`).
    pub fn eligible(&self, cfg: &Config) -> bool {
        self.missing(cfg).is_empty()
    }
}

/// `requires.{bins,anyBins,env,config}` + `os` from OpenClaw's manifest namespaces and Hermes'
/// `platforms:` (OpenClaw `src/shared/requirements.ts`, Hermes `skill_matches_platform`).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Requirements {
    pub bins: Vec<String>,
    pub any_bins: Vec<String>,
    pub env: Vec<String>,
    pub config: Vec<String>,
    pub os: Vec<String>,
}

impl Requirements {
    pub fn is_empty(&self) -> bool {
        *self == Requirements::default()
    }

    pub fn of(front: &Value) -> Requirements {
        let mut out = Requirements::default();
        // `requires` at the top level and under every manifest namespace skills are ported from.
        let mut blocks: Vec<&Value> = Vec::new();
        if front.get("requires").is_some() {
            blocks.push(&front["requires"]);
        }
        for ns in ["seagent", "ark", "openclaw", "hermes"] {
            if let Some(b) = front.get("metadata").and_then(|m| m.get(ns)) {
                if let Some(r) = b.get("requires") {
                    blocks.push(r);
                }
                if let Some(os) = b.get("os") {
                    push_unique(&mut out.os, list(Some(os)));
                }
            }
        }
        for b in blocks {
            push_unique(&mut out.bins, list(b.get("bins")));
            push_unique(&mut out.any_bins, list(b.get("anyBins").or_else(|| b.get("any_bins"))));
            push_unique(&mut out.env, list(b.get("env")));
            push_unique(&mut out.config, list(b.get("config")));
            push_unique(&mut out.os, list(b.get("os")));
        }
        // Hermes spells an OS allowlist `platforms:`; `os:` at the top level is the OpenClaw shorthand.
        push_unique(&mut out.os, list(front.get("platforms")));
        push_unique(&mut out.os, list(front.get("os")));
        out
    }
}

/// What a host lacks: one list per requirement kind (OpenClaw `missing`).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Missing {
    pub bins: Vec<String>,
    pub any_bins: Vec<String>,
    pub env: Vec<String>,
    pub config: Vec<String>,
    pub os: Vec<String>,
}

impl Missing {
    pub fn is_empty(&self) -> bool {
        *self == Missing::default()
    }

    /// `bins: git, gh; env: GH_TOKEN; os: linux` (OpenClaw `formatMissingSkillSummary`).
    pub fn describe(&self) -> String {
        let groups = [("bins", &self.bins), ("any bins", &self.any_bins), ("env", &self.env), ("config", &self.config), ("os", &self.os)];
        let parts: Vec<String> = groups.iter().filter(|(_, v)| !v.is_empty()).map(|(k, v)| format!("{k}: {}", v.join(", "))).collect();
        if parts.is_empty() {
            "unknown requirement".to_string()
        } else {
            parts.join("; ")
        }
    }
}

fn list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect(),
        Some(Value::String(s)) => s.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect(),
        _ => Vec::new(),
    }
}

fn push_unique(into: &mut Vec<String>, items: Vec<String>) {
    for i in items {
        if !into.contains(&i) {
            into.push(i);
        }
    }
}

/// The platform string requirements are matched against (`macos` ≡ `darwin`).
pub fn host_platform() -> &'static str {
    std::env::consts::OS
}

pub fn os_satisfied(required: &[String], platform: &str) -> bool {
    let norm = |s: &str| match s.trim().to_ascii_lowercase() {
        m if m == "macos" || m == "mac" => "darwin".to_string(),
        other => other,
    };
    let now = norm(platform);
    required.iter().any(|r| norm(r) == now)
}

/// Is `bin` on PATH (or an executable path)?
pub fn has_bin(bin: &str) -> bool {
    let bin = bin.trim();
    if bin.is_empty() {
        return false;
    }
    let executable = |p: &Path| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(p).map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
        }
        #[cfg(not(unix))]
        {
            p.is_file()
        }
    };
    // Windows: `git` is `git.exe` (PATHEXT), and paths may use `\`.
    // `bash` / `python3` mean the real thing: not System32\bash.exe (WSL) or the WindowsApps
    // Store aliases, which `which` finds on every Windows 10/11 machine.
    #[cfg(not(unix))]
    {
        use seagent_core::platform::layout;
        match bin {
            "bash" | "bash.exe" => return layout::bash().is_some(),
            "python3" | "python" | "python3.exe" | "python.exe" => return layout::python3().is_some(),
            _ => {}
        }
        if layout::which(bin).is_some_and(|p| !layout::is_windows_apps_alias(&p)) {
            return true;
        }
    }
    if bin.contains('/') {
        return executable(Path::new(bin));
    }
    std::env::var_os("PATH").is_some_and(|paths| std::env::split_paths(&paths).any(|d| executable(&d.join(bin))))
}

/// `requires.env` is satisfied by the process environment, or by a value the skill's own
/// `[skills.env.<skill>]` / `[skills.entries]` entry supplies before it runs.
fn env_satisfied(cfg: &Config, skill: &str, name: &str) -> bool {
    if std::env::var(name).is_ok_and(|v| !v.is_empty()) {
        return true;
    }
    let table_value = |v: &toml::Value| match v {
        toml::Value::String(s) => !s.trim().is_empty(),
        toml::Value::Boolean(b) => *b,
        toml::Value::Integer(i) => *i != 0,
        toml::Value::Array(a) => !a.is_empty(),
        _ => true,
    };
    if let Some(v) = cfg.skills.get("env").and_then(|e| e.get(skill)).and_then(|e| e.get(name)) {
        if table_value(v) {
            return true;
        }
    }
    if let Some(v) = cfg.skills.get("entries").and_then(|e| e.get(skill)).and_then(|e| e.get("env")).and_then(|e| e.get(name)) {
        return table_value(v);
    }
    // A dotenv-style value nested under the skill's own entry (`[skills.entries.<name>] NAME = "…"`).
    cfg.skills.get("entries").and_then(|e| e.get(skill)).and_then(|e| e.get(name)).is_some_and(table_value)
}

/// A dotted config path (`skills.entries.coding-agent.enabled`) is satisfied when it exists and is
/// truthy — the OpenClaw `requires.config` check.
pub fn config_satisfied(cfg: &Config, path: &str) -> bool {
    let path = path.trim();
    let rest = path.strip_prefix("skills.").unwrap_or(path);
    let mut cur: &toml::Value = match cfg.skills.get(rest.split('.').next().unwrap_or(rest)) {
        Some(v) => v,
        None => return false,
    };
    for key in rest.split('.').skip(1) {
        match cur.get(key) {
            Some(v) => cur = v,
            None => return false,
        }
    }
    match cur {
        toml::Value::Boolean(b) => *b,
        toml::Value::String(s) => !s.trim().is_empty(),
        toml::Value::Integer(i) => *i != 0,
        toml::Value::Array(a) => !a.is_empty(),
        toml::Value::Table(t) => !t.is_empty(),
        toml::Value::Float(f) => *f != 0.0,
        toml::Value::Datetime(_) => true,
    }
}

/// The skill roots for a workspace, most specific first. `bundled` is the share dir's
/// `skills/` when seagent ships one (see `share_dir`).
pub fn roots(paths: &Paths, ws: &Path, extra: &[PathBuf]) -> Vec<(PathBuf, Source)> {
    let mut v: Vec<(PathBuf, Source)> = vec![
        // Joined per component: `ws\.seagent\skills` on Windows, not `ws\.seagent/skills`.
        (ws.join(".seagent").join("skills"), Source::Project),
        (ws.join(".claude").join("skills"), Source::Project),
        (ws.join(".agents").join("skills"), Source::Project),
        (user_dir(paths), Source::User),
    ];
    if let Some(s) = share_dir() {
        v.push((s.join("skills"), Source::Bundled));
    }
    if let Some(h) = std::env::var_os("HOME") {
        v.push((PathBuf::from(h).join(".claude").join("skills"), Source::Extra));
    }
    v.extend(extra.iter().map(|p| (p.clone(), Source::Extra)));
    v
}

/// `<data>/skills`: where skills are created, installed and synced.
pub fn user_dir(paths: &Paths) -> PathBuf {
    paths.data.join("skills")
}

/// seagent's shared data dir (bundled skills, optional-skills, optional-mcps, plugin-catalog, roles):
/// `$SEAGENT_SHARE_DIR`, `<exe>/../share/seagent`, `/usr/{local/,}share/seagent`, or the checkout the binary
/// runs from. Resolved at run time only (see `seagent_core::share`).
pub fn share_dir() -> Option<PathBuf> {
    seagent_core::share::share_dir()
}

/// Every skill under `roots` (first definition of a name wins). Nested category folders are
/// walked up to depth 4; hidden dirs and `.archive` are skipped.
pub fn discover(roots: &[(PathBuf, Source)]) -> Vec<Skill> {
    let mut out: Vec<Skill> = Vec::new();
    for (root, src) in roots {
        let mut found = Vec::new();
        walk(root, root, 0, src, &mut found);
        // gen2-508: a shipped skill that no longer matches this build's pins is not loaded.
        if matches!(src, Source::Bundled) && crate::integrity::applies(root) {
            found.retain(|s| match crate::integrity::check_skill(root, &s.dir) {
                Ok(()) => true,
                Err(e) => {
                    warn_once(&e);
                    false
                }
            });
        }
        for s in found {
            if !out.iter().any(|o| o.name == s.name) {
                out.push(s);
            }
        }
    }
    out
}

/// Every skill under `root`, without the bundled-integrity filter (the integrity check
/// itself needs to see what is on disk).
pub(crate) fn discover_unchecked(root: &Path, src: Source) -> Vec<Skill> {
    let mut found = Vec::new();
    walk(root, root, 0, &src, &mut found);
    found
}

fn warn_once(msg: &str) {
    static SAID: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> = std::sync::OnceLock::new();
    if SAID.get_or_init(Default::default).lock().unwrap_or_else(|p| p.into_inner()).insert(msg.to_string()) {
        let _ = std::io::Write::write_all(&mut std::io::stderr(), format!("seagent: skills: {msg}; not loaded\n").as_bytes());
    }
}

fn walk(root: &Path, dir: &Path, depth: u32, src: &Source, out: &mut Vec<Skill>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = rd.flatten().filter(|e| e.path().is_dir()).collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let n = e.file_name().to_string_lossy().to_string();
        if n.starts_with('.') || n == "node_modules" || n == "__pycache__" {
            continue;
        }
        let p = e.path();
        if p.join("SKILL.md").is_file() {
            if let Ok(s) = Skill::load(&p, root, src.clone()) {
                out.push(s);
            }
        } else if depth < 3 {
            walk(root, &p, depth + 1, src, out);
        }
    }
}

/// Find a skill by name (also `category/name` and `plugin:name`).
pub fn find<'a>(skills: &'a [Skill], name: &str) -> Option<&'a Skill> {
    let n = name.trim().trim_start_matches('/');
    skills.iter().find(|s| s.name == n).or_else(|| {
        let (cat, base) = n.rsplit_once('/')?;
        skills.iter().find(|s| s.name == base && s.category.as_deref() == Some(cat))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_nested_categories_first_root_wins() {
        let base = seagent_core::tmp::scratch_path(format!("seagent-skill-model-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let (a, b) = (base.join("a"), base.join("b"));
        fs::create_dir_all(a.join("devops/deploy")).unwrap();
        fs::write(a.join("devops/deploy/SKILL.md"), "---\nname: deploy\ndescription: Ship it\nmetadata:\n  hermes:\n    tags: [ops]\n---\nbody").unwrap();
        fs::create_dir_all(b.join("deploy")).unwrap();
        fs::write(b.join("deploy/SKILL.md"), "---\nname: deploy\ndescription: other\n---\n").unwrap();
        fs::create_dir_all(b.join("plain")).unwrap();
        fs::write(b.join("plain/SKILL.md"), "no frontmatter").unwrap();
        let s = discover(&[(a.clone(), Source::Project), (b, Source::User)]);
        assert_eq!(s.len(), 2);
        assert_eq!((s[0].name.as_str(), s[0].description.as_str(), s[0].category.as_deref()), ("deploy", "Ship it", Some("devops")));
        assert_eq!(s[0].meta("metadata.hermes.tags").unwrap()[0], "ops");
        assert_eq!(s[0].body().unwrap(), "body");
        assert_eq!((s[1].name.as_str(), s[1].source.label()), ("plain", "user".to_string()));
        assert!(find(&s, "devops/deploy").is_some() && find(&s, "/plain").is_some() && find(&s, "x").is_none());
        assert!(valid_name("my-skill_1.2") && !valid_name("Bad") && !valid_name("-x") && !valid_name(""));
        let _ = fs::remove_dir_all(&base);
    }

    /// OpenClaw `metadata.<ns>.requires` + Hermes `platforms:` decide eligibility; the reasons are
    /// reported in the OpenClaw summary shape.
    // Requires `sh` + `/bin/sh` and os [linux, macos]: a Unix host by construction.
    #[cfg(unix)]
    #[test]
    fn requirements_gate_bins_anybins_env_config_and_os() {
        let base = seagent_core::tmp::scratch_path(format!("seagent-skill-req-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let mk = |n: &str, extra: &str| {
            let d = base.join(n);
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("SKILL.md"), format!("---\nname: {n}\ndescription: d\n{extra}---\nbody")).unwrap();
            Skill::load(&d, &base, Source::User).unwrap()
        };
        let sh = if has_bin("sh") { "sh" } else { "bash" };
        let ok = mk("ok", &format!("metadata:\n  openclaw:\n    requires:\n      bins: [{sh}, /bin/sh]\n      os: [linux, macos]\n"));
        let ok_any = mk("ok-any", "metadata:\n  openclaw:\n    requires:\n      anyBins: [seagent-not-a-real-bin, sh]\n");
        let bins = mk("bins", "requires:\n  bins: [git, seagent-not-a-real-bin]\n");
        let any = mk("any", "metadata:\n  openclaw:\n    requires:\n      anyBins: [seagent-not-a-real-bin, seagent-nope-2]\n");
        let env = mk("env", "metadata:\n  openclaw:\n    requires:\n      env: [SEAGENT_T_GATE_MISSING_VAR]\n");
        let cfg_path = mk("cfg", "requires:\n  config: [skills.entries.cfg.enabled]\n");
        let os = mk("os", "platforms: [solaris]\nmetadata:\n  hermes:\n    os: [plan9]\n");
        let cfg = Config::default();
        assert_eq!(ok.requirements().bins, [sh.to_string(), "/bin/sh".to_string()]);
        assert!(ok.missing(&cfg).is_empty(), "{:?}", ok.missing(&cfg));
        assert!(ok_any.eligible(&cfg));
        assert_eq!(ok.missing_on(&cfg, "solaris").describe(), "os: linux, macos");
        assert!(os_satisfied(&["macos".into()], "darwin") && !os_satisfied(&["windows".into()], "linux"));
        let m = bins.missing(&cfg);
        assert_eq!((m.bins, m.any_bins), (vec!["seagent-not-a-real-bin".to_string()], vec![]));
        assert_eq!(any.missing(&cfg).describe(), "any bins: seagent-not-a-real-bin, seagent-nope-2");
        assert_eq!(env.missing(&cfg).describe(), "env: SEAGENT_T_GATE_MISSING_VAR");
        assert_eq!(os.missing(&cfg).describe(), "os: plan9, solaris");
        // A config requirement is satisfied by a truthy `[skills.entries.<name>]` key.
        assert_eq!(cfg_path.missing(&cfg).describe(), "config: skills.entries.cfg.enabled");
        let mut on: Config = Config::default();
        on.skills.insert("entries".into(), toml::from_str("[cfg]\nenabled = true\n").unwrap());
        assert!(cfg_path.missing(&on).is_empty());
        on.skills.insert("entries".into(), toml::from_str("[cfg]\nenabled = false\n").unwrap());
        assert_eq!(cfg_path.missing(&on).config.len(), 1, "false is not satisfied");
        // `[skills.env.<skill>]` supplies a declared env name before the skill runs.
        std::env::remove_var("SEAGENT_T_GATE_SUPPLIED");
        let supplied = mk("supplied", "requires:\n  env: [SEAGENT_T_GATE_SUPPLIED]\n");
        assert_eq!(supplied.missing(&cfg).env, ["SEAGENT_T_GATE_SUPPLIED"]);
        let mut with_env: Config = Config::default();
        with_env.skills.insert("env".into(), toml::from_str("[supplied]\nSEAGENT_T_GATE_SUPPLIED = \"x\"\n").unwrap());
        assert!(supplied.missing(&with_env).is_empty());
        let _ = fs::remove_dir_all(&base);
    }
}
