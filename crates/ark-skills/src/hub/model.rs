//! Hub data model, path validators and hub state files (Hermes `tools/skills_hub_models.py` +
//! `tools/skills_hub.py`, MIT): search results (`SkillMeta`), downloaded bundles
//! (`SkillBundle`), the `Source` trait every registry adapter implements, the lock file
//! (provenance of installed hub skills), taps (extra GitHub repos) and the audit log.

use super::super::core::settings::Store;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SkillMeta {
    pub name: String,
    pub description: String,
    /// `official`, `github`, `clawhub`, `skills-sh`, `lobehub`, `browse-sh`, `well-known`, `url`.
    pub source: String,
    /// Source-specific id (`openai/skills/skill-creator`, `@owner/slug`, a URL …).
    pub identifier: String,
    /// `builtin` | `trusted` | `community`.
    pub trust_level: String,
    #[serde(default)]
    pub repo: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Default)]
pub struct SkillBundle {
    pub name: String,
    /// relative path → content.
    pub files: BTreeMap<String, Vec<u8>>,
    pub source: String,
    pub identifier: String,
    pub trust_level: String,
    pub metadata: Map<String, Value>,
}

pub trait Source: Send + Sync {
    fn id(&self) -> &'static str;
    fn search(&self, query: &str, limit: usize) -> Vec<SkillMeta>;
    fn fetch(&self, identifier: &str) -> Option<SkillBundle>;
    fn inspect(&self, identifier: &str) -> Option<SkillMeta>;
    /// Whether this source claims `identifier` when no source prefix routes it.
    fn claims(&self, _identifier: &str) -> bool {
        false
    }
}

pub fn trust_rank(t: &str) -> u8 {
    match t {
        "builtin" => 2,
        "trusted" => 1,
        _ => 0,
    }
}

/// Dedupe by identifier, keeping the higher-trust copy (first wins on ties).
pub fn dedupe_by_trust(results: Vec<SkillMeta>) -> Vec<SkillMeta> {
    let mut out: Vec<SkillMeta> = Vec::new();
    for r in results {
        match out.iter_mut().find(|o| o.identifier == r.identifier) {
            Some(o) if trust_rank(&r.trust_level) > trust_rank(&o.trust_level) => *o = r,
            Some(_) => {}
            None => out.push(r),
        }
    }
    out
}

pub fn matches_query(q: &str, fields: &[&str]) -> bool {
    q.is_empty() || fields.join(" ").to_lowercase().contains(&q.to_lowercase())
}

fn terms(q: &str) -> Vec<String> {
    q.to_lowercase().split(|c: char| !c.is_ascii_alphanumeric()).filter(|t| !t.is_empty()).map(String::from).collect()
}

/// Relevance score (ClawHub `_search_score`): exact id/name, prefix, term matches, description.
pub fn search_score(query: &str, m: &SkillMeta) -> i64 {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return 1;
    }
    let (id, name, desc) = (m.identifier.to_lowercase(), m.name.to_lowercase(), m.description.to_lowercase());
    let (qt, it, nt) = (terms(&q), terms(&id), terms(&name));
    let (ni, nn) = (it.join(" "), nt.join(" "));
    let checks = [
        (140, q == id),
        (130, q == name),
        (125, ni == q),
        (120, nn == q),
        (95, ni.starts_with(&q)),
        (90, nn.starts_with(&q)),
        (70, !qt.is_empty() && it.len() >= qt.len() && it[..qt.len()] == qt[..]),
        (65, !qt.is_empty() && nt.len() >= qt.len() && nt[..qt.len()] == qt[..]),
        (40, id.contains(&q)),
        (35, name.contains(&q)),
        (10, desc.contains(&q)),
    ];
    let mut s: i64 = checks.iter().filter(|c| c.1).map(|c| c.0).sum();
    for t in &qt {
        s += 15 * it.contains(t) as i64 + 12 * nt.contains(t) as i64 + 3 * desc.contains(t.as_str()) as i64;
    }
    s
}

// ───────────── path validators ─────────────

/// Normalize a bundle-controlled path; rejects absolute paths, `..`, drive letters (`:`), empty parts.
pub fn normalize_bundle_path(p: &str, field: &str, allow_nested: bool) -> Result<String, String> {
    let raw = p.trim().replace('\\', "/");
    if raw.is_empty() {
        return Err(format!("Unsafe {field}: empty path"));
    }
    let parts: Vec<&str> = raw.split('/').filter(|x| !x.is_empty() && *x != ".").collect();
    if raw.starts_with('/') || parts.is_empty() || parts.iter().any(|x| *x == ".." || x.contains(':')) || (!allow_nested && parts.len() != 1) {
        return Err(format!("Unsafe {field}: {p}"));
    }
    Ok(parts.join("/"))
}

pub fn validate_skill_name(n: &str) -> Result<String, String> {
    normalize_bundle_path(n, "skill name", false)
}

/// Longest accepted user-supplied name/category. Upstream has no cap (its regexes bound the shape
/// only); names become directory components, so keep them well inside `NAME_MAX`.
pub const MAX_SKILL_NAME_LEN: usize = 64;
pub const MAX_CATEGORY_LEN: usize = 128;

/// Placeholders upstream refuses as a skill name (`_is_valid_installed_skill_name`).
const SENTINEL_NAMES: [&str; 4] = ["skill", "readme", "index", "unnamed-skill"];

/// A *user-supplied* skill name (`--name`, interactive prompt): Hermes `_VALID_NAME_RE`
/// (`^[a-z][a-z0-9_-]*$`) + sentinel rejection, lowercased first like
/// `_is_valid_installed_skill_name`. Bundle-declared names keep the plain path-shape validator
/// (`validate_skill_name`) — upstream's official catalog has e.g. `1password`/`3-statement-model`,
/// which this regex intentionally rejects for typed input only.
pub fn validate_user_skill_name(n: &str) -> Result<String, String> {
    let candidate = n.trim().to_lowercase();
    if candidate.is_empty() || SENTINEL_NAMES.contains(&candidate.as_str()) {
        return Err(format!("Invalid name: '{n}'. Aborting install."));
    }
    if candidate.len() > MAX_SKILL_NAME_LEN || !regex::Regex::new(r"^[a-z][a-z0-9_-]*$").unwrap().is_match(&candidate) {
        return Err(format!(
            "Invalid name: '{n}'. Skills must be lowercase letters, digits, hyphens or underscores, starting with a letter (max {MAX_SKILL_NAME_LEN} characters). Aborting install."
        ));
    }
    validate_skill_name(&candidate)
}

/// A *user-supplied* install category/parent path (`--category`, prompt): Hermes `_VALID_CATEGORY_RE`
/// (`^[a-z][a-z0-9_/-]*$`) after normalizing the path. Metadata-derived parents skip the regex
/// (upstream applies it to typed answers only).
pub fn validate_user_category(c: &str) -> Result<String, String> {
    let norm = normalize_bundle_path(c, "install parent path", true)?;
    if norm.len() > MAX_CATEGORY_LEN || !regex::Regex::new(r"^[a-z][a-z0-9_/-]*$").unwrap().is_match(&norm) {
        return Err(format!(
            "Invalid category '{c}': categories are lowercase letters, digits, hyphens, underscores and '/' (max {MAX_CATEGORY_LEN} characters)."
        ));
    }
    Ok(norm)
}

pub fn validate_rel(p: &str) -> Result<String, String> {
    normalize_bundle_path(p, "bundle file path", true)
}

/// A lock `install_path`: relative, traversal-free and ending with the skill name (it is the
/// uninstall `remove_dir_all` target).
pub fn normalize_lock_install_path(install_path: &str, name: &str) -> Result<String, String> {
    let n = validate_skill_name(name)?;
    let p = normalize_bundle_path(install_path, "install path", true)?;
    if p.rsplit('/').next() != Some(n.as_str()) {
        return Err(format!("Unsafe install path: {install_path}"));
    }
    Ok(p)
}

/// Files under references/templates/scripts/assets/examples (and same-dir links) a SKILL.md
/// references; None on a traversal attempt (fail closed). URL-only sources fetch exactly these.
pub fn referenced_support_paths(skill_md: &str) -> Option<Vec<String>> {
    let norm = skill_md.replace('\\', "/");
    let sus = regex::Regex::new(r"(?:references|templates|scripts|assets|examples)/(?:[^\s)`'<>]*/)?\.\.(?:/|$)").unwrap();
    if sus.is_match(&norm) {
        return None;
    }
    let link = regex::Regex::new(r#"((?:references|templates|scripts|assets|examples)/[^\s)`"'<>]+)"#).unwrap();
    let mut out: Vec<String> = Vec::new();
    for m in link.captures_iter(&norm) {
        let c = m[1].trim_end_matches(['.', ',', ';', ':']);
        let path = c.split(['?', '#']).next().unwrap_or("");
        if path.contains(['*', '[', ']']) || !path.chars().last().is_some_and(|ch| ch.is_ascii_alphanumeric()) {
            continue;
        }
        let safe = validate_rel(path).ok()?;
        if !out.contains(&safe) {
            out.push(safe);
        }
    }
    let same = regex::Regex::new(r#"\]\(([^)\s"'<>]+)"#).unwrap();
    let name_re = regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]*$").unwrap();
    for m in same.captures_iter(&norm) {
        let raw = m[1].trim_end_matches(['.', ',', ';', ':']);
        if raw.contains("://") || raw.starts_with("mailto:") || raw.starts_with('#') || raw.starts_with('/') || raw.starts_with("..") {
            continue;
        }
        let n = raw.trim_start_matches("./").split(['?', '#']).next().unwrap_or("");
        if n.contains('/') || n.eq_ignore_ascii_case("skill.md") || !n.trim_start_matches('.').contains('.') || !name_re.is_match(n) {
            continue;
        }
        if !out.contains(&n.to_string()) {
            out.push(n.to_string());
        }
    }
    out.sort();
    Some(out)
}

/// VCS / dependency / cache / state dirs a skill bundle must not carry (Hermes
/// `agent.skill_utils.EXCLUDED_SKILL_DIRS`) plus byte-code and OS litter. Applied when copying a
/// bundle into quarantine and when hashing an installed tree, so both sides of `check` agree.
pub fn skip_bundle_file(rel: &str) -> bool {
    const EXCLUDED: [&str; 17] = [
        ".git", ".github", ".hub", ".archive", ".curator_backups", ".locks", ".venv", "venv", "node_modules", "site-packages", "__pycache__", ".tox", ".nox",
        ".pytest_cache", ".mypy_cache", ".ruff_cache", ".DS_Store",
    ];
    rel.split('/').any(|p| EXCLUDED.contains(&p)) || rel.ends_with(".pyc") || rel.ends_with(".pyo")
}

// ───────────── hub state ─────────────

fn read_json(p: &std::path::Path, empty: Value) -> Value {
    fs::read_to_string(p).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(empty)
}

fn write_json(p: &std::path::Path, v: &Value) -> Result<(), String> {
    fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
    ark_kernel::util::atomic_write(p, (serde_json::to_string_pretty(v).unwrap() + "\n").as_bytes()).map_err(|e| e.to_string())
}

pub struct Lock<'a>(pub &'a Store);

impl Lock<'_> {
    fn path(&self) -> std::path::PathBuf {
        self.0.hub().join("lock.json")
    }
    pub fn load(&self) -> Value {
        read_json(&self.path(), json!({"version": 1, "installed": {}}))
    }
    #[allow(clippy::too_many_arguments)]
    pub fn record_install(&self, name: &str, source: &str, identifier: &str, trust: &str, verdict: &str, hash: &str, install_path: &str, files: &[String], metadata: Map<String, Value>) -> Result<(), String> {
        let n = validate_skill_name(name)?;
        let ip = normalize_lock_install_path(install_path, &n)?;
        let mut d = self.load();
        let now = ark_kernel::util::unix_now();
        let prev_at = d["installed"][&n]["installed_at"].as_i64().unwrap_or(now);
        d["installed"][&n] = json!({"source": source, "identifier": identifier, "trust_level": trust, "scan_verdict": verdict, "content_hash": hash, "install_path": ip, "files": files, "metadata": metadata, "installed_at": prev_at, "updated_at": now});
        write_json(&self.path(), &d)
    }
    pub fn record_uninstall(&self, name: &str) -> Result<(), String> {
        let mut d = self.load();
        if let Some(m) = d["installed"].as_object_mut() {
            m.remove(name);
        }
        write_json(&self.path(), &d)
    }
    pub fn get(&self, name: &str) -> Option<Value> {
        self.load()["installed"].get(name).cloned().filter(|v| v.is_object())
    }
    pub fn list(&self) -> Vec<(String, Value)> {
        self.load()["installed"].as_object().map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default()
    }
}

pub struct Taps<'a>(pub &'a Store);

impl Taps<'_> {
    fn path(&self) -> std::path::PathBuf {
        self.0.hub().join("taps.json")
    }
    pub fn list(&self) -> Vec<(String, String)> {
        read_json(&self.path(), json!({"taps": []}))["taps"].as_array().into_iter().flatten().filter_map(|t| Some((t["repo"].as_str()?.to_string(), t["path"].as_str().unwrap_or("skills/").to_string()))).collect()
    }
    pub fn add(&self, repo: &str, path: &str) -> Result<bool, String> {
        if !regex::Regex::new(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$").unwrap().is_match(repo) {
            return Err(format!("not a GitHub owner/repo: {repo}"));
        }
        let mut t = self.list();
        if t.iter().any(|(r, _)| r == repo) {
            return Ok(false);
        }
        t.push((repo.into(), path.into()));
        write_json(&self.path(), &json!({"taps": t.iter().map(|(r, p)| json!({"repo": r, "path": p})).collect::<Vec<_>>()}))?;
        Ok(true)
    }
    pub fn remove(&self, repo: &str) -> Result<bool, String> {
        let t = self.list();
        let kept: Vec<_> = t.iter().filter(|(r, _)| r != repo).collect();
        if kept.len() == t.len() {
            return Ok(false);
        }
        write_json(&self.path(), &json!({"taps": kept.iter().map(|(r, p)| json!({"repo": r, "path": p})).collect::<Vec<_>>()}))?;
        Ok(true)
    }
}

/// One space-separated audit line (best-effort).
pub fn audit(st: &Store, action: &str, name: &str, source: &str, trust: &str, verdict: &str, extra: &str) {
    let p = st.hub().join("audit.log");
    let _ = fs::create_dir_all(st.hub());
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(p) {
        let ts = ark_kernel::util::fmt_time(ark_kernel::util::unix_now(), 0);
        let _ = writeln!(f, "{} {action} {name} {source}:{trust} {verdict}{}", ts.replace(' ', "T"), if extra.is_empty() { String::new() } else { format!(" {extra}") });
    }
}

/// Parse SKILL.md frontmatter of a bundle.
pub fn bundle_front(b: &SkillBundle) -> Value {
    b.files.get("SKILL.md").map(|f| crate::yaml::frontmatter(&String::from_utf8_lossy(f)).0).unwrap_or(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validators_score_state() {
        assert_eq!(validate_rel("./references/a.md").unwrap(), "references/a.md");
        for bad in ["../x", "/etc/passwd", "a/../../b", "C:/x", ""] {
            assert!(validate_rel(bad).is_err(), "{bad}");
        }
        assert!(validate_skill_name("a/b").is_err());
        assert!(normalize_lock_install_path("mlops/train/acc", "acc").is_ok());
        assert!(normalize_lock_install_path(".", "acc").is_err() && normalize_lock_install_path("x/other", "acc").is_err());
        let refs = referenced_support_paths("See [guide](references/guide.md), run `scripts/run.sh`, and [notes](notes.txt). Ignore references/*.md and https://x/y.").unwrap();
        assert_eq!(refs, ["notes.txt", "references/guide.md", "scripts/run.sh"]);
        assert!(referenced_support_paths("cat references/../../secret").is_none());
        let m = |id: &str, name: &str, d: &str| SkillMeta { identifier: id.into(), name: name.into(), description: d.into(), ..Default::default() };
        assert!(search_score("pdf tools", &m("pdf-tools", "PDF Tools", "")) > search_score("pdf tools", &m("x", "other", "has pdf tools inside")));
        let d = dedupe_by_trust(vec![SkillMeta { trust_level: "community".into(), ..m("a", "a", "") }, SkillMeta { trust_level: "builtin".into(), ..m("a", "a", "") }, m("b", "b", "")]);
        assert_eq!((d.len(), d[0].trust_level.as_str()), (2, "builtin"));
        let dir = ark_core::tmp::scratch_path(format!("ark-hubmodel-{}", std::process::id()));
        let st = Store::at(&dir);
        let l = Lock(&st);
        l.record_install("pdf", "github", "o/r/pdf", "community", "safe", "h", "pdf", &["SKILL.md".into()], Map::new()).unwrap();
        assert!(l.record_install("x", "github", "o/r/x", "community", "safe", "h", "../x", &[], Map::new()).is_err());
        assert_eq!(l.get("pdf").unwrap()["trust_level"], "community");
        l.record_uninstall("pdf").unwrap();
        assert!(l.list().is_empty());
        let t = Taps(&st);
        assert!(t.add("me/skills", "skills/").unwrap() && !t.add("me/skills", "skills/").unwrap());
        assert!(t.add("bad repo", "x").is_err());
        assert!(t.remove("me/skills").unwrap() && t.list().is_empty());
        audit(&st, "install", "pdf", "github", "community", "safe", "");
        assert!(fs::read_to_string(st.hub().join("audit.log")).unwrap().contains("install pdf github:community safe"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn typed_name_and_category_limits_match_cli_regexes() {
        // `--name`/prompt input: `_VALID_NAME_RE` after lowercasing (`_is_valid_installed_skill_name`).
        assert_eq!(validate_user_skill_name("  PDF-Tools ").unwrap(), "pdf-tools");
        assert_eq!(validate_user_skill_name("a_1-b").unwrap(), "a_1-b");
        for bad in ["1password", "3-statement-model", "skill", "readme", "index", "unnamed-skill", "", "a b", "a.b", "a/b", "../x"] {
            assert!(validate_user_skill_name(bad).is_err(), "{bad}");
        }
        assert!(validate_user_skill_name(&"a".repeat(MAX_SKILL_NAME_LEN + 1)).is_err());
        assert!(validate_user_skill_name(&"a".repeat(MAX_SKILL_NAME_LEN)).is_ok());
        // Bundle-declared names keep the path-shape validator only: the official catalog ships
        // `1password`/`3-statement-model`, which the typed-name regex refuses.
        assert_eq!(validate_skill_name("1password").unwrap(), "1password");
        // `--category`: `_VALID_CATEGORY_RE` over the normalized path.
        assert_eq!(validate_user_category("ml/train").unwrap(), "ml/train");
        assert_eq!(validate_user_category("a//b/").unwrap(), "a/b");
        assert_eq!(validate_user_category("a1_b-c").unwrap(), "a1_b-c");
        for bad in ["ML/Train", "1ml", "-x", "../x", "/abs", "", "a b"] {
            assert!(validate_user_category(bad).is_err(), "{bad}");
        }
        assert!(validate_user_category(&"a".repeat(MAX_CATEGORY_LEN + 1)).is_err());
        // Junk dirs/files skipped while installing and hashing (upstream EXCLUDED_SKILL_DIRS).
        for junk in [".git/config", "node_modules/p/index.js", "__pycache__/m.cpython-311.pyc", "a/b.pyc", ".venv/lib/x.py", ".DS_Store"] {
            assert!(skip_bundle_file(junk), "{junk}");
        }
        for kept in ["SKILL.md", "references/guide.md", "scripts/run.sh", "assets/py.typed", "docs/python.md"] {
            assert!(!skip_bundle_file(kept), "{kept}");
        }
    }
}
