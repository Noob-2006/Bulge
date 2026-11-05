//! Occupational role packs at run time (BATCH-next §3 and §7-6).
//!
//! `share/roles/` holds layered `SKILL.md` packs: one L0 core (`professional-core`), ten L1
//! ISCO major groups and 537 L2 unit groups, each with `layer`, `isco` and `extends` in its
//! frontmatter, plus `boundaries.toml` (reserved acts of regulated professions) and
//! `presets.toml` (the five pre-assembled professional roles). This module is the runtime
//! side of that tree:
//!
//! - **Loader** — [`parse_pack`] reads the frontmatter (`isco` is normalised to a string
//!   whether or not it was quoted, pro-066), [`Catalog`] indexes every pack under
//!   [`roles_dir`] (`$ARK_ROLES_DIR`, `[role] dir`, then `<share>/roles`), and the L0 core,
//!   the boundaries and the presets are compiled in, so the core and the boundary checks work
//!   even on an install that ships no `share/`.
//! - **Assembly** — the default agent carries only L0, folded into the identity segment
//!   ([`core_text`], always loaded, ≤ 300 tokens). Choosing an occupation (`[role] active`,
//!   `ark role use`, `/role`, `ark agents add --role`) resolves a preset or a pack, walks
//!   `extends` up to L0 and renders L1 + L2 as the `role` system segment ([`Role::segment`]).
//! - **Selection** — [`find`] matches an ISCO code (4-digit unit group, 1-digit major group),
//!   a slug, a preset id or alias, or a Chinese / English title; an ambiguous code (56 codes
//!   are shared by several packs) returns every candidate instead of guessing.
//! - **Policy** — a preset's default permissions ([`Policy`]) tighten the config the agent
//!   runs with ([`apply_policy`]) and are enforced per session by [`hook::RoleHook`],
//!   together with the reserved-act boundaries of regulated packs ([`boundary`]).
//! - **Progressive disclosure** — a pack's `references/*.md` are listed in the segment by
//!   path and first line only; the model reads one when the task needs it (pro-069).

pub mod boundary;
pub mod hook;

use crate::config::Config;
use ark_core::SystemSegment;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// The L0 core, compiled in: it is part of every identity, so it must not depend on `share/`.
pub const CORE_MD: &str = include_str!("../../../share/roles/L0/professional-core/SKILL.md");
/// Reserved acts per regulated area (compiled in for the same reason).
pub const BOUNDARIES_TOML: &str = include_str!("../../../share/roles/boundaries.toml");
/// The pre-assembled professional roles.
pub const PRESETS_TOML: &str = include_str!("../../../share/roles/presets.toml");
pub const CORE_SLUG: &str = "professional-core";
/// System segment id of the assembled L1 + L2 role.
pub const SEGMENT_ID: &str = "role";
/// Token budgets per layer (chars / 4 of the injected body; BATCH-next §7-2, check.py).
pub const BUDGET_L0: u64 = 300;
pub const BUDGET_L1: u64 = 300;
pub const BUDGET_L2: u64 = 400;
/// Team-role seeds `ark agents add --role` predates occupations with (they set an identity,
/// not a pack).
pub const TEAM_SEEDS: &[&str] = &["coordinator", "researcher", "writer", "reviewer"];

/// `[role]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RoleConfig {
    /// Preset id or pack slug the default agent works as; empty = the L0 core only.
    pub active: String,
    /// Fold the L0 professional core into every identity (default true).
    pub core: bool,
    /// Extra roles directory searched before the shipped `share/roles`.
    pub dir: String,
    /// Targets (host names, IPs, CIDR prefixes like `10.0.0.`) active scanners may hit under a
    /// role whose policy sets `scan_allowlist` (secops).
    pub scan_targets: Vec<String>,
}

impl Default for RoleConfig {
    fn default() -> Self {
        RoleConfig { active: String::new(), core: true, dir: String::new(), scan_targets: vec![] }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Layer {
    L0,
    L1,
    L2,
}

impl Layer {
    pub fn parse(s: &str) -> Option<Layer> {
        match s.trim() {
            "L0" | "l0" => Some(Layer::L0),
            "L1" | "l1" => Some(Layer::L1),
            "L2" | "l2" => Some(Layer::L2),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Layer::L0 => "L0",
            Layer::L1 => "L1",
            Layer::L2 => "L2",
        }
    }
    pub fn budget(self) -> u64 {
        match self {
            Layer::L0 => BUDGET_L0,
            Layer::L1 => BUDGET_L1,
            Layer::L2 => BUDGET_L2,
        }
    }
}

/// One parsed role pack.
#[derive(Debug, Clone, PartialEq)]
pub struct Pack {
    pub slug: String,
    pub title_zh: String,
    pub layer: Layer,
    /// Always a string: `all` (L0), one digit (L1), four digits (L2).
    pub isco: String,
    pub extends: Option<String>,
    pub description: String,
    pub regulated: bool,
    /// Reserved-act ids (boundaries.toml) of a regulated pack.
    pub boundary: Vec<String>,
    /// Markdown body without the frontmatter.
    pub body: String,
    /// The pack directory (None for the compiled-in core).
    pub dir: Option<PathBuf>,
}

impl Pack {
    /// chars / 4 of the body, the measure check.py budgets.
    pub fn tokens(&self) -> u64 {
        (self.body.trim().chars().count() as u64).div_ceil(4)
    }
    /// Words of the slug, for English matching (`software-developer` → `software developer`).
    pub fn title_en(&self) -> String {
        self.slug.replace('-', " ")
    }
    /// `references/*.md` (sorted): deeper checklists the model reads on demand.
    pub fn references(&self) -> Vec<(PathBuf, String)> {
        let Some(dir) = &self.dir else { return vec![] };
        let Ok(rd) = std::fs::read_dir(dir.join("references")) else { return vec![] };
        let mut v: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.is_file() && p.extension().is_some_and(|e| e == "md")).collect();
        v.sort();
        v.into_iter()
            .map(|p| {
                let first = std::fs::read_to_string(&p).ok().and_then(|t| t.lines().map(|l| l.trim().trim_start_matches('#').trim().to_string()).find(|l| !l.is_empty())).unwrap_or_default();
                (p, first)
            })
            .collect()
    }
}

/// `isco` as a string whatever the YAML spelling: quotes stripped, a bare integer kept as its
/// digits and, for L2 unit groups, left-padded to four (`0110` written bare reads as `110`).
pub fn normalize_isco(raw: &str, layer: Option<Layer>) -> String {
    let v = raw.trim().trim_matches('"').trim_matches('\'').trim().to_string();
    if layer == Some(Layer::L2) && !v.is_empty() && v.len() < 4 && v.chars().all(|c| c.is_ascii_digit()) {
        return format!("{v:0>4}");
    }
    v
}

fn unquote(v: &str) -> String {
    let v = v.trim();
    if v.len() >= 2 && ((v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\''))) {
        v[1..v.len() - 1].to_string()
    } else {
        v.to_string()
    }
}

/// `[a, b]` → `["a", "b"]`.
fn list(v: &str) -> Vec<String> {
    let v = v.trim();
    let inner = v.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(v);
    inner.split(',').map(unquote).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

/// Parse one `SKILL.md` of the role tree (the flat `key: value` frontmatter check.py defines).
pub fn parse_pack(text: &str, dir: Option<PathBuf>) -> Result<Pack, String> {
    let t = text.strip_prefix('\u{feff}').unwrap_or(text);
    let rest = t.strip_prefix("---\n").ok_or("missing opening `---`")?;
    let end = rest.find("\n---\n").ok_or("missing closing `---`")?;
    let (raw, body) = (&rest[..end], &rest[end + 5..]);
    let mut m: BTreeMap<String, String> = BTreeMap::new();
    for line in raw.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let (k, v) = l.split_once(':').ok_or_else(|| format!("unparseable frontmatter line `{l}`"))?;
        m.insert(k.trim().to_string(), v.trim().to_string());
    }
    let get = |k: &str| m.get(k).map(|v| unquote(v)).unwrap_or_default();
    let layer = Layer::parse(&get("layer")).ok_or_else(|| format!("layer `{}` is not L0, L1 or L2", get("layer")))?;
    let slug = get("name");
    if slug.is_empty() {
        return Err("frontmatter has no `name`".into());
    }
    Ok(Pack {
        isco: normalize_isco(m.get("isco").map(String::as_str).unwrap_or(""), Some(layer)),
        extends: Some(get("extends")).filter(|s| !s.is_empty()),
        title_zh: get("title_zh"),
        description: get("description"),
        regulated: get("regulated").eq_ignore_ascii_case("true"),
        boundary: m.get("boundary").map(|v| list(v)).unwrap_or_default(),
        body: body.to_string(),
        slug,
        layer,
        dir,
    })
}

/// ark's shared data dir; one resolver for the whole binary (see `ark_core::share`).
pub fn share_dir() -> Option<PathBuf> {
    ark_core::share::share_dir()
}

/// Role directories, most specific first: `$ARK_ROLES_DIR`, `[role] dir`, `<share>/roles`.
pub fn roles_dirs(cfg: &Config) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(p) = std::env::var_os("ARK_ROLES_DIR").map(PathBuf::from) {
        v.push(p);
    }
    if !cfg.role.dir.trim().is_empty() {
        v.push(ark_core::tool::expand_home(cfg.role.dir.trim()));
    }
    if let Some(s) = share_dir() {
        v.push(s.join("roles"));
    }
    v.retain(|p| p.is_dir());
    v.dedup();
    v
}

/// The shipped roles directory (first of [`roles_dirs`]) for a default config.
pub fn roles_dir() -> Option<PathBuf> {
    roles_dirs(&Config::default()).into_iter().next()
}

/// Every pack under some roles directories (first definition of a slug wins), plus the
/// compiled-in core when no directory has one.
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    pub packs: BTreeMap<String, Pack>,
    pub dirs: Vec<PathBuf>,
    /// Packs that failed to parse: `(path, error)`.
    pub errors: Vec<(PathBuf, String)>,
}

impl Catalog {
    pub fn load_dirs(dirs: &[PathBuf]) -> Catalog {
        let mut c = Catalog { dirs: dirs.to_vec(), ..Default::default() };
        for d in dirs {
            for layer in ["L0", "L1", "L2"] {
                let Ok(rd) = std::fs::read_dir(d.join(layer)) else { continue };
                let mut entries: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
                entries.sort();
                for dir in entries {
                    let file = dir.join("SKILL.md");
                    let Ok(text) = std::fs::read_to_string(&file) else { continue };
                    match parse_pack(&text, Some(dir.clone())) {
                        Ok(p) => {
                            c.packs.entry(p.slug.clone()).or_insert(p);
                        }
                        Err(e) => c.errors.push((file, e)),
                    }
                }
            }
        }
        if !c.packs.contains_key(CORE_SLUG) {
            if let Ok(p) = parse_pack(CORE_MD, None) {
                c.packs.insert(CORE_SLUG.into(), p);
            }
        }
        c
    }

    /// Cached per set of directories (the tree is read-only at run time).
    pub fn for_config(cfg: &Config) -> Arc<Catalog> {
        static CACHE: OnceLock<Mutex<BTreeMap<Vec<PathBuf>, Arc<Catalog>>>> = OnceLock::new();
        let dirs = roles_dirs(cfg);
        let mut g = CACHE.get_or_init(Default::default).lock().unwrap();
        g.entry(dirs.clone()).or_insert_with(|| Arc::new(Catalog::load_dirs(&dirs))).clone()
    }

    pub fn get(&self, slug: &str) -> Option<&Pack> {
        self.packs.get(slug)
    }

    pub fn by_layer(&self, layer: Layer) -> impl Iterator<Item = &Pack> {
        self.packs.values().filter(move |p| p.layer == layer)
    }

    /// `slug` and its ancestors, L0 first. Errors on an unknown pack, a missing parent or a cycle.
    pub fn chain(&self, slug: &str) -> Result<Vec<&Pack>, String> {
        let mut out = Vec::new();
        let mut cur = Some(slug.to_string());
        while let Some(s) = cur {
            if out.iter().any(|p: &&Pack| p.slug == s) || out.len() > 3 {
                return Err(format!("role pack `{slug}`: `extends` loops at `{s}`"));
            }
            let p = self.get(&s).ok_or_else(|| format!("unknown role pack `{s}`"))?;
            out.push(p);
            cur = p.extends.clone();
        }
        out.reverse();
        Ok(out)
    }
}

/// `[preset.policy]` of presets.toml: a role's default permissions (pro-004).
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    /// relaxed | standard | strict.
    pub approval: Option<String>,
    pub workspace_only: bool,
    pub write_deny: Vec<String>,
    /// Command globs the role never runs.
    pub deny: Vec<String>,
    pub db_read_only: bool,
    pub scan_allowlist: bool,
    pub no_password_entry: bool,
    /// What the role hands to a human first (shown to the model; the tiers enforce the rest).
    pub approve: Vec<String>,
}

impl Policy {
    pub fn is_empty(&self) -> bool {
        *self == Policy::default()
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Preset {
    pub id: String,
    pub title_zh: String,
    pub title_en: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub packs: Vec<String>,
    /// Tool profile (`ark_security::toolpolicy::profile`).
    pub tools: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub policy: Policy,
}

#[derive(Deserialize)]
struct PresetFile {
    #[serde(default)]
    preset: Vec<Preset>,
}

/// The compiled-in presets (a `presets.toml` in `[role] dir` / `$ARK_ROLES_DIR` replaces them).
pub fn presets(cfg: &Config) -> Vec<Preset> {
    for d in roles_dirs(cfg) {
        if let Ok(t) = std::fs::read_to_string(d.join("presets.toml")) {
            if let Ok(f) = toml::from_str::<PresetFile>(&t) {
                return f.preset;
            }
        }
    }
    builtin_presets()
}

pub fn builtin_presets() -> Vec<Preset> {
    toml::from_str::<PresetFile>(PRESETS_TOML).map(|f| f.preset).unwrap_or_default()
}

/// An assembled role: the L0 core plus the L1/L2 packs it brings, deduplicated, in order.
#[derive(Debug, Clone, PartialEq)]
pub struct Role {
    /// Preset id or pack slug (what config / agents.toml store).
    pub id: String,
    pub title: String,
    pub preset: Option<Preset>,
    pub core: Pack,
    /// L1 then L2 packs (each once).
    pub packs: Vec<Pack>,
}

impl Role {
    pub fn l2(&self) -> impl Iterator<Item = &Pack> {
        self.packs.iter().filter(|p| p.layer == Layer::L2)
    }
    pub fn regulated(&self) -> bool {
        self.l2().any(|p| p.regulated)
    }
    /// Reserved-act ids over every L2 pack.
    pub fn acts(&self) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        for p in self.l2().filter(|p| p.regulated) {
            for a in &p.boundary {
                if !v.contains(a) {
                    v.push(a.clone());
                }
            }
        }
        v
    }
    pub fn policy(&self) -> Policy {
        self.preset.as_ref().map(|p| p.policy.clone()).unwrap_or_default()
    }
    pub fn tool_profile(&self) -> Option<&str> {
        self.preset.as_ref().map(|p| p.tools.as_str()).filter(|t| !t.is_empty() && *t != "full")
    }
    /// ISCO codes of the L2 packs.
    pub fn isco(&self) -> Vec<String> {
        self.l2().map(|p| p.isco.clone()).collect()
    }
    /// The `role` system segment: L1 + L2 (the core is in the identity).
    pub fn segment(&self) -> SystemSegment {
        SystemSegment { id: SEGMENT_ID.into(), text: self.segment_text(), cache: false }
    }
    pub fn segment_text(&self) -> String {
        let mut t = format!("# Professional role: {} [role:{}]\n", self.title, self.id);
        t.push_str("Work as this professional. These rules add to the professional conduct rules above; where two conflict, the more specific one (further down) wins.\n");
        for p in &self.packs {
            let what = match p.layer {
                Layer::L2 => format!("{} ({}, ISCO {})", p.title_zh, p.slug, p.isco),
                _ => format!("{} ({}, ISCO group {})", p.title_zh, p.slug, p.isco),
            };
            t.push_str(&format!("\n## {what}\n{}\n", demote(&p.body)));
        }
        let pol = self.policy();
        if !pol.approve.is_empty() {
            t.push_str(&format!("\n## Ask the user before\n- {}\n", pol.approve.join("; ")));
        }
        let acts = self.acts();
        if !acts.is_empty() {
            let b = boundary::boundaries();
            let names: Vec<String> = acts.iter().map(|a| b.act(a).map(|x| format!("{} ({})", x.zh, x.en)).unwrap_or_else(|| a.clone())).collect();
            t.push_str(&format!("\n## Reserved acts (never perform; prepare the material and hand over)\n- {}\n", names.join("; ")));
        }
        let refs: Vec<String> = self.packs.iter().flat_map(|p| p.references()).map(|(path, first)| format!("- {}: {}", path.display(), first)).collect();
        if !refs.is_empty() {
            t.push_str("\n## References (read one with the read tool only when the task needs it)\n");
            t.push_str(&refs.join("\n"));
            t.push('\n');
        }
        t
    }
    /// (L0, L1, L2) token estimates of what this role puts in the prompt.
    pub fn tokens(&self) -> (u64, u64, u64) {
        let by = |l: Layer| self.packs.iter().filter(|p| p.layer == l).map(Pack::tokens).sum::<u64>();
        (self.core.tokens(), by(Layer::L1), by(Layer::L2))
    }
}

/// `## X` → `### X`, so stacked packs nest under their own heading.
fn demote(body: &str) -> String {
    body.trim().lines().map(|l| if l.starts_with("## ") { format!("#{l}") } else { l.to_string() }).collect::<Vec<_>>().join("\n")
}

/// The core pack (disk first, then the compiled-in copy).
pub fn core_pack(cat: &Catalog) -> Pack {
    cat.get(CORE_SLUG).cloned().or_else(|| parse_pack(CORE_MD, None).ok()).expect("compiled-in professional core parses")
}

/// The L0 text folded into the identity segment (`[role] core = false` turns it off).
pub fn core_text(cfg: &Config) -> Option<String> {
    if !cfg.role.core {
        return None;
    }
    let cat = Catalog::for_config(cfg);
    let p = core_pack(&cat);
    Some(format!("# Professional conduct\n{}", demote(&p.body)))
}

/// Resolve an exact id (preset id or pack slug) into an assembled role.
pub fn resolve(cfg: &Config, cat: &Catalog, id: &str) -> Result<Role, String> {
    let id = id.trim();
    let core = core_pack(cat);
    let mut packs: Vec<Pack> = Vec::new();
    let push = |cat: &Catalog, slug: &str, packs: &mut Vec<Pack>| -> Result<(), String> {
        for p in cat.chain(slug)? {
            if p.layer != Layer::L0 && !packs.iter().any(|x| x.slug == p.slug) {
                packs.push(p.clone());
            }
        }
        Ok(())
    };
    if let Some(pr) = presets(cfg).into_iter().find(|p| p.id == id) {
        for slug in &pr.packs {
            push(cat, slug, &mut packs)?;
        }
        packs.sort_by_key(|p| p.layer);
        return Ok(Role { id: pr.id.clone(), title: format!("{} / {}", pr.title_zh, pr.title_en), preset: Some(pr), core, packs });
    }
    let p = cat.get(id).ok_or_else(|| format!("unknown role `{id}` (see `ark role list`)"))?;
    if p.layer == Layer::L0 {
        return Ok(Role { id: id.into(), title: p.title_zh.clone(), preset: None, core, packs: vec![] });
    }
    push(cat, id, &mut packs)?;
    Ok(Role { id: id.into(), title: p.title_zh.clone(), preset: None, core, packs })
}

/// The role the default agent runs as (`[role] active`), if set and resolvable.
pub fn active(cfg: &Config) -> Option<Role> {
    let id = cfg.role.active.trim();
    if id.is_empty() || is_none(id) {
        return None;
    }
    resolve(cfg, &Catalog::for_config(cfg), id).ok()
}

/// Words that mean "no occupation, core only".
pub fn is_none(s: &str) -> bool {
    matches!(s.trim().to_lowercase().as_str(), "" | "none" | "off" | "core" | "default" | "professional-core")
}

/// The `role` segment for a config (None = core only).
pub fn active_segment(cfg: &Config) -> Option<SystemSegment> {
    active(cfg).map(|r| r.segment())
}

/// Role id in a rendered segment (`… [role:<id>]` on its first line).
pub fn segment_role_id(text: &str) -> Option<String> {
    let first = text.lines().next()?;
    let at = first.rfind("[role:")?;
    let rest = &first[at + 6..];
    let id = rest.split(']').next()?.trim();
    (!id.is_empty()).then(|| id.to_string())
}

/// Result of [`find`].
#[derive(Debug, Clone, PartialEq)]
pub enum Found {
    One(String),
    /// Several candidates: `(id, label)`, best first.
    Many(Vec<(String, String)>),
    None,
}

fn label(p: &Pack) -> String {
    format!("{} — {} ({} ISCO {})", p.slug, p.title_zh, p.layer.as_str(), p.isco)
}

/// Match a user's words to a role: preset id / alias, slug, ISCO code, Chinese or English
/// title. Exact matches win; several equally good ones come back for the user to choose.
pub fn find(cfg: &Config, cat: &Catalog, query: &str) -> Found {
    let q = query.trim().trim_matches('"').trim();
    let ql = q.to_lowercase();
    if ql.is_empty() {
        return Found::None;
    }
    let presets = presets(cfg);
    if let Some(p) = presets.iter().find(|p| p.id == ql || p.aliases.iter().any(|a| a.eq_ignore_ascii_case(&ql))) {
        return Found::One(p.id.clone());
    }
    if cat.get(&ql).is_some() {
        return Found::One(ql);
    }
    let one_or_many = |v: Vec<&Pack>| -> Found {
        match v.len() {
            0 => Found::None,
            1 => Found::One(v[0].slug.clone()),
            _ => Found::Many(v.into_iter().map(|p| (p.slug.clone(), label(p))).collect()),
        }
    };
    if ql.chars().all(|c| c.is_ascii_digit()) {
        let hits: Vec<&Pack> = match ql.len() {
            1 => cat.by_layer(Layer::L1).filter(|p| p.isco == ql).collect(),
            4 => cat.by_layer(Layer::L2).filter(|p| p.isco == ql).collect(),
            2 | 3 => cat.by_layer(Layer::L2).filter(|p| p.isco.starts_with(&ql)).collect(),
            _ => vec![],
        };
        return one_or_many(hits);
    }
    // Exact titles (Chinese title, preset titles, English slug words).
    let norm = |s: &str| s.to_lowercase().replace(['／', '/', '-', '_'], " ").split_whitespace().collect::<Vec<_>>().join(" ");
    let qn = norm(q);
    if let Some(p) = presets.iter().find(|p| norm(&p.title_zh) == qn || norm(&p.title_en) == qn) {
        return Found::One(p.id.clone());
    }
    let exact: Vec<&Pack> = cat.packs.values().filter(|p| p.title_zh == q || norm(&p.title_en()) == qn).collect();
    if !exact.is_empty() {
        return one_or_many(exact);
    }
    // Substrings: presets first, then packs by title, slug words and description.
    let mut many: Vec<(String, String)> = presets
        .iter()
        .filter(|p| norm(&p.title_zh).contains(&qn) || norm(&p.title_en).contains(&qn) || p.summary.to_lowercase().contains(&ql))
        .map(|p| (p.id.clone(), format!("{} — {} / {} (preset)", p.id, p.title_zh, p.title_en)))
        .collect();
    let mut scored: Vec<(u8, &Pack)> = cat
        .packs
        .values()
        .filter_map(|p| {
            if p.title_zh.contains(q) || norm(&p.title_en()).contains(&qn) {
                Some((0, p))
            } else if p.description.to_lowercase().contains(&ql) {
                Some((1, p))
            } else {
                None
            }
        })
        .collect();
    if scored.is_empty() && many.is_empty() {
        // `護理師` / `會計師` / `technicians`: retry without a common job-title suffix.
        let stem = ["工程師", "人員", "師", "員", "者", "家", "s"].iter().find_map(|suf| q.strip_suffix(suf).filter(|s| s.chars().count() >= 2));
        if let Some(stem) = stem {
            return find(cfg, cat, stem);
        }
    }
    scored.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.layer.cmp(&b.1.layer)).then(a.1.slug.cmp(&b.1.slug)));
    many.extend(scored.into_iter().map(|(_, p)| (p.slug.clone(), label(p))));
    match many.len() {
        0 => Found::None,
        1 => Found::One(many.remove(0).0),
        _ => Found::Many(many),
    }
}

/// Tighten `cfg` with the active role's default permissions (pro-004). A role never loosens
/// anything: the stricter approval preset wins, deny lists only grow, a tool profile is set
/// only when the config has none. Returns what changed (for `ark role show`).
pub fn apply_policy(cfg: &mut Config) -> Vec<String> {
    let Some(role) = active(cfg) else { return vec![] };
    apply_role_policy(cfg, &role)
}

pub fn apply_role_policy(cfg: &mut Config, role: &Role) -> Vec<String> {
    use ark_security::risk::Preset as P;
    let pol = role.policy();
    let mut changed = Vec::new();
    let rank = |p: P| match p {
        P::Relaxed => 0,
        P::Standard => 1,
        P::Strict => 2,
    };
    if let Some(want) = pol.approval.as_deref().and_then(|a| match a.trim().to_lowercase().as_str() {
        "relaxed" => Some(P::Relaxed),
        "standard" => Some(P::Standard),
        "strict" => Some(P::Strict),
        _ => None,
    }) {
        if rank(want) > rank(cfg.approvals.preset) {
            cfg.approvals.preset = want;
            changed.push(format!("approvals.preset = {}", pol.approval.as_deref().unwrap_or_default()));
        }
    }
    if pol.workspace_only && !cfg.security.workspace_only {
        cfg.security.workspace_only = true;
        changed.push("security.workspace_only = true".into());
    }
    for g in &pol.write_deny {
        if !cfg.security.write_deny.contains(g) {
            cfg.security.write_deny.push(g.clone());
            changed.push(format!("security.write_deny += {g}"));
        }
    }
    if let Some(p) = role.tool_profile() {
        if cfg.tools.profile.is_none() && cfg.tools.allow.is_empty() {
            cfg.tools.profile = Some(p.to_string());
            changed.push(format!("tools.profile = {p}"));
        }
    }
    changed
}

#[cfg(test)]
mod tests;
