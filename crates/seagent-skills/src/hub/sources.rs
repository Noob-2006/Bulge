//! Registry adapters (Hermes `tools/skills_hub_{official,github,clawhub,skillssh,sources}.py`,
//! MIT). Each turns a query into `SkillMeta` rows and an identifier into a `SkillBundle`; every
//! request goes through the guarded client. Base URLs come from `[skills.hub]`.
//!
//! - `official`: Hermes' optional-skills catalog (shipped as `share/optional-skills/index.json`,
//!   content fetched from the upstream repo on install — or from a local copy under
//!   `share/optional-skills/<path>` when a packager ships one). Trust `builtin`.
//! - `github`: GitHub repos ("taps": defaults + `seagent skills tap add`), Contents + Trees API,
//!   files pinned to the tree revision via raw.githubusercontent. `trusted` for the trusted repos.
//! - `clawhub`: clawhub.ai API (listing, detail, versions, ZIP download). Always `community`.
//! - `skills-sh`: skills.sh search, content resolved through the GitHub source.
//! - `lobehub`: LobeHub agents converted to SKILL.md; `browse-sh`: browse.sh site skills;
//!   `well-known`: `/.well-known/skills/index.json`; `url`: a direct SKILL.md URL.

use super::http::{with_query, Http};
use super::model::*;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

fn tags_of(fm: &Value) -> Vec<String> {
    let t = fm.pointer("/metadata/seagent/tags").or_else(|| fm.pointer("/metadata/hermes/tags")).or_else(|| fm.get("tags"));
    t.and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

/// `12345` → `12,345` (Python's `f"{n:,}"`, used in the skills.sh install count).
fn thousands(n: i64) -> String {
    let digits = n.unsigned_abs().to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    if n < 0 { format!("-{out}") } else { out }
}

/// Dedupe by lowercased identifier (name fallback), first wins (Hermes `_dedupe_results`).
fn dedupe_ids(results: Vec<SkillMeta>) -> Vec<SkillMeta> {
    let mut seen: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for m in results {
        let k = if m.identifier.is_empty() { m.name.to_lowercase() } else { m.identifier.to_lowercase() };
        if !seen.contains(&k) {
            seen.push(k);
            out.push(m);
        }
    }
    out
}

// ───────────── official ─────────────

/// `extra.provider` label of a raw index entry, lowercased ("" when absent).
fn entry_provider(e: &Value) -> String {
    e.pointer("/extra/provider").and_then(Value::as_str).unwrap_or("").trim().to_lowercase()
}

/// Rank of an index entry for a lowercased query: None when nothing matches, else 0 exact name,
/// 1 name prefix, 2 provider, 3 whole word, 4 name substring, 5 any other field.
fn index_rank(q: &str, e: &Value) -> Option<usize> {
    let name = s(e, "name").to_lowercase();
    let provider = entry_provider(e);
    let tags: Vec<String> = e["tags"].as_array().map(|a| a.iter().map(|t| t.as_str().unwrap_or("").to_lowercase()).collect()).unwrap_or_default();
    let hay = [name.clone(), s(e, "description").to_lowercase(), tags.join(" "), s(e, "identifier").to_lowercase(), s(e, "path").to_lowercase(), provider.clone()].join(" ");
    if !hay.contains(q) {
        return None;
    }
    let ranks = [name == q, name.starts_with(q), provider == q, name.split_whitespace().any(|t| t == q) || provider.split_whitespace().any(|t| t == q), name.contains(q), true];
    ranks.iter().position(|x| *x)
}

pub struct Official<'a> {
    pub http: &'a Http,
}

impl Official<'_> {
    pub fn index(&self) -> Vec<Value> {
        let Some(share) = crate::skill::share_dir() else { return vec![] };
        let v: Value = std::fs::read_to_string(share.join("optional-skills/index.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(json!({}));
        v["skills"].as_array().cloned().unwrap_or_default()
    }
    fn meta(&self, e: &Value) -> SkillMeta {
        let path = s(e, "path");
        SkillMeta { name: s(e, "name"), description: s(e, "description"), source: "official".into(), identifier: format!("official/{path}"), trust_level: "builtin".into(), repo: Some(self.http.settings.hub.official_repo.clone()), path: Some(format!("{}/{path}", self.http.settings.hub.official_prefix)), tags: e["tags"].as_array().map(|a| a.iter().filter_map(|t| t.as_str().map(String::from)).collect()).unwrap_or_default(), extra: Map::new() }
    }
    fn entry(&self, identifier: &str) -> Option<Value> {
        let rel = identifier.strip_prefix("official/").unwrap_or(identifier).trim_matches('/');
        if validate_rel(rel).is_err() {
            return None;
        }
        let idx = self.index();
        idx.iter().find(|e| s(e, "path") == rel).cloned().or_else(|| {
            let base = rel.rsplit('/').next().unwrap_or(rel);
            let hits: Vec<&Value> = idx.iter().filter(|e| s(e, "name") == base || s(e, "path").rsplit('/').next() == Some(base)).collect();
            (hits.len() == 1).then(|| hits[0].clone())
        })
    }
}

impl Source for Official<'_> {
    fn id(&self) -> &'static str {
        "official"
    }
    fn search(&self, q: &str, limit: usize) -> Vec<SkillMeta> {
        let ql = q.trim().to_lowercase();
        let idx = self.index();
        let mut hits: Vec<(usize, usize)> = idx.iter().enumerate().filter_map(|(i, e)| index_rank(&ql, e).map(|r| (r, i))).collect();
        hits.sort();
        hits.into_iter().take(limit).map(|(_, i)| self.meta(&idx[i])).collect()
    }
    fn inspect(&self, id: &str) -> Option<SkillMeta> {
        self.entry(id).map(|e| self.meta(&e))
    }
    fn fetch(&self, id: &str) -> Option<SkillBundle> {
        let e = self.entry(id)?;
        let rel = s(&e, "path");
        let files: Vec<String> = e["files"].as_array().map(|a| a.iter().filter_map(|f| f.as_str().map(String::from)).collect()).unwrap_or_else(|| vec!["SKILL.md".into()]);
        let mut out = BTreeMap::new();
        let local = crate::skill::share_dir().map(|d| d.join("optional-skills").join(&rel)).filter(|d| d.join("SKILL.md").is_file());
        for f in files {
            let f = validate_rel(&f).ok()?;
            if skip_bundle_file(&f) {
                continue;
            }
            let data = match &local {
                Some(d) => std::fs::read(d.join(&f)).ok()?,
                None => {
                    let h = &self.http.settings.hub;
                    let url = format!("{}/{}/main/{}/{rel}/{f}", h.github_raw, h.official_repo, h.official_prefix);
                    self.http.get(&url).filter(|r| r.ok())?.body
                }
            };
            out.insert(f, data);
        }
        out.contains_key("SKILL.md").then(|| SkillBundle { name: rel.rsplit('/').next().unwrap_or(&rel).to_string(), files: out, source: "official".into(), identifier: format!("official/{rel}"), trust_level: "builtin".into(), metadata: Map::from_iter([("install_parent".to_string(), json!(rel.rsplit_once('/').map(|x| x.0).unwrap_or("")))]) })
    }
    fn claims(&self, id: &str) -> bool {
        id.starts_with("official/")
    }
}

// ───────────── github ─────────────

/// GitHub tap repo (`owner/repo`) → provider label (Hermes `GITHUB_TAP_PROVIDERS`). The runtime
/// index collapses every tap into source `github`; `extra.provider` keeps per-tap identity.
const TAP_PROVIDERS: &[(&str, &str)] = &[
    ("openai/skills", "OpenAI"),
    ("anthropics/skills", "Anthropic"),
    ("huggingface/skills", "HuggingFace"),
    ("nvidia/skills", "NVIDIA"),
    ("voltagent/awesome-agent-skills", "VoltAgent"),
    ("garrytan/gstack", "gstack"),
    ("minimax-ai/cli", "MiniMax"),
];

/// Provider label for an `owner/repo` tap (case-insensitive), or None.
pub fn github_provider_for(repo: &str) -> Option<&'static str> {
    TAP_PROVIDERS.iter().find(|(r, _)| r.eq_ignore_ascii_case(repo.trim())).map(|(_, p)| *p)
}

pub struct GitHub<'a> {
    pub http: &'a Http,
    pub taps: Vec<(String, String)>,
}

pub fn split_repo_id(id: &str) -> Option<(String, String)> {
    let p: Vec<&str> = id.splitn(3, '/').collect();
    (p.len() >= 3 && !p[0].is_empty() && !p[1].is_empty()).then(|| (format!("{}/{}", p[0], p[1]), p[2].trim_matches('/').to_string()))
}

impl GitHub<'_> {
    pub fn trust_for(id: &str) -> &'static str {
        let p: Vec<&str> = id.splitn(3, '/').collect();
        if p.len() >= 2 && seagent_security::skills_guard::TRUSTED_REPOS.contains(&format!("{}/{}", p[0], p[1]).as_str()) {
            "trusted"
        } else {
            "community"
        }
    }
    fn api(&self) -> &str {
        &self.http.settings.hub.github_api
    }
    /// (default branch, tree sha, entries).
    pub fn tree(&self, repo: &str) -> Option<(String, String, Vec<Value>)> {
        let r = self.http.get_json(&format!("{}/repos/{repo}", self.api()))?;
        let branch = r["default_branch"].as_str().unwrap_or("main").to_string();
        let t = self.http.get_json(&with_query(&format!("{}/repos/{repo}/git/trees/{branch}", self.api()), &[("recursive", "1".into())]))?;
        if t["truncated"].as_bool() == Some(true) {
            return None;
        }
        Some((branch, s(&t, "sha"), t["tree"].as_array().cloned().unwrap_or_default()))
    }
    pub fn file(&self, repo: &str, path: &str, rev: Option<&str>) -> Option<Vec<u8>> {
        if let Some(r) = rev.filter(|r| !r.is_empty()) {
            if let Some(resp) = self.http.get(&format!("{}/{repo}/{r}/{path}", self.http.settings.hub.github_raw)).filter(|x| x.ok()) {
                return Some(resp.body);
            }
        }
        let url = format!("{}/repos/{repo}/contents/{path}", self.api());
        let url = match rev.filter(|r| !r.is_empty()) {
            Some(r) => with_query(&url, &[("ref", r.into())]),
            None => url,
        };
        let v = self.http.get_json(&url)?;
        let content = v["content"].as_str()?.replace('\n', "");
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(content).ok()
    }
    /// Full identifier of `<name>/SKILL.md` anywhere in the repo tree (one tree lookup),
    /// else the generic single-skill dir case. Mirrors Hermes `_find_skill_in_repo_tree`.
    pub fn find_in_tree(&self, repo: &str, name: &str) -> Option<String> {
        let skill_md = "/SKILL.md";
        let mut dirs: Vec<String> = Vec::new();
        for e in self.tree(repo)?.2 {
            let p = s(&e, "path");
            if e["type"] != "blob" || e["mode"] == "120000" || !p.ends_with(skill_md) {
                continue;
            }
            if p.ends_with(&format!("/{name}{skill_md}")) {
                return Some(format!("{repo}/{}", &p[..p.len() - skill_md.len()]));
            }
            dirs.push(p[..p.len() - skill_md.len()].trim_end_matches('/').to_string());
        }
        // A single-skill repo may keep it in a generic dir (`skills/SKILL.md`) no slug matches; a
        // lone NAMED dir is another skill, and a lone root SKILL.md is `root_skill`'s case.
        (dirs.len() == 1 && matches!(dirs[0].as_str(), "skills" | ".agents/skills" | ".claude/skills")).then(|| format!("{repo}/{}", dirs[0]))
    }
    /// Identifier of a single-skill repo whose `SKILL.md` sits at the repo root — the empty path
    /// segment denotes the skill directory being the repo root (Hermes `_find_repo_root_skill`).
    /// Only repos with EXACTLY ONE SKILL.md in the whole tree qualify.
    pub fn root_skill(&self, repo: &str) -> Option<String> {
        let md = "SKILL.md";
        let hits: Vec<String> = self.tree(repo)?.2.iter().filter(|e| e["type"] == "blob" && e["mode"] != "120000").map(|e| s(e, "path")).filter(|p| p == md || p.ends_with("/SKILL.md")).collect();
        (hits.len() == 1 && hits[0] == md).then(|| format!("{repo}/"))
    }
    fn list(&self, repo: &str, path: &str) -> Vec<SkillMeta> {
        let key = format!("github_{repo}_{path}");
        let v = self.http.memo(&key, || {
            let entries = self.children(repo, path)?;
            let mut out = Self::rows(&entries, repo, path, self);
            // Upstream points its taps at the inner paths (`openai/skills` keeps its skills under
            // `skills/.curated/` + `skills/.system/`, both of which the dot/underscore skip hides).
            // When a tap path yields nothing but such dirs, descend one level instead of going dark.
            if out.is_empty() {
                for n in Self::skipped_children(&entries) {
                    let inner = if path.trim_matches('/').is_empty() { n.clone() } else { format!("{}/{n}", path.trim_matches('/')) };
                    if let Some(e) = self.children(repo, &inner) {
                        out.extend(Self::rows(&e, repo, &inner, self));
                    }
                }
            }
            Some(Value::Array(out))
        });
        v.and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default()
    }
    fn children(&self, repo: &str, path: &str) -> Option<Vec<Value>> {
        let entries = self.http.get_json(&format!("{}/repos/{repo}/contents/{}", self.api(), path.trim_end_matches('/')))?;
        entries.as_array().cloned()
    }
    /// Child directories a listing skips (`.`/`_` prefixed, minus the junk dirs).
    fn skipped_children(entries: &[Value]) -> Vec<String> {
        entries.iter().filter(|e| e["type"] == "dir").map(|e| s(e, "name")).filter(|n| n.starts_with(['.', '_']) && !matches!(n.as_str(), ".git" | "__pycache__" | "node_modules")).collect()
    }
    fn rows(entries: &[Value], repo: &str, path: &str, g: &Self) -> Vec<Value> {
        let mut out = Vec::new();
        for e in entries {
            let n = s(e, "name");
            if e["type"] != "dir" || n.starts_with(['.', '_']) {
                continue;
            }
            let id = if path.trim_matches('/').is_empty() { format!("{repo}/{n}") } else { format!("{repo}/{}/{n}", path.trim_matches('/')) };
            if let Some(m) = g.inspect(&id) {
                if let Ok(v) = serde_json::to_value(m) {
                    out.push(v);
                }
            }
        }
        out
    }
}

impl Source for GitHub<'_> {
    fn id(&self) -> &'static str {
        "github"
    }
    fn search(&self, q: &str, limit: usize) -> Vec<SkillMeta> {
        let mut r = Vec::new();
        for (repo, path) in &self.taps {
            r.extend(self.list(repo, path).into_iter().filter(|m| matches_query(q, &[&m.name, &m.description, &m.tags.join(" ")])));
        }
        dedupe_by_trust(r).into_iter().take(limit).collect()
    }
    fn inspect(&self, id: &str) -> Option<SkillMeta> {
        let (repo, path) = split_repo_id(id)?;
        let md = self.file(&repo, &if path.is_empty() { "SKILL.md".into() } else { format!("{path}/SKILL.md") }, None)?;
        let fm = crate::yaml::frontmatter(&String::from_utf8_lossy(&md)).0;
        let mut extra = Map::new();
        if let Some(p) = github_provider_for(&repo) {
            extra.insert("provider".into(), json!(p));
        }
        Some(SkillMeta { name: fm.get("name").and_then(Value::as_str).map(String::from).unwrap_or_else(|| path.rsplit('/').next().unwrap_or(&repo).to_string()), description: s(&fm, "description"), source: "github".into(), identifier: id.to_string(), trust_level: Self::trust_for(id).into(), repo: Some(repo), path: Some(path), tags: tags_of(&fm), extra })
    }
    /// Full skill directory from the pinned tree; symlinked or unsafe entries reject the bundle.
    fn fetch(&self, id: &str) -> Option<SkillBundle> {
        let (repo, path) = split_repo_id(id)?;
        let tree = self.tree(&repo);
        let rev = tree.as_ref().map(|t| t.1.clone()).filter(|r| !r.is_empty());
        let md_path = if path.is_empty() { "SKILL.md".to_string() } else { format!("{path}/SKILL.md") };
        let md = self.file(&repo, &md_path, rev.as_deref())?;
        let referenced = referenced_support_paths(&String::from_utf8_lossy(&md))?;
        let mut files = BTreeMap::from([("SKILL.md".to_string(), md)]);
        let prefix = if path.is_empty() { String::new() } else { format!("{path}/") };
        // A bundle with a transiently failed blob fetch must not record the tree sha: an update
        // check would otherwise see "same revision" and never re-fetch the gap (#101454).
        let mut complete = true;
        match &tree {
            Some((_, _, entries)) => {
                let mut symlinked = Vec::new();
                for e in entries {
                    let ip = s(e, "path");
                    let Some(rel) = ip.strip_prefix(&prefix) else { continue };
                    if e["type"] != "blob" || e["mode"] == "120000" {
                        symlinked.push(rel.to_string());
                        continue;
                    }
                    if rel == "SKILL.md" || skip_bundle_file(rel) || rel.rsplit('/').next().is_some_and(|b| b.starts_with('.')) {
                        continue;
                    }
                    let rel = validate_rel(rel).ok()?;
                    match self.file(&repo, &ip, rev.as_deref()) {
                        Some(b) => {
                            files.insert(rel, b);
                        }
                        None => complete = false,
                    }
                }
                if referenced.iter().any(|r| symlinked.contains(r)) {
                    return None;
                }
            }
            None => {
                for r in &referenced {
                    if let Some(b) = self.file(&repo, &format!("{prefix}{r}"), None) {
                        files.insert(r.clone(), b);
                    }
                }
            }
        }
        let name = path.rsplit('/').next().filter(|n| !n.is_empty()).unwrap_or(repo.rsplit('/').next().unwrap_or("skill")).to_string();
        let revision = rev.filter(|_| complete).unwrap_or_default();
        let url = if revision.is_empty() { format!("https://github.com/{repo}/{path}") } else { format!("https://github.com/{repo}/tree/{revision}/{path}") };
        Some(SkillBundle { name, files, source: "github".into(), identifier: id.into(), trust_level: Self::trust_for(id).into(), metadata: Map::from_iter([("source_url".to_string(), json!(url)), ("source_revision".to_string(), json!(revision))]) })
    }
    fn claims(&self, id: &str) -> bool {
        !id.contains("://") && split_repo_id(id).is_some() && !id.starts_with('@')
    }
}

// ───────────── clawhub ─────────────

pub struct ClawHub<'a> {
    pub http: &'a Http,
}

impl ClawHub<'_> {
    fn base(&self) -> &str {
        &self.http.settings.hub.clawhub
    }
    /// `…@<version>` pin → (rest, Some(version)); the LAST `@` counts, and a leading `@` (the owner
    /// marker of `@owner/slug`) never does (OpenClaw `infra/clawhub-spec.ts`). A pin with an empty
    /// version (`slug@`) rejects the whole id.
    fn split_pin(raw: &str) -> Option<(&str, Option<&str>)> {
        match raw.rfind('@') {
            None | Some(0) => Some((raw, None)),
            Some(i) => {
                let (name, ver) = (raw[..i].trim_end(), raw[i + 1..].trim());
                (!ver.is_empty() && !ver.contains('/') && !ver.chars().any(char::is_whitespace)).then_some((name, Some(ver)))
            }
        }
    }
    /// `slug`, `clawhub/slug`, `@owner/slug`, `owner/skills/slug` → (slug, owner); a `@version` pin is
    /// stripped (see `parse_pinned` for the version itself).
    pub fn parse_id(id: &str) -> Option<(String, Option<String>)> {
        let (base, _) = Self::split_pin(id.trim())?;
        Self::parse_unpinned(base)
    }
    /// Identifier plus its `@version` pin: `@owner/slug@1.2.0` → (slug, Some(owner), Some("1.2.0")).
    pub fn parse_pinned(id: &str) -> Option<(String, Option<String>, Option<String>)> {
        let (base, ver) = Self::split_pin(id.trim())?;
        let (slug, owner) = Self::parse_unpinned(base)?;
        Some((slug, owner, ver.map(String::from)))
    }
    fn parse_unpinned(raw: &str) -> Option<(String, Option<String>)> {
        let mut at = raw.starts_with('@');
        let mut st = raw.trim_start_matches('@').trim_start_matches("clawhub/");
        if st.starts_with('@') {
            at = true;
            st = &st[1..];
        }
        let parts: Vec<&str> = st.split('/').filter(|p| !p.is_empty()).collect();
        let slug_re = regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]*$").unwrap();
        let (owner, slug) = match parts.len() {
            1 => (None, parts[0]),
            2 if at => (Some(parts[0]), parts[1]),
            3 if parts[1].eq_ignore_ascii_case("skills") => (Some(parts[0]), parts[2]),
            _ => return None,
        };
        (slug_re.is_match(slug) && owner.is_none_or(|o| slug_re.is_match(o))).then(|| (slug.to_string(), owner.map(String::from)))
    }
    fn owner_of(v: &Value) -> Option<String> {
        let o = v.get("owner")?;
        o.get("handle").and_then(Value::as_str).or(o.as_str()).map(str::trim).filter(|s| !s.is_empty()).map(String::from)
    }
    /// Whether a payload may belong to `want`: an absent owner on either side never rejects.
    fn owner_matches(want: Option<&String>, v: &Value) -> bool {
        match want {
            None => true,
            Some(w) => Self::owner_of(v).is_none_or(|got| got.eq_ignore_ascii_case(w)),
        }
    }
    fn terms(q: &str) -> Vec<String> {
        q.to_lowercase().split(|c: char| !c.is_alphanumeric()).filter(|t| !t.is_empty()).map(String::from).collect()
    }
    /// Exact-slug candidates for a query (Hermes `_exact_slug_meta`): the parsed slug, else the query
    /// when it is a bare slug, then the term-joined base slug and its `-agent/-skill/…` variants.
    fn slug_candidates(q: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        match Self::parse_id(q) {
            Some((slug, _)) => out.push(slug),
            None if !q.contains('/') && regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]*$").unwrap().is_match(q) => out.push(q.to_string()),
            None => {}
        }
        let t = Self::terms(q);
        if !t.is_empty() {
            let base = t.join("-");
            if t.len() >= 2 {
                out.extend(["agent", "skill", "tool", "assistant", "playbook"].iter().map(|s| format!("{base}-{s}")));
            }
            out.push(base);
        }
        let mut uniq: Vec<String> = Vec::new();
        for c in out {
            if !uniq.contains(&c) {
                uniq.push(c);
            }
        }
        uniq
    }
    /// First exact-slug candidate that exists on the registry.
    fn exact_meta(&self, q: &str) -> Option<SkillMeta> {
        Self::slug_candidates(q).iter().find_map(|c| self.inspect(c))
    }
    /// Rank, score-cut and dedupe listing rows (Hermes `_finalize_search_results`): a resolved exact
    /// slug is promoted and near-irrelevant rows are dropped so it stays visible.
    fn finalize(&self, q: &str, rows: Vec<SkillMeta>, limit: usize) -> Vec<SkillMeta> {
        let qn = q.trim();
        if qn.is_empty() {
            return dedupe_ids(rows).into_iter().take(limit).collect();
        }
        let all = dedupe_ids(rows.clone());
        let mut f: Vec<SkillMeta> = rows.into_iter().filter(|m| search_score(qn, m) > 0).collect();
        f.sort_by_key(|m| (-search_score(qn, m), m.name.to_lowercase(), m.identifier.to_lowercase()));
        let mut f = dedupe_ids(f);
        if let Some(exact) = self.exact_meta(qn) {
            let mut v = vec![exact];
            v.extend(f.into_iter().filter(|m| search_score(qn, m) >= 20));
            f = dedupe_ids(v);
        }
        if f.is_empty() && !regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$").unwrap().is_match(qn) {
            f = dedupe_ids(all);
        }
        f.into_iter().take(limit).collect()
    }
    fn coerce(v: Value) -> Value {
        match v.get("skill") {
            Some(Value::Object(sk)) => {
                let mut m = sk.clone();
                for k in ["latestVersion", "owner"] {
                    if let Some(x) = v.get(k) {
                        m.entry(k.to_string()).or_insert(x.clone());
                    }
                }
                Value::Object(m)
            }
            _ => v,
        }
    }
    fn item_meta(item: &Value) -> Option<SkillMeta> {
        let slug = item.get("slug").and_then(Value::as_str).filter(|s| !s.is_empty())?;
        let mut extra = Map::new();
        if let Some(o) = Self::owner_of(item) {
            extra.insert("owner".into(), json!(o));
        }
        let tags = match item.get("tags") {
            Some(Value::Array(a)) => a.iter().filter_map(|t| t.as_str().map(String::from)).collect(),
            Some(Value::Object(o)) => o.keys().filter(|k| *k != "latest").cloned().collect(),
            _ => vec![],
        };
        Some(SkillMeta { name: item.get("displayName").or(item.get("name")).and_then(Value::as_str).unwrap_or(slug).to_string(), description: item.get("summary").or(item.get("description")).and_then(Value::as_str).unwrap_or("").to_string(), source: "clawhub".into(), identifier: slug.to_string(), trust_level: "community".into(), repo: None, path: None, tags, extra })
    }
    fn detail(&self, id: &str) -> Option<(String, Option<String>, Value)> {
        let (slug, owner) = Self::parse_id(id)?;
        let q: Vec<(&str, String)> = owner.iter().map(|o| ("owner", o.clone())).collect();
        let d = Self::coerce(self.http.get_json(&with_query(&format!("{}/skills/{slug}", self.base()), &q))?);
        if let (Some(want), Some(got)) = (&owner, Self::owner_of(&d)) {
            if !want.eq_ignore_ascii_case(&got) {
                return None;
            }
        }
        Some((slug, owner, d))
    }
    fn latest_version(&self, slug: &str, d: &Value, owner: &Option<String>) -> Option<String> {
        let v = d.pointer("/latestVersion/version").and_then(Value::as_str).or_else(|| d.pointer("/tags/latest").and_then(Value::as_str));
        if let Some(v) = v {
            return Some(v.to_string());
        }
        let q: Vec<(&str, String)> = owner.iter().map(|o| ("owner", o.clone())).collect();
        let vd = self.http.get_json(&with_query(&format!("{}/skills/{slug}/versions", self.base()), &q))?;
        let items = vd.get("items").cloned().unwrap_or(vd);
        items.get(0)?.get("version")?.as_str().map(String::from)
    }
    fn extract_files(&self, vd: &Value) -> BTreeMap<String, Vec<u8>> {
        let mut out = BTreeMap::new();
        match vd.get("files") {
            Some(Value::Object(m)) => {
                for (k, v) in m {
                    if let (Some(t), Ok(k)) = (v.as_str(), validate_rel(k)) {
                        out.insert(k, t.as_bytes().to_vec());
                    }
                }
            }
            Some(Value::Array(a)) => {
                for f in a {
                    let Some(name) = f.get("path").or(f.get("name")).and_then(Value::as_str) else { continue };
                    let Ok(name) = validate_rel(name) else { continue };
                    if let Some(c) = f.get("content").and_then(Value::as_str) {
                        out.insert(name, c.as_bytes().to_vec());
                    } else if let Some(u) = f.get("rawUrl").or(f.get("downloadUrl")).or(f.get("url")).and_then(Value::as_str).filter(|u| u.starts_with("http")) {
                        if let Some(b) = self.http.get(u).filter(|r| r.ok()) {
                            out.insert(name, b.body);
                        }
                    }
                }
            }
            _ => {}
        }
        out
    }
}

impl Source for ClawHub<'_> {
    fn id(&self) -> &'static str {
        "clawhub"
    }
    fn search(&self, q: &str, limit: usize) -> Vec<SkillMeta> {
        let q = q.trim();
        if Self::terms(q).len() >= 2 {
            if let Some(m) = self.exact_meta(q) {
                return vec![m];
            }
        }
        let data = self.http.get_json(&with_query(&format!("{}/skills", self.base()), &[("search", q.into()), ("limit", limit.to_string())]));
        let items = data.map(|d| d.get("items").cloned().unwrap_or(d)).and_then(|d| d.as_array().cloned()).unwrap_or_default();
        let rows: Vec<SkillMeta> = items.iter().filter_map(Self::item_meta).collect();
        self.finalize(q, rows, limit)
    }
    fn inspect(&self, id: &str) -> Option<SkillMeta> {
        let (slug, owner, d) = self.detail(id)?;
        let mut d2 = d.clone();
        d2["slug"] = json!(d.get("slug").and_then(Value::as_str).unwrap_or(&slug));
        let mut m = Self::item_meta(&d2)?;
        if let Some(o) = owner.or_else(|| Self::owner_of(&d)) {
            m.identifier = format!("@{o}/{slug}");
            m.extra.insert("owner".into(), json!(o));
        }
        Some(m)
    }
    fn fetch(&self, id: &str) -> Option<SkillBundle> {
        let (slug, owner0, pin) = Self::parse_pinned(id)?;
        let d = self.detail(id)?.2;
        let owner = owner0.or_else(|| Self::owner_of(&d));
        // A pinned install resolves that exact version (OpenClaw `clawhub-install-core.ts`:
        // `version = params.version ?? detail.latestVersion?.version`, refusing a mismatch).
        let ver = match &pin {
            Some(v) => v.clone(),
            None => self.latest_version(&slug, &d, &owner)?,
        };
        let mut q = vec![("slug", slug.clone()), ("version", ver.clone())];
        if let Some(o) = &owner {
            q.push(("owner", o.clone()));
        }
        let mut files = self.http.get(&with_query(&format!("{}/download", self.base()), &q)).filter(|r| r.ok()).map(|r| super::zip::text_members(&r.body, 500_000)).unwrap_or_default();
        if !files.contains_key("SKILL.md") {
            let oq: Vec<(&str, String)> = owner.iter().map(|o| ("owner", o.clone())).collect();
            if let Some(vd) = self.http.get_json(&with_query(&format!("{}/skills/{slug}/versions/{ver}", self.base()), &oq)) {
                // Content from a payload owned by someone else is never installed (#104117).
                if Self::owner_matches(owner.as_ref(), &vd) {
                    // `Skill <slug>@<version> resolved to <other>.`
                    let got = vd.get("version").and_then(Value::as_str).or_else(|| vd.pointer("/version/version").and_then(Value::as_str));
                    if pin.is_some() && got.is_some_and(|g| g != ver) {
                        return None;
                    }
                    files = self.extract_files(&vd);
                    if !files.contains_key("SKILL.md") {
                        if let Some(n) = vd.get("version") {
                            files = self.extract_files(n);
                        }
                    }
                }
            }
        }
        files.contains_key("SKILL.md").then(|| SkillBundle { name: slug.clone(), files, source: "clawhub".into(), identifier: owner.as_ref().map(|o| format!("@{o}/{slug}")).unwrap_or(slug.clone()), trust_level: "community".into(), metadata: Map::from_iter([("version".to_string(), json!(ver)), ("requested_version".to_string(), json!(pin.unwrap_or_default()))]) })
    }
    fn claims(&self, id: &str) -> bool {
        let Some((base, _)) = Self::split_pin(id.trim()) else { return false };
        base.starts_with("clawhub/") || (base.starts_with('@') && base.matches('/').count() == 1)
    }
}

// ───────────── skills.sh ─────────────

pub struct SkillsSh<'a> {
    pub http: &'a Http,
    pub github: GitHub<'a>,
}

const SKILLS_SH_PREFIXES: &[&str] = &["skills-sh/", "skills.sh/", "skils-sh/", "skils.sh/"];

impl SkillsSh<'_> {
    fn canonical(id: &str) -> String {
        SKILLS_SH_PREFIXES.iter().find_map(|p| id.strip_prefix(p)).unwrap_or(id).to_string()
    }
    fn candidates(c: &str) -> Vec<String> {
        let Some((repo, path)) = split_repo_id(c) else { return vec![c.into()] };
        let mut v = vec![format!("{repo}/{path}")];
        for b in ["skills/", ".agents/skills/", ".claude/skills/"] {
            let x = format!("{repo}/{b}{path}");
            if !v.contains(&x) {
                v.push(x);
            }
        }
        v
    }
    /// Last-resort resolution when no standard path holds the skill: a slug-named dir anywhere in
    /// the repo tree, then a lone generic dir, then a single-skill repo root (Hermes
    /// `_discover_identifier`). A concrete path that is gone stays gone.
    fn discover(&self, c: &str) -> Option<String> {
        let (repo, path) = split_repo_id(c)?;
        let name = path.trim_end_matches('/').rsplit('/').next().filter(|n| !n.is_empty())?;
        self.github.find_in_tree(&repo, name).or_else(|| self.github.root_skill(&repo))
    }
    /// `detail_url` / `repo_url` provenance rows (Hermes `_urls_for`).
    fn add_urls(&self, extra: &mut Map<String, Value>, c: &str) {
        extra.insert("detail_url".into(), json!(format!("{}/{c}", self.http.settings.hub.skills_sh)));
        if let Some((repo, _)) = split_repo_id(c) {
            extra.insert("repo_url".into(), json!(format!("https://github.com/{repo}")));
        }
    }
}

impl Source for SkillsSh<'_> {
    fn id(&self) -> &'static str {
        "skills-sh"
    }
    fn search(&self, q: &str, limit: usize) -> Vec<SkillMeta> {
        if q.trim().is_empty() {
            return vec![];
        }
        let Some(d) = self.http.get_json(&with_query(&format!("{}/api/search", self.http.settings.hub.skills_sh), &[("q", q.into()), ("limit", limit.to_string())])) else { return vec![] };
        let mut out = Vec::new();
        for it in d["skills"].as_array().into_iter().flatten().take(limit) {
            let mut c = s(it, "id");
            if c.matches('/').count() < 2 {
                c = format!("{}/{}", s(it, "source"), s(it, "skillId"));
            }
            let Some((repo, path)) = split_repo_id(&c) else { continue };
            let installs = it["installs"].as_i64();
            let label = installs.map(|i| format!(" · {} installs", thousands(i))).unwrap_or_default();
            let mut extra = Map::new();
            if let Some(i) = installs {
                extra.insert("installs".into(), json!(i));
            }
            self.add_urls(&mut extra, &c);
            out.push(SkillMeta { name: it.get("name").and_then(Value::as_str).map(String::from).unwrap_or_else(|| path.rsplit('/').next().unwrap_or("").to_string()), description: format!("Indexed by skills.sh from {repo}{label}"), source: "skills.sh".into(), identifier: format!("skills-sh/{c}"), trust_level: GitHub::trust_for(&c).into(), repo: Some(repo), path: Some(path), tags: vec![], extra });
        }
        out
    }
    fn inspect(&self, id: &str) -> Option<SkillMeta> {
        let c = Self::canonical(id);
        let m = Self::candidates(&c).iter().find_map(|x| self.github.inspect(x)).or_else(|| self.discover(&c).and_then(|x| self.github.inspect(&x)))?;
        let mut m = m;
        m.source = "skills.sh".into();
        m.identifier = format!("skills-sh/{c}");
        self.add_urls(&mut m.extra, &c);
        Some(m)
    }
    fn fetch(&self, id: &str) -> Option<SkillBundle> {
        let c = Self::canonical(id);
        let mut b = Self::candidates(&c).iter().find_map(|x| self.github.fetch(x)).or_else(|| self.discover(&c).and_then(|x| self.github.fetch(&x)))?;
        b.source = "skills.sh".into();
        b.identifier = format!("skills-sh/{c}");
        if b.name == "skills" {
            // A generic `skills/` dir installs under the slug, as the index does.
            b.name = c.trim_end_matches('/').rsplit('/').next().unwrap_or("skill").to_string();
        }
        self.add_urls(&mut b.metadata, &c);
        Some(b)
    }
    fn claims(&self, id: &str) -> bool {
        SKILLS_SH_PREFIXES.iter().any(|p| id.starts_with(p))
    }
}

// ───────────── lobehub / browse.sh / well-known / url ─────────────

pub struct LobeHub<'a> {
    pub http: &'a Http,
}

impl LobeHub<'_> {
    fn agents(&self) -> Vec<Value> {
        let base = self.http.settings.hub.lobehub.clone();
        let idx = self.http.memo("lobehub_index", || self.http.get_json(&format!("{base}/index.json")));
        idx.map(|i| i.get("agents").cloned().unwrap_or(i)).and_then(|a| a.as_array().cloned()).unwrap_or_default()
    }
    pub fn to_skill_md(a: &Value) -> String {
        let meta = a.get("meta").unwrap_or(a);
        let id = a.get("identifier").and_then(Value::as_str).unwrap_or("lobehub-agent");
        let title = meta.get("title").and_then(Value::as_str).unwrap_or(id);
        let desc = meta.get("description").and_then(Value::as_str).unwrap_or("");
        let tags: Vec<String> = meta.get("tags").and_then(Value::as_array).map(|t| t.iter().map(|x| x.as_str().unwrap_or("").to_string()).collect()).unwrap_or_default();
        let role = a.pointer("/config/systemRole").and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or("(No system role defined)");
        format!("---\nname: {id}\ndescription: {}\nmetadata:\n  seagent:\n    tags: [{}]\n  lobehub:\n    source: lobehub\n---\n\n# {title}\n\n{desc}\n\n## Instructions\n\n{role}\n", serde_json::to_string(&desc.chars().take(500).collect::<String>()).unwrap(), tags.join(", "))
    }
}

impl Source for LobeHub<'_> {
    fn id(&self) -> &'static str {
        "lobehub"
    }
    fn search(&self, q: &str, limit: usize) -> Vec<SkillMeta> {
        self.agents()
            .iter()
            .filter(|a| {
                let m = a.get("meta").unwrap_or(a);
                matches_query(q, &[m.get("title").and_then(Value::as_str).unwrap_or(""), m.get("description").and_then(Value::as_str).unwrap_or(""), &m.get("tags").map(|t| t.to_string()).unwrap_or_default()])
            })
            .take(limit)
            .map(|a| {
                let m = a.get("meta").unwrap_or(a);
                let id = a.get("identifier").and_then(Value::as_str).unwrap_or("").to_string();
                let tags: Vec<String> = m.get("tags").and_then(Value::as_array).map(|t| t.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
                SkillMeta { name: id.clone(), description: m.get("description").and_then(Value::as_str).unwrap_or("").chars().take(200).collect(), source: "lobehub".into(), identifier: format!("lobehub/{id}"), trust_level: "community".into(), tags, ..Default::default() }
            })
            .collect()
    }
    fn inspect(&self, id: &str) -> Option<SkillMeta> {
        let aid = id.strip_prefix("lobehub/").unwrap_or(id);
        self.search("", usize::MAX).into_iter().find(|m| m.name == aid)
    }
    fn fetch(&self, id: &str) -> Option<SkillBundle> {
        let aid = id.strip_prefix("lobehub/").unwrap_or(id);
        validate_skill_name(aid).ok()?;
        let a = self.http.get_json(&format!("{}/{aid}.json", self.http.settings.hub.lobehub))?;
        Some(SkillBundle { name: aid.into(), files: BTreeMap::from([("SKILL.md".to_string(), Self::to_skill_md(&a).into_bytes())]), source: "lobehub".into(), identifier: format!("lobehub/{aid}"), trust_level: "community".into(), metadata: Map::new() })
    }
    fn claims(&self, id: &str) -> bool {
        id.starts_with("lobehub/")
    }
}

pub struct BrowseSh<'a> {
    pub http: &'a Http,
}

impl BrowseSh<'_> {
    fn catalog(&self) -> Vec<Value> {
        let base = self.http.settings.hub.browse_sh.clone();
        self.http.memo("browse_sh_catalog", || self.http.get_json(&base).and_then(|d| d.get("skills").cloned())).and_then(|v| v.as_array().cloned()).unwrap_or_default()
    }
    fn meta(it: &Value) -> Option<SkillMeta> {
        let (slug, name) = (s(it, "slug"), s(it, "name"));
        if slug.is_empty() || name.is_empty() {
            return None;
        }
        let mut desc = it.get("description").or(it.get("title")).and_then(Value::as_str).unwrap_or(&name).to_string();
        if desc.len() > 1024 {
            desc = format!("{}...", desc.chars().take(1021).collect::<String>());
        }
        let tags: Vec<String> = it["tags"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
        let extra = Map::from_iter([
            ("slug".to_string(), json!(slug)),
            ("hostname".to_string(), json!(s(it, "hostname"))),
            ("category".to_string(), json!(s(it, "category"))),
            ("source_url".to_string(), json!(s(it, "sourceUrl"))),
            ("recommended_method".to_string(), json!(s(it, "recommendedMethod"))),
            ("proxies".to_string(), it.get("proxies").cloned().unwrap_or(json!(false))),
            ("install_count".to_string(), it.get("installCount").cloned().unwrap_or(json!(0))),
        ]);
        Some(SkillMeta { name, description: desc, source: "browse-sh".into(), identifier: format!("browse-sh/{slug}"), trust_level: "community".into(), tags, extra, ..Default::default() })
    }
}

impl Source for BrowseSh<'_> {
    fn id(&self) -> &'static str {
        "browse-sh"
    }
    fn search(&self, q: &str, limit: usize) -> Vec<SkillMeta> {
        self.catalog().iter().filter(|i| matches_query(q, &[&s(i, "name"), &s(i, "title"), &s(i, "description"), &s(i, "hostname"), &s(i, "category"), &i["tags"].to_string()])).filter_map(Self::meta).take(limit).collect()
    }
    fn inspect(&self, id: &str) -> Option<SkillMeta> {
        let slug = id.strip_prefix("browse-sh/").unwrap_or(id);
        self.catalog().iter().find(|i| s(i, "slug") == slug).and_then(Self::meta)
    }
    fn fetch(&self, id: &str) -> Option<SkillBundle> {
        let slug = id.strip_prefix("browse-sh/").unwrap_or(id).to_string();
        let item = self.catalog().into_iter().find(|i| s(i, "slug") == slug)?;
        let d = self.http.get_json(&format!("{}/{slug}", self.http.settings.hub.browse_sh));
        let md_url = d.and_then(|d| d.get("skillMdUrl").and_then(Value::as_str).map(String::from)).filter(|u| u.starts_with("http")).or_else(|| Some(s(&item, "sourceUrl")).filter(|u| u.starts_with("https://raw.githubusercontent.com/")))?;
        let content = self.http.get_text(&md_url)?;
        let m = Self::meta(&item)?;
        Some(SkillBundle { name: m.name, files: BTreeMap::from([("SKILL.md".to_string(), content.into_bytes())]), source: "browse-sh".into(), identifier: id.into(), trust_level: "community".into(), metadata: Map::from_iter([("skill_md_url".to_string(), json!(md_url))]) })
    }
    fn claims(&self, id: &str) -> bool {
        id.starts_with("browse-sh/")
    }
}

pub struct WellKnown<'a> {
    pub http: &'a Http,
}

const WK: &str = "/.well-known/skills";

impl WellKnown<'_> {
    fn index_url(q: &str) -> Option<String> {
        let q = q.trim();
        if !q.starts_with("http://") && !q.starts_with("https://") {
            return None;
        }
        Some(if q.ends_with("/index.json") {
            q.to_string()
        } else if let Some((a, _)) = q.split_once(&format!("{WK}/")) {
            format!("{a}{WK}/index.json")
        } else {
            format!("{}{WK}/index.json", q.trim_end_matches('/'))
        })
    }
    /// (index url, base url, skill name, skill url).
    fn parse_id(id: &str) -> Option<(String, String, String, String)> {
        let raw = id.strip_prefix("well-known:").unwrap_or(id);
        if !raw.starts_with("http://") && !raw.starts_with("https://") {
            return None;
        }
        let (clean, frag) = raw.split_once('#').map(|(a, b)| (a, Some(b))).unwrap_or((raw, None));
        let (base, name, skill_url) = if let Some(b) = clean.strip_suffix("/index.json") {
            let n = frag.filter(|f| !f.is_empty())?;
            (b.to_string(), n.to_string(), format!("{b}/{n}"))
        } else {
            let su = clean.strip_suffix("/SKILL.md").unwrap_or(clean).trim_end_matches('/').to_string();
            if !su.contains(&format!("{WK}/")) {
                return None;
            }
            let (b, n) = su.rsplit_once('/')?;
            (b.to_string(), n.to_string(), su.clone())
        };
        Some((format!("{base}/index.json"), base, name, skill_url))
    }
    fn index(&self, url: &str) -> Vec<Value> {
        let key = format!("well_known_{}", super::super::core::ledger::sha256_hex(url.as_bytes()));
        self.http.memo(&key, || self.http.get_json(url).filter(|d| d["skills"].is_array())).and_then(|d| d["skills"].as_array().cloned()).unwrap_or_default()
    }
    /// Meta row for one index entry (Hermes `_meta`): the entry's own name is the skill path and
    /// its advertised `files` list travels in `extra`.
    fn meta(&self, iu: &str, base: &str, e: &Value) -> SkillMeta {
        let name = s(e, "name");
        let files = e["files"].as_array().filter(|v| !v.is_empty()).cloned().unwrap_or_else(|| vec![json!("SKILL.md")]);
        SkillMeta { name: name.clone(), description: s(e, "description"), source: "well-known".into(), identifier: format!("well-known:{base}/{name}"), trust_level: "community".into(), path: Some(name), extra: Map::from_iter([("index_url".to_string(), json!(iu)), ("base_url".to_string(), json!(base)), ("files".to_string(), Value::Array(files))]), ..Default::default() }
    }
}

impl Source for WellKnown<'_> {
    fn id(&self) -> &'static str {
        "well-known"
    }
    fn search(&self, q: &str, limit: usize) -> Vec<SkillMeta> {
        let Some(iu) = Self::index_url(q) else { return vec![] };
        let base = iu.trim_end_matches("/index.json").to_string();
        self.index(&iu).iter().take(limit).filter(|e| !s(e, "name").is_empty()).map(|e| self.meta(&iu, &base, e)).collect()
    }
    fn inspect(&self, id: &str) -> Option<SkillMeta> {
        let (iu, base, name, su) = Self::parse_id(id)?;
        let e = self.index(&iu).into_iter().find(|e| s(e, "name") == name)?;
        let md = self.http.get_text(&format!("{su}/SKILL.md"))?;
        let fm = crate::yaml::frontmatter(&md).0;
        let mut m = self.meta(&iu, &base, &e);
        m.name = fm.get("name").and_then(Value::as_str).map(String::from).unwrap_or(name);
        if let Some(d) = fm.get("description").and_then(Value::as_str) {
            m.description = d.to_string();
        }
        m.extra.insert("endpoint".into(), json!(su));
        Some(m)
    }
    fn fetch(&self, id: &str) -> Option<SkillBundle> {
        let (iu, base, name, su) = Self::parse_id(id)?;
        let name = validate_skill_name(&name).ok()?;
        let e = self.index(&iu).into_iter().find(|e| s(e, "name") == name)?;
        let list: Vec<String> = e["files"].as_array().map(|a| a.iter().filter_map(|f| f.as_str().map(String::from)).collect()).filter(|v: &Vec<String>| !v.is_empty()).unwrap_or_else(|| vec!["SKILL.md".into()]);
        let mut files = BTreeMap::new();
        for f in list {
            let f = validate_rel(&f).ok()?;
            files.insert(f.clone(), self.http.get(&format!("{su}/{f}")).filter(|r| r.ok())?.body);
        }
        files.contains_key("SKILL.md").then(|| SkillBundle { name: name.clone(), files, source: "well-known".into(), identifier: format!("well-known:{base}/{name}"), trust_level: "community".into(), metadata: Map::from_iter([("index_url".to_string(), json!(iu)), ("base_url".to_string(), json!(base)), ("endpoint".to_string(), json!(su)), ("files".to_string(), e["files"].clone())]) })
    }
    fn claims(&self, id: &str) -> bool {
        id.starts_with("well-known:") || id.contains("/.well-known/skills/")
    }
}

pub struct Url<'a> {
    pub http: &'a Http,
}

impl Url<'_> {
    /// Skill-name candidates must look like identifiers (lowercase letters/digits + `-_`); `skill`,
    /// `readme`, `index` and `unnamed-skill` are useless auto-names, not skill names.
    fn name_from(fm: &Value, url: &str) -> Option<String> {
        let re = regex::Regex::new(r"^[a-z][a-z0-9_-]*$").unwrap();
        if let Some(n) = fm.get("name").and_then(Value::as_str).map(str::trim).filter(|n| re.is_match(n)) {
            return Some(n.to_string());
        }
        let path = url.split(['?', '#']).next().unwrap_or(url);
        let parts: Vec<&str> = path.trim_end_matches('/').rsplit('/').collect();
        let cand = if parts.first().is_some_and(|p| p.eq_ignore_ascii_case("SKILL.md")) { parts.get(1).copied() } else { parts.first().map(|p| p.trim_end_matches(".md")) };
        cand.map(|c| c.to_lowercase()).filter(|c| re.is_match(c) && !matches!(c.as_str(), "skill" | "readme" | "index" | "unnamed-skill"))
    }
}

impl Source for Url<'_> {
    fn id(&self) -> &'static str {
        "url"
    }
    fn search(&self, _q: &str, _limit: usize) -> Vec<SkillMeta> {
        vec![]
    }
    fn inspect(&self, id: &str) -> Option<SkillMeta> {
        if !self.claims(id) {
            return None;
        }
        let t = self.http.get_text(id)?;
        let fm = crate::yaml::frontmatter(&t).0;
        let name = Self::name_from(&fm, id).unwrap_or_default();
        Some(SkillMeta { name: name.clone(), description: s(&fm, "description"), source: "url".into(), identifier: id.into(), trust_level: "community".into(), path: Some(name.clone()), tags: tags_of(&fm), extra: Map::from_iter([("url".to_string(), json!(id)), ("awaiting_name".to_string(), json!(name.is_empty()))]), ..Default::default() })
    }
    fn fetch(&self, id: &str) -> Option<SkillBundle> {
        if !self.claims(id) {
            return None;
        }
        let t = self.http.get_text(id)?;
        let refs = referenced_support_paths(&t)?;
        let fm = crate::yaml::frontmatter(&t).0;
        let base = id.rsplit_once('/').map(|x| x.0).unwrap_or(id).to_string();
        let mut files = BTreeMap::from([("SKILL.md".to_string(), t.into_bytes())]);
        for r in refs {
            if let Some(b) = self.http.get(&format!("{base}/{r}")).filter(|x| x.ok()) {
                files.insert(r, b.body);
            }
        }
        let name = Self::name_from(&fm, id).unwrap_or_default();
        Some(SkillBundle { name: name.clone(), files, source: "url".into(), identifier: id.into(), trust_level: "community".into(), metadata: Map::from_iter([("source_url".to_string(), json!(id)), ("awaiting_name".to_string(), json!(name.is_empty()))]) })
    }
    fn claims(&self, id: &str) -> bool {
        let i = id.trim();
        (i.starts_with("http://") || i.starts_with("https://")) && !i.contains("/.well-known/skills/") && i.split(['?', '#']).next().unwrap_or("").to_lowercase().ends_with(".md")
    }
}

#[cfg(test)]
mod tests {
    use crate::core::settings::{Settings, Store};
    use crate::hub::http::testserver::{ok, serve, serve_on};
    use super::*;

    fn settings(base: &str) -> Settings {
        let t: toml::Table = toml::from_str(&format!(
            "[hub]\nallow_private = true\ngithub_api = \"{base}/gh\"\ngithub_raw = \"{base}/raw\"\nclawhub = \"{base}/claw/api/v1\"\nskills_sh = \"{base}/ssh\"\nlobehub = \"{base}/lobe\"\nbrowse_sh = \"{base}/browse/api/skills\"\n"
        ))
        .unwrap();
        Settings::from_table(&t)
    }

    fn store(tag: &str) -> (std::path::PathBuf, Store) {
        let d = seagent_core::tmp::scratch_path(format!("seagent-hubsources-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        (d.clone(), Store::at(&d))
    }

    fn b64(s: &str) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    #[test]
    fn github_provider_label_pinned_bundle_and_incomplete_revision() {
        let md = "---\nname: pdf-tools\ndescription: Work with PDF\ntags: [docs]\n---\nSee references/guide.md\n";
        let (base, _log) = serve(vec![
            ok("/gh/repos/openai/skills", json!({"default_branch": "main"}).to_string()),
            ok("/gh/repos/openai/skills/git/trees/main", json!({"sha": "rev1", "tree": [
                {"path": "skills/pdf-tools/SKILL.md", "type": "blob", "mode": "100644"},
                {"path": "skills/pdf-tools/references/guide.md", "type": "blob", "mode": "100644"},
            ]}).to_string()),
            ok("/gh/repos/openai/skills/contents/skills", json!([{"name": "pdf-tools", "type": "dir"}]).to_string()),
            ok("/gh/repos/openai/skills/contents/skills/pdf-tools/SKILL.md", json!({"content": b64(md)}).to_string()),
            ok("/raw/openai/skills/rev1/skills/pdf-tools/SKILL.md", md.to_string()),
            ok("/raw/openai/skills/rev1/skills/pdf-tools/references/guide.md", "guide"),
            // A repo whose second blob is gone everywhere: the tree revision must not be recorded.
            ok("/gh/repos/acme/broken", json!({"default_branch": "main"}).to_string()),
            ok("/gh/repos/acme/broken/git/trees/main", json!({"sha": "rev2", "tree": [
                {"path": "skills/b/SKILL.md", "type": "blob", "mode": "100644"},
                {"path": "skills/b/notes.md", "type": "blob", "mode": "100644"},
            ]}).to_string()),
            ok("/raw/acme/broken/rev2/skills/b/SKILL.md", "---\nname: b\n---\nbody\n".to_string()),
            ok("/gh/repos/acme/broken/contents/skills/b/SKILL.md", json!({"content": b64("---\nname: b\n---\nbody\n")}).to_string()),
        ]);
        let (d, st) = store("gh");
        let s = settings(&base);
        let h = Http::new(&s, &st);
        let gh = GitHub { http: &h, taps: vec![("openai/skills".into(), "skills/".into())] };
        assert_eq!(github_provider_for("OpenAI/Skills"), Some("OpenAI"));
        assert_eq!(github_provider_for("acme/skills"), None);
        let r = gh.search("pdf", 10);
        assert_eq!(r.len(), 1, "{r:?}");
        assert_eq!(r[0].identifier, "openai/skills/skills/pdf-tools");
        assert_eq!(r[0].extra["provider"], "OpenAI", "per-tap provider label survives the listing cache");
        let m = gh.inspect("openai/skills/skills/pdf-tools").unwrap();
        assert_eq!((m.extra["provider"].as_str(), m.trust_level.as_str()), (Some("OpenAI"), "trusted"), "openai/skills is a trusted repo");
        assert!(gh.inspect("acme/broken/skills/b").unwrap().extra.get("provider").is_none(), "unlabelled repo stays bare");
        let b = gh.fetch("openai/skills/skills/pdf-tools").unwrap();
        assert_eq!((b.metadata["source_revision"].as_str(), b.files.len()), (Some("rev1"), 2), "{:?}", b.metadata);
        assert_eq!(b.metadata["source_url"], "https://github.com/openai/skills/tree/rev1/skills/pdf-tools");
        let bad = gh.fetch("acme/broken/skills/b").unwrap();
        assert_eq!(bad.metadata["source_revision"], "", "a bundle with a failed blob fetch records no revision");
        assert_eq!(bad.metadata["source_url"], "https://github.com/acme/broken/skills/b");
        assert!(!bad.files.contains_key("notes.md"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn skills_sh_installs_label_and_tree_discovery() {
        let md = "---\nname: lint-kit\ndescription: Lint things\n---\nSee references/x.md\n";
        let (base, _log) = serve(vec![
            ok("/ssh/api/search", json!({"skills": [{"id": "acme/mono/lint-kit", "name": "lint-kit", "installs": 12345}]}).to_string()),
            ok("/gh/repos/acme/mono", json!({"default_branch": "main"}).to_string()),
            ok(
                "/gh/repos/acme/mono/git/trees/main",
                json!({"sha": "rev3", "tree": [
                    {"path": "tools/quality/lint-kit/SKILL.md", "type": "blob", "mode": "100644"},
                    {"path": "tools/quality/lint-kit/references/x.md", "type": "blob", "mode": "100644"},
                ]})
                .to_string(),
            ),
            ok("/gh/repos/acme/mono/contents/tools/quality/lint-kit/SKILL.md", json!({"content": b64(md)}).to_string()),
            ok("/raw/acme/mono/rev3/tools/quality/lint-kit/SKILL.md", md.to_string()),
            ok("/raw/acme/mono/rev3/tools/quality/lint-kit/references/x.md", "x"),
            ok("/gh/repos/acme/solo", json!({"default_branch": "main"}).to_string()),
            ok("/gh/repos/acme/solo/git/trees/main", json!({"sha": "rev4", "tree": [{"path": "SKILL.md", "type": "blob", "mode": "100644"}]}).to_string()),
        ]);
        let (d, st) = store("ssh");
        let s = settings(&base);
        let h = Http::new(&s, &st);
        let gh = GitHub { http: &h, taps: vec![] };
        let ss = SkillsSh { http: &h, github: GitHub { http: &h, taps: vec![] } };
        let r = ss.search("lint", 10);
        assert_eq!(r.len(), 1, "{r:?}");
        assert_eq!(r[0].description, "Indexed by skills.sh from acme/mono · 12,345 installs");
        assert_eq!(r[0].extra["installs"], 12345);
        assert_eq!(r[0].extra["detail_url"], json!(format!("{base}/ssh/acme/mono/lint-kit")));
        assert_eq!(r[0].extra["repo_url"], "https://github.com/acme/mono");
        // The skill lives outside the standard skills/ dirs: discovery resolves it from the tree.
        assert_eq!(gh.find_in_tree("acme/mono", "lint-kit").as_deref(), Some("acme/mono/tools/quality/lint-kit"));
        assert_eq!(gh.find_in_tree("acme/mono", "nope"), None);
        assert_eq!(gh.root_skill("acme/solo").as_deref(), Some("acme/solo/"));
        assert_eq!(gh.root_skill("acme/mono"), None, "a multi-skill repo never resolves at the root");
        let i = ss.inspect("skills-sh/acme/mono/lint-kit").unwrap();
        assert_eq!((i.name.as_str(), i.identifier.as_str()), ("lint-kit", "skills-sh/acme/mono/lint-kit"));
        let b = ss.fetch("skills-sh/acme/mono/lint-kit").unwrap();
        assert_eq!((b.name.as_str(), b.files.len()), ("lint-kit", 2), "{:?}", b.files.keys());
        assert!(b.files.contains_key("references/x.md"));
        assert_eq!(b.metadata["detail_url"], json!(format!("{base}/ssh/acme/mono/lint-kit")));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn clawhub_slug_candidates_owner_guard_and_dedupe() {
        let detail = |slug: &str, owner: &str| {
            json!({"slug": slug, "displayName": "PDF Tools", "summary": "Make PDFs",
                   "owner": {"handle": owner}, "latestVersion": {"version": "1.2.0"},
                   "tags": {"latest": "1.2.0", "docs": "1.1.0"}})
            .to_string()
        };
        let (base, _log) = serve(vec![
            ok("/claw/api/v1/skills/pdf-tools-agent", detail("pdf-tools-agent", "acme")),
            ok("/claw/api/v1/skills/pdf-tools", detail("pdf-tools", "acme")),
            // Listing: same slug twice plus an irrelevant row the score cut must drop.
            ok(
                "/claw/api/v1/skills",
                json!({"items": [
                    {"slug": "pdf-tools", "summary": "Make PDFs", "owner": {"handle": "acme"}},
                    {"slug": "pdf-tools", "summary": "Make PDFs", "owner": {"handle": "acme"}},
                    {"slug": "unrelated", "summary": "Compress images"},
                ]})
                .to_string(),
            ),
            ok("/claw/api/v1/skills/pdf-tools/versions", json!({"items": [{"version": "1.2.0"}]}).to_string()),
            ok("/claw/api/v1/skills/pdf-tools/versions/1.2.0", json!({"owner": {"handle": "acme"}, "files": {"SKILL.md": "---\nname: pdf-tools\n---\nok\n"}}).to_string()),
            ok("/claw/api/v1/download", "not a zip".to_string()),
        ]);
        let (d, st) = store("claw");
        let s = settings(&base);
        let h = Http::new(&s, &st);
        let ch = ClawHub { http: &h };
        // Two-term queries try the exact-slug variants before the listing API.
        assert_eq!(ClawHub::slug_candidates("pdf tools")[..2], ["pdf-tools-agent", "pdf-tools-skill"]);
        let r = ch.search("pdf tools", 10);
        assert_eq!(r.len(), 1, "{r:?}");
        assert_eq!(r[0].identifier, "@acme/pdf-tools-agent");
        assert_eq!(r[0].tags, ["docs"], "the `latest` tag is not a skill tag");
        // A single-term query falls through to the listing API (no slug candidate exists).
        assert_eq!(ch.search("pdf", 10)[0].identifier, "pdf-tools");
        // Listing rows are deduped and the unrelated one is scored out.
        let listing = ch.finalize("pdf-tools", vec![SkillMeta { identifier: "pdf-tools".into(), name: "pdf-tools".into(), description: "Make PDFs".into(), ..Default::default() }, SkillMeta { identifier: "pdf-tools".into(), name: "pdf-tools".into(), ..Default::default() }, SkillMeta { identifier: "unrelated".into(), name: "unrelated".into(), ..Default::default() }], 10);
        assert_eq!(listing.iter().map(|m| m.identifier.as_str()).collect::<Vec<_>>(), ["@acme/pdf-tools", "pdf-tools"], "exact slug promoted, duplicates dropped");
        // An `@other/…` request never accepts content owned by someone else.
        assert!(ch.inspect("@other/pdf-tools").is_none());
        assert!(!ClawHub::owner_matches(Some(&"acme".to_string()), &json!({"owner": {"handle": "evil"}})));
        let b = ch.fetch("@acme/pdf-tools").unwrap();
        assert_eq!((b.identifier.as_str(), b.metadata["version"].as_str()), ("@acme/pdf-tools", Some("1.2.0")));
        assert!(b.files.contains_key("SKILL.md"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn official_index_ranking() {
        let e = |name: &str, desc: &str, extra: Value| json!({"name": name, "description": desc, "path": format!("cat/{}", name.replace(' ', "-")), "tags": ["Multi-Agent"], "extra": extra});
        let entries = [
            e("agent merge arbiter", "Neutral arbiter for merge conflicts", json!({})),
            e("pdf-tools pro", "Work with PDF files", json!({"provider": "nvidia"})),
            e("docs", "Write pdf documents", json!({"provider": "OpenAI"})),
            e("unrelated", "nothing here", json!({})),
        ];
        assert_eq!(index_rank("pdf-tools pro", &entries[1]), Some(0), "exact name");
        assert_eq!(index_rank("pdf-tools", &entries[1]), Some(1), "name prefix");
        assert_eq!(index_rank("nvidia", &entries[1]), Some(2), "provider label");
        assert_eq!(index_rank("openai", &entries[2]), Some(2), "provider label is case-insensitive");
        assert_eq!(index_rank("nvidia", &entries[2]), None, "no provider, no match");
        assert_eq!(index_rank("arbiter", &entries[0]), Some(3), "whole word");
        assert_eq!(index_rank("tool", &entries[1]), Some(4), "name substring");
        assert_eq!(index_rank("documents", &entries[2]), Some(5), "description only");
        assert_eq!(index_rank("multi-agent", &entries[0]), Some(5), "tags");
        assert_eq!(entry_provider(&entries[2]), "openai");
        // Ranking orders an exact/prefix hit above a description-only one, index order breaking ties.
        let mut hits: Vec<(usize, usize)> = entries.iter().enumerate().filter_map(|(i, x)| index_rank("pdf", x).map(|r| (r, i))).collect();
        hits.sort();
        assert_eq!(hits.iter().map(|(_, i)| *i).collect::<Vec<_>>(), [1, 2], "{hits:?}");
    }

    #[test]
    fn well_known_browse_sh_lobehub_and_url_metadata() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let (base, _log) = serve_on(l, vec![
            ok("/wk/.well-known/skills/index.json", json!({"skills": [{"name": "pdf-tools", "description": "Indexed description", "files": ["SKILL.md", "references/a.md"]}]}).to_string()),
            ok("/wk/.well-known/skills/pdf-tools/SKILL.md", "---\nname: pdf-tools\ndescription: Files first\n---\nSee references/a.md\n".to_string()),
            ok("/wk/.well-known/skills/pdf-tools/references/a.md", "a"),
            ok("/browse/api/skills", json!({"skills": [{"slug": "airbnb/search-listings", "name": "Search listings", "description": "Find stays", "hostname": "www.airbnb.com", "category": "bookings", "tags": ["travel"], "sourceUrl": "https://github.com/x/y", "recommendedMethod": "GET", "proxies": true, "installCount": 42}]}).to_string()),
            ok("/browse/api/skills/airbnb/search-listings", json!({"skillMdUrl": format!("{base}/cdn/skill.md")}).to_string()),
            ok("/cdn/skill.md", "---\nname: search-listings\ndescription: Find stays\n---\nbody\n".to_string()),
            ok("/lobe/index.json", json!({"agents": [{"identifier": "my-agent", "meta": {"title": "My Agent", "description": "Helps", "tags": ["writing"]}, "config": {"systemRole": "write"}}]}).to_string()),
            ok("/lobe/my-agent.json", json!({"identifier": "my-agent", "meta": {"title": "My Agent", "description": "Helps", "tags": ["writing"]}, "config": {"systemRole": "write"}}).to_string()),
            ok("/u/pdf-tools/SKILL.md", "---\nname: pdf-tools\ndescription: From a URL\n---\nSee [guide](references/guide.md)\n".to_string()),
            ok("/u/pdf-tools/references/guide.md", "guide"),
            ok("/u/x/index.md", "---\nname: Index\n---\nbody\n".to_string()),
        ]);
        let (d, st) = store("misc");
        let s = settings(&base);
        let h = Http::new(&s, &st);
        let wk = WellKnown { http: &h };
        let site = format!("{base}/wk");
        let r = wk.search(&site, 10);
        assert_eq!(r.len(), 1, "{r:?}");
        assert_eq!(r[0].path.as_deref(), Some("pdf-tools"));
        assert_eq!(r[0].extra["base_url"], json!(format!("{base}/wk/.well-known/skills")));
        assert_eq!(r[0].extra["files"], json!(["SKILL.md", "references/a.md"]));
        let m = wk.inspect(&r[0].identifier).unwrap();
        assert_eq!((m.name.as_str(), m.description.as_str()), ("pdf-tools", "Files first"), "frontmatter wins");
        assert_eq!(m.extra["endpoint"], json!(format!("{base}/wk/.well-known/skills/pdf-tools")));
        let b = wk.fetch(&r[0].identifier).unwrap();
        assert_eq!(b.files.len(), 2, "{:?}", b.files.keys());
        assert_eq!(b.metadata["endpoint"], json!(format!("{base}/wk/.well-known/skills/pdf-tools")));

        let bs = BrowseSh { http: &h };
        let r = bs.search("travel", 10);
        assert_eq!(r.len(), 1, "tags are searchable: {r:?}");
        assert_eq!((r[0].name.as_str(), r[0].tags.clone()), ("Search listings", vec!["travel".to_string()]));
        assert_eq!((r[0].extra["category"].as_str(), r[0].extra["source_url"].as_str(), r[0].extra["recommended_method"].as_str()), (Some("bookings"), Some("https://github.com/x/y"), Some("GET")));
        assert_eq!((r[0].extra["proxies"].as_bool(), r[0].extra["install_count"].as_i64()), (Some(true), Some(42)));
        assert_eq!(bs.fetch("browse-sh/airbnb/search-listings").unwrap().metadata["skill_md_url"], json!(format!("{base}/cdn/skill.md")));

        let lh = LobeHub { http: &h };
        let r = lh.search("my", 10);
        assert_eq!((r[0].name.as_str(), r[0].tags.clone()), ("my-agent", vec!["writing".to_string()]));
        assert!(lh.fetch("lobehub/my-agent").unwrap().files["SKILL.md"].starts_with(b"---\nname: my-agent"));

        let u = Url { http: &h };
        let id = format!("{base}/u/pdf-tools/SKILL.md");
        let m = u.inspect(&id).unwrap();
        assert_eq!((m.name.as_str(), m.path.as_deref()), ("pdf-tools", Some("pdf-tools")));
        assert_eq!((m.extra["url"].as_str(), m.extra["awaiting_name"].as_bool()), (Some(id.as_str()), Some(false)));
        assert_eq!(u.fetch(&id).unwrap().files.len(), 2);
        // `index` is never used as an auto-name: the install asks for one instead of guessing.
        let m = u.inspect(&format!("{base}/u/x/index.md")).unwrap();
        assert_eq!((m.name.as_str(), m.extra["awaiting_name"].as_bool()), ("", Some(true)));
        assert_eq!(Url::name_from(&json!({"name": "SKILL"}), "https://example.com/unnamed-skill.md"), None, "useless URL slug");
        assert_eq!(Url::name_from(&json!({}), "https://example.com/index.md"), None, "`index.md` is not a skill name");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn clawhub_version_pin_and_inner_tap_descent() {
        let detail = json!({"slug": "weather", "displayName": "Weather", "summary": "Weather now",
                            "owner": {"handle": "steipete"}, "latestVersion": {"version": "2.0.0"}})
        .to_string();
        let vfiles = |v: &str| json!({"version": v, "owner": {"handle": "steipete"}, "files": {"SKILL.md": format!("---\nname: weather\n---\n{v}\n")}}).to_string();
        let (base, log) = serve(vec![
            ok("/claw/api/v1/skills/weather", detail),
            ok("/claw/api/v1/skills/weather/versions/1.5.0", vfiles("1.5.0")),
            ok("/claw/api/v1/skills/weather/versions/2.0.0", vfiles("2.0.0")),
            // A registry that answers the pinned version with something else.
            ok("/claw/api/v1/skills/weather/versions/9.9.9", vfiles("2.0.0")),
            ok("/claw/api/v1/download", "not a zip"),
            // A tap whose path only holds dot-dirs (`openai/skills` → `skills/.curated/`).
            ok("/gh/repos/openai/skills/contents/skills", json!([{"name": ".curated", "type": "dir"}, {"name": ".system", "type": "dir"}, {"name": ".git", "type": "dir"}]).to_string()),
            ok("/gh/repos/openai/skills/contents/skills/.curated", json!([{"name": "pdf-tools", "type": "dir"}]).to_string()),
            ok("/gh/repos/openai/skills/contents/skills/.curated/pdf-tools/SKILL.md", json!({"content": b64("---\nname: pdf-tools\ndescription: Make PDFs\n---\nbody\n")}).to_string()),
            ok("/gh/repos/openai/skills/contents/skills/.system", json!([]).to_string()),
        ]);
        let (d, st) = store("pin");
        let s = settings(&base);
        let h = Http::new(&s, &st);
        let ch = ClawHub { http: &h };
        // OpenClaw `clawhub-spec.ts`: the last `@` splits the pin, a leading one is the owner marker.
        assert_eq!(ClawHub::parse_pinned("@steipete/weather@1.5.0").unwrap(), ("weather".to_string(), Some("steipete".to_string()), Some("1.5.0".to_string())));
        assert_eq!(ClawHub::parse_pinned("@steipete/weather").unwrap().2, None);
        assert_eq!(ClawHub::parse_pinned("weather").unwrap().2, None);
        assert!(ClawHub::parse_pinned("@steipete/weather@").is_none(), "an empty pin rejects the id");
        assert!(ClawHub::parse_pinned("@steipete/weather@1/2").is_none(), "a pin never contains a slash");
        assert!(ch.claims("@steipete/weather@1.5.0") && ch.claims("clawhub/weather@1.5.0") && !ch.claims("acme/skills/pdf-tools"));
        let b = ch.fetch("@steipete/weather@1.5.0").unwrap();
        assert_eq!((b.metadata["version"].as_str(), b.metadata["requested_version"].as_str()), (Some("1.5.0"), Some("1.5.0")));
        assert_eq!(b.identifier, "@steipete/weather", "the pin is provenance metadata, not identity");
        assert!(b.files["SKILL.md"].ends_with(b"1.5.0\n"), "{:?}", String::from_utf8_lossy(&b.files["SKILL.md"]));
        assert!(log.lock().unwrap().iter().any(|l| l == "/claw/api/v1/download?slug=weather&version=1.5.0&owner=steipete"), "the pinned version reaches the download URL");
        // Unpinned installs resolve the latest version.
        assert_eq!(ch.fetch("@steipete/weather").unwrap().metadata["version"], "2.0.0");
        assert!(ch.fetch("@steipete/weather@9.9.9").is_none(), "a resolved-version mismatch is refused");

        // The default `openai/skills` tap (path `skills/`) is all dot-dirs: descend one level.
        let gh = GitHub { http: &h, taps: vec![("openai/skills".to_string(), "skills/".to_string())] };
        let r = gh.search("pdf", 10);
        assert_eq!(r.iter().map(|m| m.identifier.as_str()).collect::<Vec<_>>(), ["openai/skills/skills/.curated/pdf-tools"], "the tap lists its inner skills");
        assert_eq!(r[0].extra["provider"], "OpenAI");
        let _ = std::fs::remove_dir_all(&d);
    }
}
