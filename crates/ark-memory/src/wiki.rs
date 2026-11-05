//! Compiled wiki / Obsidian-friendly knowledge vault (OpenClaw extensions/memory-wiki, MIT).
//! Pages live in kind directories (sources, entities, concepts, syntheses, reports) with
//! frontmatter (id, pageType, title, sourceIds, claims[evidence], contradictions, questions,
//! confidence, status, updatedAt). `compile` regenerates index.md, `## Related` backlink
//! blocks and dashboards; `lint` reports structure/provenance/link/quality issues; the
//! tools are wiki_status / wiki_search / wiki_get / wiki_apply / wiki_lint, the CLI `ark wiki`.

use crate::util::{self, clip};
use crate::Host;
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const KINDS: &[(&str, &str, &str)] = &[("source", "sources", "Sources"), ("entity", "entities", "Entities"), ("concept", "concepts", "Concepts"), ("synthesis", "syntheses", "Syntheses"), ("report", "reports", "Reports")];
const DIRS: &[&str] = &["entities", "concepts", "syntheses", "sources", "reports", "_attachments", "_views", ".ark-wiki"];
pub const AGING_DAYS: f64 = 30.0;
pub const STALE_DAYS: f64 = 90.0;
const HUMAN_START: &str = "<!-- ark:human:start -->";

pub fn root(h: &Host) -> PathBuf {
    if h.settings.wiki.vault_path.is_empty() {
        h.memory_dir().join("wiki")
    } else {
        ark_core::tool::expand_home(&h.settings.wiki.vault_path)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Page {
    pub rel: String,
    pub kind: String,
    pub fm: Map<String, Value>,
    pub body: String,
    pub title: String,
    pub id: String,
}

impl Page {
    fn list(&self, k: &str) -> Vec<Value> {
        self.fm.get(k).and_then(Value::as_array).cloned().unwrap_or_default()
    }
    fn strs(&self, k: &str) -> Vec<String> {
        self.list(k).iter().filter_map(|v| v.as_str().map(str::to_string)).collect()
    }
    pub fn links(&self) -> Vec<String> {
        Regex::new(r"\[\[([^\]|#]+)(?:#[^\]|]*)?(?:\|[^\]]*)?\]\]").unwrap().captures_iter(&self.body).map(|c| c[1].trim().to_string()).collect()
    }
}

pub fn slug(s: &str) -> String {
    let mut out = String::new();
    for c in s.trim().to_lowercase().chars() {
        if c.is_alphanumeric() {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let o = out.trim_matches('-').to_string();
    if o.is_empty() {
        "page".into()
    } else {
        clip(&o, 80)
    }
}

/// Frontmatter: `key: value` lines; values that parse as JSON (lists, objects, numbers,
/// booleans, quoted strings) are JSON — valid YAML flow style, readable by Obsidian.
pub fn parse(text: &str) -> (Map<String, Value>, String) {
    let mut fm = Map::new();
    if let Some(rest) = text.strip_prefix("---\n") {
        if let Some(end) = rest.find("\n---") {
            for l in rest[..end].lines() {
                if let Some((k, v)) = l.split_once(':') {
                    let v = v.trim();
                    let val = serde_json::from_str::<Value>(v).unwrap_or_else(|_| Value::String(v.to_string()));
                    fm.insert(k.trim().to_string(), val);
                }
            }
            let body = rest[end + 4..].trim_start_matches('\n').to_string();
            return (fm, body);
        }
    }
    (fm, text.to_string())
}

pub fn render(fm: &Map<String, Value>, body: &str) -> String {
    let order = ["id", "pageType", "title", "status", "confidence", "sourceIds", "sourcePath", "sourceType", "claims", "contradictions", "questions", "updatedAt"];
    let mut keys: Vec<&String> = fm.keys().collect();
    keys.sort_by_key(|k| (order.iter().position(|o| o == k).unwrap_or(99), k.to_string()));
    let lines: Vec<String> = keys.iter().map(|k| format!("{k}: {}", fm[*k])).collect();
    format!("---\n{}\n---\n\n{}\n", lines.join("\n"), body.trim_end())
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut v: Vec<_> = rd.flatten().collect();
    v.sort_by_key(|e| e.file_name());
    for e in v {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else if p.extension().is_some_and(|x| x == "md") {
            out.push(p);
        }
    }
}

pub fn pages(h: &Host) -> Vec<Page> {
    let r = root(h);
    let mut out = Vec::new();
    for (kind, dir, _) in KINDS {
        let mut files = Vec::new();
        walk(&r.join(dir), &mut files);
        for f in files {
            let Ok(t) = fs::read_to_string(&f) else { continue };
            let (fm, body) = parse(&t);
            let rel = f.strip_prefix(&r).unwrap_or(&f).display().to_string();
            let title = fm.get("title").and_then(Value::as_str).map(str::to_string).or_else(|| body.lines().find(|l| l.starts_with("# ")).map(|l| l[2..].trim().to_string())).unwrap_or_default();
            let id = fm.get("id").and_then(Value::as_str).unwrap_or("").to_string();
            out.push(Page { rel, kind: kind.to_string(), fm, body, title, id });
        }
    }
    out
}

fn write_if_missing(p: &Path, content: &str, created: &mut Vec<String>) -> Result<(), String> {
    if !p.exists() {
        util::write_atomic(p, content.as_bytes())?;
        created.push(p.display().to_string());
    }
    Ok(())
}

pub fn init(h: &Host) -> Result<Vec<String>, String> {
    let r = root(h);
    let mut created = Vec::new();
    for d in DIRS {
        if !r.join(d).is_dir() {
            fs::create_dir_all(r.join(d)).map_err(|e| e.to_string())?;
            created.push(r.join(d).display().to_string());
        }
    }
    write_if_missing(&r.join("AGENTS.md"), "# Memory Wiki Agent Guide\n\n- Treat generated blocks as plugin-owned.\n- Preserve human notes outside managed markers.\n- Prefer source-backed claims over wiki-to-wiki citation loops.\n- Prefer structured `claims` with evidence over burying key beliefs only in prose.\n- Use the wiki tools for machine reads; Markdown pages are the human view.\n", &mut created)?;
    write_if_missing(&r.join("WIKI.md"), &format!("# Memory Wiki\n\nThis vault is maintained by ark's memory wiki.\n\n- Render mode: `{}`\n- Search corpus default: `{}`\n\n## Architecture\n- Raw sources remain the evidence layer.\n- Wiki pages are the human-readable synthesis layer.\n\n## Notes\n{HUMAN_START}\n<!-- ark:human:end -->\n", h.settings.wiki.render_mode, h.settings.wiki.search_corpus), &mut created)?;
    write_if_missing(&r.join("index.md"), "# Wiki Index\n\n## Generated\n<!-- ark:wiki:index:start -->\n- No compiled pages yet.\n<!-- ark:wiki:index:end -->\n", &mut created)?;
    write_if_missing(&r.join(".ark-wiki/log.jsonl"), "", &mut created)?;
    Ok(created)
}

fn log(h: &Host, op: &str, detail: Value) {
    let _ = util::append_line(&root(h).join(".ark-wiki/log.jsonl"), &json!({"ts": util::iso(util::now_ms()), "op": op, "detail": detail}).to_string());
}

fn managed(original: &str, tag: &str, heading: &str, body: &str) -> String {
    let (s, e) = (format!("<!-- ark:wiki:{tag}:start -->"), format!("<!-- ark:wiki:{tag}:end -->"));
    if let (Some(a), Some(b)) = (original.find(&s), original.find(&e)) {
        if b > a {
            return format!("{}{s}\n{}\n{}", &original[..a], body.trim_end(), &original[b..]);
        }
    }
    format!("{}\n\n{heading}\n{s}\n{}\n{e}\n", original.trim_end(), body.trim_end())
}

fn link(h: &Host, p: &Page) -> String {
    if h.settings.wiki.render_mode == "obsidian" {
        format!("[[{}|{}]]", p.rel.trim_end_matches(".md"), if p.title.is_empty() { &p.rel } else { &p.title })
    } else {
        format!("[{}]({})", if p.title.is_empty() { &p.rel } else { &p.title }, p.rel)
    }
}

/// Bridge mode: mirror MEMORY.md, DREAMS.md and daily notes as source pages.
fn sync_bridge(h: &Host) -> Result<usize, String> {
    let mut n = 0;
    for f in crate::index::source_files(&h.data, &crate::settings::SearchSettings::default()) {
        if !(f.display == "MEMORY.md" || f.display == "DREAMS.md" || crate::index::dated(&f.display).is_some()) {
            continue;
        }
        let text = fs::read_to_string(&f.abs).unwrap_or_default();
        let s = slug(&format!("memory-{}", f.display.trim_end_matches(".md")));
        let mut fm = Map::new();
        fm.insert("id".into(), json!(format!("source.{s}")));
        fm.insert("pageType".into(), json!("source"));
        fm.insert("title".into(), json!(format!("Memory: {}", f.display)));
        fm.insert("sourceType".into(), json!("memory-bridge"));
        fm.insert("sourcePath".into(), json!(f.abs.display().to_string()));
        fm.insert("bridgeRelativePath".into(), json!(f.display));
        fm.insert("updatedAt".into(), json!(util::iso(util::now_ms())));
        util::write_atomic(&root(h).join("sources").join(format!("{s}.md")), render(&fm, &text).as_bytes())?;
        n += 1;
    }
    Ok(n)
}

/// Rebuild index.md, per-page `## Related` blocks and the dashboards.
pub fn compile(h: &Host) -> Result<String, String> {
    init(h)?;
    let bridged = if h.settings.wiki.bridge { sync_bridge(h)? } else { 0 };
    let all = pages(h);
    let r = root(h);
    let mut body = Vec::new();
    for (kind, _, heading) in KINDS {
        let mut ps: Vec<&Page> = all.iter().filter(|p| p.kind == *kind).collect();
        if ps.is_empty() {
            continue;
        }
        ps.sort_by(|a, b| a.title.cmp(&b.title));
        body.push(format!("### {heading}"));
        body.extend(ps.iter().map(|p| format!("- {}", link(h, p))));
        body.push(String::new());
    }
    if body.is_empty() {
        body.push("- No compiled pages yet.".into());
    }
    let idx = fs::read_to_string(r.join("index.md")).unwrap_or_else(|_| "# Wiki Index\n".into());
    util::write_atomic(&r.join("index.md"), managed(&idx, "index", "## Generated", &body.join("\n")).as_bytes())?;
    if h.settings.wiki.create_backlinks {
        let by_id: HashMap<&str, &Page> = all.iter().filter(|p| !p.id.is_empty()).map(|p| (p.id.as_str(), p)).collect();
        for p in &all {
            let mut lines = Vec::new();
            for sid in p.strs("sourceIds") {
                if let Some(s) = by_id.get(sid.as_str()) {
                    lines.push(format!("- Source: {}", link(h, s)));
                }
            }
            let stem = p.rel.trim_end_matches(".md");
            for q in all.iter().filter(|q| q.rel != p.rel && (q.links().iter().any(|l| l == stem || l.eq_ignore_ascii_case(&p.title)) || q.strs("sourceIds").contains(&p.id))) {
                lines.push(format!("- Backlink: {}", link(h, q)));
            }
            if lines.is_empty() {
                continue;
            }
            let path = r.join(&p.rel);
            let cur = fs::read_to_string(&path).unwrap_or_default();
            let next = managed(&cur, "related", "## Related", &lines.join("\n"));
            if next != cur {
                util::write_atomic(&path, next.as_bytes())?;
            }
        }
    }
    if h.settings.wiki.create_dashboards {
        let all = pages(h);
        for (name, key, title) in [("open-questions", "questions", "Open Questions"), ("contradictions", "contradictions", "Contradictions")] {
            let mut lines = Vec::new();
            for p in all.iter().filter(|p| p.kind != "report") {
                for q in p.strs(key) {
                    lines.push(format!("- {q} ({})", link(h, p)));
                }
            }
            if lines.is_empty() {
                lines.push("- None.".into());
            }
            let mut fm = Map::new();
            fm.insert("id".into(), json!(format!("report.{name}")));
            fm.insert("pageType".into(), json!("report"));
            fm.insert("title".into(), json!(title));
            fm.insert("updatedAt".into(), json!(util::iso(util::now_ms())));
            util::write_atomic(&r.join("reports").join(format!("{name}.md")), render(&fm, &format!("# {title}\n\n{}", lines.join("\n"))).as_bytes())?;
        }
    }
    log(h, "compile", json!({"pages": all.len(), "bridged": bridged}));
    Ok(format!("compiled {} page(s){}", all.len(), if bridged > 0 { format!(", {bridged} bridged memory source(s)") } else { String::new() }))
}

/// Import a file (or text) as a raw source page.
pub fn ingest(h: &Host, path: Option<&Path>, text: Option<&str>, title: Option<&str>) -> Result<String, String> {
    init(h)?;
    let (content, src) = match (path, text) {
        (Some(p), _) => (fs::read_to_string(p).map_err(|e| format!("cannot read {}: {e}", p.display()))?, Some(p.display().to_string())),
        (None, Some(t)) => (t.to_string(), None),
        _ => return Err("ingest needs a file or text".into()),
    };
    let title = title.map(str::to_string).or_else(|| path.and_then(|p| p.file_stem()).map(|s| s.to_string_lossy().into_owned())).unwrap_or_else(|| clip(content.lines().next().unwrap_or("note"), 60));
    let s = slug(&title);
    let mut fm = Map::new();
    fm.insert("id".into(), json!(format!("source.{s}")));
    fm.insert("pageType".into(), json!("source"));
    fm.insert("title".into(), json!(title));
    if let Some(p) = src {
        fm.insert("sourcePath".into(), json!(p));
    }
    fm.insert("updatedAt".into(), json!(util::iso(util::now_ms())));
    let rel = format!("sources/{s}.md");
    util::write_atomic(&root(h).join(&rel), render(&fm, &content).as_bytes())?;
    log(h, "ingest", json!({"page": rel}));
    compile(h)?;
    Ok(format!("ingested {rel} (id source.{s})"))
}

#[derive(Debug, Clone, PartialEq)]
pub struct Issue {
    pub severity: &'static str,
    pub category: &'static str,
    pub code: &'static str,
    pub path: String,
    pub message: String,
}

fn kind_of(code: &str) -> (&'static str, &'static str) {
    match code {
        "missing-id" | "duplicate-id" | "missing-page-type" | "page-type-mismatch" | "missing-title" | "invalid-frontmatter" => ("error", "structure"),
        "missing-source-ids" | "missing-import-provenance" | "claim-missing-evidence" => ("warning", "provenance"),
        "broken-wikilink" => ("warning", "links"),
        "contradiction-present" | "claim-conflict" => ("warning", "contradictions"),
        "open-question" => ("warning", "open-questions"),
        _ => ("warning", "quality"),
    }
}

fn age_days(v: Option<&Value>, now: u64) -> Option<f64> {
    util::parse_iso(v?.as_str()?).map(|t| now.saturating_sub(t) as f64 / util::DAY_MS)
}

pub fn lint_pages(all: &[Page], now: u64) -> Vec<Issue> {
    let mut out = Vec::new();
    let mut add = |code: &'static str, path: &str, msg: String| {
        let (severity, category) = kind_of(code);
        out.push(Issue { severity, category, code, path: path.into(), message: msg });
    };
    let mut ids: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut targets: HashSet<String> = HashSet::new();
    for p in all {
        targets.insert(p.rel.trim_end_matches(".md").to_lowercase());
        if let Some(stem) = Path::new(&p.rel).file_stem() {
            targets.insert(stem.to_string_lossy().to_lowercase());
        }
        targets.insert(p.title.to_lowercase());
        targets.insert(slug(&p.title));
    }
    for p in all {
        let raw = p.rel.starts_with("sources/") && p.fm.is_empty();
        if p.id.is_empty() {
            if !raw {
                add("missing-id", &p.rel, "Missing `id` frontmatter.".into());
            }
        } else {
            ids.entry(p.id.as_str()).or_default().push(&p.rel);
        }
        match p.fm.get("pageType").and_then(Value::as_str) {
            None if !raw => add("missing-page-type", &p.rel, "Missing `pageType` frontmatter.".into()),
            Some(t) if t != p.kind => add("page-type-mismatch", &p.rel, format!("Expected pageType `{}`, found `{t}`.", p.kind)),
            _ => {}
        }
        if p.title.trim().is_empty() {
            add("missing-title", &p.rel, "Missing page title.".into());
        }
        if p.kind != "source" && p.kind != "report" && p.strs("sourceIds").is_empty() {
            add("missing-source-ids", &p.rel, "Non-source page is missing `sourceIds` provenance.".into());
        }
        if p.fm.get("sourceType").and_then(Value::as_str) == Some("memory-bridge") && (p.fm.get("sourcePath").is_none() || p.fm.get("bridgeRelativePath").is_none()) {
            add("missing-import-provenance", &p.rel, "Bridge-imported source page is missing `sourcePath` or `bridgeRelativePath` provenance.".into());
        }
        let c = p.strs("contradictions").len();
        if c > 0 {
            add("contradiction-present", &p.rel, format!("Page lists {c} contradiction{} to resolve.", if c == 1 { "" } else { "s" }));
        }
        let q = p.strs("questions").len();
        if q > 0 {
            add("open-question", &p.rel, format!("Page lists {q} open question{}.", if q == 1 { "" } else { "s" }));
        }
        if let Some(cf) = p.fm.get("confidence").and_then(Value::as_f64) {
            if cf < 0.5 {
                add("low-confidence", &p.rel, format!("Page confidence is low ({cf:.2})."));
            }
        }
        if !raw && p.kind != "report" {
            match age_days(p.fm.get("updatedAt"), now) {
                None => add("stale-page", &p.rel, "Page freshness needs review (missing updatedAt).".into()),
                Some(d) if d >= STALE_DAYS => add("stale-page", &p.rel, format!("Page freshness needs review (updated {d:.0} days ago).")),
                _ => {}
            }
        }
        for cl in p.list("claims") {
            let label = format!("Claim `{}`", cl["id"].as_str().or(cl["text"].as_str()).unwrap_or("?"));
            if cl["evidence"].as_array().is_none_or_empty() {
                add("claim-missing-evidence", &p.rel, format!("{label} is missing structured evidence."));
            }
            if let Some(cf) = cl["confidence"].as_f64() {
                if cf < 0.5 {
                    add("claim-low-confidence", &p.rel, format!("{label} has low confidence ({cf:.2})."));
                }
            }
            if let Some(d) = age_days(cl.get("updatedAt").or(p.fm.get("updatedAt")), now) {
                if d >= STALE_DAYS {
                    add("stale-claim", &p.rel, format!("{label} freshness needs review (updated {d:.0} days ago)."));
                }
            }
        }
        for l in p.links() {
            let t = l.trim().to_lowercase();
            if !(targets.contains(&t) || targets.contains(t.trim_end_matches(".md")) || targets.contains(&slug(&t))) {
                add("broken-wikilink", &p.rel, format!("Broken wikilink target `{l}`."));
            }
        }
    }
    // Competing claim variants: same claim id with different text across pages.
    let mut claims: BTreeMap<String, HashSet<(String, String)>> = BTreeMap::new();
    for p in all {
        for cl in p.list("claims") {
            if let (Some(id), Some(t)) = (cl["id"].as_str(), cl["text"].as_str()) {
                claims.entry(id.to_string()).or_default().insert((p.rel.clone(), t.trim().to_lowercase()));
            }
        }
    }
    for (id, v) in claims {
        let texts: HashSet<&String> = v.iter().map(|(_, t)| t).collect();
        if texts.len() > 1 {
            for (path, _) in &v {
                add("claim-conflict", path, format!("Claim cluster `{id}` has competing variants across {} pages.", v.len()));
            }
        }
    }
    for (id, paths) in ids {
        if paths.len() > 1 {
            for p in paths {
                add("duplicate-id", p, format!("Duplicate page id `{id}`."));
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

trait EmptyArr {
    fn is_none_or_empty(&self) -> bool;
}
impl EmptyArr for Option<&Vec<Value>> {
    fn is_none_or_empty(&self) -> bool {
        self.is_none_or(|a| a.is_empty())
    }
}

pub fn lint(h: &Host) -> Result<(Vec<Issue>, String), String> {
    init(h)?;
    let issues = lint_pages(&pages(h), util::now_ms());
    let body = if issues.is_empty() { "No issues found.".to_string() } else { issues.iter().map(|i| format!("- [{}] {} `{}`: {}", i.severity, i.code, i.path, i.message)).collect::<Vec<_>>().join("\n") };
    let mut fm = Map::new();
    fm.insert("id".into(), json!("report.lint"));
    fm.insert("pageType".into(), json!("report"));
    fm.insert("title".into(), json!("Lint Report"));
    fm.insert("updatedAt".into(), json!(util::iso(util::now_ms())));
    util::write_atomic(&root(h).join("reports/lint.md"), render(&fm, &format!("# Lint Report\n\n{body}")).as_bytes())?;
    Ok((issues, "reports/lint.md".into()))
}

pub fn lint_summary(issues: &[Issue], report: &str) -> String {
    if issues.is_empty() {
        return "No wiki lint issues.".into();
    }
    let n = |c: &str| issues.iter().filter(|i| i.category == c).count();
    format!("Issues: {} total ({} errors, {} warnings)\nContradictions: {}\nOpen questions: {}\nProvenance gaps: {}\nReport: {report}", issues.len(), issues.iter().filter(|i| i.severity == "error").count(), issues.iter().filter(|i| i.severity == "warning").count(), n("contradictions"), n("open-questions"), n("provenance"))
}

pub fn status(h: &Host) -> Value {
    let all = pages(h);
    let counts: BTreeMap<&str, usize> = KINDS.iter().map(|(k, _, _)| (*k, all.iter().filter(|p| p.kind == *k).count())).collect();
    let obsidian = std::env::var_os("PATH").map(|p| std::env::split_paths(&p).any(|d| d.join("obsidian").is_file() || d.join("obsidian-cli").is_file())).unwrap_or(false);
    json!({"vault": root(h), "initialized": root(h).join("index.md").is_file(), "renderMode": h.settings.wiki.render_mode, "vaultMode": if h.settings.wiki.bridge { "bridge" } else { "isolated" }, "searchCorpus": h.settings.wiki.search_corpus, "pages": all.len(), "byKind": counts, "obsidianCli": obsidian})
}

#[derive(Debug, Clone)]
pub struct WikiHit {
    pub path: String,
    pub title: String,
    pub id: String,
    pub score: f64,
    pub snippet: String,
}

pub fn search(h: &Host, query: &str, max: usize) -> Vec<WikiHit> {
    let qt = util::token_set(query);
    if qt.is_empty() {
        return vec![];
    }
    let ql = query.trim().to_lowercase();
    let mut out: Vec<WikiHit> = pages(h)
        .into_iter()
        .filter_map(|p| {
            let title = util::token_set(&p.title);
            let body: Vec<String> = util::tokens(&p.body);
            let bset: HashSet<&String> = body.iter().collect();
            let t_hit = qt.iter().filter(|t| title.contains(*t)).count() as f64 / qt.len() as f64;
            let b_hit = qt.iter().filter(|t| bset.contains(t)).count() as f64 / qt.len() as f64;
            let exact = if p.title.to_lowercase() == ql || p.id.to_lowercase() == ql || p.rel.to_lowercase().contains(&ql) { 0.3 } else { 0.0 };
            let score = (0.5 * t_hit + 0.4 * b_hit + exact).min(1.0);
            if score <= 0.0 {
                return None;
            }
            let line = p.body.lines().find(|l| qt.iter().any(|t| l.to_lowercase().contains(t.as_str()))).unwrap_or("").trim().to_string();
            Some(WikiHit { path: p.rel, title: p.title, id: p.id, score, snippet: clip(&line, 300) })
        })
        .collect();
    out.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap().then(a.path.cmp(&b.path)));
    out.truncate(max);
    out
}

pub fn find(h: &Host, lookup: &str) -> Option<Page> {
    let l = lookup.trim().trim_start_matches("./");
    let all = pages(h);
    all.iter().find(|p| p.id == l || p.rel == l || p.rel.trim_end_matches(".md") == l).or_else(|| all.iter().find(|p| p.title.eq_ignore_ascii_case(l) || slug(&p.title) == slug(l))).cloned()
}

pub fn get(h: &Host, lookup: &str, from: Option<usize>, lines: Option<usize>) -> Option<Value> {
    let p = find(h, lookup)?;
    let text = fs::read_to_string(root(h).join(&p.rel)).ok()?;
    let mut v = crate::tools::excerpt(&text, &p.rel, from, lines);
    v["id"] = json!(p.id);
    v["title"] = json!(p.title);
    v["found"] = json!(true);
    v["source"] = json!("wiki");
    Some(v)
}

/// Narrow mutations: create_synthesis (synthesis) and update_metadata (metadata).
pub fn apply(h: &Host, m: &Value) -> Result<Value, String> {
    if !m.is_object() {
        return Err("wiki_apply needs an object".into());
    }
    init(h)?;
    let now = util::iso(util::now_ms());
    let op = m["op"].as_str().unwrap_or("");
    let meta_keys = ["sourceIds", "claims", "contradictions", "questions", "confidence", "status"];
    match op {
        "create_synthesis" | "synthesis" => {
            let title = m["title"].as_str().filter(|t| !t.trim().is_empty()).ok_or("create_synthesis needs `title`")?;
            let body = m["body"].as_str().filter(|t| !t.trim().is_empty()).ok_or("create_synthesis needs `body`")?;
            let s = slug(title);
            let rel = format!("syntheses/{s}.md");
            let path = root(h).join(&rel);
            let (mut fm, human) = match fs::read_to_string(&path) {
                Ok(t) => {
                    let (fm, b) = parse(&t);
                    (fm, b.find(HUMAN_START).map(|i| b[i..].to_string()))
                }
                Err(_) => (Map::new(), None),
            };
            fm.insert("id".into(), json!(format!("synthesis.{s}")));
            fm.insert("pageType".into(), json!("synthesis"));
            fm.insert("title".into(), json!(title));
            for k in meta_keys {
                if let Some(v) = m.get(k).filter(|v| !v.is_null()) {
                    fm.insert(k.into(), v.clone());
                }
            }
            fm.entry("sourceIds").or_insert(json!([]));
            fm.insert("updatedAt".into(), json!(now));
            let mut b = format!("# {title}\n\n{}", body.trim());
            if let Some(hb) = human {
                b = format!("{b}\n\n{hb}");
            }
            util::write_atomic(&path, render(&fm, &b).as_bytes())?;
            log(h, "create_synthesis", json!({"page": rel}));
            compile(h)?;
            Ok(json!({"op": "create_synthesis", "path": rel, "id": format!("synthesis.{s}"), "changed": true}))
        }
        "update_metadata" | "metadata" => {
            let lookup = m["lookup"].as_str().ok_or("update_metadata needs `lookup`")?;
            let p = find(h, lookup).ok_or_else(|| format!("Wiki page not found: {lookup}"))?;
            let path = root(h).join(&p.rel);
            let (mut fm, body) = parse(&fs::read_to_string(&path).map_err(|e| e.to_string())?);
            let mut changed = Vec::new();
            for k in meta_keys {
                if let Some(v) = m.get(k) {
                    if v.is_null() {
                        fm.remove(k);
                    } else {
                        fm.insert(k.into(), v.clone());
                    }
                    changed.push(k);
                }
            }
            if changed.is_empty() {
                return Err("update_metadata needs at least one of sourceIds, claims, contradictions, questions, confidence, status".into());
            }
            fm.insert("updatedAt".into(), json!(now));
            util::write_atomic(&path, render(&fm, &body).as_bytes())?;
            log(h, "update_metadata", json!({"page": p.rel, "fields": changed}));
            Ok(json!({"op": "update_metadata", "path": p.rel, "id": p.id, "fields": changed, "changed": true}))
        }
        other => Err(format!("unknown wiki_apply op `{other}`; use create_synthesis or update_metadata")),
    }
}

pub fn tools(h: &Arc<Host>) -> Vec<Arc<dyn Tool>> {
    ["wiki_status", "wiki_search", "wiki_get", "wiki_apply", "wiki_lint"].iter().map(|n| Arc::new(WikiTool(h.clone(), n)) as Arc<dyn Tool>).collect()
}

pub struct WikiTool(pub Arc<Host>, pub &'static str);

impl Tool for WikiTool {
    fn spec(&self) -> ToolSpec {
        let s = |d: &str| json!({"type":"string","description":d});
        let (desc, schema) = match self.1 {
            "wiki_status" => ("Inspect the memory wiki vault mode, health, and Obsidian CLI availability.", json!({"type":"object","properties":{}})),
            "wiki_search" => ("Search wiki pages by title, path, id, or body text (corpus=all also searches memory).", json!({"type":"object","properties":{"query":{"type":"string","minLength":1},"maxResults":{"type":"integer","minimum":1},"corpus":{"type":"string","enum":["wiki","memory","all"]}},"required":["query"]})),
            "wiki_get" => ("Read a wiki page by id or relative path (fromLine/lineCount for a bounded excerpt).", json!({"type":"object","properties":{"lookup":{"type":"string","minLength":1},"fromLine":{"type":"integer","minimum":1},"lineCount":{"type":"integer","minimum":1}},"required":["lookup"]})),
            "wiki_apply" => ("Apply narrow wiki mutations for syntheses and page metadata without freeform markdown surgery. op=create_synthesis (title, body, sourceIds, claims, contradictions, questions, confidence, status) or op=update_metadata (lookup + fields).", json!({"type":"object","properties":{"op":{"type":"string","enum":["create_synthesis","update_metadata","synthesis","metadata"]},"title":s("Synthesis title"),"body":s("Synthesis Markdown body"),"lookup":s("Page id or path (update_metadata)"),"sourceIds":{"type":"array","items":{"type":"string"}},"claims":{"type":"array","items":{"type":"object","properties":{"id":{"type":"string"},"text":{"type":"string"},"status":{"type":"string"},"confidence":{"type":"number"},"evidence":{"type":"array","items":{"type":"object"}},"updatedAt":{"type":"string"}},"required":["text"]}},"contradictions":{"type":"array","items":{"type":"string"}},"questions":{"type":"array","items":{"type":"string"}},"confidence":{"type":["number","null"]},"status":{"type":"string"}},"required":["op"]})),
            _ => ("Lint the wiki vault and surface structural issues, provenance gaps, contradictions, and open questions.", json!({"type":"object","properties":{}})),
        };
        let ro = !matches!(self.1, "wiki_apply" | "wiki_lint");
        ToolSpec { name: self.1.into(), description: desc.into(), input_schema: schema, parallel_safe: ro, idempotent: ro, pinned: false }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        let path = root(&self.0);
        if matches!(self.1, "wiki_apply" | "wiki_lint") {
            vec![Effect::Write { path }]
        } else {
            vec![Effect::Read { path }]
        }
    }
    fn call(&self, _: &ToolCtx, input: Value) -> ToolOutput {
        let h = &self.0;
        match self.1 {
            "wiki_status" => ToolOutput::ok(serde_json::to_string_pretty(&status(h)).unwrap_or_default()),
            "wiki_search" => {
                let Some(q) = input["query"].as_str().filter(|q| !q.trim().is_empty()) else { return ToolOutput::err("wiki_search needs `query`") };
                let max = input["maxResults"].as_u64().unwrap_or(10) as usize;
                let corpus = input["corpus"].as_str().unwrap_or(&h.settings.wiki.search_corpus).to_string();
                let mut res: Vec<Value> = Vec::new();
                if corpus != "memory" {
                    res.extend(search(h, q, max).into_iter().map(|w| json!({"corpus": "wiki", "path": w.path, "id": w.id, "title": w.title, "score": w.score, "snippet": w.snippet})));
                }
                if corpus != "wiki" {
                    if let Ok(o) = h.search(q, max, h.settings.search.min_score, &[]) {
                        res.extend(o.hits.into_iter().map(|x| json!({"corpus": "memory", "path": x.path, "score": x.score, "snippet": x.snippet, "citation": x.citation()})));
                    }
                }
                res.sort_by(|a, b| b["score"].as_f64().partial_cmp(&a["score"].as_f64()).unwrap());
                res.truncate(max);
                if res.is_empty() {
                    return ToolOutput::ok("No wiki results.");
                }
                ToolOutput::ok(serde_json::to_string_pretty(&json!({"results": res})).unwrap_or_default())
            }
            "wiki_get" => {
                let l = input["lookup"].as_str().unwrap_or("").trim();
                if l.is_empty() {
                    return ToolOutput::err("wiki_get requires a non-empty `lookup` path or id.");
                }
                match get(h, l, input["fromLine"].as_u64().map(|n| n as usize), input["lineCount"].as_u64().map(|n| n as usize)) {
                    Some(v) => ToolOutput::ok(serde_json::to_string_pretty(&v).unwrap_or_default()),
                    None => ToolOutput::ok(format!("Wiki page not found: {l}")),
                }
            }
            "wiki_apply" => match apply(h, &input) {
                Ok(v) => ToolOutput::ok(serde_json::to_string_pretty(&v).unwrap_or_default()),
                Err(e) => ToolOutput::err(e),
            },
            _ => match lint(h) {
                Ok((i, r)) => ToolOutput::ok(lint_summary(&i, &r)),
                Err(e) => ToolOutput::err(e),
            },
        }
    }
}

/// `ark wiki <init|status|compile|ingest <file>|lint|search <q>|get <lookup>|apply <json>>`.
pub fn cli(h: &Host, args: &[String]) -> Result<String, String> {
    let rest = args.get(1..).map(|r| r.join(" ")).unwrap_or_default();
    match args.first().map(String::as_str).unwrap_or("status") {
        "init" => Ok(format!("vault {}: {} created", root(h).display(), init(h)?.len())),
        "status" => Ok(serde_json::to_string_pretty(&status(h)).unwrap_or_default()),
        "compile" => compile(h),
        "ingest" => ingest(h, Some(Path::new(args.get(1).ok_or("usage: ark wiki ingest <file> [title]")?)), None, args.get(2).map(String::as_str)),
        "lint" => lint(h).map(|(i, r)| lint_summary(&i, &r)),
        "search" => Ok(search(h, &rest, 10).iter().map(|w| format!("{:.2}  {}  {}", w.score, w.path, w.title)).collect::<Vec<_>>().join("\n")),
        "get" => get(h, &rest, None, None).and_then(|v| v["text"].as_str().map(str::to_string)).ok_or_else(|| format!("Wiki page not found: {rest}")),
        "apply" => apply(h, &serde_json::from_str(&rest).map_err(|e| format!("apply needs a JSON mutation: {e}"))?).map(|v| v.to_string()),
        other => Err(format!("unknown `wiki {other}`; use init, status, compile, ingest, lint, search, get or apply")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_lifecycle() {
        let h = crate::test_host("wiki", |_| {});
        assert!(init(&h).unwrap().len() >= 8);
        let src = h.data.join("notes.md");
        fs::write(&src, "# Postgres\nWe run Postgres 16 with logical replication.").unwrap();
        assert!(ingest(&h, Some(&src), None, Some("Postgres ops")).unwrap().contains("source.postgres-ops"));
        let r = apply(&h, &json!({"op":"create_synthesis","title":"Database choice","body":"We chose [[sources/postgres-ops|Postgres]] over MySQL. See [[Nowhere]].","sourceIds":["source.postgres-ops"],"claims":[{"id":"db","text":"Primary DB is Postgres","confidence":0.4}],"questions":["Upgrade to 17?"]})).unwrap();
        assert_eq!(r["path"], "syntheses/database-choice.md");
        let idx = fs::read_to_string(root(&h).join("index.md")).unwrap();
        assert!(idx.contains("### Syntheses") && idx.contains("[[syntheses/database-choice|Database choice]]"));
        let src_page = fs::read_to_string(root(&h).join("sources/postgres-ops.md")).unwrap();
        assert!(src_page.contains("## Related") && src_page.contains("Backlink: [[syntheses/database-choice"), "{src_page}");
        assert!(fs::read_to_string(root(&h).join("reports/open-questions.md")).unwrap().contains("Upgrade to 17?"));
        let (issues, rep) = lint(&h).unwrap();
        let codes: Vec<&str> = issues.iter().map(|i| i.code).collect();
        assert!(codes.contains(&"broken-wikilink") && codes.contains(&"open-question") && codes.contains(&"claim-missing-evidence") && codes.contains(&"claim-low-confidence"), "{codes:?}");
        assert!(!codes.contains(&"missing-source-ids"));
        assert!(lint_summary(&issues, &rep).contains("Open questions: 1"));
        let hits = search(&h, "postgres replication", 5);
        assert_eq!(hits[0].path, "sources/postgres-ops.md");
        let g = get(&h, "synthesis.database-choice", Some(1), Some(3)).unwrap();
        assert_eq!(g["found"], true);
        apply(&h, &json!({"op":"metadata","lookup":"Database choice","questions":null,"confidence":0.9})).unwrap();
        let p = find(&h, "synthesis.database-choice").unwrap();
        assert!(p.fm.get("questions").is_none() && p.fm["confidence"] == json!(0.9));
        assert!(apply(&h, &json!({"op":"metadata","lookup":"nope","status":"x"})).is_err());
        assert!(apply(&h, &json!({"op":"drop"})).is_err());
        let t = tools(&h);
        let c = crate::tools::tests_ctx(&h.data);
        assert!(t[1].call(&c, json!({"query":"database"})).content.contains("database-choice"));
        assert!(t[2].call(&c, json!({"lookup":""})).is_error);
        assert!(t[4].call(&c, json!({})).content.contains("Issues:"));
        assert!(t[0].call(&c, json!({})).content.contains("\"pages\""));
        assert!(cli(&h, &["search".into(), "postgres".into()]).unwrap().contains("postgres-ops"));
    }

    #[test]
    fn lint_duplicates_conflicts_and_staleness() {
        let mk = |rel: &str, kind: &str, fm: Value| {
            let fm: Map<String, Value> = fm.as_object().cloned().unwrap();
            Page { rel: rel.into(), kind: kind.into(), title: fm.get("title").and_then(Value::as_str).unwrap_or("").into(), id: fm.get("id").and_then(Value::as_str).unwrap_or("").into(), fm, body: String::new() }
        };
        let now = util::now_ms();
        let pages = vec![
            mk("concepts/a.md", "concept", json!({"id":"x","pageType":"entity","title":"A","sourceIds":["s"],"updatedAt":"2020-01-01T00:00:00Z","claims":[{"id":"c","text":"sky is blue","evidence":[{"sourceId":"s"}]}]})),
            mk("concepts/b.md", "concept", json!({"id":"x","pageType":"concept","title":"B","updatedAt":util::iso(now),"claims":[{"id":"c","text":"sky is green","evidence":[{"sourceId":"s"}]}]})),
        ];
        let codes: Vec<&str> = lint_pages(&pages, now).iter().map(|i| i.code).collect();
        for c in ["duplicate-id", "page-type-mismatch", "stale-page", "stale-claim", "claim-conflict", "missing-source-ids"] {
            assert!(codes.contains(&c), "{c}: {codes:?}");
        }
        let (fm, body) = parse(&render(&pages[0].fm, "# Body"));
        assert_eq!(fm["claims"][0]["text"], "sky is blue");
        assert_eq!(body.trim(), "# Body");
    }
}
