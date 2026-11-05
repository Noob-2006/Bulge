//! `seagent distill` (BATCH-next 7-6-3, pro-059/060; team mode 7-5, pro-067): turn the documented
//! working methods of an occupation's exemplary practitioners into a nameless L2 guideline
//! pack, with an internal provenance record, automatic checks, an evaluation and a signature.
//!
//! ```text
//! seagent distill research --isco 2512 [--title T] [--model M] --out DIR      1st distillation
//! seagent distill abstract --out DIR [--slug S] [--extends L1] [--model M]   2nd distillation
//! seagent distill check    --out DIR                                          names, sources, check.py
//! seagent distill eval     --out DIR --questions FILE --model M --judge J [--ablate]
//! seagent distill sign     --out DIR --seed-file FILE                         `seagent role sign` on the staged tree
//! seagent distill run      --isco 2512 --model M [--judge J --questions F] [--seed-file F] --out DIR
//! seagent distill team     --input DIR --authorization FILE.toml --model M --slug S --out DIR
//! seagent distill purge    --out DIR                                          drop the (masked) source material
//! ```
//!
//! Stages and files (`DIR/`):
//! - **research** — an agent (web tools) finds 1–3 exemplary practitioners for the ISCO
//!   occupation and their methods, each with at least one source URL → `research.json`.
//!   Methods without a verifiable source are dropped, never kept (no fabrication).
//! - **abstract** — the methods (labelled `m1…`, practitioners only as `E1…`, so names never
//!   reach this prompt) are rewritten as observable, trigger→action guidelines in the pack
//!   format → `pack/<slug>/SKILL.md`, and `provenance.json` maps each rule to the methods,
//!   practitioners and sources behind it (internal, never shipped with the pack).
//! - **check** — no practitioner name, URL or quotation in the pack; every rule traced to a
//!   sourced method; then the pack is staged into a copy of the shipped role tree (`tree/`) and
//!   `share/roles/check.py` runs over it (format, extends/isco, token budget, hashed-name list).
//! - **eval** — the role scenario evaluation with and without the candidate guidelines (and
//!   optional ablation), through the evaluation runner.
//! - **sign** — `seagent role sign` over the staged tree, then `seagent role verify --key` on it.
//!
//! Team mode distils a team's own practice from material its members consented to or the
//! company is entitled to use. It refuses to run without an authorization statement that
//! passes the checks derived from docs/compliance-tw.md (purpose, notice, legal basis,
//! no special-category data, retention, cross-border disclosure), masks personal data with the
//! same masker as exports (`seagent_security::pii`) plus the listed people's names, works only on
//! the masked copy, and records the run in the audit stream.

use crate::args::Args;
use crate::ops::evalkit::{self, grade::extract_json, run::Runner, Task};
use crate::R;
use seagent_kernel::config::Paths;
use seagent_kernel::roles::{self, Catalog, Layer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const COMMANDS: &[&str] = &["distill"];
pub const VALUE_FLAGS: &[&str] = &["isco", "extends", "authorization", "input", "seed-file"];
pub const BOOL_FLAGS: &[&str] = &[];

const USAGE: &str = "usage: seagent distill research|abstract|check|eval|sign|run|team|purge … (see `seagent distill help`)";
const HELP: &str = "seagent distill — occupation guidelines from documented practice (BATCH-next 7-6-3)
  research --isco CODE [--title T] [--model M] --out DIR
  abstract --out DIR [--slug S] [--extends L1] [--model M]
  check    --out DIR
  eval     --out DIR --questions FILE --model M --judge J [--ablate] [--repeat N]
  sign     --out DIR --seed-file FILE
  run      --isco CODE --model M --out DIR [--judge J --questions FILE] [--seed-file FILE]
  team     --input DIR --authorization FILE.toml --model M --slug S --out DIR [--extends L1]
  purge    --out DIR
models: provider/model as configured; fake/oracle runs the whole flow offline";

// ───────────────────────── research ─────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Source {
    #[serde(default)]
    pub title: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Method {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub method: String,
    pub description: String,
    #[serde(default)]
    pub sources: Vec<Source>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Exemplar {
    pub name: String,
    #[serde(default)]
    pub why: String,
    #[serde(default)]
    pub methods: Vec<Method>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Research {
    #[serde(default)]
    pub occupation: String,
    #[serde(default)]
    pub isco: String,
    pub exemplars: Vec<Exemplar>,
    /// "web" (sources are URLs) or "team" (sources are `file:` references into the masked corpus).
    #[serde(default)]
    pub mode: String,
    /// Methods dropped for lacking a verifiable source.
    #[serde(default)]
    pub dropped: Vec<String>,
}

fn valid_url(u: &str) -> bool {
    let rest = u.strip_prefix("https://").or_else(|| u.strip_prefix("http://"));
    rest.is_some_and(|r| r.split('/').next().is_some_and(|h| h.contains('.') && !h.contains(' ')))
}

/// Keep only sourced methods (URL sources in web mode, existing `file:` refs in team mode),
/// number them `m1…`, and fail when nothing sourced is left.
pub fn validate_research(mut r: Research, corpus: Option<&Path>) -> Result<Research, String> {
    if r.exemplars.is_empty() || r.exemplars.len() > 3 {
        return Err(format!("research must name 1–3 exemplars, got {}", r.exemplars.len()));
    }
    let mut n = 0;
    let mut dropped = vec![];
    for e in &mut r.exemplars {
        if e.name.trim().is_empty() {
            return Err("an exemplar has no name".into());
        }
        let name = e.name.clone();
        e.methods.retain_mut(|m| {
            m.sources.retain(|s| match corpus {
                None => valid_url(&s.url),
                Some(c) => s.url.strip_prefix("file:").map(|f| f.split('#').next().unwrap_or("")).is_some_and(|f| evalkit::safe_rel(f).is_ok() && c.join(f).is_file()),
            });
            let ok = !m.sources.is_empty() && !m.description.trim().is_empty();
            if !ok {
                dropped.push(format!("{name}: {}", if m.method.is_empty() { &m.description } else { &m.method }));
            }
            ok
        });
        for m in &mut e.methods {
            n += 1;
            m.id = format!("m{n}");
        }
    }
    r.exemplars.retain(|e| !e.methods.is_empty());
    if n == 0 {
        return Err("no method carries a verifiable source; nothing can be distilled (sources are required, never invented)".into());
    }
    r.dropped = dropped;
    Ok(r)
}

pub fn research_prompt(title: &str, isco: &str) -> String {
    format!(
        "[seagent-distill:research]\nOccupation: {title} (ISCO-08 {isco})\n\nIdentify 1-3 exemplary practitioners of this occupation whose way of working is well documented, and 3-6 concrete working methods for each. Every method needs at least one verifiable source with a URL (a publisher or library page, a DOI, an archived article, an official biography). Never invent a source: leave out any method you cannot source. Describe each method as observable behaviour — what is done, when, and why — and keep only methods a professional can apply today. Use the web tools.\n\nReply with JSON only:\n{{\"occupation\": \"…\", \"isco\": \"{isco}\", \"exemplars\": [{{\"name\": \"…\", \"why\": \"…\", \"methods\": [{{\"method\": \"short name\", \"description\": \"…\", \"sources\": [{{\"title\": \"…\", \"url\": \"https://…\"}}]}}]}}]}}\n"
    )
}

/// Occupation title of an ISCO code from the role catalog (first L2 pack with that code).
pub fn occupation(cat: &Catalog, isco: &str) -> Option<(String, String)> {
    cat.by_layer(Layer::L2).find(|p| p.isco == isco).map(|p| (p.title_zh.clone(), p.slug.clone()))
}

fn run_text(r: &Runner, model: &str, id: &str, prompt: String, agent: bool) -> Result<(String, u64, u64), String> {
    let t = Task { id: id.into(), suite: "distill".into(), kind: if agent { evalkit::Kind::Agent } else { evalkit::Kind::Chat }, prompt, timeout_secs: Some(3600), ..Default::default() };
    let a = r.attempt(&evalkit::run::Subject::seagent(model), &t, 1);
    if let Some(e) = a.error {
        return Err(format!("{id}: {e}"));
    }
    Ok((a.answer, a.input_tokens, a.output_tokens))
}

fn write_json(p: &Path, v: &impl Serialize) -> Result<(), String> {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    std::fs::write(p, serde_json::to_string_pretty(v).map_err(|e| e.to_string())? + "\n").map_err(|e| format!("{}: {e}", p.display()))
}

fn read_json<T: for<'de> Deserialize<'de>>(p: &Path) -> Result<T, String> {
    serde_json::from_str(&std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?).map_err(|e| format!("{}: {e}", p.display()))
}

pub fn research(r: &Runner, model: &str, cat: &Catalog, isco: &str, title: Option<&str>, out: &Path) -> Result<Research, String> {
    let isco = roles::normalize_isco(isco, Some(Layer::L2));
    let title = match title {
        Some(t) => t.to_string(),
        None => occupation(cat, &isco).map(|(t, _)| t).ok_or_else(|| format!("ISCO {isco} has no pack in the role catalog; pass --title"))?,
    };
    let prompt = research_prompt(&title, &isco);
    std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
    std::fs::write(out.join("research-prompt.md"), &prompt).map_err(|e| e.to_string())?;
    let (answer, i, o) = run_text(r, model, "distill-research", prompt, true)?;
    let v = extract_json(&answer).ok_or_else(|| format!("research reply is not JSON: {}", answer.chars().take(300).collect::<String>()))?;
    let mut res: Research = serde_json::from_value(v).map_err(|e| format!("research reply: {e}"))?;
    res.isco = isco.clone();
    if res.occupation.is_empty() {
        res.occupation = title;
    }
    res.mode = "web".into();
    let res = validate_research(res, None)?;
    write_json(&out.join("research.json"), &res)?;
    write_json(&out.join("usage.json"), &json!({"research": {"input_tokens": i, "output_tokens": o}}))?;
    Ok(res)
}

// ───────────────────────── abstract ─────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Rule {
    pub rule: String,
    #[serde(default)]
    pub from: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Abstracted {
    #[serde(default)]
    pub title_zh: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub triggers: Vec<Rule>,
    #[serde(default)]
    pub priorities: Vec<Rule>,
    #[serde(default)]
    pub stop: Vec<Rule>,
    #[serde(default)]
    pub checklist: Vec<Rule>,
    #[serde(default)]
    pub avoid: Vec<Rule>,
}

impl Abstracted {
    pub fn sections(&self) -> Vec<(&'static str, &Vec<Rule>)> {
        vec![("Triggers → Actions", &self.triggers), ("Decision priorities", &self.priorities), ("Stop and escalate when", &self.stop), ("Checklist", &self.checklist), ("Avoid", &self.avoid)]
    }
    pub fn rules(&self) -> Vec<&Rule> {
        self.sections().into_iter().flat_map(|(_, v)| v.iter()).collect()
    }
}

/// The abstraction prompt: methods by id, practitioners only as E1/E2/E3.
pub fn abstract_prompt(r: &Research) -> String {
    let mut methods = String::new();
    for (i, e) in r.exemplars.iter().enumerate() {
        for m in &e.methods {
            methods.push_str(&format!("- {} [E{}]: {}\n", m.id, i + 1, m.description.trim()));
        }
    }
    format!(
        "[seagent-distill:abstract]\nOccupation: {} (ISCO-08 {})\n\nRewrite the documented methods below as guidelines a model follows when working in this occupation. Rules:\n- Imperative, observable behaviour with its trigger (\"Before X, do Y; if Z, stop and report\"), never \"be like someone\".\n- No person names, places, events, organisations, titles of works or quotations.\n- Where methods conflict, write the condition for each (\"In A prefer X; in B prefer Y\"); never keep two contradicting rules.\n- Keep only what transfers to today's practice; merge duplicates.\n- The whole pack must stay under 400 tokens (about 1,600 characters).\n- Every rule lists the method ids it comes from.\n\nMethods:\n{methods}\nReply with JSON only:\n{{\"title_zh\": \"…\", \"description\": \"Applies to … (at most 25 words)\", \"triggers\": [{{\"rule\": \"…\", \"from\": [\"m1\"]}}], \"priorities\": [], \"stop\": [], \"checklist\": [], \"avoid\": []}}\n",
        r.occupation, r.isco
    )
}

/// The L1 pack an ISCO code belongs to.
pub fn l1_for(cat: &Catalog, isco: &str) -> Option<String> {
    let d = isco.chars().next()?.to_string();
    cat.by_layer(Layer::L1).find(|p| p.isco == d).map(|p| p.slug.clone())
}

fn yaml_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "'"))
}

/// Render the pack (`SKILL.md`). Regulated status, reserved acts and the scope section are
/// taken from the shipped pack of the same ISCO code, so distilling never loosens a boundary.
pub fn render_pack(slug: &str, isco: &str, extends: &str, a: &Abstracted, title: &str, regulated_from: Option<&roles::Pack>) -> String {
    let mut s = format!("---\nname: {slug}\ntitle_zh: {}\nlayer: L2\nisco: \"{isco}\"\nextends: {extends}\ndescription: {}\n", if a.title_zh.trim().is_empty() { title } else { a.title_zh.trim() }, yaml_str(a.description.trim()));
    let reg = regulated_from.filter(|p| p.regulated);
    match reg {
        Some(p) => s.push_str(&format!("regulated: true\nboundary: [{}]\n", p.boundary.join(", "))),
        None => s.push_str("regulated: false\n"),
    }
    s.push_str("---\n");
    for (head, rules) in a.sections() {
        if rules.is_empty() {
            continue;
        }
        s.push_str(&format!("\n## {head}\n"));
        for r in rules {
            s.push_str(&format!("- {}\n", r.rule.trim().replace('\n', " ")));
        }
    }
    if let Some(p) = reg {
        if let Some(i) = p.body.find("## Scope and boundaries") {
            s.push('\n');
            s.push_str(p.body[i..].trim_end());
            s.push('\n');
        }
    }
    s
}

/// `provenance.json` in the internal format check.py reads: one record per rule.
pub fn provenance(r: &Research, a: &Abstracted) -> Value {
    let mut by_id: BTreeMap<&str, (&Exemplar, &Method)> = BTreeMap::new();
    for e in &r.exemplars {
        for m in &e.methods {
            by_id.insert(m.id.as_str(), (e, m));
        }
    }
    let rows: Vec<Value> = a
        .rules()
        .iter()
        .enumerate()
        .map(|(i, rule)| {
            let from: Vec<Value> = rule.from.iter().filter_map(|id| by_id.get(id.as_str())).map(|(e, m)| json!({"name": e.name, "method": if m.method.is_empty() { &m.description } else { &m.method }, "method_id": m.id, "sources": m.sources.iter().map(|s| s.url.clone()).collect::<Vec<_>>()})).collect();
            json!({"rule_index": i + 1, "rule": rule.rule.trim(), "from": from})
        })
        .collect();
    json!(rows)
}

pub struct Abstraction {
    pub slug: String,
    pub pack_dir: PathBuf,
}

pub fn abstract_stage(r: &Runner, model: &str, cat: &Catalog, out: &Path, slug: Option<&str>, extends: Option<&str>) -> Result<Abstraction, String> {
    let res: Research = read_json(&out.join("research.json"))?;
    let isco = roles::normalize_isco(&res.isco, Some(Layer::L2));
    let slug = slug.map(String::from).unwrap_or_else(|| format!("distilled-{isco}"));
    if !slug.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') || slug.starts_with('-') {
        return Err(format!("slug `{slug}` must be kebab-case (a-z, 0-9, -)"));
    }
    let extends = match extends {
        Some(e) => e.to_string(),
        None => l1_for(cat, &isco).ok_or_else(|| format!("no L1 pack for ISCO major group of {isco}; pass --extends"))?,
    };
    let prompt = abstract_prompt(&res);
    std::fs::write(out.join("abstract-prompt.md"), &prompt).map_err(|e| e.to_string())?;
    let (answer, i, o) = run_text(r, model, "distill-abstract", prompt, false)?;
    let v = extract_json(&answer).ok_or_else(|| format!("abstraction reply is not JSON: {}", answer.chars().take(300).collect::<String>()))?;
    let a: Abstracted = serde_json::from_value(v).map_err(|e| format!("abstraction reply: {e}"))?;
    if a.rules().is_empty() {
        return Err("abstraction produced no rules".into());
    }
    let same = cat.by_layer(Layer::L2).find(|p| p.isco == isco);
    let pack = render_pack(&slug, &isco, &extends, &a, &res.occupation, same);
    let pack_dir = out.join("pack").join(&slug);
    std::fs::create_dir_all(&pack_dir).map_err(|e| e.to_string())?;
    std::fs::write(pack_dir.join("SKILL.md"), pack).map_err(|e| e.to_string())?;
    write_json(&out.join("abstracted.json"), &a)?;
    write_json(&out.join("provenance.json"), &provenance(&res, &a))?;
    let mut usage: Value = read_json(&out.join("usage.json")).unwrap_or(json!({}));
    usage["abstract"] = json!({"input_tokens": i, "output_tokens": o});
    write_json(&out.join("usage.json"), &usage)?;
    write_json(&out.join("state.json"), &json!({"slug": slug, "isco": isco, "extends": extends, "mode": res.mode}))?;
    Ok(Abstraction { slug, pack_dir })
}

// ───────────────────────── checks ─────────────────────────

/// Names that must not appear in the pack: each full name, and each part of it that is long
/// enough to identify (Latin parts ≥ 4 letters, matched as whole words; CJK names whole).
pub fn name_needles(names: &[String]) -> Vec<String> {
    let mut v = vec![];
    for n in names {
        let n = n.trim();
        if n.is_empty() {
            continue;
        }
        v.push(n.to_string());
        if n.is_ascii() {
            for part in n.split(|c: char| !c.is_alphanumeric() && c != '\'') {
                if part.chars().count() >= 4 && part.chars().next().is_some_and(char::is_uppercase) {
                    v.push(part.to_string());
                }
            }
        }
    }
    v.sort();
    v.dedup();
    v
}

pub fn find_names(text: &str, needles: &[String]) -> Vec<String> {
    let lower = text.to_lowercase();
    needles
        .iter()
        .filter(|n| {
            if !n.is_ascii() {
                return text.contains(n.as_str());
            }
            let nl = n.to_lowercase();
            // whole-word match
            lower.match_indices(&nl).any(|(i, _)| {
                let before = lower[..i].chars().next_back();
                let after = lower[i + nl.len()..].chars().next();
                !before.is_some_and(|c| c.is_alphanumeric()) && !after.is_some_and(|c| c.is_alphanumeric())
            })
        })
        .cloned()
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckRow {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

fn copy_tree(from: &Path, to: &Path) -> Result<(), String> {
    std::fs::create_dir_all(to).map_err(|e| format!("{}: {e}", to.display()))?;
    for e in std::fs::read_dir(from).map_err(|e| format!("{}: {e}", from.display()))?.flatten() {
        let (p, q) = (e.path(), to.join(e.file_name()));
        let ft = e.file_type().map_err(|e| e.to_string())?;
        if ft.is_dir() {
            if e.file_name() == "__pycache__" {
                continue;
            }
            copy_tree(&p, &q)?;
        } else if ft.is_file() && e.file_name() != crate::role_cli::SIG_FILE {
            std::fs::copy(&p, &q).map_err(|e| format!("{}: {e}", p.display()))?;
        }
    }
    Ok(())
}

/// Stage the candidate pack into a copy of the shipped role tree (`out/tree`).
pub fn stage_tree(src: &Path, out: &Path, slug: &str) -> Result<PathBuf, String> {
    let tree = out.join("tree");
    if tree.exists() {
        std::fs::remove_dir_all(&tree).map_err(|e| e.to_string())?;
    }
    copy_tree(src, &tree)?;
    let dst = tree.join("L2").join(slug);
    if dst.exists() {
        std::fs::remove_dir_all(&dst).map_err(|e| e.to_string())?;
    }
    copy_tree(&out.join("pack").join(slug), &dst)?;
    Ok(tree)
}

/// All automatic checks; `checks.json` records them. Ok only when every row passes.
pub fn check_stage(out: &Path, roles_src: &Path, extra_names: &[String]) -> Result<(bool, Vec<CheckRow>), String> {
    let st: Value = read_json(&out.join("state.json"))?;
    let slug = st["slug"].as_str().unwrap_or("").to_string();
    let res: Research = read_json(&out.join("research.json"))?;
    let a: Abstracted = read_json(&out.join("abstracted.json"))?;
    let skill = std::fs::read_to_string(out.join("pack").join(&slug).join("SKILL.md")).map_err(|e| e.to_string())?;
    let mut rows = vec![];
    let mut names: Vec<String> = res.exemplars.iter().map(|e| e.name.clone()).collect();
    names.extend(extra_names.iter().cloned());
    let hits = find_names(&skill, &name_needles(&names));
    rows.push(CheckRow { name: "no person names".into(), ok: hits.is_empty(), detail: if hits.is_empty() { format!("{} name(s) checked", names.len()) } else { format!("found: {}", hits.join(", ")) } });
    let urls = skill.contains("http://") || skill.contains("https://") || skill.contains("www.");
    let quotes = skill.lines().filter(|l| l.starts_with("- ")).any(|l| l.contains(['“', '”', '「', '」', '«', '»']) || l.matches('"').count() >= 2);
    rows.push(CheckRow { name: "no links or quotations".into(), ok: !urls && !quotes, detail: format!("links: {urls}, quotations: {quotes}") });
    let prov = provenance(&res, &a);
    let unsourced: Vec<String> = prov.as_array().cloned().unwrap_or_default().iter().filter(|r| r["from"].as_array().is_none_or(|f| f.is_empty() || f.iter().all(|x| x["sources"].as_array().is_none_or(|s| s.is_empty())))).map(|r| r["rule"].as_str().unwrap_or("").chars().take(60).collect()).collect();
    rows.push(CheckRow { name: "every rule traced to a sourced method".into(), ok: unsourced.is_empty(), detail: if unsourced.is_empty() { format!("{} rules", a.rules().len()) } else { format!("untraced: {}", unsourced.join(" | ")) } });
    let body = skill.splitn(3, "---\n").nth(2).unwrap_or("");
    let tokens = (body.trim().chars().count() as u64).div_ceil(4);
    rows.push(CheckRow { name: "L2 token budget (≤ 400)".into(), ok: tokens <= 400, detail: format!("≈{tokens} tokens") });
    let tree = stage_tree(roles_src, out, &slug)?;
    let script = tree.join("check.py");
    let row = if !script.is_file() {
        CheckRow { name: "share/roles/check.py".into(), ok: false, detail: format!("{} missing in the role tree", script.display()) }
    } else {
        let mut c = std::process::Command::new("python3");
        c.arg("-I").arg(&script).arg("--quiet").current_dir(&tree).env("SEAGENT_AUDIT_ROOT", &tree);
        match evalkit::run::capture(c, std::time::Duration::from_secs(300)) {
            Ok((o, code)) => {
                let relevant: Vec<&str> = o.lines().filter(|l| l.contains(&slug) || l.starts_with("OK") || l.contains("problem") || l.contains("SKIPPED") || l.contains("FAIL")).take(20).collect();
                CheckRow { name: "share/roles/check.py".into(), ok: code == 0, detail: format!("exit {code}: {}", if relevant.is_empty() { o.lines().last().unwrap_or("").to_string() } else { relevant.join(" / ") }) }
            }
            Err(e) => CheckRow { name: "share/roles/check.py".into(), ok: false, detail: format!("could not run python3: {e}") },
        }
    };
    rows.push(row);
    let ok = rows.iter().all(|r| r.ok);
    write_json(&out.join("checks.json"), &json!({"ok": ok, "checks": rows}))?;
    Ok((ok, rows))
}

// ───────────────────────── eval / sign ─────────────────────────

/// Guidelines text for a candidate pack (the same shape `seagent role use` would inject).
pub fn pack_guidelines(cfg: &seagent_kernel::config::Config, skill: &str, slug: &str) -> Result<(String, Vec<String>), String> {
    let p = roles::parse_pack(skill, None)?;
    let mut text = roles::core_text(cfg).unwrap_or_default();
    if !text.is_empty() {
        text.push_str("\n\n");
    }
    text.push_str(&format!("# Professional role: {} [role:{slug}]\n", p.title_zh));
    let body: Vec<String> = p.body.trim().lines().map(|l| if l.starts_with("## ") { format!("#{l}") } else { l.to_string() }).collect();
    text.push_str(&body.join("\n"));
    let rules = p.body.lines().filter_map(|l| l.trim_start().strip_prefix("- ").map(|r| r.trim().to_string())).collect();
    Ok((text, rules))
}

pub fn eval_stage(r: &Runner, model: &str, out: &Path, questions: &Path, ablate: bool) -> Result<Value, String> {
    let st: Value = read_json(&out.join("state.json"))?;
    let slug = st["slug"].as_str().unwrap_or("").to_string();
    let skill = std::fs::read_to_string(out.join("pack").join(&slug).join("SKILL.md")).map_err(|e| e.to_string())?;
    let (text, rules) = pack_guidelines(&r.base_cfg, &skill, &slug)?;
    let tasks = evalkit::load_native(questions)?;
    let _ = std::fs::remove_file(r.results_path());
    let ab = r.out.join("ablation");
    let c = evalkit::roles::Compare { model, name: &slug, text: &text, rules: &rules, mode: "both", threshold: 0.0, ablation_root: ablate.then_some(ab.as_path()) };
    let block = evalkit::roles::compare_guidelines(r, &tasks, &c)?;
    std::fs::write(r.out.join("roles.json"), serde_json::to_string_pretty(&vec![block.clone()]).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    evalkit::report::write(&r.out, &json!({"kind": "distill-eval", "suites": [questions.display().to_string()], "models": [model], "judge": r.judge.as_ref().map(|j| j.model.clone())}), Some(&evalkit::roles::render_md(std::slice::from_ref(&block))))?;
    Ok(block)
}

pub fn sign_stage(out: &Path, seed_file: &Path) -> Result<String, String> {
    let checks: Value = read_json(&out.join("checks.json")).map_err(|_| "run `seagent distill check` first: an unchecked pack is never signed".to_string())?;
    if checks["ok"].as_bool() != Some(true) {
        return Err("the checks failed (checks.json); fix the pack before signing".into());
    }
    let tree = out.join("tree");
    let paths = Paths::from_env();
    let seed = std::fs::read_to_string(seed_file).map_err(|e| format!("{}: {e}", seed_file.display()))?;
    let key = seagent_security::signing::public_of(seed.trim())?;
    let (signed, _) = crate::role_cli::run(&paths, &["sign".into(), "--seed-file".into(), seed_file.display().to_string(), "--dir".into(), tree.display().to_string()])?;
    let (verified, code) = crate::role_cli::run(&paths, &["verify".into(), "--dir".into(), tree.display().to_string(), "--key".into(), key])?;
    if code != 0 {
        return Err(format!("signed tree does not verify:\n{verified}"));
    }
    Ok(format!("{signed}\n{}", verified.lines().filter(|l| l.starts_with("signature") || l.starts_with("verify") || l.starts_with("Skills Guard")).collect::<Vec<_>>().join("\n")))
}

// ───────────────────────── team mode ─────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    pub name: String,
    #[serde(default)]
    pub consent: bool,
    #[serde(default)]
    pub aliases: Vec<String>,
}

/// The authorization statement team mode requires (TOML).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    /// `consent` (each person agreed) or `employer` (the company is entitled to the material).
    pub basis: String,
    /// Who granted it (the consenting people's coordinator, or the authorizing manager).
    pub granted_by: String,
    /// Their role (required for `employer`).
    #[serde(default)]
    pub authority: String,
    /// YYYY-MM-DD.
    pub granted_at: String,
    /// The specific purpose (個資法 §5, §19/§20).
    pub purpose: String,
    /// The people were told what is collected and why (個資法 §8/§9).
    pub notice_given: bool,
    /// Material contains special-category data (個資法 §6: medical, genetic, sex life, health
    /// examination, criminal record) — must be false.
    pub sensitive_data: bool,
    /// Days the (masked) source material is kept (1–365).
    pub retention_days: u32,
    /// The model provider processes data abroad and the people were told (個資法 §21).
    #[serde(default)]
    pub cross_border: bool,
    pub subjects: Vec<Subject>,
}

/// Providers that run on the user's own machine (no cross-border transfer).
pub const LOCAL_PROVIDERS: &[&str] = &["ollama", "lmstudio", "llamacpp", "llama-cpp", "vllm", "localai", "fake"];

fn valid_date(s: &str) -> bool {
    let p: Vec<&str> = s.split('-').collect();
    p.len() == 3 && p[0].len() == 4 && p.iter().all(|x| x.chars().all(|c| c.is_ascii_digit())) && (1..=12).contains(&p[1].parse::<u32>().unwrap_or(0)) && (1..=31).contains(&p[2].parse::<u32>().unwrap_or(0))
}

/// Every reason the statement is not enough (docs/compliance-tw.md §2 and checklist #3/#5/#6).
pub fn check_authorization(a: &Authorization, model: &str) -> Vec<String> {
    let mut v = vec![];
    match a.basis.as_str() {
        "consent" => {
            for s in a.subjects.iter().filter(|s| !s.consent) {
                v.push(format!("basis = consent but `{}` has not consented (個資法 §19/§20)", s.name));
            }
        }
        "employer" => {
            if a.authority.trim().is_empty() {
                v.push("basis = employer needs `authority` (the authorizing role)".into());
            }
        }
        o => v.push(format!("basis must be `consent` or `employer`, got `{o}`")),
    }
    if a.granted_by.trim().is_empty() {
        v.push("granted_by is empty".into());
    }
    if !valid_date(&a.granted_at) {
        v.push(format!("granted_at `{}` is not YYYY-MM-DD", a.granted_at));
    } else {
        let today = seagent_kernel::trajectory::iso_ms(seagent_kernel::event::now_ms());
        if a.granted_at.as_str() > &today[..10] {
            v.push(format!("granted_at {} is in the future", a.granted_at));
        }
    }
    if a.purpose.trim().chars().count() < 8 {
        v.push("purpose must state the specific purpose (個資法 §5/§19)".into());
    }
    if !a.notice_given {
        v.push("notice_given must be true: the people must be told what is collected and why (個資法 §8/§9)".into());
    }
    if a.sensitive_data {
        v.push("material with special-category data (個資法 §6) is not distilled".into());
    }
    if !(1..=365).contains(&a.retention_days) {
        v.push("retention_days must be 1–365 (data minimisation, 人工智慧基本法 §4)".into());
    }
    let provider = model.split('/').next().unwrap_or("");
    if !LOCAL_PROVIDERS.contains(&provider) && !a.cross_border {
        v.push(format!("model provider `{provider}` processes the material outside this machine: set cross_border = true only after telling the people (個資法 §21)"));
    }
    if a.subjects.is_empty() {
        v.push("subjects must list the people whose material is used (their names are masked)".into());
    }
    v
}

/// Mask personal data and the listed people's names; returns the text and the alias map.
pub fn mask_team_text(text: &str, subjects: &[Subject]) -> String {
    let cfg = seagent_security::pii::PiiConfig { ip: true, ..Default::default() };
    let mut out = seagent_security::pii::mask_with(text, &cfg);
    let mut pairs: Vec<(String, String)> = vec![];
    for (i, s) in subjects.iter().enumerate() {
        let alias = alias(i);
        for n in std::iter::once(&s.name).chain(&s.aliases) {
            if !n.trim().is_empty() {
                pairs.push((n.trim().to_string(), alias.clone()));
            }
        }
    }
    pairs.sort_by_key(|(n, _)| std::cmp::Reverse(n.chars().count()));
    for (n, a) in pairs {
        out = out.replace(&n, &a);
    }
    out
}

pub fn alias(i: usize) -> String {
    let letters = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'];
    if i < letters.len() {
        format!("成員{}", letters[i])
    } else {
        format!("成員{}", i + 1)
    }
}

const TEAM_EXT: &[&str] = &["md", "txt", "log", "json", "csv", "yaml", "yml"];

/// Copy the input into `out/masked` (masked, 0600); refuses names that survive masking.
pub fn mask_corpus(input: &Path, out: &Path, subjects: &[Subject]) -> Result<Vec<String>, String> {
    use std::os::unix::fs::PermissionsExt;
    let dst = out.join("masked");
    std::fs::create_dir_all(&dst).map_err(|e| e.to_string())?;
    std::fs::set_permissions(out, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let mut files = vec![];
    fn walk(d: &Path, v: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        let mut es: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        es.sort();
        for p in es {
            if p.is_dir() && !p.is_symlink() {
                walk(&p, v);
            } else if p.is_file() && !p.is_symlink() {
                v.push(p);
            }
        }
    }
    let mut all = vec![];
    walk(input, &mut all);
    for p in all.into_iter().take(500) {
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        if !TEAM_EXT.contains(&ext.as_str()) || std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0) > 2 * 1024 * 1024 {
            continue;
        }
        let rel = p.strip_prefix(input).map_err(|e| e.to_string())?.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
        let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        let masked = mask_team_text(&text, subjects);
        let left: Vec<&str> = subjects.iter().map(|s| s.name.as_str()).filter(|n| !n.is_empty() && masked.contains(n)).collect();
        if !left.is_empty() {
            return Err(format!("{rel}: names survived masking ({})", left.len()));
        }
        // file names can carry names too
        let rel_masked = mask_team_text(&rel, subjects).replace(['[', ']'], "_");
        let q = dst.join(&rel_masked);
        std::fs::create_dir_all(q.parent().unwrap_or(&dst)).map_err(|e| e.to_string())?;
        std::fs::write(&q, masked).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&q, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
        files.push(rel_masked);
    }
    if files.is_empty() {
        return Err(format!("no readable text material under {} ({})", input.display(), TEAM_EXT.join(", ")));
    }
    Ok(files)
}

pub fn team_prompt(out: &Path, files: &[String], n_subjects: usize, title: &str) -> String {
    let mut corpus = String::new();
    for f in files {
        let t = std::fs::read_to_string(out.join("masked").join(f)).unwrap_or_default();
        if corpus.len() + t.len() > 60_000 {
            corpus.push_str(&format!("=== file: masked/{f} (omitted: budget) ===\n"));
            continue;
        }
        corpus.push_str(&format!("=== file: masked/{f} ===\n"));
        for (i, l) in t.lines().enumerate() {
            corpus.push_str(&format!("{:>4}| {l}\n", i + 1));
        }
    }
    let aliases: Vec<String> = (0..n_subjects).map(alias).collect();
    format!(
        "[seagent-distill:team]\nOccupation: {title}\nTeam members (pseudonyms): {}\n\nFrom the team's own material below (personal data is masked), extract the concrete working methods the team members use. Attribute each method to the pseudonym it comes from and cite where it is written as `file:masked/<file>#L<line>`. Do not guess methods the material does not show.\n\nReply with JSON only:\n{{\"occupation\": \"{title}\", \"exemplars\": [{{\"name\": \"成員A\", \"methods\": [{{\"method\": \"short name\", \"description\": \"…\", \"sources\": [{{\"title\": \"…\", \"url\": \"file:masked/notes.md#L3\"}}]}}]}}]}}\n\n{corpus}",
        aliases.join(", ")
    )
}

/// What team mode reads: the material, the authorization statement and the occupation.
pub struct TeamInput<'a> {
    pub input: &'a Path,
    pub authorization: Option<&'a Path>,
    pub title: &'a str,
    pub isco: &'a str,
}

pub fn team(r: &Runner, model: &str, ti: &TeamInput, out: &Path) -> Result<Research, String> {
    let (input, title, isco) = (ti.input, ti.title, ti.isco);
    let Some(af) = ti.authorization else {
        return Err("team distillation refuses to run without an authorization statement (--authorization FILE.toml; see docs/evals.md)".into());
    };
    let auth: Authorization = toml::from_str(&std::fs::read_to_string(af).map_err(|e| format!("{}: {e}", af.display()))?).map_err(|e| format!("{}: {e}", af.display()))?;
    let problems = check_authorization(&auth, model);
    if !problems.is_empty() {
        return Err(format!("authorization statement rejected:\n- {}", problems.join("\n- ")));
    }
    std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
    let files = mask_corpus(input, out, &auth.subjects)?;
    let prompt = team_prompt(out, &files, auth.subjects.len(), title);
    let (answer, i, o) = run_text(r, model, "distill-team", prompt, false)?;
    let v = extract_json(&answer).ok_or_else(|| format!("team extraction reply is not JSON: {}", answer.chars().take(300).collect::<String>()))?;
    let mut res: Research = serde_json::from_value(v).map_err(|e| format!("team extraction reply: {e}"))?;
    // only pseudonyms may name a source person; a real name in the reply is refused
    let real: Vec<String> = auth.subjects.iter().flat_map(|s| std::iter::once(s.name.clone()).chain(s.aliases.clone())).collect();
    if !find_names(&answer, &name_needles(&real)).is_empty() {
        return Err("the model's reply contains a real name; refusing to keep it".into());
    }
    res.mode = "team".into();
    res.isco = roles::normalize_isco(isco, Some(Layer::L2));
    if res.occupation.is_empty() {
        res.occupation = title.into();
    }
    let res = validate_research(res, Some(out))?;
    write_json(&out.join("research.json"), &res)?;
    write_json(&out.join("usage.json"), &json!({"team": {"input_tokens": i, "output_tokens": o}}))?;
    let today = seagent_kernel::trajectory::iso_ms(seagent_kernel::event::now_ms());
    write_json(&out.join("authorization.json"), &json!({"basis": auth.basis, "granted_by": auth.granted_by, "authority": auth.authority, "granted_at": auth.granted_at, "purpose": auth.purpose, "retention_days": auth.retention_days, "cross_border": auth.cross_border, "subjects": auth.subjects.len(), "masked_files": files.len(), "run_at": today}))?;
    // the real names stay in the caller's file; the check stage needs them, kept 0600 here
    write_json(&out.join(".names.json"), &real)?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(out.join(".names.json"), std::fs::Permissions::from_mode(0o600));
    }
    let paths = Paths::from_env();
    seagent_security::audit::record(
        &paths.data,
        seagent_security::audit::Event::new("distill.team", seagent_security::audit::Actor::local(), &out.display().to_string(), "ok").detail(json!({"basis": auth.basis, "purpose": seagent_security::pii::mask(&auth.purpose), "subjects": auth.subjects.len(), "files": files.len(), "retention_days": auth.retention_days, "cross_border": auth.cross_border, "model": model})),
    );
    Ok(res)
}

pub fn purge(out: &Path) -> Result<Vec<String>, String> {
    let mut gone = vec![];
    for p in ["masked", ".names.json", "research.json", "research-prompt.md", "abstract-prompt.md"] {
        let q = out.join(p);
        if q.is_dir() {
            std::fs::remove_dir_all(&q).map_err(|e| e.to_string())?;
            gone.push(p.to_string());
        } else if q.is_file() {
            std::fs::remove_file(&q).map_err(|e| e.to_string())?;
            gone.push(p.to_string());
        }
    }
    Ok(gone)
}

// ───────────────────────── fake model answers ─────────────────────────

/// `fake/oracle`'s structured answers to distill prompts (offline pipeline proof).
pub fn fake_reply(prompt: &str) -> Option<String> {
    if prompt.starts_with("[seagent-distill:research]") {
        let occ = prompt.lines().find_map(|l| l.strip_prefix("Occupation: ")).unwrap_or("").to_string();
        let isco = occ.rsplit("ISCO-08 ").next().unwrap_or("").trim_end_matches(')').to_string();
        return Some(
            json!({
                "occupation": occ.split(" (ISCO").next().unwrap_or(""), "isco": isco,
                "exemplars": [
                    {"name": "Mara Quellbrook", "why": "documented incident practice", "methods": [
                        {"method": "staged rollout", "description": "Before a change reaches every user, release it to a small share first and widen only while the error budget holds.", "sources": [{"title": "Field notes", "url": "https://example.org/notes/staged-rollout"}]},
                        {"method": "blameless review", "description": "After every outage, write a review that names the failed safeguard and the new one, with an owner and a date.", "sources": [{"title": "Review handbook", "url": "https://example.org/handbook/review"}]},
                        {"method": "folk wisdom", "description": "Trust your gut when the dashboard looks fine.", "sources": []}
                    ]},
                    {"name": "Ivo Brandtner", "why": "documented test discipline", "methods": [
                        {"method": "failing test first", "description": "Before fixing a defect, write a test that reproduces it and keep it in the suite.", "sources": [{"title": "Lecture series", "url": "https://example.org/lectures/3"}]},
                        {"method": "small reviewed changes", "description": "Keep each change small enough for one reviewer to read in one sitting; split anything larger.", "sources": [{"title": "Essay", "url": "https://example.org/essays/small"}]}
                    ]}
                ]
            })
            .to_string(),
        );
    }
    if prompt.starts_with("[seagent-distill:abstract]") {
        let methods: Vec<(String, String)> = prompt.lines().filter_map(|l| l.strip_prefix("- m")).filter_map(|l| l.split_once(": ").map(|(id, d)| (format!("m{}", id.split_whitespace().next().unwrap_or("")), d.trim().to_string()))).collect();
        let rule = |i: usize| methods.get(i).map(|(id, d)| json!({"rule": d, "from": [id]}));
        let ids: Vec<&String> = methods.iter().map(|(i, _)| i).collect();
        return Some(
            json!({
                "title_zh": "", "description": "Applies to planning, shipping and reviewing changes to running software.",
                "triggers": (0..methods.len()).filter_map(rule).collect::<Vec<_>>(),
                "priorities": [{"rule": "A safe, reversible release before a fast one.", "from": ids.iter().take(1).collect::<Vec<_>>()}],
                "stop": [{"rule": "A change cannot be split, tested or rolled back: stop and get a second reviewer.", "from": ids.iter().take(2).collect::<Vec<_>>()}],
                "checklist": [{"rule": "Reproducing test, small change, reviewer, staged release, review owner.", "from": ids.clone()}],
                "avoid": [{"rule": "No unreviewed change and no outage without a written review.", "from": ids.iter().rev().take(1).collect::<Vec<_>>()}]
            })
            .to_string(),
        );
    }
    if prompt.starts_with("[seagent-distill:team]") {
        // methods = bullet lines of the material, attributed to the pseudonym on the line
        let mut file = String::new();
        let mut by: BTreeMap<String, Vec<Value>> = BTreeMap::new();
        for l in prompt.lines() {
            if let Some(f) = l.strip_prefix("=== file: ") {
                file = f.split(" ===").next().unwrap_or("").split(" (omitted").next().unwrap_or("").to_string();
                continue;
            }
            let Some((n, text)) = l.split_once("| ") else { continue };
            let Some(item) = text.trim().strip_prefix("- ") else { continue };
            let who = item.split(['：', ':']).next().unwrap_or("").trim().to_string();
            if !who.starts_with("成員") {
                continue;
            }
            let desc = item.split_once(['：', ':']).map(|(_, d)| d.trim().to_string()).unwrap_or_default();
            by.entry(who).or_default().push(json!({"method": desc.chars().take(20).collect::<String>(), "description": desc, "sources": [{"title": file, "url": format!("file:{}#L{}", file, n.trim())}]}));
        }
        let ex: Vec<Value> = by.into_iter().take(3).map(|(n, m)| json!({"name": n, "methods": m})).collect();
        return Some(json!({"occupation": "", "exemplars": ex}).to_string());
    }
    None
}

// ───────────────────────── CLI ─────────────────────────

fn out_dir(a: &Args) -> Result<PathBuf, String> {
    a.val("out").map(PathBuf::from).ok_or_else(|| "--out DIR is required (the distillation's working directory)".into())
}

fn runner(a: &Args, out: &Path) -> Result<Runner, String> {
    let model = a.val("model").unwrap_or("");
    let mut models = vec![];
    if !model.is_empty() {
        models.push(model.to_string());
    }
    if let Some(j) = a.val("judge") {
        models.push(j.to_string());
    }
    let mut r = evalkit::cli::runner_for(a, &out.join(".run"), &models)?;
    r.quiet = true;
    Ok(r)
}

fn model_of(a: &Args, r: &Runner) -> Result<String, String> {
    match a.val("model") {
        Some(m) => Ok(m.to_string()),
        None if !r.base_cfg.model.default.is_empty() => Ok(r.base_cfg.model.default.clone()),
        None => Err("--model provider/model is required".into()),
    }
}

fn roles_src() -> Result<PathBuf, String> {
    roles::roles_dir().ok_or_else(|| "no shipped role tree found (set SEAGENT_SHARE_DIR or SEAGENT_ROLES_DIR)".into())
}

fn catalog(r: &Runner) -> std::sync::Arc<Catalog> {
    Catalog::for_config(&r.base_cfg)
}

fn print_checks(rows: &[CheckRow]) {
    for c in rows {
        println!("  {} {:<40} {}", if c.ok { "✓" } else { "✗" }, c.name, c.detail);
    }
}

fn extra_names(out: &Path) -> Vec<String> {
    read_json::<Vec<String>>(&out.join(".names.json")).map(|v| {
        let mut all = v;
        // pseudonyms are not real names but must not appear in a shipped pack either
        all.extend((0..all.len()).map(alias));
        all
    })
    .unwrap_or_default()
}

fn cli(a: &Args) -> R {
    let sub = a.pos(0).unwrap_or("help");
    if sub == "help" {
        println!("{HELP}");
        return Ok(0);
    }
    let out = out_dir(a)?;
    let r = runner(a, &out)?;
    match sub {
        "research" => {
            let m = model_of(a, &r)?;
            let res = research(&r, &m, &catalog(&r), a.val("isco").ok_or("--isco CODE is required")?, a.val("title"), &out)?;
            println!("research: {} exemplar(s), {} sourced method(s), {} dropped → {}", res.exemplars.len(), res.exemplars.iter().map(|e| e.methods.len()).sum::<usize>(), res.dropped.len(), out.join("research.json").display());
            Ok(0)
        }
        "abstract" => {
            let m = model_of(a, &r)?;
            let ab = abstract_stage(&r, &m, &catalog(&r), &out, a.val("slug"), a.val("extends"))?;
            println!("pack {}: {}\nprovenance: {} (internal; not shipped)", ab.slug, ab.pack_dir.join("SKILL.md").display(), out.join("provenance.json").display());
            Ok(0)
        }
        "check" => {
            let (ok, rows) = check_stage(&out, &roles_src()?, &extra_names(&out))?;
            print_checks(&rows);
            Ok(if ok { 0 } else { 1 })
        }
        "eval" => {
            let m = model_of(a, &r)?;
            let q = a.val("questions").ok_or("--questions FILE (scenario questions with judge points) is required")?;
            if r.judge.is_none() {
                return crate::usage("--judge MODEL is required (fake/judge offline)");
            }
            let mut er = runner(a, &out.join("eval"))?;
            er.out = out.join("eval");
            let b = eval_stage(&er, &m, &out, Path::new(q), a.flag("ablate"))?;
            println!("with guidelines {:.3} / without {:.3} → {}", b["with"].as_f64().unwrap_or(0.0), b["without"].as_f64().unwrap_or(0.0), out.join("eval/report.md").display());
            Ok(0)
        }
        "sign" => {
            let seed = a.val("seed-file").ok_or("--seed-file FILE is required (keep the seed out of the repo)")?;
            println!("{}", sign_stage(&out, Path::new(seed))?);
            Ok(0)
        }
        "run" | "team" => {
            let m = model_of(a, &r)?;
            let cat = catalog(&r);
            if sub == "run" {
                let res = research(&r, &m, &cat, a.val("isco").ok_or("--isco CODE is required")?, a.val("title"), &out)?;
                println!("1/5 research: {} exemplar(s), {} sourced method(s), {} dropped", res.exemplars.len(), res.exemplars.iter().map(|e| e.methods.len()).sum::<usize>(), res.dropped.len());
            } else {
                let input = PathBuf::from(a.val("input").ok_or("--input DIR (the team's material) is required")?);
                let isco = a.val("isco").unwrap_or("2512");
                let title = a.val("title").map(String::from).or_else(|| occupation(&cat, &roles::normalize_isco(isco, Some(Layer::L2))).map(|(t, _)| t)).unwrap_or_else(|| "team".into());
                let res = team(&r, &m, &TeamInput { input: &input, authorization: a.val("authorization").map(Path::new), title: &title, isco }, &out)?;
                println!("1/5 team material (masked): {} member(s), {} sourced method(s)", res.exemplars.len(), res.exemplars.iter().map(|e| e.methods.len()).sum::<usize>());
            }
            let slug = a.val("slug").map(String::from).or_else(|| (sub == "team").then(|| "team-practice".to_string()));
            let ab = abstract_stage(&r, &m, &cat, &out, slug.as_deref(), a.val("extends"))?;
            println!("2/5 abstract: {}", ab.pack_dir.join("SKILL.md").display());
            let (ok, rows) = check_stage(&out, &roles_src()?, &extra_names(&out))?;
            println!("3/5 checks: {}", if ok { "pass" } else { "FAIL" });
            print_checks(&rows);
            if !ok {
                return Ok(1);
            }
            match (a.val("questions"), r.judge.is_some()) {
                (Some(q), true) => {
                    let mut er = runner(a, &out.join("eval"))?;
                    er.out = out.join("eval");
                    let b = eval_stage(&er, &m, &out, Path::new(q), a.flag("ablate"))?;
                    println!("4/5 eval: with {:.3} / without {:.3} ({})", b["with"].as_f64().unwrap_or(0.0), b["without"].as_f64().unwrap_or(0.0), out.join("eval/report.md").display());
                }
                _ => println!("4/5 eval: skipped (pass --questions FILE --judge MODEL)"),
            }
            match a.val("seed-file") {
                Some(s) => println!("5/5 sign:\n{}", sign_stage(&out, Path::new(s))?),
                None => println!("5/5 sign: skipped (pass --seed-file FILE)"),
            }
            Ok(0)
        }
        "purge" => {
            let gone = purge(&out)?;
            println!("removed: {}", if gone.is_empty() { "nothing".into() } else { gone.join(", ") });
            Ok(0)
        }
        _ => crate::usage(USAGE),
    }
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    COMMANDS.contains(&cmd).then(|| cli(a))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(v: &[&str]) -> Args {
        Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    fn seed(dir: &Path) -> PathBuf {
        use base64::Engine;
        let f = dir.join("seed-test.b64");
        std::fs::write(&f, base64::engine::general_purpose::STANDARD.encode([9u8; 32])).unwrap();
        f
    }

    /// The whole two-stage flow with the fake model: research (sourced methods only) →
    /// abstraction (no names) → checks incl. check.py → evaluation → signature.
    #[test]
    fn distill_run_end_to_end_with_the_fake_model() {
        let _l = crate::testkit::env_lock();
        let share = evalkit::repo_share();
        let home = seagent_core::tmp::scratch("seagent-distill-home");
        let prev = std::env::var_os("SEAGENT_HOME");
        std::env::set_var("SEAGENT_HOME", &home);
        std::env::set_var("SEAGENT_ROLES_DIR", share.join("roles"));
        let out = seagent_core::tmp::scratch("seagent-distill");
        let qs = share.join("evals/roles/swdev.jsonl");
        let res = cli(&p(&["run", "--isco", "2512", "--model", "fake/oracle", "--judge", "fake/judge", "--questions", &qs.display().to_string(), "--seed-file", &seed(&home).display().to_string(), "--out", &out.display().to_string()]));
        std::env::remove_var("SEAGENT_ROLES_DIR");
        match prev {
            Some(v) => std::env::set_var("SEAGENT_HOME", v),
            None => std::env::remove_var("SEAGENT_HOME"),
        }
        let checks = std::fs::read_to_string(out.join("checks.json")).unwrap_or_default();
        assert_eq!(res.unwrap(), 0, "{checks}");
        let research: Research = read_json(&out.join("research.json")).unwrap();
        assert_eq!(research.dropped.len(), 1, "the unsourced method is dropped");
        assert!(research.exemplars.iter().flat_map(|e| &e.methods).all(|m| m.sources.iter().all(|s| s.url.starts_with("https://"))));
        let skill = std::fs::read_to_string(out.join("pack/distilled-2512/SKILL.md")).unwrap();
        assert!(skill.contains("isco: \"2512\"") && skill.contains("extends: professional-practice"), "{skill}");
        assert!(!skill.contains("Quellbrook") && !skill.contains("Brandtner") && !skill.contains("example.org"));
        let prov: Value = read_json(&out.join("provenance.json")).unwrap();
        assert!(prov.as_array().unwrap().iter().all(|r| !r["from"].as_array().unwrap().is_empty()));
        assert!(prov.to_string().contains("Mara Quellbrook"), "provenance keeps the internal record");
        let c: Value = serde_json::from_str(&checks).unwrap();
        assert_eq!(c["ok"], true, "{c}");
        assert!(c["checks"].as_array().unwrap().iter().any(|r| r["name"] == "share/roles/check.py" && r["ok"] == true));
        assert!(out.join("eval/report.md").is_file());
        assert!(std::fs::read_to_string(out.join("tree/roles.sig")).unwrap().contains("signature = "));
    }

    #[test]
    fn name_check_catches_names_and_parts_but_not_words() {
        let n = name_needles(&["Mara Quellbrook".into(), "王小明".into(), "Li Wu".into()]);
        assert!(n.contains(&"Quellbrook".to_string()) && !n.contains(&"Wu".to_string()));
        assert_eq!(find_names("Ask quellbrook first", &n), vec!["Quellbrook"]);
        assert!(find_names("Quellbrooks are rare", &n).is_empty());
        assert_eq!(find_names("如王小明所說", &n), vec!["王小明"]);
        // a given name of four letters or more counts too (conservative: a pack never needs it)
        assert_eq!(find_names("a Mara-style review", &n), vec!["Mara"]);
        assert!(find_names("Wu-style is two letters short", &n).is_empty());
        // research validation: unsourced methods dropped, none left → error
        let r = Research { exemplars: vec![Exemplar { name: "X Y".into(), methods: vec![Method { description: "d".into(), sources: vec![Source { title: "t".into(), url: "not a url".into() }], ..Default::default() }], ..Default::default() }], ..Default::default() };
        assert!(validate_research(r, None).unwrap_err().contains("never invented"));
    }

    fn auth(basis: &str) -> Authorization {
        Authorization {
            basis: basis.into(),
            granted_by: "工程部主管".into(),
            authority: "部門主管".into(),
            granted_at: "2026-10-01".into(),
            purpose: "整理團隊值班與事故處理的共同做法".into(),
            notice_given: true,
            sensitive_data: false,
            retention_days: 90,
            cross_border: false,
            subjects: vec![Subject { name: "王小明".into(), consent: true, aliases: vec!["小明".into()] }, Subject { name: "Alice Chen".into(), consent: true, aliases: vec![] }],
        }
    }

    #[test]
    fn team_authorization_rules_follow_the_compliance_checklist() {
        assert!(check_authorization(&auth("consent"), "fake/oracle").is_empty());
        assert!(check_authorization(&auth("employer"), "ollama/llama3").is_empty());
        let mut a = auth("consent");
        a.subjects[1].consent = false;
        a.notice_given = false;
        a.sensitive_data = true;
        a.retention_days = 0;
        a.granted_at = "2999-01-01".into();
        let v = check_authorization(&a, "openai/gpt-x");
        for want in ["has not consented", "notice_given", "§6", "retention_days", "future", "cross_border"] {
            assert!(v.iter().any(|x| x.contains(want)), "{want}: {v:?}");
        }
        let mut b = auth("employer");
        b.authority.clear();
        assert!(check_authorization(&b, "fake/x").iter().any(|x| x.contains("authority")));
        assert!(check_authorization(&auth("whatever"), "fake/x").iter().any(|x| x.contains("basis")));
        let m = mask_team_text("小明 (ming@corp.test, 0912-345-678, A123456789) 和 Alice Chen 在 10.1.2.3 上線；王小明負責", &auth("consent").subjects);
        assert!(!m.contains("小明") && !m.contains("Alice") && !m.contains("ming@") && !m.contains("A123456789") && !m.contains("10.1.2.3"), "{m}");
        assert!(m.contains("成員A") && m.contains("成員B"), "{m}");
    }

    #[test]
    fn team_mode_refuses_without_authorization_and_masks_everything_it_keeps() {
        let _l = crate::testkit::env_lock();
        let share = evalkit::repo_share();
        let home = seagent_core::tmp::scratch("seagent-team-home");
        let prev = std::env::var_os("SEAGENT_HOME");
        std::env::set_var("SEAGENT_HOME", &home);
        std::env::set_var("SEAGENT_ROLES_DIR", share.join("roles"));
        let input = seagent_core::tmp::scratch("seagent-team-in");
        std::fs::write(input.join("oncall-王小明.md"), "# 值班筆記\n- 成員A: 每次變更前先在測試環境跑完整流程，任何一步失敗就停下回報。\n- 王小明: 告警響起先保存日誌與時間軸，再動手止血。\n聯絡：ming@corp.test 0912-345-678\n- Alice Chen: 事故後一週內寫檢討，列出失效的防護與新的防護，指定負責人。\n").unwrap();
        std::fs::write(input.join("photo.png"), [0u8, 1, 2]).unwrap();
        let out = seagent_core::tmp::scratch("seagent-team-out");
        let run = |extra: &[&str]| {
            let mut v = vec!["team", "--input", input.to_str().unwrap(), "--model", "fake/oracle", "--isco", "2522", "--out", out.to_str().unwrap()];
            v.extend_from_slice(extra);
            cli(&p(&v))
        };
        // 1. no statement → refused before anything is read or written
        let e = run(&[]).unwrap_err().to_string();
        assert!(e.contains("refuses to run without an authorization statement"), "{e}");
        assert!(!out.join("masked").exists());
        // 2. a statement that fails the checks → refused
        let af = out.join("auth.toml");
        let mut bad = auth("consent");
        bad.notice_given = false;
        std::fs::write(&af, toml::to_string(&bad).unwrap()).unwrap();
        assert!(run(&["--authorization", af.to_str().unwrap()]).unwrap_err().to_string().contains("notice_given"));
        assert!(!out.join("masked").exists());
        // 3. a proper statement → masked corpus, nameless pack, audit event
        std::fs::write(&af, toml::to_string(&auth("consent")).unwrap()).unwrap();
        let r = run(&["--authorization", af.to_str().unwrap()]);
        let checks = std::fs::read_to_string(out.join("checks.json")).unwrap_or_default();
        std::env::remove_var("SEAGENT_ROLES_DIR");
        let audit_dir = Paths::from_env().data;
        match prev {
            Some(v) => std::env::set_var("SEAGENT_HOME", v),
            None => std::env::remove_var("SEAGENT_HOME"),
        }
        assert_eq!(r.unwrap(), 0, "{checks}");
        let masked: Vec<String> = std::fs::read_dir(out.join("masked")).unwrap().flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
        assert_eq!(masked, vec!["oncall-成員A.md".to_string()], "binary skipped, name masked in the file name");
        let body = std::fs::read_to_string(out.join("masked/oncall-成員A.md")).unwrap();
        assert!(!body.contains("王小明") && !body.contains("Alice") && !body.contains("ming@") && body.contains("[email]"), "{body}");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(out.join("masked/oncall-成員A.md")).unwrap().permissions().mode() & 0o777, 0o600);
        let skill = std::fs::read_to_string(out.join("pack/team-practice/SKILL.md")).unwrap();
        assert!(!skill.contains("成員") && !skill.contains("王小明"), "{skill}");
        let research: Research = read_json(&out.join("research.json")).unwrap();
        assert!(research.exemplars.iter().all(|e| e.name.starts_with("成員")));
        assert!(research.exemplars.iter().flat_map(|e| &e.methods).flat_map(|m| &m.sources).all(|s| s.url.starts_with("file:masked/")));
        let auth_rec = std::fs::read_to_string(out.join("authorization.json")).unwrap();
        assert!(!auth_rec.contains("王小明"), "{auth_rec}");
        let ev = std::fs::read_dir(&audit_dir).unwrap().flatten().map(|e| e.path()).find(|p| p.to_string_lossy().contains("audit")).map(|p| if p.is_dir() { std::fs::read_dir(&p).unwrap().flatten().map(|e| std::fs::read_to_string(e.path()).unwrap_or_default()).collect::<String>() } else { std::fs::read_to_string(&p).unwrap_or_default() }).unwrap_or_default();
        assert!(ev.contains("distill.team"), "audit stream: {ev}");
        // purge drops the masked material and the names
        let gone = purge(&out).unwrap();
        assert!(gone.contains(&"masked".to_string()) && gone.contains(&".names.json".to_string()));
    }
}
