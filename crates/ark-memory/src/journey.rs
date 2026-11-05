//! `ark journey` / learning timeline / memory graph (Hermes hermes_cli/journey.py +
//! agent/learning_graph.py, MIT): learned skills and memory entries as graph nodes on a
//! timeline (oldest first), related-skill and memory→skill lexical edges, a terminal bar
//! chart, `--json`, `list`, `delete <id> --yes` and `edit <id> <text>`.

use crate::util::{self, clip, sha256_hex};
use crate::Host;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub fn fingerprint(entry: &str) -> String {
    sha256_hex(entry.trim().as_bytes())[..12].to_string()
}

fn mtime_secs(p: &Path) -> Option<u64> {
    std::fs::metadata(p).ok()?.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs())
}

pub fn memory_cards(h: &Host) -> Vec<Value> {
    let mut cards = Vec::new();
    for (f, src) in [("MEMORY.md", "memory"), ("USER.md", "profile")] {
        let p = h.memory_dir().join(f);
        let Some(ts) = mtime_secs(&p) else { continue };
        for (i, e) in ark_tools::memory_store::load(&p).unwrap_or_default().iter().enumerate() {
            let first = e.lines().next().unwrap_or("").trim().trim_start_matches("# ").trim().to_string();
            let title = if first.chars().count() > 80 { format!("{}…", clip(&first, 80)) } else { first };
            cards.push(json!({"source": src, "timestamp": ts + i as u64, "title": title, "body": clip(e, 1200), "fingerprint": fingerprint(e)}));
        }
    }
    cards
}

fn node_id(card: &Value, i: usize) -> String {
    format!("memory:{}:{i}:{}", card["source"].as_str().unwrap_or(""), card["fingerprint"].as_str().unwrap_or(""))
}

fn frontmatter(text: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    if let Some(rest) = text.strip_prefix("---\n") {
        if let Some(end) = rest.find("\n---") {
            for l in rest[..end].lines() {
                if let Some((k, v)) = l.split_once(':') {
                    m.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
                }
            }
        }
    }
    m
}

fn walk_skills(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    if depth > 6 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') || name == "node_modules" {
            continue;
        }
        if p.is_dir() {
            walk_skills(&p, out, depth + 1);
        } else if name == "SKILL.md" {
            out.push(p);
        }
    }
}

/// Graph payload. `skill_roots` = (source, dir) with source `base` | `profile` | `external`;
/// usage from `<data>/skills/usage.json` (`{name: {use_count, created_by, state, pinned}}`) when present.
pub fn build(h: &Host, skill_roots: &[(String, PathBuf)]) -> Value {
    let usage = util::read_json(&h.data.join("skills/usage.json"));
    let mut skills: BTreeMap<String, Value> = BTreeMap::new();
    for (source, root) in skill_roots {
        let mut files = Vec::new();
        walk_skills(root, &mut files, 0);
        files.sort();
        for f in files {
            let text = std::fs::read_to_string(&f).unwrap_or_default();
            let fm = frontmatter(&clip(&text, 4000));
            let name = fm.get("name").cloned().unwrap_or_else(|| f.parent().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
            if name.is_empty() || skills.contains_key(&name) {
                continue;
            }
            let rec = usage.as_ref().map(|u| u[&name].clone()).unwrap_or(Value::Null);
            let use_count = rec["use_count"].as_u64().unwrap_or(0);
            let created_by = rec["created_by"].as_str().map(str::to_string);
            let learned = source != "external" && source != "base" && (usage.is_none() || created_by.as_deref().is_some_and(|c| c == "agent" || c == "learn") || use_count > 0);
            if !learned {
                continue;
            }
            let related: Vec<String> = fm.get("related_skills").map(|r| r.trim_matches(['[', ']']).split(',').map(|s| s.trim().trim_matches('"').to_string()).filter(|s| !s.is_empty()).collect()).unwrap_or_default();
            let category = fm.get("category").cloned().unwrap_or_else(|| f.parent().and_then(|p| p.parent()).and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "general".into()));
            skills.insert(name.clone(), json!({"id": name, "label": name, "kind": "skill", "timestamp": rec["last_used_at"].as_u64().or(mtime_secs(&f)), "category": category, "useCount": use_count, "state": rec["state"].as_str().unwrap_or("active"), "createdBy": created_by, "pinned": rec["pinned"].as_bool().unwrap_or(false), "related": related}));
        }
    }
    let mut edges: Vec<(String, String)> = Vec::new();
    for (n, s) in &skills {
        for r in s["related"].as_array().cloned().unwrap_or_default().iter().filter_map(|v| v.as_str()) {
            if skills.contains_key(r) && r != n {
                let e = if n.as_str() < r { (n.clone(), r.to_string()) } else { (r.to_string(), n.clone()) };
                if !edges.contains(&e) {
                    edges.push(e);
                }
            }
        }
    }
    let cards = memory_cards(h);
    let tok = |t: &str| -> BTreeSet<String> { t.to_lowercase().split(|c: char| !c.is_ascii_alphanumeric()).filter(|w| w.len() >= 3).map(str::to_string).collect() };
    let mut mem_edges = 0;
    for (i, c) in cards.iter().enumerate() {
        let text = format!("{}\n{}", c["title"].as_str().unwrap_or(""), c["body"].as_str().unwrap_or("")).to_lowercase();
        let tt = tok(&text);
        let mut scored: Vec<(usize, String)> = skills.keys().map(|n| ((if text.contains(&n.to_lowercase()) { 6 } else { 0 }) + tok(n).intersection(&tt).count(), n.clone())).filter(|(s, _)| *s > 0).collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        for (_, n) in scored.into_iter().take(4) {
            edges.push((node_id(c, i), n));
            mem_edges += 1;
        }
    }
    let mut nodes: Vec<Value> = skills.values().cloned().collect();
    nodes.extend(cards.iter().enumerate().map(|(i, c)| json!({"id": node_id(c, i), "label": c["title"], "kind": "memory", "memorySource": c["source"], "timestamp": c["timestamp"], "category": "memory", "useCount": 0, "state": "active", "createdBy": "memory", "pinned": false})));
    let mut clusters: BTreeMap<String, usize> = BTreeMap::new();
    for n in &nodes {
        *clusters.entry(n["category"].as_str().unwrap_or("general").to_string()).or_default() += 1;
    }
    json!({"nodes": nodes, "edges": edges.iter().map(|(a, b)| json!({"source": a, "target": b})).collect::<Vec<_>>(), "clusters": clusters.iter().map(|(c, n)| json!({"category": c, "count": n})).collect::<Vec<_>>(), "memory": cards, "stats": {"learned_skills": skills.len(), "memory_nodes": cards.len(), "memory_skill_edges": mem_edges, "related_edges": edges.len() - mem_edges}})
}

fn date(ts: Option<u64>) -> String {
    ts.map(|t| util::day_stamp(t * 1000, 0)).unwrap_or_else(|| "????-??-??".into())
}

/// Timeline bar chart by month (oldest at top) up to `reveal` (0..1) of the nodes.
pub fn render(payload: &Value, reveal: f64) -> String {
    let mut nodes: Vec<&Value> = payload["nodes"].as_array().map(|a| a.iter().collect()).unwrap_or_default();
    if nodes.is_empty() {
        return "No learning yet.".into();
    }
    nodes.sort_by_key(|n| n["timestamp"].as_u64().unwrap_or(0));
    let shown = ((nodes.len() as f64 * reveal.clamp(0.0, 1.0)).ceil() as usize).max(1);
    let mut months: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for n in &nodes[..shown] {
        let m = date(n["timestamp"].as_u64())[..7].to_string();
        let e = months.entry(m).or_default();
        if n["kind"] == "memory" {
            e.1 += 1;
        } else {
            e.0 += 1;
        }
    }
    let max = months.values().map(|(a, b)| a + b).max().unwrap_or(1).max(1);
    let mut out = vec![format!("Journey — {} skill(s), {} memory node(s)", payload["stats"]["learned_skills"], payload["stats"]["memory_nodes"])];
    for (m, (s, mm)) in &months {
        let w = 40 * (s + mm) / max;
        let ws = (w * s).checked_div(s + mm).unwrap_or(0);
        out.push(format!("{m} {}{} {s}●  {mm}◆", "█".repeat(ws), "▒".repeat(w - ws)));
    }
    out.push(String::new());
    for n in &nodes[..shown] {
        out.push(format!("{}  {} {}", date(n["timestamp"].as_u64()), if n["kind"] == "memory" { "◆" } else { "●" }, n["label"].as_str().unwrap_or("")));
    }
    out.join("\n")
}

fn memory_node(h: &Host, id: &str) -> Result<(String, String), String> {
    let p: Vec<&str> = id.splitn(4, ':').collect();
    if p.len() != 4 || p[0] != "memory" {
        return Err(format!("not found: {id} (skill nodes are managed with `ark skill`)"));
    }
    let file = if p[1] == "profile" { "user" } else { "memory" };
    let entries = ark_tools::memory_store::load(&ark_tools::memory_store::path_of(&h.data, file)?)?;
    let e = entries.iter().find(|e| fingerprint(e) == p[3]).ok_or_else(|| format!("memory entry {id} changed or was removed; run `ark journey list` again"))?;
    Ok((file.to_string(), e.clone()))
}

fn write_entries(h: &Host, file: &str, entries: &[String]) -> Result<(), String> {
    let p = ark_tools::memory_store::path_of(&h.data, file)?;
    util::write_atomic(&p, entries.join(ark_tools::memory_store::SEP).as_bytes())
}

/// `journey [--json] [--reveal x] | list | delete <id> --yes | edit <id> <text>`.
pub fn run(h: &Host, args: &[String], skill_roots: &[(String, PathBuf)]) -> Result<String, String> {
    let payload = build(h, skill_roots);
    let pos: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let flag = |f: &str| args.iter().any(|a| a == f);
    match pos.first().map(|s| s.as_str()) {
        None => {
            if flag("--json") {
                return Ok(serde_json::to_string_pretty(&payload).unwrap_or_default());
            }
            let reveal = args.iter().position(|a| a == "--reveal").and_then(|i| args.get(i + 1)).and_then(|s| s.parse().ok()).unwrap_or(1.0);
            Ok(render(&payload, reveal))
        }
        Some("list") => {
            let mut nodes: Vec<Value> = payload["nodes"].as_array().cloned().unwrap_or_default();
            if nodes.is_empty() {
                return Ok("No learning yet.".into());
            }
            nodes.sort_by_key(|n| n["timestamp"].as_u64().unwrap_or(0));
            Ok(nodes.iter().map(|n| format!("{}  {} {}  {}", n["id"].as_str().unwrap_or(""), if n["kind"] == "memory" { "◆" } else { "●" }, n["label"].as_str().unwrap_or(""), date(n["timestamp"].as_u64()))).collect::<Vec<_>>().join("\n"))
        }
        Some("delete") => {
            let id = pos.get(1).ok_or("usage: journey delete <id> --yes")?;
            let (file, entry) = memory_node(h, id)?;
            if !flag("--yes") {
                return Err(format!("Delete {:?}? Re-run with --yes to confirm.", clip(&entry, 80)));
            }
            let mut entries = ark_tools::memory_store::load(&ark_tools::memory_store::path_of(&h.data, &file)?)?;
            entries.retain(|e| e != &entry);
            write_entries(h, &file, &entries)?;
            Ok(format!("deleted {id}"))
        }
        Some("edit") => {
            let id = pos.get(1).ok_or("usage: journey edit <id> <new text>")?;
            let text = pos[2..].iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" ");
            if text.trim().is_empty() || text.contains('§') {
                return Err("edit needs the new entry text (without §)".into());
            }
            let (file, entry) = memory_node(h, id)?;
            if text.trim() == entry {
                return Ok("no changes".into());
            }
            let r = ark_tools::memory_store::apply_batch(&h.data, &file, &[json!({"action": "replace", "old": entry, "matched_entry": entry, "text": text.trim()})])?;
            Ok(format!("edited {id}: {r}"))
        }
        Some(other) => Err(format!("unknown `journey {other}`; use list, delete or edit (or --json / --reveal)")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_timeline_and_mutations() {
        let h = crate::test_host("journey", |_| {});
        std::fs::write(h.memory_dir().join("MEMORY.md"), "deploys use the docker-compose skill\n§\nprefers terse answers").unwrap();
        let sk = h.data.join("skills/devops/docker-compose");
        std::fs::create_dir_all(&sk).unwrap();
        std::fs::write(sk.join("SKILL.md"), "---\nname: docker-compose\nrelated_skills: [kubernetes]\n---\n# x").unwrap();
        let roots = vec![("profile".to_string(), h.data.join("skills"))];
        let g = build(&h, &roots);
        assert_eq!(g["stats"]["learned_skills"], 1);
        assert_eq!(g["stats"]["memory_nodes"], 2);
        assert_eq!(g["stats"]["memory_skill_edges"], 1);
        assert_eq!(g["nodes"][0]["category"], "devops");
        let t = run(&h, &[], &roots).unwrap();
        assert!(t.contains("Journey — 1 skill(s), 2 memory node(s)") && t.contains("◆ prefers terse answers"));
        let list = run(&h, &["list".into()], &roots).unwrap();
        let id = list.lines().find(|l| l.contains("terse")).unwrap().split_whitespace().next().unwrap().to_string();
        assert!(run(&h, &["delete".into(), id.clone()], &roots).unwrap_err().contains("--yes"));
        run(&h, &["edit".into(), id.clone(), "prefers".into(), "concise".into(), "answers".into()], &roots).unwrap();
        assert!(run(&h, &["delete".into(), id.clone(), "--yes".into()], &roots).unwrap_err().contains("changed"), "stale fingerprint");
        let list = run(&h, &["list".into()], &roots).unwrap();
        let id = list.lines().find(|l| l.contains("concise")).unwrap().split_whitespace().next().unwrap().to_string();
        run(&h, &["delete".into(), id, "--yes".into()], &roots).unwrap();
        assert_eq!(std::fs::read_to_string(h.memory_dir().join("MEMORY.md")).unwrap(), "deploys use the docker-compose skill");
        assert!(run(&h, &["delete".into(), "docker-compose".into()], &roots).is_err());
        assert!(run(&h, &["--json".into()], &roots).unwrap().contains("\"edges\""));
    }
}
