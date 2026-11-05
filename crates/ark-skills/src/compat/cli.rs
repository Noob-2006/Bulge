//! `ark skills compat scan|import` — find OpenClaw / Hermes / Claude Code material in a
//! directory tree, say what ark can do with each item, and import it.
//!
//! Import targets are the ones ark already uses: skills → `<data>/skills/<name>/`,
//! plugin shims → `<data>/plugins/<id>/`, MCP servers → `[mcp.<name>]` (and plugin
//! processes → `[plugins.<id>]`) via [`crate::core::confedit`], the same path
//! `ark plugins install` takes. `--dry-run` prints the same plan without writing.

use super::skill::{self, SkillImport};
use crate::core::confedit;
use ark_kernel::config::{Config, Paths};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub const USAGE: &str = "usage: ark skills compat scan <dir> [--json] | import <dir> [--dry-run] [--json]";

/// One thing found on disk, with what ark can do about it.
#[derive(Debug, Clone)]
pub struct Item {
    /// `skill` | `plugin` | `mcp`.
    pub kind: String,
    /// `openclaw` | `hermes` | `claude-code` | `ark` | `plain`.
    pub idiom: String,
    pub id: String,
    pub path: PathBuf,
    /// `direct` (usable as is) | `convert` (needs a shim / a rewrite) | `unusable`.
    pub status: String,
    pub reason: String,
    pub warnings: Vec<String>,
    /// The normalized skill, when this item is one.
    skill: Option<SkillImport>,
    /// The imported plugin/MCP, when this item is one.
    import: Option<ark_plugin::compat::Imported>,
}

impl Item {
    fn to_json(&self) -> Value {
        json!({
            "kind": self.kind,
            "idiom": self.idiom,
            "id": self.id,
            "path": self.path.display().to_string(),
            "status": self.status,
            "reason": self.reason,
            "warnings": self.warnings,
        })
    }

    fn line(&self) -> String {
        let mut s = format!("{:<28} {:<11} {:<8} {}", self.id, format!("{}/{}", self.kind, self.idiom), self.status, self.reason);
        for w in &self.warnings {
            s.push_str(&format!("\n    ! {w}"));
        }
        s
    }
}

pub fn run(cfg: &Config, paths: &Paths, ws: &Path, argv: &[String]) -> Result<String, String> {
    let _ = (cfg, ws);
    let args: Vec<String> = argv.iter().filter(|a| a.as_str() != "compat").cloned().collect();
    let flag = |f: &str| args.iter().any(|a| a == f);
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let sub = positional.first().map(|s| s.as_str()).unwrap_or("scan");
    let dir = positional.get(1).map(|s| PathBuf::from(s.as_str())).ok_or_else(|| USAGE.to_string())?;
    let dir = dir.canonicalize().map_err(|e| format!("{}: {e}", dir.display()))?;
    if !dir.is_dir() {
        return Err(format!("{}: not a directory", dir.display()));
    }
    match sub {
        "scan" | "list" => Ok(scan_text(&scan(&dir), flag("--json"))),
        "import" | "apply" => import(paths, &dir, flag("--dry-run"), flag("--json")),
        other => Err(format!("unknown compat action `{other}`; {USAGE}")),
    }
}

fn scan_text(items: &[Item], json_out: bool) -> String {
    if json_out {
        return serde_json::to_string_pretty(&Value::Array(items.iter().map(Item::to_json).collect())).unwrap_or_default();
    }
    let counts = counts(items);
    let mut out = items.iter().map(Item::line).collect::<Vec<_>>().join("\n");
    if out.is_empty() {
        out.push_str("nothing to import");
    }
    format!("{out}\n\n{}\n{}", summary(&counts), legend())
}

fn counts(items: &[Item]) -> [usize; 3] {
    let mut c = [0usize; 3];
    for i in items {
        match i.status.as_str() {
            "direct" => c[0] += 1,
            "convert" => c[1] += 1,
            _ => c[2] += 1,
        }
    }
    c
}

fn summary(c: &[usize; 3]) -> String {
    if c.iter().all(|n| *n == 0) {
        return String::new();
    }
    format!("{} found: {} direct, {} need conversion, {} unusable", c[0] + c[1] + c[2], c[0], c[1], c[2])
}

fn legend() -> &'static str {
    "direct = usable as is · convert = imported through a shim/rewrite · unusable = no ark equivalent (see the reasons)"
}

fn import(paths: &Paths, dir: &Path, dry: bool, json_out: bool) -> Result<String, String> {
    let items = scan(dir);
    let mut lines: Vec<String> = Vec::new();
    let mut report: Vec<Value> = Vec::new();
    for it in &items {
        if it.status == "unusable" {
            lines.push(format!("skip   {:<24} {} ({})", it.id, it.reason, it.kind));
            report.push(json!({"id": it.id, "kind": it.kind, "action": "skipped", "reason": it.reason}));
            continue;
        }
        let res = import_one(paths, it, dry);
        match res {
            Ok((action, path)) => {
                lines.push(format!("{:<6} {:<24} {}", if dry { "plan" } else { "ok" }, it.id, action));
                report.push(json!({"id": it.id, "kind": it.kind, "status": it.status, "action": action, "path": path}));
            }
            Err(e) => {
                lines.push(format!("fail   {:<24} {e}", it.id));
                report.push(json!({"id": it.id, "kind": it.kind, "action": "failed", "error": e}));
            }
        }
    }
    if json_out {
        return Ok(serde_json::to_string_pretty(&json!({"dry_run": dry, "items": report})).unwrap_or_default());
    }
    let failed = report.iter().filter(|r| r["action"] == "failed").count();
    let mut out = lines.join("\n");
    out.push_str(&format!("\n\n{}", summary(&counts(&items))));
    if dry {
        out.push_str("\n(dry run: nothing written)");
    }
    if failed > 0 {
        out.push_str(&format!("\n{failed} item(s) failed"));
    }
    Ok(out)
}

/// One item → its ark home. Returns a human-readable description of what was done.
fn import_one(paths: &Paths, it: &Item, dry: bool) -> Result<(String, String), String> {
    match it.kind.as_str() {
        "skill" => {
            let imp = it.skill.as_ref().ok_or("skill was not normalized")?;
            let dest = paths.data.join("skills").join(&imp.name);
            if dry {
                return Ok(("skill → {}".to_string(), dest.display().to_string()));
            }
            fs::create_dir_all(dest.parent().unwrap_or(&paths.data)).map_err(|e| e.to_string())?;
            skill::write(imp, &dest)?;
            // Supporting files (references/, templates/, scripts/) travel with the skill.
            copy_tree(&it.path, &dest, 0)?;
            Ok((format!("skill → {}", dest.display()), dest.display().to_string()))
        }
        "plugin" => {
            let imp = it.import.as_ref().ok_or("plugin was not imported")?;
            let root = paths.data.join("plugins");
            let rendered = ark_plugin::compat::config_toml(imp, &root.join(&imp.id));
            if dry {
                let mut what = format!("shim → {}/{}/", root.display(), imp.id);
                if rendered.is_some() {
                    what.push_str(&format!(" + [plugins.{}]", imp.id));
                }
                for (n, _) in &imp.mcp_servers {
                    what.push_str(&format!(" + [mcp.{n}]"));
                }
                for s in &imp.skills {
                    what.push_str(&format!(" + skill from {}", s.display()));
                }
                return Ok((what, root.display().to_string()));
            }
            let files = ark_plugin::compat::write_imported(imp, &root)?;
            let mut what = Vec::new();
            for f in &files {
                what.push(format!("wrote {}", f.display()));
            }
            if let Some(text) = rendered {
                let t: toml::Table = text.parse().map_err(|e| format!("generated [plugins.{}]: {e}", imp.id))?;
                let table = t.get("plugins").and_then(|p| p.get(&imp.id)).and_then(|v| v.as_table()).cloned().ok_or("generated fragment has no [plugins.<id>]")?;
                confedit::set(paths, &["plugins", &imp.id], toml::Value::Table(table))?;
                what.push(format!("[plugins.{}]", imp.id));
            }
            for (n, t) in &imp.mcp_servers {
                if confedit::get(paths, &["mcp", n]).is_none() {
                    confedit::set(paths, &["mcp", n], toml::Value::Table(t.clone()))?;
                    what.push(format!("[mcp.{n}]"));
                }
            }
            let skills: Vec<String> = imp.skills.iter().filter_map(|s| import_skill_dir(paths, s).ok()).collect();
            what.extend(skills);
            Ok((what.join(", "), root.join(&imp.id).display().to_string()))
        }
        "mcp" => {
            let imp = it.import.as_ref().ok_or("mcp entry was not imported")?;
            let mut what = Vec::new();
            for (n, t) in &imp.mcp_servers {
                if dry {
                    what.push(format!("[mcp.{n}]"));
                    continue;
                }
                if confedit::get(paths, &["mcp", n]).is_some() {
                    what.push(format!("[mcp.{n}] already configured"));
                    continue;
                }
                confedit::set(paths, &["mcp", n], toml::Value::Table(t.clone()))?;
                what.push(format!("[mcp.{n}]"));
            }
            Ok((what.join(", "), it.path.display().to_string()))
        }
        other => Err(format!("unknown item kind `{other}`")),
    }
}

fn import_skill_dir(paths: &Paths, dir: &Path) -> Result<String, String> {
    let imp = skill::from_dir(dir)?;
    let dest = paths.data.join("skills").join(&imp.name);
    skill::write(&imp, &dest)?;
    copy_tree(dir, &dest, 0)?;
    Ok(format!("skill {} → {}", imp.name, dest.display()))
}

/// Recursive copy of a skill directory (depth-limited, no VCS/tooling trees).
fn copy_tree(src: &Path, dst: &Path, depth: usize) -> Result<(), String> {
    if depth > 6 {
        return Ok(());
    }
    let rd = fs::read_dir(src).map_err(|e| format!("{}: {e}", src.display()))?;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if matches!(name.as_str(), "node_modules" | "__pycache__" | ".git" | ".venv" | "target") {
            continue;
        }
        let from = e.path();
        let to = dst.join(&name);
        let ty = e.file_type().map_err(|e| e.to_string())?;
        if ty.is_dir() {
            fs::create_dir_all(&to).map_err(|e| format!("{}: {e}", to.display()))?;
            copy_tree(&from, &to, depth + 1)?;
        } else if ty.is_file() && name != "SKILL.md" {
            fs::copy(&from, &to).map_err(|e| format!("{}: {e}", to.display()))?;
        }
    }
    Ok(())
}

/// Walk `root` and classify everything ark knows how to import.
pub fn scan(root: &Path) -> Vec<Item> {
    let mut items = Vec::new();
    walk(root, 0, &mut items);
    items.sort_by(|a, b| a.path.cmp(&b.path));
    items
}

fn walk(dir: &Path, depth: usize, out: &mut Vec<Item>) {
    if depth > 6 {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut subdirs = Vec::new();
    for e in rd.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if name.starts_with('.') && depth > 0 {
            continue;
        }
        if matches!(name.as_str(), "node_modules" | "target" | "__pycache__" | "dist-runtime") {
            continue;
        }
        if p.is_dir() {
            subdirs.push(p);
        }
    }
    // A plugin/MCP manifest claims the directory (its skills are still scanned below).
    if let Some(item) = classify(dir) {
        out.push(item);
    } else if dir.join("SKILL.md").is_file() {
        out.push(classify_skill(dir));
    }
    for d in subdirs {
        walk(&d, depth + 1, out);
    }
}

fn classify_skill(dir: &Path) -> Item {
    let path_disp = dir.to_path_buf();
    let idiom = fs::read_to_string(dir.join("SKILL.md")).ok().and_then(|t| skill::variant_of(&t)).unwrap_or("plain").to_string();
    match skill::from_dir(dir) {
        Ok(imp) => {
            let changed = !imp.mapped.is_empty() || !imp.dropped.is_empty();
            Item {
                kind: "skill".into(),
                idiom,
                id: imp.name.clone(),
                path: path_disp,
                status: if changed { "convert" } else { "direct" }.into(),
                reason: if changed {
                    format!("rewritten for ark ({})", imp.mapped.iter().chain(imp.dropped.iter()).cloned().collect::<Vec<_>>().join(", "))
                } else {
                    "ark format already".into()
                },
                warnings: imp.warnings.clone(),
                skill: Some(imp),
                import: None,
            }
        }
        Err(e) => Item { kind: "skill".into(), idiom: "unknown".into(), id: dir.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(), path: path_disp, status: "unusable".into(), reason: e, warnings: vec![], skill: None, import: None },
    }
}

fn classify(dir: &Path) -> Option<Item> {
    let idiom = ark_plugin::compat::detect(dir)?;
    let id_dir = dir.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    match ark_plugin::compat::import(dir) {
        Ok(imp) => {
            let is_mcp = imp.kind == "declarative" && !imp.mcp_servers.is_empty();
            let status = if is_mcp {
                "direct"
            } else if imp.shim.is_some() || !imp.mcp_servers.is_empty() || !imp.skills.is_empty() {
                "convert"
            } else {
                "unusable"
            };
            let reason = match (status, is_mcp) {
                ("direct", _) => format!("MCP server {}", imp.mcp_servers.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(", ")),
                ("convert", _) => format!("{} plugin → shim {} + {}", imp.kind, imp.shim.as_ref().map(|s| s.file.as_str()).unwrap_or("-"), if imp.mcp_servers.is_empty() { "metadata".into() } else { "MCP tables".to_string() }),
                _ => "nothing runnable: declarations only".to_string(),
            };
            let kind = if is_mcp { "mcp" } else { "plugin" };
            Some(Item { kind: kind.into(), idiom: idiom.into(), id: imp.id.clone(), path: dir.to_path_buf(), status: status.into(), reason, warnings: imp.warnings.clone(), skill: None, import: Some(imp) })
        }
        Err(e) => Some(Item { kind: "plugin".into(), idiom: idiom.into(), id: id_dir, path: dir.to_path_buf(), status: "unusable".into(), reason: e, warnings: vec![], skill: None, import: None }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = ark_core::tmp::scratch_path(format!("ark-compat-cli-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn paths_at(d: &Path) -> Paths {
        Paths { data: d.join("data"), config_dir: d.join("cfg"), runtime: d.join("run") }
    }

    fn tree(d: &Path) -> PathBuf {
        let root = d.join("tree");
        let skill = root.join("skills").join("notes");
        fs::create_dir_all(skill.join("references")).unwrap();
        fs::write(skill.join("SKILL.md"), "---\nname: notes\ndescription: Keep notes\nmetadata: {\"openclaw\": {\"requires\": {\"bins\": [\"rg\"]}}}\nallowed-tools: [read]\n---\n# Notes\n").unwrap();
        fs::write(skill.join("references/deep.md"), "deep").unwrap();
        fs::create_dir_all(root.join("oc")).unwrap();
        fs::write(root.join("oc/openclaw.plugin.json"), "{\"id\":\"demo\",\"name\":\"Demo\",\"description\":\"d\"}").unwrap();
        fs::create_dir_all(root.join("mcp")).unwrap();
        fs::write(root.join("mcp/manifest.yaml"), "name: demo-mcp\ntransport:\n  type: http\n  url: https://mcp.example.com/mcp\nauth:\n  type: oauth\n").unwrap();
        fs::write(root.join("mcp/broken.yaml"), "x").unwrap();
        root
    }

    #[test]
    fn compat_cli_scan_classifies_and_reports() {
        let d = tmp("scan");
        let root = tree(&d);
        let items = scan(&root);
        let by = |id: &str| items.iter().find(|i| i.id == id).unwrap_or_else(|| panic!("no item {id}: {items:#?}"));
        assert_eq!(by("notes").kind, "skill");
        assert_eq!(by("notes").status, "convert", "the OpenClaw requires block is hoisted");
        assert_eq!(by("demo").kind, "plugin");
        assert_eq!(by("demo").status, "unusable", "manifest only: declarations, nothing runs");
        assert_eq!(by("demo-mcp").kind, "mcp");
        assert_eq!(by("demo-mcp").status, "direct");
        let text = run(&Config::default(), &paths_at(&d), &d, &["compat".into(), "scan".into(), root.display().to_string()]).unwrap();
        assert!(text.contains("notes") && text.contains("direct = usable as is"), "{text}");
        let js = run(&Config::default(), &paths_at(&d), &d, &["compat".into(), "scan".into(), root.display().to_string(), "--json".into()]).unwrap();
        let v: Value = serde_json::from_str(&js).unwrap();
        assert!(v.as_array().map(|a| a.len()).unwrap_or(0) >= 3, "{js}");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn compat_cli_import_dry_run_writes_nothing_then_imports_through_confedit() {
        let d = tmp("import");
        let root = tree(&d);
        let p = paths_at(&d);
        let dry = run(&Config::default(), &p, &d, &["compat".into(), "import".into(), root.display().to_string(), "--dry-run".into()]).unwrap();
        assert!(dry.contains("dry run: nothing written"), "{dry}");
        assert!(!p.data.join("skills/notes/SKILL.md").exists());
        assert!(!p.user_config().exists());
        let out = run(&Config::default(), &p, &d, &["compat".into(), "import".into(), root.display().to_string()]).unwrap();
        assert!(out.contains("ok"), "{out}");
        // Skill: normalized SKILL.md plus the supporting file.
        let sk = p.data.join("skills/notes");
        let text = fs::read_to_string(sk.join("SKILL.md")).unwrap();
        assert!(text.contains("requires") && !text.contains("allowed-tools"), "{text}");
        assert_eq!(fs::read_to_string(sk.join("references/deep.md")).unwrap(), "deep");
        // MCP: written through core::confedit, so it is valid ark config.
        let cfg = fs::read_to_string(p.user_config()).unwrap();
        assert!(cfg.contains("[mcp.demo-mcp]") && cfg.contains("auth = \"oauth\""), "{cfg}");
        let _ = fs::remove_dir_all(&d);
    }

    /// The scan over the real OpenClaw tree: every extension + its skills is classified.
    #[test]
    fn compat_cli_scans_the_real_openclaw_tree() {
        let root = Path::new("/home/noob/openclaw/dist/extensions");
        if !root.is_dir() {
            eprintln!("skipping: no OpenClaw checkout");
            return;
        }
        let items = scan(root);
        let mut by_status = std::collections::BTreeMap::new();
        let mut by_kind = std::collections::BTreeMap::new();
        for i in &items {
            *by_status.entry(i.status.clone()).or_insert(0usize) += 1;
            *by_kind.entry(format!("{}/{}", i.kind, i.idiom)).or_insert(0usize) += 1;
        }
        let plugins = items.iter().filter(|i| i.kind == "plugin").count();
        let skills = items.iter().filter(|i| i.kind == "skill").count();
        println!("openclaw tree: {} items ({} plugins, {} skills): {:?}", items.len(), plugins, skills, by_status);
        for (k, n) in &by_kind {
            println!("  {k}: {n}");
        }
        assert!(plugins >= 150, "expected the whole extension set, got {plugins}");
        assert!(skills >= 10, "extension skills are found too, got {skills}");
        assert!(!items.iter().any(|i| i.status == "unusable" && i.kind == "plugin" && i.reason.contains("panicked")), "no panic paths");
    }

    /// `ark skills compat …` reaches this module through `hub::cli`'s dispatch.
    #[test]
    fn compat_cli_is_dispatched_by_the_skills_cli() {
        let d = tmp("dispatch");
        let root = tree(&d);
        let p = paths_at(&d);
        let cfg = Config::default();
        let c = crate::hub::cli::Ctx { cfg: &cfg, paths: &p, ws: &d, ask: None };
        let out = crate::hub::cli::run(&c, &["compat".into(), "scan".into(), root.display().to_string()]).unwrap();
        assert!(out.contains("notes") && out.contains("demo-mcp"), "{out}");
        assert!(!out.contains("unknown `ark skills` subcommand"), "{out}");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn compat_cli_rejects_a_missing_directory() {
        let d = tmp("missing");
        let e = run(&Config::default(), &paths_at(&d), &d, &["compat".into(), "scan".into(), d.join("nope").display().to_string()]).unwrap_err();
        assert!(e.contains("nope"), "{e}");
        let e = run(&Config::default(), &paths_at(&d), &d, &["compat".into()]).unwrap_err();
        assert!(e.contains("usage"), "{e}");
        let _ = fs::remove_dir_all(&d);
    }
}
