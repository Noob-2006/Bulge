//! Board metadata (`board.json`) and lifecycle: create, list, archive/delete, rename.
//! The directory slug is the identity; `board.json` is display metadata and the
//! marker that a directory holds a board (an archived slug keeps a tombstone).

use super::{board_dir, boards_root, current_board, kanban_home, normalize_slug, now, store, DEFAULT_BOARD};
use crate::util::atomic_write;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Orchestration {
    pub auto_decompose: Option<bool>,
    pub auto_decompose_per_dispatch: Option<u32>,
    pub default_assignee: Option<String>,
    pub orchestrator_profile: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkspaceSpec {
    pub kind: String,
    pub path: Option<String>,
    pub branch: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct BoardMeta {
    pub slug: String,
    pub name: String,
    pub description: String,
    pub icon: String,
    pub color: String,
    pub default_workdir: Option<String>,
    pub created_at: Option<i64>,
    pub archived: bool,
    /// Workboard: `cards` (default) or `sessions` (rule-based session columns). Permanent.
    pub kind: String,
    pub automation_job_id: Option<String>,
    pub orchestration: Orchestration,
    pub default_workspace: Option<WorkspaceSpec>,
    /// Sessions-board spec (`columns`, `scope`) when `kind == "sessions"`.
    pub sessions: Option<Value>,
}

/// Optional fields for create/update; `None` keeps the stored value.
#[derive(Debug, Clone, Default)]
pub struct MetaPatch {
    pub name: Option<String>,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub default_workdir: Option<String>,
    pub archived: Option<bool>,
    pub kind: Option<String>,
    pub automation_job_id: Option<String>,
    pub orchestration: Option<Orchestration>,
    pub default_workspace: Option<WorkspaceSpec>,
    pub sessions: Option<Value>,
}

/// `atm10-server` -> `Atm10 Server`.
pub fn display_name(slug: &str) -> String {
    let s: Vec<String> = slug.replace('_', "-").split('-').filter(|p| !p.is_empty()).map(|p| {
        let mut c = p.chars();
        c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
    }).collect();
    if s.is_empty() { slug.to_string() } else { s.join(" ") }
}

fn meta_path(data: &Path, slug: &str) -> std::path::PathBuf {
    board_dir(data, slug).join("board.json")
}

pub fn board_exists(data: &Path, slug: &str) -> bool {
    slug == DEFAULT_BOARD || meta_path(data, slug).exists()
}

/// `board.json` merged over defaults; never fails (a broken file yields defaults).
pub fn read_meta(data: &Path, slug: &str) -> BoardMeta {
    let mut m: BoardMeta = std::fs::read_to_string(meta_path(data, slug)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    m.slug = slug.to_string();
    if m.name.trim().is_empty() {
        m.name = display_name(slug);
    }
    if m.kind.is_empty() {
        m.kind = "cards".into();
    }
    m
}

pub fn write_meta(data: &Path, slug: &str, p: MetaPatch) -> Result<BoardMeta, String> {
    let mut m = read_meta(data, slug);
    if let Some(n) = p.name {
        m.name = if n.trim().is_empty() { display_name(slug) } else { n.trim().to_string() };
    }
    if let Some(v) = p.description {
        m.description = v;
    }
    if let Some(v) = p.icon {
        m.icon = v;
    }
    if let Some(v) = p.color {
        m.color = v;
    }
    if let Some(v) = p.default_workdir {
        m.default_workdir = Some(v).filter(|s| !s.is_empty());
    }
    if let Some(v) = p.archived {
        m.archived = v;
    }
    if let Some(k) = p.kind {
        if !matches!(k.as_str(), "cards" | "sessions") {
            return Err("board kind must be cards or sessions".into());
        }
        if meta_path(data, slug).exists() && m.kind != k {
            return Err(format!("board {slug:?} is a {} board; kind cannot change after creation", m.kind));
        }
        m.kind = k;
    }
    if let Some(v) = p.automation_job_id {
        m.automation_job_id = Some(v).filter(|s| !s.is_empty());
    }
    if let Some(v) = p.orchestration {
        m.orchestration = v;
    }
    if let Some(v) = p.default_workspace {
        m.default_workspace = Some(v);
    }
    if let Some(v) = p.sessions {
        m.sessions = Some(v);
    }
    if m.created_at.is_none() {
        m.created_at = Some(now());
    }
    let text = serde_json::to_string_pretty(&m).map_err(|e| e.to_string())?;
    atomic_write(&meta_path(data, slug), text.as_bytes()).map_err(|e| e.to_string())?;
    Ok(m)
}

/// `mkdir -p` semantics: an existing board returns its (updated) metadata; an archived
/// tombstone at the slug is revived as a fresh board.
pub fn create_board(data: &Path, slug: &str, mut p: MetaPatch) -> Result<BoardMeta, String> {
    let slug = normalize_slug(Some(slug))?.ok_or("slug is required")?;
    p.archived = Some(false);
    let m = write_meta(data, &slug, p)?;
    store::with_board(data, &slug, |_| Ok(()))?;
    if m.kind == "sessions" && m.sessions.is_none() {
        return write_meta(data, &slug, MetaPatch { sessions: Some(super::sessions_board::default_spec()), ..Default::default() });
    }
    Ok(m)
}

/// `default` first (always present), then every board directory holding `board.json`.
pub fn list_boards(data: &Path, include_archived: bool) -> Vec<BoardMeta> {
    let mut out = vec![read_meta(data, DEFAULT_BOARD)];
    let mut names: Vec<String> = std::fs::read_dir(boards_root(data)).map(|rd| rd.flatten().filter(|e| e.path().is_dir()).filter_map(|e| e.file_name().into_string().ok()).collect()).unwrap_or_default();
    names.sort_by_key(|n| n.to_lowercase());
    for n in names {
        let Ok(Some(slug)) = normalize_slug(Some(&n)) else { continue };
        if slug == DEFAULT_BOARD || slug != n || !meta_path(data, &slug).exists() {
            continue;
        }
        let m = read_meta(data, &slug);
        if m.archived && !include_archived {
            continue;
        }
        out.push(m);
    }
    out
}

pub struct Removed {
    pub slug: String,
    pub action: &'static str,
    pub new_path: String,
}

/// Archive (move to `boards/_archived/<slug>-<ts>/`, leaving a tombstone) or delete.
pub fn remove_board(data: &Path, slug: &str, archive: bool) -> Result<Removed, String> {
    let slug = normalize_slug(Some(slug))?.ok_or("slug is required")?;
    if slug == DEFAULT_BOARD {
        return Err("the 'default' board cannot be removed".into());
    }
    let d = board_dir(data, &slug);
    if !d.exists() {
        return Err(format!("board {slug:?} does not exist"));
    }
    if current_board(data) == slug {
        let _ = std::fs::remove_file(kanban_home(data).join("current"));
    }
    if archive {
        let prior = read_meta(data, &slug);
        let root = boards_root(data).join("_archived");
        std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        let ts = now();
        let mut target = root.join(format!("{slug}-{ts}"));
        let mut n = 1;
        while target.exists() {
            target = root.join(format!("{slug}-{ts}-{n}"));
            n += 1;
        }
        std::fs::rename(&d, &target).map_err(|e| e.to_string())?;
        write_meta(data, &slug, MetaPatch { name: Some(prior.name), description: Some(prior.description), icon: Some(prior.icon), color: Some(prior.color), archived: Some(true), kind: Some(prior.kind), ..Default::default() })?;
        return Ok(Removed { slug, action: "archived", new_path: target.display().to_string() });
    }
    std::fs::remove_dir_all(&d).map_err(|e| e.to_string())?;
    Ok(Removed { slug, action: "deleted", new_path: String::new() })
}

/// `{status: count}` for a board (empty when it has no data yet).
pub fn task_counts(data: &Path, slug: &str) -> std::collections::BTreeMap<String, u64> {
    let mut m = std::collections::BTreeMap::new();
    if let Ok(b) = store::read_board(data, slug) {
        for t in &b.tasks {
            *m.entry(t.status.clone()).or_insert(0) += 1;
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_list_rename_archive_delete() {
        let d = super::super::testutil::data();
        assert_eq!(list_boards(&d, false).len(), 1, "default always listed");
        let m = create_board(&d, "atm10-server", MetaPatch { description: Some("mods".into()), ..Default::default() }).unwrap();
        assert_eq!(m.name, "Atm10 Server");
        assert_eq!(m.kind, "cards");
        assert!(board_exists(&d, "atm10-server"));
        let m = write_meta(&d, "atm10-server", MetaPatch { name: Some("Minecraft".into()), ..Default::default() }).unwrap();
        assert_eq!(m.name, "Minecraft");
        assert_eq!(m.description, "mods", "unmentioned fields preserved");
        assert!(write_meta(&d, "atm10-server", MetaPatch { kind: Some("sessions".into()), ..Default::default() }).is_err(), "kind is permanent");
        std::fs::create_dir_all(boards_root(&d).join("junk")).unwrap();
        assert_eq!(list_boards(&d, false).iter().map(|b| b.slug.as_str()).collect::<Vec<_>>(), ["default", "atm10-server"]);
        super::super::set_current_board(&d, "atm10-server").unwrap();
        let r = remove_board(&d, "atm10-server", true).unwrap();
        assert_eq!(r.action, "archived");
        assert_eq!(current_board(&d), "default", "removing the current board reverts to default");
        assert!(read_meta(&d, "atm10-server").archived, "tombstone left behind");
        assert_eq!(list_boards(&d, false).len(), 1);
        assert_eq!(list_boards(&d, true).len(), 2);
        assert!(remove_board(&d, "default", false).is_err());
        let m = create_board(&d, "atm10-server", MetaPatch::default()).unwrap();
        assert!(!m.archived, "explicit create revives an archived slug");
        assert_eq!(remove_board(&d, "atm10-server", false).unwrap().action, "deleted");
        assert!(!board_exists(&d, "atm10-server"));
        let s = create_board(&d, "chat", MetaPatch { kind: Some("sessions".into()), ..Default::default() }).unwrap();
        assert!(s.sessions.is_some(), "sessions boards start with the default columns");
    }
}
