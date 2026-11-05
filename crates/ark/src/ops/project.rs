//! Projects (Hermes `hermes project`, `projects_db.py`): human-named workspaces that
//! span several folders, one primary. Per profile, in `<data>/projects.json`
//! (`{"active": id, "projects": [...]}`), written atomically.
//!
//! `ark project create <name> [folders…] [--slug S] [--primary P] [--description D]
//! [--icon I] [--color C] [--board B] [--use]`, `list [--all]`, `show`, `add-folder
//! <p> <path> [--label L] [--as-primary]`, `remove-folder`, `rename`, `set-primary`,
//! `use [p]`, `archive`, `restore`, `bind-board <p> [board]`, `rm`, `which [path]`.

use crate::args::Args;
use crate::R;
use ark_kernel::config::Paths;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const COMMANDS: &[&str] = &["project", "projects"];
pub const VALUE_FLAGS: &[&str] = &["slug", "primary", "description", "icon", "color", "board", "label"];
pub const BOOL_FLAGS: &[&str] = &["use", "as-primary"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Folder {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default)]
    pub is_primary: bool,
    #[serde(default)]
    pub added_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Project {
    pub id: String,
    pub slug: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub board_slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_path: Option<String>,
    pub created_at: u64,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub folders: Vec<Folder>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Db {
    #[serde(default)]
    pub active: Option<String>,
    #[serde(default)]
    pub projects: Vec<Project>,
}

pub fn db_path(paths: &Paths) -> PathBuf {
    paths.data.join("projects.json")
}

pub fn load(paths: &Paths) -> Db {
    std::fs::read_to_string(db_path(paths)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

pub fn save(paths: &Paths, db: &Db) -> Result<(), String> {
    let p = db_path(paths);
    std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
    ark_kernel::util::atomic_write(&p, serde_json::to_string_pretty(db).map_err(|e| e.to_string())?.as_bytes()).map_err(|e| e.to_string())
}

fn now() -> u64 {
    ark_kernel::event::now_ms() / 1000
}

fn slugify(name: &str) -> String {
    let mut s = String::new();
    for c in name.trim().to_lowercase().chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            s.push(c);
        } else if !s.ends_with('-') {
            s.push('-');
        }
    }
    let s: String = s.trim_matches(|c| c == '-' || c == '_').chars().take(64).collect();
    let s = s.trim_matches(|c| c == '-' || c == '_').to_string();
    if s.is_empty() { "project".into() } else { s }
}

pub fn normalize_slug(slug: &str) -> Result<String, String> {
    let s = slug.trim().to_lowercase();
    let ok = !s.is_empty() && s.len() <= 64 && s.as_bytes()[0].is_ascii_alphanumeric() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if !ok {
        return Err(format!("invalid project slug {slug:?}: must be 1-64 chars, lowercase alphanumerics / hyphens / underscores, not starting with '-' or '_'"));
    }
    Ok(s)
}

/// Absolute, `~`-expanded, no trailing separator.
pub fn norm_path(p: &str) -> String {
    let p = p.trim();
    let expanded = match p.strip_prefix("~/") {
        Some(rest) => std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default().join(rest),
        None if p == "~" => std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default(),
        None => PathBuf::from(p),
    };
    let abs = if expanded.is_absolute() { expanded } else { std::env::current_dir().unwrap_or_default().join(expanded) };
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            c => out.push(c),
        }
    }
    let s = out.to_string_lossy().to_string();
    if s.len() > 1 { s.trim_end_matches('/').to_string() } else { s }
}

impl Db {
    pub fn get(&self, ident: &str) -> Option<&Project> {
        let l = ident.to_lowercase();
        self.projects.iter().find(|p| p.id == ident).or_else(|| self.projects.iter().find(|p| p.slug == l))
    }
    fn get_mut(&mut self, ident: &str) -> Result<&mut Project, String> {
        let id = self.get(ident).map(|p| p.id.clone()).ok_or_else(|| format!("no such project: {ident}"))?;
        Ok(self.projects.iter_mut().find(|p| p.id == id).unwrap())
    }
    fn unique_slug(&self, cand: &str) -> String {
        let mut slug = cand.to_string();
        // Upstream `_unique_slug` numbers the first duplicate `-2` (n starts at 1, bumped first).
        let mut n = 1;
        while self.projects.iter().any(|p| p.slug == slug) {
            n += 1;
            let suffix = format!("-{n}");
            slug = format!("{}{suffix}", cand.chars().take(64 - suffix.len()).collect::<String>().trim_end_matches(['-', '_']));
            n += 1;
        }
        slug
    }
    pub fn find_by_primary(&self, path: &str) -> Option<&Project> {
        let n = norm_path(path);
        self.projects.iter().find(|p| !p.archived && p.primary_path.as_deref() == Some(n.as_str()))
    }
    /// The project owning `path` (deepest folder containing it).
    pub fn for_path(&self, path: &str) -> Option<&Project> {
        let n = norm_path(path);
        self.projects
            .iter()
            .filter(|p| !p.archived)
            .filter_map(|p| p.folders.iter().filter(|f| Path::new(&n).starts_with(&f.path)).map(|f| f.path.len()).max().map(|l| (l, p)))
            .max_by_key(|(l, _)| *l)
            .map(|(_, p)| p)
    }
}

pub struct NewProject<'a> {
    pub name: &'a str,
    pub slug: Option<&'a str>,
    pub folders: Vec<String>,
    pub primary: Option<&'a str>,
    pub description: Option<&'a str>,
    pub icon: Option<&'a str>,
    pub color: Option<&'a str>,
    pub board: Option<&'a str>,
}

pub fn create(db: &mut Db, n: &NewProject) -> Result<String, String> {
    let name = n.name.trim();
    if name.is_empty() {
        return Err("project name must not be empty".into());
    }
    let cand = match n.slug {
        Some(s) => normalize_slug(s)?,
        None => slugify(name),
    };
    let mut folders: Vec<String> = vec![];
    for f in n.folders.iter().map(|f| norm_path(f)).filter(|f| !f.is_empty()) {
        if !folders.contains(&f) {
            folders.push(f);
        }
    }
    let primary = n.primary.map(norm_path);
    if let Some(p) = &primary {
        if !folders.contains(p) {
            folders.insert(0, p.clone());
        }
    }
    let primary = primary.or_else(|| folders.first().cloned());
    if let Some(e) = primary.as_deref().and_then(|p| db.find_by_primary(p)) {
        return Err(format!("folder already belongs to project '{}' ({}); switch to it instead of creating a duplicate", e.slug, e.id));
    }
    let id = format!("p_{}", ark_kernel::util::random_hex(4));
    let t = now();
    let board = n.board.map(normalize_slug).transpose()?;
    let slug = db.unique_slug(&cand);
    db.projects.push(Project {
        id: id.clone(),
        slug,
        name: name.into(),
        description: n.description.map(String::from),
        icon: n.icon.map(String::from),
        color: n.color.map(String::from),
        board_slug: board,
        primary_path: primary.clone(),
        created_at: t,
        archived: false,
        folders: folders.into_iter().map(|p| Folder { is_primary: Some(&p) == primary.as_ref(), path: p, label: None, added_at: t }).collect(),
    });
    Ok(id)
}

fn set_primary_in(p: &mut Project, path: &str) {
    for f in &mut p.folders {
        f.is_primary = f.path == path;
    }
    p.primary_path = Some(path.to_string());
}

pub fn add_folder(db: &mut Db, ident: &str, path: &str, label: Option<&str>, primary: bool) -> Result<String, String> {
    let n = norm_path(path);
    if path.trim().is_empty() {
        return Err("folder path must not be empty".into());
    }
    let p = db.get_mut(ident)?;
    match p.folders.iter_mut().find(|f| f.path == n) {
        Some(f) => {
            if label.is_some() {
                f.label = label.map(String::from);
            }
        }
        None => p.folders.push(Folder { path: n.clone(), label: label.map(String::from), is_primary: false, added_at: now() }),
    }
    if primary || !p.folders.iter().any(|f| f.is_primary) {
        set_primary_in(p, &n);
    }
    Ok(n)
}

pub fn remove_folder(db: &mut Db, ident: &str, path: &str) -> Result<bool, String> {
    let n = norm_path(path);
    let p = db.get_mut(ident)?;
    let Some(i) = p.folders.iter().position(|f| f.path == n) else { return Ok(false) };
    let was = p.folders.remove(i).is_primary;
    if was {
        match p.folders.iter().min_by_key(|f| f.added_at).map(|f| f.path.clone()) {
            Some(next) => set_primary_in(p, &next),
            None => p.primary_path = None,
        }
    }
    Ok(true)
}

pub fn set_primary(db: &mut Db, ident: &str, path: &str) -> Result<bool, String> {
    let n = norm_path(path);
    let p = db.get_mut(ident)?;
    if !p.folders.iter().any(|f| f.path == n) {
        return Ok(false);
    }
    set_primary_in(p, &n);
    Ok(true)
}

fn describe(p: &Project) -> String {
    let mut o = format!("{}  [{}]{}\n  name:    {}\n", p.slug, p.id, if p.archived { " (archived)" } else { "" }, p.name);
    for (label, v) in [("about", &p.description), ("board", &p.board_slug), ("primary", &p.primary_path)] {
        if let Some(v) = v.as_ref().filter(|v| !v.is_empty()) {
            o.push_str(&format!("  {label}:{}{v}\n", " ".repeat(8 - label.len())));
        }
    }
    if !p.folders.is_empty() {
        o.push_str("  folders:\n");
        for f in &p.folders {
            o.push_str(&format!("   {} {}{}\n", if f.is_primary { " *" } else { "  " }, f.path, f.label.as_ref().map(|l| format!(" ({l})")).unwrap_or_default()));
        }
    }
    o
}

pub fn list_text(db: &Db, all: bool) -> String {
    let v: Vec<&Project> = db.projects.iter().filter(|p| all || !p.archived).collect();
    if v.is_empty() {
        return "No projects yet. Create one with `ark project create <name>`.\n".into();
    }
    v.iter()
        .map(|p| format!("{} {:<24} {}{}  [{} folder(s)]\n", if db.active.as_deref() == Some(p.id.as_str()) { "*" } else { " " }, p.slug, p.name, if p.archived { " (archived)" } else { "" }, p.folders.len()))
        .collect()
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if !COMMANDS.contains(&cmd) {
        return None;
    }
    Some((|| -> R {
        let paths = Paths::from_env();
        let mut db = load(&paths);
        let sub = a.pos(0).unwrap_or("list");
        let out: String = match sub {
            "list" | "ls" => {
                if a.flag("json") {
                    println!("{}", serde_json::to_string_pretty(&db).unwrap_or_default());
                    return Ok(0);
                }
                print!("{}", list_text(&db, a.flag("all")));
                return Ok(0);
            }
            "create" | "new" => {
                let name = a.need(1, "name")?;
                let n = NewProject { name, slug: a.val("slug"), folders: a.pos.iter().skip(2).cloned().collect(), primary: a.val("primary"), description: a.val("description"), icon: a.val("icon"), color: a.val("color"), board: a.val("board") };
                let id = create(&mut db, &n).map_err(|e| format!("project: {e}"))?;
                if a.flag("use") {
                    db.active = Some(id.clone());
                }
                save(&paths, &db)?;
                let p = db.get(&id).unwrap();
                format!("Created project {} ({id})\n{}", p.slug, describe(p).trim_end())
            }
            "show" => {
                let p = db.get(a.need(1, "project")?).ok_or_else(|| format!("project: no such project: {}", a.pos(1).unwrap_or("")))?;
                if a.flag("json") {
                    println!("{}", serde_json::to_string_pretty(p).unwrap_or_default());
                    return Ok(0);
                }
                describe(p).trim_end().to_string()
            }
            "which" => {
                let path = a.pos(1).map(String::from).unwrap_or_else(|| std::env::current_dir().unwrap_or_default().to_string_lossy().to_string());
                match db.for_path(&path) {
                    Some(p) => p.slug.clone(),
                    None => return Err(format!("project: no project owns {path}").into()),
                }
            }
            "add-folder" => {
                let id = a.need(1, "project")?;
                let path = add_folder(&mut db, id, a.need(2, "path")?, a.val("label"), a.flag("as-primary"))?;
                save(&paths, &db)?;
                format!("Added {path} to {}", db.get(id).unwrap().slug)
            }
            "remove-folder" => {
                let id = a.need(1, "project")?;
                let path = a.need(2, "path")?;
                if !remove_folder(&mut db, id, path)? {
                    return Err(format!("project: folder not in project: {path}").into());
                }
                save(&paths, &db)?;
                format!("Removed {path} from {}", db.get(id).unwrap().slug)
            }
            "rename" => {
                let id = a.need(1, "project")?;
                let name = a.rest(2);
                if name.trim().is_empty() {
                    return Err("project: project name must not be empty".into());
                }
                let p = db.get_mut(id)?;
                p.name = name.trim().into();
                let slug = p.slug.clone();
                save(&paths, &db)?;
                format!("Renamed {slug} -> {}", name.trim())
            }
            "set-primary" => {
                let id = a.need(1, "project")?;
                let path = a.need(2, "path")?;
                if !set_primary(&mut db, id, path)? {
                    return Err(format!("project: '{path}' is not a folder of {id}; add it first with `ark project add-folder`.").into());
                }
                save(&paths, &db)?;
                format!("Set primary of {} -> {path}", db.get(id).unwrap().slug)
            }
            "use" => match a.pos(1) {
                None => {
                    db.active = None;
                    save(&paths, &db)?;
                    "Cleared active project".into()
                }
                Some(id) => {
                    let p = db.get(id).ok_or_else(|| format!("project: no such project: {id}"))?.clone();
                    db.active = Some(p.id);
                    save(&paths, &db)?;
                    format!("Active project: {}", p.slug)
                }
            },
            "archive" | "restore" => {
                let p = db.get_mut(a.need(1, "project")?)?;
                p.archived = sub == "archive";
                let slug = p.slug.clone();
                save(&paths, &db)?;
                format!("{} {slug}", if sub == "archive" { "Archived" } else { "Restored" })
            }
            "bind-board" => {
                let board = a.pos(2).unwrap_or("");
                let b = if board.trim().is_empty() { None } else { Some(normalize_slug(board)?) };
                let p = db.get_mut(a.need(1, "project")?)?;
                p.board_slug = b.clone();
                let slug = p.slug.clone();
                save(&paths, &db)?;
                match b {
                    Some(b) => format!("Bound {slug} to board {b}"),
                    None => format!("Unbound board from {slug}"),
                }
            }
            "rm" | "delete" => {
                let id = db.get(a.need(1, "project")?).map(|p| p.id.clone()).ok_or("project: no such project")?;
                if !a.flag("yes") {
                    return crate::usage(format!("deleting project {id} cannot be undone (folders are not touched); rerun with --yes"));
                }
                db.projects.retain(|p| p.id != id);
                if db.active.as_deref() == Some(id.as_str()) {
                    db.active = None;
                }
                save(&paths, &db)?;
                format!("Deleted {id}")
            }
            other => return crate::usage(format!("unknown project action: {other} (create|list|show|which|add-folder|remove-folder|rename|set-primary|use|archive|restore|bind-board|rm)")),
        };
        println!("{out}");
        Ok(0)
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn np<'a>(name: &'a str, folders: &[&str]) -> NewProject<'a> {
        NewProject { name, slug: None, folders: folders.iter().map(|s| s.to_string()).collect(), primary: None, description: None, icon: None, color: None, board: None }
    }

    #[test]
    fn create_folders_primary_and_lookup() {
        let mut db = Db::default();
        let id = create(&mut db, &np("Hermes Agent!", &["/src/a", "/src/b/", "/src/a"])).unwrap();
        let p = db.get(&id).unwrap().clone();
        assert_eq!(p.slug, "hermes-agent");
        assert_eq!(p.folders.len(), 2, "dedup + trailing slash normalised");
        assert_eq!(p.primary_path.as_deref(), Some("/src/a"));
        assert!(db.get("HERMES-AGENT").is_some(), "slug lookup is case-insensitive");
        assert!(create(&mut db, &np("Other", &["/src/a"])).unwrap_err().contains("already belongs"));
        let id2 = create(&mut db, &np("Hermes Agent", &[])).unwrap();
        assert_eq!(db.get(&id2).unwrap().slug, "hermes-agent-2", "unique slug (upstream numbers from -2)");
        assert!(normalize_slug("-bad").is_err() && normalize_slug("Ok_1").unwrap() == "ok_1");
        assert_eq!(slugify("  ***  "), "project");

        assert_eq!(add_folder(&mut db, &id, "/src/c", Some("docs"), true).unwrap(), "/src/c");
        assert_eq!(db.get(&id).unwrap().primary_path.as_deref(), Some("/src/c"));
        assert_eq!(db.for_path("/src/b/deep/file.rs").unwrap().id, id);
        assert!(remove_folder(&mut db, &id, "/src/c").unwrap());
        assert_eq!(db.get(&id).unwrap().primary_path.as_deref(), Some("/src/a"), "primary repointed to the oldest folder");
        assert!(!remove_folder(&mut db, &id, "/nope").unwrap());
        assert!(!set_primary(&mut db, &id, "/nope").unwrap());
        assert!(set_primary(&mut db, &id, "/src/b").unwrap());
        assert!(add_folder(&mut db, "missing", "/x", None, false).unwrap_err().contains("no such project"));
        assert_eq!(norm_path("/a/b/../c/./"), "/a/c");
        db.active = Some(id.clone());
        let t = list_text(&db, false);
        assert!(t.starts_with("* hermes-agent"), "{t}");
        db.get_mut(&id).unwrap().archived = true;
        assert!(!list_text(&db, false).contains("hermes-agent "));
        assert!(list_text(&db, true).contains("(archived)"));
    }

    #[test]
    fn persists_per_profile() {
        let kit = crate::testkit::kit();
        let mut db = load(&kit.paths);
        create(&mut db, &np("X", &["/x"])).unwrap();
        save(&kit.paths, &db).unwrap();
        assert_eq!(load(&kit.paths).projects.len(), 1);
    }

    /// Restores `ARK_HOME` even when an assertion below panics.
    struct EnvHome(Option<std::ffi::OsString>);
    impl Drop for EnvHome {
        fn drop(&mut self) {
            match self.0.take() {
                Some(h) => std::env::set_var("ARK_HOME", h),
                None => std::env::remove_var("ARK_HOME"),
            }
        }
    }

    /// The path `main` takes: `ark project …` → `ops::dispatch` → `project::dispatch`.
    #[test]
    fn dispatch_creates_lists_and_shows() {
        let _env = crate::testkit::env_lock();
        assert!(crate::ops::owns("project"), "project is registered in ops::MODULES");
        assert!(dispatch("storage", &Args::parse(&[]).unwrap(), &[]).is_none(), "other commands fall through");
        let root = std::env::temp_dir().join(format!("ark-proj-{}", ark_kernel::util::random_hex(6)));
        std::fs::create_dir_all(&root).unwrap();
        let prev = std::env::var_os("ARK_HOME");
        std::env::set_var("ARK_HOME", &root);
        let _home = EnvHome(prev);
        let run = |v: &[&str]| -> Result<i32, String> {
            let a = Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>())?;
            dispatch("project", &a, &[]).ok_or_else(|| "project is not dispatched".to_string())?.map_err(|e| e.to_string())
        };
        assert_eq!(run(&["create", "Demo", "/src/demo", "--slug", "demo", "--use"]).unwrap(), 0);
        let db = load(&Paths::from_env());
        let p = &db.projects[0];
        assert_eq!((p.slug.as_str(), p.primary_path.as_deref()), ("demo", Some("/src/demo")));
        assert_eq!(db.active.as_deref(), Some(p.id.as_str()), "--use sets the active project");
        assert_eq!(run(&["list"]).unwrap(), 0);
        assert_eq!(run(&["add-folder", "demo", "/src/other", "--label", "docs"]).unwrap(), 0);
        assert!(load(&Paths::from_env()).projects[0].folders.iter().any(|f| f.label.as_deref() == Some("docs")));
        assert_eq!(run(&["which", "/src/other/x.rs"]).unwrap(), 0);
        assert_eq!(run(&["use", "demo"]).unwrap(), 0);
        assert_eq!(run(&["archive", "demo"]).unwrap(), 0);
        assert!(load(&Paths::from_env()).projects[0].archived);
        assert!(run(&["show", "nope"]).is_err(), "unknown project is an error");
        assert!(run(&["bogus"]).is_err(), "unknown action is an error");
    }
}
