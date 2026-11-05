//! Ecosystem compatibility: turn an OpenClaw plugin (`openclaw.plugin.json`) or a
//! Hermes plugin / optional-MCP (`plugin.yaml`, `manifest.yaml`) into something seagent
//! can load — a shim process plus a `[plugins.<id>]` fragment, a `[mcp.<name>]`
//! table, the skills to copy and an honest list of what will not work.
//!
//! Everything here is a pure function of the files on disk: no network, no process
//! spawn, no panic on malformed input (`Err` carries the reason). Writing the
//! generated shim is [`write_imported`]; the config edits belong to the caller
//! (`seagent_skills::compat::cli`, which goes through `core::confedit`).
//!
//! Upstreams, read-only: OpenClaw `dist/extensions/*/openclaw.plugin.json`,
//! `src/plugins/*`; Hermes `plugins/**/plugin.yaml`, `optional-mcps/*/manifest.yaml`,
//! `hermes_cli/plugins.py`, `hermes_cli/mcp_catalog.py`.

use std::fs;
use std::path::{Path, PathBuf};

pub mod hermes;
pub mod openclaw;

/// One imported plugin (or MCP entry, or skill set) and everything needed to use it.
#[derive(Debug, Clone)]
pub struct Imported {
    pub id: String,
    pub name: String,
    /// `"openclaw"` | `"hermes"`.
    pub idiom: String,
    pub description: String,
    /// `"declarative"` (manifest only) | `"python"` | `"node"`.
    pub kind: String,
    /// When a process is needed: a complete `[plugins.<id>]` fragment. `{{shim}}`
    /// stands for the installed shim's absolute path ([`SHIM_PLACEHOLDER`]); render
    /// it with [`config_toml`] once the destination is known.
    pub config_toml: Option<String>,
    /// Environment variables the plugin needs. Names only — the fragment references
    /// them as `{{secret:NAME}}`, never as literals.
    pub secrets: Vec<String>,
    /// Skill directories to import alongside (already canonicalized, inside the plugin).
    pub skills: Vec<PathBuf>,
    /// MCP servers the plugin/manifest declares → `[mcp.<name>]`.
    pub mcp_servers: Vec<(String, toml::Table)>,
    /// Declared hooks / tools / commands / providers, human-readable.
    pub capabilities: Vec<String>,
    /// What will not work on seagent, and why.
    pub warnings: Vec<String>,
    pub shim: Option<Shim>,
}

#[derive(Debug, Clone)]
pub struct Shim {
    /// File name written under `dest/<id>/` (`hermes_shim.py`, `openclaw_shim.mjs`).
    pub file: String,
    pub contents: String,
}

/// Replaced by [`config_toml`] with the installed shim path.
pub const SHIM_PLACEHOLDER: &str = "{{shim}}";

/// Which upstream manifest a directory carries.
pub fn detect(dir: &Path) -> Option<&'static str> {
    if dir.join("openclaw.plugin.json").is_file() {
        Some("openclaw")
    } else if dir.join("plugin.yaml").is_file() || dir.join("manifest.yaml").is_file() {
        Some("hermes")
    } else {
        None
    }
}

/// [`detect`] + dispatch.
pub fn import(dir: &Path) -> Result<Imported, String> {
    match detect(dir) {
        Some("openclaw") => import_openclaw(dir),
        Some(_) => import_hermes(dir),
        None => Err(format!("{}: no openclaw.plugin.json, plugin.yaml or manifest.yaml", dir.display())),
    }
}

pub fn import_openclaw(dir: &Path) -> Result<Imported, String> {
    openclaw::import(dir)
}

pub fn import_hermes(dir: &Path) -> Result<Imported, String> {
    hermes::import(dir)
}

/// Hermes `optional-mcps/<name>/manifest.yaml` → the `[mcp.<name>]` table
/// (http/sse transport, `url`, `auth = "oauth"`, headers, env, `exclude_tools`).
pub fn hermes_optional_mcp(manifest: &Path) -> Result<toml::Table, String> {
    hermes::optional_mcp(manifest)
}

/// `source:` / `post_install:` of an optional-MCP manifest — they have no table key
/// of their own, so the caller shows them next to the install.
pub fn hermes_optional_mcp_notes(manifest: &Path) -> Result<Vec<String>, String> {
    hermes::optional_mcp_notes(manifest)
}

/// A name usable as `[plugins.<id>]` / `[mcp.<id>]` and as a directory name.
pub fn sanitize_id(raw: &str) -> String {
    let mut out = String::new();
    for c in raw.trim().chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            out.push(c.to_ascii_lowercase());
        } else {
            out.push('-');
        }
    }
    while out.contains("--") {
        out = out.replace("--", "-");
    }
    while out.contains("__") {
        out = out.replace("__", "-");
    }
    out.trim_matches('-').to_string()
}

/// Render [`Imported::config_toml`] for a shim installed in `shim_dir`.
pub fn config_toml(imp: &Imported, shim_dir: &Path) -> Option<String> {
    let t = imp.config_toml.as_ref()?;
    let path = imp.shim.as_ref().map(|s| shim_dir.join(&s.file));
    let rendered = match path {
        Some(p) => t.replace(SHIM_PLACEHOLDER, &p.display().to_string()),
        None => t.clone(),
    };
    Some(rendered)
}

/// Path components seagent never writes into (keys, agent credentials).
fn forbidden(p: &Path) -> Option<&'static str> {
    const DENY: &[&str] = &[".ssh", ".gnupg", ".aws", ".kube", ".password-store", ".docker"];
    p.components().find_map(|c| DENY.iter().copied().find(|d| c.as_os_str().to_str() == Some(*d)))
}

/// Write the generated shim to `dest/<id>/` (mode 0700, as are the files) and return
/// what was written. Refuses symlinked, out-of-destination and credential paths.
pub fn write_imported(imp: &Imported, dest: &Path) -> Result<Vec<PathBuf>, String> {
    let id = sanitize_id(&imp.id);
    if id.is_empty() {
        return Err("plugin has no usable id".into());
    }
    fs::create_dir_all(dest).map_err(|e| format!("{}: {e}", dest.display()))?;
    let dest = dest.canonicalize().map_err(|e| format!("{}: {e}", dest.display()))?;
    if let Some(d) = forbidden(&dest) {
        return Err(format!("refusing to write shims under `{d}` ({})", dest.display()));
    }
    let dir = dest.join(&id);
    if dir.symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(false) {
        return Err(format!("{}: is a symlink", dir.display()));
    }
    let mut out = Vec::new();
    let Some(shim) = &imp.shim else { return Ok(out) };
    fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let name = Path::new(&shim.file).file_name().and_then(|n| n.to_str()).filter(|n| !n.is_empty()).ok_or_else(|| format!("shim file name `{}` is not a plain name", shim.file))?;
    let path = dir.join(name);
    if forbidden(&path).is_some() {
        return Err(format!("refusing to write {}", path.display()));
    }
    fs::write(&path, shim.contents.as_bytes()).map_err(|e| format!("{}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    out.push(path);
    Ok(out)
}

/// A child of `root` named by a manifest, canonicalized; `None` when it is missing or
/// escapes `root` (`../`, an absolute path, a symlink pointing elsewhere).
pub(crate) fn child_within(root: &Path, rel: &str) -> Option<PathBuf> {
    let rel = rel.trim();
    if rel.is_empty() || Path::new(rel).is_absolute() {
        return None;
    }
    let p = root.join(rel).canonicalize().ok()?;
    if p.starts_with(root) && p != root {
        Some(p)
    } else {
        None
    }
}

/// `[[plugins.<id>]]`-style fragment from a process table.
pub(crate) fn fragment(id: &str, table: toml::Table) -> Result<String, String> {
    let mut plugins = toml::Table::new();
    plugins.insert(id.to_string(), toml::Value::Table(table));
    let mut root = toml::Table::new();
    root.insert("plugins".into(), toml::Value::Table(plugins));
    toml::to_string(&root).map_err(|e| e.to_string())
}

/// `env = { NAME = "{{secret:NAME}}" }` for the secrets a plugin declares.
pub(crate) fn secret_env(names: &[String]) -> toml::Table {
    let mut t = toml::Table::new();
    for n in names {
        if !n.trim().is_empty() {
            t.insert(n.trim().to_string(), toml::Value::String(format!("{{{{secret:{}}}}}", n.trim())));
        }
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = seagent_core::tmp::scratch_path(format!("seagent-compat-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn compat_sanitize_id_never_produces_an_invalid_key() {
        assert_eq!(sanitize_id("Hermes Agent/Excel2"), "hermes-agent-excel2");
        assert_eq!(sanitize_id("@openclaw/x_y"), "openclaw-x_y");
        assert_eq!(sanitize_id("a__b"), "a-b");
        assert_eq!(sanitize_id("  .. "), "");
    }

    #[test]
    fn compat_detect_and_import_dispatch() {
        let d = tmp("detect");
        fs::create_dir_all(&d).unwrap();
        assert_eq!(detect(&d), None);
        assert!(import(&d).unwrap_err().contains("no openclaw.plugin.json"));
        fs::write(d.join("plugin.yaml"), "name: x\n").unwrap();
        assert_eq!(detect(&d), Some("hermes"));
        let imp = import(&d).unwrap();
        assert_eq!((imp.id.as_str(), imp.idiom.as_str(), imp.kind.as_str()), ("x", "hermes", "declarative"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn compat_write_imported_creates_0700_dir_and_files() {
        let d = tmp("write");
        let imp = Imported {
            id: "demo".into(),
            name: "Demo".into(),
            idiom: "hermes".into(),
            description: String::new(),
            kind: "python".into(),
            config_toml: Some("[plugins.demo]\ncommand = \"python3\"\nargs = [\"{{shim}}\"]\n".into()),
            secrets: vec![],
            skills: vec![],
            mcp_servers: vec![],
            capabilities: vec![],
            warnings: vec![],
            shim: Some(Shim { file: "hermes_shim.py".into(), contents: "print('hi')\n".into() }),
        };
        let out = write_imported(&imp, &d.join("plugins")).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], d.join("plugins").canonicalize().unwrap().join("demo/hermes_shim.py"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(out[0].parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
            assert_eq!(fs::metadata(&out[0]).unwrap().permissions().mode() & 0o777, 0o700);
        }
        let tomltext = config_toml(&imp, out[0].parent().unwrap()).unwrap();
        assert!(tomltext.contains(out[0].to_str().unwrap()), "{tomltext}");
        assert!(!tomltext.contains(SHIM_PLACEHOLDER));
        // A shim file name cannot climb out of the target directory.
        let bad = Imported { shim: Some(Shim { file: "../escape.py".into(), contents: String::new() }), ..imp };
        let _ = fs::remove_dir_all(&d);
        assert!(write_imported(&bad, &d).is_ok(), "file_name() strips the parent component");
        assert!(!d.join("escape.py").exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn compat_write_imported_refuses_credential_dirs() {
        let d = tmp("write-deny");
        fs::create_dir_all(d.join(".ssh")).unwrap();
        let imp = Imported {
            id: "demo".into(),
            name: "Demo".into(),
            idiom: "hermes".into(),
            description: String::new(),
            kind: "python".into(),
            config_toml: None,
            secrets: vec![],
            skills: vec![],
            mcp_servers: vec![],
            capabilities: vec![],
            warnings: vec![],
            shim: Some(Shim { file: "s.py".into(), contents: String::new() }),
        };
        assert!(write_imported(&imp, &d.join(".ssh")).unwrap_err().contains(".ssh"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn compat_child_within_rejects_escapes() {
        let d = tmp("within");
        fs::create_dir_all(d.join("skills")).unwrap();
        let root = d.canonicalize().unwrap();
        assert!(child_within(&root, "skills").is_some());
        assert!(child_within(&root, "../etc").is_none());
        assert!(child_within(&root, "/etc").is_none());
        assert!(child_within(&root, "missing").is_none());
        let _ = fs::remove_dir_all(&d);
    }
}
