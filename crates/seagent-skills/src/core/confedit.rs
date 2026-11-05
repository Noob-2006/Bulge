//! Small edits to the user config (`config.toml`): set / remove one table at a dotted path,
//! validated by re-loading before the file is replaced. Used by plugin and MCP installs,
//! `seagent skills config` (enable/disable) and `/plugins enable|disable`.

use seagent_kernel::config::{Config, Paths};

fn read(paths: &Paths) -> Result<toml::Table, String> {
    match std::fs::read_to_string(paths.user_config()) {
        Ok(t) => t.parse::<toml::Table>().map_err(|e| format!("{}: {e}", paths.user_config().display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(toml::Table::new()),
        Err(e) => Err(e.to_string()),
    }
}

fn write(paths: &Paths, t: &toml::Table) -> Result<(), String> {
    let text = toml::to_string_pretty(t).map_err(|e| e.to_string())?;
    let tmp = paths.config_dir.join(".config.toml.check");
    std::fs::create_dir_all(&paths.config_dir).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, &text).map_err(|e| e.to_string())?;
    let ok = Config::load(Some(&tmp), None, &[]);
    let _ = std::fs::remove_file(&tmp);
    ok.map_err(|e| format!("refusing to write an invalid config: {e}"))?;
    seagent_kernel::util::atomic_write(&paths.user_config(), text.as_bytes()).map_err(|e| e.to_string())
}

/// Set `path` (e.g. `["plugins", "foo"]`) to `value`, creating parent tables.
pub fn set(paths: &Paths, path: &[&str], value: toml::Value) -> Result<(), String> {
    let mut t = read(paths)?;
    let mut cur = &mut t;
    for k in &path[..path.len() - 1] {
        cur = cur.entry(k.to_string()).or_insert_with(|| toml::Value::Table(toml::Table::new())).as_table_mut().ok_or_else(|| format!("`{k}` is not a table"))?;
    }
    cur.insert(path[path.len() - 1].to_string(), value);
    write(paths, &t)
}

/// Remove `path`; Ok(false) when absent.
pub fn remove(paths: &Paths, path: &[&str]) -> Result<bool, String> {
    let mut t = read(paths)?;
    let mut cur = &mut t;
    for k in &path[..path.len() - 1] {
        match cur.get_mut(*k).and_then(|v| v.as_table_mut()) {
            Some(x) => cur = x,
            None => return Ok(false),
        }
    }
    let hit = cur.remove(path[path.len() - 1]).is_some();
    if hit {
        write(paths, &t)?;
    }
    Ok(hit)
}

pub fn get(paths: &Paths, path: &[&str]) -> Option<toml::Value> {
    let t = read(paths).ok()?;
    let mut cur = toml::Value::Table(t);
    for k in path {
        cur = cur.get(k)?.clone();
    }
    Some(cur)
}
