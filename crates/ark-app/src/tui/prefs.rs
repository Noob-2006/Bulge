//! Terminal display preferences shared by `ark tui`, `ark chat` and the slash commands
//! that change them (Hermes `display.*` in config.yaml): `<config_dir>/ui.json`.
//!
//! Keys: `skin`, `battery`, `indicator`, `statusbar`, `tips`, `bell_on_complete`,
//! `bell_on_prompt`, `dock`, `pet.{enabled,slug,scale,render_mode,unicode_cols}`.

use ark_kernel::config::Paths;
use serde_json::{json, Value};
use std::path::PathBuf;

pub fn path(paths: &Paths) -> PathBuf {
    paths.config_dir.join("ui.json")
}

pub fn load(paths: &Paths) -> Value {
    std::fs::read_to_string(path(paths)).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()).filter(Value::is_object).unwrap_or_else(|| json!({}))
}

/// Dotted lookup (`pet.slug`).
pub fn get(v: &Value, key: &str) -> Value {
    let mut cur = v;
    for part in key.split('.') {
        match cur.get(part) {
            Some(n) => cur = n,
            None => return Value::Null,
        }
    }
    cur.clone()
}

pub fn get_bool(v: &Value, key: &str, default: bool) -> bool {
    match get(v, key) {
        Value::Bool(b) => b,
        Value::String(s) => matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Value::Number(n) => n.as_f64().unwrap_or(0.0) != 0.0,
        _ => default,
    }
}

pub fn get_str(v: &Value, key: &str, default: &str) -> String {
    get(v, key).as_str().map(str::trim).filter(|s| !s.is_empty()).unwrap_or(default).to_string()
}

/// Write several dotted keys at once (null removes a key).
pub fn set_many(paths: &Paths, kv: &[(&str, Value)]) -> Result<Value, String> {
    let mut all = load(paths);
    for (key, val) in kv {
        let parts: Vec<&str> = key.split('.').collect();
        let mut cur = &mut all;
        for p in &parts[..parts.len() - 1] {
            if !cur.get(*p).is_some_and(Value::is_object) {
                cur[*p] = json!({});
            }
            cur = cur.get_mut(*p).expect("just inserted");
        }
        let last = parts[parts.len() - 1];
        if val.is_null() {
            if let Some(o) = cur.as_object_mut() {
                o.remove(last);
            }
        } else {
            cur[last] = val.clone();
        }
    }
    std::fs::create_dir_all(&paths.config_dir).map_err(|e| e.to_string())?;
    ark_kernel::util::atomic_write(&path(paths), serde_json::to_string_pretty(&all).unwrap_or_default().as_bytes()).map_err(|e| e.to_string())?;
    Ok(all)
}

pub fn set(paths: &Paths, key: &str, val: Value) -> Result<Value, String> {
    set_many(paths, &[(key, val)])
}

/// `on|off|toggle|""` against the current boolean.
pub fn parse_toggle(arg: &str, current: bool) -> Option<bool> {
    match arg.trim().to_ascii_lowercase().as_str() {
        "" | "toggle" => Some(!current),
        "on" | "true" | "yes" | "1" => Some(true),
        "off" | "false" | "no" | "0" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) fn test_paths(tag: &str) -> Paths {
    // Removed when the test's thread ends (ark_core::tmp::scratch).
    let root = ark_core::tmp::scratch(&format!("ark-tuiprefs-{tag}"));
    let p = Paths { data: root.join("data"), config_dir: root.join("config"), runtime: root.join("run") };
    std::fs::create_dir_all(&p.config_dir).unwrap();
    std::fs::create_dir_all(&p.data).unwrap();
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotted_set_get_and_toggle() {
        let p = test_paths("prefs");
        set(&p, "pet.slug", json!("boba")).unwrap();
        set(&p, "battery", json!(true)).unwrap();
        let v = load(&p);
        assert_eq!(get_str(&v, "pet.slug", ""), "boba");
        assert!(get_bool(&v, "battery", false));
        assert!(!get_bool(&v, "pet.enabled", false));
        set(&p, "pet.slug", Value::Null).unwrap();
        assert_eq!(get(&load(&p), "pet.slug"), Value::Null);
        assert_eq!(parse_toggle("", true), Some(false));
        assert_eq!(parse_toggle("on", false), Some(true));
        assert_eq!(parse_toggle("maybe", false), None);
    }
}
