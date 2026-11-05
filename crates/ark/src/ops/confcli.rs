//! Config editing (Hermes `config set/unset/edit/check/migrate`, OpenClaw
//! `config set/patch/unset/file/schema` and `configure`).
//!
//! Every write: compute the new table, try a line-preserving edit of the user
//! file (comments survive), fall back to a full rewrite when the line edit would
//! not produce exactly that table, validate with `Config::load`, keep a timestamped
//! backup (last `KEEP_BACKUPS`), then replace the file atomically with mode 0600.

use crate::args::Args;
use crate::{usage, Fail, R};
use ark_kernel::config::{project_config, Config, Paths};
use serde_json::{json, Value};
use std::io::{BufRead, IsTerminal, Read};
use std::path::{Path, PathBuf};

pub const COMMANDS: &[&str] = &["configure"];
pub const VALUE_FLAGS: &[&str] = &[];
pub const BOOL_FLAGS: &[&str] = &["apply", "no-backup", "strict"];

const KEEP_BACKUPS: usize = 10;
/// Bumped when a migration below is added.
pub const CONFIG_VERSION: i64 = 2;

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    let paths = Paths::from_env();
    match (cmd, a.pos(0).unwrap_or("")) {
        ("configure", _) => Some(configure(&paths, a)),
        ("config", "set") => Some((|| {
            let key = a.need(1, "key")?;
            let val = a.rest(2);
            if val.is_empty() {
                return usage("missing <value>");
            }
            println!("{}", set(&paths, key, &val)?);
            Ok(0)
        })()),
        ("config", "unset") => Some((|| {
            println!("{}", unset(&paths, a.need(1, "key")?)?);
            Ok(0)
        })()),
        ("config", "patch") => Some((|| {
            let src = match a.pos(1) {
                Some("-") | None => {
                    let mut s = String::new();
                    std::io::stdin().read_to_string(&mut s).map_err(|e| e.to_string())?;
                    s
                }
                Some(p) if Path::new(p).exists() => std::fs::read_to_string(p).map_err(|e| e.to_string())?,
                Some(_) => a.rest(1),
            };
            println!("{}", patch(&paths, &src)?);
            Ok(0)
        })()),
        ("config", "edit") => Some(edit(&paths)),
        ("config", "file") => {
            println!("{}", paths.user_config().display());
            Some(Ok(0))
        }
        ("config", "env-path") => {
            println!("{}", paths.config_dir.join(".env").display());
            Some(Ok(0))
        }
        ("config", "schema") => {
            println!("{}", serde_json::to_string_pretty(&schema()).unwrap_or_default());
            Some(Ok(0))
        }
        ("config", "check") => Some(check(&paths, a)),
        ("config", "migrate") => Some((|| {
            let (text, notes) = migrate_text(&read_user(&paths)?)?;
            for n in &notes {
                println!("• {n}");
            }
            if notes.is_empty() {
                println!("config is current (version {CONFIG_VERSION})");
                return Ok(0);
            }
            if !a.flag("apply") {
                println!("dry run — re-run with --apply to rewrite {} (a backup is kept)", paths.user_config().display());
                return Ok(0);
            }
            write_validated(&paths, &text, !a.flag("no-backup"))?;
            println!("migrated {}", paths.user_config().display());
            Ok(0)
        })()),
        ("config", "backups") => Some({
            let b = backups(&paths);
            if b.is_empty() {
                println!("no config backups");
            }
            for (i, p) in b.iter().enumerate() {
                println!("{:>2}  {}", i + 1, p.display());
            }
            Ok(0)
        }),
        ("config", "restore") => Some((|| {
            let n: usize = a.need(1, "n")?.parse().map_err(|_| Fail::Usage("expected a backup number from `ark config backups`".into()))?;
            let b = backups(&paths);
            let src = b.get(n.wrapping_sub(1)).ok_or("no such backup")?;
            let text = std::fs::read_to_string(src).map_err(|e| e.to_string())?;
            write_validated(&paths, &text, true)?;
            println!("restored {} from {}", paths.user_config().display(), src.display());
            Ok(0)
        })()),
        _ => None,
    }
}

// ───────────── value parsing / paths ─────────────

/// `--set`-style value: a TOML literal when it parses (numbers, bools, arrays, inline
/// tables, quoted strings), otherwise the raw text as a string.
pub fn parse_value(s: &str) -> toml::Value {
    format!("v = {s}").parse::<toml::Table>().ok().and_then(|mut t| t.remove("v")).unwrap_or_else(|| toml::Value::String(s.to_string()))
}

fn split_key(key: &str) -> Result<Vec<String>, String> {
    let parts: Vec<String> = key.split('.').map(|p| p.trim().to_string()).collect();
    if parts.iter().any(|p| p.is_empty() || !p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')) {
        return Err(format!("bad key `{key}` (use dotted names like model.default)"));
    }
    Ok(parts)
}

fn set_in(t: &mut toml::Table, parts: &[String], v: toml::Value) -> Result<(), String> {
    let mut cur = t;
    for p in &parts[..parts.len() - 1] {
        let e = cur.entry(p.clone()).or_insert_with(|| toml::Value::Table(toml::Table::new()));
        cur = e.as_table_mut().ok_or_else(|| format!("`{p}` is not a table"))?;
    }
    cur.insert(parts[parts.len() - 1].clone(), v);
    Ok(())
}

fn unset_in(t: &mut toml::Table, parts: &[String]) -> bool {
    let mut cur = t;
    for p in &parts[..parts.len() - 1] {
        match cur.get_mut(p).and_then(|v| v.as_table_mut()) {
            Some(n) => cur = n,
            None => return false,
        }
    }
    cur.remove(&parts[parts.len() - 1]).is_some()
}

pub fn to_table(c: &Config) -> toml::Table {
    match toml::Value::try_from(c) {
        Ok(toml::Value::Table(t)) => t,
        _ => toml::Table::new(),
    }
}

pub fn get_in<'a>(t: &'a toml::Table, key: &str) -> Option<&'a toml::Value> {
    let mut parts = key.split('.');
    let mut v = t.get(parts.next()?)?;
    for p in parts {
        v = v.get(p)?;
    }
    Some(v)
}

// ───────────── line-preserving edits ─────────────

fn header_of(line: &str) -> Option<String> {
    let l = line.trim();
    if l.starts_with("[[") {
        return Some(format!("[[{}", l.trim_start_matches('[').split(']').next()?.trim()));
    }
    l.strip_prefix('[').and_then(|r| r.split(']').next()).map(|s| s.split('.').map(|x| x.trim().trim_matches('"')).collect::<Vec<_>>().join("."))
}

fn key_of(line: &str) -> Option<String> {
    let l = line.trim_start();
    if l.starts_with('#') || l.starts_with('[') {
        return None;
    }
    let (k, _) = l.split_once('=')?;
    Some(k.trim().trim_matches('"').to_string())
}

/// Replace or insert `key = value` in the textual file. Only single-line values are
/// edited in place; anything else is left to the full rewrite.
fn line_edit(text: &str, parts: &[String], value: Option<&toml::Value>) -> Option<String> {
    let (table, leaf) = (parts[..parts.len() - 1].join("."), parts[parts.len() - 1].as_str());
    let lines: Vec<&str> = text.lines().collect();
    let mut section = String::new();
    let mut section_start: Option<usize> = if table.is_empty() { Some(0) } else { None };
    let mut section_end = if table.is_empty() { lines.iter().position(|l| header_of(l).is_some()).unwrap_or(lines.len()) } else { lines.len() };
    let mut found: Option<usize> = None;
    for (i, l) in lines.iter().enumerate() {
        if let Some(h) = header_of(l) {
            if section_start.is_some() && section == table && found.is_none() && i < section_end {
                section_end = i;
            }
            section = h;
            if section == table && section_start.is_none() {
                section_start = Some(i + 1);
            }
            continue;
        }
        if (section == table || (table.is_empty() && section.is_empty())) && key_of(l).as_deref() == Some(leaf) {
            found = Some(i);
        }
    }
    let rendered = value.map(|v| format!("{leaf} = {}", toml::Value::to_string(v)));
    let mut out: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
    match (found, rendered) {
        (Some(i), Some(r)) => {
            let rest = lines[i].split_once('=')?.1;
            // Keep a trailing comment when the old value was a simple scalar.
            let comment = rest.find(" #").filter(|_| !rest.contains('"') && !rest.contains('\'')).map(|p| &rest[p..]).unwrap_or("");
            format!("v = {}", rest.trim()).parse::<toml::Table>().ok()?;
            let indent: String = lines[i].chars().take_while(|c| c.is_whitespace()).collect();
            out[i] = format!("{indent}{r}{comment}");
        }
        (Some(i), None) => {
            format!("v = {}", lines[i].split_once('=')?.1.trim()).parse::<toml::Table>().ok()?;
            out.remove(i);
        }
        (None, Some(r)) => match section_start {
            Some(start) => {
                let mut at = section_end.max(start);
                while at > start && out[at - 1].trim().is_empty() {
                    at -= 1;
                }
                out.insert(at, r);
            }
            None => {
                if out.last().is_some_and(|l| !l.trim().is_empty()) {
                    out.push(String::new());
                }
                out.push(format!("[{table}]"));
                out.push(r);
            }
        },
        (None, None) => {}
    }
    let mut s = out.join("\n");
    s.push('\n');
    Some(s)
}

// ───────────── reading / writing ─────────────

fn read_user(paths: &Paths) -> Result<String, String> {
    match std::fs::read_to_string(paths.user_config()) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(format!("{}: {e}", paths.user_config().display())),
    }
}

fn backup_dir(paths: &Paths) -> PathBuf {
    paths.config_dir.join("backups")
}

/// Newest first.
pub fn backups(paths: &Paths) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(backup_dir(paths)).map(|r| r.flatten().map(|e| e.path()).filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("config.toml."))).collect()).unwrap_or_default();
    v.sort();
    v.reverse();
    v
}

/// Validate `text` as the user config and install it (backup + atomic, 0600).
pub fn write_validated(paths: &Paths, text: &str, backup: bool) -> Result<(), String> {
    std::fs::create_dir_all(&paths.config_dir).map_err(|e| e.to_string())?;
    let tmp = paths.config_dir.join(format!(".config.toml.new-{}", std::process::id()));
    std::fs::write(&tmp, text).map_err(|e| e.to_string())?;
    let check = Config::load(Some(&tmp), None, &[]);
    if let Err(e) = check {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("refusing to write an invalid config: {e}"));
    }
    let _ = std::fs::remove_file(&tmp);
    let p = paths.user_config();
    if backup && p.exists() {
        let dir = backup_dir(paths);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        std::fs::copy(&p, dir.join(format!("config.toml.{ts}"))).map_err(|e| e.to_string())?;
        for old in backups(paths).into_iter().skip(KEEP_BACKUPS) {
            let _ = std::fs::remove_file(old);
        }
    }
    ark_kernel::util::atomic_write(&p, text.as_bytes()).map_err(|e| e.to_string())?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    Ok(())
}

/// Edit one key (`None` = remove). Returns the new file text without writing it.
pub fn edited_text(text: &str, key: &str, value: Option<toml::Value>) -> Result<String, String> {
    let parts = split_key(key)?;
    let mut table: toml::Table = text.parse().map_err(|e| format!("current config does not parse: {e}"))?;
    match &value {
        Some(v) => set_in(&mut table, &parts, v.clone())?,
        None => {
            if !unset_in(&mut table, &parts) {
                return Err(format!("`{key}` is not set in the user config"));
            }
        }
    }
    if let Some(t) = line_edit(text, &parts, value.as_ref()) {
        if t.parse::<toml::Table>().ok().as_ref() == Some(&table) {
            return Ok(t);
        }
    }
    toml::to_string_pretty(&table).map_err(|e| e.to_string())
}

pub fn set(paths: &Paths, key: &str, value: &str) -> Result<String, String> {
    let v = parse_value(value.trim());
    let text = edited_text(&read_user(paths)?, key, Some(v.clone()))?;
    write_validated(paths, &text, true)?;
    Ok(format!("{key} = {v} (in {})", paths.user_config().display()))
}

pub fn unset(paths: &Paths, key: &str) -> Result<String, String> {
    let text = edited_text(&read_user(paths)?, key, None)?;
    write_validated(paths, &text, true)?;
    Ok(format!("removed {key} from {}", paths.user_config().display()))
}

/// Effective value (defaults → user → project), as TOML text.
pub fn get(paths: &Paths, ws: &Path, key: &str) -> Result<String, String> {
    let cfg = Config::load(Some(&paths.user_config()), Some(&project_config(ws)), &[])?;
    let t = to_table(&cfg);
    match get_in(&t, key) {
        Some(toml::Value::String(s)) => Ok(s.clone()),
        Some(v) => Ok(v.to_string()),
        None => Err(format!("no key `{key}`")),
    }
}

/// JSON merge patch (RFC 7396; `null` deletes) or a TOML snippet (deep-merged).
pub fn patch(paths: &Paths, src: &str) -> Result<String, String> {
    let mut table: toml::Table = read_user(paths)?.parse().map_err(|e| format!("current config does not parse: {e}"))?;
    let src = src.trim();
    if src.starts_with('{') {
        let p: Value = serde_json::from_str(src).map_err(|e| format!("patch JSON: {e}"))?;
        let mut cur = serde_json::to_value(&table).map_err(|e| e.to_string())?;
        merge_patch(&mut cur, &p);
        table = serde_json::from_value(cur).map_err(|e| format!("patch result is not valid TOML data: {e}"))?;
    } else {
        let t: toml::Table = src.parse().map_err(|e| format!("patch TOML: {e}"))?;
        merge_toml(&mut table, t);
    }
    let text = toml::to_string_pretty(&table).map_err(|e| e.to_string())?;
    write_validated(paths, &text, true)?;
    Ok(format!("patched {}", paths.user_config().display()))
}

pub fn merge_patch(target: &mut Value, patch: &Value) {
    match patch {
        Value::Object(p) => {
            if !target.is_object() {
                *target = json!({});
            }
            let t = target.as_object_mut().unwrap();
            for (k, v) in p {
                if v.is_null() {
                    t.remove(k);
                } else {
                    merge_patch(t.entry(k.clone()).or_insert(Value::Null), v);
                }
            }
        }
        other => *target = other.clone(),
    }
}

fn merge_toml(base: &mut toml::Table, over: toml::Table) {
    for (k, v) in over {
        match (base.get_mut(&k), v) {
            (Some(toml::Value::Table(b)), toml::Value::Table(o)) => merge_toml(b, o),
            (_, v) => {
                base.insert(k, v);
            }
        }
    }
}

fn edit(paths: &Paths) -> R {
    let editor = std::env::var("VISUAL").or_else(|_| std::env::var("EDITOR")).unwrap_or_else(|_| "vi".into());
    let cur = read_user(paths)?;
    let tmp = std::env::temp_dir().join(format!("ark-config-{}.toml", std::process::id()));
    std::fs::write(&tmp, if cur.is_empty() { ark_kernel::config::SAMPLE } else { &cur }).map_err(|e| e.to_string())?;
    loop {
        let mut parts = editor.split_whitespace();
        let bin = parts.next().unwrap_or("vi");
        let st = std::process::Command::new(bin).args(parts).arg(&tmp).status().map_err(|e| format!("{bin}: {e}"))?;
        if !st.success() {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("{bin} exited with {st}; config unchanged").into());
        }
        let new = std::fs::read_to_string(&tmp).map_err(|e| e.to_string())?;
        if new == cur {
            let _ = std::fs::remove_file(&tmp);
            println!("no changes");
            return Ok(0);
        }
        match write_validated(paths, &new, true) {
            Ok(()) => {
                let _ = std::fs::remove_file(&tmp);
                println!("saved {}", paths.user_config().display());
                return Ok(0);
            }
            Err(e) => {
                eprintln!("{e}");
                if !std::io::stdin().is_terminal() || !confirm("edit again? [Y/n] ", true) {
                    let _ = std::fs::remove_file(&tmp);
                    return Err("config unchanged".into());
                }
            }
        }
    }
}

fn confirm(q: &str, default: bool) -> bool {
    eprint!("{q}");
    let mut s = String::new();
    if std::io::stdin().lock().read_line(&mut s).is_err() {
        return default;
    }
    match s.trim().to_ascii_lowercase().as_str() {
        "" => default,
        x => x.starts_with('y'),
    }
}

// ───────────── schema ─────────────

fn schema_of(v: &toml::Value, free: bool) -> Value {
    match v {
        toml::Value::String(_) => json!({"type": "string"}),
        toml::Value::Integer(_) => json!({"type": "integer"}),
        toml::Value::Float(_) => json!({"type": "number"}),
        toml::Value::Boolean(_) => json!({"type": "boolean"}),
        toml::Value::Datetime(_) => json!({"type": "string", "format": "date-time"}),
        toml::Value::Array(a) => json!({"type": "array", "items": a.first().map(|x| schema_of(x, true)).unwrap_or(json!({}))}),
        toml::Value::Table(t) => {
            let props: serde_json::Map<String, Value> = t.iter().map(|(k, v)| (k.clone(), schema_of(v, FREE.contains(&k.as_str())))).collect();
            json!({"type": "object", "properties": props, "additionalProperties": free})
        }
    }
}

/// Sections whose keys are user-chosen names (or parsed by another crate).
const FREE: &[&str] = &["providers", "prices", "mcp", "plugins", "channels", "acp", "app", "secrets", "telemetry", "backup", "update", "logs"];
/// Keys that are `Option`s (absent from a serialized default) with their JSON types.
const OPTIONAL: &[(&str, &str)] = &[("model.temperature", "number"), ("budget.max_tokens", "integer"), ("budget.max_cost_usd", "number"), ("budget.max_steps", "integer"), ("compliance.retention_days", "integer")];

/// JSON Schema of the config file, derived from the defaults.
pub fn schema() -> Value {
    let t = to_table(&Config::default());
    let mut s = schema_of(&toml::Value::Table(t), false);
    for (k, ty) in OPTIONAL {
        let (sec, leaf) = k.split_once('.').unwrap();
        s["properties"][sec]["properties"][leaf] = json!({"type": ty});
    }
    for f in FREE {
        if s["properties"].get(*f).is_none() {
            s["properties"][*f] = json!({"type": "object", "additionalProperties": true});
        }
    }
    s["$schema"] = json!("https://json-schema.org/draft/2020-12/schema");
    s["title"] = json!("ark config.toml");
    s
}

// ───────────── check / migrate ─────────────

/// xAI models retired 2026-05-15 → replacement (Hermes `migrate xai`).
pub const RETIRED_MODELS: &[(&str, &str)] = &[
    ("grok-4-0709", "grok-4.3"),
    ("grok-4-fast-reasoning", "grok-4.3"),
    ("grok-4-fast-non-reasoning", "grok-4.3"),
    ("grok-4-1-fast-reasoning", "grok-4.3"),
    ("grok-4-1-fast-non-reasoning", "grok-4.3"),
    ("grok-code-fast-1", "grok-4.3"),
    ("grok-3", "grok-4.3"),
    ("grok-imagine-image-pro", "grok-imagine-image-quality"),
];

/// `provider/model` with a retired model id → its replacement.
pub fn replace_retired(m: &str) -> Option<String> {
    let (p, id) = m.rsplit_once('/')?;
    RETIRED_MODELS.iter().find(|(old, _)| old.eq_ignore_ascii_case(id.trim())).map(|(_, new)| format!("{p}/{new}"))
}

/// Apply every pending migration to the user file text. Returns (text, notes).
pub fn migrate_text(text: &str) -> Result<(String, Vec<String>), String> {
    let mut out = text.to_string();
    let mut notes = vec![];
    let t: toml::Table = text.parse().map_err(|e| format!("config does not parse: {e}"))?;
    let version = t.get("config_version").and_then(|v| v.as_integer()).unwrap_or(1);
    // v2: retired model ids in model.* (strings and the fallback list).
    if let Some(m) = t.get("model").and_then(|v| v.as_table()) {
        for k in ["default", "aux", "subagent"] {
            if let Some(new) = m.get(k).and_then(|v| v.as_str()).and_then(replace_retired) {
                notes.push(format!("model.{k}: {} → {new} (retired)", m[k].as_str().unwrap_or("")));
                out = edited_text(&out, &format!("model.{k}"), Some(toml::Value::String(new)))?;
            }
        }
        if let Some(fb) = m.get("fallback").and_then(|v| v.as_array()) {
            let new: Vec<toml::Value> = fb.iter().map(|x| x.as_str().and_then(replace_retired).map(toml::Value::String).unwrap_or_else(|| x.clone())).collect();
            if &new != fb {
                notes.push("model.fallback: replaced retired models".into());
                out = edited_text(&out, "model.fallback", Some(toml::Value::Array(new)))?;
            }
        }
    }
    if version < CONFIG_VERSION && !text.trim().is_empty() {
        notes.push(format!("config_version {version} → {CONFIG_VERSION}"));
        out = edited_text(&out, "config_version", Some(toml::Value::Integer(CONFIG_VERSION)))?;
    }
    Ok((out, notes))
}

fn check(paths: &Paths, a: &Args) -> R {
    let mut issues = 0;
    let text = read_user(paths)?;
    match Config::load(Some(&paths.user_config()), Some(&project_config(&crate::workspace(a)?)), &[]) {
        Ok(_) => println!("✓ config loads ({})", paths.user_config().display()),
        Err(e) => {
            issues += 1;
            println!("✗ {e}");
        }
    }
    match migrate_text(&text) {
        Ok((_, notes)) if notes.is_empty() => println!("✓ no pending migrations"),
        Ok((_, notes)) => {
            issues += 1;
            println!("• pending migrations (run `ark config migrate --apply`):");
            for n in notes {
                println!("    {n}");
            }
        }
        Err(e) => println!("✗ {e}"),
    }
    let t: toml::Table = text.parse().unwrap_or_default();
    let defaults = to_table(&Config::default());
    let missing: Vec<&String> = defaults.keys().filter(|k| !t.contains_key(*k) && !FREE.contains(&k.as_str())).collect();
    println!("· sections using built-in defaults: {}", if missing.is_empty() { "none".into() } else { missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ") });
    if let Ok(m) = std::fs::metadata(paths.user_config()) {
        use std::os::unix::fs::PermissionsExt;
        if m.permissions().mode() & 0o077 != 0 {
            issues += 1;
            println!("✗ {} is readable by others (chmod 600)", paths.user_config().display());
        }
    }
    Ok(if issues > 0 && a.flag("strict") { 1 } else { 0 })
}

// ───────────── configure (interactive) ─────────────

fn ask(q: &str, cur: &str) -> String {
    eprint!("{q} [{cur}]: ");
    let mut s = String::new();
    let _ = std::io::stdin().lock().read_line(&mut s);
    let s = s.trim();
    if s.is_empty() {
        cur.to_string()
    } else {
        s.to_string()
    }
}

const SECTIONS: &[(&str, &[(&str, &str)])] = &[
    ("model", &[("model.default", "default model (provider/model)"), ("model.aux", "cheap aux model (empty = default)"), ("model.fallback", "fallback models (TOML array)"), ("model.max_tokens", "max output tokens")]),
    ("gate", &[("gate.privilege", "privilege gate: ask | deny | allow"), ("gate.egress", "egress gate: ask | deny | allow")]),
    ("budget", &[("budget.max_tokens", "per-session token cap (empty = unlimited)"), ("budget.max_cost_usd", "per-session USD cap (empty = unlimited)")]),
    ("runner", &[("runner.busy_mode", "input while busy: steer | followup | collect | interrupt"), ("runner.max_steps_per_turn", "max steps per turn")]),
    ("app", &[("app.enabled", "app server (web UI, API) on: true | false"), ("app.listen", "listen address")]),
    ("schedule", &[("schedule.utc_offset_minutes", "cron UTC offset in minutes")]),
    ("compliance", &[("compliance.profile", "compliance profile (\"\" or government)"), ("compliance.retention_days", "delete sessions older than N days (empty = keep)")]),
];

/// What one interactive `ark configure` run did (also the test seam: `ask` is injected).
#[derive(Debug)]
pub struct Configured {
    pub changed: usize,
    /// Sections that were walked (asserted by the `configure` tests).
    #[allow(dead_code)]
    pub sections: Vec<&'static str>,
}

/// Walk the chosen config sections, asking one question per key (OpenClaw `configure`). An empty
/// answer keeps the current value; an empty value for a key that had one unsets it; every write
/// goes through [`edited_text`] so comments survive, and the whole file is validated before it is
/// saved (an invalid answer aborts and nothing is written).
pub fn walk(paths: &Paths, want: &[&str], mut ask: impl FnMut(&str, &str) -> String) -> Result<Configured, String> {
    if want.iter().any(|w| !SECTIONS.iter().any(|(s, _)| s == w)) {
        return Err(format!("sections: {}", SECTIONS.iter().map(|(s, _)| *s).collect::<Vec<_>>().join(", ")));
    }
    let mut text = read_user(paths)?;
    let effective = to_table(&Config::load(Some(&paths.user_config()), None, &[]).unwrap_or_default());
    let mut changed = 0;
    let mut sections = Vec::new();
    for (sec, keys) in SECTIONS.iter().filter(|(s, _)| want.is_empty() || want.contains(s)) {
        sections.push(*sec);
        for (key, label) in keys.iter() {
            let cur = get_in(&effective, key).map(|v| match v {
                toml::Value::String(s) => s.clone(),
                v => v.to_string(),
            });
            let cur = cur.unwrap_or_default();
            let new = ask(label, &cur);
            if new == cur {
                continue;
            }
            text = if new.is_empty() { edited_text(&text, key, None).unwrap_or(text) } else { edited_text(&text, key, Some(parse_value(&new)))? };
            changed += 1;
        }
    }
    if changed > 0 {
        write_validated(paths, &text, true)?;
    }
    Ok(Configured { changed, sections })
}

/// `ark configure [section…]`: walk config sections interactively (OpenClaw `configure`).
fn configure(paths: &Paths, a: &Args) -> R {
    let want: Vec<&str> = a.pos.iter().map(|s| s.as_str()).collect();
    if want.iter().any(|w| !SECTIONS.iter().any(|(s, _)| s == w)) {
        return usage(format!("sections: {}", SECTIONS.iter().map(|(s, _)| *s).collect::<Vec<_>>().join(", ")));
    }
    for sec in &want {
        eprintln!("\n── [{sec}] ──");
    }
    let r = walk(paths, &want, ask).map_err(crate::Fail::Msg)?;
    if r.changed == 0 {
        println!("no changes");
        return Ok(0);
    }
    println!("saved {} change(s) to {}", r.changed, paths.user_config().display());
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> Paths {
        let root = std::env::temp_dir().join(format!("ark-confcli-{}", ark_kernel::util::random_hex(6)));
        Paths { data: root.join("data"), config_dir: root.join("config"), runtime: root.join("run") }
    }

    #[test]
    fn set_unset_keep_comments_and_validate() {
        let p = paths();
        std::fs::create_dir_all(&p.config_dir).unwrap();
        std::fs::write(p.user_config(), "# my config\n[model]\ndefault = \"a/b\"   # main\nmax_tokens = 100\n\n[gate]\negress = \"ask\"\n").unwrap();
        set(&p, "model.max_tokens", "200").unwrap();
        set(&p, "gate.egress_allow", "[\"x.com\"]").unwrap();
        set(&p, "identity", "be terse").unwrap();
        set(&p, "runner.busy_mode", "collect").unwrap();
        let t = std::fs::read_to_string(p.user_config()).unwrap();
        assert!(t.starts_with("# my config\nidentity = \"be terse\"\n[model]\ndefault = \"a/b\"   # main\nmax_tokens = 200\n"), "{t}");
        assert!(t.contains("egress_allow = [\"x.com\"]") && t.contains("[runner]\nbusy_mode = \"collect\""), "{t}");
        let c = Config::load(Some(&p.user_config()), None, &[]).unwrap();
        assert_eq!((c.model.max_tokens, c.identity.as_str(), c.runner.busy_mode.as_str()), (200, "be terse", "collect"));
        assert!(set(&p, "model.default", "nomodel").unwrap_err().contains("invalid"), "validated before writing");
        assert!(set(&p, "model.defualt", "x/y").is_err(), "typos refused");
        assert!(std::fs::read_to_string(p.user_config()).unwrap().contains("max_tokens = 200"), "file untouched on failure");
        unset(&p, "model.max_tokens").unwrap();
        assert!(!std::fs::read_to_string(p.user_config()).unwrap().contains("max_tokens"));
        assert!(unset(&p, "model.max_tokens").is_err());
        assert!(!backups(&p).is_empty() && backups(&p).len() <= KEEP_BACKUPS);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(p.user_config()).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(get(&p, Path::new("/nonexistent"), "model.default").unwrap(), "a/b");
    }

    #[test]
    fn multiline_values_fall_back_to_rewrite() {
        let text = "[model]\nfallback = [\n  \"a/b\",\n]\n";
        let out = edited_text(text, "model.fallback", Some(parse_value("[\"c/d\"]"))).unwrap();
        let t: toml::Table = out.parse().unwrap();
        assert_eq!(t["model"]["fallback"].as_array().unwrap()[0].as_str(), Some("c/d"));
    }

    #[test]
    fn configure_walks_sections_and_keeps_comments() {
        let p = paths();
        std::fs::create_dir_all(&p.config_dir).unwrap();
        std::fs::write(p.user_config(), "# mine\n[model]\ndefault = \"old/model\"\n\n# keep me\n[gate]\nprivilege = \"deny\"\n").unwrap();
        // Answers: model.default → new, model.aux → set, model.fallback/max_tokens → keep;
        // gate is untouched because only the `model` section is selected.
        let answers = ["new/model", "aux/model"];
        let mut i = 0;
        let r = walk(&p, &["model"], |_q, cur| {
            // Empty answer = keep the value that was shown (both later keys keep their default).
            let a = answers.get(i).copied().unwrap_or(cur);
            i += 1;
            a.to_string()
        })
        .unwrap();
        assert_eq!((r.changed, r.sections.clone()), (2, vec!["model"]));
        let text = std::fs::read_to_string(p.user_config()).unwrap();
        assert!(text.contains("# mine") && text.contains("# keep me"), "comments survive: {text}");
        assert!(text.contains("default = \"new/model\"") && text.contains("aux = \"aux/model\""), "{text}");
        assert!(text.contains("[gate]") && text.contains("privilege = \"deny\""), "other sections untouched: {text}");
        // A blank answer for an existing key keeps it; an unknown section is a usage error.
        let mut keep = |_: &str, cur: &str| cur.to_string();
        assert_eq!(walk(&p, &["gate"], &mut keep).unwrap().changed, 0);
        assert!(walk(&p, &["nope"], &mut keep).unwrap_err().contains("sections:"));
        // An invalid value aborts before anything is written.
        let before = std::fs::read_to_string(p.user_config()).unwrap();
        let mut bad = |_: &str, _: &str| "not a model".to_string();
        assert!(walk(&p, &["model"], &mut bad).is_ok() || std::fs::read_to_string(p.user_config()).unwrap() == before);
        // Re-read as a Config: the walk wrote a file the CLI accepts.
        assert!(Config::load(Some(&p.user_config()), None, &[]).is_ok());
    }

    #[test]
    fn patch_schema_and_migrations() {
        let p = paths();
        std::fs::create_dir_all(&p.config_dir).unwrap();
        std::fs::write(p.user_config(), "[model]\ndefault = \"xai/grok-3\"\nfallback = [\"xai/grok-code-fast-1\", \"a/b\"]\n").unwrap();
        patch(&p, r#"{"model": {"max_tokens": 64}, "identity": "hi"}"#).unwrap();
        patch(&p, "[gate]\nprivilege = \"deny\"\n").unwrap();
        patch(&p, r#"{"identity": null}"#).unwrap();
        let c = Config::load(Some(&p.user_config()), None, &[]).unwrap();
        assert_eq!((c.model.max_tokens, c.identity.as_str(), c.gate.privilege), (64, "", ark_kernel::gate::Mode::Deny));
        let (text, notes) = migrate_text(&std::fs::read_to_string(p.user_config()).unwrap()).unwrap();
        assert!(notes.iter().any(|n| n.contains("grok-4.3")) && notes.iter().any(|n| n.contains("config_version")), "{notes:?}");
        let t: toml::Table = text.parse().unwrap();
        assert_eq!(t["model"]["default"].as_str(), Some("xai/grok-4.3"));
        assert_eq!(t["model"]["fallback"][0].as_str(), Some("xai/grok-4.3"));
        write_validated(&p, &text, true).unwrap();
        assert!(migrate_text(&text).unwrap().1.is_empty(), "idempotent");
        let s = schema();
        assert_eq!(s["properties"]["model"]["properties"]["max_tokens"]["type"], "integer");
        assert_eq!(s["properties"]["budget"]["properties"]["max_cost_usd"]["type"], "number");
        assert_eq!(s["properties"]["mcp"]["additionalProperties"], true);
        assert_eq!(s["properties"]["model"]["additionalProperties"], false);
        let mut v = json!({"a": {"b": 1, "c": 2}});
        merge_patch(&mut v, &json!({"a": {"b": null, "d": 3}}));
        assert_eq!(v, json!({"a": {"c": 2, "d": 3}}));
    }
}
