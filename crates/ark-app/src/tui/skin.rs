//! Skin/theme engine for the terminal surfaces (Hermes `hermes_cli/skin_engine.py` +
//! `skin_cmd.py`). Built-in skins ship in `skins.json` (palettes/branding/spinners ported
//! from Hermes; ark's own crimson-and-gold look is `default`, Hermes' gold one is
//! `hermes`). User skins live in `<config_dir>/skins/<name>.yaml` (or `.json`); a user
//! file of the same name wins on load but never shadows a built-in in the listing. The
//! active skin is `skin` in `ui.json`; `ark skin set <key> <#rrggbb>` edits one colour of
//! the active skin in place, forking a built-in into `<name>-custom` first.

use super::prefs;
use ark_kernel::config::Paths;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const BUILTIN_JSON: &str = include_str!("skins.json");

fn builtins() -> &'static Map<String, Value> {
    static B: OnceLock<Map<String, Value>> = OnceLock::new();
    B.get_or_init(|| serde_json::from_str::<Value>(BUILTIN_JSON).ok().and_then(|v| v.as_object().cloned()).unwrap_or_default())
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Skin {
    pub name: String,
    pub description: String,
    pub colors: BTreeMap<String, String>,
    pub light_colors: BTreeMap<String, String>,
    pub dark_colors: BTreeMap<String, String>,
    pub spinner: Value,
    pub branding: BTreeMap<String, String>,
    pub tool_prefix: String,
    pub tool_emojis: BTreeMap<String, String>,
}

fn str_map(v: Option<&Value>) -> BTreeMap<String, String> {
    v.and_then(Value::as_object).map(|o| o.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect()).unwrap_or_default()
}

impl Skin {
    pub fn color(&self, key: &str) -> Option<(u8, u8, u8)> {
        self.colors.get(key).and_then(|c| hex(c))
    }
    pub fn color_or(&self, key: &str, fallback: (u8, u8, u8)) -> (u8, u8, u8) {
        self.color(key).unwrap_or(fallback)
    }
    pub fn branding(&self, key: &str, fallback: &str) -> String {
        self.branding.get(key).filter(|s| !s.trim().is_empty()).cloned().unwrap_or_else(|| fallback.to_string())
    }
    /// Prompt symbol (bare token) plus one trailing space.
    pub fn prompt_symbol(&self) -> String {
        format!("{} ", self.branding("prompt_symbol", "▸").trim())
    }
    pub fn spinner_list(&self, key: &str) -> Vec<String> {
        self.spinner.get(key).and_then(Value::as_array).map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect()).unwrap_or_default()
    }
    /// Spinner wing pairs `(left, right)`.
    pub fn wings(&self) -> Vec<(String, String)> {
        self.spinner.get("wings").and_then(Value::as_array).map(|a| a.iter().filter_map(|p| Some((p.get(0)?.as_str()?.to_string(), p.get(1)?.as_str()?.to_string()))).collect()).unwrap_or_default()
    }
}

/// `#rrggbb` → rgb.
pub fn hex(s: &str) -> Option<(u8, u8, u8)> {
    let h = s.trim().strip_prefix('#')?;
    if h.len() != 6 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let p = |i: usize| u8::from_str_radix(&h[i..i + 2], 16).ok();
    Some((p(0)?, p(2)?, p(4)?))
}

pub fn is_hex(s: &str) -> bool {
    hex(s).is_some()
}

/// Build a skin from raw data, merging `colors`/`spinner`/`branding` over the default skin
/// (paired light/dark palettes are NOT merged: empty = no hand-tuned variant).
pub fn build(data: &Value) -> Skin {
    let def = builtins().get("default").cloned().unwrap_or_else(|| json!({}));
    let merged = |k: &str| {
        let mut m = def.get(k).and_then(Value::as_object).cloned().unwrap_or_default();
        if let Some(o) = data.get(k).and_then(Value::as_object) {
            for (a, b) in o {
                m.insert(a.clone(), b.clone());
            }
        }
        Value::Object(m)
    };
    Skin {
        name: data.get("name").and_then(Value::as_str).unwrap_or("unknown").to_string(),
        description: data.get("description").and_then(Value::as_str).unwrap_or("").to_string(),
        colors: str_map(Some(&merged("colors"))),
        light_colors: str_map(data.get("light_colors")),
        dark_colors: str_map(data.get("dark_colors")),
        spinner: merged("spinner"),
        branding: str_map(Some(&merged("branding"))),
        tool_prefix: data.get("tool_prefix").and_then(Value::as_str).or(def.get("tool_prefix").and_then(Value::as_str)).unwrap_or("┊").to_string(),
        tool_emojis: str_map(data.get("tool_emojis")),
    }
}

pub fn skins_dir(paths: &Paths) -> PathBuf {
    paths.config_dir.join("skins")
}

fn parse_file(p: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(p).ok()?;
    let text = text.trim_start_matches('\u{feff}');
    let v = if p.extension().is_some_and(|e| e == "json") { serde_json::from_str(text).ok()? } else { crate::surfaces::yaml::parse(text).ok()? };
    v.get("name").is_some().then_some(v)
}

fn user_file(paths: &Paths, name: &str) -> Option<PathBuf> {
    ["yaml", "yml", "json"].iter().map(|e| skins_dir(paths).join(format!("{name}.{e}"))).find(|p| p.is_file())
}

/// `(name, description, source)` — built-ins first, then user skins that do not shadow one.
pub fn list(paths: &Paths) -> Vec<(String, String, &'static str)> {
    let mut out: Vec<(String, String, &'static str)> = builtins().iter().map(|(n, d)| (n.clone(), d["description"].as_str().unwrap_or("").to_string(), "builtin")).collect();
    let mut files: Vec<PathBuf> = std::fs::read_dir(skins_dir(paths)).map(|rd| rd.flatten().map(|e| e.path()).collect()).unwrap_or_default();
    files.sort();
    for f in files {
        if !f.extension().is_some_and(|e| e == "yaml" || e == "yml" || e == "json") {
            continue;
        }
        if let Some(d) = parse_file(&f) {
            let name = d["name"].as_str().map(str::to_string).unwrap_or_else(|| f.file_stem().unwrap_or_default().to_string_lossy().into_owned());
            if !out.iter().any(|s| s.0 == name) {
                out.push((name, d["description"].as_str().unwrap_or("").to_string(), "user"));
            }
        }
    }
    out
}

/// User skin first, then built-in, then default.
pub fn load(paths: &Paths, name: &str) -> Skin {
    let data = user_file(paths, name).and_then(|p| parse_file(&p)).or_else(|| builtins().get(name).cloned()).or_else(|| builtins().get("default").cloned()).unwrap_or_else(|| json!({"name": "default"}));
    build(&data)
}

pub fn exists(paths: &Paths, name: &str) -> bool {
    list(paths).iter().any(|s| s.0 == name)
}

pub fn active_name(paths: &Paths) -> String {
    prefs::get_str(&prefs::load(paths), "skin", "default")
}

pub fn active(paths: &Paths) -> Skin {
    load(paths, &active_name(paths))
}

pub fn set_active(paths: &Paths, name: &str) -> Result<Skin, String> {
    let name = name.trim().to_ascii_lowercase();
    if !exists(paths, &name) {
        let mut names: Vec<String> = list(paths).into_iter().map(|s| s.0).collect();
        names.sort();
        return Err(format!("unknown skin `{name}` (available: {})", names.join(", ")));
    }
    prefs::set(paths, "skin", json!(name))?;
    Ok(load(paths, &name))
}

fn yq(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

/// Minimal YAML writer for a skin file (name, description, colour/branding maps, tool prefix).
pub fn to_yaml(v: &Value) -> String {
    let mut o = String::new();
    for key in ["name", "description", "tool_prefix"] {
        if let Some(s) = v.get(key).and_then(Value::as_str) {
            o.push_str(&format!("{key}: {}\n", yq(s)));
        }
    }
    for key in ["colors", "light_colors", "dark_colors", "branding", "tool_emojis"] {
        if let Some(m) = v.get(key).and_then(Value::as_object).filter(|m| !m.is_empty()) {
            o.push_str(&format!("{key}:\n"));
            for (k, val) in m {
                o.push_str(&format!("  {k}: {}\n", yq(val.as_str().unwrap_or(""))));
            }
        }
    }
    // Spinner frames are sequences of strings; `wings` is a sequence of pairs.
    if let Some(sp) = v.get("spinner").and_then(Value::as_object).filter(|m| !m.is_empty()) {
        o.push_str("spinner:\n");
        for (k, val) in sp {
            let Some(items) = val.as_array() else { continue };
            o.push_str(&format!("  {k}:\n"));
            for it in items {
                match it {
                    Value::String(s) => o.push_str(&format!("    - {}\n", yq(s))),
                    Value::Array(pair) => o.push_str(&format!("    - [{}]\n", pair.iter().map(|x| yq(x.as_str().unwrap_or(""))).collect::<Vec<_>>().join(", "))),
                    _ => {}
                }
            }
        }
    }
    o
}

/// Change ONE colour of the active (or named) skin in place. Returns `(skin, file)`.
pub fn set_color(paths: &Paths, key: &str, value: &str, skin: Option<&str>) -> Result<(String, PathBuf), String> {
    if !is_hex(value) {
        return Err(format!("{value:?} is not a #rrggbb hex color"));
    }
    if key.trim().is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(format!("invalid color key {key:?}"));
    }
    let name = skin.map(str::to_string).unwrap_or_else(|| active_name(paths));
    let (target, path, mut data) = match user_file(paths, &name) {
        Some(p) => (name.clone(), p.clone(), parse_file(&p).unwrap_or_else(|| json!({}))),
        None => {
            // Built-in (or missing): fork an editable copy that keeps the full look
            // (palette, branding, spinner wings, tool prefix).
            let r = load(paths, &name);
            let target = format!("{name}-custom");
            let data = json!({"name": target, "description": format!("{name} + custom {key}"), "colors": r.colors, "light_colors": r.light_colors, "dark_colors": r.dark_colors, "spinner": r.spinner, "branding": r.branding, "tool_prefix": r.tool_prefix, "tool_emojis": r.tool_emojis});
            (target.clone(), skins_dir(paths).join(format!("{target}.yaml")), data)
        }
    };
    if !data.get("colors").is_some_and(Value::is_object) {
        data["colors"] = json!({});
    }
    data["colors"][key] = json!(value);
    if data.get("name").is_none() {
        data["name"] = json!(target);
    }
    std::fs::create_dir_all(skins_dir(paths)).map_err(|e| e.to_string())?;
    let body = if path.extension().is_some_and(|e| e == "json") { serde_json::to_string_pretty(&data).unwrap_or_default() } else { to_yaml(&data) };
    ark_kernel::util::atomic_write(&path, body.as_bytes()).map_err(|e| e.to_string())?;
    if target != name {
        prefs::set(paths, "skin", json!(target))?;
    }
    Ok((target, path))
}

/// Text for `/skin` with no argument and `ark skin list`.
pub fn listing(paths: &Paths) -> String {
    let cur = active_name(paths);
    let mut o = format!("current skin: {cur}\n");
    for (n, d, src) in list(paths) {
        o.push_str(&format!(" {} {n:<16} {src:<8} {d}\n", if n == cur { "●" } else { " " }));
    }
    o.push_str(&format!("use /skin <name> · custom skins: {}/<name>.yaml", skins_dir(paths).display()));
    o
}

/// Resolved colours the TUI paints with.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Palette {
    pub bg: (u8, u8, u8),
    pub panel: (u8, u8, u8),
    pub text: (u8, u8, u8),
    pub dim: (u8, u8, u8),
    pub accent: (u8, u8, u8),
    pub label: (u8, u8, u8),
    pub status_bg: (u8, u8, u8),
    pub status_text: (u8, u8, u8),
    pub status_strong: (u8, u8, u8),
    pub status_dim: (u8, u8, u8),
    pub good: (u8, u8, u8),
    pub warn: (u8, u8, u8),
    pub bad: (u8, u8, u8),
    pub critical: (u8, u8, u8),
}

impl Palette {
    /// Hermes `_STYLE_PALETTE` resolution order (missing keys inherit an earlier entry).
    pub fn of(s: &Skin) -> Palette {
        let title = s.color_or("banner_title", (0xff, 0xd7, 0x00));
        let text = s.color_or("banner_text", (0xff, 0xf8, 0xdc));
        let dim = s.color_or("banner_dim", (0x55, 0x55, 0x55));
        let warn = s.color_or("ui_warn", (0xff, 0x8c, 0x00));
        let error = s.color_or("ui_error", (0xff, 0x6b, 0x6b));
        let ok = s.color_or("ui_ok", (0x8f, 0xbc, 0x8f));
        let accent = s.color_or("banner_accent", warn);
        let status_bg = s.color_or("status_bar_bg", (0x1a, 0x1a, 0x2e));
        Palette {
            bg: s.color_or("background", s.color_or("completion_menu_bg", (0x12, 0x02, 0x0a))),
            panel: s.color_or("panel_bg", status_bg),
            text,
            dim,
            accent: s.color_or("ui_accent", accent),
            label: s.color_or("ui_label", title),
            status_bg,
            status_text: s.color_or("status_bar_text", text),
            status_strong: s.color_or("status_bar_strong", title),
            status_dim: s.color_or("status_bar_dim", dim),
            good: s.color_or("status_bar_good", ok),
            warn: s.color_or("status_bar_warn", warn),
            bad: s.color_or("status_bar_bad", accent),
            critical: s.color_or("status_bar_critical", error),
        }
    }
    pub fn by_name(&self, style: &str) -> (u8, u8, u8) {
        match style {
            "good" => self.good,
            "warn" => self.warn,
            "bad" => self.bad,
            "critical" => self.critical,
            "strong" => self.status_strong,
            "dim" => self.status_dim,
            _ => self.status_text,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::prefs::test_paths;

    #[test]
    fn builtins_user_skins_and_set_color() {
        let p = test_paths("skin");
        let names: Vec<String> = list(&p).into_iter().map(|s| s.0).collect();
        for n in ["default", "hermes", "ares", "mono", "slate", "daylight", "warm-lightmode", "poseidon", "sisyphus", "charizard"] {
            assert!(names.contains(&n.to_string()), "{n}");
        }
        let ares = load(&p, "ares");
        assert_eq!(ares.color("banner_border"), Some((0xA9, 0x33, 0x33)));
        assert_eq!(ares.branding("agent_name", ""), "Ares Agent");
        assert_eq!(ares.tool_prefix, "╎");
        assert_eq!(ares.wings()[0], ("⟪⚔".to_string(), "⚔⟫".to_string()));
        // Missing keys merge from the default skin.
        assert!(load(&p, "mono").colors.contains_key("background"));
        assert_eq!(load(&p, "nope").name, "default");
        // A user YAML skin is listed, loads, and cannot shadow a built-in in the list.
        std::fs::create_dir_all(skins_dir(&p)).unwrap();
        std::fs::write(skins_dir(&p).join("neon.yaml"), "name: neon\ndescription: \"Neon test\"\ncolors:\n  ui_accent: \"#00FFFF\"\n").unwrap();
        let l = list(&p);
        assert!(l.iter().any(|s| s.0 == "neon" && s.2 == "user"));
        assert_eq!(load(&p, "neon").color("ui_accent"), Some((0, 255, 255)));
        // A `.json` user skin works too, and a file shadowing a built-in never hides it.
        std::fs::write(skins_dir(&p).join("glow.json"), serde_json::to_string(&json!({"name": "glow", "colors": {"ui_accent": "#ff00ff"}})).unwrap()).unwrap();
        std::fs::write(skins_dir(&p).join("mono.yaml"), "name: mono\ncolors:\n  banner_title: \"#010101\"\n").unwrap();
        let l = list(&p);
        assert_eq!(load(&p, "glow").color("ui_accent"), Some((0xff, 0x00, 0xff)));
        assert!(l.iter().any(|s| s.0 == "glow" && s.2 == "user"));
        assert!(l.iter().any(|s| s.0 == "mono" && s.2 == "builtin"), "a user file never shadows a built-in in the listing");
        assert!(set_active(&p, "bogus").unwrap_err().contains("unknown skin"));
        set_active(&p, "ares").unwrap();
        assert_eq!(active_name(&p), "ares");
        // set on a built-in forks `<name>-custom` and activates it.
        let (t, file) = set_color(&p, "ui_accent", "#123456", None).unwrap();
        assert_eq!(t, "ares-custom");
        assert!(file.ends_with("skins/ares-custom.yaml"));
        assert_eq!(active_name(&p), "ares-custom");
        let s = active(&p);
        assert_eq!(s.color("ui_accent"), Some((0x12, 0x34, 0x56)));
        assert_eq!(s.color("banner_border"), Some((0xA9, 0x33, 0x33)), "rest of the palette kept");
        assert_eq!(s.branding("agent_name", ""), "Ares Agent", "branding survives the fork");
        assert_eq!(s.tool_prefix, "╎", "tool prefix survives the fork");
        assert_eq!(s.wings(), ares.wings(), "spinner wings survive the fork");
        assert!(!s.wings().is_empty(), "the fork kept a non-empty spinner");
        // set again edits the user file in place.
        set_color(&p, "banner_border", "#000001", None).unwrap();
        assert_eq!(active(&p).color("banner_border"), Some((0, 0, 1)));
        assert!(set_color(&p, "x", "red", None).is_err());
        assert!(set_color(&p, "#bad", "#123456", None).is_err(), "keys are identifiers");
        assert!(set_color(&p, "ui_accent", "#fff", None).is_err(), "only #rrggbb is accepted");
        let pal = Palette::of(&load(&p, "default"));
        assert_eq!(pal.status_bg, (0x1f, 0x04, 0x11));
        // Palette resolution order: `status_bar_*` overrides the base key, `ui_accent`
        // refines `accent` only, and `status_bad` keeps following `banner_accent`.
        let synth = build(&json!({"name": "t", "colors": {"banner_accent": "#010203", "ui_accent": "#040506", "banner_title": "#070809", "ui_label": "#111213", "status_bar_strong": "#0a0b0c", "status_bar_bad": "#0d0e0f"}}));
        let sp = Palette::of(&synth);
        assert_eq!((sp.accent, sp.label), ((4, 5, 6), (0x11, 0x12, 0x13)));
        assert_eq!((sp.status_strong, sp.bad), ((10, 11, 12), (13, 14, 15)), "status_bar_* wins over the banner key");
        // Without a status_bar_* layer each field inherits its documented base key.
        let bare = Skin {
            name: "bare".into(),
            colors: [("banner_title", "#070809"), ("banner_accent", "#010203"), ("ui_accent", "#040506"), ("banner_text", "#161718")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            ..Default::default()
        };
        let bp = Palette::of(&bare);
        assert_eq!((bp.label, bp.status_strong), ((7, 8, 9), (7, 8, 9)), "label/status_strong inherit banner_title");
        assert_eq!((bp.accent, bp.bad), ((4, 5, 6), (1, 2, 3)), "status_bad follows banner_accent, not ui_accent");
        assert_eq!((bp.text, bp.status_text), ((0x16, 0x17, 0x18), (0x16, 0x17, 0x18)), "status_text inherits banner_text");
        assert!(listing(&p).contains("● ares-custom"));
    }
}
