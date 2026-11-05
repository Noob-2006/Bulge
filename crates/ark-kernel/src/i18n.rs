//! Lightweight i18n for ark's static user-facing strings (approval prompts, notices, CLI
//! headings). Ports Hermes `agent/i18n.py`, `agent/i18n_layers.py` and `agent/i18n_languages.py`.
//!
//! Catalogs are flat dotted-key maps resolved through layers, top first:
//!
//! 1. plugin language packs ([`register_pack`]; last registered wins)
//! 2. the user overlay `$ARK_HOME/locales/<lang>.json` (or `.yaml`) of the current home
//! 3. the bundled `locales/<lang>.json`
//! 4. the same chain for `en`
//! 5. the bare key
//!
//! Every layer may be partial. Language resolution: explicit argument > `ARK_LANGUAGE` >
//! `display.language` config (fed by [`set_config_language`]) > `en`; any id some layer supplies
//! is accepted, so a pack-only language works the moment its pack loads. [`t`] is a hot path:
//! one cached merged dict per `(home, lang)`, invalidated by [`reset_cache`] (which every pack
//! registration and every config change calls).

use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

pub const DEFAULT_LANGUAGE: &str = "en";
/// Bundled catalogs. A language supplied only by an overlay file or a pack is still supported —
/// see [`supported_languages`].
pub const BUNDLED_LANGUAGES: &[&str] = &["en", "zh", "zh-hant", "ja"];

const BUNDLED: &[(&str, &str)] = &[
    ("en", include_str!("../locales/en.json")),
    ("zh", include_str!("../locales/zh.json")),
    ("zh-hant", include_str!("../locales/zh-hant.json")),
    ("ja", include_str!("../locales/ja.json")),
];

/// Natural aliases, so `chinese` / `zh-CN` / `jp` hit the right catalog instead of silently
/// falling back to English. Bare `chinese` defaults to Simplified; Taiwan/HK/Macau tags route
/// to the distinct Traditional catalog.
const ALIASES: &[(&str, &str)] = &[
    ("english", "en"),
    ("en-us", "en"),
    ("en-gb", "en"),
    ("chinese", "zh"),
    ("mandarin", "zh"),
    ("zh-cn", "zh"),
    ("zh-hans", "zh"),
    ("zh-sg", "zh"),
    ("simplified-chinese", "zh"),
    ("simplified_chinese", "zh"),
    ("traditional-chinese", "zh-hant"),
    ("traditional_chinese", "zh-hant"),
    ("zh-tw", "zh-hant"),
    ("zh-hk", "zh-hant"),
    ("zh-mo", "zh-hant"),
    ("japanese", "ja"),
    ("jp", "ja"),
    ("ja-jp", "ja"),
];

/// `id -> (endonym, rtl)` for the bundled catalogs (Hermes `BUNDLED_LANGUAGE_INFO`).
const LANGUAGE_INFO: &[(&str, &str, bool)] = &[("en", "English", false), ("ja", "日本語", false), ("zh", "简体中文", false), ("zh-hant", "繁體中文", false)];

// ───────────────────────── language ids ─────────────────────────

/// Canonical spelling of a language id: lowercase, `_` → `-`, surrounding whitespace dropped.
pub fn normalize_language_id(value: &str) -> String {
    value.trim().to_lowercase().replace('_', "-")
}

/// `zh`, `zh-hant`, `pt-br`, `sr-latn-rs`: a 2–3 letter language subtag plus region/script parts.
pub fn is_language_id(value: &str) -> bool {
    let id = normalize_language_id(value);
    let mut parts = id.split('-');
    let head = parts.next().unwrap_or("");
    if !(2..=3).contains(&head.len()) || !head.chars().all(|c| c.is_ascii_lowercase()) {
        return false;
    }
    parts.all(|p| (2..=8).contains(&p.len()) && p.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()))
}

fn alias(key: &str) -> Option<&'static str> {
    ALIASES.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

fn bundled_language(lang: &str) -> Option<&'static str> {
    BUNDLED.iter().find(|(id, _)| *id == lang).map(|(_, text)| *text)
}

// ───────────────────────── paths & state ─────────────────────────

/// `$ARK_HOME` (tests, portable installs) else ark's data dir — the directory that holds
/// `locales/` for the user overlay, mirroring Hermes' `$HERMES_HOME/locales`.
pub fn home() -> PathBuf {
    if let Some(h) = std::env::var_os("ARK_HOME").filter(|h| !h.is_empty()) {
        return PathBuf::from(h);
    }
    crate::config::Paths::from_env().data
}

pub fn overlay_dir(home: &Path) -> PathBuf {
    home.join("locales")
}

fn config_language() -> &'static Mutex<Option<String>> {
    static CFG: OnceLock<Mutex<Option<String>>> = OnceLock::new();
    CFG.get_or_init(|| Mutex::new(None))
}

/// Record `display.language` from the loaded config (call after loading it; "" clears it).
pub fn set_config_language(language: &str) {
    let value = (!language.trim().is_empty()).then(|| language.trim().to_string());
    *config_language().lock().unwrap() = value;
    reset_cache();
}

pub fn config_language_value() -> Option<String> {
    config_language().lock().unwrap().clone()
}

/// One registered pack layer. `token` orders registrations: the last one registered wins.
#[derive(Debug, Clone)]
pub struct PackEntry {
    pub lang: String,
    pub messages: HashMap<String, String>,
    pub source: String,
    pub endonym: Option<String>,
    pub rtl: bool,
    pub token: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguageOption {
    pub id: String,
    pub endonym: String,
    pub rtl: bool,
    /// `plugin:<name>` > `overlay` > `bundled` — where the language comes from.
    pub source: String,
}

fn packs() -> &'static Mutex<Vec<PackEntry>> {
    static PACKS: OnceLock<Mutex<Vec<PackEntry>>> = OnceLock::new();
    PACKS.get_or_init(|| Mutex::new(Vec::new()))
}

type Catalog = Arc<HashMap<String, String>>;

fn catalog_cache() -> &'static Mutex<HashMap<(PathBuf, String), Catalog>> {
    static CACHE: OnceLock<Mutex<HashMap<(PathBuf, String), Catalog>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn supported_cache() -> &'static Mutex<HashMap<PathBuf, Arc<Vec<String>>>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, Arc<Vec<String>>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn overlay_cache() -> &'static Mutex<HashMap<(PathBuf, String), Catalog>> {
    static CACHE: OnceLock<Mutex<HashMap<(PathBuf, String), Catalog>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Drop every cached view (call after editing an overlay file, changing `display.language`, or
/// registering/unregistering a pack). Registrations survive.
pub fn reset_cache() {
    catalog_cache().lock().unwrap().clear();
    supported_cache().lock().unwrap().clear();
    overlay_cache().lock().unwrap().clear();
}

// ───────────────────────── parsing ─────────────────────────

fn flatten(node: &Value, prefix: &str, out: &mut HashMap<String, String>) {
    match node {
        Value::Object(map) => {
            for (k, v) in map {
                let path = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                flatten(v, &path, out);
            }
        }
        Value::String(s) => {
            out.insert(prefix.to_string(), s.clone());
        }
        // Catalogs are text-only: numbers / lists / nulls are dropped, like upstream's `flatten`.
        _ => {}
    }
}

/// Flatten nested JSON into `{dotted.key: text}`.
pub fn parse_json_catalog(text: &str) -> Result<HashMap<String, String>, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    if !v.is_object() {
        return Err("top level must be a mapping".into());
    }
    let mut out = HashMap::new();
    flatten(&v, "", &mut out);
    Ok(out)
}

fn strip_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    for (i, c) in line.char_indices() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == '#' => return &line[..i],
            None => {}
        }
    }
    line
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    for q in ['"', '\''] {
        if s.len() >= 2 && s.starts_with(q) && s.ends_with(q) {
            let inner = &s[1..s.len() - 1];
            if q == '"' {
                let mut out = String::with_capacity(inner.len());
                let mut chars = inner.chars();
                while let Some(c) = chars.next() {
                    if c != '\\' {
                        out.push(c);
                        continue;
                    }
                    match chars.next() {
                        Some('n') => out.push('\n'),
                        Some('t') => out.push('\t'),
                        Some(other) => out.push(other),
                        None => out.push('\\'),
                    }
                }
                return out;
            }
            return inner.replace("''", "'");
        }
    }
    s.to_string()
}

/// Parse a small YAML subset into a flat catalog: nested mappings by indentation, `key: value`
/// scalars, `#` comments, single/double quoted strings. This is the shape locale overlays are
/// written in; anything else (sequences, anchors, multi-line scalars) is refused with a message
/// rather than silently mis-parsed.
pub fn parse_yaml_catalog(text: &str) -> Result<HashMap<String, String>, String> {
    let mut out = HashMap::new();
    let mut stack: Vec<(usize, String)> = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim_end();
        if line.trim().is_empty() || line.trim() == "---" {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let body = line.trim_start();
        if body.starts_with("- ") || body == "-" {
            return Err(format!("line {}: sequences are not supported in locale files", n + 1));
        }
        let Some((key, value)) = body.split_once(':') else {
            return Err(format!("line {}: expected `key: value`", n + 1));
        };
        let key = unquote(key);
        if key.is_empty() || (key.contains(' ') && !key.contains('.')) {
            return Err(format!("line {}: bad key {key:?}", n + 1));
        }
        while stack.last().is_some_and(|(i, _)| *i >= indent) {
            stack.pop();
        }
        let mut path = stack.iter().map(|(_, k)| k.as_str()).collect::<Vec<_>>().join(".");
        if !path.is_empty() {
            path.push('.');
        }
        path.push_str(&key);
        let value = value.trim();
        if value.is_empty() {
            stack.push((indent, key));
        } else {
            out.insert(path, unquote(value));
        }
    }
    Ok(out)
}

/// One locale file (`.json` or `.yaml`/`.yml`), flattened to dotted keys.
pub fn parse_locale_file(path: &Path) -> Result<HashMap<String, String>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    match path.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase()).as_deref() {
        Some("json") => parse_json_catalog(text),
        Some("yaml" | "yml") => parse_yaml_catalog(text),
        other => Err(format!("{}: unknown locale file type {other:?}", path.display())),
    }
}

// ───────────────────────── layers ─────────────────────────

fn load_bundled(lang: &str) -> HashMap<String, String> {
    bundled_language(lang).and_then(|text| parse_json_catalog(text).ok()).unwrap_or_default()
}

/// `$ARK_HOME/locales/<lang>.json` then `<lang>.yaml` (the YAML overlay wins a key conflict).
pub fn overlay_layer(home: &Path, lang: &str) -> Catalog {
    let key = (home.to_path_buf(), lang.to_string());
    if let Some(hit) = overlay_cache().lock().unwrap().get(&key) {
        return hit.clone();
    }
    let dir = overlay_dir(home);
    let mut flat: HashMap<String, String> = HashMap::new();
    for ext in ["json", "yaml", "yml"] {
        let path = dir.join(format!("{lang}.{ext}"));
        if !path.is_file() {
            continue;
        }
        match parse_locale_file(&path) {
            Ok(map) => flat.extend(map),
            Err(e) => {
                // A broken overlay must never take the CLI down: keep the layers below it.
                eprintln!("ark: i18n overlay {} ignored: {e}", path.display());
            }
        }
    }
    let arc: Catalog = Arc::new(flat);
    overlay_cache().lock().unwrap().insert(key, arc.clone());
    arc
}

/// Languages with at least one overlay file under `home`.
fn overlay_languages(home: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(overlay_dir(home)) else { return vec![] };
    let mut langs: Vec<String> = entries
        .flatten()
        .filter(|e| e.path().is_file())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let stem = name.strip_suffix(".json").or_else(|| name.strip_suffix(".yaml")).or_else(|| name.strip_suffix(".yml"))?;
            is_language_id(stem).then(|| normalize_language_id(stem))
        })
        .collect();
    langs.sort();
    langs.dedup();
    langs
}

/// Add a pack layer (per language); later registrations shadow earlier ones key by key.
pub fn register_pack(lang: &str, messages: &[(&str, &str)], source: &str) -> u64 {
    static TOKENS: AtomicU64 = AtomicU64::new(1);
    let id = normalize_language_id(lang);
    if !is_language_id(&id) {
        return 0; // invalid ids are refused like upstream; 0 = never a valid token
    }
    let token = TOKENS.fetch_add(1, Ordering::SeqCst);
    let entry = PackEntry {
        lang: id,
        messages: messages.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        source: source.to_string(),
        endonym: None,
        rtl: false,
        token,
    };
    packs().lock().unwrap().push(entry);
    reset_cache();
    token
}

/// Add a pack layer with picker metadata (`endonym`, `rtl`).
pub fn register_pack_full(lang: &str, messages: &[(&str, &str)], source: &str, endonym: Option<&str>, rtl: bool) -> u64 {
    let token = register_pack(lang, messages, source);
    if token != 0 {
        if let Some(e) = packs().lock().unwrap().iter_mut().find(|e| e.token == token) {
            e.endonym = endonym.map(str::to_string);
            e.rtl = rtl;
        }
    }
    token
}

/// Drop one registration (a plugin unloading). `false` when it was already gone.
pub fn unregister_pack(token: u64) -> bool {
    let mut g = packs().lock().unwrap();
    let before = g.len();
    g.retain(|e| e.token != token);
    let removed = g.len() != before;
    drop(g);
    if removed {
        reset_cache();
    }
    removed
}

/// Merged pack messages for `lang` in registration order (last wins).
fn pack_layer(lang: &str) -> HashMap<String, String> {
    let mut merged = HashMap::new();
    for e in packs().lock().unwrap().iter().filter(|e| e.lang == lang) {
        merged.extend(e.messages.clone());
    }
    merged
}

fn pack_languages() -> Vec<String> {
    let mut langs: Vec<String> = packs().lock().unwrap().iter().map(|e| e.lang.clone()).collect();
    langs.sort();
    langs.dedup();
    langs
}

fn pack_info(lang: &str) -> Option<PackEntry> {
    let g = packs().lock().unwrap();
    let entries: Vec<&PackEntry> = g.iter().filter(|e| e.lang == lang).collect();
    let newest = (*entries.iter().max_by_key(|e| e.token)?).clone();
    // endonym / rtl come from the newest registration that declared them.
    let endonym = entries.iter().rev().find_map(|e| e.endonym.clone());
    let rtl = entries.iter().rev().find(|e| e.endonym.is_some()).map(|e| e.rtl).unwrap_or(newest.rtl);
    Some(PackEntry { endonym, rtl, ..newest })
}

/// Merged catalog for `lang` in `home`: bundled < overlay < packs (cached per `(home, lang)`).
pub fn catalog(home: &Path, lang: &str) -> Catalog {
    let key = (home.to_path_buf(), lang.to_string());
    if let Some(hit) = catalog_cache().lock().unwrap().get(&key) {
        return hit.clone();
    }
    let mut merged = load_bundled(lang);
    merged.extend(overlay_layer(home, lang).iter().map(|(k, v)| (k.clone(), v.clone())));
    merged.extend(pack_layer(lang));
    let arc: Catalog = Arc::new(merged);
    catalog_cache().lock().unwrap().insert(key, arc.clone());
    arc
}

/// Every language some layer supplies for `home`: bundled ∪ overlay ∪ packs, `en` first then
/// sorted. Cached until [`reset_cache`].
pub fn supported_languages(home: &Path) -> Vec<String> {
    if let Some(hit) = supported_cache().lock().unwrap().get(home) {
        return (**hit).clone();
    }
    let mut langs: Vec<String> = BUNDLED_LANGUAGES.iter().map(|s| s.to_string()).collect();
    langs.extend(overlay_languages(home));
    langs.extend(pack_languages());
    langs.sort();
    langs.dedup();
    langs.retain(|l| *l != DEFAULT_LANGUAGE);
    let mut result = vec![DEFAULT_LANGUAGE.to_string()];
    result.extend(langs);
    supported_cache().lock().unwrap().insert(home.to_path_buf(), Arc::new(result.clone()));
    result
}

/// Canonical supported id for a user-supplied value (code, alias, regional tag), or `None` when
/// no layer supplies it — the validation `ark config set display.language` runs.
pub fn resolve_language_id(value: &str, home: &Path) -> Option<String> {
    let key = normalize_language_id(value);
    if key.is_empty() {
        return None;
    }
    let supported = supported_languages(home);
    if supported.contains(&key) {
        return Some(key);
    }
    if let Some(a) = alias(&key) {
        if supported.iter().any(|s| s == a) {
            return Some(a.to_string());
        }
    }
    let base = key.split('-').next().unwrap_or("").to_string();
    supported.contains(&base).then_some(base)
}

/// Picker rows for every supported language, `en` first: endonym + script direction + the
/// highest layer that supplies it.
pub fn languages(home: &Path) -> Vec<LanguageOption> {
    let overlays = overlay_languages(home);
    supported_languages(home)
        .into_iter()
        .map(|id| {
            let bundled = LANGUAGE_INFO.iter().find(|(l, _, _)| *l == id);
            let pack = pack_info(&id);
            let endonym = bundled.map(|(_, e, _)| e.to_string()).or_else(|| pack.as_ref().and_then(|p| p.endonym.clone())).unwrap_or_else(|| id.clone());
            let rtl = bundled.map(|(_, _, r)| *r).or_else(|| pack.as_ref().map(|p| p.rtl)).unwrap_or(false);
            let source = match &pack {
                Some(p) if !p.source.is_empty() => format!("plugin:{}", p.source),
                _ if overlays.contains(&id) && bundled.is_none() => "overlay".to_string(),
                _ => "bundled".to_string(),
            };
            LanguageOption { id, endonym, rtl, source }
        })
        .collect()
}

// ───────────────────────── resolution & lookup ─────────────────────────

fn env_language() -> Option<String> {
    std::env::var("ARK_LANGUAGE").ok().filter(|v| !v.trim().is_empty())
}

thread_local! {
    /// Explicit language for this thread — upstream's `t(key, lang=…)` argument, for a host that
    /// renders one language per task (and how tests localize without touching process state).
    static THREAD_LANGUAGE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Pin the language for the current thread (`None` clears it). Wins over every other source.
pub fn set_thread_language(lang: Option<&str>) {
    THREAD_LANGUAGE.with(|c| *c.borrow_mut() = lang.map(str::to_string));
}

pub fn thread_language() -> Option<String> {
    THREAD_LANGUAGE.with(|c| c.borrow().clone())
}

/// The active language: thread override > `ARK_LANGUAGE` > `display.language` > `en`.
pub fn active_language() -> String {
    active_language_in(&home())
}

pub fn active_language_in(home: &Path) -> String {
    let raw = thread_language().or_else(env_language).or_else(config_language_value);
    match raw {
        Some(v) => resolve_language_id(&v, home).unwrap_or_else(|| DEFAULT_LANGUAGE.to_string()),
        None => DEFAULT_LANGUAGE.to_string(),
    }
}

fn lookup(home: &Path, target: &str, key: &str) -> String {
    if let Some(v) = catalog(home, target).get(key) {
        return v.clone();
    }
    if target != DEFAULT_LANGUAGE {
        if let Some(v) = catalog(home, DEFAULT_LANGUAGE).get(key) {
            return v.clone();
        }
    }
    key.to_string()
}

/// Translate a dotted catalog key into the active language.
pub fn t(key: &str) -> String {
    t_in(&active_language(), key)
}

/// Translate into an explicit language (an unknown id falls back to the default).
pub fn t_in(lang: &str, key: &str) -> String {
    t_at(&home(), lang, key)
}

/// Translate into an explicit language for an explicit home (tests, multiplexed profiles).
pub fn t_at(home: &Path, lang: &str, key: &str) -> String {
    let target = resolve_language_id(lang, home).unwrap_or_else(|| DEFAULT_LANGUAGE.to_string());
    lookup(home, &target, key)
}

/// `{name}` substitution with the given arguments (missing names are left as written, so a bad
/// placeholder never hides the message).
pub fn render(text: &str, args: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            out.push('{');
            rest = after;
            continue;
        };
        let name = &after[..close];
        match args.iter().find(|(k, _)| *k == name) {
            Some((_, v)) => out.push_str(v),
            None => {
                out.push('{');
                out.push_str(name);
                out.push('}');
            }
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

/// Localized `/help` category heading (`"Session"` → `help.category.session`). A category no
/// catalog names is returned unchanged, so a plugin's own category still reads as written.
pub fn help_category(category: &str) -> String {
    let key = format!("help.category.{}", category.trim().to_lowercase().replace(' ', "_"));
    let home = home();
    let target = active_language_in(&home);
    if let Some(v) = catalog(&home, &target).get(&key) {
        return v.clone();
    }
    if let Some(v) = catalog(&home, DEFAULT_LANGUAGE).get(&key) {
        return v.clone();
    }
    category.to_string()
}

/// Translate with format arguments: `t_fmt("notice.error", &[("message", m)])`.
pub fn t_fmt(key: &str, args: &[(&str, &str)]) -> String {
    render(&t(key), args)
}

pub fn t_fmt_in(lang: &str, key: &str, args: &[(&str, &str)]) -> String {
    render(&t_in(lang, key), args)
}

pub fn t_fmt_at(home: &Path, lang: &str, key: &str, args: &[(&str, &str)]) -> String {
    render(&t_at(home, lang, key), args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// The engine keeps process-wide state (config language, caches, packs); tests that touch it
    /// take this lock so they never see each other's resets.
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        static L: OnceLock<Mutex<()>> = OnceLock::new();
        L.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
    }

    fn tmp_home() -> PathBuf {
        let d = std::env::temp_dir().join(format!("ark-i18n-{}", crate::util::random_hex(8)));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn reset() {
        reset_cache();
        *config_language().lock().unwrap() = None;
    }

    #[test]
    fn bundled_catalogs_are_complete_and_carry_the_same_keys() {
        let _g = lock();
        let en: Vec<String> = {
            let mut k: Vec<String> = parse_json_catalog(bundled_language("en").unwrap()).unwrap().into_keys().collect();
            k.sort();
            k
        };
        assert!(en.iter().any(|k| k == "approval.choices"));
        for lang in BUNDLED_LANGUAGES {
            let cat = parse_json_catalog(bundled_language(lang).unwrap_or_else(|| panic!("missing bundle {lang}"))).unwrap();
            for k in &en {
                assert!(matches!(cat.get(k), Some(v) if !v.trim().is_empty()), "{lang} lacks {k}");
                // Placeholders must survive translation or formatting silently breaks.
                for ph in placeholders(&en_text(k)) {
                    assert!(cat[k].contains(&ph), "{lang}:{k} lost {ph}");
                }
            }
        }
    }

    fn en_text(key: &str) -> String {
        parse_json_catalog(bundled_language("en").unwrap()).unwrap()[key].clone()
    }

    fn placeholders(text: &str) -> Vec<String> {
        let mut out = vec![];
        let mut rest = text;
        while let Some(open) = rest.find('{') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('}') else { break };
            out.push(format!("{{{}}}", &after[..close]));
            rest = &after[close + 1..];
        }
        out
    }

    #[test]
    fn layers_precedence_is_packs_over_overlay_over_bundled() {
        let _g = lock();
        let home = tmp_home();
        reset();
        // Bundled only.
        assert_eq!(t_at(&home, "ja", "notice.error"), "エラー: {message}");
        // Overlay overrides bundled (JSON).
        fs::create_dir_all(overlay_dir(&home)).unwrap();
        fs::write(overlay_dir(&home).join("ja.json"), r#"{"notice": {"error": "独自: {message}"}}"#).unwrap();
        reset();
        assert_eq!(t_at(&home, "ja", "notice.error"), "独自: {message}");
        assert_eq!(t_at(&home, "ja", "notice.bullet"), "• {text}", "a partial overlay keeps the bundled keys");
        // A YAML overlay wins a key conflict with the JSON one.
        fs::write(overlay_dir(&home).join("ja.yaml"), "notice:\n  error: \"YAML: {message}\"\n").unwrap();
        reset();
        assert_eq!(t_at(&home, "ja", "notice.error"), "YAML: {message}");
        // Packs beat both.
        let pack = register_pack("ja", &[("notice.error", "pack: {message}")], "acme");
        reset();
        assert_eq!(t_at(&home, "ja", "notice.error"), "pack: {message}");
        assert!(unregister_pack(pack));
        reset();
        assert_eq!(t_at(&home, "ja", "notice.error"), "YAML: {message}");
    }

    #[test]
    fn aliases_and_regional_tags_resolve_to_the_right_catalog() {
        let _g = lock();
        let home = tmp_home();
        reset();
        assert_eq!(resolve_language_id("chinese", &home).as_deref(), Some("zh"));
        assert_eq!(resolve_language_id("zh-CN", &home).as_deref(), Some("zh"));
        assert_eq!(resolve_language_id("zh_TW", &home).as_deref(), Some("zh-hant"));
        assert_eq!(resolve_language_id("Traditional_Chinese", &home).as_deref(), Some("zh-hant"));
        assert_eq!(resolve_language_id("jp", &home).as_deref(), Some("ja"));
        assert_eq!(resolve_language_id("Japanese", &home).as_deref(), Some("ja"));
        assert_eq!(resolve_language_id("en-GB", &home).as_deref(), Some("en"));
        assert_eq!(resolve_language_id("klingon", &home), None);
        assert_eq!(resolve_language_id("", &home), None);
        // A pack-only language becomes supported the moment its pack loads.
        assert_eq!(resolve_language_id("pl", &home), None);
        let pack = register_pack("pl", &[("notice.error", "błąd: {message}")], "acme");
        reset();
        assert!(supported_languages(&home).contains(&"pl".to_string()));
        assert_eq!(t_in("pl", "notice.error"), "błąd: {message}");
        unregister_pack(pack);
        reset();
    }

    #[test]
    fn supported_languages_and_picker_rows_name_their_source() {
        let _g = lock();
        let home = tmp_home();
        reset();
        fs::create_dir_all(overlay_dir(&home)).unwrap();
        fs::write(overlay_dir(&home).join("de.json"), r#"{"notice": {"bullet": "• {text}"}}"#).unwrap();
        reset();
        let langs = supported_languages(&home);
        assert_eq!(langs[0], "en", "en first");
        assert!(langs.contains(&"zh-hant".to_string()) && langs.contains(&"de".to_string()));
        let rows = languages(&home);
        let de = rows.iter().find(|r| r.id == "de").unwrap();
        assert_eq!((de.endonym.as_str(), de.source.as_str()), ("de", "overlay"));
        let ja = rows.iter().find(|r| r.id == "ja").unwrap();
        assert_eq!((ja.endonym.as_str(), ja.rtl, ja.source.as_str()), ("日本語", false, "bundled"));
    }

    #[test]
    fn env_overrides_config_and_config_overrides_the_default() {
        let _g = lock();
        let home = tmp_home();
        reset();
        set_config_language("ja");
        assert_eq!(active_language_in(&home), "ja");
        assert!(t_fmt_at(&home, &active_language_in(&home), "notice.error", &[("message", "boom")]).starts_with("エラー: boom"));
        // The env var wins over display.language, and is itself alias-resolved.
        std::env::set_var("ARK_LANGUAGE", "chinese");
        assert_eq!(active_language_in(&home), "zh");
        assert_eq!(t_fmt_at(&home, &active_language_in(&home), "notice.error", &[("message", "boom")]), "错误：boom");
        std::env::remove_var("ARK_LANGUAGE");
        // An unknown config value falls back to English rather than an empty catalog.
        set_config_language("klingon");
        assert_eq!(active_language_in(&home), "en");
        reset();
    }

    #[test]
    fn missing_keys_fall_back_to_english_then_the_bare_key() {
        let _g = lock();
        let home = tmp_home();
        reset();
        // Bundled in en only: zh falls back to English.
        let key = "help.title";
        assert_eq!(t_at(&home, "ja", key), "コマンド");
        assert_ne!(t_at(&home, "ja", "not.a.key"), "コマンド");
        assert_eq!(t_at(&home, "ja", "not.a.key"), "not.a.key");
        fs::create_dir_all(overlay_dir(&home)).unwrap();
        fs::write(overlay_dir(&home).join("ja.json"), r#"{"only": {"here": "ここだけ"}}"#).unwrap();
        reset();
        assert_eq!(t_at(&home, "ja", "only.here"), "ここだけ");
        // en is filled from its own bundle for a key the overlay-only language lacks.
        assert_eq!(t_at(&home, "ja", "notice.bullet"), "• {text}");
    }

    #[test]
    fn overlay_files_are_reloaded_after_cache_invalidation() {
        let _g = lock();
        let home = tmp_home();
        reset();
        fs::create_dir_all(overlay_dir(&home)).unwrap();
        let path = overlay_dir(&home).join("ja.json");
        fs::write(&path, r#"{"notice": {"bullet": "・{text}"}}"#).unwrap();
        reset();
        assert_eq!(t_at(&home, "ja", "notice.bullet"), "・{text}");
        fs::write(&path, r#"{"notice": {"bullet": "■ {text}"}}"#).unwrap();
        assert_eq!(t_at(&home, "ja", "notice.bullet"), "・{text}", "cached until invalidated");
        reset_cache();
        assert_eq!(t_at(&home, "ja", "notice.bullet"), "■ {text}");
    }

    #[test]
    fn yaml_subset_parser_handles_nesting_quotes_and_comments() {
        let _g = lock();
        let flat = parse_yaml_catalog("# header\napproval:\n  heading: \"⚑ {gate} gate — {reason}\"\n  choices: 'it''s here'\nhelp.category:\n  session: セッション\nnotice.error: plain # trailing comment\n").unwrap();
        assert_eq!(flat["approval.heading"], "⚑ {gate} gate — {reason}");
        assert_eq!(flat["approval.choices"], "it's here");
        assert_eq!(flat["help.category.session"], "セッション");
        assert_eq!(flat["notice.error"], "plain");
        assert!(parse_yaml_catalog("- a\n").is_err(), "sequences are refused, not misread");
    }

    #[test]
    fn help_category_headings_translate_and_unknown_ones_pass_through() {
        let _g = lock();
        reset();
        assert_eq!(help_category("Session"), "Session");
        set_config_language("zh-hant");
        assert_eq!(help_category("Session"), "工作階段");
        assert_eq!(help_category("Configuration"), "設定");
        assert_eq!(help_category("My Plugin Category"), "My Plugin Category", "unknown categories are not mangled");
        reset();
    }

    #[test]
    fn format_arguments_substitute_and_unknown_names_survive() {
        let _g = lock();
        assert_eq!(render("{a} and {b}", &[("a", "1"), ("b", "2")]), "1 and 2");
        assert_eq!(render("{a} {missing}", &[("a", "1")]), "1 {missing}");
        assert_eq!(render("no args", &[]), "no args");
        assert_eq!(render("{unclosed", &[("x", "1")]), "{unclosed");
    }

    #[test]
    fn display_language_config_key_reaches_the_engine() {
        let _g = lock();
        let dir = std::env::temp_dir().join(format!("ark-i18n-cfg-{}", crate::util::random_hex(8)));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("c.toml");
        fs::write(&file, "[display]\nlanguage = \"zh-TW\"\n").unwrap();
        let cfg = crate::config::Config::load(Some(&file), None, &[]).unwrap();
        assert_eq!(cfg.display.language, "zh-TW");
        reset();
        set_config_language(&cfg.display.language);
        let home = tmp_home();
        assert_eq!(active_language_in(&home), "zh-hant", "the config key is alias-resolved");
        assert!(t_fmt_at(&home, &active_language_in(&home), "notice.error", &[("message", "x")]).contains('x'));
        reset();
    }
}
