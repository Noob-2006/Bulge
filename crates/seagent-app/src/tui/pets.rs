//! Petdex mascots (Hermes `agent/pet/*`, `hermes_cli/pets.py`): animated sprite pets from
//! the public gallery at petdex.dev (or hatched locally) that react to agent activity in
//! the TUI.
//!
//! Store: `<data>/pets/<slug>/{pet.json, spritesheet.webp|png}` (profile-scoped). The
//! manifest (`https://petdex.dev/api/manifest`) is fetched read-only and cached for 5
//! minutes; asset downloads are host-pinned to petdex.dev and stream through a `.part`
//! file. Sheets are 8×9 (Codex, 1536×1872) or legacy 9×8 grids of 192×208 frames.
//! Sheets (WebP or PNG) are decoded in-process.
//! Config: `pet.{enabled,slug,scale,render_mode,unicode_cols}` in `ui.json`.

use super::png::{self, Rgba};
use super::prefs;
use seagent_kernel::config::Paths;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const MANIFEST_URL: &str = "https://petdex.dev/api/manifest";
pub const FRAME_W: usize = 192;
pub const FRAME_H: usize = 208;
pub const FRAMES_PER_STATE: usize = 6;
pub const LOOP_MS: u64 = 1100;
pub const DEFAULT_SCALE: f64 = 0.33;
pub const MIN_SCALE: f64 = 0.1;
pub const MAX_SCALE: f64 = 3.0;
pub const BASE_UNICODE_COLS: usize = FRAME_W / 8;
pub const UNICODE_MIN_COLS: usize = 16;
const MANIFEST_TTL: Duration = Duration::from_secs(300);
const UA: &str = "seagent-petdex";

pub const LEGACY_ROWS: &[&str] = &["idle", "wave", "run", "failed", "review", "jump", "extra1", "extra2"];
pub const CODEX_ROWS: &[&str] = &["idle", "running-right", "running-left", "waving", "jumping", "failed", "waiting", "running", "review"];
pub const STATES: &[&str] = &["idle", "wave", "run", "failed", "review", "jump", "waiting"];

pub fn clamp_scale(s: f64) -> f64 {
    s.clamp(MIN_SCALE, MAX_SCALE)
}

pub fn cols_for_scale(scale: f64) -> usize {
    let s = if scale > 0.0 { scale } else { DEFAULT_SCALE };
    ((BASE_UNICODE_COLS as f64 * s).round() as usize).max(UNICODE_MIN_COLS)
}

pub fn resolve_cols(scale: f64, unicode_cols: usize) -> usize {
    if unicode_cols > 0 {
        unicode_cols
    } else {
        cols_for_scale(scale)
    }
}

fn aliases(state: &str) -> Vec<&str> {
    match state {
        "wave" => vec!["wave", "waving"],
        "jump" => vec!["jump", "jumping"],
        "run" => vec!["run", "running"],
        s => vec![s],
    }
}

pub fn rows_for_grid(row_count: usize) -> &'static [&'static str] {
    if row_count >= CODEX_ROWS.len() {
        CODEX_ROWS
    } else {
        LEGACY_ROWS
    }
}

/// Spritesheet row for `state` (0 = idle when unknown).
pub fn state_row(state: &str, row_count: usize) -> usize {
    let rows = rows_for_grid(row_count);
    aliases(state).iter().find_map(|a| rows.iter().position(|r| r == a)).unwrap_or(0)
}

/// Activity → animation state (Hermes `derive_pet_state` priority order).
#[derive(Debug, Default, Clone, Copy)]
pub struct Activity {
    pub busy: bool,
    pub awaiting_input: bool,
    pub error: bool,
    pub celebrate: bool,
    pub just_completed: bool,
    pub tool_running: bool,
    pub reasoning: bool,
}

pub fn derive_state(a: &Activity) -> &'static str {
    [(a.error, "failed"), (a.celebrate, "jump"), (a.just_completed, "wave"), (a.awaiting_input, "waiting"), (a.tool_running, "run"), (a.reasoning, "review"), (a.busy, "run")].iter().find(|(f, _)| *f).map(|(_, s)| *s).unwrap_or("idle")
}

// ───────────── manifest ─────────────

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub slug: String,
    pub display_name: String,
    pub kind: String,
    pub submitted_by: String,
    pub spritesheet_url: String,
    pub pet_json_url: String,
    pub zip_url: String,
}

impl Entry {
    pub fn from_json(v: &Value) -> Entry {
        let s = |k: &str| v[k].as_str().unwrap_or("").trim().to_string();
        let slug = s("slug");
        Entry { display_name: Some(s("displayName")).filter(|x| !x.is_empty()).unwrap_or_else(|| slug.clone()), kind: Some(s("kind")).filter(|x| !x.is_empty()).unwrap_or_else(|| "pet".into()), submitted_by: s("submittedBy"), spritesheet_url: s("spritesheetUrl"), pet_json_url: s("petJsonUrl"), zip_url: s("zipUrl"), slug }
    }
}

/// Where the gallery lives; tests point it at a local server and widen the host pin.
#[derive(Debug, Clone)]
pub struct Petdex {
    pub manifest_url: String,
    /// Accept asset URLs on this host (and subdomains) only.
    pub host: String,
    pub timeout: Duration,
}

impl Default for Petdex {
    fn default() -> Self {
        Petdex { manifest_url: MANIFEST_URL.into(), host: "petdex.dev".into(), timeout: Duration::from_secs(60) }
    }
}

static MANIFEST_CACHE: Mutex<Option<(Instant, String, Vec<Entry>)>> = Mutex::new(None);

fn url_host(url: &str) -> String {
    let rest = url.split_once("://").map(|x| x.1).unwrap_or("");
    let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
    let auth = auth.rsplit('@').next().unwrap_or("");
    auth.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map(|(h, _)| h).unwrap_or(auth).to_ascii_lowercase()
}

impl Petdex {
    pub fn allowed(&self, url: &str) -> bool {
        let h = url_host(url);
        let https = url.starts_with("https://") || (self.host != "petdex.dev" && url.starts_with("http://"));
        https && (h == self.host || h.ends_with(&format!(".{}", self.host)))
    }
    fn agent(&self) -> ureq::Agent {
        seagent_net::http::builder().timeout_global(Some(self.timeout)).build().into()
    }
    fn get(&self, url: &str, limit: u64) -> Result<Vec<u8>, String> {
        let mut r = self.agent().get(url).header("User-Agent", UA).call().map_err(|e| format!("{url}: {e}"))?;
        r.body_mut().with_config().limit(limit).read_to_vec().map_err(|e| format!("{url}: {e}"))
    }
    /// Every approved pet (cached 5 min unless `force`).
    pub fn manifest(&self, force: bool) -> Result<Vec<Entry>, String> {
        if !force {
            if let Some((t, u, e)) = MANIFEST_CACHE.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
                if t.elapsed() < MANIFEST_TTL && *u == self.manifest_url {
                    return Ok(e.clone());
                }
            }
        }
        let body = self.get(&self.manifest_url, 32 << 20).map_err(|e| format!("could not fetch petdex manifest: {e}"))?;
        let v: Value = serde_json::from_slice(&body).map_err(|e| format!("could not fetch petdex manifest: {e}"))?;
        let pets = v["pets"].as_array().ok_or("petdex manifest had no 'pets' array")?;
        let entries: Vec<Entry> = pets.iter().filter(|p| p.is_object()).map(Entry::from_json).filter(|e| !e.slug.is_empty() && !e.spritesheet_url.is_empty()).collect();
        *MANIFEST_CACHE.lock().unwrap_or_else(|e| e.into_inner()) = Some((Instant::now(), self.manifest_url.clone(), entries.clone()));
        Ok(entries)
    }
    pub fn find(&self, slug: &str) -> Result<Option<Entry>, String> {
        let s = slug.trim().to_lowercase();
        Ok(self.manifest(false)?.into_iter().find(|e| e.slug.to_lowercase() == s))
    }
}

// ───────────── store ─────────────

#[derive(Debug, Clone, PartialEq)]
pub struct Pet {
    pub slug: String,
    pub display_name: String,
    pub description: String,
    pub dir: PathBuf,
    pub spritesheet: PathBuf,
    /// "generator" for hatched pets.
    pub created_by: String,
}

impl Pet {
    pub fn exists(&self) -> bool {
        self.spritesheet.is_file()
    }
    /// The sheet when it decodes (WebP / PNG / JPEG).
    pub fn png_sheet(&self) -> Option<PathBuf> {
        let b = std::fs::read(&self.spritesheet).ok()?;
        png::decode_any(&b).ok().map(|_| self.spritesheet.clone())
    }
}

pub fn pets_dir(paths: &Paths) -> PathBuf {
    let d = paths.data.join("pets");
    let _ = std::fs::create_dir_all(&d);
    d
}

/// One bare path segment, so `pets/<slug>` never escapes the store.
pub fn safe_slug(slug: &str) -> String {
    let seg = Path::new(slug.trim()).file_name().map(|x| x.to_string_lossy().into_owned()).unwrap_or_default();
    if seg == "." || seg == ".." {
        String::new()
    } else {
        seg
    }
}

pub fn slugify(name: &str) -> String {
    let mut o = String::new();
    let mut dash = false;
    for c in name.trim().to_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            o.push(c);
            dash = false;
        } else if !dash && !o.is_empty() {
            o.push('-');
            dash = true;
        }
    }
    let o = o.trim_end_matches('-').to_string();
    if o.is_empty() {
        "pet".into()
    } else {
        o
    }
}

pub fn unique_slug(paths: &Paths, name: &str) -> String {
    let base = slugify(name);
    (1..).map(|i| if i == 1 { base.clone() } else { format!("{base}-{i}") }).find(|s| !pets_dir(paths).join(s).exists()).unwrap_or(base)
}

fn read_meta(dir: &Path) -> Value {
    std::fs::read_to_string(dir.join("pet.json")).ok().and_then(|s| serde_json::from_str(s.trim_start_matches('\u{feff}')).ok()).filter(Value::is_object).unwrap_or_else(|| json!({}))
}

fn resolve_sheet(dir: &Path, meta: &Value) -> PathBuf {
    let declared = meta["spritesheetPath"].as_str().map(str::trim).filter(|s| !s.is_empty() && !s.contains('/') && !s.contains("..")).map(str::to_string);
    declared.into_iter().chain(["spritesheet.webp", "spritesheet.png", "sprite.webp", "sprite.png"].map(String::from)).map(|n| dir.join(n)).find(|p| p.is_file()).unwrap_or_else(|| dir.join("spritesheet.webp"))
}

pub fn load(paths: &Paths, slug: &str) -> Option<Pet> {
    let slug = safe_slug(slug);
    let dir = pets_dir(paths).join(&slug);
    if slug.is_empty() || !dir.is_dir() {
        return None;
    }
    let meta = read_meta(&dir);
    let s = |k: &str, d: &str| meta[k].as_str().filter(|x| !x.is_empty()).unwrap_or(d).to_string();
    Some(Pet { display_name: s("displayName", &slug), description: s("description", ""), created_by: s("createdBy", ""), spritesheet: resolve_sheet(&dir, &meta), dir, slug })
}

fn usable(paths: &Paths, slug: &str) -> Option<Pet> {
    load(paths, slug).filter(Pet::exists)
}

pub fn installed(paths: &Paths) -> Vec<Pet> {
    let mut names: Vec<String> = std::fs::read_dir(pets_dir(paths)).map(|rd| rd.flatten().filter(|e| e.path().is_dir()).map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| !n.starts_with('.')).collect()).unwrap_or_default();
    names.sort();
    names.iter().filter_map(|n| usable(paths, n)).collect()
}

/// The configured slug if installed, else the first pet alphabetically.
pub fn resolve_active(paths: &Paths, configured: &str) -> Option<Pet> {
    if !configured.trim().is_empty() {
        if let Some(p) = usable(paths, configured.trim()) {
            return Some(p);
        }
    }
    installed(paths).into_iter().next()
}

fn download(dex: &Petdex, url: &str, dest: &Path) -> Result<(), String> {
    let bytes = dex.get(url, 64 << 20).map_err(|e| format!("download failed for {url}: {e}"))?;
    let tmp = dest.with_extension(format!("{}.part", dest.extension().and_then(|e| e.to_str()).unwrap_or("")));
    std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, dest).map_err(|e| e.to_string())
}

/// Download `slug` from the gallery (idempotent unless `force`).
pub fn install(paths: &Paths, dex: &Petdex, slug: &str, force: bool) -> Result<Pet, String> {
    let slug = safe_slug(slug);
    if slug.is_empty() {
        return Err("invalid pet slug".into());
    }
    if !force {
        if let Some(p) = usable(paths, &slug) {
            return Ok(p);
        }
    }
    let e = dex.find(&slug)?.ok_or_else(|| format!("pet '{slug}' is not in the petdex manifest"))?;
    if !dex.allowed(&e.spritesheet_url) {
        return Err(format!("refusing non-petdex spritesheet host for '{slug}'"));
    }
    let dir = pets_dir(paths).join(&slug);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let ext = if e.spritesheet_url.split('?').next().unwrap_or("").to_lowercase().ends_with(".png") { "png" } else { "webp" };
    let sheet = dir.join(format!("spritesheet.{ext}"));
    download(dex, &e.spritesheet_url, &sheet)?;
    let _ = std::fs::remove_file(dir.join(".spritesheet.png"));
    let mut meta = if !e.pet_json_url.is_empty() && dex.allowed(&e.pet_json_url) { dex.get(&e.pet_json_url, 1 << 20).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()).filter(Value::is_object).unwrap_or_else(|| json!({})) } else { json!({}) };
    if meta.as_object().is_none_or(|o| o.is_empty()) {
        meta = json!({"id": slug, "displayName": e.display_name, "description": ""});
    }
    meta["spritesheetPath"] = json!(sheet.file_name().unwrap().to_string_lossy());
    if meta.get("id").is_none() {
        meta["id"] = json!(slug);
    }
    if meta.get("displayName").is_none() {
        meta["displayName"] = json!(e.display_name);
    }
    std::fs::write(dir.join("pet.json"), serde_json::to_string_pretty(&meta).unwrap_or_default()).map_err(|e| e.to_string())?;
    usable(paths, &slug).ok_or_else(|| format!("install of '{slug}' did not produce a spritesheet"))
}

/// Write a locally generated (hatched) PNG sheet into the store.
pub fn register_local(paths: &Paths, sheet_png: &[u8], slug: &str, display_name: &str, description: &str) -> Result<Pet, String> {
    let slug = slugify(slug);
    let dir = pets_dir(paths).join(&slug);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("spritesheet.png"), sheet_png).map_err(|e| format!("could not write spritesheet for '{slug}': {e}"))?;
    let meta = json!({"id": slug, "displayName": if display_name.is_empty() { slug.as_str() } else { display_name }, "description": description, "spritesheetPath": "spritesheet.png", "createdBy": "generator"});
    std::fs::write(dir.join("pet.json"), serde_json::to_string_pretty(&meta).unwrap_or_default()).map_err(|e| e.to_string())?;
    usable(paths, &slug).ok_or_else(|| format!("register of generated pet '{slug}' did not produce a spritesheet"))
}

pub fn remove(paths: &Paths, slug: &str) -> bool {
    let slug = safe_slug(slug);
    let dir = pets_dir(paths).join(&slug);
    if slug.is_empty() || !dir.is_dir() {
        return false;
    }
    let _ = std::fs::remove_dir_all(&dir);
    !dir.exists()
}

/// Rename a pet's display name and move it to `slugify(name)` when that slug is free.
pub fn rename(paths: &Paths, slug: &str, display_name: &str) -> Option<String> {
    let slug = safe_slug(slug);
    let name = display_name.trim();
    let mut dir = pets_dir(paths).join(&slug);
    if slug.is_empty() || name.is_empty() || !dir.join("pet.json").is_file() {
        return None;
    }
    let mut meta = read_meta(&dir);
    meta["displayName"] = json!(name);
    let mut new_slug = slug.clone();
    let want = slugify(name);
    if want != slug && !pets_dir(paths).join(&want).exists() && std::fs::rename(&dir, pets_dir(paths).join(&want)).is_ok() {
        dir = pets_dir(paths).join(&want);
        new_slug = want.clone();
        meta["id"] = json!(want);
    }
    std::fs::write(dir.join("pet.json"), serde_json::to_string_pretty(&meta).unwrap_or_default()).ok()?;
    let cfg = prefs::load(paths);
    if prefs::get_str(&cfg, "pet.slug", "") == slug && new_slug != slug {
        let _ = prefs::set(paths, "pet.slug", json!(new_slug));
    }
    Some(new_slug)
}

// ───────────── config helpers (pet.* in ui.json) ─────────────

pub fn config(paths: &Paths) -> Value {
    let v = prefs::get(&prefs::load(paths), "pet");
    if v.is_object() {
        v
    } else {
        json!({})
    }
}

pub fn enabled(cfg: &Value) -> bool {
    prefs::get_bool(cfg, "enabled", false)
}

pub fn set_active(paths: &Paths, slug: &str) -> Result<(), String> {
    prefs::set_many(paths, &[("pet.slug", json!(slug)), ("pet.enabled", json!(true))]).map(|_| ())
}

pub fn set_enabled(paths: &Paths, on: bool) -> Result<(), String> {
    prefs::set(paths, "pet.enabled", json!(on)).map(|_| ())
}

pub fn set_scale(paths: &Paths, value: &str) -> Result<f64, String> {
    let s: f64 = value.trim().parse().map_err(|_| format!("not a number: {value:?} — try a value like 0.5"))?;
    let s = clamp_scale(s);
    prefs::set(paths, "pet.scale", json!(s))?;
    Ok(s)
}

/// `/pet` toggle: (now enabled, pet name, error).
pub fn toggle(paths: &Paths) -> (bool, Option<String>, Option<String>) {
    let cfg = config(paths);
    let pet = resolve_active(paths, cfg["slug"].as_str().unwrap_or(""));
    if enabled(&cfg) {
        let _ = set_enabled(paths, false);
        return (false, pet.map(|p| p.display_name), None);
    }
    let Some(p) = pet else { return (false, None, Some("no pets installed — /pet list to browse, or /pet <slug> to adopt".into())) };
    let _ = set_active(paths, &p.slug);
    (true, Some(p.display_name), None)
}

/// Clear the active pet iff it is `slug` (after removal).
pub fn clear_active_if(paths: &Paths, slug: &str) -> bool {
    if config(paths)["slug"].as_str() == Some(slug) {
        return prefs::set_many(paths, &[("pet.slug", json!("")), ("pet.enabled", json!(false))]).is_ok();
    }
    false
}

// ───────────── rendering ─────────────

/// Terminal graphics protocol: kitty / iterm / unicode (sixel falls back to unicode).
pub fn detect_graphics(env: &std::collections::HashMap<String, String>) -> &'static str {
    let g = |k: &str| env.get(k).map(String::as_str).unwrap_or("");
    if g("TERM") == "xterm-kitty" || !g("KITTY_WINDOW_ID").is_empty() || g("TERM_PROGRAM") == "ghostty" {
        "kitty"
    } else if g("TERM_PROGRAM") == "iTerm.app" || g("TERM_PROGRAM") == "WezTerm" || g("LC_TERMINAL") == "iTerm2" {
        "iterm"
    } else {
        "unicode"
    }
}

pub fn resolve_mode(configured: &str, env: &std::collections::HashMap<String, String>) -> &'static str {
    match configured {
        "kitty" => "kitty",
        "iterm" => "iterm",
        "unicode" | "sixel" => "unicode",
        _ => detect_graphics(env),
    }
}

pub struct Sheet {
    pub img: Rgba,
    pub cols: usize,
    pub rows: usize,
}

impl Sheet {
    pub fn load(path: &Path) -> Result<Sheet, String> {
        let img = png::decode_any(&std::fs::read(path).map_err(|e| e.to_string())?)?;
        let cols = (img.w / FRAME_W).max(1);
        let rows = (img.h / FRAME_H).max(1);
        Ok(Sheet { img, cols, rows })
    }
    pub fn frame(&self, state: &str, i: usize) -> Rgba {
        let row = state_row(state, self.rows).min(self.rows - 1);
        let n = self.frame_count(state);
        let col = i % n.max(1);
        self.img.crop(col * FRAME_W, row * FRAME_H, FRAME_W, FRAME_H)
    }
    /// Non-empty frames in the state's row (≤ FRAMES_PER_STATE stepped, like petdex CSS).
    pub fn frame_count(&self, state: &str) -> usize {
        let row = state_row(state, self.rows).min(self.rows - 1);
        let filled = (0..self.cols).take_while(|c| self.img.crop(c * FRAME_W, row * FRAME_H, FRAME_W, FRAME_H).bbox(16).is_some()).count();
        filled.clamp(1, FRAMES_PER_STATE.max(1)).min(self.cols)
    }
}

fn ansi_rgb(bgnd: bool, c: [u8; 4]) -> String {
    format!("\x1b[{};2;{};{};{}m", if bgnd { 48 } else { 38 }, c[0], c[1], c[2])
}

/// Truecolor half-block rendering, `cols` wide (one cell = 1×2 sampled pixels).
pub fn render_unicode(frame: &Rgba, cols: usize) -> Vec<String> {
    let cols = cols.max(1);
    let rows2 = ((frame.h as f64 * cols as f64 / frame.w as f64).round() as usize).max(2);
    let small = frame.resize(cols, rows2 + rows2 % 2);
    let mut lines = vec![];
    for y in (0..small.h).step_by(2) {
        let mut l = String::new();
        for x in 0..small.w {
            let (t, b) = (small.get(x, y), small.get(x, y + 1));
            match (t[3] > 64, b[3] > 64) {
                (false, false) => l.push_str("\x1b[0m "),
                (true, false) => l.push_str(&format!("\x1b[0m{}▀", ansi_rgb(false, t))),
                (false, true) => l.push_str(&format!("\x1b[0m{}▄", ansi_rgb(false, b))),
                (true, true) => l.push_str(&format!("{}{}▀", ansi_rgb(false, t), ansi_rgb(true, b))),
            }
        }
        l.push_str("\x1b[0m");
        lines.push(l);
    }
    lines
}

fn b64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                o.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                o.push('=');
            }
        }
    }
    o
}

/// kitty graphics protocol (PNG payload, chunked 4096).
pub fn render_kitty(frame: &Rgba, cols: usize) -> String {
    let data = b64(&png::encode(frame));
    let chunks: Vec<&str> = data.as_bytes().chunks(4096).map(|c| std::str::from_utf8(c).unwrap_or("")).collect();
    let mut o = String::new();
    for (i, c) in chunks.iter().enumerate() {
        let more = if i + 1 < chunks.len() { 1 } else { 0 };
        if i == 0 {
            o.push_str(&format!("\x1b_Gf=100,a=T,c={cols},m={more};{c}\x1b\\"));
        } else {
            o.push_str(&format!("\x1b_Gm={more};{c}\x1b\\"));
        }
    }
    o
}

/// iTerm2 inline image (also WezTerm).
pub fn render_iterm(frame: &Rgba, cols: usize) -> String {
    let p = png::encode(frame);
    format!("\x1b]1337;File=inline=1;size={};width={cols};preserveAspectRatio=1:{}\x07", p.len(), b64(&p))
}

/// `seagent pets doctor` report.
pub fn doctor(paths: &Paths) -> String {
    let cfg = config(paths);
    let env: std::collections::HashMap<String, String> = std::env::vars().collect();
    let pets = installed(paths);
    let configured = cfg["slug"].as_str().unwrap_or("").to_string();
    let active = resolve_active(paths, &configured);
    let mode = cfg["render_mode"].as_str().unwrap_or("auto").to_string();
    let mut o = String::from("petdex doctor\n");
    o.push_str(&format!("  pets dir:            {}\n", pets_dir(paths).display()));
    o.push_str(&format!("  installed:           {} ({})\n", pets.len(), if pets.is_empty() { "none".into() } else { pets.iter().map(|p| p.slug.as_str()).collect::<Vec<_>>().join(", ") }));
    o.push_str(&format!("  pet.enabled:         {}\n", enabled(&cfg)));
    o.push_str(&format!("  pet.slug:            {}\n", if configured.is_empty() { "(unset)" } else { &configured }));
    o.push_str(&format!("  active (resolved):   {}\n", active.as_ref().map(|p| p.slug.as_str()).unwrap_or("(none)")));
    o.push_str(&format!("  pet.render_mode:     {mode}\n"));
    o.push_str(&format!("  detected graphics:   {}\n", detect_graphics(&env)));
    o.push_str(&format!("  effective mode:      {}\n", resolve_mode(&mode, &env)));
    let mut ok = true;
    if pets.is_empty() {
        o.push_str("  → no pets installed. Run: seagent pets install boba\n");
        ok = false;
    } else if let Some(p) = &active {
        if p.png_sheet().is_none() {
            o.push_str(&format!("  ✗ {}'s spritesheet does not decode ({})\n", p.slug, p.spritesheet.display()));
            ok = false;
        }
        if !enabled(&cfg) {
            o.push_str(&format!("  → pet display is disabled. Run: seagent pets select {}\n", p.slug));
        }
    } else {
        o.push_str("  → active pet unresolved. Run: seagent pets select <slug>\n");
        ok = false;
    }
    o.push_str(if ok && enabled(&cfg) { "  ✓ ready" } else { "  (run the suggestions above to finish setup)" });
    o
}

/// Gallery listing (`/pet list`, `seagent pets list`).
pub fn gallery_text(paths: &Paths, dex: &Petdex, query: &str, limit: usize) -> Result<String, String> {
    let q = query.trim().to_lowercase();
    let entries: Vec<Entry> = dex.manifest(false)?.into_iter().filter(|e| q.is_empty() || e.slug.to_lowercase().contains(&q) || e.display_name.to_lowercase().contains(&q)).collect();
    let have: Vec<String> = installed(paths).into_iter().map(|p| p.slug).collect();
    let shown = if limit > 0 { &entries[..entries.len().min(limit)] } else { &entries[..] };
    let mut o = format!("petdex gallery — {} pet(s){}:\n", entries.len(), if q.is_empty() { String::new() } else { format!(" matching '{q}'") });
    for e in shown {
        o.push_str(&format!("  {} {:<28} {}  ({})\n", if have.contains(&e.slug) { "✓" } else { " " }, e.slug, e.display_name, e.kind));
    }
    if limit > 0 && entries.len() > limit {
        o.push_str(&format!("  … {} more (use --limit 0 or a query to filter)\n", entries.len() - limit));
    }
    o.push_str("\nInstall one with: seagent pets install <slug>   (or /pet <slug>)");
    Ok(o)
}

/// Rendered pet lines for the TUI corner (unicode only), or empty when off / unrenderable.
#[derive(Default)]
pub struct Pane {
    sheet: Option<(PathBuf, Sheet)>,
    checked: Option<Instant>,
}

impl Pane {
    pub fn lines(&mut self, paths: &Paths, state: &str, tick_ms: u64) -> Vec<String> {
        let cfg = config(paths);
        if !enabled(&cfg) {
            self.sheet = None;
            return vec![];
        }
        if self.checked.is_none_or(|t| t.elapsed() > Duration::from_secs(2)) {
            self.checked = Some(Instant::now());
            let want = resolve_active(paths, cfg["slug"].as_str().unwrap_or("")).and_then(|p| p.png_sheet());
            if want.as_ref() != self.sheet.as_ref().map(|s| &s.0) {
                self.sheet = want.and_then(|p| Sheet::load(&p).ok().map(|s| (p, s)));
            }
        }
        let Some((_, sheet)) = &self.sheet else { return vec![] };
        let scale = cfg["scale"].as_f64().unwrap_or(DEFAULT_SCALE);
        let cols = resolve_cols(scale, cfg["unicode_cols"].as_u64().unwrap_or(0) as usize);
        let n = sheet.frame_count(state) as u64;
        let i = ((tick_ms % LOOP_MS) * n / LOOP_MS) as usize;
        render_unicode(&sheet.frame(state, i), cols)
    }
}

// ───────────── hatching ─────────────

/// Image backend for sprite generation: returns encoded image bytes (PNG preferred).
pub trait SpriteGen: Send + Sync {
    fn generate(&self, prompt: &str, reference: Option<&[u8]>, aspect: &str) -> Result<Vec<u8>, String>;
}

pub const ROW_SPECS: &[(&str, usize, usize)] = &[("idle", 0, 6), ("running-right", 1, 8), ("running-left", 2, 8), ("waving", 3, 4), ("jumping", 4, 5), ("failed", 5, 8), ("waiting", 6, 6), ("running", 7, 6), ("review", 8, 6)];
const REQUIRED: &[&str] = &["idle", "running-right", "waving"];
const MIN_FILLED: usize = 6;

fn action(state: &str) -> &'static str {
    match state {
        "idle" => "a calm idle loop: subtle breathing, a tiny blink or gentle bob, no big gestures",
        "running-right" => "a sideways walk/run locomotion cycle moving to the RIGHT: the character faces and travels right with clear directional steps, a smooth gait loop",
        "running-left" => "a sideways walk/run locomotion cycle moving to the LEFT: the character faces and travels left with clear directional steps (the mirror of the right-facing run)",
        "waving" => "a friendly greeting: raising a paw/hand/limb to wave, clear up-and-down gesture",
        "jumping" => "a happy celebration jump: anticipation, lift off the ground, peak, and land",
        "failed" => "a sad or deflated reaction: slumped, dejected, small frown — readable but not noisy",
        "waiting" => "an expectant 'waiting on you' pose: looking up/out as if asking for input or approval — distinct from idle and review",
        "running" => "focused active work, staying IN PLACE (NOT walking or foot-running): leaning in, concentrating, busy 'thinking / processing / typing' energy",
        "review" => "careful inspection: a focused lean, head tilt, studying something intently",
        _ => "a simple idle pose",
    }
}

const BACKGROUND: &str = "Center the character on a SINGLE flat, uniform, high-contrast chroma-key background — pure hot magenta #FF00FF (only if magenta appears on the character, use pure green #00FF00 instead). The background is ONE continuous even color that completely surrounds the character with NO gradient, vignette, texture, pattern, scenery, shadow, ground line, frame, border, panel, comic cell, gutter line, grid, or divider of any kind, so it keys out cleanly. The background color must not appear anywhere on the character. No text, no labels, no speech bubbles, no UI.";

pub fn style_hint(style: &str) -> &'static str {
    match style.trim().to_lowercase().as_str() {
        "pixel" => " Render in clean 16-bit pixel-art style with visible square pixels and a limited palette.",
        "plush" => " Render as a soft plush toy.",
        "clay" => " Render as a claymation / soft 3D clay figure.",
        "sticker" => " Render as a glossy die-cut sticker.",
        "flat-vector" => " Render in flat vector mascot style.",
        "3d-toy" => " Render as a glossy 3D toy.",
        "painterly" => " Render in a soft painterly style.",
        _ => " Style: crisp 16-bit PIXEL-ART game sprite — visible square pixels, a small limited palette, clean dark outline, flat cel shading, chunky chibi proportions, like a classic SNES/JRPG party member or a petdex.dev mascot. Absolutely NOT 3D-rendered, NOT a smooth painted or vector illustration, NOT photorealistic — no soft gradients, no realistic lighting, no figurine look.",
    }
}

pub fn base_prompt(concept: &str, style: &str) -> String {
    let concept = if concept.trim().is_empty() { "a distinctive mascot creature" } else { concept.trim() };
    format!("A stylized mascot pet character: {concept}. Honor the requested tone and mood exactly (cute, eerie, scary, menacing, whimsical, etc.) while staying non-graphic. Compact, whole-body silhouette that reads clearly at small size, clear readable facial features, simple consistent palette. Neutral front-facing standing pose, upright and symmetric, arms/limbs relaxed at the sides, feet together on the ground, any cape/accessories hanging straight and still. {BACKGROUND}{}", style_hint(style))
}

pub fn row_prompt(state: &str, frames: usize, concept: &str, style: &str) -> String {
    let concept = if concept.trim().is_empty() { "the mascot" } else { concept.trim() };
    let slot = 1536.0 / frames.max(1) as f64;
    let (pose, gap) = ((slot * 0.7).round() as usize, ((slot * 0.3).round() as usize).max(48));
    format!("Using the attached reference image as the exact same character ({concept}: same species, face, colors, markings, proportions, and props), preserving the same emotional tone/mood (e.g., scary stays scary, cute stays cute), draw a single WIDE horizontal strip of {frames} animation frames showing {}. LAYOUT: arrange {frames} poses in ONE horizontal row at equal spacing, each pose centered in its own imaginary equal region. Draw NO panel borders, NO comic cells, NO boxes, NO vertical divider/gutter lines, NO grid, NO frame outlines between poses — the backdrop is one unbroken flat field behind all of them. Fill the WHOLE strip with the SAME single flat chroma-key color as the attached reference image's background (identical hue in every frame, no per-pose color shifts). SPACING (critical): draw each pose at a consistent, healthy, clearly visible size (roughly {pose}px wide on a 1536px strip) — do NOT shrink it tiny — but keep its ENTIRE silhouette (wings, tail, halo, horns, cape, every appendage) fully INSIDE its own cell. Leave at least {gap}px of empty chroma-key background between neighboring silhouettes at their closest point, and the same empty margin before the first pose and after the last. Silhouettes must NEVER touch, overlap, share a shadow, share a ground line, share motion trails, or merge into one connected shape. REGISTRATION (critical): the character is the SAME height and SAME width in every frame, drawn at the SAME scale, centered over the SAME point, with all feet aligned to the SAME invisible horizontal baseline across the whole strip — draw NO ground line, floor, platform, horizon, or contact shadow beneath the feet. Keep the body's center, size, and stance fixed frame to frame — ONLY the limbs/features the action needs may move. No pose is cropped at the strip edges. {BACKGROUND}{}", action(state), style_hint(style))
}

/// Key out the flat background (the dominant corner colour) to transparency.
pub fn chroma_key(img: &mut Rgba) {
    if img.w == 0 || img.h == 0 {
        return;
    }
    let corners = [img.get(0, 0), img.get(img.w - 1, 0), img.get(0, img.h - 1), img.get(img.w - 1, img.h - 1)];
    let bg = *corners.iter().max_by_key(|c| corners.iter().filter(|d| dist(c, d) < 60).count()).unwrap();
    if bg[3] < 16 {
        return; // already transparent
    }
    for y in 0..img.h {
        for x in 0..img.w {
            let p = img.get(x, y);
            let d = dist(&p, &bg);
            if d < 90 {
                img.put(x, y, [0, 0, 0, 0]);
            } else if d < 140 {
                // Soft edge: fade and de-spill.
                let a = ((d - 90) * 255 / 50) as u8;
                img.put(x, y, [p[0], p[1], p[2], a.min(p[3])]);
            }
        }
    }
}

fn dist(a: &[u8; 4], b: &[u8; 4]) -> u32 {
    (0..3).map(|i| (a[i] as i32 - b[i] as i32).unsigned_abs()).sum()
}

/// Fit a sprite into one 192×208 cell: trim, scale to fit (pad 14), centre, sit on the baseline.
pub fn fit_cell(sprite: &Rgba) -> Rgba {
    let mut cell = Rgba::new(FRAME_W, FRAME_H);
    let Some((x0, y0, x1, y1)) = sprite.bbox(16) else { return cell };
    let trimmed = sprite.crop(x0, y0, x1 - x0, y1 - y0);
    let pad = 14;
    let (mw, mh) = ((FRAME_W - 2 * pad) as f64, (FRAME_H - 2 * pad) as f64);
    let s = (mw / trimmed.w as f64).min(mh / trimmed.h as f64);
    let (w, h) = (((trimmed.w as f64 * s).round() as usize).max(1), ((trimmed.h as f64 * s).round() as usize).max(1));
    let r = trimmed.resize(w, h);
    cell.blit(&r, (FRAME_W - w) / 2, FRAME_H - pad - h);
    cell
}

/// Slice a keyed strip into `n` equal regions, each fitted to a cell; empty regions dropped.
pub fn slice_strip(strip: &Rgba, n: usize) -> Vec<Rgba> {
    let w = strip.w / n.max(1);
    (0..n).map(|i| strip.crop(i * w, 0, w, strip.h)).filter(|r| r.bbox(16).is_some()).map(|r| fit_cell(&r)).collect()
}

pub fn friendly_error(e: &str) -> String {
    let l = e.to_lowercase();
    if ["moderation_blocked", "safety system", "content policy", "content_policy"].iter().any(|k| l.contains(k)) {
        return "The image provider blocked this prompt — its safety filter rejects trademarked characters and real people. Try an original description.".into();
    }
    if ["api key", "unauthorized", "401"].iter().any(|k| l.contains(k)) {
        return "The image provider rejected the request — check its API key ([media.providers.*] or the provider env var).".into();
    }
    if l.contains("rate limit") || l.contains("429") {
        return "The image provider is rate-limiting — wait a moment and try again.".into();
    }
    e.to_string()
}

pub struct Hatched {
    pub pet: Pet,
    pub states: Vec<String>,
}

/// Generate a pet from a description: base look → one strip per state (running-left is
/// mirrored) → keyed, sliced, fitted frames → 8×9 atlas → store, then adopt it.
pub fn hatch(paths: &Paths, gen: &dyn SpriteGen, concept: &str, style: &str, progress: &(dyn Fn(&str) + Sync)) -> Result<Hatched, String> {
    let concept = concept.trim();
    if concept.is_empty() {
        return Err("usage: /hatch <description of your pet>".into());
    }
    let display: String = concept.split_whitespace().take(3).map(|w| {
        let mut c = w.chars();
        c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
    }).collect::<Vec<_>>().join(" ").chars().take(28).collect::<String>().trim().to_string();
    let display = if display.is_empty() { "New Pet".to_string() } else { display };
    progress(&format!("designing “{concept}”…"));
    let base_bytes = gen.generate(&base_prompt(concept, style), None, "square").map_err(|e| friendly_error(&e))?;
    let mut base = png::decode_any(&base_bytes)?;
    chroma_key(&mut base);
    let base_png = png::encode(&base);
    let specs: Vec<(&str, usize, usize)> = ROW_SPECS.iter().copied().filter(|s| s.0 != "running-left").collect();
    let results: Mutex<Vec<(String, Vec<Rgba>)>> = Mutex::new(vec![]);
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|sc| {
        for _ in 0..4 {
            sc.spawn(|| loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let Some(&(state, _, count)) = specs.get(i) else { break };
                progress(&format!("drawing {state}…"));
                let mut frames = vec![];
                for _attempt in 0..2 {
                    if let Ok(b) = gen.generate(&row_prompt(state, count, concept, style), Some(&base_png), "landscape") {
                        if let Ok(mut strip) = png::decode_any(&b) {
                            chroma_key(&mut strip);
                            frames = slice_strip(&strip, count);
                            if !frames.is_empty() {
                                break;
                            }
                        }
                    }
                }
                frames.truncate(count);
                results.lock().unwrap_or_else(|e| e.into_inner()).push((state.to_string(), frames));
            });
        }
    });
    let mut by: std::collections::HashMap<String, Vec<Rgba>> = results.into_inner().unwrap_or_default().into_iter().filter(|(_, f)| !f.is_empty()).collect();
    if !by.contains_key("idle") {
        // Idle falls back to the base look so the pet always renders.
        by.insert("idle".into(), vec![fit_cell(&base); 6]);
    }
    if let Some(r) = by.get("running-right").cloned() {
        by.insert("running-left".into(), r.iter().map(Rgba::mirror).collect());
    }
    let missing: Vec<&str> = REQUIRED.iter().copied().filter(|s| !by.contains_key(*s)).collect();
    if !missing.is_empty() || by.len() < MIN_FILLED {
        return Err(format!("hatch failed: only {} of {} animation rows came back (missing {})", by.len(), ROW_SPECS.len(), if missing.is_empty() { "several".into() } else { missing.join(", ") }));
    }
    progress("composing the spritesheet…");
    let mut atlas = Rgba::new(8 * FRAME_W, ROW_SPECS.len() * FRAME_H);
    for (state, row, count) in ROW_SPECS {
        for (col, f) in by.get(*state).into_iter().flatten().take((*count).min(8)).enumerate() {
            atlas.blit(f, col * FRAME_W, row * FRAME_H);
        }
    }
    let slug = unique_slug(paths, &display);
    let pet = register_local(paths, &png::encode(&atlas), &slug, &display, concept)?;
    set_active(paths, &pet.slug)?;
    let mut states: Vec<String> = by.into_keys().collect();
    states.sort();
    Ok(Hatched { pet, states })
}

/// Test fixtures shared with the `seagent` crate's tests (a fake petdex gallery).
#[doc(hidden)]
pub mod tests_support {
    use super::*;
    use std::io::{BufRead, BufReader, Write};

    /// A sprite strip: `n` filled squares on a magenta field.
    pub fn strip(n: usize, w: usize, h: usize) -> Vec<u8> {
        let mut img = Rgba::new(w, h);
        for y in 0..h {
            for x in 0..w {
                img.put(x, y, [255, 0, 255, 255]);
            }
        }
        let slot = w / n.max(1);
        for i in 0..n {
            for y in h / 4..h * 3 / 4 {
                for x in i * slot + slot / 4..i * slot + slot * 3 / 4 {
                    img.put(x, y, [20, 120 + i as u8 * 10, 40, 255]);
                }
            }
        }
        png::encode(&img)
    }

    /// Serves `/api/manifest`, `/s/<slug>.png` and `/j/<slug>.json` for the given slugs.
    pub fn fake_petdex(slugs: &[&str]) -> (String, std::thread::JoinHandle<()>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
        let pets: Vec<Value> = slugs.iter().map(|s| json!({"slug": s, "displayName": s.to_uppercase(), "kind": "creature", "spritesheetUrl": format!("{base}/s/{s}.png"), "petJsonUrl": format!("{base}/j/{s}.json")})).chain([json!({"slug": "evil", "spritesheetUrl": "https://evil.example/x.png"}), json!({"slug": "", "spritesheetUrl": "x"})]).collect();
        let manifest = serde_json::to_vec(&json!({"total": pets.len(), "pets": pets})).unwrap();
        let mut atlas = Rgba::new(8 * FRAME_W, 9 * FRAME_H);
        for row in 0..9 {
            for col in 0..6 {
                for y in 40..160 {
                    for x in 50..140 {
                        atlas.put(col * FRAME_W + x, row * FRAME_H + y, [200, row as u8 * 20, col as u8 * 30, 255]);
                    }
                }
            }
        }
        let sheet = png::encode(&atlas);
        let h = std::thread::spawn(move || {
            for s in l.incoming().take(16) {
                let Ok(mut s) = s else { continue };
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                loop {
                    let mut h = String::new();
                    if r.read_line(&mut h).unwrap() == 0 || h == "\r\n" {
                        break;
                    }
                }
                let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (code, body): (u16, Vec<u8>) = if path == "/api/manifest" {
                    (200, manifest.clone())
                } else if path.starts_with("/s/") {
                    (200, sheet.clone())
                } else if let Some(j) = path.strip_prefix("/j/") {
                    (200, serde_json::to_vec(&json!({"id": j.trim_end_matches(".json"), "displayName": "From JSON", "description": "d"})).unwrap())
                } else {
                    (404, b"no".to_vec())
                };
                let _ = write!(s, "HTTP/1.1 {code} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len());
                let _ = s.write_all(&body);
            }
        });
        (base, h)
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::*;
    use super::*;
    use crate::tui::prefs::test_paths;

    #[test]
    fn geometry_states_and_scale() {
        assert_eq!(state_row("wave", 9), 3);
        assert_eq!(state_row("wave", 8), 1);
        assert_eq!(state_row("run", 9), 7);
        assert_eq!(state_row("run", 8), 2);
        assert_eq!(state_row("jump", 9), 4);
        assert_eq!(state_row("jump", 8), 5);
        assert_eq!(state_row("review", 9), 8);
        assert_eq!(state_row("review", 8), 4);
        assert_eq!(state_row("bogus", 9), 0);
        assert_eq!(rows_for_grid(9), CODEX_ROWS);
        assert_eq!(rows_for_grid(8), LEGACY_ROWS, "legacy 8-row sheets keep their own row order");
        assert_eq!(cols_for_scale(0.33), UNICODE_MIN_COLS);
        assert_eq!(cols_for_scale(1.0), 24);
        assert_eq!(resolve_cols(1.0, 30), 30);
        assert_eq!(clamp_scale(9.0), MAX_SCALE);
        assert_eq!(clamp_scale(0.01), MIN_SCALE);
        assert_eq!(derive_state(&Activity { busy: true, awaiting_input: true, ..Default::default() }), "waiting");
        assert_eq!(derive_state(&Activity { busy: true, tool_running: true, ..Default::default() }), "run");
        assert_eq!(derive_state(&Activity { error: true, celebrate: true, ..Default::default() }), "failed");
        assert_eq!(derive_state(&Activity { celebrate: true, ..Default::default() }), "jump");
        assert_eq!(derive_state(&Activity { just_completed: true, ..Default::default() }), "wave");
        // just_completed outranks awaiting_input, which outranks reasoning.
        assert_eq!(derive_state(&Activity { just_completed: true, awaiting_input: true, ..Default::default() }), "wave");
        assert_eq!(derive_state(&Activity { awaiting_input: true, reasoning: true, ..Default::default() }), "waiting");
        assert_eq!(derive_state(&Activity { reasoning: true, ..Default::default() }), "review");
        assert_eq!(derive_state(&Activity::default()), "idle");
        assert_eq!(slugify("  Fire Dragon!! "), "fire-dragon");
        assert_eq!(safe_slug("../../etc"), "etc");
        assert_eq!(safe_slug(".."), "");
        let dex = Petdex::default();
        assert!(dex.allowed("https://cdn.petdex.dev/a.webp"));
        assert!(!dex.allowed("https://petdex.dev.evil.com/a"));
        assert!(!dex.allowed("http://petdex.dev/a"));
        let mut env = std::collections::HashMap::new();
        env.insert("TERM".to_string(), "xterm-kitty".to_string());
        assert_eq!(resolve_mode("auto", &env), "kitty");
        assert_eq!(resolve_mode("sixel", &env), "unicode");
    }

    #[test]
    fn install_select_render_and_remove() {
        let p = test_paths("pets");
        let (base, _h) = fake_petdex(&["boba", "mochi"]);
        let dex = Petdex { manifest_url: format!("{base}/api/manifest"), host: "127.0.0.1".into(), timeout: Duration::from_secs(5) };
        let entries = dex.manifest(true).unwrap();
        assert_eq!(entries.iter().map(|e| e.slug.as_str()).collect::<Vec<_>>(), ["boba", "mochi", "evil"]);
        assert!(install(&p, &dex, "evil", false).unwrap_err().contains("refusing non-petdex"));
        assert!(install(&p, &dex, "nope", false).unwrap_err().contains("not in the petdex manifest"));
        // The store never escapes `<data>/pets`: traversal collapses to one bare segment.
        assert!(install(&p, &dex, "..", false).unwrap_err().contains("invalid pet slug"));
        assert!(load(&p, "..").is_none() && !remove(&p, ".."));
        assert!(install(&p, &dex, "/etc/passwd", false).unwrap_err().contains("not in the petdex manifest"));
        // Traversal collapses to the last segment, so it can never land outside `<data>/pets`.
        let escaped = install(&p, &dex, "../../boba/", false).unwrap();
        assert_eq!(escaped.slug, "boba");
        assert!(escaped.dir.starts_with(pets_dir(&p)), "{:?}", escaped.dir);
        assert!(remove(&p, "boba"));
        assert!(installed(&p).is_empty());
        let pet = install(&p, &dex, "boba", false).unwrap();
        assert_eq!(pet.display_name, "From JSON");
        assert!(pet.spritesheet.ends_with("boba/spritesheet.png"));
        let meta = read_meta(&pet.dir);
        assert_eq!(meta["spritesheetPath"], "spritesheet.png");
        assert!(gallery_text(&p, &dex, "bo", 40).unwrap().contains("✓ boba"));
        assert_eq!(installed(&p).len(), 1);
        // toggle adopts the first installed pet; second toggle turns it off.
        assert!(toggle(&p).0);
        assert_eq!(config(&p)["slug"], "boba");
        assert!(!toggle(&p).0);
        set_active(&p, "boba").unwrap();
        assert_eq!(set_scale(&p, "7").unwrap(), MAX_SCALE);
        assert!(set_scale(&p, "big").is_err());
        prefs::set(&p, "pet.scale", json!(0.33)).unwrap();
        let sheet = Sheet::load(&pet.png_sheet().unwrap()).unwrap();
        assert_eq!((sheet.cols, sheet.rows), (8, 9));
        assert_eq!(sheet.frame_count("idle"), 6);
        let lines = render_unicode(&sheet.frame("wave", 1), 16);
        assert!(lines.len() >= 8 && lines.iter().any(|l| l.contains("▀")));
        let mut pane = Pane::default();
        assert!(!pane.lines(&p, "run", 500).is_empty());
        assert!(render_kitty(&sheet.frame("idle", 0), 16).starts_with("\x1b_Gf=100,a=T,c=16,"));
        assert!(render_iterm(&sheet.frame("idle", 0), 16).starts_with("\x1b]1337;File=inline=1;"));
        assert!(doctor(&p).contains("active (resolved):   boba"));
        assert_eq!(rename(&p, "boba", "Boba Tea").as_deref(), Some("boba-tea"));
        assert_eq!(config(&p)["slug"], "boba-tea", "config follows the rename");
        assert!(remove(&p, "boba-tea"));
        assert!(clear_active_if(&p, "boba-tea"));
        assert!(!enabled(&config(&p)));
        assert!(pane.lines(&p, "idle", 0).is_empty());
    }

    /// An asymmetric sprite strip: a body with a head bump on the upper-left of each pose,
    /// so a horizontal mirror is observable in pixels (the shared `strip()` is symmetric).
    fn lopsided_strip(n: usize, w: usize, h: usize) -> Vec<u8> {
        let mut img = Rgba::new(w, h);
        for y in 0..h {
            for x in 0..w {
                img.put(x, y, [255, 0, 255, 255]);
            }
        }
        let slot = w / n.max(1);
        for i in 0..n {
            for y in h / 4..h * 3 / 4 {
                for x in i * slot + slot / 4..i * slot + slot * 3 / 4 {
                    img.put(x, y, [20, 120 + i as u8 * 10, 40, 255]);
                }
            }
            for y in h / 8..h / 4 {
                for x in i * slot + slot / 4..i * slot + slot / 2 {
                    img.put(x, y, [240, 200, 30, 255]);
                }
            }
        }
        png::encode(&img)
    }

    struct FakeGen(Mutex<Vec<String>>);
    impl SpriteGen for FakeGen {
        fn generate(&self, prompt: &str, reference: Option<&[u8]>, aspect: &str) -> Result<Vec<u8>, String> {
            self.0.lock().unwrap().push(format!("{aspect}:{}", reference.is_some()));
            if prompt.contains("happy celebration jump") {
                return Err("boom".into());
            }
            let n = ROW_SPECS.iter().find(|s| prompt.contains(action(s.0))).map(|s| s.2).unwrap_or(1);
            Ok(if aspect == "square" { lopsided_strip(1, 256, 256) } else { lopsided_strip(n, 1536, 512) })
        }
    }

    #[test]
    fn hatch_composes_a_full_atlas() {
        let p = test_paths("hatch");
        let g = FakeGen(Mutex::new(vec![]));
        let seen = Mutex::new(vec![]);
        let h = hatch(&p, &g, "a tiny green frog wizard", "auto", &|m| seen.lock().unwrap().push(m.to_string())).unwrap();
        assert_eq!(h.pet.slug, "a-tiny-green");
        assert_eq!(h.pet.created_by, "generator");
        assert!(h.states.contains(&"running-left".to_string()) && !h.states.contains(&"jumping".to_string()));
        let calls = g.0.lock().unwrap().clone();
        assert_eq!(calls[0], "square:false");
        assert_eq!(calls.iter().filter(|c| *c == "landscape:true").count(), 7 + 2, "8 generated rows (running-left is mirrored); the failing row is retried once");
        let sheet = Sheet::load(&h.pet.spritesheet).unwrap();
        assert_eq!((sheet.img.w, sheet.img.h), (1536, 1872));
        assert_eq!(sheet.frame_count("running-right"), 6);
        assert!(sheet.img.crop(0, 4 * FRAME_H, FRAME_W, FRAME_H).bbox(16).is_none(), "jumping row left empty");
        // `running-left` is the mirrored `running-right` row, not an empty placeholder.
        let right = sheet.img.crop(0, FRAME_H, FRAME_W, FRAME_H);
        let left = sheet.img.crop(0, 2 * FRAME_H, FRAME_W, FRAME_H);
        assert!(right.bbox(16).is_some() && left.bbox(16).is_some(), "both run rows are drawn");
        assert_eq!(left.px, right.mirror().px, "running-left is the horizontal mirror of running-right");
        assert_ne!(left.px, right.px, "the mock sprite is asymmetric enough to tell them apart");
        // Keyed background is transparent, and no magenta survives the chroma key.
        let f = sheet.frame("idle", 0);
        assert_eq!(f.get(0, 0)[3], 0);
        assert!(f.bbox(16).is_some());
        let magenta = (0..f.h).flat_map(|y| (0..f.w).map(move |x| (x, y))).filter(|&(x, y)| {
            let p = f.get(x, y);
            p[3] > 0 && p[0] > 200 && p[1] < 60 && p[2] > 200
        }).count();
        assert_eq!(magenta, 0, "the #FF00FF field was keyed out, not scaled into the cell");
        let opaque = (0..f.h).flat_map(|y| (0..f.w).map(move |x| (x, y))).filter(|&(x, y)| f.get(x, y)[3] > 0).count();
        assert!(opaque > 100, "the sprite itself survives the key ({opaque} opaque pixels)");
        assert_eq!(config(&p)["slug"], "a-tiny-green");
        assert!(seen.lock().unwrap().iter().any(|m| m.contains("composing")));
        assert!(hatch(&p, &g, "  ", "auto", &|_| {}).is_err());
        assert!(friendly_error("400 moderation_blocked").contains("safety filter"));
    }
}
