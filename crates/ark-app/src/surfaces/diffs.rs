//! `diffs`: read-only diff viewer and renderer (OpenClaw extensions/diffs, MIT).
//!
//! Input is before/after text or a unified patch. `mode=view` stores a self-contained
//! viewer page behind a capability URL (`/surfaces/diffs/view/<id>/<token>`, expires after
//! `ttlSeconds`); `mode=file` renders the same diff to PNG or PDF with a headless Chromium;
//! `mode=both` does both.

use super::{esc_html, now_ms, read_json, write_atomic, write_json, Env};
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use ark_net::httpd::Response;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const MAX_BEFORE_AFTER: usize = 512 * 1024;
const MAX_PATCH: usize = 2 * 1024 * 1024;
const MAX_TITLE: usize = 1024;
const MAX_PATH: usize = 2048;
const MAX_LANG: usize = 128;
const MAX_TTL_SECONDS: u64 = 21_600;
const CONTEXT: usize = 3;

fn d_mode() -> String {
    "both".into()
}
fn d_theme() -> String {
    "dark".into()
}
fn d_layout() -> String {
    "unified".into()
}
fn d_ttl() -> u64 {
    1800
}
fn d_quality() -> String {
    "standard".into()
}
fn d_format() -> String {
    "png".into()
}

/// `[surfaces.diffs]`: defaults the tool uses when a call omits them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DiffsConfig {
    /// view | file | image | both. Default both.
    #[serde(default = "d_mode")]
    pub mode: String,
    /// light | dark. Default dark.
    #[serde(default = "d_theme")]
    pub theme: String,
    /// unified | split. Default unified.
    #[serde(default = "d_layout")]
    pub layout: String,
    /// Artifact lifetime. Default 1800 s, max 21600.
    #[serde(default = "d_ttl")]
    pub ttl_seconds: u64,
    /// standard | hq | print. Default standard.
    #[serde(default = "d_quality")]
    pub file_quality: String,
    /// png | pdf. Default png.
    #[serde(default = "d_format")]
    pub file_format: String,
    /// Origin for viewer links (default `[surfaces] public_url`).
    pub viewer_base_url: Option<String>,
    /// Headless browser binary for file rendering (default: first of chromium,
    /// chromium-browser, google-chrome, google-chrome-stable, brave-browser on PATH).
    pub browser: Option<String>,
}

impl Default for DiffsConfig {
    fn default() -> Self {
        DiffsConfig { mode: d_mode(), theme: d_theme(), layout: d_layout(), ttl_seconds: d_ttl(), file_quality: d_quality(), file_format: d_format(), viewer_base_url: None, browser: None }
    }
}

/// One line of a rendered hunk.
#[derive(Debug, Clone, PartialEq)]
pub enum Line {
    Same(usize, usize, String),
    Del(usize, String),
    Add(usize, String),
    /// Collapsed unchanged lines.
    Skip(usize),
}

#[derive(Debug, Clone)]
pub struct FileDiff {
    pub old_path: String,
    pub new_path: String,
    pub lines: Vec<Line>,
    pub added: usize,
    pub removed: usize,
}

/// Myers line diff after trimming the common prefix/suffix; huge edit distances fall back
/// to "replace everything" so a hostile input cannot stall the call.
pub fn diff_lines(a: &[&str], b: &[&str]) -> Vec<(char, usize, usize)> {
    let pre = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let suf = a[pre..].iter().rev().zip(b[pre..].iter().rev()).take_while(|(x, y)| x == y).count();
    let (am, bm) = (&a[pre..a.len() - suf], &b[pre..b.len() - suf]);
    let mut ops: Vec<(char, usize, usize)> = (0..pre).map(|i| ('=', i, i)).collect();
    let (n, m) = (am.len() as isize, bm.len() as isize);
    let max = (n + m) as usize;
    let mut mid: Vec<(char, usize, usize)> = Vec::new();
    let budget = 4000usize;
    let mut trace: Vec<Vec<isize>> = Vec::new();
    let off = max as isize + 1;
    let mut v = vec![0isize; 2 * max + 3];
    let mut found = None;
    'outer: for d in 0..=max.min(budget) as isize {
        trace.push(v.clone());
        let mut k = -d;
        while k <= d {
            let i = (k + off) as usize;
            let mut x = if k == -d || (k != d && v[i - 1] < v[i + 1]) { v[i + 1] } else { v[i - 1] + 1 };
            let mut y = x - k;
            while x < n && y < m && am[x as usize] == bm[y as usize] {
                x += 1;
                y += 1;
            }
            v[i] = x;
            if x >= n && y >= m {
                found = Some(d);
                break 'outer;
            }
            k += 2;
        }
    }
    match found {
        Some(dmax) => {
            let (mut x, mut y) = (n, m);
            for d in (0..=dmax).rev() {
                let v = &trace[d as usize];
                let k = x - y;
                let i = (k + off) as usize;
                let prev_k = if k == -d || (k != d && v[i - 1] < v[i + 1]) { k + 1 } else { k - 1 };
                let px = v[(prev_k + off) as usize];
                let py = px - prev_k;
                while x > px && y > py {
                    x -= 1;
                    y -= 1;
                    mid.push(('=', x as usize, y as usize));
                }
                if d > 0 {
                    if x == px {
                        mid.push(('+', x as usize, py as usize));
                    } else {
                        mid.push(('-', px as usize, y as usize));
                    }
                }
                x = px;
                y = py;
            }
            mid.reverse();
        }
        None => {
            mid.extend((0..am.len()).map(|i| ('-', i, 0)));
            mid.extend((0..bm.len()).map(|j| ('+', am.len(), j)));
        }
    }
    ops.extend(mid.into_iter().map(|(o, x, y)| (o, x + pre, y + pre)));
    ops.extend((0..suf).map(|i| ('=', a.len() - suf + i, b.len() - suf + i)));
    ops
}

/// before/after → lines with collapsed context.
pub fn diff_text(before: &str, after: &str, expand: bool) -> (Vec<Line>, usize, usize) {
    let a: Vec<&str> = before.lines().collect();
    let b: Vec<&str> = after.lines().collect();
    let ops = diff_lines(&a, &b);
    let mut full = Vec::new();
    let (mut added, mut removed) = (0, 0);
    for (o, x, y) in ops {
        match o {
            '=' => full.push(Line::Same(x + 1, y + 1, a[x].to_string())),
            '-' => {
                removed += 1;
                full.push(Line::Del(x + 1, a[x].to_string()));
            }
            _ => {
                added += 1;
                full.push(Line::Add(y + 1, b[y].to_string()));
            }
        }
    }
    (if expand { full } else { collapse(full) }, added, removed)
}

fn collapse(full: Vec<Line>) -> Vec<Line> {
    let changed: Vec<bool> = full.iter().map(|l| !matches!(l, Line::Same(..))).collect();
    let near = |i: usize| {
        let lo = i.saturating_sub(CONTEXT);
        let hi = (i + CONTEXT).min(full.len() - 1);
        (lo..=hi).any(|j| changed[j])
    };
    let mut out = Vec::new();
    let mut skipped = 0;
    for (i, l) in full.iter().enumerate() {
        if near(i) {
            if skipped > 0 {
                out.push(Line::Skip(skipped));
                skipped = 0;
            }
            out.push(l.clone());
        } else {
            skipped += 1;
        }
    }
    if skipped > 0 {
        out.push(Line::Skip(skipped));
    }
    out
}

/// Unified diff / git patch → files.
pub fn parse_patch(patch: &str) -> Result<Vec<FileDiff>, String> {
    let mut files: Vec<FileDiff> = Vec::new();
    let mut cur: Option<FileDiff> = None;
    let (mut o, mut n) = (0usize, 0usize);
    let mut in_hunk = false;
    let strip = |p: &str| -> String {
        let p = p.split('\t').next().unwrap_or("").trim();
        p.strip_prefix("a/").or_else(|| p.strip_prefix("b/")).unwrap_or(p).to_string()
    };
    for line in patch.lines() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            if let Some(f) = cur.take() {
                files.push(f);
            }
            let mut parts = rest.split(' ');
            let (a, b) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
            cur = Some(FileDiff { old_path: strip(a), new_path: strip(b), lines: vec![], added: 0, removed: 0 });
            in_hunk = false;
        } else if line.starts_with("--- ") && !in_hunk {
            if cur.as_ref().is_some_and(|f| !f.lines.is_empty()) {
                files.push(cur.take().unwrap());
            }
            let f = cur.get_or_insert_with(|| FileDiff { old_path: String::new(), new_path: String::new(), lines: vec![], added: 0, removed: 0 });
            f.old_path = strip(&line[4..]);
        } else if line.starts_with("+++ ") && !in_hunk {
            if let Some(f) = cur.as_mut() {
                f.new_path = strip(&line[4..]);
            }
        } else if let Some(h) = line.strip_prefix("@@ ") {
            let f = cur.get_or_insert_with(|| FileDiff { old_path: String::new(), new_path: String::new(), lines: vec![], added: 0, removed: 0 });
            let spec = h.split(" @@").next().unwrap_or("");
            let mut it = spec.split(' ');
            let num = |s: Option<&str>, c: char| -> Option<usize> { s?.trim_start_matches(c).split(',').next()?.parse().ok() };
            let (a, b) = (num(it.next(), '-'), num(it.next(), '+'));
            let (Some(a), Some(b)) = (a, b) else { return Err(format!("Invalid hunk header: {line}")) };
            if !f.lines.is_empty() {
                let gap = a.saturating_sub(o);
                if gap > 0 {
                    f.lines.push(Line::Skip(gap));
                }
            } else if a > 1 {
                f.lines.push(Line::Skip(a - 1));
            }
            o = a;
            n = b;
            in_hunk = true;
        } else if in_hunk {
            let f = cur.as_mut().unwrap();
            match line.chars().next() {
                Some('+') => {
                    f.lines.push(Line::Add(n, line[1..].to_string()));
                    f.added += 1;
                    n += 1;
                }
                Some('-') => {
                    f.lines.push(Line::Del(o, line[1..].to_string()));
                    f.removed += 1;
                    o += 1;
                }
                Some(' ') | None => {
                    f.lines.push(Line::Same(o, n, line.get(1..).unwrap_or("").to_string()));
                    o += 1;
                    n += 1;
                }
                Some('\\') => {}
                _ => in_hunk = false,
            }
        }
    }
    if let Some(f) = cur {
        files.push(f);
    }
    files.retain(|f| !f.lines.is_empty() || !f.new_path.is_empty());
    if files.iter().all(|f| f.added + f.removed == 0) {
        return Err("Patch contains no changes (expected a unified diff with @@ hunks).".into());
    }
    Ok(files)
}

fn theme_css(theme: &str) -> &'static str {
    if theme == "light" {
        ":root{--bg:#fff;--fg:#1f2328;--muted:#656d76;--line:#d0d7de;--add:#e6ffec;--addh:#abf2bc;--del:#ffebe9;--delh:#ffcecb;--skip:#f6f8fa;--head:#f6f8fa}"
    } else {
        ":root{--bg:#0d1117;--fg:#e6edf3;--muted:#7d8590;--line:#30363d;--add:#0f2d1a;--addh:#1f6f3b;--del:#3a1215;--delh:#8e2a30;--skip:#161b22;--head:#161b22}"
    }
}

/// Self-contained HTML (no scripts) for the viewer and the file renderer.
pub fn render_html(title: &str, files: &[FileDiff], layout: &str, theme: &str, width: Option<u32>) -> String {
    let mut h = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"referrer\" content=\"no-referrer\"><title>{}</title><style>{}body{{margin:0;background:var(--bg);color:var(--fg);font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace{}}}h1{{font:600 16px system-ui,sans-serif;margin:16px}}.file{{margin:0 16px 16px;border:1px solid var(--line);border-radius:8px;overflow:hidden}}.fh{{background:var(--head);padding:8px 12px;border-bottom:1px solid var(--line);font-family:system-ui,sans-serif}}.st{{color:var(--muted);margin-left:8px}}table{{border-collapse:collapse;width:100%;table-layout:fixed}}td{{padding:0 8px;vertical-align:top;white-space:pre-wrap;word-break:break-all}}td.n{{width:4.5em;color:var(--muted);text-align:right;user-select:none}}td.m{{width:1.2em;color:var(--muted);user-select:none;padding:0}}tr.a td{{background:var(--add)}}tr.d td{{background:var(--del)}}td.a{{background:var(--add)}}td.d{{background:var(--del)}}tr.s td{{background:var(--skip);color:var(--muted);text-align:center;font-family:system-ui,sans-serif;font-size:12px}}</style></head><body><h1>{}</h1>",
        esc_html(title),
        theme_css(theme),
        width.map(|w| format!(";width:{w}px")).unwrap_or_default(),
        esc_html(title)
    );
    for f in files {
        let name = if f.old_path != f.new_path && !f.old_path.is_empty() && f.old_path != "/dev/null" && f.new_path != "/dev/null" { format!("{} → {}", f.old_path, f.new_path) } else if f.new_path == "/dev/null" { f.old_path.clone() } else { f.new_path.clone() };
        h.push_str(&format!("<div class=\"file\"><div class=\"fh\">{}<span class=\"st\">+{} −{}</span></div><table>", esc_html(&name), f.added, f.removed));
        if layout == "split" {
            h.push_str("<colgroup><col style=\"width:4.5em\"><col><col style=\"width:4.5em\"><col></colgroup>");
            let mut i = 0;
            while i < f.lines.len() {
                match &f.lines[i] {
                    Line::Same(a, b, t) => {
                        h.push_str(&format!("<tr><td class=\"n\">{a}</td><td>{}</td><td class=\"n\">{b}</td><td>{}</td></tr>", esc_html(t), esc_html(t)));
                        i += 1;
                    }
                    Line::Skip(n) => {
                        h.push_str(&format!("<tr class=\"s\"><td colspan=\"4\">⋯ {n} unchanged line{} ⋯</td></tr>", if *n == 1 { "" } else { "s" }));
                        i += 1;
                    }
                    _ => {
                        let (mut dels, mut adds) = (vec![], vec![]);
                        while i < f.lines.len() {
                            match &f.lines[i] {
                                Line::Del(n, t) => dels.push((*n, t.clone())),
                                Line::Add(n, t) => adds.push((*n, t.clone())),
                                _ => break,
                            }
                            i += 1;
                        }
                        for r in 0..dels.len().max(adds.len()) {
                            let l = dels.get(r).map(|(n, t)| format!("<td class=\"n d\">{n}</td><td class=\"d\">{}</td>", esc_html(t))).unwrap_or_else(|| "<td class=\"n\"></td><td></td>".into());
                            let rr = adds.get(r).map(|(n, t)| format!("<td class=\"n a\">{n}</td><td class=\"a\">{}</td>", esc_html(t))).unwrap_or_else(|| "<td class=\"n\"></td><td></td>".into());
                            h.push_str(&format!("<tr>{l}{rr}</tr>"));
                        }
                    }
                }
            }
        } else {
            h.push_str("<colgroup><col style=\"width:4.5em\"><col style=\"width:4.5em\"><col style=\"width:1.2em\"><col></colgroup>");
            for l in &f.lines {
                h.push_str(&match l {
                    Line::Same(a, b, t) => format!("<tr><td class=\"n\">{a}</td><td class=\"n\">{b}</td><td class=\"m\"> </td><td>{}</td></tr>", esc_html(t)),
                    Line::Del(a, t) => format!("<tr class=\"d\"><td class=\"n\">{a}</td><td class=\"n\"></td><td class=\"m\">-</td><td>{}</td></tr>", esc_html(t)),
                    Line::Add(b, t) => format!("<tr class=\"a\"><td class=\"n\"></td><td class=\"n\">{b}</td><td class=\"m\">+</td><td>{}</td></tr>", esc_html(t)),
                    Line::Skip(n) => format!("<tr class=\"s\"><td colspan=\"4\">⋯ {n} unchanged line{} ⋯</td></tr>", if *n == 1 { "" } else { "s" }),
                });
            }
        }
        h.push_str("</table></div>");
    }
    h.push_str("</body></html>");
    h
}

// ───────────────────────── artifacts ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Meta {
    id: String,
    token_hash: String,
    title: String,
    expires_ms: u64,
    input_kind: String,
    file_count: usize,
    #[serde(default)]
    session: String,
}

fn store_dir(dir: &Path) -> PathBuf {
    dir.join("diffs")
}

fn hash(token: &str) -> String {
    ark_net::crypto::hex(&ark_net::crypto::sha256(token.as_bytes()))
}

/// Drop expired viewers and files.
fn sweep(dir: &Path) {
    let now = now_ms();
    for e in std::fs::read_dir(store_dir(dir)).into_iter().flatten().flatten() {
        let p = e.path();
        if let Some(m) = read_json::<Meta>(&p.join("meta.json")) {
            if m.expires_ms <= now {
                let _ = std::fs::remove_dir_all(&p);
            }
        }
    }
    for e in std::fs::read_dir(store_dir(dir).join("files")).into_iter().flatten().flatten() {
        if let Some(m) = read_json::<Meta>(&e.path().with_extension("json")).filter(|m| m.expires_ms <= now) {
            let _ = std::fs::remove_file(e.path());
            let _ = std::fs::remove_file(e.path().with_extension("json"));
            let _ = m;
        }
    }
}

/// Returns (id, viewer path, expires ms).
fn create_viewer(dir: &Path, html: &str, title: &str, kind: &str, files: usize, ttl_ms: u64, session: &str) -> Result<(String, String, u64), String> {
    sweep(dir);
    let id = ark_net::crypto::hex(&ark_net::crypto::random_bytes(10));
    let token = ark_net::crypto::hex(&ark_net::crypto::random_bytes(24));
    let root = store_dir(dir).join(&id);
    write_atomic(&root.join("viewer.html"), html.as_bytes())?;
    let expires = now_ms() + ttl_ms;
    write_json(&root.join("meta.json"), &Meta { id: id.clone(), token_hash: hash(&token), title: title.into(), expires_ms: expires, input_kind: kind.into(), file_count: files, session: session.into() })?;
    Ok((id.clone(), format!("/surfaces/diffs/view/{id}/{token}"), expires))
}

/// `GET /surfaces/diffs/view/<id>/<token>`
pub fn serve_viewer(dir: &Path, rest: &str) -> Response {
    let mut it = rest.split(['/', '?', '#']);
    let (id, token) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
    let nf = || Response::text(404, "not found");
    if id.len() != 20 || token.len() != 48 || !id.chars().chain(token.chars()).all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
        return nf();
    }
    let root = store_dir(dir).join(id);
    let Some(m) = read_json::<Meta>(&root.join("meta.json")) else { return nf() };
    if !ark_net::crypto::ct_eq(hash(token).as_bytes(), m.token_hash.as_bytes()) {
        return nf();
    }
    if m.expires_ms <= now_ms() {
        let _ = std::fs::remove_dir_all(&root);
        return Response::text(410, "diff viewer expired");
    }
    match std::fs::read(root.join("viewer.html")) {
        Ok(b) => Response::new(200, "text/html; charset=utf-8", b).with_header("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors *"),
        Err(_) => nf(),
    }
}

fn browser(cfg: &DiffsConfig) -> Option<PathBuf> {
    if let Some(b) = cfg.browser.as_deref().filter(|b| !b.trim().is_empty()) {
        return Some(PathBuf::from(b));
    }
    let path = std::env::var_os("PATH")?;
    ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "brave-browser"].iter().find_map(|b| std::env::split_paths(&path).map(|d| d.join(b)).find(|f| f.is_file()))
}

/// (scale, max width, max pixels) per quality preset.
fn quality(q: &str) -> (f64, u32, u64) {
    match q {
        "hq" => (2.5, 1200, 14_000_000),
        "print" => (3.0, 1400, 24_000_000),
        _ => (2.0, 960, 8_000_000),
    }
}

/// Headless render of `html` to `out` (png or pdf).
#[allow(clippy::too_many_arguments)]
fn render_file(cfg: &DiffsConfig, html: &str, out: &Path, format: &str, scale: f64, width: u32, rows: usize, max_pixels: u64) -> Result<(), String> {
    let bin = browser(cfg).ok_or("file rendering needs a Chromium-based browser (chromium, google-chrome; or set [surfaces.diffs] browser); use mode=view instead")?;
    let tmp = out.with_extension("src.html");
    write_atomic(&tmp, html.as_bytes())?;
    let height = ((rows as f64 * 19.0 + 120.0) as u64).clamp(200, (max_pixels as f64 / (width as f64 * scale * scale)) as u64);
    let profile = out.with_extension("profile");
    let mut cmd = std::process::Command::new(&bin);
    cmd.args(["--headless=new", "--disable-gpu", "--hide-scrollbars", "--mute-audio", "--no-first-run", "--disable-extensions"]).arg(format!("--user-data-dir={}", profile.display()));
    if format == "pdf" {
        cmd.arg(format!("--print-to-pdf={}", out.display())).arg("--no-pdf-header-footer");
    } else {
        cmd.arg(format!("--screenshot={}", out.display())).arg(format!("--window-size={},{height}", width + 32)).arg(format!("--force-device-scale-factor={scale}"));
    }
    cmd.arg(format!("file://{}", tmp.display())).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("{}: {e}", bin.display()))?;
    let until = std::time::Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
            break s;
        }
        if std::time::Instant::now() > until {
            let _ = child.kill();
            let _ = child.wait();
            return Err("browser render timed out after 60 s".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_dir_all(&profile);
    if !status.success() || !out.exists() {
        let mut err = String::new();
        if let Some(mut e) = child.stderr.take() {
            use std::io::Read;
            let _ = e.read_to_string(&mut err);
        }
        return Err(format!("browser render failed ({status}): {}", err.lines().last().unwrap_or("")));
    }
    Ok(())
}

pub struct DiffsTool(pub Arc<Env>);

fn check_len(v: &str, label: &str, max: usize) -> Result<(), String> {
    if v.len() > max {
        Err(format!("{label} exceeds maximum size ({max} bytes)."))
    } else {
        Ok(())
    }
}

impl DiffsTool {
    fn run(&self, ctx: &ToolCtx, p: &Value) -> Result<String, String> {
        let cfg = &self.0.cfg.diffs;
        let pick = |k: &str, allowed: &[&str], d: &str| -> String { p[k].as_str().filter(|v| allowed.contains(v)).unwrap_or(if allowed.contains(&d) { d } else { allowed[0] }).to_string() };
        let mode = pick("mode", &["view", "image", "file", "both"], &cfg.mode);
        let theme = pick("theme", &["light", "dark"], &cfg.theme);
        let layout = pick("layout", &["unified", "split"], &cfg.layout);
        let expand = p["expandUnchanged"] == true;
        let s = |k: &str| p[k].as_str().map(str::trim).filter(|x| !x.is_empty());
        if let Some(t) = s("title") {
            check_len(t, "title", MAX_TITLE)?;
        }
        let (title, files, kind) = match p["patch"].as_str().map(str::trim).filter(|x| !x.is_empty()) {
            Some(patch) => {
                check_len(patch, "patch", MAX_PATCH)?;
                if p.get("before").is_some_and(|v| !v.is_null()) || p.get("after").is_some_and(|v| !v.is_null()) {
                    return Err("Provide either patch or before/after input, not both.".into());
                }
                let files = parse_patch(patch)?;
                let t = s("title").map(str::to_string).unwrap_or_else(|| if files.len() == 1 { files[0].new_path.clone() } else { format!("{} files changed", files.len()) });
                (t, files, "patch")
            }
            None => {
                let (Some(before), Some(after)) = (p["before"].as_str(), p["after"].as_str()) else { return Err("Provide patch or both before and after text.".into()) };
                check_len(before, "before", MAX_BEFORE_AFTER)?;
                check_len(after, "after", MAX_BEFORE_AFTER)?;
                if let Some(x) = s("path") {
                    check_len(x, "path", MAX_PATH)?;
                }
                if let Some(x) = s("lang") {
                    check_len(x, "lang", MAX_LANG)?;
                }
                if before == after {
                    return Ok(format!("Before and after are identical — no changes to render.\n{}", json!({"changed": false})));
                }
                let (lines, added, removed) = diff_text(before, after, expand);
                let path = s("path").unwrap_or("file").to_string();
                let t = s("title").map(str::to_string).unwrap_or_else(|| path.clone());
                (t, vec![FileDiff { old_path: path.clone(), new_path: path, lines, added, removed }], "before_after")
            }
        };
        let ttl = p["ttlSeconds"].as_f64().map(|f| f.clamp(1.0, MAX_TTL_SECONDS as f64) as u64).unwrap_or(cfg.ttl_seconds.clamp(1, MAX_TTL_SECONDS));
        let mut details = json!({"changed": true, "title": title, "inputKind": kind, "fileCount": files.len(), "mode": mode});
        let mut text = Vec::new();
        if mode == "view" || mode == "both" {
            let html = render_html(&title, &files, &layout, &theme, None);
            let (id, path, exp) = create_viewer(&self.0.dir, &html, &title, kind, files.len(), ttl * 1000, &ctx.session_id)?;
            let base = p["baseUrl"].as_str().or(cfg.viewer_base_url.as_deref()).map(|b| b.trim().trim_end_matches('/').to_string()).unwrap_or_else(|| self.0.base_url.clone());
            if !(base.starts_with("http://") || base.starts_with("https://")) || base.contains(['?', '#']) {
                return Err(format!("Invalid baseUrl: {base}"));
            }
            let url = format!("{base}{path}");
            details["artifactId"] = id.into();
            details["viewerUrl"] = url.clone().into();
            details["viewerPath"] = path.into();
            details["expiresAt"] = super::iso(exp).into();
            if mode == "view" {
                return Ok(format!("Diff viewer ready.\n{url}\n{details}"));
            }
            text.push(format!("Diff viewer: {url}"));
        }
        let fmt = pick("fileFormat", &["png", "pdf"], &cfg.file_format);
        let q = pick("fileQuality", &["standard", "hq", "print"], &cfg.file_quality);
        let (mut scale, mut width, max_px) = quality(&q);
        if let Some(sc) = p["fileScale"].as_f64() {
            scale = sc.clamp(1.0, 4.0);
        }
        if let Some(w) = p["fileMaxWidth"].as_f64() {
            width = w.clamp(640.0, 2400.0) as u32;
        }
        let rows: usize = files.iter().map(|f| f.lines.len() + 3).sum();
        let html = render_html(&title, &files, &layout, &theme, Some(width));
        let id = ark_net::crypto::hex(&ark_net::crypto::random_bytes(10));
        let out = store_dir(&self.0.dir).join("files").join(format!("{id}.{fmt}"));
        let rendered = render_file(cfg, &html, &out, &fmt, scale, width, rows, max_px).and_then(|_| {
            write_json(&out.with_extension("json"), &Meta { id: id.clone(), token_hash: String::new(), title: title.clone(), expires_ms: now_ms() + ttl * 1000, input_kind: kind.into(), file_count: files.len(), session: ctx.session_id.clone() })?;
            std::fs::metadata(&out).map(|m| m.len()).map_err(|e| e.to_string())
        });
        match rendered {
            Ok(bytes) => {
                details["filePath"] = out.display().to_string().into();
                details["path"] = out.display().to_string().into();
                details["fileBytes"] = bytes.into();
                details["fileFormat"] = fmt.clone().into();
                details["fileQuality"] = q.into();
                details["fileScale"] = scale.into();
                details["fileMaxWidth"] = width.into();
                text.push(format!("Diff {} generated at: {}", fmt.to_uppercase(), out.display()));
                text.push("To send this file, use an available file-sending tool to send it as an attachment.".into());
                Ok(format!("{}\n{details}", text.join("\n")))
            }
            Err(e) if mode == "both" => {
                details["fileError"] = e.clone().into();
                Ok(format!("Diff viewer ready.\n{}\nFile rendering failed: {e}\n{details}", details["viewerUrl"].as_str().unwrap_or("")))
            }
            Err(e) => Err(e),
        }
    }
}

impl Tool for DiffsTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "diffs".into(),
            description: "Create a read-only diff viewer from before/after text or a unified patch. Returns a viewer URL for interactive viewing and can also render the same diff to a PNG or PDF (mode=file or both; details.filePath — send it with a file-sending tool). Identical before/after returns changed=false. Include `path` for before/after text when you know the file name.".into(),
            input_schema: json!({"type": "object", "properties": {
                "before": {"type": "string", "description": "Original text content."},
                "after": {"type": "string", "description": "Updated text content."},
                "patch": {"type": "string", "description": "Unified diff or patch text.", "maxLength": MAX_PATCH},
                "path": {"type": "string", "description": "Display path for before/after input."},
                "lang": {"type": "string", "description": "Optional language override for before/after input."},
                "title": {"type": "string", "description": "Optional title for the rendered diff."},
                "mode": {"type": "string", "enum": ["view", "file", "image", "both"], "description": "view, file, image (alias for file), or both."},
                "theme": {"type": "string", "enum": ["light", "dark"]},
                "layout": {"type": "string", "enum": ["unified", "split"]},
                "fileQuality": {"type": "string", "enum": ["standard", "hq", "print"]},
                "fileFormat": {"type": "string", "enum": ["png", "pdf"]},
                "fileScale": {"type": "number", "minimum": 1, "maximum": 4},
                "fileMaxWidth": {"type": "number", "minimum": 640, "maximum": 2400},
                "expandUnchanged": {"type": "boolean", "description": "Expand unchanged sections instead of collapsing them."},
                "ttlSeconds": {"type": "number", "minimum": 1, "maximum": MAX_TTL_SECONDS, "description": "Artifact lifetime in seconds. Default 1800."},
                "baseUrl": {"type": "string", "description": "Origin override for the viewer URL."}
            }, "additionalProperties": false}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, _ctx: &ToolCtx, _input: &Value) -> Vec<Effect> {
        // Writes only ark's own artifact store; the browser render reads a file it wrote.
        vec![]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        match self.run(ctx, &input) {
            Ok(t) => ToolOutput::ok(t),
            Err(e) => ToolOutput::err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit;
    use super::*;

    #[test]
    fn myers_diff_and_context() {
        let (lines, a, r) = diff_text("a\nb\nc\nd\ne\nf\ng\nh\ni\nj\n", "a\nb\nc\nd\ne\nF\ng\nh\ni\nj\nk\n", false);
        assert_eq!((a, r), (2, 1));
        assert_eq!(lines[0], Line::Skip(2));
        assert!(lines.contains(&Line::Del(6, "f".into())) && lines.contains(&Line::Add(6, "F".into())) && lines.contains(&Line::Add(11, "k".into())));
        let (full, ..) = diff_text("x\ny\n", "y\nz\n", true);
        assert_eq!(full, vec![Line::Del(1, "x".into()), Line::Same(2, 1, "y".into()), Line::Add(2, "z".into())]);
    }

    #[test]
    fn patches_parse() {
        let p = "diff --git a/src/x.rs b/src/x.rs\n--- a/src/x.rs\n+++ b/src/x.rs\n@@ -10,3 +10,3 @@ fn f\n ctx\n-old\n+new\n ctx2\n\\ No newline at end of file\ndiff --git a/y b/y\n--- a/y\n+++ b/y\n@@ -1 +1,2 @@\n a\n+b\n";
        let f = parse_patch(p).unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!((f[0].new_path.as_str(), f[0].added, f[0].removed), ("src/x.rs", 1, 1));
        assert_eq!(f[0].lines[0], Line::Skip(9));
        assert!(f[0].lines.contains(&Line::Del(11, "old".into())));
        assert!(parse_patch("hello").is_err());
        let html = render_html("T", &f, "split", "light", None);
        assert!(html.contains("<td class=\"n d\">11</td><td class=\"d\">old</td><td class=\"n a\">11</td><td class=\"a\">new</td>"));
        assert!(!html.contains("<script"));
    }

    #[test]
    fn viewer_is_capability_scoped_and_expires() {
        let (env, _) = testkit::env("diffs", &[], "[diffs]\nmode = \"view\"\n");
        let t = DiffsTool(env.clone());
        let ws = testkit::temp("d-ws");
        let ctx = testkit::ctx(&env, &ws);
        assert!(t.call(&ctx, json!({"before": "a", "after": "a"})).content.contains("\"changed\":false"));
        assert!(t.call(&ctx, json!({"before": "a"})).content.contains("Provide patch or both"));
        assert!(t.call(&ctx, json!({"patch": "@@ -1 +1 @@\n-a\n+b\n", "before": "x"})).content.contains("not both"));
        let o = t.call(&ctx, json!({"before": "one\ntwo\n", "after": "one\n2\n", "path": "n.txt", "ttlSeconds": 60}));
        assert!(o.content.starts_with("Diff viewer ready.\nhttp://127.0.0.1:8640/surfaces/diffs/view/"), "{}", o.content);
        let rest = o.content.lines().nth(1).unwrap().split("/surfaces/diffs/view/").nth(1).unwrap().to_string();
        let r = serve_viewer(&env.dir, &rest);
        assert_eq!(r.status, 200);
        let body = match r.body {
            ark_net::httpd::Body::Bytes(b) => String::from_utf8(b).unwrap(),
            _ => panic!(),
        };
        assert!(body.contains("n.txt") && body.contains(">2</td>"));
        let (id, _) = rest.split_once('/').unwrap();
        assert_eq!(serve_viewer(&env.dir, &format!("{id}/{}", "0".repeat(48))).status, 404, "wrong token");
        // Expired.
        let mp = store_dir(&env.dir).join(id).join("meta.json");
        let mut m: Meta = read_json(&mp).unwrap();
        m.expires_ms = 1;
        write_json(&mp, &m).unwrap();
        assert_eq!(serve_viewer(&env.dir, &rest).status, 410);
        // File mode without a browser fails clearly; both mode keeps the viewer.
        let (env2, _) = testkit::env("diffs2", &[], "[diffs]\nbrowser = \"/nonexistent/chromium\"\n");
        let t2 = DiffsTool(env2.clone());
        let o = t2.call(&ctx, json!({"before": "a", "after": "b"}));
        assert!(!o.is_error && o.content.contains("File rendering failed"), "{}", o.content);
        assert!(t2.call(&ctx, json!({"before": "a", "after": "b", "mode": "file"})).is_error);
    }

    #[test]
    fn file_mode_renders_with_a_browser() {
        // A stand-in "browser" that writes the --screenshot target.
        let d = testkit::temp("fake-chrome");
        let bin = d.join("chromium");
        std::fs::write(&bin, "#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in --screenshot=*) printf PNG > \"${a#--screenshot=}\";; --print-to-pdf=*) printf PDF > \"${a#--print-to-pdf=}\";; esac; done\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let (env, _) = testkit::env("diffs3", &[], &format!("[diffs]\nbrowser = \"{}\"\n", bin.display()));
        let t = DiffsTool(env.clone());
        let ws = testkit::temp("d3-ws");
        let ctx = testkit::ctx(&env, &ws);
        let o = t.call(&ctx, json!({"patch": "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n", "mode": "file", "fileFormat": "pdf", "fileQuality": "print"}));
        assert!(!o.is_error, "{}", o.content);
        let v: Value = serde_json::from_str(o.content.lines().last().unwrap()).unwrap();
        assert_eq!(std::fs::read(v["filePath"].as_str().unwrap()).unwrap(), b"PDF");
        assert_eq!(v["fileScale"], 3.0);
    }
}
