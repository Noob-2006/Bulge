//! Office/notebook extractors (Hermes `tools/read_extract.py`: Jupyter, DOCX, XLSX; plus the
//! formats Hermes reaches through the optional anydoc converter — PPTX, OpenDocument, EPUB,
//! RTF — written natively here). A tiny ZIP reader (stored + deflate via miniz_oxide) and an
//! event-style XML scanner are enough for OOXML/ODF packages.

use serde_json::Value;
use std::collections::HashMap;

/// Hermes `MAX_DOCUMENT_BYTES` and per-format caps.
pub const MAX_DOCUMENT_BYTES: usize = 50 * 1024 * 1024;
const MAX_UNZIPPED: usize = 256 * 1024 * 1024;
const MAX_XLSX_ROWS_PER_SHEET: usize = 5000;
const MAX_XLSX_COLS: usize = 256;
const MAX_NOTEBOOK_OUTPUT_CHARS: usize = 20_000;

// ───── zip ─────

pub struct Zip<'a> {
    b: &'a [u8],
    entries: Vec<(String, u16, usize, usize, usize)>, // name, method, comp size, uncomp size, local offset
}

fn u16le(b: &[u8], i: usize) -> Option<usize> {
    Some(u16::from_le_bytes(b.get(i..i + 2)?.try_into().ok()?) as usize)
}
fn u32le(b: &[u8], i: usize) -> Option<usize> {
    Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?) as usize)
}

impl<'a> Zip<'a> {
    pub fn open(b: &'a [u8], kind: &str) -> Result<Self, String> {
        let bad = || format!("Not a valid {kind}: bad zip file");
        let start = b.len().saturating_sub(65_557);
        let eocd = (start..b.len().saturating_sub(21)).rev().find(|&i| b[i..].starts_with(b"PK\x05\x06")).ok_or_else(bad)?;
        let n = u16le(b, eocd + 10).ok_or_else(bad)?;
        let mut p = u32le(b, eocd + 16).ok_or_else(bad)?;
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            if !b.get(p..).is_some_and(|r| r.starts_with(b"PK\x01\x02")) {
                return Err(bad());
            }
            let method = u16le(b, p + 10).ok_or_else(bad)? as u16;
            let csize = u32le(b, p + 20).ok_or_else(bad)?;
            let usize_ = u32le(b, p + 24).ok_or_else(bad)?;
            let (nl, el, cl) = (u16le(b, p + 28).ok_or_else(bad)?, u16le(b, p + 30).ok_or_else(bad)?, u16le(b, p + 32).ok_or_else(bad)?);
            let off = u32le(b, p + 42).ok_or_else(bad)?;
            let name = String::from_utf8_lossy(b.get(p + 46..p + 46 + nl).ok_or_else(bad)?).into_owned();
            entries.push((name, method, csize, usize_, off));
            p += 46 + nl + el + cl;
        }
        Ok(Zip { b, entries })
    }
    pub fn names(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.0.as_str()).collect()
    }
    pub fn read(&self, name: &str) -> Option<Vec<u8>> {
        let (_, method, csize, usize_, off) = self.entries.iter().find(|e| e.0 == name)?.clone();
        if usize_ > MAX_UNZIPPED {
            return None;
        }
        let b = self.b;
        if !b.get(off..)?.starts_with(b"PK\x03\x04") {
            return None;
        }
        let data_at = off + 30 + u16le(b, off + 26)? + u16le(b, off + 28)?;
        let data = b.get(data_at..data_at + csize)?;
        match method {
            0 => Some(data.to_vec()),
            8 => miniz_oxide::inflate::decompress_to_vec_with_limit(data, MAX_UNZIPPED).ok(),
            _ => None,
        }
    }
    pub fn text(&self, name: &str) -> Option<String> {
        self.read(name).map(|b| String::from_utf8_lossy(&b).into_owned())
    }
}

// ───── xml ─────

#[derive(Debug, Clone, PartialEq)]
pub enum Ev<'a> {
    /// (local name with prefix, raw attributes, self-closing)
    Start(&'a str, &'a str, bool),
    End(&'a str),
    Text(String),
}

pub fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(end) = rest.find(';').filter(|e| *e <= 12) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let ent = &rest[1..end];
        let c = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some('\u{a0}'),
            e if e.starts_with("#x") || e.starts_with("#X") => u32::from_str_radix(&e[2..], 16).ok().and_then(char::from_u32),
            e if e.starts_with('#') => e[1..].parse().ok().and_then(char::from_u32),
            _ => None,
        };
        match c {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Flat XML events (comments, PIs, CDATA handled; no validation).
pub fn events(x: &str) -> Vec<Ev<'_>> {
    let mut v = Vec::new();
    let mut i = 0;
    let b = x.as_bytes();
    while i < b.len() {
        if b[i] == b'<' {
            if x[i..].starts_with("<!--") {
                i = x[i..].find("-->").map(|e| i + e + 3).unwrap_or(b.len());
                continue;
            }
            if x[i..].starts_with("<![CDATA[") {
                let e = x[i..].find("]]>").map(|e| i + e).unwrap_or(b.len());
                v.push(Ev::Text(x[i + 9..e].to_string()));
                i = (e + 3).min(b.len());
                continue;
            }
            let Some(end) = x[i..].find('>').map(|e| i + e) else { break };
            let tag = &x[i + 1..end];
            i = end + 1;
            if tag.starts_with('?') || tag.starts_with('!') {
                continue;
            }
            if let Some(name) = tag.strip_prefix('/') {
                v.push(Ev::End(name.trim()));
                continue;
            }
            let self_closing = tag.ends_with('/');
            let tag = tag.trim_end_matches('/');
            let (name, attrs) = tag.split_once(|c: char| c.is_whitespace()).unwrap_or((tag, ""));
            v.push(Ev::Start(name, attrs, self_closing));
        } else {
            let e = x[i..].find('<').map(|e| i + e).unwrap_or(b.len());
            v.push(Ev::Text(unescape(&x[i..e])));
            i = e;
        }
    }
    v
}

pub fn attr(attrs: &str, key: &str) -> Option<String> {
    let mut rest = attrs;
    while let Some(eq) = rest.find('=') {
        let k = rest[..eq].trim();
        let after = rest[eq + 1..].trim_start();
        let q = after.chars().next()?;
        if q != '"' && q != '\'' {
            return None;
        }
        let end = after[1..].find(q)? + 1;
        if k == key {
            return Some(unescape(&after[1..end]));
        }
        rest = &after[end + 1..];
    }
    None
}

fn local(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

fn joined(lines: Vec<String>, empty_error: &str) -> Result<String, String> {
    if !lines.iter().any(|l| !l.trim().is_empty()) {
        return Err(empty_error.into());
    }
    Ok(format!("{}\n", lines.join("\n").trim_end_matches('\n')))
}

// ───── DOCX ─────

pub fn docx(b: &[u8]) -> Result<String, String> {
    let z = Zip::open(b, "DOCX")?;
    let x = z.text("word/document.xml").ok_or("Missing word/document.xml")?;
    let mut lines = Vec::new();
    let (mut para, mut in_p, mut in_t, mut ruby_guide) = (String::new(), false, false, 0usize);
    for e in events(&x) {
        match e {
            Ev::Start("w:p", _, sc) => {
                in_p = !sc;
                para.clear();
            }
            Ev::End("w:p") => {
                lines.extend(para.split('\n').map(str::to_string));
                para.clear();
                in_p = false;
            }
            Ev::Start("w:rt", _, false) => ruby_guide += 1,
            Ev::End("w:rt") => ruby_guide = ruby_guide.saturating_sub(1),
            Ev::Start("w:t", _, sc) => in_t = !sc,
            Ev::End("w:t") => in_t = false,
            Ev::Start("w:tab", _, _) if in_p && ruby_guide == 0 => para.push('\t'),
            Ev::Start("w:br" | "w:cr", _, _) if in_p && ruby_guide == 0 => para.push('\n'),
            Ev::Text(t) if in_t && ruby_guide == 0 => para.push_str(&t),
            _ => {}
        }
    }
    joined(lines, "DOCX contains no extractable text")
}

// ───── XLSX ─────

fn col_index(r: &str) -> usize {
    r.chars().take_while(|c| c.is_ascii_alphabetic()).fold(0usize, |a, c| a * 26 + (c.to_ascii_uppercase() as usize - 'A' as usize + 1)).saturating_sub(1)
}

/// Base text of `<si>`/`<is>`: `t` children and `r/t`, excluding `rPh` phonetics.
fn string_items(x: &str, item: &str) -> Vec<String> {
    let mut out = Vec::new();
    let (mut cur, mut in_item, mut in_t, mut rph) = (String::new(), false, false, 0usize);
    for e in events(x) {
        match e {
            Ev::Start(n, _, sc) if n == item => {
                in_item = !sc;
                cur.clear();
                if sc {
                    out.push(String::new());
                }
            }
            Ev::End(n) if n == item => {
                out.push(std::mem::take(&mut cur));
                in_item = false;
            }
            Ev::Start("rPh", _, false) => rph += 1,
            Ev::End("rPh") => rph = rph.saturating_sub(1),
            Ev::Start("t", _, sc) => in_t = !sc,
            Ev::End("t") => in_t = false,
            Ev::Text(t) if in_item && in_t && rph == 0 => cur.push_str(&t),
            _ => {}
        }
    }
    out
}

fn sheet_rows(x: &str, shared: &[String]) -> Vec<Vec<String>> {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut cells: HashMap<usize, String> = HashMap::new();
    let mut max_col: i64 = -1;
    let (mut col, mut typ, mut val, mut in_v, mut in_is_t, mut in_is, mut in_row) = (0usize, String::new(), String::new(), false, false, false, false);
    let mut rph = 0usize;
    for e in events(x) {
        match e {
            Ev::Start("row", _, sc) => {
                if rows.len() >= MAX_XLSX_ROWS_PER_SHEET {
                    break;
                }
                cells.clear();
                max_col = -1;
                in_row = true;
                if sc {
                    rows.push(vec![]);
                    in_row = false;
                }
            }
            Ev::End("row") if in_row => {
                rows.push((0..=max_col).map(|i| cells.get(&(i as usize)).cloned().unwrap_or_default()).collect());
                in_row = false;
            }
            Ev::Start("c", a, sc) => {
                col = attr(a, "r").map(|r| col_index(&r)).unwrap_or((max_col + 1) as usize);
                typ = attr(a, "t").unwrap_or_default();
                val.clear();
                if sc && col < MAX_XLSX_COLS {
                    max_col = max_col.max(col as i64);
                    cells.insert(col, String::new());
                }
            }
            Ev::End("c") => {
                if col < MAX_XLSX_COLS {
                    let v = match typ.as_str() {
                        "s" => val.trim().parse::<usize>().ok().and_then(|i| shared.get(i).cloned()).unwrap_or_default(),
                        "b" => if ["1", "true", "TRUE"].contains(&val.trim()) { "TRUE".into() } else { "FALSE".into() },
                        "e" => if val.is_empty() { "#ERROR".into() } else { val.clone() },
                        _ => val.clone(),
                    };
                    cells.insert(col, v);
                    max_col = max_col.max(col as i64);
                }
            }
            Ev::Start("v", _, sc) => in_v = !sc,
            Ev::End("v") => in_v = false,
            Ev::Start("is", _, sc) => in_is = !sc,
            Ev::End("is") => in_is = false,
            Ev::Start("t", _, sc) if in_is => in_is_t = !sc,
            Ev::End("t") => in_is_t = false,
            // Inline strings carry phonetics too (`<is><rPh>`); drop them like shared strings.
            Ev::Start("rPh", _, false) => rph += 1,
            Ev::End("rPh") => rph = rph.saturating_sub(1),
            Ev::Text(t) if rph == 0 && (in_v || (in_is && in_is_t)) => val.push_str(&t),
            _ => {}
        }
    }
    while rows.last().is_some_and(|r| !r.iter().any(|v| !v.trim().is_empty())) {
        rows.pop();
    }
    rows
}

fn norm_path(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    parts.join("/")
}

pub fn xlsx(b: &[u8]) -> Result<String, String> {
    let z = Zip::open(b, "XLSX")?;
    let shared = z.text("xl/sharedStrings.xml").map(|x| string_items(&x, "si")).unwrap_or_default();
    let mut rels = HashMap::new();
    for e in events(&z.text("xl/_rels/workbook.xml.rels").unwrap_or_default()) {
        if let Ev::Start("Relationship", a, _) = e {
            if let (Some(id), Some(t)) = (attr(a, "Id"), attr(a, "Target")) {
                rels.insert(id, t);
            }
        }
    }
    let wb = z.text("xl/workbook.xml").ok_or("Missing xl/workbook.xml")?;
    let names: Vec<String> = z.names().into_iter().map(str::to_string).collect();
    let mut out = Vec::new();
    for e in events(&wb) {
        let Ev::Start(n, a, _) = e else { continue };
        if local(n) != "sheet" {
            continue;
        }
        let state = attr(a, "state").unwrap_or_else(|| "visible".into());
        let target = attr(a, "r:id").and_then(|id| rels.get(&id).cloned()).unwrap_or_default();
        let target = target.trim_start_matches('/');
        let part = norm_path(&if target.starts_with("xl/") { target.to_string() } else { format!("xl/{target}") });
        if state == "hidden" || state == "veryHidden" || !names.contains(&part) {
            continue;
        }
        let rows = sheet_rows(&z.text(&part).unwrap_or_default(), &shared);
        out.push(format!("# ── Sheet: {} ──", attr(a, "name").unwrap_or_else(|| "Sheet".into())));
        if rows.is_empty() {
            out.push("(empty)".into());
        } else {
            out.extend(rows.iter().map(|r| r.join("\t")));
        }
        out.push(String::new());
    }
    joined(out, "XLSX has no visible sheets with content")
}

// ───── PPTX ─────

pub fn pptx(b: &[u8]) -> Result<String, String> {
    let z = Zip::open(b, "PPTX")?;
    let mut slides: Vec<(usize, String)> = z.names().into_iter().filter_map(|n| n.strip_prefix("ppt/slides/slide").and_then(|r| r.strip_suffix(".xml")).and_then(|d| d.parse().ok()).map(|i| (i, n.to_string()))).collect();
    slides.sort();
    let mut out = Vec::new();
    for (i, name) in slides {
        out.push(format!("# ── Slide {i} ──"));
        let mut para = String::new();
        let mut in_t = false;
        for e in events(&z.text(&name).unwrap_or_default()) {
            match e {
                Ev::Start("a:t", _, sc) => in_t = !sc,
                Ev::End("a:t") => in_t = false,
                Ev::Start("a:br", _, _) => para.push('\n'),
                Ev::End("a:p") => {
                    if !para.trim().is_empty() {
                        out.push(std::mem::take(&mut para));
                    }
                    para.clear();
                }
                Ev::Text(t) if in_t => para.push_str(&t),
                _ => {}
            }
        }
        out.push(String::new());
    }
    joined(out, "PPTX contains no extractable text")
}

// ───── OpenDocument (odt / ods / odp) ─────

pub fn odf(b: &[u8], kind: &str) -> Result<String, String> {
    let z = Zip::open(b, kind)?;
    let x = z.text("content.xml").ok_or("Missing content.xml")?;
    let mut out = Vec::new();
    let mut line = String::new();
    let mut row: Vec<String> = Vec::new();
    let (mut depth_p, mut in_cell) = (0usize, false);
    for e in events(&x) {
        match e {
            Ev::Start("text:p" | "text:h", _, sc) => {
                if !sc {
                    depth_p += 1;
                }
            }
            Ev::End("text:p" | "text:h") => {
                depth_p = depth_p.saturating_sub(1);
                if in_cell {
                    line.push('\n');
                } else {
                    out.push(std::mem::take(&mut line));
                }
            }
            Ev::Start("text:tab", _, _) => line.push('\t'),
            Ev::Start("text:line-break", _, _) => line.push('\n'),
            Ev::Start("text:s", a, _) => line.push_str(&" ".repeat(attr(a, "text:c").and_then(|c| c.parse().ok()).unwrap_or(1usize).min(64))),
            Ev::Start("table:table", a, false) => out.push(format!("# ── Table: {} ──", attr(a, "table:name").unwrap_or_default())),
            Ev::Start("table:table-cell", a, sc) => {
                let rep = attr(a, "table:number-columns-repeated").and_then(|c| c.parse().ok()).unwrap_or(1usize).min(MAX_XLSX_COLS);
                if sc {
                    row.extend(std::iter::repeat_n(String::new(), rep));
                } else {
                    in_cell = true;
                    line.clear();
                }
            }
            Ev::End("table:table-cell") => {
                row.push(line.trim_end_matches('\n').to_string());
                line.clear();
                in_cell = false;
            }
            Ev::End("table:table-row") => {
                while row.last().is_some_and(String::is_empty) {
                    row.pop();
                }
                if !row.is_empty() {
                    out.push(row.join("\t"));
                }
                row.clear();
            }
            Ev::Text(t) if depth_p > 0 => line.push_str(&t),
            _ => {}
        }
    }
    joined(out, &format!("{kind} contains no extractable text"))
}

// ───── EPUB / HTML ─────

/// Visible text of HTML/XHTML (scripts/styles dropped, block elements become line breaks).
pub fn html_text(x: &str) -> String {
    let mut out = String::new();
    let mut skip = 0usize;
    for e in events(x) {
        match e {
            Ev::Start(n, _, sc) => {
                let n = local(n).to_ascii_lowercase();
                if matches!(n.as_str(), "script" | "style" | "head") && !sc {
                    skip += 1;
                }
                if matches!(n.as_str(), "p" | "div" | "br" | "li" | "tr" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "section" | "article" | "blockquote" | "pre" | "table") && !out.ends_with('\n') {
                    out.push('\n');
                }
            }
            Ev::End(n) => {
                let n = local(n).to_ascii_lowercase();
                if matches!(n.as_str(), "script" | "style" | "head") {
                    skip = skip.saturating_sub(1);
                }
                if matches!(n.as_str(), "p" | "div" | "li" | "tr" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6") && !out.ends_with('\n') {
                    out.push('\n');
                }
            }
            Ev::Text(t) if skip == 0 => out.push_str(&t.split_whitespace().collect::<Vec<_>>().join(" ")),
            _ => {}
        }
    }
    out.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join("\n")
}

pub fn epub(b: &[u8]) -> Result<String, String> {
    let z = Zip::open(b, "EPUB")?;
    let container = z.text("META-INF/container.xml").ok_or("Missing META-INF/container.xml")?;
    let opf_path = events(&container).into_iter().find_map(|e| if let Ev::Start(n, a, _) = e { (local(n) == "rootfile").then(|| attr(a, "full-path")).flatten() } else { None }).ok_or("EPUB has no rootfile")?;
    let opf = z.text(&opf_path).ok_or("Missing EPUB package document")?;
    let base = opf_path.rsplit_once('/').map(|(d, _)| format!("{d}/")).unwrap_or_default();
    let mut manifest = HashMap::new();
    let mut spine = Vec::new();
    for e in events(&opf) {
        if let Ev::Start(n, a, _) = e {
            match local(n) {
                "item" => {
                    if let (Some(id), Some(h)) = (attr(a, "id"), attr(a, "href")) {
                        manifest.insert(id, h);
                    }
                }
                "itemref" => spine.extend(attr(a, "idref")),
                _ => {}
            }
        }
    }
    let mut out = Vec::new();
    for id in spine {
        if let Some(h) = manifest.get(&id) {
            let t = html_text(&z.text(&norm_path(&format!("{base}{h}"))).unwrap_or_default());
            if !t.is_empty() {
                out.push(t);
                out.push(String::new());
            }
        }
    }
    joined(out, "EPUB contains no extractable text")
}

// ───── RTF ─────

pub fn rtf(b: &[u8]) -> Result<String, String> {
    let s = String::from_utf8_lossy(b);
    if !s.trim_start().starts_with("{\\rtf") {
        return Err("Not a valid RTF document".into());
    }
    const SKIP: &[&str] = &["fonttbl", "colortbl", "stylesheet", "info", "pict", "header", "footer", "listtable", "listoverridetable", "rsidtbl", "generator", "xmlnstbl", "themedata", "datastore", "latentstyles"];
    let c: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut stack: Vec<bool> = Vec::new(); // skipping?
    let mut skip = false;
    let mut uc_skip = 0usize;
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            '{' => {
                stack.push(skip);
                if c.get(i + 1) == Some(&'\\') && c.get(i + 2) == Some(&'*') {
                    skip = true;
                }
                i += 1;
            }
            '}' => {
                skip = stack.pop().unwrap_or(false);
                i += 1;
            }
            '\\' => {
                i += 1;
                let Some(&n) = c.get(i) else { break };
                if n == '\'' {
                    let h: String = c.iter().skip(i + 1).take(2).collect();
                    if let Ok(v) = u8::from_str_radix(&h, 16) {
                        if !skip {
                            out.push(if (0x80..0xa0).contains(&v) { ['€', '\u{fffd}', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u{fffd}', 'Ž', '\u{fffd}', '\u{fffd}', '‘', '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', '\u{fffd}', 'ž', 'Ÿ'][(v - 0x80) as usize] } else { v as char });
                        }
                    }
                    i += 3;
                    continue;
                }
                if !n.is_ascii_alphabetic() {
                    if !skip {
                        match n {
                            '\\' | '{' | '}' => out.push(n),
                            '~' => out.push('\u{a0}'),
                            '-' => {}
                            '_' => out.push('-'),
                            _ => {}
                        }
                    }
                    i += 1;
                    continue;
                }
                let ws = i;
                while i < c.len() && c[i].is_ascii_alphabetic() {
                    i += 1;
                }
                let word: String = c[ws..i].iter().collect();
                let ns = i;
                if i < c.len() && (c[i] == '-' || c[i].is_ascii_digit()) {
                    i += 1;
                    while i < c.len() && c[i].is_ascii_digit() {
                        i += 1;
                    }
                }
                let num: Option<i64> = c[ns..i].iter().collect::<String>().parse().ok();
                if c.get(i) == Some(&' ') {
                    i += 1;
                }
                if SKIP.contains(&word.as_str()) {
                    skip = true;
                    continue;
                }
                if skip {
                    continue;
                }
                match word.as_str() {
                    "par" | "line" | "sect" | "row" => out.push('\n'),
                    "tab" | "cell" => out.push('\t'),
                    "emdash" => out.push('—'),
                    "endash" => out.push('–'),
                    "lquote" => out.push('‘'),
                    "rquote" => out.push('’'),
                    "ldblquote" => out.push('“'),
                    "rdblquote" => out.push('”'),
                    "bullet" => out.push('•'),
                    "uc" => uc_skip = num.unwrap_or(1).max(0) as usize,
                    "u" => {
                        if let Some(v) = num {
                            let v = if v < 0 { v + 65536 } else { v };
                            if let Some(ch) = char::from_u32(v as u32) {
                                out.push(ch);
                            }
                            // skip the ANSI fallback characters
                            let mut k = 0;
                            while k < uc_skip.max(1) && i < c.len() && c[i] != '\\' && c[i] != '{' && c[i] != '}' {
                                i += 1;
                                k += 1;
                            }
                        }
                    }
                    _ => {}
                }
            }
            '\r' | '\n' => i += 1,
            ch => {
                if !skip {
                    out.push(ch);
                }
                i += 1;
            }
        }
    }
    let text: Vec<String> = out.lines().map(|l| l.trim_end().to_string()).collect();
    joined(text, "RTF contains no extractable text")
}

// ───── Jupyter ─────

fn source_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
        _ => String::new(),
    }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\u{1b}' {
            if it.peek() == Some(&'[') {
                it.next();
                for d in it.by_ref() {
                    if ('@'..='~').contains(&d) {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// Strip ANSI and keep only the final `\r` frame of each line (tqdm redraws).
fn clean_stream(s: &str) -> String {
    strip_ansi(s).replace("\r\n", "\n").split('\n').map(|l| l.split('\r').rfind(|f| !f.is_empty()).unwrap_or("")).collect::<Vec<_>>().join("\n")
}

fn human_size(n: usize) -> String {
    if n >= 1024 {
        format!("{} KB", (n as f64 / 1024.0).round() as usize)
    } else {
        format!("{n} B")
    }
}

fn notebook_output(o: &Value) -> String {
    let Some(map) = o.as_object() else { return String::new() };
    let otype = map.get("output_type").and_then(Value::as_str).unwrap_or("");
    match otype {
        "stream" => {
            let b = clean_stream(&source_text(map.get("text").unwrap_or(&Value::Null)));
            if b.trim().is_empty() {
                String::new()
            } else {
                b
            }
        }
        "error" | "pyerr" => {
            let tb = map.get("traceback").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n")).unwrap_or_default();
            let header = format!("Error: {}: {}", map.get("ename").and_then(Value::as_str).unwrap_or(""), map.get("evalue").and_then(Value::as_str).unwrap_or(""));
            format!("{}\n{}", header.trim_end_matches([':', ' ']), clean_stream(&tb)).trim_end().to_string()
        }
        "execute_result" | "display_data" | "pyout" => {
            let mut data: serde_json::Map<String, Value> = map.get("data").and_then(Value::as_object).cloned().unwrap_or_default();
            if !map.get("data").is_some_and(Value::is_object) {
                if let Some(t) = map.get("text") {
                    data.insert("text/plain".into(), t.clone());
                }
                for (k, mime) in [("png", "image/png"), ("jpeg", "image/jpeg"), ("svg", "image/svg+xml"), ("html", "text/html")] {
                    if let Some(v) = map.get(k) {
                        data.insert(mime.into(), v.clone());
                    }
                }
            }
            if data.contains_key("application/vnd.jupyter.widget-view+json") {
                return "[interactive widget — omitted]".into();
            }
            for mime in ["text/plain", "text/markdown"] {
                if let Some(v) = data.get(mime) {
                    let b = clean_stream(&source_text(v));
                    if !b.trim().is_empty() {
                        return b;
                    }
                }
            }
            for (mime, v) in &data {
                if mime.starts_with("image/") {
                    let payload: String = source_text(v).chars().filter(|c| c.is_ascii_alphanumeric() || "+/=".contains(*c)).collect();
                    let pad = payload.len() - payload.trim_end_matches('=').len();
                    return format!("[{mime} output — {}, omitted]", human_size((payload.len() * 3 / 4).saturating_sub(pad.min(2))));
                }
            }
            if let Some(h) = data.get("text/html") {
                return format!("[text/html output — {} chars, omitted]", source_text(h).chars().count());
            }
            let keys: Vec<&str> = data.keys().map(String::as_str).collect();
            format!("[{} output — omitted]", if keys.is_empty() { "unknown".into() } else { keys.join(", ") })
        }
        _ => String::new(),
    }
}

pub fn ipynb(b: &[u8], display_name: &str) -> Result<String, String> {
    let s = String::from_utf8_lossy(b);
    let nb: Value = serde_json::from_str(s.trim_start_matches('\u{feff}')).map_err(|e| format!("Not a valid notebook: {e}"))?;
    if !nb.is_object() {
        return Err("Notebook root is not an object".into());
    }
    let mut cells: Vec<(String, &Value)> = Vec::new();
    if let Some(a) = nb["cells"].as_array() {
        cells.extend(a.iter().enumerate().map(|(i, c)| (format!(".cells[{i}].outputs"), c)));
    } else if let Some(ws) = nb["worksheets"].as_array() {
        for (wi, w) in ws.iter().enumerate() {
            for (ci, c) in w["cells"].as_array().into_iter().flatten().enumerate() {
                cells.push((format!(".worksheets[{wi}].cells[{ci}].outputs"), c));
            }
        }
    }
    if cells.is_empty() {
        return Err("Notebook contains no cells".into());
    }
    let mut counts: HashMap<&str, usize> = HashMap::new();
    let mut out = Vec::new();
    for (ptr, cell) in cells {
        let typ = cell["cell_type"].as_str().unwrap_or("");
        let label = match typ {
            "markdown" => "Markdown",
            "code" => "Code",
            "raw" => "Raw",
            _ => continue,
        };
        let n = counts.entry(typ).or_insert(0);
        *n += 1;
        let n = *n;
        let suffix = if typ == "raw" { String::new() } else { format!(" {n}") };
        out.push(format!("# ── {label} cell{suffix} ──"));
        out.push(source_text(&cell["source"]).trim_end_matches('\n').to_string());
        out.push(String::new());
        if typ == "code" {
            let joined_out = cell["outputs"].as_array().map(|a| a.iter().map(notebook_output).filter(|s| !s.is_empty()).collect::<Vec<_>>().join("\n")).unwrap_or_default();
            if !joined_out.is_empty() {
                let rendered = if joined_out.chars().count() <= MAX_NOTEBOOK_OUTPUT_CHARS {
                    joined_out
                } else {
                    let omitted = joined_out.chars().count() - MAX_NOTEBOOK_OUTPUT_CHARS;
                    format!("{}\n… [{omitted} output chars truncated — full output: jq -r '{ptr}' {}]", joined_out.chars().take(MAX_NOTEBOOK_OUTPUT_CHARS).collect::<String>(), crate::proc::shell_quote(display_name))
                };
                out.push(format!("# ── Output (cell {n}) ──"));
                out.push(rendered.trim_end_matches('\n').to_string());
                out.push(String::new());
            }
        }
    }
    joined(out, "Notebook contains no readable cells")
}

#[cfg(test)]
pub(crate) mod testzip {
    /// Build a zip (deflate) from `(name, contents)`.
    pub fn build(files: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, body) in files {
            let comp = miniz_oxide::deflate::compress_to_vec(body.as_bytes(), 6);
            let off = out.len() as u32;
            let mut h = vec![];
            h.extend_from_slice(b"PK\x03\x04");
            h.extend_from_slice(&[20, 0, 0, 0, 8, 0, 0, 0, 0, 0]);
            h.extend_from_slice(&0u32.to_le_bytes()); // crc (unchecked)
            h.extend_from_slice(&(comp.len() as u32).to_le_bytes());
            h.extend_from_slice(&(body.len() as u32).to_le_bytes());
            h.extend_from_slice(&(name.len() as u16).to_le_bytes());
            h.extend_from_slice(&0u16.to_le_bytes());
            h.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&h);
            out.extend_from_slice(&comp);
            let mut c = vec![];
            c.extend_from_slice(b"PK\x01\x02");
            c.extend_from_slice(&[20, 0, 20, 0, 0, 0, 8, 0, 0, 0, 0, 0]);
            c.extend_from_slice(&0u32.to_le_bytes());
            c.extend_from_slice(&(comp.len() as u32).to_le_bytes());
            c.extend_from_slice(&(body.len() as u32).to_le_bytes());
            c.extend_from_slice(&(name.len() as u16).to_le_bytes());
            c.extend_from_slice(&[0u8; 12]);
            c.extend_from_slice(&off.to_le_bytes());
            c.extend_from_slice(name.as_bytes());
            central.extend_from_slice(&c);
        }
        let cd_off = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
        out.extend_from_slice(&(files.len() as u16).to_le_bytes());
        out.extend_from_slice(&(files.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docx_xlsx_pptx() {
        let d = testzip::build(&[("word/document.xml", r#"<?xml version="1.0"?><w:document xmlns:w="x"><w:body><w:p><w:r><w:t>Hello</w:t></w:r><w:r><w:tab/><w:t xml:space="preserve">world &amp; co</w:t></w:r></w:p><w:p><w:r><w:ruby><w:rt><w:r><w:t>guide</w:t></w:r></w:rt><w:rubyBase><w:r><w:t>漢字</w:t></w:r></w:rubyBase></w:ruby><w:br/><w:t>line2</w:t></w:r></w:p></w:body></w:document>"#)]);
        assert_eq!(docx(&d).unwrap(), "Hello\tworld & co\n漢字\nline2\n");
        let x = testzip::build(&[
            ("xl/workbook.xml", r#"<workbook xmlns:r="r"><sheets><sheet name="Data" sheetId="1" r:id="rId1"/><sheet name="Secret" sheetId="2" state="hidden" r:id="rId2"/></sheets></workbook>"#),
            ("xl/_rels/workbook.xml.rels", r#"<Relationships><Relationship Id="rId1" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Target="worksheets/sheet2.xml"/></Relationships>"#),
            ("xl/sharedStrings.xml", r#"<sst><si><t>name</t></si><si><r><t>Bo</t></r><r><t>b</t></r><rPh><t>ぼぶ</t></rPh></si></sst>"#),
            ("xl/worksheets/sheet1.xml", r#"<worksheet><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c><c r="C1" t="b"><v>1</v></c></row><row r="2"><c r="A2" t="s"><v>1</v></c><c r="B2"><v>42</v></c><c r="C2" t="inlineStr"><is><r><t>inline</t></r><rPh><t>いん</t></rPh></is></c><c r="D2" t="inlineStr"><is><r><t>漢</t></r><rPh><t>かん</t></rPh></is></c></row><row r="3"/></sheetData></worksheet>"#),
            ("xl/worksheets/sheet2.xml", r#"<worksheet><sheetData><row><c><v>hidden</v></c></row></sheetData></worksheet>"#),
        ]);
        // Inline strings drop `rPh` phonetics exactly like shared strings (Hermes `_xlsx_string_text`).
        assert_eq!(xlsx(&x).unwrap(), "# ── Sheet: Data ──\nname\t\tTRUE\nBob\t42\tinline\t漢\n");
        let p = testzip::build(&[("ppt/slides/slide2.xml", "<p:sld><a:p><a:r><a:t>Second</a:t></a:r></a:p></p:sld>"), ("ppt/slides/slide1.xml", "<p:sld><a:p><a:r><a:t>Title</a:t></a:r><a:br/><a:r><a:t>sub</a:t></a:r></a:p></p:sld>")]);
        assert_eq!(pptx(&p).unwrap(), "# ── Slide 1 ──\nTitle\nsub\n\n# ── Slide 2 ──\nSecond\n");
        assert!(docx(b"PK nonsense").unwrap_err().contains("Not a valid DOCX"));
    }

    #[test]
    fn odf_epub_rtf_ipynb() {
        let o = testzip::build(&[("content.xml", r#"<office:document-content><office:body><office:text><text:h>Head</text:h><text:p>a<text:s text:c="2"/>b<text:tab/>c</text:p><table:table table:name="T"><table:table-row><table:table-cell><text:p>x</text:p></table:table-cell><table:table-cell table:number-columns-repeated="2"/><table:table-cell><text:p>y</text:p></table:table-cell></table:table-row></table:table></office:text></office:body></office:document-content>"#)]);
        assert_eq!(odf(&o, "ODT").unwrap(), "Head\na  b\tc\n# ── Table: T ──\nx\t\t\ty\n");
        let e = testzip::build(&[
            ("META-INF/container.xml", r#"<container><rootfiles><rootfile full-path="OEBPS/content.opf"/></rootfiles></container>"#),
            ("OEBPS/content.opf", r#"<package><manifest><item id="c1" href="ch1.xhtml"/><item id="c2" href="text/ch2.xhtml"/></manifest><spine><itemref idref="c1"/><itemref idref="c2"/></spine></package>"#),
            ("OEBPS/ch1.xhtml", "<html><head><title>x</title><style>p{}</style></head><body><h1>One</h1><p>First  para.</p></body></html>"),
            ("OEBPS/text/ch2.xhtml", "<html><body><p>Two</p><script>evil()</script></body></html>"),
        ]);
        assert_eq!(epub(&e).unwrap(), "One\nFirst para.\n\nTwo\n");
        let r = br"{\rtf1\ansi{\fonttbl{\f0 Arial;}}{\*\generator x;}\f0 Hello \b bold\b0  \'e9t\'e9\par Line \u8364? two\tab end}";
        assert_eq!(rtf(r).unwrap(), "Hello bold été\nLine € two\tend\n");
        let nb = serde_json::json!({"cells": [
            {"cell_type": "markdown", "source": ["# Title\n", "text"]},
            {"cell_type": "code", "source": "print(1)", "outputs": [
                {"output_type": "stream", "text": ["10%\r50%\r100%\n", "\u{1b}[31mdone\u{1b}[0m"]},
                {"output_type": "display_data", "data": {"image/png": "iVBORw0KGgo="}},
                {"output_type": "error", "ename": "ValueError", "evalue": "bad", "traceback": ["tb line"]}
            ]}
        ]});
        let t = ipynb(nb.to_string().as_bytes(), "n.ipynb").unwrap();
        assert_eq!(t, "# ── Markdown cell 1 ──\n# Title\ntext\n\n# ── Code cell 1 ──\nprint(1)\n\n# ── Output (cell 1) ──\n100%\ndone\n[image/png output — 8 B, omitted]\nError: ValueError: bad\ntb line\n");
        assert!(ipynb(b"{}", "x").unwrap_err().contains("no cells"));
    }
}
