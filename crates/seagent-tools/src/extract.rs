//! Document-to-text extraction for `read` (port of Hermes `tools/read_extract.py`, MIT):
//! Jupyter notebooks, DOCX, XLSX, PPTX, OpenDocument (odt/ods/odp), EPUB, RTF, PDF and
//! SQLite render as paginated text. Hermes needs the optional `anydoc` package for the
//! non-stdlib formats; here they are hand-written (PDF prefers `pdftotext` when present
//! and falls back to decoding FlateDecode content streams).

use crate::zip::{zlib_decompress, Zip};
use serde_json::Value;
use std::path::Path;
use std::process::Stdio;

pub const MAX_DOCUMENT_BYTES: u64 = 50 * 1024 * 1024;
const MAX_XLSX_ROWS: usize = 5000;
const MAX_XLSX_COLS: usize = 256;
const MAX_OUTPUT_CHARS: usize = 20_000;

/// Extensions extracted instead of read as text.
pub const EXTRACTABLE: &[&str] = &["ipynb", "docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "ppsx", "odt", "ods", "odp", "epub", "rtf", "pdf", "db", "sqlite", "sqlite3", "doc", "xls", "ppt"];

pub fn ext_of(p: &Path) -> String {
    p.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default()
}

pub fn is_extractable(p: &Path) -> bool {
    EXTRACTABLE.contains(&ext_of(p).as_str())
}

/// Text of a document, or Err with the reason it can't be converted.
pub fn extract(p: &Path, data: &[u8]) -> Result<String, String> {
    if data.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(format!("Document too large to convert ({} bytes, limit is {MAX_DOCUMENT_BYTES})", data.len()));
    }
    match ext_of(p).as_str() {
        "ipynb" => notebook(data, &p.display().to_string()),
        "docx" | "docm" => docx(data),
        "xlsx" | "xlsm" => xlsx(data),
        "pptx" | "pptm" | "ppsx" => pptx(data),
        "odt" | "ods" | "odp" => odf(data),
        "epub" => epub(data),
        "rtf" => joined(rtf(&String::from_utf8_lossy(data)).lines().map(str::to_string).collect(), "RTF contains no extractable text"),
        "pdf" => pdf(p, data),
        "db" | "sqlite" | "sqlite3" => sqlite(p, data),
        "doc" | "xls" | "ppt" => legacy_office(p),
        e => Err(format!("Unsupported document type: .{e}")),
    }
}

fn joined(lines: Vec<String>, empty: &str) -> Result<String, String> {
    if !lines.iter().any(|l| !l.trim().is_empty()) {
        return Err(empty.into());
    }
    Ok(lines.join("\n").trim_end_matches('\n').to_string() + "\n")
}

// ───────────────────── minimal XML ─────────────────────

#[derive(Debug, PartialEq)]
pub enum Ev {
    /// local name, attributes, self-closing
    Open(String, Vec<(String, String)>, bool),
    Close(String),
    Text(String),
}

pub fn unescape_xml(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let Some(end) = tail.find(';').filter(|&e| e <= 12) else {
            out.push('&');
            rest = &tail[1..];
            continue;
        };
        let ent = &tail[1..end];
        let ch = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some('\u{a0}'),
            _ if ent.starts_with("#x") || ent.starts_with("#X") => u32::from_str_radix(&ent[2..], 16).ok().and_then(char::from_u32),
            _ if ent.starts_with('#') => ent[1..].parse().ok().and_then(char::from_u32),
            _ => None,
        };
        match ch {
            Some(c) => {
                out.push(c);
                rest = &tail[end + 1..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn local(name: &str) -> String {
    name.rsplit(':').next().unwrap_or(name).to_string()
}

pub fn xml_events(s: &str) -> Vec<Ev> {
    let mut out = Vec::new();
    let mut i = 0;
    let b = s.as_bytes();
    while i < b.len() {
        if b[i] != b'<' {
            let e = s[i..].find('<').map(|k| i + k).unwrap_or(s.len());
            out.push(Ev::Text(unescape_xml(&s[i..e])));
            i = e;
            continue;
        }
        let rest = &s[i..];
        if rest.starts_with("<!--") {
            i += rest.find("-->").map(|k| k + 3).unwrap_or(rest.len());
            continue;
        }
        if rest.starts_with("<![CDATA[") {
            let e = rest.find("]]>").unwrap_or(rest.len());
            out.push(Ev::Text(rest[9..e].to_string()));
            i += (e + 3).min(rest.len());
            continue;
        }
        if rest.starts_with("<?") || rest.starts_with("<!") {
            i += rest.find('>').map(|k| k + 1).unwrap_or(rest.len());
            continue;
        }
        // Find the closing '>' outside quotes.
        let mut k = 1;
        let mut q: Option<u8> = None;
        let rb = rest.as_bytes();
        while k < rb.len() {
            match (q, rb[k]) {
                (None, b'"') | (None, b'\'') => q = Some(rb[k]),
                (Some(c), x) if c == x => q = None,
                (None, b'>') => break,
                _ => {}
            }
            k += 1;
        }
        let inner = &rest[1..k.min(rest.len())];
        i += (k + 1).min(rest.len());
        if let Some(n) = inner.strip_prefix('/') {
            out.push(Ev::Close(local(n.trim())));
            continue;
        }
        let selfc = inner.ends_with('/');
        let inner = inner.trim_end_matches('/');
        let mut parts = inner.splitn(2, char::is_whitespace);
        let name = local(parts.next().unwrap_or(""));
        let mut attrs = Vec::new();
        let mut a = parts.next().unwrap_or("").trim();
        while let Some(eq) = a.find('=') {
            let key = a[..eq].trim().to_string();
            let v = a[eq + 1..].trim_start();
            let Some(qc) = v.chars().next().filter(|c| *c == '"' || *c == '\'') else { break };
            let Some(end) = v[1..].find(qc) else { break };
            attrs.push((key, unescape_xml(&v[1..1 + end])));
            a = v[end + 2..].trim_start();
        }
        out.push(Ev::Open(name, attrs, selfc));
    }
    out
}

pub fn attr<'a>(attrs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    attrs.iter().find(|(k, _)| k == key || local(k) == key).map(|(_, v)| v.as_str())
}

// ───────────────────── OOXML ─────────────────────

fn open_zip<'a>(data: &'a [u8], kind: &str) -> Result<Zip<'a>, String> {
    Zip::open(data).map_err(|e| format!("Not a valid {kind}: {e}"))
}

/// Paragraph text of WordprocessingML / DrawingML runs.
fn paragraphs(xml: &str, para: &str, text: &str, ruby: Option<&str>) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur: Option<String> = None;
    let (mut in_text, mut in_ruby) = (false, 0usize);
    for ev in xml_events(xml) {
        match ev {
            Ev::Open(n, _, sc) if n == para && !sc => cur = Some(String::new()),
            Ev::Open(n, _, true) if n == para => lines.push(String::new()),
            Ev::Close(n) if n == para => {
                if let Some(t) = cur.take() {
                    lines.extend(t.split('\n').map(str::to_string));
                }
            }
            Ev::Open(n, _, false) if Some(n.as_str()) == ruby => in_ruby += 1,
            Ev::Close(n) if Some(n.as_str()) == ruby => in_ruby = in_ruby.saturating_sub(1),
            Ev::Open(n, _, sc) if n == text => in_text = !sc,
            Ev::Close(n) if n == text => in_text = false,
            Ev::Open(n, _, _) if in_ruby == 0 => {
                if let Some(c) = cur.as_mut() {
                    match n.as_str() {
                        "tab" => c.push('\t'),
                        "br" | "cr" => c.push('\n'),
                        _ => {}
                    }
                }
            }
            Ev::Text(t) if in_text && in_ruby == 0 => {
                if let Some(c) = cur.as_mut() {
                    c.push_str(&t);
                }
            }
            _ => {}
        }
    }
    lines
}

fn docx(data: &[u8]) -> Result<String, String> {
    let z = open_zip(data, "DOCX")?;
    let xml = z.read_str("word/document.xml")?;
    joined(paragraphs(&xml, "p", "t", Some("rt")), "DOCX contains no extractable text")
}

fn col_index(r: &str) -> usize {
    let n = r.chars().take_while(|c| c.is_ascii_alphabetic()).fold(0usize, |acc, c| acc * 26 + (c.to_ascii_uppercase() as usize - 'A' as usize + 1));
    n.saturating_sub(1)
}

/// Shared/inline string text excluding phonetic runs (`rPh`).
fn si_texts(xml: &str, item: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    let (mut in_t, mut in_rph) = (false, 0);
    for ev in xml_events(xml) {
        match ev {
            Ev::Open(n, _, sc) if n == item => {
                if sc {
                    out.push(String::new());
                } else {
                    cur = Some(String::new());
                }
            }
            Ev::Close(n) if n == item => out.extend(cur.take()),
            Ev::Open(n, _, false) if n == "rPh" => in_rph += 1,
            Ev::Close(n) if n == "rPh" => in_rph -= 1,
            Ev::Open(n, _, sc) if n == "t" => in_t = !sc,
            Ev::Close(n) if n == "t" => in_t = false,
            Ev::Text(t) if in_t && in_rph == 0 => {
                if let Some(c) = cur.as_mut() {
                    c.push_str(&t);
                }
            }
            _ => {}
        }
    }
    out
}

fn sheet_rows(xml: &str, shared: &[String]) -> Vec<Vec<String>> {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut cells: Vec<(usize, String)> = Vec::new();
    let mut max_col: isize = -1;
    let (mut ctype, mut col) = (String::new(), 0usize);
    let (mut in_v, mut in_is, mut in_t) = (false, false, false);
    let mut val = String::new();
    for ev in xml_events(xml) {
        match ev {
            Ev::Open(n, _, sc) if n == "row" => {
                cells.clear();
                max_col = -1;
                if sc {
                    rows.push(vec![]);
                }
            }
            Ev::Close(n) if n == "row" => {
                if rows.len() >= MAX_XLSX_ROWS {
                    break;
                }
                let mut r = vec![String::new(); (max_col + 1) as usize];
                for (c, v) in cells.drain(..) {
                    r[c] = v;
                }
                rows.push(r);
            }
            Ev::Open(n, a, sc) if n == "c" => {
                ctype = attr(&a, "t").unwrap_or("").to_string();
                col = attr(&a, "r").map(col_index).unwrap_or((max_col + 1) as usize);
                val.clear();
                if sc && col < MAX_XLSX_COLS {
                    cells.push((col, String::new()));
                    max_col = max_col.max(col as isize);
                }
            }
            Ev::Close(n) if n == "c" => {
                if col < MAX_XLSX_COLS {
                    let v = match ctype.as_str() {
                        "s" => val.trim().parse::<usize>().ok().and_then(|i| shared.get(i).cloned()).unwrap_or_default(),
                        "b" => if matches!(val.trim(), "1" | "true" | "TRUE") { "TRUE".into() } else { "FALSE".into() },
                        "e" if val.is_empty() => "#ERROR".into(),
                        _ => val.clone(),
                    };
                    cells.push((col, v));
                    max_col = max_col.max(col as isize);
                }
            }
            Ev::Open(n, _, sc) if n == "v" => in_v = !sc,
            Ev::Close(n) if n == "v" => in_v = false,
            Ev::Open(n, _, sc) if n == "is" => in_is = !sc,
            Ev::Close(n) if n == "is" => in_is = false,
            Ev::Open(n, _, sc) if n == "t" => in_t = !sc,
            Ev::Close(n) if n == "t" => in_t = false,
            Ev::Text(t) if in_v || (in_is && in_t) => val.push_str(&t),
            _ => {}
        }
    }
    while rows.last().is_some_and(|r| r.iter().all(|v| v.trim().is_empty())) {
        rows.pop();
    }
    rows
}

fn norm_part(target: &str, base: &str) -> String {
    let t = target.trim_start_matches('/');
    let joined = if t.starts_with(base) { t.to_string() } else { format!("{base}{t}") };
    let mut parts: Vec<&str> = Vec::new();
    for p in joined.split('/') {
        match p {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    parts.join("/")
}

fn rels(z: &Zip, path: &str) -> Vec<(String, String)> {
    let Ok(x) = z.read_str(path) else { return vec![] };
    xml_events(&x).into_iter().filter_map(|e| match e {
        Ev::Open(n, a, _) if n == "Relationship" => Some((attr(&a, "Id")?.to_string(), attr(&a, "Target")?.to_string())),
        _ => None,
    }).collect()
}

fn xlsx(data: &[u8]) -> Result<String, String> {
    let z = open_zip(data, "XLSX")?;
    let shared = z.read_str("xl/sharedStrings.xml").map(|x| si_texts(&x, "si")).unwrap_or_default();
    let rels = rels(&z, "xl/_rels/workbook.xml.rels");
    let names = z.names();
    let wb = z.read_str("xl/workbook.xml")?;
    let mut out = Vec::new();
    for ev in xml_events(&wb) {
        let Ev::Open(n, a, _) = ev else { continue };
        if n != "sheet" {
            continue;
        }
        if matches!(attr(&a, "state"), Some("hidden") | Some("veryHidden")) {
            continue;
        }
        let rid = a.iter().find(|(k, _)| k.ends_with(":id") || k == "id").map(|(_, v)| v.as_str()).unwrap_or("");
        let Some((_, target)) = rels.iter().find(|(id, _)| id == rid) else { continue };
        let part = norm_part(target, "xl/");
        if !names.contains(&part.as_str()) {
            continue;
        }
        let Ok(x) = z.read_str(&part) else { continue };
        let rows = sheet_rows(&x, &shared);
        out.push(format!("# ── Sheet: {} ──", attr(&a, "name").unwrap_or("Sheet")));
        if rows.is_empty() {
            out.push("(empty)".into());
        }
        out.extend(rows.iter().map(|r| r.join("\t")));
        out.push(String::new());
    }
    joined(out, "XLSX has no visible sheets with content")
}

fn pptx(data: &[u8]) -> Result<String, String> {
    let z = open_zip(data, "PPTX")?;
    // Slide order from the presentation's sldIdLst; fall back to file-name order.
    let rels = rels(&z, "ppt/_rels/presentation.xml.rels");
    let mut slides: Vec<String> = Vec::new();
    if let Ok(p) = z.read_str("ppt/presentation.xml") {
        for ev in xml_events(&p) {
            if let Ev::Open(n, a, _) = ev {
                if n == "sldId" {
                    if let Some(rid) = a.iter().find(|(k, _)| k.ends_with(":id")).map(|(_, v)| v) {
                        if let Some((_, t)) = rels.iter().find(|(id, _)| id == rid) {
                            slides.push(norm_part(t, "ppt/"));
                        }
                    }
                }
            }
        }
    }
    if slides.is_empty() {
        let mut v: Vec<(usize, String)> = z.names().into_iter().filter(|n| n.starts_with("ppt/slides/slide") && n.ends_with(".xml")).map(|n| (n[16..n.len() - 4].parse().unwrap_or(0), n.to_string())).collect();
        v.sort();
        slides = v.into_iter().map(|x| x.1).collect();
    }
    let mut out = Vec::new();
    for (i, s) in slides.iter().enumerate() {
        let Ok(x) = z.read_str(s) else { continue };
        out.push(format!("# ── Slide {} ──", i + 1));
        out.extend(paragraphs(&x, "p", "t", None).into_iter().filter(|l| !l.trim().is_empty()));
        out.push(String::new());
    }
    joined(out, "PPTX contains no extractable text")
}

fn odf(data: &[u8]) -> Result<String, String> {
    let z = open_zip(data, "OpenDocument file")?;
    let xml = z.read_str("content.xml")?;
    let mut out = Vec::new();
    let mut line: Option<String> = None;
    let mut row: Option<Vec<String>> = None;
    let mut depth_p = 0;
    for ev in xml_events(&xml) {
        match ev {
            Ev::Open(n, _, false) if n == "table-row" => row = Some(vec![]),
            Ev::Close(n) if n == "table-row" => {
                if let Some(r) = row.take() {
                    if r.iter().any(|c| !c.is_empty()) {
                        out.push(r.join("\t").trim_end().to_string());
                    }
                }
            }
            Ev::Open(n, _, sc) if n == "table-cell" && row.is_some() => {
                row.as_mut().unwrap().push(String::new());
                let _ = sc;
            }
            Ev::Open(n, _, false) if n == "p" || n == "h" => {
                depth_p += 1;
                if row.is_none() {
                    line = Some(String::new());
                }
            }
            Ev::Close(n) if n == "p" || n == "h" => {
                depth_p -= 1;
                if let Some(l) = line.take() {
                    out.push(l);
                }
            }
            Ev::Open(n, _, _) if n == "tab" => {
                if let Some(l) = line.as_mut() {
                    l.push('\t');
                }
            }
            Ev::Open(n, _, _) if n == "line-break" => {
                if let Some(l) = line.as_mut() {
                    l.push('\n');
                }
            }
            Ev::Open(n, a, _) if n == "s" => {
                if let Some(l) = line.as_mut() {
                    l.push_str(&" ".repeat(attr(&a, "c").and_then(|c| c.parse().ok()).unwrap_or(1)));
                }
            }
            Ev::Text(t) if depth_p > 0 => {
                if let Some(r) = row.as_mut() {
                    if let Some(c) = r.last_mut() {
                        c.push_str(&t);
                    }
                } else if let Some(l) = line.as_mut() {
                    l.push_str(&t);
                }
            }
            _ => {}
        }
    }
    joined(out, "OpenDocument contains no extractable text")
}

/// Visible text of an (X)HTML document.
pub fn html_text(html: &str) -> String {
    let mut out = String::new();
    let mut skip = 0;
    for ev in xml_events(html) {
        match ev {
            Ev::Open(n, _, false) if matches!(n.to_ascii_lowercase().as_str(), "script" | "style" | "head") => skip += 1,
            Ev::Close(n) if matches!(n.to_ascii_lowercase().as_str(), "script" | "style" | "head") => skip -= 1,
            Ev::Open(n, _, _) | Ev::Close(n) if matches!(n.to_ascii_lowercase().as_str(), "p" | "div" | "br" | "li" | "tr" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "section" | "blockquote") => out.push('\n'),
            Ev::Text(t) if skip == 0 => out.push_str(&t.split_whitespace().collect::<Vec<_>>().join(" ")),
            _ => {}
        }
    }
    let mut lines: Vec<String> = out.lines().map(|l| l.trim().to_string()).collect();
    lines.dedup_by(|a, b| a.is_empty() && b.is_empty());
    lines.join("\n").trim().to_string()
}

fn epub(data: &[u8]) -> Result<String, String> {
    let z = open_zip(data, "EPUB")?;
    let container = z.read_str("META-INF/container.xml")?;
    let opf_path = xml_events(&container).into_iter().find_map(|e| match e {
        Ev::Open(n, a, _) if n == "rootfile" => attr(&a, "full-path").map(str::to_string),
        _ => None,
    }).ok_or("EPUB container names no rootfile")?;
    let base = opf_path.rsplit_once('/').map(|(b, _)| format!("{b}/")).unwrap_or_default();
    let opf = z.read_str(&opf_path)?;
    let mut manifest: Vec<(String, String)> = Vec::new();
    let mut spine: Vec<String> = Vec::new();
    for e in xml_events(&opf) {
        if let Ev::Open(n, a, _) = e {
            if n == "item" {
                if let (Some(id), Some(h)) = (attr(&a, "id"), attr(&a, "href")) {
                    manifest.push((id.into(), h.into()));
                }
            } else if n == "itemref" {
                spine.extend(attr(&a, "idref").map(str::to_string));
            }
        }
    }
    let mut out = Vec::new();
    for id in spine {
        let Some((_, href)) = manifest.iter().find(|(i, _)| *i == id) else { continue };
        let Ok(h) = z.read_str(&norm_part(href, &base)) else { continue };
        let t = html_text(&h);
        if !t.is_empty() {
            out.push(t);
            out.push(String::new());
        }
    }
    joined(out, "EPUB contains no extractable text")
}

// ───────────────────── RTF ─────────────────────

pub fn rtf(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::new();
    // Group stack: whether text in this group is skipped.
    let mut stack: Vec<bool> = vec![false];
    let mut uc_skip = 1usize;
    let mut pending_skip = 0usize;
    let mut i = 0;
    let skip_dest = ["fonttbl", "colortbl", "stylesheet", "info", "pict", "header", "footer", "headerl", "headerr", "footerl", "footerr", "object", "themedata", "colorschememapping", "latentstyles", "datastore", "xmlnstbl", "listtable", "listoverridetable", "rsidtbl", "generator"];
    let mut uni = String::new();
    let flush_uni = |out: &mut Vec<u8>, uni: &mut String| {
        out.extend_from_slice(uni.as_bytes());
        uni.clear();
    };
    while i < b.len() {
        let skipping = *stack.last().unwrap_or(&false);
        match b[i] {
            b'{' => {
                stack.push(skipping);
                i += 1;
            }
            b'}' => {
                stack.pop();
                if stack.is_empty() {
                    stack.push(false);
                }
                i += 1;
            }
            b'\\' => {
                i += 1;
                if i >= b.len() {
                    break;
                }
                let c = b[i];
                if c == b'\\' || c == b'{' || c == b'}' {
                    if !skipping && pending_skip == 0 {
                        out.push(c);
                    }
                    pending_skip = pending_skip.saturating_sub(1);
                    i += 1;
                } else if c == b'\'' {
                    let h = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok());
                    if let Some(h) = h {
                        if !skipping && pending_skip == 0 {
                            // cp1252 for the common range; Latin-1 otherwise.
                            let ch = match h {
                                0x91 | 0x92 => '\'',
                                0x93 | 0x94 => '"',
                                0x96 => '-',
                                0x97 => '—',
                                _ => h as char,
                            };
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        pending_skip = pending_skip.saturating_sub(1);
                    }
                    i += 3;
                } else if c == b'*' {
                    *stack.last_mut().unwrap() = true;
                    i += 1;
                } else if c.is_ascii_alphabetic() {
                    let ws = i;
                    while i < b.len() && b[i].is_ascii_alphabetic() {
                        i += 1;
                    }
                    let word = &s[ws..i];
                    let ns = i;
                    if i < b.len() && (b[i] == b'-' || b[i].is_ascii_digit()) {
                        i += 1;
                        while i < b.len() && b[i].is_ascii_digit() {
                            i += 1;
                        }
                    }
                    let num: Option<i64> = s[ns..i].parse().ok();
                    if i < b.len() && b[i] == b' ' {
                        i += 1;
                    }
                    if skip_dest.contains(&word) {
                        *stack.last_mut().unwrap() = true;
                        continue;
                    }
                    if skipping {
                        continue;
                    }
                    match word {
                        "par" | "line" | "sect" | "page" | "row" => {
                            flush_uni(&mut out, &mut uni);
                            out.push(b'\n')
                        }
                        "tab" | "cell" => out.push(b'\t'),
                        "uc" => uc_skip = num.unwrap_or(1).max(0) as usize,
                        "u" => {
                            let n = num.unwrap_or(0);
                            let n = if n < 0 { n + 65536 } else { n } as u32;
                            if let Some(ch) = char::from_u32(n) {
                                uni.push(ch);
                                flush_uni(&mut out, &mut uni);
                            }
                            pending_skip = uc_skip;
                        }
                        "emdash" => out.extend_from_slice("—".as_bytes()),
                        "endash" => out.extend_from_slice("–".as_bytes()),
                        "lquote" | "rquote" => out.push(b'\''),
                        "ldblquote" | "rdblquote" => out.push(b'"'),
                        "bullet" => out.extend_from_slice("•".as_bytes()),
                        _ => {}
                    }
                } else {
                    // \~ \- \_ etc.
                    if c == b'~' && !skipping {
                        out.push(b' ');
                    }
                    i += 1;
                }
            }
            b'\r' | b'\n' => i += 1,
            c => {
                if !skipping {
                    if pending_skip > 0 {
                        pending_skip -= 1;
                    } else {
                        out.push(c);
                    }
                }
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ───────────────────── notebooks ─────────────────────

fn src_text(v: &Value) -> String {
    match v {
        Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
        Value::String(s) => s.clone(),
        _ => String::new(),
    }
}

fn clean_stream(t: &str) -> String {
    crate::extract::strip_ansi(&t.replace("\r\n", "\n")).split('\n').map(|l| l.split('\r').rfind(|f| !f.is_empty()).unwrap_or("").to_string()).collect::<Vec<_>>().join("\n")
}

/// Minimal ANSI CSI/OSC stripper for notebook stream output.
pub fn strip_ansi(s: &str) -> String {
    if !s.contains('\x1b') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        match it.peek() {
            Some('[') => {
                it.next();
                for d in it.by_ref() {
                    if ('@'..='~').contains(&d) {
                        break;
                    }
                }
            }
            Some(']') => {
                it.next();
                while let Some(d) = it.next() {
                    if d == '\x07' || (d == '\x1b' && it.peek() == Some(&'\\')) {
                        if d == '\x1b' {
                            it.next();
                        }
                        break;
                    }
                }
            }
            Some(_) => {
                it.next();
            }
            None => {}
        }
    }
    out
}

fn human_size(n: usize) -> String {
    if n >= 1024 {
        format!("{} KB", (n as f64 / 1024.0).round() as usize)
    } else {
        format!("{n} B")
    }
}

fn output_text(o: &Value) -> String {
    let otype = o.get("output_type").and_then(Value::as_str).unwrap_or("");
    match otype {
        "stream" => {
            let b = clean_stream(&src_text(o.get("text").unwrap_or(&Value::Null)));
            if b.trim().is_empty() { String::new() } else { b }
        }
        "error" | "pyerr" => {
            let tb = o.get("traceback").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n")).unwrap_or_default();
            let header = format!("Error: {}: {}", o.get("ename").and_then(Value::as_str).unwrap_or(""), o.get("evalue").and_then(Value::as_str).unwrap_or(""));
            format!("{}\n{}", header.trim_end_matches([':', ' ']), clean_stream(&tb)).trim_end().to_string()
        }
        "execute_result" | "display_data" | "pyout" => {
            let mut data = o.get("data").and_then(Value::as_object).cloned().unwrap_or_default();
            if o.get("data").is_none() {
                if let Some(t) = o.get("text") {
                    data.insert("text/plain".into(), t.clone());
                }
                for (k, m) in [("png", "image/png"), ("jpeg", "image/jpeg"), ("svg", "image/svg+xml"), ("html", "text/html")] {
                    if let Some(v) = o.get(k) {
                        data.insert(m.into(), v.clone());
                    }
                }
            }
            if data.contains_key("application/vnd.jupyter.widget-view+json") {
                return "[interactive widget — omitted]".into();
            }
            for m in ["text/plain", "text/markdown"] {
                if let Some(v) = data.get(m) {
                    let b = clean_stream(&src_text(v));
                    if !b.trim().is_empty() {
                        return b;
                    }
                }
            }
            for (m, v) in &data {
                if m.starts_with("image/") {
                    let clean: String = src_text(v).chars().filter(|c| c.is_ascii_alphanumeric() || "+/=".contains(*c)).collect();
                    let pad = clean.len() - clean.trim_end_matches('=').len();
                    return format!("[{m} output — {}, omitted]", human_size((clean.len() * 3 / 4).saturating_sub(pad.min(2))));
                }
            }
            if let Some(h) = data.get("text/html") {
                return format!("[text/html output — {} chars, omitted]", src_text(h).chars().count());
            }
            let keys: Vec<&str> = data.keys().map(|s| s.as_str()).collect();
            format!("[{} output — omitted]", if keys.is_empty() { "unknown".into() } else { keys.join(", ") })
        }
        _ => String::new(),
    }
}

fn notebook(data: &[u8], name: &str) -> Result<String, String> {
    let text = String::from_utf8_lossy(data);
    let nb: Value = serde_json::from_str(text.trim_start_matches('\u{feff}')).map_err(|e| format!("Not a valid notebook: {e}"))?;
    let Some(obj) = nb.as_object() else { return Err("Notebook root is not an object".into()) };
    let mut cells: Vec<(String, &Value)> = Vec::new();
    if let Some(cs) = obj.get("cells").and_then(Value::as_array) {
        cells.extend(cs.iter().enumerate().map(|(i, c)| (format!(".cells[{i}].outputs"), c)));
    } else if let Some(ws) = obj.get("worksheets").and_then(Value::as_array) {
        for (wi, w) in ws.iter().enumerate() {
            for (ci, c) in w.get("cells").and_then(Value::as_array).into_iter().flatten().enumerate() {
                cells.push((format!(".worksheets[{wi}].cells[{ci}].outputs"), c));
            }
        }
    }
    if cells.is_empty() {
        return Err("Notebook contains no cells".into());
    }
    let mut counts = std::collections::HashMap::new();
    let mut out = Vec::new();
    for (ptr, cell) in cells {
        let typ = cell.get("cell_type").and_then(Value::as_str).unwrap_or("");
        let label = match typ {
            "markdown" => "Markdown",
            "code" => "Code",
            "raw" => "Raw",
            _ => continue,
        };
        let n = counts.entry(typ).or_insert(0);
        *n += 1;
        let suffix = if typ == "raw" { String::new() } else { format!(" {n}") };
        out.push(format!("# ── {label} cell{suffix} ──"));
        out.push(src_text(cell.get("source").unwrap_or(&Value::Null)).trim_end_matches('\n').to_string());
        out.push(String::new());
        if typ == "code" {
            let mut joined_out: String = cell.get("outputs").and_then(Value::as_array).into_iter().flatten().map(output_text).filter(|s| !s.is_empty()).collect::<Vec<_>>().join("\n");
            if joined_out.chars().count() > MAX_OUTPUT_CHARS {
                let omitted = joined_out.chars().count() - MAX_OUTPUT_CHARS;
                joined_out = joined_out.chars().take(MAX_OUTPUT_CHARS).collect::<String>() + &format!("\n… [{omitted} output chars truncated — full output: jq -r '{ptr}' {name}]");
            }
            if !joined_out.is_empty() {
                out.push(format!("# ── Output (cell {n}) ──"));
                out.push(joined_out.trim_end_matches('\n').to_string());
                out.push(String::new());
            }
        }
    }
    joined(out, "Notebook contains no readable cells")
}

// ───────────────────── PDF ─────────────────────

const PDF_EMPTY_PAGE_CHARS: usize = 20;

fn which(bin: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
}

/// Warning header when many pages yielded no text (likely scans), else "".
pub fn pdf_coverage_note(pages: &[String], shown: &str) -> String {
    if pages.len() < 2 {
        return String::new();
    }
    let counts: Vec<usize> = pages.iter().map(|p| p.trim().chars().count()).collect();
    let empty: Vec<usize> = counts.iter().enumerate().filter(|(_, n)| **n < PDF_EMPTY_PAGE_CHARS).map(|(i, _)| i + 1).collect();
    let (total, ne) = (counts.len(), empty.len());
    let enough = ne as f64 / total as f64 >= 0.2 || ne >= 10;
    if ne < 2 || !enough {
        return String::new();
    }
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for &p in &empty {
        match ranges.last_mut() {
            Some(r) if r.1 + 1 == p => r.1 = p,
            _ => ranges.push((p, p)),
        }
    }
    let mut lines = Vec::new();
    for &(a, b) in ranges.iter().take(20) {
        let mut label = String::new();
        for prev in (0..a.saturating_sub(1)).rev() {
            if counts[prev] >= PDF_EMPTY_PAGE_CHARS {
                let snip: String = pages[prev].split_whitespace().collect::<Vec<_>>().join(" ").chars().take(60).collect();
                label = format!(" — after \"{snip}\" (p{})", prev + 1);
                break;
            }
        }
        let n = b - a + 1;
        let span = if a == b { format!("page {a}") } else { format!("pages {a}-{b}") };
        lines.push(format!("  {span} ({n} page{}){label}", if n == 1 { "" } else { "s" }));
    }
    if ranges.len() > 20 {
        let rest = &ranges[20..];
        lines.push(format!("  … {} more gaps ({} pages)", rest.len(), rest.iter().map(|(a, b)| b - a + 1).sum::<usize>()));
    }
    format!(
        "[EXTRACTION COVERAGE WARNING: {ne} of {total} pages in this PDF yielded no text. Those pages are likely scanned images (or blank) — their content is MISSING from the extracted text below, even where section headers appear with empty bodies. Unreadable gaps, each labeled with the last text extracted before it:\n{}\nDecide which gaps you actually need — do NOT OCR or render everything. For the gaps that matter, render just that range with `pdftoppm -jpeg -r 150 -f <first> -l <last> '{shown}' $TMPDIR/page` and inspect the images, or use an OCR skill for bulk OCR of large ranges.]\n",
        lines.join("\n")
    )
}

fn pdf(p: &Path, data: &[u8]) -> Result<String, String> {
    if !data.starts_with(b"%PDF") {
        return Err("not a PDF (missing %PDF header)".into());
    }
    if which("pdftotext") {
        let out = seagent_core::platform::proc::command("pdftotext").arg(p).arg("-").stdin(Stdio::null()).stderr(Stdio::null()).output();
        if let Some(o) = out.ok().filter(|o| o.status.success()) {
            let text = String::from_utf8_lossy(&o.stdout).into_owned();
            let mut pages: Vec<String> = text.split('\x0c').map(str::to_string).collect();
            if pages.last().is_some_and(|l| l.trim().is_empty()) {
                pages.pop();
            }
            if pages.iter().all(|pg| pg.trim().is_empty()) {
                return Ok(needs_ocr(p, pages.len()));
            }
            let note = pdf_coverage_note(&pages, &p.display().to_string());
            return Ok(note + text.trim_end_matches(['\n', '\x0c']) + "\n");
        }
    }
    let pages = pdf_pages_text(data)?;
    if pages.iter().all(|pg| pg.trim().is_empty()) {
        return Ok(needs_ocr(p, pages.len()));
    }
    let note = pdf_coverage_note(&pages, &p.display().to_string());
    Ok(note + pages.join("\n\n").trim_end() + "\n")
}

fn needs_ocr(p: &Path, n: usize) -> String {
    let list = if n == 0 { "unknown".to_string() } else { (1..=n).map(|i| i.to_string()).collect::<Vec<_>>().join(", ") };
    format!("[NEEDS OCR: pages {list} of this PDF are scanned images with no text layer — their content is MISSING below. If the missing pages matter: render just those pages with `pdftoppm -jpeg -r 150 -f <first> -l <last> '{}' $TMPDIR/page` and inspect the images, or check whether an OCR skill is available.]\n", p.display())
}

/// Content streams of a PDF, decoded, one entry per stream that holds text operators.
fn pdf_pages_text(data: &[u8]) -> Result<Vec<String>, String> {
    let mut pages = Vec::new();
    let mut i = 0;
    while let Some(k) = find(data, b"stream", i) {
        // Dictionary before the stream keyword.
        let dict_start = rfind(&data[..k], b"<<").unwrap_or(k.saturating_sub(200));
        let dict = String::from_utf8_lossy(&data[dict_start..k]).into_owned();
        let mut s = k + 6;
        if data.get(s) == Some(&b'\r') {
            s += 1;
        }
        if data.get(s) == Some(&b'\n') {
            s += 1;
        }
        let Some(e) = find(data, b"endstream", s) else { break };
        i = e + 9;
        let raw = &data[s..e];
        let body = if dict.contains("FlateDecode") {
            match zlib_decompress(raw, 64 * 1024 * 1024) {
                Ok(b) => b,
                Err(_) => continue,
            }
        } else if dict.contains("/Filter") {
            continue; // images and other encodings carry no text operators we can read
        } else {
            raw.to_vec()
        };
        if !(contains(&body, b"Tj") || contains(&body, b"TJ")) || !contains(&body, b"BT") {
            continue;
        }
        pages.push(content_text(&body));
    }
    if pages.is_empty() && !contains(data, b"/Encrypt") {
        return Ok(vec![]);
    }
    if contains(data, b"/Encrypt") && pages.iter().all(|p| p.trim().is_empty()) {
        return Err("PDF is encrypted; install pdftotext (poppler-utils) or decrypt it first".into());
    }
    Ok(pages)
}

fn find(h: &[u8], n: &[u8], from: usize) -> Option<usize> {
    (from..h.len().saturating_sub(n.len() - 1)).find(|&i| h[i..].starts_with(n))
}
fn rfind(h: &[u8], n: &[u8]) -> Option<usize> {
    (0..h.len().saturating_sub(n.len() - 1)).rev().find(|&i| h[i..].starts_with(n))
}
fn contains(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}

/// Text shown by a content stream's Tj/TJ/'/" operators; Td/TD/T*/ET start new lines.
pub fn content_text(b: &[u8]) -> String {
    let mut out = String::new();
    let mut operands: Vec<String> = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'(' => {
                let (s, n) = pdf_literal(&b[i..]);
                operands.push(s);
                i += n;
            }
            b'<' if b.get(i + 1) != Some(&b'<') => {
                let e = b[i..].iter().position(|&c| c == b'>').map(|k| i + k).unwrap_or(b.len());
                let hex: String = String::from_utf8_lossy(&b[i + 1..e]).chars().filter(|c| c.is_ascii_hexdigit()).collect();
                let bytes: Vec<u8> = (0..hex.len() / 2).filter_map(|k| u8::from_str_radix(&hex[2 * k..2 * k + 2], 16).ok()).collect();
                // Two-byte (UTF-16BE-ish CID) strings: keep printable low bytes.
                let s = if bytes.len().is_multiple_of(2) && bytes.iter().step_by(2).all(|&x| x == 0) { bytes.iter().skip(1).step_by(2).map(|&c| c as char).collect() } else { bytes.iter().map(|&c| c as char).collect() };
                operands.push(s);
                i = e + 1;
            }
            b'[' => {
                operands.push("[".into());
                i += 1;
            }
            b']' => {
                // Collapse the array into one operand; big negative kerns are spaces.
                let mut parts = Vec::new();
                while let Some(o) = operands.pop() {
                    if o == "[" {
                        break;
                    }
                    parts.push(o);
                }
                parts.reverse();
                let mut s = String::new();
                for p in parts {
                    if let Some(num) = p.strip_prefix('\u{0}') {
                        if num.parse::<f64>().is_ok_and(|v| v < -200.0) {
                            s.push(' ');
                        }
                    } else {
                        s.push_str(&p);
                    }
                }
                operands.push(s);
                i += 1;
            }
            c if c.is_ascii_whitespace() => i += 1,
            b'%' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            _ => {
                let st = i;
                while i < b.len() && !b[i].is_ascii_whitespace() && !b"()<>[]/%".contains(&b[i]) {
                    i += 1;
                }
                if i == st {
                    // '/Name'
                    i += 1;
                    while i < b.len() && !b[i].is_ascii_whitespace() && !b"()<>[]/%".contains(&b[i]) {
                        i += 1;
                    }
                    operands.push("\u{1}name".into());
                    continue;
                }
                let tok = String::from_utf8_lossy(&b[st..i]).into_owned();
                if tok.parse::<f64>().is_ok() {
                    operands.push(format!("\u{0}{tok}"));
                    continue;
                }
                match tok.as_str() {
                    "Tj" | "TJ" => {
                        if let Some(s) = operands.last() {
                            if !s.starts_with('\u{0}') && !s.starts_with('\u{1}') {
                                out.push_str(s);
                            }
                        }
                    }
                    "'" | "\"" => {
                        out.push('\n');
                        if let Some(s) = operands.last() {
                            out.push_str(s);
                        }
                    }
                    "T*" | "ET" => out.push('\n'),
                    "Td" | "TD" => {
                        let ty = operands.last().and_then(|s| s.strip_prefix('\u{0}')).and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);
                        if ty.abs() > 0.01 {
                            out.push('\n');
                        } else {
                            out.push(' ');
                        }
                    }
                    _ => {}
                }
                operands.clear();
            }
        }
    }
    let mut lines: Vec<&str> = out.lines().map(str::trim_end).collect();
    lines.dedup_by(|a, b| a.is_empty() && b.is_empty());
    lines.join("\n").trim().to_string()
}

fn pdf_literal(b: &[u8]) -> (String, usize) {
    let mut out = Vec::new();
    let mut depth = 0;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match c {
            b'(' => {
                if depth > 0 {
                    out.push(c);
                }
                depth += 1;
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    i += 1;
                    break;
                }
                out.push(c);
            }
            b'\\' => {
                i += 1;
                match b.get(i) {
                    Some(b'n') => out.push(b'\n'),
                    Some(b'r') => out.push(b'\r'),
                    Some(b't') => out.push(b'\t'),
                    Some(b'b') | Some(b'f') => {}
                    Some(d @ b'0'..=b'7') => {
                        let mut v = (*d - b'0') as u32;
                        for _ in 0..2 {
                            if let Some(n @ b'0'..=b'7') = b.get(i + 1) {
                                v = v * 8 + (*n - b'0') as u32;
                                i += 1;
                            }
                        }
                        out.push(v as u8);
                    }
                    Some(b'\r') | Some(b'\n') => {}
                    Some(&x) => out.push(x),
                    None => {}
                }
            }
            _ => out.push(c),
        }
        i += 1;
    }
    (out.iter().map(|&c| c as char).collect(), i)
}

// ───────────────────── SQLite / legacy Office ─────────────────────

const SQLITE_PY: &str = r###"
import sqlite3, sys, pathlib
p = sys.argv[1]
con = sqlite3.connect(pathlib.Path(p).resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
objs = con.execute("SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type DESC, name").fetchall()
tables = [o for o in objs if o[0] == "table"]
others = [o for o in objs if o[0] != "table"]
out = ["# SQLite database", "", f"{len(tables)} table(s), {len(others)} index/view/trigger(s)"]
def cell(v):
    if v is None: return "NULL"
    if isinstance(v, (bytes, bytearray)): return f"<blob {len(v)} bytes>"
    t = str(v).replace("|", "\\|").replace("\n", " ")
    return t if len(t) <= 80 else t[:79] + "…"
for _, name, sql in tables[:200]:
    q = '"' + name.replace('"', '""') + '"'
    n = con.execute(f"SELECT COUNT(*) FROM {q}").fetchone()[0]
    out += ["", f"## {name}  ({n:,} rows)", sql.strip()]
    cur = con.execute(f"SELECT * FROM {q} LIMIT 5")
    cols = [d[0] for d in cur.description]
    rows = cur.fetchall()
    if rows:
        out.append("| " + " | ".join(cols) + " |")
        out.append("|" + "---|" * len(cols))
        out += ["| " + " | ".join(cell(v) for v in r) + " |" for r in rows]
if len(tables) > 200: out.append(f"\n... {len(tables) - 200} more tables omitted")
if others: out += ["", "## Indexes / views / triggers"] + [f"- {t} {n}" for t, n, _ in others]
out += ["", "Query it with the shell tool: sqlite3 <path> 'SELECT ...'  (or Python's sqlite3 module)."]
print("\n".join(out))
"###;

fn sqlite(p: &Path, data: &[u8]) -> Result<String, String> {
    if !data.starts_with(b"SQLite format 3\0") {
        return Err("not a SQLite database (magic bytes do not match)".into());
    }
    let o = seagent_core::platform::proc::command("python3").arg("-I").arg("-c").arg(SQLITE_PY).arg(p).stdin(Stdio::null()).output().map_err(|e| format!("SQLite read needs python3: {e}"))?;
    if !o.status.success() {
        return Err(format!("SQLite read failed: {}", String::from_utf8_lossy(&o.stderr).lines().last().unwrap_or("")));
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

fn legacy_office(p: &Path) -> Result<String, String> {
    let ext = ext_of(p);
    let tools: &[(&str, &[&str])] = match ext.as_str() {
        "doc" => &[("antiword", &[]), ("catdoc", &[])],
        "xls" => &[("xls2csv", &[])],
        _ => &[("catppt", &[])],
    };
    for (bin, args) in tools {
        if which(bin) {
            if let Ok(o) = seagent_core::platform::proc::command(bin).args(*args).arg(p).stdin(Stdio::null()).output() {
                if o.status.success() && !o.stdout.is_empty() {
                    return Ok(String::from_utf8_lossy(&o.stdout).into_owned());
                }
            }
        }
    }
    Err(format!("Cannot convert {:?}: legacy binary .{ext} needs a converter (antiword/catdoc/xls2csv/catppt) that is not installed; convert the file with the shell tool (e.g. libreoffice --headless --convert-to txt).", p.display().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zip::write_stored;

    #[test]
    fn docx_paragraphs_breaks_and_ruby() {
        let doc = r#"<?xml version="1.0"?><w:document xmlns:w="x"><w:body><w:p><w:r><w:t>Hello</w:t></w:r><w:r><w:tab/><w:t xml:space="preserve">world &amp; co</w:t></w:r></w:p><w:p><w:r><w:ruby><w:rt><w:t>ふりがな</w:t></w:rt><w:rubyBase><w:t>漢字</w:t></w:rubyBase></w:ruby><w:br/><w:t>next</w:t></w:r></w:p></w:body></w:document>"#;
        let z = write_stored(&[("word/document.xml", doc.as_bytes())]);
        assert_eq!(extract(Path::new("a.docx"), &z).unwrap(), "Hello\tworld & co\n漢字\nnext\n");
        assert!(extract(Path::new("a.docx"), b"junk").unwrap_err().contains("Not a valid DOCX"));
    }

    #[test]
    fn xlsx_shared_strings_types_and_hidden_sheets() {
        let wb = r#"<workbook xmlns:r="r"><sheets><sheet name="Data" sheetId="1" r:id="rId1"/><sheet name="Secret" state="hidden" r:id="rId2"/></sheets></workbook>"#;
        let rels = r#"<Relationships><Relationship Id="rId1" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Target="worksheets/sheet2.xml"/></Relationships>"#;
        let sst = r#"<sst><si><t>name</t></si><si><r><t>Al</t></r><r><t>ice</t></r><rPh><t>phon</t></rPh></si></sst>"#;
        let s1 = r#"<worksheet><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c><c r="C1"><v>42</v></c></row><row r="2"><c r="A2" t="s"><v>1</v></c><c r="B2" t="b"><v>1</v></c><c r="C2" t="inlineStr"><is><t>inline</t></is></c></row><row r="3"/></sheetData></worksheet>"#;
        let z = write_stored(&[("xl/workbook.xml", wb.as_bytes()), ("xl/_rels/workbook.xml.rels", rels.as_bytes()), ("xl/sharedStrings.xml", sst.as_bytes()), ("xl/worksheets/sheet1.xml", s1.as_bytes()), ("xl/worksheets/sheet2.xml", s1.as_bytes())]);
        assert_eq!(extract(Path::new("b.xlsx"), &z).unwrap(), "# ── Sheet: Data ──\nname\t\t42\nAlice\tTRUE\tinline\n");
        assert_eq!(col_index("AB7"), 27);
    }

    #[test]
    fn pptx_odf_epub() {
        let pres = r#"<p:presentation xmlns:r="r"><p:sldIdLst><p:sldId id="1" r:id="rId2"/><p:sldId id="2" r:id="rId1"/></p:sldIdLst></p:presentation>"#;
        let rels = r#"<Relationships><Relationship Id="rId1" Target="slides/slide1.xml"/><Relationship Id="rId2" Target="slides/slide2.xml"/></Relationships>"#;
        let z = write_stored(&[("ppt/presentation.xml", pres.as_bytes()), ("ppt/_rels/presentation.xml.rels", rels.as_bytes()), ("ppt/slides/slide1.xml", b"<p:sld><a:p><a:r><a:t>Second</a:t></a:r></a:p></p:sld>"), ("ppt/slides/slide2.xml", b"<p:sld><a:p><a:r><a:t>First</a:t></a:r></a:p></p:sld>")]);
        assert_eq!(extract(Path::new("c.pptx"), &z).unwrap(), "# ── Slide 1 ──\nFirst\n\n# ── Slide 2 ──\nSecond\n");
        let content = r#"<office:document-content><office:body><office:text><text:h>Title</text:h><text:p>a<text:s text:c="2"/>b<text:tab/>c</text:p></office:text><table:table><table:table-row><table:table-cell><text:p>x</text:p></table:table-cell><table:table-cell><text:p>y</text:p></table:table-cell></table:table-row></table:table></office:body></office:document-content>"#;
        let z = write_stored(&[("content.xml", content.as_bytes())]);
        assert_eq!(extract(Path::new("d.odt"), &z).unwrap(), "Title\na  b\tc\nx\ty\n");
        let container = r#"<container><rootfiles><rootfile full-path="OEBPS/c.opf"/></rootfiles></container>"#;
        let opf = r#"<package><manifest><item id="a" href="ch1.xhtml"/><item id="b" href="ch2.xhtml"/></manifest><spine><itemref idref="b"/><itemref idref="a"/></spine></package>"#;
        let z = write_stored(&[("META-INF/container.xml", container.as_bytes()), ("OEBPS/c.opf", opf.as_bytes()), ("OEBPS/ch1.xhtml", b"<html><head><title>t</title></head><body><p>One</p></body></html>"), ("OEBPS/ch2.xhtml", b"<html><body><h1>Two</h1><script>x()</script><p>words  here</p></body></html>")]);
        assert_eq!(extract(Path::new("e.epub"), &z).unwrap(), "Two\n\nwords here\n\nOne\n");
    }

    #[test]
    fn rtf_text() {
        let r = r"{\rtf1\ansi{\fonttbl{\f0 Times;}}{\*\generator x;}\f0 Hello \b bold\b0\par caf\'e9 \u8364?, \{braces\}\tab end}";
        assert_eq!(rtf(r), "Hello bold\ncafé €, {braces}\tend");
    }

    #[test]
    fn notebook_cells_and_outputs() {
        let nb = serde_json::json!({"cells": [
            {"cell_type": "markdown", "source": ["# Title\n"]},
            {"cell_type": "code", "source": "print(1)", "outputs": [
                {"output_type": "stream", "text": ["\x1b[31mred\x1b[0m\n", "10%\r100%\n"]},
                {"output_type": "execute_result", "data": {"image/png": "iVBORw0KGgo=", "text/plain": ""}},
                {"output_type": "error", "ename": "ValueError", "evalue": "bad", "traceback": ["tb line"]}]}]});
        let t = extract(Path::new("n.ipynb"), nb.to_string().as_bytes()).unwrap();
        assert!(t.starts_with("# ── Markdown cell 1 ──\n# Title\n\n# ── Code cell 1 ──\nprint(1)\n\n# ── Output (cell 1) ──\nred\n100%"), "{t}");
        assert!(t.contains("[image/png output — 8 B, omitted]") && t.contains("Error: ValueError: bad\ntb line"), "{t}");
        assert!(extract(Path::new("n.ipynb"), b"{}").unwrap_err().contains("no cells"));
        assert!(extract(Path::new("n.ipynb"), b"[").unwrap_err().contains("Not a valid notebook"));
    }

    #[test]
    fn pdf_content_streams_and_coverage() {
        // Hand-built PDF: one FlateDecode content stream ("BT (Hello PDF) Tj ET") + one plain.
        let z = crate::zip::unhex("789c730a51d0f048cdc9c957087071d35408c952700d01003ae0058d");
        let mut pdf = b"%PDF-1.4\n1 0 obj\n<< /Length 28 /Filter /FlateDecode >>\nstream\n".to_vec();
        pdf.extend_from_slice(&z);
        pdf.extend_from_slice(b"\nendstream\nendobj\n2 0 obj\n<< /Length 60 >>\nstream\nBT /F1 12 Tf 72 700 Td [(Sec) -50 (ond) -400 (page)] TJ 0 -14 Td (line\\051 two) Tj ET\nendstream\nendobj\n%%EOF");
        let pages = pdf_pages_text(&pdf).unwrap();
        assert_eq!(pages, vec!["Hello PDF".to_string(), "Second page\nline) two".to_string()]);
        let pages: Vec<String> = vec!["intro text that is long enough".into(), "".into(), " ".into(), "more real text here please ok".into()];
        let n = pdf_coverage_note(&pages, "x.pdf");
        assert!(n.contains("2 of 4 pages") && n.contains("pages 2-3 (2 pages) — after \"intro text"), "{n}");
        assert!(pdf_coverage_note(&pages[..1], "x").is_empty());
        assert!(extract(Path::new("x.pdf"), b"nope").is_err());
    }

    #[test]
    fn sqlite_and_legacy() {
        assert!(extract(Path::new("x.db"), b"not sqlite").unwrap_err().contains("magic"));
        let d = crate::testutil::tmpdir("sqlite");
        let db = d.join("t.db");
        let ok = seagent_core::platform::proc::command("python3").arg("-c").arg("import sqlite3,sys;c=sqlite3.connect(sys.argv[1]);c.execute('create table t(a,b)');c.execute(\"insert into t values(1,'x')\");c.commit()").arg(&db).status().map(|s| s.success()).unwrap_or(false);
        if ok {
            let t = extract(&db, &std::fs::read(&db).unwrap()).unwrap();
            assert!(t.contains("## t  (1 rows)") && t.contains("| 1 | x |"), "{t}");
        }
        let doc = d.join("old.doc");
        std::fs::write(&doc, b"\xd0\xcf\x11\xe0").unwrap();
        let r = extract(&doc, b"\xd0\xcf\x11\xe0");
        assert!(r.is_ok() || r.unwrap_err().contains("legacy binary .doc"));
    }
}
