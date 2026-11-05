//! Minimal PDF text extraction for fetched PDF URLs (web_extract / web_fetch "PDF via fetch"):
//! object table, FlateDecode streams, content-stream text operators (Tj TJ ' " Td TD T* Tm),
//! literal / hex strings and ToUnicode CMaps (bfchar / bfrange) per font resource name.
//! Encrypted PDFs and image-only scans yield an error rather than garbage.

#[path = "../../../ark-channel/src/zlib.rs"]
#[allow(dead_code)]
mod zlib;

use std::collections::HashMap;

const MAX_INFLATED: usize = 64 * 1024 * 1024;

pub fn is_pdf(bytes: &[u8]) -> bool {
    bytes.len() > 4 && bytes[..1024.min(bytes.len())].windows(5).any(|w| w == b"%PDF-")
}

fn inflate(data: &[u8]) -> Option<Vec<u8>> {
    let mut z = zlib::ZlibStream::default();
    z.limit = MAX_INFLATED;
    let mut input = data.to_vec();
    input.extend_from_slice(&[0, 0, 0xff, 0xff]);
    z.push(&input).ok().flatten()
}

struct Obj {
    dict: String,
    stream: Option<Vec<u8>>,
}

fn find(h: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= h.len() {
        return None;
    }
    h[from..].windows(needle.len()).position(|w| w == needle).map(|p| p + from)
}

/// `N G obj … endobj` table (later definitions win, as incremental updates do).
fn objects(b: &[u8]) -> HashMap<u32, Obj> {
    let mut out = HashMap::new();
    let mut i = 0;
    while let Some(p) = find(b, b" obj", i) {
        // Walk back over "N G".
        let mut s = p;
        let mut fields = 0;
        let mut j = p;
        while j > 0 && fields < 2 {
            while j > 0 && b[j - 1] == b' ' {
                j -= 1;
            }
            let end = j;
            while j > 0 && b[j - 1].is_ascii_digit() {
                j -= 1;
            }
            if j == end {
                break;
            }
            fields += 1;
            s = j;
        }
        i = p + 4;
        if fields < 2 {
            continue;
        }
        let num: u32 = std::str::from_utf8(&b[s..p]).ok().and_then(|t| t.split_whitespace().next()).and_then(|n| n.parse().ok()).unwrap_or(u32::MAX);
        let end = find(b, b"endobj", i).unwrap_or(b.len());
        let body = &b[i..end];
        let (dict, stream) = match find(body, b"stream", 0) {
            Some(sp) => {
                let mut ds = sp + 6;
                if body.get(ds) == Some(&b'\r') {
                    ds += 1;
                }
                if body.get(ds) == Some(&b'\n') {
                    ds += 1;
                }
                let dict = String::from_utf8_lossy(&body[..sp]).into_owned();
                let len = length_of(&dict);
                let de = match len {
                    Some(l) if ds + l <= body.len() => ds + l,
                    _ => find(body, b"endstream", ds).unwrap_or(body.len()),
                };
                (dict, Some(body[ds..de].to_vec()))
            }
            None => (String::from_utf8_lossy(body).into_owned(), None),
        };
        out.insert(num, Obj { dict, stream });
        i = end;
    }
    out
}

fn length_of(dict: &str) -> Option<usize> {
    let i = dict.find("/Length")? + 7;
    let rest = dict[i..].trim_start();
    let n: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    // `/Length 12 0 R` is indirect: fall back to scanning for endstream.
    if rest[n.len()..].trim_start().starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    n.parse().ok()
}

fn decoded(o: &Obj) -> Option<Vec<u8>> {
    let s = o.stream.as_ref()?;
    if o.dict.contains("/FlateDecode") || o.dict.contains("/Fl ") || o.dict.contains("/Fl]") {
        inflate(s)
    } else if o.dict.contains("/Filter") {
        None
    } else {
        Some(s.clone())
    }
}

/// Parse a ToUnicode CMap into code → text.
fn parse_cmap(data: &str) -> HashMap<u32, String> {
    let mut m = HashMap::new();
    let hex = |s: &str| u32::from_str_radix(s.trim_matches(|c| c == '<' || c == '>'), 16).ok();
    let utf16 = |s: &str| -> String {
        let h = s.trim_matches(|c| c == '<' || c == '>');
        let units: Vec<u16> = (0..h.len() / 4).filter_map(|i| u16::from_str_radix(&h[i * 4..i * 4 + 4], 16).ok()).collect();
        String::from_utf16_lossy(&units)
    };
    for sec in data.split("beginbfchar").skip(1) {
        let body = sec.split("endbfchar").next().unwrap_or("");
        let toks: Vec<&str> = body.split_whitespace().collect();
        for p in toks.chunks(2) {
            if let [a, b] = p {
                if let Some(k) = hex(a) {
                    m.insert(k, utf16(b));
                }
            }
        }
    }
    for sec in data.split("beginbfrange").skip(1) {
        let body = sec.split("endbfrange").next().unwrap_or("");
        let toks: Vec<&str> = body.split_whitespace().collect();
        let mut i = 0;
        while i + 2 < toks.len() {
            let (lo, hi) = (hex(toks[i]), hex(toks[i + 1]));
            if toks[i + 2].starts_with('[') {
                let mut j = i + 2;
                let mut k = lo.unwrap_or(0);
                loop {
                    let t = toks[j].trim_start_matches('[');
                    let done = t.ends_with(']');
                    let t = t.trim_end_matches(']');
                    if !t.is_empty() {
                        m.insert(k, utf16(t));
                        k += 1;
                    }
                    j += 1;
                    if done || j >= toks.len() {
                        break;
                    }
                }
                i = j;
            } else {
                if let (Some(lo), Some(hi)) = (lo, hi) {
                    let base = utf16(toks[i + 2]);
                    let mut chars: Vec<u16> = base.encode_utf16().collect();
                    for c in lo..=hi.min(lo + 0xffff) {
                        m.insert(c, String::from_utf16_lossy(&chars));
                        if let Some(l) = chars.last_mut() {
                            *l = l.wrapping_add(1);
                        }
                    }
                }
                i += 3;
            }
        }
    }
    m
}

/// Resource font name → ToUnicode map, gathered from every font dict in the file.
fn font_maps(objs: &HashMap<u32, Obj>) -> HashMap<String, (HashMap<u32, String>, usize)> {
    let refnum = |s: &str, key: &str| -> Option<u32> { s.find(key).and_then(|i| s[i + key.len()..].split_whitespace().next()).and_then(|n| n.parse().ok()) };
    let mut out = HashMap::new();
    for o in objs.values() {
        let Some(fi) = o.dict.find("/Font") else { continue };
        let rest = &o.dict[fi + 5..];
        let rest = rest.trim_start();
        let Some(inner) = rest.strip_prefix("<<") else { continue };
        let inner = &inner[..inner.find(">>").unwrap_or(inner.len())];
        let toks: Vec<&str> = inner.split_whitespace().collect();
        let mut i = 0;
        while i + 3 < toks.len() + 1 && i < toks.len() {
            if let Some(name) = toks[i].strip_prefix('/') {
                if let Some(num) = toks.get(i + 1).and_then(|n| n.parse::<u32>().ok()) {
                    if let Some(font) = objs.get(&num) {
                        if let Some(cm) = refnum(&font.dict, "/ToUnicode").and_then(|n| objs.get(&n)).and_then(decoded) {
                            let text = String::from_utf8_lossy(&cm).into_owned();
                            let width = if text.contains("<0000> <FFFF>") || text.contains("begincodespacerange\n<0000>") || font.dict.contains("Identity-H") { 2 } else { 1 };
                            out.insert(name.to_string(), (parse_cmap(&text), width));
                        }
                    }
                    i += 3;
                    continue;
                }
            }
            i += 1;
        }
    }
    out
}

fn literal(b: &[u8], i: &mut usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut depth = 1;
    *i += 1;
    while *i < b.len() {
        let c = b[*i];
        match c {
            b'\\' => {
                *i += 1;
                let e = *b.get(*i).unwrap_or(&b'\\');
                match e {
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'b' | b'f' => {}
                    b'0'..=b'7' => {
                        let mut v = 0u32;
                        let mut k = 0;
                        while k < 3 && *i < b.len() && (b'0'..=b'7').contains(&b[*i]) {
                            v = v * 8 + (b[*i] - b'0') as u32;
                            *i += 1;
                            k += 1;
                        }
                        *i -= 1;
                        out.push(v as u8);
                    }
                    b'\r' | b'\n' => {}
                    other => out.push(other),
                }
            }
            b'(' => {
                depth += 1;
                out.push(c);
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    *i += 1;
                    return out;
                }
                out.push(c);
            }
            _ => out.push(c),
        }
        *i += 1;
    }
    out
}

fn decode_str(bytes: &[u8], font: Option<&(HashMap<u32, String>, usize)>) -> String {
    match font {
        Some((map, w)) if !map.is_empty() => {
            let mut s = String::new();
            for ch in bytes.chunks(*w) {
                let code = ch.iter().fold(0u32, |a, b| (a << 8) | *b as u32);
                s.push_str(map.get(&code).map(|x| x.as_str()).unwrap_or(""));
            }
            s
        }
        _ => {
            if bytes.starts_with(&[0xfe, 0xff]) {
                let u: Vec<u16> = bytes[2..].chunks(2).map(|c| ((c[0] as u16) << 8) | *c.get(1).unwrap_or(&0) as u16).collect();
                return String::from_utf16_lossy(&u);
            }
            bytes.iter().map(|&b| b as char).collect()
        }
    }
}

/// Text of one content stream.
fn content_text(b: &[u8], fonts: &HashMap<String, (HashMap<u32, String>, usize)>) -> String {
    let mut out = String::new();
    let mut operands: Vec<Vec<u8>> = Vec::new();
    let mut font: Option<String> = None;
    let mut last_name = String::new();
    let mut i = 0;
    let push_text = |out: &mut String, s: &str| out.push_str(s);
    while i < b.len() {
        let c = b[i];
        match c {
            b'(' => operands.push(literal(b, &mut i)),
            b'<' if b.get(i + 1) != Some(&b'<') => {
                let end = b[i..].iter().position(|&x| x == b'>').map(|p| p + i).unwrap_or(b.len());
                let h: Vec<u8> = b[i + 1..end].iter().copied().filter(|x| x.is_ascii_hexdigit()).collect();
                let mut bytes = Vec::new();
                for k in (0..h.len()).step_by(2) {
                    let pair = [h[k], *h.get(k + 1).unwrap_or(&b'0')];
                    bytes.push(u8::from_str_radix(std::str::from_utf8(&pair).unwrap_or("00"), 16).unwrap_or(0));
                }
                operands.push(bytes);
                i = end + 1;
            }
            b'[' | b']' => i += 1,
            b'/' => {
                let s = i + 1;
                i += 1;
                while i < b.len() && !b[i].is_ascii_whitespace() && !b"/[]()<>".contains(&b[i]) {
                    i += 1;
                }
                last_name = String::from_utf8_lossy(&b[s..i]).into_owned();
            }
            b'%' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            c if c.is_ascii_alphabetic() || c == b'\'' || c == b'"' || c == b'*' => {
                let s = i;
                while i < b.len() && (b[i].is_ascii_alphabetic() || b[i] == b'*' || b[i] == b'\'' || b[i] == b'"') {
                    i += 1;
                }
                let op = &b[s..i];
                let f = font.as_ref().and_then(|n| fonts.get(n));
                match op {
                    b"Tf" => font = Some(last_name.clone()),
                    b"Tj" | b"TJ" => {
                        for o in operands.drain(..) {
                            push_text(&mut out, &decode_str(&o, f));
                        }
                    }
                    b"'" | b"\"" => {
                        out.push('\n');
                        for o in operands.drain(..) {
                            push_text(&mut out, &decode_str(&o, f));
                        }
                    }
                    b"Td" | b"TD" | b"T*" | b"Tm" | b"ET" if !out.ends_with('\n') && !out.is_empty() => {
                        out.push('\n');
                    }
                    _ => {}
                }
                operands.clear();
            }
            _ => i += 1,
        }
    }
    out
}

/// Extract the text of a PDF. Errors name the reason (encrypted, no text layer).
pub fn extract_text(bytes: &[u8]) -> Result<String, String> {
    if !is_pdf(bytes) {
        return Err("not a PDF".into());
    }
    let objs = objects(bytes);
    if objs.values().any(|o| o.dict.contains("/Encrypt")) || bytes.windows(8).any(|w| w == b"/Encrypt") {
        return Err("PDF is encrypted; text extraction is not supported".into());
    }
    let fonts = font_maps(&objs);
    // Page content streams: referenced by /Contents; fall back to every text-bearing stream.
    let mut nums: Vec<u32> = objs.keys().copied().collect();
    nums.sort_unstable();
    let mut text = String::new();
    for n in nums {
        let o = &objs[&n];
        if o.dict.contains("/Type /XObject") || o.dict.contains("/Type/XObject") || o.dict.contains("/Subtype /Image") || o.dict.contains("/FontFile") || o.dict.contains("/Length1") {
            continue;
        }
        let Some(data) = decoded(o) else { continue };
        if find(&data, b"BT", 0).is_none() || find(&data, b"begincmap", 0).is_some() {
            continue;
        }
        let t = content_text(&data, &fonts);
        if !t.trim().is_empty() {
            text.push_str(t.trim_end());
            text.push_str("\n\n");
        }
    }
    let cleaned: String = text.chars().filter(|c| !c.is_control() || *c == '\n' || *c == '\t').collect();
    let out = super::markdown::normalize_whitespace(&cleaned);
    if out.is_empty() {
        return Err("PDF has no extractable text layer (scanned image?)".into());
    }
    Ok(out)
}

/// `/Title (…)` from the document info dictionary.
pub fn title(bytes: &[u8]) -> Option<String> {
    let i = find(bytes, b"/Title", 0)? + 6;
    let rest = &bytes[i..(i + 600).min(bytes.len())];
    let s = rest.iter().position(|&c| c == b'(')?;
    let mut k = s;
    let raw = literal(rest, &mut k);
    let t = decode_str(&raw, None).trim().to_string();
    (!t.is_empty()).then_some(t)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A tiny PDF with one uncompressed page, for tests elsewhere too.
    pub fn sample_pdf(text: &str) -> Vec<u8> {
        let content = format!("BT /F1 12 Tf 72 720 Td ({}) Tj 0 -14 Td [(Second) -200 ( line)] TJ ET", text.replace('(', "\\(").replace(')', "\\)"));
        format!(
            "%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n3 0 obj << /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n5 0 obj << /Length {} >>\nstream\n{content}\nendstream\nendobj\n6 0 obj << /Title (Sample \\(doc\\)) >> endobj\ntrailer << /Root 1 0 R /Info 6 0 R >>\n%%EOF",
            content.len()
        )
        .into_bytes()
    }

    /// zlib-wrap `data` in stored (uncompressed) deflate blocks.
    fn zlib_stored(data: &[u8]) -> Vec<u8> {
        let mut o = vec![0x78, 0x01];
        o.push(1);
        let l = data.len() as u16;
        o.extend_from_slice(&l.to_le_bytes());
        o.extend_from_slice(&(!l).to_le_bytes());
        o.extend_from_slice(data);
        o.extend_from_slice(&[0, 0, 0, 0]);
        o
    }

    #[test]
    fn plain_page_text_and_title() {
        let pdf = sample_pdf("Hello (PDF) world");
        assert!(is_pdf(&pdf));
        assert_eq!(extract_text(&pdf).unwrap(), "Hello (PDF) world\nSecond line");
        assert_eq!(title(&pdf).as_deref(), Some("Sample (doc)"));
        assert!(extract_text(b"<html>").is_err());
    }

    #[test]
    fn flate_stream_with_tounicode_cmap() {
        let cmap = "/CIDInit /ProcSet findresource begin begincmap\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n2 beginbfchar\n<0001> <4E2D>\n<0002> <6587>\nendbfchar\n1 beginbfrange\n<0010> <0012> <0041>\nendbfrange\nendcmap";
        let content = "BT /F2 10 Tf <00010002> Tj T* <001000110012> Tj ET";
        let z = zlib_stored(content.as_bytes());
        let mut pdf = format!("%PDF-1.7\n3 0 obj << /Type /Page /Resources << /Font << /F2 7 0 R >> >> /Contents 5 0 R >> endobj\n7 0 obj << /Type /Font /Subtype /Type0 /Encoding /Identity-H /ToUnicode 8 0 R >> endobj\n8 0 obj << /Length {} >>\nstream\n{cmap}\nendstream\nendobj\n5 0 obj << /Length {} /Filter /FlateDecode >>\nstream\n", cmap.len(), z.len()).into_bytes();
        pdf.extend_from_slice(&z);
        pdf.extend_from_slice(b"\nendstream\nendobj\n%%EOF");
        assert_eq!(extract_text(&pdf).unwrap(), "中文\nABC");
    }

    #[test]
    fn refusals() {
        let enc = b"%PDF-1.4\n1 0 obj << /Filter /Standard >> endobj\ntrailer << /Encrypt 1 0 R >>".to_vec();
        assert!(extract_text(&enc).unwrap_err().contains("encrypted"));
        assert!(extract_text(b"%PDF-1.4\n1 0 obj << >> endobj").unwrap_err().contains("no extractable text"));
    }
}
