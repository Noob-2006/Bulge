//! PDF text extraction (OpenClaw `extensions/document-extract` + `src/media/pdf-extract.ts`).
//!
//! A native reader handles ordinary PDFs: objects (also inside object streams), FlateDecode /
//! ASCIIHex / ASCII85 streams, the page tree with inherited resources, content-stream text
//! operators (Tj, TJ, ', ", Td, TD, T*, Tm, form XObjects) and font decoding through ToUnicode
//! CMaps, WinAnsi and `/Differences`. Encrypted PDFs (and PDFs the native reader cannot read)
//! fall back to poppler's `pdftotext` when installed (`-upw` for passwords). Pages whose text
//! layer is shorter than `min_text_chars` are rendered to PNG with `pdftoppm` for vision
//! models, sharing a pixel budget (OpenClaw `pageRenderOptions`).

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

/// OpenClaw `MAX_EXTRACTED_TEXT_CHARS` / `MAX_RENDER_DIMENSION`.
pub const MAX_TEXT_CHARS: usize = 200_000;
pub const MAX_RENDER_DIMENSION: u64 = 10_000;

#[derive(Debug, Clone, PartialEq)]
enum Obj {
    Null,
    Bool(bool),
    Num(f64),
    Str(Vec<u8>),
    Name(String),
    Arr(Vec<Obj>),
    Dict(BTreeMap<String, Obj>),
    Ref(u32),
    Stream(BTreeMap<String, Obj>, Vec<u8>),
    Op(String),
}

impl Obj {
    fn dict(&self) -> Option<&BTreeMap<String, Obj>> {
        match self {
            Obj::Dict(d) | Obj::Stream(d, _) => Some(d),
            _ => None,
        }
    }
    fn num(&self) -> Option<f64> {
        if let Obj::Num(n) = self {
            Some(*n)
        } else {
            None
        }
    }
    fn name(&self) -> Option<&str> {
        if let Obj::Name(n) = self {
            Some(n)
        } else {
            None
        }
    }
}

fn is_ws(c: u8) -> bool {
    matches!(c, 0 | 9 | 10 | 12 | 13 | 32)
}
fn is_delim(c: u8) -> bool {
    matches!(c, b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%')
}

struct Lexer<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Lexer<'a> {
    fn new(b: &'a [u8], i: usize) -> Self {
        Lexer { b, i }
    }
    fn skip_ws(&mut self) {
        while self.i < self.b.len() {
            let c = self.b[self.i];
            if is_ws(c) {
                self.i += 1;
            } else if c == b'%' {
                while self.i < self.b.len() && self.b[self.i] != b'\n' && self.b[self.i] != b'\r' {
                    self.i += 1;
                }
            } else {
                break;
            }
        }
    }
    fn word(&mut self) -> &'a [u8] {
        let s = self.i;
        while self.i < self.b.len() && !is_ws(self.b[self.i]) && !is_delim(self.b[self.i]) {
            self.i += 1;
        }
        &self.b[s..self.i]
    }
    fn literal(&mut self) -> Vec<u8> {
        // after '('
        let mut out = Vec::new();
        let mut depth = 1;
        while self.i < self.b.len() {
            let c = self.b[self.i];
            self.i += 1;
            match c {
                b'\\' if self.i < self.b.len() => {
                    let e = self.b[self.i];
                    self.i += 1;
                    match e {
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'\r' => {
                            if self.b.get(self.i) == Some(&b'\n') {
                                self.i += 1;
                            }
                        }
                        b'\n' => {}
                        b'0'..=b'7' => {
                            let mut v = (e - b'0') as u32;
                            for _ in 0..2 {
                                match self.b.get(self.i) {
                                    Some(d @ b'0'..=b'7') => {
                                        v = v * 8 + (d - b'0') as u32;
                                        self.i += 1;
                                    }
                                    _ => break,
                                }
                            }
                            out.push(v as u8);
                        }
                        o => out.push(o),
                    }
                }
                b'(' => {
                    depth += 1;
                    out.push(c);
                }
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    out.push(c);
                }
                _ => out.push(c),
            }
        }
        out
    }
    fn hex(&mut self) -> Vec<u8> {
        // after '<'
        let mut digits = Vec::new();
        while self.i < self.b.len() && self.b[self.i] != b'>' {
            let c = self.b[self.i];
            if c.is_ascii_hexdigit() {
                digits.push(c);
            }
            self.i += 1;
        }
        self.i += 1;
        if digits.len() % 2 == 1 {
            digits.push(b'0');
        }
        digits.chunks(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap_or("00"), 16).unwrap_or(0)).collect()
    }
    fn name(&mut self) -> String {
        // after '/'
        let w = self.word();
        let mut out = Vec::new();
        let mut i = 0;
        while i < w.len() {
            if w[i] == b'#' && i + 2 < w.len() {
                if let Ok(v) = u8::from_str_radix(std::str::from_utf8(&w[i + 1..i + 3]).unwrap_or("zz"), 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
            out.push(w[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Next object; `ops` = keep bare words as operators (content streams).
    fn obj(&mut self, ops: bool, depth: usize) -> Option<Obj> {
        if depth > 64 {
            return None;
        }
        self.skip_ws();
        let c = *self.b.get(self.i)?;
        match c {
            b'(' => {
                self.i += 1;
                Some(Obj::Str(self.literal()))
            }
            b'<' if self.b.get(self.i + 1) == Some(&b'<') => {
                self.i += 2;
                let mut d = BTreeMap::new();
                loop {
                    self.skip_ws();
                    match self.b.get(self.i) {
                        None => break,
                        Some(b'>') => {
                            self.i += 2;
                            break;
                        }
                        Some(b'/') => {
                            self.i += 1;
                            let k = self.name();
                            let v = self.obj(false, depth + 1).unwrap_or(Obj::Null);
                            d.insert(k, v);
                        }
                        _ => {
                            // junk: skip one token
                            let before = self.i;
                            let _ = self.obj(false, depth + 1);
                            if self.i == before {
                                self.i += 1;
                            }
                        }
                    }
                }
                Some(Obj::Dict(d))
            }
            b'<' => {
                self.i += 1;
                Some(Obj::Str(self.hex()))
            }
            b'[' => {
                self.i += 1;
                let mut a = Vec::new();
                loop {
                    self.skip_ws();
                    match self.b.get(self.i) {
                        None => break,
                        Some(b']') => {
                            self.i += 1;
                            break;
                        }
                        _ => {
                            let before = self.i;
                            match self.obj(ops, depth + 1) {
                                Some(o) => a.push(o),
                                None => break,
                            }
                            if self.i == before {
                                self.i += 1;
                            }
                        }
                    }
                }
                Some(Obj::Arr(self.fold_refs(a)))
            }
            b'/' => {
                self.i += 1;
                Some(Obj::Name(self.name()))
            }
            b')' | b'>' | b']' | b'{' | b'}' => {
                self.i += 1;
                Some(Obj::Op(String::from_utf8_lossy(&[c]).into_owned()))
            }
            _ => {
                let w = self.word();
                if w.is_empty() {
                    self.i += 1;
                    return Some(Obj::Op(String::new()));
                }
                let s = String::from_utf8_lossy(w);
                if let Ok(n) = s.parse::<f64>() {
                    // `N G R` reference outside arrays
                    if !ops && w.iter().all(u8::is_ascii_digit) {
                        let save = self.i;
                        let mut l2 = Lexer::new(self.b, self.i);
                        l2.skip_ws();
                        let g = l2.word();
                        if !g.is_empty() && g.iter().all(u8::is_ascii_digit) {
                            l2.skip_ws();
                            if l2.b.get(l2.i) == Some(&b'R') && l2.b.get(l2.i + 1).is_none_or(|c| is_ws(*c) || is_delim(*c)) {
                                self.i = l2.i + 1;
                                return Some(Obj::Ref(n as u32));
                            }
                        }
                        self.i = save;
                    }
                    return Some(Obj::Num(n));
                }
                Some(match s.as_ref() {
                    "true" => Obj::Bool(true),
                    "false" => Obj::Bool(false),
                    "null" => Obj::Null,
                    other => Obj::Op(other.to_string()),
                })
            }
        }
    }

    fn fold_refs(&self, a: Vec<Obj>) -> Vec<Obj> {
        // Arrays are parsed without ref lookahead in content mode; fold `N G R` triples.
        let mut out = Vec::with_capacity(a.len());
        let mut i = 0;
        while i < a.len() {
            if let (Some(Obj::Num(n)), Some(Obj::Num(_)), Some(Obj::Op(r))) = (a.get(i), a.get(i + 1), a.get(i + 2)) {
                if r == "R" {
                    out.push(Obj::Ref(*n as u32));
                    i += 3;
                    continue;
                }
            }
            out.push(a[i].clone());
            i += 1;
        }
        out
    }
}

fn inflate(data: &[u8]) -> Result<Vec<u8>, String> {
    miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(data, 256 * 1024 * 1024).or_else(|_| miniz_oxide::inflate::decompress_to_vec_with_limit(data, 256 * 1024 * 1024)).map_err(|e| format!("FlateDecode: {e:?}"))
}

fn png_predict(data: &[u8], columns: usize, colors: usize, bpc: usize) -> Vec<u8> {
    let bpp = (colors * bpc).div_ceil(8).max(1);
    let row = (columns * colors * bpc).div_ceil(8);
    let mut out = Vec::with_capacity(data.len());
    let mut prev = vec![0u8; row];
    for chunk in data.chunks(row + 1) {
        if chunk.len() < row + 1 {
            break;
        }
        let (t, src) = (chunk[0], &chunk[1..]);
        let mut cur = vec![0u8; row];
        for i in 0..row {
            let a = if i >= bpp { cur[i - bpp] } else { 0 } as i16;
            let b = prev[i] as i16;
            let c = if i >= bpp { prev[i - bpp] } else { 0 } as i16;
            let x = src[i];
            cur[i] = match t {
                1 => x.wrapping_add(a as u8),
                2 => x.wrapping_add(b as u8),
                3 => x.wrapping_add(((a + b) / 2) as u8),
                4 => {
                    let p = a + b - c;
                    let (pa, pb, pc) = ((p - a).abs(), (p - b).abs(), (p - c).abs());
                    x.wrapping_add(if pa <= pb && pa <= pc { a } else if pb <= pc { b } else { c } as u8)
                }
                _ => x,
            };
        }
        out.extend_from_slice(&cur);
        prev = cur;
    }
    out
}

fn ascii_hex(d: &[u8]) -> Vec<u8> {
    let mut l = Lexer::new(d, 0);
    l.hex()
}

fn ascii85(d: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut group = Vec::with_capacity(5);
    let mut it = d.iter().copied().filter(|c| !is_ws(*c)).peekable();
    if d.starts_with(b"<~") {
        it.next();
        it.next();
    }
    for c in it {
        if c == b'~' {
            break;
        }
        if c == b'z' && group.is_empty() {
            out.extend_from_slice(&[0, 0, 0, 0]);
            continue;
        }
        if !(b'!'..=b'u').contains(&c) {
            continue;
        }
        group.push(c - b'!');
        if group.len() == 5 {
            let v = group.iter().fold(0u64, |a, &x| a * 85 + x as u64) as u32;
            out.extend_from_slice(&v.to_be_bytes());
            group.clear();
        }
    }
    if !group.is_empty() {
        let n = group.len();
        while group.len() < 5 {
            group.push(84);
        }
        let v = group.iter().fold(0u64, |a, &x| a * 85 + x as u64) as u32;
        out.extend_from_slice(&v.to_be_bytes()[..n - 1]);
    }
    out
}

struct Doc {
    objs: HashMap<u32, Obj>,
    trailer: BTreeMap<String, Obj>,
}

impl Doc {
    fn get<'a>(&'a self, o: &'a Obj) -> &'a Obj {
        let mut cur = o;
        for _ in 0..16 {
            match cur {
                Obj::Ref(n) => match self.objs.get(n) {
                    Some(x) => cur = x,
                    None => return &Obj::Null,
                },
                _ => return cur,
            }
        }
        &Obj::Null
    }
    fn key<'a>(&'a self, d: &'a BTreeMap<String, Obj>, k: &str) -> &'a Obj {
        d.get(k).map(|o| self.get(o)).unwrap_or(&Obj::Null)
    }

    fn decode_stream(&self, d: &BTreeMap<String, Obj>, raw: &[u8]) -> Result<Vec<u8>, String> {
        let filters: Vec<String> = match self.key(d, "Filter") {
            Obj::Name(n) => vec![n.clone()],
            Obj::Arr(a) => a.iter().filter_map(|x| self.get(x).name().map(str::to_string)).collect(),
            _ => vec![],
        };
        let parms: Vec<Obj> = match self.key(d, "DecodeParms") {
            Obj::Arr(a) => a.iter().map(|x| self.get(x).clone()).collect(),
            Obj::Null => vec![],
            o => vec![o.clone()],
        };
        let mut data = raw.to_vec();
        for (i, f) in filters.iter().enumerate() {
            data = match f.as_str() {
                "FlateDecode" | "Fl" => {
                    let mut out = inflate(&data)?;
                    if let Some(p) = parms.get(i).and_then(|p| p.dict()) {
                        let n = |k: &str, dflt: f64| p.get(k).and_then(|v| self.get(v).num()).unwrap_or(dflt) as usize;
                        if n("Predictor", 1.0) >= 10 {
                            out = png_predict(&out, n("Columns", 1.0), n("Colors", 1.0), n("BitsPerComponent", 8.0));
                        }
                    }
                    out
                }
                "ASCIIHexDecode" | "AHx" => ascii_hex(&data),
                "ASCII85Decode" | "A85" => ascii85(&data),
                other => return Err(format!("unsupported stream filter {other}")),
            };
        }
        Ok(data)
    }

    fn stream_data(&self, o: &Obj) -> Option<Vec<u8>> {
        match self.get(o) {
            Obj::Stream(d, raw) => self.decode_stream(d, raw).ok(),
            _ => None,
        }
    }
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= hay.len() {
        return None;
    }
    hay[from..].windows(needle.len()).position(|w| w == needle).map(|p| p + from)
}

/// Parse every `N G obj … endobj` (later definitions win: incremental updates), then the
/// objects packed in object streams.
fn parse(b: &[u8]) -> Result<Doc, String> {
    if !b.starts_with(b"%PDF-") && find(&b[..b.len().min(1024)], b"%PDF-", 0).is_none() {
        return Err("not a PDF (missing %PDF- header)".into());
    }
    let mut objs: HashMap<u32, Obj> = HashMap::new();
    let mut pending: Vec<(u32, BTreeMap<String, Obj>, usize)> = Vec::new();
    let mut i = 0;
    while let Some(p) = find(b, b"obj", i) {
        i = p + 3;
        if b.get(p + 3).is_some_and(|c| !is_ws(*c) && !is_delim(*c)) || (p > 0 && !is_ws(b[p - 1])) {
            continue;
        }
        // walk back over "<num> <gen> "
        let mut j = p;
        while j > 0 && is_ws(b[j - 1]) {
            j -= 1;
        }
        let ge = j;
        while j > 0 && b[j - 1].is_ascii_digit() {
            j -= 1;
        }
        if j == ge {
            continue;
        }
        let ne = {
            let mut k = j;
            while k > 0 && is_ws(b[k - 1]) {
                k -= 1;
            }
            k
        };
        let mut ns = ne;
        while ns > 0 && b[ns - 1].is_ascii_digit() {
            ns -= 1;
        }
        if ns == ne {
            continue;
        }
        let Ok(num) = std::str::from_utf8(&b[ns..ne]).unwrap_or("").parse::<u32>() else { continue };
        let mut l = Lexer::new(b, p + 3);
        let Some(o) = l.obj(false, 0) else { continue };
        l.skip_ws();
        let o = match o {
            Obj::Dict(d) if b[l.i..].starts_with(b"stream") => {
                let mut s = l.i + 6;
                if b.get(s) == Some(&b'\r') {
                    s += 1;
                }
                if b.get(s) == Some(&b'\n') {
                    s += 1;
                }
                pending.push((num, d, s));
                continue;
            }
            o => o,
        };
        objs.insert(num, o);
    }
    let mut doc = Doc { objs, trailer: BTreeMap::new() };
    // Streams: /Length may be an indirect object, so resolve after the first pass.
    for (num, d, s) in pending {
        let len = match d.get("Length").map(|o| doc.get(o)) {
            Some(Obj::Num(n)) if *n >= 0.0 && s + (*n as usize) <= b.len() && find(&b[s + *n as usize..(s + *n as usize + 32).min(b.len())], b"endstream", 0).is_some() => *n as usize,
            _ => match find(b, b"endstream", s) {
                Some(e) => {
                    let mut e2 = e;
                    if e2 > s && b[e2 - 1] == b'\n' {
                        e2 -= 1;
                    }
                    if e2 > s && b[e2 - 1] == b'\r' {
                        e2 -= 1;
                    }
                    e2 - s
                }
                None => b.len() - s,
            },
        };
        doc.objs.insert(num, Obj::Stream(d, b[s..s + len].to_vec()));
    }
    // Object streams.
    let objstms: Vec<(BTreeMap<String, Obj>, Vec<u8>)> = doc.objs.values().filter_map(|o| match o {
        Obj::Stream(d, raw) if d.get("Type").and_then(Obj::name) == Some("ObjStm") => Some((d.clone(), raw.clone())),
        _ => None,
    }).collect();
    for (d, raw) in objstms {
        let Ok(data) = doc.decode_stream(&d, &raw) else { continue };
        let n = d.get("N").and_then(|o| doc.get(o).num()).unwrap_or(0.0) as usize;
        let first = d.get("First").and_then(|o| doc.get(o).num()).unwrap_or(0.0) as usize;
        let mut l = Lexer::new(&data, 0);
        let mut heads = Vec::new();
        for _ in 0..n {
            let (Some(Obj::Num(on)), Some(Obj::Num(off))) = (l.obj(true, 0), l.obj(true, 0)) else { break };
            heads.push((on as u32, off as usize));
        }
        for (on, off) in heads {
            if doc.objs.contains_key(&on) {
                continue;
            }
            let mut l = Lexer::new(&data, first + off);
            if let Some(o) = l.obj(false, 0) {
                doc.objs.insert(on, o);
            }
        }
    }
    // Trailer: classic `trailer` dicts and cross-reference stream dicts (last wins).
    let mut t = BTreeMap::new();
    let mut k = 0;
    while let Some(p) = find(b, b"trailer", k) {
        k = p + 7;
        if let Some(Obj::Dict(d)) = Lexer::new(b, k).obj(false, 0) {
            t.extend(d);
        }
    }
    for o in doc.objs.values() {
        if let Obj::Stream(d, _) = o {
            if d.get("Type").and_then(Obj::name) == Some("XRef") {
                for key in ["Root", "Encrypt", "Info"] {
                    if let Some(v) = d.get(key) {
                        t.insert(key.to_string(), v.clone());
                    }
                }
            }
        }
    }
    if !t.contains_key("Root") {
        if let Some((n, _)) = doc.objs.iter().find(|(_, o)| o.dict().and_then(|d| d.get("Type")).and_then(Obj::name) == Some("Catalog")) {
            t.insert("Root".into(), Obj::Ref(*n));
        }
    }
    doc.trailer = t;
    Ok(doc)
}

// ───── fonts ─────

#[derive(Default, Clone)]
struct Font {
    two_byte: bool,
    cmap: HashMap<u32, String>,
    diffs: HashMap<u8, char>,
}

const WIN_ANSI_80: [char; 32] = [
    '€', '\u{fffd}', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u{fffd}', 'Ž', '\u{fffd}', '\u{fffd}', '‘', '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', '\u{fffd}', 'ž', 'Ÿ',
];

fn glyph_char(name: &str) -> Option<char> {
    if let Some(h) = name.strip_prefix("uni").filter(|h| h.len() >= 4) {
        return u32::from_str_radix(&h[..4], 16).ok().and_then(char::from_u32);
    }
    if let Some(h) = name.strip_prefix('u').filter(|h| (4..=6).contains(&h.len()) && h.chars().all(|c| c.is_ascii_hexdigit())) {
        return u32::from_str_radix(h, 16).ok().and_then(char::from_u32);
    }
    if name.len() == 1 {
        return name.chars().next();
    }
    Some(match name {
        "space" => ' ', "exclam" => '!', "quotedbl" => '"', "numbersign" => '#', "dollar" => '$', "percent" => '%', "ampersand" => '&', "quotesingle" | "quoteright" => '\'',
        "parenleft" => '(', "parenright" => ')', "asterisk" => '*', "plus" => '+', "comma" => ',', "hyphen" | "minus" => '-', "period" => '.', "slash" => '/',
        "zero" => '0', "one" => '1', "two" => '2', "three" => '3', "four" => '4', "five" => '5', "six" => '6', "seven" => '7', "eight" => '8', "nine" => '9',
        "colon" => ':', "semicolon" => ';', "less" => '<', "equal" => '=', "greater" => '>', "question" => '?', "at" => '@', "bracketleft" => '[', "backslash" => '\\',
        "bracketright" => ']', "asciicircum" => '^', "underscore" => '_', "grave" | "quoteleft" => '‘', "braceleft" => '{', "bar" => '|', "braceright" => '}', "asciitilde" => '~',
        "bullet" => '•', "endash" => '–', "emdash" => '—', "quotedblleft" => '“', "quotedblright" => '”', "ellipsis" => '…', "fi" => 'ﬁ', "fl" => 'ﬂ', "copyright" => '©',
        "registered" => '®', "degree" => '°', "eacute" => 'é', "egrave" => 'è', "agrave" => 'à', "ccedilla" => 'ç', "udieresis" => 'ü', "odieresis" => 'ö', "adieresis" => 'ä',
        "germandbls" => 'ß', "nbspace" => '\u{a0}',
        _ => return None,
    })
}

fn utf16be(b: &[u8]) -> String {
    let u: Vec<u16> = b.chunks(2).map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])).collect();
    String::from_utf16_lossy(&u)
}

fn parse_cmap(data: &[u8], font: &mut Font) {
    let mut l = Lexer::new(data, 0);
    let mut toks: Vec<Obj> = Vec::new();
    while l.i < data.len() {
        let before = l.i;
        match l.obj(true, 0) {
            Some(Obj::Op(op)) => match op.as_str() {
                "endcodespacerange" => {
                    if let Some(Obj::Str(s)) = toks.first() {
                        font.two_byte = s.len() >= 2;
                    }
                    toks.clear();
                }
                "endbfchar" => {
                    for p in toks.chunks(2) {
                        if let [Obj::Str(src), Obj::Str(dst)] = p {
                            font.cmap.insert(be(src), utf16be(dst));
                        }
                    }
                    toks.clear();
                }
                "endbfrange" => {
                    for p in toks.chunks(3) {
                        if let [Obj::Str(lo), Obj::Str(hi), dst] = p {
                            let (lo, hi) = (be(lo), be(hi));
                            if hi < lo || hi - lo > 65535 {
                                continue;
                            }
                            match dst {
                                Obj::Str(d) => {
                                    let base: Vec<u16> = d.chunks(2).map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])).collect();
                                    for (k, code) in (lo..=hi).enumerate() {
                                        let mut u = base.clone();
                                        if let Some(last) = u.last_mut() {
                                            *last = last.wrapping_add(k as u16);
                                        }
                                        font.cmap.insert(code, String::from_utf16_lossy(&u));
                                    }
                                }
                                Obj::Arr(a) => {
                                    for (k, code) in (lo..=hi).enumerate() {
                                        if let Some(Obj::Str(d)) = a.get(k) {
                                            font.cmap.insert(code, utf16be(d));
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    toks.clear();
                }
                "begincodespacerange" | "beginbfchar" | "beginbfrange" => toks.clear(),
                _ => {}
            },
            Some(o) => toks.push(o),
            None => break,
        }
        if l.i == before {
            l.i += 1;
        }
    }
}

fn be(b: &[u8]) -> u32 {
    b.iter().fold(0u32, |a, &x| (a << 8) | x as u32)
}

impl Font {
    fn load(doc: &Doc, d: &BTreeMap<String, Obj>) -> Font {
        let mut f = Font { two_byte: doc.key(d, "Subtype").name() == Some("Type0"), ..Default::default() };
        if let Some(data) = d.get("ToUnicode").and_then(|o| doc.stream_data(o)) {
            parse_cmap(&data, &mut f);
        }
        if let Some(enc) = doc.key(d, "Encoding").dict() {
            if let Obj::Arr(a) = doc.key(enc, "Differences") {
                let mut code = 0u32;
                for x in a {
                    match doc.get(x) {
                        Obj::Num(n) => code = *n as u32,
                        Obj::Name(nm) => {
                            if let (Some(c), true) = (glyph_char(nm), code < 256) {
                                f.diffs.insert(code as u8, c);
                            }
                            code += 1;
                        }
                        _ => {}
                    }
                }
            }
        }
        f
    }

    fn decode(&self, s: &[u8]) -> String {
        let mut out = String::new();
        if self.two_byte {
            for c in s.chunks(2) {
                let code = be(c);
                match self.cmap.get(&code) {
                    Some(t) => out.push_str(t),
                    None if self.cmap.is_empty() => {}
                    None => {}
                }
            }
            return out;
        }
        for &b in s {
            if let Some(t) = self.cmap.get(&(b as u32)) {
                out.push_str(t);
            } else if let Some(c) = self.diffs.get(&b) {
                out.push(*c);
            } else if (0x80..0xa0).contains(&b) {
                out.push(WIN_ANSI_80[(b - 0x80) as usize]);
            } else if b >= 0x20 || b == b'\t' {
                out.push(b as char);
            }
        }
        out
    }
}

// ───── content streams ─────

struct TextOut {
    s: String,
    last_y: Option<f64>,
}

impl TextOut {
    fn nl(&mut self) {
        if !self.s.is_empty() && !self.s.ends_with('\n') {
            self.s.push('\n');
        }
    }
    fn space(&mut self) {
        if !self.s.is_empty() && !self.s.ends_with([' ', '\n']) {
            self.s.push(' ');
        }
    }
}

fn fonts_of(doc: &Doc, res: &BTreeMap<String, Obj>) -> HashMap<String, Font> {
    let mut m = HashMap::new();
    if let Some(fd) = doc.key(res, "Font").dict() {
        for (k, v) in fd {
            if let Some(d) = doc.get(v).dict() {
                m.insert(k.clone(), Font::load(doc, d));
            }
        }
    }
    m
}

fn run_content(doc: &Doc, data: &[u8], res: &BTreeMap<String, Obj>, out: &mut TextOut, depth: usize) {
    if depth > 6 {
        return;
    }
    let fonts = fonts_of(doc, res);
    let mut font: Option<&Font> = None;
    let mut stack: Vec<Obj> = Vec::new();
    let mut l = Lexer::new(data, 0);
    let show = |f: Option<&Font>, s: &[u8]| f.map(|f| f.decode(s)).unwrap_or_else(|| String::from_utf8_lossy(s).into_owned());
    while l.i < data.len() {
        let before = l.i;
        let Some(o) = l.obj(true, 0) else { break };
        if l.i == before {
            l.i += 1;
        }
        let Obj::Op(op) = o else {
            stack.push(o);
            if stack.len() > 4096 {
                stack.clear();
            }
            continue;
        };
        match op.as_str() {
            "BT" => {}
            "ET" => {}
            "Tf" => {
                if let Some(Obj::Name(n)) = stack.iter().rev().nth(1) {
                    font = fonts.get(n);
                }
            }
            "Tj" => {
                if let Some(Obj::Str(s)) = stack.last() {
                    out.s.push_str(&show(font, s));
                }
            }
            "'" | "\"" => {
                out.nl();
                if let Some(Obj::Str(s)) = stack.last() {
                    out.s.push_str(&show(font, s));
                }
            }
            "TJ" => {
                if let Some(Obj::Arr(a)) = stack.last() {
                    for x in a {
                        match x {
                            Obj::Str(s) => out.s.push_str(&show(font, s)),
                            Obj::Num(n) if *n < -200.0 => out.space(),
                            _ => {}
                        }
                    }
                }
            }
            "Td" | "TD" => {
                let ty = stack.last().and_then(Obj::num).unwrap_or(0.0);
                let tx = stack.iter().rev().nth(1).and_then(Obj::num).unwrap_or(0.0);
                if ty.abs() > 0.5 {
                    out.nl();
                } else if tx.abs() > 1.0 {
                    out.space();
                }
            }
            "T*" => out.nl(),
            "Tm" => {
                let y = stack.last().and_then(Obj::num);
                if let (Some(y), Some(prev)) = (y, out.last_y) {
                    if (y - prev).abs() > 0.5 {
                        out.nl();
                    } else {
                        out.space();
                    }
                }
                out.last_y = y;
            }
            "Do" => {
                if let Some(Obj::Name(n)) = stack.last() {
                    if let Some(xo) = doc.key(res, "XObject").dict() {
                        if let Obj::Stream(d, _) = doc.key(xo, n) {
                            if doc.key(d, "Subtype").name() == Some("Form") {
                                if let Some(data) = xo.get(n).and_then(|o| doc.stream_data(o)) {
                                    let r = doc.key(d, "Resources").dict().cloned().unwrap_or_else(|| res.clone());
                                    run_content(doc, &data, &r, out, depth + 1);
                                }
                            }
                        }
                    }
                }
            }
            "BI" => {
                // Inline image: skip to whitespace-delimited EI.
                if let Some(p) = find(data, b"ID", l.i) {
                    let mut k = p + 2;
                    while let Some(e) = find(data, b"EI", k) {
                        if e > 0 && is_ws(data[e - 1]) && data.get(e + 2).is_none_or(|c| is_ws(*c)) {
                            l.i = e + 2;
                            break;
                        }
                        k = e + 2;
                    }
                }
            }
            _ => {}
        }
        stack.clear();
    }
}

#[derive(Debug, Clone)]
pub struct Page {
    pub text: String,
    /// MediaBox width/height in points.
    pub size: (f64, f64),
}

type RawPage = (BTreeMap<String, Obj>, BTreeMap<String, Obj>, (f64, f64));

fn collect_pages(doc: &Doc, node: &Obj, inherited: &BTreeMap<String, Obj>, out: &mut Vec<RawPage>, depth: usize, inh_box: (f64, f64)) {
    if depth > 64 || out.len() > 100_000 {
        return;
    }
    let Some(d) = doc.get(node).dict() else { return };
    let res = doc.key(d, "Resources").dict().cloned().unwrap_or_else(|| inherited.clone());
    let bx = match doc.key(d, "MediaBox") {
        Obj::Arr(a) if a.len() == 4 => {
            let v: Vec<f64> = a.iter().map(|x| doc.get(x).num().unwrap_or(0.0)).collect();
            ((v[2] - v[0]).abs(), (v[3] - v[1]).abs())
        }
        _ => inh_box,
    };
    match (doc.key(d, "Type").name(), doc.key(d, "Kids")) {
        (Some("Pages"), Obj::Arr(kids)) | (None, Obj::Arr(kids)) => {
            for k in kids {
                collect_pages(doc, k, &res, out, depth + 1, bx);
            }
        }
        _ => out.push((d.clone(), res, bx)),
    }
}

/// Error for encrypted documents the native reader cannot decrypt.
pub const ENCRYPTED: &str = "PDF requires a password or password is incorrect.";

/// Native per-page text.
pub fn native_pages(b: &[u8]) -> Result<Vec<Page>, String> {
    let doc = parse(b)?;
    if doc.trailer.contains_key("Encrypt") {
        return Err(ENCRYPTED.into());
    }
    let root = doc.trailer.get("Root").ok_or("PDF has no document catalog")?;
    let pages_node = doc.get(root).dict().and_then(|c| c.get("Pages")).cloned().ok_or("PDF catalog has no page tree")?;
    let mut raw = Vec::new();
    collect_pages(&doc, &pages_node, &BTreeMap::new(), &mut raw, 0, (612.0, 792.0));
    if raw.is_empty() {
        return Err("PDF has no pages".into());
    }
    Ok(raw
        .into_iter()
        .map(|(d, res, size)| {
            let mut data = Vec::new();
            match doc.key(&d, "Contents") {
                Obj::Arr(a) => {
                    for c in a {
                        if let Some(x) = doc.stream_data(c) {
                            data.extend_from_slice(&x);
                            data.push(b'\n');
                        }
                    }
                }
                _ => {
                    if let Some(c) = d.get("Contents") {
                        data = doc.stream_data(c).unwrap_or_default();
                    }
                }
            }
            let mut out = TextOut { s: String::new(), last_y: None };
            run_content(&doc, &data, &res, &mut out, 0);
            Page { text: out.s.trim().to_string(), size }
        })
        .collect())
}

fn poppler_pages(b: &[u8], password: Option<&str>) -> Result<Vec<Page>, String> {
    let bin = crate::proc::which("pdftotext").ok_or("pdftotext is not installed")?;
    let dir = scratch();
    let inp = dir.join("in.pdf");
    std::fs::write(&inp, b).map_err(|e| e.to_string())?;
    let mut argv = vec![bin.display().to_string(), "-enc".into(), "UTF-8".into()];
    if let Some(p) = password {
        argv.extend(["-upw".into(), p.to_string()]);
    }
    argv.extend([inp.display().to_string(), "-".into()]);
    let r = crate::proc::run(&argv, None, Duration::from_secs(60), &seagent_core::Cancel::new());
    let _ = std::fs::remove_dir_all(&dir);
    let o = r?;
    if !o.success() {
        let l = o.stderr.to_ascii_lowercase();
        return Err(if l.contains("password") || l.contains("encrypt") { ENCRYPTED.into() } else { format!("pdftotext failed: {}", o.stderr.trim()) });
    }
    let text = String::from_utf8_lossy(&o.stdout).into_owned();
    let mut pages: Vec<Page> = text.split('\u{c}').map(|t| Page { text: t.trim().to_string(), size: (612.0, 792.0) }).collect();
    if pages.last().is_some_and(|p| p.text.is_empty()) && pages.len() > 1 {
        pages.pop();
    }
    Ok(pages)
}

fn scratch() -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let d = std::env::var_os("TMPDIR").map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir).join(format!("seagent-pdf-{}-{n}-{}", std::process::id(), crate::store::stem("x")));
    // 0700 at creation, not after the input PDF lands in it: the scratch dir holds the document's
    // extracted text and page renders, so on a multi-user box a 0755/0775 directory would let
    // other local users walk it while poppler is still writing.
    use std::os::unix::fs::DirBuilderExt;
    let _ = std::fs::DirBuilder::new().mode(0o700).create(&d);
    d
}

/// Per-page text: native first; poppler for encrypted/unreadable files or when a password is given.
pub fn pages(b: &[u8], password: Option<&str>) -> Result<Vec<Page>, String> {
    if password.is_some() {
        return poppler_pages(b, password).or_else(|e| native_pages(b).map_err(|_| e));
    }
    match native_pages(b) {
        Ok(p) if p.iter().any(|x| !x.text.is_empty()) => Ok(p),
        Ok(p) => Ok(poppler_pages(b, None).ok().filter(|q| q.len() == p.len() && q.iter().any(|x| !x.text.is_empty())).unwrap_or(p)),
        Err(e) => poppler_pages(b, None).map_err(|pe| if e == ENCRYPTED || pe == ENCRYPTED { ENCRYPTED.to_string() } else { format!("{e} (pdftotext fallback: {pe})") }),
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PagesMeta {
    pub processed: Vec<usize>,
    pub total: usize,
    pub explicit: bool,
    pub truncated: bool,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Metadata {
    pub pages: PagesMeta,
    pub text_truncated: bool,
    pub images_truncated: bool,
    /// Selected pages whose text layer was shorter than `min_text_chars` (scan candidates).
    /// Upstream always extracts page images; seagent skips the render when no vision model will
    /// see them, but still reports `image rendering truncated` (OpenClaw `imagesTruncated`).
    pub low_text_pages: usize,
}

#[derive(Debug, Clone, Default)]
pub struct Request<'a> {
    pub max_pages: usize,
    pub max_pixels: u64,
    pub min_text_chars: usize,
    pub password: Option<&'a str>,
    pub page_numbers: Option<Vec<usize>>,
    /// Render low-text pages to images.
    pub render: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Content {
    pub text: String,
    /// PNG page renders for pages with too little text.
    pub images: Vec<Vec<u8>>,
    pub metadata: Metadata,
}

/// OpenClaw `pageRenderOptions`: 96 dpi when it fits the per-page pixel budget, else the
/// largest integer long edge whose (rounded-up) area fits. Returns `(w, h, reduced)` in px.
pub fn render_plan(width_pt: f64, height_pt: f64, max_pixels: u64) -> Option<(u64, u64, bool)> {
    if !(width_pt.is_finite() && height_pt.is_finite()) || width_pt <= 0.0 || height_pt <= 0.0 {
        return None;
    }
    let (dw, dh) = ((width_pt * 96.0 / 72.0).ceil() as u64, (height_pt * 96.0 / 72.0).ceil() as u64);
    if dw <= MAX_RENDER_DIMENSION && dh <= MAX_RENDER_DIMENSION && dw * dh <= max_pixels {
        return Some((dw, dh, false));
    }
    let landscape = width_pt >= height_pt;
    let (longer, shorter) = if landscape { (width_pt, height_pt) } else { (height_pt, width_pt) };
    let (mut lo, mut hi, mut size) = (1u64, MAX_RENDER_DIMENSION.min((longer * 96.0 / 72.0).ceil() as u64), 1u64);
    while lo <= hi {
        let c = (lo + hi) / 2;
        let other = ((shorter * (c as f64 / longer)).ceil() as u64).max(1);
        if c * other <= max_pixels {
            size = c;
            lo = c + 1;
        } else {
            hi = c - 1;
        }
    }
    let other = ((shorter * (size as f64 / longer)).ceil() as u64).max(1);
    Some(if landscape { (size, other, true) } else { (other, size, true) })
}

fn render_page(b: &[u8], page: usize, w: u64, h: u64, password: Option<&str>) -> Result<Vec<u8>, String> {
    let bin = crate::proc::which("pdftoppm").ok_or("pdftoppm is not installed (needed to render scanned PDF pages)")?;
    let dir = scratch();
    let inp = dir.join("in.pdf");
    std::fs::write(&inp, b).map_err(|e| e.to_string())?;
    let root = dir.join("page");
    let mut argv = vec![bin.display().to_string(), "-png".into(), "-singlefile".into(), "-f".into(), page.to_string(), "-l".into(), page.to_string(), "-scale-to-x".into(), w.to_string(), "-scale-to-y".into(), h.to_string()];
    if let Some(p) = password {
        argv.extend(["-upw".into(), p.to_string()]);
    }
    argv.extend([inp.display().to_string(), root.display().to_string()]);
    let r = crate::proc::run(&argv, None, Duration::from_secs(60), &seagent_core::Cancel::new()).and_then(|o| o.check("pdftoppm")).and_then(|_| std::fs::read(root.with_extension("png")).map_err(|e| e.to_string()));
    let _ = std::fs::remove_dir_all(&dir);
    r
}

/// OpenClaw `extractPdfContent`: selected pages' text (capped at 200k chars) plus page renders
/// for pages whose text layer is shorter than `min_text_chars`.
pub fn extract(b: &[u8], req: &Request) -> Result<Content, String> {
    let all = pages(b, req.password)?;
    let total = all.len();
    let selected: Vec<usize> = match &req.page_numbers {
        Some(want) => {
            let v: Vec<usize> = want.iter().copied().filter(|p| *p >= 1 && *p <= total).take(req.max_pages).collect();
            if !want.is_empty() && v.is_empty() {
                return Err(format!("No requested PDF pages exist in this {total}-page document."));
            }
            v
        }
        None => (1..=total.min(req.max_pages)).collect(),
    };
    let mut md = Metadata {
        pages: PagesMeta {
            processed: selected.clone(),
            total,
            explicit: req.page_numbers.is_some(),
            truncated: match &req.page_numbers {
                Some(w) => w.len() > selected.len(),
                None => total > req.max_pages,
            },
        },
        ..Default::default()
    };
    let mut text = String::new();
    let mut image_pages = Vec::new();
    for &p in &selected {
        let pt = &all[p - 1].text;
        if pt.trim().chars().count() < req.min_text_chars {
            image_pages.push(p);
        }
        let sep = if text.is_empty() { "" } else { "\n\n" };
        let remaining = MAX_TEXT_CHARS.saturating_sub(text.chars().count() + sep.len());
        let prefix: String = pt.chars().take(remaining).collect();
        md.text_truncated |= prefix.chars().count() < pt.chars().count();
        if !prefix.is_empty() {
            text.push_str(sep);
            text.push_str(&prefix);
        }
    }
    let mut images = Vec::new();
    md.low_text_pages = image_pages.len();
    if req.render && !image_pages.is_empty() {
        let mut remaining = req.max_pixels as i64;
        for (idx, &p) in image_pages.iter().enumerate() {
            if remaining <= 0 {
                md.images_truncated = true;
                break;
            }
            let per = (remaining as u64).div_ceil((image_pages.len() - idx) as u64).max(1);
            let (w, h) = all[p - 1].size;
            let Some((pw, ph, reduced)) = render_plan(w, h, per) else {
                md.images_truncated = true;
                continue;
            };
            md.images_truncated |= reduced;
            match render_page(b, p, pw, ph, req.password) {
                Ok(png) => {
                    let used = super::super::vision::prep::dimensions(&png).map(|(a, b)| a as i64 * b as i64).unwrap_or((pw * ph) as i64);
                    remaining -= used;
                    images.push(png);
                }
                Err(e) => {
                    md.images_truncated = true;
                    if text.trim().is_empty() {
                        return Err(format!("PDF image extraction failed with no extractable text. ({e})"));
                    }
                    break;
                }
            }
        }
    }
    Ok(Content { text, images, metadata: md })
}

/// OpenClaw `renderDocumentTruncationNotice`.
pub fn truncation_notice(md: &Metadata, explicit_selection_limit: Option<usize>) -> Option<String> {
    let mut r = Vec::new();
    if let Some(n) = explicit_selection_limit {
        r.push(format!("requested page selection limited to {n} pages"));
    }
    if md.pages.truncated {
        r.push(if md.pages.explicit { format!("some requested pages omitted; {} pages processed", md.pages.processed.len()) } else { format!("{} of {} pages processed", md.pages.processed.len(), md.pages.total) });
    }
    if md.text_truncated {
        r.push("text truncated".into());
    }
    if md.images_truncated {
        r.push("image rendering truncated".into());
    }
    (!r.is_empty()).then(|| format!("[Partial document: {}.]", r.join("; ")))
}

/// OpenClaw `parsePageRange`: up to `max_pages` sorted, unique, 1-based pages; `(pages, truncated)`.
pub fn parse_page_range(range: &str, max_pages: usize) -> Result<(Vec<usize>, bool), String> {
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let num = |v: &str, label: &str| -> Result<usize, String> { v.trim().parse::<usize>().ok().filter(|n| *n >= 1).ok_or_else(|| format!("{label}: \"{v}\"")) };
    for part in range.split(',').map(str::trim) {
        if part.is_empty() {
            continue;
        }
        // Only `^(\d+)\s*-\s*(\d+)$` is a range (upstream `dashMatch`); anything else falls
        // through to the single-page branch and is reported as an invalid page *number*.
        let range_pair = part.split_once('-').filter(|(a, b)| !b.contains('-') && !a.trim().is_empty() && !b.trim().is_empty() && a.trim().chars().all(|c| c.is_ascii_digit()) && b.trim().chars().all(|c| c.is_ascii_digit()));
        if let Some((a, b)) = range_pair {
            let (s, e) = (num(a, "Invalid page range")?, num(b, "Invalid page range")?);
            if e < s {
                return Err(format!("Invalid page range: \"{part}\""));
            }
            ranges.push((s, e));
        } else {
            if !part.chars().all(|c| c.is_ascii_digit()) {
                return Err(format!("Invalid page number: \"{part}\""));
            }
            let n = num(part, "Invalid page number")?;
            ranges.push((n, n));
        }
    }
    ranges.sort();
    let mut pages: Vec<usize> = Vec::new();
    for (s, e) in ranges {
        let mut p = s.max(pages.last().copied().unwrap_or(0) + 1);
        while p <= e {
            if pages.len() >= max_pages {
                return Ok((pages, true));
            }
            pages.push(p);
            p += 1;
        }
    }
    if pages.is_empty() {
        return Err(format!("No PDF pages matched requested range \"{range}\""));
    }
    Ok((pages, false))
}

#[cfg(test)]
pub(crate) mod testpdf {
    /// A small PDF: page 1 has text in a Flate stream with a ToUnicode font, page 2 a WinAnsi
    /// font with TJ kerning, page 3 is blank (a "scanned" page).
    pub fn build(compress: bool) -> Vec<u8> {
        let p1 = b"BT /F1 12 Tf 72 720 Td <00480049> Tj 0 -14 Td /F2 12 Tf [(W) -50 (orld)] TJ ET".to_vec();
        let p2 = b"BT /F2 12 Tf 72 720 Td (Caf\xe9 \x93quoted\x94) Tj T* [(Two) -300 (words)] TJ ET".to_vec();
        let cmap = b"/CIDInit /ProcSet findresource begin 12 dict begin begincmap 1 begincodespacerange <0000> <FFFF> endcodespacerange 1 beginbfrange <0048> <0049> <0048> endbfrange endcmap end end".to_vec();
        let stream = |d: &[u8]| -> (String, Vec<u8>) {
            if compress {
                let z = miniz_oxide::deflate::compress_to_vec_zlib(d, 6);
                (format!("<< /Length {} /Filter /FlateDecode >>", z.len()), z)
            } else {
                (format!("<< /Length {} >>", d.len()), d.to_vec())
            }
        };
        let mut objs: Vec<Vec<u8>> = vec![
            b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
            b"<< /Type /Pages /Kids [3 0 R 4 0 R 5 0 R] /Count 3 /MediaBox [0 0 612 792] >>".to_vec(),
            b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R /F2 9 0 R >> >> /Contents 6 0 R >>".to_vec(),
            b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F2 9 0 R >> >> /Contents 10 0 R >>".to_vec(),
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 400] >>".to_vec(),
        ];
        let (h, d) = stream(&p1);
        objs.push([h.as_bytes(), b"\nstream\n", &d, b"\nendstream"].concat());
        objs.push(b"<< /Type /Font /Subtype /Type0 /BaseFont /X /Encoding /Identity-H /ToUnicode 8 0 R >>".to_vec());
        let (h, d) = stream(&cmap);
        objs.push([h.as_bytes(), b"\nstream\n", &d, b"\nendstream"].concat());
        objs.push(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>".to_vec());
        let (h, d) = stream(&p2);
        objs.push([h.as_bytes(), b"\nstream\n", &d, b"\nendstream"].concat());
        let mut out = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
        for (i, o) in objs.iter().enumerate() {
            out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
            out.extend_from_slice(o);
            out.extend_from_slice(b"\nendobj\n");
        }
        out.extend_from_slice(b"trailer\n<< /Root 1 0 R /Size 11 >>\n%%EOF\n");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_text_fonts_and_streams() {
        for compress in [true, false] {
            let p = native_pages(&testpdf::build(compress)).unwrap();
            assert_eq!(p.len(), 3);
            assert_eq!(p[0].text, "HI\nWorld");
            assert_eq!(p[1].text, "Café “quoted”\nTwo words");
            assert_eq!(p[2].text, "");
            assert_eq!(p[2].size, (300.0, 400.0));
        }
        assert!(native_pages(b"hello").unwrap_err().contains("not a PDF"));
        let mut enc = testpdf::build(false);
        let at = enc.len() - b"%%EOF\n".len();
        enc.splice(at..at, b"trailer << /Encrypt 99 0 R >>\n".iter().copied());
        assert_eq!(native_pages(&enc).unwrap_err(), ENCRYPTED);
        assert_eq!(ascii85(b"<~9jqo^~>"), b"Man ");
        assert_eq!(ascii_hex(b"48 69>"), b"Hi");
    }

    #[test]
    fn extract_selection_metadata_and_notices() {
        let pdf = testpdf::build(true);
        let c = extract(&pdf, &Request { max_pages: 2, max_pixels: 4_000_000, min_text_chars: 5, ..Default::default() }).unwrap();
        assert_eq!(c.text, "HI\nWorld\n\nCafé “quoted”\nTwo words");
        assert_eq!((c.metadata.pages.total, c.metadata.pages.truncated), (3, true));
        assert_eq!(truncation_notice(&c.metadata, None).unwrap(), "[Partial document: 2 of 3 pages processed.]");
        let c = extract(&pdf, &Request { max_pages: 20, max_pixels: 4_000_000, min_text_chars: 0, page_numbers: Some(vec![2, 9]), ..Default::default() }).unwrap();
        assert_eq!(c.metadata.pages.processed, vec![2]);
        assert!(truncation_notice(&c.metadata, None).unwrap().contains("some requested pages omitted; 1 pages processed"));
        assert!(extract(&pdf, &Request { max_pages: 5, page_numbers: Some(vec![7]), ..Default::default() }).unwrap_err().contains("3-page document"));
        assert_eq!(parse_page_range("5-7, 1,3", 10).unwrap(), (vec![1, 3, 5, 6, 7], false));
        assert_eq!(parse_page_range("1-100", 3).unwrap(), (vec![1, 2, 3], true));
        assert!(parse_page_range("3-1", 5).unwrap_err().contains("Invalid page range"));
        assert!(parse_page_range("x", 5).unwrap_err().contains("Invalid page number"));
        assert_eq!(render_plan(612.0, 792.0, 4_000_000), Some((816, 1056, false)));
        let (w, h, reduced) = render_plan(612.0, 792.0, 100_000).unwrap();
        assert!(reduced && w * h <= 100_000 && h > w);
    }

    /// The scratch directory holds the extracted text/renders of the document while poppler runs.
    /// It must be private from creation: on a multi-user box a 0755 directory lets other users
    /// walk in and read the user's document mid-render.
    #[test]
    fn scratch_dir_is_created_private_and_cleaned_up() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch();
        let mode = std::fs::metadata(&d).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "{} was created {mode:o}", d.display());
        std::fs::write(d.join("in.pdf"), b"%PDF-1.7\n").unwrap();
        std::fs::remove_dir_all(&d).unwrap();
        assert!(!d.exists(), "the cleanup path still works");
    }

    #[test]
    fn renders_low_text_pages_when_poppler_is_installed() {
        if crate::proc::which("pdftoppm").is_none() {
            return;
        }
        let c = extract(&testpdf::build(true), &Request { max_pages: 20, max_pixels: 400_000, min_text_chars: 3, render: true, ..Default::default() }).unwrap();
        assert_eq!(c.images.len(), 1, "only the blank page is rendered");
        assert!(c.images[0].starts_with(b"\x89PNG"));
    }
}
