//! Lenient HTML tokenizer and tree builder for page extraction. Hidden content (OpenClaw
//! `web-fetch-visibility.ts`: `display:none`, `aria-hidden`, `hidden`, `sr-only`, zero-size,
//! off-screen, transparent text, `<template>`, `<svg>`, …) never enters the tree, so prompt
//! injections hidden from human readers do not reach the model either.

use regex::Regex;
use std::sync::OnceLock;

pub type NodeId = usize;

#[derive(Debug, Clone)]
pub enum Kind {
    Element { tag: String, attrs: Vec<(String, String)> },
    Text(String),
}

#[derive(Debug, Clone)]
pub struct Node {
    pub kind: Kind,
    pub parent: Option<NodeId>,
    pub children: Vec<NodeId>,
}

#[derive(Debug, Clone)]
pub struct Doc {
    pub nodes: Vec<Node>,
    /// `<title>` text.
    pub title: Option<String>,
    /// `<meta name|property=… content=…>` pairs (lower-cased keys).
    pub meta: Vec<(String, String)>,
    /// `<html lang>`.
    pub lang: Option<String>,
}

pub const ROOT: NodeId = 0;

const VOID: &[&str] = &["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr", "keygen"];
const RAW_TEXT: &[&str] = &["script", "style", "textarea", "title", "xmp", "iframe", "noembed", "noframes", "noscript", "plaintext", "template"];
/// Elements dropped with their subtree.
const DROPPED: &[&str] = &["script", "style", "noscript", "template", "svg", "canvas", "iframe", "object", "embed", "meta", "link", "head", "button", "select", "option", "datalist", "math", "textarea", "input", "dialog"];
/// A start tag of one of these closes an open `<p>`.
const CLOSES_P: &[&str] = &[
    "address", "article", "aside", "blockquote", "details", "div", "dl", "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hgroup", "hr", "main", "menu", "nav", "ol", "p", "pre", "section", "table", "ul", "li", "dd", "dt",
];
const HIDDEN_CLASSES: &[&str] = &["sr-only", "visually-hidden", "d-none", "hidden", "invisible", "screen-reader-only", "offscreen"];

// ── entities ─────────────────────────────────────────────────────────────────────

const NAMED: &[(&str, &str)] = &[
    ("amp", "&"), ("lt", "<"), ("gt", ">"), ("quot", "\""), ("apos", "'"), ("nbsp", " "), ("ensp", " "), ("emsp", " "), ("thinsp", " "), ("ndash", "–"), ("mdash", "—"), ("hellip", "…"), ("lsquo", "‘"), ("rsquo", "’"),
    ("sbquo", "‚"), ("ldquo", "“"), ("rdquo", "”"), ("bdquo", "„"), ("laquo", "«"), ("raquo", "»"), ("lsaquo", "‹"), ("rsaquo", "›"), ("bull", "•"), ("middot", "·"), ("copy", "©"), ("reg", "®"), ("trade", "™"),
    ("deg", "°"), ("plusmn", "±"), ("times", "×"), ("divide", "÷"), ("frac12", "½"), ("frac14", "¼"), ("frac34", "¾"), ("sup1", "¹"), ("sup2", "²"), ("sup3", "³"), ("micro", "µ"), ("para", "¶"), ("sect", "§"),
    ("cent", "¢"), ("pound", "£"), ("yen", "¥"), ("euro", "€"), ("curren", "¤"), ("iexcl", "¡"), ("iquest", "¿"), ("shy", ""), ("zwj", ""), ("zwnj", ""), ("lrm", ""), ("rlm", ""), ("larr", "←"), ("rarr", "→"),
    ("uarr", "↑"), ("darr", "↓"), ("harr", "↔"), ("rArr", "⇒"), ("lArr", "⇐"), ("hearts", "♥"), ("spades", "♠"), ("clubs", "♣"), ("diams", "♦"), ("prime", "′"), ("Prime", "″"), ("dagger", "†"), ("Dagger", "‡"),
    ("permil", "‰"), ("infin", "∞"), ("ne", "≠"), ("le", "≤"), ("ge", "≥"), ("asymp", "≈"), ("minus", "−"), ("sum", "∑"), ("radic", "√"), ("alpha", "α"), ("beta", "β"), ("gamma", "γ"), ("delta", "δ"),
    ("pi", "π"), ("sigma", "σ"), ("omega", "ω"), ("mu", "μ"), ("lambda", "λ"), ("theta", "θ"), ("Agrave", "À"), ("Aacute", "Á"), ("Auml", "Ä"), ("Ouml", "Ö"), ("Uuml", "Ü"), ("agrave", "à"), ("aacute", "á"),
    ("acirc", "â"), ("auml", "ä"), ("aring", "å"), ("ccedil", "ç"), ("egrave", "è"), ("eacute", "é"), ("ecirc", "ê"), ("euml", "ë"), ("iacute", "í"), ("iuml", "ï"), ("ntilde", "ñ"), ("oacute", "ó"),
    ("ocirc", "ô"), ("ouml", "ö"), ("oslash", "ø"), ("uacute", "ú"), ("uuml", "ü"), ("szlig", "ß"), ("Eacute", "É"), ("Ntilde", "Ñ"), ("Ccedil", "Ç"),
];

/// Decode named (common set) and numeric character references; unknown ones stay as-is.
pub fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let end = rest[1..].find(|c: char| !(c.is_ascii_alphanumeric() || c == '#')).map(|e| e + 1).unwrap_or(rest.len());
        let name = &rest[1..end];
        let semi = rest[end..].starts_with(';');
        let decoded = if let Some(num) = name.strip_prefix('#') {
            let cp = if let Some(h) = num.strip_prefix(['x', 'X']) { u32::from_str_radix(h, 16).ok() } else { num.parse::<u32>().ok() };
            cp.map(|c| match c {
                0 => '\u{fffd}',
                0x80..=0x9f => win1252(c),
                _ => char::from_u32(c).unwrap_or('\u{fffd}'),
            })
            .map(|c| c.to_string())
        } else {
            NAMED.iter().find(|(n, _)| *n == name).map(|(_, v)| v.to_string())
        };
        match decoded {
            Some(d) if !name.is_empty() => {
                out.push_str(&d);
                rest = &rest[end + usize::from(semi)..];
            }
            _ => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn win1252(c: u32) -> char {
    const T: [u32; 32] = [
        0x20ac, 0x81, 0x201a, 0x192, 0x201e, 0x2026, 0x2020, 0x2021, 0x2c6, 0x2030, 0x160, 0x2039, 0x152, 0x8d, 0x17d, 0x8f, 0x90, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014, 0x2dc, 0x2122, 0x161,
        0x203a, 0x153, 0x9d, 0x17e, 0x178,
    ];
    char::from_u32(T[(c - 0x80) as usize]).unwrap_or('\u{fffd}')
}

// ── tokenizer ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Text(String),
    Start { name: String, attrs: Vec<(String, String)>, self_closing: bool },
    End(String),
}

fn parse_attrs(s: &str) -> Vec<(String, String)> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"([^\s"'>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?"#).unwrap());
    let mut out: Vec<(String, String)> = Vec::new();
    for c in re.captures_iter(s) {
        let k = c[1].to_ascii_lowercase();
        if out.iter().any(|(a, _)| *a == k) {
            continue;
        }
        let v = c.get(2).or(c.get(3)).or(c.get(4)).map(|m| decode_entities(m.as_str())).unwrap_or_default();
        out.push((k, v));
    }
    out
}

/// Find the end `>` of a tag starting at `i` (quotes respected).
fn tag_end(b: &[u8], mut i: usize) -> Option<usize> {
    let mut q = 0u8;
    while i < b.len() {
        let c = b[i];
        if q != 0 {
            if c == q {
                q = 0;
            }
        } else if c == b'"' || c == b'\'' {
            q = c;
        } else if c == b'>' {
            return Some(i);
        }
        i += 1;
    }
    None
}

pub fn tokenize(html: &str) -> Vec<Token> {
    let b = html.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let mut text_start = 0;
    let flush = |out: &mut Vec<Token>, a: usize, z: usize| {
        if z > a {
            out.push(Token::Text(html[a..z].to_string()));
        }
    };
    while i < b.len() {
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        let next = b.get(i + 1).copied().unwrap_or(0);
        if html[i..].starts_with("<!--") {
            flush(&mut out, text_start, i);
            i = html[i + 4..].find("-->").map(|e| i + 4 + e + 3).unwrap_or(b.len());
            text_start = i;
            continue;
        }
        if next == b'!' || next == b'?' {
            flush(&mut out, text_start, i);
            i = tag_end(b, i).map(|e| e + 1).unwrap_or(b.len());
            text_start = i;
            continue;
        }
        let closing = next == b'/';
        let ns = if closing { i + 2 } else { i + 1 };
        if !b.get(ns).is_some_and(|c| c.is_ascii_alphabetic()) {
            i += 1;
            continue;
        }
        let Some(end) = tag_end(b, ns) else {
            i += 1;
            continue;
        };
        flush(&mut out, text_start, i);
        let inner = &html[ns..end];
        let name_end = inner.find(|c: char| c.is_whitespace() || c == '/' || c == '>').unwrap_or(inner.len());
        let name = inner[..name_end].to_ascii_lowercase();
        i = end + 1;
        text_start = i;
        if closing {
            out.push(Token::End(name));
            continue;
        }
        let self_closing = inner.trim_end().ends_with('/');
        let attrs = parse_attrs(&inner[name_end..]);
        if RAW_TEXT.contains(&name.as_str()) && !self_closing {
            let close = format!("</{name}");
            let lower = html[i..].to_ascii_lowercase();
            let (content_end, after) = match lower.find(&close) {
                Some(p) => (i + p, tag_end(b, i + p).map(|e| e + 1).unwrap_or(b.len())),
                None => (b.len(), b.len()),
            };
            let raw = html[i..content_end].to_string();
            out.push(Token::Start { name: name.clone(), attrs, self_closing: false });
            if !raw.is_empty() {
                out.push(Token::Text(raw));
            }
            out.push(Token::End(name));
            i = after;
            text_start = i;
            continue;
        }
        out.push(Token::Start { name, attrs, self_closing });
    }
    flush(&mut out, text_start, b.len());
    out
}

// ── visibility ───────────────────────────────────────────────────────────────────

fn style_hidden(style: &str) -> bool {
    static RES: OnceLock<Vec<(Regex, Regex)>> = OnceLock::new();
    let res = RES.get_or_init(|| {
        let pats: &[(&str, &str)] = &[
            ("display", r"(?i)^\s*none\s*(!important)?\s*$"),
            ("visibility", r"(?i)^\s*hidden\s*(!important)?\s*$"),
            ("opacity", r"^\s*0(\.0+)?\s*(!important)?\s*$"),
            ("font-size", r"(?i)^\s*0(px|em|rem|pt|%)?\s*(!important)?\s*$"),
            ("text-indent", r"^\s*-\d{4,}px\s*$"),
            ("color", r"(?i)^\s*transparent\s*$"),
            ("color", r"(?i)^\s*rgba\s*\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*0(?:\.0+)?\s*\)\s*$"),
            ("color", r"(?i)^\s*hsla\s*\(\s*[\d.]+\s*,\s*[\d.]+%?\s*,\s*[\d.]+%?\s*,\s*0(?:\.0+)?\s*\)\s*$"),
            ("clip-path", r"(?i)inset\s*\(\s*(?:0*\.\d+|[1-9]\d*(?:\.\d+)?)%"),
            ("transform", r"(?i)scale\s*\(\s*0\s*\)|translate[XY]\s*\(\s*-\d{4,}px\s*\)"),
            ("left", r"(?i)^\s*-\d{4,}px\s*$"),
            ("top", r"(?i)^\s*-\d{4,}px\s*$"),
        ];
        pats.iter().map(|(p, v)| (Regex::new(&format!(r"(?i)(?:^|;)\s*{}\s*:\s*([^;]+)", regex::escape(p))).unwrap(), Regex::new(v).unwrap())).collect()
    });
    if res.iter().any(|(p, v)| p.captures(style).is_some_and(|c| v.is_match(&c[1]))) {
        return true;
    }
    let get = |prop: &str| Regex::new(&format!(r"(?i)(?:^|;)\s*{prop}\s*:\s*([^;]+)")).ok().and_then(|r| r.captures(style).map(|c| c[1].trim().to_ascii_lowercase()));
    let zero = |v: Option<String>| v.is_some_and(|v| v == "0" || v == "0px");
    zero(get("width")) && zero(get("height")) && get("overflow").as_deref() == Some("hidden")
}

pub fn attr<'a>(attrs: &'a [(String, String)], k: &str) -> Option<&'a str> {
    attrs.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str())
}

/// The element (and its subtree) is invisible or non-content.
pub fn hidden(tag: &str, attrs: &[(String, String)]) -> bool {
    if DROPPED.contains(&tag) {
        return true;
    }
    if attr(attrs, "hidden").is_some() || attr(attrs, "aria-hidden").is_some_and(|v| v.trim().eq_ignore_ascii_case("true")) {
        return true;
    }
    if attr(attrs, "class").is_some_and(|c| c.split_whitespace().any(|x| HIDDEN_CLASSES.contains(&x.to_ascii_lowercase().as_str()))) {
        return true;
    }
    attr(attrs, "style").is_some_and(style_hidden)
}

// ── tree ─────────────────────────────────────────────────────────────────────────

impl Doc {
    pub fn parse(html: &str) -> Doc {
        let mut d = Doc { nodes: vec![Node { kind: Kind::Element { tag: "#root".into(), attrs: vec![] }, parent: None, children: vec![] }], title: None, meta: vec![], lang: None };
        let mut stack: Vec<NodeId> = vec![ROOT];
        // While > 0 we are inside a hidden subtree: track its own nesting only.
        let mut hidden_depth = 0usize;
        let mut hidden_tag = String::new();
        let mut in_title = false;
        let tokens = tokenize(html);
        let tag_of = |d: &Doc, id: NodeId| match &d.nodes[id].kind {
            Kind::Element { tag, .. } => tag.clone(),
            _ => String::new(),
        };
        for t in tokens {
            match t {
                Token::Text(s) => {
                    if in_title {
                        let v = decode_entities(&s).split_whitespace().collect::<Vec<_>>().join(" ");
                        if d.title.is_none() && !v.is_empty() {
                            d.title = Some(v);
                        }
                        continue;
                    }
                    if hidden_depth > 0 {
                        continue;
                    }
                    let parent = *stack.last().unwrap();
                    let id = d.nodes.len();
                    d.nodes.push(Node { kind: Kind::Text(decode_entities(&s)), parent: Some(parent), children: vec![] });
                    d.nodes[parent].children.push(id);
                }
                Token::Start { name, attrs, self_closing } => {
                    if name == "title" {
                        in_title = !self_closing;
                        continue;
                    }
                    if name == "meta" {
                        let key = attr(&attrs, "name").or(attr(&attrs, "property")).map(|k| k.to_ascii_lowercase());
                        if let (Some(k), Some(v)) = (key, attr(&attrs, "content")) {
                            d.meta.push((k, v.trim().to_string()));
                        }
                    }
                    if name == "html" {
                        d.lang = attr(&attrs, "lang").map(str::to_string);
                    }
                    let void = VOID.contains(&name.as_str()) || self_closing;
                    if hidden_depth > 0 {
                        if name == hidden_tag && !void {
                            hidden_depth += 1;
                        }
                        continue;
                    }
                    if hidden(&name, &attrs) {
                        if !void {
                            hidden_depth = 1;
                            hidden_tag = name;
                        }
                        continue;
                    }
                    if matches!(name.as_str(), "html" | "body") {
                        continue;
                    }
                    // Implied end tags.
                    let close_through = |stack: &mut Vec<NodeId>, d: &Doc, names: &[&str], stop: &[&str]| {
                        for i in (1..stack.len()).rev() {
                            let t = tag_of(d, stack[i]);
                            if names.contains(&t.as_str()) {
                                stack.truncate(i);
                                return;
                            }
                            if stop.contains(&t.as_str()) {
                                return;
                            }
                        }
                    };
                    if CLOSES_P.contains(&name.as_str()) {
                        close_through(&mut stack, &d, &["p"], &["div", "td", "th", "li", "blockquote", "section", "article", "table", "button"]);
                    }
                    match name.as_str() {
                        "li" => close_through(&mut stack, &d, &["li"], &["ul", "ol", "menu"]),
                        "dt" | "dd" => close_through(&mut stack, &d, &["dt", "dd"], &["dl"]),
                        "td" | "th" => close_through(&mut stack, &d, &["td", "th"], &["tr", "table"]),
                        "tr" => close_through(&mut stack, &d, &["tr"], &["table", "tbody", "thead", "tfoot"]),
                        "tbody" | "thead" | "tfoot" => close_through(&mut stack, &d, &["tbody", "thead", "tfoot"], &["table"]),
                        _ => {}
                    }
                    let parent = *stack.last().unwrap();
                    let id = d.nodes.len();
                    d.nodes.push(Node { kind: Kind::Element { tag: name, attrs }, parent: Some(parent), children: vec![] });
                    d.nodes[parent].children.push(id);
                    if !void {
                        stack.push(id);
                    }
                }
                Token::End(name) => {
                    if name == "title" {
                        in_title = false;
                        continue;
                    }
                    if hidden_depth > 0 {
                        if name == hidden_tag {
                            hidden_depth -= 1;
                        }
                        continue;
                    }
                    if let Some(i) = (1..stack.len()).rev().find(|&i| tag_of(&d, stack[i]) == name) {
                        stack.truncate(i);
                    }
                }
            }
        }
        d
    }

    pub fn tag(&self, id: NodeId) -> &str {
        match &self.nodes[id].kind {
            Kind::Element { tag, .. } => tag,
            Kind::Text(_) => "#text",
        }
    }
    pub fn attr(&self, id: NodeId, k: &str) -> Option<&str> {
        match &self.nodes[id].kind {
            Kind::Element { attrs, .. } => attr(attrs, k),
            _ => None,
        }
    }
    pub fn is_text(&self, id: NodeId) -> bool {
        matches!(self.nodes[id].kind, Kind::Text(_))
    }
    /// Concatenated text of the subtree.
    pub fn text(&self, id: NodeId) -> String {
        let mut s = String::new();
        self.collect_text(id, &mut s);
        s
    }
    fn collect_text(&self, id: NodeId, out: &mut String) {
        match &self.nodes[id].kind {
            Kind::Text(t) => out.push_str(t),
            Kind::Element { tag, .. } => {
                if tag == "br" {
                    out.push('\n');
                }
                for &c in &self.nodes[id].children {
                    self.collect_text(c, out);
                }
            }
        }
    }
    /// Whitespace-collapsed text length (chars).
    pub fn text_len(&self, id: NodeId) -> usize {
        self.text(id).split_whitespace().map(|w| w.chars().count() + 1).sum::<usize>().saturating_sub(1)
    }
    /// All element descendants (pre-order) with the given tag(s).
    pub fn find(&self, id: NodeId, tags: &[&str]) -> Vec<NodeId> {
        let mut out = Vec::new();
        let mut st: Vec<NodeId> = self.nodes[id].children.iter().rev().copied().collect();
        while let Some(n) = st.pop() {
            if tags.contains(&self.tag(n)) {
                out.push(n);
            }
            st.extend(self.nodes[n].children.iter().rev());
        }
        out
    }
    /// Detach a node from its parent.
    pub fn remove(&mut self, id: NodeId) {
        if let Some(p) = self.nodes[id].parent.take() {
            self.nodes[p].children.retain(|&c| c != id);
        }
    }
    /// Is `id` still attached under ROOT?
    pub fn attached(&self, mut id: NodeId) -> bool {
        while id != ROOT {
            match self.nodes[id].parent {
                Some(p) => id = p,
                None => return false,
            }
        }
        true
    }
    pub fn meta(&self, keys: &[&str]) -> Option<String> {
        keys.iter().find_map(|k| self.meta.iter().find(|(a, _)| a == k).map(|(_, v)| decode_entities(v))).filter(|s| !s.is_empty())
    }
    /// The `<body>` equivalent: ROOT (html/body wrappers are not materialised).
    pub fn body(&self) -> NodeId {
        ROOT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entities() {
        assert_eq!(decode_entities("a &amp; b &lt;c&gt; &#39;x&#x27; &nbsp;&hellip; &#150; &bogus; & &copy"), "a & b <c> 'x'  … – &bogus; & ©");
        assert_eq!(decode_entities("&#0;&#128512;"), "\u{fffd}😀");
    }

    #[test]
    fn tokenizer_handles_raw_text_and_quotes() {
        let t = tokenize(r#"<p class="a>b">x<script>if (a<b) {"</p>"}</script><!-- c --><br/>y</p>"#);
        assert_eq!(t[0], Token::Start { name: "p".into(), attrs: vec![("class".into(), "a>b".into())], self_closing: false });
        assert!(t.contains(&Token::Text("if (a<b) {\"</p>\"}".into())));
        assert!(t.contains(&Token::Start { name: "br".into(), attrs: vec![], self_closing: true }));
        assert_eq!(tokenize("a < b <3"), vec![Token::Text("a < b <3".into())]);
    }

    #[test]
    fn tree_drops_hidden_content_and_implies_end_tags() {
        let d = Doc::parse(
            r#"<html lang="en"><head><title>T &amp; U</title><meta name="description" content="Desc"></head><body>
            <p>one<p>two
            <div style="display:none">secret instructions</div>
            <span class="sr-only">sr</span><div aria-hidden="true"><div>nested</div></div>
            <p style="font-size:0">zero</p><p style="position:absolute;left:-9999px">off</p>
            <template>tpl</template><input type="hidden" value="v">
            <ul><li>a<li>b</ul><p hidden>h</p>visible</body></html>"#,
        );
        let text = d.text(ROOT);
        assert_eq!((d.title.as_deref(), d.lang.as_deref(), d.meta(&["description"]).as_deref()), (Some("T & U"), Some("en"), Some("Desc")));
        assert!(!d.find(ROOT, &["p"]).iter().any(|&p| d.text(p) == "h"));
        for bad in ["secret", "sr", "nested", "zero", "off", "tpl"] {
            assert!(!text.contains(bad), "{bad} leaked: {text}");
        }
        assert!(text.contains("one") && text.contains("two") && text.contains("visible"));
        let ps = d.find(ROOT, &["p"]);
        assert_eq!(d.text(ps[0]), "one", "second <p> closes the first");
        let lis = d.find(ROOT, &["li"]);
        assert_eq!((lis.len(), d.text(lis[0]).as_str()), (2, "a"));
    }

    #[test]
    fn style_rules() {
        for s in ["display: none", "visibility:hidden", "opacity:0", "color: rgba(0,0,0,0)", "width:0;height:0;overflow:hidden", "transform: scale(0)", "clip-path: inset(50%)"] {
            assert!(style_hidden(s), "{s}");
        }
        for s in ["display:block", "opacity:0.5", "clip-path: inset(0%)", "width:0;height:10px;overflow:hidden"] {
            assert!(!style_hidden(s), "{s}");
        }
    }
}
