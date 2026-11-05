//! HTML subtree → Markdown, and Markdown → plain text (OpenClaw `web-fetch-utils.ts`
//! `htmlToMarkdown` / `markdownToText` / `normalizeWhitespace`).

use super::html::{Doc, Kind, NodeId};
use super::ssrf::join_url;
use regex::Regex;
use std::sync::OnceLock;

const BLOCK: &[&str] = &["p", "div", "section", "article", "header", "footer", "main", "aside", "nav", "figure", "figcaption", "form", "fieldset", "address", "details", "summary", "dl", "dt", "dd", "center"];

/// Trim line ends, collapse 3+ newlines and inner space runs; leading indentation and
/// fenced code blocks are kept as they are.
pub fn normalize_whitespace(s: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let inner = RE.get_or_init(|| Regex::new(r"(\S)[ \t]{2,}").unwrap());
    let mut out: Vec<String> = Vec::new();
    let mut fence = false;
    let mut blanks = 0;
    for line in s.replace('\r', "").split('\n') {
        if line.trim_start().starts_with("```") {
            fence = !fence;
        }
        let l = if fence || line.trim_start().starts_with("```") { line.trim_end().to_string() } else { inner.replace_all(line.trim_end(), "$1 ").into_owned() };
        if l.trim().is_empty() && !fence {
            blanks += 1;
            if blanks > 1 {
                continue;
            }
            out.push(String::new());
        } else {
            blanks = 0;
            out.push(l);
        }
    }
    out.join("\n").trim_matches(|c: char| c == '\n' || c == ' ' || c == '\t').to_string()
}

struct R<'a> {
    d: &'a Doc,
    base: &'a str,
    out: String,
    list: Vec<(bool, usize)>,
    pre: usize,
}

impl R<'_> {
    fn nl(&mut self, n: usize) {
        let have = self.out.chars().rev().take_while(|c| *c == '\n').count();
        if self.out.is_empty() {
            return;
        }
        for _ in have..n {
            self.out.push('\n');
        }
    }
    fn url(&self, u: &str) -> String {
        let u = u.trim();
        if u.is_empty() || u.starts_with('#') || u.starts_with("javascript:") || u.starts_with("data:") || u.starts_with("mailto:") || self.base.is_empty() {
            return u.to_string();
        }
        join_url(self.base, u)
    }
    fn inline(&self, id: NodeId) -> String {
        let mut r = R { d: self.d, base: self.base, out: String::new(), list: vec![], pre: self.pre };
        r.children(id);
        r.out.split_whitespace().collect::<Vec<_>>().join(" ")
    }
    fn children(&mut self, id: NodeId) {
        for &c in &self.d.nodes[id].children.clone() {
            self.node(c);
        }
    }
    fn node(&mut self, id: NodeId) {
        let tag = match &self.d.nodes[id].kind {
            Kind::Text(t) => {
                if self.pre > 0 {
                    self.out.push_str(t);
                } else {
                    let collapsed: String = t.chars().map(|c| if c.is_whitespace() { ' ' } else { c }).collect();
                    let prev_space = self.out.ends_with([' ', '\n']) || self.out.is_empty();
                    let mut s = collapsed.split(' ').filter(|x| !x.is_empty()).collect::<Vec<_>>().join(" ");
                    if collapsed.starts_with(' ') && !prev_space && !s.is_empty() {
                        s.insert(0, ' ');
                    }
                    if (collapsed.ends_with(' ') && !s.is_empty()) || (s.is_empty() && !collapsed.is_empty() && !prev_space) {
                        s.push(' ');
                    }
                    self.out.push_str(&s);
                }
                return;
            }
            Kind::Element { tag, .. } => tag.clone(),
        };
        match tag.as_str() {
            "br" => self.out.push('\n'),
            "hr" => {
                self.nl(2);
                self.out.push_str("---");
                self.nl(2);
            }
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                let t = self.inline(id);
                if !t.is_empty() {
                    self.nl(2);
                    self.out.push_str(&format!("{} {t}", "#".repeat(tag[1..].parse().unwrap_or(1))));
                    self.nl(2);
                }
            }
            "a" => {
                let t = self.inline(id);
                let href = self.d.attr(id, "href").map(|h| self.url(h)).unwrap_or_default();
                if !t.is_empty() && !href.is_empty() && !href.starts_with('#') && !href.starts_with("javascript:") {
                    self.out.push_str(&format!("[{t}]({href})"));
                } else {
                    self.out.push_str(&t);
                }
            }
            "img" => {
                let src = self.d.attr(id, "src").or(self.d.attr(id, "data-src")).map(|s| self.url(s)).unwrap_or_default();
                let alt = self.d.attr(id, "alt").unwrap_or("").trim().to_string();
                if !src.is_empty() {
                    self.out.push_str(&format!("![{alt}]({src})"));
                }
            }
            "strong" | "b" => {
                let t = self.inline(id);
                if !t.is_empty() {
                    self.out.push_str(&format!("**{t}**"));
                }
            }
            "em" | "i" => {
                let t = self.inline(id);
                if !t.is_empty() {
                    self.out.push_str(&format!("_{t}_"));
                }
            }
            "code" if self.pre == 0 => {
                let t = self.d.text(id);
                if !t.trim().is_empty() {
                    self.out.push_str(&format!("`{}`", t.trim()));
                }
            }
            "pre" => {
                self.nl(2);
                let lang = self.d.find(id, &["code"]).first().and_then(|&c| self.d.attr(c, "class")).and_then(|c| c.split_whitespace().find_map(|x| x.strip_prefix("language-"))).unwrap_or("").to_string();
                self.out.push_str(&format!("```{lang}\n{}\n```", self.d.text(id).trim_end_matches('\n')));
                self.nl(2);
            }
            "ul" | "ol" | "menu" => {
                self.list.push((tag == "ol", 0));
                self.nl(if self.list.len() > 1 { 1 } else { 2 });
                self.children(id);
                self.list.pop();
                self.nl(2);
            }
            "li" => {
                self.nl(1);
                let depth = self.list.len().saturating_sub(1);
                let marker = match self.list.last_mut() {
                    Some((true, n)) => {
                        *n += 1;
                        format!("{n}.")
                    }
                    _ => "-".into(),
                };
                self.out.push_str(&format!("{}{marker} ", "  ".repeat(depth)));
                self.children(id);
            }
            "blockquote" => {
                let mut r = R { d: self.d, base: self.base, out: String::new(), list: vec![], pre: 0 };
                r.children(id);
                let q = normalize_whitespace(&r.out);
                if !q.is_empty() {
                    self.nl(2);
                    self.out.push_str(&q.lines().map(|l| format!("> {l}")).collect::<Vec<_>>().join("\n"));
                    self.nl(2);
                }
            }
            "table" => self.table(id),
            t if BLOCK.contains(&t) => {
                self.nl(2);
                self.children(id);
                self.nl(2);
            }
            _ => self.children(id),
        }
    }
    fn table(&mut self, id: NodeId) {
        let rows: Vec<Vec<String>> = self.d.find(id, &["tr"]).into_iter().map(|tr| self.d.nodes[tr].children.iter().filter(|&&c| matches!(self.d.tag(c), "td" | "th")).map(|&c| self.inline(c).replace('|', "\\|")).collect::<Vec<_>>()).filter(|r: &Vec<String>| !r.is_empty()).collect();
        if rows.is_empty() {
            return;
        }
        let w = rows.iter().map(|r| r.len()).max().unwrap_or(1);
        self.nl(2);
        for (i, r) in rows.iter().enumerate() {
            let mut cells = r.clone();
            cells.resize(w, String::new());
            self.out.push_str(&format!("| {} |\n", cells.join(" | ")));
            if i == 0 {
                self.out.push_str(&format!("|{}\n", " --- |".repeat(w)));
            }
        }
        self.nl(2);
    }
}

/// Render the subtree at `id` (its children) as Markdown; relative links resolve against `base`.
pub fn render(d: &Doc, id: NodeId, base: &str) -> String {
    let mut r = R { d, base, out: String::new(), list: vec![], pre: 0 };
    if matches!(d.tag(id), "#root") {
        r.children(id);
    } else {
        r.node(id);
    }
    normalize_whitespace(&r.out)
}

/// Whole-document conversion (no main-content detection): `(markdown, title)`.
pub fn html_to_markdown(html: &str, base: &str) -> (String, Option<String>) {
    let d = Doc::parse(html);
    (super::content::strip_invisible(&render(&d, super::html::ROOT, base)), d.title.clone())
}

/// Markdown → plain text: drop images, keep link text, unwrap code spans, strip heading/list markers.
pub fn markdown_to_text(md: &str) -> String {
    static RES: OnceLock<[Regex; 6]> = OnceLock::new();
    let [img, link, code, head, bullet, num] = RES.get_or_init(|| {
        [
            Regex::new(r"!\[[^\]]*]\([^)]+\)").unwrap(),
            Regex::new(r"\[([^\]]+)]\([^)]+\)").unwrap(),
            Regex::new(r"`([^`]+)`").unwrap(),
            Regex::new(r"(?m)^#{1,6}\s+").unwrap(),
            Regex::new(r"(?m)^[ \t]*[-*+]\s+").unwrap(),
            Regex::new(r"(?m)^[ \t]*\d+\.\s+").unwrap(),
        ]
    });
    // Fenced code is kept literally.
    let mut blocks = Vec::new();
    let mut prose = String::new();
    let mut rest = md;
    while let Some(i) = rest.find("```") {
        prose.push_str(&rest[..i]);
        let after = &rest[i + 3..];
        let body_start = after.find('\n').map(|n| n + 1).unwrap_or(0);
        let (code_body, next) = match after[body_start..].find("```") {
            Some(e) => (&after[body_start..body_start + e], &after[body_start + e + 3..]),
            None => (&after[body_start..], ""),
        };
        prose.push_str(&format!("\u{0}{}\u{0}", blocks.len()));
        blocks.push(code_body.trim_end_matches('\n').to_string());
        rest = next;
    }
    prose.push_str(rest);
    let t = img.replace_all(&prose, "");
    let t = link.replace_all(&t, "$1");
    let t = code.replace_all(&t, "$1");
    let t = head.replace_all(&t, "");
    let t = bullet.replace_all(&t, "");
    let t = num.replace_all(&t, "");
    let mut out = normalize_whitespace(&t);
    for (i, b) in blocks.iter().enumerate() {
        out = out.replace(&format!("\u{0}{i}\u{0}"), b);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_common_markup() {
        let html = r#"<title>Doc</title><h1>Head</h1><p>Hello <b>bold</b> and <a href="/x">link</a>.<br>Next</p>
            <ul><li>one</li><li>two<ol><li>a</li></ol></li></ul><pre><code class="language-rs">fn x() {}
  y</code></pre><blockquote><p>quote</p></blockquote><img src="i.png" alt="pic">
            <table><tr><th>k</th><th>v</th></tr><tr><td>a|b</td><td>2</td></tr></table><p>code <code>z()</code></p>"#;
        let (md, title) = html_to_markdown(html, "https://ex.com/dir/page");
        assert_eq!(title.as_deref(), Some("Doc"));
        for want in ["# Head", "Hello **bold** and [link](https://ex.com/x).\nNext", "- one", "- two", "  1. a", "```rs\nfn x() {}\n  y\n```", "> quote", "![pic](https://ex.com/dir/i.png)", "| k | v |", "| --- | --- |", "| a\\|b | 2 |", "code `z()`"] {
            assert!(md.contains(want), "missing {want:?} in:\n{md}");
        }
    }

    #[test]
    fn markdown_to_plain_text() {
        let t = markdown_to_text("# T\n\n- item [x](http://u)\n1. n ![i](p)\n\n```\n# not a heading\n```\n`c`");
        assert_eq!(t, "T\n\nitem x\nn \n\n# not a heading\nc".replace(" \n", "\n"));
        assert_eq!(normalize_whitespace("a  b \n\n\n\nc\r"), "a b\n\nc");
    }
}
