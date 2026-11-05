//! Main-content extraction in the manner of Mozilla Readability (used by OpenClaw
//! `extensions/web-readability`): drop unlikely candidates, score paragraphs into their
//! ancestors (commas, length, class/id weight, link density), pick the top candidate plus
//! qualifying siblings, clean the result conditionally; retry with relaxed flags when the
//! article is short. Rendered to Markdown or plain text.

use super::html::{Doc, NodeId, ROOT};
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Upstream bails out above these sizes (`READABILITY_MAX_HTML_CHARS`, nesting depth).
pub const MAX_HTML_CHARS: usize = 1_000_000;
const CHAR_THRESHOLD: usize = 500;
const TAGS_TO_SCORE: &[&str] = &["section", "h2", "h3", "h4", "h5", "h6", "p", "td", "pre"];
const BLOCKISH: &[&str] = &["a", "blockquote", "dl", "div", "img", "ol", "p", "pre", "table", "ul", "section", "article", "h1", "h2", "h3", "h4", "h5", "h6", "figure"];
const ALWAYS_DROP: &[&str] = &["nav", "aside", "footer", "form", "fieldset", "header", "menu"];

struct Res {
    unlikely: Regex,
    maybe: Regex,
    positive: Regex,
    negative: Regex,
}

fn res() -> &'static Res {
    static R: OnceLock<Res> = OnceLock::new();
    R.get_or_init(|| Res {
        unlikely: Regex::new(r"(?i)-ad-|ai2html|banner|breadcrumbs|combx|comment|community|cover-wrap|disqus|extra|footer|gdpr|header|legends|menu|related|remark|replies|rss|shoutbox|sidebar|skyscraper|social|sponsor|supplemental|ad-break|agegate|pagination|pager|popup|yom-remote").unwrap(),
        maybe: Regex::new(r"(?i)and|article|body|column|content|main|mathjax|shadow").unwrap(),
        positive: Regex::new(r"(?i)article|body|content|entry|hentry|h-entry|main|page|pagination|post|text|blog|story").unwrap(),
        negative: Regex::new(r"(?i)-ad-|hidden|^hid$| hid$| hid |^hid |banner|combx|comment|com-|contact|footer|gdpr|masthead|media|meta|outbrain|promo|related|scroll|share|shoutbox|sidebar|skyscraper|sponsor|shopping|tags|widget").unwrap(),
    })
}

fn match_string(d: &Doc, id: NodeId) -> String {
    format!("{} {}", d.attr(id, "class").unwrap_or(""), d.attr(id, "id").unwrap_or(""))
}

fn class_weight(d: &Doc, id: NodeId) -> f64 {
    let r = res();
    let mut w = 0.0;
    for v in [d.attr(id, "class"), d.attr(id, "id")].into_iter().flatten().filter(|v| !v.is_empty()) {
        if r.negative.is_match(v) {
            w -= 25.0;
        }
        if r.positive.is_match(v) {
            w += 25.0;
        }
    }
    w
}

fn base_score(tag: &str) -> f64 {
    match tag {
        "div" | "article" => 5.0,
        "pre" | "td" | "blockquote" => 3.0,
        "address" | "ol" | "ul" | "dl" | "dd" | "dt" | "li" | "form" => -3.0,
        "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "th" => -5.0,
        _ => 0.0,
    }
}

pub fn link_density(d: &Doc, id: NodeId) -> f64 {
    let len = d.text_len(id);
    if len == 0 {
        return 0.0;
    }
    let links: f64 = d.find(id, &["a"]).iter().map(|&a| {
        let coeff = if d.attr(a, "href").is_some_and(|h| h.trim_start().starts_with('#')) { 0.3 } else { 1.0 };
        d.text_len(a) as f64 * coeff
    }).sum();
    links / len as f64
}

fn ancestors(d: &Doc, id: NodeId, max: usize) -> Vec<NodeId> {
    let mut out = Vec::new();
    let mut cur = d.nodes[id].parent;
    while let Some(p) = cur {
        if p == ROOT || out.len() >= max {
            break;
        }
        out.push(p);
        cur = d.nodes[p].parent;
    }
    out
}

fn has_block_child(d: &Doc, id: NodeId) -> bool {
    d.nodes[id].children.iter().any(|&c| BLOCKISH.contains(&d.tag(c)) || has_block_child(d, c) && !d.is_text(c))
}

#[derive(Clone, Copy)]
struct Flags {
    strip_unlikely: bool,
    weight_classes: bool,
    clean_conditionally: bool,
}

fn grab(mut d: Doc, f: Flags) -> Option<(Doc, NodeId)> {
    let r = res();
    // 1. Remove unlikely candidates and chrome.
    let all: Vec<NodeId> = (1..d.nodes.len()).filter(|&i| !d.is_text(i)).collect();
    for id in all {
        if !d.attached(id) {
            continue;
        }
        let tag = d.tag(id).to_string();
        if ALWAYS_DROP.contains(&tag.as_str()) && !d.find(id, &["article", "main"]).iter().any(|_| true) {
            d.remove(id);
            continue;
        }
        let role = d.attr(id, "role").unwrap_or("").to_ascii_lowercase();
        if ["menu", "menubar", "complementary", "navigation", "alert", "alertdialog", "dialog"].contains(&role.as_str()) {
            d.remove(id);
            continue;
        }
        if f.strip_unlikely && !matches!(tag.as_str(), "body" | "a" | "article" | "main") {
            let ms = match_string(&d, id);
            if r.unlikely.is_match(&ms) && !r.maybe.is_match(&ms) && d.find(id, &["article", "main"]).is_empty() {
                d.remove(id);
            }
        }
    }
    // 2. Score paragraphs into ancestors.
    let mut scores: HashMap<NodeId, f64> = HashMap::new();
    let elems: Vec<NodeId> = (1..d.nodes.len()).filter(|&i| !d.is_text(i) && d.attached(i)).collect();
    for id in elems {
        let tag = d.tag(id);
        let scorable = TAGS_TO_SCORE.contains(&tag) || (tag == "div" && !has_block_child(&d, id));
        if !scorable {
            continue;
        }
        let text = d.text(id);
        let len = text.split_whitespace().map(|w| w.chars().count() + 1).sum::<usize>();
        if len < 25 {
            continue;
        }
        let anc = ancestors(&d, id, 5);
        if anc.is_empty() {
            continue;
        }
        let commas = text.matches([',', '，', '、', '،']).count() as f64;
        let score = 1.0 + commas + (len as f64 / 100.0).floor().min(3.0);
        for (level, &a) in anc.iter().enumerate() {
            let e = scores.entry(a).or_insert_with(|| base_score(d.tag(a)) + if f.weight_classes { class_weight(&d, a) } else { 0.0 });
            let div = match level {
                0 => 1.0,
                1 => 2.0,
                l => l as f64 * 3.0,
            };
            *e += score / div;
        }
    }
    // 3. Top candidate with link-density penalty.
    let mut ranked: Vec<(NodeId, f64)> = scores.iter().map(|(&id, &s)| (id, s * (1.0 - link_density(&d, id)))).collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal).then(a.0.cmp(&b.0)));
    let (mut top, top_score) = *ranked.first()?;
    // Promote to the parent when several near-top candidates share it (Readability's alternative-ancestor rule).
    let near: Vec<NodeId> = ranked.iter().skip(1).take(5).filter(|(_, s)| *s >= top_score * 0.75).map(|(id, _)| *id).collect();
    if near.len() >= 3 {
        if let Some(common) = ancestors(&d, top, 5).into_iter().find(|a| near.iter().filter(|&&n| ancestors(&d, n, 6).contains(a)).count() >= 3) {
            top = common;
        }
    }
    // 4. Siblings worth keeping.
    let threshold = (top_score * 0.2).max(10.0);
    let parent = d.nodes[top].parent.unwrap_or(ROOT);
    let top_class = d.attr(top, "class").unwrap_or("").to_string();
    let wrapper = d.nodes.len();
    d.nodes.push(super::html::Node { kind: super::html::Kind::Element { tag: "div".into(), attrs: vec![] }, parent: None, children: vec![] });
    for sib in d.nodes[parent].children.clone() {
        let keep = sib == top || {
            let mut bonus = 0.0;
            if !top_class.is_empty() && d.attr(sib, "class") == Some(top_class.as_str()) {
                bonus += top_score * 0.2;
            }
            let s = scores.get(&sib).copied().map(|s| s * (1.0 - link_density(&d, sib)));
            if s.is_some_and(|s| s + bonus >= threshold) {
                true
            } else if d.tag(sib) == "p" {
                let len = d.text_len(sib);
                let ld = link_density(&d, sib);
                let text = d.text(sib);
                (len > 80 && ld < 0.25) || (len < 80 && len > 0 && ld == 0.0 && (text.contains(". ") || text.trim_end().ends_with('.')))
            } else {
                false
            }
        };
        if keep {
            d.nodes[wrapper].children.push(sib);
        }
    }
    // 5. Conditional clean of the article.
    if f.clean_conditionally {
        for id in d.find(wrapper, &["form", "fieldset", "table", "ul", "ol", "div", "section"]) {
            if id == top {
                continue;
            }
            let w = if f.weight_classes { class_weight(&d, id) } else { 0.0 };
            let s = scores.get(&id).copied().unwrap_or(0.0);
            if w + s < 0.0 {
                d.remove(id);
                d.nodes[wrapper].children.retain(|&c| c != id);
                continue;
            }
            let text = d.text(id);
            if text.matches(',').count() >= 10 {
                continue;
            }
            let p = d.find(id, &["p"]).len() as f64;
            let img = d.find(id, &["img"]).len() as f64;
            let li = d.find(id, &["li"]).len() as f64 - 100.0;
            let input = d.find(id, &["input"]).len() as f64;
            let embeds = d.find(id, &["embed", "object", "iframe", "video"]).len();
            let len = d.text_len(id);
            let ld = link_density(&d, id);
            let tag = d.tag(id);
            let is_list = tag == "ul" || tag == "ol";
            let bad = (img > 1.0 && p / img < 0.5 && !d.find(id, &["figure"]).iter().any(|_| true))
                || (!is_list && li > p)
                || input > (p / 3.0).floor()
                || (!is_list && len < 25 && (img == 0.0 || img > 2.0) && d.find(id, &["pre", "code"]).is_empty())
                || (!is_list && w < 25.0 && ld > 0.2)
                || (w >= 25.0 && ld > 0.5)
                || ((embeds == 1 && len < 75) || embeds > 1);
            if bad && d.find(id, &["pre"]).is_empty() {
                d.remove(id);
                d.nodes[wrapper].children.retain(|&c| c != id);
            }
        }
    }
    Some((d, wrapper))
}

#[derive(Debug, Clone, PartialEq)]
pub struct Article {
    pub title: Option<String>,
    pub byline: Option<String>,
    pub excerpt: Option<String>,
    pub text: String,
}

/// Readability-style title: `<title>` trimmed of site suffixes when the remainder is meaningful.
pub fn article_title(d: &Doc) -> Option<String> {
    let og = d.meta(&["og:title", "twitter:title"]);
    let raw = d.title.clone().or(og.clone())?;
    for sep in [" | ", " - ", " – ", " — ", " :: ", " » ", " / "] {
        if let Some(i) = raw.rfind(sep) {
            let head = raw[..i].trim();
            if head.split_whitespace().count() >= 3 {
                return Some(head.to_string());
            }
            if let Some(o) = &og {
                if raw.starts_with(o.as_str()) {
                    return Some(o.clone());
                }
            }
        }
    }
    Some(raw)
}

/// Extract the main article; `text_mode` gives plain text instead of Markdown.
pub fn extract(html: &str, base: &str, text_mode: bool) -> Option<Article> {
    if html.len() > MAX_HTML_CHARS {
        return None;
    }
    let doc = Doc::parse(html);
    let title = article_title(&doc);
    let byline = doc.meta(&["author", "article:author", "dc.creator"]);
    let excerpt = doc.meta(&["description", "og:description", "twitter:description"]);
    let attempts = [
        Flags { strip_unlikely: true, weight_classes: true, clean_conditionally: true },
        Flags { strip_unlikely: false, weight_classes: true, clean_conditionally: true },
        Flags { strip_unlikely: false, weight_classes: false, clean_conditionally: true },
        Flags { strip_unlikely: false, weight_classes: false, clean_conditionally: false },
    ];
    let mut best: Option<String> = None;
    for f in attempts {
        let Some((d, root)) = grab(doc.clone(), f) else { continue };
        let md = super::markdown::render(&d, root, base);
        let md = md.trim_start_matches('\n').to_string();
        let len = md.chars().count();
        if best.as_ref().is_none_or(|b| len > b.chars().count()) {
            best = Some(md);
        }
        if len >= CHAR_THRESHOLD {
            break;
        }
    }
    let md = super::content::strip_invisible(&best?);
    let text = if text_mode { super::markdown::markdown_to_text(&md) } else { md };
    (!text.trim().is_empty()).then_some(Article { title, byline, excerpt, text })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page() -> String {
        let para = "Rust is a systems programming language that runs blazingly fast, prevents segfaults, and guarantees thread safety. It accomplishes these goals without a garbage collector, which makes it useful for many things.";
        format!(
            r#"<html><head><title>Why Rust Matters Today | Example Blog</title><meta name="author" content="Ferris"><meta name="description" content="An essay."></head><body>
            <header class="site-header"><a href="/">Home</a> <a href="/about">About</a></header>
            <nav><ul><li><a href="/a">A</a></li><li><a href="/b">B</a></li></ul></nav>
            <div class="sidebar"><p>Subscribe to our newsletter, it is great, really, truly, honestly, we promise.</p></div>
            <div id="main-content" class="post"><h1>Why Rust Matters</h1><p>{para}</p><p>{para}</p><p>Read the <a href="/docs">docs</a>, then build something, test it, and ship it.</p><pre><code>fn main() {{}}</code></pre></div>
            <div class="comments"><p>Great post, thanks, love it, agree, nice, cool, wow, yes.</p></div>
            <footer>© 2025 Example, all rights reserved, forever, and ever.</footer></body></html>"#
        )
    }

    #[test]
    fn finds_main_content() {
        let a = extract(&page(), "https://blog.example/post/1", false).unwrap();
        assert_eq!((a.title.as_deref(), a.byline.as_deref(), a.excerpt.as_deref()), (Some("Why Rust Matters Today"), Some("Ferris"), Some("An essay.")));
        assert!(a.text.contains("blazingly fast") && a.text.contains("[docs](https://blog.example/docs)") && a.text.contains("```\nfn main() {}\n```"), "{}", a.text);
        for junk in ["newsletter", "Great post", "rights reserved", "About"] {
            assert!(!a.text.contains(junk), "{junk} leaked:\n{}", a.text);
        }
        let t = extract(&page(), "", true).unwrap();
        assert!(t.text.contains("Read the docs, then") && !t.text.contains("]("));
    }

    #[test]
    fn short_and_degenerate_pages() {
        let a = extract("<p>Just one short line.</p>", "", false);
        assert!(a.is_none() || a.unwrap().text.contains("short line"));
        assert!(extract(&"x".repeat(MAX_HTML_CHARS + 1), "", false).is_none());
        let d = Doc::parse("<div><a href='#x'>aaaa</a> bbbb</div>");
        assert!(link_density(&d, d.find(ROOT, &["div"])[0]) < 0.5);
    }
}
