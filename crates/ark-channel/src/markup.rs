//! Convert the model's CommonMark to each platform's dialect: Telegram HTML,
//! Slack mrkdwn, Matrix/Teams HTML, Discord (CommonMark-ish, passthrough) or
//! plain text. Handles the subset models actually produce: fenced and inline
//! code, bold, italic, strikethrough, links, headings, quotes and lists.
//! Anything unrecognised passes through as text, escaped for HTML targets.

use crate::Markup;

#[derive(Debug, Clone, PartialEq)]
enum Span {
    Text(String),
    Code(String),
    Bold(Vec<Span>),
    Italic(Vec<Span>),
    Strike(Vec<Span>),
    Link(Vec<Span>, String),
}

fn parse_inline(s: &str) -> Vec<Span> {
    let c: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut text = String::new();
    let mut i = 0;
    let flush = |text: &mut String, out: &mut Vec<Span>| {
        if !text.is_empty() {
            out.push(Span::Text(std::mem::take(text)));
        }
    };
    let find = |from: usize, pat: &[char]| -> Option<usize> { (from..c.len().saturating_sub(pat.len() - 1)).find(|&j| c[j..j + pat.len()] == *pat) };
    while i < c.len() {
        let rest = &c[i..];
        if rest[0] == '\\' && rest.len() > 1 && "\\`*_~[]()#>".contains(rest[1]) {
            text.push(rest[1]);
            i += 2;
            continue;
        }
        if rest[0] == '`' {
            if let Some(j) = find(i + 1, &['`']) {
                flush(&mut text, &mut out);
                out.push(Span::Code(c[i + 1..j].iter().collect()));
                i = j + 1;
                continue;
            }
        }
        let mut matched = false;
        for (open, kind) in [(&['*', '*'][..], 0), (&['_', '_'][..], 0), (&['~', '~'][..], 2), (&['*'][..], 1), (&['_'][..], 1)] {
            if rest.starts_with(open) {
                let after = i + open.len();
                // Opening delimiter must be followed by non-space; `_` inside words is literal.
                if after < c.len() && !c[after].is_whitespace() && !((open[0] == '_' || open.len() == 1) && i > 0 && c[i - 1].is_alphanumeric()) {
                    if let Some(j) = find(after, open).filter(|&j| j > after && !c[j - 1].is_whitespace()) {
                        flush(&mut text, &mut out);
                        let inner = parse_inline(&c[after..j].iter().collect::<String>());
                        out.push(match kind {
                            0 => Span::Bold(inner),
                            1 => Span::Italic(inner),
                            _ => Span::Strike(inner),
                        });
                        i = j + open.len();
                        matched = true;
                        break;
                    }
                }
            }
        }
        if matched {
            continue;
        }
        if rest[0] == '[' {
            if let Some(j) = find(i + 1, &[']', '(']) {
                if let Some(k) = find(j + 2, &[')']) {
                    let url: String = c[j + 2..k].iter().collect();
                    if !url.contains(char::is_whitespace) {
                        flush(&mut text, &mut out);
                        out.push(Span::Link(parse_inline(&c[i + 1..j].iter().collect::<String>()), url));
                        i = k + 1;
                        continue;
                    }
                }
            }
        }
        text.push(rest[0]);
        i += 1;
    }
    flush(&mut text, &mut out);
    out
}

pub fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn render(spans: &[Span], m: Markup) -> String {
    let mut o = String::new();
    for sp in spans {
        match (sp, m) {
            (Span::Text(t), Markup::TelegramHtml | Markup::MatrixHtml) => o.push_str(&escape_html(t)),
            (Span::Text(t), Markup::SlackMrkdwn) => o.push_str(&t.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")),
            (Span::Text(t), _) => o.push_str(t),
            (Span::Code(t), Markup::TelegramHtml | Markup::MatrixHtml) => o.push_str(&format!("<code>{}</code>", escape_html(t))),
            (Span::Code(t), Markup::Plain) => o.push_str(t),
            (Span::Code(t), _) => o.push_str(&format!("`{t}`")),
            (Span::Bold(i), Markup::TelegramHtml | Markup::MatrixHtml) => o.push_str(&format!("<b>{}</b>", render(i, m))),
            (Span::Bold(i), Markup::SlackMrkdwn) => o.push_str(&format!("*{}*", render(i, m))),
            (Span::Bold(i), Markup::Plain) => o.push_str(&render(i, m)),
            (Span::Bold(i), _) => o.push_str(&format!("**{}**", render(i, m))),
            (Span::Italic(i), Markup::TelegramHtml | Markup::MatrixHtml) => o.push_str(&format!("<i>{}</i>", render(i, m))),
            (Span::Italic(i), Markup::Plain) => o.push_str(&render(i, m)),
            (Span::Italic(i), _) => o.push_str(&format!("_{}_", render(i, m))),
            (Span::Strike(i), Markup::TelegramHtml | Markup::MatrixHtml) => o.push_str(&format!("<s>{}</s>", render(i, m))),
            (Span::Strike(i), Markup::SlackMrkdwn) => o.push_str(&format!("~{}~", render(i, m))),
            (Span::Strike(i), Markup::Plain) => o.push_str(&render(i, m)),
            (Span::Strike(i), _) => o.push_str(&format!("~~{}~~", render(i, m))),
            (Span::Link(t, u), Markup::TelegramHtml | Markup::MatrixHtml) => o.push_str(&format!("<a href=\"{}\">{}</a>", escape_html(u).replace('"', "&quot;"), render(t, m))),
            (Span::Link(t, u), Markup::SlackMrkdwn) => o.push_str(&format!("<{u}|{}>", render(t, m))),
            (Span::Link(t, u), Markup::Plain) => {
                let label = render(t, m);
                if label == *u {
                    o.push_str(u)
                } else {
                    o.push_str(&format!("{label} ({u})"))
                }
            }
            (Span::Link(t, u), _) => o.push_str(&format!("[{}]({u})", render(t, m))),
        }
    }
    o
}

/// Convert CommonMark text to the target dialect.
pub fn convert(md: &str, m: Markup) -> String {
    if m == Markup::Markdown || m == Markup::DiscordMarkdown {
        return md.to_string();
    }
    let html = matches!(m, Markup::TelegramHtml | Markup::MatrixHtml);
    let mut out: Vec<String> = Vec::new();
    let mut lines = md.lines().peekable();
    while let Some(line) = lines.next() {
        let t = line.trim_start();
        if let Some(lang) = t.strip_prefix("```") {
            let mut body = Vec::new();
            for l in lines.by_ref() {
                if l.trim_start().starts_with("```") {
                    break;
                }
                body.push(l);
            }
            let code = body.join("\n");
            out.push(match m {
                Markup::TelegramHtml if !lang.trim().is_empty() => format!("<pre><code class=\"language-{}\">{}</code></pre>", escape_html(lang.trim()), escape_html(&code)),
                Markup::TelegramHtml | Markup::MatrixHtml => format!("<pre><code>{}</code></pre>", escape_html(&code)),
                Markup::SlackMrkdwn => format!("```\n{code}\n```"),
                _ => code,
            });
            continue;
        }
        let hashes = t.chars().take_while(|&c| c == '#').count();
        if (1..=6).contains(&hashes) && t[hashes..].starts_with(' ') {
            let inner = parse_inline(t[hashes..].trim());
            out.push(render(&[Span::Bold(inner)], m));
            continue;
        }
        if let Some(q) = t.strip_prefix('>') {
            let body = render(&parse_inline(q.trim_start()), m);
            out.push(match m {
                Markup::TelegramHtml => format!("<blockquote>{body}</blockquote>"),
                Markup::MatrixHtml => format!("<blockquote>{body}</blockquote>"),
                Markup::SlackMrkdwn => format!("> {body}"),
                _ => format!("> {body}"),
            });
            continue;
        }
        let (bullet, rest) = if let Some(r) = t.strip_prefix("- ").or_else(|| t.strip_prefix("* ")).or_else(|| t.strip_prefix("+ ")) {
            ("• ", r)
        } else {
            ("", t)
        };
        let indent = &line[..line.len() - t.len()];
        out.push(format!("{indent}{bullet}{}", render(&parse_inline(rest), m)));
    }
    let joined = out.join(if m == Markup::MatrixHtml { "<br>" } else { "\n" });
    // Telegram collapses adjacent blockquotes oddly; keep them as written.
    if html {
        joined.replace("</blockquote><br><blockquote>", "<br>")
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telegram_html() {
        let md = "# Title\nHello **bold** and *it* and `x<y` and ~~old~~ [site](https://e.com?a=1&b=2)\n```rust\nfn a() -> u8 { 1 < 2 }\n```\n- item\n> quote";
        let h = convert(md, Markup::TelegramHtml);
        assert!(h.starts_with("<b>Title</b>\n"), "{h}");
        assert!(h.contains("<b>bold</b>") && h.contains("<i>it</i>") && h.contains("<code>x&lt;y</code>") && h.contains("<s>old</s>"), "{h}");
        assert!(h.contains("<a href=\"https://e.com?a=1&amp;b=2\">site</a>"), "{h}");
        assert!(h.contains("<pre><code class=\"language-rust\">fn a() -&gt; u8 { 1 &lt; 2 }</code></pre>"), "{h}");
        assert!(h.contains("• item") && h.contains("<blockquote>quote</blockquote>"), "{h}");
    }

    #[test]
    fn slack_plain_and_edge_cases() {
        let s = convert("**b** _i_ ~~s~~ [t](http://u) a<b", Markup::SlackMrkdwn);
        assert_eq!(s, "*b* _i_ ~s~ <http://u|t> a&lt;b");
        assert_eq!(convert("**b** [t](http://u) `c`", Markup::Plain), "b t (http://u) c");
        assert_eq!(convert("snake_case_name and 2*3*4", Markup::TelegramHtml), "snake_case_name and 2*3*4", "no false emphasis");
        assert_eq!(convert("\\*not bold\\*", Markup::Plain), "*not bold*");
        assert_eq!(convert("unclosed **bold", Markup::TelegramHtml), "unclosed **bold");
        assert_eq!(convert("x", Markup::DiscordMarkdown), "x");
        assert_eq!(convert("a\nb", Markup::MatrixHtml), "a<br>b");
    }
}
