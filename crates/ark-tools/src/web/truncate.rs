//! Long-page handling for `web_extract` / `web_fetch` (Hermes `tools/web_tools_truncate.py`,
//! OpenClaw `spillWebFetchContent`): char-budget clamping, inline base64 images → `[IMAGE: alt]`,
//! raw-binary payload detection, and the head (~75 %) + tail (~25 %) window whose footer
//! names the spilled full-text file and the `read` call that pages the omitted middle.

use regex::Regex;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const DEFAULT_CHAR_LIMIT: usize = 15_000;
pub const CHAR_LIMIT_FLOOR: usize = 2_000;
pub const CHAR_LIMIT_CEILING: usize = 500_000;
/// Ceiling on a spilled full-text file (a multi-MB page must not write unbounded bytes).
pub const MAX_STORED_TEXT_CHARS: usize = super::cache::MAX_STORED_TEXT_CHARS;

/// Clamp to [2 000, 500 000]: below 2k the footer dominates, a typo must not blow up context.
pub fn clamp_char_limit(v: usize) -> usize {
    v.clamp(CHAR_LIMIT_FLOOR, CHAR_LIMIT_CEILING)
}

/// Model-supplied `char_limit` (number or numeric string), else `default`; clamped.
pub fn effective_char_limit(v: Option<&serde_json::Value>, default: usize) -> usize {
    let n = v.and_then(|x| x.as_f64().or_else(|| x.as_str().and_then(|s| s.trim().parse().ok()))).filter(|f| f.is_finite() && *f >= 0.0);
    clamp_char_limit(n.map(|f| f as usize).unwrap_or(default))
}

pub fn char_len(s: &str) -> usize {
    s.chars().count()
}

/// First `n` chars.
pub fn head_chars(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// Last `n` chars.
pub fn tail_chars(s: &str, n: usize) -> &str {
    let total = char_len(s);
    if n >= total {
        return s;
    }
    let (i, _) = s.char_indices().nth(total - n).unwrap_or((0, ' '));
    &s[i..]
}

/// Inline base64 images (token bombs) → `[IMAGE: alt]` / `[IMAGE]`; real http(s) image links stay.
pub fn convert_base64_images(text: &str) -> String {
    if !text.contains("data:image/") {
        return text.to_string();
    }
    static RES: OnceLock<[Regex; 3]> = OnceLock::new();
    let [md, paren, bare] = RES.get_or_init(|| {
        [
            Regex::new(r"!\[(?P<alt>[^\]]*)\]\(\s*data:image/[^;]+;base64,[A-Za-z0-9+/=\s]+\)").unwrap(),
            Regex::new(r"\(\s*data:image/[^;]+;base64,[A-Za-z0-9+/=\s]+\)").unwrap(),
            Regex::new(r"data:image/[^;]+;base64,[A-Za-z0-9+/=]+").unwrap(),
        ]
    });
    let out = md.replace_all(text, |c: &regex::Captures| {
        let alt = c.name("alt").map(|m| m.as_str().trim()).unwrap_or("");
        if alt.is_empty() {
            "[IMAGE]".to_string()
        } else {
            format!("[IMAGE: {alt}]")
        }
    });
    let out = paren.replace_all(&out, "[IMAGE]");
    bare.replace_all(&out, "[IMAGE]").into_owned()
}

/// Unambiguous file signatures (Hermes `_UNAMBIGUOUS_BINARY_KINDS` over `_MAGIC_SIGNATURES`).
const MAGIC: &[(&[u8], &str)] = &[
    (b"\x89PNG\r\n\x1a\n", "PNG image data"),
    (b"\xff\xd8\xff", "JPEG image data"),
    (b"GIF87a", "GIF image data"),
    (b"GIF89a", "GIF image data"),
    (b"PK\x03\x04", "ZIP archive (also docx/xlsx/jar/apk)"),
    (b"PK\x05\x06", "ZIP archive (empty)"),
    (b"\x1f\x8b", "gzip compressed data"),
    (b"BZh", "bzip2 compressed data"),
    (b"\xfd7zXZ\x00", "xz compressed data"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\x7fELF", "ELF executable"),
    (b"\xcf\xfa\xed\xfe", "Mach-O executable (64-bit)"),
    (b"\xca\xfe\xba\xbe", "Mach-O universal binary / Java class"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"OggS", "Ogg container"),
    (b"fLaC", "FLAC audio"),
    (b"II*\x00", "TIFF image data (little-endian)"),
    (b"MM\x00*", "TIFF image data (big-endian)"),
];

/// Type name when a fetched "text" body is really a binary file. Backends drop NULs, so
/// signatures are compared NUL-stripped on both sides (latin-1 view of the first 32 chars).
pub fn binary_kind(text: &str) -> Option<&'static str> {
    let head: Vec<u8> = text.chars().take(32).filter(|c| (*c as u32) <= 0xff && *c != '\0').map(|c| c as u32 as u8).collect();
    MAGIC.iter().find_map(|(sig, name)| {
        let s: Vec<u8> = sig.iter().copied().filter(|b| *b != 0).collect();
        (!s.is_empty() && head.starts_with(&s)).then_some(*name)
    })
}

/// Same check on raw bytes (with NULs).
pub fn binary_kind_bytes(b: &[u8]) -> Option<&'static str> {
    MAGIC.iter().find_map(|(sig, name)| b.starts_with(sig).then_some(*name))
}

/// Write `content` (capped at [`MAX_STORED_TEXT_CHARS`]) to `<dir>/<prefix>-<host>-<hash>.md`.
/// Symlinks planted at the predictable name are not followed. None on failure (best effort).
pub fn store_full_text(dir: &Path, prefix: &str, url: &str, content: &str) -> Option<PathBuf> {
    std::fs::create_dir_all(dir).ok()?;
    let name = format!("{prefix}-{}-{}.md", super::cache::host_slug(url), &super::cache::digest(url)[..10]);
    let path = dir.join(name);
    let total = char_len(content);
    let body = if total > MAX_STORED_TEXT_CHARS {
        format!("{}\n\n[... stored copy truncated at {MAX_STORED_TEXT_CHARS} chars of {total}; re-extract a more specific URL for the rest ...]", head_chars(content, MAX_STORED_TEXT_CHARS))
    } else {
        content.to_string()
    };
    super::cache::write_no_follow(&path, &body).ok()?;
    Some(path)
}

/// `(model_text, truncated)`. Over `limit` chars: ~75 % head + ~25 % tail cut on line
/// boundaries, the full text stored under `dir`, and a footer with the path and the `read`
/// offset of the omitted middle. Deterministic. The footer (whose size grows with the spill
/// path) is paid out of `limit`, so the model sees about `limit` chars whatever the path length.
pub fn truncate_with_footer(content: &str, url: &str, limit: usize, dir: &Path) -> (String, bool) {
    truncate_with_footer_for("web_extract", content, url, limit, dir)
}

/// [`truncate_with_footer`] for `tool` (`web_extract` / `web_fetch`): names the spill file and
/// the re-run hint after it.
pub fn truncate_with_footer_for(tool: &str, content: &str, url: &str, limit: usize, dir: &Path) -> (String, bool) {
    let total = char_len(content);
    if total <= limit {
        return (content.to_string(), false);
    }
    const MARKER: &str = "\n\n[... middle omitted — see footer ...]\n\n";
    let stored = store_full_text(dir, &tool.replace('_', "-"), url, content);
    let bar = "─".repeat(8);
    let tail_lines = |head_n: usize, tail_n: usize, middle_line: usize| -> Vec<String> {
        let mut f = vec![String::new(), format!("{bar} [TRUNCATED] {bar}"), format!("Showing {head_n} chars (head) + {tail_n} chars (tail) of {total} total clean characters.")];
        match &stored {
            Some(p) => {
                f.push(format!("Full text saved to: {}", p.display()));
                f.push(format!("To read the omitted middle: read path=\"{}\" offset={middle_line} limit=200  (the file is the complete page; raise/lower offset to page through it).", p.display()));
            }
            None => f.push(format!("Full text could not be stored; re-run {tool} on a more specific URL or use a browser for the complete page.")),
        }
        f.push("─".repeat(29));
        f
    };
    // Footer size with worst-case numbers; never let it eat more than half of the window.
    let overhead = char_len(MARKER) + 1 + char_len(&tail_lines(total, total, total).join("\n"));
    let window = limit.saturating_sub(overhead).max(limit / 2);
    let head_budget = window * 3 / 4;
    let tail_budget = window - head_budget;
    let mut head = head_chars(content, head_budget);
    let mut tail = tail_chars(content, tail_budget);
    // Snap both cuts to line boundaries (head back, tail forward) so no line is sliced.
    if let Some(nl) = head.rfind('\n') {
        if char_len(&head[..nl]) * 2 > head_budget {
            head = &head[..nl];
        }
    }
    if let Some(nl) = tail.find('\n') {
        if char_len(&tail[..nl]) * 2 < tail_budget {
            tail = &tail[nl + 1..];
        }
    }
    let footer = tail_lines(char_len(head), char_len(tail), head.matches('\n').count() + 2);
    (format!("{head}{MARKER}{tail}\n{}", footer.join("\n")), true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn limits_and_slicing() {
        assert_eq!((clamp_char_limit(10), clamp_char_limit(9_000_000), clamp_char_limit(5000)), (2000, 500_000, 5000));
        assert_eq!(effective_char_limit(Some(&json!("3000")), 15_000), 3000);
        assert_eq!(effective_char_limit(Some(&json!("x")), 15_000), 15_000);
        assert_eq!(effective_char_limit(None, 1), 2000);
        assert_eq!((head_chars("héllo", 2), tail_chars("héllo", 4), tail_chars("ab", 5)), ("hé", "éllo", "ab"));
    }

    #[test]
    fn base64_images_and_binary() {
        let t = "a ![logo](data:image/png;base64,iVBORw0KGgo=) b ![](data:image/gif;base64,R0lG) c (data:image/png;base64,AAAA) d data:image/jpeg;base64,/9j/ e ![x](https://i.com/x.png)";
        assert_eq!(convert_base64_images(t), "a [IMAGE: logo] b [IMAGE] c [IMAGE] d [IMAGE] e ![x](https://i.com/x.png)");
        assert_eq!(binary_kind("SQLite format 3 rest"), Some("SQLite database"));
        assert_eq!(binary_kind("\u{89}PNG\r\n\u{1a}\nxx"), Some("PNG image data"));
        assert_eq!(binary_kind("PK\u{3}\u{4}zip"), Some("ZIP archive (also docx/xlsx/jar/apk)"));
        assert_eq!(binary_kind("# Markdown\nPK"), None);
        assert_eq!(binary_kind_bytes(b"\x7fELF\x02"), Some("ELF executable"));
    }

    #[test]
    fn head_tail_window_with_spill() {
        let dir = crate::testutil::tmpdir("webtrunc");
        let content: String = (0..2000).map(|i| format!("line {i:04} {}\n", "x".repeat(20))).collect();
        let (short, t) = truncate_with_footer("small", "https://a.com/", 2000, &dir);
        assert_eq!((short.as_str(), t), ("small", false));
        let (out, t) = truncate_with_footer(&content, "https://a.com/p", 4000, &dir);
        assert!(t && out.starts_with("line 0000") && out.contains("[... middle omitted — see footer ...]") && out.contains("line 1999"));
        assert!(out.contains("[TRUNCATED]") && out.contains("total clean characters"));
        let path = out.lines().find_map(|l| l.strip_prefix("Full text saved to: ")).unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), content);
        // The read offset lands on the first line after the shown head.
        let head_lines = out.split("\n\n[... middle").next().unwrap().lines().count();
        assert!(out.contains(&format!("offset={} limit=200", head_lines + 1)), "{out}");
        assert!(char_len(&out) < 4000 + 700);
        // Line-snapped: no partial line at either cut.
        let tail = out.split("see footer ...]\n\n").nth(1).unwrap();
        assert!(tail.starts_with("line "));
        // A long spill path is paid out of the budget, not added on top of it.
        let deep = dir.join("d".repeat(120)).join("e".repeat(120));
        let (out, _) = truncate_with_footer(&content, "https://a.com/p", 4000, &deep);
        assert!(char_len(&out) <= 4000 && out.contains("Full text saved to: ") && out.contains("line 1999"), "{}", char_len(&out));
    }
}
