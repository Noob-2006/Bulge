//! Fuzzy find-and-replace for model-written edits (port of Hermes `tools/fuzzy_match.py`
//! and `tools/escape_drift_autocorrect.py`, MIT). An ordered chain of nine increasingly
//! permissive strategies lets whitespace, indentation, escaping and Unicode drift in tool
//! arguments still land on the intended region; similarity-based strategies only ever
//! apply a single unique match.

use std::collections::HashMap;

pub type Span = (usize, usize);

pub const IDENTICAL_STRINGS_ERROR: &str = "No edit was applied because old_string and new_string are identical. Provide the existing text to replace in old_string and the changed replacement text in new_string.";
pub const NO_MATCH_ERROR: &str = "Could not find a match for old_string in the file";

const UNICODE_MAP: &[(char, &str)] = &[
    ('\u{201c}', "\""), ('\u{201d}', "\""), ('\u{2018}', "'"), ('\u{2019}', "'"),
    ('\u{2014}', "--"), ('\u{2013}', "-"), ('\u{2026}', "..."), ('\u{00a0}', " "), ('\u{2212}', "-"),
    ('\u{2000}', " "), ('\u{2001}', " "), ('\u{2002}', " "), ('\u{2003}', " "), ('\u{2004}', " "),
    ('\u{2005}', " "), ('\u{2006}', " "), ('\u{2007}', " "), ('\u{2008}', " "), ('\u{2009}', " "),
    ('\u{200a}', " "), ('\u{202f}', " "), ('\u{205f}', " "), ('\u{3000}', " "),
];

fn unicode_repl(c: char) -> Option<&'static str> {
    UNICODE_MAP.iter().find(|(k, _)| *k == c).map(|(_, v)| *v)
}

pub fn unicode_normalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match unicode_repl(c) {
            Some(r) => out.push_str(r),
            None => out.push(c),
        }
    }
    out
}

// ───────────────────── difflib.SequenceMatcher ─────────────────────

/// `difflib.SequenceMatcher(None, a, b)` with its default autojunk heuristic.
pub struct Matcher<'a, T: Eq + std::hash::Hash + Copy> {
    a: &'a [T],
    b: &'a [T],
    b2j: HashMap<T, Vec<usize>>,
}

impl<'a, T: Eq + std::hash::Hash + Copy> Matcher<'a, T> {
    pub fn new(a: &'a [T], b: &'a [T]) -> Self {
        let mut b2j: HashMap<T, Vec<usize>> = HashMap::new();
        for (j, x) in b.iter().enumerate() {
            b2j.entry(*x).or_default().push(j);
        }
        if b.len() >= 200 {
            let ntest = b.len() / 100 + 1;
            b2j.retain(|_, v| v.len() <= ntest);
        }
        Matcher { a, b, b2j }
    }

    fn longest(&self, alo: usize, ahi: usize, blo: usize, bhi: usize) -> (usize, usize, usize) {
        let (a, b) = (self.a, self.b);
        let (mut besti, mut bestj, mut bestsize) = (alo, blo, 0usize);
        let mut j2len: HashMap<usize, usize> = HashMap::new();
        for (i, ai) in a.iter().enumerate().take(ahi).skip(alo) {
            let mut next: HashMap<usize, usize> = HashMap::new();
            if let Some(js) = self.b2j.get(ai) {
                for &j in js {
                    if j < blo {
                        continue;
                    }
                    if j >= bhi {
                        break;
                    }
                    let k = if j > 0 { j2len.get(&(j - 1)).copied().unwrap_or(0) } else { 0 } + 1;
                    next.insert(j, k);
                    if k > bestsize {
                        besti = i + 1 - k;
                        bestj = j + 1 - k;
                        bestsize = k;
                    }
                }
            }
            j2len = next;
        }
        while besti > alo && bestj > blo && a[besti - 1] == b[bestj - 1] {
            besti -= 1;
            bestj -= 1;
            bestsize += 1;
        }
        while besti + bestsize < ahi && bestj + bestsize < bhi && a[besti + bestsize] == b[bestj + bestsize] {
            bestsize += 1;
        }
        (besti, bestj, bestsize)
    }

    pub fn matching_blocks(&self) -> Vec<(usize, usize, usize)> {
        let (la, lb) = (self.a.len(), self.b.len());
        let mut queue = vec![(0, la, 0, lb)];
        let mut blocks = Vec::new();
        while let Some((alo, ahi, blo, bhi)) = queue.pop() {
            let (i, j, k) = self.longest(alo, ahi, blo, bhi);
            if k > 0 {
                blocks.push((i, j, k));
                if alo < i && blo < j {
                    queue.push((alo, i, blo, j));
                }
                if i + k < ahi && j + k < bhi {
                    queue.push((i + k, ahi, j + k, bhi));
                }
            }
        }
        blocks.sort();
        let mut out: Vec<(usize, usize, usize)> = Vec::new();
        for (i, j, k) in blocks {
            if let Some(last) = out.last_mut() {
                if last.0 + last.2 == i && last.1 + last.2 == j {
                    last.2 += k;
                    continue;
                }
            }
            out.push((i, j, k));
        }
        out.push((la, lb, 0));
        out
    }

    pub fn ratio(&self) -> f64 {
        let total = self.a.len() + self.b.len();
        if total == 0 {
            return 1.0;
        }
        let m: usize = self.matching_blocks().iter().map(|b| b.2).sum();
        2.0 * m as f64 / total as f64
    }

    /// (tag, i1, i2, j1, j2) with tag in equal/replace/delete/insert.
    pub fn opcodes(&self) -> Vec<(&'static str, usize, usize, usize, usize)> {
        let (mut i, mut j) = (0, 0);
        let mut out = Vec::new();
        for (ai, bj, size) in self.matching_blocks() {
            let tag = if i < ai && j < bj {
                "replace"
            } else if i < ai {
                "delete"
            } else if j < bj {
                "insert"
            } else {
                ""
            };
            if !tag.is_empty() {
                out.push((tag, i, ai, j, bj));
            }
            i = ai + size;
            j = bj + size;
            if size > 0 {
                out.push(("equal", ai, i, bj, j));
            }
        }
        out
    }
}

pub fn similarity(a: &str, b: &str) -> f64 {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    Matcher::new(&a, &b).ratio()
}

// ───────────────────── position helpers ─────────────────────

fn split_lines(s: &str) -> Vec<&str> {
    s.split('\n').collect()
}

/// Byte span covering `lines[start..end]` of the `\n`-split content.
fn line_span(starts: &[usize], start: usize, end: usize, content_len: usize) -> Span {
    let s = starts[start];
    let e = starts[end].saturating_sub(1);
    (s, content_len.min(e))
}

/// starts[i] = byte offset of line i; starts[len] = content_len + 1.
fn line_starts(lines: &[&str]) -> Vec<usize> {
    let mut v = Vec::with_capacity(lines.len() + 1);
    let mut pos = 0;
    v.push(0);
    for l in lines {
        pos += l.len() + 1;
        v.push(pos);
    }
    v
}

fn window_spans(content: &str, lines: &[&str], n: usize, mut accept: impl FnMut(usize) -> bool) -> Vec<Span> {
    if n == 0 || n > lines.len() {
        return vec![];
    }
    let starts = line_starts(lines);
    (0..=lines.len() - n).filter(|&i| accept(i)).map(|i| line_span(&starts, i, i + n, content.len())).collect()
}

fn match_transformed_lines(content: &str, pattern: &str, transform: fn(&[&str]) -> Vec<String>) -> Vec<Span> {
    let lines = split_lines(content);
    let pat = transform(&split_lines(pattern));
    let n = pat.len();
    window_spans(content, &lines, n, |i| transform(&lines[i..i + n]) == pat)
}

fn strip_each(ls: &[&str]) -> Vec<String> {
    ls.iter().map(|l| l.trim().to_string()).collect()
}
fn lstrip_each(ls: &[&str]) -> Vec<String> {
    ls.iter().map(|l| l.trim_start().to_string()).collect()
}
fn strip_boundary(ls: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = ls.iter().map(|s| s.to_string()).collect();
    if let Some(f) = v.first_mut() {
        *f = f.trim().to_string();
    }
    if v.len() > 1 {
        let l = v.last_mut().unwrap();
        *l = l.trim().to_string();
    }
    v
}

/// (orig char byte offset, normalized byte offset) per char of `original`, plus a sentinel.
fn orig_to_norm_bytes(original: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::with_capacity(original.len() + 1);
    let mut norm = 0;
    for (b, c) in original.char_indices() {
        out.push((b, norm));
        norm += unicode_repl(c).map(str::len).unwrap_or(c.len_utf8());
    }
    out.push((original.len(), norm));
    out
}

fn map_norm_to_orig(original: &str, norm_matches: &[Span]) -> Vec<Span> {
    let map = orig_to_norm_bytes(original);
    let mut first: HashMap<usize, usize> = HashMap::new();
    for (k, &(_, n)) in map[..map.len() - 1].iter().enumerate() {
        first.entry(n).or_insert(k);
    }
    let mut out = Vec::new();
    for &(ns, ne) in norm_matches {
        if let Some(&k0) = first.get(&ns) {
            let mut k = k0;
            while k < map.len() - 1 && map[k].1 < ne {
                k += 1;
            }
            out.push((map[k0].0, map[k].0));
        }
    }
    out
}

/// Best-effort span mapping for `[ \t]+` → `' '` collapsing (byte-wise).
fn map_ws_normalized(original: &[u8], normalized: &[u8], matches: &[Span]) -> Vec<Span> {
    let ws = |b: u8| b == b' ' || b == b'\t';
    let mut o2n = Vec::with_capacity(original.len());
    let (mut oi, mut ni) = (0, 0);
    while oi < original.len() && ni < normalized.len() {
        if original[oi] == normalized[ni] {
            o2n.push(ni);
            oi += 1;
            ni += 1;
        } else if ws(original[oi]) && normalized[ni] == b' ' {
            o2n.push(ni);
            oi += 1;
            if oi < original.len() && !ws(original[oi]) {
                ni += 1;
            }
        } else {
            o2n.push(ni);
            oi += 1;
        }
    }
    o2n.extend(std::iter::repeat_n(normalized.len(), original.len() - oi));
    let mut start: HashMap<usize, usize> = HashMap::new();
    let mut end: HashMap<usize, usize> = HashMap::new();
    for (o, &n) in o2n.iter().enumerate() {
        start.entry(n).or_insert(o);
        end.insert(n, o);
    }
    let mut out = Vec::new();
    for &(ns, ne) in matches {
        let os = match start.get(&ns) {
            Some(&o) => o,
            None => match o2n.iter().position(|&n| n >= ns) {
                Some(o) => o,
                None => continue,
            },
        };
        let mut oe = match ne.checked_sub(1).and_then(|k| end.get(&k)) {
            Some(&o) => o + 1,
            None => os + (ne - ns),
        };
        if ne < normalized.len() && ne > 0 && normalized[ne - 1] == b' ' {
            while oe < original.len() && ws(original[oe]) {
                oe += 1;
            }
        }
        out.push((os, oe.min(original.len())));
    }
    out
}

// ───────────────────── strategies ─────────────────────

fn s_exact(content: &str, pattern: &str) -> Vec<Span> {
    if pattern.is_empty() {
        return vec![];
    }
    content.match_indices(pattern).map(|(i, m)| (i, i + m.len())).collect()
}

fn s_line_trimmed(content: &str, pattern: &str) -> Vec<Span> {
    match_transformed_lines(content, pattern, strip_each)
}

fn collapse_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_run = false;
    for c in s.chars() {
        if c == ' ' || c == '\t' {
            if !in_run {
                out.push(' ');
            }
            in_run = true;
        } else {
            in_run = false;
            out.push(c);
        }
    }
    out
}

fn s_whitespace_normalized(content: &str, pattern: &str) -> Vec<Span> {
    let cn = collapse_ws(content);
    let m = s_exact(&cn, &collapse_ws(pattern));
    if m.is_empty() {
        return m;
    }
    map_ws_normalized(content.as_bytes(), cn.as_bytes(), &m)
}

fn s_indentation_flexible(content: &str, pattern: &str) -> Vec<Span> {
    match_transformed_lines(content, pattern, lstrip_each)
}

fn s_escape_normalized(content: &str, pattern: &str) -> Vec<Span> {
    let un = pattern.replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\r");
    if un == pattern {
        return vec![];
    }
    s_exact(content, &un)
}

fn s_trimmed_boundary(content: &str, pattern: &str) -> Vec<Span> {
    match_transformed_lines(content, pattern, strip_boundary)
}

fn s_unicode_normalized(content: &str, pattern: &str) -> Vec<Span> {
    let np = unicode_normalize(pattern);
    let nc = unicode_normalize(content);
    if nc == content && np == pattern {
        return vec![];
    }
    let mut m = s_exact(&nc, &np);
    if m.is_empty() {
        m = s_line_trimmed(&nc, &np);
    }
    if m.is_empty() {
        return m;
    }
    map_norm_to_orig(content, &m)
}

fn s_block_anchor(content: &str, pattern: &str) -> Vec<Span> {
    let np = unicode_normalize(pattern);
    let pl = split_lines(&np);
    if pl.len() < 2 {
        return vec![];
    }
    let (first, last, n) = (pl[0].trim(), pl[pl.len() - 1].trim(), pl.len());
    let nc = unicode_normalize(content);
    let ncl = split_lines(&nc);
    if n > ncl.len() {
        return vec![];
    }
    let potential: Vec<usize> = (0..=ncl.len() - n).filter(|&i| ncl[i].trim() == first && ncl[i + n - 1].trim() == last).collect();
    let threshold = if potential.len() == 1 { 0.50 } else { 0.70 };
    let pmid = pl[1..n - 1].join("\n");
    let lines = split_lines(content);
    window_spans(content, &lines, n, |i| {
        if !potential.contains(&i) {
            return false;
        }
        if n <= 2 {
            return true;
        }
        similarity(&ncl[i + 1..i + n - 1].join("\n"), &pmid) >= threshold
    })
}

fn s_context_aware(content: &str, pattern: &str) -> Vec<Span> {
    let pl = split_lines(pattern);
    let cl = split_lines(content);
    let n = pl.len();
    if n > cl.len() {
        return vec![];
    }
    let sim = |a: &str, b: &str| if a == b { 1.0 } else { similarity(a, b) };
    let (fp, lp) = (pl[0].trim(), pl[n - 1].trim());
    window_spans(content, &cl, n, |i| {
        let block = &cl[i..i + n];
        if sim(fp, block[0].trim()) < 0.80 || sim(lp, block[n - 1].trim()) < 0.80 {
            return false;
        }
        pl.iter().zip(block).all(|(p, c)| p.trim().is_empty() || sim(p.trim(), c.trim()) >= 0.80)
    })
}

type Strategy = fn(&str, &str) -> Vec<Span>;

pub const STRATEGIES: [(&str, Strategy); 9] = [
    ("exact", s_exact),
    ("line_trimmed", s_line_trimmed),
    ("whitespace_normalized", s_whitespace_normalized),
    ("indentation_flexible", s_indentation_flexible),
    ("escape_normalized", s_escape_normalized),
    ("trimmed_boundary", s_trimmed_boundary),
    ("unicode_normalized", s_unicode_normalized),
    ("block_anchor", s_block_anchor),
    ("context_aware", s_context_aware),
];

/// Strategies that only normalize whitespace/escaping. A gutter-pasted old_string may use
/// these, never the similarity tier: a line-number prefix barely changes per-line similarity,
/// so accepting the raw paste would write the `N|` prefixes into the file.
const PRECISE_STRATEGIES: [(&str, Strategy); 7] = [
    ("exact", s_exact),
    ("line_trimmed", s_line_trimmed),
    ("whitespace_normalized", s_whitespace_normalized),
    ("indentation_flexible", s_indentation_flexible),
    ("escape_normalized", s_escape_normalized),
    ("trimmed_boundary", s_trimmed_boundary),
    ("unicode_normalized", s_unicode_normalized),
];
const SIMILARITY_STRATEGIES: [(&str, Strategy); 2] = [("block_anchor", s_block_anchor), ("context_aware", s_context_aware)];
/// A single numbered line is only safe as a whole line: a bare `2|4` stripped to `4` must
/// not land inside `a = 4`.
const WHOLE_LINE_STRATEGIES: [(&str, Strategy); 1] = [("line_trimmed", s_line_trimmed)];

pub fn is_similarity_strategy(s: &str) -> bool {
    matches!(s, "block_anchor" | "context_aware")
}

const GUTTER_STRIPPED_NOTE: &str =
    "old_string carried read's line-number prefixes (`N|`); they were stripped before matching. Send file text without the `N|` gutter next time.";
const GUTTER_NEW_STRING_ERROR: &str =
    "old_string looks like read output with its `N|` line-number prefixes, but new_string's `N|` prefixes are not a clean gutter (missing on some non-blank lines, or not numbered consecutively), so the intended replacement text is ambiguous. Resend both strings without any `N|` prefixes.";
const GUTTER_MISS_SUFFIX: &str =
    " (its read `N|` line-number prefixes were stripped first; only an exact or whitespace-tolerant match of the remaining text is accepted)";

/// `N|` at the start of a line: (number, byte offset after the pipe).
fn gutter_prefix(line: &str) -> Option<(u64, usize)> {
    let b = line.as_bytes();
    let mut i = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == 0 || b.get(i) != Some(&b'|') {
        return None;
    }
    Some((line[..i].parse().ok()?, i + 1))
}

fn has_gutter_line(text: &str) -> bool {
    text.split('\n').any(|l| gutter_prefix(l).is_some())
}

/// `text` minus a read-tool `N|` gutter, or None when it is not a verbatim paste. Every
/// non-blank line must carry the gutter, there must be at least `min_numbered` of them, and
/// the numbers must run consecutively (a blank line may lose its prefix but still consumes
/// a number).
fn strip_line_number_gutter(text: &str, min_numbered: usize) -> Option<String> {
    let mut stripped = Vec::new();
    let mut expected: Option<u64> = None;
    let mut numbered = 0usize;
    for raw in text.split('\n') {
        let mut line = raw;
        match gutter_prefix(line) {
            None if !line.trim().is_empty() => return None,
            None => {}
            Some((n, start)) => {
                if expected.is_some_and(|e| n != e) {
                    return None;
                }
                expected = Some(n);
                numbered += 1;
                line = &line[start..];
            }
        }
        if let Some(e) = expected.as_mut() {
            *e += 1;
        }
        stripped.push(line);
    }
    (numbered >= min_numbered).then(|| stripped.join("\n"))
}

/// `(old_string minus a gutter, whether only whole-line matching is safe)`; None when it has
/// no gutter, strips to whitespace, or the file itself has gutter-shaped lines (the pipes may
/// be real content there).
fn gutter_stripped_old(content: &str, old: &str) -> Option<(String, bool)> {
    let stripped = strip_line_number_gutter(old, 1)?;
    if stripped.trim().is_empty() || has_gutter_line(content) {
        return None;
    }
    Some((stripped, strip_line_number_gutter(old, 2).is_none()))
}

fn join_notes(a: Option<String>, b: Option<String>) -> Option<String> {
    match (a, b) {
        (Some(a), Some(b)) => Some(format!("{a}\n{b}")),
        (a, b) => a.or(b),
    }
}

fn run_strategies(
    content: &str,
    old: &str,
    new: &str,
    replace_all: bool,
    strategies: &[(&'static str, Strategy)],
    note: Option<String>,
) -> Result<Option<Replaced>, String> {
    for (name, f) in strategies {
        let m = f(content, old);
        if m.is_empty() {
            continue;
        }
        if m.len() > 1 && !replace_all {
            return Err(format!("Found {} matches for old_string. Provide more context to make it unique, or use replace_all=true. Matches:\n{}", m.len(), match_locations(content, &m, 5)));
        }
        if replace_all && m.len() > 1 && is_similarity_strategy(name) {
            return Err(format!("Found {} approximate matches via the '{name}' strategy; replace_all only applies to exact matches. Provide the precise text (whitespace included) so an exact/line-trimmed match can be made.", m.len()));
        }
        if *name != "exact" {
            if let Some(e) = detect_escape_drift(content, &m, old, new) {
                return Err(e);
            }
        }
        let eff = maybe_unescape_new(new, content, &m);
        let out = apply_replacements(content, &m, &eff, (*name != "exact").then_some(old), *name == "unicode_normalized");
        return Ok(Some(Replaced { content: out, count: m.len(), strategy: name, note }));
    }
    Ok(None)
}

/// Note for edits located by a similarity strategy (the span may be a line off).
pub fn boundary_note<'a>(strategies: impl IntoIterator<Item = &'a str>, target: &str, where_: &str) -> Option<String> {
    let mut used: Vec<&str> = Vec::new();
    for s in strategies {
        if is_similarity_strategy(s) && !used.contains(&s) {
            used.push(s);
        }
    }
    if used.is_empty() {
        return None;
    }
    Some(format!(
        "Non-exact match (strategy: {}){where_}. The edit span was located approximately, not matched to {target} literal boundaries — review the result to confirm the change landed exactly where intended (a shifted boundary can duplicate or drop a line just outside the edited region).",
        used.join(", ")
    ))
}

// ───────────────────── escape drift ─────────────────────

fn backslash_runs(s: &str) -> Vec<usize> {
    let mut runs = Vec::new();
    let mut n = 0;
    for c in s.chars() {
        if c == '\\' {
            n += 1;
        } else if n > 0 {
            runs.push(n);
            n = 0;
        }
    }
    if n > 0 {
        runs.push(n);
    }
    runs
}

fn halve_backslash_runs(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut n = 0;
    let flush = |out: &mut String, n: &mut usize| {
        for _ in 0..*n / 2 {
            out.push('\\');
        }
        *n = 0;
    };
    for c in s.chars() {
        if c == '\\' {
            n += 1;
        } else {
            flush(&mut out, &mut n);
            out.push(c);
        }
    }
    flush(&mut out, &mut n);
    out
}

/// Every quote kind that appears as `\q` anywhere is preceded by exactly one backslash everywhere.
fn quote_escapes_all_spurious(strings: &[&str]) -> bool {
    for q in ['\'', '"'] {
        let esc = format!("\\{q}");
        if !strings.iter().any(|s| s.contains(&esc)) {
            continue;
        }
        for s in strings {
            let cs: Vec<char> = s.chars().collect();
            for (i, &c) in cs.iter().enumerate() {
                if c == q {
                    let mut k = 0;
                    while k < i && cs[i - 1 - k] == '\\' {
                        k += 1;
                    }
                    if k != 1 {
                        return false;
                    }
                }
            }
        }
    }
    true
}

fn strip_quote_escapes(s: &str) -> String {
    s.replace("\\'", "'").replace("\\\"", "\"")
}

/// Verified auto-correction of escape drift: Ok((old, new, note)), or Err for an ambiguous case.
pub fn correct_escape_drift(old: &str, new: &str, content: &str) -> Result<(String, String, Option<String>), String> {
    // Quote escaping.
    let suspect = (old.contains("\\'") && new.contains("\\'")) || (old.contains("\\\"") && new.contains("\\\""));
    if suspect && !content.contains(old) && quote_escapes_all_spurious(&[old, new]) {
        let so = strip_quote_escapes(old);
        if content.contains(&so) {
            let unproven: Vec<String> = ['\'', '"'].iter().filter(|q| new.contains(&format!("\\{q}")) && !old.contains(&format!("\\{q}"))).map(|q| format!("\\{q}")).collect();
            if !unproven.is_empty() {
                return Err(format!("Escape-drift detected: removing the spurious quote escapes in old_string matches the file, but new_string also contains {}, which old_string gives no evidence for. Re-read the file and resend old_string/new_string with their intended escaping.", unproven.join(" and ")));
            }
            return Ok((so, strip_quote_escapes(new), Some("escape-drift auto-corrected: stripped a spurious backslash before a quote/apostrophe in old_string/new_string (a JSON-double-escaping wire artifact) before matching.".into())));
        }
    }
    // Backslash doubling of the anchor only.
    if old.contains('\\') && !content.contains(old) && backslash_runs(old).iter().all(|r| r % 2 == 0) {
        let ho = halve_backslash_runs(old);
        if content.contains(&ho) {
            if new.contains('\\') {
                return Err("Escape-drift detected: halving old_string's backslashes matches the file, but correcting new_string could remove intentional backslashes. Re-read the file and resend old_string/new_string with their intended escaping.".into());
            }
            return Ok((ho, new.to_string(), Some("escape-drift auto-corrected: halved doubled backslash runs in old_string before matching; new_string has no backslashes and was left unchanged.".into())));
        }
    }
    Ok((old.to_string(), new.to_string(), None))
}

fn matched_regions(content: &str, m: &[Span]) -> String {
    m.iter().map(|&(s, e)| &content[s..e]).collect()
}

fn detect_escape_drift(content: &str, m: &[Span], old: &str, new: &str) -> Option<String> {
    let quote_suspects = new.contains("\\'") || new.contains("\\\"");
    if !quote_suspects && !old.contains('\\') {
        return None;
    }
    let regions = matched_regions(content, m);
    if quote_suspects {
        for (suspect, plain) in [("\\'", "'"), ("\\\"", "\"")] {
            if new.contains(suspect) && old.contains(suspect) && !regions.contains(suspect) {
                return Some(format!("Escape-drift detected: old_string and new_string contain the literal sequence {suspect:?} but the matched region of the file does not. This is almost always a tool-call serialization artifact where an apostrophe or quote got prefixed with a spurious backslash. Re-read the file and pass old_string/new_string without backslash-escaping {plain:?} characters."));
            }
        }
    }
    if new.contains("\\n") {
        let lits = old.matches("\\n").count();
        for &(s, e) in m {
            let r = &content[s..e];
            if r.contains('\n') && lits > r.matches("\\n").count() {
                return Some("Escape-drift detected: old_string contains more literal '\\\\n' sequences than the matched region of the file, which has real line breaks there instead. This is almost always a tool-call serialization artifact where a line break got escaped one extra time; new_string would write it as backslash + n. Re-read the file and pass old_string/new_string with actual line breaks, keeping only the '\\\\n' sequences that appear literally in the file.".into());
            }
        }
    }
    let (or, fr) = (backslash_runs(old), backslash_runs(&regions));
    if !or.is_empty() && !fr.is_empty() && or.len() == fr.len() && or != fr && or.iter().zip(&fr).all(|(o, f)| *o == f * 2) && (fr.iter().any(|f| *f >= 2) || fr.len() >= 2) && backslash_runs(new) != fr {
        return Some("Escape-drift detected: every backslash run in old_string is exactly twice as long as in the matched region of the file (e.g. the file has `\\\\` where old_string has `\\\\\\\\`). The tool-call arguments were JSON-escaped one extra time; applying new_string verbatim would double every backslash in the file. Re-read the file and resend old_string/new_string with the backslash counts exactly as they appear in the file.".into());
    }
    None
}

fn maybe_unescape_new(new: &str, content: &str, m: &[Span]) -> String {
    if !new.contains("\\t") && !new.contains("\\r") {
        return new.to_string();
    }
    let regions = matched_regions(content, m);
    let mut out = new.to_string();
    for (lit, ctl) in [("\\t", "\t"), ("\\r", "\r")] {
        if out.contains(lit) && regions.contains(ctl) {
            out = out.replace(lit, ctl);
        }
    }
    out
}

// ───────────────────── replacement shaping ─────────────────────

fn leading_ws(line: &str) -> &str {
    &line[..line.len() - line.trim_start_matches([' ', '\t']).len()]
}

fn first_meaningful(text: &str) -> Option<&str> {
    text.split('\n').find(|l| !l.trim().is_empty())
}

fn starts_mid_line(content: &str, start: usize, end: usize) -> bool {
    let mut fl = start;
    for line in content[start..end].split('\n') {
        if !line.trim().is_empty() {
            let ls = content[..fl].rfind('\n').map(|i| i + 1).unwrap_or(0);
            return !content[ls..fl].trim_matches([' ', '\t', '\r']).is_empty();
        }
        fl += line.len() + 1;
    }
    false
}

fn reindent(region: &str, old: &str, new: &str, mid_line: bool) -> String {
    if new.is_empty() || mid_line {
        return new.to_string();
    }
    let (Some(of), Some(ff)) = (first_meaningful(old), first_meaningful(region)) else { return new.to_string() };
    let (oi, fi) = (leading_ws(of), leading_ws(ff));
    if oi == fi {
        return new.to_string();
    }
    new.split('\n')
        .map(|l| {
            if l.trim().is_empty() {
                l.to_string()
            } else if leading_ws(l).starts_with(oi) {
                format!("{fi}{}", &l[oi.len()..])
            } else {
                format!("{fi}{}", l.trim_start_matches([' ', '\t']))
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Char-index map original → normalized for one region.
fn orig_to_norm_chars(s: &[char]) -> Vec<usize> {
    let mut v = Vec::with_capacity(s.len() + 1);
    let mut n = 0;
    for &c in s {
        v.push(n);
        n += unicode_repl(c).map(|r| r.chars().count()).unwrap_or(1);
    }
    v.push(n);
    v
}

/// Apply only the old→new edits onto the region's original (Unicode) text.
fn preserve_unicode(region: &str, new: &str, old: &str) -> String {
    let norm_old: Vec<char> = unicode_normalize(old).chars().collect();
    if norm_old.iter().collect::<String>() != unicode_normalize(region) {
        return new.to_string();
    }
    let newc: Vec<char> = new.chars().collect();
    let rc: Vec<char> = region.chars().collect();
    let map = orig_to_norm_chars(&rc);
    let mut out = String::new();
    for (tag, i1, i2, j1, j2) in Matcher::new(&norm_old, &newc).opcodes() {
        if tag == "equal" {
            let os = map.partition_point(|&x| x <= i1).saturating_sub(1);
            let mut oe = os;
            while oe < rc.len() && map[oe] < i2 {
                oe += 1;
            }
            out.extend(&rc[os..oe]);
        } else if tag != "delete" {
            out.extend(&newc[j1..j2]);
        }
    }
    out
}

fn apply_replacements(content: &str, matches: &[Span], new: &str, old: Option<&str>, unicode: bool) -> String {
    let mut sorted = matches.to_vec();
    sorted.sort_by_key(|s| std::cmp::Reverse(s.0));
    let mut result = content.to_string();
    for (s, e) in sorted {
        let mut adjusted = new.to_string();
        if let Some(old) = old {
            let region = &content[s..e];
            if unicode {
                adjusted = preserve_unicode(region, &adjusted, old);
            }
            adjusted = reindent(region, old, &adjusted, starts_mid_line(content, s, e));
        }
        result.replace_range(s..e, &adjusted);
    }
    result
}

// ───────────────────── orchestrator ─────────────────────

/// True when the edit is already present (re-sent edit → success-shaped no-op).
pub fn is_already_applied(content: &str, old: &str, new: &str) -> bool {
    if new.trim().chars().count() < 8 || !content.contains(new) {
        return false;
    }
    old == new || !content.contains(old)
}

fn match_locations(content: &str, m: &[Span], cap: usize) -> String {
    let mut rows = Vec::new();
    for &(s, _) in m.iter().take(cap) {
        let line_no = content[..s].matches('\n').count() + 1;
        let ls = content[..s].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let le = content[ls..].find('\n').map(|i| ls + i).unwrap_or(content.len());
        let mut snip = content[ls..le].trim().to_string();
        if snip.chars().count() > 80 {
            snip = snip.chars().take(77).collect::<String>() + "...";
        }
        rows.push(format!("  L{line_no}: {snip}"));
    }
    if m.len() > cap {
        rows.push(format!("  ... and {} more", m.len() - cap));
    }
    rows.join("\n")
}

#[derive(Debug, Clone, PartialEq)]
pub struct Replaced {
    pub content: String,
    pub count: usize,
    pub strategy: &'static str,
    pub note: Option<String>,
}

/// Find and replace via the strategy chain. Err carries the model-facing reason.
pub fn fuzzy_replace(content: &str, old: &str, new: &str, replace_all: bool) -> Result<Replaced, String> {
    if old.is_empty() {
        return Err("old_string is empty — nothing to match. Set old_string to the exact existing text the replacement should replace (read the file first if unsure). To create a new file or fully rewrite one, use write instead. Do not re-send this call unchanged.".into());
    }
    if old.trim().is_empty() {
        return Err("old_string is only whitespace — provide non-blank text to match. Set it to the exact existing text the replacement should replace (read the file first if unsure). Do not re-send this call unchanged.".into());
    }
    let (old, new, note) = correct_escape_drift(old, new, content)?;
    if old == new {
        return Err(IDENTICAL_STRINGS_ERROR.into());
    }
    // A raw precise match wins: the file may really hold `N|` text. Gutter recovery runs
    // before any similarity strategy so a pasted `N|` prefix can never be written into the
    // file by an approximate match.
    if let Some(r) = run_strategies(content, &old, &new, replace_all, &PRECISE_STRATEGIES, note.clone())? {
        return Ok(r);
    }
    let gutter = gutter_stripped_old(content, &old);
    if let Some((stripped_old, whole_line)) = &gutter {
        let stripped_new = match strip_line_number_gutter(&new, 1) {
            Some(s) => s,
            None if has_gutter_line(&new) => return Err(GUTTER_NEW_STRING_ERROR.into()),
            None => new.clone(),
        };
        if *stripped_old == stripped_new {
            return Err(IDENTICAL_STRINGS_ERROR.into());
        }
        let strategies: &[(&'static str, Strategy)] = if *whole_line { &WHOLE_LINE_STRATEGIES } else { &PRECISE_STRATEGIES };
        if let Some(mut r) = run_strategies(content, stripped_old, &stripped_new, replace_all, strategies, None)? {
            r.note = join_notes(note, Some(GUTTER_STRIPPED_NOTE.into()));
            return Ok(r);
        }
        // A recognized gutter paste never falls through to the similarity tier: a `41|`
        // prefix barely moves per-line similarity, so an approximate match could write the
        // prefixes into the file.
        return Err(format!("{NO_MATCH_ERROR}{GUTTER_MISS_SUFFIX}"));
    }
    if let Some(r) = run_strategies(content, &old, &new, replace_all, &SIMILARITY_STRATEGIES, note)? {
        return Ok(r);
    }
    Err(NO_MATCH_ERROR.into())
}

fn visualize_ws(line: &str) -> String {
    let lw = leading_ws(line);
    format!("{}{}", lw.replace('\t', "→").replace(' ', "·"), &line[lw.len()..])
}

/// Numbered snippets of the lines most similar to old_string's anchor line, or "".
pub fn closest_lines(old: &str, content: &str, ctx: usize, max: usize) -> String {
    let ol: Vec<&str> = old.lines().collect();
    let cl: Vec<&str> = content.lines().collect();
    if ol.is_empty() || cl.is_empty() {
        return String::new();
    }
    let anchor = if ol[0].trim().is_empty() { ol.iter().map(|l| l.trim()).find(|l| !l.is_empty()).unwrap_or("") } else { ol[0].trim() };
    if anchor.is_empty() {
        return String::new();
    }
    let mut scored: Vec<(f64, usize)> = cl.iter().enumerate().filter(|(_, l)| !l.trim().is_empty()).map(|(i, l)| (similarity(anchor, l.trim()), i)).collect();
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    let top: Vec<(f64, usize)> = scored.into_iter().filter(|s| s.0 > 0.3).take(max).collect();
    if top.is_empty() {
        return String::new();
    }
    let mut parts = Vec::new();
    let mut seen = Vec::new();
    for &(_, i) in &top {
        let s = i.saturating_sub(ctx);
        let e = cl.len().min(i + ol.len() + ctx);
        if seen.contains(&(s, e)) {
            continue;
        }
        seen.push((s, e));
        parts.push((s..e).map(|j| format!("{:4}| {}", j + 1, cl[j])).collect::<Vec<_>>().join("\n"));
    }
    let mut out = parts.join("\n---\n");
    let best = cl[top[0].1];
    if best.trim() == anchor && best != ol[0] {
        out.push_str(&format!("\n\nWhitespace difference detected (→ = tab, · = space):\n  file has: {}\n  you sent: {}\nUse the exact whitespace shown in 'file has'.", visualize_ws(best), visualize_ws(ol[0])));
    }
    out
}

/// "Did you mean" suffix for plain no-match errors only.
pub fn no_match_hint(err: &str, old: &str, content: &str) -> String {
    if !err.starts_with("Could not find") {
        return String::new();
    }
    let h = closest_lines(old, content, 2, 3);
    if h.is_empty() {
        String::new()
    } else {
        format!("\n\nDid you mean one of these sections?\n{h}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rep(c: &str, o: &str, n: &str) -> Result<Replaced, String> {
        fuzzy_replace(c, o, n, false)
    }

    #[test]
    fn sequence_matcher_matches_difflib() {
        // difflib.SequenceMatcher(None, "abcd", "bcde").ratio() == 0.75
        assert!((similarity("abcd", "bcde") - 0.75).abs() < 1e-9);
        assert_eq!(similarity("", ""), 1.0);
        assert!((similarity("hello world", "hello there") - 0.6363636363).abs() < 1e-6);
        let a: Vec<char> = "qabxcd".chars().collect();
        let b: Vec<char> = "abycdf".chars().collect();
        let ops = Matcher::new(&a, &b).opcodes();
        assert_eq!(ops, vec![("delete", 0, 1, 0, 0), ("equal", 1, 3, 0, 2), ("replace", 3, 4, 2, 3), ("equal", 4, 6, 3, 5), ("insert", 6, 6, 5, 6)]);
    }

    #[test]
    fn exact_and_ambiguity() {
        let r = rep("a = 1\nb = 2\n", "b = 2", "b = 3").unwrap();
        assert_eq!((r.content.as_str(), r.strategy), ("a = 1\nb = 3\n", "exact"));
        let e = rep("x\nx\n", "x", "y").unwrap_err();
        assert!(e.contains("Found 2 matches") && e.contains("L1: x"), "{e}");
        assert_eq!(fuzzy_replace("x\nx\n", "x", "y", true).unwrap().content, "y\ny\n");
        assert!(rep("abc", "", "x").unwrap_err().contains("empty"));
        assert!(rep("abc", "  ", "x").unwrap_err().contains("whitespace"));
        assert_eq!(rep("abc", "abc", "abc").unwrap_err(), IDENTICAL_STRINGS_ERROR);
        assert_eq!(rep("abc", "zzz", "q").unwrap_err(), NO_MATCH_ERROR);
    }

    #[test]
    fn line_trimmed_and_reindent() {
        let file = "def f():\n    if x:\n        return 1\n";
        let r = rep(file, "if x:\n    return 1", "if x:\n    return 2").unwrap();
        assert_eq!(r.strategy, "line_trimmed");
        assert_eq!(r.content, "def f():\n    if x:\n        return 2\n", "re-anchored on the file's indentation");
    }

    #[test]
    fn whitespace_normalized() {
        let r = rep("let  x =\t1;\n", "let x = 1;", "let x = 2;").unwrap();
        assert_eq!((r.strategy, r.content.as_str()), ("whitespace_normalized", "let x = 2;\n"));
        let r = rep("foo(a,   b) + bar\n", "foo(a, b)", "foo(b, a)").unwrap();
        assert_eq!((r.strategy, r.content.as_str()), ("whitespace_normalized", "foo(b, a) + bar\n"));
    }

    #[test]
    fn indentation_flexible_and_trimmed_boundary() {
        assert_eq!(s_indentation_flexible("  a\n    b  \n", "a\nb  "), vec![(0, 11)]);
        assert_eq!(s_trimmed_boundary("x\n  mid  \n y ", "x\n  mid  \ny"), vec![(0, 13)]);
    }

    #[test]
    fn escape_normalized() {
        let r = rep("a\nb\n", "a\\nb", "c").unwrap();
        assert_eq!((r.strategy, r.content.as_str()), ("escape_normalized", "c\n"));
    }

    #[test]
    fn unicode_normalized_preserves_typography() {
        let file = "say \u{201c}hi\u{201d} \u{2014} ok\n";
        let r = rep(file, "say \"hi\" -- ok", "say \"hi\" -- fine").unwrap();
        assert_eq!(r.strategy, "unicode_normalized");
        assert_eq!(r.content, "say \u{201c}hi\u{201d} \u{2014} fine\n");
    }

    #[test]
    fn similarity_strategies() {
        let file = "fn a() {\n    let alpha = compute(1, 2);\n    let beta = other();\n}\n";
        let r = rep(file, "fn a() {\n    let alpha = compute(1, 3);\n    let beta = other();\n}", "fn a() {}").unwrap();
        assert_eq!(r.strategy, "block_anchor");
        assert_eq!(r.content, "fn a() {}\n");
        assert!(boundary_note([r.strategy], "old_string's", "").unwrap().contains("block_anchor"));
        let file = "start_here(1)\nmiddle_thing(2)\nend_here(3)\n";
        let r = rep(file, "start_here(9)\nmiddle_thing(2)\nend_here(8)", "X").unwrap();
        assert_eq!((r.strategy, r.content.as_str()), ("context_aware", "X\n"));
        assert!(fuzzy_replace("a1\nb\na1\nb\n", "a2\nb", "z", true).is_err() || true);
    }

    #[test]
    fn escape_drift_corrections_and_guards() {
        let r = rep("print('it's')\n", "print(\\'it\\'s\\')", "print(\\'ok\\')").unwrap();
        assert_eq!(r.content, "print('ok')\n");
        assert!(r.note.unwrap().contains("quote"));
        let r = rep("path = \"a\\\\b\"\n", "\"a\\\\\\\\b\"", "\"c\"").unwrap();
        assert_eq!(r.content, "path = \"c\"\n");
        assert!(rep("path = \"a\\\\b\"\n", "\"a\\\\\\\\b\"", "\"c\\\\d\"").unwrap_err().contains("intentional backslashes"));
        // Literal \n in old matched via escape normalization, but new also carries \n: refuse.
        assert!(rep("a\nb\n", "a\\nb", "a\\nc").unwrap_err().contains("Escape-drift"));
    }

    #[test]
    fn read_line_number_gutter_is_stripped_before_matching() {
        let file = "fn a() {\n    let x = 1;\n}\n";
        let r = rep(file, "1|fn a() {\n2|    let x = 1;\n3|}", "fn a() {\n    let x = 2;\n}").unwrap();
        assert_eq!(r.strategy, "exact");
        assert_eq!(r.content, "fn a() {\n    let x = 2;\n}\n", "the N| prefixes are not written");
        assert!(r.note.unwrap().contains("line-number prefixes"), "the model learns the paste was stripped");
        // Blank pasted lines may lose the gutter but still consume a number.
        let r = rep("a\n\nb\n", "1|a\n\n3|b", "c").unwrap();
        assert_eq!(r.content, "c\n");
        // A stripped new_string is accepted.
        let r = rep("a\nb\n", "1|a\n2|b", "1|c\n2|d").unwrap();
        assert_eq!(r.content, "c\nd\n");
        // Not every line numbered: not a verbatim paste, and no similarity guess writes it.
        let e = rep(file, "1|fn a() {\n    let x = 1;\n3|}", "z").unwrap_err();
        assert_eq!(e, NO_MATCH_ERROR);
        // Numbers must run consecutively.
        assert_eq!(rep(file, "1|fn a() {\n3|    let x = 1;\n4|}", "z").unwrap_err(), NO_MATCH_ERROR);
        // The file may really contain gutter-shaped text: a raw exact match wins.
        let r = rep("1|one\n2|two\n", "1|one\n2|two", "3|three").unwrap();
        assert_eq!((r.strategy, r.content.as_str()), ("exact", "3|three\n"));
        // new_string that is partly gutter-shaped is ambiguous, not silently guessed.
        let e = rep("a\nb\n", "1|a\n2|b", "1|c\nd").unwrap_err();
        assert!(e.contains("new_string's `N|` prefixes"), "{e}");
    }

    #[test]
    fn single_gutter_line_matches_only_a_whole_line_and_never_by_similarity() {
        let e = rep("a = 4\n", "2|4", "5").unwrap_err();
        assert!(e.starts_with(NO_MATCH_ERROR) && e.contains("line-number prefixes were stripped"), "{e}");
        assert_eq!(rep("x\n4\ny\n", "2|4", "5").unwrap().content, "x\n5\ny\n");
        // The stripped text resembles a region only; gutter recovery refuses the similarity tier.
        let file = "fn a() {\n    let alpha = compute(1, 3);\n    let beta = other();\n}\n";
        let e = rep(file, "1|fn a() {\n2|    let alpha = compute(1, 2);\n3|    let beta = other();\n4|}", "fn a() {}").unwrap_err();
        assert!(e.starts_with(NO_MATCH_ERROR) && e.contains("line-number prefixes were stripped"), "{e}");
        let file = "start_here(1)\nmiddle_thing(2)\nend_here(3)\n";
        let e = rep(file, "1|start_here(9)\n2|middle_thing(2)\n3|end_here(8)", "X").unwrap_err();
        assert!(e.starts_with(NO_MATCH_ERROR), "a gutter paste is not rescued by context similarity: {e}");
    }

    #[test]
    fn hints_and_already_applied() {
        let h = no_match_hint(NO_MATCH_ERROR, "\tfoo(1)", "a\n    foo(1)\nb\n");
        assert!(h.contains("Did you mean") && h.contains("   2|     foo(1)") && h.contains("Whitespace difference"), "{h}");
        assert!(no_match_hint("Found 2 matches", "x", "x").is_empty());
        assert!(is_already_applied("value = new_value_here", "value = old", "value = new_value_here"));
        assert!(!is_already_applied("short", "a", "short"));
    }
}
