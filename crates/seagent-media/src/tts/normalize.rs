//! Assistant Markdown → a spoken script (Hermes `tts_text_normalize.py`): drop
//! reasoning blocks, Markdown, URLs, `MEDIA:` paths, emoji and identifier-dense
//! tokens; spell out units, currency and percentages; fold headings into the next
//! sentence; flatten to one line. Also the incremental [`SentenceChunker`] used for
//! streaming playback, OpenClaw `[[tts:…]]` reply directives and the code-heavy check.

/// Sentinel appended to former heading lines (folded into the next sentence later).
const HEAD: char = '\u{0}';

/// The full pipeline (Hermes `prepare_spoken_text` without a cap).
pub fn prepare_spoken_text(text: &str) -> String {
    let t = strip_nonspoken_blocks(text);
    let t = strip_markdown(&t);
    let t = normalize_symbols(&t);
    let t = prune_identifiers(&t);
    let t = smooth_whitespace(&t);
    flatten_newlines(&t)
}

fn lower(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// `<think>…</think>` (also unterminated) and the file-mutation verifier footer.
pub fn strip_nonspoken_blocks(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    loop {
        let l = lower(rest);
        let open = ["<think>", "<think ", "<think\n"].iter().filter_map(|p| l.find(p)).min();
        let Some(i) = open else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..i]);
        out.push(' ');
        match l[i..].find("</think>") {
            Some(j) => rest = &rest[i + j + 8..],
            None => break,
        }
    }
    let mut lines: Vec<&str> = Vec::new();
    let mut in_footer = false;
    for line in out.lines() {
        let t = line.trim_start();
        if t.trim_start_matches(['⚠', '\u{fe0f}']).trim_start().starts_with("File-mutation verifier:") {
            in_footer = true;
            continue;
        }
        if in_footer && (line.starts_with(' ') || line.starts_with('\t')) && t.starts_with('•') {
            continue;
        }
        in_footer = false;
        lines.push(line);
    }
    lines.join("\n")
}

fn html_unescape(s: &str) -> String {
    let mut out = s.to_string();
    for (e, c) in [("&lt;", "<"), ("&gt;", ">"), ("&quot;", "\""), ("&#39;", "'"), ("&apos;", "'"), ("&nbsp;", "\u{a0}"), ("&amp;", "&")] {
        out = out.replace(e, c);
    }
    out
}

/// Remove `open … close` spans, replacing each with `f(inner)`.
fn replace_delimited(s: &str, open: &str, close: &str, f: impl Fn(&str) -> String) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find(open) {
        let after = &rest[i + open.len()..];
        match after.find(close) {
            Some(j) => {
                out.push_str(&rest[..i]);
                out.push_str(&f(&after[..j]));
                rest = &after[j + close.len()..];
            }
            None => break,
        }
    }
    out.push_str(rest);
    out
}

/// `[label](target)` and `![alt](target)` (one level of parentheses inside the target).
fn replace_links(s: &str) -> String {
    let cs: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < cs.len() {
        let img = cs[i] == '!' && cs.get(i + 1) == Some(&'[');
        if cs[i] == '[' || img {
            let start = if img { i + 2 } else { i + 1 };
            if let Some(close) = (start..cs.len()).find(|&k| cs[k] == ']') {
                if cs.get(close + 1) == Some(&'(') {
                    let mut depth = 0;
                    let mut end = None;
                    for (k, &c) in cs.iter().enumerate().skip(close + 1) {
                        match c {
                            '(' => depth += 1,
                            ')' => {
                                depth -= 1;
                                if depth == 0 {
                                    end = Some(k);
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    if let Some(e) = end {
                        let label: String = cs[start..close].iter().collect();
                        if img {
                            out.push_str(&format!(" {label} "));
                        } else {
                            out.push_str(&label);
                        }
                        i = e + 1;
                        continue;
                    }
                }
            }
        }
        out.push(cs[i]);
        i += 1;
    }
    out
}

/// Remove `http(s)://…` and `MEDIA:…` tokens (MEDIA keeps trailing sentence punctuation).
fn drop_urls(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    loop {
        let next = [rest.find("http://"), rest.find("https://"), rest.find("MEDIA:")].into_iter().flatten().min();
        let Some(i) = next else { break };
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let end = tail.find(char::is_whitespace).unwrap_or(tail.len());
        let token = &tail[..end];
        if token.starts_with("MEDIA:") {
            let keep: String = token.chars().rev().take_while(|c| ".,;:!?)]".contains(*c)).collect::<Vec<_>>().into_iter().rev().collect();
            out.push(' ');
            out.push_str(&keep);
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// `**x**` / `__x__` / `*x*` / `_x_` / `~~x~~` emphasis markers.
fn strip_emphasis(s: &str) -> String {
    let mut t = replace_delimited(s, "**", "**", |x| x.to_string());
    t = replace_delimited(&t, "~~", "~~", |x| x.to_string());
    t = strip_pair(&t, "__");
    strip_single(&strip_single(&t, '*'), '_')
}

/// `__x__` only at word boundaries (keeps `__init__`-style identifiers out of reach of bold).
fn strip_pair(s: &str, d: &str) -> String {
    replace_delimited(s, d, d, |x| x.to_string())
}

/// `*x*` / `_x_` where the opener is not inside a word (snake_case stays).
fn strip_single(s: &str, d: char) -> String {
    let cs: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < cs.len() {
        let c = cs[i];
        let prev_word = i > 0 && cs[i - 1].is_alphanumeric();
        if c == d && !prev_word && cs.get(i + 1).is_some_and(|n| !n.is_whitespace() && *n != d) {
            if let Some(j) = (i + 1..cs.len()).find(|&k| cs[k] == d && cs[k - 1] != d && !cs.get(k + 1).is_some_and(|n| n.is_alphanumeric() || *n == d) && cs[k - 1] != ' ') {
                out.extend(&cs[i + 1..j]);
                i = j + 1;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Markdown/Telegram formatting → readable words (Hermes `strip_markdown_for_tts`).
pub fn strip_markdown(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    let mut t = html_unescape(text);
    t = replace_delimited(&t, "```", "```", |_| " ".into());
    t = replace_links(&t);
    t = drop_urls(&t);
    t = replace_delimited(&t, "`", "`", |x| x.to_string());
    t = strip_emphasis(&t);
    let mut lines = Vec::new();
    for line in t.lines() {
        let lead = line.len() - line.trim_start_matches([' ', '\t']).len();
        let body = &line[lead..];
        let hashes = body.chars().take_while(|c| *c == '#').count();
        if lead <= 3 && (1..=6).contains(&hashes) && body[hashes..].starts_with([' ', '\t']) {
            let h = body[hashes..].trim().trim_end_matches('#').trim();
            lines.push(format!("{h}{HEAD}"));
            continue;
        }
        let mut l = line.trim_start().to_string();
        while let Some(r) = l.strip_prefix('>') {
            l = r.strip_prefix(' ').unwrap_or(r).to_string();
        }
        let tl = l.trim();
        if tl.len() >= 3 && (tl.chars().all(|c| c == '-') || tl.chars().all(|c| c == '*') || tl.chars().all(|c| c == '_')) {
            lines.push(String::new());
            continue;
        }
        // List markers: -, *, +, 1. 1)
        let trimmed = l.trim_start();
        let marker = if trimmed.starts_with(['-', '*', '+']) && trimmed[1..].starts_with([' ', '\t']) {
            Some(1)
        } else {
            let d = trimmed.chars().take_while(|c| c.is_ascii_digit()).count();
            (d > 0 && trimmed[d..].starts_with(['.', ')']) && trimmed[d + 1..].starts_with([' ', '\t'])).then_some(d + 1)
        };
        if let Some(n) = marker {
            l = trimmed[n..].trim_start().to_string();
        }
        lines.push(l);
    }
    let joined = lines.join("\n");
    // Table pipes become pauses.
    let mut out = String::new();
    for part in joined.split('|') {
        if !out.is_empty() {
            out = out.trim_end().to_string();
            out.push_str("; ");
            out.push_str(part.trim_start());
        } else {
            out.push_str(part);
        }
    }
    out
}

pub fn is_emoji(c: char) -> bool {
    matches!(c as u32, 0x1F1E6..=0x1F1FF | 0x1F300..=0x1F5FF | 0x1F600..=0x1F64F | 0x1F680..=0x1F6FF | 0x1F700..=0x1F77F | 0x1F780..=0x1F7FF | 0x1F800..=0x1F8FF | 0x1F900..=0x1F9FF | 0x1FA00..=0x1FAFF | 0x2600..=0x27BF | 0xFE0E | 0xFE0F)
}

fn is_num_char(c: char) -> bool {
    c.is_ascii_digit() || c == '.'
}

/// Read a number (optionally signed) starting at `i`; returns end index.
fn number_end(cs: &[char], i: usize) -> Option<usize> {
    let mut j = i;
    if j < cs.len() && (cs[j] == '-' || cs[j] == '+') {
        j += 1;
    }
    let s = j;
    while j < cs.len() && is_num_char(cs[j]) {
        j += 1;
    }
    (j > s && cs[s].is_ascii_digit() && cs[j - 1].is_ascii_digit()).then_some(j)
}

/// Units, temperatures, currency, percentages and stray symbols → words.
pub fn normalize_symbols(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    let t: String = text.chars().map(|c| if matches!(c, '\u{a0}' | '\u{2009}' | '\u{202f}') { ' ' } else { c }).collect();
    let t = t.replace('\u{2212}', "-").replace('…', "...");
    let cs: Vec<char> = t.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    let unit_word = |u: char| if u.eq_ignore_ascii_case(&'c') { "Celsius" } else { "Fahrenheit" };
    while i < cs.len() {
        let c = cs[i];
        let word_before = i > 0 && (cs[i - 1].is_alphanumeric() || cs[i - 1] == '_');
        // Currency prefixes: NZ$, A$, US$, €, £, $.
        let cur = [("NZ$", "New Zealand dollars"), ("A$", "Australian dollars"), ("US$", "US dollars"), ("€", "euros"), ("£", "pounds"), ("$", "dollars")].into_iter().find(|(p, _)| {
            let pc: Vec<char> = p.chars().collect();
            cs.len() >= i + pc.len() && cs[i..i + pc.len()].iter().zip(&pc).all(|(a, b)| a.eq_ignore_ascii_case(b)) && (pc.len() == 1 || !word_before)
        });
        if let Some((p, w)) = cur {
            let mut j = i + p.chars().count();
            while j < cs.len() && cs[j] == ' ' {
                j += 1;
            }
            let s = j;
            while j < cs.len() && (cs[j].is_ascii_digit() || cs[j] == ',' || cs[j] == '.') {
                j += 1;
            }
            while j > s && !cs[j - 1].is_ascii_digit() {
                j -= 1;
            }
            if j > s {
                out.push_str(&cs[s..j].iter().collect::<String>());
                out.push(' ');
                out.push_str(w);
                i = j;
                continue;
            }
        }
        if (c.is_ascii_digit() || ((c == '-' || c == '+') && cs.get(i + 1).is_some_and(|d| d.is_ascii_digit()))) && !word_before {
            if let Some(e) = number_end(&cs, i) {
                let n: String = cs[i..e].iter().collect();
                let mut k = e;
                while k < cs.len() && cs[k] == ' ' {
                    k += 1;
                }
                // Range: 11-17°C → 11 to 17 degrees Celsius.
                if k < cs.len() && matches!(cs[k], '-' | '–' | '—') {
                    let mut k2 = k + 1;
                    while k2 < cs.len() && cs[k2] == ' ' {
                        k2 += 1;
                    }
                    if let Some(e2) = number_end(&cs, k2) {
                        let mut k3 = e2;
                        while k3 < cs.len() && cs[k3] == ' ' {
                            k3 += 1;
                        }
                        if cs.get(k3) == Some(&'°') {
                            let mut k4 = k3 + 1;
                            while k4 < cs.len() && cs[k4] == ' ' {
                                k4 += 1;
                            }
                            if let Some(u) = cs.get(k4).filter(|u| matches!(u.to_ascii_lowercase(), 'c' | 'f')).filter(|_| !cs.get(k4 + 1).is_some_and(|x| x.is_alphanumeric())) {
                                out.push_str(&format!("{n} to {} degrees {}", cs[k2..e2].iter().collect::<String>(), unit_word(*u)));
                                i = k4 + 1;
                                continue;
                            }
                        }
                    }
                }
                if cs.get(k) == Some(&'°') {
                    let mut k2 = k + 1;
                    while k2 < cs.len() && cs[k2] == ' ' {
                        k2 += 1;
                    }
                    match cs.get(k2).filter(|u| matches!(u.to_ascii_lowercase(), 'c' | 'f')).filter(|_| !cs.get(k2 + 1).is_some_and(|x| x.is_alphanumeric())) {
                        Some(u) => {
                            out.push_str(&format!("{n} degrees {}", unit_word(*u)));
                            i = k2 + 1;
                        }
                        None => {
                            out.push_str(&format!("{n} degrees"));
                            i = k + 1;
                        }
                    }
                    continue;
                }
                if cs.get(k) == Some(&'%') {
                    out.push_str(&format!("{n} percent"));
                    i = k + 1;
                    continue;
                }
                // Units right after the number (km/h, mm, cm, m) at a word boundary.
                let rest: String = cs[k..cs.len().min(k + 8)].iter().collect::<String>().to_ascii_lowercase();
                let mut done = false;
                for (u, w) in [("km/h", "kilometres per hour"), ("km / h", "kilometres per hour"), ("mm", "millimetres"), ("cm", "centimetres"), ("m", "metres")] {
                    if rest.starts_with(u) && !cs.get(k + u.chars().count()).is_some_and(|x| x.is_alphanumeric() || *x == '_') {
                        out.push_str(&format!("{n} {w}"));
                        i = k + u.chars().count();
                        done = true;
                        break;
                    }
                }
                if done {
                    continue;
                }
                // Rates: 5/month → 5 per month.
                if cs.get(k) == Some(&'/') {
                    let mut k2 = k + 1;
                    while k2 < cs.len() && cs[k2] == ' ' {
                        k2 += 1;
                    }
                    if cs.get(k2).is_some_and(|x| x.is_ascii_alphabetic()) {
                        out.push_str(&format!("{n} per "));
                        i = k2;
                        continue;
                    }
                }
                out.push_str(&n);
                i = e;
                continue;
            }
        }
        if c == '°' {
            let mut k = i + 1;
            while k < cs.len() && cs[k] == ' ' {
                k += 1;
            }
            if let Some(u) = cs.get(k).filter(|u| matches!(u.to_ascii_lowercase(), 'c' | 'f')).filter(|_| !cs.get(k + 1).is_some_and(|x| x.is_alphanumeric())) {
                out.push_str(&format!("degrees {}", unit_word(*u)));
                i = k + 1;
            } else {
                out.push_str(" degrees");
                i += 1;
            }
            continue;
        }
        match c {
            '&' => out.push_str(" and "),
            '•' | '◦' | '▪' | '▫' => out.push(' '),
            '→' | '⇒' => out.push_str(" to "),
            '≈' | '~' => out.push_str(" about "),
            c if is_emoji(c) => {}
            c => out.push(c),
        }
        i += 1;
    }
    out
}

fn has_file_ext(tok: &str) -> bool {
    const EXTS: &[&str] = &[
        "wav", "ogg", "mp3", "flac", "m4a", "aac", "py", "pyc", "ts", "tsx", "js", "jsx", "mjs", "cjs", "json", "yaml", "yml", "toml", "md", "mdx", "txt", "csv", "xlsx", "xls", "pdf", "png", "jpg", "jpeg", "gif", "webp", "svg", "log", "sql", "sh", "bash", "zsh", "rs", "go", "java", "rb", "php",
        "html", "css", "lock", "tar", "gz", "zip", "db", "sqlite", "sqlite3", "onnx", "pt", "bin", "env", "ini", "conf", "cfg", "xml",
    ];
    tok.split(['/', '~', '@']).any(|seg| {
        let mut parts = seg.rsplit('.');
        let ext = parts.next().unwrap_or("");
        seg.contains('.') && EXTS.contains(&ext.to_ascii_lowercase().as_str())
    })
}

fn is_uuid(tok: &str) -> bool {
    let groups: Vec<&str> = tok.split('-').collect();
    tok.len() >= 36 && groups.windows(5).any(|w| [8, 4, 4, 4, 12].iter().zip(w).all(|(n, g)| g.len() >= *n && g.chars().all(|c| c.is_ascii_hexdigit())))
}

fn is_date(tok: &str) -> bool {
    let p: Vec<&str> = tok.split(['-', '/']).collect();
    (p.len() == 2 || p.len() == 3) && p[0].len() == 4 && p.iter().all(|x| !x.is_empty() && x.len() <= 4 && x.chars().all(|c| c.is_ascii_digit())) && p[1..].iter().all(|x| x.len() <= 2)
}

/// Machine tokens a voice would spell out character by character.
pub fn is_dense_identifier(tok: &str) -> bool {
    if tok.contains('@') || is_date(tok) {
        return false;
    }
    if tok.starts_with("~/") || tok.starts_with("./") || tok.starts_with("../") || tok.starts_with('/') {
        return true;
    }
    let digits = tok.chars().any(|c| c.is_ascii_digit());
    if tok.contains('/') && (has_file_ext(tok) || digits) {
        return true;
    }
    if has_file_ext(tok) || is_uuid(tok) {
        return true;
    }
    if (7..=64).contains(&tok.len()) && tok.chars().all(|c| c.is_ascii_hexdigit()) && digits {
        return true;
    }
    if !digits {
        return false;
    }
    let seps = ['_', '.', '/'].iter().filter(|c| tok.contains(**c)).count();
    let hyphens = tok.matches('-').count();
    if seps >= 2 || hyphens >= 2 {
        return true;
    }
    tok.contains('/') || (hyphens >= 1 && seps >= 1)
}

/// Silence identifier-dense tokens (`sha256:…` hashes, paths, file names, UUIDs, versions).
pub fn prune_identifiers(text: &str) -> String {
    let mut out = String::new();
    let mut tok = String::new();
    let flush = |tok: &mut String, out: &mut String| {
        if !tok.is_empty() {
            // Trailing sentence dots are not part of the token.
            let core = tok.trim_end_matches('.');
            let tail = &tok[core.len()..];
            if is_dense_identifier(core) {
                out.push(' ');
                out.push_str(tail);
            } else {
                out.push_str(tok);
            }
            tok.clear();
        }
    };
    let lower_text = text.to_ascii_lowercase();
    let mut skip_until = 0usize;
    for (bi, c) in text.char_indices() {
        if bi < skip_until {
            continue;
        }
        if tok.is_empty() {
            // sha256:<hex> / md5 <hex> prefixes.
            for p in ["sha256", "sha-256", "sha512", "sha-512", "sha1", "sha-1", "sha3", "sha", "blake2b", "blake2s", "blake2", "md5", "crc32", "crc"] {
                if lower_text[bi..].starts_with(p) && !text[..bi].chars().next_back().is_some_and(|x| x.is_alphanumeric()) {
                    let after = &text[bi + p.len()..];
                    let sep = after.chars().take_while(|c| *c == ':' || c.is_whitespace()).count();
                    let hex = after[sep..].chars().take_while(|c| c.is_ascii_hexdigit()).count();
                    if sep > 0 && (7..=64).contains(&hex) {
                        out.push(' ');
                        skip_until = bi + p.len() + sep + hex;
                        break;
                    }
                }
            }
            if bi < skip_until {
                continue;
            }
        }
        if c.is_ascii_alphanumeric() || "_./~@-".contains(c) {
            tok.push(c);
        } else {
            flush(&mut tok, &mut out);
            out.push(c);
        }
    }
    flush(&mut tok, &mut out);
    out
}

/// Visual formatting → calm spoken paragraphs; headings fold into the next line.
pub fn smooth_whitespace(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    let raw: Vec<&str> = text.lines().collect();
    let pauses = raw.iter().filter(|l| !l.replace(HEAD, "").trim().is_empty()).count() > 1;
    let mut lines: Vec<String> = Vec::new();
    let mut pending: Option<String> = None;
    let trim_p = |s: &str| s.trim_end_matches(['.', ':', ';', ',']).to_string();
    for r in raw {
        let heading = r.trim_end().ends_with(HEAD);
        let line = r.replace(HEAD, "").trim().to_string();
        if line.is_empty() {
            if pending.is_none() && lines.last().is_some_and(|l| !l.is_empty()) {
                lines.push(String::new());
            }
            continue;
        }
        if heading {
            if let Some(p) = pending.take() {
                lines.push(format!("{}.", trim_p(&p)));
            }
            pending = Some(trim_p(&line));
            continue;
        }
        let mut line = match pending.take() {
            Some(p) => format!("{}, {line}", trim_p(&p)),
            None => line,
        };
        if pauses {
            if line.ends_with([':', ';']) {
                line = format!("{}.", line.trim_end_matches([':', ';']).trim_end());
            } else if !line.ends_with(['.', '!', '?']) {
                line.push('.');
            }
        }
        lines.push(line);
    }
    if let Some(p) = pending {
        lines.push(format!("{}.", trim_p(&p)));
    }
    let mut t = lines.join("\n");
    while t.contains("\n\n\n") {
        t = t.replace("\n\n\n", "\n\n");
    }
    t = collapse_spaces(&t);
    // No space before punctuation; one after a sentence mark glued to a word.
    let cs: Vec<char> = t.chars().collect();
    let mut out = String::new();
    for (i, &c) in cs.iter().enumerate() {
        if (c == ' ' || c == '\t' || c == '\n') && cs.get(i + 1).is_some_and(|n| ",.;:!?".contains(*n)) && c != '\n' {
            continue;
        }
        out.push(c);
        if ",.;:!?".contains(c) && cs.get(i + 1).is_some_and(|n| n.is_ascii_alphabetic()) && !(i > 0 && cs[i - 1].is_ascii_alphanumeric()) {
            out.push(' ');
        }
    }
    while out.contains("....") {
        out = out.replace("....", "...");
    }
    close_final_colon(out.trim())
}

fn collapse_spaces(t: &str) -> String {
    let mut out = String::new();
    let mut prev_space = false;
    for c in t.chars() {
        let sp = c == ' ' || c == '\t';
        if sp && prev_space {
            continue;
        }
        out.push(if sp { ' ' } else { c });
        prev_space = sp;
    }
    out
}

/// A trailing `:`/`;` becomes a full stop unless it follows a digit (`3:2`).
fn close_final_colon(t: &str) -> String {
    let core = t.trim_end_matches(|c: char| c == ':' || c == ';' || c.is_whitespace());
    if core.len() < t.len() && t.trim_end().ends_with([':', ';']) && core.chars().last().is_some_and(|c| !c.is_ascii_digit()) {
        format!("{core}.")
    } else {
        t.to_string()
    }
}

/// Newlines → sentence breaks for single-line payloads (some servers stop at `\n`).
pub fn flatten_newlines(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    let mut t = text.to_string();
    while t.contains("\n\n") {
        t = t.replace("\n\n", "\n");
    }
    let cs: Vec<char> = t.chars().collect();
    let mut out = String::new();
    for (i, &c) in cs.iter().enumerate() {
        if c == '\n' {
            if i > 0 && ".!?;:,".contains(cs[i - 1]) {
                out.push(' ');
            } else {
                out.push_str(". ");
            }
        } else {
            out.push(c);
        }
    }
    let mut out = out.replace(". .", ".").replace("..", ".").replace(".  ", ". ");
    out = collapse_spaces(&out);
    close_final_colon(out.trim())
}

/// More than half of the text is fenced code (OpenClaw `isCodeHeavySpeechText`).
pub fn is_code_heavy(text: &str) -> bool {
    let t = text.trim();
    if t.is_empty() {
        return false;
    }
    let mut code = 0usize;
    let mut rest = t;
    while let Some(i) = rest.find("```") {
        let after = &rest[i + 3..];
        let j = after.find("```").map(|j| j + 3).unwrap_or(after.len());
        code += 3 + j;
        rest = &after[j.min(after.len())..];
    }
    code as f64 / t.len() as f64 >= 0.5
}

/// OpenClaw reply directives: `[[tts]]`, `[[tts:key=value …]]`, `[[tts:text]]…[[/tts:text]]`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Directives {
    pub cleaned: String,
    pub has_directive: bool,
    /// Text spoken instead of the visible reply.
    pub tts_text: Option<String>,
    pub provider: Option<String>,
    pub voice: Option<String>,
    pub model: Option<String>,
    pub speed: Option<f32>,
}

pub fn parse_directives(text: &str) -> Directives {
    let mut d = Directives::default();
    let mut out = String::new();
    let mut rest = text;
    let mut hidden: Option<String> = None;
    while let Some(i) = rest.find("[[") {
        let Some(j) = rest[i + 2..].find("]]") else { break };
        let body = &rest[i + 2..i + 2 + j];
        let norm: String = body.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_lowercase();
        let before = &rest[..i];
        match &mut hidden {
            Some(h) => h.push_str(before),
            None => out.push_str(before),
        }
        rest = &rest[i + 4 + j..];
        if norm == "tts:text" {
            d.has_directive = true;
            hidden = Some(String::new());
        } else if norm == "/tts:text" {
            if let Some(h) = hidden.take() {
                d.tts_text = Some(h.trim().to_string());
            }
        } else if norm == "tts" || norm == "/tts" || norm.starts_with("tts:") || norm.starts_with("/tts:") {
            d.has_directive = true;
            let kv = body.trim().trim_start_matches('/').trim_start_matches(|c: char| c.is_ascii_alphabetic()).trim_start_matches(':');
            for pair in kv.split_whitespace() {
                if let Some((k, v)) = pair.split_once('=') {
                    let v = v.trim_matches(|c| c == '"' || c == '\'').to_string();
                    match k.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
                        "provider" => d.provider = Some(v.to_ascii_lowercase()),
                        "voice" | "voiceid" | "voicename" | "speakervoice" => d.voice = Some(v),
                        "model" | "modelid" => d.model = Some(v),
                        "speed" => d.speed = v.parse().ok(),
                        _ => {}
                    }
                }
            }
        } else {
            match &mut hidden {
                Some(h) => h.push_str(&format!("[[{body}]]")),
                None => out.push_str(&format!("[[{body}]]")),
            }
        }
    }
    match hidden {
        Some(h) => {
            h.clone_into(&mut String::new());
            d.tts_text.get_or_insert_with(|| format!("{h}{rest}").trim().to_string());
        }
        None => out.push_str(rest),
    }
    d.cleaned = out.trim().to_string();
    d
}

/// The visible reply with every `[[tts…]]` directive removed.
pub fn strip_directives(text: &str) -> String {
    parse_directives(text).cleaned
}

/// Hermes `agent.think_scrubber.THINK_TAG_NAMES`.
pub const THINK_TAG_NAMES: &[&str] = &["think", "thinking", "reasoning", "thought", "REASONING_SCRATCHPAD", "思考", "反思", "推理", "推敲"];

/// Incremental sentence cutter for streamed model text (Hermes `SentenceChunker`):
/// cuts after `.!?` + whitespace or at blank lines, merges fragments shorter than
/// `min_len`, and never speaks reasoning blocks ([`THINK_TAG_NAMES`]).
#[derive(Debug, Clone)]
pub struct SentenceChunker {
    pub min_len: usize,
    buf: String,
}

impl Default for SentenceChunker {
    fn default() -> Self {
        SentenceChunker::new(20)
    }
}

impl SentenceChunker {
    pub fn new(min_len: usize) -> Self {
        SentenceChunker { min_len: min_len.max(1), buf: String::new() }
    }

    /// Earliest `<name` opening tag (followed by `>`, whitespace or end of text) of any
    /// reasoning tag name: `(byte offset, name)`.
    fn find_open(s: &str, from: usize) -> Option<(usize, &'static str)> {
        let l = s.to_lowercase();
        if l.len() != s.len() {
            // Lowercasing changed byte lengths (rare non-ASCII case folds): fall back to exact case.
            return Self::find_open_in(s, s, from);
        }
        Self::find_open_in(&l, s, from)
    }

    fn find_open_in(l: &str, _s: &str, from: usize) -> Option<(usize, &'static str)> {
        let mut best: Option<(usize, &'static str)> = None;
        for name in THINK_TAG_NAMES {
            let tag = format!("<{}", name.to_lowercase());
            let mut i = from;
            while let Some(k) = l.get(i..).and_then(|r| r.find(&tag)).map(|k| k + i) {
                let after = l[k + tag.len()..].chars().next();
                if after.is_none_or(|c| c == '>' || c.is_whitespace()) {
                    if best.is_none_or(|(b, _)| k < b) {
                        best = Some((k, name));
                    }
                    break;
                }
                i = k + tag.len();
            }
        }
        best
    }

    /// Remove complete `<tag …>…</tag>` reasoning blocks (Hermes `_THINK_BLOCK_RE`).
    fn strip_think(s: &str) -> String {
        let mut out = String::new();
        let mut i = 0;
        while let Some((k, name)) = Self::find_open(s, i) {
            let close = format!("</{}>", name.to_lowercase());
            let l = s.to_lowercase();
            match l.get(k..).and_then(|r| r.find(&close)) {
                Some(e) if l.len() == s.len() => {
                    out.push_str(&s[i..k]);
                    i = k + e + close.len();
                }
                _ => {
                    out.push_str(&s[i..]);
                    return out;
                }
            }
        }
        out.push_str(&s[i..]);
        out
    }

    fn open_think(s: &str) -> Option<usize> {
        Self::find_open(s, 0).map(|(k, _)| k)
    }

    /// Absorb `delta`; return each complete sentence now ready to speak.
    pub fn feed(&mut self, delta: &str) -> Vec<String> {
        self.buf = Self::strip_think(&format!("{}{delta}", self.buf));
        if Self::open_think(&self.buf).is_some() {
            return vec![];
        }
        let mut out = Vec::new();
        let mut start = 0;
        loop {
            let cs: Vec<(usize, char)> = self.buf.char_indices().collect();
            let mut cut = None;
            for w in 0..cs.len() {
                let (bi, c) = cs[w];
                if bi < start {
                    continue;
                }
                let next = cs.get(w + 1).map(|x| x.1);
                if ".!?".contains(c) && next.is_some_and(|n| n.is_whitespace()) {
                    cut = Some(cs[w + 1].0 + next.unwrap().len_utf8());
                    break;
                }
                if c == '\n' && next == Some('\n') {
                    cut = Some(cs[w + 1].0 + 1);
                    break;
                }
            }
            let Some(end) = cut else { break };
            let head = self.buf[..end].to_string();
            if head.trim().chars().count() < self.min_len {
                start = end;
                continue;
            }
            out.push(head);
            self.buf = self.buf[end..].to_string();
            start = 0;
        }
        out
    }

    /// Drain the tail (end of text).
    pub fn flush(&mut self) -> Vec<String> {
        let mut tail = Self::strip_think(&std::mem::take(&mut self.buf));
        if let Some(k) = Self::open_think(&tail) {
            tail.truncate(k);
        }
        let t = tail.trim();
        if t.is_empty() {
            vec![]
        } else {
            vec![t.to_string()]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_and_links() {
        let t = prepare_spoken_text("# Weather\nIt will be **sunny** with `light` wind. See [the forecast](https://x.y/(a)) and https://example.com/z.\n\n- item one\n- item two\n```\ncode\n```");
        assert_eq!(t, "Weather, It will be sunny with light wind. See the forecast and. item one. item two.");
    }

    #[test]
    fn units_currency_and_symbols() {
        assert_eq!(normalize_symbols("11-17°C and 5km/h, 3m"), "11 to 17 degrees Celsius and 5 kilometres per hour, 3 metres");
        assert_eq!(normalize_symbols("NZ$50, $3.50 and 20% off, 5/month"), "50 New Zealand dollars, 3.50 dollars and 20 percent off, 5 per month");
        assert_eq!(normalize_symbols("A → B & C 😀"), "A  to  B  and  C ");
        assert_eq!(normalize_symbols("TCP/IP and N/A"), "TCP/IP and N/A");
    }

    #[test]
    fn identifiers_are_silenced() {
        assert_eq!(prune_identifiers("open peyton-sample-20260922.wav now").split_whitespace().collect::<Vec<_>>(), vec!["open", "now"]);
        assert_eq!(prune_identifiers("on 2026-09-28 mail a@b.com COVID-19 well-known").trim(), "on 2026-09-28 mail a@b.com COVID-19 well-known");
        assert!(!prune_identifiers("hash sha256:e3b0c44298fc1c14 done").contains("e3b0"));
        assert!(!prune_identifiers("model meta-llama/Llama-3.3-70B ok").contains("Llama"));
        assert_eq!(prune_identifiers("defaced 73688014f78.").trim(), "defaced  .".trim());
    }

    #[test]
    fn think_blocks_and_media_paths() {
        assert_eq!(prepare_spoken_text("<think>secret</think>Hello. See MEDIA:/tmp/a.ogg. Then"), "Hello. See. Then");
        assert_eq!(strip_nonspoken_blocks("ok <think>never closed"), "ok  ");
        assert_eq!(prepare_spoken_text("Done\n⚠️ File-mutation verifier:\n  • a.rs"), "Done");
    }

    #[test]
    fn final_colon_closes_except_ratios() {
        assert_eq!(prepare_spoken_text("Here is the list:"), "Here is the list.");
        assert_eq!(prepare_spoken_text("final score 3:2"), "final score 3:2");
    }

    #[test]
    fn sentence_chunker() {
        let mut c = SentenceChunker::new(10);
        assert!(c.feed("Hi. ").is_empty());
        assert_eq!(c.feed("This is long enough. And"), vec!["Hi. This is long enough. "]);
        assert!(c.feed(" <think>hidden. stuff. ").is_empty());
        assert_eq!(c.feed("</think>more words here.\n\nNext"), vec!["And more words here.\n"]);
        assert_eq!(c.flush(), vec!["Next"]);
        let mut c = SentenceChunker::new(1);
        c.feed("tail <think>never");
        assert_eq!(c.flush(), vec!["tail"]);
        let mut c = SentenceChunker::new(1);
        assert!(c.feed("<reasoning>x. y. ").is_empty());
        assert_eq!(c.feed("</reasoning>Said. <思考>no</思考>Also. "), vec!["Said. ", "Also. "]);
    }

    #[test]
    fn directives() {
        let d = parse_directives("Visible reply. [[tts:voice=nova provider=openai speed=1.2]]");
        assert!(d.has_directive);
        assert_eq!((d.cleaned.as_str(), d.voice.as_deref(), d.provider.as_deref(), d.speed), ("Visible reply.", Some("nova"), Some("openai"), Some(1.2)));
        let d = parse_directives("Text [[tts:text]]spoken only[[/tts:text]] end [[other]]");
        assert_eq!((d.cleaned.as_str(), d.tts_text.as_deref()), ("Text  end [[other]]", Some("spoken only")));
        assert!(!parse_directives("plain").has_directive);
    }

    #[test]
    fn code_heavy() {
        assert!(is_code_heavy("```rust\nfn main() { println!(\"hi\"); }\n```\nok"));
        assert!(!is_code_heavy("A long explanation with only `inline` code in it."));
    }
}
