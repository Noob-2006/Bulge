//! A YAML subset → JSON reader for SKILL.md frontmatter, plugin-catalog / optional-mcps
//! manifests and hub metadata: block mappings and sequences, flow `[..]` / `{..}`,
//! single/double-quoted and plain (multi-line) scalars, `|` / `>` block scalars with
//! chomping indicators, comments, `---` document markers. No anchors, tags or multi-docs.

use serde_json::{Map, Value};

struct Line<'a> {
    indent: usize,
    text: &'a str,
    /// 1-based line number for error messages.
    no: usize,
}

/// Parse a YAML document into JSON. Errors name the offending line.
pub fn parse(src: &str) -> Result<Value, String> {
    let src = src.strip_prefix('\u{feff}').unwrap_or(src);
    let raw: Vec<&str> = src.lines().collect();
    let mut p = Parser { raw, pos: 0 };
    p.skip_blank();
    if p.peek().is_some_and(|l| l.text == "---") {
        p.pos += 1;
    }
    let Some(first) = p.peek() else { return Ok(Value::Null) };
    let v = p.block(first.indent)?;
    p.skip_blank();
    match p.peek() {
        Some(l) if l.text == "---" || l.text == "..." => Ok(v),
        Some(l) => Err(format!("line {}: unexpected indentation", l.no)),
        None => Ok(v),
    }
}

/// Split `---\n<yaml>\n---\n<body>`: (frontmatter as JSON object, body). Text without a
/// frontmatter block (or with invalid YAML) yields an empty object and the whole text.
pub fn frontmatter(text: &str) -> (Value, &str) {
    match split_frontmatter(text) {
        Some((y, body)) => match parse(y) {
            Ok(v @ Value::Object(_)) => (v, body),
            _ => (Value::Object(Map::new()), body),
        },
        None => (Value::Object(Map::new()), text),
    }
}

/// Strict variant: errors when the frontmatter block exists but does not parse.
pub fn frontmatter_strict(text: &str) -> Result<(Value, &str), String> {
    match split_frontmatter(text) {
        Some((y, body)) => match parse(y)? {
            v @ Value::Object(_) => Ok((v, body)),
            Value::Null => Ok((Value::Object(Map::new()), body)),
            _ => Err("frontmatter must be a mapping".into()),
        },
        None => Ok((Value::Object(Map::new()), text)),
    }
}

/// (yaml, body) when `text` starts with a `---` fenced block.
pub fn split_frontmatter(text: &str) -> Option<(&str, &str)> {
    let t = text.strip_prefix('\u{feff}').unwrap_or(text);
    let rest = t.strip_prefix("---")?;
    let rest = rest.strip_prefix("\r\n").or_else(|| rest.strip_prefix('\n'))?;
    let mut off = 0;
    for line in rest.split_inclusive('\n') {
        if line.trim_end() == "---" || line.trim_end() == "..." {
            let body = &rest[off + line.len()..];
            return Some((&rest[..off], body));
        }
        off += line.len();
    }
    None
}

struct Parser<'a> {
    raw: Vec<&'a str>,
    pos: usize,
}

/// Strip a trailing ` # comment` outside quotes.
fn strip_comment(s: &str) -> &str {
    let b = s.as_bytes();
    let (mut sq, mut dq) = (false, false);
    for (i, &c) in b.iter().enumerate() {
        match c {
            b'\'' if !dq => sq = !sq,
            b'"' if !sq => dq = !dq,
            b'\\' if dq => {}
            b'#' if !sq && !dq && (i == 0 || b[i - 1] == b' ' || b[i - 1] == b'\t') => return s[..i].trim_end(),
            _ => {}
        }
    }
    s.trim_end()
}

impl<'a> Parser<'a> {
    fn line(&self, i: usize) -> Option<Line<'a>> {
        let r = *self.raw.get(i)?;
        let indent = r.len() - r.trim_start_matches(' ').len();
        Some(Line { indent, text: strip_comment(r[indent..].trim_start_matches('\t')), no: i + 1 })
    }
    fn skip_blank(&mut self) {
        while let Some(l) = self.line(self.pos) {
            if l.text.is_empty() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }
    fn peek(&mut self) -> Option<Line<'a>> {
        self.skip_blank();
        self.line(self.pos)
    }

    fn block(&mut self, indent: usize) -> Result<Value, String> {
        let Some(l) = self.peek() else { return Ok(Value::Null) };
        if l.text == "-" || l.text.starts_with("- ") {
            self.seq(indent)
        } else if split_key(l.text).is_some() {
            self.map(indent)
        } else if l.text.starts_with(['[', '{']) {
            self.pos += 1;
            self.value(l.text, indent.saturating_sub(1), l.no)
        } else {
            // A bare scalar document / nested plain scalar.
            self.pos += 1;
            let mut s = l.text.to_string();
            while let Some(n) = self.peek() {
                if n.indent < indent || n.text == "---" {
                    break;
                }
                s.push(' ');
                s.push_str(n.text);
                self.pos += 1;
            }
            scalar(&s, l.no)
        }
    }

    fn seq(&mut self, indent: usize) -> Result<Value, String> {
        let mut out = Vec::new();
        while let Some(l) = self.peek() {
            if l.indent != indent || !(l.text == "-" || l.text.starts_with("- ")) {
                if l.indent > indent {
                    return Err(format!("line {}: bad indentation in list", l.no));
                }
                break;
            }
            self.pos += 1;
            let rest = l.text[1..].trim_start();
            if rest.is_empty() {
                match self.peek() {
                    Some(n) if n.indent > indent => out.push(self.block(n.indent)?),
                    _ => out.push(Value::Null),
                }
                continue;
            }
            // `- key: value` starts an inline mapping whose further keys sit at the item column.
            let col = indent + (l.text.len() - rest.len());
            if !rest.starts_with(['"', '\'', '[', '{']) && split_key(rest).is_some() {
                self.pos -= 1;
                out.push(self.map_from(col, Some(rest), l.no)?);
                continue;
            }
            out.push(self.value(rest, indent, l.no)?);
        }
        Ok(Value::Array(out))
    }

    fn map(&mut self, indent: usize) -> Result<Value, String> {
        self.map_from(indent, None, 0)
    }

    /// A mapping at column `indent`; `first` = the remainder of a `- key: v` line.
    fn map_from(&mut self, indent: usize, first: Option<&'a str>, first_no: usize) -> Result<Value, String> {
        let mut m = Map::new();
        let mut pending = first.map(|t| (t, first_no));
        loop {
            let (text, no) = match pending.take() {
                Some(x) => {
                    self.pos += 1;
                    x
                }
                None => {
                    let Some(l) = self.peek() else { break };
                    if l.indent != indent || l.text == "---" || l.text == "..." {
                        if l.indent > indent {
                            return Err(format!("line {}: bad indentation", l.no));
                        }
                        break;
                    }
                    if l.text.starts_with("- ") || l.text == "-" {
                        break;
                    }
                    self.pos += 1;
                    (l.text, l.no)
                }
            };
            let Some((k, v)) = split_key(text) else { return Err(format!("line {no}: expected `key: value`")) };
            let key = unquote_key(k);
            let val = if v.is_empty() {
                match self.peek() {
                    Some(n) if n.indent > indent => self.block(n.indent)?,
                    // YAML lets a list sit at the same column as its key.
                    Some(n) if n.indent == indent && (n.text.starts_with("- ") || n.text == "-") => self.seq(indent)?,
                    _ => Value::Null,
                }
            } else {
                self.value(v, indent, no)?
            };
            m.insert(key, val);
        }
        Ok(Value::Object(m))
    }

    /// The value after `key:` or `- `, possibly continuing on more-indented lines.
    fn value(&mut self, v: &'a str, indent: usize, no: usize) -> Result<Value, String> {
        if let Some(h) = block_header(v) {
            return Ok(Value::String(self.block_scalar(h, indent)));
        }
        if v.starts_with('[') || v.starts_with('{') {
            // Flow collections may span lines.
            let mut s = v.to_string();
            while !balanced(&s) {
                let Some(n) = self.line(self.pos) else { return Err(format!("line {no}: unterminated flow collection")) };
                self.pos += 1;
                s.push(' ');
                s.push_str(n.text);
            }
            let mut f = Flow { s: s.as_bytes(), i: 0, no };
            let out = f.value()?;
            f.ws();
            if f.i != f.s.len() {
                return Err(format!("line {no}: trailing characters after flow collection"));
            }
            return Ok(out);
        }
        if (v.starts_with('"') && !closed_quote(v, '"')) || (v.starts_with('\'') && !closed_quote(v, '\'')) {
            let q = v.chars().next().unwrap();
            let mut s = v.to_string();
            loop {
                let Some(r) = self.raw.get(self.pos) else { return Err(format!("line {no}: unterminated string")) };
                self.pos += 1;
                s.push(' ');
                s.push_str(r.trim());
                if closed_quote(&s, q) {
                    break;
                }
            }
            return scalar(&s, no);
        }
        // Plain multi-line scalar: continuation lines are more indented and not `key:`.
        let mut s = v.to_string();
        if !v.starts_with(['"', '\'']) {
            while let Some(n) = self.line(self.pos) {
                if n.text.is_empty() {
                    // Blank line inside a plain scalar = newline; stop if nothing follows.
                    let mut j = self.pos + 1;
                    while self.line(j).is_some_and(|x| x.text.is_empty()) {
                        j += 1;
                    }
                    match self.line(j) {
                        Some(x) if x.indent > indent && split_key(x.text).is_none() => {
                            s.push('\n');
                            self.pos = j;
                            continue;
                        }
                        _ => break,
                    }
                }
                if n.indent <= indent || split_key(n.text).is_some() || n.text.starts_with("- ") {
                    break;
                }
                s.push(' ');
                s.push_str(n.text);
                self.pos += 1;
            }
        }
        scalar(&s, no)
    }

    fn block_scalar(&mut self, (fold, chomp): (bool, char), parent: usize) -> String {
        let mut lines: Vec<String> = Vec::new();
        let mut ind: Option<usize> = None;
        while let Some(r) = self.raw.get(self.pos) {
            let t = r.trim_end();
            if t.trim().is_empty() {
                lines.push(String::new());
                self.pos += 1;
                continue;
            }
            let i = r.len() - r.trim_start_matches(' ').len();
            if i <= parent {
                break;
            }
            let base = *ind.get_or_insert(i);
            if i < base {
                break;
            }
            lines.push(r[base..].trim_end_matches('\r').to_string());
            self.pos += 1;
        }
        // Trailing blank lines belong to chomping, not content.
        let mut trailing = 0;
        while lines.last().is_some_and(|l| l.is_empty()) {
            lines.pop();
            trailing += 1;
        }
        // Give back blank lines we swallowed past the end so the parent sees them (harmless).
        let mut out = if fold {
            let mut s = String::new();
            let mut prev_blank = true;
            for l in &lines {
                if l.is_empty() {
                    s.push('\n');
                    prev_blank = true;
                } else if l.starts_with(' ') {
                    if !prev_blank {
                        s.push('\n');
                    }
                    s.push_str(l);
                    prev_blank = false;
                } else {
                    if !prev_blank {
                        s.push(' ');
                    }
                    s.push_str(l);
                    prev_blank = false;
                }
            }
            s
        } else {
            lines.join("\n")
        };
        match chomp {
            '-' => {}
            '+' => {
                out.push('\n');
                out.push_str(&"\n".repeat(trailing));
            }
            _ => {
                if !out.is_empty() {
                    out.push('\n');
                }
            }
        }
        out
    }
}

fn block_header(v: &str) -> Option<(bool, char)> {
    let mut c = v.chars();
    let fold = match c.next()? {
        '|' => false,
        '>' => true,
        _ => return None,
    };
    let mut chomp = ' ';
    for x in c {
        match x {
            '-' | '+' => chomp = x,
            '1'..='9' => {}
            _ => return None,
        }
    }
    Some((fold, chomp))
}

fn closed_quote(s: &str, q: char) -> bool {
    let b: Vec<char> = s.chars().collect();
    let mut i = 1;
    while i < b.len() {
        if q == '"' && b[i] == '\\' {
            i += 2;
            continue;
        }
        if b[i] == q {
            if q == '\'' && b.get(i + 1) == Some(&'\'') {
                i += 2;
                continue;
            }
            return true;
        }
        i += 1;
    }
    false
}

fn balanced(s: &str) -> bool {
    let (mut depth, mut sq, mut dq, mut esc) = (0i32, false, false, false);
    for c in s.chars() {
        if esc {
            esc = false;
            continue;
        }
        match c {
            '\\' if dq => esc = true,
            '"' if !sq => dq = !dq,
            '\'' if !dq => sq = !sq,
            '[' | '{' if !sq && !dq => depth += 1,
            ']' | '}' if !sq && !dq => depth -= 1,
            _ => {}
        }
    }
    depth <= 0
}

/// `key: rest` (the colon must be followed by space or end). Quoted keys allowed.
fn split_key(t: &str) -> Option<(&str, &str)> {
    if t.starts_with('"') || t.starts_with('\'') {
        let q = t.chars().next()?;
        let end = t[1..].find(q)? + 1;
        let after = &t[end + 1..];
        let rest = after.strip_prefix(':')?;
        return (rest.is_empty() || rest.starts_with(' ')).then(|| (&t[..=end], rest.trim()));
    }
    if t.starts_with(['[', '{', '|', '>', '#']) {
        return None;
    }
    let b = t.as_bytes();
    for i in 0..b.len() {
        if b[i] == b':' && (i + 1 == b.len() || b[i + 1] == b' ' || b[i + 1] == b'\t') {
            let k = t[..i].trim_end();
            if k.is_empty() {
                return None;
            }
            return Some((k, t[i + 1..].trim()));
        }
    }
    None
}

fn unquote_key(k: &str) -> String {
    match scalar(k, 0) {
        Ok(Value::String(s)) => s,
        _ => k.to_string(),
    }
}

fn scalar(s: &str, no: usize) -> Result<Value, String> {
    let s = s.trim();
    if let Some(inner) = s.strip_prefix('"') {
        let inner = inner.strip_suffix('"').ok_or_else(|| format!("line {no}: unterminated string"))?;
        return Ok(Value::String(unescape(inner)));
    }
    if let Some(inner) = s.strip_prefix('\'') {
        let inner = inner.strip_suffix('\'').ok_or_else(|| format!("line {no}: unterminated string"))?;
        return Ok(Value::String(inner.replace("''", "'")));
    }
    Ok(match s {
        "" | "~" | "null" | "Null" | "NULL" => Value::Null,
        "true" | "True" | "TRUE" | "yes" | "Yes" | "on" | "On" => Value::Bool(true),
        "false" | "False" | "FALSE" | "no" | "No" | "off" | "Off" => Value::Bool(false),
        _ => {
            if let Ok(i) = s.parse::<i64>() {
                if !(s.len() > 1 && s.starts_with('0')) {
                    return Ok(Value::from(i));
                }
            }
            if s.contains('.') && s.chars().all(|c| c.is_ascii_digit() || matches!(c, '.' | '-' | '+' | 'e' | 'E')) && s.chars().filter(|c| *c == '.').count() == 1 {
                if let Ok(f) = s.parse::<f64>() {
                    return Ok(serde_json::Number::from_f64(f).map(Value::Number).unwrap_or(Value::String(s.into())));
                }
            }
            Value::String(s.to_string())
        }
    })
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('0') => out.push('\0'),
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('/') => out.push('/'),
            Some('u') => {
                let h: String = it.by_ref().take(4).collect();
                if let Some(ch) = u32::from_str_radix(&h, 16).ok().and_then(char::from_u32) {
                    out.push(ch);
                }
            }
            Some(o) => {
                out.push('\\');
                out.push(o);
            }
            None => out.push('\\'),
        }
    }
    out
}

struct Flow<'b> {
    s: &'b [u8],
    i: usize,
    no: usize,
}

impl Flow<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && (self.s[self.i] as char).is_whitespace() {
            self.i += 1;
        }
    }
    fn err(&self, m: &str) -> String {
        format!("line {}: {m}", self.no)
    }
    fn value(&mut self) -> Result<Value, String> {
        self.ws();
        match self.s.get(self.i) {
            Some(b'[') => {
                self.i += 1;
                let mut v = Vec::new();
                loop {
                    self.ws();
                    if self.s.get(self.i) == Some(&b']') {
                        self.i += 1;
                        return Ok(Value::Array(v));
                    }
                    v.push(self.value()?);
                    self.ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {}
                        _ => return Err(self.err("expected `,` or `]`")),
                    }
                }
            }
            Some(b'{') => {
                self.i += 1;
                let mut m = Map::new();
                loop {
                    self.ws();
                    if self.s.get(self.i) == Some(&b'}') {
                        self.i += 1;
                        return Ok(Value::Object(m));
                    }
                    let k = match self.atom(true)? {
                        Value::String(s) => s,
                        o => o.to_string(),
                    };
                    self.ws();
                    let v = if self.s.get(self.i) == Some(&b':') {
                        self.i += 1;
                        self.value()?
                    } else {
                        Value::Null
                    };
                    m.insert(k, v);
                    self.ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {}
                        _ => return Err(self.err("expected `,` or `}`")),
                    }
                }
            }
            Some(_) => self.atom(false),
            None => Err(self.err("unexpected end of flow collection")),
        }
    }
    fn atom(&mut self, key: bool) -> Result<Value, String> {
        self.ws();
        let start = self.i;
        match self.s.get(self.i) {
            Some(&q @ (b'"' | b'\'')) => {
                self.i += 1;
                while self.i < self.s.len() {
                    let c = self.s[self.i];
                    if q == b'"' && c == b'\\' {
                        self.i += 2;
                        continue;
                    }
                    if c == q {
                        if q == b'\'' && self.s.get(self.i + 1) == Some(&b'\'') {
                            self.i += 2;
                            continue;
                        }
                        self.i += 1;
                        let t = std::str::from_utf8(&self.s[start..self.i]).map_err(|_| self.err("bad utf-8"))?;
                        return scalar(t, self.no);
                    }
                    self.i += 1;
                }
                Err(self.err("unterminated string"))
            }
            _ => {
                while self.i < self.s.len() {
                    let c = self.s[self.i];
                    if c == b',' || c == b']' || c == b'}' || (key && c == b':' && self.s.get(self.i + 1).is_none_or(|n| *n == b' ')) {
                        break;
                    }
                    if c == b':' && self.s.get(self.i + 1) == Some(&b' ') && !key {
                        break;
                    }
                    self.i += 1;
                }
                let t = std::str::from_utf8(&self.s[start..self.i]).map_err(|_| self.err("bad utf-8"))?;
                scalar(t, self.no)
            }
        }
    }
}

/// Serialize JSON back to a YAML subset `parse` reads (used when writing frontmatter).
pub fn to_yaml(v: &Value) -> String {
    let mut out = String::new();
    emit(v, 0, &mut out);
    out
}

fn emit(v: &Value, indent: usize, out: &mut String) {
    let pad = " ".repeat(indent);
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                match x {
                    Value::Object(o) if !o.is_empty() => {
                        out.push_str(&format!("{pad}{}:\n", quote_if_needed(k)));
                        emit(x, indent + 2, out);
                    }
                    Value::Array(a) if !a.is_empty() && a.iter().any(|e| e.is_object() || e.is_array()) => {
                        out.push_str(&format!("{pad}{}:\n", quote_if_needed(k)));
                        emit(x, indent + 2, out);
                    }
                    _ => out.push_str(&format!("{pad}{}: {}\n", quote_if_needed(k), inline(x))),
                }
            }
        }
        Value::Array(a) => {
            for x in a {
                match x {
                    Value::Object(_) | Value::Array(_) => {
                        let mut sub = String::new();
                        emit(x, indent + 2, &mut sub);
                        let sub = sub.trim_start().to_string();
                        out.push_str(&format!("{pad}- {sub}"));
                    }
                    _ => out.push_str(&format!("{pad}- {}\n", inline(x))),
                }
            }
        }
        _ => out.push_str(&format!("{pad}{}\n", inline(v))),
    }
}

fn inline(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => quote_if_needed(s),
        Value::Array(a) => format!("[{}]", a.iter().map(inline).collect::<Vec<_>>().join(", ")),
        Value::Object(m) => format!("{{{}}}", m.iter().map(|(k, x)| format!("{}: {}", quote_if_needed(k), inline(x))).collect::<Vec<_>>().join(", ")),
    }
}

fn quote_if_needed(s: &str) -> String {
    let plain_ok = !s.is_empty()
        && !s.starts_with([' ', '-', '?', ':', ',', '[', ']', '{', '}', '#', '&', '*', '!', '|', '>', '\'', '"', '%', '@', '`'])
        && !s.ends_with(' ')
        && !s.contains(": ")
        && !s.contains(" #")
        && !s.contains('\n')
        && !s.contains([',', '[', ']', '{', '}'])
        && matches!(scalar(s, 0), Ok(Value::String(_)));
    if plain_ok {
        s.to_string()
    } else {
        serde_json::to_string(s).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn frontmatter_with_nesting_lists_and_flow() {
        let t = "---\nname: airtable\ndescription: Airtable REST API via curl. Records CRUD.\nversion: 1.1.0\nplatforms: [linux, macos, windows]\nprerequisites:\n  env_vars: [AIRTABLE_API_KEY]\n  commands: [curl]\nmetadata:\n  hermes:\n    tags: [Airtable, \"API\"]\n    homepage: https://airtable.com/x\n---\n\n# Body\n";
        let (v, body) = frontmatter(t);
        assert_eq!(v["name"], "airtable");
        assert_eq!(v["version"], "1.1.0");
        assert_eq!(v["platforms"], json!(["linux", "macos", "windows"]));
        assert_eq!(v["prerequisites"]["env_vars"], json!(["AIRTABLE_API_KEY"]));
        assert_eq!(v["metadata"]["hermes"]["tags"], json!(["Airtable", "API"]));
        assert_eq!(v["metadata"]["hermes"]["homepage"], "https://airtable.com/x");
        assert_eq!(body, "\n# Body\n");
    }

    #[test]
    fn block_scalars_comments_and_sequences() {
        let y = "# c\nname: 0bull  # trailing\ndescription: >-\n  Control real iPhones\n  and publish.\npost: |\n  line one\n  line two\nlist:\n- a\n- b: 1\n  c: two\n-\n  - nested\nsame:\n  - x\n  - 'it''s'\nempty:\nnum: 3\nflt: 1.5\nzip: \"0123\"\nver: \"1.0.0\"\nflag: true\n";
        let v = parse(y).unwrap();
        assert_eq!(v["name"], "0bull");
        assert_eq!(v["description"], "Control real iPhones and publish.");
        assert_eq!(v["post"], "line one\nline two\n");
        assert_eq!(v["list"], json!(["a", {"b": 1, "c": "two"}, ["nested"]]));
        assert_eq!(v["same"], json!(["x", "it's"]));
        assert_eq!(v["empty"], Value::Null);
        assert_eq!((v["num"].clone(), v["flt"].clone(), v["zip"].clone(), v["flag"].clone()), (json!(3), json!(1.5), json!("0123"), json!(true)));
    }

    #[test]
    fn plain_multiline_and_flow_maps() {
        let y = "description: a long line\n  continued here\nmeta: {a: 1, b: [x, y], 'c d': \"e: f\"}\nurl: https://x.y/z#frag\n";
        let v = parse(y).unwrap();
        assert_eq!(v["description"], "a long line continued here");
        assert_eq!(v["meta"], json!({"a": 1, "b": ["x", "y"], "c d": "e: f"}));
        assert_eq!(v["url"], "https://x.y/z#frag");
    }

    #[test]
    fn errors_and_round_trip() {
        assert!(parse("a: [1, 2").is_err());
        assert!(frontmatter_strict("---\na: [\n---\nbody").is_err());
        let (v, b) = frontmatter("no frontmatter");
        assert_eq!((v, b), (json!({}), "no frontmatter"));
        let v = json!({"name": "x", "description": "has: colon", "tags": ["a", "b"], "meta": {"k": [{"n": 1}], "e": "", "t": "true"}});
        assert_eq!(parse(&to_yaml(&v)).unwrap(), v);
    }
}
#[cfg(test)]
mod corpus {
    /// `SEAGENT_UPSTREAM_HERMES` / `SEAGENT_UPSTREAM_OPENCLAW`: the upstream checkouts.
    #[test]
    #[ignore]
    fn upstream_corpus() {
        let mut bad = 0;
        let mut n = 0;
        let out = std::process::Command::new("sh").arg("-c").arg("find $SEAGENT_UPSTREAM_HERMES/skills $SEAGENT_UPSTREAM_HERMES/optional-skills $SEAGENT_UPSTREAM_OPENCLAW/skills $SEAGENT_UPSTREAM_OPENCLAW/custodian-skills -name SKILL.md; ls $SEAGENT_UPSTREAM_HERMES/plugin-catalog/*.yaml $SEAGENT_UPSTREAM_HERMES/optional-mcps/*/manifest.yaml").output().unwrap();
        for p in String::from_utf8_lossy(&out.stdout).lines() {
            let t = std::fs::read_to_string(p).unwrap();
            n += 1;
            let r = if p.ends_with(".md") { super::frontmatter_strict(&t).map(|(v, _)| v) } else { super::parse(&t) };
            match r {
                Ok(v) if v.get("name").is_some() || v.get("removed").is_some() => {}
                Ok(v) => { bad += 1; eprintln!("{p}: no name {v}"); }
                Err(e) => { bad += 1; eprintln!("{p}: {e}"); }
            }
        }
        eprintln!("{bad}/{n} bad");
        assert_eq!(bad, 0);
    }
}
