//! A small YAML subset for workflow files: block mappings and sequences, plain / quoted
//! scalars, `|` and `>` block scalars (with `-` / `+` chomping), flow `[...]` / `{...}`
//! collections, and comments. Anchors, tags and multi-document streams are refused.

use serde_json::{Map, Value};

struct Line {
    indent: usize,
    text: String,
    no: usize,
}

pub fn parse(src: &str) -> Result<Value, String> {
    let raw: Vec<String> = src.lines().map(str::to_string).collect();
    let mut p = P { raw, i: 0 };
    p.skip_blank();
    if p.i >= p.raw.len() {
        return Ok(Value::Null);
    }
    let first = p.peek().unwrap();
    let v = p.block(first.indent)?;
    p.skip_blank();
    if let Some(l) = p.peek() {
        return Err(format!("line {}: unexpected content `{}`", l.no, l.text));
    }
    Ok(v)
}

struct P {
    raw: Vec<String>,
    i: usize,
}

fn strip_comment(s: &str) -> &str {
    let (mut sq, mut dq) = (false, false);
    let b = s.as_bytes();
    for (i, c) in s.char_indices() {
        match c {
            '\'' if !dq => sq = !sq,
            '"' if !sq => dq = !dq,
            '#' if !sq && !dq && (i == 0 || b[i - 1] == b' ' || b[i - 1] == b'\t') => return &s[..i],
            _ => {}
        }
    }
    s
}

impl P {
    fn skip_blank(&mut self) {
        while self.i < self.raw.len() {
            let t = strip_comment(&self.raw[self.i]).trim();
            if t.is_empty() || t == "---" {
                self.i += 1;
            } else {
                break;
            }
        }
    }
    fn peek(&self) -> Option<Line> {
        let r = self.raw.get(self.i)?;
        let indent = r.len() - r.trim_start_matches(' ').len();
        Some(Line { indent, text: strip_comment(r).trim().to_string(), no: self.i + 1 })
    }

    fn block(&mut self, indent: usize) -> Result<Value, String> {
        self.skip_blank();
        let Some(l) = self.peek() else { return Ok(Value::Null) };
        if l.text.starts_with("- ") || l.text == "-" {
            self.seq(indent)
        } else {
            self.map(indent)
        }
    }

    fn seq(&mut self, indent: usize) -> Result<Value, String> {
        let mut out = Vec::new();
        loop {
            self.skip_blank();
            let Some(l) = self.peek() else { break };
            if l.indent < indent {
                break;
            }
            if l.indent > indent {
                return Err(format!("line {}: bad indentation", l.no));
            }
            if !(l.text.starts_with("- ") || l.text == "-") {
                break;
            }
            let rest = l.text[1..].trim_start().to_string();
            if rest.is_empty() {
                self.i += 1;
                self.skip_blank();
                match self.peek() {
                    Some(n) if n.indent > indent => out.push(self.block(n.indent)?),
                    _ => out.push(Value::Null),
                }
                continue;
            }
            // `- key: value` starts a mapping whose keys sit at the item's content column.
            let col = indent + (l.text.len() - rest.len());
            if key_split(&rest).is_some() && !rest.starts_with(['[', '{', '"', '\'']) {
                let mut s = " ".repeat(col);
                s.push_str(&rest);
                self.raw[self.i] = s;
                out.push(self.map(col)?);
            } else {
                self.i += 1;
                out.push(self.scalar_or_block(&rest, indent, l.no)?);
            }
        }
        Ok(Value::Array(out))
    }

    fn map(&mut self, indent: usize) -> Result<Value, String> {
        let mut out = Map::new();
        loop {
            self.skip_blank();
            let Some(l) = self.peek() else { break };
            if l.indent < indent {
                break;
            }
            if l.indent > indent {
                return Err(format!("line {}: bad indentation", l.no));
            }
            if l.text.starts_with("- ") {
                break;
            }
            let (k, v) = key_split(&l.text).ok_or_else(|| format!("line {}: expected `key: value`, got `{}`", l.no, l.text))?;
            let key = unquote(k.trim())?;
            self.i += 1;
            let v = v.trim();
            let val = if v.is_empty() {
                self.skip_blank();
                match self.peek() {
                    Some(n) if n.indent > indent => self.block(n.indent)?,
                    // A sequence may sit at the key's own indentation.
                    Some(n) if n.indent == indent && n.text.starts_with("- ") => self.seq(indent)?,
                    _ => Value::Null,
                }
            } else {
                self.scalar_or_block(v, indent, l.no)?
            };
            if out.insert(key.clone(), val).is_some() {
                return Err(format!("line {}: duplicate key `{key}`", l.no));
            }
        }
        Ok(Value::Object(out))
    }

    fn scalar_or_block(&mut self, v: &str, indent: usize, no: usize) -> Result<Value, String> {
        if let Some(h) = v.strip_prefix('|').or_else(|| v.strip_prefix('>')) {
            let folded = v.starts_with('>');
            let chomp = h.trim();
            let mut lines = Vec::new();
            let mut block_indent = None;
            while self.i < self.raw.len() {
                let r = self.raw[self.i].clone();
                let ind = r.len() - r.trim_start_matches(' ').len();
                if r.trim().is_empty() {
                    lines.push(String::new());
                    self.i += 1;
                    continue;
                }
                if ind <= indent {
                    break;
                }
                let bi = *block_indent.get_or_insert(ind);
                if ind < bi {
                    break;
                }
                lines.push(r[bi..].to_string());
                self.i += 1;
            }
            while lines.last().is_some_and(|l| l.is_empty()) && chomp != "+" {
                lines.pop();
            }
            let mut s = if folded {
                let mut o = String::new();
                for (i, l) in lines.iter().enumerate() {
                    if i > 0 {
                        o.push(if l.is_empty() || lines[i - 1].is_empty() { '\n' } else { ' ' });
                    }
                    o.push_str(l);
                }
                o
            } else {
                lines.join("\n")
            };
            if chomp != "-" {
                s.push('\n');
            }
            return Ok(Value::String(s));
        }
        if v.starts_with('&') || v.starts_with('*') || v.starts_with('!') {
            return Err(format!("line {no}: anchors, aliases and tags are not supported"));
        }
        scalar(v).map_err(|e| format!("line {no}: {e}"))
    }
}

/// Split `key: value` at the first colon outside quotes followed by space or end.
fn key_split(s: &str) -> Option<(&str, &str)> {
    let (mut sq, mut dq) = (false, false);
    let b = s.as_bytes();
    for (i, c) in s.char_indices() {
        match c {
            '\'' if !dq => sq = !sq,
            '"' if !sq => dq = !dq,
            '[' | '{' if i == 0 => return None,
            ':' if !sq && !dq && (i + 1 == s.len() || b[i + 1] == b' ') => return Some((&s[..i], &s[i + 1..])),
            _ => {}
        }
    }
    None
}

fn unquote(s: &str) -> Result<String, String> {
    match scalar(s)? {
        Value::String(x) => Ok(x),
        v => Ok(v.to_string()),
    }
}

pub fn scalar(v: &str) -> Result<Value, String> {
    let v = v.trim();
    if let Some(inner) = v.strip_prefix('"').and_then(|x| x.strip_suffix('"')) {
        return serde_json::from_str::<String>(&format!("\"{inner}\"")).map(Value::String).map_err(|e| format!("bad double-quoted string: {e}"));
    }
    if let Some(inner) = v.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')) {
        return Ok(Value::String(inner.replace("''", "'")));
    }
    if v.starts_with('[') || v.starts_with('{') {
        return flow(v);
    }
    Ok(match v {
        "" | "~" | "null" | "Null" | "NULL" => Value::Null,
        "true" | "True" | "TRUE" => Value::Bool(true),
        "false" | "False" | "FALSE" => Value::Bool(false),
        _ => {
            if let Ok(i) = v.parse::<i64>() {
                Value::from(i)
            } else if let Ok(f) = v.parse::<f64>().map_err(|_| ()).and_then(|f| if f.is_finite() && v.chars().any(|c| c.is_ascii_digit()) && !v.chars().any(|c| c.is_alphabetic() && c != 'e' && c != 'E') { Ok(f) } else { Err(()) }) {
                Value::from(f)
            } else {
                Value::String(v.to_string())
            }
        }
    })
}

/// Flow collections: JSON when it parses, else YAML flow with plain scalars.
fn flow(v: &str) -> Result<Value, String> {
    if let Ok(j) = serde_json::from_str(v) {
        return Ok(j);
    }
    let chars: Vec<char> = v.chars().collect();
    let mut i = 0;
    let r = flow_item(&chars, &mut i)?;
    if chars[i..].iter().any(|c| !c.is_whitespace()) {
        return Err("trailing characters after flow collection".into());
    }
    Ok(r)
}

fn flow_item(c: &[char], i: &mut usize) -> Result<Value, String> {
    while *i < c.len() && c[*i].is_whitespace() {
        *i += 1;
    }
    match c.get(*i) {
        Some('[') => {
            *i += 1;
            let mut out = Vec::new();
            loop {
                while *i < c.len() && c[*i].is_whitespace() {
                    *i += 1;
                }
                if c.get(*i) == Some(&']') {
                    *i += 1;
                    return Ok(Value::Array(out));
                }
                out.push(flow_item(c, i)?);
                while *i < c.len() && c[*i].is_whitespace() {
                    *i += 1;
                }
                match c.get(*i) {
                    Some(',') => *i += 1,
                    Some(']') => {}
                    _ => return Err("expected , or ] in flow sequence".into()),
                }
            }
        }
        Some('{') => {
            *i += 1;
            let mut out = Map::new();
            loop {
                while *i < c.len() && c[*i].is_whitespace() {
                    *i += 1;
                }
                if c.get(*i) == Some(&'}') {
                    *i += 1;
                    return Ok(Value::Object(out));
                }
                let k = flow_plain(c, i, &[':', ',', '}'])?;
                if c.get(*i) != Some(&':') {
                    return Err("expected : in flow mapping".into());
                }
                *i += 1;
                let v = flow_item(c, i)?;
                out.insert(unquote(&k)?, v);
                while *i < c.len() && c[*i].is_whitespace() {
                    *i += 1;
                }
                match c.get(*i) {
                    Some(',') => *i += 1,
                    Some('}') => {}
                    _ => return Err("expected , or } in flow mapping".into()),
                }
            }
        }
        _ => scalar(&flow_plain(c, i, &[',', ']', '}'])?),
    }
}

fn flow_plain(c: &[char], i: &mut usize, stop: &[char]) -> Result<String, String> {
    while *i < c.len() && c[*i].is_whitespace() {
        *i += 1;
    }
    let start = *i;
    if let Some(q @ ('"' | '\'')) = c.get(*i).copied() {
        *i += 1;
        while *i < c.len() && c[*i] != q {
            if c[*i] == '\\' && q == '"' {
                *i += 1;
            }
            *i += 1;
        }
        *i += 1;
        return Ok(c[start..(*i).min(c.len())].iter().collect());
    }
    while *i < c.len() && !stop.contains(&c[*i]) {
        *i += 1;
    }
    Ok(c[start..*i].iter().collect::<String>().trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn workflow_shaped_documents() {
        let y = r#"
name: jacket-advice   # comment
args:
  location:
    default: Phoenix
steps:
  - id: fetch
    run: weather --json ${location}
  - id: confirm
    approval: "Want jacket advice?"
    stdin: $fetch.json
  - id: advice
    pipeline: >
      llm.invoke --prompt "Given this weather,
      should I wear a jacket?"
    when: $confirm.approved
    retry: {max: 2, delay_ms: 10}
    tags: [a, 'b c', 3]
  - id: lit
    run: |
      echo one
      echo two
empty:
list:
- 1
- true
- ~
"#;
        let v = parse(y).unwrap();
        assert_eq!(v["args"]["location"]["default"], "Phoenix");
        assert_eq!(v["steps"][1]["approval"], "Want jacket advice?");
        assert_eq!(v["steps"][2]["pipeline"], "llm.invoke --prompt \"Given this weather, should I wear a jacket?\"\n");
        assert_eq!(v["steps"][2]["retry"], json!({"max": 2, "delay_ms": 10}));
        assert_eq!(v["steps"][2]["tags"], json!(["a", "b c", 3]));
        assert_eq!(v["steps"][3]["run"], "echo one\necho two\n");
        assert_eq!(v["empty"], Value::Null);
        assert_eq!(v["list"], json!([1, true, null]));
        assert!(parse("a: 1\na: 2").unwrap_err().contains("duplicate"));
        assert!(parse("a: *x").is_err());
    }
}
