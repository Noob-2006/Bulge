//! Minimal JSON value with JavaScript semantics: object keys keep `JSON.parse` order
//! (integer-like keys first, ascending; duplicates keep the first slot, last value)
//! and numbers print like `Number#toString` / `JSON.stringify`.

#[derive(Debug, Clone, PartialEq)]
pub enum J {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    #[allow(dead_code)] // part of the value API; the reducer only needs `is_record`
    pub fn get(&self, key: &str) -> Option<&J> {
        match self {
            J::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    #[allow(dead_code)]
    pub fn str(&self, key: &str) -> Option<&str> {
        match self.get(key) {
            Some(J::Str(s)) => Some(s),
            _ => None,
        }
    }
    #[allow(dead_code)]
    pub fn num(&self, key: &str) -> Option<f64> {
        match self.get(key) {
            Some(J::Num(n)) => Some(*n),
            _ => None,
        }
    }
    pub fn is_record(&self) -> bool {
        matches!(self, J::Obj(_))
    }
}

pub fn parse(text: &str) -> Option<J> {
    let mut p = P { s: text.as_bytes(), i: 0, src: text };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    (p.i == p.s.len()).then_some(v)
}

struct P<'a> {
    s: &'a [u8],
    i: usize,
    src: &'a str,
}

fn is_array_index(k: &str) -> bool {
    !k.is_empty() && k.len() <= 10 && k.bytes().all(|b| b.is_ascii_digit()) && (k == "0" || !k.starts_with('0')) && k.parse::<u64>().is_ok_and(|n| n < u32::MAX as u64)
}

impl P<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn lit(&mut self, w: &str, v: J) -> Option<J> {
        if self.s[self.i..].starts_with(w.as_bytes()) {
            self.i += w.len();
            Some(v)
        } else {
            None
        }
    }
    fn value(&mut self, depth: usize) -> Option<J> {
        if depth > 512 {
            return None;
        }
        match *self.s.get(self.i)? {
            b'{' => {
                self.i += 1;
                let mut m: Vec<(String, J)> = vec![];
                self.ws();
                if self.s.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Some(J::Obj(m));
                }
                loop {
                    self.ws();
                    if self.s.get(self.i) != Some(&b'"') {
                        return None;
                    }
                    let k = self.string()?;
                    self.ws();
                    if self.s.get(self.i) != Some(&b':') {
                        return None;
                    }
                    self.i += 1;
                    self.ws();
                    let v = self.value(depth + 1)?;
                    match m.iter_mut().find(|(e, _)| *e == k) {
                        Some(slot) => slot.1 = v,
                        None => m.push((k, v)),
                    }
                    self.ws();
                    match self.s.get(self.i)? {
                        b',' => self.i += 1,
                        b'}' => {
                            self.i += 1;
                            break;
                        }
                        _ => return None,
                    }
                }
                // Property order of JS objects: array-index keys ascending, then insertion order.
                let (mut idx, rest): (Vec<_>, Vec<_>) = m.into_iter().partition(|(k, _)| is_array_index(k));
                idx.sort_by_key(|(k, _)| k.parse::<u64>().unwrap_or(0));
                idx.extend(rest);
                Some(J::Obj(idx))
            }
            b'[' => {
                self.i += 1;
                let mut a = vec![];
                self.ws();
                if self.s.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Some(J::Arr(a));
                }
                loop {
                    self.ws();
                    a.push(self.value(depth + 1)?);
                    self.ws();
                    match self.s.get(self.i)? {
                        b',' => self.i += 1,
                        b']' => {
                            self.i += 1;
                            return Some(J::Arr(a));
                        }
                        _ => return None,
                    }
                }
            }
            b'"' => self.string().map(J::Str),
            b't' => self.lit("true", J::Bool(true)),
            b'f' => self.lit("false", J::Bool(false)),
            b'n' => self.lit("null", J::Null),
            _ => self.number(),
        }
    }
    fn number(&mut self) -> Option<J> {
        let start = self.i;
        let digits = |p: &mut Self| {
            let s = p.i;
            while p.i < p.s.len() && p.s[p.i].is_ascii_digit() {
                p.i += 1;
            }
            p.i - s
        };
        if self.s.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        let int_start = self.i;
        let n = digits(self);
        if n == 0 || (n > 1 && self.s[int_start] == b'0') {
            return None;
        }
        if self.s.get(self.i) == Some(&b'.') {
            self.i += 1;
            if digits(self) == 0 {
                return None;
            }
        }
        if matches!(self.s.get(self.i), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.s.get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if digits(self) == 0 {
                return None;
            }
        }
        self.src[start..self.i].parse::<f64>().ok().map(J::Num)
    }
    fn hex4(&mut self) -> Option<u32> {
        let h = self.src.get(self.i..self.i + 4)?;
        let v = u32::from_str_radix(h, 16).ok()?;
        if !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        self.i += 4;
        Some(v)
    }
    fn string(&mut self) -> Option<String> {
        self.i += 1;
        let mut out = String::new();
        loop {
            let start = self.i;
            while self.i < self.s.len() && self.s[self.i] != b'"' && self.s[self.i] != b'\\' {
                if self.s[self.i] < 0x20 {
                    return None;
                }
                self.i += 1;
            }
            out.push_str(&self.src[start..self.i]);
            match *self.s.get(self.i)? {
                b'"' => {
                    self.i += 1;
                    return Some(out);
                }
                _ => {
                    self.i += 1;
                    let c = *self.s.get(self.i)?;
                    self.i += 1;
                    match c {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let a = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&a) && self.s[self.i..].starts_with(b"\\u") {
                                let save = self.i;
                                self.i += 2;
                                match self.hex4() {
                                    Some(b) if (0xDC00..0xE000).contains(&b) => 0x10000 + ((a - 0xD800) << 10) + (b - 0xDC00),
                                    _ => {
                                        self.i = save;
                                        a
                                    }
                                }
                            } else {
                                a
                            };
                            out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                        }
                        _ => return None,
                    }
                }
            }
        }
    }
}

/// `Number.prototype.toString()` for finite and non-finite values.
pub fn js_num(n: f64) -> String {
    if n.is_nan() {
        return "NaN".into();
    }
    if n.is_infinite() {
        return if n > 0.0 { "Infinity" } else { "-Infinity" }.into();
    }
    if n == 0.0 {
        return "0".into();
    }
    // Shortest round-trip digits and decimal exponent, then JS layout rules.
    let e = format!("{:e}", n.abs());
    let (mant, exp) = e.split_once('e').unwrap_or((&e, "0"));
    let digits: String = mant.chars().filter(|c| c.is_ascii_digit()).collect();
    let exp: i32 = exp.parse().unwrap_or(0);
    let k = digits.len() as i32;
    let point = exp + 1; // position of the decimal point relative to the digits
    let sign = if n < 0.0 { "-" } else { "" };
    let body = if k <= point && point <= 21 {
        format!("{digits}{}", "0".repeat((point - k) as usize))
    } else if 0 < point && point <= 21 {
        format!("{}.{}", &digits[..point as usize], &digits[point as usize..])
    } else if -6 < point && point <= 0 {
        format!("0.{}{digits}", "0".repeat((-point) as usize))
    } else {
        let es = if exp >= 0 { format!("+{exp}") } else { exp.to_string() };
        if k == 1 { format!("{digits}e{es}") } else { format!("{}.{}e{es}", &digits[..1], &digits[1..]) }
    };
    format!("{sign}{body}")
}

fn quote(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `JSON.stringify(value, null, 2)`.
#[allow(dead_code)] // used by tests; the reducer emits its own schema summary
pub fn pretty(v: &J) -> String {
    fn go(v: &J, ind: usize, out: &mut String) {
        match v {
            J::Null => out.push_str("null"),
            J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            J::Num(n) => out.push_str(&if n.is_finite() { js_num(*n) } else { "null".into() }),
            J::Str(s) => quote(s, out),
            J::Arr(a) if a.is_empty() => out.push_str("[]"),
            J::Obj(m) if m.is_empty() => out.push_str("{}"),
            J::Arr(a) => {
                out.push_str("[\n");
                for (i, x) in a.iter().enumerate() {
                    out.push_str(&" ".repeat(ind + 2));
                    go(x, ind + 2, out);
                    out.push_str(if i + 1 < a.len() { ",\n" } else { "\n" });
                }
                out.push_str(&" ".repeat(ind));
                out.push(']');
            }
            J::Obj(m) => {
                out.push_str("{\n");
                for (i, (k, x)) in m.iter().enumerate() {
                    out.push_str(&" ".repeat(ind + 2));
                    quote(k, out);
                    out.push_str(": ");
                    go(x, ind + 2, out);
                    out.push_str(if i + 1 < m.len() { ",\n" } else { "\n" });
                }
                out.push_str(&" ".repeat(ind));
                out.push('}');
            }
        }
    }
    let mut out = String::new();
    go(v, 0, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_number_formatting() {
        for (n, s) in [(1.0, "1"), (1.5, "1.5"), (-0.25, "-0.25"), (1e21, "1e+21"), (1e20, "100000000000000000000"), (1.5e-7, "1.5e-7"), (0.000001, "0.000001"), (123456.789, "123456.789")] {
            assert_eq!(js_num(n), s);
        }
    }

    #[test]
    fn parse_keeps_js_key_order() {
        let v = parse(r#"{"b":1,"2":0,"a":[true,null,"x\u00e9"],"1":2,"b":3}"#).unwrap();
        let J::Obj(m) = &v else { panic!() };
        let keys: Vec<_> = m.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["1", "2", "b", "a"]);
        assert_eq!(v.num("b"), Some(3.0));
        assert_eq!(pretty(&parse("[]").unwrap()), "[]");
        assert!(parse("{\"a\":01}").is_none() && parse("[1,]").is_none() && parse("tru").is_none());
        assert_eq!(pretty(&parse(r#"{"a":[1,{"b":"c"}]}"#).unwrap()), "{\n  \"a\": [\n    1,\n    {\n      \"b\": \"c\"\n    }\n  ]\n}");
    }
}
