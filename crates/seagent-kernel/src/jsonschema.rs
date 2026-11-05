//! A JSON Schema validator (draft 2020-12 / draft-07 keywords that matter for
//! model output contracts) plus the output-contract helpers shared by
//! `delegate_task` `output_schema`, `structured_output`, `llm_task` and
//! `decision_evaluate` (Hermes tools/delegation_output_schema.py).

use serde_json::{Map, Value};

/// Errors reported per validation (Hermes bounds the retry prompt the same way).
pub const MAX_ERRORS: usize = 10;

/// Check that `schema` is usable: an object (or boolean) whose keywords have the
/// right shapes and whose regexes compile. `Err` explains the first problem.
pub fn check_schema(schema: &Value) -> Result<(), String> {
    fn walk(s: &Value, path: &str) -> Result<(), String> {
        let o = match s {
            Value::Bool(_) => return Ok(()),
            Value::Object(o) => o,
            _ => return Err(format!("{path}: a schema must be an object or a boolean")),
        };
        if let Some(t) = o.get("type") {
            let ok = |v: &Value| v.as_str().is_some_and(|t| ["null", "boolean", "object", "array", "number", "integer", "string"].contains(&t));
            match t {
                Value::Array(a) if a.iter().all(ok) => {}
                v if ok(v) => {}
                _ => return Err(format!("{path}.type: unknown type {t}")),
            }
        }
        if let Some(p) = o.get("pattern") {
            let p = p.as_str().ok_or_else(|| format!("{path}.pattern must be a string"))?;
            regex::Regex::new(p).map_err(|e| format!("{path}.pattern: invalid regex: {e}"))?;
        }
        if let Some(r) = o.get("required") {
            if !r.as_array().is_some_and(|a| a.iter().all(Value::is_string)) {
                return Err(format!("{path}.required must be an array of strings"));
            }
        }
        if let Some(e) = o.get("enum") {
            if !e.is_array() {
                return Err(format!("{path}.enum must be an array"));
            }
        }
        for k in ["minimum", "maximum", "multipleOf", "minLength", "maxLength", "minItems", "maxItems", "minProperties", "maxProperties"] {
            if let Some(v) = o.get(k) {
                if !v.is_number() {
                    return Err(format!("{path}.{k} must be a number"));
                }
            }
        }
        for k in ["properties", "patternProperties", "$defs", "definitions", "dependentSchemas"] {
            if let Some(v) = o.get(k) {
                let m = v.as_object().ok_or_else(|| format!("{path}.{k} must be an object"))?;
                for (name, sub) in m {
                    if k == "patternProperties" {
                        regex::Regex::new(name).map_err(|e| format!("{path}.{k}: invalid regex `{name}`: {e}"))?;
                    }
                    walk(sub, &format!("{path}.{k}.{name}"))?;
                }
            }
        }
        for k in ["items", "additionalProperties", "additionalItems", "contains", "propertyNames", "not", "if", "then", "else", "unevaluatedProperties"] {
            match o.get(k) {
                Some(Value::Array(a)) if k == "items" => {
                    for (i, sub) in a.iter().enumerate() {
                        walk(sub, &format!("{path}.{k}[{i}]"))?;
                    }
                }
                Some(sub) => walk(sub, &format!("{path}.{k}"))?,
                None => {}
            }
        }
        for k in ["allOf", "anyOf", "oneOf", "prefixItems"] {
            if let Some(v) = o.get(k) {
                let a = v.as_array().ok_or_else(|| format!("{path}.{k} must be an array"))?;
                for (i, sub) in a.iter().enumerate() {
                    walk(sub, &format!("{path}.{k}[{i}]"))?;
                }
            }
        }
        Ok(())
    }
    if !schema.is_object() && !schema.is_boolean() {
        return Err("schema must be a JSON Schema object".into());
    }
    walk(schema, "$")
}

/// Validate `value` against `schema`. Returns at most [`MAX_ERRORS`] messages in
/// the `$.path: message` form.
pub fn validate(schema: &Value, value: &Value) -> Vec<String> {
    let mut v = Validator { root: schema, errors: Vec::new(), depth: 0 };
    v.check(schema, value, "$");
    v.errors.truncate(MAX_ERRORS);
    v.errors
}

pub fn is_valid(schema: &Value, value: &Value) -> bool {
    validate(schema, value).is_empty()
}

struct Validator<'a> {
    root: &'a Value,
    errors: Vec<String>,
    depth: u32,
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn type_matches(t: &str, v: &Value) -> bool {
    match t {
        "integer" => match v {
            Value::Number(n) => n.is_i64() || n.is_u64() || n.as_f64().is_some_and(|f| f.fract() == 0.0),
            _ => false,
        },
        "number" => v.is_number(),
        other => type_name(v) == other || (other == "integer" && v.is_number()),
    }
}

/// JSON equality with numeric comparison (1 == 1.0).
fn json_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(a, b)| json_eq(a, b)),
        (Value::Object(x), Value::Object(y)) => x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| json_eq(v, w))),
        _ => a == b,
    }
}

impl<'a> Validator<'a> {
    fn err(&mut self, path: &str, msg: String) {
        if self.errors.len() < MAX_ERRORS * 4 {
            self.errors.push(format!("{path}: {msg}"));
        }
    }

    /// Does `value` match `schema` (without recording errors)?
    fn matches(&mut self, schema: &'a Value, value: &Value) -> bool {
        let saved = std::mem::take(&mut self.errors);
        self.check(schema, value, "$");
        let ok = self.errors.is_empty();
        self.errors = saved;
        ok
    }

    fn resolve(&self, r: &str) -> Option<&'a Value> {
        let ptr = r.strip_prefix('#')?;
        if ptr.is_empty() {
            return Some(self.root);
        }
        let mut cur = self.root;
        for part in ptr.trim_start_matches('/').split('/') {
            let part = part.replace("~1", "/").replace("~0", "~");
            cur = match cur {
                Value::Object(o) => o.get(&part)?,
                Value::Array(a) => a.get(part.parse::<usize>().ok()?)?,
                _ => return None,
            };
        }
        Some(cur)
    }

    fn check(&mut self, schema: &'a Value, value: &Value, path: &str) {
        let o = match schema {
            Value::Bool(true) => return,
            Value::Bool(false) => return self.err(path, "no value is allowed here".into()),
            Value::Object(o) => o,
            _ => return,
        };
        if self.depth > 64 {
            return self.err(path, "schema nesting too deep (recursive $ref?)".into());
        }
        if let Some(r) = o.get("$ref").and_then(Value::as_str) {
            match self.resolve(r) {
                Some(target) => {
                    self.depth += 1;
                    self.check(target, value, path);
                    self.depth -= 1;
                }
                None => self.err(path, format!("unresolvable $ref `{r}`")),
            }
        }
        if let Some(t) = o.get("type") {
            let ok = match t {
                Value::String(s) => type_matches(s, value),
                Value::Array(a) => a.iter().filter_map(Value::as_str).any(|s| type_matches(s, value)),
                _ => true,
            };
            if !ok {
                let want = match t {
                    Value::String(s) => s.clone(),
                    Value::Array(a) => a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" or "),
                    _ => String::new(),
                };
                // A type mismatch makes the type-specific keywords meaningless.
                return self.err(path, format!("expected {want}, got {}", type_name(value)));
            }
        }
        if let Some(e) = o.get("enum").and_then(Value::as_array) {
            if !e.iter().any(|x| json_eq(x, value)) {
                let shown: Vec<String> = e.iter().take(12).map(|x| x.to_string()).collect();
                self.err(path, format!("{value} is not one of [{}]", shown.join(", ")));
            }
        }
        if let Some(c) = o.get("const") {
            if !json_eq(c, value) {
                self.err(path, format!("must equal {c}"));
            }
        }
        match value {
            Value::String(s) => self.string(o, s, path),
            Value::Number(_) => self.number(o, value, path),
            Value::Array(a) => self.array(o, a, path),
            Value::Object(m) => self.object(o, m, path),
            _ => {}
        }
        if let Some(all) = o.get("allOf").and_then(Value::as_array) {
            for s in all {
                self.check(s, value, path);
            }
        }
        if let Some(any) = o.get("anyOf").and_then(Value::as_array) {
            if !any.iter().any(|s| self.matches(s, value)) {
                self.err(path, "does not match any of the allowed schemas (anyOf)".into());
            }
        }
        if let Some(one) = o.get("oneOf").and_then(Value::as_array) {
            let n = one.iter().filter(|s| self.matches(s, value)).count();
            if n != 1 {
                self.err(path, format!("must match exactly one schema in oneOf (matched {n})"));
            }
        }
        if let Some(not) = o.get("not") {
            if self.matches(not, value) {
                self.err(path, "must not match the `not` schema".into());
            }
        }
        if let Some(cond) = o.get("if") {
            let branch = if self.matches(cond, value) { o.get("then") } else { o.get("else") };
            if let Some(b) = branch {
                self.check(b, value, path);
            }
        }
    }

    fn string(&mut self, o: &Map<String, Value>, s: &str, path: &str) {
        let n = s.chars().count() as u64;
        if let Some(min) = o.get("minLength").and_then(Value::as_u64) {
            if n < min {
                self.err(path, format!("string shorter than {min} characters"));
            }
        }
        if let Some(max) = o.get("maxLength").and_then(Value::as_u64) {
            if n > max {
                self.err(path, format!("string longer than {max} characters"));
            }
        }
        if let Some(p) = o.get("pattern").and_then(Value::as_str) {
            match regex::Regex::new(p) {
                Ok(re) if !re.is_match(s) => self.err(path, format!("does not match pattern `{p}`")),
                Ok(_) => {}
                Err(e) => self.err(path, format!("invalid pattern `{p}`: {e}")),
            }
        }
        if let Some(f) = o.get("format").and_then(Value::as_str) {
            let ok = match f {
                "date" => is_date(s),
                "date-time" => s.len() >= 19 && is_date(&s[..10]) && matches!(s.as_bytes()[10], b'T' | b't' | b' '),
                "email" => s.split_once('@').is_some_and(|(a, b)| !a.is_empty() && b.contains('.') && !b.starts_with('.')),
                "uri" | "url" => s.split_once("://").is_some_and(|(sch, rest)| !sch.is_empty() && sch.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) && !rest.is_empty()),
                "uuid" => s.len() == 36 && s.chars().enumerate().all(|(i, c)| if [8, 13, 18, 23].contains(&i) { c == '-' } else { c.is_ascii_hexdigit() }),
                _ => true,
            };
            if !ok {
                self.err(path, format!("is not a valid {f}"));
            }
        }
    }

    fn number(&mut self, o: &Map<String, Value>, v: &Value, path: &str) {
        let x = v.as_f64().unwrap_or(0.0);
        let f = |k: &str| o.get(k).and_then(Value::as_f64);
        let draft4_excl = |k: &str| o.get(k).and_then(Value::as_bool).unwrap_or(false);
        if let Some(m) = f("minimum") {
            if x < m || (draft4_excl("exclusiveMinimum") && x == m) {
                self.err(path, format!("{v} is less than the minimum {m}"));
            }
        }
        if let Some(m) = f("maximum") {
            if x > m || (draft4_excl("exclusiveMaximum") && x == m) {
                self.err(path, format!("{v} is greater than the maximum {m}"));
            }
        }
        if let Some(m) = f("exclusiveMinimum") {
            if x <= m {
                self.err(path, format!("{v} must be greater than {m}"));
            }
        }
        if let Some(m) = f("exclusiveMaximum") {
            if x >= m {
                self.err(path, format!("{v} must be less than {m}"));
            }
        }
        if let Some(m) = f("multipleOf").filter(|m| *m > 0.0) {
            let q = x / m;
            if (q - q.round()).abs() > 1e-9 {
                self.err(path, format!("{v} is not a multiple of {m}"));
            }
        }
    }

    fn array(&mut self, o: &'a Map<String, Value>, a: &[Value], path: &str) {
        let n = a.len() as u64;
        if let Some(min) = o.get("minItems").and_then(Value::as_u64) {
            if n < min {
                self.err(path, format!("array has {n} items, fewer than {min}"));
            }
        }
        if let Some(max) = o.get("maxItems").and_then(Value::as_u64) {
            if n > max {
                self.err(path, format!("array has {n} items, more than {max}"));
            }
        }
        if o.get("uniqueItems").and_then(Value::as_bool) == Some(true) {
            for i in 0..a.len() {
                if a[..i].iter().any(|x| json_eq(x, &a[i])) {
                    self.err(&format!("{path}[{i}]"), "duplicate item (uniqueItems)".into());
                    break;
                }
            }
        }
        // Tuple forms: 2020-12 `prefixItems` + `items`, draft-07 `items: [..]` + `additionalItems`.
        let (prefix, rest): (&[Value], Option<&'a Value>) = match (o.get("prefixItems").and_then(Value::as_array), o.get("items")) {
            (Some(p), items) => (p.as_slice(), items),
            (None, Some(Value::Array(p))) => (p.as_slice(), o.get("additionalItems")),
            (None, items) => (&[], items),
        };
        for (i, item) in a.iter().enumerate() {
            let sub = if i < prefix.len() { Some(&prefix[i]) } else { rest };
            if let Some(s) = sub {
                self.check(s, item, &format!("{path}[{i}]"));
            }
        }
        if let Some(c) = o.get("contains") {
            let matched = a.iter().filter(|x| self.matches(c, x)).count() as u64;
            let min = o.get("minContains").and_then(Value::as_u64).unwrap_or(1);
            if matched < min {
                self.err(path, "no item matches `contains`".into());
            }
            if let Some(max) = o.get("maxContains").and_then(Value::as_u64) {
                if matched > max {
                    self.err(path, format!("more than {max} items match `contains`"));
                }
            }
        }
    }

    fn object(&mut self, o: &'a Map<String, Value>, m: &Map<String, Value>, path: &str) {
        let n = m.len() as u64;
        if let Some(min) = o.get("minProperties").and_then(Value::as_u64) {
            if n < min {
                self.err(path, format!("object has fewer than {min} properties"));
            }
        }
        if let Some(max) = o.get("maxProperties").and_then(Value::as_u64) {
            if n > max {
                self.err(path, format!("object has more than {max} properties"));
            }
        }
        if let Some(req) = o.get("required").and_then(Value::as_array) {
            for k in req.iter().filter_map(Value::as_str) {
                if !m.contains_key(k) {
                    self.err(path, format!("'{k}' is a required property"));
                }
            }
        }
        if let Some(dr) = o.get("dependentRequired").and_then(Value::as_object) {
            for (k, needs) in dr {
                if m.contains_key(k) {
                    for need in needs.as_array().into_iter().flatten().filter_map(Value::as_str) {
                        if !m.contains_key(need) {
                            self.err(path, format!("'{need}' is required when '{k}' is present"));
                        }
                    }
                }
            }
        }
        let props = o.get("properties").and_then(Value::as_object);
        let pattern_props: Vec<(regex::Regex, &'a Value)> = o.get("patternProperties").and_then(Value::as_object).map(|pp| pp.iter().filter_map(|(k, v)| regex::Regex::new(k).ok().map(|r| (r, v))).collect()).unwrap_or_default();
        let additional = o.get("additionalProperties").or_else(|| o.get("unevaluatedProperties"));
        for (k, v) in m {
            let p = format!("{path}.{k}");
            let mut known = false;
            if let Some(s) = props.and_then(|p| p.get(k)) {
                known = true;
                self.check(s, v, &p);
            }
            for (re, s) in &pattern_props {
                if re.is_match(k) {
                    known = true;
                    self.check(s, v, &p);
                }
            }
            if !known {
                match additional {
                    Some(Value::Bool(false)) => self.err(path, format!("additional property '{k}' is not allowed")),
                    Some(s @ Value::Object(_)) => self.check(s, v, &p),
                    _ => {}
                }
            }
            if let Some(pn) = o.get("propertyNames") {
                if !self.matches(pn, &Value::String(k.clone())) {
                    self.err(path, format!("property name '{k}' is not allowed"));
                }
            }
        }
        if let Some(ds) = o.get("dependentSchemas").and_then(Value::as_object) {
            for (k, s) in ds {
                if m.contains_key(k) {
                    self.check(s, &Value::Object(m.clone()), path);
                }
            }
        }
    }
}

fn is_date(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let num = |r: std::ops::Range<usize>| s[r].parse::<u32>().ok();
    matches!((num(0..4), num(5..7), num(8..10)), (Some(_), Some(m), Some(d)) if (1..=12).contains(&m) && (1..=31).contains(&d))
}

// ───────────────────────── output contracts ─────────────────────────

/// `output_schema` from a tool argument: an object, or a JSON string holding one.
pub fn coerce_schema(raw: Option<&Value>) -> Result<Option<Value>, String> {
    let v = match raw {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => serde_json::from_str::<Value>(s).map_err(|_| "output_schema must be a JSON Schema object, got a non-JSON string.".to_string())?,
        Some(v) => v.clone(),
    };
    if !v.is_object() {
        return Err(format!("output_schema must be a JSON Schema object, got {}.", type_name(&v)));
    }
    check_schema(&v).map_err(|e| format!("output_schema is not a valid JSON Schema: {e}"))?;
    Ok(Some(v))
}

/// The OUTPUT CONTRACT block appended to a child's brief (Hermes wording).
pub fn output_contract(schema: &Value) -> String {
    format!(
        "OUTPUT CONTRACT (machine-validated):\nYour FINAL response must be ONLY the JSON value that validates against this JSON Schema — no prose before or after it, no code fence, no explanation. Anything else costs a correction turn and, if it fails again, is handed to the caller unvalidated.\n{}",
        serde_json::to_string_pretty(schema).unwrap_or_default()
    )
}

/// Strip fences and prose around the outermost `{…}` / `[…]`.
pub fn extract_json_candidate(text: &str) -> String {
    let mut raw = text.trim().to_string();
    if raw.starts_with("```") {
        raw = raw.split_once('\n').map(|(_, r)| r.to_string()).unwrap_or_default();
        let t = raw.trim_end();
        if let Some(stripped) = t.strip_suffix("```") {
            raw = stripped.to_string();
        }
        raw = raw.trim().to_string();
        if raw.to_lowercase().starts_with("json\n") {
            raw = raw[5..].to_string();
        }
    }
    let mut spans: Vec<(usize, String)> = Vec::new();
    for (open, close) in [('{', '}'), ('[', ']')] {
        if let (Some(a), Some(b)) = (raw.find(open), raw.rfind(close)) {
            if b > a {
                spans.push((a, raw[a..=b].to_string()));
            }
        }
    }
    spans.sort_by_key(|(a, _)| *a);
    for (_, c) in &spans {
        if serde_json::from_str::<Value>(c).is_ok() {
            return c.clone();
        }
    }
    spans.into_iter().next().map(|(_, c)| c).unwrap_or(raw)
}

/// Parse and validate a final answer. Ok(parsed) or Err(errors for the retry turn).
pub fn validate_output(text: &str, schema: &Value) -> Result<Value, Vec<String>> {
    let candidate = extract_json_candidate(text);
    if candidate.trim().is_empty() {
        return Err(vec!["Response was empty — expected a JSON object matching the schema.".into()]);
    }
    let parsed: Value = serde_json::from_str(&candidate).map_err(|e| vec![format!("Response is not valid JSON: {e}")])?;
    let errs = validate(schema, &parsed);
    if errs.is_empty() {
        Ok(parsed)
    } else {
        Err(errs)
    }
}

/// The single bounded correction turn: errors verbatim, schema not re-pasted.
pub fn retry_message(errors: &[String]) -> String {
    let block: Vec<String> = errors.iter().map(|e| format!("- {e}")).collect();
    format!(
        "Your previous final response was rejected by the output contract validator. Validation errors:\n{}\n\nReply with ONLY the corrected JSON object matching the OUTPUT CONTRACT schema from your task context. No prose, no explanations.",
        block.join("\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn types_required_and_additional() {
        let s = json!({"type":"object","properties":{"name":{"type":"string","minLength":2},"n":{"type":"integer","minimum":0},"tags":{"type":"array","items":{"type":"string"},"maxItems":2,"uniqueItems":true}},"required":["name","n"],"additionalProperties":false});
        assert!(is_valid(&s, &json!({"name":"ab","n":3,"tags":["x"]})));
        assert!(is_valid(&s, &json!({"name":"ab","n":3.0})), "3.0 is an integer");
        let e = validate(&s, &json!({"name":"a","n":-1,"tags":["x","x","y"],"extra":1}));
        assert!(e.iter().any(|m| m.starts_with("$.name:") && m.contains("shorter")), "{e:?}");
        assert!(e.iter().any(|m| m.starts_with("$.n:") && m.contains("minimum")));
        assert!(e.iter().any(|m| m.contains("more than 2")));
        assert!(e.iter().any(|m| m.contains("duplicate")));
        assert!(e.iter().any(|m| m.contains("'extra'")));
        let e = validate(&s, &json!({"n":"3"}));
        assert!(e.iter().any(|m| m.contains("'name' is a required property")));
        assert!(e.iter().any(|m| m.contains("expected integer, got string")));
        assert_eq!(validate(&s, &json!([1])), vec!["$: expected object, got array".to_string()]);
    }

    #[test]
    fn combinators_refs_enum_const_and_tuples() {
        let s = json!({"$defs":{"pos":{"type":"number","exclusiveMinimum":0}},
            "type":"object","properties":{
                "k":{"enum":["a","b"]},"c":{"const":1},
                "p":{"$ref":"#/$defs/pos"},
                "u":{"anyOf":[{"type":"string"},{"type":"null"}]},
                "o":{"oneOf":[{"type":"integer"},{"type":"number","maximum":5}]},
                "t":{"type":"array","prefixItems":[{"type":"string"},{"type":"integer"}],"items":false},
                "d":{"type":"string","format":"date"},
                "x":{"not":{"type":"string"}},
                "i":{"if":{"type":"string"},"then":{"pattern":"^v"},"else":{"type":"integer"}}}});
        assert!(is_valid(&s, &json!({"k":"a","c":1.0,"p":2,"u":null,"o":7,"t":["s",1],"d":"2026-11-03","x":1,"i":"v1"})));
        let e = validate(&s, &json!({"k":"z","c":2,"p":0,"u":3,"o":2,"t":["s",1,2],"d":"2026-13-01","x":"s","i":"w"}));
        for needle in ["$.k:", "$.c:", "$.p:", "$.u:", "$.o:", "$.t[2]:", "$.d:", "$.x:", "$.i:"] {
            assert!(e.iter().any(|m| m.starts_with(needle)), "{needle} missing in {e:?}");
        }
        assert!(validate(&json!({"$ref":"#/nope"}), &json!(1))[0].contains("unresolvable"));
        assert_eq!(validate(&json!(false), &json!(1)).len(), 1);
        // Error volume is bounded.
        let many = json!({"type":"array","items":{"type":"string"}});
        assert_eq!(validate(&many, &json!((0..50).collect::<Vec<_>>())).len(), MAX_ERRORS);
    }

    #[test]
    fn schema_checks_and_coercion() {
        assert!(check_schema(&json!({"type":"object","properties":{"a":{"type":"string","pattern":"^x"}}})).is_ok());
        assert!(check_schema(&json!({"type":"thing"})).unwrap_err().contains("unknown type"));
        assert!(check_schema(&json!({"pattern":"("})).unwrap_err().contains("invalid regex"));
        assert!(check_schema(&json!({"required":"a"})).is_err());
        assert!(check_schema(&json!([1])).is_err());
        assert_eq!(coerce_schema(None).unwrap(), None);
        assert!(coerce_schema(Some(&json!("{\"type\":\"object\"}"))).unwrap().is_some());
        assert!(coerce_schema(Some(&json!("not json"))).unwrap_err().contains("non-JSON string"));
        assert!(coerce_schema(Some(&json!(3))).unwrap_err().contains("got integer"));
        assert!(coerce_schema(Some(&json!({"type":"nope"}))).unwrap_err().contains("not a valid JSON Schema"));
    }

    #[test]
    fn output_contract_extraction_and_retry() {
        assert_eq!(extract_json_candidate("```json\n{\"a\":1}\n```"), "{\"a\":1}");
        assert_eq!(extract_json_candidate("Here you go: {\"a\": [1]} done"), "{\"a\": [1]}");
        assert_eq!(extract_json_candidate("[1,2] then {"), "[1,2]");
        let s = json!({"type":"object","required":["ok"]});
        assert_eq!(validate_output("{\"ok\":true}", &s).unwrap(), json!({"ok":true}));
        assert!(validate_output("", &s).unwrap_err()[0].contains("empty"));
        assert!(validate_output("nope", &s).unwrap_err()[0].contains("not valid JSON"));
        let errs = validate_output("{}", &s).unwrap_err();
        let m = retry_message(&errs);
        assert!(m.contains("- $: 'ok' is a required property") && !m.contains("\"required\""));
        assert!(output_contract(&s).starts_with("OUTPUT CONTRACT") && output_contract(&s).contains("\"required\""));
    }
}
