//! Compact JSON Schema (2020-12 subset, draft-07 compatible) validator for MCP
//! `outputSchema` checks: type, properties, required, additionalProperties,
//! items / prefixItems, enum, const, numeric and length bounds, uniqueItems,
//! anyOf / oneOf / allOf / not, if/then/else, and `$ref` into the same
//! document (`#`, `#/$defs/…`, `#/definitions/…`). `pattern` and `format` are
//! not checked. Network `$ref`s are refused, never fetched (MCP spec). Work is
//! bounded so a hostile schema cannot stall the client.

use serde_json::Value;

const MAX_DEPTH: usize = 64;
const MAX_STEPS: usize = 200_000;

/// `Err` names the first failing location (`$.a.b[2]`) and the reason.
pub fn validate(schema: &Value, value: &Value) -> Result<(), String> {
    let mut v = V { root: schema, steps: 0 };
    v.check(schema, value, "$", 0)
}

struct V<'a> {
    root: &'a Value,
    steps: usize,
}

fn type_of(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() || n.as_f64().is_some_and(|f| f.fract() == 0.0) => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn type_ok(want: &str, v: &Value) -> bool {
    let t = type_of(v);
    want == t || (want == "number" && t == "integer")
}

/// JSON equality with 1 == 1.0 (schema `enum`/`const`/`uniqueItems` semantics).
fn json_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| json_eq(p, q)),
        (Value::Object(x), Value::Object(y)) => x.len() == y.len() && x.iter().all(|(k, p)| y.get(k).is_some_and(|q| json_eq(p, q))),
        _ => a == b,
    }
}

fn pointer_token(t: &str) -> String {
    let t = ark_net::urldecode(t);
    t.replace("~1", "/").replace("~0", "~")
}

impl<'a> V<'a> {
    fn resolve(&self, r: &str) -> Result<&'a Value, String> {
        let Some(frag) = r.strip_prefix('#') else { return Err(format!("$ref `{r}` points outside the schema (not fetched)")) };
        let mut cur = self.root;
        for tok in frag.split('/').skip(1) {
            let tok = pointer_token(tok);
            cur = match cur {
                Value::Object(o) => o.get(&tok),
                Value::Array(a) => tok.parse::<usize>().ok().and_then(|i| a.get(i)),
                _ => None,
            }
            .ok_or_else(|| format!("$ref `{r}` does not resolve"))?;
        }
        Ok(cur)
    }

    fn check(&mut self, s: &'a Value, v: &Value, at: &str, depth: usize) -> Result<(), String> {
        self.steps += 1;
        if depth > MAX_DEPTH || self.steps > MAX_STEPS {
            return Err(format!("{at}: schema too deep or too complex to validate"));
        }
        let o = match s {
            Value::Bool(true) => return Ok(()),
            Value::Bool(false) => return Err(format!("{at}: not allowed by schema `false`")),
            Value::Object(o) => o,
            _ => return Ok(()),
        };
        let fail = |why: String| Err(format!("{at}: {why}"));
        if let Some(r) = o.get("$ref").and_then(Value::as_str) {
            let t = self.resolve(r)?;
            self.check(t, v, at, depth + 1)?;
        }
        match o.get("type") {
            Some(Value::String(t)) if !type_ok(t, v) => return fail(format!("expected {t}, got {}", type_of(v))),
            Some(Value::Array(ts)) if !ts.iter().filter_map(Value::as_str).any(|t| type_ok(t, v)) => {
                return fail(format!("expected one of {}, got {}", ts.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("|"), type_of(v)));
            }
            _ => {}
        }
        if let Some(Value::Array(e)) = o.get("enum") {
            if !e.iter().any(|x| json_eq(x, v)) {
                return fail(format!("{v} is not one of {}", Value::Array(e.clone())));
            }
        }
        if let Some(c) = o.get("const") {
            if !json_eq(c, v) {
                return fail(format!("expected constant {c}"));
            }
        }
        let num = |k: &str| o.get(k).and_then(Value::as_f64);
        if let Some(x) = v.as_f64() {
            // draft-04 style boolean exclusive* modifies minimum/maximum.
            let ex = |k: &str| o.get(k).and_then(Value::as_bool).unwrap_or(false);
            if let Some(m) = num("minimum") {
                if x < m || (ex("exclusiveMinimum") && x == m) {
                    return fail(format!("{x} is below the minimum {m}"));
                }
            }
            if let Some(m) = num("maximum") {
                if x > m || (ex("exclusiveMaximum") && x == m) {
                    return fail(format!("{x} is above the maximum {m}"));
                }
            }
            if let Some(m) = num("exclusiveMinimum").filter(|m| x <= *m) {
                return fail(format!("{x} must be greater than {m}"));
            }
            if let Some(m) = num("exclusiveMaximum").filter(|m| x >= *m) {
                return fail(format!("{x} must be less than {m}"));
            }
            if let Some(m) = num("multipleOf").filter(|m| *m > 0.0) {
                let q = x / m;
                if (q - q.round()).abs() > 1e-9 {
                    return fail(format!("{x} is not a multiple of {m}"));
                }
            }
        }
        let count = |k: &str| o.get(k).and_then(Value::as_u64).map(|n| n as usize);
        if let Value::String(t) = v {
            let n = t.chars().count();
            if count("minLength").is_some_and(|m| n < m) {
                return fail(format!("string shorter than {}", count("minLength").unwrap()));
            }
            if count("maxLength").is_some_and(|m| n > m) {
                return fail(format!("string longer than {}", count("maxLength").unwrap()));
            }
        }
        if let Value::Array(a) = v {
            if count("minItems").is_some_and(|m| a.len() < m) {
                return fail(format!("fewer than {} items", count("minItems").unwrap()));
            }
            if count("maxItems").is_some_and(|m| a.len() > m) {
                return fail(format!("more than {} items", count("maxItems").unwrap()));
            }
            if o.get("uniqueItems").and_then(Value::as_bool) == Some(true) {
                for i in 0..a.len() {
                    if a[..i].iter().any(|x| json_eq(x, &a[i])) {
                        return fail(format!("item {i} is a duplicate"));
                    }
                }
            }
            // 2020-12 prefixItems + items; draft-07 array-form items + additionalItems.
            let (prefix, rest) = match (o.get("prefixItems"), o.get("items")) {
                (Some(Value::Array(p)), r) => (p.as_slice(), r),
                (None, Some(Value::Array(p))) => (p.as_slice(), o.get("additionalItems")),
                (_, r) => (&[][..], r),
            };
            for (i, x) in a.iter().enumerate() {
                let sub = if i < prefix.len() { Some(&prefix[i]) } else { rest };
                if let Some(sub) = sub {
                    self.check(sub, x, &format!("{at}[{i}]"), depth + 1)?;
                }
            }
            if let Some(c) = o.get("contains") {
                let mut hit = false;
                for x in a {
                    if self.check(c, x, at, depth + 1).is_ok() {
                        hit = true;
                        break;
                    }
                }
                if !hit {
                    return fail("no item matches `contains`".into());
                }
            }
        }
        if let Value::Object(m) = v {
            if count("minProperties").is_some_and(|n| m.len() < n) {
                return fail(format!("fewer than {} properties", count("minProperties").unwrap()));
            }
            if count("maxProperties").is_some_and(|n| m.len() > n) {
                return fail(format!("more than {} properties", count("maxProperties").unwrap()));
            }
            for r in o.get("required").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                if !m.contains_key(r) {
                    return fail(format!("missing required property `{r}`"));
                }
            }
            let props = o.get("properties").and_then(Value::as_object);
            for (k, x) in m {
                let child = format!("{at}.{k}");
                match props.and_then(|p| p.get(k)) {
                    Some(ps) => self.check(ps, x, &child, depth + 1)?,
                    None => match o.get("additionalProperties") {
                        Some(Value::Bool(false)) => return fail(format!("unexpected property `{k}`")),
                        Some(ap @ Value::Object(_)) => self.check(ap, x, &child, depth + 1)?,
                        _ => {}
                    },
                }
            }
        }
        if let Some(Value::Array(all)) = o.get("allOf") {
            for sub in all {
                self.check(sub, v, at, depth + 1)?;
            }
        }
        if let Some(Value::Array(any)) = o.get("anyOf") {
            let mut last = String::new();
            let mut ok = false;
            for sub in any {
                match self.check(sub, v, at, depth + 1) {
                    Ok(()) => {
                        ok = true;
                        break;
                    }
                    Err(e) => last = e,
                }
            }
            if !ok {
                return fail(format!("matches none of anyOf (last: {last})"));
            }
        }
        if let Some(Value::Array(one)) = o.get("oneOf") {
            let mut n = 0;
            for sub in one {
                if self.check(sub, v, at, depth + 1).is_ok() {
                    n += 1;
                }
            }
            if n != 1 {
                return fail(format!("matches {n} of oneOf (exactly 1 required)"));
            }
        }
        if let Some(not) = o.get("not") {
            if self.check(not, v, at, depth + 1).is_ok() {
                return fail("matches a `not` schema".into());
            }
        }
        if let Some(cond) = o.get("if") {
            let branch = if self.check(cond, v, at, depth + 1).is_ok() { o.get("then") } else { o.get("else") };
            if let Some(b) = branch {
                self.check(b, v, at, depth + 1)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn core_keywords() {
        let s = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string", "minLength": 1, "maxLength": 5},
                "n": {"type": "integer", "minimum": 0, "exclusiveMaximum": 10},
                "tags": {"type": "array", "items": {"enum": ["a", "b"]}, "uniqueItems": true, "maxItems": 2},
                "kind": {"const": "x"},
                "pair": {"prefixItems": [{"type": "string"}, {"type": "number"}], "items": false}
            },
            "required": ["name"],
            "additionalProperties": false
        });
        assert!(validate(&s, &json!({"name": "abc", "n": 3, "tags": ["a"], "kind": "x", "pair": ["k", 1.5]})).is_ok());
        assert!(validate(&s, &json!({"name": "abc", "n": 3.0})).is_ok(), "3.0 is an integer");
        let e = |v: Value| validate(&s, &v).unwrap_err();
        assert!(e(json!({})).contains("missing required property `name`"));
        assert!(e(json!({"name": ""})).contains("$.name: string shorter"));
        assert!(e(json!({"name": "a", "n": 10})).contains("less than 10"));
        assert!(e(json!({"name": "a", "n": 1.5})).contains("expected integer"));
        assert!(e(json!({"name": "a", "tags": ["a", "a"]})).contains("duplicate"));
        assert!(e(json!({"name": "a", "tags": ["c"]})).contains("$.tags[0]"));
        assert!(e(json!({"name": "a", "kind": "y"})).contains("constant"));
        assert!(e(json!({"name": "a", "pair": ["k", 1, 2]})).contains("$.pair[2]"));
        assert!(e(json!({"name": "a", "extra": 1})).contains("unexpected property `extra`"));
        assert!(validate(&json!({"type": ["string", "null"]}), &json!(null)).is_ok());
    }

    #[test]
    fn composition_refs_and_limits() {
        let s = json!({
            "$defs": {"pos": {"type": "number", "minimum": 0}, "tree": {"type": "object", "properties": {"kids": {"type": "array", "items": {"$ref": "#/$defs/tree"}}}, "additionalProperties": {"$ref": "#/$defs/pos"}}},
            "anyOf": [{"$ref": "#/$defs/pos"}, {"$ref": "#/$defs/tree"}]
        });
        assert!(validate(&s, &json!(4)).is_ok());
        assert!(validate(&s, &json!({"kids": [{"w": 1}, {"kids": []}]})).is_ok());
        assert!(validate(&s, &json!({"kids": [{"w": -1}]})).unwrap_err().contains("anyOf"));
        assert!(validate(&s, &json!("x")).is_err());
        let one = json!({"oneOf": [{"type": "integer"}, {"type": "number"}]});
        assert!(validate(&one, &json!(1.5)).is_ok());
        assert!(validate(&one, &json!(2)).unwrap_err().contains("matches 2 of oneOf"));
        assert!(validate(&json!({"allOf": [{"minimum": 1}, {"maximum": 2}]}), &json!(3)).is_err());
        assert!(validate(&json!({"not": {"type": "string"}}), &json!("s")).is_err());
        assert!(validate(&json!({"if": {"properties": {"a": {"const": 1}}}, "then": {"required": ["b"]}}), &json!({"a": 1})).is_err());
        assert!(validate(&json!({"$ref": "https://evil.example/s.json"}), &json!(1)).unwrap_err().contains("not fetched"));
        assert!(validate(&json!({"definitions": {"a": {"type": "string"}}, "$ref": "#/definitions/a"}), &json!(1)).is_err());
        // A self-referential loop is cut off instead of overflowing the stack.
        assert!(validate(&json!({"$ref": "#"}), &json!(1)).unwrap_err().contains("too deep"));
    }
}
