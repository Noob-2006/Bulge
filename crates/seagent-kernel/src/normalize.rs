//! Repair common model mistakes in tool input before it reaches a tool:
//! arrays/objects sent as JSON strings, numbers and booleans sent as strings.
//! Seen in practice with DeepSeek and Mistral; every repaired call is one
//! fewer error round trip. Only coerces when the schema says so and the
//! string parses to exactly that type.

use serde_json::Value;

pub fn coerce(schema: &Value, v: &mut Value) {
    let Some(props) = schema.get("properties").and_then(Value::as_object) else { return };
    let Some(obj) = v.as_object_mut() else { return };
    for (k, ps) in props {
        if let Some(x) = obj.get_mut(k) {
            coerce_value(ps, x, 0);
        }
    }
}

fn coerce_value(ps: &Value, x: &mut Value, depth: u32) {
    if depth > 4 {
        return;
    }
    let ty = ps.get("type").and_then(Value::as_str).unwrap_or("");
    if let Value::String(s) = x {
        let t = s.trim();
        let parsed: Option<Value> = match ty {
            "array" if t.starts_with('[') => serde_json::from_str(t).ok().filter(Value::is_array),
            "object" if t.starts_with('{') => serde_json::from_str(t).ok().filter(Value::is_object),
            "integer" => t.parse::<i64>().ok().map(Value::from),
            "number" => t.parse::<f64>().ok().filter(|f| f.is_finite()).map(Value::from),
            "boolean" => match t {
                "true" => Some(Value::Bool(true)),
                "false" => Some(Value::Bool(false)),
                _ => None,
            },
            _ => None,
        };
        if let Some(p) = parsed {
            *x = p;
        }
    }
    match (ty, x) {
        ("array", Value::Array(items)) => {
            if let Some(is) = ps.get("items") {
                for i in items {
                    coerce_value(is, i, depth + 1);
                }
            }
        }
        ("object", o @ Value::Object(_)) => coerce(ps, o),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn repairs_only_what_the_schema_asks_for() {
        let schema = json!({"type":"object","properties":{
            "items":{"type":"array","items":{"type":"object","properties":{"n":{"type":"integer"}}}},
            "id":{"type":"integer"}, "ratio":{"type":"number"}, "on":{"type":"boolean"},
            "cfg":{"type":"object","properties":{"deep":{"type":"array"}}},
            "text":{"type":"string"}}});
        let mut v = json!({"items":"[{\"n\":\"3\"}]","id":"7","ratio":"0.5","on":"true","cfg":"{\"deep\":\"[1]\"}","text":"[1,2]","extra":"5"});
        coerce(&schema, &mut v);
        assert_eq!(v, json!({"items":[{"n":3}],"id":7,"ratio":0.5,"on":true,"cfg":{"deep":[1]},"text":"[1,2]","extra":"5"}));
        // Unparseable or wrong-shaped strings are left for the tool to reject clearly.
        let mut v = json!({"items":"[broken","id":"seven","on":"yes","cfg":"[1]","ratio":"NaN"});
        let before = v.clone();
        coerce(&schema, &mut v);
        assert_eq!(v, before);
        let mut not_obj = json!("x");
        coerce(&schema, &mut not_obj);
        assert_eq!(not_obj, json!("x"));
    }
}
