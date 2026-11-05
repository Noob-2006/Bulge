//! PII masking for data at rest and data leaving the box (ent-078).
//!
//! One masker for the audit stream, session exports, eDiscovery bundles and (when
//! `[compliance.pii] at_rest = true`) the stored conversation itself. Each class can be
//! switched off; masks are fixed tokens so a reviewer still sees *that* something was there.
//!
//! | class    | mask          | what matches |
//! |----------|---------------|--------------|
//! | email    | `[email]`     | `local@domain.tld` |
//! | phone    | `[phone]`     | international / grouped numbers (≥ 9 digits) |
//! | card     | `[card]`      | 13–19 digit numbers that pass the Luhn check |
//! | national | `[id]`        | US SSN `123-45-6789`, Taiwan ID `A123456789` |
//! | ip       | `[ip]`        | IPv4 addresses (off by default: audit needs client IPs) |

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PiiConfig {
    /// Mask stored conversation text as it is written (the model then sees masked history too).
    pub at_rest: bool,
    /// Mask session / eDiscovery exports (on by default; `--raw` needs admin and is audited).
    pub exports: bool,
    pub email: bool,
    pub phone: bool,
    pub card: bool,
    pub national_id: bool,
    pub ip: bool,
}

impl Default for PiiConfig {
    fn default() -> Self {
        PiiConfig { at_rest: false, exports: true, email: true, phone: true, card: true, national_id: true, ip: false }
    }
}

struct Res {
    email: Regex,
    phone: Regex,
    card: Regex,
    ssn: Regex,
    twid: Regex,
    ip: Regex,
}

fn res() -> &'static Res {
    static R: OnceLock<Res> = OnceLock::new();
    R.get_or_init(|| Res {
        email: Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap(),
        card: Regex::new(r"\b(?:\d[ -]?){12,18}\d\b").unwrap(),
        ssn: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
        twid: Regex::new(r"\b[A-Z][12]\d{8}\b").unwrap(),
        phone: Regex::new(r"(?:\+\d{1,3}[ .-]?)?\(?\d{2,4}\)?[ .-]\d{3,4}[ .-]\d{3,4}\b").unwrap(),
        ip: Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap(),
    })
}

fn luhn(digits: &str) -> bool {
    let d: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&d.len()) {
        return false;
    }
    let sum: u32 = d.iter().rev().enumerate().map(|(i, &x)| if i % 2 == 1 { let y = x * 2; if y > 9 { y - 9 } else { y } } else { x }).sum();
    sum.is_multiple_of(10)
}

/// Mask with every class the config enables.
pub fn mask_with(s: &str, c: &PiiConfig) -> String {
    let r = res();
    let mut out = s.to_string();
    if c.email {
        out = r.email.replace_all(&out, "[email]").into_owned();
    }
    if c.card {
        out = r.card.replace_all(&out, |m: &regex::Captures| if luhn(&m[0]) { "[card]".to_string() } else { m[0].to_string() }).into_owned();
    }
    if c.national_id {
        out = r.ssn.replace_all(&out, "[id]").into_owned();
        out = r.twid.replace_all(&out, "[id]").into_owned();
    }
    if c.ip {
        out = r.ip.replace_all(&out, "[ip]").into_owned();
    }
    if c.phone {
        out = r.phone.replace_all(&out, "[phone]").into_owned();
    }
    out
}

/// Mask with the default classes.
pub fn mask(s: &str) -> String {
    static D: OnceLock<PiiConfig> = OnceLock::new();
    mask_with(s, D.get_or_init(PiiConfig::default))
}

/// Mask every string inside a JSON value (keys untouched).
pub fn mask_json(v: &serde_json::Value, c: &PiiConfig) -> serde_json::Value {
    use serde_json::Value;
    match v {
        Value::String(s) => Value::String(mask_with(s, c)),
        Value::Array(a) => Value::Array(a.iter().map(|x| mask_json(x, c)).collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), mask_json(x, c))).collect()),
        o => o.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_each_class_and_leaves_ordinary_text() {
        let s = "mail bob@corp.example, call +1 415-555-0100, card 4111 1111 1111 1111, ssn 123-45-6789, id A123456789, host 10.1.2.3";
        let m = mask(s);
        for leaked in ["bob@corp.example", "415-555-0100", "4111 1111 1111 1111", "123-45-6789", "A123456789"] {
            assert!(!m.contains(leaked), "{leaked} in {m}");
        }
        assert!(m.contains("[email]") && m.contains("[card]") && m.contains("[id]") && m.contains("[phone]"));
        assert!(m.contains("10.1.2.3"), "ip is off by default");
        assert!(mask_with(s, &PiiConfig { ip: true, ..Default::default() }).contains("[ip]"));
        // Not a card (Luhn fails), not a phone: an ordinary order number survives.
        assert_eq!(mask("order 1234567890123 shipped"), "order 1234567890123 shipped");
        assert_eq!(mask("nothing here"), "nothing here");
        let off = PiiConfig { email: false, ..Default::default() };
        assert!(mask_with("a@b.io", &off).contains("a@b.io"));
    }

    #[test]
    fn masks_inside_json() {
        let v = serde_json::json!({"text": "reach me at x@y.org", "n": 1, "list": ["123-45-6789"]});
        let m = mask_json(&v, &PiiConfig::default());
        assert_eq!(m["text"], "reach me at [email]");
        assert_eq!(m["list"][0], "[id]");
        assert_eq!(m["n"], 1);
    }
}
