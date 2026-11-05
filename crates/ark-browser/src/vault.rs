//! Model-blind browser autofill (Hermes `browser_vault_tool.py`,
//! `agent/vault_login_classifier.py`, `agent/vault_store.py`, `agent/vault_backends/*`;
//! the classifier itself ports Merit-Systems/OpenInstinct `kernel-login-autofill.ts`; all MIT).
//! Items (logins, cards, addresses) live in `<home>/browser/vault.json` (0600) or in
//! Bitwarden / 1Password through their CLIs. The model only ever sees handles and
//! metadata; fills run as in-page script over the CDP socket (never argv) and report counts.

use crate::util;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

pub const PAYMENT_FIELDS: &[(&str, &str)] = &[("card_number", "cc-number"), ("cardholder_name", "cc-name"), ("exp_month", "cc-exp-month"), ("exp_year", "cc-exp-year"), ("cvc", "cc-csc"), ("billing_postal_code", "postal-code")];
pub const ADDRESS_FIELDS: &[(&str, &str)] = &[("address_line1", "address-line1"), ("address_line2", "address-line2"), ("city", "address-level2"), ("state", "address-level1"), ("postal_code", "postal-code"), ("country", "country-name")];
const REQUIRED_PAYMENT: &[&str] = &["card_number", "exp_month", "exp_year", "cvc"];
const REQUIRED_ADDRESS: &[&str] = &["address_line1", "city", "postal_code", "country"];

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Item {
    pub id: String,
    pub kind: String,
    pub label: String,
    #[serde(default)]
    pub origin: String,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default)]
    pub identifier: String,
    #[serde(default)]
    pub identifier_type: String,
    /// Secret fields (password, totp_secret, card/address fields). Never leave this module.
    #[serde(default)]
    pub secret: BTreeMap<String, String>,
    #[serde(default)]
    pub created_at: u64,
}

impl Item {
    pub fn meta(&self, backend: &str) -> Value {
        let mut e = json!({"handle": self.id, "backend": backend, "label": self.label, "kind": self.kind, "origin": self.origin, "available": self.kind == "login" || !self.origin.is_empty()});
        if self.allowed_origins.len() > 1 {
            e["allowed_origins"] = json!(self.allowed_origins);
        }
        if self.secret.contains_key("totp_secret") {
            e["two_factor"] = "automatic".into();
        }
        if !self.identifier.is_empty() {
            e["identifier"] = self.identifier.clone().into();
            e["identifier_type"] = self.identifier_type.clone().into();
        }
        e
    }
    pub fn origins(&self) -> Vec<String> {
        if !self.allowed_origins.is_empty() {
            self.allowed_origins.clone()
        } else if !self.origin.is_empty() {
            vec![self.origin.clone()]
        } else {
            vec![]
        }
    }
}

pub fn store_path(home: &Path) -> PathBuf {
    home.join("browser").join("vault.json")
}

pub fn load(home: &Path) -> Result<Vec<Item>, String> {
    let p = store_path(home);
    let Ok(s) = std::fs::read_to_string(&p) else { return Ok(vec![]) };
    use std::os::unix::fs::PermissionsExt;
    if std::fs::metadata(&p).map(|m| m.permissions().mode() & 0o077 != 0).unwrap_or(false) {
        return Err(format!("{} must not be readable by group/others (chmod 600)", p.display()));
    }
    serde_json::from_str(&s).map_err(|e| format!("{}: {e}", p.display()))
}

fn save(home: &Path, items: &[Item]) -> Result<(), String> {
    util::write_private(&store_path(home), serde_json::to_string_pretty(items).unwrap().as_bytes()).map_err(|e| e.to_string())
}

/// Normalize to `scheme://host[:port]` (Hermes `normalize_origin`).
pub fn normalize_origin(u: &str) -> Result<String, String> {
    let u = u.trim();
    let u = if u.contains("://") { u.to_string() } else { format!("https://{u}") };
    let o = crate::policy::origin(&u).ok_or_else(|| format!("not a URL: {u}"))?;
    if !(o.starts_with("https://") || o.starts_with("http://")) {
        return Err(format!("vault origins must be http(s): {u}"));
    }
    Ok(o)
}

/// Add an item to the local vault; returns it (with a new handle).
pub fn add(home: &Path, kind: &str, label: &str, origin: &str, mut secret: BTreeMap<String, String>) -> Result<Item, String> {
    let mut items = load(home)?;
    let origin = if origin.is_empty() { String::new() } else { normalize_origin(origin)? };
    let (identifier, id_type) = match kind {
        "login" => {
            let ident = secret.remove("identifier").unwrap_or_default().trim().to_string();
            if secret.get("password").is_none_or(|p| p.is_empty()) {
                return Err("login items require a password".into());
            }
            if origin.is_empty() {
                return Err("login items require an origin (the site's URL)".into());
            }
            let t = if ident.contains('@') { "email" } else if !ident.is_empty() && ident.trim_start_matches('+').chars().all(|c| c.is_ascii_digit()) { "phone" } else { "username" };
            (ident, t.to_string())
        }
        "payment" | "address" => {
            let (allowed, req) = if kind == "payment" { (PAYMENT_FIELDS, REQUIRED_PAYMENT) } else { (ADDRESS_FIELDS, REQUIRED_ADDRESS) };
            secret.retain(|k, v| allowed.iter().any(|(f, _)| f == k) && !v.trim().is_empty());
            let missing: Vec<&str> = req.iter().filter(|f| !secret.contains_key(**f)).copied().collect();
            if !missing.is_empty() {
                return Err(format!("{kind} items require {}", missing.join(", ")));
            }
            (String::new(), String::new())
        }
        o => return Err(format!("unknown vault item kind `{o}` (login, payment, address)")),
    };
    if let Some(t) = secret.get("totp_secret") {
        base32(t).ok_or("totp_secret must be a base32 authenticator key")?;
    }
    let id = format!("v_{}", ark_net::crypto::hex(&ark_net::crypto::random_bytes(6)));
    let it = Item { id, kind: kind.into(), label: if label.is_empty() { origin.split("://").nth(1).unwrap_or("item").to_string() } else { label.into() }, origin, allowed_origins: vec![], identifier, identifier_type: id_type, secret, created_at: util::now_ms() / 1000 };
    items.push(it.clone());
    save(home, &items)?;
    Ok(it)
}

pub fn remove(home: &Path, id: &str) -> Result<bool, String> {
    let mut items = load(home)?;
    let n = items.len();
    items.retain(|i| i.id != id);
    if items.len() == n {
        return Ok(false);
    }
    save(home, &items)?;
    Ok(true)
}

// ---- TOTP (RFC 6238, SHA-1, 30 s, 6 digits) ----

pub fn base32(s: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut n = 0;
    let mut out = vec![];
    for c in s.chars().filter(|c| !c.is_whitespace() && *c != '=' && *c != '-') {
        let v = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u32 - 'A' as u32,
            c @ '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => return None,
        };
        bits = (bits << 5) | v;
        n += 5;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
            bits &= (1 << n) - 1;
        }
    }
    (!out.is_empty()).then_some(out)
}

pub fn totp(secret_b32: &str, unix: u64) -> Option<String> {
    let key = base32(secret_b32)?;
    let h = ark_net::crypto::hmac_sha1(&key, &(unix / 30).to_be_bytes());
    let o = (h[19] & 0xf) as usize;
    let code = (u32::from_be_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]) & 0x7fff_ffff) % 1_000_000;
    Some(format!("{code:06}"))
}

// ---- external managers ----

fn sessions() -> &'static Mutex<HashMap<String, String>> {
    static S: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn backends_enabled() -> Vec<&'static str> {
    let mut v = vec!["local"];
    if util::which("bw").is_some() || std::env::var("ARK_BW").is_ok() {
        v.push("bitwarden");
    }
    if util::which("op").is_some() || std::env::var("ARK_OP").is_ok() {
        v.push("onepassword");
    }
    v
}

fn bin(name: &str) -> String {
    let var = if name == "bw" { "ARK_BW" } else { "ARK_OP" };
    std::env::var(var).unwrap_or_else(|_| name.into())
}

pub fn display_name(b: &str) -> &'static str {
    match b {
        "bitwarden" => "Bitwarden",
        "onepassword" => "1Password",
        _ => "ark vault",
    }
}

pub fn is_unlocked(b: &str) -> bool {
    b == "local" || (b == "onepassword" && std::env::var("OP_SERVICE_ACCOUNT_TOKEN").is_ok()) || sessions().lock().unwrap().contains_key(b)
}

fn cli_env(b: &str) -> Vec<(String, String)> {
    let mut env = vec![("NO_COLOR".to_string(), "1".to_string())];
    if let Some(t) = sessions().lock().unwrap().get(b) {
        env.push((if b == "bitwarden" { "BW_SESSION" } else { "OP_SESSION" }.to_string(), t.clone()));
    }
    env
}

fn run_cli(b: &str, args: &[&str], stdin: Option<&[u8]>, extra: &[(&str, &str)]) -> Result<String, String> {
    let exe = bin(if b == "bitwarden" { "bw" } else { "op" });
    let mut argv = vec![exe.as_str()];
    argv.extend_from_slice(args);
    if b == "bitwarden" {
        argv.push("--nointeraction");
    }
    let mut env: Vec<(String, String)> = cli_env(b);
    env.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    let e: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let (code, out, err) = util::run(&argv, Duration::from_secs(30), stdin, &e)?;
    if code != 0 {
        let low = err.to_ascii_lowercase();
        if low.contains("locked") || low.contains("session") || low.contains("sign in") || low.contains("not signed in") {
            sessions().lock().unwrap().remove(b);
            return Err(format!("unlock_required: {} is locked; call browser_vault action=unlock", display_name(b)));
        }
        return Err(format!("{} failed: {}", argv[0], util::cut(err.trim(), 200)));
    }
    Ok(out)
}

/// Unlock with the master password (bw: --passwordenv; op: signin --raw on stdin).
pub fn unlock(b: &str, master: &str) -> Result<(), String> {
    let token = match b {
        "bitwarden" => run_cli(b, &["unlock", "--raw", "--passwordenv", "ARK_BW_MASTER"], None, &[("ARK_BW_MASTER", master)]).map_err(|e| if e.contains("not logged in") { "Bitwarden unlock failed: not logged in — run `bw login` once in a terminal first".into() } else { format!("Bitwarden unlock failed: {e}") })?,
        "onepassword" => run_cli(b, &["signin", "--raw"], Some(master.as_bytes()), &[]).map_err(|e| format!("1Password unlock failed: {e}"))?,
        _ => return Err(format!("No unlockable vault backend named {b:?}.")),
    };
    let t = token.trim().to_string();
    if t.is_empty() {
        return Err(format!("{} unlock failed: no session key", display_name(b)));
    }
    sessions().lock().unwrap().insert(b.into(), t);
    Ok(())
}

fn web_origins(urls: &[String]) -> Vec<String> {
    let mut o: Vec<String> = vec![];
    for u in urls {
        if let Ok(x) = normalize_origin(u) {
            if !o.contains(&x) {
                o.push(x);
            }
        }
    }
    o
}

/// Logins in an external manager (metadata only).
pub fn list_external(b: &str) -> Result<Vec<Item>, String> {
    let raw: Value = match b {
        "bitwarden" => serde_json::from_str(&run_cli(b, &["list", "items"], None, &[])?).unwrap_or_default(),
        "onepassword" => serde_json::from_str(&run_cli(b, &["item", "list", "--categories", "Login", "--format", "json"], None, &[])?).unwrap_or_default(),
        _ => return Ok(vec![]),
    };
    let mut out = vec![];
    for it in raw.as_array().into_iter().flatten() {
        let (id, label, urls, user) = if b == "bitwarden" {
            if it["type"] != 1 || !it["login"].is_object() {
                continue;
            }
            let urls: Vec<String> = it["login"]["uris"].as_array().into_iter().flatten().filter(|u| u["match"] != 5).filter_map(|u| u["uri"].as_str().map(str::to_string)).collect();
            (format!("bw:{}", it["id"].as_str().unwrap_or("")), it["name"].as_str().unwrap_or("").to_string(), urls, it["login"]["username"].as_str().unwrap_or("").to_string())
        } else {
            let urls: Vec<String> = it["urls"].as_array().into_iter().flatten().filter_map(|u| u["href"].as_str().map(str::to_string)).collect();
            let vault = it["vault"]["id"].as_str().unwrap_or("");
            (format!("op:{}:{vault}", it["id"].as_str().unwrap_or("")), it["title"].as_str().unwrap_or("").to_string(), urls, it["additional_information"].as_str().unwrap_or("").to_string())
        };
        let origins = web_origins(&urls);
        if origins.is_empty() {
            continue;
        }
        out.push(Item { id, kind: "login".into(), label: if label.is_empty() { origins[0].clone() } else { label }, origin: origins[0].clone(), allowed_origins: origins, identifier_type: if user.is_empty() { String::new() } else { "username".into() }, identifier: user, ..Default::default() });
    }
    Ok(out)
}

pub fn backend_of(handle: &str) -> &'static str {
    if handle.starts_with("bw:") {
        "bitwarden"
    } else if handle.starts_with("op:") {
        "onepassword"
    } else {
        "local"
    }
}

/// Find an item's metadata by handle.
pub fn get(home: &Path, handle: &str) -> Result<Option<Item>, String> {
    match backend_of(handle) {
        "local" => Ok(load(home)?.into_iter().find(|i| i.id == handle)),
        b => Ok(list_external(b)?.into_iter().find(|i| i.id == handle)),
    }
}

/// Resolve the secret payload (password for logins).
pub fn resolve(home: &Path, it: &Item) -> Result<BTreeMap<String, String>, String> {
    match backend_of(&it.id) {
        "local" => Ok(load(home)?.into_iter().find(|i| i.id == it.id).map(|i| i.secret).unwrap_or_default()),
        "bitwarden" => {
            let pw = run_cli("bitwarden", &["get", "password", &it.id[3..]], None, &[])?;
            Ok(BTreeMap::from([("password".into(), pw.trim_end_matches(['\r', '\n']).to_string())]))
        }
        _ => {
            let mut p = it.id[3..].splitn(2, ':');
            let (id, vault) = (p.next().unwrap_or(""), p.next().unwrap_or(""));
            let mut args = vec!["item", "get", id];
            if !vault.is_empty() {
                args.extend(["--vault", vault]);
            }
            args.extend(["--fields", "label=password", "--reveal"]);
            let pw = run_cli("onepassword", &args, None, &[])?;
            Ok(BTreeMap::from([("password".into(), pw.trim_end_matches(['\r', '\n']).to_string())]))
        }
    }
}

/// Current one-time code from a stored authenticator seed, if any.
pub fn resolve_otp(home: &Path, handle: &str) -> Option<String> {
    let code = match backend_of(handle) {
        "local" => {
            let it = load(home).ok()?.into_iter().find(|i| i.id == handle)?;
            totp(it.secret.get("totp_secret")?, util::now_ms() / 1000)
        }
        "bitwarden" => run_cli("bitwarden", &["get", "totp", &handle[3..]], None, &[]).ok().map(|s| s.trim().to_string()),
        _ => {
            let id = handle[3..].split(':').next().unwrap_or("");
            run_cli("onepassword", &["item", "get", id, "--otp"], None, &[]).ok().map(|s| s.trim().to_string())
        }
    };
    code.filter(|c| !c.is_empty() && c.chars().all(|x| x.is_ascii_digit()))
}

// ---- classifier (OpenInstinct kernel-login-autofill.ts via Hermes) ----

#[derive(Debug, Clone, Default)]
pub struct Control {
    pub autocomplete: String,
    pub form_index: Option<i64>,
    pub index: i64,
    pub label: String,
    pub name: String,
    pub ty: String,
    pub max_length: Option<i64>,
}

impl Control {
    pub fn from_json(v: &Value) -> Control {
        Control { autocomplete: v["autocomplete"].as_str().unwrap_or("").into(), form_index: v["formIndex"].as_i64(), index: v["index"].as_i64().unwrap_or(0), label: v["label"].as_str().unwrap_or("").into(), name: v["name"].as_str().unwrap_or("").into(), ty: v["type"].as_str().unwrap_or("").into(), max_length: v["maxLength"].as_i64() }
    }
}

#[derive(Debug, Clone)]
pub struct Classified {
    pub c: Control,
    pub score: u32,
    pub token: String,
}

fn norm_text(s: &str) -> String {
    let lower = s.to_lowercase();
    let mut out = String::new();
    let mut sp = false;
    for ch in lower.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            sp = false;
        } else if !sp {
            out.push(' ');
            sp = true;
        }
    }
    out.trim().to_string()
}

fn re(p: &str) -> Regex {
    Regex::new(p).unwrap()
}

pub fn classify_login(c: &Control) -> Option<Classified> {
    let toks: Vec<String> = c.autocomplete.to_lowercase().split_whitespace().map(str::to_string).collect();
    if toks.iter().any(|t| t == "new-password" || t == "one-time-code") {
        return None;
    }
    for t in ["username", "email", "tel", "current-password"] {
        if toks.iter().any(|x| x == t) {
            return Some(Classified { c: c.clone(), score: 100, token: t.into() });
        }
    }
    let s = norm_text(&format!("{} {}", c.name, c.label));
    if re(r"\b(?:new|confirm|create|repeat)\s*password\b").is_match(&s) {
        return None;
    }
    let mk = |score, t: &str| Some(Classified { c: c.clone(), score, token: t.into() });
    match c.ty.as_str() {
        "password" => return mk(90, "current-password"),
        "email" => return mk(85, "email"),
        "tel" => return mk(85, "tel"),
        _ => {}
    }
    if re(r"\b(?:e[\s-]?mail|email address)\b").is_match(&s) {
        return mk(75, "email");
    }
    if re(r"\b(?:phone|telephone|mobile)\b").is_match(&s) {
        return mk(75, "tel");
    }
    if re(r"\b(?:user\s*name|username|login|account|member|membership|mileageplus)\b").is_match(&s) {
        return mk(70, "username");
    }
    None
}

pub fn classify_otp(cs: &[Control]) -> Vec<Classified> {
    let r = re(r"\b(?:one[\s-]?time|verification|security|auth(?:entication|enticator)?|2fa|two[\s-]?factor|mfa|totp|otp|passcode|sms)\b.*\b(?:code|pin|token)\b|\b(?:otp|totp|2fa|mfa|verification\s*code|passcode)\b");
    cs.iter()
        .filter_map(|c| {
            if c.autocomplete.to_lowercase().split_whitespace().any(|t| t == "one-time-code") {
                return Some(Classified { c: c.clone(), score: 100, token: "one-time-code".into() });
            }
            if !["text", "tel", "number", "password", ""].contains(&c.ty.as_str()) {
                return None;
            }
            r.is_match(&norm_text(&format!("{} {}", c.name, c.label))).then(|| Classified { c: c.clone(), score: 70, token: "one-time-code".into() })
        })
        .collect()
}

pub fn classify_checkout(c: &Control) -> Option<Classified> {
    let toks: Vec<String> = c.autocomplete.to_lowercase().split_whitespace().map(str::to_string).collect();
    for t in ["cc-number", "cc-name", "cc-exp", "cc-exp-month", "cc-exp-year", "cc-csc", "address-line1", "address-line2", "address-level2", "address-level1", "postal-code", "country-name", "country"] {
        if toks.iter().any(|x| x == t) {
            return Some(Classified { c: c.clone(), score: 100, token: if t == "country" { "country-name".into() } else { t.into() } });
        }
    }
    if c.ty == "password" || c.ty == "email" {
        return None;
    }
    let s = norm_text(&format!("{} {}", c.name, c.label));
    let h: &[(&str, &str)] = &[
        (r"\b(?:card\s*number|cardnumber|ccnumber|cc\s*num|pan)\b", "cc-number"),
        (r"\b(?:name\s*on\s*card|cardholder|cc\s*name|ccname)\b", "cc-name"),
        (r"\b(?:cvc|cvv|csc|security\s*code|card\s*code)\b", "cc-csc"),
        (r"\b(?:exp(?:iry|iration)?\s*month|exp\s*mm|ccmonth)\b", "cc-exp-month"),
        (r"\b(?:exp(?:iry|iration)?\s*year|exp\s*yy(?:yy)?|ccyear)\b", "cc-exp-year"),
        (r"\b(?:exp(?:iry|iration)?(?:\s*date)?|mm\s*yy|valid\s*thru)\b", "cc-exp"),
        (r"\b(?:address\s*(?:line\s*)?2|apt|suite|unit)\b", "address-line2"),
        (r"\b(?:address(?:\s*line\s*1)?|street)\b", "address-line1"),
        (r"\b(?:city|town|locality)\b", "address-level2"),
        (r"\b(?:state|province|region|county)\b", "address-level1"),
        (r"\b(?:zip|postal|postcode)\b", "postal-code"),
        (r"\b(?:country)\b", "country-name"),
    ];
    h.iter().find(|(p, _)| re(p).is_match(&s)).map(|(_, t)| Classified { c: c.clone(), score: 70, token: (*t).into() })
}

fn best<'a>(v: impl Iterator<Item = &'a Classified>) -> Option<&'a Classified> {
    v.min_by_key(|c| (std::cmp::Reverse(c.score), c.c.index))
}

pub fn select_password(cs: &[Classified], pw: &str) -> Vec<Value> {
    if pw.is_empty() {
        return vec![];
    }
    best(cs.iter().filter(|c| c.token == "current-password")).map(|b| vec![json!({"index": b.c.index, "token": "current-password", "value": pw})]).unwrap_or_default()
}

pub fn select_checkout(cs: &[Classified], secret: &BTreeMap<String, String>, fields: &[(&str, &str)]) -> Vec<Value> {
    let mut values: Vec<(String, String)> = fields.iter().filter_map(|(f, t)| secret.get(*f).filter(|v| !v.is_empty()).map(|v| (t.to_string(), v.clone()))).collect();
    let get = |vals: &Vec<(String, String)>, k: &str| vals.iter().find(|(t, _)| t == k).map(|(_, v)| v.clone());
    if let (Some(m), Some(y)) = (get(&values, "cc-exp-month"), get(&values, "cc-exp-year")) {
        values.push(("cc-exp".into(), format!("{:0>2}/{}", m, &y[y.len().saturating_sub(2)..])));
    }
    let mut fills: Vec<Value> = values.iter().filter_map(|(t, v)| best(cs.iter().filter(|c| &c.token == t)).map(|b| json!({"index": b.c.index, "token": t, "value": v}))).collect();
    if fills.iter().any(|f| f["token"] == "cc-exp") {
        fills.retain(|f| f["token"] != "cc-exp-month" && f["token"] != "cc-exp-year");
    }
    fills
}

pub fn otp_fills(cs: &[Classified], code: &str) -> Vec<Value> {
    let Some(top) = cs.iter().max_by_key(|c| c.score) else { return vec![] };
    let mut boxes: Vec<&Classified> = cs.iter().filter(|c| c.c.max_length == Some(1)).collect();
    boxes.sort_by_key(|c| c.c.index);
    let same_form = boxes.iter().map(|b| b.c.form_index).collect::<std::collections::HashSet<_>>().len() == 1;
    if boxes.len() == code.chars().count() && same_form && boxes.windows(2).all(|w| w[1].c.index - w[0].c.index == 1) {
        return boxes.iter().zip(code.chars()).map(|(b, ch)| json!({"index": b.c.index, "token": "one-time-code", "value": ch.to_string()})).collect();
    }
    vec![json!({"index": top.c.index, "token": "one-time-code", "value": code})]
}

pub const STAMP: &str = "data-ark-vault-slot";

pub fn inspection_js(nonce: &str) -> String {
    r#"(() => {
  const nonce = __NONCE__;
  const elements = Array.from(document.querySelectorAll("input, select"));
  const forms = Array.from(document.forms);
  elements.forEach((element, index) => element.setAttribute("data-ark-vault-slot", nonce + ":" + index));
  return elements.flatMap((element, index) => {
    if (element.disabled || element.readOnly) return [];
    if (["hidden", "submit", "button", "reset", "file", "image", "checkbox", "radio"].includes(element.type)) return [];
    const style = getComputedStyle(element);
    if (style.display === "none" || style.visibility === "hidden" || element.getClientRects().length === 0) return [];
    const labels = element.labels ? Array.from(element.labels, (l) => l.textContent || "") : [];
    const ariaText = (element.getAttribute("aria-labelledby") || "").split(/\s+/).filter(Boolean).map((id) => { const n = document.getElementById(id); return n ? (n.textContent || "") : ""; }).join(" ");
    const fi = element.form ? forms.indexOf(element.form) : -1;
    return [{autocomplete: element.autocomplete || "", formIndex: fi >= 0 ? fi : null, index, maxLength: element.maxLength > 0 ? element.maxLength : null,
      label: [...labels, element.getAttribute("aria-label") || "", ariaText, element.getAttribute("placeholder") || "", element.getAttribute("title") || ""].join(" "),
      name: [element.name, element.id].join(" "), type: element.tagName === "SELECT" ? "select" : (element.type || "")}];
  });
})()"#
        .replace("__NONCE__", &util::json_str(nonce))
}

/// Fill script: asserts the origin synchronously before writing, reports only a count.
pub fn fill_js(fills: &[Value], expected_origin: &str, nonce: &str) -> String {
    r#"(() => {
  const expectedOrigin = __ORIGIN__;
  if (window.location.origin !== expectedOrigin) return { refused: "origin_changed", found: window.location.origin };
  const fills = __FILLS__;
  const nonce = __NONCE__;
  let filled = 0;
  const norm = (t) => String(t || "").trim().toLowerCase();
  for (const f of fills) {
    const el = document.querySelector('[data-ark-vault-slot="' + nonce + ':' + f.index + '"]');
    if (!el || (f.token === "current-password" && el.type !== "password")) continue;
    try {
      if (el.tagName === "SELECT") {
        const want = norm(f.value);
        const opt = Array.from(el.options).find((o) => [o.value, o.textContent].some((t) => norm(t) === want || norm(t) === want.replace(/^0/, "")));
        if (opt) { el.value = opt.value; el.dispatchEvent(new Event("change", { bubbles: true })); filled += 1; }
        continue;
      }
      el.focus();
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
      if (setter && setter.set) { setter.set.call(el, f.value); } else { el.value = f.value; }
      el.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText" }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
      if (el.value.length > 0) filled += 1;
    } catch (e) {}
  }
  document.querySelectorAll("[data-ark-vault-slot]").forEach((n) => n.removeAttribute("data-ark-vault-slot"));
  return { filled };
})()"#
        .replace("__ORIGIN__", &util::json_str(expected_origin))
        .replace("__FILLS__", &Value::Array(fills.to_vec()).to_string())
        .replace("__NONCE__", &util::json_str(nonce))
}

pub fn scrub(text: &str, secret: &BTreeMap<String, String>) -> String {
    let mut t = text.to_string();
    for v in secret.values().filter(|v| v.len() >= 3) {
        t = t.replace(v.as_str(), "[REDACTED]");
    }
    t
}

// ---- masked prompts on the user's terminal ----

/// Test hook / alternate surface: answers prompts instead of /dev/tty.
pub type PromptFn = Box<dyn Fn(&str, bool) -> Option<String> + Send + Sync>;
static PROMPTER: OnceLock<Mutex<Option<PromptFn>>> = OnceLock::new();

pub fn set_prompter(f: Option<PromptFn>) {
    *PROMPTER.get_or_init(|| Mutex::new(None)).lock().unwrap() = f;
}

pub fn can_prompt() -> bool {
    PROMPTER.get().is_some_and(|p| p.lock().unwrap().is_some()) || (std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").is_ok() && std::env::var("ARK_NO_TTY_PROMPT").is_err())
}

/// Ask on the controlling terminal; `masked` turns echo off. None = declined/unavailable.
pub fn prompt(label: &str, masked: bool) -> Option<String> {
    if let Some(p) = PROMPTER.get() {
        if let Some(f) = p.lock().unwrap().as_ref() {
            return f(label, masked);
        }
    }
    if std::env::var("ARK_NO_TTY_PROMPT").is_ok() {
        return None;
    }
    use std::io::{BufRead, Write};
    use std::os::unix::io::AsRawFd;
    let mut tty = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").ok()?;
    let fd = tty.as_raw_fd();
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    let have = unsafe { libc::tcgetattr(fd, &mut old) } == 0;
    if masked && have {
        let mut t = old;
        t.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &t) };
    }
    let _ = write!(tty, "\n[ark browser vault] {label}: ");
    let _ = tty.flush();
    let mut line = String::new();
    let r = std::io::BufReader::new(tty.try_clone().ok()?).read_line(&mut line);
    if masked && have {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old) };
        let _ = writeln!(tty);
    }
    r.ok()?;
    let v = line.trim_end_matches(['\r', '\n']).to_string();
    (!v.is_empty()).then_some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_matches_rfc6238() {
        // RFC 6238 SHA-1 test key "12345678901234567890" in base32.
        let k = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert_eq!(totp(k, 59).unwrap(), "287082");
        assert_eq!(totp(k, 1111111109).unwrap(), "081804");
        assert!(base32("not base32!").is_none());
    }

    #[test]
    fn classifier_picks_current_password_and_card_fields() {
        let c = |ty: &str, name: &str, ac: &str, i: i64| Control { ty: ty.into(), name: name.into(), autocomplete: ac.into(), index: i, ..Default::default() };
        let cs: Vec<Classified> = [c("email", "email", "", 0), c("password", "new password", "", 1), c("password", "pw", "", 2), c("password", "x", "current-password", 3)].iter().filter_map(classify_login).collect();
        assert_eq!(cs.len(), 3);
        assert_eq!(select_password(&cs, "s3cret")[0]["index"], 3);
        assert!(classify_login(&c("text", "otp", "one-time-code", 0)).is_none());
        let pay: Vec<Classified> = [c("text", "cardnumber", "", 0), c("text", "exp date", "", 1), c("text", "cvc", "", 2), c("text", "exp month", "", 3)].iter().filter_map(classify_checkout).collect();
        let s = BTreeMap::from([("card_number".to_string(), "4111111111111111".to_string()), ("exp_month".into(), "3".into()), ("exp_year".into(), "2031".into()), ("cvc".into(), "123".into())]);
        let f = select_checkout(&pay, &s, PAYMENT_FIELDS);
        assert!(f.iter().any(|x| x["token"] == "cc-exp" && x["value"] == "03/31") && !f.iter().any(|x| x["token"] == "cc-exp-month"));
        let otp = classify_otp(&[Control { max_length: Some(1), form_index: Some(0), index: 4, label: "digit".into(), autocomplete: "one-time-code".into(), ..Default::default() }, Control { max_length: Some(1), form_index: Some(0), index: 5, autocomplete: "one-time-code".into(), ..Default::default() }]);
        assert_eq!(otp_fills(&otp, "12").len(), 2);
        assert_eq!(otp_fills(&otp, "123456").len(), 1);
        let js = fill_js(&f, "https://shop.example", "n1");
        assert!(js.contains("\"https://shop.example\"") && js.contains("n1"));
    }

    #[test]
    fn local_store_and_external_managers() {
        let home = ark_core::tmp::scratch_path(format!("ark-vault-{}", std::process::id()));
        let it = add(&home, "login", "", "https://Login.Example.com/signin", BTreeMap::from([("identifier".into(), "me@x.example".into()), ("password".into(), "pw-123456".into()), ("totp_secret".into(), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into())])).unwrap();
        assert_eq!((it.origin.as_str(), it.identifier_type.as_str(), it.label.as_str()), ("https://login.example.com", "email", "login.example.com"));
        let meta = it.meta("local");
        assert!(meta.get("password").is_none() && !meta.to_string().contains("pw-123456") && meta["two_factor"] == "automatic");
        assert_eq!(resolve(&home, &it).unwrap()["password"], "pw-123456");
        assert_eq!(resolve_otp(&home, &it.id).unwrap().len(), 6);
        assert!(add(&home, "payment", "card", "https://shop.example", BTreeMap::from([("card_number".into(), "4111".into())])).unwrap_err().contains("exp_month"));
        assert!(remove(&home, &it.id).unwrap() && !remove(&home, &it.id).unwrap());
        // Bitwarden through a fake `bw`.
        let bw = home.join("bw");
        std::fs::write(&bw, "#!/bin/sh\ncase \"$1\" in unlock) [ \"$ARK_BW_MASTER\" = right ] && echo SESSION1 || { echo 'Invalid master password.' >&2; exit 1; } ;; list) [ \"$BW_SESSION\" = SESSION1 ] || { echo 'Vault is locked.' >&2; exit 1; }; echo '[{\"id\":\"i1\",\"type\":1,\"name\":\"Site\",\"login\":{\"username\":\"bob\",\"uris\":[{\"uri\":\"https://site.example/login\"},{\"uri\":\"https://never.example\",\"match\":5}]}}]' ;; get) [ \"$2\" = password ] && echo 'bw-pass' || echo 654321 ;; esac\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bw, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::env::set_var("ARK_BW", &bw);
        assert!(list_external("bitwarden").unwrap_err().contains("unlock_required"));
        assert!(unlock("bitwarden", "wrong").is_err());
        unlock("bitwarden", "right").unwrap();
        let items = list_external("bitwarden").unwrap();
        assert_eq!((items.len(), items[0].id.as_str(), items[0].allowed_origins.len()), (1, "bw:i1", 1));
        assert_eq!(resolve(&home, &items[0]).unwrap()["password"], "bw-pass");
        assert_eq!(resolve_otp(&home, "bw:i1").as_deref(), Some("654321"));
        std::env::remove_var("ARK_BW");
    }
}
