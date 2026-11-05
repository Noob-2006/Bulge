//! The curated catalog of vendor-hosted MCP servers (Hermes `optional-mcps/`,
//! transcribed in `mcp_presets.json`): list/search/show, and the `[mcp.<name>]`
//! block `ark mcp add <name> --preset <preset>` writes.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::OnceLock;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct EnvSpec {
    pub name: String,
    #[serde(default)]
    pub prompt: String,
    #[serde(default = "yes")]
    pub secret: bool,
    #[serde(default = "yes")]
    pub required: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Preset {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub source: String,
    pub url: String,
    /// "oauth" or "none".
    pub auth: String,
    #[serde(default)]
    pub env: Vec<EnvSpec>,
    #[serde(default)]
    pub oauth: BTreeMap<String, serde_json::Value>,
    /// Tool allow list to start with (`tools`), or a deny list (`exclude_tools`).
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub post_install: String,
    #[serde(default)]
    pub connector_slug: Option<String>,
}

pub fn catalog() -> &'static [Preset] {
    static C: OnceLock<Vec<Preset>> = OnceLock::new();
    C.get_or_init(|| serde_json::from_str(include_str!("mcp_presets.json")).expect("bundled MCP preset catalog"))
}

pub fn get(name: &str) -> Option<&'static Preset> {
    let n = name.to_lowercase();
    catalog().iter().find(|p| p.name == n || p.connector_slug.as_deref() == Some(&n))
}

/// Name, description, keyword or host match (case-insensitive substring).
pub fn search(q: &str) -> Vec<&'static Preset> {
    let q = q.to_lowercase();
    catalog().iter().filter(|p| p.name.contains(&q) || p.description.to_lowercase().contains(&q) || p.keywords.iter().any(|k| k.contains(&q)) || p.hosts.iter().any(|h| h.contains(&q))).collect()
}

/// Upstream's install notes speak of Hermes; point them at ark's commands.
pub fn notes(p: &Preset) -> String {
    p.post_install.replace("hermes mcp", "ark mcp").replace("Hermes", "ark")
}

fn toml_str(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

/// Replace `${VAR}`: non-secret values are inlined, secrets become vault references
/// (config never carries credentials, as upstream keeps them in `.env`).
fn fill(s: &str, p: &Preset, values: &BTreeMap<String, String>) -> Result<String, String> {
    let mut out = s.to_string();
    for e in &p.env {
        let r = format!("${{{}}}", e.name);
        if !out.contains(&r) {
            continue;
        }
        let v = if e.secret {
            format!("{{{{secret:{}}}}}", e.name)
        } else {
            match values.get(&e.name) {
                Some(v) => v.clone(),
                None if e.required => return Err(format!("preset `{}` needs --env {}=… ({})", p.name, e.name, e.prompt)),
                None => String::new(),
            }
        };
        out = out.replace(&r, &v);
    }
    Ok(out)
}

/// The `[mcp.<name>]` block for a preset (same keys `ark mcp add --url` writes).
pub fn config_block(name: &str, p: &Preset, values: &BTreeMap<String, String>) -> Result<String, String> {
    let url = fill(&p.url, p, values)?;
    if url.trim().is_empty() {
        return Err(format!("preset `{}` has no URL", p.name));
    }
    let mut b = format!("\n[mcp.{name}]\nurl = {}\n", toml_str(&url));
    // Legacy HTTP+SSE endpoints.
    if url.trim_end_matches('/').ends_with("/sse") {
        b.push_str("transport = \"sse\"\n");
    }
    if !p.include.is_empty() {
        b.push_str(&format!("tools = {}\n", toml::Value::Array(p.include.iter().map(|t| toml::Value::String(t.clone())).collect())));
    } else if !p.exclude.is_empty() {
        b.push_str(&format!("exclude_tools = {}\n", toml::Value::Array(p.exclude.iter().map(|t| toml::Value::String(t.clone())).collect())));
    }
    if p.auth == "oauth" {
        b.push_str("auth = \"oauth\"\n");
        let mut o = toml::Table::new();
        for (k, v) in &p.oauth {
            match (k.as_str(), v) {
                ("client_id" | "client_secret", serde_json::Value::String(s)) => {
                    o.insert(k.clone(), toml::Value::String(fill(s, p, values)?));
                }
                ("redirect_port", serde_json::Value::Number(n)) => {
                    o.insert(k.clone(), toml::Value::Integer(n.as_i64().unwrap_or(0)));
                }
                ("scope", serde_json::Value::String(s)) => {
                    o.insert("scopes".into(), toml::Value::Array(s.split_whitespace().map(|x| toml::Value::String(x.into())).collect()));
                }
                // redirect_host: ark's loopback redirect is always localhost.
                _ => {}
            }
        }
        if !o.is_empty() {
            b.push_str(&format!("oauth = {}\n", toml::Value::Table(o)));
        }
    }
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_complete_and_well_formed() {
        let c = catalog();
        assert_eq!(c.len(), 65);
        for p in c {
            assert!(!p.description.is_empty() && !p.url.is_empty(), "{}", p.name);
            assert!(matches!(p.auth.as_str(), "oauth" | "none"), "{}", p.name);
            assert!(p.include.is_empty() || p.exclude.is_empty(), "{} mixes include/exclude", p.name);
        }
        assert!(get("linear").is_some() && get("jira").is_some_and(|p| p.name == "atlassian"));
        assert!(search("postgres").iter().any(|p| p.name == "neon"));
        assert!(notes(get("airtable").unwrap()).contains("ark mcp login airtable"));
    }

    fn parse(block: &str, name: &str) -> ark_plugin::McpServerConfig {
        let t: toml::Table = block.parse().unwrap();
        let c: ark_plugin::McpServerConfig = toml::Value::Table(t["mcp"][name].as_table().cloned().unwrap()).try_into().unwrap();
        c.validate(name).unwrap();
        c
    }

    #[test]
    fn blocks_are_valid_server_configs() {
        let none = BTreeMap::new();
        for p in catalog().iter().filter(|p| p.env.is_empty()) {
            let b = config_block(&p.name.replace('.', "-"), p, &none).unwrap();
            parse(&b, &p.name.replace('.', "-"));
        }
        let c = parse(&config_block("lin", get("linear").unwrap(), &none).unwrap(), "lin");
        assert!(c.uses_oauth() && c.url.as_deref() == Some("https://mcp.linear.app/mcp"));
        let c = parse(&config_block("pp", get("paypal").unwrap(), &none).unwrap(), "pp");
        assert_eq!(c.transport.as_deref(), Some("sse"));
        let c = parse(&config_block("w", get("wolfram").unwrap(), &none).unwrap(), "w");
        assert!(!c.uses_oauth());
    }

    #[test]
    fn env_values_inline_non_secrets_and_vault_secrets() {
        let asana = get("asana").unwrap();
        assert!(config_block("a", asana, &BTreeMap::new()).unwrap_err().contains("ASANA_CLIENT_ID"));
        let vals = BTreeMap::from([("ASANA_CLIENT_ID".to_string(), "cid-123".to_string())]);
        let b = config_block("a", asana, &vals).unwrap();
        let c = parse(&b, "a");
        assert_eq!(c.oauth.client_id.as_deref(), Some("cid-123"));
        assert_eq!(c.oauth.client_secret.as_deref(), Some("{{secret:ASANA_CLIENT_SECRET}}"));
        assert_eq!(c.oauth.redirect_port, Some(27890));
        let n8n = get("n8n-official").unwrap();
        let b = config_block("n", n8n, &BTreeMap::from([("N8N_MCP_SERVER_URL".to_string(), "https://n8n.example/mcp-server/http".to_string())])).unwrap();
        assert_eq!(parse(&b, "n").url.as_deref(), Some("https://n8n.example/mcp-server/http"));
    }
}
