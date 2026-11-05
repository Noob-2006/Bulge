//! Directory lookups for IT support (BATCH-next §3, pro-039/045): `directory_lookup` over
//! LDAP / Active Directory, Microsoft Entra ID and Okta.
//!
//! ```toml
//! [integrations.directory.providers.corp]       # LDAP or AD, through the OpenLDAP `ldapsearch`
//! kind = "ad"                                   # ldap | ad | entra | okta
//! uri = "ldaps://dc1.corp.example:636"
//! base_dn = "DC=corp,DC=example"
//! bind_dn = "CN=svc-ark,OU=Service,DC=corp,DC=example"
//! bind_password = "{{secret:LDAP_BIND_PW}}"     # a read-only service account
//! [integrations.directory.providers.cloud]
//! kind = "entra"
//! tenant = "…"; client_id = "…"; client_secret = "{{secret:ENTRA_SECRET}}"   # or token = "{{secret:GRAPH_TOKEN}}"
//! [integrations.directory.providers.sso]
//! kind = "okta"
//! org_url = "https://example.okta.com"
//! token = "{{secret:OKTA_TOKEN}}"
//! ```
//!
//! **Read-only by construction.** The tool can look up users, groups, a group's members and a
//! user's groups; it has no operation that changes anything and it never returns a credential
//! attribute. Creating, changing, unlocking or disabling an account — and above all setting a
//! password — is a person's decision: the IT-support role hands those over through `ask_user`
//! or a ticket (the `it-support-triage` skill spells out the flow), and the role policy refuses
//! `chpasswd`, `passwd --stdin` and friends outright. Use a service account / API token that
//! has directory *read* rights only, so a mistake here cannot become a change there.

pub mod cloud;
pub mod ldap;

use ark_core::tool::{arg_opt_str, arg_opt_u64, arg_str};
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

pub const DEFAULT_LIMIT: usize = 25;
pub const HARD_LIMIT: usize = 200;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Provider {
    pub kind: String,
    pub description: String,
    // ldap / ad
    pub uri: Option<String>,
    pub base_dn: Option<String>,
    pub bind_dn: Option<String>,
    pub bind_password: Option<String>,
    pub starttls: bool,
    pub client: Vec<String>,
    // entra
    pub tenant: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub api_base: Option<String>,
    pub login_base: Option<String>,
    // okta
    pub org_url: Option<String>,
    // entra (bearer) / okta (SSWS)
    pub token: Option<String>,
    pub timeout_seconds: Option<u64>,
}

impl Provider {
    pub fn timeout(&self) -> u64 {
        self.timeout_seconds.unwrap_or(20).clamp(1, 120)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DirectoryConfig {
    pub enabled: Option<bool>,
    pub max_results: Option<usize>,
    pub providers: BTreeMap<String, Provider>,
}

pub struct Query {
    pub kind: String,
    pub query: String,
    pub limit: usize,
}

impl DirectoryConfig {
    pub fn from_value(v: Value) -> Result<DirectoryConfig, String> {
        let cfg: DirectoryConfig = if v.is_null() { DirectoryConfig::default() } else { serde_json::from_value(v).map_err(|e| format!("[integrations.directory]: {e}"))? };
        let has = |a: &Option<String>| a.as_deref().is_some_and(|x| !x.trim().is_empty());
        for (n, p) in &cfg.providers {
            let missing = match p.kind.as_str() {
                "ldap" | "ad" => (!has(&p.uri)).then_some("`uri`").or((!has(&p.base_dn)).then_some("`base_dn`")),
                "entra" => (!has(&p.token) && !(has(&p.tenant) && has(&p.client_id) && has(&p.client_secret))).then_some("`token` or `tenant`+`client_id`+`client_secret`"),
                "okta" => (!has(&p.org_url)).then_some("`org_url`").or((!has(&p.token)).then_some("`token`")),
                other => return Err(format!("[integrations.directory.providers.{n}]: kind `{other}` is not one of ldap, ad, entra, okta")),
            };
            if let Some(m) = missing {
                return Err(format!("[integrations.directory.providers.{n}]: {} needs {m}", p.kind));
            }
        }
        Ok(cfg)
    }
}

pub fn tools(cfg: Value) -> Result<Vec<Arc<dyn Tool>>, String> {
    let cfg = DirectoryConfig::from_value(cfg)?;
    if cfg.enabled == Some(false) || cfg.providers.is_empty() {
        return Ok(vec![]);
    }
    Ok(vec![Arc::new(DirectoryLookup { cfg: Arc::new(cfg) })])
}

pub(crate) fn secret(ctx: &ToolCtx, raw: &str) -> Result<String, String> {
    let v = (ctx.secrets)(raw.trim());
    if let Some(i) = v.find("{{secret:") {
        let name: String = v[i + 9..].chars().take_while(|c| *c != '}').collect();
        return Err(format!("secret `{name}` is not set; store it in the vault ({{{{secret:{name}}}}})"));
    }
    Ok(v)
}

pub(crate) fn clip(s: &str) -> String {
    if s.chars().count() > 500 {
        let mut t: String = s.chars().take(500).collect();
        t.push('…');
        t
    } else {
        s.to_string()
    }
}

pub struct DirectoryLookup {
    cfg: Arc<DirectoryConfig>,
}

impl DirectoryLookup {
    fn pick(&self, input: &Value) -> Result<(&str, &Provider), String> {
        match arg_opt_str(input, "provider") {
            Some(n) => self.cfg.providers.get_key_value(n).map(|(k, v)| (k.as_str(), v)).ok_or_else(|| format!("unknown provider `{n}`; configured: {}", self.cfg.providers.keys().cloned().collect::<Vec<_>>().join(", "))),
            None if self.cfg.providers.len() == 1 => self.cfg.providers.iter().next().map(|(k, v)| (k.as_str(), v)).ok_or_else(|| "no providers".into()),
            None => Err(format!("name a `provider`: {}", self.cfg.providers.keys().cloned().collect::<Vec<_>>().join(", "))),
        }
    }
}

impl Tool for DirectoryLookup {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "directory_lookup".into(),
            description: format!(
                "Read-only identity directory lookup (LDAP / Active Directory / Microsoft Entra ID / Okta): find a user, find a group, list a group's members, or list the groups a user belongs to. It cannot create, change, unlock, disable or reset anything, and it never returns passwords or hashes — account changes go to a person (ask_user / ticket). Providers: {}.",
                self.cfg.providers.iter().map(|(n, p)| if p.description.is_empty() { format!("{n} ({})", p.kind) } else { format!("{n} ({}: {})", p.kind, p.description) }).collect::<Vec<_>>().join("; ")
            ),
            input_schema: json!({"type":"object","properties":{
                "provider":{"type":"string","description":"Configured provider (optional when only one exists)"},
                "kind":{"type":"string","enum":["user","group","members","groups_of"],"description":"user: find users by login/mail/name; group: find groups by name; members: members of the group named in query; groups_of: groups of the user named in query"},
                "query":{"type":"string","description":"Login, e-mail, name or group name; a trailing * means prefix"},
                "limit":{"type":"integer","minimum":1,"description":"Maximum results (default 25, at most 200)"}},"required":["kind","query"]}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let Ok((_, p)) = self.pick(input) else { return vec![] };
        let dest = match p.kind.as_str() {
            "entra" => crate::pro_http::dest_of(p.api_base.as_deref().unwrap_or("https://graph.microsoft.com")),
            "okta" => crate::pro_http::dest_of(p.org_url.as_deref().unwrap_or("")),
            _ => crate::pro_http::dest_of(p.uri.as_deref().unwrap_or("")),
        };
        vec![Effect::Net { dest, payload: String::new() }]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let run = || -> Result<String, String> {
            let (name, p) = self.pick(&input)?;
            let kind = arg_str(&input, "kind")?.to_string();
            if !matches!(kind.as_str(), "user" | "group" | "members" | "groups_of") {
                return Err("kind must be user, group, members or groups_of".into());
            }
            let query = arg_str(&input, "query")?.trim().to_string();
            if query.is_empty() || query.len() > 256 || query.chars().any(char::is_control) {
                return Err("query must be 1-256 characters without control characters".into());
            }
            let limit = arg_opt_u64(&input, "limit").map(|l| l as usize).unwrap_or(self.cfg.max_results.unwrap_or(DEFAULT_LIMIT)).clamp(1, HARD_LIMIT);
            let q = Query { kind, query, limit };
            let mut out = match p.kind.as_str() {
                "ldap" | "ad" => ldap::lookup(p, ctx, &q)?,
                "entra" => cloud::entra(p, ctx, &q)?,
                "okta" => cloud::okta(p, ctx, &q)?,
                _ => return Err("unknown provider kind".into()),
            };
            out["provider"] = json!(name);
            out["directory"] = json!(p.kind);
            out["query"] = json!({"kind": q.kind, "query": q.query, "limit": limit});
            out["read_only"] = json!(true);
            Ok(crate::web::content::wrap(&serde_json::to_string_pretty(&out).unwrap_or_default(), "directory_lookup", true))
        };
        match run() {
            Ok(t) => ToolOutput::ok(t),
            Err(e) => ToolOutput::err(e),
        }
    }
}

#[cfg(test)]
mod tests;
