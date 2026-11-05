//! GitHub Copilot as a model provider (Hermes `hermes_cli/copilot_auth.py`, OpenClaw
//! `extensions/github-copilot`): a GitHub OAuth token (device login, `gh`, Copilot CLI or
//! VS Code) is exchanged at `api.github.com/copilot_internal/v2/token` for a ~30-minute
//! Copilot token; requests carry the editor identity headers Copilot expects.

use crate::auth::{Cred, CredSource};
use seagent_core::{ProviderError, ProviderErrorKind as K};
use std::sync::Mutex;

pub const EDITOR_VERSION: &str = "vscode/1.104.1";
const EXCHANGE_UA: &str = "GitHubCopilotChat/0.26.7";

fn exchange_url() -> String {
    std::env::var("SEAGENT_COPILOT_EXCHANGE_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "https://api.github.com/copilot_internal/v2/token".into())
}

/// Standard Copilot request headers.
pub fn headers() -> Vec<(String, String)> {
    vec![
        ("Editor-Version".into(), EDITOR_VERSION.into()),
        ("Editor-Plugin-Version".into(), "copilot-chat/0.26.7".into()),
        ("Copilot-Integration-Id".into(), "vscode-chat".into()),
        ("Openai-Intent".into(), "conversation-edits".into()),
        ("x-initiator".into(), "agent".into()),
    ]
}

/// `proxy-ep=proxy.<host>` inside the token → `https://api.<host>`.
pub fn base_from_token(token: &str) -> Option<String> {
    let ep = token
        .split(';')
        .find_map(|p| p.trim().strip_prefix("proxy-ep="))?;
    let ep = ep
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    let ep = ep
        .strip_prefix("proxy.")
        .map(|r| format!("api.{r}"))
        .unwrap_or_else(|| ep.to_string());
    Some(format!("https://{ep}"))
}

/// Cached exchange of one GitHub token.
pub struct Exchange {
    cache: Mutex<Option<(String, String, u64, Option<String>)>>,
}

impl Default for Exchange {
    fn default() -> Self {
        Self::new()
    }
}

impl Exchange {
    pub fn new() -> Exchange {
        Exchange {
            cache: Mutex::new(None),
        }
    }
    pub fn clear(&self) {
        self.cache.lock().unwrap().take();
    }
    /// Copilot credential for GitHub token `gh` (`base` = stored enterprise endpoint).
    pub fn get(&self, gh: &str, base: Option<&str>) -> Result<Cred, ProviderError> {
        let now = crate::ratelimit::now_ms();
        if let Some((src, tok, exp, b)) = self.cache.lock().unwrap().as_ref() {
            if src == gh && now + 60_000 < *exp {
                return Ok(Cred {
                    token: Some(tok.clone()),
                    headers: headers(),
                    base: b.clone().or_else(|| base.map(String::from)),
                });
            }
        }
        let auth = format!("token {gh}");
        let v = crate::login::get_json(&exchange_url(), &[("authorization", &auth), ("user-agent", EXCHANGE_UA), ("editor-version", EDITOR_VERSION)]).map_err(|e| {
            let k = if e.contains("401") || e.contains("403") || e.contains("404") { K::Auth } else { K::Network };
            ProviderError::new(k, format!("Copilot token exchange failed: {e} (is Copilot enabled for this GitHub account? `seagent login github-copilot`)"))
        })?;
        let tok = v["token"]
            .as_str()
            .filter(|t| !t.is_empty())
            .ok_or_else(|| ProviderError::new(K::Auth, "Copilot token exchange returned no token"))?
            .to_string();
        let exp = v["expires_at"]
            .as_u64()
            .map(|s| s * 1000)
            .unwrap_or(now + 1_800_000);
        let b = v["endpoints"]["api"]
            .as_str()
            .map(|s| s.trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| base_from_token(&tok))
            .or_else(|| base.map(String::from));
        *self.cache.lock().unwrap() = Some((gh.to_string(), tok.clone(), exp, b.clone()));
        Ok(Cred {
            token: Some(tok),
            headers: headers(),
            base: b,
        })
    }
}

/// A GitHub token from the environment/config, exchanged per request.
pub struct FromToken {
    gh: String,
    x: Exchange,
}

impl FromToken {
    pub fn new(gh: String) -> FromToken {
        FromToken {
            gh,
            x: Exchange::new(),
        }
    }
}

impl CredSource for FromToken {
    fn get(&self) -> Result<Cred, ProviderError> {
        self.x.get(&self.gh, None)
    }
    fn invalidate(&self) -> bool {
        self.x.clear();
        true
    }
    fn describe(&self) -> String {
        format!("GitHub token {}", crate::store::mask(&self.gh))
    }
}

/// A GitHub token some other Copilot client already stored: `$COPILOT_GITHUB_TOKEN`,
/// `$GH_TOKEN`, `$GITHUB_TOKEN`, Copilot CLI `~/.copilot/config.json`, VS Code/neovim
/// `~/.config/github-copilot/{apps,hosts}.json`, then `gh auth token`.
pub fn cli_token() -> Option<String> {
    for k in ["COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"] {
        if let Some(v) = std::env::var(k).ok().filter(|v| !v.trim().is_empty()) {
            return Some(v.trim().to_string());
        }
    }
    let home = std::path::PathBuf::from(std::env::var_os("HOME")?);
    let read = |p: std::path::PathBuf| -> Option<serde_json::Value> {
        let s = std::fs::read_to_string(p).ok()?;
        // JSONC: drop `//` comment lines.
        let s: String = s
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        serde_json::from_str(&s).ok()
    };
    if let Some(v) = read(home.join(".copilot/config.json")) {
        if let Some(t) = v["copilotTokens"]
            .as_object()
            .and_then(|o| o.values().find_map(|x| x.as_str().map(String::from)))
        {
            return Some(t);
        }
    }
    let cfg = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    for f in ["apps.json", "hosts.json"] {
        if let Some(v) = read(cfg.join("github-copilot").join(f)) {
            if let Some(t) = v.as_object().and_then(|o| {
                o.values()
                    .find_map(|x| x["oauth_token"].as_str().map(String::from))
            }) {
                return Some(t);
            }
        }
    }
    crate::auth::run_capture(
        "gh auth token 2>/dev/null",
        std::time::Duration::from_secs(5),
    )
    .ok()
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty() && !s.contains(' '))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_endpoint_from_token() {
        assert_eq!(
            base_from_token("tid=1;exp=2;proxy-ep=proxy.enterprise.githubcopilot.com;x=y")
                .as_deref(),
            Some("https://api.enterprise.githubcopilot.com")
        );
        assert_eq!(base_from_token("tid=1"), None);
    }

    #[test]
    fn exchange_caches_and_uses_endpoint() {
        let srv = crate::login::tests::fake_server(vec![(200, r#"{"token":"cop-tok;proxy-ep=proxy.individual.githubcopilot.com","expires_at":4102444800,"endpoints":{"api":"https://api.individual.githubcopilot.com/"}}"#.into())]);
        std::env::set_var(
            "SEAGENT_COPILOT_EXCHANGE_URL",
            format!("{}/copilot_internal/v2/token", srv.base),
        );
        let x = FromToken::new("gho_abc".into());
        let c = x.get().unwrap();
        assert!(c.token.unwrap().starts_with("cop-tok"));
        assert_eq!(
            c.base.as_deref(),
            Some("https://api.individual.githubcopilot.com")
        );
        assert!(c
            .headers
            .iter()
            .any(|(k, v)| k == "Copilot-Integration-Id" && v == "vscode-chat"));
        x.get().unwrap();
        assert_eq!(srv.requests().len(), 1, "cached");
        assert!(srv
            .headers(0)
            .iter()
            .any(|(k, v)| k == "authorization" && v == "token gho_abc"));
        assert!(x.invalidate());
        x.get().unwrap();
        assert_eq!(srv.requests().len(), 2);
        std::env::remove_var("SEAGENT_COPILOT_EXCHANGE_URL");
    }
}
