//! Provider account usage windows and balances (OpenClaw `src/infra/provider-usage.fetch.*`,
//! Hermes `agent/account_usage.py`): Claude subscription 5h/week windows, ChatGPT Codex
//! primary/secondary windows, Copilot quota, OpenRouter key credit, DeepSeek balance,
//! Moonshot/Kimi balance, Z.AI quota. Shown by `/usage`, `seagent usage --account` and the web
//! console's API keys page (`ui.keys.balance`).
//!
//! Balance endpoints, as the providers document them:
//! - DeepSeek `GET https://api.deepseek.com/user/balance` → `balance_infos[].{currency,
//!   total_balance}` (amounts are strings), `is_available`.
//! - OpenRouter `GET https://openrouter.ai/api/v1/key` → `data.{limit, limit_remaining, usage}`
//!   (numbers; `limit` null = no limit). The account-wide `GET /api/v1/credits` needs a
//!   management key, which a chat key is not, so it is not used.
//! - Moonshot / Kimi `GET https://api.moonshot.ai/v1/users/me/balance` (USD) and
//!   `https://api.moonshot.cn/v1/users/me/balance` (CNY; keys are per platform) →
//!   `data.{available_balance, voucher_balance, cash_balance}` (numbers).

use crate::auth::Cred;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Window {
    pub label: String,
    pub used_percent: f64,
    pub reset_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Account {
    pub provider: String,
    pub plan: Option<String>,
    pub windows: Vec<Window>,
    /// Remaining credit, e.g. "USD 12.40".
    pub balance: Option<String>,
    /// The same credit as numbers, one entry per currency (what a UI formats itself).
    pub credits: Vec<Credit>,
}

/// One currency's credit on an account or key.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Credit {
    pub currency: String,
    /// What can still be spent (`None` when the provider reports no limit).
    pub remaining: Option<f64>,
    /// Spent so far, when the provider reports it.
    pub used: Option<f64>,
    /// The cap it is measured against, when there is one.
    pub limit: Option<f64>,
}

/// A JSON amount the provider sends as a number or as a decimal string.
fn amount(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

fn origin_env(var: &str, default: &str) -> String {
    std::env::var(var)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn reset(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(if n > 1_000_000_000_000 { n } else { n * 1000 });
    }
    v.as_str().and_then(crate::ratelimit::parse_rfc3339)
}

fn pct(v: &Value) -> Option<f64> {
    v.as_f64().map(|p| p.clamp(0.0, 100.0))
}

/// Which usage endpoint a provider has, if any.
pub fn supported(provider: &str) -> bool {
    matches!(
        provider,
        "anthropic"
            | "openai-codex"
            | "github-copilot"
            | "openrouter"
            | "deepseek"
            | "moonshot"
            | "moonshot-cn"
            | "zai"
            | "zai-coding"
    )
}

/// Fetch the account usage of `provider` with credential `c`.
pub fn fetch(provider: &str, c: &Cred) -> Result<Account, String> {
    let tok = c.token.as_deref().ok_or("no credential")?;
    let bearer = format!("Bearer {tok}");
    let mut a = Account {
        provider: provider.to_string(),
        ..Default::default()
    };
    match provider {
        "anthropic" => {
            if !crate::anthropic::is_oauth_token(tok) {
                return Err(
                    "account windows need a Claude subscription login (`seagent login anthropic`)"
                        .into(),
                );
            }
            let url = format!(
                "{}/api/oauth/usage",
                origin_env("SEAGENT_ANTHROPIC_USAGE_ORIGIN", "https://api.anthropic.com")
            );
            let v = crate::login::get_json(
                &url,
                &[
                    ("authorization", &bearer),
                    ("anthropic-beta", "oauth-2025-04-20"),
                ],
            )?;
            for (k, label) in [
                ("five_hour", "5h"),
                ("seven_day", "week"),
                ("seven_day_sonnet", "Sonnet week"),
                ("seven_day_opus", "Opus week"),
            ] {
                if let Some(p) = pct(&v[k]["utilization"]) {
                    a.windows.push(Window {
                        label: label.into(),
                        used_percent: p,
                        reset_at_ms: reset(&v[k]["resets_at"]),
                    });
                }
            }
        }
        "openai-codex" => {
            let url = format!(
                "{}/backend-api/wham/usage",
                origin_env("SEAGENT_CODEX_USAGE_ORIGIN", "https://chatgpt.com")
            );
            let mut h: Vec<(&str, &str)> = vec![("authorization", &bearer)];
            for (k, v) in &c.headers {
                if k.eq_ignore_ascii_case("ChatGPT-Account-ID") {
                    h.push(("ChatGPT-Account-Id", v));
                }
            }
            let v = crate::login::get_json(&url, &h)?;
            a.plan = v["plan_type"].as_str().map(String::from);
            for (k, label) in [
                ("primary_window", "primary"),
                ("secondary_window", "secondary"),
            ] {
                let w = &v["rate_limit"][k];
                if let Some(p) = pct(&w["used_percent"]) {
                    let secs = w["limit_window_seconds"].as_u64().unwrap_or(0);
                    let label = match secs {
                        18_000 => "5h".to_string(),
                        604_800 => "week".to_string(),
                        0 => label.to_string(),
                        s => format!("{}h", s / 3600),
                    };
                    let r = w["reset_at"].as_u64().map(|s| s * 1000).or_else(|| {
                        w["reset_after_seconds"]
                            .as_u64()
                            .map(|s| crate::ratelimit::now_ms() + s * 1000)
                    });
                    a.windows.push(Window {
                        label,
                        used_percent: p,
                        reset_at_ms: r,
                    });
                }
            }
        }
        "github-copilot" => {
            let gh = c
                .headers
                .iter()
                .find(|(k, _)| k == "x-github-token")
                .map(|(_, v)| v.as_str())
                .unwrap_or(tok);
            let url = format!(
                "{}/copilot_internal/user",
                origin_env("SEAGENT_GITHUB_API_ORIGIN", "https://api.github.com")
            );
            let auth = format!("token {gh}");
            let v = crate::login::get_json(
                &url,
                &[
                    ("authorization", &auth),
                    ("editor-version", crate::copilot::EDITOR_VERSION),
                ],
            )?;
            a.plan = v["copilot_plan"].as_str().map(String::from);
            for (k, label) in [
                ("premium_interactions", "premium requests"),
                ("chat", "chat"),
            ] {
                let q = &v["quota_snapshots"][k];
                if let Some(rem) = q["percent_remaining"].as_f64() {
                    if q["unlimited"].as_bool() != Some(true) {
                        a.windows.push(Window {
                            label: label.into(),
                            used_percent: (100.0 - rem).clamp(0.0, 100.0),
                            reset_at_ms: reset(&v["quota_reset_date"]),
                        });
                    }
                }
            }
        }
        "openrouter" => {
            let url = format!(
                "{}/api/v1/key",
                origin_env("SEAGENT_OPENROUTER_ORIGIN", "https://openrouter.ai")
            );
            let v = crate::login::get_json(&url, &[("authorization", &bearer)])?;
            let d = &v["data"];
            if let (Some(lim), Some(used)) = (d["limit"].as_f64(), d["usage"].as_f64()) {
                let left = d["limit_remaining"].as_f64().unwrap_or(lim - used).max(0.0);
                a.balance = Some(format!("USD {left:.2} of {lim:.2} left"));
                a.credits.push(Credit { currency: "USD".into(), remaining: Some(left), used: Some(used), limit: Some(lim) });
                if lim > 0.0 {
                    a.windows.push(Window {
                        label: "key limit".into(),
                        used_percent: (used / lim * 100.0).clamp(0.0, 100.0),
                        reset_at_ms: None,
                    });
                }
            } else if let Some(used) = d["usage"].as_f64() {
                a.balance = Some(format!("USD {used:.2} used (no limit)"));
                a.credits.push(Credit { currency: "USD".into(), remaining: None, used: Some(used), limit: None });
            }
        }
        "deepseek" => {
            let url = format!(
                "{}/user/balance",
                origin_env("SEAGENT_DEEPSEEK_ORIGIN", "https://api.deepseek.com")
            );
            let v = crate::login::get_json(&url, &[("authorization", &bearer)])?;
            let parts: Vec<String> = v["balance_infos"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|b| {
                    Some(format!(
                        "{} {}",
                        b["currency"].as_str()?,
                        b["total_balance"]
                            .as_str()
                            .map(String::from)
                            .or_else(|| b["total_balance"].as_f64().map(|f| f.to_string()))?
                    ))
                })
                .collect();
            if !parts.is_empty() {
                a.balance = Some(parts.join(", "));
            }
            for b in v["balance_infos"].as_array().into_iter().flatten() {
                if let (Some(cur), Some(total)) = (b["currency"].as_str(), amount(&b["total_balance"])) {
                    a.credits.push(Credit { currency: cur.into(), remaining: Some(total), ..Default::default() });
                }
            }
            if v["is_available"].as_bool() == Some(false) {
                a.plan = Some("balance too low for API calls".into());
            }
        }
        "moonshot" | "moonshot-cn" => {
            // Keys and currencies are per platform: api.moonshot.ai bills in USD, .cn in CNY.
            let (var, origin, currency) = if provider == "moonshot" {
                ("SEAGENT_MOONSHOT_ORIGIN", "https://api.moonshot.ai", "USD")
            } else {
                ("SEAGENT_MOONSHOT_CN_ORIGIN", "https://api.moonshot.cn", "CNY")
            };
            let url = format!("{}/v1/users/me/balance", origin_env(var, origin));
            let v = crate::login::get_json(&url, &[("authorization", &bearer)])?;
            let d = &v["data"];
            let avail = amount(&d["available_balance"]).ok_or("the balance answer has no data.available_balance")?;
            a.balance = Some(format!("{currency} {avail:.2}"));
            a.credits.push(Credit { currency: currency.into(), remaining: Some(avail), ..Default::default() });
        }
        "zai" | "zai-coding" => {
            let url = format!(
                "{}/api/monitor/usage/quota/limit",
                origin_env("SEAGENT_ZAI_ORIGIN", "https://api.z.ai")
            );
            let v = crate::login::get_json(&url, &[("authorization", &bearer)])?;
            let d = if v["data"].is_object() {
                &v["data"]
            } else {
                &v
            };
            for l in d["limits"].as_array().into_iter().flatten() {
                if let Some(p) = pct(&l["percentage"]) {
                    let unit = match l["unit"].as_u64().unwrap_or(0) {
                        3 => "h",
                        5 => "min",
                        6 => "week",
                        _ => "",
                    };
                    let label = format!(
                        "{} {}{unit}",
                        l["type"].as_str().unwrap_or("quota"),
                        l["number"]
                            .as_u64()
                            .map(|n| n.to_string())
                            .unwrap_or_default()
                    );
                    a.windows.push(Window {
                        label: label.trim().into(),
                        used_percent: p,
                        reset_at_ms: reset(&l["nextResetTime"]),
                    });
                }
            }
        }
        other => return Err(format!("{other}: no account usage endpoint")),
    }
    Ok(a)
}

pub fn describe(a: &Account) -> String {
    let now = crate::ratelimit::now_ms();
    let mut parts: Vec<String> = a
        .windows
        .iter()
        .map(|w| {
            let r = w.reset_at_ms.filter(|r| *r > now).map(|r| {
                let m = (r - now) / 60_000;
                if m >= 120 {
                    format!(", resets in {}h", m / 60)
                } else {
                    format!(", resets in {m}m")
                }
            });
            format!(
                "{} {:.0}% used{}",
                w.label,
                w.used_percent,
                r.unwrap_or_default()
            )
        })
        .collect();
    if let Some(b) = &a.balance {
        parts.push(b.clone());
    }
    let plan = a
        .plan
        .as_deref()
        .map(|p| format!(" ({p})"))
        .unwrap_or_default();
    format!(
        "{}{plan}: {}",
        a.provider,
        if parts.is_empty() {
            "no usage data".into()
        } else {
            parts.join(" · ")
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::login::tests::fake_server;

    #[test]
    fn claude_codex_openrouter_deepseek_zai() {
        let s = fake_server(vec![(200, r#"{"five_hour":{"utilization":42.5,"resets_at":"2099-01-01T00:00:00Z"},"seven_day":{"utilization":10}}"#.into())]);
        std::env::set_var("SEAGENT_ANTHROPIC_USAGE_ORIGIN", &s.base);
        let a = fetch("anthropic", &Cred::token("sk-ant-oat01-x")).unwrap();
        assert_eq!(a.windows.len(), 2);
        assert_eq!(a.windows[0].used_percent, 42.5);
        assert!(describe(&a).contains("5h 42% used, resets in"));
        assert!(s
            .headers(0)
            .iter()
            .any(|(k, v)| k == "anthropic-beta" && v.contains("oauth")));
        assert!(fetch("anthropic", &Cred::token("sk-ant-api03-x")).is_err());

        let s = fake_server(vec![(200, r#"{"plan_type":"plus","rate_limit":{"primary_window":{"used_percent":7,"limit_window_seconds":18000,"reset_after_seconds":600},"secondary_window":{"used_percent":3,"limit_window_seconds":604800}}}"#.into())]);
        std::env::set_var("SEAGENT_CODEX_USAGE_ORIGIN", &s.base);
        let c = Cred {
            token: Some("t".into()),
            headers: vec![("ChatGPT-Account-ID".into(), "acct".into())],
            base: None,
        };
        let a = fetch("openai-codex", &c).unwrap();
        assert_eq!(
            (
                a.plan.as_deref(),
                a.windows[0].label.as_str(),
                a.windows[1].label.as_str()
            ),
            (Some("plus"), "5h", "week")
        );
        assert_eq!(s.requests()[0].0, "/backend-api/wham/usage");

        let s = fake_server(vec![(200, r#"{"data":{"limit":20,"usage":5}}"#.into())]);
        std::env::set_var("SEAGENT_OPENROUTER_ORIGIN", &s.base);
        assert_eq!(
            fetch("openrouter", &Cred::token("k"))
                .unwrap()
                .balance
                .as_deref(),
            Some("USD 15.00 of 20.00 left")
        );

        let s = fake_server(vec![(200, r#"{"is_available":true,"balance_infos":[{"currency":"CNY","total_balance":"110.00"}]}"#.into())]);
        std::env::set_var("SEAGENT_DEEPSEEK_ORIGIN", &s.base);
        assert_eq!(
            fetch("deepseek", &Cred::token("k"))
                .unwrap()
                .balance
                .as_deref(),
            Some("CNY 110.00")
        );
        assert_eq!(s.requests()[0].0, "/user/balance");

        let s = fake_server(vec![(200, r#"{"code":0,"data":{"available_balance":49.58894,"voucher_balance":46.58893,"cash_balance":3.00001},"scode":"0x0","status":true}"#.into())]);
        std::env::set_var("SEAGENT_MOONSHOT_ORIGIN", &s.base);
        let a = fetch("moonshot", &Cred::token("k")).unwrap();
        assert_eq!(a.balance.as_deref(), Some("USD 49.59"));
        assert_eq!(a.credits, vec![Credit { currency: "USD".into(), remaining: Some(49.58894), ..Default::default() }]);
        assert_eq!(s.requests()[0].0, "/v1/users/me/balance");
        assert!(s.headers(0).iter().any(|(k, v)| k == "authorization" && v == "Bearer k"));
        let s = fake_server(vec![(200, r#"{"code":0,"data":{"available_balance":12,"voucher_balance":0,"cash_balance":12},"status":true}"#.into())]);
        std::env::set_var("SEAGENT_MOONSHOT_CN_ORIGIN", &s.base);
        assert_eq!(fetch("moonshot-cn", &Cred::token("k")).unwrap().credits[0].currency, "CNY");

        let s = fake_server(vec![(200, r#"{"data":{"limits":[{"type":"TOKENS_LIMIT","unit":3,"number":5,"percentage":30,"nextResetTime":4102444800000}]}}"#.into())]);
        std::env::set_var("SEAGENT_ZAI_ORIGIN", &s.base);
        let a = fetch("zai", &Cred::token("k")).unwrap();
        assert_eq!(a.windows[0].label, "TOKENS_LIMIT 5h");
        assert!(!supported("groq"));
    }
}
