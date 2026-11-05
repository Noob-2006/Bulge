//! QR scan-to-create onboarding (Hermes `qr_register`, MIT): the device-code flow of
//! `accounts.{feishu.cn,larksuite.com}/oauth/v1/app/registration` creates a configured
//! "PersonalAgent" bot app. `init` checks client_secret auth is offered, `begin` returns
//! the URL to show as a QR code, `poll` (every `interval` s) yields the app credentials
//! once scanned and follows a Lark tenant to the Lark domain.

use crate::{ChannelError, ChannelErrorKind as K};
use serde_json::Value;

pub const FEISHU_ACCOUNTS: &str = "https://accounts.feishu.cn";
pub const LARK_ACCOUNTS: &str = "https://accounts.larksuite.com";
const PATH: &str = "/oauth/v1/app/registration";

/// Where to post: `base` overrides both domains (tests).
fn accounts(domain: &str, base: Option<&str>) -> String {
    base.map(|b| b.trim_end_matches('/').to_string()).unwrap_or_else(|| if domain == "lark" { LARK_ACCOUNTS } else { FEISHU_ACCOUNTS }.to_string())
}

/// Form POST; JSON is parsed even on 4xx (the pending answer is a 400).
fn post(domain: &str, base: Option<&str>, form: &[(&str, &str)]) -> Result<Value, ChannelError> {
    let http = crate::http::Http::new(std::time::Duration::from_secs(10));
    let r = http.call("POST", &format!("{}{PATH}", accounts(domain, base)), &[], crate::http::Payload::Form(form))?;
    serde_json::from_str(&r.body).map_err(|_| ChannelError::new(K::Protocol, format!("feishu registration: HTTP {} without JSON", r.status)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub device_code: String,
    /// Show this as the QR code (or open it).
    pub qr_url: String,
    pub user_code: String,
    pub interval: u64,
    pub expire_in: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Poll {
    Pending,
    /// The tenant turned out to be Lark: poll there from now on.
    SwitchDomain(String),
    Done { app_id: String, app_secret: String, domain: String, open_id: String },
    /// `access_denied` / `expired_token`.
    Failed(String),
}

/// Refuse environments that do not offer client_secret auth.
pub fn init(domain: &str, base: Option<&str>) -> Result<(), ChannelError> {
    let v = post(domain, base, &[("action", "init")])?;
    let ok = v["supported_auth_methods"].as_array().is_some_and(|a| a.iter().any(|m| m == "client_secret"));
    if ok {
        Ok(())
    } else {
        Err(ChannelError::new(K::Fatal, format!("feishu registration does not support client_secret auth (supported: {})", v["supported_auth_methods"])))
    }
}

pub fn begin(domain: &str, base: Option<&str>) -> Result<Registration, ChannelError> {
    let v = post(domain, base, &[("action", "begin"), ("archetype", "PersonalAgent"), ("auth_method", "client_secret"), ("request_user_info", "open_id")])?;
    let device_code = v["device_code"].as_str().filter(|d| !d.is_empty()).ok_or_else(|| ChannelError::new(K::Protocol, "feishu registration returned no device_code"))?.to_string();
    let mut qr_url = v["verification_uri_complete"].as_str().unwrap_or("").to_string();
    qr_url.push_str(if qr_url.contains('?') { "&" } else { "?" });
    qr_url.push_str("from=seagent&tp=seagent");
    Ok(Registration {
        device_code,
        qr_url,
        user_code: v["user_code"].as_str().unwrap_or("").to_string(),
        interval: v["interval"].as_u64().filter(|i| *i > 0).unwrap_or(5),
        expire_in: v["expire_in"].as_u64().filter(|i| *i > 0).unwrap_or(600),
    })
}

/// One poll on `domain` (start with the domain `begin` used; switch on `SwitchDomain`).
pub fn poll(domain: &str, base: Option<&str>, device_code: &str) -> Result<Poll, ChannelError> {
    let v = post(domain, base, &[("action", "poll"), ("device_code", device_code), ("tp", "ob_app")])?;
    let lark = v["user_info"]["tenant_brand"] == "lark" && domain != "lark";
    let dom = if lark { "lark" } else { domain };
    if let (Some(id), Some(secret)) = (v["client_id"].as_str().filter(|x| !x.is_empty()), v["client_secret"].as_str().filter(|x| !x.is_empty())) {
        return Ok(Poll::Done { app_id: id.into(), app_secret: secret.into(), domain: dom.into(), open_id: v["user_info"]["open_id"].as_str().unwrap_or("").into() });
    }
    match v["error"].as_str().unwrap_or("") {
        e @ ("access_denied" | "expired_token") => Ok(Poll::Failed(e.into())),
        _ if lark => Ok(Poll::SwitchDomain("lark".into())),
        _ => Ok(Poll::Pending),
    }
}
