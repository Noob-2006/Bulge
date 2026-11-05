//! Dashboard auth providers a plugin contributes to the app's login gate.
//!
//! Hermes models dashboard login as a pluggy ABC — `hermes_cli/dashboard_auth.py`
//! (`DashboardAuthProvider`) — whose instances plugins register with
//! `PluginContext.register_dashboard_auth_provider(provider)`; the gate then resolves one by
//! the configured provider name and runs the OAuth 2.0 authorization-code + PKCE login
//! through it. ark keeps the upstream selection rules:
//!
//! * the built-in providers (`basic`, `self_hosted`) and the hosted Hermes ones
//!   (`nous`, `drain`) are **reserved**: registering those names fails, and [`find`] never
//!   returns them (`none`/`auto` mean "no login" / "pick one for me");
//! * a provider is only used when its name is configured (`[app.auth] provider`) — nothing
//!   plugin-supplied is ever auto-selected;
//! * a provider that cannot be configured is skipped with an operator-facing reason instead
//!   of crashing the gate (upstream `SkipRegistration`); in ark that check lives in the
//!   consuming crate, which reports `Err` from [`Provider::login_start`] / `find` misses as
//!   the reason.
//!
//! ark's plugins are MCP processes, so a provider crosses the process boundary as one
//! JSON-RPC request, declared in `initialize`:
//!
//! ```json
//! {"capabilities": {"experimental": {"ark": {"dashboard_auth": {"id": "acme", "label": "Acme SSO"}}}}}
//! ```
//!
//! (`"dashboard_auth": true` declares the provider under the plugin's own name.) The host then
//! serves it with `ark/auth.<method>` — `<method>` is `login_start`, `exchange`, `verify` or
//! `refresh`, and `params` is `{"id": …, "params": {…}}`:
//!
//! | method | `params.params` | answer |
//! |---|---|---|
//! | `login_start` | `{redirect_uri}` | `{url, state}` — the IDP URL to redirect to and the `state` the callback must carry |
//! | `exchange` | `{code, state, redirect_uri}` | `{subject, email?, name?, expires_at?, admin?}` |
//! | `verify` | `{token}` | the same session object |
//! | `refresh` | `{token}` | the same session object |
//!
//! An `error` string in the answer is a failure; the browser only ever sees a generic message.
//! `nous` and `drain` (Hermes' own hosted OAuth services) have no ark implementation — a
//! plugin can register a provider for them under its own name instead.
//!
//! In-process code (the built-ins in `ark-app`) implements the same [`Provider`] and serves it
//! through `crates/ark-app/src/dashboard_auth.rs`; process plugins get
//! [`PluginAuth`](crate::plugin::PluginAuth).

use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock, RwLock};

/// Names a built-in or hosted-upstream provider keeps (Hermes' bundled `basic` / `self_hosted` /
/// `nous` / `drain`, plus the "no login" and "pick one for me" spellings). A plugin may never
/// take one of these.
pub const RESERVED: &[&str] = &["none", "basic", "self_hosted", "self-hosted", "nous", "drain", "auto"];

/// First leg of the OAuth round trip: `url` is the IDP's authorize endpoint (the `basic`
/// provider answers its own form URL), `state` is the CSRF/PKCE handle the callback must carry
/// (empty when the provider has no redirect flow).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LoginStart {
    pub url: String,
    pub state: String,
}

/// A verified interactive identity (upstream `Session`, minus the opaque tokens ark does not
/// keep: the app mints its own signed session cookie instead).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Session {
    /// Stable user id (`sub` claim / configured username). Mandatory.
    pub subject: String,
    pub email: Option<String>,
    pub name: Option<String>,
    /// Unix seconds; `None` when the provider does not know.
    pub expires_at: Option<i64>,
    /// The provider says this identity may administer the app (`[app.auth]` has no roles of its
    /// own; a plugin provider may know better).
    pub admin: bool,
}

/// One dashboard auth provider. In-process implementations live in the binary / app crate;
/// process plugins get [`PluginAuth`](crate::plugin::PluginAuth).
pub trait Provider: Send + Sync {
    /// The name `[app.auth] provider` selects it by (lowercase `[a-z0-9_-]`).
    fn name(&self) -> &str;
    /// Usable right now. Must be cheap: no network (upstream `is_available`).
    fn available(&self) -> bool;
    /// Build the authorization redirect (and the `state` the callback must carry).
    fn login_start(&self, redirect_uri: &str) -> Result<LoginStart, String>;
    /// Finish the round trip: `code` + `state` from the callback, `redirect_uri` as sent in
    /// [`Provider::login_start`].
    fn exchange(&self, code: &str, state: &str, redirect_uri: &str) -> Result<Session, String>;
    /// A credential presented later (upstream `verify_session`): a bearer token, not a login.
    fn verify(&self, token: &str) -> Result<Session, String>;
    /// Renew a session from its refresh token (upstream `refresh_session`). Providers with
    /// stateless sessions cannot.
    fn refresh(&self, token: &str) -> Result<Session, String> {
        let _ = token;
        Err(format!("{} cannot refresh sessions", self.name()))
    }
}

fn registry() -> &'static RwLock<Vec<Arc<dyn Provider>>> {
    static R: OnceLock<RwLock<Vec<Arc<dyn Provider>>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_'))
}

/// Is `name` a built-in / hosted provider name (or a "pick one" spelling)?
pub fn is_reserved(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    RESERVED.contains(&n.as_str())
}

/// Register (or replace) the provider named `p.name()`.
pub fn register(p: Arc<dyn Provider>) -> Result<(), String> {
    let raw = p.name().trim();
    if !valid_name(raw) {
        return Err(format!("provider name `{raw}`: use lowercase letters, digits, `-` or `_` (1-64 chars)"));
    }
    let name = raw.to_ascii_lowercase();
    if is_reserved(&name) {
        return Err(format!("provider name `{name}` is reserved for a built-in dashboard auth provider ({}), so it cannot come from a plugin", RESERVED.join(", ")));
    }
    let mut r = registry().write().unwrap();
    r.retain(|x| !x.name().eq_ignore_ascii_case(&name));
    r.push(p);
    Ok(())
}

/// Every registered provider, in registration order.
pub fn list() -> Vec<Arc<dyn Provider>> {
    registry().read().unwrap().clone()
}

/// The provider `name`, unless that name belongs to a built-in (the app crate keeps those).
pub fn find(name: &str) -> Option<Arc<dyn Provider>> {
    let n = name.trim().to_ascii_lowercase();
    if n.is_empty() || is_reserved(&n) {
        return None;
    }
    registry().read().unwrap().iter().find(|p| p.name().eq_ignore_ascii_case(&n)).cloned()
}

/// Drop every registration (tests, and a host re-reading its plugin set).
#[doc(hidden)]
pub fn clear() {
    registry().write().unwrap().clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Fake {
        name: &'static str,
        available: bool,
    }

    impl Provider for Fake {
        fn name(&self) -> &str {
            self.name
        }
        fn available(&self) -> bool {
            self.available
        }
        fn login_start(&self, redirect_uri: &str) -> Result<LoginStart, String> {
            Ok(LoginStart { url: format!("https://idp.test/authorize?redirect_uri={redirect_uri}"), state: "st".into() })
        }
        fn exchange(&self, code: &str, state: &str, _redirect_uri: &str) -> Result<Session, String> {
            if code == "good" && state == "st" {
                Ok(Session { subject: format!("{}:user", self.name), email: Some("u@idp.test".into()), name: None, expires_at: Some(1_800_000_000), admin: self.available })
            } else {
                Err("invalid code".into())
            }
        }
        fn verify(&self, token: &str) -> Result<Session, String> {
            if token == "good" {
                Ok(Session { subject: format!("{}:user", self.name), ..Default::default() })
            } else {
                Err("bad token".into())
            }
        }
    }

    fn fake(name: &'static str) -> Arc<dyn Provider> {
        Arc::new(Fake { name, available: true })
    }

    /// The registry is process-global: the registration tests must not interleave.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static L: Mutex<()> = Mutex::new(());
        L.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn registration_validates_names_and_reserved_collisions() {
        let _g = serial();
        clear();
        assert!(register(fake("acme-sso")).is_ok());
        assert!(register(fake("Acme")).unwrap_err().contains("lowercase"));
        assert!(register(Arc::new(Fake { name: "x".repeat(65).leak(), available: true })).unwrap_err().contains("lowercase"), "too long is not a valid name");
        for reserved in RESERVED {
            let e = register(fake(reserved)).unwrap_err();
            assert!(e.contains("reserved"), "{reserved}: {e}");
            assert!(find(reserved).is_none(), "{reserved} never resolves to a plugin");
        }
        assert!(find("").is_none());
        clear();
    }

    #[test]
    fn find_and_list_are_ordered_and_replaced() {
        let _g = serial();
        clear();
        register(fake("acme")).unwrap();
        register(fake("beta")).unwrap();
        assert_eq!(list().iter().map(|p| p.name().to_string()).collect::<Vec<_>>(), ["acme", "beta"]);
        let found = find("ACME").expect("case-insensitive");
        assert_eq!(found.name(), "acme");
        let s = found.exchange("good", "st", "https://ark.test/auth/callback").unwrap();
        assert_eq!((s.subject.as_str(), s.email.as_deref(), s.admin), ("acme:user", Some("u@idp.test"), true));
        assert_eq!(found.exchange("bad", "st", "x").unwrap_err(), "invalid code");
        assert_eq!(found.verify("good").unwrap().subject, "acme:user");
        assert!(found.refresh("rt").unwrap_err().contains("cannot refresh"));
        // The same name replaces (a plugin reload must not stack providers).
        register(fake("acme")).unwrap();
        assert_eq!(list().len(), 2);
        clear();
        assert!(list().is_empty() && find("acme").is_none());
    }

    #[test]
    fn provider_names_cannot_shadow_the_builtins() {
        let _g = serial();
        clear();
        for n in ["basic", "self_hosted", "self-hosted"] {
            assert!(is_reserved(n));
            assert!(register(fake(n)).unwrap_err().contains("reserved"));
        }
        assert!(!is_reserved("acme"));
        clear();
    }
}
