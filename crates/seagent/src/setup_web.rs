//! First-run **web** setup wizard (backend). The page is `ui/web/setup.html` + `setup.js`,
//! served at `GET /setup`; it talks to `POST /setup/rpc` (JSON-RPC 2.0) with a short-lived,
//! single-use **setup token** in the `x-seagent-setup-token` header — never the long-lived app token.
//!
//! - `seagent setup link` mints the token (`<data>/setup/token.json` keeps only its SHA-256 and the
//!   expiry, mode 0600) and prints `http://<listen>/setup#token=…` (a fragment: browsers never
//!   send it to the server, to logs or in `Referer`).
//! - `setup.apply` that succeeds consumes the token and writes `<data>/setup/done.json`: from then
//!   on the wizard is **locked** (every call is refused) until `seagent setup link --reopen`.
//!   `seagent setup` (terminal) and `seagent setup --non-interactive` lock it too: there is one setup.
//! - Admins can call the same methods over ARP with an admin credential (no setup token).
//!
//! | method | params | result |
//! |---|---|---|
//! | `setup.status` | – | `{locked, token_valid, mode, paths, configured, providers[], security_modes[], auth_modes[], channels[], workspace, service, expires_ms}` (only `{locked, token_valid, reason}` without a valid token) |
//! | `setup.test_provider` | `{provider, api_key?, base_url?}` | `{ok, count, models[]}` or `{ok: false, error}` — the key is never echoed |
//! | `setup.apply` | `{provider, model, api_key?, base_url?, security?, workspace?, auth?: {mode: "token"\|"oidc", issuer?, client_id?, client_secret?}, channel?: {kind, token, owner?}, autostart?}` | `{ok, config, lines[], console_url, restart}` |
//!
//! The provider / key / model / channel part is `setup_server::apply`, the same code the
//! unattended `seagent setup --non-interactive` runs; the config is written by
//! `setup::save_config` (validated, rolled back on error) like the terminal wizard does.

use crate::setup::t;
use crate::setup_server::{self, Plan};
use seagent_kernel::config::Paths;
use seagent_kernel::vault::Vault;
use seagent_net::httpd::{Request, Response};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub const METHODS: &[&str] = &["setup.status", "setup.test_provider", "setup.apply"];
/// Lifetime of a setup link.
pub const DEFAULT_TTL_SECS: i64 = 30 * 60;
pub const HEADER: &str = "x-seagent-setup-token";
pub const SECURITY_MODES: &[&str] = &["strict", "balanced", "relaxed"];

fn dir(paths: &Paths) -> PathBuf {
    paths.data.join("setup")
}
fn token_file(paths: &Paths) -> PathBuf {
    dir(paths).join("token.json")
}
fn done_file(paths: &Paths) -> PathBuf {
    dir(paths).join("done.json")
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn digest(token: &str) -> String {
    seagent_net::crypto::hex(&seagent_net::crypto::sha256(token.as_bytes()))
}

fn write_private(p: &Path, body: &[u8]) -> Result<(), String> {
    use crate::ops::hostos::set_mode;
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        let _ = set_mode(d, 0o700);
    }
    seagent_kernel::util::atomic_write(p, body).map_err(|e| format!("{}: {e}", p.display()))?;
    set_mode(p, 0o600).map_err(|e| e.to_string())
}

/// Setup is complete (the wizard is locked).
pub fn locked(paths: &Paths) -> bool {
    done_file(paths).exists()
}

/// Lock the wizard: setup was completed by `how` (`web`, `tty`, `unattended`).
pub fn mark_done(paths: &Paths, how: &str) {
    let _ = std::fs::remove_file(token_file(paths));
    let _ = write_private(&done_file(paths), json!({"at_ms": now_ms(), "by": how}).to_string().as_bytes());
}

/// Mint a one-time setup token (replacing any earlier one). `reopen` unlocks a completed setup.
pub fn issue(paths: &Paths, ttl_secs: i64, reopen: bool) -> Result<(String, i64), String> {
    if locked(paths) {
        if !reopen {
            return Err(t("設定已完成，網頁精靈已鎖定（要重新開啟：seagent setup link --reopen）", "setup is already complete and the web wizard is locked (to open it again: seagent setup link --reopen)").into());
        }
        std::fs::remove_file(done_file(paths)).map_err(|e| e.to_string())?;
    }
    let token = seagent_net::crypto::random_token(32);
    let expires = now_ms() + ttl_secs.clamp(60, 24 * 3600) * 1000;
    write_private(&token_file(paths), json!({"sha256": digest(&token), "expires_ms": expires}).to_string().as_bytes())?;
    Ok((token, expires))
}

/// Why a presented setup token is not accepted (`None` = it is).
pub fn check(paths: &Paths, presented: Option<&str>, now: i64) -> Option<&'static str> {
    if locked(paths) {
        return Some("setup is complete; the wizard is locked");
    }
    let Some(stored) = std::fs::read_to_string(token_file(paths)).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()) else {
        return Some("no setup link is active; run `seagent setup link`");
    };
    if stored["expires_ms"].as_i64().unwrap_or(0) <= now {
        return Some("the setup link expired; run `seagent setup link` for a new one");
    }
    let Some(p) = presented.map(str::trim).filter(|p| !p.is_empty()) else { return Some("missing setup token") };
    if !seagent_net::crypto::ct_eq(digest(p).as_bytes(), stored["sha256"].as_str().unwrap_or("").as_bytes()) {
        return Some("invalid setup token");
    }
    None
}

fn read_root(paths: &Paths) -> Result<(toml::Table, Option<String>), String> {
    let p = paths.user_config();
    let existing = std::fs::read_to_string(&p).ok();
    let root = match &existing {
        Some(s) => s.parse().map_err(|e| format!("{}: {e}", p.display()))?,
        None => toml::Table::new(),
    };
    Ok((root, existing))
}

fn table<'a>(root: &'a mut toml::Table, key: &str) -> &'a mut toml::Table {
    let e = root.entry(key.to_string()).or_insert_with(|| toml::Value::Table(toml::Table::new()));
    if !e.is_table() {
        *e = toml::Value::Table(toml::Table::new());
    }
    e.as_table_mut().expect("table")
}

/// `[app] listen` of a config table (default `127.0.0.1:8640`).
pub fn listen_of(root: &toml::Table) -> String {
    root.get("app").and_then(|a| a.get("listen")).and_then(|v| v.as_str()).map(String::from).unwrap_or_else(|| "127.0.0.1:8640".into())
}

pub const DEFAULT_HOST: &str = "127.0.0.1";
pub const DEFAULT_PORT: u16 = 8640;
/// Ports the default loopback listener may move to when 8640 is busy.
pub const AUTO_PORTS: std::ops::RangeInclusive<u16> = 8640..=8659;

/// Holds the `[app] listen` value we chose (bootstrap / seagentd); a different configured value is the user's.
fn auto_marker(paths: &Paths) -> PathBuf {
    paths.data.join("app-listen.auto")
}

/// Can we bind `host:port` right now? (The probe socket is closed immediately.)
pub fn port_free(host: &str, port: u16) -> bool {
    std::net::TcpListener::bind((host, port)).is_ok()
}

/// The first free port of [`AUTO_PORTS`] on `host`.
pub fn pick_free_port(host: &str) -> Option<u16> {
    AUTO_PORTS.clone().find(|p| port_free(host, *p))
}

/// May the daemon move `[app] listen` (`listen`, as configured) to another port? Only a loopback
/// address on the default range whose value came from the default: no `[app] listen` in the user
/// config at all, or one written by `setup bootstrap` (marker file). A port the user set is never
/// changed.
pub fn listen_is_auto(paths: &Paths, listen: &str) -> bool {
    let Some((host, port)) = listen.rsplit_once(':') else { return false };
    if host != DEFAULT_HOST || !port.parse::<u16>().is_ok_and(|p| AUTO_PORTS.contains(&p)) {
        return false;
    }
    let configured = read_root(paths).ok().is_some_and(|(root, _)| root.get("app").and_then(|a| a.get("listen")).is_some());
    !configured || std::fs::read_to_string(auto_marker(paths)).is_ok_and(|m| m.trim() == listen)
}

/// Write `[app] listen = listen` into the user config (comments kept) and keep the auto marker.
pub fn persist_listen(paths: &Paths, listen: &str) -> Result<(), String> {
    let (mut root, existing) = read_root(paths)?;
    table(&mut root, "app").insert("listen".into(), listen.into());
    crate::setup::save_config(&paths.user_config(), &root, existing.as_deref())?;
    let _ = std::fs::write(auto_marker(paths), format!("{listen}\n"));
    Ok(())
}

/// Who answers on `addr` (`host:port`): "another SE Agent (version …)" when its `GET /health`
/// looks like ours, else "another program". `None` when nothing accepts the connection.
pub fn who_listens(addr: &str) -> Option<String> {
    use std::io::{Read, Write};
    let sa: std::net::SocketAddr = addr.parse().ok()?;
    let t = std::time::Duration::from_millis(800);
    let mut s = std::net::TcpStream::connect_timeout(&sa, t).ok()?;
    let _ = s.set_read_timeout(Some(t));
    let _ = s.set_write_timeout(Some(t));
    let _ = write!(s, "GET /health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    let mut buf = Vec::new();
    let _ = s.take(64 * 1024).read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    let v: Option<Value> = body.find('{').and_then(|i| serde_json::from_str(body[i..].trim_end_matches(|c: char| c != '}')).ok());
    Some(match v {
        Some(v) if v["ok"] == true && v["version"].is_string() => {
            let wsl = if cfg!(windows) { "; on Windows this can be the Linux SE Agent inside WSL, whose localhost ports are forwarded here" } else { "" };
            format!("another SE Agent (version {}) is already listening there{wsl}", v["version"].as_str().unwrap_or("?"))
        }
        _ => "another program is listening there".into(),
    })
}

/// The URL a browser on this machine opens for `listen` (a wildcard bind is reached on loopback).
pub fn base_url(listen: &str) -> String {
    let l = listen.replacen("0.0.0.0:", "127.0.0.1:", 1).replacen("[::]:", "[::1]:", 1);
    format!("http://{l}")
}

/// `seagent setup bootstrap`: just enough config for the daemon to serve the web console and the
/// setup wizard — `[app] enabled`, `listen` (only written when given or absent) and a
/// `{{secret:APP_TOKEN}}` reference with a freshly minted token. Idempotent; never touches
/// provider settings.
pub fn bootstrap(paths: &Paths, listen: Option<&str>) -> Result<Vec<String>, String> {
    std::fs::create_dir_all(&paths.config_dir).map_err(|e| format!("{}: {e}", paths.config_dir.display()))?;
    let vault = Vault::load(&paths.secrets())?;
    let (mut root, existing) = read_root(paths)?;
    let before = root.clone();
    let have = vault.names().iter().any(|n| n == "APP_TOKEN");
    let mut said = vec![];
    if let Some(secret) = crate::ops::wizard::gateway_config(&mut root, true, have) {
        vault.set(secret, &seagent_net::crypto::random_token(24))?;
        said.push(format!("minted {secret} (vault)"));
    }
    let app = table(&mut root, "app");
    match listen.map(str::trim).filter(|l| !l.is_empty()) {
        Some(l) => {
            l.parse::<std::net::SocketAddr>().map_err(|_| format!("--listen `{l}`: expected HOST:PORT, e.g. 127.0.0.1:8640"))?;
            app.insert("listen".into(), l.into());
        }
        None => {
            if !app.contains_key("listen") {
                // The default port may be taken (another app, a second SE Agent, or a Linux one
                // in WSL whose localhost ports Windows forwards): take the first free port of
                // the small default range and remember that it was our choice, so the daemon
                // may move it again later (`listen_is_auto`).
                let port = pick_free_port(DEFAULT_HOST).unwrap_or(DEFAULT_PORT);
                if port != DEFAULT_PORT {
                    said.push(format!("port {DEFAULT_PORT} is in use{}; using {port}", who_listens(&format!("{DEFAULT_HOST}:{DEFAULT_PORT}")).map(|w| format!(" ({w})")).unwrap_or_default()));
                }
                app.insert("listen".into(), format!("{DEFAULT_HOST}:{port}").into());
                let _ = std::fs::create_dir_all(&paths.data);
                let _ = std::fs::write(auto_marker(paths), format!("{DEFAULT_HOST}:{port}\n"));
            }
        }
    }
    if root != before || existing.is_none() {
        crate::setup::save_config(&paths.user_config(), &root, existing.as_deref())?;
        said.push(format!("wrote {}", paths.user_config().display()));
    }
    said.push(format!("console: {}", base_url(&listen_of(&root))));
    Ok(said)
}

fn provider_list(vault: &Vault) -> Vec<Value> {
    let all = seagent_model::presets();
    crate::setup::MENU
        .iter()
        .filter_map(|(id, en, zh)| {
            let p = all.iter().find(|p| p.id == *id)?;
            let has_key = match &p.api_key_env {
                None => true,
                Some(env) => std::env::var(env).is_ok_and(|v| !v.trim().is_empty()) || vault.names().contains(env),
            };
            Some(json!({"id": id, "label": if crate::setup::t("zh", "en") == "zh" { *zh } else { *en }, "needs_key": p.api_key_env.is_some(), "key_env": p.api_key_env, "has_key": has_key, "base_url": p.base_url}))
        })
        .collect()
}

pub fn status(paths: &Paths, token_ok: bool, reason: Option<&str>) -> Value {
    let is_locked = locked(paths);
    if !token_ok {
        return json!({"locked": is_locked, "token_valid": false, "reason": reason});
    }
    let vault = Vault::load(&paths.secrets()).unwrap_or_else(|_| Vault::empty());
    let (root, _) = read_root(paths).unwrap_or_default();
    let model = root.get("model").and_then(|m| m.get("default")).and_then(|v| v.as_str());
    let expires = std::fs::read_to_string(token_file(paths)).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()).and_then(|v| v["expires_ms"].as_i64());
    let systemd = Path::new("/run/systemd/system").is_dir();
    json!({
        "locked": is_locked,
        "token_valid": true,
        "mode": paths.mode.as_str(),
        "paths": {"config": paths.user_config(), "data": paths.data, "logs": paths.log_dir()},
        "configured": {"model": model},
        "providers": provider_list(&vault),
        "security_modes": SECURITY_MODES,
        "auth_modes": ["token", "oidc"],
        "channels": ["telegram", "discord"],
        "workspace": root.get("app").and_then(|a| a.get("workspace")).and_then(|v| v.as_str()).map(PathBuf::from).unwrap_or_else(|| paths.default_workspace()),
        "service": {"systemd": systemd, "mode": paths.mode.as_str()},
        "lan": lan_of(&root),
        "expires_ms": expires,
    })
}

fn s<'a>(p: &'a Value, k: &str) -> Option<&'a str> {
    p[k].as_str().map(str::trim).filter(|v| !v.is_empty())
}

/// The provider a request names: a preset (optionally with another base URL) or a custom
/// OpenAI-compatible endpoint.
fn provider_of(p: &Value) -> Result<seagent_model::ProviderConfig, String> {
    let id = s(p, "provider").ok_or("missing `provider`")?;
    let mut prov = match seagent_model::presets().into_iter().find(|x| x.id == id) {
        Some(x) => x,
        None => {
            let base = s(p, "base_url").ok_or_else(|| format!("unknown provider `{id}`: give `base_url` for a custom OpenAI-compatible endpoint"))?;
            seagent_model::ProviderConfig { id: id.into(), format: seagent_model::WireFormat::OpenAiChat, base_url: base.into(), api_key_env: s(p, "api_key").map(|_| format!("{}_API_KEY", id.to_uppercase().replace('-', "_"))), ..Default::default() }
        }
    };
    if let Some(b) = s(p, "base_url") {
        if !(b.starts_with("http://") || b.starts_with("https://")) {
            return Err("`base_url` must start with http:// or https://".into());
        }
        prov.base_url = b.into();
    }
    Ok(prov)
}

pub fn test_provider(paths: &Paths, p: &Value) -> Value {
    let prov = match provider_of(p) {
        Ok(x) => x,
        Err(e) => return json!({"ok": false, "error": e}),
    };
    let vault = Vault::load(&paths.secrets()).unwrap_or_else(|_| Vault::empty());
    let key = s(p, "api_key").map(String::from).or_else(|| {
        let env = prov.api_key_env.as_ref()?;
        let v = vault.substitute(&format!("{{{{secret:{env}}}}}"));
        (!v.starts_with("{{secret:")).then_some(v)
    });
    if prov.api_key_env.is_some() && key.is_none() {
        return json!({"ok": false, "error": "this provider needs an API key"});
    }
    match seagent_model::list_models(&prov, key.as_deref()) {
        Ok(m) => {
            let m = crate::setup::chat_models(m);
            // Never echo the key: a provider error message could quote it back.
            json!({"ok": true, "count": m.len(), "models": m.into_iter().take(200).collect::<Vec<_>>()})
        }
        Err(e) => json!({"ok": false, "error": redact(&e, key.as_deref())}),
    }
}

fn redact(msg: &str, key: Option<&str>) -> String {
    match key.filter(|k| k.len() >= 4) {
        Some(k) => msg.replace(k, "••••"),
        None => msg.to_string(),
    }
}

/// `strict` | `balanced` | `relaxed` → approvals and gates.
pub fn apply_security(root: &mut toml::Table, mode: &str) -> Result<&'static str, String> {
    let (approvals, privilege, egress, ws_only) = match mode {
        "strict" => ("manual", "deny", "ask", true),
        "balanced" => ("smart", "ask", "ask", false),
        "relaxed" => ("auto", "ask", "allow", false),
        other => return Err(format!("security mode `{other}`: expected strict, balanced or relaxed")),
    };
    table(root, "approvals").insert("mode".into(), approvals.into());
    let g = table(root, "gate");
    g.insert("privilege".into(), privilege.into());
    g.insert("egress".into(), egress.into());
    table(root, "security").insert("workspace_only".into(), ws_only.into());
    Ok(match mode {
        "strict" => "strict",
        "balanced" => "balanced",
        _ => "relaxed",
    })
}

/// "Allow devices on this network to connect": LAN mode on (`[app.exposure] lan = true`, the
/// listener on every interface — the server admits only private-range peers with a paired-device
/// token and speaks TLS to them) or off (back to loopback).
pub fn apply_lan(root: &mut toml::Table, on: bool) -> String {
    let listen = listen_of(root);
    let port = listen.rsplit_once(':').map(|(_, p)| p.to_string()).filter(|p| !p.is_empty()).unwrap_or_else(|| "8640".into());
    let app = table(root, "app");
    if on {
        if seagent_security::exposure::is_loopback(&listen) {
            app.insert("listen".into(), format!("0.0.0.0:{port}").into());
        }
        table(app, "exposure").insert("lan".into(), true.into());
        format!("LAN: devices on this network can pair (https://<this computer>:{port}; `seagent pair code` or the console's Devices page)")
    } else {
        if let Some(e) = app.get_mut("exposure").and_then(|e| e.as_table_mut()) {
            e.insert("lan".into(), false.into());
        }
        if listen.starts_with("0.0.0.0:") || listen.starts_with("[::]:") {
            app.insert("listen".into(), format!("127.0.0.1:{port}").into());
        }
        "LAN: off (this computer only)".into()
    }
}

/// `[app.exposure] lan` of a config table.
pub fn lan_of(root: &toml::Table) -> bool {
    root.get("app").and_then(|a| a.get("exposure")).and_then(|e| e.get("lan")).and_then(|v| v.as_bool()).unwrap_or(false)
}

/// `[app] workspace`, created when missing.
pub fn apply_workspace(root: &mut toml::Table, dir: &str) -> Result<PathBuf, String> {
    let d = seagent_core::expand_home(dir.trim());
    if !d.is_absolute() {
        return Err("workspace must be an absolute path (or start with ~/)".into());
    }
    crate::ops::wizard::validate_workspace_path(&d)?;
    std::fs::create_dir_all(&d).map_err(|e| format!("{}: {e}", d.display()))?;
    table(root, "app").insert("workspace".into(), d.display().to_string().into());
    Ok(d)
}

/// Console access: `token` (the app token is the admin credential; default) or `oidc`
/// (`[app.auth]` self-hosted OIDC relying party; endpoints from the issuer's discovery document).
pub fn apply_auth(root: &mut toml::Table, vault: &Vault, auth: &Value, discover: &dyn Fn(&str) -> Result<Value, String>) -> Result<String, String> {
    let have = vault.names().iter().any(|n| n == "APP_TOKEN");
    if let Some(secret) = crate::ops::wizard::gateway_config(root, true, have) {
        vault.set(secret, &seagent_net::crypto::random_token(24))?;
    }
    match s(auth, "mode").unwrap_or("token") {
        "token" => Ok("console login: app token".into()),
        "oidc" => {
            let issuer = s(auth, "issuer").ok_or("oidc: missing `issuer`")?.trim_end_matches('/').to_string();
            let client = s(auth, "client_id").ok_or("oidc: missing `client_id`")?;
            if !issuer.starts_with("https://") && !issuer.starts_with("http://127.0.0.1") && !issuer.starts_with("http://localhost") {
                return Err("oidc: the issuer must be an https:// URL".into());
            }
            let d = discover(&format!("{issuer}/.well-known/openid-configuration"))?;
            let ep = |k: &str| d[k].as_str().map(String::from).ok_or_else(|| format!("oidc: discovery document has no `{k}`"));
            let mut sh = toml::Table::new();
            sh.insert("issuer".into(), d["issuer"].as_str().unwrap_or(&issuer).into());
            sh.insert("authorization_endpoint".into(), ep("authorization_endpoint")?.into());
            sh.insert("token_endpoint".into(), ep("token_endpoint")?.into());
            sh.insert("jwks".into(), ep("jwks_uri")?.into());
            sh.insert("client_id".into(), client.into());
            sh.insert("scopes".into(), "openid profile email".into());
            if let Some(cs) = s(auth, "client_secret") {
                vault.set("APP_OIDC_CLIENT_SECRET", cs)?;
                sh.insert("client_secret".into(), "{{secret:APP_OIDC_CLIENT_SECRET}}".into());
            }
            if !vault.names().iter().any(|n| n == "APP_AUTH_SECRET") {
                vault.set("APP_AUTH_SECRET", &seagent_net::crypto::random_token(48))?;
            }
            let a = table(table(root, "app"), "auth");
            a.insert("enabled".into(), true.into());
            a.insert("provider".into(), "self_hosted".into());
            a.insert("secret".into(), "{{secret:APP_AUTH_SECRET}}".into());
            a.insert("self_hosted".into(), toml::Value::Table(sh));
            Ok(format!("console login: OIDC ({issuer})"))
        }
        other => Err(format!("auth mode `{other}`: expected token or oidc")),
    }
}

fn discover_http(url: &str) -> Result<Value, String> {
    use std::io::Read;
    let r = seagent_net::http::agent().get(url).call().map_err(|e| format!("oidc discovery {url}: {e}"))?;
    let mut raw = String::new();
    let _ = r.into_body().into_reader().take(1 << 20).read_to_string(&mut raw);
    serde_json::from_str(&raw).map_err(|e| format!("oidc discovery {url}: {e}"))
}

/// What the host does beyond files (service autostart), so tests can fake it.
pub type Autostart<'a> = &'a dyn Fn(&Paths) -> String;

/// launchd agent / Task Scheduler logon task / the phones' host app (ops::service_os).
#[cfg(any(target_os = "macos", windows, target_os = "android", target_os = "ios"))]
fn real_autostart(paths: &Paths) -> String {
    crate::ops::service_os::autostart(paths)
}

#[cfg(not(any(target_os = "macos", windows, target_os = "android", target_os = "ios")))]
fn real_autostart(paths: &Paths) -> String {
    use seagent_core::layout::Mode;
    if paths.mode == Mode::System {
        return t("系統服務由安裝程式啟用（systemctl enable seagentd）", "the system service is enabled by the installer (systemctl enable seagentd)").into();
    }
    let unit = crate::ops::service::user_unit_dir().join(crate::ops::service::unit_name());
    if !unit.exists() {
        return t("沒有 systemd 使用者單元：重新開機後請執行 seagent daemon start", "no systemd user unit: run `seagent daemon start` after a reboot").into();
    }
    let ok = std::process::Command::new("systemctl").args(["--user", "enable", &crate::ops::service::unit_name()]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().is_ok_and(|s| s.success());
    let linger = setup_server::linger_lines(&crate::ops::service::ensure_linger());
    format!("{} · {linger}", if ok { "autostart enabled" } else { "systemctl --user enable failed" })
}

/// The whole wizard submission. Pure over the files under `paths` plus `discover` / `autostart`.
pub fn apply(paths: &Paths, p: &Value, discover: &dyn Fn(&str) -> Result<Value, String>, autostart: Autostart) -> Result<Value, String> {
    let provider = s(p, "provider").ok_or("missing `provider`")?.to_string();
    let model = s(p, "model").ok_or("missing `model`")?.to_string();
    // Refuse bad choices before anything (vault included) is written.
    if let Some(m) = s(p, "security").filter(|m| !SECURITY_MODES.contains(m)) {
        return Err(format!("security mode `{m}`: expected strict, balanced or relaxed"));
    }
    if let Some(m) = s(&p["auth"], "mode").filter(|m| !["token", "oidc"].contains(m)) {
        return Err(format!("auth mode `{m}`: expected token or oidc"));
    }
    std::fs::create_dir_all(&paths.config_dir).map_err(|e| format!("{}: {e}", paths.config_dir.display()))?;
    let vault = Vault::load(&paths.secrets())?;
    let (mut root, existing) = read_root(paths)?;
    let channel = &p["channel"];
    let kind = s(channel, "kind").map(str::to_ascii_lowercase);
    let plan = Plan { provider: Some(provider), model: Some(model), base_url: s(p, "base_url").map(String::from), channel: kind, owner: s(channel, "owner").map(String::from), service: false, linger: false, verify: false };
    if let Some(c) = &plan.channel {
        if !["telegram", "discord"].contains(&c.as_str()) {
            return Err(format!("channel `{c}`: the wizard connects telegram or discord (others: config file)"));
        }
    }
    let key = s(p, "api_key").map(String::from);
    let chan_token = s(channel, "token").map(String::from);
    let env = move |k: &str| match k {
        "SEAGENT_SETUP_API_KEY" => key.clone(),
        // a custom endpoint names its key `<ID>_API_KEY` (setup_server::apply)
        k if k.ends_with("_API_KEY") => key.clone(),
        "SEAGENT_SETUP_CHANNEL_TOKEN" => chan_token.clone(),
        _ => None,
    };
    let (mut lines, _, _) = setup_server::apply(&mut root, &vault, &plan, &env)?;
    if let Some(m) = s(p, "security") {
        lines.push(format!("security: {}", apply_security(&mut root, m)?));
    }
    if let Some(w) = s(p, "workspace") {
        lines.push(format!("workspace: {}", apply_workspace(&mut root, w)?.display()));
    }
    lines.push(apply_auth(&mut root, &vault, &p["auth"], discover)?);
    if let Some(on) = p["lan"].as_bool() {
        lines.push(apply_lan(&mut root, on));
    }
    let cfg = paths.user_config();
    crate::setup::save_config(&cfg, &root, existing.as_deref())?;
    lines.push(format!("wrote {}", cfg.display()));
    if p["autostart"].as_bool().unwrap_or(true) {
        lines.push(autostart(paths));
    }
    mark_done(paths, "web");
    let token = vault.substitute("{{secret:APP_TOKEN}}");
    let base = base_url(&listen_of(&root));
    // Once: the setup token that unlocked this response is now consumed.
    let console = if token.starts_with("{{secret:") { base.clone() } else { format!("{base}/#token={token}") };
    Ok(json!({"ok": true, "config": cfg, "lines": lines, "console_url": console, "restart": true}))
}

// ───────────── restart after apply ─────────────

static RESTART: AtomicBool = AtomicBool::new(false);

/// Ask the daemon to stop shortly (after the response is out) and come back with the new config.
pub fn restart_soon() {
    RESTART.store(true, Ordering::SeqCst);
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_millis(800));
        seagent_kernel::daemon::Daemon::stop();
    });
}

pub fn restart_requested() -> bool {
    RESTART.load(Ordering::SeqCst)
}

/// Called by `seagent daemon run` after a requested stop. Under systemd (user or system unit,
/// `Restart=on-failure`) the exit status 75 brings the daemon back; without a service manager
/// a detached helper waits for this process to exit and runs `seagent daemon start` with the same
/// arguments.
pub fn after_stop() -> i32 {
    // `seagent daemon start` marks the daemons it detaches (and strips a service manager's variables
    // they could have inherited); anything else with NOTIFY_SOCKET is a systemd service.
    let detached = std::env::var_os("SEAGENT_DAEMON_DETACHED").is_some();
    if !detached && (std::env::var_os("NOTIFY_SOCKET").is_some() || std::env::var_os("INVOCATION_ID").is_some()) {
        eprintln!("seagentd: configuration changed by the setup wizard; exiting for systemd to restart");
        return 75;
    }
    if !detached {
        eprintln!("seagentd: configuration changed by the setup wizard; start the daemon again to use it");
        return 0;
    }
    let Ok(exe) = std::env::current_exe() else { return 0 };
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(i) = args.iter().position(|a| a == "run") {
        args[i] = "start".into();
    }
    #[cfg(unix)]
    let mut c = {
        let mut c = std::process::Command::new("sh");
        c.arg("-c").arg("while kill -0 \"$0\" 2>/dev/null; do sleep 0.2; done; exec \"$@\"").arg(std::process::id().to_string()).arg(&exe).args(&args);
        c
    };
    // No `sh` on Windows: the waiting helper is PowerShell (Wait-Process, then the same command).
    #[cfg(not(unix))]
    let mut c = {
        let quote = |s: &str| format!("'{}'", s.replace('\'', "''"));
        let script = format!("Wait-Process -Id {} -ErrorAction SilentlyContinue; & {} {}", std::process::id(), quote(&exe.to_string_lossy()), args.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" "));
        let mut c = std::process::Command::new("powershell.exe");
        c.args(["-NoProfile", "-NonInteractive", "-Command", &script]);
        c
    };
    c.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    crate::ops::hostos::detach(&mut c);
    let _ = c.spawn();
    eprintln!("seagentd: configuration changed by the setup wizard; restarting");
    0
}

// ───────────── HTTP + ARP ─────────────

pub struct Env {
    pub paths: Paths,
    pub allow_origins: Vec<String>,
}

fn rpc_reply(id: Value, r: Result<Value, (i32, String)>) -> Response {
    let body = match r {
        Ok(v) => json!({"jsonrpc": "2.0", "id": id, "result": v}),
        Err((code, message)) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}),
    };
    Response::json(200, &body.to_string()).with_header("cache-control", "no-store")
}

/// One method call. `authorized` = a valid setup token or an admin credential.
pub fn call(paths: &Paths, method: &str, params: &Value, authorized: Result<(), &str>) -> Result<Value, (i32, String)> {
    match (method, authorized) {
        ("setup.status", Ok(())) => Ok(status(paths, true, None)),
        ("setup.status", Err(why)) => Ok(status(paths, false, Some(why))),
        (_, Err(why)) => Err((-32001, why.to_string())),
        ("setup.test_provider", Ok(())) => Ok(test_provider(paths, params)),
        ("setup.apply", Ok(())) => {
            let v = apply(paths, params, &discover_http, &real_autostart).map_err(|e| (-32602, e))?;
            restart_soon();
            Ok(v)
        }
        (m, _) => Err((-32601, format!("unknown method `{m}`"))),
    }
}

fn handle(env: &Env, r: &Request) -> Response {
    if r.method != "POST" {
        return Response::json(405, &json!({"error": "POST only"}).to_string()).with_header("allow", "POST");
    }
    if let Some(o) = r.header("origin") {
        if !seagent_app::exposure::origin_allowed(o, r.header("host").unwrap_or(""), &env.allow_origins) {
            return Response::json(403, &json!({"error": "forbidden: cross-origin request"}).to_string());
        }
    }
    if !seagent_app::exposure::is_json_content_type(r.header("content-type")) {
        return Response::json(415, &json!({"error": "needs content-type: application/json"}).to_string());
    }
    let req: Value = match serde_json::from_slice(&r.body) {
        Ok(v) => v,
        Err(e) => return Response::json(400, &json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": e.to_string()}}).to_string()),
    };
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req["method"].as_str().unwrap_or("");
    let why = check(&env.paths, r.header(HEADER), now_ms());
    if let Some(w) = why {
        if method != "setup.status" {
            let ip = r.peer.map(|p| p.ip().to_string()).unwrap_or_default();
            seagent_security::audit::record(&env.paths.data, seagent_security::audit::Event::new("auth.denied", seagent_security::audit::Actor::new("setup-wizard", "").with_ip(&ip), method, "deny").detail(json!({"reason": w})));
        }
    }
    let r = call(&env.paths, method, &req.get("params").cloned().unwrap_or(json!({})), why.map_or(Ok(()), Err));
    if method == "setup.apply" && r.is_ok() {
        seagent_security::audit::record(&env.paths.data, seagent_security::audit::Event::new("setup.apply", seagent_security::audit::Actor::new("setup-wizard", ""), "setup", "allow"));
    }
    rpc_reply(id, r)
}

/// The `/setup/rpc` route (served before the app-token check: it authenticates with the setup token).
pub fn routes(env: Arc<Env>) -> Vec<(String, seagent_net::httpd::Handler)> {
    let h: seagent_net::httpd::Handler = Arc::new(move |r: Request| handle(&env, &r));
    vec![("/setup/rpc".to_string(), h)]
}

/// The same methods over ARP for an admin credential (no setup token needed).
pub fn methods(paths: &Paths) -> seagent_kernel::daemon::MethodExt {
    let paths = paths.clone();
    Arc::new(move |m: &str, p: &Value| METHODS.contains(&m).then(|| call(&paths, m, p, Ok(()))))
}

/// `seagent setup …`: `link` / `bootstrap` (this module), the unattended path (`setup_server`) or the
/// terminal wizard (`setup`). Every way of finishing setup locks the web wizard: there is one setup.
pub fn dispatch(a: &crate::args::Args) -> Result<i32, String> {
    let paths = Paths::from_env();
    if matches!(a.pos(0), Some("link" | "bootstrap" | "status")) {
        return cli(&paths, a);
    }
    let (rc, how) = if setup_server::wanted(a, &setup_server::real_env) {
        let plan = setup_server::plan(a, &setup_server::real_env)?;
        (setup_server::run(&paths, &plan, &setup_server::real_env, &mut setup_server::RealHost)?, "unattended")
    } else {
        (crate::setup::run(&paths)?, "tty")
    };
    if rc == 0 {
        mark_done(&paths, how);
    }
    Ok(rc)
}

/// `seagent setup link|bootstrap|status`. With `--json` (the desktop shell) every outcome is one
/// JSON object on stdout; a failure is `{"error": …}` with exit status 1.
pub fn cli(paths: &Paths, a: &crate::args::Args) -> Result<i32, String> {
    let json_out = a.flag("json");
    match cli_inner(paths, a) {
        Err(e) if json_out => {
            println!("{}", json!({"error": e}));
            Ok(1)
        }
        r => r,
    }
}

fn cli_inner(paths: &Paths, a: &crate::args::Args) -> Result<i32, String> {
    match a.pos(0) {
        Some("status") => {
            let (root, _) = read_root(paths)?;
            let listen = listen_of(&root);
            let console = format!("{}/", base_url(&listen));
            if a.flag("json") {
                println!("{}", json!({"done": locked(paths), "listen": listen, "console_url": console}));
            } else {
                println!("{} · {console}", if locked(paths) { t("設定已完成", "setup complete") } else { t("尚未設定", "setup not done yet") });
            }
            Ok(0)
        }
        Some("bootstrap") => {
            std::fs::create_dir_all(&paths.data).map_err(|e| format!("{}: {e}", paths.data.display()))?;
            let lines = bootstrap(paths, a.val("listen"))?;
            if a.flag("json") {
                let (root, _) = read_root(paths)?;
                let listen = listen_of(&root);
                println!("{}", json!({"ok": true, "changes": lines, "listen": listen, "config": paths.user_config(), "console_url": format!("{}/", base_url(&listen))}));
            } else {
                for l in lines {
                    eprintln!("  {l}");
                }
            }
            Ok(0)
        }
        Some("link") => {
            let (root, _) = read_root(paths)?;
            let ttl = a.val("ttl").map(|v| v.parse::<i64>().map_err(|_| format!("--ttl `{v}`: minutes"))).transpose()?.map(|m| m * 60).unwrap_or(DEFAULT_TTL_SECS);
            let (token, expires) = issue(paths, ttl, a.flag("reopen"))?;
            let url = format!("{}/setup#token={token}", base_url(&listen_of(&root)));
            if a.flag("json") {
                println!("{}", json!({"url": url, "expires_ms": expires, "expires_at_ms": expires}));
            } else {
                println!("{url}");
                eprintln!("  {} {} {}", t("一次性設定連結，", "one-time setup link, valid for"), ttl / 60, t("分鐘內有效", "minutes"));
            }
            Ok(0)
        }
        _ => Err("usage: seagent setup link [--ttl MINUTES] [--reopen] [--json] | seagent setup bootstrap [--listen HOST:PORT] [--json] | seagent setup status [--json]".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> (seagent_core::tmp::TempDir, Paths) {
        let root = seagent_core::tmp::TempDir::new(&format!("seagent-setupweb-{tag}"));
        let p = Paths { data: root.join("data"), config_dir: root.join("config"), runtime: root.join("run"), ..Default::default() };
        std::fs::create_dir_all(&p.config_dir).unwrap();
        std::fs::create_dir_all(&p.data).unwrap();
        (root, p)
    }

    #[test]
    fn bootstrap_skips_a_busy_default_port_and_only_moves_ports_it_chose() {
        let (_r, p) = scratch("autoport");
        // Hold the default port (if something else already does, that is the same situation).
        let _hold = std::net::TcpListener::bind((DEFAULT_HOST, DEFAULT_PORT));
        bootstrap(&p, None).unwrap();
        let (root, _) = read_root(&p).unwrap();
        let listen = listen_of(&root);
        let port: u16 = listen.rsplit_once(':').unwrap().1.parse().unwrap();
        assert!(AUTO_PORTS.contains(&port), "{listen}");
        assert!(port != DEFAULT_PORT || pick_free_port(DEFAULT_HOST).is_none(), "the busy default port is skipped: {listen}");
        assert!(listen_is_auto(&p, &listen), "bootstrap's own choice may move");
        persist_listen(&p, "127.0.0.1:8645").unwrap();
        assert_eq!(listen_of(&read_root(&p).unwrap().0), "127.0.0.1:8645");
        assert!(listen_is_auto(&p, "127.0.0.1:8645"));
        // The user sets another port afterwards: theirs from now on.
        let (mut root, existing) = read_root(&p).unwrap();
        table(&mut root, "app").insert("listen".into(), "127.0.0.1:8650".into());
        crate::setup::save_config(&p.user_config(), &root, existing.as_deref()).unwrap();
        assert!(!listen_is_auto(&p, "127.0.0.1:8650"));
        // An explicit port is the user's: never moved.
        let (_r2, q) = scratch("autoport-explicit");
        bootstrap(&q, Some("127.0.0.1:8641")).unwrap();
        assert!(!listen_is_auto(&q, "127.0.0.1:8641"));
        // No `[app] listen` at all: the default, movable; other hosts / ports never.
        let (_r3, e) = scratch("autoport-none");
        assert!(listen_is_auto(&e, "127.0.0.1:8640"));
        assert!(!listen_is_auto(&e, "0.0.0.0:8640") && !listen_is_auto(&e, "127.0.0.1:9000") && !listen_is_auto(&e, "192.168.1.2:8640"));
    }

    #[test]
    fn who_listens_recognises_another_se_agent() {
        use std::io::{Read, Write};
        let serve = |body: &'static str| {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = l.local_addr().unwrap().to_string();
            std::thread::spawn(move || {
                if let Ok((mut s, _)) = l.accept() {
                    let mut b = [0u8; 1024];
                    let _ = s.read(&mut b);
                    let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                }
            });
            addr
        };
        assert!(who_listens(&serve(r#"{"ok":true,"version":"0.1.0"}"#)).unwrap().contains("another SE Agent (version 0.1.0)"));
        assert_eq!(who_listens(&serve("hello")).unwrap(), "another program is listening there");
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().to_string();
        assert_eq!(who_listens(&free), None, "nothing listening");
    }

    #[test]
    fn setup_token_is_hashed_short_lived_single_use_and_locks() {
        let (_r, p) = scratch("token");
        assert_eq!(check(&p, Some("x"), now_ms()), Some("no setup link is active; run `seagent setup link`"));
        let (tok, exp) = issue(&p, 600, false).unwrap();
        let stored = std::fs::read_to_string(token_file(&p)).unwrap();
        assert!(!stored.contains(&tok), "only the hash is stored");
        #[cfg(unix)]
        assert_eq!(crate::ops::hostos::mode_of(&token_file(&p)).unwrap() & 0o777, 0o600);
        assert_eq!(check(&p, Some(&tok), now_ms()), None);
        assert_eq!(check(&p, Some("wrong"), now_ms()), Some("invalid setup token"));
        assert_eq!(check(&p, None, now_ms()), Some("missing setup token"));
        assert!(check(&p, Some(&tok), exp + 1).unwrap().contains("expired"));
        // a new link replaces the old one
        let (tok2, _) = issue(&p, 600, false).unwrap();
        assert_eq!(check(&p, Some(&tok), now_ms()), Some("invalid setup token"));
        mark_done(&p, "web");
        assert!(locked(&p));
        assert!(check(&p, Some(&tok2), now_ms()).unwrap().contains("locked"));
        assert!(issue(&p, 600, false).is_err(), "a completed setup needs --reopen");
        let (tok3, _) = issue(&p, 600, true).unwrap();
        assert_eq!(check(&p, Some(&tok3), now_ms()), None);
        // without a valid token the status says nothing about the install
        let st = call(&p, "setup.status", &json!({}), Err("invalid setup token")).unwrap();
        assert_eq!(st, json!({"locked": false, "token_valid": false, "reason": "invalid setup token"}));
        assert!(call(&p, "setup.apply", &json!({}), Err("invalid setup token")).is_err());
    }

    #[test]
    fn bootstrap_enables_the_console_once() {
        let (_r, p) = scratch("boot");
        bootstrap(&p, Some("127.0.0.1:18641")).unwrap();
        let text = std::fs::read_to_string(p.user_config()).unwrap();
        let root: toml::Table = text.parse().unwrap();
        assert_eq!(root["app"]["enabled"].as_bool(), Some(true));
        assert_eq!(root["app"]["listen"].as_str(), Some("127.0.0.1:18641"));
        assert_eq!(root["app"]["token"].as_str(), Some("{{secret:APP_TOKEN}}"));
        let tok = Vault::load(&p.secrets()).unwrap().substitute("{{secret:APP_TOKEN}}");
        assert!(!tok.contains("{{"), "APP_TOKEN minted");
        // idempotent: same token, listen kept when not given
        bootstrap(&p, None).unwrap();
        assert_eq!(Vault::load(&p.secrets()).unwrap().substitute("{{secret:APP_TOKEN}}"), tok);
        assert_eq!(std::fs::read_to_string(p.user_config()).unwrap(), text);
        assert!(bootstrap(&p, Some("nonsense")).is_err());
    }

    #[test]
    fn apply_writes_everything_through_the_shared_setup_code() {
        let (_r, p) = scratch("apply");
        bootstrap(&p, Some("127.0.0.1:18642")).unwrap();
        issue(&p, 600, false).unwrap();
        let ws = p.data.join("ws");
        let discover = |u: &str| -> Result<Value, String> {
            assert_eq!(u, "https://id.example.test/.well-known/openid-configuration");
            Ok(json!({"issuer": "https://id.example.test", "authorization_endpoint": "https://id.example.test/a", "token_endpoint": "https://id.example.test/t", "jwks_uri": "https://id.example.test/j"}))
        };
        let auto = |_: &Paths| "autostart skipped (test)".to_string();
        let params = json!({"provider": "openai", "model": "gpt-x", "api_key": "sk-test-1234567890", "security": "strict", "workspace": ws.display().to_string(),
            "auth": {"mode": "oidc", "issuer": "https://id.example.test/", "client_id": "seagent", "client_secret": "cs-1"},
            "channel": {"kind": "telegram", "token": "123:abc", "owner": "42"}, "autostart": true});
        let v = apply(&p, &params, &discover, &auto).unwrap();
        let out = v.to_string();
        assert!(!out.contains("sk-test-1234567890") && !out.contains("cs-1") && !out.contains("123:abc"), "secrets never echoed: {out}");
        assert!(v["console_url"].as_str().unwrap().starts_with("http://127.0.0.1:18642/#token="));
        let text = std::fs::read_to_string(p.user_config()).unwrap();
        assert!(!text.contains("sk-test") && !text.contains("cs-1") && !text.contains("123:abc"), "config holds references only:\n{text}");
        let root: toml::Table = text.parse().unwrap();
        assert_eq!(root["model"]["default"].as_str(), Some("openai/gpt-x"));
        assert_eq!(root["approvals"]["mode"].as_str(), Some("manual"));
        assert_eq!(root["gate"]["privilege"].as_str(), Some("deny"));
        assert_eq!(root["app"]["workspace"].as_str(), Some(ws.display().to_string().as_str()));
        assert!(ws.is_dir());
        assert_eq!(root["app"]["auth"]["provider"].as_str(), Some("self_hosted"));
        assert_eq!(root["app"]["auth"]["self_hosted"]["jwks"].as_str(), Some("https://id.example.test/j"));
        assert_eq!(root["channels"]["telegram"]["allow"][0].as_str(), Some("42"));
        let vault = Vault::load(&p.secrets()).unwrap();
        for n in ["OPENAI_API_KEY", "APP_TOKEN", "APP_AUTH_SECRET", "APP_OIDC_CLIENT_SECRET", "TELEGRAM_TOKEN"] {
            assert!(vault.names().iter().any(|x| x == n), "{n} in the vault");
        }
        // single use: the wizard is now locked
        assert!(locked(&p));
        assert!(check(&p, Some("anything"), now_ms()).unwrap().contains("locked"));
        // bad input is refused before anything is written
        let (_r2, p2) = scratch("apply-bad");
        assert!(apply(&p2, &json!({"provider": "openai", "model": "m", "api_key": "k", "security": "yolo"}), &discover, &auto).is_err());
        assert!(!p2.user_config().exists() && !locked(&p2));
        assert!(apply(&p2, &json!({"provider": "openai"}), &discover, &auto).unwrap_err().contains("model"));
    }

    #[test]
    fn test_provider_never_echoes_the_key() {
        let (_r, p) = scratch("probe");
        let v = test_provider(&p, &json!({"provider": "custom-x", "base_url": "http://127.0.0.1:9/v1", "api_key": "sk-secret-abcdef"}));
        assert_eq!(v["ok"], json!(false));
        assert!(!v.to_string().contains("sk-secret-abcdef"));
        assert!(test_provider(&p, &json!({"provider": "openai"}))["error"].as_str().unwrap().contains("API key"));
    }

    #[test]
    fn lan_toggle_switches_listen_and_mode() {
        let mut root: toml::Table = "[app]\nenabled = true\nlisten = \"127.0.0.1:8640\"\n".parse().unwrap();
        assert!(apply_lan(&mut root, true).contains("https://"));
        assert!(lan_of(&root));
        assert_eq!(listen_of(&root), "0.0.0.0:8640");
        // The result is a config the app server accepts (LAN mode + TLS, no allow_public).
        let app = seagent_app::AppConfig::parse(root["app"].as_table().unwrap()).unwrap();
        assert!(app.exposure.lan && !app.exposure.allow_public && seagent_app::exposure::lan_only(&app));
        apply_lan(&mut root, false);
        assert!(!lan_of(&root));
        assert_eq!(listen_of(&root), "127.0.0.1:8640");
        // A specific private address the operator chose is kept.
        let mut r2: toml::Table = "[app]\nlisten = \"192.168.1.5:9000\"\n".parse().unwrap();
        apply_lan(&mut r2, true);
        assert_eq!(listen_of(&r2), "192.168.1.5:9000");
    }

    #[test]
    fn urls() {
        assert_eq!(base_url("0.0.0.0:8640"), "http://127.0.0.1:8640");
        assert_eq!(base_url("127.0.0.1:9"), "http://127.0.0.1:9");
    }
}
