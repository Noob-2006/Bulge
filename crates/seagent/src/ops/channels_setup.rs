//! Chat channels set up without editing `config.toml`: a guided form per platform, a
//! credential check, a test message and a live status — the Connections page's "Chat channels"
//! tab (`ui.connectors.channels.*`) and the matching CLI, `seagent channel kinds|add|rm|test`.
//!
//! Both surfaces run the same code: [`save`] builds the `[channels.<name>]` table, parses it
//! with `seagent_channel::config::parse_config` and constructs it with the channel's own
//! builder (the daemon's startup path, so `deny_unknown_fields` and missing credentials show
//! up before anything is written), then writes it with `confcli::put_table` (validated,
//! audited, backed up). Credentials typed into the form go to the vault and the table only
//! holds `{{secret:NAME}}`; on the command line a literal credential is refused, like
//! `seagent mcp add` refuses secret `--env` values. [`KINDS`] lists the fields of the common
//! platforms; every other registered kind gets a free key/value form that the builder
//! validates the same way.

use super::connectors::{bad, fail, fresh, need, user_table, valid_name, vault, vault_name, ConnCtx, Pending, Res};
use crate::args::Args;
use crate::{Fail, R};
use seagent_channel::Channel;
use seagent_kernel::config::Paths;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

pub const METHODS: &[&str] = &[
    "ui.connectors.channels.kinds", "ui.connectors.channels.list", "ui.connectors.channels.get", "ui.connectors.channels.save", "ui.connectors.channels.remove",
    "ui.connectors.channels.test", "ui.connectors.channels.verify",
];
pub const COMMANDS: &[&str] = &[];
pub const VALUE_FLAGS: &[&str] = &["kind", "dm-policy", "allow", "chat", "text"];
pub const BOOL_FLAGS: &[&str] = &[];

#[derive(Clone, Copy, PartialEq)]
pub enum FieldKind {
    Text,
    Secret,
    Number,
    Bool,
    List,
}

pub struct Field {
    pub key: &'static str,
    pub label: &'static str,
    pub kind: FieldKind,
    pub required: bool,
    pub hint: &'static str,
}

pub struct KindSpec {
    pub kind: &'static str,
    pub label: &'static str,
    pub help: &'static str,
    /// What a chat id looks like on this platform (for the test message).
    pub chat_hint: &'static str,
    pub fields: &'static [Field],
}

const fn f(key: &'static str, label: &'static str, kind: FieldKind, required: bool, hint: &'static str) -> Field {
    Field { key, label, kind, required, hint }
}
use FieldKind::{Bool, List, Number, Secret, Text};

/// The guided forms. Field names are the channel modules' own `Settings` keys (a test builds
/// every entry with its builder, so a renamed key fails here, not in someone's config).
pub const KINDS: &[KindSpec] = &[
    KindSpec { kind: "telegram", label: "Telegram", help: "Create a bot with @BotFather and paste its token.", chat_hint: "numeric chat id, e.g. 123456789", fields: &[
        f("token", "Bot token", Secret, true, "123456:ABC-DEF…"),
        f("webhook_url", "Webhook URL (optional)", Text, false, "leave empty to use long polling"),
        f("webhook_listen", "Webhook listen address", Text, false, "127.0.0.1:8443"),
        f("webhook_secret", "Webhook secret", Secret, false, ""),
    ] },
    KindSpec { kind: "discord", label: "Discord", help: "Discord Developer Portal → Applications → Bot → Reset token. Enable the Message Content intent.", chat_hint: "channel id (enable Developer Mode → Copy ID)", fields: &[
        f("token", "Bot token", Secret, true, ""),
        f("command_guild", "Register slash commands in guild", Text, false, "guild id; empty = global"),
        f("auto_thread", "Reply in a thread", Bool, false, ""),
        f("voice", "Voice channels", Bool, false, ""),
    ] },
    KindSpec { kind: "slack", label: "Slack", help: "api.slack.com/apps → your app. Socket Mode needs the app-level token (xapp-…); the Events API needs the signing secret and a listen address instead.", chat_hint: "channel id, e.g. C0123456789", fields: &[
        f("bot_token", "Bot token", Secret, true, "xoxb-…"),
        f("app_token", "App-level token (Socket Mode)", Secret, false, "xapp-…"),
        f("signing_secret", "Signing secret (Events API)", Secret, false, ""),
        f("listen", "Events API listen address", Text, false, "127.0.0.1:3000"),
    ] },
    KindSpec { kind: "matrix", label: "Matrix", help: "Any homeserver. Give an access token, or a user id and password for SE Agent to log in.", chat_hint: "room id, e.g. !abc:matrix.org", fields: &[
        f("homeserver", "Homeserver URL", Text, true, "https://matrix.org"),
        f("user_id", "User id", Text, false, "@bot:matrix.org"),
        f("access_token", "Access token", Secret, false, ""),
        f("password", "Password", Secret, false, "used once to log in"),
        f("device_name", "Device name", Text, false, "SE Agent"),
        f("e2ee", "End-to-end encryption", Bool, false, ""),
        f("recovery_key", "Key backup recovery key", Secret, false, ""),
    ] },
    KindSpec { kind: "mattermost", label: "Mattermost", help: "System Console → Integrations → Bot accounts.", chat_hint: "channel id", fields: &[
        f("url", "Server URL", Text, true, "https://chat.example.com"),
        f("token", "Bot access token", Secret, true, ""),
    ] },
    KindSpec { kind: "msteams", label: "Microsoft Teams", help: "Azure Bot registration: app id and client secret; Teams POSTs to the listen address.", chat_hint: "conversation id", fields: &[
        f("app_id", "App (client) id", Text, true, ""),
        f("app_password", "Client secret", Secret, true, ""),
        f("tenant", "Tenant id", Text, false, "single-tenant bots"),
        f("listen", "Listen address", Text, false, "127.0.0.1:3978"),
    ] },
    KindSpec { kind: "email", label: "Email (IMAP/SMTP)", help: "A mailbox SE Agent reads over IMAP and answers over SMTP. Use an app password where the provider offers one.", chat_hint: "an email address", fields: &[
        f("address", "Address", Text, true, "agent@example.com"),
        f("password", "Password / app password", Secret, true, ""),
        f("imap_host", "IMAP host", Text, true, "imap.example.com"),
        f("imap_port", "IMAP port", Number, false, "993"),
        f("smtp_host", "SMTP host", Text, false, "smtp.example.com"),
        f("smtp_port", "SMTP port", Number, false, "465 or 587"),
        f("username", "Login name (if not the address)", Text, false, ""),
        f("from_name", "From name", Text, false, "SE Agent"),
        f("mailbox", "Mailbox", Text, false, "INBOX"),
    ] },
    KindSpec { kind: "whatsapp", label: "WhatsApp (bridge)", help: "Runs the bundled Baileys bridge (bridges/whatsapp, needs Node.js); scan its QR code once. Or point it at a bridge already running.", chat_hint: "phone number with country code, e.g. 886912345678", fields: &[
        f("bridge_url", "Existing bridge URL", Text, false, "http://127.0.0.1:3010"),
        f("port", "Bridge port", Number, false, "3010"),
        f("bridge_dir", "Bridge directory", Text, false, "bridges/whatsapp"),
        f("token", "Bridge token", Secret, false, ""),
    ] },
    KindSpec { kind: "signal", label: "Signal", help: "Talks to signal-cli's HTTP daemon (signal-cli daemon --http).", chat_hint: "phone number, e.g. +886912345678", fields: &[
        f("account", "Account number", Text, true, "+886912345678"),
        f("url", "signal-cli URL", Text, false, "http://127.0.0.1:8080"),
    ] },
    KindSpec { kind: "line", label: "LINE", help: "LINE Developers → Messaging API channel. LINE POSTs to the webhook, so the listen address must be reachable (public URL).", chat_hint: "user / group id", fields: &[
        f("channel_access_token", "Channel access token", Secret, true, ""),
        f("channel_secret", "Channel secret", Secret, true, ""),
        f("listen", "Listen address", Text, true, "127.0.0.1:8088"),
        f("public_url", "Public URL", Text, false, "https://bot.example.com"),
    ] },
    KindSpec { kind: "irc", label: "IRC", help: "Any IRC network; TLS on by default.", chat_hint: "#channel or a nick", fields: &[
        f("host", "Server", Text, true, "irc.libera.chat"),
        f("port", "Port", Number, false, "6697"),
        f("tls", "TLS", Bool, false, ""),
        f("nick", "Nick", Text, true, "seagent"),
        f("channels", "Channels to join", List, false, "#a, #b"),
        f("password", "Server password", Secret, false, ""),
        f("sasl_username", "SASL user", Text, false, ""),
        f("sasl_password", "SASL password", Secret, false, ""),
    ] },
    KindSpec { kind: "ntfy", label: "ntfy", help: "Push notifications through ntfy.sh or your own server; replies arrive on the topic.", chat_hint: "topic name", fields: &[
        f("topic", "Topic", Text, true, "my-agent-topic"),
        f("server", "Server", Text, false, "https://ntfy.sh"),
        f("publish_topic", "Publish topic", Text, false, ""),
        f("token", "Access token", Secret, false, ""),
    ] },
    KindSpec { kind: "homeassistant", label: "Home Assistant", help: "Profile → Security → Long-lived access tokens.", chat_hint: "state_chat (default)", fields: &[
        f("url", "Home Assistant URL", Text, true, "http://homeassistant.local:8123"),
        f("token", "Long-lived access token", Secret, true, ""),
        f("notify_service", "Notify service", Text, false, "notify.mobile_app_phone"),
        f("watch_entities", "Entities to watch", List, false, "binary_sensor.door, …"),
    ] },
    KindSpec { kind: "webhook", label: "Webhook", help: "A generic HTTP endpoint: POST JSON in, optional outbound URL for replies. Subscriptions are managed under Webhooks.", chat_hint: "any chat id the caller uses", fields: &[
        f("listen", "Listen address", Text, false, "127.0.0.1:8787"),
        f("token", "Inbound bearer token", Secret, false, ""),
        f("secret", "HMAC secret", Secret, false, ""),
        f("outbound_url", "Outbound URL", Text, false, "https://example.com/hook"),
        f("outbound_token", "Outbound token", Secret, false, ""),
    ] },
];

/// Shared `[channels.<name>]` keys the form edits next to the platform fields (the router
/// reads them; channel modules never see them).
const POLICY: &[&str] = &["dm_policy", "group_policy", "allow", "groups", "require_mention", "default_chat", "privacy_notice", "ai_label", "allow_admin_from", "session_per"];

fn spec(kind: &str) -> Option<&'static KindSpec> {
    KINDS.iter().find(|k| k.kind == kind)
}

fn registry_kinds() -> Vec<&'static str> {
    seagent_channel::config::registry().into_iter().map(|(k, _)| k).collect()
}

fn kind_json(k: &KindSpec) -> Value {
    json!({"kind": k.kind, "label": k.label, "help": k.help, "chat_hint": k.chat_hint, "verify": matches!(k.kind, "telegram" | "discord" | "slack"),
        "fields": k.fields.iter().map(|f| json!({"key": f.key, "label": f.label, "required": f.required, "hint": f.hint, "type": match f.kind { Text => "text", Secret => "secret", Number => "number", Bool => "bool", List => "list" }})).collect::<Vec<_>>()})
}

pub struct ChanCtx {
    pub conn: ConnCtx,
    /// Channels the running daemon built: name → adapter.
    live: BTreeMap<String, Arc<dyn Channel>>,
    /// Startup warnings about channels (a channel that failed to build says why here).
    warnings: Vec<String>,
}

pub fn methods(paths: &Paths, k: &seagent_kernel::kernel::Kernel, ext: Option<&crate::ext::Ext>) -> seagent_kernel::daemon::MethodExt {
    let ws = k.cfg.app.get("workspace").and_then(|v| v.as_str()).map(std::path::PathBuf::from).or_else(|| std::env::current_dir().ok()).unwrap_or_else(|| ".".into());
    let c = Arc::new(ChanCtx {
        conn: ConnCtx::new(paths, &ws),
        live: ext.map(|e| e.channels.iter().map(|(n, (ch, _))| (n.clone(), ch.clone())).collect()).unwrap_or_default(),
        warnings: ext.map(|e| e.warnings.iter().filter(|w| w.contains("channel")).cloned().collect()).unwrap_or_default(),
    });
    Arc::new(move |m: &str, p: &Value| call(&c, m, p))
}

pub fn call(c: &ChanCtx, m: &str, p: &Value) -> Option<Res> {
    let s = |k: &str| p[k].as_str().unwrap_or("").trim().to_string();
    Some(match m {
        "ui.connectors.channels.kinds" => Ok(json!({"kinds": KINDS.iter().map(kind_json).collect::<Vec<_>>(), "all": registry_kinds()})),
        "ui.connectors.channels.list" => list(c),
        "ui.connectors.channels.get" => get(&c.conn, &s("name")),
        "ui.connectors.channels.save" => save(&c.conn, p, true),
        "ui.connectors.channels.remove" => need(&s("name"), "name").and_then(|n| super::connectors::remove_table(&c.conn, &format!("channels.{n}"))),
        "ui.connectors.channels.test" => test(&c.conn, Some(&c.live), &s("name"), &s("chat"), &s("text")),
        "ui.connectors.channels.verify" => verify(&c.conn, &s("name")),
        _ => return None,
    })
}

/// `{{secret:NAME}}` references in a table whose vault entry is missing.
fn missing_secrets(t: &toml::Table, names: &[String]) -> Vec<String> {
    let text = toml::to_string(t).unwrap_or_default();
    let mut out = vec![];
    for part in text.split("{{secret:").skip(1) {
        if let Some(n) = part.split("}}").next() {
            if !names.iter().any(|x| x == n) && !out.iter().any(|x: &String| x == n) {
                out.push(n.to_string());
            }
        }
    }
    out
}

fn list(c: &ChanCtx) -> Res {
    let cfg = fresh(&c.conn)?;
    let names = vault(&c.conn).map(|v| v.names()).unwrap_or_default();
    let mut out = vec![];
    for (n, t) in &cfg.channels {
        let kind = t.get("kind").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let parsed = seagent_channel::config::parse_config(n, &serde_json::to_value(t).unwrap_or(Value::Null));
        let missing = missing_secrets(t, &names);
        let enabled = t.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
        let warn: Vec<&String> = c.warnings.iter().filter(|w| w.contains(&format!("[channels.{n}]")) || w.contains(&format!("channel {n}:"))).collect();
        let (status, detail) = if c.live.contains_key(n) {
            ("running", String::new())
        } else if !enabled {
            ("disabled", String::new())
        } else if let Err(e) = &parsed {
            ("error", e.clone())
        } else if !missing.is_empty() {
            ("error", format!("secret(s) not set: {}", missing.join(", ")))
        } else if let Some(w) = warn.first() {
            ("error", w.to_string())
        } else {
            ("restart", "saved; restart the daemon to start it".to_string())
        };
        out.push(json!({
            "name": n, "kind": kind, "label": spec(&kind).map(|k| k.label).unwrap_or(&kind), "enabled": enabled, "status": status, "detail": detail,
            "dm_policy": t.get("dm_policy").and_then(|v| v.as_str()).unwrap_or("pairing"),
            "allow": t.get("allow").cloned().unwrap_or(toml::Value::Array(vec![])),
            "default_chat": t.get("default_chat").and_then(|v| v.as_str()),
            "chat_hint": spec(&kind).map(|k| k.chat_hint),
            "editable": user_table(&c.conn, &format!("channels.{n}")).is_some(),
            "verify": matches!(kind.as_str(), "telegram" | "discord" | "slack"),
        }));
    }
    Ok(json!({"channels": out}))
}

/// The form view: platform fields (secrets as set/unset only), policy, and the remaining keys.
fn get(c: &ConnCtx, name: &str) -> Res {
    valid_name(name)?;
    let t = user_table(c, &format!("channels.{name}")).ok_or_else(|| bad(format!("no [channels.{name}] in {}", c.paths.user_config().display())))?;
    let kind = t.get("kind").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let names = vault(c).map(|v| v.names()).unwrap_or_default();
    let known: Vec<&str> = spec(&kind).map(|s| s.fields.iter().map(|f| f.key).collect()).unwrap_or_default();
    let mut fields = serde_json::Map::new();
    let mut extra = vec![];
    for (k, v) in &t {
        if k == "kind" || k == "enabled" || POLICY.contains(&k.as_str()) {
            continue;
        }
        let raw = v.as_str().map(String::from).unwrap_or_else(|| v.to_string());
        let secretish = spec(&kind).and_then(|s| s.fields.iter().find(|f| f.key == k)).map(|f| f.kind == Secret).unwrap_or_else(|| crate::mcp_cli::secret_name(k));
        let view = match super::connectors::secret_ref(&raw) {
            Some(r) => json!({"secret": true, "set": names.iter().any(|x| x == r), "ref": r}),
            None if secretish => json!({"secret": true, "set": true, "literal": true}),
            None => match v {
                toml::Value::Array(a) => json!(a.iter().map(|x| x.as_str().map(String::from).unwrap_or_else(|| x.to_string())).collect::<Vec<_>>().join(", ")),
                toml::Value::Boolean(b) => json!(b),
                toml::Value::Integer(i) => json!(i),
                _ => json!(raw),
            },
        };
        if known.contains(&k.as_str()) {
            fields.insert(k.clone(), view);
        } else {
            extra.push(json!({"key": k, "value": if view.is_object() { json!("") } else { json!(v.to_string()) }, "secret": view.is_object(), "keep": view.is_object()}));
        }
    }
    let policy: serde_json::Map<String, Value> = POLICY.iter().filter_map(|k| t.get(*k).map(|v| (k.to_string(), serde_json::to_value(v).unwrap_or(Value::Null)))).collect();
    Ok(json!({"name": name, "kind": kind, "enabled": t.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true), "fields": fields, "policy": policy, "extra": extra}))
}

fn list_value(v: &Value) -> Vec<toml::Value> {
    match v {
        Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(str::trim).filter(|x| !x.is_empty()).map(|x| toml::Value::String(x.into()))).collect(),
        Value::String(s) => s.split([',', '\n']).map(str::trim).filter(|x| !x.is_empty()).map(|x| toml::Value::String(x.into())).collect(),
        _ => vec![],
    }
}

/// Create or replace `[channels.<name>]` from a form / CLI request:
/// `{name, kind, original?, enabled?, fields: {key: value}, extra: [{key, value, secret, keep}],
/// policy: {dm_policy, allow, default_chat, …}}`. `literal_secrets = false` (the CLI) refuses a
/// credential typed as a literal instead of storing it in the vault.
pub fn save(c: &ConnCtx, p: &Value, literal_secrets: bool) -> Res {
    let name = p["name"].as_str().unwrap_or("").trim().to_string();
    valid_name(&name)?;
    let kind = p["kind"].as_str().unwrap_or("").trim().to_string();
    if kind != "plugin" && !registry_kinds().contains(&kind.as_str()) {
        return Err(bad(format!("unknown channel kind `{kind}`; known: {}", registry_kinds().join(", "))));
    }
    let original = p["original"].as_str().map(str::trim).filter(|o| !o.is_empty()).map(String::from);
    let base = user_table(c, &format!("channels.{}", original.as_deref().unwrap_or(&name)));
    if original.is_none() && base.is_some() {
        return Err(bad(format!("[channels.{name}] already exists; edit it instead")));
    }
    // A kind change starts over: the old platform's keys would only fail the new builder.
    let mut t = base.clone().filter(|b| b.get("kind").and_then(|v| v.as_str()) == Some(kind.as_str())).unwrap_or_default();
    t.insert("kind".into(), kind.clone().into());
    let mut pend = Pending::default();
    let secret = |key: &str, raw: &str, pend: &mut Pending| -> Result<String, (i32, String)> {
        if !literal_secrets && super::connectors::secret_ref(raw).is_none() {
            return Err(bad(format!("`{key}` is a credential: store it with `seagent secrets set NAME` and pass {{{{secret:NAME}}}}, never on the command line")));
        }
        Ok(pend.value(vault_name(&["CHANNEL", &name, key]), raw))
    };
    if let Some(sp) = spec(&kind) {
        for fd in sp.fields {
            let v = &p["fields"][fd.key];
            let text = v.as_str().map(str::trim).unwrap_or("");
            match fd.kind {
                Secret if !text.is_empty() => {
                    let r = secret(fd.key, text, &mut pend)?;
                    t.insert(fd.key.into(), r.into());
                }
                // Empty secret: keep what is stored (the form never sees it).
                Secret => {}
                Text if !text.is_empty() => {
                    t.insert(fd.key.into(), text.into());
                }
                Number if !text.is_empty() || v.is_number() => {
                    let n = v.as_i64().or_else(|| text.parse::<i64>().ok()).filter(|n| *n >= 0).ok_or_else(|| bad(format!("{}: `{text}` is not a number", fd.label)))?;
                    t.insert(fd.key.into(), toml::Value::Integer(n));
                }
                Bool if v.is_boolean() => {
                    t.insert(fd.key.into(), v.as_bool().unwrap_or(false).into());
                }
                List if !list_value(v).is_empty() => {
                    t.insert(fd.key.into(), toml::Value::Array(list_value(v)));
                }
                Bool => {}
                _ => {
                    t.remove(fd.key);
                }
            }
            if fd.required && fd.kind != Bool && !t.contains_key(fd.key) {
                return Err(bad(format!("{} is required", fd.label)));
            }
        }
    }
    for r in p["extra"].as_array().into_iter().flatten() {
        let k = r["key"].as_str().unwrap_or("").trim();
        if k.is_empty() || k == "kind" || POLICY.contains(&k) {
            continue;
        }
        if r["keep"].as_bool() == Some(true) && base.as_ref().is_some_and(|b| b.contains_key(k)) {
            continue;
        }
        let raw = r["value"].as_str().unwrap_or("").trim();
        if raw.is_empty() {
            t.remove(k);
        } else if r["secret"].as_bool() == Some(true) {
            let v = secret(k, raw, &mut pend)?;
            t.insert(k.into(), v.into());
        } else {
            t.insert(k.into(), crate::ops::confcli::parse_value(raw));
        }
    }
    let pol = &p["policy"];
    for k in POLICY {
        let v = &pol[*k];
        match (*k, v) {
            (_, Value::Null) => {}
            ("allow" | "groups" | "allow_admin_from", _) => {
                let l = list_value(v);
                if l.is_empty() {
                    t.remove(*k);
                } else {
                    t.insert(k.to_string(), toml::Value::Array(l));
                }
            }
            ("require_mention", Value::Bool(b)) => {
                t.insert(k.to_string(), (*b).into());
            }
            (_, Value::String(s)) if s.trim().is_empty() => {
                t.remove(*k);
            }
            (_, Value::String(s)) => {
                t.insert(k.to_string(), s.trim().into());
            }
            _ => return Err(bad(format!("policy `{k}` has the wrong type"))),
        }
    }
    if !t.contains_key("dm_policy") {
        // Same default as `seagent setup`: strangers must pair before the agent answers.
        t.insert("dm_policy".into(), "pairing".into());
    }
    match p["enabled"].as_bool() {
        Some(false) => {
            t.insert("enabled".into(), false.into());
        }
        Some(true) => {
            t.remove("enabled");
        }
        None => {}
    }
    let built = validate(c, &name, &t, &pend)?;
    crate::ops::confcli::put_table(&c.paths, &format!("channels.{name}"), Some(&t)).map_err(fail)?;
    let stored = pend.store(c)?;
    if let Some(o) = original.as_deref().filter(|o| *o != name) {
        crate::ops::confcli::put_table(&c.paths, &format!("channels.{o}"), None).map_err(fail)?;
    }
    Ok(json!({"ok": true, "name": name, "kind": kind, "secrets": stored, "checked": built, "restart": true}))
}

/// Parse the table and construct the adapter with its own builder (secrets from the vault
/// plus the ones about to be stored), in a scratch state dir. A listening channel is only
/// parsed: building it would bind the port the running daemon may hold.
fn validate(c: &ConnCtx, name: &str, t: &toml::Table, pend: &Pending) -> Result<&'static str, (i32, String)> {
    let enabled = t.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
    let cfg = seagent_channel::config::parse_config(name, &serde_json::to_value(t).map_err(|e| fail(e.to_string()))?).map_err(bad)?;
    if cfg.is_plugin() || cfg.listens() || !enabled {
        return Ok("parsed");
    }
    let state = seagent_core::tmp::TempDir::new_in(&c.paths.data, "channel-check");
    let secrets = pend.secrets(Arc::new(vault(c)?));
    let ch = seagent_channel::config::build(name, &cfg, state.path(), &secrets).map_err(bad)?;
    ch.stop();
    Ok("built")
}

/// Build a configured channel the way the daemon does (`ext::load` without the plugin hosts).
fn build_fresh(c: &ConnCtx, name: &str) -> Result<Arc<dyn Channel>, (i32, String)> {
    let cfg = fresh(c)?;
    let t = cfg.channels.get(name).ok_or_else(|| bad(format!("no channel `{name}`")))?;
    let cc = seagent_channel::config::parse_config(name, &serde_json::to_value(t).unwrap_or(Value::Null)).map_err(bad)?;
    if cc.listens() || cc.is_plugin() {
        return Err(bad(format!("channel `{name}` {} — start (or restart) the daemon, then test it here", if cc.is_plugin() { "comes from a plugin" } else { "listens for webhooks, so only the daemon runs it" })));
    }
    let state = c.paths.data.join("channels");
    let _ = std::fs::create_dir_all(&state);
    let v = Arc::new(vault(c)?);
    seagent_channel::config::build(name, &cc, &state, &crate::ext::secrets_fn(&v)).map_err(bad)
}

/// Send a test message (`seagent channel test`): through the daemon's live adapter when it runs
/// one, otherwise through a freshly built one. `chat` defaults to `default_chat`.
pub fn test(c: &ConnCtx, live: Option<&BTreeMap<String, Arc<dyn Channel>>>, name: &str, chat: &str, text: &str) -> Res {
    valid_name(name)?;
    let cfg = fresh(c)?;
    let t = cfg.channels.get(name).ok_or_else(|| bad(format!("no channel `{name}`")))?;
    let chat = if chat.is_empty() { t.get("default_chat").and_then(|v| v.as_str()).unwrap_or("").to_string() } else { chat.to_string() };
    if chat.is_empty() {
        let hint = t.get("kind").and_then(|v| v.as_str()).and_then(spec).map(|s| s.chat_hint).unwrap_or("the platform's chat id");
        return Err(bad(format!("give a chat to send to ({hint}), or set default_chat")));
    }
    let (ch, via) = match live.and_then(|l| l.get(name)) {
        Some(ch) => (ch.clone(), "daemon"),
        None => (build_fresh(c, name)?, "fresh"),
    };
    let text = if text.is_empty() { "SE Agent test message ✓".to_string() } else { text.to_string() };
    match ch.send(&seagent_channel::Outbound { chat: chat.clone(), text, reply_to: None, ..Default::default() }) {
        Ok(sent) => Ok(json!({"ok": true, "via": via, "chat": chat, "ids": sent.ids})),
        Err(e) => Ok(json!({"ok": false, "via": via, "chat": chat, "error": format!("{:?}: {}", e.kind, e.message)})),
    }
}

/// Check the credentials against the platform (`seagent setup`'s check: Telegram getMe,
/// Discord /users/@me, Slack auth.test); other kinds report whether the adapter builds.
fn verify(c: &ConnCtx, name: &str) -> Res {
    valid_name(name)?;
    let cfg = fresh(c)?;
    let t = cfg.channels.get(name).ok_or_else(|| bad(format!("no channel `{name}`")))?;
    let kind = t.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    let v = vault(c)?;
    let get = |k: &str| t.get(k).and_then(|x| x.as_str()).map(|x| v.substitute(x)).filter(|x| !x.contains("{{secret:"));
    let r = match kind {
        "telegram" | "discord" => get("token").ok_or_else(|| "the token secret is not set".to_string()).and_then(|tok| crate::setup::check_channel(kind, &tok, None)),
        "slack" => get("bot_token").ok_or_else(|| "the bot token secret is not set".to_string()).and_then(|tok| crate::setup::check_channel(kind, &tok, get("app_token").as_deref())),
        _ => match build_fresh(c, name) {
            Ok(_) => Ok(String::new()),
            Err((_, e)) => Err(e),
        },
    };
    Ok(match r {
        Ok(who) => json!({"ok": true, "identity": who, "online": matches!(kind, "telegram" | "discord" | "slack")}),
        Err(e) => json!({"ok": false, "error": e}),
    })
}

// ───────────────────────── CLI ─────────────────────────

/// `seagent channel kinds | add <name> --kind K [--set key=value]… [--dm-policy P] [--allow a,b]
/// | rm <name> | test <name> [--chat C] [--text T]` — `list` and `send` stay in `main.rs`.
pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if !matches!(cmd, "channel" | "channels") {
        return None;
    }
    let sub = a.pos(0)?;
    if !matches!(sub, "kinds" | "add" | "rm" | "remove" | "test") {
        return None;
    }
    Some(cli(sub, a))
}

fn cli(sub: &str, a: &Args) -> R {
    let paths = Paths::from_env();
    let ws = std::env::current_dir().unwrap_or_else(|_| ".".into());
    let c = ConnCtx::new(&paths, &ws);
    let msg = |e: (i32, String)| Fail::Msg(e.1);
    match sub {
        "kinds" => {
            for k in KINDS {
                println!("{:<14} {}  — {}", k.kind, k.label, k.fields.iter().map(|f| format!("{}{}", f.key, if f.required { "*" } else { "" })).collect::<Vec<_>>().join(", "));
            }
            println!("other kinds (any key = value): {}", registry_kinds().into_iter().filter(|k| spec(k).is_none()).collect::<Vec<_>>().join(", "));
            Ok(0)
        }
        "add" => {
            let name = a.need(1, "name")?;
            let kind = a.val("kind").ok_or_else(|| Fail::Usage("--kind is required (see `seagent channel kinds`)".into()))?;
            let mut fields = serde_json::Map::new();
            let mut policy = serde_json::Map::new();
            let mut extra = vec![];
            for kv in a.vals("set") {
                let (k, v) = kv.split_once('=').ok_or_else(|| Fail::Usage("--set expects key=value".into()))?;
                let k = k.trim();
                if POLICY.contains(&k) {
                    policy.insert(k.into(), json!(v.trim()));
                } else if spec(kind).is_some_and(|s| s.fields.iter().any(|f| f.key == k)) {
                    let bool_field = spec(kind).and_then(|s| s.fields.iter().find(|f| f.key == k)).is_some_and(|f| f.kind == Bool);
                    fields.insert(k.into(), if bool_field { json!(v.trim() == "true") } else { json!(v.trim()) });
                } else {
                    extra.push(json!({"key": k, "value": v.trim(), "secret": crate::mcp_cli::secret_name(k)}));
                }
            }
            if let Some(d) = a.val("dm-policy") {
                policy.insert("dm_policy".into(), json!(d));
            }
            if let Some(al) = a.val("allow") {
                policy.insert("allow".into(), json!(al));
            }
            let r = save(&c, &json!({"name": name, "kind": kind, "fields": fields, "extra": extra, "policy": policy}), false).map_err(msg)?;
            println!("added [channels.{name}] ({kind}, {}) to {} — restart the daemon to start it; `seagent channel test {name} --chat …` sends a test message", r["checked"].as_str().unwrap_or(""), paths.user_config().display());
            Ok(0)
        }
        "rm" | "remove" => {
            let name = a.need(1, "name")?;
            super::connectors::remove_table(&c, &format!("channels.{name}")).map_err(msg)?;
            println!("removed [channels.{name}]");
            Ok(0)
        }
        _ => {
            let name = a.need(1, "name")?;
            let r = test(&c, None, name, a.val("chat").unwrap_or(""), a.val("text").unwrap_or("")).map_err(msg)?;
            if r["ok"] == true {
                println!("sent to {} on {name}", r["chat"].as_str().unwrap_or(""));
                Ok(0)
            } else {
                Err(Fail::Msg(format!("{name}: {}", r["error"].as_str().unwrap_or("send failed"))))
            }
        }
    }
}

/// For `ConnCtx`-only callers (tests).
#[cfg(test)]
pub fn ctx_for(paths: &Paths, ws: &std::path::Path) -> ChanCtx {
    ChanCtx { conn: ConnCtx::new(paths, ws), live: BTreeMap::new(), warnings: vec![] }
}
