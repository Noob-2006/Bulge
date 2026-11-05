//! Hermes `discord` / `discord_admin` model tools (ported from
//! `hermes-agent/tools/discord_tool.py`, MIT): one action table split into the
//! participation trio (`discord`: fetch_messages, search_members, create_thread) and
//! server management (`discord_admin`). Same names, params, results and error texts.
//!
//! The schema is filtered by intents and the `server_actions` allowlist. Intents come
//! from the channel's configured Identify intents (GUILD_MEMBERS / MESSAGE_CONTENT set
//! there count as available); a bit that is not configured is looked up once in the
//! background from `GET /applications/@me` `flags`, like upstream (permissive until the
//! answer arrives or when it fails). Per-guild permissions are not pre-checked: a 403
//! is mapped to guidance. Calls go through the channel's REST client (rate-limit buckets).

use super::{Body, Inner};
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const GUILD_MEMBERS_INTENT: u64 = 1 << 1;
const MESSAGE_CONTENT_INTENT: u64 = 1 << 15;
/// Application flag bits; the *_LIMITED bit is the <100-guild variant of the same intent.
const FLAGS_GUILD_MEMBERS: u64 = (1 << 14) | (1 << 15);
const FLAGS_MESSAGE_CONTENT: u64 = (1 << 18) | (1 << 19);

/// (action, required params, description) — schema/enum order.
const MANIFEST: [(&str, &[&str], &str); 15] = [
    ("list_guilds", &[], "list servers the bot is in"),
    ("server_info", &["guild_id"], "server details + member counts"),
    ("list_channels", &["guild_id"], "all channels grouped by category"),
    ("channel_info", &["channel_id"], "single channel details"),
    ("list_roles", &["guild_id"], "roles sorted by position"),
    ("member_info", &["guild_id", "user_id"], "lookup a specific member"),
    ("search_members", &["guild_id", "query"], "find members by name prefix"),
    ("fetch_messages", &["channel_id"], "recent messages; optional before/after snowflakes"),
    ("list_pins", &["channel_id"], "pinned messages in a channel"),
    ("pin_message", &["channel_id", "message_id"], "pin a message"),
    ("unpin_message", &["channel_id", "message_id"], "unpin a message"),
    ("delete_message", &["channel_id", "message_id"], "delete a message"),
    ("create_thread", &["channel_id", "name"], "create a public thread; optional message_id anchor"),
    ("add_role", &["guild_id", "user_id", "role_id"], "assign a role"),
    ("remove_role", &["guild_id", "user_id", "role_id"], "remove a role"),
];
const CORE: [&str; 3] = ["fetch_messages", "search_members", "create_thread"];
const MEMBERS_GATED: [&str; 2] = ["member_info", "search_members"];

const CONTENT_NOTE: &str = "\n\nNOTE: Bot does NOT have the MESSAGE_CONTENT privileged intent. {names} will return message metadata (author, timestamps, attachments, reactions, pin state) but `content` will be empty for messages not sent as a direct mention to the bot or in DMs. Enable the intent in the Discord Developer Portal to see all content.";

const NO_MANAGE_MESSAGES: &str = "Bot lacks MANAGE_MESSAGES permission in this channel";
const VIEW_HISTORY: &str = "Bot cannot view this channel (missing VIEW_CHANNEL or READ_MESSAGE_HISTORY).";
const ROLE_HIERARCHY: &str = "Either the bot lacks MANAGE_ROLES, or the target role sits higher than the bot's highest role.";

fn hint_403(action: &str) -> Option<String> {
    Some(match action {
        "pin_message" => format!("{NO_MANAGE_MESSAGES}. Ask the server admin to grant the bot a role that has MANAGE_MESSAGES, or a per-channel overwrite."),
        "unpin_message" => format!("{NO_MANAGE_MESSAGES}."),
        "delete_message" => format!("{NO_MANAGE_MESSAGES}, or cannot view the channel/message."),
        "create_thread" => "Bot lacks CREATE_PUBLIC_THREADS in this channel, or cannot view it.".into(),
        "add_role" => format!("{ROLE_HIERARCHY} Roles can only be assigned below the bot's own position in the role hierarchy."),
        "remove_role" => ROLE_HIERARCHY.into(),
        "fetch_messages" | "list_pins" => VIEW_HISTORY.into(),
        "channel_info" => "Bot cannot view this channel (missing VIEW_CHANNEL).".into(),
        "search_members" => "Likely missing the Server Members privileged intent — enable it in the Discord Developer Portal under your bot's settings.".into(),
        "member_info" => "Bot cannot see this guild member (missing Server Members intent or insufficient permissions).".into(),
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Caps {
    members: bool,
    content: bool,
    /// From the configured intents or `/applications/@me` (false = permissive default).
    detected: bool,
}

const PERMISSIVE: Caps = Caps { members: true, content: true, detected: false };

/// State shared by both tools of one channel.
struct Shared {
    inner: Arc<Inner>,
    /// `/applications/@me` result once the background lookup finished.
    app: Mutex<Option<Caps>>,
}

impl Shared {
    fn configured(&self) -> (bool, bool) {
        let i = self.inner.cfg.intents;
        (i & GUILD_MEMBERS_INTENT != 0, i & MESSAGE_CONTENT_INTENT != 0)
    }

    fn caps(&self) -> Caps {
        let (members, content) = self.configured();
        if members && content {
            return Caps { members, content, detected: true };
        }
        match *self.app.lock().unwrap() {
            Some(app) => Caps { members: members || app.members, content: content || app.content, detected: app.detected },
            None => PERMISSIVE,
        }
    }

    /// Best-effort `GET /applications/@me`; failure stays permissive.
    fn fetch_app_caps(&self) -> Caps {
        match self.inner.rest("GET", "/applications/@me", Body::None) {
            Ok(app) => {
                let flags = app["flags"].as_u64().unwrap_or(0);
                Caps { members: flags & FLAGS_GUILD_MEMBERS != 0, content: flags & FLAGS_MESSAGE_CONTENT != 0, detected: true }
            }
            Err(_) => PERMISSIVE,
        }
    }

    fn allowlist(&self) -> Option<Vec<&'static str>> {
        let list = self.inner.cfg.server_actions.as_ref()?;
        Some(MANIFEST.iter().map(|m| m.0).filter(|n| list.iter().any(|l| l.trim() == *n)).collect())
    }

    /// Visible actions from intents + allowlist, in manifest order.
    fn available(&self, caps: Caps, core: bool) -> Vec<&'static str> {
        let allow = self.allowlist();
        MANIFEST
            .iter()
            .map(|m| m.0)
            .filter(|n| CORE.contains(n) == core)
            .filter(|n| caps.members || !MEMBERS_GATED.contains(n))
            .filter(|n| allow.as_ref().is_none_or(|a| a.contains(n)))
            .collect()
    }
}

/// `discord` + `discord_admin` for this channel (a channel not named `discord` suffixes its id).
/// Starts the intent lookup when the configured intents leave a privileged bit open.
pub(super) fn tools(inner: &Arc<Inner>) -> Vec<Arc<dyn Tool>> {
    let shared = Arc::new(Shared { inner: inner.clone(), app: Mutex::new(None) });
    let (members, content) = shared.configured();
    if !(members && content) {
        let s = shared.clone();
        let _ = std::thread::Builder::new().name("discord-caps-detect".into()).spawn(move || {
            let caps = s.fetch_app_caps();
            *s.app.lock().unwrap() = Some(caps);
        });
    }
    let safe: String = inner.cfg.id.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' }).collect();
    let name = |base: &str| if safe == "discord" { base.to_string() } else { format!("{base}_{safe}") };
    let mut out: Vec<Arc<dyn Tool>> = Vec::new();
    for (base, core) in [("discord", true), ("discord_admin", false)] {
        // An allowlist that leaves a tool no actions drops it (upstream: schema `None`).
        if !shared.available(PERMISSIVE, core).is_empty() {
            out.push(Arc::new(DiscordTool { name: name(base), core, shared: shared.clone() }));
        }
    }
    out
}

pub struct DiscordTool {
    name: String,
    core: bool,
    shared: Arc<Shared>,
}

fn err(msg: impl Into<String>) -> String {
    json!({"error": msg.into()}).to_string()
}

fn listing(key: &str, items: Vec<Value>) -> String {
    let mut out = serde_json::Map::new();
    out.insert("count".into(), json!(items.len()));
    out.insert(key.into(), Value::Array(items));
    Value::Object(out).to_string()
}

fn channel_type_name(t: u64) -> String {
    match t {
        0 => "text".into(),
        2 => "voice".into(),
        4 => "category".into(),
        5 => "announcement".into(),
        10 => "announcement_thread".into(),
        11 => "public_thread".into(),
        12 => "private_thread".into(),
        13 => "stage".into(),
        15 => "forum".into(),
        16 => "media".into(),
        t => format!("unknown({t})"),
    }
}

fn member_summary(m: &Value, full: bool) -> Value {
    let u = &m["user"];
    let mut row = json!({
        "user_id": u["id"], "username": u["username"], "display_name": u["global_name"], "nickname": m["nick"],
        "bot": u.get("bot").cloned().unwrap_or(json!(false)), "roles": m.get("roles").cloned().unwrap_or(json!([])),
    });
    if full {
        row["avatar"] = u["avatar"].clone();
        row["joined_at"] = m["joined_at"].clone();
        row["premium_since"] = m["premium_since"].clone();
    }
    row
}

fn message_summary(m: &Value) -> Value {
    let a = &m["author"];
    let attachments: Vec<Value> = m["attachments"].as_array().into_iter().flatten().map(|x| json!({"filename": x["filename"], "url": x["url"], "size": x["size"]})).collect();
    let reactions: Vec<Value> = m["reactions"].as_array().into_iter().flatten().map(|r| json!({"emoji": r["emoji"]["name"], "count": r.get("count").cloned().unwrap_or(json!(0))})).collect();
    json!({
        "id": m["id"], "content": m.get("content").cloned().unwrap_or(json!("")),
        "author": {"id": a["id"], "username": a["username"], "display_name": a["global_name"], "bot": a.get("bot").cloned().unwrap_or(json!(false))},
        "timestamp": m["timestamp"], "edited_timestamp": m["edited_timestamp"], "attachments": attachments, "reactions": reactions,
        "pinned": m.get("pinned").cloned().unwrap_or(json!(false)),
    })
}

fn pos(v: &Value) -> i64 {
    v["position"].as_i64().unwrap_or(0)
}

/// Discord caps list endpoints at 100 per page.
fn limit_param(v: &Value, default: i64) -> String {
    let n = match v {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Value::String(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    };
    n.unwrap_or(default).min(100).to_string()
}

fn qs(pairs: &[(&str, String)]) -> String {
    format!("?{}", pairs.iter().map(|(k, v)| format!("{k}={}", ark_net::urlencode(v))).collect::<Vec<_>>().join("&"))
}

impl DiscordTool {
    fn actions(&self) -> Vec<&'static str> {
        MANIFEST.iter().map(|m| m.0).filter(|n| CORE.contains(n) == self.core).collect()
    }

    fn arg(input: &Value, k: &str) -> String {
        match &input[k] {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            _ => String::new(),
        }
    }

    fn rest(&self, method: &str, path: &str, body: Body) -> Result<Value, crate::ChannelError> {
        self.shared.inner.rest(method, path, body)
    }

    fn run(&self, action: &str, input: &Value) -> Result<String, crate::ChannelError> {
        let a = |k| Self::arg(input, k);
        let (g, c, u, m) = (a("guild_id"), a("channel_id"), a("user_id"), a("message_id"));
        let limit = if input["limit"].is_null() { json!(50) } else { input["limit"].clone() };
        let ok = |message: String| json!({"success": true, "message": message}).to_string();
        Ok(match action {
            "list_guilds" => {
                let v = self.rest("GET", "/users/@me/guilds", Body::None)?;
                listing("guilds", v.as_array().into_iter().flatten().map(|x| json!({"id": x["id"], "name": x["name"], "icon": x["icon"], "owner": x.get("owner").cloned().unwrap_or(json!(false)), "permissions": x["permissions"]})).collect())
            }
            "server_info" => {
                let x = self.rest("GET", &format!("/guilds/{g}?with_counts=true"), Body::None)?;
                json!({
                    "id": x["id"], "name": x["name"], "description": x["description"], "icon": x["icon"], "owner_id": x["owner_id"],
                    "member_count": x["approximate_member_count"], "online_count": x["approximate_presence_count"],
                    "features": x.get("features").cloned().unwrap_or(json!([])), "premium_tier": x["premium_tier"],
                    "premium_subscription_count": x["premium_subscription_count"], "verification_level": x["verification_level"],
                })
                .to_string()
            }
            "list_channels" => {
                let v = self.rest("GET", &format!("/guilds/{g}/channels"), Body::None)?;
                let all: Vec<Value> = v.as_array().cloned().unwrap_or_default();
                let mut cats: Vec<&Value> = all.iter().filter(|ch| ch["type"] == 4).collect();
                cats.sort_by_key(|c| pos(c));
                let mut uncategorized = Vec::new();
                let mut groups: Vec<Vec<Value>> = vec![Vec::new(); cats.len()];
                for ch in all.iter().filter(|ch| ch["type"] != 4) {
                    let row = json!({
                        "id": ch["id"], "name": ch.get("name").cloned().unwrap_or(json!("")), "type": channel_type_name(ch["type"].as_u64().unwrap_or(0)),
                        "position": ch.get("position").cloned().unwrap_or(json!(0)), "topic": ch["topic"], "nsfw": ch.get("nsfw").cloned().unwrap_or(json!(false)),
                    });
                    match cats.iter().position(|c| ch["parent_id"].is_string() && c["id"] == ch["parent_id"]) {
                        Some(i) => groups[i].push(row),
                        None => uncategorized.push(row),
                    }
                }
                uncategorized.sort_by_key(pos);
                for gr in &mut groups {
                    gr.sort_by_key(pos);
                }
                let mut result = Vec::new();
                if !uncategorized.is_empty() {
                    result.push(json!({"category": null, "channels": uncategorized}));
                }
                for (cat, chans) in cats.iter().zip(groups) {
                    result.push(json!({"category": {"id": cat["id"], "name": cat["name"]}, "channels": chans}));
                }
                let total: usize = result.iter().map(|r| r["channels"].as_array().map_or(0, Vec::len)).sum();
                json!({"channel_groups": result, "total_channels": total}).to_string()
            }
            "channel_info" => {
                let x = self.rest("GET", &format!("/channels/{c}"), Body::None)?;
                json!({
                    "id": x["id"], "name": x["name"], "type": channel_type_name(x["type"].as_u64().unwrap_or(0)), "guild_id": x["guild_id"],
                    "topic": x["topic"], "nsfw": x.get("nsfw").cloned().unwrap_or(json!(false)), "position": x["position"], "parent_id": x["parent_id"],
                    "rate_limit_per_user": x.get("rate_limit_per_user").cloned().unwrap_or(json!(0)), "last_message_id": x["last_message_id"],
                })
                .to_string()
            }
            "list_roles" => {
                let v = self.rest("GET", &format!("/guilds/{g}/roles"), Body::None)?;
                let mut roles: Vec<Value> = v.as_array().cloned().unwrap_or_default();
                roles.sort_by_key(|r| std::cmp::Reverse(pos(r)));
                listing(
                    "roles",
                    roles
                        .iter()
                        .map(|r| {
                            let color = r["color"].as_u64().filter(|c| *c != 0).map(|c| format!("#{c:06x}"));
                            json!({
                                "id": r["id"], "name": r["name"], "color": color, "position": r.get("position").cloned().unwrap_or(json!(0)),
                                "mentionable": r.get("mentionable").cloned().unwrap_or(json!(false)), "managed": r.get("managed").cloned().unwrap_or(json!(false)),
                                "member_count": r["member_count"], "hoist": r.get("hoist").cloned().unwrap_or(json!(false)),
                            })
                        })
                        .collect(),
                )
            }
            "member_info" => member_summary(&self.rest("GET", &format!("/guilds/{g}/members/{u}"), Body::None)?, true).to_string(),
            "search_members" => {
                let q = qs(&[("query", a("query")), ("limit", limit_param(&limit, 20))]);
                let v = self.rest("GET", &format!("/guilds/{g}/members/search{q}"), Body::None)?;
                listing("members", v.as_array().into_iter().flatten().map(|x| member_summary(x, false)).collect())
            }
            "fetch_messages" => {
                let mut p = vec![("limit", limit_param(&limit, 50))];
                for k in ["before", "after"] {
                    let v = a(k);
                    if !v.is_empty() {
                        p.push((k, v));
                    }
                }
                let v = self.rest("GET", &format!("/channels/{c}/messages{}", qs(&p)), Body::None)?;
                listing("messages", v.as_array().into_iter().flatten().map(message_summary).collect())
            }
            "list_pins" => {
                let v = self.rest("GET", &format!("/channels/{c}/pins"), Body::None)?;
                listing(
                    "pinned_messages",
                    v.as_array()
                        .into_iter()
                        .flatten()
                        .map(|x| json!({"id": x["id"], "content": x["content"].as_str().unwrap_or("").chars().take(200).collect::<String>(), "author": x["author"]["username"], "timestamp": x["timestamp"]}))
                        .collect(),
                )
            }
            "pin_message" => {
                self.rest("PUT", &format!("/channels/{c}/pins/{m}"), Body::None)?;
                ok(format!("Message {m} pinned."))
            }
            "unpin_message" => {
                self.rest("DELETE", &format!("/channels/{c}/pins/{m}"), Body::None)?;
                ok(format!("Message {m} unpinned."))
            }
            "delete_message" => {
                self.rest("DELETE", &format!("/channels/{c}/messages/{m}"), Body::None)?;
                ok(format!("Message {m} deleted."))
            }
            "create_thread" => {
                let archive = if input["auto_archive_duration"].is_null() { json!(1440) } else { input["auto_archive_duration"].clone() };
                let mut body = json!({"name": a("name"), "auto_archive_duration": archive});
                let path = if m.is_empty() {
                    body["type"] = json!(11);
                    format!("/channels/{c}/threads")
                } else {
                    format!("/channels/{c}/messages/{m}/threads")
                };
                let t = self.rest("POST", &path, Body::Json(&body))?;
                json!({"success": true, "thread_id": t["id"], "name": t["name"]}).to_string()
            }
            "add_role" | "remove_role" => {
                let r = a("role_id");
                self.rest(if action == "add_role" { "PUT" } else { "DELETE" }, &format!("/guilds/{g}/members/{u}/roles/{r}"), Body::None)?;
                ok(if action == "add_role" { format!("Role {r} added to user {u}.") } else { format!("Role {r} removed from user {u}.") })
            }
            other => return Err(crate::unsupported(other)),
        })
    }
}

impl Tool for DiscordTool {
    fn spec(&self) -> ToolSpec {
        let caps = self.shared.caps();
        let actions = self.shared.available(caps, self.core);
        let block: Vec<String> = MANIFEST.iter().filter(|m| actions.contains(&m.0)).map(|(n, sig, d)| format!("  {n}({})  — {d}", sig.join(", "))).collect();
        let affected: Vec<&str> = ["fetch_messages", "list_pins"].into_iter().filter(|n| actions.contains(n)).collect();
        let note = if !affected.is_empty() && caps.detected && !caps.content { CONTENT_NOTE.replace("{names}", &affected.join(" and ")) } else { String::new() };
        let (lead, guidance) = if self.core {
            ("Read and participate in a Discord server.", "Use the channel_id from the current conversation context. Use search_members to look up user IDs by name prefix.")
        } else {
            (
                "Manage a Discord server via the REST API.",
                "Call list_guilds first to discover guild_ids, then list_channels for channel_ids. Runtime errors will tell you if the bot lacks a specific per-guild permission (e.g. MANAGE_ROLES for add_role).",
            )
        };
        ToolSpec {
            name: self.name.clone(),
            description: format!("{lead}\n\nAvailable actions:\n{}\n\n{guidance}{note}", block.join("\n")),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": actions},
                    "guild_id": {"type": "string", "description": "Discord server (guild) ID."},
                    "channel_id": {"type": "string", "description": "Discord channel ID."},
                    "user_id": {"type": "string", "description": "Discord user ID."},
                    "role_id": {"type": "string", "description": "Discord role ID."},
                    "message_id": {"type": "string", "description": "Discord message ID."},
                    "query": {"type": "string", "description": "Member name prefix to search for (search_members)."},
                    "name": {"type": "string", "description": "New thread name (create_thread)."},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 100, "description": "Max results (default 50). Applies to fetch_messages, search_members."},
                    "before": {"type": "string", "description": "Snowflake ID for reverse pagination (fetch_messages)."},
                    "after": {"type": "string", "description": "Snowflake ID for forward pagination (fetch_messages)."},
                    "auto_archive_duration": {"type": "integer", "enum": [60, 1440, 4320, 10080], "description": "Thread archive duration in minutes (create_thread, default 1440)."}
                },
                "required": ["action"]
            }),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }

    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let action = Self::arg(input, "action");
        let ids: Vec<String> = ["guild_id", "channel_id", "user_id", "role_id", "message_id"].iter().map(|k| (k, Self::arg(input, k))).filter(|(_, v)| !v.is_empty()).map(|(k, v)| format!("{k}={v}")).collect();
        let name = Self::arg(input, "name");
        let mut payload = format!("discord {action} {}", ids.join(" "));
        if !name.is_empty() {
            payload.push_str(&format!(" name={name}"));
        }
        vec![Effect::Net { dest: self.shared.inner.cfg.api_base.clone(), payload: payload.trim().to_string() }]
    }

    fn call(&self, _ctx: &ToolCtx, input: Value) -> ToolOutput {
        let action = Self::arg(&input, "action");
        let valid = self.actions();
        if !valid.contains(&action.as_str()) {
            return ToolOutput::err(json!({"error": format!("Unknown action: {action}"), "available_actions": valid}).to_string());
        }
        // Defense in depth: a stale schema must not let a denied action through.
        if let Some(allow) = self.shared.allowlist() {
            if !allow.contains(&action.as_str()) {
                let list = if allow.is_empty() { "<none>".to_string() } else { allow.join(", ") };
                return ToolOutput::err(err(format!("Action '{action}' is disabled by config (channels.{}.server_actions). Allowed: {list}", self.shared.inner.cfg.id)));
            }
        }
        let required = MANIFEST.iter().find(|m| m.0 == action).map(|m| m.1).unwrap_or(&[]);
        let missing: Vec<&str> = required.iter().copied().filter(|k| Self::arg(&input, k).is_empty()).collect();
        if !missing.is_empty() {
            return ToolOutput::err(err(format!("Missing required parameters for '{action}': {}", missing.join(", "))));
        }
        match self.run(&action, &input) {
            Ok(s) => ToolOutput::ok(s),
            Err(e) if e.message.contains(": HTTP 403 ") => {
                let base = format!("Discord API 403 (forbidden) on '{action}'.");
                ToolOutput::err(err(match hint_403(&action) {
                    Some(h) => format!("{base} {h} (Raw: {})", e.message),
                    None => format!("{base} (Raw: {})", e.message),
                }))
            }
            Err(e) => ToolOutput::err(err(format!("Discord API error: {}", e.message))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Config, Discord, DEFAULT_INTENTS};
    use super::*;
    use crate::testutil::FakeServer;
    use crate::Channel;
    use std::time::{Duration, Instant};

    fn ctx() -> ToolCtx {
        struct H;
        impl ark_core::ToolHost for H {
            fn spawn_agent(&self, _: ark_core::tool::SpawnRequest, _: &ark_core::Cancel) -> Result<String, String> {
                Err("no".into())
            }
            fn ask_user(&self, _: &str) -> Result<String, String> {
                Err("no".into())
            }
        }
        ToolCtx {
            workspace: ark_core::tmp::scratch("ark-ws"),
            session_id: "s".into(),
            artifacts: ark_core::tmp::scratch("ark-ws"),
            home: ark_core::tmp::scratch("ark-ws"),
            cancel: ark_core::Cancel::new(),
            host: Arc::new(H),
            secrets: Arc::new(|s: &str| s.to_string()),
        }
    }

    fn channel(srv: &FakeServer, id: &str, intents: u64, allow: Option<Vec<&str>>) -> Discord {
        let mut c = Config::new(id, "TOKEN");
        c.api_base = srv.url.clone();
        c.max_retries = 0;
        c.intents = intents;
        c.server_actions = allow.map(|a| a.into_iter().map(str::to_string).collect());
        Discord::new(c).unwrap()
    }

    fn find(tools: &[Arc<dyn Tool>], name: &str) -> Arc<dyn Tool> {
        tools.iter().find(|t| t.spec().name == name).cloned().unwrap_or_else(|| panic!("no tool {name}"))
    }

    fn enum_of(t: &Arc<dyn Tool>) -> Vec<String> {
        t.spec().input_schema["properties"]["action"]["enum"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect()
    }

    fn wait_until(f: impl Fn() -> bool) {
        let until = Instant::now() + Duration::from_secs(5);
        while !f() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(f(), "condition never became true");
    }

    fn run(t: &Arc<dyn Tool>, input: Value) -> (bool, Value) {
        let out = t.call(&ctx(), input);
        (out.is_error, serde_json::from_str(&out.content).unwrap())
    }

    fn api() -> FakeServer {
        FakeServer::start(|r, _| {
            let p = r.path.as_str();
            let v = match (r.method.as_str(), p) {
                ("GET", "/applications/@me") => json!({"id": "APP", "flags": 1 << 19}),
                ("GET", "/users/@me/guilds") => json!([{"id": "G", "name": "Guild", "icon": null, "owner": true, "permissions": "8"}]),
                ("GET", "/guilds/G?with_counts=true") => json!({"id": "G", "name": "Guild", "approximate_member_count": 5, "approximate_presence_count": 2, "premium_tier": 1}),
                ("GET", "/guilds/G/channels") => json!([
                    {"id": "C2", "type": 0, "name": "b", "position": 2, "parent_id": "K1"},
                    {"id": "K1", "type": 4, "name": "Cat", "position": 1},
                    {"id": "C1", "type": 0, "name": "a", "position": 1, "parent_id": "K1"},
                    {"id": "C3", "type": 2, "name": "v", "position": 0},
                    {"id": "C4", "type": 0, "name": "lost", "position": 5, "parent_id": "GONE"},
                    {"id": "K0", "type": 4, "name": "Empty", "position": 0}]),
                ("GET", "/channels/C1") => json!({"id": "C1", "type": 15, "guild_id": "G", "name": "a"}),
                ("GET", "/guilds/G/roles") => json!([{"id": "R1", "name": "low", "position": 1, "color": 0}, {"id": "R2", "name": "high", "position": 3, "color": 16711680}]),
                ("GET", "/guilds/G/members/U1") => json!({"user": {"id": "U1", "username": "amy", "global_name": "Amy", "avatar": "av"}, "nick": "a", "roles": ["R1"], "joined_at": "2020"}),
                ("GET", q) if q.starts_with("/guilds/G/members/search") => json!([{"user": {"id": "U1", "username": "amy"}, "roles": []}]),
                ("GET", q) if q.starts_with("/channels/C1/messages") => json!([{"id": "9", "content": "hi", "author": {"id": "U1", "username": "amy"}, "attachments": [{"filename": "a.png", "url": "u", "size": 3}], "reactions": [{"emoji": {"name": "👍"}, "count": 2}]}]),
                ("GET", "/channels/C1/pins") => json!([{"id": "9", "content": "x".repeat(300), "author": {"username": "amy"}}]),
                ("PUT", "/channels/C9/pins/9") => return (403, vec![], json!({"message": "Missing Permissions", "code": 50013}).to_string()),
                ("POST", q) if q.ends_with("/threads") => json!({"id": "T1", "name": "plan"}),
                (_, _) => return (204, vec![], String::new()),
            };
            (200, vec![], v.to_string())
        })
    }

    #[test]
    fn core_tool_actions_and_schema() {
        let srv = api();
        // Configured GUILD_MEMBERS + MESSAGE_CONTENT: no app lookup, every action visible.
        let d = channel(&srv, "discord", DEFAULT_INTENTS | GUILD_MEMBERS_INTENT, None);
        let tools = d.tools();
        let t = find(&tools, "discord");
        assert_eq!(enum_of(&t), ["search_members", "fetch_messages", "create_thread"]);
        assert!(t.spec().description.contains("  fetch_messages(channel_id)  — recent messages") && !t.spec().description.contains("NOTE"));
        let (e, v) = run(&t, json!({"action": "fetch_messages", "channel_id": "C1", "limit": 500, "before": "100"}));
        assert!(!e);
        assert_eq!((v["count"].as_u64(), v["messages"][0]["reactions"][0]["emoji"].as_str(), v["messages"][0]["attachments"][0]["size"].as_u64()), (Some(1), Some("👍"), Some(3)));
        assert_eq!(v["messages"][0]["author"]["bot"], false);
        let (_, v) = run(&t, json!({"action": "search_members", "guild_id": "G", "query": "am"}));
        assert_eq!(v["members"][0]["user_id"], "U1");
        assert!(v["members"][0].get("avatar").is_none());
        let (_, v) = run(&t, json!({"action": "create_thread", "channel_id": "C1", "name": "plan"}));
        assert_eq!(v, json!({"success": true, "thread_id": "T1", "name": "plan"}));
        let (_, v) = run(&t, json!({"action": "create_thread", "channel_id": "C1", "name": "plan", "message_id": "9", "auto_archive_duration": 60}));
        assert_eq!(v["thread_id"], "T1");
        let reqs = srv.requests();
        let paths: Vec<&str> = reqs.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(paths, ["/channels/C1/messages?limit=100&before=100", "/guilds/G/members/search?query=am&limit=50", "/channels/C1/threads", "/channels/C1/messages/9/threads"]);
        assert_eq!(reqs[2].json(), json!({"name": "plan", "auto_archive_duration": 1440, "type": 11}));
        assert_eq!(reqs[3].json(), json!({"name": "plan", "auto_archive_duration": 60}));
        // Validation and dispatch errors.
        let (e, v) = run(&t, json!({"action": "pin_message"}));
        assert!(e && v["error"] == "Unknown action: pin_message" && v["available_actions"].as_array().unwrap().len() == 3);
        let (e, v) = run(&t, json!({"action": "search_members", "guild_id": "G"}));
        assert!(e && v["error"] == "Missing required parameters for 'search_members': query");
        let eff = t.effects(&ctx(), &json!({"action": "create_thread", "channel_id": "C1", "name": "plan"}));
        assert_eq!(eff, vec![Effect::Net { dest: srv.url.clone(), payload: "discord create_thread channel_id=C1 name=plan".into() }]);
    }

    #[test]
    fn admin_tool_actions_and_403_guidance() {
        let srv = api();
        let d = channel(&srv, "dc", DEFAULT_INTENTS | GUILD_MEMBERS_INTENT, None);
        let tools = d.tools();
        assert!(tools.iter().any(|t| t.spec().name == "discord_dc"));
        let t = find(&tools, "discord_admin_dc");
        assert_eq!(enum_of(&t).len(), 12);
        let (_, v) = run(&t, json!({"action": "list_guilds"}));
        assert_eq!((v["count"].as_u64(), v["guilds"][0]["owner"].as_bool()), (Some(1), Some(true)));
        let (_, v) = run(&t, json!({"action": "server_info", "guild_id": "G"}));
        assert_eq!((v["member_count"].as_u64(), v["online_count"].as_u64(), v["features"].clone()), (Some(5), Some(2), json!([])));
        let (_, v) = run(&t, json!({"action": "list_channels", "guild_id": "G"}));
        assert_eq!(v["total_channels"], 4);
        let groups = v["channel_groups"].as_array().unwrap();
        assert_eq!(groups[0]["category"], Value::Null);
        assert_eq!(groups[0]["channels"].as_array().unwrap().iter().map(|c| c["id"].as_str().unwrap()).collect::<Vec<_>>(), ["C3", "C4"]);
        assert_eq!((groups[1]["category"]["name"].as_str(), groups[1]["channels"].as_array().unwrap().len()), (Some("Empty"), 0));
        assert_eq!(groups[2]["channels"].as_array().unwrap().iter().map(|c| c["id"].as_str().unwrap()).collect::<Vec<_>>(), ["C1", "C2"]);
        assert_eq!(groups[0]["channels"][0]["type"], "voice");
        let (_, v) = run(&t, json!({"action": "channel_info", "channel_id": "C1"}));
        assert_eq!((v["type"].as_str(), v["rate_limit_per_user"].as_u64()), (Some("forum"), Some(0)));
        let (_, v) = run(&t, json!({"action": "list_roles", "guild_id": "G"}));
        assert_eq!((v["roles"][0]["name"].as_str(), v["roles"][0]["color"].as_str(), v["roles"][1]["color"].clone()), (Some("high"), Some("#ff0000"), Value::Null));
        let (_, v) = run(&t, json!({"action": "member_info", "guild_id": "G", "user_id": "U1"}));
        assert_eq!((v["display_name"].as_str(), v["avatar"].as_str(), v["joined_at"].as_str()), (Some("Amy"), Some("av"), Some("2020")));
        let (_, v) = run(&t, json!({"action": "list_pins", "channel_id": "C1"}));
        assert_eq!(v["pinned_messages"][0]["content"].as_str().unwrap().len(), 200);
        let start = srv.requests().len();
        for (input, msg) in [
            (json!({"action": "pin_message", "channel_id": "C1", "message_id": "9"}), "Message 9 pinned."),
            (json!({"action": "unpin_message", "channel_id": "C1", "message_id": "9"}), "Message 9 unpinned."),
            (json!({"action": "delete_message", "channel_id": "C1", "message_id": "9"}), "Message 9 deleted."),
            (json!({"action": "add_role", "guild_id": "G", "user_id": "U1", "role_id": "R1"}), "Role R1 added to user U1."),
            (json!({"action": "remove_role", "guild_id": "G", "user_id": "U1", "role_id": "R1"}), "Role R1 removed from user U1."),
        ] {
            assert_eq!(run(&t, input), (false, json!({"success": true, "message": msg})));
        }
        let got: Vec<(String, String)> = srv.requests()[start..].iter().map(|r| (r.method.clone(), r.path.clone())).collect();
        let want = [("PUT", "/channels/C1/pins/9"), ("DELETE", "/channels/C1/pins/9"), ("DELETE", "/channels/C1/messages/9"), ("PUT", "/guilds/G/members/U1/roles/R1"), ("DELETE", "/guilds/G/members/U1/roles/R1")];
        assert_eq!(got, want.map(|(a, b)| (a.to_string(), b.to_string())));
        assert_eq!(srv.requests()[start].header("authorization"), Some("Bot TOKEN"));
        let (e, v) = run(&t, json!({"action": "pin_message", "channel_id": "C9", "message_id": "9"}));
        let msg = v["error"].as_str().unwrap();
        assert!(e && msg.starts_with("Discord API 403 (forbidden) on 'pin_message'. Bot lacks MANAGE_MESSAGES") && msg.contains("Missing Permissions"), "{msg}");
    }

    #[test]
    fn intents_from_app_flags_and_allowlist() {
        let srv = api();
        // No GUILD_MEMBERS / MESSAGE_CONTENT configured: the app flags decide (fake: content only).
        let d = channel(&srv, "discord", DEFAULT_INTENTS & !MESSAGE_CONTENT_INTENT, None);
        let tools = d.tools();
        let core = find(&tools, "discord");
        // Permissive until the lookup lands.
        wait_until(|| enum_of(&core).len() == 2);
        assert_eq!(enum_of(&core), ["fetch_messages", "create_thread"]);
        assert!(!enum_of(&find(&tools, "discord_admin")).contains(&"member_info".to_string()));
        assert!(srv.requests().iter().any(|r| r.path == "/applications/@me"));
        assert!(!core.spec().description.contains("NOTE"));
        // An app without MESSAGE_CONTENT gets the note on fetch_messages / list_pins.
        let srv2 = FakeServer::start(|_, _| (200, vec![], json!({"flags": 1 << 14}).to_string()));
        let d2 = channel(&srv2, "discord", DEFAULT_INTENTS & !MESSAGE_CONTENT_INTENT, Some(vec!["fetch_messages", "list_pins", "bogus"]));
        let tools2 = d2.tools();
        let admin = find(&tools2, "discord_admin");
        wait_until(|| admin.spec().description.contains("NOTE"));
        assert!(admin.spec().description.contains("NOTE: Bot does NOT have the MESSAGE_CONTENT privileged intent. list_pins will return"));
        assert_eq!(enum_of(&admin), ["list_pins"]);
        assert!(find(&tools2, "discord").spec().description.contains("fetch_messages will return"));
        let (e, v) = run(&admin, json!({"action": "list_guilds"}));
        assert!(e && v["error"] == "Action 'list_guilds' is disabled by config (channels.discord.server_actions). Allowed: fetch_messages, list_pins");
        // An allowlist that leaves the core tool nothing drops it.
        let d3 = channel(&srv, "discord", DEFAULT_INTENTS | GUILD_MEMBERS_INTENT, Some(vec!["list_guilds"]));
        let names: Vec<String> = d3.tools().iter().map(|t| t.spec().name).collect();
        assert_eq!(names, ["discord_admin"]);
        // A failed lookup stays permissive.
        let srv4 = FakeServer::start(|_, _| (401, vec![], json!({"message": "401: Unauthorized", "code": 0}).to_string()));
        let d4 = channel(&srv4, "discord", DEFAULT_INTENTS, None);
        let tools4 = d4.tools();
        wait_until(|| !srv4.requests().is_empty());
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(enum_of(&find(&tools4, "discord")).len(), 3);
    }
}
