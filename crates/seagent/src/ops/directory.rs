//! `seagent directory` (OpenClaw `openclaw directory`): look up contact and group ids for
//! configured chat channels, to paste into allow lists, `default_chat`, cron targets…
//!
//! `self`, `peers list [--query Q] [--limit N]`, `groups list [--query Q] [--limit N]`,
//! `groups members --group-id ID [--limit N]`, each with `--channel NAME` (automatic
//! when one channel is configured) and `--json`.
//!
//! Sources: Slack (`auth.test`, `users.list`, `conversations.list`,
//! `conversations.members`) and Discord (`/users/@me`, guilds → text channels,
//! guild members) are queried live with the channel's bot token; Telegram's Bot API
//! has no directory, so `self` uses `getMe` and peers/groups come from the channel's
//! `allow` / `groups` lists (as upstream). Other kinds list their configured ids.

use crate::args::Args;
use crate::ops::net;
use crate::R;
use seagent_kernel::config::Config;
use serde_json::{json, Value};
use std::time::Duration;

pub const COMMANDS: &[&str] = &["directory"];
pub const VALUE_FLAGS: &[&str] = &["channel", "query", "group-id", "account"];
pub const BOOL_FLAGS: &[&str] = &[];

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Entry {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
}

fn e(id: impl Into<String>, name: Option<String>, handle: Option<String>) -> Entry {
    Entry { id: id.into(), name: name.filter(|n| !n.is_empty()), handle }
}

pub struct Chan {
    pub name: String,
    pub kind: String,
    pub cfg: seagent_channel::config::ChannelConfig,
    pub token: Option<String>,
}

fn setting(c: &seagent_channel::config::ChannelConfig, k: &str) -> Option<String> {
    c.settings.get(k).and_then(|v| v.as_str()).map(String::from)
}

impl Chan {
    fn base(&self) -> String {
        let (k, d) = match self.kind.as_str() {
            "telegram" => ("base_url", "https://api.telegram.org"),
            "discord" => ("api_base", "https://discord.com/api/v10"),
            _ => ("api_base", "https://slack.com/api"),
        };
        setting(&self.cfg, k).unwrap_or_else(|| d.into()).trim_end_matches('/').to_string()
    }
    fn token(&self) -> Result<&str, String> {
        self.token.as_deref().filter(|t| !t.is_empty() && !t.contains("{{secret:")).ok_or_else(|| format!("channel {}: bot token is not available (check the vault / secrets)", self.name))
    }
    fn get(&self, url: &str, auth: &[(&str, String)]) -> Result<Value, String> {
        let (s, b) = net::request("GET", url, auth, None, 8 << 20, Duration::from_secs(20))?;
        let v: Value = serde_json::from_slice(&b).map_err(|_| format!("{}: HTTP {s}: invalid JSON", self.kind))?;
        if !(200..300).contains(&s) {
            return Err(format!("{} API HTTP {s}: {}", self.kind, v["message"].as_str().or(v["description"].as_str()).unwrap_or("error")));
        }
        Ok(v)
    }
    fn slack(&self, method: &str, params: &str) -> Result<Value, String> {
        let v = self.get(&format!("{}/{method}?{params}", self.base()), &[("authorization", format!("Bearer {}", self.token()?))])?;
        if v["ok"] != true {
            return Err(format!("slack {method}: {}", v["error"].as_str().unwrap_or("error")));
        }
        Ok(v)
    }
    fn discord(&self, path: &str) -> Result<Value, String> {
        self.get(&format!("{}{path}", self.base()), &[("authorization", format!("Bot {}", self.token()?))])
    }
}

/// Resolve `--channel` (auto when exactly one channel is configured).
pub fn resolve(cfg: &Config, want: Option<&str>, subst: &dyn Fn(&str) -> String) -> Result<Chan, String> {
    let name = match want {
        Some(w) => w.to_string(),
        None => match cfg.channels.keys().collect::<Vec<_>>().as_slice() {
            [one] => one.to_string(),
            [] => return Err("no channels are configured".into()),
            many => return Err(format!("several channels are configured ({}); pass --channel", many.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "))),
        },
    };
    let t = cfg.channels.get(&name).ok_or_else(|| format!("unknown channel `{name}` (configured: {})", cfg.channels.keys().cloned().collect::<Vec<_>>().join(", ")))?;
    let v = serde_json::to_value(t).map_err(|e| e.to_string())?;
    let c = seagent_channel::config::parse_config(&name, &v)?;
    let token = setting(&c, "token").or_else(|| setting(&c, "bot_token")).map(|t| subst(&t));
    Ok(Chan { name, kind: c.kind.clone(), cfg: c, token })
}

fn filter(mut v: Vec<Entry>, q: Option<&str>, limit: Option<usize>) -> Vec<Entry> {
    if let Some(q) = q.map(|q| q.to_lowercase()).filter(|q| !q.is_empty()) {
        v.retain(|e| e.id.to_lowercase().contains(&q) || e.name.as_deref().is_some_and(|n| n.to_lowercase().contains(&q)) || e.handle.as_deref().is_some_and(|h| h.to_lowercase().contains(&q)));
    }
    v.sort_by(|a, b| a.name.clone().unwrap_or_default().to_lowercase().cmp(&b.name.clone().unwrap_or_default().to_lowercase()).then(a.id.cmp(&b.id)));
    v.dedup_by(|a, b| a.id == b.id);
    if let Some(n) = limit {
        v.truncate(n);
    }
    v
}

fn tg_norm(s: &str) -> Option<String> {
    let t = s.trim().trim_start_matches("telegram:").trim_start_matches("tg:").trim();
    if t.is_empty() || t == "*" {
        return None;
    }
    let num = t.strip_prefix('-').unwrap_or(t).bytes().all(|b| b.is_ascii_digit());
    Some(if num || t.starts_with('@') { t.to_string() } else { format!("@{t}") })
}

fn from_config(c: &Chan, groups: bool) -> Vec<Entry> {
    let list = if groups { &c.cfg.policy.groups } else { &c.cfg.policy.allow };
    let mut ids: Vec<String> = list.iter().filter_map(|s| if c.kind == "telegram" && !groups { tg_norm(s) } else { Some(s.trim().to_string()).filter(|s| !s.is_empty() && s != "*") }).collect();
    if let Some(d) = c.cfg.default_chat() {
        let is_group = d.starts_with('-') || d.starts_with('C') || d.starts_with('G');
        if is_group == groups && !ids.iter().any(|i| i == d) {
            ids.push(d.to_string());
        }
    }
    ids.into_iter().map(|i| e(i, None, None)).collect()
}

pub fn self_entry(c: &Chan) -> Result<Entry, String> {
    match c.kind.as_str() {
        "telegram" => {
            let v = c.get(&format!("{}/bot{}/getMe", c.base(), c.token()?), &[])?;
            let r = &v["result"];
            Ok(e(r["id"].to_string(), r["first_name"].as_str().map(String::from), r["username"].as_str().map(|u| format!("@{u}"))))
        }
        "discord" => {
            let v = c.discord("/users/@me")?;
            Ok(e(v["id"].as_str().unwrap_or(""), v["global_name"].as_str().or(v["username"].as_str()).map(String::from), v["username"].as_str().map(|u| format!("@{u}"))))
        }
        "slack" => {
            let v = c.slack("auth.test", "")?;
            Ok(e(v["user_id"].as_str().unwrap_or(""), v["user"].as_str().map(String::from), v["team"].as_str().map(|t| format!("team {t}"))))
        }
        k => Err(format!("directory self is not supported for {k} channels")),
    }
}

fn slack_pages(c: &Chan, method: &str, params: &str, key: &str, max: usize) -> Result<Vec<Value>, String> {
    let mut out = vec![];
    let mut cursor = String::new();
    loop {
        let v = c.slack(method, &format!("{params}&limit=200{}", if cursor.is_empty() { String::new() } else { format!("&cursor={cursor}") }))?;
        out.extend(v[key].as_array().cloned().unwrap_or_default());
        cursor = v["response_metadata"]["next_cursor"].as_str().unwrap_or("").to_string();
        if cursor.is_empty() || out.len() >= max {
            return Ok(out);
        }
    }
}

pub fn peers(c: &Chan) -> Result<Vec<Entry>, String> {
    match c.kind.as_str() {
        "slack" => Ok(slack_pages(c, "users.list", "", "members", 5000)?
            .into_iter()
            .filter(|m| m["deleted"] != true && m["is_bot"] != true && m["id"] != "USLACKBOT")
            .map(|m| {
                let p = &m["profile"];
                let name = [p["display_name"].as_str(), p["real_name"].as_str(), m["real_name"].as_str(), m["name"].as_str()].into_iter().flatten().find(|s| !s.is_empty()).map(String::from);
                e(m["id"].as_str().unwrap_or(""), name, m["name"].as_str().map(|n| format!("@{n}")))
            })
            .collect()),
        "discord" => {
            let mut v = from_config(c, false);
            for g in c.discord("/users/@me/guilds")?.as_array().cloned().unwrap_or_default() {
                if let Ok(ms) = c.discord(&format!("/guilds/{}/members?limit=1000", g["id"].as_str().unwrap_or(""))) {
                    for m in ms.as_array().into_iter().flatten().filter(|m| m["user"]["bot"] != true) {
                        let u = &m["user"];
                        v.push(e(u["id"].as_str().unwrap_or(""), m["nick"].as_str().or(u["global_name"].as_str()).or(u["username"].as_str()).map(String::from), u["username"].as_str().map(|n| format!("@{n}"))));
                    }
                }
            }
            Ok(v)
        }
        _ => Ok(from_config(c, false)),
    }
}

pub fn groups(c: &Chan) -> Result<Vec<Entry>, String> {
    match c.kind.as_str() {
        "slack" => Ok(slack_pages(c, "conversations.list", "types=public_channel,private_channel&exclude_archived=true", "channels", 5000)?
            .into_iter()
            .filter_map(|ch| {
                let name = ch["name"].as_str()?.trim().to_string();
                Some(e(ch["id"].as_str()?, Some(name.clone()), Some(format!("#{name}"))))
            })
            .collect()),
        "discord" => {
            let mut v = vec![];
            for g in c.discord("/users/@me/guilds")?.as_array().cloned().unwrap_or_default() {
                let gname = g["name"].as_str().unwrap_or("").to_string();
                for ch in c.discord(&format!("/guilds/{}/channels", g["id"].as_str().unwrap_or("")))?.as_array().into_iter().flatten().filter(|ch| matches!(ch["type"].as_u64(), Some(0 | 5 | 15))) {
                    let n = ch["name"].as_str().unwrap_or("");
                    v.push(e(ch["id"].as_str().unwrap_or(""), Some(format!("{gname} #{n}")), Some(format!("#{n}"))));
                }
            }
            Ok(v)
        }
        _ => Ok(from_config(c, true)),
    }
}

pub fn members(c: &Chan, group: &str) -> Result<Vec<Entry>, String> {
    match c.kind.as_str() {
        "slack" => {
            let ids = slack_pages(c, "conversations.members", &format!("channel={group}"), "members", 5000)?;
            let names: std::collections::HashMap<String, Entry> = peers(c).unwrap_or_default().into_iter().map(|p| (p.id.clone(), p)).collect();
            Ok(ids.iter().filter_map(|i| i.as_str()).map(|i| names.get(i).cloned().unwrap_or_else(|| e(i, None, None))).collect())
        }
        "discord" => {
            // Discord members are per guild: accept a guild id or a channel id.
            let gid = match c.discord(&format!("/channels/{group}")) {
                Ok(ch) if ch["guild_id"].is_string() => ch["guild_id"].as_str().unwrap().to_string(),
                _ => group.to_string(),
            };
            Ok(c.discord(&format!("/guilds/{gid}/members?limit=1000"))?.as_array().into_iter().flatten().map(|m| e(m["user"]["id"].as_str().unwrap_or(""), m["nick"].as_str().or(m["user"]["global_name"].as_str()).or(m["user"]["username"].as_str()).map(String::from), m["user"]["username"].as_str().map(|n| format!("@{n}")))).collect())
        }
        k => Err(format!("group members listing is not supported for {k} channels")),
    }
}

pub fn table(title: &str, empty: &str, v: &[Entry]) -> String {
    if v.is_empty() {
        return empty.into();
    }
    let w = v.iter().map(|e| e.id.chars().count()).max().unwrap_or(2).max(16);
    let mut o = format!("{title} ({})\n{:<w$}  NAME\n", v.len(), "ID");
    for x in v {
        let id: String = x.id.chars().filter(|c| !c.is_control()).collect();
        let name: String = x.name.as_deref().or(x.handle.as_deref()).unwrap_or("").chars().filter(|c| !c.is_control()).collect();
        o.push_str(&format!("{id:<w$}  {name}\n"));
    }
    o.trim_end().to_string()
}

pub fn run(cfg: &Config, a: &Args, subst: &dyn Fn(&str) -> String) -> Result<String, String> {
    let c = resolve(cfg, a.val("channel"), subst)?;
    let js = a.flag("json");
    let limit = a.num::<usize>("limit")?;
    let q = a.val("query");
    let scope = format!("channel \"{}\" ({})", c.name, c.kind);
    let (title, empty, v) = match (a.pos(0).unwrap_or(""), a.pos(1).unwrap_or("list")) {
        ("self", _) => {
            let s = self_entry(&c)?;
            return Ok(if js { serde_json::to_string_pretty(&s).unwrap_or_default() } else { table("Self", "No self info", &[s]) });
        }
        ("peers", "list") => ("Peers", "No peers found", filter(peers(&c)?, q, limit)),
        ("groups", "list") => ("Groups", "No groups found", filter(groups(&c)?, q, limit)),
        ("groups", "members") => {
            let g = a.val("group-id").ok_or("--group-id <id> is required")?;
            ("Group Members", "No group members found", filter(members(&c, g)?, None, limit))
        }
        _ => return Err("usage: seagent directory self | peers list | groups list | groups members --group-id ID  [--channel NAME] [--query Q] [--limit N] [--json]".into()),
    };
    Ok(if js { serde_json::to_string_pretty(&json!({"channel": c.name, "entries": v})).unwrap_or_default() } else { format!("{}\n{}", scope, table(title, empty, &v)) })
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if cmd != "directory" {
        return None;
    }
    Some((|| -> R {
        let paths = seagent_kernel::config::Paths::from_env();
        let ws = crate::workspace(a)?;
        let cfg = crate::load_config(a, &ws, &paths)?;
        let vault = crate::load_vault(&paths)?;
        println!("{}", run(&cfg, a, &|s: &str| vault.substitute(s))?);
        Ok(0)
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::net::fake;
    use std::sync::Arc;

    fn args(v: &[&str]) -> Args {
        Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn slack_discord_live_and_telegram_config() {
        let (base, log) = fake::serve(Arc::new(|r: &fake::Req| {
            let j = |v: Value| (200, "application/json".to_string(), v.to_string().into_bytes());
            let p = r.path.as_str();
            if p.starts_with("/slack/auth.test") {
                j(json!({"ok": true, "user_id": "UBOT", "user": "seagentbot", "team": "T"}))
            } else if p.starts_with("/slack/users.list") && !p.contains("cursor=") {
                j(json!({"ok": true, "members": [{"id": "U1", "name": "alice", "profile": {"display_name": "Alice A"}}, {"id": "U2", "name": "bot", "is_bot": true}], "response_metadata": {"next_cursor": "c2"}}))
            } else if p.starts_with("/slack/users.list") {
                j(json!({"ok": true, "members": [{"id": "U3", "name": "bob", "real_name": "Bob B", "profile": {}}, {"id": "U4", "name": "gone", "deleted": true}]}))
            } else if p.starts_with("/slack/conversations.list") {
                j(json!({"ok": true, "channels": [{"id": "C1", "name": "general"}, {"id": "C2", "name": "ops"}]}))
            } else if p.starts_with("/slack/conversations.members") {
                j(json!({"ok": true, "members": ["U1", "U9"]}))
            } else if p == "/discord/users/@me" {
                j(json!({"id": "D0", "username": "seagentd"}))
            } else if p == "/discord/users/@me/guilds" {
                j(json!([{"id": "G1", "name": "Home"}]))
            } else if p == "/discord/guilds/G1/channels" {
                j(json!([{"id": "CH1", "name": "chat", "type": 0}, {"id": "V1", "name": "voice", "type": 2}]))
            } else if p.starts_with("/discord/guilds/G1/members") {
                j(json!([{"user": {"id": "M1", "username": "zed"}, "nick": "Zed"}, {"user": {"id": "B", "username": "b", "bot": true}}]))
            } else if p == "/discord/channels/CH1" {
                j(json!({"id": "CH1", "guild_id": "G1"}))
            } else if p.ends_with("/getMe") {
                j(json!({"ok": true, "result": {"id": 42, "first_name": "SE Agent", "username": "seagent_bot"}}))
            } else {
                (404, "application/json".into(), b"{}".to_vec())
            }
        }));
        let mut cfg = Config::default();
        let t = |s: String| -> toml::Table { s.parse().unwrap() };
        cfg.channels.insert("work".into(), t(format!("kind = \"slack\"\nbot_token = \"{{{{secret:SLACK}}}}\"\napi_base = \"{base}/slack\"\n")));
        cfg.channels.insert("dc".into(), t(format!("kind = \"discord\"\ntoken = \"tok\"\napi_base = \"{base}/discord\"\n")));
        cfg.channels.insert("phone".into(), t(format!("kind = \"telegram\"\ntoken = \"tg\"\nbase_url = \"{base}\"\nallow = [\"alice\", \"123\", \"*\"]\ngroups = [\"-100200\"]\n")));
        let subst = |s: &str| s.replace("{{secret:SLACK}}", "xoxb-1");
        let r = |v: &[&str]| run(&cfg, &args(v), &subst);
        assert!(r(&["self"]).unwrap_err().contains("pass --channel"));
        assert!(r(&["self", "--channel", "work"]).unwrap().contains("UBOT"));
        let p = r(&["peers", "list", "--channel", "work"]).unwrap();
        assert!(p.contains("Peers (2)") && p.contains("Alice A") && p.contains("Bob B") && !p.contains("U2") && !p.contains("U4"), "{p}");
        assert!(r(&["peers", "list", "--channel", "work", "--query", "bob"]).unwrap().contains("Peers (1)"));
        assert!(r(&["groups", "list", "--channel", "work", "--limit", "1"]).unwrap().contains("Groups (1)"));
        let m = r(&["groups", "members", "--channel", "work", "--group-id", "C1", "--json"]).unwrap();
        assert!(m.contains("\"U9\"") && m.contains("Alice A"));
        assert!(log.lock().unwrap().iter().any(|q| q.headers.iter().any(|(k, v)| k == "authorization" && v == "Bearer xoxb-1")));
        assert!(r(&["self", "--channel", "dc"]).unwrap().contains("D0"));
        let g = r(&["groups", "list", "--channel", "dc"]).unwrap();
        assert!(g.contains("Home #chat") && !g.contains("voice"));
        assert!(r(&["groups", "members", "--channel", "dc", "--group-id", "CH1"]).unwrap().contains("Zed"));
        assert!(r(&["self", "--channel", "phone"]).unwrap().contains("@seagent_bot") || r(&["self", "--channel", "phone"]).unwrap().contains("SE Agent"));
        let tp = r(&["peers", "list", "--channel", "phone"]).unwrap();
        assert!(tp.contains("@alice") && tp.contains("123") && !tp.contains('*'), "{tp}");
        assert!(r(&["groups", "list", "--channel", "phone"]).unwrap().contains("-100200"));
        assert!(r(&["groups", "members", "--channel", "phone", "--group-id", "x"]).unwrap_err().contains("not supported"));
        assert!(r(&["bogus", "--channel", "phone"]).is_err());
    }
}
