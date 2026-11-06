//! `/handoff <channel>[:<chat>]` (Hermes `hermes_cli/commands.py`, `_handle_handoff_command`):
//! move a CLI/TUI conversation into a chat channel and keep it there. The target chat is
//! bound to this session in the daemon's router (so replies continue the same conversation)
//! and a short handoff message is posted. A CLI process has no channel hub of its own, so
//! it asks the running daemon through the `session.handoff` host method.

use super::sid;
use crate::slash::{Ctx, Reply};
use seagent_channel::{Channel, Outbound};
use seagent_kernel::event::EventKind;
use seagent_kernel::kernel::Kernel;
use seagent_kernel::projection::project;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Channel name → (channel, `default_chat`).
pub type Channels = BTreeMap<String, (Arc<dyn Channel>, Option<String>)>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub channel: String,
    pub chat: String,
}

pub fn channels(ext: &crate::ext::Ext) -> Channels {
    ext.channels.iter().map(|(n, (ch, cfg))| (n.clone(), (ch.clone(), cfg.default_chat().map(String::from)))).collect()
}

fn usage(channels: &Channels) -> String {
    let names: Vec<&str> = channels.keys().map(String::as_str).collect();
    if names.is_empty() {
        "no channels are configured; add [channels.<name>] and start seagentd".into()
    } else {
        format!("usage: /handoff <channel>[:<chat>] (configured: {})", names.join(", "))
    }
}

/// Parse `/handoff telegram`, `/handoff telegram:123`, or `/handoff telegram 123`.
/// The chat defaults to the channel's `default_chat`; without one it must be given.
pub fn resolve(arg: &str, channels: &Channels) -> Result<Target, String> {
    let arg = arg.trim();
    if arg.is_empty() || arg.eq_ignore_ascii_case("list") {
        return Err(usage(channels));
    }
    let mut parts = arg.split_whitespace();
    let first = parts.next().unwrap_or("");
    let (name, mut chat) = match first.split_once(':') {
        Some((n, c)) => (n, c.to_string()),
        None => (first, String::new()),
    };
    let rest = parts.collect::<Vec<_>>().join(" ");
    if !rest.is_empty() {
        if !chat.is_empty() {
            return Err(format!("usage: /handoff {name}[:<chat>] — give the chat id once"));
        }
        chat = rest;
    }
    let Some((_, default)) = channels.get(name) else { return Err(format!("unknown channel `{name}`. {}", usage(channels))) };
    if chat.is_empty() {
        chat = default.clone().unwrap_or_default();
    }
    if chat.trim().is_empty() {
        return Err(format!("channel `{name}` has no default_chat; use /handoff {name}:<chat id>"));
    }
    if chat.contains('\u{1f}') {
        return Err("chat id contains a reserved separator".into());
    }
    Ok(Target { channel: name.to_string(), chat })
}

/// Bind `target` to `session` and post the handoff notice. The router must be the daemon's
/// (the one its channel loops use), otherwise replies in the chat would not find the session.
pub fn perform(k: &Kernel, channels: &Channels, router: Option<&seagent_channel::router::Router>, session: &str, target: &Target) -> Result<String, String> {
    let Some((ch, _)) = channels.get(&target.channel) else { return Err(format!("unknown channel `{}`", target.channel)) };
    let Some(router) = router else {
        return Err("the channel hub is not running — start seagentd, then retry /handoff".into());
    };
    let events = k.store.read(session).map_err(|e| e.to_string())?;
    let v = project(&events);
    let title = v.title.clone().filter(|t| !t.trim().is_empty()).unwrap_or_else(|| format!("session {}", &session[..session.len().min(8)]));
    router.bind(&seagent_channel::router::RouteKey::chat(&target.channel, &target.chat), session);
    let text = format!("🔗 Session handoff · {title}\n\n`{session}` now continues in this chat. Reply here to keep going.");
    let out = Outbound { chat: target.chat.clone(), text: text.clone(), format: seagent_channel::TextFormat::Markdown, ..Default::default() };
    ch.send(&out).map_err(|e| format!("{}: {}", target.channel, e.message))?;
    let _ = k.record(session, EventKind::Notice { level: "info".into(), text: format!("handed off to {}:{}", target.channel, target.chat) });
    Ok(format!("handed off to {}:{} — replies there continue this session (`{session}`)", target.channel, target.chat))
}

/// `/handoff`: run in the daemon when the local process is the hub, otherwise ask the daemon.
pub fn cmd_handoff(c: &Ctx, a: &str) -> Result<Reply, String> {
    if c.sender.is_some() {
        return Err("/handoff starts from the CLI or TUI, not from inside a chat".into());
    }
    let id = sid(c)?.to_string();
    if c.k.is_running(&id) {
        return Err("a turn is still running — stop it before handing the session off".into());
    }
    let ext = c.ext.ok_or("channels are not loaded in this process; start seagentd and add [channels.<name>]")?;
    let map = channels(ext);
    let target = resolve(a, &map)?;
    let text = match super::bindings::router() {
        Some(router) => perform(c.k, &map, Some(router.as_ref()), &id, &target)?,
        None => {
            let r = seagent_kernel::daemon::call(&c.k.paths.socket(), "session.handoff", json!({"session": id, "channel": target.channel, "chat": target.chat}))?;
            r["text"].as_str().unwrap_or("handed off").to_string()
        }
    };
    Ok(Reply::text(text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::kit;
    use seagent_channel::router::{RouteKey, Router};
    use seagent_channel::Sent;
    use seagent_core::Cancel;
    use std::sync::Mutex;

    struct Rec(Arc<Mutex<Vec<Outbound>>>);
    impl Channel for Rec {
        fn id(&self) -> &str {
            "tg"
        }
        fn poll(&self, _: &Cancel) -> Result<Vec<seagent_channel::Inbound>, seagent_channel::ChannelError> {
            Ok(vec![])
        }
        fn send(&self, out: &Outbound) -> Result<Sent, seagent_channel::ChannelError> {
            self.0.lock().unwrap().push(out.clone());
            Ok(Sent::one("m1"))
        }
    }

    #[test]
    fn resolves_channel_chat_and_default() {
        let got = Arc::new(Mutex::new(vec![]));
        let mut ch: Channels = Channels::new();
        ch.insert("tg".into(), (Arc::new(Rec(got)), Some("100".into())));
        ch.insert("slack".into(), (Arc::new(Rec(Arc::default())), None));
        assert_eq!(resolve("tg", &ch), Ok(Target { channel: "tg".into(), chat: "100".into() }));
        assert_eq!(resolve("tg:200", &ch), Ok(Target { channel: "tg".into(), chat: "200".into() }));
        assert_eq!(resolve("tg 300", &ch), Ok(Target { channel: "tg".into(), chat: "300".into() }));
        assert!(resolve("", &ch).unwrap_err().contains("usage") && resolve("", &ch).unwrap_err().contains("tg"));
        assert!(resolve("nope", &ch).unwrap_err().contains("unknown channel"));
        assert!(resolve("slack", &ch).unwrap_err().contains("no default_chat"));
        assert!(resolve("slack:1\u{1f}2", &ch).is_err());
    }

    #[test]
    fn perform_binds_the_chat_and_posts_the_handoff() {
        let t = kit();
        let id = t.k.create_session(&t.ws, None, None, Some("incident 42")).unwrap();
        let got = Arc::new(Mutex::new(vec![]));
        let mut ch: Channels = Channels::new();
        ch.insert("tg".into(), (Arc::new(Rec(got.clone())), Some("100".into())));
        let router = Router::open(t.paths.data.join("routes"), Default::default());
        let target = resolve("tg", &ch).unwrap();
        let text = perform(&t.k, &ch, Some(&router), &id, &target).unwrap();
        assert!(text.contains("tg:100") && text.contains(&id), "{text}");
        assert_eq!(router.session_for(&RouteKey::chat("tg", "100")).as_deref(), Some(id.as_str()), "replies continue the session");
        let sent = got.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].text.contains("incident 42") && sent[0].text.contains(&id));
        assert_eq!(sent[0].chat, "100");
        drop(sent);
        // Without the daemon's hub nothing is bound and nothing is sent.
        let before = got.lock().unwrap().len();
        assert!(perform(&t.k, &ch, None, &id, &target).unwrap_err().contains("seagentd"));
        assert_eq!(got.lock().unwrap().len(), before);
    }
}
