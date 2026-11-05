//! `seagent message …`: the CLI face of the `message` tool.
//!
//! Ported from OpenClaw `src/cli/program/register.message.ts` + `src/cli/program/message/*`
//! (MIT): one command per action, `--channel` / `--target` routing, `--poll-question` /
//! `--poll-option` / `--poll-duration-*` for polls, `--json` for the raw result. Unlike
//! upstream it has no gateway: every action is dispatched through
//! [`seagent_channel::message_tool::dispatch`], the very same code path the model's `message` tool
//! calls, so `seagent message react …` and a tool call cannot drift apart.

use seagent_channel::message_tool::{self, Targets};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

/// Actions `seagent message` accepts (the tool's own enum is per-channel; these are the shared ones).
pub const ACTIONS: &[&str] = &["send", "edit", "delete", "react", "poll", "pin", "unpin", "thread", "read"];

const VALUE_FLAGS: &[&str] = &[
    "channel", "chat", "target", "thread", "thread-id", "text", "message", "m", "message-id", "emoji", "reply-to", "poll", "poll-question", "poll-option", "poll-duration-hours",
    "poll-duration-seconds", "question", "options", "max-selections", "limit", "before", "after", "format",
];
const BOOL_FLAGS: &[&str] = &["json", "remove", "silent", "list", "help", "poll-multi"];

pub fn usage() -> String {
    format!(
        "seagent message — send and manage messages through the `message` tool's dispatcher

USAGE
  seagent message <{}> --channel <name> --chat <id> [--thread T] [--text …] [--message-id …]
              [--poll \"question=… options=a,b\"] [--json]

FLAGS
  --channel NAME    configured channel (optional when only one is configured)
  --chat ID         chat id (defaults to the channel's default chat)
  --target T        shorthand: channel:chat[:thread]
  --thread T        thread / topic id inside the chat (also --thread-id / threadId)
  -m, --text TEXT   body for send/reply/edit (trailing words also work)
  --message-id ID   target message for read/react/edit/delete/pin/unpin
  --emoji E         react: unicode emoji
  --remove          react: remove the reaction
  --reply-to ID     send: reply to a message
  --silent          send without a notification where supported
  --poll \"question=… options=a,b [multi] [duration-hours=N|duration-seconds=N]\"
                    poll payload (unquoted words continue the previous field)
  --poll-question Q --poll-option A --poll-option B [--poll-multi]
                    [--max-selections N] [--poll-duration-hours N | --poll-duration-seconds N]
  --limit N         read: how many messages
  --before/--after  read: page from an id
  --json            print the raw JSON result

EXAMPLES
  seagent message send --channel telegram --chat 42 --text \"build finished\"
  seagent message poll --channel discord --target discord:C1 --poll \"question=Lunch? options=Pizza,Sushi\"
  seagent message react --channel slack --chat C1 --message-id 1700000000.1 --emoji 👍",
        ACTIONS.join("|")
    )
}

struct Flags {
    vals: BTreeMap<String, Vec<String>>,
    bools: Vec<String>,
    rest: Vec<String>,
}

impl Flags {
    fn last(&self, k: &str) -> Option<&str> {
        self.vals.get(k).and_then(|v| v.last()).map(String::as_str)
    }
    fn all(&self, k: &str) -> Vec<String> {
        self.vals.get(k).cloned().unwrap_or_default()
    }
    fn flag(&self, k: &str) -> bool {
        self.bools.iter().any(|b| b == k)
    }
    fn first(&self, ks: &[&str]) -> Option<&str> {
        ks.iter().find_map(|k| self.last(k))
    }
}

fn parse(argv: &[String]) -> Result<Flags, String> {
    let mut f = Flags { vals: BTreeMap::new(), bools: Vec::new(), rest: Vec::new() };
    let mut i = 0;
    let mut only_pos = false;
    while i < argv.len() {
        let r = &argv[i];
        i += 1;
        if only_pos || r == "-" || !r.starts_with('-') {
            f.rest.push(r.clone());
            continue;
        }
        if r == "--" {
            only_pos = true;
            continue;
        }
        let (name, inline) = match r.trim_start_matches('-').split_once('=') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (r.trim_start_matches('-').to_string(), None),
        };
        if VALUE_FLAGS.contains(&name.as_str()) {
            let v = match inline {
                Some(v) => v,
                None => {
                    let v = argv.get(i).cloned().ok_or_else(|| format!("--{name} needs a value"))?;
                    i += 1;
                    v
                }
            };
            f.vals.entry(name).or_default().push(v);
        } else if BOOL_FLAGS.contains(&name.as_str()) {
            if inline.is_some() {
                return Err(format!("--{name} takes no value"));
            }
            f.bools.push(name);
        } else {
            return Err(format!("unknown option `{r}`; see `seagent message --help`"));
        }
    }
    Ok(f)
}

fn list_of(v: &str) -> Value {
    json!(v.split(',').map(str::trim).filter(|s| !s.is_empty()).collect::<Vec<_>>())
}

fn int_or_str(v: &str, flag: &str) -> Result<Value, String> {
    v.trim().parse::<u64>().map(|n| json!(n)).map_err(|_| format!("--{flag} must be a positive integer, got `{v}`"))
}

fn truthy(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "" | "1" | "true" | "yes" | "on")
}

/// `question=Lunch today? options=Pizza,Sushi multi` → fields; a word without `=` continues the
/// previous field's value (so a quoted question may contain spaces).
fn poll_pairs(raw: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for tok in raw.split_whitespace() {
        let bare_flag = matches!(tok.to_ascii_lowercase().as_str(), "multi" | "multiselect" | "multiple");
        match tok.split_once('=') {
            Some((k, v)) => out.push((k.trim().to_ascii_lowercase(), v.to_string())),
            None if bare_flag => out.push((tok.to_ascii_lowercase(), String::new())),
            None => match out.last_mut() {
                Some(last) => {
                    last.1.push(' ');
                    last.1.push_str(tok);
                }
                None => out.push(("question".into(), tok.to_string())),
            },
        }
    }
    out
}

fn build_input(action: &str, f: &Flags) -> Result<Value, String> {
    let mut m = Map::new();
    m.insert("action".into(), json!(action));
    for (flag, key) in [("channel", "channel"), ("chat", "chat"), ("target", "target"), ("message-id", "messageId"), ("emoji", "emoji"), ("reply-to", "replyTo"), ("format", "format"), ("before", "before"), ("after", "after")] {
        if let Some(v) = f.last(flag) {
            m.insert(key.into(), json!(v));
        }
    }
    if let Some(t) = f.first(&["thread", "thread-id"]) {
        m.insert("threadId".into(), json!(t));
    }
    if let Some(v) = f.last("limit") {
        m.insert("limit".into(), int_or_str(v, "limit")?);
    }
    let text = f.first(&["text", "m", "message"]).map(str::to_string).or_else(|| (!f.rest.is_empty()).then(|| f.rest.join(" ")));
    if let Some(t) = text {
        m.insert("text".into(), json!(t));
    }
    for b in ["remove", "silent", "list"] {
        if f.flag(b) {
            m.insert(b.into(), json!(true));
        }
    }
    // Poll: the compact `--poll "question=… options=a,b"` form first, then the explicit flags.
    if let Some(raw) = f.last("poll") {
        for (k, v) in poll_pairs(raw) {
            match k.as_str() {
                "question" | "q" => {
                    m.insert("question".into(), json!(v.trim()));
                }
                "options" | "option" | "answers" | "choices" => {
                    m.insert("options".into(), list_of(&v));
                }
                "multi" | "multiselect" | "multiple" => {
                    m.insert("pollMulti".into(), json!(truthy(&v)));
                }
                "duration-hours" | "hours" => {
                    m.insert("durationHours".into(), int_or_str(&v, "poll duration-hours")?);
                }
                "duration-seconds" | "seconds" => {
                    m.insert("durationSeconds".into(), int_or_str(&v, "poll duration-seconds")?);
                }
                other => return Err(format!("unknown `--poll` field `{other}`; use question=…, options=a,b, multi, duration-hours=N, duration-seconds=N")),
            }
        }
    }
    if let Some(q) = f.first(&["poll-question", "question"]) {
        m.insert("question".into(), json!(q));
    }
    let opts = f.all("poll-option");
    if !opts.is_empty() {
        m.insert("options".into(), json!(opts.iter().flat_map(|o| o.split(',')).map(str::trim).filter(|s| !s.is_empty()).collect::<Vec<_>>()));
    } else if let Some(o) = f.last("options") {
        m.insert("options".into(), list_of(o));
    }
    if f.flag("poll-multi") {
        m.insert("pollMulti".into(), json!(true));
    }
    if let Some(n) = f.last("max-selections") {
        m.insert("maxSelections".into(), int_or_str(n, "max-selections")?);
    }
    if let Some(h) = f.last("poll-duration-hours") {
        m.insert("durationHours".into(), int_or_str(h, "poll-duration-hours")?);
    }
    if let Some(s) = f.last("poll-duration-seconds") {
        m.insert("durationSeconds".into(), int_or_str(s, "poll-duration-seconds")?);
    }
    Ok(Value::Object(m))
}

/// Run one `seagent message …` invocation and return what to print.
pub fn run(argv: &[String], targets: &Targets) -> Result<String, String> {
    let Some(first) = argv.first() else { return Ok(usage()) };
    if first.starts_with('-') {
        return match first.as_str() {
            "-h" | "--help" => Ok(usage()),
            other => Err(format!("expected an action ({}), got `{other}`", ACTIONS.join(", "))),
        };
    }
    let f = parse(&argv[1..])?;
    if f.flag("help") {
        return Ok(usage());
    }
    let action = first.as_str();
    if action == "help" {
        return Ok(usage());
    }
    if !ACTIONS.contains(&action) {
        return Err(format!("unknown action `{action}`; use one of: {}", ACTIONS.join(", ")));
    }
    let input = build_input(action, &f)?;
    let o = message_tool::dispatch(targets, &input)?;
    Ok(if f.flag("json") { serde_json::to_string_pretty(&o.result).unwrap_or_else(|_| o.result.to_string()) } else { o.summary })
}

/// Self-registration (`seagent_core::registry`): `seagent message …` (own flags `--channel`, `--chat`,
/// `--poll`; one dispatcher shared with the `message` tool).
pub fn register_route() {
    seagent_core::registry::register_command_route("message", None, route);
}

fn route(_cmd: &str, argv: &[String]) -> Result<i32, String> {
    let a = crate::args::Args::parse(&[])?;
    let c = crate::build_agent(&a, crate::approver_for(&a, false), false).map_err(|e| e.to_string())?;
    let channels: Targets = c.ext.as_ref().map(|e| e.channels.iter().map(|(n, (ch, cfg))| (n.clone(), (ch.clone(), cfg.default_chat().map(String::from)))).collect()).unwrap_or_default();
    println!("{}", run(argv, &channels)?);
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_channel::{Caps, Channel, ChannelError, Inbound, Outbound, Sent};
    use seagent_core::Cancel;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Fake {
        sent: Mutex<Vec<Outbound>>,
        edits: Mutex<Vec<(String, String, String)>>,
        reactions: Mutex<Vec<(String, String, String, bool)>>,
        calls: Mutex<Vec<(String, Value)>>,
    }

    impl Fake {
        fn new() -> Arc<Fake> {
            Arc::new(Fake::default())
        }
    }

    impl Channel for Fake {
        fn id(&self) -> &str {
            "fake"
        }
        fn poll(&self, _: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
            Ok(vec![])
        }
        fn caps(&self) -> Caps {
            Caps { edit: true, delete: true, reply: true, reactions: 1, ..Default::default() }
        }
        fn send(&self, out: &Outbound) -> Result<Sent, ChannelError> {
            self.sent.lock().unwrap().push(out.clone());
            Ok(Sent { ids: vec!["m1".into()] })
        }
        fn edit(&self, chat: &str, id: &str, text: &str) -> Result<(), ChannelError> {
            self.edits.lock().unwrap().push((chat.into(), id.into(), text.into()));
            Ok(())
        }
        fn react(&self, chat: &str, id: &str, emoji: &str, remove: bool) -> Result<(), ChannelError> {
            self.reactions.lock().unwrap().push((chat.into(), id.into(), emoji.into(), remove));
            Ok(())
        }
        fn message_actions(&self) -> Vec<&'static str> {
            vec!["poll", "pin", "read"]
        }
        fn message_action(&self, action: &str, args: &Value) -> Result<Value, ChannelError> {
            self.calls.lock().unwrap().push((action.into(), args.clone()));
            Ok(json!({"ok": true, "action": action, "messageId": "P1"}))
        }
    }

    fn targets(ch: Arc<Fake>) -> Targets {
        let mut t = Targets::new();
        t.insert("tg".into(), (ch as Arc<dyn Channel>, Some("42".into())));
        t
    }

    fn argv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn send_goes_through_the_shared_dispatch() {
        let ch = Fake::new();
        let out = run(&argv(&["send", "--channel", "tg", "--chat", "7", "--thread", "3", "--text", "hello"]), &targets(ch.clone())).unwrap();
        assert!(out.contains("sent 5 chars to tg/7"), "{out}");
        let sent = ch.sent.lock().unwrap().clone();
        assert_eq!((sent[0].chat.as_str(), sent[0].text.as_str(), sent[0].thread.as_deref()), ("7", "hello", Some("3")));
        // Trailing words are the body; the channel default chat applies when --chat is absent.
        let out = run(&argv(&["send", "--channel", "tg", "hello", "there"]), &targets(ch.clone())).unwrap();
        assert!(out.contains("tg/42"), "{out}");
        assert_eq!(ch.sent.lock().unwrap()[1].text, "hello there");
        // `--target channel:chat:thread` and `--reply-to`.
        run(&argv(&["send", "--target", "tg:9:4", "-m", "x", "--reply-to", "5"]), &targets(ch.clone())).unwrap();
        let sent = ch.sent.lock().unwrap().clone();
        assert_eq!((sent[2].chat.as_str(), sent[2].thread.as_deref(), sent[2].reply_to.as_deref()), ("9", Some("4"), Some("5")));
        // send without body is an error, not an empty message.
        assert!(run(&argv(&["send", "--channel", "tg"]), &targets(ch)).unwrap_err().contains("`text` is empty"));
    }

    #[test]
    fn json_mode_prints_the_result() {
        let ch = Fake::new();
        let out = run(&argv(&["send", "--channel", "tg", "--chat", "42", "--text", "hi", "--json"]), &targets(ch)).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!((v["ok"].as_bool(), v["chat"].as_str(), v["messageIds"][0].as_str()), (Some(true), Some("42"), Some("m1")));
    }

    #[test]
    fn poll_flags_build_a_normalised_poll() {
        let ch = Fake::new();
        let out = run(&argv(&["poll", "--channel", "tg", "--chat", "C", "--poll", "question=Lunch today? options=Pizza, Sushi multi duration-hours=2", "--json"]), &targets(ch.clone())).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["action"], "poll");
        let calls = ch.calls.lock().unwrap().clone();
        assert_eq!(calls[0].0, "poll");
        assert_eq!(calls[0].1["question"], "Lunch today?");
        assert_eq!(calls[0].1["options"], json!(["Pizza", "Sushi"]));
        assert_eq!((calls[0].1["maxSelections"].as_u64(), calls[0].1["durationHours"].as_u64()), (Some(2), Some(2)));
        assert_eq!(calls[0].1["target"], "C");
        // The explicit flags do the same thing.
        run(&argv(&["poll", "--channel", "tg", "--chat", "C", "--poll-question", "Snack?", "--poll-option", "Pizza", "--poll-option", "Sushi", "--poll-duration-seconds", "60"]), &targets(ch.clone())).unwrap();
        let calls = ch.calls.lock().unwrap().clone();
        assert_eq!((calls[1].1["question"].as_str(), calls[1].1["options"].as_array().unwrap().len(), calls[1].1["durationSeconds"].as_u64()), (Some("Snack?"), 2, Some(60)));
        // A one-option poll is refused before the channel is called.
        let e = run(&argv(&["poll", "--channel", "tg", "--chat", "C", "--poll-question", "q", "--poll-option", "only"]), &targets(ch.clone())).unwrap_err();
        assert!(e.contains("at least 2 options"), "{e}");
        assert_eq!(ch.calls.lock().unwrap().len(), 2);
        let e = run(&argv(&["poll", "--channel", "tg", "--chat", "C", "--poll", "bogus=1"]), &targets(ch)).unwrap_err();
        assert!(e.contains("unknown `--poll` field `bogus`"), "{e}");
    }

    #[test]
    fn edit_react_pin_and_read_map_to_the_tool_actions() {
        let ch = Fake::new();
        run(&argv(&["edit", "--channel", "tg", "--chat", "C", "--message-id", "5", "--text", "new"]), &targets(ch.clone())).unwrap();
        assert_eq!(ch.edits.lock().unwrap().clone(), vec![("C".to_string(), "5".to_string(), "new".to_string())]);
        let out = run(&argv(&["react", "--channel", "tg", "--chat", "C", "--message-id", "5", "--emoji", "👍", "--remove"]), &targets(ch.clone())).unwrap();
        assert!(out.contains("removed 👍"), "{out}");
        assert_eq!(ch.reactions.lock().unwrap().clone(), vec![("C".to_string(), "5".to_string(), "👍".to_string(), true)]);
        run(&argv(&["pin", "--channel", "tg", "--chat", "C", "--message-id", "5"]), &targets(ch.clone())).unwrap();
        run(&argv(&["read", "--channel", "tg", "--chat", "C", "--limit", "10"]), &targets(ch.clone())).unwrap();
        let calls = ch.calls.lock().unwrap().clone();
        assert_eq!((calls[0].0.as_str(), calls[0].1["messageId"].as_str()), ("pin", Some("5")));
        assert_eq!((calls[1].0.as_str(), calls[1].1["limit"].as_u64()), ("read", Some(10)));
        assert!(run(&argv(&["edit", "--channel", "tg", "--chat", "C", "--text", "x"]), &targets(ch.clone())).unwrap_err().contains("messageId required"));
        assert!(run(&argv(&["react", "--channel", "tg", "--chat", "C", "--message-id", "5"]), &targets(ch)).unwrap_err().contains("emoji required"));
    }

    #[test]
    fn the_message_tool_is_registered_next_to_channel_send() {
        // The wiring under test is `ext::load`'s tool list: `build_agent` extends the kernel's
        // tools with exactly these, which is what the model sees (`k.specs()`).
        let kit = crate::testkit::kit_with(|cfg| {
            cfg.channels.insert("phone".into(), "kind = \"telegram\"\ntoken = \"tg\"".parse::<toml::Table>().unwrap());
        });
        let (ext, tools, _hooks) = crate::ext::load(&kit.k.cfg, &kit.paths, &kit.k.vault, &kit.ws, false);
        assert!(ext.channels.contains_key("phone"), "warnings: {:?}", ext.warnings);
        let names: Vec<String> = tools.iter().map(|t| t.spec().name).collect();
        assert!(names.contains(&"channel_send".to_string()), "{names:?}");
        assert!(names.contains(&"message".to_string()), "the `message` tool is not registered: {names:?}");
        let spec = tools.iter().find(|t| t.spec().name == "message").map(|t| t.spec()).unwrap();
        assert_eq!(spec.input_schema["type"], "object");
        assert_eq!(spec.input_schema["properties"]["target"]["type"], "string");
        let enum_ = spec.input_schema["properties"]["action"]["enum"].as_array().unwrap();
        assert!(enum_.iter().any(|v| v.as_str() == Some("send")), "{enum_:?}");
        assert!(spec.description.contains("phone"), "the description names the configured channels: {}", spec.description);
    }

    #[test]
    fn errors_name_what_to_do() {
        let ch = Fake::new();
        let mut t = targets(ch.clone());
        t.insert("other".into(), (ch as Arc<dyn Channel>, None));
        assert!(run(&argv(&["send", "--text", "x"]), &t).unwrap_err().contains("several channels configured"));
        assert!(run(&argv(&["send", "--channel", "nope", "--text", "x"]), &t).unwrap_err().contains("unknown channel `nope`; configured: other, tg"));
        assert!(run(&argv(&["kick", "--channel", "tg"]), &t).unwrap_err().contains("unknown action `kick`; use one of: send"));
        // `thread` is upstream's `thread-create`; this fake does not offer it.
        let e = run(&argv(&["thread", "--channel", "tg", "--chat", "C", "--text", "t"]), &t).unwrap_err();
        assert!(e.contains("does not support action `thread-create`") && e.contains("poll, pin, read"), "{e}");
        assert!(run(&argv(&["send", "--bogus"]), &t).unwrap_err().contains("unknown option"));
        assert!(run(&argv(&["send", "--limit", "ten"]), &t).unwrap_err().contains("positive integer"));
        assert!(run(&argv(&["--help"]), &t).unwrap().contains("seagent message"));
        assert!(run(&argv(&[]), &t).unwrap().contains("USAGE"));
        assert!(run(&argv(&["send", "--help"]), &t).unwrap().contains("EXAMPLES"));
        assert!(message_tool::dispatch(&Targets::new(), &json!({"text": "x"})).unwrap_err().contains("no channels"));
    }
}
