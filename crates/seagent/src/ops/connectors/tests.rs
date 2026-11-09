//! Connections page backend against real fixtures: the stdio and Streamable HTTP MCP test
//! server (`tests/fixtures/mcp/server.py`), the channel builders, the skills hub, small local
//! HTTP peers, and the config write path the CLI shares. Every test runs in its own `kit()`
//! home; nothing reads the real `$HOME` (the importer gets an injected one).

use super::*;
use crate::ops::channels_setup;
use crate::testkit::{kit, Kit};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;

fn ctx(t: &Kit) -> ConnCtx {
    let mut c = ConnCtx::new(&t.paths, &t.ws);
    c.home = t.ws.join("home");
    c.appdata = Some(t.ws.join("appdata"));
    c
}
fn ok(c: &ConnCtx, m: &str, p: Value) -> Value {
    call(c, m, &p).unwrap_or_else(|| panic!("{m} not handled")).unwrap_or_else(|e| panic!("{m}: {e:?}"))
}
fn err(c: &ConnCtx, m: &str, p: Value) -> String {
    call(c, m, &p).unwrap_or_else(|| panic!("{m} not handled")).unwrap_err().1
}
fn chan(t: &Kit, m: &str, p: Value) -> Result<Value, (i32, String)> {
    let c = channels_setup::ctx_for(&t.paths, &t.ws);
    channels_setup::call(&c, m, &p).unwrap_or_else(|| panic!("{m} not handled"))
}
fn user_config(t: &Kit) -> String {
    std::fs::read_to_string(t.paths.user_config()).unwrap_or_default()
}

/// The MCP fixture, or `None` (the test says so and passes) when there is no Python 3.
fn fixture() -> Option<String> {
    if seagent_core::platform::layout::python3().is_none() {
        eprintln!("python3 missing: skipping the MCP fixture part");
        return None;
    }
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/mcp/server.py");
    Some(p.canonicalize().unwrap().to_string_lossy().into_owned())
}

/// A child process killed when the test ends, pass or fail.
struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// One-shot HTTP peer: answers every request with `reply`, hands each request (head + body)
/// to the test.
fn http_peer(reply: &'static str) -> (String, mpsc::Receiver<String>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = format!("http://{}", l.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut head = String::new();
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
                head.push_str(&line);
            }
            let mut body = vec![0u8; len];
            let _ = r.read_exact(&mut body);
            let _ = tx.send(format!("{head}\n{}", String::from_utf8_lossy(&body)));
            let mut s = s;
            let _ = write!(s, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}", reply.len());
        }
    });
    (addr, rx)
}

#[test]
fn resolve_program_follows_the_platform_layout() {
    let me = std::env::current_exe().unwrap();
    assert_eq!(resolve_program(&me.display().to_string()).as_deref(), Some(me.as_path()), "a full path that exists");
    assert!(resolve_program("seagent-no-such-program-4711").is_none());
    assert!(resolve_program("").is_none());
    assert!(resolve_program(&t_missing_path()).is_none(), "a full path that does not exist");
    // Whatever Python the fixture tests use resolves the way the stdio transport will start it
    // (`py -3` / python.exe on Windows, python3 elsewhere).
    if seagent_core::platform::layout::python3().is_some() {
        assert!(resolve_program("python3").is_some());
    }
    assert!(not_found("npx").contains("`npx`"));
}

fn t_missing_path() -> String {
    std::env::current_exe().unwrap().with_file_name("no-such-binary-here").display().to_string()
}

#[test]
fn stdio_server_lifecycle_through_the_console() {
    let t = kit();
    let c = ctx(&t);
    let Some(fx) = fixture() else { return };
    let spec = json!({"transport": "stdio", "command": "python3", "args": ["-I", fx], "env": [{"key": "FX_TOKEN", "value": "tok-123", "secret": true}, {"key": "REGION", "value": "eu"}], "timeout_secs": 10});
    // A draft is tested before it is saved: tools come back, nothing is written.
    let d = ok(&c, "ui.connectors.mcp.test", json!({"name": "fx", "spec": spec}));
    assert_eq!(d["ok"], true, "{d}");
    let names: Vec<&str> = d["tools"].as_array().unwrap().iter().map(|x| x["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"echo") && names.contains(&"add"), "{names:?}");
    assert!(d["tools"].as_array().unwrap().iter().any(|x| x["name"] == "echo" && x["read_only"] == true));
    assert!(!user_config(&t).contains("[mcp.fx]"), "a draft test writes nothing");
    assert!(!t.paths.data.join("mcp-pins.json").exists(), "a draft is not pinned under its name");
    // Saving a stdio server asks for consent first, with the exact argv and masked secrets.
    let r = ok(&c, "ui.connectors.mcp.save", json!({"name": "fx", "spec": spec}));
    assert_eq!(r["consent_required"], true, "{r}");
    let line = r["consent"].as_str().unwrap();
    assert!(line.contains("command=python3") && line.contains("FX_TOKEN=<masked>") && !line.contains("tok-123"), "{line}");
    assert!(!user_config(&t).contains("[mcp.fx]"), "nothing written before consent");
    let r = ok(&c, "ui.connectors.mcp.save", json!({"name": "fx", "spec": spec, "consent": true}));
    assert_eq!(r["ok"], true, "{r}");
    let text = user_config(&t);
    assert!(text.contains("[mcp.fx]") && text.contains("{{secret:MCP_FX_FX_TOKEN}}") && !text.contains("tok-123"), "{text}");
    assert_eq!(Vault::load(&t.paths.secrets()).unwrap().substitute("{{secret:MCP_FX_FX_TOKEN}}"), "tok-123", "the value went to the vault");
    // The saved server tests like `seagent mcp test fx`, and the list shows it.
    let s = ok(&c, "ui.connectors.mcp.test", json!({"name": "fx"}));
    assert_eq!(s["ok"], true, "{s}");
    let l = ok(&c, "ui.connectors.mcp.list", json!({}));
    let fx_row = l["servers"].as_array().unwrap().iter().find(|x| x["name"] == "fx").unwrap().clone();
    assert_eq!((fx_row["transport"].as_str(), fx_row["editable"].as_bool(), fx_row["enabled"].as_bool()), (Some("stdio"), Some(true), Some(true)), "{fx_row}");
    // The edit form gets references, never values; an unchanged save keeps them.
    let g = ok(&c, "ui.connectors.mcp.get", json!({"name": "fx"}));
    assert_eq!(g["env"][0]["ref"], "MCP_FX_FX_TOKEN");
    assert_eq!(g["env"][0]["set"], true);
    assert!(!g.to_string().contains("tok-123"));
    // Per-tool switch: off lands in exclude_tools, the next test reports it hidden; on again removes it.
    assert_eq!(ok(&c, "ui.connectors.mcp.tool", json!({"name": "fx", "tool": "add", "enabled": false}))["enabled"], false);
    assert!(Config::load(Some(&t.paths.user_config()), None, &[]).unwrap().mcp["fx"]["exclude_tools"].as_array().unwrap().iter().any(|x| x.as_str() == Some("add")));
    let s = ok(&c, "ui.connectors.mcp.test", json!({"name": "fx"}));
    assert!(s["tools"].as_array().unwrap().iter().any(|x| x["name"] == "add" && x["exposed"] == false), "{s}");
    assert_eq!(ok(&c, "ui.connectors.mcp.tool", json!({"name": "fx", "tool": "add", "enabled": true}))["enabled"], true);
    assert!(!user_config(&t).contains("exclude_tools"));
    // Rename keeps everything and drops the old table; remove takes it out (backups stay).
    let mut g = ok(&c, "ui.connectors.mcp.get", json!({"name": "fx"}));
    g["env"][0]["keep"] = json!(true);
    let r = ok(&c, "ui.connectors.mcp.save", json!({"name": "fx2", "original": "fx", "spec": g, "consent": true}));
    assert_eq!(r["ok"], true, "{r}");
    let text = user_config(&t);
    assert!(text.contains("[mcp.fx2]") && !text.contains("[mcp.fx]") && text.contains("{{secret:MCP_FX_FX_TOKEN}}"), "{text}");
    ok(&c, "ui.connectors.mcp.remove", json!({"name": "fx2"}));
    assert!(!user_config(&t).contains("[mcp.fx2]"));
    assert!(err(&c, "ui.connectors.mcp.remove", json!({"name": "fx2"})).contains("no [mcp.fx2]"));
    assert!(!crate::ops::confcli::backups(&t.paths).is_empty(), "every write left a backup the Config page restores");
}

#[test]
fn http_server_with_a_secret_header_and_clear_failures() {
    let t = kit();
    let c = ctx(&t);
    // A server that is not there fails at the connect stage, with the reason.
    let r = ok(&c, "ui.connectors.mcp.test", json!({"name": "nobody", "spec": {"transport": "http", "url": format!("http://127.0.0.1:{}/mcp", free_port()), "timeout_secs": 3}}));
    assert_eq!((r["ok"].as_bool(), r["stage"].as_str()), (Some(false), Some("connect")), "{r}");
    assert!(!r["error"].as_str().unwrap_or("").is_empty());
    // A program that does not exist is caught before anything is spawned.
    let r = ok(&c, "ui.connectors.mcp.test", json!({"name": "nope", "spec": {"transport": "stdio", "command": "seagent-no-such-program-4711"}}));
    assert_eq!(r["stage"], "command", "{r}");
    assert!(r["error"].as_str().unwrap().contains("not found"), "{r}");
    // Form validation errors say what is wrong.
    assert!(err(&c, "ui.connectors.mcp.save", json!({"name": "x", "spec": {"transport": "http", "url": ""}})).contains("url is required"));
    assert!(err(&c, "ui.connectors.mcp.save", json!({"name": "bad name", "spec": {}})).contains("letters, digits"));
    assert!(err(&c, "ui.connectors.mcp.save", json!({"name": "x", "spec": {"transport": "http", "url": "ftp://x"}})).contains("http"));
    let Some(fx) = fixture() else { return };
    let port = free_port();
    let child = seagent_core::platform::layout::python3_command().args(["-I", &fx, "--http", &port.to_string(), "--token", "bearer-77"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
    let _guard = Child(child);
    let url = format!("http://127.0.0.1:{port}/mcp");
    let up = Instant::now();
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() && up.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(50));
    }
    // Without the header the server refuses; with it (stored as a secret) the tools list.
    let r = ok(&c, "ui.connectors.mcp.test", json!({"name": "web", "spec": {"transport": "http", "url": url}}));
    assert_eq!(r["ok"], false, "{r}");
    let spec = json!({"transport": "http", "url": url, "headers": [{"key": "Authorization", "value": "Bearer bearer-77", "secret": true}]});
    let r = ok(&c, "ui.connectors.mcp.test", json!({"name": "web", "spec": spec}));
    assert_eq!(r["ok"], true, "{r}");
    assert!(r["tools"].as_array().unwrap().len() >= 5);
    let r = ok(&c, "ui.connectors.mcp.save", json!({"name": "web", "spec": spec}));
    assert_eq!(r["ok"], true, "HTTP servers need no stdio consent: {r}");
    let text = user_config(&t);
    assert!(text.contains("Authorization = \"{{secret:MCP_WEB_AUTHORIZATION}}\"") && !text.contains("bearer-77"), "{text}");
    assert_eq!(ok(&c, "ui.connectors.mcp.test", json!({"name": "web"}))["ok"], true);
    // Sign-in state is reported per server; logout of a server never signed in is harmless.
    assert_eq!(ok(&c, "ui.connectors.mcp.login.status", json!({"name": "web"}))["state"], "idle");
    assert_eq!(ok(&c, "ui.connectors.mcp.logout", json!({"name": "web"}))["had_tokens"], false);
    assert!(err(&c, "ui.connectors.mcp.login", json!({"name": "nobody"})).contains("no MCP server"));
}

#[test]
fn presets_and_mcp_json_import() {
    let t = kit();
    let c = ctx(&t);
    let all = ok(&c, "ui.connectors.mcp.presets", json!({}));
    assert!(all.as_array().unwrap().len() > 10);
    let p = all.as_array().unwrap().iter().find(|p| p["auth"] == "none" && p["env"].as_array().unwrap().is_empty()).expect("a preset without env").clone();
    let name = p["name"].as_str().unwrap();
    let r = ok(&c, "ui.connectors.mcp.preset.add", json!({"preset": name}));
    assert_eq!(r["ok"], true, "{r}");
    assert!(user_config(&t).contains(&format!("[mcp.{name}]")));
    assert!(err(&c, "ui.connectors.mcp.preset.add", json!({"preset": name})).contains("already exists"), "the CLI's refusal, word for word");
    // Import: nothing detected in an empty home; a Claude Desktop file in %APPDATA% is found.
    assert_eq!(ok(&c, "ui.connectors.mcp.import", json!({}))["candidates"].as_array().unwrap().len(), 0);
    let claude = c.appdata.clone().unwrap().join("Claude");
    std::fs::create_dir_all(&claude).unwrap();
    let file = claude.join("claude_desktop_config.json");
    std::fs::write(&file, r#"{"mcpServers": {"files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"], "env": {"GITHUB_TOKEN": "ghp_live_secret"}}, "remote": {"type": "http", "url": "https://mcp.example.com/mcp"}}, }"#).unwrap();
    let cands = ok(&c, "ui.connectors.mcp.import", json!({}));
    let cand = &cands["candidates"][0];
    assert_eq!((cand["label"].as_str(), cand["servers"].as_u64()), (Some("Claude Desktop"), Some(2)), "{cands}");
    assert!(err(&c, "ui.connectors.mcp.import", json!({"candidate": t.paths.user_config().display().to_string()})).contains("not one of"), "only detected files are read");
    let prev = ok(&c, "ui.connectors.mcp.import", json!({"candidate": file.display().to_string()}));
    assert_eq!(prev["applied"], false);
    let rows = prev["servers"].as_array().unwrap();
    assert!(rows.iter().any(|r| r["name"] == "files" && r["secrets"][0] == "MCP_FILES_GITHUB_TOKEN" && r["transport"] == "stdio"), "{prev}");
    assert!(!user_config(&t).contains("[mcp.files]"), "a preview writes nothing");
    let done = ok(&c, "ui.connectors.mcp.import", json!({"candidate": file.display().to_string(), "apply": true, "names": ["files"]}));
    assert!(done["servers"].as_array().unwrap().iter().any(|r| r["name"] == "files" && r["imported"] == true), "{done}");
    let text = user_config(&t);
    assert!(text.contains("[mcp.files]") && !text.contains("[mcp.remote]") && !text.contains("ghp_live_secret"), "{text}");
    assert_eq!(Vault::load(&t.paths.secrets()).unwrap().substitute("{{secret:MCP_FILES_GITHUB_TOKEN}}"), "ghp_live_secret");
    // VS Code's `servers` shape (JSONC), pasted.
    let vs = r#"{
      // VS Code mcp.json
      "servers": {"gh": {"type": "http", "url": "https://api.githubcopilot.com/mcp/"}},
      "inputs": []
    }"#;
    let r = ok(&c, "ui.connectors.mcp.import", json!({"text": vs, "apply": true}));
    assert!(r["servers"][0]["imported"] == true, "{r}");
    assert_eq!(Config::load(Some(&t.paths.user_config()), None, &[]).unwrap().mcp["gh"]["url"].as_str(), Some("https://api.githubcopilot.com/mcp/"));
    assert!(err(&c, "ui.connectors.mcp.import", json!({"text": "{\"x\": 1}"})).contains("mcpServers"));
}

/// Every guided channel form builds with the channel's own builder: a field the module does
/// not know (`deny_unknown_fields`) would fail here.
#[test]
fn every_channel_form_field_is_a_real_setting() {
    let t = kit();
    let state = seagent_core::tmp::TempDir::new_in(&t.paths.data, "kinds");
    let secrets: seagent_plugin::Secrets = Arc::new(|s: &str| s.to_string());
    for k in channels_setup::KINDS {
        let mut m = serde_json::Map::new();
        m.insert("kind".into(), json!(k.kind));
        for f in k.fields {
            let v = match f.kind {
                channels_setup::FieldKind::Number => json!(1),
                channels_setup::FieldKind::Bool => json!(false),
                channels_setup::FieldKind::List => json!(["x"]),
                _ if f.key.contains("listen") => json!("127.0.0.1:0"),
                _ if f.key.contains("url") || f.key == "homeserver" || f.key == "server" => json!("http://127.0.0.1:9"),
                _ if f.key == "account" => json!("+15550001"),
                _ => json!("value-1"),
            };
            m.insert(f.key.into(), v);
        }
        let cfg = seagent_channel::config::parse_config("probe", &Value::Object(m)).unwrap_or_else(|e| panic!("{}: {e}", k.kind));
        if cfg.listens() {
            continue;
        }
        if let Err(e) = seagent_channel::config::build("probe", &cfg, state.path(), &secrets) {
            assert!(!e.contains("unknown field"), "{}: {e}", k.kind);
        }
    }
    // Every guided kind is a registered kind.
    let kinds = ok_kinds(&t);
    for k in channels_setup::KINDS {
        assert!(kinds.contains(&k.kind.to_string()), "{}", k.kind);
    }
}

fn ok_kinds(t: &Kit) -> Vec<String> {
    let v = chan(t, "ui.connectors.channels.kinds", json!({})).unwrap();
    v["all"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect()
}

#[test]
fn channel_setup_validates_stores_secrets_and_sends_a_test_message() {
    let t = kit();
    // Telegram: the token goes to the vault, the table holds a reference and pairs strangers.
    let r = chan(&t, "ui.connectors.channels.save", json!({"name": "tg", "kind": "telegram", "fields": {"token": "123:abc"}, "policy": {"allow": "42, @amy"}})).unwrap();
    assert_eq!((r["ok"].as_bool(), r["checked"].as_str()), (Some(true), Some("built")), "{r}");
    let cfg = Config::load(Some(&t.paths.user_config()), None, &[]).unwrap();
    let tg = &cfg.channels["tg"];
    assert_eq!(tg["token"].as_str(), Some("{{secret:CHANNEL_TG_TOKEN}}"));
    assert_eq!(tg["dm_policy"].as_str(), Some("pairing"));
    assert_eq!(tg["allow"].as_array().unwrap().len(), 2);
    assert_eq!(Vault::load(&t.paths.secrets()).unwrap().substitute("{{secret:CHANNEL_TG_TOKEN}}"), "123:abc");
    let g = chan(&t, "ui.connectors.channels.get", json!({"name": "tg"})).unwrap();
    assert_eq!(g["fields"]["token"]["set"], true);
    assert!(!g.to_string().contains("123:abc"), "{g}");
    // Editing without retyping the token keeps it.
    chan(&t, "ui.connectors.channels.save", json!({"name": "tg", "original": "tg", "kind": "telegram", "fields": {"token": ""}, "policy": {"dm_policy": "allowlist"}})).unwrap();
    let cfg = Config::load(Some(&t.paths.user_config()), None, &[]).unwrap();
    assert_eq!((cfg.channels["tg"]["token"].as_str(), cfg.channels["tg"]["dm_policy"].as_str()), (Some("{{secret:CHANNEL_TG_TOKEN}}"), Some("allowlist")));
    // Clear errors: a missing required field, a duplicate, an unknown kind, a typo'd extra key.
    assert!(chan(&t, "ui.connectors.channels.save", json!({"name": "mm", "kind": "mattermost", "fields": {"url": "https://chat.example.com"}})).unwrap_err().1.contains("Bot access token is required"));
    assert!(chan(&t, "ui.connectors.channels.save", json!({"name": "tg", "kind": "telegram", "fields": {"token": "1:x"}})).unwrap_err().1.contains("already exists"));
    assert!(chan(&t, "ui.connectors.channels.save", json!({"name": "p", "kind": "carrier-pigeon"})).unwrap_err().1.contains("unknown channel kind"));
    let e = chan(&t, "ui.connectors.channels.save", json!({"name": "tg2", "kind": "telegram", "fields": {"token": "1:x"}, "extra": [{"key": "tokn", "value": "\"y\""}]})).unwrap_err().1;
    assert!(e.contains("tokn"), "the builder's own unknown-field error: {e}");
    assert!(!user_config(&t).contains("tg2"), "nothing written on failure");
    // The CLI path refuses a literal credential and takes a reference.
    let c = ConnCtx::new(&t.paths, &t.ws);
    let e = channels_setup::save(&c, &json!({"name": "dc", "kind": "discord", "fields": {"token": "literal"}}), false).unwrap_err().1;
    assert!(e.contains("secrets set"), "{e}");
    let dc = json!({"name": "dc", "kind": "discord", "fields": {"token": "{{secret:DISCORD_TOKEN}}"}});
    assert!(channels_setup::save(&c, &dc, false).unwrap_err().1.contains("not set"), "a reference to a secret nobody stored is caught");
    let v = Vault::load(&t.paths.secrets()).unwrap();
    v.set("DISCORD_TOKEN", "dc-token").unwrap();
    channels_setup::save(&c, &dc, false).unwrap();
    v.remove("DISCORD_TOKEN").unwrap();
    // Status: saved but not running, or missing its secret.
    let l = chan(&t, "ui.connectors.channels.list", json!({})).unwrap();
    let row = |n: &str| l["channels"].as_array().unwrap().iter().find(|x| x["name"] == n).unwrap().clone();
    assert_eq!(row("tg")["status"], "restart");
    assert_eq!(row("dc")["status"], "error");
    assert!(row("dc")["detail"].as_str().unwrap().contains("DISCORD_TOKEN"));
    // A test message through a webhook channel that posts replies to a local peer.
    let (url, got) = http_peer("{}");
    chan(&t, "ui.connectors.channels.save", json!({"name": "hook", "kind": "webhook", "fields": {"outbound_url": url}, "policy": {"default_chat": "room-1"}})).unwrap();
    let r = chan(&t, "ui.connectors.channels.test", json!({"name": "hook", "text": "hello from the console"})).unwrap();
    assert_eq!((r["ok"].as_bool(), r["via"].as_str(), r["chat"].as_str()), (Some(true), Some("fresh"), Some("room-1")), "{r}");
    let req = got.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(req.contains("hello from the console"), "{req}");
    assert!(chan(&t, "ui.connectors.channels.test", json!({"name": "tg"})).unwrap_err().1.contains("numeric chat id"), "no chat: the platform's hint");
    // A listening channel is only parsed (the daemon owns its port), and cannot be tested fresh.
    let r = chan(&t, "ui.connectors.channels.save", json!({"name": "in", "kind": "webhook", "fields": {"listen": "127.0.0.1:0", "token": "hook-token"}})).unwrap();
    assert_eq!(r["checked"], "parsed");
    assert!(chan(&t, "ui.connectors.channels.test", json!({"name": "in", "chat": "x"})).unwrap_err().1.contains("daemon"));
    // Verify reports a non-online kind by building it.
    assert_eq!(chan(&t, "ui.connectors.channels.verify", json!({"name": "hook"})).unwrap()["ok"], true);
    // Remove, and the generic editor for a kind without a guided form.
    chan(&t, "ui.connectors.channels.remove", json!({"name": "hook"})).unwrap();
    assert!(!user_config(&t).contains("[channels.hook]"));
    let e = chan(&t, "ui.connectors.channels.save", json!({"name": "qa", "kind": "qa-channel", "extra": []})).unwrap_err().1;
    assert!(e.contains("inbox"), "the module says what it needs: {e}");
    let inbox = t.ws.join("qa-inbox").display().to_string();
    let r = chan(&t, "ui.connectors.channels.save", json!({"name": "qa", "kind": "qa-channel", "extra": [{"key": "inbox", "value": inbox}]})).unwrap();
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(Config::load(Some(&t.paths.user_config()), None, &[]).unwrap().channels["qa"]["inbox"].as_str(), Some(inbox.as_str()), "a bare value is kept as text");
}

#[test]
fn skills_upload_installs_through_the_hub_and_uninstalls() {
    let t = kit();
    let c = ctx(&t);
    let md = "---\nname: upload-demo\ndescription: A skill picked from a folder.\n---\n# Demo\nSay hi.\n";
    let b64 = |s: &str| seagent_net::crypto::b64(s.as_bytes());
    let r = ok(&c, "ui.connectors.skills.upload", json!({"label": "upload-demo", "files": [{"path": "upload-demo/SKILL.md", "data": b64(md)}, {"path": "upload-demo/references/notes.md", "data": b64("notes")}]}));
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(r["name"], "upload-demo");
    let dir = PathBuf::from(r["path"].as_str().unwrap());
    assert!(dir.join("SKILL.md").is_file() && dir.join("references/notes.md").is_file());
    assert!(err(&c, "ui.connectors.skills.upload", json!({"files": [{"path": "SKILL.md", "data": b64(md)}]})).contains("already installed"), "the hub's own refusal");
    let r = ok(&c, "ui.connectors.skills.uninstall", json!({"name": "upload-demo"}));
    assert_eq!(r["ok"], true, "{r}");
    assert!(!dir.exists());
    // A ZIP with the skill in a top folder.
    let zip = seagent_skills::hub::zip::build_stored(&[("zipped/SKILL.md", md.replace("upload-demo", "zip-demo").as_bytes())]);
    let r = ok(&c, "ui.connectors.skills.upload", json!({"files": [{"path": "zipped.zip", "data": seagent_net::crypto::b64(&zip)}]}));
    assert_eq!(r["name"], "zip-demo", "{r}");
    assert!(err(&c, "ui.connectors.skills.upload", json!({"files": [{"path": "README.md", "data": b64("x")}]})).contains("no SKILL.md"));
    assert!(err(&c, "ui.connectors.skills.upload", json!({"files": [{"path": "x.zip", "data": b64("not a zip")}]})).contains("ZIP"));
    assert!(ok(&c, "ui.connectors.skills.bundled", json!({}))["skills"].is_array());
    assert!(err(&c, "ui.connectors.skills.install", json!({})).contains("id is required"));
}

#[test]
fn acp_agents_a2a_and_webhooks() {
    let t = kit();
    let c = ctx(&t);
    let me = std::env::current_exe().unwrap().display().to_string();
    let r = ok(&c, "ui.connectors.acp.save", json!({"name": "mine", "command": me, "args": "acp --quiet", "description": "local", "env": [{"key": "MY_API_KEY", "value": "k-1", "secret": true}]}));
    assert_eq!(r["ok"], true, "{r}");
    let l = ok(&c, "ui.connectors.acp.list", json!({}));
    let a = l["agents"].as_array().unwrap().iter().find(|x| x["name"] == "mine").unwrap();
    assert_eq!((a["configured"].as_bool(), a["editable"].as_bool(), a["resolved"].is_string()), (Some(true), Some(true), true), "{a}");
    assert_eq!(a["args"], json!(["acp", "--quiet"]));
    assert!(l["agents"].as_array().unwrap().iter().any(|x| x["preset"] == true), "presets are listed too");
    assert!(err(&c, "ui.connectors.acp.save", json!({"name": "bad", "command": "x", "permission_mode": "yolo"})).contains("permission"));
    ok(&c, "ui.connectors.acp.remove", json!({"name": "mine"}));
    assert!(!user_config(&t).contains("[acp.agents.mine]"));
    // A2A: a remote agent with a token, tested against a local agent card.
    let (url, _) = http_peer(r#"{"name": "peer-agent", "description": "d", "skills": [{"id": "a"}]}"#);
    let r = ok(&c, "ui.connectors.a2a.agent.save", json!({"name": "peer", "url": url, "token": "tok-a2a", "capabilities": ["search"]}));
    assert_eq!(r["ok"], true, "{r}");
    let x = ok(&c, "ui.connectors.a2a.agent.test", json!({"name": "peer"}));
    assert_eq!((x["ok"].as_bool(), x["agent"].as_str(), x["skills"].as_u64()), (Some(true), Some("peer-agent"), Some(1)), "{x}");
    let l = ok(&c, "ui.connectors.a2a.list", json!({}));
    assert_eq!(l["agents"][0]["token"], true);
    assert!(!l.to_string().contains("tok-a2a"));
    assert!(err(&c, "ui.connectors.a2a.agent.save", json!({"name": "p2", "url": "ftp://x"})).contains("https://"));
    assert!(err(&c, "ui.connectors.a2a.peer.save", json!({"name": "laptop", "token": "short"})).contains("16"));
    ok(&c, "ui.connectors.a2a.peer.save", json!({"name": "laptop", "token": "a-long-enough-peer-token"}));
    assert_eq!(ok(&c, "ui.connectors.a2a.list", json!({}))["peers"][0]["set"], true);
    ok(&c, "ui.connectors.a2a.enable", json!({"enabled": true}));
    assert_eq!(ok(&c, "ui.connectors.a2a.list", json!({}))["enabled"], true);
    // Webhooks: subscriptions on a webhook channel; other kinds are refused with the reason.
    std::fs::write(t.paths.user_config(), format!("{}\n[channels.hooks]\nkind = \"webhook\"\nlisten = \"127.0.0.1:0\"\n\n[channels.tg]\nkind = \"telegram\"\ntoken = \"x\"\n", user_config(&t))).unwrap();
    let r = ok(&c, "ui.connectors.webhooks.subscribe", json!({"channel": "hooks", "route": "deploys", "spec": {"prompt": "A deploy finished: {payload}"}}));
    assert!(r["secret"].as_str().is_some_and(|s| s.len() >= 16), "{r}");
    let l = ok(&c, "ui.connectors.webhooks.list", json!({}));
    assert_eq!(l["channels"][0]["subscriptions"][0]["route"], "deploys", "{l}");
    assert!(err(&c, "ui.connectors.webhooks.subscribe", json!({"channel": "tg", "route": "x"})).contains("not a webhook"));
    assert_eq!(ok(&c, "ui.connectors.webhooks.remove", json!({"channel": "hooks", "route": "deploys"}))["removed"], true);
    let o = ok(&c, "ui.connectors.overview", json!({}));
    assert_eq!(o["webhooks"]["channels"], 1);
    assert_eq!(o["a2a"]["agents"], 1);
}

/// The Connections page calls only methods the daemon serves and advertises (this module,
/// `channels_setup`, the sibling `ui.*` registries and the host methods).
#[test]
fn connectors_js_calls_only_served_methods() {
    const JS: &str = include_str!("../../../../../ui/web/connectors.js");
    let mut called: Vec<String> = vec![];
    for (i, _) in JS.match_indices("rpc('") {
        let name: String = JS[i + 5..].chars().take_while(|c| *c != '\'').collect();
        if !called.contains(&name) {
            called.push(name);
        }
    }
    assert!(called.len() >= 40, "scanner found only {called:?}");
    let t = kit();
    let c = ctx(&t);
    let cc = channels_setup::ctx_for(&t.paths, &t.ws);
    for m in &called {
        let mine = METHODS.contains(&m.as_str()) || channels_setup::METHODS.contains(&m.as_str());
        let sibling = crate::ops::ui_methods::METHODS.contains(&m.as_str()) || crate::ops::webui::METHODS.contains(&m.as_str()) || crate::HOST_METHODS.contains(&m.as_str());
        assert!(mine || sibling, "connectors.js calls `{m}`, which nothing serves");
        if METHODS.contains(&m.as_str()) {
            assert!(call(&c, m, &json!({})).is_some(), "`{m}` is listed but not dispatched");
        }
        if channels_setup::METHODS.contains(&m.as_str()) {
            assert!(channels_setup::call(&cc, m, &json!({})).is_some(), "`{m}` is listed but not dispatched");
        }
    }
    for m in METHODS.iter().chain(channels_setup::METHODS) {
        assert!(called.iter().any(|x| x == m), "`{m}` is served but the page never calls it");
        assert!(!crate::ops::ui_methods::METHODS.contains(m) && !crate::ops::webui::METHODS.contains(m), "`{m}` registered twice");
    }
}
