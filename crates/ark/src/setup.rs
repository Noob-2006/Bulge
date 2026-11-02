//! `ark setup`: first-run wizard. Picks a provider, stores its key in the vault,
//! lists the provider's models to choose from, proves the key with one call, and
//! optionally turns on the web UI and one chat channel. Speaks Chinese when the
//! locale does. Reads answers from the terminal, or from stdin when there is none
//! (so it can be scripted and tested).

use ark_kernel::config::{Config, Paths};
use ark_kernel::vault::Vault;
use ark_model::{presets, ProviderConfig, WireFormat};
use serde_json::Value;
use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

fn zh() -> bool {
    static ZH: OnceLock<bool> = OnceLock::new();
    *ZH.get_or_init(|| ["LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"].iter().find_map(|v| std::env::var(v).ok().filter(|s| !s.is_empty())).is_some_and(|l| l.starts_with("zh")))
}

/// Pick the Chinese or English text.
pub fn t(zh_text: &'static str, en: &'static str) -> &'static str {
    if zh() {
        zh_text
    } else {
        en
    }
}

fn colon() -> &'static str {
    t("：", ": ")
}

fn paren(s: &str) -> String {
    if zh() {
        format!("（{s}）")
    } else {
        format!("({s})")
    }
}

/// What to suggest after a run fails, if `ark setup` would fix it.
pub fn hint(err: &str) -> Option<&'static str> {
    (err.contains("API key missing") || err.contains("no API key") || err.contains("unknown provider")).then(|| t("執行 `ark setup` 設定模型與金鑰", "run `ark setup` to configure a model and key"))
}

/// Providers offered by name; the rest stay reachable through "other".
const MENU: &[(&str, &str, &str)] = &[
    ("anthropic", "Anthropic (Claude)", "Anthropic（Claude）"),
    ("openai", "OpenAI", "OpenAI"),
    ("gemini", "Google Gemini", "Google Gemini"),
    ("openrouter", "OpenRouter (many vendors, one key)", "OpenRouter（一把金鑰用多家模型）"),
    ("deepseek", "DeepSeek", "DeepSeek"),
    ("dashscope", "Alibaba Qwen (DashScope)", "阿里通義千問（DashScope）"),
    ("moonshot", "Moonshot (Kimi)", "月之暗面（Kimi）"),
    ("zhipu", "Zhipu (GLM)", "智譜（GLM）"),
    ("siliconflow", "SiliconFlow", "矽基流動（SiliconFlow）"),
    ("ollama", "Ollama (local, no key)", "Ollama（本機，免金鑰）"),
];

struct Io {
    tty: Option<std::fs::File>,
    input: Box<dyn BufRead>,
}

impl Io {
    fn new() -> Io {
        let tty = std::io::stdin().is_terminal().then(|| std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").ok()).flatten();
        let input: Box<dyn BufRead> = match &tty {
            Some(f) => Box::new(BufReader::new(f.try_clone().expect("tty"))),
            None => Box::new(BufReader::new(std::io::stdin())),
        };
        Io { tty, input }
    }
    fn say(&self, s: &str) {
        eprintln!("{s}");
    }
    fn line(&mut self, prompt: &str) -> Result<String, String> {
        eprint!("{prompt}");
        let _ = std::io::stderr().flush();
        let mut l = String::new();
        if self.input.read_line(&mut l).map_err(|e| e.to_string())? == 0 {
            return Err(t("輸入結束，未完成設定", "input ended before setup finished").into());
        }
        Ok(l.trim().to_string())
    }
    fn ask(&mut self, q: &str, default: &str) -> Result<String, String> {
        let a = self.line(&if default.is_empty() { format!("{q}: ") } else { format!("{q} [{default}]: ") })?;
        Ok(if a.is_empty() { default.to_string() } else { a })
    }
    fn yes(&mut self, q: &str, default: bool) -> Result<bool, String> {
        let a = self.line(&format!("{q} [{}]: ", if default { "Y/n" } else { "y/N" }))?.to_lowercase();
        Ok(match a.as_str() {
            "" => default,
            _ => matches!(a.as_str(), "y" | "yes" | "是" | "好" | "要" | "對"),
        })
    }
    /// A secret: echo is turned off on a terminal so it never shows on screen.
    fn secret(&mut self, q: &str) -> Result<String, String> {
        let Some(tty) = &self.tty else { return self.line(&format!("{q}: ")) };
        use std::os::fd::AsRawFd;
        let fd = tty.as_raw_fd();
        let mut old: libc::termios = unsafe { std::mem::zeroed() };
        let have = unsafe { libc::tcgetattr(fd, &mut old) } == 0;
        if have {
            let mut quiet = old;
            quiet.c_lflag &= !libc::ECHO;
            quiet.c_lflag |= libc::ECHONL;
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) };
        }
        let r = self.line(&format!("{q} {}: ", t("（輸入不會顯示）", "(hidden)")));
        if have {
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old) };
        }
        r
    }
    fn choose(&mut self, q: &str, items: &[String], default: usize) -> Result<usize, String> {
        for (i, it) in items.iter().enumerate() {
            self.say(&format!("  {:>2}) {it}", i + 1));
        }
        loop {
            let a = self.ask(q, &(default + 1).to_string())?;
            match a.parse::<usize>() {
                Ok(n) if (1..=items.len()).contains(&n) => return Ok(n - 1),
                _ => self.say(t("  請輸入清單中的編號", "  pick a number from the list")),
            }
        }
    }
}

fn mask(k: &str) -> String {
    let n = k.chars().count();
    if n <= 8 {
        "••••".into()
    } else {
        format!("{}…{}", k.chars().take(4).collect::<String>(), k.chars().skip(n - 4).collect::<String>())
    }
}

/// Text-only models; drops embeddings, speech, images and the like from pickers.
fn chat_models(all: Vec<String>) -> Vec<String> {
    const SKIP: &[&str] = &["embed", "tts", "whisper", "dall-e", "moderation", "audio", "image", "transcribe", "realtime", "search", "rerank", "babbage", "davinci", "aqa", "imagen", "veo"];
    all.into_iter().filter(|m| !SKIP.iter().any(|s| m.to_lowercase().contains(s))).collect()
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(20))).build().into()
}

fn read_json(r: ureq::http::Response<ureq::Body>) -> (u16, Value) {
    let status = r.status().as_u16();
    let mut raw = String::new();
    let _ = r.into_body().into_reader().take(1 << 20).read_to_string(&mut raw);
    (status, serde_json::from_str(&raw).unwrap_or(Value::Null))
}

/// Check a channel token against the platform; returns the bot's display name.
fn check_channel(kind: &str, token: &str, app_token: Option<&str>) -> Result<String, String> {
    let a = agent();
    let net = |e: ureq::Error| e.to_string();
    match kind {
        "telegram" => {
            let (s, v) = read_json(a.get(&format!("https://api.telegram.org/bot{token}/getMe")).call().map_err(net)?);
            match (s, v["result"]["username"].as_str()) {
                (200, Some(u)) => Ok(format!("@{u}")),
                _ => Err(v["description"].as_str().unwrap_or("rejected").to_string()),
            }
        }
        "discord" => {
            let (s, v) = read_json(a.get("https://discord.com/api/v10/users/@me").header("authorization", &format!("Bot {token}")).call().map_err(net)?);
            match (s, v["username"].as_str()) {
                (200, Some(u)) => Ok(u.to_string()),
                _ => Err(v["message"].as_str().unwrap_or("rejected").to_string()),
            }
        }
        "slack" => {
            let (_, v) = read_json(a.post("https://slack.com/api/auth.test").header("authorization", &format!("Bearer {token}")).send_empty().map_err(net)?);
            if v["ok"] != true {
                return Err(v["error"].as_str().unwrap_or("rejected").to_string());
            }
            if let Some(app) = app_token {
                let (_, w) = read_json(a.post("https://slack.com/api/apps.connections.open").header("authorization", &format!("Bearer {app}")).send_empty().map_err(net)?);
                if w["ok"] != true {
                    return Err(format!("app token: {}", w["error"].as_str().unwrap_or("rejected")));
                }
            }
            Ok(format!("{} @ {}", v["user"].as_str().unwrap_or("?"), v["team"].as_str().unwrap_or("?")))
        }
        _ => Ok(String::new()),
    }
}

fn table<'a>(root: &'a mut toml::Table, key: &str) -> &'a mut toml::Table {
    let e = root.entry(key.to_string()).or_insert_with(|| toml::Value::Table(toml::Table::new()));
    if !e.is_table() {
        *e = toml::Value::Table(toml::Table::new());
    }
    e.as_table_mut().unwrap()
}

pub fn run(paths: &Paths) -> Result<i32, String> {
    let mut io = Io::new();
    std::fs::create_dir_all(&paths.config_dir).map_err(|e| e.to_string())?;
    let vault = Vault::load(&paths.secrets())?;
    let cfg_path = paths.user_config();
    let existing = std::fs::read_to_string(&cfg_path).ok();
    let mut root: toml::Table = match &existing {
        Some(s) => s.parse().map_err(|e| format!("{}: {e}", cfg_path.display()))?,
        None => toml::Table::new(),
    };
    let current_model = root.get("model").and_then(|m| m.get("default")).and_then(|d| d.as_str()).map(String::from);

    io.say(&format!("\n✦ ark setup — {}\n", t("首次設定精靈", "first-run setup")));
    io.say(&match &existing {
        Some(_) => format!("{} {}", t("將更新設定檔（原檔會備份）：", "Updating config (the old file is backed up):"), cfg_path.display()),
        None => format!("{} {}", t("將建立設定檔：", "Creating config:"), cfg_path.display()),
    });
    io.say(&format!("{}\n", t("金鑰存在只有你能讀的 secrets.toml（權限 0600），不會寫進設定檔，也不會送進模型。按 Enter 採用括號內的預設值。", "Keys go to secrets.toml (readable only by you, mode 0600), never into the config file or the model. Press Enter to take the default in brackets.")));

    // ── 1. provider ──
    let all: Vec<ProviderConfig> = presets();
    let has_key = |p: &ProviderConfig| match &p.api_key_env {
        None => true,
        Some(env) => std::env::var(env).is_ok_and(|v| !v.trim().is_empty()) || vault.names().contains(env),
    };
    let mut labels: Vec<String> = MENU
        .iter()
        .map(|(id, en, zh_l)| {
            let p = all.iter().find(|p| p.id == *id).expect("preset");
            let tag = if p.api_key_env.is_some() && has_key(p) { t("  ✓ 已有金鑰", "  ✓ key found") } else { "" };
            format!("{}{tag}", if zh() { zh_l } else { en })
        })
        .collect();
    labels.push(t("其他（列出全部，或自訂 OpenAI 相容端點）", "Other (all presets, or a custom OpenAI-compatible endpoint)").into());
    let cur_pid = current_model.as_deref().and_then(|m| m.split_once('/')).map(|(p, _)| p.to_string());
    let default = cur_pid
        .as_deref()
        .and_then(|c| MENU.iter().position(|(id, ..)| *id == c))
        .or_else(|| MENU.iter().position(|(id, ..)| all.iter().any(|p| p.id == *id && p.api_key_env.is_some() && has_key(p))))
        .unwrap_or(0);
    io.say(t("① 選擇模型供應商", "① Model provider"));
    let pick = io.choose(t("編號", "Number"), &labels, default)?;
    let mut custom: Option<toml::Table> = None;
    let mut prov: ProviderConfig = if pick < MENU.len() {
        all.iter().find(|p| p.id == MENU[pick].0).cloned().unwrap()
    } else {
        let ids: Vec<String> = all.iter().map(|p| format!("{} — {}", p.id, p.base_url)).chain([t("自訂端點", "custom endpoint").to_string()]).collect();
        let i = io.choose(t("編號", "Number"), &ids, 0)?;
        if i < all.len() {
            all[i].clone()
        } else {
            let id = io.ask(t("名稱（英數，用於 provider/model）", "Name (letters/digits, used as provider/model)"), "custom")?;
            if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return Err(t("名稱只能用英數字、- 與 _", "name may only use letters, digits, - and _").into());
            }
            let base = io.ask(t("Base URL（例如 http://127.0.0.1:8000/v1）", "Base URL (e.g. http://127.0.0.1:8000/v1)"), "")?;
            if !(base.starts_with("http://") || base.starts_with("https://")) {
                return Err(t("Base URL 須以 http:// 或 https:// 開頭", "base URL must start with http:// or https://").into());
            }
            let needs_key = io.yes(t("需要 API 金鑰嗎？", "Does it need an API key?"), true)?;
            let env = format!("{}_API_KEY", id.to_uppercase().replace('-', "_"));
            let mut tb = toml::Table::new();
            tb.insert("format".into(), "openai_chat".into());
            tb.insert("base_url".into(), base.clone().into());
            if needs_key {
                tb.insert("api_key_env".into(), env.clone().into());
            }
            custom = Some(tb);
            ProviderConfig { id, format: WireFormat::OpenAiChat, base_url: base, api_key_env: needs_key.then_some(env), api_key: None, headers: Default::default(), idle_timeout_secs: None }
        }
    };
    let local = prov.api_key_env.is_none();
    if local && custom.is_none() {
        let base = io.ask(t("服務位址", "Server address"), &prov.base_url)?;
        if base != prov.base_url {
            let mut tb = toml::Table::new();
            tb.insert("base_url".into(), base.clone().into());
            custom = Some(tb);
            prov.base_url = base;
        }
    }

    // ── 2. key + model list (the list call doubles as the key check) ──
    let mut key: Option<String> = None;
    let mut models: Vec<String> = vec![];
    if let Some(env) = prov.api_key_env.clone() {
        let found = std::env::var(&env).ok().filter(|v| !v.trim().is_empty()).map(|v| (v, t("環境變數", "environment"))).or_else(|| {
            let v = vault.substitute(&format!("{{{{secret:{env}}}}}"));
            (!v.starts_with("{{secret:")).then_some((v, t("保管庫", "vault")))
        });
        io.say(&format!("\n{}", t("② API 金鑰", "② API key")));
        if let Some((k, from)) = &found {
            io.say(&format!("  {} {env} {}{}{}", t("已找到", "Found"), paren(from), colon(), mask(k)));
            if io.yes(t("  沿用這把金鑰？", "  Use it?"), true)? {
                key = Some(k.clone());
            }
        }
        for attempt in 0..3 {
            if key.is_none() {
                let k = io.secret(&format!("  {env}"))?;
                if k.is_empty() {
                    return Err(t("沒有輸入金鑰", "no key entered").into());
                }
                key = Some(k);
            }
            io.say(t("  驗證中…", "  checking…"));
            match ark_model::list_models(&prov, key.as_deref()) {
                Ok(m) => {
                    io.say(&format!("  ✓ {} {}", t("金鑰有效", "key works"), paren(&format!("{} {}", m.len(), t("個模型", "models")))));
                    models = m;
                    break;
                }
                Err(e) if e.contains("Auth") || e.contains("401") || e.contains("403") => {
                    io.say(&format!("  ✗ {}{}{e}", t("金鑰被拒絕", "key rejected"), colon()));
                    if attempt == 2 {
                        return Err(t("金鑰驗證失敗三次", "key rejected three times").into());
                    }
                    key = None;
                }
                Err(e) => {
                    io.say(&format!("  ! {}{}{e}", t("無法取得模型清單，稍後以實際呼叫驗證", "could not list models; will verify with a real call"), colon()));
                    break;
                }
            }
        }
        let k = key.clone().unwrap_or_default();
        // Also when it came from the environment: a new shell may not export it.
        if found.as_ref().is_none_or(|(v, from)| *v != k || *from != t("保管庫", "vault")) {
            vault.set(&env, &k)?;
            io.say(&format!("  {} {env}", t("已存入保管庫：", "Stored in vault:")));
        }
    } else {
        io.say(&format!("\n{}", t("② 連線檢查", "② Connection check")));
        match ark_model::list_models(&prov, None) {
            Ok(m) => {
                io.say(&format!("  ✓ {} {}", t("連線成功", "reachable"), paren(&format!("{} {}", m.len(), t("個模型", "models")))));
                models = m;
            }
            Err(e) => io.say(&format!("  ! {e}\n  {}", t("請確認服務已啟動；仍可繼續設定", "make sure the server is running; you can still continue"))),
        }
    }

    // ── 3. model ──
    io.say(&format!("\n{}", t("③ 預設模型", "③ Default model")));
    let models = chat_models(models);
    let cur_name = current_model.as_deref().and_then(|m| m.strip_prefix(&format!("{}/", prov.id))).map(String::from);
    let model = if models.is_empty() {
        let d = cur_name.unwrap_or_default();
        io.ask(t("模型名稱", "Model name"), &d)?
    } else {
        let shown: Vec<String> = models.iter().take(30).cloned().chain([t("手動輸入其他名稱", "type another name").to_string()]).collect();
        let pref = ["sonnet", "flash", "chat", "plus", "latest"];
        let d = cur_name.as_ref().and_then(|c| models.iter().take(30).position(|m| m == c)).or_else(|| pref.iter().find_map(|p| models.iter().take(30).position(|m| m.contains(p)))).unwrap_or(0);
        let i = io.choose(t("編號", "Number"), &shown, d)?;
        if i < shown.len() - 1 {
            shown[i].clone()
        } else {
            io.ask(t("模型名稱", "Model name"), "")?
        }
    };
    if model.is_empty() {
        return Err(t("沒有選擇模型", "no model chosen").into());
    }
    let full = format!("{}/{model}", prov.id);

    // ── 4. one real call ──
    io.say(&format!("  {} {full}…", t("試打一次", "Test call to")));
    let mut pc = prov.clone();
    pc.api_key = key.clone();
    let probe = ark_model::build(&pc).and_then(|p| {
        let req = ark_core::ModelRequest { model: model.clone(), system: vec![], messages: vec![ark_core::Message::user("Reply with exactly: pong")], tools: vec![], max_tokens: 256, temperature: None, cache_after_message: None, reasoning: None };
        let t0 = Instant::now();
        p.complete(&req, &mut |_| {}, &ark_core::Cancel::new().with_deadline(Instant::now() + Duration::from_secs(60))).map(|r| (t0.elapsed(), r.message.text())).map_err(|e| e.to_string())
    });
    match &probe {
        Ok((d, reply)) => io.say(&format!("  ✓ {} {:.1}s{}{}", t("回應", "replied in"), d.as_secs_f32(), colon(), crate::term::one_line(reply, 40))),
        Err(e) => {
            io.say(&format!("  ✗ {e}"));
            if !io.yes(t("  仍要儲存這個設定嗎？", "  Save this setup anyway?"), false)? {
                return Ok(1);
            }
        }
    }

    // ── 5. web UI ──
    io.say(&format!("\n{}", t("④ 網頁介面", "④ Web UI")));
    let app_on = root.get("app").and_then(|a| a.get("enabled")).and_then(|v| v.as_bool()).unwrap_or(false);
    let web = io.yes(t("  啟用網頁介面（瀏覽器聊天、管理工作階段）？", "  Turn on the web UI (chat and sessions in a browser)?"), true)?;
    if web {
        if !vault.names().iter().any(|n| n == "APP_TOKEN") {
            vault.set("APP_TOKEN", &ark_net::crypto::random_token(24))?;
        }
        let app = table(&mut root, "app");
        app.insert("enabled".into(), true.into());
        app.entry("token").or_insert_with(|| "{{secret:APP_TOKEN}}".into());
    } else if app_on {
        table(&mut root, "app").insert("enabled".into(), false.into());
    }

    // ── 6. one chat channel ──
    io.say(&format!("\n{}", t("⑤ 聊天平台（之後可在設定檔加更多，共 46 種）", "⑤ Chat platform (more can be added to the config later; 46 kinds)")));
    let kinds = [t("略過", "Skip"), "Telegram", "Discord", "Slack"].map(String::from);
    let mut channel_added: Option<String> = None;
    let c = io.choose(t("編號", "Number"), &kinds, 0)?;
    if c > 0 {
        let kind = ["", "telegram", "discord", "slack"][c];
        let help = match kind {
            "telegram" => t("  在 Telegram 找 @BotFather，/newbot 取得 token", "  In Telegram, message @BotFather and /newbot to get a token"),
            "discord" => t("  Discord Developer Portal → 應用程式 → Bot → Reset Token；並開啟 Message Content Intent", "  Discord Developer Portal → your app → Bot → Reset Token; enable the Message Content intent"),
            _ => t("  api.slack.com/apps → OAuth 的 Bot token（xoxb-）與開啟 Socket Mode 後的 App token（xapp-）", "  api.slack.com/apps → OAuth Bot token (xoxb-) and, with Socket Mode on, an App token (xapp-)"),
        };
        io.say(help);
        let (tok_name, app_name) = match kind {
            "telegram" => ("TELEGRAM_TOKEN", None),
            "discord" => ("DISCORD_TOKEN", None),
            _ => ("SLACK_BOT_TOKEN", Some("SLACK_APP_TOKEN")),
        };
        let tok = io.secret(&format!("  {tok_name}"))?;
        let app_tok = match app_name {
            Some(n) => Some(io.secret(&format!("  {n}"))?),
            None => None,
        };
        if tok.is_empty() || app_tok.as_deref() == Some("") {
            io.say(t("  沒有輸入 token，略過聊天平台", "  no token entered; skipping the chat platform"));
        } else {
            io.say(t("  驗證中…", "  checking…"));
            let ok = match check_channel(kind, &tok, app_tok.as_deref()) {
                Ok(name) => {
                    io.say(&format!("  ✓ {name}"));
                    true
                }
                Err(e) => {
                    io.say(&format!("  ✗ {e}"));
                    io.yes(t("  仍要加入嗎？", "  Add it anyway?"), false)?
                }
            };
            if ok {
                vault.set(tok_name, &tok)?;
                if let (Some(n), Some(v)) = (app_name, &app_tok) {
                    vault.set(n, v)?;
                }
                let channels = table(&mut root, "channels");
                let mut name = kind.to_string();
                let mut i = 2;
                while channels.contains_key(&name) {
                    name = format!("{kind}{i}");
                    i += 1;
                }
                let mut ch = toml::Table::new();
                ch.insert("kind".into(), kind.into());
                match kind {
                    "slack" => {
                        ch.insert("bot_token".into(), "{{secret:SLACK_BOT_TOKEN}}".into());
                        ch.insert("app_token".into(), "{{secret:SLACK_APP_TOKEN}}".into());
                    }
                    _ => {
                        ch.insert("token".into(), format!("{{{{secret:{tok_name}}}}}").into());
                    }
                }
                // Strangers get a one-time code; you approve them with `ark pairing approve`.
                ch.insert("dm_policy".into(), "pairing".into());
                channels.insert(name.clone(), toml::Value::Table(ch));
                channel_added = Some(name);
            }
        }
    }

    // ── 7. write, validate, roll back on error ──
    table(&mut root, "model").insert("default".into(), full.clone().into());
    if let Some(tb) = custom {
        let provs = table(&mut root, "providers");
        let entry = table(provs, &prov.id);
        for (k, v) in tb {
            entry.insert(k, v);
        }
    }
    let body = toml::to_string_pretty(&root).map_err(|e| e.to_string())?;
    let header = t("# 由 `ark setup` 產生；所有選項見 docs/config-example.toml\n\n", "# Written by `ark setup`; every option is in docs/config-example.toml\n\n");
    let backup = cfg_path.with_extension(format!("toml.bak.{}", ark_kernel::util::random_hex(4)));
    if existing.is_some() {
        std::fs::copy(&cfg_path, &backup).map_err(|e| e.to_string())?;
    }
    let text = if existing.as_deref().is_some_and(|s| s.starts_with("# ")) { body } else { format!("{header}{body}") };
    std::fs::write(&cfg_path, text).map_err(|e| e.to_string())?;
    if let Err(e) = Config::load(Some(&cfg_path), None, &[]) {
        if existing.is_some() {
            let _ = std::fs::copy(&backup, &cfg_path);
        }
        return Err(format!("{}: {e}", t("新設定無法通過檢查，已還原", "the new config failed validation and was rolled back")));
    }

    io.say(&format!("\n✓ {} {}", t("已寫入", "Wrote"), cfg_path.display()));
    if existing.is_some() {
        io.say(&format!("  {} {}", t("原檔備份：", "Backup:"), backup.display()));
    }
    io.say(&format!("\n{}", t("接下來：", "Next:")));
    io.say(&format!("  ark chat                      {}", t("在終端機對話", "talk in the terminal")));
    io.say(&format!("  ark run \"…\"                   {}", t("交辦一件事", "hand it one task")));
    if web || channel_added.is_some() {
        io.say(&format!("  ark daemon start              {}", t("啟動背景服務（網頁介面與聊天平台需要）", "start the background service (the web UI and chat platforms need it)")));
        io.say(&format!("  ark service install           {}", t("改用 systemd 開機自動啟動（含沙箱設定）", "or run it under systemd at login (hardened unit)")));
    }
    if web {
        io.say(&format!("  ark app open                  {}", t("開啟網頁介面", "open the web UI")));
    }
    if let Some(n) = channel_added {
        io.say(&format!("  ark pairing approve {n} <code>   {}", t("核准第一次私訊你的人（對方會收到配對碼）", "approve whoever messages first (they receive a pairing code)")));
    }
    io.say(&format!("  ark doctor                    {}", t("檢查環境", "check everything")));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_and_filters() {
        assert_eq!(mask("sk-abcdefghijkl"), "sk-a…ijkl");
        assert_eq!(mask("short"), "••••");
        assert_eq!(chat_models(vec!["gpt-x".into(), "text-embedding-3".into(), "whisper-1".into(), "gemini-2-flash".into()]), vec!["gpt-x", "gemini-2-flash"]);
        assert!(hint("provider `anthropic`: API key missing — set $X").is_some());
        assert!(hint("rate limited").is_none());
    }

    #[test]
    fn nested_tables_are_created_or_replaced() {
        let mut r: toml::Table = "app = 3\n[model]\ndefault = \"a/b\"".parse().unwrap();
        table(&mut r, "app").insert("enabled".into(), true.into());
        table(&mut r, "model").insert("default".into(), "c/d".into());
        assert_eq!(r["app"]["enabled"].as_bool(), Some(true));
        assert_eq!(r["model"]["default"].as_str(), Some("c/d"));
    }
}
