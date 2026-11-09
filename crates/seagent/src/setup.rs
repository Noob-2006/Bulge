//! `seagent setup`: first-run wizard. Picks a provider, stores its key in the vault,
//! lists the provider's models to choose from, proves the key with one call, and
//! optionally turns on the web UI and one chat channel. Speaks Chinese when the
//! locale does. Reads answers from the terminal, or from stdin when there is none
//! (so it can be scripted and tested).

use seagent_kernel::config::{Config, Paths};
use seagent_kernel::vault::Vault;
use seagent_model::{presets, ProviderConfig, WireFormat};
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

/// What to suggest after a run fails, if `seagent setup` would fix it.
pub fn hint(err: &str) -> Option<&'static str> {
    (err.contains("API key missing") || err.contains("no API key") || err.contains("unknown provider")).then(|| t("執行 `seagent setup` 設定模型與金鑰", "run `seagent setup` to configure a model and key"))
}

/// Providers offered by name; the rest stay reachable through "other".
pub(crate) const MENU: &[(&str, &str, &str)] = &[
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
        let tty = std::io::stdin().is_terminal().then(|| std::fs::OpenOptions::new().read(true).write(true).open(crate::ops::hostos::TTY_IN).ok()).flatten();
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
        let quiet = crate::ops::hostos::EchoOff::file(tty, true);
        let r = self.line(&format!("{q} {}: ", t("（輸入不會顯示）", "(hidden)")));
        drop(quiet);
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

impl crate::ops::wizard::Prompt for Io {
    fn say(&self, s: &str) {
        Io::say(self, s)
    }
    fn yes(&mut self, q: &str, default: bool) -> Result<bool, String> {
        Io::yes(self, q, default)
    }
    fn ask(&mut self, q: &str, default: &str) -> Result<String, String> {
        Io::ask(self, q, default)
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
pub(crate) fn chat_models(all: Vec<String>) -> Vec<String> {
    const SKIP: &[&str] = &["embed", "tts", "whisper", "dall-e", "moderation", "audio", "image", "transcribe", "realtime", "search", "rerank", "babbage", "davinci", "aqa", "imagen", "veo"];
    all.into_iter().filter(|m| !SKIP.iter().any(|s| m.to_lowercase().contains(s))).collect()
}

// ── web search provider (OpenClaw `src/flows/search-setup.ts`) ──

/// Providers that answer without any credential but are not keyless-ring members: a local
/// server (Ollama), the Codex app-server and DuckDuckGo's public HTML endpoint.
const KEY_FREE: &[&str] = &["ollama", "codex", "duckduckgo"];

/// One row of the wizard's search step, resolved from the provider registry (pure, no I/O).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchOption {
    pub id: &'static str,
    pub label: &'static str,
    /// Env var / vault name the step asks for; `None` = nothing to ask.
    pub credential: Option<&'static str>,
    /// `credential` is a server address, not a secret (SearXNG).
    pub credential_is_url: bool,
    /// Works with no credential at all (keyless ring member or a local server).
    pub keyless: bool,
    /// Already configured: the credential is the environment or the vault.
    pub configured: bool,
    /// Where to get the credential (upstream `entry.signupUrl`).
    pub signup_url: &'static str,
}

/// The wizard's provider menu: every provider, sorted by label then id (upstream
/// `resolveSearchProviderOptions` ends with a `localeCompare` on the label). `has` reports
/// whether an environment variable / vault secret of that name is set.
pub fn search_options(has: impl Fn(&str) -> bool) -> Vec<SearchOption> {
    let mut opts: Vec<SearchOption> = seagent_tools::web::providers::all()
        .iter()
        .map(|p| {
            let keyless = p.keyless() || KEY_FREE.contains(&p.id());
            SearchOption {
                id: p.id(),
                label: p.label(),
                credential: if keyless { None } else { p.env_vars().first().copied() },
                credential_is_url: p.id() == "searxng",
                keyless,
                configured: p.env_vars().iter().any(|v| has(v)),
                signup_url: p.signup_url(),
            }
        })
        .collect();
    opts.sort_by(|a, b| a.label.to_lowercase().cmp(&b.label.to_lowercase()).then(a.id.cmp(b.id)));
    opts
}

/// What one answer writes (upstream `applySearchProviderSelection`): the `[web.search]` pin, the
/// per-provider entry and, for a typed key, the vault secret the entry references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchWrite {
    pub provider: String,
    /// `[web.search] enabled`. `false` only when a key is required and none is available.
    pub enabled: bool,
    /// `[web.providers.<id>] <key> = <value>`.
    pub provider_entry: Option<(&'static str, String)>,
    /// Vault entry to store before the placeholder is written.
    pub secret: Option<(&'static str, String)>,
    /// The provider needs a credential and the user supplied none.
    pub missing_credential: bool,
}

/// Decide what to write for `answer` (the key, the server URL, or "" to take an existing one).
pub fn search_write(opt: &SearchOption, answer: &str) -> SearchWrite {
    let answer = answer.trim();
    let mut w = SearchWrite { provider: opt.id.to_string(), enabled: true, provider_entry: None, secret: None, missing_credential: false };
    // Key-free providers write nothing but the pin.
    let Some(var) = opt.credential else { return w };
    if answer.is_empty() {
        if !opt.configured {
            w.enabled = false;
            w.missing_credential = true;
        }
        return w;
    }
    if opt.credential_is_url {
        w.provider_entry = Some(("base_url", answer.to_string()));
    } else {
        w.secret = Some((var, answer.to_string()));
        w.provider_entry = Some(("api_key", format!("{{{{secret:{var}}}}}")));
    }
    w
}

/// Write a choice into the `[web]` table (the caller stores `secret` in the vault first).
pub fn apply_search(root: &mut toml::Table, w: &SearchWrite) {
    let web = table(root, "web");
    let search = table(web, "search");
    search.insert("provider".into(), w.provider.clone().into());
    search.insert("enabled".into(), w.enabled.into());
    if let Some((k, v)) = &w.provider_entry {
        let providers = table(web, "providers");
        let entry = table(providers, w.provider.as_str());
        entry.insert((*k).to_string(), v.clone().into());
    }
}

/// Write a choice into the `[web]` table, then keep a previously-disabled search off (upstream
/// `preserveDisabledState`).
pub fn apply_search_keeping_disabled(root: &mut toml::Table, w: &SearchWrite, was_off: bool) {
    apply_search(root, w);
    if was_off {
        table(table(root, "web"), "search").insert("enabled".into(), false.into());
    }
}

fn agent() -> ureq::Agent {
    seagent_net::http::builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(20))).build().into()
}

fn read_json(r: ureq::http::Response<ureq::Body>) -> (u16, Value) {
    let status = r.status().as_u16();
    let mut raw = String::new();
    let _ = r.into_body().into_reader().take(1 << 20).read_to_string(&mut raw);
    (status, serde_json::from_str(&raw).unwrap_or(Value::Null))
}

/// Check a channel token against the platform; returns the bot's display name.
pub(crate) fn check_channel(kind: &str, token: &str, app_token: Option<&str>) -> Result<String, String> {
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

/// Write the config (old file backed up first), validate it, and restore the backup when the
/// result does not load. Returns the backup path when there was a previous file.
pub fn save_config(cfg_path: &std::path::Path, root: &toml::Table, existing: Option<&str>) -> Result<Option<std::path::PathBuf>, String> {
    let body = toml::to_string_pretty(root).map_err(|e| e.to_string())?;
    let header = t("# 由 `seagent setup` 產生；所有選項見 docs/config-example.toml\n\n", "# Written by `seagent setup`; every option is in docs/config-example.toml\n\n");
    let backup = cfg_path.with_extension(format!("toml.bak.{}", seagent_kernel::util::random_hex(4)));
    if existing.is_some() {
        std::fs::copy(cfg_path, &backup).map_err(|e| e.to_string())?;
    }
    let text = if existing.is_some_and(|s| s.starts_with("# ")) { body } else { format!("{header}{body}") };
    std::fs::write(cfg_path, text).map_err(|e| e.to_string())?;
    if let Err(e) = Config::load(Some(cfg_path), None, &[]) {
        if existing.is_some() {
            let _ = std::fs::copy(&backup, cfg_path);
        } else {
            let _ = std::fs::remove_file(cfg_path);
        }
        return Err(format!("{}: {e}", t("新設定無法通過檢查，已還原", "the new config failed validation and was rolled back")));
    }
    Ok(existing.is_some().then_some(backup))
}

pub fn run(paths: &Paths) -> Result<i32, String> {
    let mut io = Io::new();
    std::fs::create_dir_all(&paths.config_dir).map_err(|e| e.to_string())?;
    // Security note + importing another agent's setup (before the config is read).
    if !crate::ops::wizard::pre(&mut io, paths)? {
        return Ok(1);
    }
    let vault = Vault::load(&paths.secrets())?;
    let cfg_path = paths.user_config();
    let existing = std::fs::read_to_string(&cfg_path).ok();
    let mut root: toml::Table = match &existing {
        Some(s) => s.parse().map_err(|e| format!("{}: {e}", cfg_path.display()))?,
        None => toml::Table::new(),
    };
    let current_model = root.get("model").and_then(|m| m.get("default")).and_then(|d| d.as_str()).map(String::from);

    io.say(&format!("\n✦ seagent setup — {}\n", t("首次設定精靈", "first-run setup")));
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
            ProviderConfig { id, format: WireFormat::OpenAiChat, base_url: base, api_key_env: needs_key.then_some(env), ..Default::default() }
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

    // ── 2. auth: the provider's login flow, or a key + model list (the list call doubles as
    // the key check). OpenClaw `setup.model-auth.ts` offers both.
    let mut logged_in = false;
    if let Some(flow) = crate::ops::wizard::oauth_flow(&prov) {
        io.say(&format!("\n{}", t("② 登入", "② Sign in")));
        io.say(&format!("  {} `seagent login {flow}`", t("這個供應商支援用瀏覽器登入，不必手動貼金鑰：", "This provider can sign you in with a browser instead of a pasted key:")));
        if io.yes(&format!("  {}", t("現在登入？", "Sign in now?")), true)? {
            match crate::models_cli::inline_login(flow, paths) {
                Ok(msg) => {
                    io.say(&format!("  {msg}"));
                    logged_in = true;
                }
                Err(e) => io.say(&format!("  ✗ {e}\n  {}", t("改用手動貼金鑰", "falling back to a pasted key"))),
            }
        }
    }
    let mut key: Option<String> = None;
    let mut models: Vec<String> = vec![];
    if logged_in {
        io.say(&format!("\n{}", t("② 已登入", "② Signed in")));
        models = seagent_model::list_models(&prov, None).unwrap_or_default();
    } else if let Some(env) = prov.api_key_env.clone() {
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
                match seagent_model::auth::clean_key(&k) {
                    Ok(k) => key = Some(k),
                    Err(e) => {
                        io.say(&format!("  ✗ {}{}{e}", t("金鑰格式不對，請重新貼上", "that key is malformed; paste it again"), colon()));
                        if attempt == 2 {
                            return Err(t("金鑰格式錯誤三次", "malformed key three times").into());
                        }
                        continue;
                    }
                }
            }
            io.say(t("  驗證中…", "  checking…"));
            match seagent_model::list_models(&prov, key.as_deref()) {
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
        match seagent_model::list_models(&prov, None) {
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
    let probe = seagent_model::build(&pc).and_then(|p| {
        let req = seagent_core::ModelRequest { model: model.clone(), system: vec![], messages: vec![seagent_core::Message::user("Reply with exactly: pong")], tools: vec![], max_tokens: 256, temperature: None, cache_after_message: None, reasoning: None, options: Default::default() };
        let t0 = Instant::now();
        p.complete(&req, &mut |_| {}, &seagent_core::Cancel::new().with_deadline(Instant::now() + Duration::from_secs(60))).map(|r| (t0.elapsed(), r.message.text())).map_err(|e| e.to_string())
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

    // ── 4b. web search provider ──
    // Upstream's own numbered section; no number here so the later shared steps keep theirs.
    io.say(&format!("\n{}", t("✦ 網頁搜尋（web_search）", "✦ Web search")));
    io.say(t("  Web search 讓 agent 上網查資料。有些供應商需要 API key，有些無需 key。", "  Web search lets your agent look things up online. Some providers need an API key, and some work key-free."));
    let has_var = |v: &str| std::env::var(v).is_ok_and(|x| !x.trim().is_empty()) || vault.names().iter().any(|n| n == v);
    let sopts = search_options(has_var);
    let mut slabels: Vec<String> = sopts
        .iter()
        .map(|o| {
            let hint = if o.keyless {
                t("無需 key", "key-free").to_string()
            } else if o.configured {
                t("已設定", "configured").to_string()
            } else if o.credential_is_url {
                t("需要伺服器位址", "server address required").to_string()
            } else {
                t("需要 API key", "API key required").to_string()
            };
            format!("{}{}", o.label, paren(&hint))
        })
        .collect();
    slabels.push(t("先跳過（之後用 `seagent web providers` 檢視、`seagent config set` 設定）", "Skip for now (see `seagent web providers` later, set it with `seagent config set`)").into());
    let cur_search = root.get("web").and_then(|w| w.get("search")).and_then(|s| s.get("provider")).and_then(|p| p.as_str()).map(String::from);
    // Upstream `preserveDisabledState`: a `[web.search] enabled = false` the operator wrote stays
    // off even though picking a provider normally switches search on.
    let search_off = root.get("web").and_then(|w| w.get("search")).and_then(|s| s.get("enabled")).and_then(|e| e.as_bool()) == Some(false);
    let sdefault = cur_search
        .as_deref()
        .and_then(|id| sopts.iter().position(|o| o.id == id))
        .or_else(|| sopts.iter().position(|o| o.configured && !o.keyless))
        .unwrap_or(sopts.len());
    let spick = io.choose(t("編號", "Number"), &slabels, sdefault)?;
    if spick == sopts.len() {
        io.say(t("  略過；web_search 會用自動偵測（或免 key 後援）", "  Skipped; web_search keeps autodetecting (with the key-free fallback)"));
    } else {
        let o = &sopts[spick];
        let answer = match o.credential {
            None => String::new(),
            Some(var) if o.credential_is_url => io.ask(&format!("  {var}{}SearXNG {}", colon(), t("伺服器位址", "server address")), "")?,
            Some(var) => {
                if o.configured {
                    io.say(&format!("  {var} {}{}{}", t("已設定", "is set"), colon(), t("按 Enter 沿用", "press Enter to keep it")));
                }
                io.secret(&format!("  {var}"))?
            }
        };
        let sw = search_write(o, &answer);
        if let Some((name, value)) = &sw.secret {
            vault.set(name, value)?;
            io.say(&format!("  {} {name}", t("已存入保管庫：", "Stored in vault:")));
        }
        apply_search_keeping_disabled(&mut root, &sw, search_off);
        if search_off {
            io.say(t("  web_search 原本就是停用（enabled = false），維持停用", "  web_search was already switched off (enabled = false); keeping it off"));
        }
        if sw.missing_credential {
            io.say(&format!("  ! {}", t("沒有金鑰，web_search 在金鑰可用前不會運作（已寫入 enabled = false）", "No key stored — web_search won't work until a key is available (wrote enabled = false)")));
            if !o.signup_url.is_empty() {
                io.say(&format!("  {}{}", t("取得金鑰：", "Get your key at: "), o.signup_url));
            }
        } else {
            io.say(&format!("  ✓ {}{}{}", t("已選擇", "Selected"), colon(), o.label));
            // A live check, skipped for key-free providers (nothing to prove about a credential).
            if !o.keyless && io.yes(t("  現在試搜一次？", "  Try one search now?"), true)? {
                io.say(t("  搜尋中…", "  searching…"));
                let probe_web = root.get("web").and_then(|w| w.as_table()).cloned().unwrap_or_default();
                match crate::web_cli::search_once(&probe_web, paths, "seagent setup web search check", 3) {
                    Ok(v) => {
                        let n = v["results"].as_array().map(|r| r.len()).unwrap_or(0);
                        let first = v["results"][0]["title"].as_str().or_else(|| v["answer"].as_str()).unwrap_or("");
                        io.say(&format!("  ✓ {} {} — {}", t("搜尋成功", "search works"), paren(&format!("{} {}", n, t("筆結果", "results"))), crate::term::one_line(first, 50)));
                    }
                    Err(e) => io.say(&format!("  ✗ {e}\n  {}", t("仍會儲存設定；可用 `seagent web test` 再試", "the setup is still saved; retry with `seagent web test`"))),
                }
            }
        }
    }

    // ── 5. web UI ──
    io.say(&format!("\n{}", t("④ 網頁介面", "④ Web UI")));
    let app_on = root.get("app").and_then(|a| a.get("enabled")).and_then(|v| v.as_bool()).unwrap_or(false);
    let web = io.yes(t("  啟用網頁介面（瀏覽器聊天、管理工作階段）？", "  Turn on the web UI (chat and sessions in a browser)?"), true)?;
    // Gateway config + auth (OpenClaw `setup.gateway-config.ts`): the token is a vault reference;
    // the wizard only mints the secret when the install has none.
    let have_token = vault.names().iter().any(|n| n == "APP_TOKEN");
    if let Some(secret) = crate::ops::wizard::gateway_config(&mut root, web || app_on, have_token) {
        vault.set(secret, &seagent_net::crypto::random_token(24))?;
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
                // Secret references + `dm_policy = "pairing"` (ops/wizard.rs::add_channel).
                channel_added = Some(crate::ops::wizard::add_channel(&mut root, kind)?);
            }
        }
    }

    // ── 6b. owner = approver = admin (setup_server.rs) ──
    let mut owner_set = false;
    if let Some(n) = &channel_added {
        let kind = root.get("channels").and_then(|c| c.get(n)).and_then(|c| c.get("kind")).and_then(|k| k.as_str()).unwrap_or("telegram").to_string();
        owner_set = crate::setup_server::owner_step(&mut io, &mut root, n, &kind)?.is_some();
    }
    // ── 6c. professional role (role_cli.rs): an occupation for the default agent ──
    io.say(&format!("\n{}", t("✦ 職業角色（之後可用 `seagent role use` 更改）", "✦ Professional role (change it later with `seagent role use`)")));
    let rows = crate::role_cli::setup_choices(zh());
    let cur_role = root.get("role").and_then(|r| r.get("active")).and_then(|v| v.as_str()).map(String::from);
    let rdefault = cur_role.as_deref().and_then(|c| rows.iter().position(|r| r.1.as_deref() == Some(c))).unwrap_or(0);
    let mut rpick = rows[io.choose(t("編號", "Number"), &rows.iter().map(|r| r.0.clone()).collect::<Vec<_>>(), rdefault)?].1.clone();
    if rpick.as_deref() == Some("") {
        let words = io.ask(t("  ISCO 代碼或職業名稱", "  ISCO code or occupation"), cur_role.as_deref().unwrap_or(""))?;
        let cfg_now = Config::load(None, None, &[]).unwrap_or_default();
        rpick = crate::role_cli::pick(&cfg_now, &words).unwrap_or_else(|e| {
            io.say(&format!("  ! {e}\n  {}", t("略過；之後可用 `seagent role use` 設定", "skipped; set it later with `seagent role use`")));
            None
        });
    }
    crate::role_cli::setup_apply(&mut root, rpick.as_deref());

    // Default workspace + official connectors (ops/wizard.rs).
    crate::ops::wizard::mid(&mut io, &mut root, paths)?;

    // ── 7. write, validate, roll back on error ──
    table(&mut root, "model").insert("default".into(), full.clone().into());
    if let Some(tb) = custom {
        let provs = table(&mut root, "providers");
        let entry = table(provs, &prov.id);
        for (k, v) in tb {
            entry.insert(k, v);
        }
    }
    let backup = save_config(&cfg_path, &root, existing.as_deref())?;

    io.say(&format!("\n✓ {} {}", t("已寫入", "Wrote"), cfg_path.display()));
    if let Some(backup) = &backup {
        io.say(&format!("  {} {}", t("原檔備份：", "Backup:"), backup.display()));
    }
    let app_ws = root.get("app").and_then(|a| a.get("workspace")).and_then(|v| v.as_str()).map(std::path::PathBuf::from).unwrap_or_else(|| paths.default_workspace());
    crate::ops::wizard::post(&mut io, web || channel_added.is_some(), &app_ws)?;
    io.say(&format!("\n{}", t("接下來：", "Next:")));
    io.say(&format!("  seagent chat                      {}", t("在終端機對話", "talk in the terminal")));
    io.say(&format!("  seagent run \"…\"                   {}", t("交辦一件事", "hand it one task")));
    if web || channel_added.is_some() {
        io.say(&format!("  seagent daemon start              {}", t("啟動背景服務（網頁介面與聊天平台需要）", "start the background service (the web UI and chat platforms need it)")));
        io.say(&format!("  seagent service install           {}", t("改用 systemd 開機自動啟動（含沙箱設定）", "or run it under systemd at login (hardened unit)")));
    }
    if web {
        io.say(&format!("  seagent app open                  {}", t("開啟網頁介面", "open the web UI")));
    }
    if let Some(n) = channel_added {
        if owner_set {
            io.say(&format!("  {}", t("擁有者可直接私訊機器人；其他人先收到配對碼：", "the owner can message the bot right away; anyone else gets a pairing code:")));
        }
        io.say(&format!("  seagent pairing approve {n} <code>   {}", t("核准第一次私訊你的人（對方會收到配對碼）", "approve whoever messages first (they receive a pairing code)")));
    }
    io.say(&format!("  seagent doctor                    {}", t("檢查環境", "check everything")));
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

    /// The search step's decision logic, with no terminal: what we ask for and what we write.
    #[test]
    fn search_step_options_and_writes() {
        let opts = search_options(|v| v == "BRAVE_API_KEY");
        let by = |id: &str| opts.iter().find(|o| o.id == id).expect(id).clone();
        assert_eq!(by("brave").credential, Some("BRAVE_API_KEY"));
        assert!(by("brave").configured && !by("brave").keyless);
        assert_eq!((by("tavily").credential, by("tavily").configured), (Some("TAVILY_API_KEY"), false));
        assert!(by("searxng").credential_is_url && by("searxng").credential == Some("SEARXNG_BASE_URL"));
        assert!(by("duckduckgo").keyless && by("duckduckgo").credential.is_none(), "the keyless endpoint asks nothing");
        assert!(by("ollama").keyless, "a local server needs no key");
        assert!(by("exa").keyless, "keyless ring members ask nothing");

        // A typed key is stored in the vault; the config only carries the placeholder.
        let w = search_write(&by("brave"), "  bk-123  ");
        assert!(w.enabled && !w.missing_credential);
        assert_eq!(w.secret, Some(("BRAVE_API_KEY", "bk-123".to_string())));
        assert_eq!(w.provider_entry, Some(("api_key", "{{secret:BRAVE_API_KEY}}".to_string())));
        let mut root: toml::Table = "".parse().unwrap();
        apply_search(&mut root, &w);
        assert_eq!(root["web"]["search"]["provider"].as_str(), Some("brave"));
        assert_eq!(root["web"]["search"]["enabled"].as_bool(), Some(true));
        assert_eq!(root["web"]["providers"]["brave"]["api_key"].as_str(), Some("{{secret:BRAVE_API_KEY}}"));
        let web: seagent_tools::web::WebConfig = seagent_tools::web::WebConfig::from_value(serde_json::to_value(&root["web"]).unwrap()).expect("[web] parses");
        assert_eq!((web.search.provider.as_str(), web.search.enabled), ("brave", true));

        // Key-free provider: enabled, nothing else written.
        let w = search_write(&by("duckduckgo"), "");
        assert!(w.enabled && w.secret.is_none() && w.provider_entry.is_none());
        // SearXNG asks for a server address, never a secret.
        let w = search_write(&by("searxng"), "http://127.0.0.1:8080");
        assert!(w.secret.is_none());
        assert_eq!(w.provider_entry, Some(("base_url", "http://127.0.0.1:8080".to_string())));
        // Nothing available anywhere: provider pinned but disabled (upstream's behaviour).
        let none = search_options(|_| false);
        let tavily = none.iter().find(|o| o.id == "tavily").unwrap();
        let w = search_write(tavily, "");
        assert!(!w.enabled && w.missing_credential && w.secret.is_none());
        // An empty answer with the key already in the environment keeps working.
        let env = search_options(|v| v == "TAVILY_API_KEY");
        let w = search_write(env.iter().find(|o| o.id == "tavily").unwrap(), "");
        assert!(w.enabled && !w.missing_credential && w.secret.is_none() && w.provider_entry.is_none());
        // Writing keeps the rest of `[web]` intact.
        let mut root: toml::Table = "[web]\ncache_enabled = false\n[web.search]\nprovider = \"exa\"\nmax_results = 7\n".parse().unwrap();
        apply_search(&mut root, &search_write(&by("tavily"), "tk"));
        assert_eq!(root["web"]["cache_enabled"].as_bool(), Some(false));
        assert_eq!(root["web"]["search"]["max_results"].as_integer(), Some(7));
        assert_eq!(root["web"]["search"]["provider"].as_str(), Some("tavily"));
    }

    /// The menu is the upstream order (label, then id) and a disabled search stays disabled.
    #[test]
    fn search_step_menu_order_and_preserved_disabled_state() {
        let opts = search_options(|_| false);
        let labels: Vec<String> = opts.iter().map(|o| o.label.to_lowercase()).collect();
        let mut sorted = labels.clone();
        sorted.sort();
        assert_eq!(labels, sorted, "the provider menu is sorted by label");
        assert_eq!(opts.len(), seagent_tools::web::providers::all().len(), "every provider is offered exactly once");
        assert_eq!(opts.iter().find(|o| o.id == "brave").unwrap().signup_url, "https://brave.com/search/api/");

        // Upstream `preserveDisabledState`: picking a provider keeps a written `enabled = false`.
        let by = |id: &str| opts.iter().find(|o| o.id == id).expect(id).clone();
        let mut root: toml::Table = "[web.search]\nenabled = false\nprovider = \"exa\"\n".parse().unwrap();
        apply_search_keeping_disabled(&mut root, &search_write(&by("tavily"), "tk"), true);
        assert_eq!(root["web"]["search"]["provider"].as_str(), Some("tavily"));
        assert_eq!(root["web"]["search"]["enabled"].as_bool(), Some(false), "a disabled search stays disabled");
        assert_eq!(root["web"]["providers"]["tavily"]["api_key"].as_str(), Some("{{secret:TAVILY_API_KEY}}"));
        // Without a prior `enabled = false` the selection switches search on, as upstream does.
        let mut root: toml::Table = "".parse().unwrap();
        apply_search_keeping_disabled(&mut root, &search_write(&by("tavily"), "tk"), false);
        assert_eq!(root["web"]["search"]["enabled"].as_bool(), Some(true));
    }

    /// What the wizard writes is what `seagent web` reads: the pin resolves to the chosen provider.
    #[test]
    fn search_step_writes_a_route_the_cli_uses() {
        let mut root: toml::Table = "".parse().unwrap();
        let opts = search_options(|_| false);
        let brave = opts.iter().find(|o| o.id == "brave").unwrap();
        apply_search(&mut root, &search_write(brave, "bk-123"));
        let st = crate::web_cli::status(root["web"].as_table().expect("[web] is a table"), Some(std::sync::Arc::new(|_: &str| None)), None);
        assert_eq!(st["route"].as_str(), Some("brave"), "{st}");
        assert_eq!(st["error"], Value::Null);

        // SearXNG asks for a server address; it lands as `[web.providers.searxng] base_url`.
        let mut root: toml::Table = "".parse().unwrap();
        let searx = opts.iter().find(|o| o.id == "searxng").unwrap();
        apply_search(&mut root, &search_write(searx, "http://127.0.0.1:8080"));
        assert_eq!(root["web"]["providers"]["searxng"]["base_url"].as_str(), Some("http://127.0.0.1:8080"));
        let st = crate::web_cli::status(root["web"].as_table().expect("[web] is a table"), Some(std::sync::Arc::new(|_: &str| None)), None);
        assert_eq!(st["route"].as_str(), Some("searxng"), "{st}");
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
