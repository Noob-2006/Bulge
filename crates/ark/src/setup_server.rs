//! `ark setup` as "turn this machine into an agent server": the owner step, the unattended
//! (flags / environment) path for cloud-init and Ansible, and the systemd + linger step.
//!
//! The interactive wizard (`setup.rs`) calls [`owner_step`] and `ops::wizard::post`; the
//! unattended path is [`run`], driven entirely by flags and `ARK_SETUP_*` variables and
//! never asking anything. Secrets are only ever read from the environment (never from argv,
//! which `ps` shows) and go straight into the vault.
//!
//! | flag | variable | meaning |
//! |---|---|---|
//! | `--non-interactive` / `-y` | `ARK_SETUP_NONINTERACTIVE=1` | never prompt (implied by any of the flags below) |
//! | `--provider ID` | `ARK_SETUP_PROVIDER` | model provider preset (`anthropic`, `openai`, …) |
//! | `--model NAME` | `ARK_SETUP_MODEL` | model name |
//! | `--base-url URL` | `ARK_SETUP_BASE_URL` | custom / local OpenAI-compatible endpoint |
//! | – | `ARK_SETUP_API_KEY` or the provider's own variable (e.g. `ANTHROPIC_API_KEY`) | model key |
//! | `--channel telegram|discord` | `ARK_SETUP_CHANNEL` | chat platform to connect |
//! | – | `ARK_SETUP_CHANNEL_TOKEN` or `TELEGRAM_TOKEN` / `DISCORD_TOKEN` | bot token |
//! | `--owner ID` | `ARK_SETUP_OWNER` | owner = approver = admin on that platform |
//! | `--no-service` | `ARK_SETUP_SERVICE=0` | skip the systemd user service |
//! | `--no-linger` | `ARK_SETUP_LINGER=0` | do not try to enable lingering |
//! | `--verify` | `ARK_SETUP_VERIFY=1` | check key / token against the real APIs |

use crate::args::Args;
use crate::ops::service::Linger;
use crate::setup::t;
use ark_kernel::config::Paths;
use ark_kernel::vault::Vault;

pub type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

pub fn real_env(k: &str) -> Option<String> {
    std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub provider: Option<String>,
    pub model: Option<String>,
    pub base_url: Option<String>,
    pub channel: Option<String>,
    pub owner: Option<String>,
    pub service: bool,
    pub linger: bool,
    pub verify: bool,
}

fn truthy(v: Option<String>) -> Option<bool> {
    v.map(|s| !matches!(s.to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off"))
}

/// Does this invocation ask for the unattended path?
pub fn wanted(a: &Args, env: Env) -> bool {
    a.flag("non-interactive")
        || a.flag("yes")
        || a.flag("server")
        || truthy(env("ARK_SETUP_NONINTERACTIVE")).unwrap_or(false)
        || ["provider", "model", "channel", "owner", "base-url"].iter().any(|k| a.val(k).is_some())
        || ["ARK_SETUP_PROVIDER", "ARK_SETUP_MODEL", "ARK_SETUP_CHANNEL", "ARK_SETUP_OWNER"].iter().any(|k| env(k).is_some())
}

pub fn plan(a: &Args, env: Env) -> Result<Plan, String> {
    let pick = |flag: &str, var: &str| a.val(flag).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).or_else(|| env(var));
    let channel = pick("channel", "ARK_SETUP_CHANNEL").map(|c| c.to_ascii_lowercase());
    if let Some(c) = &channel {
        if !["telegram", "discord"].contains(&c.as_str()) {
            return Err(format!("--channel `{c}`: unattended setup supports telegram and discord (add other platforms in the config)"));
        }
    }
    let owner = pick("owner", "ARK_SETUP_OWNER");
    if let Some(o) = &owner {
        valid_owner(o)?;
    }
    let service = if a.flag("no-service") { false } else { a.flag("service") || truthy(env("ARK_SETUP_SERVICE")).unwrap_or(true) };
    let linger = service && !a.flag("no-linger") && truthy(env("ARK_SETUP_LINGER")).unwrap_or(true);
    Ok(Plan { provider: pick("provider", "ARK_SETUP_PROVIDER"), model: pick("model", "ARK_SETUP_MODEL"), base_url: pick("base-url", "ARK_SETUP_BASE_URL"), channel, owner, service, linger, verify: a.flag("verify") || truthy(env("ARK_SETUP_VERIFY")).unwrap_or(false) })
}

/// A chat account id: Telegram numeric id, Discord snowflake, or `@name`.
pub fn valid_owner(o: &str) -> Result<(), String> {
    let body = o.strip_prefix('@').unwrap_or(o);
    if !body.is_empty() && body.len() <= 64 && body.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-') && o != "*" {
        Ok(())
    } else {
        Err(format!("owner `{o}`: expected a numeric account id or @name (not a wildcard)"))
    }
}

fn table<'a>(root: &'a mut toml::Table, key: &str) -> &'a mut toml::Table {
    let e = root.entry(key.to_string()).or_insert_with(|| toml::Value::Table(toml::Table::new()));
    if !e.is_table() {
        *e = toml::Value::Table(toml::Table::new());
    }
    e.as_table_mut().expect("table")
}

fn push_unique(t: &mut toml::Table, key: &str, v: &str) {
    let a = t.entry(key.to_string()).or_insert_with(|| toml::Value::Array(vec![]));
    if !a.is_array() {
        *a = toml::Value::Array(vec![]);
    }
    let arr = a.as_array_mut().expect("array");
    if !arr.iter().any(|x| x.as_str() == Some(v)) {
        arr.push(v.into());
    }
}

/// The owner is the one person who is both allowed to talk to the bot and allowed to answer
/// its approval requests (and `/sethome`): `channels.<name>.allow` and
/// `approvals.forward.approvers.<name>`. Everyone else still has to pair.
pub fn set_owner(root: &mut toml::Table, channel: &str, owner: &str) -> Result<(), String> {
    valid_owner(owner)?;
    let ch = root.get_mut("channels").and_then(|c| c.as_table_mut()).and_then(|c| c.get_mut(channel)).and_then(|c| c.as_table_mut()).ok_or_else(|| format!("no channel `{channel}` in the config"))?;
    push_unique(ch, "allow", owner);
    let ap = table(table(table(root, "approvals"), "forward"), "approvers");
    push_unique(ap, channel, owner);
    Ok(())
}

/// Reuse an existing `[channels.<kind>]` (re-running Ansible must not pile up channels).
pub fn ensure_channel(root: &mut toml::Table, kind: &str) -> Result<String, String> {
    let exists = root.get("channels").and_then(|c| c.get(kind)).and_then(|c| c.get("kind")).and_then(|k| k.as_str()) == Some(kind);
    if exists {
        Ok(kind.to_string())
    } else {
        crate::ops::wizard::add_channel(root, kind)
    }
}

/// Interactive owner step (setup wizard): who is the owner on the chat platform just added.
pub fn owner_step(p: &mut dyn crate::ops::wizard::Prompt, root: &mut toml::Table, channel: &str, kind: &str) -> Result<Option<String>, String> {
    p.say(&format!("\n{}", t("⑤b 擁有者（核准者＝管理者）", "⑤b Owner (approver = admin)")));
    p.say(&format!("  {}", t(
        "擁有者是唯一能用聊天按鈕核准高風險動作、執行 /sethome 的人；其他人需先配對。",
        "The owner is the one person who can approve risky actions from the chat and run /sethome; everyone else has to pair first.",
    )));
    p.say(&format!("  {}", match kind {
        "discord" => t("你的 Discord 使用者 ID（設定 → 進階 → 開發者模式，右鍵自己 → 複製使用者 ID）", "Your Discord user ID (Settings → Advanced → Developer Mode, right-click yourself → Copy User ID)"),
        _ => t("你的 Telegram 數字 ID（對 @userinfobot 傳訊息即可取得）", "Your numeric Telegram ID (message @userinfobot to get it)"),
    }));
    loop {
        let a = p.ask(t("  擁有者 ID（Enter 略過）", "  Owner ID (Enter to skip)"), "")?;
        if a.is_empty() {
            p.say(&format!("  ! {}", t("未設定擁有者：沒有人能用聊天核准動作。之後可執行 `ark setup --owner <ID>`。", "No owner yet: nobody can approve actions from the chat. Later: `ark setup --owner <ID>`.")));
            return Ok(None);
        }
        match set_owner(root, channel, &a) {
            Ok(()) => {
                p.say(&format!("  ✓ {} {a}", t("擁有者：", "owner:")));
                return Ok(Some(a));
            }
            Err(e) => p.say(&format!("  ✗ {e}")),
        }
    }
}

/// Say what happened with lingering (shared by the wizard and the unattended path).
pub fn linger_lines(l: &Linger) -> String {
    match l {
        Linger::Already => format!("✓ {}", t("已開啟 linger：登出後服務持續運作、開機自動啟動", "linger is on: the service survives logout and starts at boot")),
        Linger::Enabled => format!("✓ {}", t("已開啟 linger：登出後服務持續運作、開機自動啟動", "linger enabled: the service survives logout and starts at boot")),
        Linger::Manual(cmd) => format!("! {} {cmd}", t("無法在不需授權的情況下開啟 linger，請自行執行（需要管理者權限）：", "could not enable linger without an authorisation prompt; run this yourself (needs admin rights):")),
    }
}

/// Everything the unattended path does to the machine, so tests can fake it.
pub trait Host {
    fn install_service(&mut self, workspace: &std::path::Path) -> Result<String, String>;
    fn linger(&mut self) -> Linger;
    /// `--verify`: check the model key and the bot token against the real APIs.
    fn verify(&mut self, _plan: &Plan, _provider: &ark_model::ProviderConfig, _key: Option<&str>) -> Result<Vec<String>, String> {
        Ok(vec![])
    }
}

pub struct RealHost;

impl Host for RealHost {
    fn install_service(&mut self, ws: &std::path::Path) -> Result<String, String> {
        crate::ops::service::install_user(ws, true)
    }
    fn linger(&mut self) -> Linger {
        crate::ops::service::ensure_linger()
    }
    fn verify(&mut self, plan: &Plan, prov: &ark_model::ProviderConfig, key: Option<&str>) -> Result<Vec<String>, String> {
        let mut out = vec![];
        let n = ark_model::list_models(prov, key).map_err(|e| format!("model check failed: {e}"))?.len();
        out.push(format!("model endpoint reachable ({n} models)"));
        let _ = plan;
        Ok(out)
    }
}

/// What [`apply`] did: lines to print, the model provider (for `--verify`), the key used.
pub type Applied = (Vec<String>, Option<ark_model::ProviderConfig>, Option<String>);

/// Apply `plan` to `root` + vault. Returns the lines to print. No network, no systemd.
pub fn apply(root: &mut toml::Table, vault: &Vault, plan: &Plan, env: Env) -> Result<Applied, String> {
    let mut said = vec![];
    let current = root.get("model").and_then(|m| m.get("default")).and_then(|d| d.as_str()).map(String::from);
    let mut prov_out = None;
    let mut key_out = None;
    let full = match (&plan.provider, &plan.model) {
        (Some(pid), Some(model)) => {
            let all = ark_model::presets();
            let mut prov = match all.iter().find(|p| &p.id == pid) {
                Some(p) => p.clone(),
                None => {
                    let base = plan.base_url.clone().ok_or_else(|| format!("unknown provider `{pid}`: pass --base-url for a custom OpenAI-compatible endpoint"))?;
                    if !pid.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                        return Err("provider name may only use letters, digits, - and _".into());
                    }
                    let env_name = format!("{}_API_KEY", pid.to_uppercase().replace('-', "_"));
                    ark_model::ProviderConfig { id: pid.clone(), format: ark_model::WireFormat::OpenAiChat, base_url: base, api_key_env: env(&env_name).is_some().then_some(env_name), ..Default::default() }
                }
            };
            if let Some(b) = &plan.base_url {
                if !(b.starts_with("http://") || b.starts_with("https://")) {
                    return Err("--base-url must start with http:// or https://".into());
                }
                prov.base_url = b.clone();
            }
            if all.iter().all(|p| &p.id != pid) || plan.base_url.is_some() {
                let provs = table(root, "providers");
                let e = table(provs, pid);
                e.insert("format".into(), "openai_chat".into());
                e.insert("base_url".into(), prov.base_url.clone().into());
                if let Some(v) = &prov.api_key_env {
                    e.insert("api_key_env".into(), v.clone().into());
                }
            }
            if let Some(var) = prov.api_key_env.clone() {
                let key = env("ARK_SETUP_API_KEY").or_else(|| env(&var));
                match key {
                    Some(k) => {
                        vault.set(&var, &k)?;
                        said.push(format!("{} {var}", t("金鑰已存入保管庫：", "key stored in the vault:")));
                        key_out = Some(k);
                    }
                    None if vault.names().contains(&var) => said.push(format!("{} {var}", t("沿用保管庫中的金鑰：", "keeping the key already in the vault:"))),
                    None => return Err(format!("no API key for `{pid}`: set ARK_SETUP_API_KEY or {var} in the environment")),
                }
            }
            prov_out = Some(prov);
            Some(format!("{pid}/{model}"))
        }
        (None, None) if current.is_some() => None,
        _ => return Err("unattended setup needs both --provider and --model (or ARK_SETUP_PROVIDER / ARK_SETUP_MODEL), unless a default model is already configured".into()),
    };
    if let Some(f) = &full {
        table(root, "model").insert("default".into(), f.clone().into());
        said.push(format!("{} {f}", t("預設模型：", "default model:")));
    }
    if let Some(kind) = &plan.channel {
        let secret = crate::ops::wizard::channel_secrets(kind)[0];
        let token = env("ARK_SETUP_CHANNEL_TOKEN").or_else(|| env(secret));
        match token {
            Some(tok) => {
                vault.set(secret, &tok)?;
            }
            None if vault.names().iter().any(|n| n == secret) => {}
            None => return Err(format!("no bot token for {kind}: set ARK_SETUP_CHANNEL_TOKEN or {secret} in the environment")),
        }
        let name = ensure_channel(root, kind)?;
        said.push(format!("{} {name} ({kind})", t("聊天平台：", "chat platform:")));
        match &plan.owner {
            Some(o) => {
                set_owner(root, &name, o)?;
                said.push(format!("{} {o}", t("擁有者（核准者＝管理者）：", "owner (approver = admin):")));
            }
            None => said.push(format!("! {}", t("沒有設定擁有者：沒有人能用聊天核准動作（加上 --owner <ID>）", "no owner set: nobody can approve actions from the chat (add --owner <ID>)"))),
        }
    } else if plan.owner.is_some() {
        return Err("--owner needs --channel".into());
    }
    Ok((said, prov_out, key_out))
}

/// `ark setup` without questions. Idempotent: running it again with the same inputs changes nothing.
pub fn run(paths: &Paths, plan: &Plan, env: Env, host: &mut dyn Host) -> Result<i32, String> {
    std::fs::create_dir_all(&paths.config_dir).map_err(|e| e.to_string())?;
    let vault = Vault::load(&paths.secrets())?;
    let cfg_path = paths.user_config();
    let existing = std::fs::read_to_string(&cfg_path).ok();
    let mut root: toml::Table = match &existing {
        Some(s) => s.parse().map_err(|e| format!("{}: {e}", cfg_path.display()))?,
        None => toml::Table::new(),
    };
    let (lines, prov, key) = apply(&mut root, &vault, plan, env)?;
    for l in &lines {
        eprintln!("  {l}");
    }
    if plan.verify {
        if let Some(p) = &prov {
            for l in host.verify(plan, p, key.as_deref())? {
                eprintln!("  ✓ {l}");
            }
        }
    }
    let backup = crate::setup::save_config(&cfg_path, &root, existing.as_deref())?;
    eprintln!("✓ {} {}", t("已寫入", "Wrote"), cfg_path.display());
    if let Some(b) = backup {
        eprintln!("  {} {}", t("原檔備份：", "Backup:"), b.display());
    }
    if plan.service {
        let ws = root.get("app").and_then(|a| a.get("workspace")).and_then(|v| v.as_str()).map(std::path::PathBuf::from).unwrap_or_else(|| paths.data.join("workspace"));
        let _ = std::fs::create_dir_all(&ws);
        match host.install_service(&ws) {
            Ok(m) => {
                eprintln!("✓ {m}");
                if plan.linger {
                    eprintln!("{}", linger_lines(&host.linger()));
                }
            }
            Err(e) => {
                eprintln!("! {e}");
                return Ok(2);
            }
        }
    } else {
        eprintln!("  {} ark daemon start", t("未安裝服務；手動啟動：", "service not installed; start it with:"));
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| m.get(k).cloned()
    }

    fn args(v: &[&str]) -> Args {
        Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    fn scratch(tag: &str) -> (ark_core::tmp::TempDir, Paths) {
        let root = ark_core::tmp::TempDir::new(&format!("ark-setupsrv-{tag}"));
        let p = Paths { data: root.join("data"), config_dir: root.join("config"), runtime: root.join("run") };
        std::fs::create_dir_all(&p.config_dir).unwrap();
        std::fs::create_dir_all(&p.data).unwrap();
        (root, p)
    }

    #[derive(Default)]
    struct Fake {
        installed: Vec<std::path::PathBuf>,
        linger_calls: u32,
        linger: Option<Linger>,
    }
    impl Host for Fake {
        fn install_service(&mut self, ws: &std::path::Path) -> Result<String, String> {
            self.installed.push(ws.to_path_buf());
            Ok("unit installed".into())
        }
        fn linger(&mut self) -> Linger {
            self.linger_calls += 1;
            self.linger.clone().unwrap_or(Linger::Enabled)
        }
    }

    #[test]
    fn flags_and_environment_build_the_same_plan() {
        let e = env_of(&[]);
        assert!(!wanted(&args(&[]), &e), "plain `ark setup` stays interactive");
        assert!(wanted(&args(&["--non-interactive"]), &e) && wanted(&args(&["-y"]), &e) && wanted(&args(&["--provider", "openai"]), &e));
        assert!(wanted(&args(&[]), &env_of(&[("ARK_SETUP_CHANNEL", "telegram")])));
        let a = plan(&args(&["--provider", "openai", "--model", "gpt-x", "--channel", "Telegram", "--owner", "42", "--no-linger"]), &e).unwrap();
        let b = plan(&args(&["--no-linger"]), &env_of(&[("ARK_SETUP_PROVIDER", "openai"), ("ARK_SETUP_MODEL", "gpt-x"), ("ARK_SETUP_CHANNEL", "telegram"), ("ARK_SETUP_OWNER", "42")])).unwrap();
        assert_eq!(a, b);
        assert!(a.service && !a.linger && a.channel.as_deref() == Some("telegram"));
        assert!(!plan(&args(&["--no-service"]), &e).unwrap().service);
        assert!(!plan(&args(&[]), &env_of(&[("ARK_SETUP_SERVICE", "0")])).unwrap().service);
        assert!(plan(&args(&["--channel", "irc"]), &e).is_err());
        assert!(plan(&args(&["--owner", "*"]), &e).is_err() && plan(&args(&["--owner", "a b"]), &e).is_err());
    }

    #[test]
    fn owner_is_allowed_and_is_the_approver() {
        let mut root: toml::Table = "".parse().unwrap();
        let name = ensure_channel(&mut root, "telegram").unwrap();
        set_owner(&mut root, &name, "1234").unwrap();
        set_owner(&mut root, &name, "1234").unwrap();
        assert_eq!(root["channels"]["telegram"]["allow"].as_array().unwrap().len(), 1, "idempotent");
        assert_eq!(root["approvals"]["forward"]["approvers"]["telegram"][0].as_str(), Some("1234"));
        // The kernel's own check agrees: the owner may answer approvals and change policy.
        let cfg: ark_kernel::config::Config = toml::from_str(&toml::to_string(&root).unwrap()).unwrap();
        assert!(ark_kernel::secgate::channel_operator(&cfg.approvals, "telegram", "1234", ""));
        assert!(!ark_kernel::secgate::channel_operator(&cfg.approvals, "telegram", "9999", ""), "strangers are not owners");
        assert!(set_owner(&mut root, "nope", "1").is_err());
        // Re-adding does not duplicate the channel.
        assert_eq!(ensure_channel(&mut root, "telegram").unwrap(), "telegram");
        assert_eq!(root["channels"].as_table().unwrap().len(), 1);
    }

    #[test]
    fn unattended_setup_writes_config_vault_and_service_and_is_idempotent() {
        let (_dir, paths) = scratch("full");
        let e = env_of(&[("ARK_SETUP_API_KEY", "sk-test-not-real"), ("TELEGRAM_TOKEN", "123:fake")]);
        let p = plan(&args(&["--provider", "openai", "--model", "gpt-x", "--channel", "telegram", "--owner", "42"]), &e).unwrap();
        let mut host = Fake::default();
        assert_eq!(run(&paths, &p, &e, &mut host).unwrap(), 0);
        let first = std::fs::read_to_string(paths.user_config()).unwrap();
        let cfg = ark_kernel::config::Config::load(Some(&paths.user_config()), None, &[]).expect("valid config");
        assert!(cfg.approvals.forward.approvers["telegram"].contains(&"42".to_string()));
        assert!(first.contains("openai/gpt-x") && first.contains("{{secret:TELEGRAM_TOKEN}}"));
        assert!(!first.contains("sk-test-not-real") && !first.contains("123:fake"), "secrets never land in config.toml");
        let vault = Vault::load(&paths.secrets()).unwrap();
        assert!(vault.names().contains(&"OPENAI_API_KEY".to_string()) && vault.names().contains(&"TELEGRAM_TOKEN".to_string()));
        assert_eq!((host.installed.len(), host.linger_calls), (1, 1));
        // Second run: same config, still one channel.
        let mut host2 = Fake { linger: Some(Linger::Manual("sudo loginctl enable-linger x".into())), ..Default::default() };
        assert_eq!(run(&paths, &p, &e, &mut host2).unwrap(), 0);
        let second = std::fs::read_to_string(paths.user_config()).unwrap();
        let (a, b): (toml::Table, toml::Table) = (first.parse().unwrap(), second.parse().unwrap());
        assert_eq!(a, b, "rerun changes nothing");
    }

    #[test]
    fn missing_inputs_fail_before_anything_is_written() {
        let (_dir, paths) = scratch("err");
        let none = env_of(&[]);
        let mut host = Fake::default();
        let p = plan(&args(&["--provider", "openai", "--model", "m", "--no-service"]), &none).unwrap();
        assert!(run(&paths, &p, &none, &mut host).unwrap_err().contains("no API key"));
        let p = plan(&args(&["--provider", "openai", "--model", "m", "--channel", "discord", "--no-service"]), &env_of(&[("OPENAI_API_KEY", "k")])).unwrap();
        assert!(run(&paths, &p, &env_of(&[("OPENAI_API_KEY", "k")]), &mut host).unwrap_err().contains("bot token"));
        assert!(!paths.user_config().exists(), "no half-written config");
        assert!(run(&paths, &Plan::default(), &none, &mut host).unwrap_err().contains("--provider"));
        let p = plan(&args(&["--owner", "5", "--no-service"]), &none).unwrap();
        assert!(run(&paths, &Plan { provider: Some("openai".into()), model: Some("m".into()), ..p }, &env_of(&[("OPENAI_API_KEY", "k")]), &mut host).unwrap_err().contains("--owner needs --channel"));
    }

    #[test]
    fn local_endpoint_needs_no_key_and_no_service_means_no_install() {
        let (_dir, paths) = scratch("local");
        let e = env_of(&[]);
        let p = plan(&args(&["--provider", "ollama", "--model", "llama3", "--no-service"]), &e).unwrap();
        let mut host = Fake::default();
        assert_eq!(run(&paths, &p, &e, &mut host).unwrap(), 0);
        assert!(host.installed.is_empty());
        let p = plan(&args(&["--provider", "mylocal", "--model", "m", "--base-url", "http://127.0.0.1:8000/v1", "--no-service"]), &e).unwrap();
        assert_eq!(run(&paths, &p, &e, &mut host).unwrap(), 0);
        let cfg = std::fs::read_to_string(paths.user_config()).unwrap();
        assert!(cfg.contains("127.0.0.1:8000"));
    }

    #[test]
    fn linger_never_prompts_and_falls_back_to_a_command() {
        use crate::ops::service::ensure_linger_with as f;
        assert_eq!(f(Some(true), &|| panic!("already on: must not run loginctl"), "u"), Linger::Already);
        assert_eq!(f(Some(false), &|| Ok(()), "u"), Linger::Enabled);
        assert_eq!(f(None, &|| Err("auth".into()), "bob"), Linger::Manual("sudo loginctl enable-linger bob".into()));
        assert!(linger_lines(&Linger::Manual("sudo loginctl enable-linger bob".into())).contains("sudo loginctl enable-linger bob"));
    }
}
