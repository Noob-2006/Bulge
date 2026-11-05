//! Extra `ark setup` steps (OpenClaw `src/wizard/setup.*`): the security note, importing
//! another agent's setup, the default workspace, official extensions, the background service
//! and shell completion. `setup.rs` calls [`pre`] before it reads the config (an import may
//! change it), [`mid`] before it writes the config, and [`post`] after the write.

use crate::setup::t;
use ark_kernel::config::Paths;
use std::path::{Path, PathBuf};

/// The few prompt primitives the steps need (implemented by `setup.rs`'s terminal I/O).
pub trait Prompt {
    fn say(&self, s: &str);
    fn yes(&mut self, q: &str, default: bool) -> Result<bool, String>;
    fn ask(&mut self, q: &str, default: &str) -> Result<String, String>;
}

// ───────────────────────── security note ─────────────────────────

pub fn security_note() -> String {
    [
        t("ark 是開源的個人 agent，會與你一同學習成長。", "ark is an open-source personal agent that learns and grows with you."),
        t("預設情況下，ark 是供一位操作者使用的個人 agent。", "By default, ark is a personal agent for one operator."),
        t("如果啟用了工具，它可以讀取檔案並執行操作。", "If tools are enabled, it can read files and run actions."),
        t("惡意 prompt 可能誘導它執行不安全操作。", "A bad prompt can trick it into doing unsafe things."),
        "",
        t("預設情況下，ark 並非設計來安全地隔離多個使用者。", "ark is not designed to safely separate multiple users by default."),
        t("如果多個人能向同一個啟用工具的 agent 傳訊息，他們都能影響它如何使用工具。", "If several people can message the same tool-enabled agent, they can all steer how it uses those tools."),
        "",
        t("如果你不熟悉存取控制和安全加固，請在獲得協助前不要把它暴露給他人。", "If you're not comfortable managing access controls and security hardening, don't expose it to others without help."),
        t("啟用工具或暴露到網際網路之前，請找有經驗的人協助。", "Ask someone experienced to help before enabling tools or exposing it to the internet."),
        "",
        t("建議採用更安全的設定", "Recommended safer setup"),
        t("- 使用配對或允許清單；在群組聊天中要求 @ 提及。", "- Use pairing or allowlists; require mentions in group chats."),
        t("- 共享收件箱：使用獨立的 daemon 和憑證；獨立 OS 使用者或主機可提供更強隔離。", "- Shared inboxes: use separate daemons and credentials; separate OS users or hosts isolate better."),
        t("- 使用沙箱（exec.backend = bwrap／landlock／docker），並僅授予工具所需的權限。", "- Use a sandbox (exec.backend = bwrap / landlock / docker) and give tools only the permissions they need."),
        t("- 共享收件箱：每位傳訊者各自一個工作階段（session_per = \"sender\"），並盡量減少工具。", "- Shared inboxes: one session per sender (session_per = \"sender\") and minimal tools."),
        t("- 金鑰放在 secrets.toml（0600），不要放在 agent 能讀到的工作目錄裡。", "- Keep keys in secrets.toml (0600), never inside a workspace the agent can read."),
        t("- 對啟用工具或公開收件箱的 bot，使用可用的最強模型。", "- Use the strongest available model for bots with tools or shared/public inboxes."),
        "",
        t("定期執行", "Run regularly"),
        "  ark security audit --deep",
        "  ark security audit --fix",
        "  ark doctor --lint",
        "",
        t("了解更多：docs/risk-assessment.md", "Learn more: docs/risk-assessment.md"),
    ]
    .join("\n")
}

/// Show the note; `false` = the user declined and setup stops.
pub fn security_step(p: &mut dyn Prompt) -> Result<bool, String> {
    p.say(&format!("\n{}\n{}\n", t("⚠ 安全須知", "⚠ Security"), security_note()));
    p.yes(t("我理解 ark 預設面向個人使用；共享／多使用者使用需要加固。繼續？", "I understand this is personal-by-default and shared/multi-user use requires lock-down. Continue?"), false)
}

// ───────────────────────── migration import ─────────────────────────

/// Offer to import each detected agent (OpenClaw, Hermes, Claude Code, Codex). Existing ark
/// settings are kept (no overwrite). Returns what was applied.
pub fn migration_step(p: &mut dyn Prompt, paths: &Paths, found: &[(&'static str, PathBuf)]) -> Result<Vec<String>, String> {
    let mut done = vec![];
    if found.is_empty() {
        return Ok(done);
    }
    p.say(&format!("\n{}", t("偵測到其他 agent 的設定，可以匯入：", "Found other agents' setups that can be imported:")));
    for (src, path) in found {
        let acts = match crate::ops::migrate::plan(src, Some(path), &paths.data) {
            Ok(a) => a,
            Err(e) => {
                p.say(&format!("  ! {src}: {e}"));
                continue;
            }
        };
        if acts.is_empty() {
            continue;
        }
        p.say(&format!("  {src} ({}) — {} {}", path.display(), acts.len(), t("個項目", "items")));
        for a in acts.iter().take(8) {
            p.say(&format!("    {}", crate::ops::migrate::describe(a)));
        }
        if acts.len() > 8 {
            p.say(&format!("    … {}", acts.len() - 8));
        }
        if p.yes(&format!("  {} {src}?", t("現在匯入", "Import from")), true)? {
            let s = crate::ops::migrate::apply(paths, &acts, false)?;
            p.say(&format!("  ✓ {s}"));
            done.push(src.to_string());
        }
    }
    Ok(done)
}

/// Security note + migration import; `false` = stop setup.
pub fn pre(p: &mut dyn Prompt, paths: &Paths) -> Result<bool, String> {
    if !security_step(p)? {
        return Ok(false);
    }
    migration_step(p, paths, &crate::ops::migrate::detect())?;
    Ok(true)
}

// ───────────────────────── workspace ─────────────────────────

fn expand(s: &str) -> PathBuf {
    match s.strip_prefix("~/") {
        Some(r) => PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(r),
        None => PathBuf::from(s),
    }
}

/// The path, or its nearest existing ancestor, must be a directory (symlinks followed).
pub fn validate_workspace_path(dir: &Path) -> Result<(), String> {
    let mut c = if dir.is_absolute() { dir.to_path_buf() } else { std::env::current_dir().unwrap_or_default().join(dir) };
    loop {
        match std::fs::symlink_metadata(&c) {
            Ok(m) => {
                let m = if m.file_type().is_symlink() {
                    match std::fs::metadata(&c) {
                        Ok(m) => m,
                        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(format!("{} {}", c.display(), t("是循環的符號連結", "is a symlink loop"))),
                        Err(_) => return Err(format!("{} {}", c.display(), t("是指向不存在位置的符號連結", "is a symlink to a missing directory"))),
                    }
                } else {
                    m
                };
                return if m.is_dir() { Ok(()) } else { Err(format!("{} {}", c.display(), t("不是目錄", "is not a directory"))) };
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error() == Some(libc::ENOTDIR) => {}
            Err(e) => return Err(format!("{}: {e}", c.display())),
        }
        match c.parent() {
            Some(p) if p != c => c = p.to_path_buf(),
            _ => return Err(format!("{} {}", c.display(), t("不是目錄", "is not a directory"))),
        }
    }
}

/// `[app] workspace`: where sessions from the web UI and chat channels run.
pub fn workspace_step(p: &mut dyn Prompt, root: &mut toml::Table, paths: &Paths) -> Result<Option<PathBuf>, String> {
    let current = root.get("app").and_then(|a| a.get("workspace")).and_then(|v| v.as_str()).map(String::from);
    let default = current.clone().unwrap_or_else(|| paths.data.join("workspace").display().to_string());
    p.say(&format!("\n{}", t("⑥ 預設工作目錄（網頁介面與聊天平台的對話在這裡執行）", "⑥ Default workspace (where web UI and chat sessions run)")));
    let ans = p.ask(t("  目錄", "  Directory"), &default)?;
    let dir = expand(ans.trim());
    validate_workspace_path(&dir)?;
    if let Some(cur) = &current {
        if expand(cur) != dir {
            p.say(&format!("  {} {cur} → {}", t("目前已設定其他工作目錄：", "A different workspace is configured:"), dir.display()));
            if !p.yes(t("  改用新的工作目錄？（既有對話仍留在原處）", "  Switch to the new workspace? (existing sessions stay where they are)"), false)? {
                return Ok(Some(expand(cur)));
            }
        }
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let app = root.entry("app").or_insert_with(|| toml::Value::Table(toml::Table::new()));
    if let Some(t) = app.as_table_mut() {
        t.insert("workspace".into(), dir.display().to_string().into());
    }
    Ok(Some(dir))
}

// ───────────────────────── official extensions ─────────────────────────

/// Official connectors not yet configured that need no extra values (sorted by name).
pub fn official_candidates(root: &toml::Table) -> Vec<&'static crate::mcp_presets::Preset> {
    let have = root.get("mcp").and_then(|m| m.as_table()).cloned().unwrap_or_default();
    let mut v: Vec<_> = crate::mcp_presets::catalog().iter().filter(|p| !have.contains_key(&p.name) && p.env.iter().all(|e| e.secret)).collect();
    v.sort_by(|a, b| a.name.cmp(&b.name));
    v
}

/// Add one `[mcp.<name>]` table from the preset catalog and print what still has to be set up.
fn add_connector(p: &mut dyn Prompt, root: &mut toml::Table, c: &crate::mcp_presets::Preset) -> Result<bool, String> {
    let block = crate::mcp_presets::config_block(&c.name, c, &Default::default())?;
    let parsed: toml::Table = block.parse().map_err(|e| format!("{e}"))?;
    let Some(entry) = parsed.get("mcp").and_then(|m| m.get(&c.name)).cloned() else {
        return Ok(false);
    };
    let mcp = root.entry("mcp").or_insert_with(|| toml::Value::Table(toml::Table::new()));
    if let Some(m) = mcp.as_table_mut() {
        m.insert(c.name.clone(), entry);
    }
    for e in c.env.iter().filter(|e| e.secret) {
        p.say(&format!("  {} `ark secrets set {}`", t("之後設定：", "then run:"), e.name));
    }
    if c.auth == "oauth" {
        p.say(&format!("  {} `ark mcp login {}`", t("之後登入：", "then sign in:"), c.name));
    }
    Ok(true)
}

/// Multi-select (comma-separated numbers or names; Enter skips) and add `[mcp.<name>]` tables.
pub fn plugins_step(p: &mut dyn Prompt, root: &mut toml::Table) -> Result<Vec<String>, String> {
    let cands = official_candidates(root);
    if cands.is_empty() {
        return Ok(vec![]);
    }
    p.say(&format!("\n{}", t("⑦ 官方連接器（MCP；之後可用 `ark mcp presets` 查看）", "⑦ Official connectors (MCP; browse later with `ark mcp presets`)")));
    for (i, c) in cands.iter().enumerate() {
        p.say(&format!("  {:>2}) {:<18} {}{}", i + 1, c.name, crate::term::one_line(&c.description, 60), if c.auth == "oauth" { t("（需登入）", " (sign-in)") } else { "" }));
    }
    let ans = p.ask(t("  要安裝哪些？（編號或名稱，以逗號分隔；Enter 略過）", "  Install which? (numbers or names, comma-separated; Enter to skip)"), "")?;
    let mut added = vec![];
    for w in ans.split([',', ' ']).map(str::trim).filter(|w| !w.is_empty()) {
        let pick = w.parse::<usize>().ok().and_then(|n| n.checked_sub(1)).and_then(|i| cands.get(i)).or_else(|| cands.iter().find(|c| c.name == w));
        let Some(c) = pick else {
            p.say(&format!("  ! {} {w}", t("略過未知項目", "skipping unknown")));
            continue;
        };
        if add_connector(p, root, c)? {
            added.push(c.name.clone());
        }
    }
    Ok(added)
}

// ───────────────────────── app recommendations ─────────────────────────

/// Kill switch for the recommendation step (upstream `wizard.appRecommendations = false`).
/// ark's config rejects unknown tables, so this is an environment variable instead of a key:
/// `ARK_WIZARD_APP_RECOMMENDATIONS=0|false|off|no`.
pub fn app_recommendations_enabled() -> bool {
    enabled_from(std::env::var("ARK_WIZARD_APP_RECOMMENDATIONS").ok().as_deref())
}

fn enabled_from(v: Option<&str>) -> bool {
    !v.is_some_and(|s| matches!(s.trim().to_ascii_lowercase().as_str(), "0" | "false" | "off" | "no"))
}

/// Lowercase word-normalised form: `"Figma (Beta).app"` → `"figma beta app"`.
fn words(s: &str) -> String {
    s.to_lowercase().chars().map(|c| if c.is_alphanumeric() { c } else { ' ' }).collect::<String>().split_whitespace().collect::<Vec<_>>().join(" ")
}

fn read_desktop_name(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    text.lines().find_map(|l| l.strip_prefix("Name=").or_else(|| l.strip_prefix("Name[").and_then(|r| r.split_once(']')?.1.strip_prefix('=')))).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Application names visible to this user: macOS `.app` bundles and Linux `.desktop` entries.
/// Read locally and never sent anywhere (upstream scans macOS apps and asks the model + ClawHub).
pub fn installed_apps_in(dirs: &[PathBuf], cap: usize) -> Vec<String> {
    let mut v: Vec<String> = vec![];
    for d in dirs {
        for e in std::fs::read_dir(d).into_iter().flatten().flatten().take(cap) {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            let found = if p.is_dir() && name.ends_with(".app") { Some(name.trim_end_matches(".app").to_string()) } else if name.ends_with(".desktop") { read_desktop_name(&p) } else { None };
            if let Some(n) = found {
                v.push(n);
                if v.len() >= cap {
                    break;
                }
            }
        }
    }
    v.sort();
    v.dedup();
    v
}

pub fn installed_apps() -> Vec<String> {
    let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    let dirs: Vec<PathBuf> = [PathBuf::from("/Applications"), home.join("Applications"), PathBuf::from("/usr/share/applications"), home.join(".local/share/applications")].into_iter().filter(|d| d.is_dir()).collect();
    installed_apps_in(&dirs, 400)
}

fn matches_app(p: &crate::mcp_presets::Preset, app: &str) -> bool {
    let a = format!(" {} ", words(app));
    let has = |k: &str| {
        let k = words(k);
        !k.is_empty() && a.contains(&format!(" {k} "))
    };
    has(&p.name) || p.keywords.iter().any(|k| k.trim().chars().count() >= 4 && has(k))
}

/// Official connectors (still unconfigured) that match an installed application, with the app
/// that suggested each one. Sorted by connector name; capped so the prompt stays readable.
pub fn app_recommendations(root: &toml::Table, apps: &[String]) -> Vec<(&'static crate::mcp_presets::Preset, String)> {
    let mut out: Vec<(&'static crate::mcp_presets::Preset, String)> = vec![];
    for p in official_candidates(root) {
        if let Some(app) = apps.iter().find(|a| matches_app(p, a)) {
            out.push((p, app.clone()));
        }
    }
    out.truncate(12);
    out
}

/// ⑦b: offer connectors for apps this machine already has (Enter skips). Offline.
pub fn app_recommendations_step(p: &mut dyn Prompt, root: &mut toml::Table, apps: &[String]) -> Result<Vec<String>, String> {
    let cands = app_recommendations(root, apps);
    if cands.is_empty() {
        return Ok(vec![]);
    }
    p.say(&format!("\n{}", t("⑦b 依已安裝的應用建議的連接器（只在本機比對，應用名稱不會離開這台機器）", "⑦b Connectors recommended from apps on this machine (matched locally; app names never leave it)")));
    for (i, (c, app)) in cands.iter().enumerate() {
        p.say(&format!("  {:>2}) {:<18} {} — {}{}", i + 1, c.name, crate::term::one_line(&c.description, 50), app, if c.auth == "oauth" { t("（需登入）", " (sign-in)") } else { "" }));
    }
    let ans = p.ask(t("  要安裝哪些？（編號或名稱，以逗號分隔；Enter 略過）", "  Install which? (numbers or names, comma-separated; Enter to skip)"), "")?;
    let mut added = vec![];
    for w in ans.split([',', ' ']).map(str::trim).filter(|w| !w.is_empty()) {
        let pick = w.parse::<usize>().ok().and_then(|n| n.checked_sub(1)).and_then(|i| cands.get(i)).or_else(|| cands.iter().find(|(c, _)| c.name == w));
        let Some((c, _)) = pick else {
            p.say(&format!("  ! {} {w}", t("略過未知項目", "skipping unknown")));
            continue;
        };
        if add_connector(p, root, c)? && !added.iter().any(|x: &String| x == &c.name) {
            added.push(c.name.clone());
        }
    }
    Ok(added)
}

/// Workspace + official connectors + app recommendations, applied before the config is written.
pub fn mid(p: &mut dyn Prompt, root: &mut toml::Table, paths: &Paths) -> Result<(), String> {
    workspace_step(p, root, paths)?;
    plugins_step(p, root)?;
    if app_recommendations_enabled() {
        app_recommendations_step(p, root, &installed_apps())?;
    }
    Ok(())
}

// ───────────────────────── service + completion ─────────────────────────

/// Offer the background service when something needs the daemon.
pub fn service_step(p: &mut dyn Prompt, needs_daemon: bool, install: &mut dyn FnMut() -> Result<String, String>) -> Result<bool, String> {
    if !needs_daemon {
        return Ok(false);
    }
    p.say(&format!("\n{}", t("⑧ 背景服務", "⑧ Background service")));
    if !p.yes(t("  安裝成 systemd 使用者服務，登入後自動啟動？", "  Install as a systemd user service that starts at login?"), true)? {
        p.say(&format!("  {} ark daemon start", t("之後可手動啟動：", "start it later with:")));
        return Ok(false);
    }
    match install() {
        Ok(m) => {
            p.say(&format!("  ✓ {m}"));
            Ok(true)
        }
        Err(e) => {
            p.say(&format!("  ! {e}"));
            Ok(false)
        }
    }
}

/// (file, script, reload hint) for the user's shell.
pub fn completion_target(shell: &str, home: &Path) -> (PathBuf, String, &'static str) {
    if shell.ends_with("fish") {
        (home.join(".config/fish/completions/ark.fish"), crate::ops::completion::fish(), "")
    } else if shell.ends_with("zsh") {
        (home.join(".zfunc/_ark"), crate::ops::completion::zsh(), "fpath=(~/.zfunc $fpath) before compinit in ~/.zshrc")
    } else {
        (home.join(".local/share/bash-completion/completions/ark"), crate::ops::completion::bash(), "")
    }
}

pub fn completion_step(p: &mut dyn Prompt, shell: &str, home: &Path) -> Result<Option<PathBuf>, String> {
    let (path, body, hint) = completion_target(shell, home);
    let name = Path::new(shell).file_name().and_then(|n| n.to_str()).filter(|s| !s.is_empty()).unwrap_or("bash");
    if path.exists() {
        // Installed: refresh the script so new commands complete.
        let _ = std::fs::write(&path, &body);
        return Ok(None);
    }
    if !p.yes(&format!("\n{} {name} shell completion？", t("為 ark 啟用", "Enable ark")), true)? {
        return Ok(None);
    }
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    match std::fs::write(&path, body) {
        Ok(()) => {
            p.say(&format!("  ✓ {} {}{}", t("已安裝", "installed"), path.display(), if hint.is_empty() { String::new() } else { format!(" — {hint}") }));
            p.say(&format!("  {}", t("重新啟動 shell 後生效", "restart your shell to use it")));
            Ok(Some(path))
        }
        Err(e) => {
            p.say(&format!("  ! {} {}: {e}\n  {}", t("無法寫入", "could not write"), path.display(), t("可在目前的 shell 執行：source <(ark completion bash)", "for this shell only: source <(ark completion bash)")));
            Ok(None)
        }
    }
}

// ───────────────────────── gateway + auth + channel (OpenClaw `setup.gateway-config`,
// `setup.model-auth`, `channel-setup*`) ─────────────────────────

fn table<'a>(root: &'a mut toml::Table, key: &str) -> &'a mut toml::Table {
    if !root.get(key).is_some_and(|v| v.is_table()) {
        root.insert(key.into(), toml::Value::Table(toml::Table::new()));
    }
    root.get_mut(key).and_then(|v| v.as_table_mut()).expect("just inserted a table")
}

/// The `[app]` section the wizard writes for the Control UI / gateway (OpenClaw
/// `setup.gateway-config.ts` + gateway auth): on = enabled with a `{{secret:APP_TOKEN}}`
/// reference (an existing token is never overwritten), off = explicitly disabled so a re-run of
/// `ark setup` turns the server off again. Returns the vault secret the caller must mint when the
/// install has none yet.
pub fn gateway_config(root: &mut toml::Table, enable: bool, have_token_secret: bool) -> Option<&'static str> {
    if !enable {
        table(root, "app").insert("enabled".into(), false.into());
        return None;
    }
    let app = table(root, "app");
    app.insert("enabled".into(), true.into());
    app.entry("token").or_insert_with(|| toml::Value::String("{{secret:APP_TOKEN}}".into()));
    (!have_token_secret).then_some("APP_TOKEN")
}

/// How a provider authenticates in the wizard: paste a key, or run its login flow
/// (`ark login <flow>`, OpenClaw `setup.model-auth.ts`). The wizard UI lives in `main.rs`, so only
/// the tests exercise the choice list today.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    Key,
    Login,
}

/// The login flow a provider uses, when it has an OAuth/device flow instead of (or besides) a
/// static key. `ark login <flow>` stores the credential in the auth store.
pub fn oauth_flow(p: &ark_model::ProviderConfig) -> Option<&str> {
    p.oauth.as_deref().filter(|f| !f.trim().is_empty())
}

/// The auth choices the wizard offers for this provider, in upstream's order: a login flow first
/// when the provider has one, then the API key.
#[cfg(test)]
pub fn auth_options(p: &ark_model::ProviderConfig) -> Vec<Auth> {
    match oauth_flow(p) {
        Some(_) => vec![Auth::Login, Auth::Key],
        None => vec![Auth::Key],
    }
}

/// The vault secret names the wizard asks for, per channel kind (`channel-setup*.ts`).
pub fn channel_secrets(kind: &str) -> &'static [&'static str] {
    match kind {
        "telegram" => &["TELEGRAM_TOKEN"],
        "discord" => &["DISCORD_TOKEN"],
        "slack" => &["SLACK_BOT_TOKEN", "SLACK_APP_TOKEN"],
        _ => &[],
    }
}

/// The `[channels.<kind>]` table: secret references only (a token never lands in config.toml),
/// and strangers must pair (`dm_policy = "pairing"`) — `ark pairing approve` lets them in.
pub fn channel_config(kind: &str) -> Result<toml::Table, String> {
    let names = channel_secrets(kind);
    if names.is_empty() {
        return Err(format!("unknown channel kind `{kind}` (telegram, discord, slack)"));
    }
    let mut ch = toml::Table::new();
    ch.insert("kind".into(), kind.into());
    if names.len() == 2 {
        ch.insert("bot_token".into(), format!("{{{{secret:{}}}}}", names[0]).into());
        ch.insert("app_token".into(), format!("{{{{secret:{}}}}}", names[1]).into());
    } else {
        ch.insert("token".into(), format!("{{{{secret:{}}}}}", names[0]).into());
    }
    ch.insert("dm_policy".into(), "pairing".into());
    Ok(ch)
}

/// Insert a channel under an unused name (`slack`, `slack2`, …) and return the name.
pub fn add_channel(root: &mut toml::Table, kind: &str) -> Result<String, String> {
    let ch = channel_config(kind)?;
    let channels = table(root, "channels");
    let mut name = kind.to_string();
    let mut i = 2;
    while channels.contains_key(&name) {
        name = format!("{kind}{i}");
        i += 1;
    }
    channels.insert(name.clone(), toml::Value::Table(ch));
    Ok(name)
}

/// Service + completion, after the config is written.
pub fn post(p: &mut dyn Prompt, needs_daemon: bool, workspace: &Path) -> Result<(), String> {
    let ws = workspace.to_path_buf();
    service_step(p, needs_daemon, &mut || crate::ops::service::install_user(&ws, true))?;
    let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    completion_step(p, &std::env::var("SHELL").unwrap_or_default(), &home)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct Script {
        answers: VecDeque<&'static str>,
        said: std::cell::RefCell<Vec<String>>,
    }
    impl Prompt for Script {
        fn say(&self, s: &str) {
            self.said.borrow_mut().push(s.to_string());
        }
        fn yes(&mut self, _q: &str, d: bool) -> Result<bool, String> {
            Ok(match self.answers.pop_front().ok_or("no more answers")? {
                "" => d,
                a => a == "y",
            })
        }
        fn ask(&mut self, _q: &str, d: &str) -> Result<String, String> {
            Ok(match self.answers.pop_front().ok_or("no more answers")? {
                "" => d.to_string(),
                a => a.to_string(),
            })
        }
    }

    fn s(a: &[&'static str]) -> Script {
        Script { answers: a.iter().copied().collect(), said: Default::default() }
    }

    fn paths() -> (PathBuf, Paths) {
        let root = std::env::temp_dir().join(format!("ark-wiz-{}", ark_kernel::util::random_hex(6)));
        let p = Paths { data: root.join("data"), config_dir: root.join("config"), runtime: root.join("run") };
        std::fs::create_dir_all(&p.config_dir).unwrap();
        (root, p)
    }

    #[test]
    fn security_note_defaults_to_no() {
        assert!(security_note().contains("ark security audit --deep"));
        assert!(!security_step(&mut s(&[""])).unwrap());
        assert!(security_step(&mut s(&["y"])).unwrap());
    }

    #[test]
    fn migration_imports_detected_hermes() {
        let (root, p) = paths();
        let h = root.join("hermes");
        std::fs::create_dir_all(&h).unwrap();
        std::fs::write(h.join("config.yaml"), "model:\n  default: anthropic/claude-sonnet-4\n").unwrap();
        std::fs::write(h.join(".env"), "OPENROUTER_API_KEY=sk-or-test\n").unwrap();
        let mut sc = s(&["y"]);
        let done = migration_step(&mut sc, &p, &[("hermes", h.clone())]).unwrap();
        assert_eq!(done, vec!["hermes"]);
        assert!(sc.said.borrow().iter().any(|l| l.contains("hermes (")));
        // declined → nothing applied
        let (_, p2) = paths();
        assert!(migration_step(&mut s(&["n"]), &p2, &[("hermes", h)]).unwrap().is_empty());
        assert!(!p2.user_config().exists());
    }

    #[test]
    fn workspace_validation_and_conflict() {
        let (root, p) = paths();
        let f = root.join("file");
        std::fs::write(&f, "x").unwrap();
        assert!(validate_workspace_path(&f.join("sub")).unwrap_err().contains("not a directory") || validate_workspace_path(&f.join("sub")).unwrap_err().contains("不是目錄"));
        std::os::unix::fs::symlink(root.join("loop"), root.join("loop")).unwrap();
        assert!(validate_workspace_path(&root.join("loop")).is_err());
        let mut t = toml::Table::new();
        let d = workspace_step(&mut s(&[""]), &mut t, &p).unwrap().unwrap();
        assert_eq!(d, p.data.join("workspace"));
        assert!(d.is_dir());
        assert_eq!(t["app"]["workspace"].as_str().unwrap(), d.display().to_string());
        // a different existing workspace is kept unless confirmed
        let other = root.join("other").display().to_string();
        let leaked: &'static str = Box::leak(other.clone().into_boxed_str());
        let kept = workspace_step(&mut s(&[leaked, ""]), &mut t, &p).unwrap().unwrap();
        assert_eq!(kept, d);
        let moved = workspace_step(&mut s(&[leaked, "y"]), &mut t, &p).unwrap().unwrap();
        assert_eq!(moved.display().to_string(), other);
    }

    #[test]
    fn official_connectors_multiselect() {
        let mut t = toml::Table::new();
        let c = official_candidates(&t);
        assert!(c.iter().any(|p| p.name == "context7"));
        let added = plugins_step(&mut s(&["context7, 9999, nope"]), &mut t).unwrap();
        assert_eq!(added, vec!["context7"]);
        assert!(t["mcp"]["context7"]["url"].as_str().unwrap().starts_with("https://"));
        assert!(!official_candidates(&t).iter().any(|p| p.name == "context7"));
        assert!(plugins_step(&mut s(&[""]), &mut t).unwrap().is_empty());
    }

    #[test]
    fn app_recommendations_from_installed_apps() {
        assert!(enabled_from(None) && !enabled_from(Some("0")) && !enabled_from(Some(" OFF ")) && !enabled_from(Some("false")));
        let apps = vec!["Figma.app".to_string(), "Jira".to_string(), "Some Random Tool".to_string()];
        let mut t = toml::Table::new();
        let recs = app_recommendations(&t, &apps);
        let names: Vec<&str> = recs.iter().map(|(p, _)| p.name.as_str()).collect();
        assert_eq!(names, vec!["atlassian", "figma"], "{names:?}");
        assert_eq!(recs[0].1, "Jira");
        // picked by number → `[mcp.atlassian]` appears and is no longer suggested
        assert_eq!(app_recommendations_step(&mut s(&["1"]), &mut t, &apps).unwrap(), vec!["atlassian"]);
        assert!(t["mcp"]["atlassian"]["url"].as_str().unwrap().starts_with("https://"));
        assert!(!app_recommendations(&t, &apps).iter().any(|(p, _)| p.name == "atlassian"));
        // Enter skips, and no apps means no prompt at all (no answers consumed)
        assert!(app_recommendations_step(&mut s(&[""]), &mut t, &apps).unwrap().is_empty());
        assert!(app_recommendations_step(&mut s(&[]), &mut t, &[]).unwrap().is_empty());
        // unknown words are reported and skipped, picked-up names work too
        assert_eq!(app_recommendations_step(&mut s(&["figma, nope"]), &mut t, &apps).unwrap(), vec!["figma"]);
        // `.desktop` entries are read by Name=, directory scan is capped and deduped
        let root = std::env::temp_dir().join(format!("ark-apps-{}", ark_kernel::util::random_hex(6)));
        std::fs::create_dir_all(root.join("Figma.app")).unwrap();
        std::fs::create_dir_all(root.join("notes")).unwrap();
        std::fs::write(root.join("jira.desktop"), "[Desktop Entry]\nName=Jira\nExec=jira\n").unwrap();
        std::fs::write(root.join("bad.desktop"), "[Desktop Entry]\nExec=x\n").unwrap();
        assert_eq!(installed_apps_in(&[root], 10), vec!["Figma".to_string(), "Jira".to_string()]);
        assert_eq!(installed_apps_in(&[std::env::temp_dir().join("ark-nope-none")], 10).len(), 0);
    }

    #[test]
    fn mid_runs_workspace_connectors_and_recommendations() {
        let (_, p) = paths();
        let mut t = toml::Table::new();
        // workspace (Enter = default) + connectors (Enter = skip); recommendations need answers too
        // because the real machine may have matching apps, so an empty answer list must not panic.
        let mut sc = s(&["", "", ""]);
        mid(&mut sc, &mut t, &p).unwrap();
        assert!(t["app"]["workspace"].as_str().is_some());
    }

    #[test]
    fn gateway_config_and_model_auth() {
        // Web UI on: enabled + a vault reference, and the caller is told to mint APP_TOKEN once.
        let mut root: toml::Table = "".parse().unwrap();
        assert_eq!(gateway_config(&mut root, true, false), Some("APP_TOKEN"));
        assert_eq!(root["app"]["enabled"].as_bool(), Some(true));
        assert_eq!(root["app"]["token"].as_str(), Some("{{secret:APP_TOKEN}}"));
        // Re-running setup keeps an existing token and knows the secret exists.
        let mut root: toml::Table = "[app]\ntoken = \"{{secret:MY_TOKEN}}\"\n".parse().unwrap();
        assert_eq!(gateway_config(&mut root, true, true), None);
        assert_eq!(root["app"]["token"].as_str(), Some("{{secret:MY_TOKEN}}"));
        // Off: explicitly disabled, so a second run turns the server off again.
        let mut root: toml::Table = "[app]\nenabled = true\n".parse().unwrap();
        assert_eq!(gateway_config(&mut root, false, true), None);
        assert_eq!(root["app"]["enabled"].as_bool(), Some(false));

        // Model auth: providers with a login flow offer it first, key-only providers do not.
        let mut p = ark_model::ProviderConfig::default();
        assert_eq!(auth_options(&p), vec![Auth::Key]);
        assert_eq!(oauth_flow(&p), None);
        p.oauth = Some("chatgpt".into());
        assert_eq!(oauth_flow(&p), Some("chatgpt"));
        assert_eq!(auth_options(&p), vec![Auth::Login, Auth::Key]);
        p.oauth = Some("  ".into());
        assert_eq!(oauth_flow(&p), None, "a blank flow is not a choice");
    }

    #[test]
    fn channel_configs_reference_secrets_and_pair_strangers() {
        assert_eq!(channel_secrets("telegram"), &["TELEGRAM_TOKEN"]);
        assert_eq!(channel_secrets("discord"), &["DISCORD_TOKEN"]);
        assert_eq!(channel_secrets("slack"), &["SLACK_BOT_TOKEN", "SLACK_APP_TOKEN"]);
        assert!(channel_secrets("irc").is_empty() && channel_config("irc").is_err());
        let tg = channel_config("telegram").unwrap();
        assert_eq!(tg["kind"].as_str(), Some("telegram"));
        assert_eq!(tg["token"].as_str(), Some("{{secret:TELEGRAM_TOKEN}}"));
        assert_eq!(tg["dm_policy"].as_str(), Some("pairing"));
        let sl = channel_config("slack").unwrap();
        assert_eq!(sl["bot_token"].as_str(), Some("{{secret:SLACK_BOT_TOKEN}}"));
        assert_eq!(sl["app_token"].as_str(), Some("{{secret:SLACK_APP_TOKEN}}"));
        // Names never collide: slack, slack2, slack3 …
        let mut root: toml::Table = "".parse().unwrap();
        assert_eq!(add_channel(&mut root, "slack").unwrap(), "slack");
        assert_eq!(add_channel(&mut root, "slack").unwrap(), "slack2");
        assert_eq!(add_channel(&mut root, "slack").unwrap(), "slack3");
        assert_eq!(root["channels"]["slack2"]["dm_policy"].as_str(), Some("pairing"));
        assert!(add_channel(&mut root, "irc").is_err());
        // The written config parses and the channel is visible to `ark channel list`.
        let text = toml::to_string(&root).unwrap();
        let back: toml::Table = text.parse().unwrap();
        assert!(back["channels"].as_table().unwrap().contains_key("slack3"));
    }

    #[test]
    fn service_and_completion_steps() {
        let (root, _) = paths();
        let mut calls = 0;
        assert!(!service_step(&mut s(&[]), false, &mut || Ok("x".into())).unwrap());
        assert!(service_step(&mut s(&[""]), true, &mut || {
            calls += 1;
            Ok("wrote unit".into())
        }).unwrap());
        assert_eq!(calls, 1);
        assert!(!service_step(&mut s(&["n"]), true, &mut || Err("should not run".into())).unwrap());
        let p = completion_step(&mut s(&[""]), "/usr/bin/zsh", &root).unwrap().unwrap();
        assert!(p.ends_with(".zfunc/_ark") && std::fs::read_to_string(&p).unwrap().starts_with("#compdef ark"));
        // already installed: no prompt (no answers left), refreshed in place
        assert!(completion_step(&mut s(&[]), "/usr/bin/zsh", &root).unwrap().is_none());
        assert!(completion_step(&mut s(&["n"]), "/bin/bash", &root).unwrap().is_none());
    }
}
