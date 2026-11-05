//! Model, credential and usage commands: `ark login|logout|auth|model|models|fallback|usage|insights`
//! and the chat/channel slash commands `/model /models /think /reasoning /fast /usage /insights /login`.
//! Hermes `hermes_cli/subcommands/{auth,login,model,fallback,usage,insights}.py`, `commands.py`;
//! OpenClaw `src/cli/models-cli.ts`, `src/auto-reply/commands-registry.shared.ts`.

use crate::args::Args;
use crate::providers::Providers;
use ark_kernel::config::{Config, Paths};
use ark_kernel::event::EventKind;
use ark_kernel::kernel::Kernel;
use ark_kernel::ledger::Price;
use ark_kernel::projection::project;
use ark_kernel::store::Store as Sessions;
use ark_kernel::vault::Vault;
use ark_model::login::{self, Prompter};
use ark_model::store::{Entry, Store};
use ark_model::{modelsdb, ProviderConfig};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::Arc;

type R = Result<i32, String>;

// ───────────────────────── process setup ─────────────────────────

/// Wire the model layer to this process: credential store, models.dev cache, network
/// policy, built-in prices. Called whenever config is loaded.
pub fn init(paths: &Paths, cfg: &Config) {
    // `$ARK_AGENT=<name>`: this process's credential pool is the agent's own profile store,
    // layered over the shared one (`ark auth --agent <name> add …` fills it).
    match std::env::var("ARK_AGENT").ok().map(|x| x.trim().to_string()).filter(|x| !x.is_empty()) {
        Some(name) => ark_model::store::set_default_agent(&paths.config_dir, &name),
        None => ark_model::store::set_default(paths.config_dir.join("auth.json")),
    }
    modelsdb::set_mirror(&cfg.pricing.models_dev_url);
    modelsdb::set_cache(paths.data.join("models-dev.json"));
    let mut net: ark_model::net::NetConfig = toml::Value::Table(cfg.network.clone()).try_into().unwrap_or_else(|e: toml::de::Error| {
        eprintln!("ark: warning: [network]: {}", e.message());
        Default::default()
    });
    if cfg.compliance.profile == "government" {
        for h in ark_kernel::config::PRC_HOSTS {
            net.deny_hosts.push(h.to_string());
        }
    }
    ark_model::net::configure(net);
    ark_kernel::ledger::set_price_source(Box::new(|m: &str| {
        let (p, id) = m.split_once('/')?;
        let x = modelsdb::price_for(p, id)?;
        Some(Price { input: x.input, output: x.output, cache_read: x.cache_read.unwrap_or(0.0), cache_write: x.cache_write.unwrap_or(0.0) })
    }));
    auto_refresh_prices(&paths.data.join("models-dev.json"), cfg);
    // `model.context_length` is an explicit pin: say once when it disagrees with what the
    // provider is known to advertise (Hermes `context_pin.warn_once_on_pin_disagreement`).
    if let Some(w) = ark_model::contextpin::warn_once(cfg.resolve_model(&cfg.model.default), "", cfg.model.context_length) {
        eprintln!("ark: warning: {w}");
    }
}

/// Keep the models.dev price/metadata cache fresh without a manual `ark models refresh`:
/// fetched in the foreground (bounded) when missing, in the background when older than a
/// day. Off with `[pricing] auto_refresh = false`, `ARK_OFFLINE=1`, `[network] offline`, or the government
/// profile (models.dev is a third-party host).
fn auto_refresh_prices(cache: &std::path::Path, cfg: &Config) {
    const STALE: std::time::Duration = std::time::Duration::from_secs(24 * 3600);
    let enabled = cfg.pricing.auto_refresh && !ark_net::http::no_background_fetch() && cfg.compliance.profile != "government";
    if !enabled {
        return;
    }
    let age = std::fs::metadata(cache).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok());
    match age {
        None => {
            // First use: wait a little so this run already has live prices.
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(modelsdb::refresh(None));
            });
            match rx.recv_timeout(std::time::Duration::from_secs(8)) {
                Ok(Err(e)) => eprintln!("ark: warning: price refresh from models.dev failed ({e}); using built-in snapshots"),
                Err(_) => eprintln!("ark: note: models.dev is slow; prices will update in the background"),
                Ok(Ok(_)) => {}
            }
        }
        Some(a) if a > STALE => {
            std::thread::spawn(|| {
                if modelsdb::refresh(None).is_err() {
                    // Next run retries; built-in snapshots cover the common models meanwhile.
                }
            });
        }
        Some(_) => {}
    }
}

fn store(paths: &Paths) -> Store {
    Store::new(paths.config_dir.join("auth.json"))
}

/// `--agent <name>`: operate on that agent's own credential profile store
/// (`<config>/agents/<name>/auth.json`), which still reads the shared pool below it.
fn store_for(paths: &Paths, agent: Option<&str>) -> Store {
    match agent.map(str::trim).filter(|a| !a.is_empty()) {
        Some(name) => Store::for_agent(&paths.config_dir, name),
        None => store(paths),
    }
}

fn providers(cfg: &Config, vault: Arc<Vault>) -> Result<Providers, String> {
    Providers::new(&cfg.providers, vault)
}

// ───────────────────────── terminal prompter ─────────────────────────

struct Tty {
    no_browser: bool,
}

impl Prompter for Tty {
    fn device(&self, uri: &str, code: &str, complete: Option<&str>) {
        eprintln!("\nTo sign in, open:\n  {}\nand enter the code:\n  {code}\n", complete.unwrap_or(uri));
        if !self.no_browser {
            open_browser(complete.unwrap_or(uri));
        }
        eprintln!("Waiting for authorization… (Ctrl-C to cancel)");
    }
    fn open(&self, url: &str) {
        eprintln!("\nOpen this URL to sign in:\n  {url}\n");
        if !self.no_browser {
            open_browser(url);
        }
    }
    fn read(&self, prompt: &str) -> String {
        eprint!("{prompt}");
        let _ = std::io::stderr().flush();
        let mut s = String::new();
        let _ = std::io::stdin().lock().read_line(&mut s);
        s.trim().to_string()
    }
    fn info(&self, msg: &str) {
        eprintln!("{msg}");
    }
}

fn open_browser(url: &str) {
    if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
        return;
    }
    let _ = std::process::Command::new("xdg-open").arg(url).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn();
}

// ───────────────────────── login / logout ─────────────────────────

pub fn cmd_login(a: &Args, paths: &Paths) -> R {
    let Some(target) = a.pos(0) else {
        println!("Usage: ark login <provider> [--no-browser] [--label NAME]\n\nAccount logins:");
        for f in login::flows() {
            println!("  {:<24} {}  → provider `{}`", f.id, f.title, f.provider);
        }
        println!("\nAPI keys: `ark auth add <provider>`.");
        return Ok(0);
    };
    let flow = login::flow(target).ok_or_else(|| format!("no login flow for `{target}` (see `ark login`); for API keys use `ark auth add {target}`"))?;
    let s = store(paths);
    let mut e = if a.flag("import") {
        login::import_external(&flow.id).ok_or_else(|| format!("no existing {} login found to import", flow.title))?
    } else {
        let opts = login::Opts { no_browser: a.flag("no-browser"), timeout: a.num::<u64>("timeout")?.map(std::time::Duration::from_secs) };
        login::login(&flow, &Tty { no_browser: a.flag("no-browser") }, &opts)?
    };
    if let Some(l) = a.val("label") {
        e.label = l.to_string();
    }
    let id = if e.kind == "oauth" || e.kind == "token" { s.upsert_login(&flow.provider, e)? } else { s.add(&flow.provider, e, None)? };
    println!("✓ signed in: {} (credential {id} for provider `{}`; use models as `{}/<model>`)", flow.title, flow.provider, flow.provider);
    Ok(0)
}

/// `/login <provider>` inside a chat turn: run the flow with a prompter that renders into the
/// reply, store the credential, and answer with the upstream-style completion text.
/// OpenClaw `src/auto-reply/reply/commands-login.ts`, Hermes `auth_commands.py`.
pub fn inline_login(arg: &str, paths: &Paths) -> Result<String, String> {
    let flow = login::flow(arg).ok_or_else(|| {
        let flows = login::flows();
        let ids: Vec<&str> = flows.iter().map(|f| f.id.as_str()).collect();
        format!("no login flow for `{arg}` (see `ark login`): {}", ids.join(", "))
    })?;
    if login::needs_terminal_input(&flow) {
        return Err(format!(
            "`{}` needs a value typed into a terminal; run `ark login {}` there.",
            flow.title, flow.id
        ));
    }
    login::reserve_flow(&flow.id)?;
    let p = login::Inline::default();
    let opts = login::Opts { no_browser: false, timeout: Some(std::time::Duration::from_secs(600)) };
    let res = login::login(&flow, &p, &opts);
    login::release_flow(&flow.id);
    let mut out = p.lines().join("\n");
    let e = res?;
    let s = store(paths);
    let id = if e.kind == "oauth" || e.kind == "token" { s.upsert_login(&flow.provider, e)? } else { s.add(&flow.provider, e, None)? };
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(&format!(
        "✓ signed in: {} (credential {id} for provider `{}`; use models as `{}/<model>`)",
        flow.title, flow.provider, flow.provider
    ));
    Ok(out)
}

pub fn cmd_logout(a: &Args, paths: &Paths) -> R {
    let target = a.pos(0).ok_or("usage: ark logout <provider>")?;
    let provider = login::flow(target).map(|f| f.provider).unwrap_or_else(|| target.to_string());
    let n = store(paths).clear_provider(&provider)?;
    println!("removed {n} stored credential(s) for {provider}");
    Ok(0)
}

// ───────────────────────── auth (credential pool) ─────────────────────────

fn read_secret(prompt: &str) -> String {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let echo_off = unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(0, &mut t) == 0 {
            let old = t;
            t.c_lflag &= !libc::ECHO;
            libc::tcsetattr(0, libc::TCSANOW, &t);
            Some(old)
        } else {
            None
        }
    };
    let mut s = String::new();
    let _ = std::io::stdin().lock().read_line(&mut s);
    if let Some(old) = echo_off {
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &old) };
        eprintln!();
    }
    s.trim().to_string()
}

fn status_of(e: &Entry) -> String {
    let now = ark_model::ratelimit::now_ms();
    if e.status == "dead" {
        return "DEAD (re-login needed)".into();
    }
    if let Some(u) = e.blocked(None, now) {
        return format!("cooling down {}s", (u - now) / 1000);
    }
    let cooled: Vec<String> = e.model_cooldowns.iter().filter(|(_, u)| **u > now).map(|(m, u)| format!("{m} {}s", (u - now) / 1000)).collect();
    if !cooled.is_empty() {
        return format!("ok (cooling: {})", cooled.join(", "));
    }
    match e.expires_at_ms {
        Some(x) if x <= now && e.refresh.is_none() => "expired".into(),
        Some(x) if x > now => format!("ok (token valid {}m)", (x - now) / 60_000),
        _ => "ok".into(),
    }
}

/// `ark auth status <provider>` without an agent profile: the credential source, then every
/// credential this process can use — the store's pool entries first, then the vault/env/config
/// fallback. The vault must be the process vault: an empty one hides `ark secrets set` keys from
/// the listing. The CLI goes through [`auth_status_lines_for`] (it passes `--agent`), so only the
/// tests call this wrapper.
#[cfg(test)]
pub fn auth_status_lines(cfg: &Config, vault: Arc<Vault>, provider: &str) -> Result<Vec<String>, String> {
    auth_status_lines_for(cfg, vault, None, provider, None)
}

/// [`auth_status_lines`] for an agent profile store (`ark auth --agent <name> status`).
pub fn auth_status_lines_for(
    cfg: &Config,
    vault: Arc<Vault>,
    paths: Option<&Paths>,
    provider: &str,
    agent: Option<&str>,
) -> Result<Vec<String>, String> {
    let mut ps = providers(cfg, vault)?;
    if let (Some(name), Some(p)) = (agent.map(str::trim).filter(|a| !a.is_empty()), paths) {
        ps = ps.agent(&p.config_dir, name);
    }
    let c = ps.config(provider).ok_or_else(|| format!("unknown provider `{provider}`"))?;
    let mut out = vec![format!("{provider}: {}", ps.key_source(provider).map(String::from).unwrap_or_else(|e| e))];
    for (k, label, src) in ps.credentials(c).unwrap_or_default() {
        let ok = match src.get() {
            Ok(cr) if cr.token.is_some() || c.keyless() => "usable".to_string(),
            Ok(_) => "no key".into(),
            Err(e) => format!("error: {}", e.message),
        };
        out.push(format!("  {k:<10} {label}  {ok}"));
    }
    Ok(out)
}

pub fn cmd_auth(a: &Args, paths: &Paths, cfg: &Config, vault: Arc<Vault>) -> R {
    let s = store_for(paths, a.val("agent"));
    let canon = |p: &str| ark_model::resolve_alias(p).unwrap_or_else(|| p.to_string());
    match a.pos(0).unwrap_or("list") {
        "add" => {
            let p = canon(a.need(1, "provider")?);
            let ty = a.val("type").unwrap_or("api-key").replace('-', "_");
            if ty == "oauth" {
                return cmd_login(&Args::parse(std::slice::from_ref(&p)).map_err(|e| e.to_string())?, paths);
            }
            let key = match a.val("api-key") {
                Some(k) => k.to_string(),
                None => read_secret(&format!("API key for {p}: ")),
            };
            if key.is_empty() {
                return Err("no key entered".into());
            }
            let label = a.val("label").map(String::from).unwrap_or_else(|| format!("key-{}", s.entries(&p).len() + 1));
            let id = s.add(&p, Entry::new("api_key", &label, Some(key)), a.num::<u32>("priority")?)?;
            println!("added {label} ({id}) to the {p} pool");
            Ok(0)
        }
        "list" | "ls" => {
            let file = s.load();
            let filter = a.pos(1).map(canon);
            for (p, v) in &file.providers {
                if filter.as_deref().is_some_and(|f| f != p) {
                    continue;
                }
                let strat = file.strategies.get(p).map(String::as_str).unwrap_or("fill_first");
                println!("{p}  (strategy {strat})");
                let mut v = v.clone();
                v.sort_by_key(|e| e.priority);
                for (i, e) in v.iter().enumerate() {
                    println!("  {i}  {:<12} {:<7} {:<16} {:>6} reqs  {}{}", e.label, e.kind, e.masked(), e.request_count, status_of(e), e.last_error.as_deref().map(|x| format!("  last error: {}", x.chars().take(80).collect::<String>())).unwrap_or_default());
                }
            }
            if let Some(f) = a.pos(1).map(canon) {
                if s.entries(&f).is_empty() {
                    // No pooled credential: show where a key does come from (vault, env, key_cmd).
                    for line in auth_status_lines_for(cfg, vault.clone(), Some(paths), &f, a.val("agent"))? {
                        println!("{line}");
                    }
                }
            } else if file.providers.is_empty() {
                println!("no pooled credentials (add with `ark auth add <provider>` or `ark login <provider>`)");
            }
            Ok(0)
        }
        "remove" | "rm" => {
            let p = canon(a.need(1, "provider")?);
            let e = s.find(&p, a.need(2, "credential (index, id or label)")?)?;
            s.remove(&p, &e.id)?;
            println!("removed {} from {p}", e.label);
            Ok(0)
        }
        "reset" => {
            let p = canon(a.need(1, "provider")?);
            let id = match a.pos(2) {
                Some(t) => Some(s.find(&p, t)?.id),
                None => None,
            };
            println!("cleared cooldowns on {} credential(s) of {p}", s.reset(&p, id.as_deref())?);
            Ok(0)
        }
        "priority" => {
            let p = canon(a.need(1, "provider")?);
            let e = s.find(&p, a.need(2, "credential")?)?;
            let prio: u32 = a.need(3, "priority")?.parse().map_err(|_| "priority must be a number")?;
            s.set_priority(&p, &e.id, prio)?;
            println!("{} is now at priority {prio}", e.label);
            Ok(0)
        }
        "strategy" => {
            let p = canon(a.need(1, "provider")?);
            let st = a.need(2, "strategy")?.to_string();
            if !ark_model::auth::STRATEGIES.contains(&st.as_str()) {
                return Err(format!("strategy must be one of {}", ark_model::auth::STRATEGIES.join(", ")));
            }
            s.update(|f| f.strategies.insert(p.clone(), st.clone()))?;
            println!("{p}: {st}");
            Ok(0)
        }
        "refresh" => {
            let p = canon(a.need(1, "provider")?);
            let v = s.entries(&p);
            let e = match a.pos(2) {
                Some(t) => s.find(&p, t)?,
                None if v.len() == 1 => v[0].clone(),
                None => return Err(format!("{p} has {} credentials; name one (index, id or label)", v.len())),
            };
            let flow = e.flow.as_deref().and_then(login::flow).ok_or("this credential has no refreshable login")?;
            let n = login::refresh(&flow, &e)?;
            s.modify(&p, &e.id, |x| {
                x.key = n.key;
                x.refresh = n.refresh.or(x.refresh.take());
                x.expires_at_ms = n.expires_at_ms;
                x.status.clear();
                x.exhausted_until_ms = None;
            })?;
            println!("refreshed {} for {p}", e.label);
            Ok(0)
        }
        "status" => {
            let p = canon(a.need(1, "provider")?);
            for line in auth_status_lines_for(cfg, vault.clone(), Some(paths), &p, a.val("agent"))? {
                println!("{line}");
            }
            Ok(0)
        }
        "logout" => cmd_logout(&Args::parse(&[a.need(1, "provider")?.to_string()]).map_err(|e| e.to_string())?, paths),
        other => Err(format!("unknown `auth {other}` (add, list, remove, reset, priority, strategy, refresh, status, logout)")),
    }
}

// ───────────────────────── config editing ─────────────────────────

/// Set `key` in `[section]` of a TOML file, keeping everything else (comments too).
pub fn set_config_value(path: &Path, section: &str, key: &str, value: Option<&str>) -> Result<(), String> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    let header = format!("[{section}]");
    let start = lines.iter().position(|l| l.trim() == header);
    let new_line = value.map(|v| format!("{key} = {v}"));
    match start {
        Some(s) => {
            let end = lines.iter().skip(s + 1).position(|l| l.trim_start().starts_with('[') && !l.trim_start().starts_with("[[") && l.trim().ends_with(']') && !l.contains('=')).map(|i| s + 1 + i).unwrap_or(lines.len());
            let found = (s + 1..end).find(|&i| {
                let t = lines[i].trim_start();
                t.split('=').next().map(str::trim) == Some(key) && t.contains('=')
            });
            match (found, new_line) {
                (Some(i), nl) => {
                    // Drop a multi-line array value.
                    let mut j = i;
                    if lines[i].contains('[') && !lines[i].contains(']') {
                        while j + 1 < end && !lines[j].contains(']') {
                            j += 1;
                        }
                    }
                    lines.drain(i..=j);
                    if let Some(nl) = nl {
                        lines.insert(i, nl);
                    }
                }
                (None, Some(nl)) => lines.insert(s + 1, nl),
                (None, None) => {}
            }
        }
        None => {
            if let Some(nl) = new_line {
                if !lines.is_empty() && !lines.last().unwrap().is_empty() {
                    lines.push(String::new());
                }
                lines.push(header);
                lines.push(nl);
            }
        }
    }
    let out = lines.join("\n") + "\n";
    out.parse::<toml::Table>().map_err(|e| format!("refusing to write invalid TOML to {}: {e}", path.display()))?;
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, out).map_err(|e| format!("{}: {e}", path.display()))
}

fn toml_str(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

fn toml_list(v: &[String]) -> String {
    toml::Value::Array(v.iter().map(|s| toml::Value::String(s.clone())).collect()).to_string()
}

// ───────────────────────── guards ─────────────────────────

/// Hermes `model_cost_guard`: warn before picking a model above the price thresholds.
pub fn cost_warning(cfg: &Config, model: &str) -> Option<String> {
    let p = cfg.price(model)?;
    let (ti, to) = (cfg.model.confirm_input_usd, cfg.model.confirm_output_usd);
    (p.input > ti || p.output > to).then(|| format!("{model} costs ${:.2}/M input, ${:.2}/M output (above the ${ti:.0}/${to:.0} guard)", p.input, p.output))
}

/// Hermes `model_data_policy_guard`: tiers that train on your prompts.
pub fn data_policy_warning(model: &str) -> Option<String> {
    let m = model.to_lowercase();
    let id = m.rsplit('/').next().unwrap_or(&m);
    (id.ends_with("-contributor") || id.split('-').any(|p| p == "contributor")).then(|| format!("{model} is a CONTRIBUTOR tier: the vendor may train future models on your prompts and completions. Do not use it for confidential or personal data."))
}

/// Canonicalise `provider/model` (provider aliases like `grok/…` → `xai/…`).
fn canonical_model(cfg: &Config, ps: &Providers, m: &str) -> String {
    let m = cfg.resolve_model(m).to_string();
    match m.split_once('/') {
        Some((p, rest)) => ps.canonical(p).map(|c| format!("{c}/{rest}")).unwrap_or(m),
        None => m,
    }
}

// ───────────────────────── ark model (picker) ─────────────────────────

fn ask(prompt: &str) -> String {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut s = String::new();
    let _ = std::io::stdin().lock().read_line(&mut s);
    s.trim().to_string()
}

fn first_cred(ps: &Providers, c: &ProviderConfig) -> Option<Arc<dyn ark_model::auth::CredSource>> {
    ps.credentials(c).ok()?.into_iter().next().map(|(_, _, s)| s)
}

fn models_of(ps: &Providers, c: &ProviderConfig) -> Result<Vec<String>, String> {
    let cred = first_cred(ps, c).ok_or_else(|| ps.key_source(&c.id).err().unwrap_or_else(|| "no credentials".into()))?;
    ark_model::list_models_with(c, &*cred)
}

pub fn cmd_model(a: &Args, paths: &Paths, cfg: &Config, vault: Arc<Vault>) -> R {
    let ps = providers(cfg, vault)?;
    let user = paths.user_config();
    let chosen = if let Some(m) = a.pos(0) {
        canonical_model(cfg, &ps, m)
    } else {
        println!("current: {}", cfg.model.default);
        let ids: Vec<&String> = ps.configs().keys().collect();
        let ready: Vec<&String> = ids.iter().copied().filter(|id| ps.key_source(id).is_ok()).collect();
        for (i, id) in ready.iter().enumerate() {
            let c = &ps.configs()[*id];
            println!("{:>3}. {id:<24} {:?}", i + 1, c.format);
        }
        let pick = ask("provider (number or id; providers without credentials are hidden — `ark login`/`ark auth add`): ");
        let pid = pick.parse::<usize>().ok().and_then(|n| ready.get(n.wrapping_sub(1)).map(|s| s.to_string())).or_else(|| ps.canonical(&pick)).ok_or("no such provider")?;
        let c = ps.config(&pid).unwrap();
        let list = models_of(&ps, c).unwrap_or_else(|e| {
            eprintln!("(could not list models: {e})");
            vec![]
        });
        for (i, m) in list.iter().enumerate().take(60) {
            let price = modelsdb::price_for(&pid, m).map(|p| format!("  ${:.2}/${:.2} per M", p.input, p.output)).unwrap_or_default();
            println!("{:>3}. {m}{price}", i + 1);
        }
        let pm = ask("model (number or id): ");
        let m = pm.parse::<usize>().ok().and_then(|n| list.get(n.wrapping_sub(1)).cloned()).unwrap_or(pm);
        if m.is_empty() {
            return Err("no model chosen".into());
        }
        format!("{pid}/{m}")
    };
    if !chosen.contains('/') {
        return Err(format!("`{chosen}` is not provider/model or a model alias"));
    }
    for w in [cost_warning(cfg, &chosen), data_policy_warning(&chosen)].into_iter().flatten() {
        eprintln!("⚠ {w}");
        if !a.flag("yes") && ask("continue? [y/N] ").to_lowercase() != "y" {
            return Err("cancelled".into());
        }
    }
    set_config_value(&user, "model", "default", Some(&toml_str(&chosen)))?;
    println!("model.default = {chosen}  ({})", user.display());
    Ok(0)
}

// ───────────────────────── ark models ─────────────────────────

/// `ark models status`: one `route <task>` line per auxiliary task that is routed somewhere
/// (`[auxiliary.<task>]` or `[model.tasks]`), with its fallback chain and any benched provider.
pub fn aux_route_lines(cfg: &Config) -> Vec<String> {
    let mut routed: Vec<&String> = cfg.auxiliary.keys().chain(cfg.model.tasks.keys()).collect();
    routed.sort();
    routed.dedup();
    let mut out = Vec::new();
    for t in routed {
        let chain: Vec<String> = cfg
            .task_plan(t)
            .iter()
            .map(|m| {
                let held = m.split_once('/').map(|(p, _)| ark_model::aux::down(p)).unwrap_or(false);
                if held {
                    format!("{m} (held out)")
                } else {
                    m.clone()
                }
            })
            .collect();
        out.push(format!("  route {t:<16} {}", chain.join(" → ")));
    }
    out
}

pub fn cmd_models(a: &Args, paths: &Paths, cfg: &Config, vault: Arc<Vault>) -> R {
    let ps = providers(cfg, vault.clone())?;
    let user = paths.user_config();
    match a.pos(0).unwrap_or("status") {
        "status" => {
            println!("default   {}", cfg.model.default);
            println!("fallback  {}", if cfg.model.fallback.is_empty() { "-".into() } else { cfg.model.fallback.join(", ") });
            println!("aux       {}", cfg.aux_model());
            for (t, m) in &cfg.model.tasks {
                println!("  task {t:<10} {m}");
            }
            // Per-task auxiliary routes (`[auxiliary.<task>]`) with their fallback chain and any
            // provider a failed call has benched.
            for line in aux_route_lines(cfg) {
                println!("{line}");
            }
            println!("subagent  {}", cfg.subagent_model());
            println!("thinking  {}", if cfg.model.thinking.is_empty() { "provider default" } else { &cfg.model.thinking });
            println!("fast      {}", if cfg.model.fast.is_empty() { "off" } else { &cfg.model.fast });
            for (k, v) in &cfg.model.aliases {
                println!("alias     {k} → {v}");
            }
            if !cfg.model.allow.is_empty() {
                println!("allow     {}", cfg.model.allow.join(", "));
            }
            let m = cfg.resolve_model(&cfg.model.default);
            if let Some((p, id)) = m.split_once('/') {
                let pin = cfg.model.context_length;
                if let Some(i) = modelsdb::lookup_for(Some(p), id) {
                    let price = i.pricing.map(|p| format!(" · ${:.2}/${:.2} per M ({})", p.input, p.output, p.source)).unwrap_or_default();
                    let ctx = ark_model::contextpin::window(id, ps.config(p).map(|c| c.base_url.as_str()).unwrap_or(""), pin);
                    println!("info      context {}{} · max output {}{price}", ctx, ark_model::contextpin::suffix(ctx, pin), i.max_output);
                } else if let Some(pin) = pin {
                    println!("info      context {}{}", pin, ark_model::contextpin::suffix(pin, Some(pin)));
                }
                println!("auth      {}", ps.key_source(p).map(String::from).unwrap_or_else(|e| e));
            }
            Ok(0)
        }
        "list" | "ls" | "scan" => {
            let want = a.pos(1).map(|p| ps.canonical(p).unwrap_or_else(|| p.to_string()));
            let ids: Vec<String> = match &want {
                Some(p) => vec![p.clone()],
                None => ps.configs().keys().filter(|id| ps.key_source(id).is_ok() && !ps.configs()[*id].keyless()).cloned().collect(),
            };
            let mut out = serde_json::Map::new();
            for id in ids {
                let c = ps.config(&id).ok_or_else(|| format!("unknown provider `{id}`"))?;
                match models_of(&ps, c) {
                    Ok(list) => {
                        if !a.flag("json") {
                            println!("{id} ({} models)", list.len());
                            for m in &list {
                                let info = modelsdb::lookup_for(Some(&id), m);
                                let extra = info.map(|i| {
                                    let ctx = ark_model::contextpin::window(m, c.base_url.as_str(), cfg.model.context_length);
                                    format!("  ctx {}{}{}", ctx, ark_model::contextpin::suffix(ctx, cfg.model.context_length), i.pricing.map(|p| format!("  ${:.2}/${:.2}", p.input, p.output)).unwrap_or_default())
                                }).unwrap_or_default();
                                println!("  {id}/{m}{extra}");
                            }
                        }
                        out.insert(id.clone(), json!(list));
                    }
                    Err(e) => {
                        if want.is_some() {
                            return Err(e);
                        }
                        eprintln!("{id}: {e}");
                    }
                }
            }
            if a.flag("json") {
                println!("{}", Value::Object(out));
            }
            Ok(0)
        }
        "providers" => {
            for p in ark_model::catalog::catalog() {
                let st = ps.key_source(&p.cfg.id).map(|s| format!("ready ({s})")).unwrap_or_else(|_| "not configured".into());
                let al = if p.aliases.is_empty() { String::new() } else { format!(" [{}]", p.aliases.join(", ")) };
                println!("{:<26} {:<36} {st}{al}", p.cfg.id, p.name);
            }
            Ok(0)
        }
        "set" => {
            let m = canonical_model(cfg, &ps, a.need(1, "provider/model")?);
            let key = a.val("as").unwrap_or("default");
            if !matches!(key, "default" | "aux" | "subagent") {
                return Err("--as must be default, aux or subagent".into());
            }
            for w in [cost_warning(cfg, &m), data_policy_warning(&m)].into_iter().flatten() {
                if !a.flag("yes") {
                    return Err(format!("{w}; re-run with --yes to confirm"));
                }
                eprintln!("⚠ {w}");
            }
            set_config_value(&user, "model", key, Some(&toml_str(&m)))?;
            println!("model.{key} = {m}");
            Ok(0)
        }
        "aliases" | "alias" => match a.pos(1).unwrap_or("list") {
            "list" | "ls" => {
                for (k, v) in &cfg.model.aliases {
                    println!("{k} → {v}");
                }
                Ok(0)
            }
            "add" | "set" => {
                let (n, t) = (a.need(2, "name")?, canonical_model(cfg, &ps, a.need(3, "provider/model")?));
                set_config_value(&user, "model.aliases", n, Some(&toml_str(&t)))?;
                println!("alias {n} → {t}");
                Ok(0)
            }
            "rm" | "remove" => {
                set_config_value(&user, "model.aliases", a.need(2, "name")?, None)?;
                Ok(0)
            }
            o => Err(format!("unknown `models aliases {o}`")),
        },
        "fallbacks" | "fallback" => cmd_fallback_inner(a, 1, &user, cfg, &ps),
        "auth" => {
            // `ark models auth [<subcommand>] …` == `ark auth …`; a bare provider name means
            // `ark auth list <provider>` (so `ark models auth groq` lists groq's credentials).
            let rest: Vec<String> = a.pos.iter().skip(1).cloned().collect();
            const SUBS: &[&str] = &["add", "list", "ls", "remove", "rm", "reset", "priority", "strategy", "refresh", "status", "logout"];
            let mut args: Vec<String> = match rest.first().map(String::as_str) {
                Some(x) if SUBS.contains(&x) => rest,
                _ => std::iter::once("list".to_string()).chain(rest).collect(),
            };
            if let Some(agent) = a.val("agent") {
                args.push("--agent".into());
                args.push(agent.to_string());
            }
            cmd_auth(&Args::parse(&args).map_err(|e| e.to_string())?, paths, cfg, vault.clone())
        }
        "refresh" => {
            let (n, changed) = modelsdb::refresh(a.val("url"))?;
            println!("models.dev: {n} models{}", if changed { " (updated)" } else { " (unchanged)" });
            Ok(0)
        }
        "pricing" | "price" => {
            let m = canonical_model(cfg, &ps, a.need(1, "provider/model")?);
            match cfg.price(&m) {
                Some(p) => println!("{m}: ${:.4}/M input · ${:.4}/M output · ${:.4}/M cache read", p.input, p.output, p.cache_read),
                None => println!("{m}: no price known (add [prices.\"{m}\"] or run `ark models refresh`)"),
            }
            Ok(0)
        }
        other => Err(format!("unknown `models {other}` (status, list, scan, providers, set, aliases, fallbacks, auth, refresh, pricing)")),
    }
}

// ───────────────────────── ark fallback ─────────────────────────

pub fn cmd_fallback(a: &Args, paths: &Paths, cfg: &Config, vault: Arc<Vault>) -> R {
    let ps = providers(cfg, vault)?;
    cmd_fallback_inner(a, 0, &paths.user_config(), cfg, &ps)
}

fn cmd_fallback_inner(a: &Args, off: usize, user: &Path, cfg: &Config, ps: &Providers) -> R {
    let mut chain = cfg.model.fallback.clone();
    match a.pos(off).unwrap_or("list") {
        "list" | "ls" => {
            println!("1. {} (default)", cfg.model.default);
            for (i, m) in chain.iter().enumerate() {
                println!("{}. {m}", i + 2);
            }
            return Ok(0);
        }
        "add" => {
            let m = canonical_model(cfg, ps, a.need(off + 1, "provider/model")?);
            if !m.contains('/') {
                return Err("fallback must be provider/model".into());
            }
            if !chain.contains(&m) {
                chain.push(m);
            }
        }
        "remove" | "rm" => {
            let t = a.need(off + 1, "provider/model or position")?;
            let before = chain.len();
            match t.parse::<usize>() {
                Ok(n) if n >= 2 && n - 2 < chain.len() => {
                    chain.remove(n - 2);
                }
                _ => chain.retain(|m| m != t),
            }
            if chain.len() == before {
                return Err(format!("`{t}` is not in the fallback chain"));
            }
        }
        "clear" => chain.clear(),
        o => return Err(format!("unknown `fallback {o}` (list, add, remove, clear)")),
    }
    set_config_value(user, "model", "fallback", Some(&toml_list(&chain)))?;
    println!("model.fallback = [{}]", chain.join(", "));
    Ok(0)
}

// ───────────────────────── usage / insights ─────────────────────────

#[derive(Default, Clone, Copy)]
pub struct Row {
    pub calls: u64,
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    pub cost: f64,
    pub priced: bool,
}

fn cost_of(cfg: &Config, model: &str, u: &ark_core::Usage) -> Option<f64> {
    let p = cfg.price(model)?;
    let cr = if p.cache_read > 0.0 { p.cache_read } else { p.input * 0.1 };
    let cw = if p.cache_write > 0.0 { p.cache_write } else { p.input };
    Some((u.input_tokens as f64 * p.input + u.cache_write_tokens as f64 * cw + u.output_tokens as f64 * p.output + u.cache_read_tokens as f64 * cr) / 1e6)
}

fn add(rows: &mut BTreeMap<String, Row>, cfg: &Config, model: &str, u: &ark_core::Usage) {
    let r = rows.entry(model.to_string()).or_default();
    r.calls += 1;
    r.input += u.input_tokens;
    r.output += u.output_tokens;
    r.cache_read += u.cache_read_tokens;
    r.cache_write += u.cache_write_tokens;
    if let Some(c) = cost_of(cfg, model, u) {
        r.cost += c;
        r.priced = true;
    }
}

/// Per-model usage over the given sessions' events.
pub fn usage_rows(cfg: &Config, sessions: &Sessions, since_ms: u64, only: Option<&str>) -> (BTreeMap<String, Row>, usize) {
    let mut rows = BTreeMap::new();
    let mut n = 0;
    for s in sessions.list() {
        if s.updated_ms < since_ms || only.is_some_and(|o| o != s.id) {
            continue;
        }
        let Ok(evs) = sessions.read(&s.id) else { continue };
        n += 1;
        for e in evs.iter().filter(|e| e.ts >= since_ms) {
            match &e.kind {
                EventKind::Message { usage: Some(u), model: Some(m), .. } => add(&mut rows, cfg, m, u),
                EventKind::AuxUsage { model, usage, task } => add(&mut rows, cfg, &format!("{model} ({task})"), usage),
                _ => {}
            }
        }
    }
    (rows, n)
}

fn fmt_rows(rows: &BTreeMap<String, Row>) -> String {
    let mut out = String::new();
    let mut tot = Row::default();
    for (m, r) in rows {
        out.push_str(&format!("{m:<48} {:>5} calls {:>10} in {:>9} out {:>9} cached  {}\n", r.calls, r.input, r.output, r.cache_read, if r.priced { format!("${:.4}", r.cost) } else { "-".into() }));
        tot.calls += r.calls;
        tot.input += r.input;
        tot.output += r.output;
        tot.cache_read += r.cache_read;
        tot.cost += r.cost;
    }
    out.push_str(&format!("{:<48} {:>5} calls {:>10} in {:>9} out {:>9} cached  ${:.4}", "total", tot.calls, tot.input, tot.output, tot.cache_read, tot.cost));
    out
}

fn account_lines(cfg: &Config, vault: Arc<Vault>) -> Vec<String> {
    let Ok(ps) = providers(cfg, vault) else { return vec![] };
    let mut seen = std::collections::BTreeSet::new();
    let mut out = vec![];
    for m in std::iter::once(&cfg.model.default).chain(cfg.model.fallback.iter()) {
        let Some((p, _)) = cfg.resolve_model(m).split_once('/') else { continue };
        let Some(id) = ps.canonical(p) else { continue };
        if !seen.insert(id.clone()) || !ark_model::accounts::supported(&id) {
            continue;
        }
        let Some(c) = ps.config(&id) else { continue };
        let Some(src) = first_cred(&ps, c) else { continue };
        out.push(match src.get().map_err(|e| e.message).and_then(|cr| ark_model::accounts::fetch(&id, &cr)) {
            Ok(acc) => ark_model::accounts::describe(&acc),
            Err(e) => format!("{id}: {e}"),
        });
    }
    out
}

pub fn cmd_usage(a: &Args, paths: &Paths, cfg: &Config, vault: Arc<Vault>) -> R {
    // ent-070: spend per user / team (session owners, the `ark users` registry and its teams).
    if let Some(by) = a.val("by") {
        return crate::ops::enterprise::usage_by(a, by).map_err(|e| e.to_string());
    }
    let days = a.num::<u64>("days")?.unwrap_or(30);
    let since = ark_model::ratelimit::now_ms().saturating_sub(days * 86_400_000);
    let sessions = Sessions::new(paths.sessions());
    let (rows, n) = usage_rows(cfg, &sessions, since, a.val("session"));
    if a.flag("json") {
        let v: serde_json::Map<String, Value> = rows.iter().map(|(m, r)| (m.clone(), json!({"calls": r.calls, "input": r.input, "output": r.output, "cache_read": r.cache_read, "cache_write": r.cache_write, "cost_usd": r.priced.then_some(r.cost)}))).collect();
        println!("{}", json!({"days": days, "sessions": n, "models": v}));
    } else {
        println!("usage over the last {days} day(s), {n} session(s)\n{}", fmt_rows(&rows));
    }
    if a.flag("account") {
        for l in account_lines(cfg, vault.clone()) {
            println!("{l}");
        }
    }
    if a.flag("billing") {
        let lines = billing_lines(&vault, days);
        if lines.is_empty() {
            println!("billing: set ANTHROPIC_ADMIN_KEY and/or OPENAI_ADMIN_KEY (env or `ark secrets set`) to compare with what the provider billed");
        }
        for l in lines {
            println!("{l}");
        }
    }
    Ok(0)
}

/// Provider-side billed spend for every provider whose admin key is available.
fn billing_lines(vault: &Vault, days: u64) -> Vec<String> {
    let mut out = vec![];
    for p in ["anthropic", "openai"] {
        let Some(name) = ark_model::billing::admin_key_name(p) else { continue };
        let from_vault = vault.substitute(&format!("{{{{secret:{name}}}}}"));
        let key = std::env::var(name).ok().filter(|k| !k.is_empty()).or_else(|| (!from_vault.starts_with("{{secret:")).then_some(from_vault));
        let Some(key) = key else { continue };
        out.push(match ark_model::billing::fetch(p, &key, days) {
            Ok(s) => ark_model::billing::describe(&s),
            Err(e) => format!("{p}: billing report failed: {e}"),
        });
    }
    out
}

pub fn insights(cfg: &Config, sessions: &Sessions, days: u64) -> String {
    let since = ark_model::ratelimit::now_ms().saturating_sub(days * 86_400_000);
    let mut tools: BTreeMap<String, u64> = BTreeMap::new();
    let mut skills: BTreeMap<String, u64> = BTreeMap::new();
    let mut sources: BTreeMap<String, u64> = BTreeMap::new();
    let mut tool_errors = 0u64;
    let (mut nsess, mut turns, mut msgs) = (0u64, 0u64, 0u64);
    let mut days_active = std::collections::BTreeSet::new();
    let mut ends: BTreeMap<String, u64> = BTreeMap::new();
    for s in sessions.list() {
        if s.updated_ms < since {
            continue;
        }
        let Ok(evs) = sessions.read(&s.id) else { continue };
        nsess += 1;
        for e in evs.iter().filter(|e| e.ts >= since) {
            days_active.insert(e.ts / 86_400_000);
            match &e.kind {
                EventKind::ToolCalled { name, input, .. } => {
                    *tools.entry(name.clone()).or_default() += 1;
                    if name == "skill" {
                        if let Some(n) = input["name"].as_str() {
                            *skills.entry(n.to_string()).or_default() += 1;
                        }
                    }
                }
                EventKind::ToolSettled { is_error: true, .. } => tool_errors += 1,
                EventKind::Inbox { source, .. } => *sources.entry(source.split(':').next().unwrap_or(source).to_string()).or_default() += 1,
                EventKind::TurnEnd { reason, .. } => {
                    turns += 1;
                    *ends.entry(reason.split(':').next().unwrap_or(reason).to_string()).or_default() += 1;
                }
                EventKind::Message { .. } => msgs += 1,
                _ => {}
            }
        }
    }
    let (rows, _) = usage_rows(cfg, sessions, since, None);
    let top = |m: &BTreeMap<String, u64>, n: usize| -> String {
        let mut v: Vec<(&String, &u64)> = m.iter().collect();
        v.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        if v.is_empty() {
            return "-".into();
        }
        v.iter().take(n).map(|(k, c)| format!("{k} ×{c}")).collect::<Vec<_>>().join(", ")
    };
    let total_calls: u64 = tools.values().sum();
    let cost: f64 = rows.values().map(|r| r.cost).sum();
    let tokens: u64 = rows.values().map(|r| r.input + r.output).sum();
    let mut models: BTreeMap<String, u64> = BTreeMap::new();
    for (m, r) in &rows {
        models.insert(m.clone(), r.calls);
    }
    format!(
        "insights · last {days} day(s)\nsessions {nsess} · turns {turns} · messages {msgs} · active days {}\ntokens {tokens} · est. cost ${cost:.4}\nmodels: {}\ntools ({total_calls} calls, {tool_errors} errors): {}\nskills: {}\nsources: {}\nturn endings: {}",
        days_active.len(),
        top(&models, 8),
        top(&tools, 10),
        top(&skills, 8),
        top(&sources, 8),
        top(&ends, 6)
    )
}

pub fn cmd_insights(a: &Args, paths: &Paths, cfg: &Config) -> R {
    let days = a.num::<u64>("days")?.unwrap_or(30);
    println!("{}", insights(cfg, &Sessions::new(paths.sessions()), days));
    Ok(0)
}

// ───────────────────────── slash commands ─────────────────────────

/// `/usage` footer mode for one session (`/usage off|tokens|full|cost`): 0 off, 1 tokens,
/// 2 full, 3 cost. Stored per session in `<data>/display.json` (never process-global), so
/// `/usage full` in one channel or session does not change another's footer.
pub fn footer_mode(paths: &Paths, id: &str) -> u8 {
    match crate::slash::display_get(paths, id)["usage_footer"].as_str() {
        Some("tokens") => 1,
        Some("full") => 2,
        Some("cost") => 3,
        _ => 0,
    }
}

/// Show reasoning deltas while streaming (`/reasoning on|stream`) — per session
/// (`display.json` key `reasoning`).
pub fn show_reasoning_for(paths: &Paths, id: &str) -> bool {
    crate::slash::display_get(paths, id)["reasoning"] == json!(true)
}

/// [`show_reasoning_for`] for callers that only hold a kernel.
pub fn show_reasoning(k: &Kernel, id: &str) -> bool {
    show_reasoning_for(&k.paths, id)
}

/// Footer line after a reply in `ark chat` (per `/usage off|tokens|full|cost`).
pub fn footer(k: &Kernel, id: &str) -> Option<String> {
    let mode = footer_mode(&k.paths, id);
    if mode == 0 {
        return None;
    }
    let v = project(&k.store.read(id).ok()?);
    let (rows, _) = usage_rows(&k.cfg, &k.store, 0, Some(id));
    let cost: f64 = rows.values().map(|r| r.cost).sum();
    Some(match mode {
        1 => format!("· {} tokens", v.usage.total()),
        3 => format!("· session cost ${cost:.4}"),
        _ => format!("· {} in · {} out · {} cached · aux {} · ${cost:.4} · {}", v.usage.input_tokens, v.usage.output_tokens, v.usage.cache_read_tokens, v.aux_usage.total(), v.model),
    })
}

pub const SLASH: &[(&str, &str)] = &[
    ("model", "show or switch the session model (`/model provider/model|alias [confirm]`)"),
    ("models", "list providers, or the models of one (`/models [provider]`)"),
    ("think", "reasoning level: off|minimal|low|medium|high|xhigh|max|default"),
    ("reasoning", "reasoning level, or display on|off|stream"),
    ("fast", "fast mode / service tier: on|off|ultrafast|flex|auto|cold|status"),
    ("usage", "session tokens, cost, rate limits and account windows; footer off|tokens|full|cost"),
    ("insights", "usage analytics (`/insights [days]`)"),
    ("login", "connect a provider account in this chat (`/login <provider>`)"),
];

/// Handle a model/usage slash command for session `id`. None = not ours.
pub fn slash(k: &Kernel, id: &str, line: &str) -> Option<String> {
    slash_on(k, id, line, "cli")
}

/// [`slash`] for a named surface: `cli` (the chat REPL, a private terminal) or `channel`
/// (a chat bridge). Provider logins only run on a private surface — a device code posted into
/// a group chat is a credential leak (OpenClaw `isPrivateLoginContext`).
pub fn slash_on(k: &Kernel, id: &str, line: &str, surface: &str) -> Option<String> {
    let line = line.trim();
    let cmd = line.strip_prefix('/')?;
    let (name, arg) = cmd.split_once(char::is_whitespace).map(|(a, b)| (a, b.trim())).unwrap_or((cmd, ""));
    let name = match name {
        "t" => "think",
        n => n,
    };
    if !SLASH.iter().any(|(n, _)| *n == name) {
        return None;
    }
    let view = || k.store.read(id).map(|e| project(&e)).map_err(|e| e.to_string());
    let ps = || providers(&k.cfg, k.vault.clone());
    Some(match name {
        "model" if arg.is_empty() => match view() {
            Ok(v) => {
                let al = k.cfg.model.aliases.iter().map(|(a, m)| format!("{a}→{m}")).collect::<Vec<_>>().join(", ");
                format!("model {} (default {}){}", v.model, k.cfg.model.default, if al.is_empty() { String::new() } else { format!("\naliases: {al}") })
            }
            Err(e) => format!("error: {e}"),
        },
        "model" => {
            let (m, confirm) = match arg.rsplit_once(' ') {
                Some((m, "confirm" | "--yes" | "yes")) => (m.trim(), true),
                _ => (arg, false),
            };
            let m = match ps() {
                Ok(p) => canonical_model(&k.cfg, &p, m),
                Err(_) => m.to_string(),
            };
            let warns: Vec<String> = [cost_warning(&k.cfg, &m), data_policy_warning(&m)].into_iter().flatten().collect();
            if !warns.is_empty() && !confirm {
                return Some(format!("⚠ {}\nSend `/model {m} confirm` to switch anyway.", warns.join("\n⚠ ")));
            }
            match k.set_model(id, &m) {
                Ok(()) => format!("model → {m}"),
                Err(e) => format!("error: {e}"),
            }
        }
        "models" => match ps() {
            Err(e) => format!("error: {e}"),
            Ok(p) if arg.is_empty() => {
                let ready: Vec<String> = p.configs().keys().filter(|id| p.key_source(id).is_ok() && !p.configs()[*id].keyless()).cloned().collect();
                format!("providers with credentials: {}\n`/models <provider>` lists its models; `ark models providers` shows all {}.", if ready.is_empty() { "none".into() } else { ready.join(", ") }, p.configs().len())
            }
            Ok(p) => {
                let Some(c) = p.config(arg) else { return Some(format!("unknown provider `{arg}`")) };
                let id = c.id.clone();
                match models_of(&p, c) {
                    Ok(l) => format!("{id}: {}", l.iter().take(80).map(|m| format!("{id}/{m}")).collect::<Vec<_>>().join("\n")),
                    Err(e) => format!("{id}: {e}"),
                }
            }
        },
        "think" | "reasoning" => {
            let a = arg.to_lowercase();
            if name == "reasoning" && matches!(a.as_str(), "on" | "show" | "stream" | "off" | "hide") {
                let on = matches!(a.as_str(), "on" | "show" | "stream");
                if let Err(e) = crate::slash::display_set(&k.paths, id, "reasoning", json!(on)) {
                    return Some(format!("error: {e}"));
                }
                return Some(format!("reasoning display {}", if show_reasoning(k, id) { "on" } else { "off" }));
            }
            if a.is_empty() || a == "status" {
                return Some(match view() {
                    Ok(v) => format!("thinking: {} (levels {})", v.thinking.or_else(|| Some(k.cfg.model.thinking.clone()).filter(|t| !t.is_empty())).unwrap_or_else(|| "provider default".into()), ark_model::reasoning::help()),
                    Err(e) => format!("error: {e}"),
                });
            }
            match ark_model::reasoning::normalize(&a) {
                Some(l) => match k.set_thinking(id, l) {
                    Ok(()) => format!("thinking → {}", if l.is_empty() { "default" } else { l }),
                    Err(e) => format!("error: {e}"),
                },
                None => format!("unknown level `{arg}`; use {}", ark_model::reasoning::help()),
            }
        }
        "fast" => {
            if arg.is_empty() || arg == "status" {
                return Some(match view() {
                    Ok(v) => {
                        let mode = v.fast.unwrap_or_else(|| if k.cfg.model.fast.is_empty() { "normal".into() } else { k.cfg.model.fast.clone() });
                        let (p, m) = v.model.split_once('/').unwrap_or(("", &v.model));
                        let note = if p == "anthropic" && !ark_model::fast_capable(m) { " (this model has no Anthropic fast mode; the setting is ignored)" } else { "" };
                        format!("fast mode: {mode}{note}")
                    }
                    Err(e) => format!("error: {e}"),
                });
            }
            match k.set_fast(id, arg) {
                Ok(()) => format!("fast mode → {arg}"),
                Err(e) => format!("error: {e}"),
            }
        }
        "usage" => {
            match arg {
                "off" | "tokens" | "full" | "cost" => {
                    if let Err(e) = crate::slash::display_set(&k.paths, id, "usage_footer", json!(arg)) {
                        return Some(format!("error: {e}"));
                    }
                    return Some(format!("usage footer: {arg}"));
                }
                "" | "status" | "account" => {}
                o => return Some(format!("unknown `/usage {o}` (off, tokens, full, cost)")),
            }
            let v = match view() {
                Ok(v) => v,
                Err(e) => return Some(format!("error: {e}")),
            };
            let (rows, _) = usage_rows(&k.cfg, &k.store, 0, Some(id));
            let mut out = format!("session {id} · {} turns\n{}", v.turns, fmt_rows(&rows));
            let (p, m) = v.model.split_once('/').unwrap_or(("", &v.model));
            let window = ark_model::contextpin::window(m, "", k.cfg.model.context_length).max(1);
            out.push_str(&format!("\ncontext: {} of {} tokens ({:.0}%)", v.last_input_tokens, window, v.last_input_tokens as f64 * 100.0 / window as f64));
            if let Some(s) = ark_model::ratelimit::get(p) {
                out.push_str(&format!("\nrate limits ({p}): {}", ark_model::ratelimit::describe(&s)));
            }
            for l in account_lines(&k.cfg, k.vault.clone()) {
                out.push_str(&format!("\naccount {l}"));
            }
            out
        }
        "insights" => insights(&k.cfg, &k.store, arg.parse().unwrap_or(7)),
        "login" if arg.is_empty() => {
            let flows: Vec<String> = login::flows().iter().map(|f| format!("{} ({})", f.id, f.title)).collect();
            format!("Connect a provider account with `/login <provider>` (or `ark login <provider>` in a terminal).\nAvailable: {}\nAPI keys: `ark auth add <provider>` or `ark secrets set <ENV_VAR>`.", flows.join(", "))
        }
        "login" => {
            if surface != "cli" {
                return Some(format!(
                    "Provider logins only run in a private terminal session; run `ark login {arg}` on the host, then `/models {arg}`."
                ));
            }
            match inline_login(arg, &k.paths) {
                Ok(t) => t,
                Err(e) => format!("error: {e}"),
            }
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_editing_keeps_comments_and_replaces_arrays() {
        let d = std::env::temp_dir().join(format!("ark-cfgedit-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("c.toml");
        std::fs::write(&f, "# my config\n[model]\ndefault = \"a/b\" # keep\nfallback = [\n  \"x/y\",\n]\n\n[gate]\nprivilege = \"ask\"\n").unwrap();
        set_config_value(&f, "model", "default", Some("\"c/d\"")).unwrap();
        set_config_value(&f, "model", "fallback", Some(&toml_list(&["p/q".into()]))).unwrap();
        set_config_value(&f, "model.aliases", "fast", Some("\"groq/llama\"")).unwrap();
        let t = std::fs::read_to_string(&f).unwrap();
        assert!(t.starts_with("# my config"));
        let v: toml::Table = t.parse().unwrap();
        assert_eq!(v["model"]["default"].as_str(), Some("c/d"));
        assert_eq!(v["model"]["fallback"].as_array().unwrap().len(), 1);
        assert_eq!(v["model"]["aliases"]["fast"].as_str(), Some("groq/llama"));
        assert_eq!(v["gate"]["privilege"].as_str(), Some("ask"));
        set_config_value(&f, "model.aliases", "fast", None).unwrap();
        let v: toml::Table = std::fs::read_to_string(&f).unwrap().parse().unwrap();
        assert!(v["model"]["aliases"].as_table().unwrap().is_empty());
    }

    /// Minimal ordered-reply HTTP server (the login/model tests must not touch the network).
    fn fake_server(replies: Vec<String>) -> String {
        use std::io::{BufRead, BufReader, Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            let mut i = 0;
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut len = 0usize;
                loop {
                    let mut h = String::new();
                    if r.read_line(&mut h).is_err() || h.trim().is_empty() {
                        break;
                    }
                    if let Some((k, v)) = h.split_once(':') {
                        if k.eq_ignore_ascii_case("content-length") {
                            len = v.trim().parse().unwrap_or(0);
                        }
                    }
                }
                let mut body = vec![0; len];
                let _ = r.read_exact(&mut body);
                let b = replies.get(i).or(replies.last()).cloned().unwrap_or_default();
                i += 1;
                let _ = write!(s, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{b}", b.len());
            }
        });
        base
    }

    fn paths(name: &str) -> Paths {
        let root = std::env::temp_dir().join(format!("ark-models-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("config")).unwrap();
        std::fs::create_dir_all(root.join("data")).unwrap();
        Paths { data: root.join("data"), config_dir: root.join("config"), runtime: root.join("run") }
    }

    #[test]
    fn login_slash_completes_the_flow_and_stores_the_credential() {
        let now = ark_model::ratelimit::now_ms() / 1000;
        let head = ark_net::crypto::b64url(br#"{"alg":"none","typ":"JWT"}"#);
        let body = ark_net::crypto::b64url(
            format!(r#"{{"exp":{},"scope":"inference:invoke"}}"#, now + 3600).as_bytes(),
        );
        let jwt = format!("{head}.{body}.");
        let srv = fake_server(vec![
            r#"{"device_code":"dc1","user_code":"NOUS-9","verification_uri":"https://n/device","interval":1,"expires_in":60}"#.into(),
            format!(r#"{{"access_token":"{jwt}","refresh_token":"rt-1","expires_in":3600,"scope":"inference:invoke"}}"#),
        ]);
        std::env::set_var("NOUS_PORTAL_BASE_URL", &srv);
        let p = paths("login");
        let out = inline_login("nous", &p).unwrap();
        assert!(out.contains("NOUS-9"), "{out}");
        assert!(out.contains("signed in: Nous Portal"), "{out}");
        assert!(out.contains("provider `nous`"), "{out}");
        let e = Store::new(p.config_dir.join("auth.json")).entries("nous");
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].extra["agent_key"].as_str(), Some(jwt.as_str()));
        // Flows that need a pasted value cannot run inside a chat turn.
        let err = inline_login("anthropic-setup-token", &p).unwrap_err();
        assert!(err.contains("ark login anthropic-setup-token"), "{err}");
        assert!(inline_login("no-such-provider", &p).unwrap_err().contains("no login flow"));
        std::env::remove_var("NOUS_PORTAL_BASE_URL");
    }

    #[test]
    fn models_auth_status_lists_vault_keys() {
        // Regression: `ark models auth status` used to be handed an empty vault, so keys stored
        // with `ark secrets set` were invisible.
        let p = paths("vault");
        let cfg = Config::default();
        let v = Arc::new(Vault::empty());
        v.set("SILICONFLOW_API_KEY", "sk-from-vault-9").unwrap();
        let lines = auth_status_lines(&cfg, v.clone(), "siliconflow").unwrap().join("\n");
        assert!(lines.contains("vault"), "{lines}");
        assert!(lines.contains("usable"), "{lines}");
        // …and through the `ark models auth` dispatch itself: `status <provider>`, and the bare
        // `<provider>` form (list) that had no pooled credential to print.
        let a = Args::parse(&["auth".to_string(), "status".to_string(), "siliconflow".to_string()]).unwrap();
        assert_eq!(cmd_models(&a, &p, &cfg, v.clone()).unwrap(), 0);
        let a = Args::parse(&["auth".to_string(), "siliconflow".to_string()]).unwrap();
        assert_eq!(cmd_models(&a, &p, &cfg, v.clone()).unwrap(), 0);
        assert!(
            auth_status_lines_for(&cfg, v.clone(), Some(&p), "siliconflow", None).unwrap().join("\n").contains("vault"),
            "the vault key is listed for the provider"
        );
        // The former bug: an empty vault there hid the key completely.
        assert!(!auth_status_lines_for(&cfg, Arc::new(Vault::empty()), Some(&p), "siliconflow", None)
            .unwrap()
            .join("\n")
            .contains("vault"));
        let empty = auth_status_lines(&cfg, Arc::new(Vault::empty()), "siliconflow").unwrap().join("\n");
        assert!(!empty.contains("vault"), "an empty vault must not claim one: {empty}");
    }

    #[test]
    fn model_command_writes_the_default_model() {
        // `ark model <provider/model>` — the non-interactive path of the picker.
        let p = paths("model");
        let cfg = Config::default();
        let a = Args::parse(&["groq/llama-3.3-70b".to_string()]).unwrap();
        assert_eq!(cmd_model(&a, &p, &cfg, Arc::new(Vault::empty())).unwrap(), 0);
        let t: toml::Table = std::fs::read_to_string(p.user_config()).unwrap().parse().unwrap();
        assert_eq!(t["model"]["default"].as_str(), Some("groq/llama-3.3-70b"));
        // Aliases resolve to the canonical provider, and a bare model name is refused.
        let a = Args::parse(&["grok/grok-4.6".to_string()]).unwrap();
        assert_eq!(cmd_model(&a, &p, &cfg, Arc::new(Vault::empty())).unwrap(), 0);
        let t: toml::Table = std::fs::read_to_string(p.user_config()).unwrap().parse().unwrap();
        assert_eq!(t["model"]["default"].as_str(), Some("xai/grok-4.6"));
        let a = Args::parse(&["llama-3.3-70b".to_string()]).unwrap();
        assert!(cmd_model(&a, &p, &cfg, Arc::new(Vault::empty())).unwrap_err().contains("provider/model"));
    }

    #[test]
    fn auth_agent_profiles_are_per_agent_and_follow_the_env() {
        let p = paths("agentprof");
        let mut cfg = Config::default();
        cfg.pricing.auto_refresh = false;
        // A shared key, then a key added to the `reviewer` agent's own profile store.
        let a = Args::parse(&["add".into(), "groq".into(), "--api-key".into(), "gsk-shared-1".into()]).unwrap();
        assert_eq!(cmd_auth(&a, &p, &cfg, Arc::new(Vault::empty())).unwrap(), 0);
        let a = Args::parse(&[
            "--agent".into(), "reviewer".into(), "add".into(), "groq".into(),
            "--api-key".into(), "gsk-reviewer-2".into(),
        ]).unwrap();
        assert_eq!(cmd_auth(&a, &p, &cfg, Arc::new(Vault::empty())).unwrap(), 0);
        assert!(p.config_dir.join("agents/reviewer/auth.json").exists());
        let shared = Store::new(p.config_dir.join("auth.json")).entries("groq");
        assert_eq!(shared.len(), 1, "the agent key must not leak into the shared pool");
        // `ark auth --agent reviewer list` sees both, agent-local first.
        let lanes = auth_status_lines_for(&cfg, Arc::new(Vault::empty()), Some(&p), "groq", Some("reviewer")).unwrap();
        assert!(lanes[0].starts_with("groq:"), "{lanes:?}");
        assert_eq!(lanes.len(), 3, "source + two credentials: {lanes:?}");
        assert!(lanes[1].contains("`key-2`"), "agent-local key first: {lanes:?}");
        assert!(lanes[2].contains("`key-1`"), "then the inherited shared key: {lanes:?}");
        // The process pool follows `$ARK_AGENT` (channels / `ark chat` with an agent).
        std::env::set_var("ARK_AGENT", "reviewer");
        init(&p, &cfg);
        let def = ark_model::store::default_store().unwrap();
        assert!(def.is_agent_scoped());
        assert_eq!(def.entries("groq").len(), 2);
        std::env::remove_var("ARK_AGENT");
        init(&p, &cfg);
        assert_eq!(ark_model::store::default_store().unwrap().entries("groq").len(), 1);
    }

    #[test]
    fn models_status_shows_per_task_routes_and_bench_marks() {
        let mut cfg = Config::default();
        let t: toml::Table = r#"
provider = "dashscope"
model = "qwen3.7-plus"
fallback = ["zai/glm-5.3"]
"#
        .parse()
        .unwrap();
        cfg.auxiliary.insert("vision".into(), t);
        cfg.model.tasks.insert("compaction".into(), "groq/llama-3.3-70b".into());
        let lines = aux_route_lines(&cfg).join("\n");
        assert!(lines.contains("route vision"), "{lines}");
        assert!(lines.contains("dashscope/qwen3.7-plus → zai/glm-5.3"), "{lines}");
        assert!(lines.contains("route compaction"), "{lines}");
        ark_model::aux::mark_down("dashscope", "rate limit");
        let lines = aux_route_lines(&cfg).join("\n");
        assert!(lines.contains("dashscope/qwen3.7-plus (held out)"), "{lines}");
        ark_model::aux::clear("dashscope");
    }

    #[test]
    fn guards() {
        let mut cfg = Config::default();
        cfg.prices.insert("x/pricey".into(), Price { input: 30.0, output: 150.0, cache_read: 0.0, cache_write: 0.0 });
        assert!(cost_warning(&cfg, "x/pricey").unwrap().contains("$30.00/M input"));
        assert!(cost_warning(&cfg, "anthropic/claude-haiku-4-5").is_none());
        assert!(data_policy_warning("meta-ai/muse-spark-1.3-contributor").is_some());
        assert!(data_policy_warning("meta-ai/muse-spark-1.3").is_none());
    }

    /// `/reasoning` and the `/usage` footer are per session: what one channel or session
    /// sets must not change what another shows (they used to be process-global atomics).
    #[test]
    fn reasoning_and_usage_footer_are_per_session() {
        let t = crate::testkit::kit();
        let a = t.k.create_session(&t.ws, None, None, None).unwrap();
        let b = t.k.create_session(&t.ws, None, None, None).unwrap();
        // Defaults: reasoning hidden, no footer, for both sessions.
        for id in [&a, &b] {
            assert_eq!(footer_mode(&t.paths, id), 0);
            assert!(!show_reasoning_for(&t.paths, id));
            assert!(footer(&t.k, id).is_none());
        }
        // Session A: cost footer + reasoning display.
        assert_eq!(slash(&t.k, &a, "/usage cost").as_deref(), Some("usage footer: cost"));
        assert_eq!(slash(&t.k, &a, "/reasoning on").as_deref(), Some("reasoning display on"));
        assert_eq!(footer_mode(&t.paths, &a), 3);
        assert!(show_reasoning(&t.k, &a));
        assert!(footer(&t.k, &a).unwrap().contains("session cost"), "{:?}", footer(&t.k, &a));
        // Session B keeps its defaults: nothing leaked from A.
        assert_eq!(footer_mode(&t.paths, &b), 0);
        assert!(!show_reasoning_for(&t.paths, &b));
        assert!(footer(&t.k, &b).is_none());
        // Turning A's reasoning display off (the default value) still only touches A.
        assert_eq!(slash(&t.k, &a, "/reasoning off").as_deref(), Some("reasoning display off"));
        assert!(!show_reasoning(&t.k, &a));
        assert!(!show_reasoning_for(&t.paths, &b));
        // A third session reads the same defaults while A has a footer configured.
        let c = t.k.create_session(&t.ws, None, None, None).unwrap();
        assert!(footer(&t.k, &c).is_none());
        assert!(footer(&t.k, &a).is_some());
        // `/usage off` clears A's footer only; `/usage full|tokens` map to their own modes.
        assert_eq!(slash(&t.k, &a, "/usage tokens").as_deref(), Some("usage footer: tokens"));
        assert_eq!(footer_mode(&t.paths, &a), 1);
        assert!(footer(&t.k, &a).unwrap().contains("tokens"));
        assert_eq!(slash(&t.k, &a, "/usage full").as_deref(), Some("usage footer: full"));
        assert_eq!(footer_mode(&t.paths, &a), 2);
        assert_eq!(slash(&t.k, &a, "/usage off").as_deref(), Some("usage footer: off"));
        assert_eq!(footer_mode(&t.paths, &a), 0);
        assert!(footer(&t.k, &a).is_none());
        // The stored values live in the session's display.json entry.
        let d = crate::slash::display_get(&t.paths, &a);
        assert_eq!(d["reasoning"], json!(false));
        assert_eq!(d["usage_footer"], json!("off"));
        assert_eq!(crate::slash::display_get(&t.paths, &b), json!({}));
    }
}
