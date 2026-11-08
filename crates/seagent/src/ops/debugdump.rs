//! Support diagnostics: `seagent dump` (Hermes `hermes dump`), `seagent debug share|delete|list`
//! (Hermes `hermes debug`), the `/debug` chat command (Hermes: upload a report; OpenClaw:
//! `show|set|unset|reset` runtime debug overrides).
//!
//! `dump` is a compact, copy-pasteable setup summary: version, OS, profile, model,
//! which API keys are set (never the values; `--show-keys` shows first/last 4 chars)
//! and whether a key exported in this shell is missing from `.env` (a service-managed
//! daemon only sees `.env`), features and non-default config.
//!
//! `debug share` uploads the dump plus log tails to paste.rs (fallback dpaste.com),
//! force-redacted unless `--no-redact`, after a privacy notice and confirmation
//! (`--yes` required without a TTY). paste.rs pastes are recorded and deleted after
//! 6 hours by the next `seagent debug …` run; `debug delete <url>` deletes now. dpaste.com
//! pastes cannot be deleted (anonymous), so their retention is `--expire` days.
//! `--local` prints the same report without any network I/O.
//!
//! Debug overrides are process-local (never written to disk) and are merged over the
//! loaded config by [`apply_overrides`]; they vanish on restart.

use crate::args::Args;
use crate::ops::net;
use crate::slash::{Ctx, Reply};
use crate::R;
use seagent_kernel::config::{Config, Paths};
use serde_json::{json, Value};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

pub const COMMANDS: &[&str] = &["dump", "debug"];
pub const VALUE_FLAGS: &[&str] = &["lines", "expire", "out"];
pub const BOOL_FLAGS: &[&str] = &["show-keys", "local", "nous", "bundle", "keep-identity"];

const PASTE_RS: &str = "https://paste.rs/";
const DPASTE: &str = "https://dpaste.com/api/";
const MAX_LOG_BYTES: usize = 512_000;
pub const AUTO_DELETE_SECONDS: u64 = 6 * 3600;

fn paste_rs_base() -> String {
    std::env::var("SEAGENT_PASTE_RS_URL").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| PASTE_RS.into())
}
fn dpaste_base() -> String {
    std::env::var("SEAGENT_DPASTE_URL").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| DPASTE.into())
}

/// (env var, label) in display order.
const API_KEYS: &[(&str, &str)] = &[
    ("OPENROUTER_API_KEY", "openrouter"),
    ("OPENAI_API_KEY", "openai"),
    ("ANTHROPIC_API_KEY", "anthropic"),
    ("GOOGLE_API_KEY", "google/gemini"),
    ("GEMINI_API_KEY", "gemini"),
    ("GROQ_API_KEY", "groq"),
    ("MISTRAL_API_KEY", "mistral"),
    ("XAI_API_KEY", "xai"),
    ("DEEPSEEK_API_KEY", "deepseek"),
    ("GLM_API_KEY", "glm/zai"),
    ("ZAI_API_KEY", "zai"),
    ("KIMI_API_KEY", "kimi"),
    ("MINIMAX_API_KEY", "minimax"),
    ("DASHSCOPE_API_KEY", "dashscope"),
    ("HF_TOKEN", "huggingface"),
    ("NVIDIA_API_KEY", "nvidia"),
    ("NOUS_API_KEY", "nous"),
    ("FIRECRAWL_API_KEY", "firecrawl"),
    ("TAVILY_API_KEY", "tavily"),
    ("PERPLEXITY_API_KEY", "perplexity"),
    ("BRAVE_API_KEY", "brave"),
    ("BROWSERBASE_API_KEY", "browserbase"),
    ("FAL_KEY", "fal"),
    ("ELEVENLABS_API_KEY", "elevenlabs"),
    ("GITHUB_TOKEN", "github"),
];

/// First and last 4 chars (Hermes `mask_secret`); short values are fully masked.
pub fn mask(v: &str) -> String {
    let n = v.chars().count();
    if n == 0 {
        return String::new();
    }
    if n <= 12 {
        return "***".into();
    }
    let head: String = v.chars().take(4).collect();
    let tail: String = v.chars().skip(n - 4).collect();
    format!("{head}...{tail}")
}

fn dotenv_names(paths: &Paths) -> Vec<String> {
    let t = std::fs::read_to_string(paths.config_dir.join(".env")).unwrap_or_default();
    crate::ops::envfile::parse(&t).into_iter().filter(|(_, v)| !v.trim().is_empty()).map(|(k, _)| k).collect()
}

fn os_line() -> String {
    let r = |p: &str| std::fs::read_to_string(p).map(|s| s.trim().to_string()).unwrap_or_default();
    let pretty = r("/etc/os-release").lines().find_map(|l| l.strip_prefix("PRETTY_NAME=").map(|v| v.trim_matches('"').to_string())).unwrap_or_default();
    format!("{} {} {}{}", std::env::consts::OS, r("/proc/sys/kernel/osrelease"), std::env::consts::ARCH, if pretty.is_empty() { String::new() } else { format!(" ({pretty})") })
}

fn daemon_status(paths: &Paths) -> String {
    match seagent_kernel::daemon::call(&paths.socket(), "ping", json!({})) {
        Ok(_) => format!("running ({})", paths.socket().display()),
        Err(_) => "stopped".into(),
    }
}

fn count_skills(paths: &Paths) -> usize {
    let mut n = 0;
    let mut stack = vec![paths.data.join("skills")];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.file_name().is_some_and(|f| f == "SKILL.md") {
                n += 1;
            }
        }
    }
    n
}

fn cron_summary(paths: &Paths) -> String {
    let p = paths.data.join("schedules.json");
    let Ok(t) = std::fs::read_to_string(&p) else { return "0".into() };
    let v: Value = match serde_json::from_str(&t) {
        Ok(v) => v,
        Err(_) => return "(error reading)".into(),
    };
    let jobs: Vec<Value> = v.as_array().cloned().or_else(|| v["jobs"].as_array().cloned()).or_else(|| v.as_object().map(|o| o.values().cloned().collect())).unwrap_or_default();
    let active = jobs.iter().filter(|j| j["enabled"] != false && j["paused"] != true).count();
    format!("{active} active / {} total", jobs.len())
}

/// Non-default values worth reporting (paths compared against `Config::default()`).
pub fn overrides(cfg: &Config) -> Vec<(String, String)> {
    let cur = toml::Value::try_from(cfg).ok();
    let def = toml::Value::try_from(Config::default()).ok();
    const INTERESTING: &[&str] = &["runner.max_steps_per_turn", "runner.busy_mode", "model.aux", "model.thinking", "compaction.enabled", "compaction.threshold", "gate.mode", "tools.shell_backend", "checkpoint.enabled", "memory.provider", "budget.max_tokens", "budget.max_cost_usd", "context_engine"];
    let get = |v: &Option<toml::Value>, path: &str| -> Option<toml::Value> {
        let mut cur = v.clone()?;
        for k in path.split('.') {
            cur = cur.get(k)?.clone();
        }
        Some(cur)
    };
    let mut out = vec![];
    for p in INTERESTING {
        let (a, b) = (get(&cur, p), get(&def, p));
        if a.is_some() && a != b {
            out.push((p.to_string(), a.map(|v| v.to_string()).unwrap_or_default()));
        }
    }
    if !cfg.model.fallback.is_empty() {
        out.push(("model.fallback".into(), format!("{:?}", cfg.model.fallback)));
    }
    out
}

/// The dump text (`show_keys` → masked prefixes instead of set/not set).
pub fn dump(paths: &Paths, cfg: &Config, show_keys: bool) -> String {
    let (provider, model) = cfg.model.default.split_once('/').map(|(p, m)| (p.to_string(), m.to_string())).unwrap_or(("(auto)".into(), cfg.model.default.clone()));
    let in_env = dotenv_names(paths);
    let mut l = vec![
        "--- seagent dump ---".to_string(),
        format!("version:          {}", env!("CARGO_PKG_VERSION")),
        format!("os:               {}", os_line()),
        format!("profile:          {}", crate::ops::profile::current()),
        format!("config_dir:       {}", paths.config_dir.display()),
        format!("data_dir:         {}", paths.data.display()),
        format!("model:            {}", if model.is_empty() { "(not set)" } else { &model }),
        format!("provider:         {provider}"),
        String::new(),
        "api_keys:".into(),
    ];
    for (var, label) in API_KEYS {
        let v = std::env::var(var).unwrap_or_default();
        let mut d = if show_keys && !v.is_empty() { mask(&v) } else if v.is_empty() { "not set".into() } else { "set".into() };
        if !v.is_empty() && !in_env.iter().any(|k| k == var) {
            d.push_str(" (shell only — not in .env; a service-managed daemon may not see it)");
        }
        l.push(format!("  {label:<20} {d}"));
    }
    let channels: Vec<String> = cfg.channels.iter().map(|(n, t)| format!("{n}({})", t.get("kind").and_then(|k| k.as_str()).unwrap_or("?"))).collect();
    l.extend([
        String::new(),
        "features:".into(),
        format!("  mcp_servers:        {}", cfg.mcp.len()),
        format!("  plugins:            {}", cfg.plugins.len()),
        format!("  memory_provider:    {}", if cfg.memory.provider.is_empty() { "built-in" } else { &cfg.memory.provider }),
        format!("  daemon:             {}", daemon_status(paths)),
        format!("  channels:           {}", if channels.is_empty() { "none".into() } else { channels.join(", ") }),
        format!("  cron_jobs:          {}", cron_summary(paths)),
        format!("  skills:             {}", count_skills(paths)),
    ]);
    let ov = overrides(cfg);
    if !ov.is_empty() {
        l.push(String::new());
        l.push("config_overrides:".into());
        l.extend(ov.into_iter().map(|(k, v)| format!("  {k}: {v}")));
    }
    l.push("--- end dump ---".into());
    l.join("\n")
}

/// Upload-time redaction: known token shapes, `key = value` credentials, URL userinfo.
pub fn redact(s: &str) -> String {
    let t = seagent_kernel::trajectory::redact_patterns(s);
    let t = crate::slash::redact(&t);
    static URL: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = URL.get_or_init(|| regex::Regex::new(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@").unwrap());
    re.replace_all(&t, "$1***:***@").into_owned()
}

fn tail_lines(p: &Path, n: usize) -> Option<(String, String)> {
    let data = std::fs::read(p).ok()?;
    let start = data.len().saturating_sub(MAX_LOG_BYTES);
    let mut text = String::from_utf8_lossy(&data[start..]).to_string();
    if start > 0 {
        // drop the partial first line
        text = text.split_once('\n').map(|(_, r)| r.to_string()).unwrap_or_default();
    }
    let lines: Vec<&str> = text.lines().collect();
    let tail = lines[lines.len().saturating_sub(n)..].join("\n");
    Some((tail, text))
}

// ───────────── de-identification (support bundles) ─────────────

/// What identifies this machine and its owner: scrubbed from anything that leaves the host.
#[derive(Debug, Clone, Default)]
pub struct Scrub {
    pub home: String,
    pub user: String,
    pub host: String,
    pub extra: Vec<(String, String)>,
}

impl Scrub {
    /// This process's identity (`$HOME`, `$USER`, `/etc/hostname`) plus the workspace path.
    pub fn here(workspace: Option<&Path>) -> Scrub {
        let host = crate::ops::hostos::etc_hostname().map(|s| s.trim().to_string()).ok().filter(|s| !s.is_empty()).or_else(|| std::env::var("HOSTNAME").ok()).unwrap_or_default();
        let user = std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).unwrap_or_default();
        let home = std::env::var("HOME").unwrap_or_default();
        let extra = workspace.map(|w| vec![(w.display().to_string(), "<workspace>".to_string())]).unwrap_or_default();
        Scrub { home, user, host, extra }
    }

    pub fn apply(&self, s: &str) -> String {
        static IP4: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        static IP6: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        static MAC: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        static MAIL: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        let ip4 = IP4.get_or_init(|| regex::Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap());
        let ip6 = IP6.get_or_init(|| regex::Regex::new(r"(?i)\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,6}:(?:[0-9a-f]{1,4})?\b").unwrap());
        let mac = MAC.get_or_init(|| regex::Regex::new(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b").unwrap());
        let mail = MAIL.get_or_init(|| regex::Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap());
        let mut t = s.to_string();
        // Longest path first so a workspace under $HOME becomes <workspace>, not ~/…
        let mut paths: Vec<&(String, String)> = self.extra.iter().filter(|(a, _)| a.len() > 1).collect();
        paths.sort_by_key(|(a, _)| std::cmp::Reverse(a.len()));
        for (from, to) in paths {
            t = t.replace(from.as_str(), to);
        }
        if self.home.len() > 1 && self.home != "/" {
            t = t.replace(&self.home, "~");
        }
        t = mail.replace_all(&t, "<email>").into_owned();
        t = mac.replace_all(&t, "<mac>").into_owned();
        t = ip6.replace_all(&t, |c: &regex::Captures| if &c[0] == "::1" { c[0].to_string() } else { "<ip6>".into() }).into_owned();
        t = ip4.replace_all(&t, |c: &regex::Captures| {
            let ip = &c[0];
            // Versions like 1.2.3.4 and loopback/unspecified addresses carry no identity.
            if ip.starts_with("127.") || ip == "0.0.0.0" || c[0].split('.').any(|o| o.parse::<u16>().map_or(true, |n| n > 255)) { ip.to_string() } else { "<ip>".into() }
        }).into_owned();
        for (word, to) in [(&self.host, "<host>"), (&self.user, "<user>")] {
            if word.chars().count() >= 3 {
                if let Ok(re) = regex::Regex::new(&format!(r"(?i)\b{}\b", regex::escape(word))) {
                    t = re.replace_all(&t, to).into_owned();
                }
            }
        }
        t
    }
}

/// `seagent debug share` uploads to a public paste service. Policy that forbids it: `SEAGENT_DEBUG_SHARE=off`,
/// a `government` compliance profile, or an administrator's `/etc/seagent/no-debug-upload`.
pub fn upload_blocked(cfg: &Config) -> Option<String> {
    if std::env::var("SEAGENT_DEBUG_SHARE").is_ok_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "off" | "0" | "no" | "false")) {
        return Some("SEAGENT_DEBUG_SHARE=off".into());
    }
    if cfg.compliance.profile == "government" {
        return Some("compliance profile `government`".into());
    }
    let flag = Path::new(seagent_core::layout::system::CONFIG).join("no-debug-upload");
    flag.exists().then(|| format!("{} exists", flag.display()))
}

/// One diagnostic section of a support bundle: file name + text (already collected).
pub type Section = (String, String);

/// The `seagent doctor --bundle` archive: `.tar.gz` bytes with the diagnostics, secrets redacted and
/// (unless `keep_identity`) host name, user name, home/workspace paths, IP/MAC addresses and
/// e-mail addresses replaced by placeholders. Nothing is sent anywhere.
pub fn support_bundle(paths: &Paths, cfg: &Config, scrub: &Scrub, extra: Vec<Section>, lines: usize, keep_identity: bool) -> Result<Vec<u8>, String> {
    use crate::ops::archive::{gzip, tar, Entry};
    let clean = |s: &str| {
        let t = redact(s);
        if keep_identity { t } else { scrub.apply(&t) }
    };
    let mut files: Vec<Section> = vec![];
    let report = bundle(paths, cfg, lines, true);
    for (label, text) in report.into_iter().filter(|(l, _)| l == "report") {
        files.push((format!("{label}.txt"), text));
    }
    let conf = std::fs::read_to_string(paths.user_config()).unwrap_or_else(|_| "(no user config)".into());
    files.push(("config.toml".into(), conf));
    files.extend(extra);
    let manifest = format!(
        "seagent support bundle\nversion: {}\ncreated: {}\nsecrets: redacted (token shapes, key = value credentials, URL passwords)\nidentity: {}\nfiles: {}\n\nReview the files before sending them; nothing here was uploaded.\n",
        env!("CARGO_PKG_VERSION"),
        seagent_kernel::util::unix_now(),
        if keep_identity { "KEPT (--keep-identity)" } else { "host name, user name, home/workspace paths, IP/MAC addresses and e-mail addresses replaced with placeholders" },
        files.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(", ")
    );
    let mut entries: Vec<Entry> = vec![Entry { path: "seagent-diagnostics/".into(), data: vec![], mode: 0o700, dir: true }];
    entries.push(Entry::file("seagent-diagnostics/MANIFEST.txt", manifest.into_bytes()));
    for (name, text) in files {
        entries.push(Entry::file(&format!("seagent-diagnostics/{name}"), clean(&text).into_bytes()));
    }
    Ok(gzip(&tar(&entries)))
}

/// Run `seagent <args>` and capture stdout+stderr (a failing check still produces output worth keeping).
fn capture_self(args: &[&str]) -> String {
    match std::env::current_exe().and_then(|e| std::process::Command::new(e).args(args).stdin(std::process::Stdio::null()).output()) {
        Ok(o) => format!("$ seagent {}\n{}{}\n(exit {})\n", args.join(" "), String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr), o.status.code().unwrap_or(-1)),
        Err(e) => format!("$ seagent {}\n(could not run: {e})\n", args.join(" ")),
    }
}

/// `seagent doctor --bundle [--out FILE] [--lines N] [--keep-identity]`.
pub fn doctor_bundle(a: &Args) -> R {
    let paths = Paths::from_env();
    let ws = crate::workspace(a)?;
    let cfg = crate::load_config(a, &ws, &paths)?;
    let lines = a.num::<usize>("lines")?.unwrap_or(200);
    let wsarg = ws.display().to_string();
    let extra = vec![
        ("doctor.txt".to_string(), capture_self(&["doctor", "--workspace", &wsarg])),
        ("sandbox-explain.txt".to_string(), capture_self(&["sandbox", "explain", "--json", "--workspace", &wsarg])),
        ("service-audit.txt".to_string(), capture_self(&["service", "audit", "--workspace", &wsarg])),
    ];
    let bytes = support_bundle(&paths, &cfg, &Scrub::here(Some(&ws)), extra, lines, a.flag("keep-identity"))?;
    let out = a.val("out").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(format!("seagent-diagnostics-{}.tar.gz", seagent_kernel::util::unix_now())));
    std::fs::write(&out, &bytes).map_err(|e| format!("{}: {e}", out.display()))?;
    println!("wrote {} ({} bytes). Secrets are redacted{}; nothing was uploaded — review it, then send it to support.", out.display(), bytes.len(), if a.flag("keep-identity") { "" } else { " and host/user/paths/IPs anonymized" });
    Ok(0)
}

const REDACTION_BANNER: &str = "[seagent debug share: secrets were redacted before upload]\n\n";

/// label → text: the report (dump + log tails) and each full log (dump-prefixed).
pub fn bundle(paths: &Paths, cfg: &Config, lines: usize, redact_on: bool) -> Vec<(String, String)> {
    // Redacting also anonymizes what identifies the host and its owner (user/host names, home
    // path, IPs, e-mails): a public paste must not carry them either.
    let scrub = Scrub::here(None);
    let r = |s: String| if redact_on { scrub.apply(&redact(&s)) } else { s };
    let d = r(dump(paths, cfg, false));
    let logs = [("seagent.jsonl", crate::ops::logs::dir(paths).join("seagent.jsonl")), ("seagentd.log", paths.daemon_log())];
    let mut report = d.clone();
    report.push('\n');
    let mut full = vec![];
    for (name, p) in &logs {
        match tail_lines(p, lines) {
            Some((tail, all)) => {
                report.push_str(&format!("\n--- {name} (last {lines} lines) ---\n{}\n", r(tail)));
                if !all.trim().is_empty() {
                    full.push((name.to_string(), r(all)));
                }
            }
            None => report.push_str(&format!("\n--- {name} ---\n(not found: {})\n", p.display())),
        }
    }
    let banner = if redact_on { REDACTION_BANNER } else { "" };
    let mut out = vec![("report".to_string(), format!("{banner}{report}"))];
    for (n, t) in full {
        out.push((n.clone(), format!("{banner}{d}\n\n--- full {n} ---\n{t}")));
    }
    out
}

fn pending_file(paths: &Paths) -> PathBuf {
    paths.data.join("debug").join("pending.json")
}

fn load_pending(paths: &Paths) -> Vec<Value> {
    std::fs::read_to_string(pending_file(paths)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn save_pending(paths: &Paths, v: &[Value]) {
    let p = pending_file(paths);
    let _ = std::fs::create_dir_all(p.parent().unwrap());
    let _ = seagent_kernel::util::atomic_write(&p, serde_json::to_string_pretty(v).unwrap_or_default().as_bytes());
}

pub fn paste_id(url: &str) -> Option<String> {
    let base = paste_rs_base();
    let u = url.trim();
    [base.as_str(), "https://paste.rs/", "http://paste.rs/"].iter().find_map(|p| u.strip_prefix(p)).map(|id| id.split(['.', '/', '?']).next().unwrap_or("").to_string()).filter(|id| !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric()))
}

fn is_dpaste(url: &str) -> bool {
    let u = url.trim();
    u.starts_with("https://dpaste.com/") || u.starts_with("http://dpaste.com/") || u.starts_with(dpaste_base().trim_end_matches("api/"))
}

/// DELETE a paste.rs paste (the only service with an unauthenticated delete).
pub fn delete_paste(url: &str) -> Result<(), String> {
    let id = match paste_id(url) {
        Some(id) => id,
        None if is_dpaste(url) => return Err("Cannot delete: dpaste.com pastes cannot be deleted (anonymous pastes expire on their own)".into()),
        None => return Err(format!("Cannot delete: only paste.rs URLs are supported.  Got: {url}")),
    };
    let (s, b) = net::request("DELETE", &format!("{}{id}", paste_rs_base()), &[("user-agent", format!("seagent/{}", env!("CARGO_PKG_VERSION")))], None, 4096, Duration::from_secs(30))?;
    if (200..300).contains(&s) {
        Ok(())
    } else {
        Err(format!("paste.rs returned HTTP {s}: {}", String::from_utf8_lossy(&b).trim()))
    }
}

/// Delete pending paste.rs pastes whose time has come → (deleted, remaining).
pub fn sweep(paths: &Paths, now: u64) -> (usize, usize) {
    let all = load_pending(paths);
    let (due, keep): (Vec<Value>, Vec<Value>) = all.into_iter().partition(|e| e["expire_at"].as_u64().unwrap_or(0) <= now);
    let mut remaining = keep;
    let mut deleted = 0;
    for e in due {
        let url = e["url"].as_str().unwrap_or("");
        match delete_paste(url) {
            Ok(()) => deleted += 1,
            Err(_) if e["attempts"].as_u64().unwrap_or(0) >= 3 => {} // give up; paste.rs GCs eventually
            Err(_) => {
                let mut e = e.clone();
                e["attempts"] = json!(e["attempts"].as_u64().unwrap_or(0) + 1);
                remaining.push(e);
            }
        }
    }
    save_pending(paths, &remaining);
    (deleted, remaining.len())
}

fn upload_paste_rs(body: &str) -> Result<String, String> {
    let (s, b) = net::request("POST", &paste_rs_base(), &[("content-type", "text/plain; charset=utf-8".into()), ("user-agent", format!("seagent/{}", env!("CARGO_PKG_VERSION")))], Some(body.as_bytes()), 4096, Duration::from_secs(30))?;
    let url = String::from_utf8_lossy(&b).trim().to_string();
    if (200..300).contains(&s) && url.starts_with("http") {
        Ok(url)
    } else {
        Err(format!("paste.rs: HTTP {s}"))
    }
}

fn form_escape(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => o.push(b as char),
            b' ' => o.push('+'),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

fn upload_dpaste(body: &str, days: u32) -> Result<String, String> {
    let form = format!("content={}&syntax=text&expiry_days={}", form_escape(body), days.max(1));
    let (s, b) = net::request("POST", &dpaste_base(), &[("content-type", "application/x-www-form-urlencoded".into()), ("user-agent", format!("seagent/{}", env!("CARGO_PKG_VERSION")))], Some(form.as_bytes()), 4096, Duration::from_secs(30))?;
    let url = String::from_utf8_lossy(&b).trim().trim_matches('"').to_string();
    if (200..300).contains(&s) && url.starts_with("http") {
        Ok(url)
    } else {
        Err(format!("dpaste.com: HTTP {s}"))
    }
}

/// paste.rs first, dpaste.com as fallback.
pub fn upload(body: &str, expiry_days: u32) -> Result<String, String> {
    match upload_paste_rs(body) {
        Ok(u) => Ok(u),
        Err(e1) => upload_dpaste(body, expiry_days).map_err(|e2| format!("all paste services failed: {e1}; {e2}")),
    }
}

/// Uploaded bundles: `(label, url)` pairs plus the labels that failed to upload.
pub type Shared = (Vec<(String, String)>, Vec<String>);

/// Upload every bundle entry → (label → url, failures); paste.rs urls are scheduled for deletion.
pub fn share(paths: &Paths, cfg: &Config, lines: usize, expiry: u32, redact_on: bool) -> Result<Shared, String> {
    if let Some(why) = upload_blocked(cfg) {
        return Err(format!("uploading debug reports is disabled here ({why}); use `seagent doctor --bundle` to write a local, anonymized archive instead"));
    }
    let b = bundle(paths, cfg, lines, redact_on);
    let mut urls = vec![];
    let mut fails = vec![];
    for (label, text) in b {
        match upload(&text, expiry) {
            Ok(u) => urls.push((label, u)),
            Err(e) if label == "report" => return Err(e),
            Err(_) => fails.push(label),
        }
    }
    let now = seagent_kernel::event::now_ms() / 1000;
    let mut p = load_pending(paths);
    for (_, u) in urls.iter().filter(|(_, u)| paste_id(u).is_some()) {
        p.push(json!({"url": u, "expire_at": now + AUTO_DELETE_SECONDS}));
    }
    save_pending(paths, &p);
    Ok((urls, fails))
}

const PRIVACY: &str = "This uploads a debug report to a public paste service (paste.rs, dpaste.com as fallback).\nIncluded: OS/version, model/provider, which API keys are set (not the keys), feature counts,\nand the tails of seagent.jsonl / seagentd.log (may contain conversation snippets, tool names, paths).\nKnown secret shapes are redacted unless --no-redact. paste.rs pastes auto-delete after 6 hours.";

fn share_text(urls: &[(String, String)], fails: &[String], expiry: u32) -> String {
    let w = urls.iter().map(|(l, _)| l.len()).max().unwrap_or(6);
    let mut o = String::from("Debug report uploaded:\n");
    for (l, u) in urls {
        o.push_str(&format!("  {l:<w$}  {u}\n"));
    }
    if !fails.is_empty() {
        o.push_str(&format!("\n  (failed to upload: {})\n", fails.join(", ")));
    }
    let dp = urls.iter().filter(|(_, u)| paste_id(u).is_none()).count();
    if dp > 0 {
        o.push_str(&format!("\n{dp} of {} upload(s) fell back to dpaste.com: those stay public for {expiry} day(s) and CANNOT be deleted.\n", urls.len()));
    } else {
        o.push_str(&format!("\nPastes auto-delete in {} hours. To delete now: seagent debug delete <url>\n", AUTO_DELETE_SECONDS / 3600));
    }
    o
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if !COMMANDS.contains(&cmd) {
        return None;
    }
    Some(run(Paths::from_env(), cmd, a))
}

/// The `seagent dump` / `seagent debug …` body, split out so tests can drive it over a temp profile.
pub fn run(paths: Paths, cmd: &str, a: &Args) -> R {
    let ws = crate::workspace(a)?;
    if cmd == "dump" {
        let cfg = crate::load_config(a, &ws, &paths)?;
        println!("{}", dump(&paths, &cfg, a.flag("show-keys")));
        return Ok(0);
    }
    let now = seagent_kernel::event::now_ms() / 1000;
    match a.pos(0).unwrap_or("share") {
        "share" => {
            if a.flag("nous") {
                return Err("--nous uploads to Nous Research's internal storage, which seagent does not use; use `seagent debug share` (public paste) or `--local`".into());
            }
            let lines = a.num::<usize>("lines")?.unwrap_or(200);
            let expiry = a.num::<u32>("expire")?.unwrap_or(1).max(1);
            let redact_on = !a.flag("no-redact");
            let cfg = crate::load_config(a, &ws, &paths)?;
            let _ = sweep(&paths, now);
            if a.flag("local") {
                for (label, text) in bundle(&paths, &cfg, lines, redact_on) {
                    if label != "report" {
                        println!("\n\n{}\nFULL {label}\n{}\n", "=".repeat(60), "=".repeat(60));
                    }
                    println!("{text}");
                }
                return Ok(0);
            }
            if let Some(why) = upload_blocked(&cfg) {
                return Err(format!("uploading debug reports is disabled here ({why}); use `seagent doctor --bundle` (local archive) or `seagent debug share --local`").into());
            }
            eprintln!("{PRIVACY}");
            if !a.flag("yes") {
                if !std::io::stdin().is_terminal() {
                    return Err("refusing to upload without confirmation: pass --yes (non-interactive) or --local to print instead".into());
                }
                eprint!("Upload now? [y/N] ");
                let mut s = String::new();
                let _ = std::io::stdin().read_line(&mut s);
                if !matches!(s.trim().to_lowercase().as_str(), "y" | "yes") {
                    eprintln!("Cancelled.");
                    return Ok(1);
                }
            }
            if !redact_on {
                eprintln!("--no-redact is set: secrets in your logs will NOT be redacted before upload.");
            }
            eprintln!("Collecting debug report...\nUploading...");
            match share(&paths, &cfg, lines, expiry, redact_on) {
                Ok((urls, fails)) => {
                    print!("{}", share_text(&urls, &fails, expiry));
                    Ok(0)
                }
                Err(e) => {
                    eprintln!("Upload failed: {}\nRun `seagent debug share --local` to print the report instead.", redact(&e));
                    Ok(1)
                }
            }
        }
        "delete" => {
            if a.pos.len() < 2 {
                return crate::usage("usage: seagent debug delete <url> [<url>…]");
            }
            let mut rc = 0;
            let mut pend = load_pending(&paths);
            for u in &a.pos[1..] {
                match delete_paste(u) {
                    Ok(()) => {
                        println!("Deleted: {u}");
                        pend.retain(|e| e["url"].as_str() != Some(u.as_str()));
                    }
                    Err(e) => {
                        eprintln!("Could not delete {u}: {e}");
                        rc = 1;
                    }
                }
            }
            save_pending(&paths, &pend);
            Ok(rc)
        }
        "list" | "pending" => {
            let p = load_pending(&paths);
            if p.is_empty() {
                println!("no pending pastes");
            }
            for e in p {
                let left = e["expire_at"].as_u64().unwrap_or(0).saturating_sub(now);
                println!("{}  deletes in {}m", e["url"].as_str().unwrap_or(""), left / 60);
            }
            Ok(0)
        }
        "sweep" => {
            let (d, r) = sweep(&paths, now);
            println!("deleted {d} expired paste(s), {r} pending");
            Ok(0)
        }
        other => crate::usage(format!("unknown `debug {other}` (share [--lines N] [--expire DAYS] [--local] [--yes] [--no-redact] | delete <url>… | list | sweep)")),
    }
}

// ───────────────────────── runtime debug overrides (OpenClaw /debug) ─────────────────────────

static OVERRIDES: Mutex<Option<toml::Table>> = Mutex::new(None);
const BLOCKED: &[&str] = &["__proto__", "prototype", "constructor"];

fn parse_path(p: &str) -> Result<Vec<String>, String> {
    let parts: Vec<String> = p.trim().split('.').map(|s| s.trim().to_string()).collect();
    if parts.is_empty() || parts.iter().any(|s| s.is_empty()) {
        return Err(format!("invalid config path `{p}`"));
    }
    if parts.iter().any(|s| BLOCKED.contains(&s.as_str())) {
        return Err(format!("config path `{p}` uses a blocked key"));
    }
    Ok(parts)
}

/// `true`/`false`/numbers/JSON/TOML literals, else the raw string.
pub fn parse_value(raw: &str) -> Result<toml::Value, String> {
    let t = raw.trim();
    if t.is_empty() {
        return Err("missing value".into());
    }
    if let Ok(v) = format!("x = {t}").parse::<toml::Table>() {
        if let Some(v) = v.get("x") {
            return Ok(v.clone());
        }
    }
    if let Ok(j) = serde_json::from_str::<Value>(t) {
        if let Ok(v) = toml::Value::try_from(&j) {
            return Ok(v);
        }
    }
    Ok(toml::Value::String(t.to_string()))
}

pub fn set_override(path: &str, v: toml::Value) -> Result<(), String> {
    let parts = parse_path(path)?;
    let mut g = OVERRIDES.lock().unwrap();
    let mut cur = g.get_or_insert_with(toml::Table::new);
    for k in &parts[..parts.len() - 1] {
        let e = cur.entry(k.clone()).or_insert_with(|| toml::Value::Table(Default::default()));
        if !e.is_table() {
            *e = toml::Value::Table(Default::default());
        }
        cur = e.as_table_mut().unwrap();
    }
    cur.insert(parts.last().unwrap().clone(), v);
    Ok(())
}

pub fn unset_override(path: &str) -> Result<bool, String> {
    let parts = parse_path(path)?;
    let mut g = OVERRIDES.lock().unwrap();
    let Some(root) = g.as_mut() else { return Ok(false) };
    fn rm(t: &mut toml::Table, parts: &[String]) -> bool {
        if parts.len() == 1 {
            return t.remove(&parts[0]).is_some();
        }
        let Some(toml::Value::Table(sub)) = t.get_mut(&parts[0]) else { return false };
        let hit = rm(sub, &parts[1..]);
        if hit && sub.is_empty() {
            t.remove(&parts[0]);
        }
        hit
    }
    Ok(rm(root, &parts))
}

pub fn reset_overrides() {
    *OVERRIDES.lock().unwrap() = None;
}

pub fn get_overrides() -> toml::Table {
    OVERRIDES.lock().unwrap().clone().unwrap_or_default()
}

/// Merge the overrides over a config table (deep for tables, replace otherwise).
pub fn apply_overrides(base: &mut toml::Table) {
    fn merge(b: &mut toml::Table, o: &toml::Table) {
        for (k, v) in o {
            match (b.get_mut(k), v) {
                (Some(toml::Value::Table(bt)), toml::Value::Table(ot)) => merge(bt, ot),
                _ => {
                    b.insert(k.clone(), v.clone());
                }
            }
        }
    }
    if let Some(o) = OVERRIDES.lock().unwrap().as_ref() {
        merge(base, o);
    }
}

fn cfg_table(cfg: &Config) -> Result<toml::Table, String> {
    match toml::Value::try_from(cfg).map_err(|e| e.to_string())? {
        toml::Value::Table(t) => Ok(t),
        _ => Err("config is not a table".into()),
    }
}

/// The overrides applied to a typed config (None = it no longer parses).
pub fn effective(cfg: &Config) -> Result<Config, String> {
    if OVERRIDES.lock().unwrap().as_ref().is_none_or(|o| o.is_empty()) {
        return Ok(cfg.clone());
    }
    let mut t = cfg_table(cfg)?;
    apply_overrides(&mut t);
    toml::Value::Table(t).try_into().map_err(|e: toml::de::Error| e.message().to_string())
}

/// Push the validated override snapshot into this process's kernel, so the next turn runs
/// with it (upstream `config/runtime-overrides.ts` is consulted on every `getConfig()`).
fn sync_runtime(c: &Ctx) {
    if get_overrides().is_empty() {
        c.k.set_runtime_cfg(None);
        return;
    }
    if let Ok(eff) = effective(&c.k.cfg) {
        c.k.set_runtime_cfg(Some(eff));
    }
}

fn overrides_text() -> String {
    let o = get_overrides();
    if o.is_empty() {
        return "Debug overrides: (none)".into();
    }
    format!("Debug overrides (memory-only):\n```toml\n{}```", crate::slash::redact(&toml::to_string_pretty(&o).unwrap_or_default()))
}

/// `/debug` — `show|set path=value|unset path|reset` (OpenClaw runtime overrides) or
/// `[local|share]` (Hermes support report; `share` uploads, admin only).
pub fn slash(c: &Ctx, args: &str) -> Result<Reply, String> {
    let (sub, rest) = args.trim().split_once(char::is_whitespace).map(|(a, b)| (a, b.trim())).unwrap_or((args.trim(), ""));
    let text = match sub {
        "show" => overrides_text(),
        "reset" => {
            reset_overrides();
            sync_runtime(c);
            "Debug overrides cleared; using config on disk.".into()
        }
        "unset" => {
            if rest.is_empty() {
                return Err("Usage: /debug unset path".into());
            }
            let hit = unset_override(rest)?;
            sync_runtime(c);
            if hit { format!("Debug override removed for {rest}.") } else { format!("No debug override found for {rest}.") }
        }
        "set" => {
            let (path, value) = rest.split_once('=').map(|(p, v)| (p.trim(), v)).filter(|(p, _)| !p.is_empty()).ok_or("Usage: /debug set path=value")?;
            let v = parse_value(value)?;
            // Refuse an override that would make the config unloadable.
            let mut t = cfg_table(&c.k.cfg)?;
            let saved = get_overrides();
            set_override(path, v.clone())?;
            apply_overrides(&mut t);
            if let Err(e) = toml::Value::Table(t).try_into::<Config>() {
                *OVERRIDES.lock().unwrap() = if saved.is_empty() { None } else { Some(saved) };
                return Err(format!("{path}: {}", e.message()));
            }
            sync_runtime(c);
            let shown = if crate::slash::redact(&format!("{path} = {v}")).contains("***") { "***".to_string() } else { v.to_string() };
            format!("Debug override set: {path}={shown}\n(applies from the next turn in this process and to config loaded later; cleared by /debug reset or a restart)")
        }
        "" | "local" | "report" => dump(&c.k.paths, &c.k.cfg, false),
        "share" | "upload" => {
            let (urls, fails) = share(&c.k.paths, &c.k.cfg, 200, 1, true)?;
            share_text(&urls, &fails, 1)
        }
        "nous" => return Err("seagent does not upload to Nous storage; use /debug share or /debug local".into()),
        _ => return Err("Usage: /debug [local|share] · /debug show|set path=value|unset path|reset".into()),
    };
    Ok(Reply { text: Some(text.trim_end().to_string()), ..Default::default() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::net::fake;
    use std::sync::Arc;

    #[test]
    fn scrub_removes_identity_but_keeps_loopback() {
        let s = Scrub { home: "/home/amy".into(), user: "amy".into(), host: "amy-laptop".into(), extra: vec![("/home/amy/work/proj".into(), "<workspace>".into())] };
        let out = s.apply("amy@amy-laptop:/home/amy/work/proj$ seagent ; cfg /home/amy/.config/seagent ; peer 10.1.2.3 and 192.168.0.9 local 127.0.0.1 any 0.0.0.0 ; fe80:0:0:0:aa:bb:cc:dd ; mac 3c:22:fb:12:34:56 ; mail a.b@corp.example.com ; user Amy");
        for gone in ["amy", "10.1.2.3", "192.168.0.9", "3c:22:fb", "corp.example.com", "fe80:0:0:0"] {
            assert!(!out.to_lowercase().contains(gone), "{gone} leaked: {out}");
        }
        for kept in ["<workspace>", "~/.config/seagent", "127.0.0.1", "0.0.0.0", "<ip>", "<mac>", "<email>", "<ip6>", "<user>"] {
            assert!(out.contains(kept), "{kept} missing: {out}");
        }
        // Short names are not guessed at: replacing "al" would shred ordinary words.
        let t = Scrub { home: "/home/al".into(), user: "al".into(), host: "h".into(), extra: vec![] };
        assert_eq!(t.apply("the alarm"), "the alarm");
    }

    #[test]
    fn doctor_bundle_is_an_anonymized_local_archive() {
        let kit = crate::testkit::kit();
        let (home, user) = ("/home/amy", "amy");
        let scrub = Scrub { home: home.into(), user: user.into(), host: "amy-laptop".into(), extra: vec![] };
        let secret = format!("sk-{}", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4");
        std::fs::create_dir_all(crate::ops::logs::dir(&kit.paths)).unwrap();
        std::fs::write(crate::ops::logs::dir(&kit.paths).join("seagent.jsonl"), format!("{{\"msg\":\"cwd {home}/proj by {user} from 203.0.113.7 key {secret}\"}}\n")).unwrap();
        let extra = vec![("doctor.txt".to_string(), format!("✓ ok\n✗ net: cannot reach 198.51.100.4 as {user}@amy-laptop\n"))];
        let gz = support_bundle(&kit.paths, &kit.k.cfg, &scrub, extra, 50, false).unwrap();
        let entries = crate::ops::archive::untar(&crate::ops::archive::gunzip(&gz).unwrap()).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        for want in ["seagent-diagnostics/MANIFEST.txt", "seagent-diagnostics/report.txt", "seagent-diagnostics/config.toml", "seagent-diagnostics/doctor.txt"] {
            assert!(names.contains(&want), "{want} missing from {names:?}");
        }
        let all: String = entries.iter().map(|e| String::from_utf8_lossy(&e.data).to_string()).collect();
        assert!(!all.contains("203.0.113.7") && !all.contains("198.51.100.4"), "IPs leaked: {all}");
        assert!(!all.contains(&secret), "secret leaked");
        assert!(!all.contains("/home/amy") && !all.contains("amy-laptop") && !all.contains("by amy"), "identity leaked: {all}");
        assert!(all.contains("<ip>") && all.contains("~/proj") && all.contains("replaced with placeholders"));
        // --keep-identity keeps the paths (but still redacts secrets).
        let kept = support_bundle(&kit.paths, &kit.k.cfg, &scrub, vec![("doctor.txt".into(), format!("at {home}/proj key {secret}"))], 50, true).unwrap();
        let all: String = crate::ops::archive::untar(&crate::ops::archive::gunzip(&kept).unwrap()).unwrap().iter().map(|e| String::from_utf8_lossy(&e.data).to_string()).collect();
        assert!(all.contains("/home/amy/proj") && all.contains("KEPT") && !all.contains(&secret));
    }

    #[test]
    fn policy_can_forbid_the_paste_upload() {
        let kit = crate::testkit::kit();
        std::env::remove_var("SEAGENT_DEBUG_SHARE");
        assert!(upload_blocked(&kit.k.cfg).is_none() || Path::new("/etc/seagent/no-debug-upload").exists());
        std::env::set_var("SEAGENT_DEBUG_SHARE", "off");
        let why = upload_blocked(&kit.k.cfg).unwrap();
        let err = share(&kit.paths, &kit.k.cfg, 5, 1, true).unwrap_err();
        std::env::remove_var("SEAGENT_DEBUG_SHARE");
        assert!(why.contains("SEAGENT_DEBUG_SHARE") && err.contains("seagent doctor --bundle"), "{err}");
        let mut gov = kit.k.cfg.clone();
        gov.compliance.profile = "government".into();
        assert!(upload_blocked(&gov).unwrap().contains("government"));
    }

    #[test]
    fn dump_masks_and_flags_shell_only_keys() {
        let kit = crate::testkit::kit();
        std::fs::write(kit.paths.config_dir.join(".env"), "OPENAI_API_KEY=sk-in-dotenv\n").unwrap();
        assert_eq!(mask("sk-abcdefghijklmnop"), "sk-a...mnop");
        assert_eq!(mask("short"), "***");
        assert_eq!(mask(""), "");
        let d = dump(&kit.paths, &kit.k.cfg, false);
        assert!(d.starts_with("--- seagent dump ---") && d.ends_with("--- end dump ---"));
        assert!(d.contains("model:            m") && d.contains("provider:         echo"));
        assert!(d.contains("daemon:             stopped"));
        let mut cfg = Config::default();
        cfg.runner.max_steps_per_turn = 3;
        assert!(overrides(&cfg).iter().any(|(k, v)| k == "runner.max_steps_per_turn" && v == "3"), "{:?}", overrides(&cfg));
    }

    /// The `--show-keys` branch of [`dump`]: a set key is reported as first/last 4 chars,
    /// an unset one as "not set", and the value itself never reaches the text.
    #[test]
    fn show_keys_prints_masked_keys_and_never_the_value() {
        let kit = crate::testkit::kit();
        // A key exported in this shell (but not in `.env`) is what `--show-keys` reports on.
        std::env::set_var("KIMI_API_KEY", "sk-kimi-0123456789abcdef");
        std::env::remove_var("GLM_API_KEY");
        let masked = dump(&kit.paths, &kit.k.cfg, true);
        assert!(masked.contains(&format!("  {:<20} sk-k...cdef", "kimi")), "{masked}");
        assert!(masked.contains(&format!("  {:<20} not set", "glm/zai")), "{masked}");
        assert!(!masked.contains("0123456789abcdef"), "the key value must never be printed: {masked}");
        assert!(masked.contains("(shell only — not in .env"), "a shell-only key is still flagged: {masked}");
        // Without the flag the same key is only "set" — the masking branch is the difference.
        let plain = dump(&kit.paths, &kit.k.cfg, false);
        assert!(plain.contains(&format!("  {:<20} set (shell only — not in .env", "kimi")), "{plain}");
        assert!(!plain.contains("sk-k"), "{plain}");
        std::env::remove_var("KIMI_API_KEY");
    }

    #[test]
    fn redaction_covers_tokens_kv_and_url_userinfo() {
        let r = redact("token = \"abcdef123456\"\nurl https://user:pw@host/x\nkey sk-ant-aaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(!r.contains("abcdef123456") && !r.contains("user:pw") && !r.contains("sk-ant-aaaa"), "{r}");
    }

    #[test]
    fn share_falls_back_schedules_and_deletes() {
        let kit = crate::testkit::kit();
        std::fs::create_dir_all(crate::ops::logs::dir(&kit.paths)).unwrap();
        std::fs::write(crate::ops::logs::dir(&kit.paths).join("seagent.jsonl"), "{\"msg\":\"a\"}\n{\"msg\":\"Authorization: Bearer abcdefghijklmnopqrstu\"}\n").unwrap();
        let fail_first = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ff = fail_first.clone();
        let me = Arc::new(Mutex::new(String::new()));
        let me2 = me.clone();
        let (base, log) = fake::serve(Arc::new(move |r: &fake::Req| match (r.method.as_str(), r.path.as_str()) {
            ("POST", "/prs/") if ff.load(std::sync::atomic::Ordering::SeqCst) => (503, "text/plain".into(), vec![]),
            ("POST", "/prs/") => (201, "text/plain".into(), format!("{}/prs/abc123\n", me2.lock().unwrap()).into_bytes()),
            ("POST", "/dp/api/") => (200, "text/plain".into(), b"https://dpaste.com/XYZ\n".to_vec()),
            ("DELETE", p) if p.starts_with("/prs/") => (200, "text/plain".into(), vec![]),
            _ => (404, "text/plain".into(), vec![]),
        }));
        *me.lock().unwrap() = base.clone();
        std::env::set_var("SEAGENT_PASTE_RS_URL", format!("{base}/prs/"));
        std::env::set_var("SEAGENT_DPASTE_URL", format!("{base}/dp/api/"));
        let (urls, fails) = share(&kit.paths, &kit.k.cfg, 50, 1, true).unwrap();
        assert!(fails.is_empty());
        assert_eq!(urls[0].0, "report");
        let posted = String::from_utf8_lossy(&log.lock().unwrap()[0].body).to_string();
        assert!(posted.contains("--- seagent dump ---") && posted.contains("seagent.jsonl") && !posted.contains("abcdefghijklmnopqrstu"), "{posted}");
        assert!(posted.starts_with(REDACTION_BANNER));
        // pending entries are paste.rs urls only
        let pend = load_pending(&kit.paths);
        assert!(pend.is_empty() || pend.iter().all(|e| paste_id(e["url"].as_str().unwrap()).is_some()));
        let u = urls[0].1.clone();
        assert_eq!(paste_id(&u).as_deref(), Some("abc123"));
        save_pending(&kit.paths, &[json!({"url": u, "expire_at": 10})]);
        assert_eq!(sweep(&kit.paths, 11), (1, 0));
        assert!(log.lock().unwrap().iter().any(|r| r.method == "DELETE" && r.path == "/prs/abc123"));
        // fallback to dpaste; dpaste urls cannot be deleted
        fail_first.store(true, std::sync::atomic::Ordering::SeqCst);
        let (urls, _) = share(&kit.paths, &kit.k.cfg, 50, 3, false).unwrap();
        assert_eq!(urls[0].1, "https://dpaste.com/XYZ");
        let form = log.lock().unwrap().iter().rev().find(|r| r.path == "/dp/api/").map(|r| String::from_utf8_lossy(&r.body).to_string()).unwrap();
        assert!(form.contains("expiry_days=3") && form.contains("syntax=text"));
        assert!(delete_paste("https://dpaste.com/XYZ").unwrap_err().contains("cannot be deleted"));
        assert!(delete_paste("https://example.com/x").unwrap_err().contains("only paste.rs"));
        assert!(share_text(&urls, &[], 3).contains("CANNOT be deleted"));
        std::env::remove_var("SEAGENT_PASTE_RS_URL");
        std::env::remove_var("SEAGENT_DPASTE_URL");
    }

    /// The override table is process-wide (like upstream's runtime-overrides singleton), so
    /// tests that mutate it must not interleave with each other.
    static OVERRIDE_TESTS: Mutex<()> = Mutex::new(());

    #[test]
    fn overrides_reach_the_running_kernel_next_turn() {
        let _serial = OVERRIDE_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let kit = crate::testkit::kit();
        let c = Ctx { k: &kit.k, ext: None, session: None, workspace: kit.ws.clone(), surface: crate::slash::Surface::Cli, sender: None, notify: None };
        let t = |a: &str| slash(&c, a).map(|r| r.text.unwrap_or_default());
        reset_overrides();
        kit.k.set_runtime_cfg(None);
        // A live daemon turn sees the override without a reload or a restart.
        t("set model.default=\"override/m\"").unwrap();
        t("set runner.max_steps_per_turn=9").unwrap();
        t("set tools.disabled=[\"web_search\"]").unwrap();
        let now = kit.k.cfg_now();
        assert_eq!(now.model.default, "override/m");
        assert_eq!(now.runner.max_steps_per_turn, 9);
        assert!(kit.k.specs().iter().all(|s| s.name != "web_search"), "disabled override hides the tool");
        assert!(kit.k.cfg.model.default == "echo/m", "the startup snapshot is untouched");
        // An override that would make the config unparseable is refused and leaves the last good snapshot.
        assert!(t("set model.default=3").is_err());
        assert_eq!(kit.k.cfg_now().model.default, "override/m");
        // unset/reset clear the live snapshot again.
        t("unset tools.disabled").unwrap();
        assert!(kit.k.specs().iter().any(|s| s.name == "web_search"));
        t("reset").unwrap();
        assert!(kit.k.runtime_cfg().is_none());
        assert_eq!(kit.k.cfg_now().model.default, "echo/m");
    }

    #[test]
    fn debug_overrides_set_show_unset_reset() {
        let _serial = OVERRIDE_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let kit = crate::testkit::kit();
        let c = Ctx { k: &kit.k, ext: None, session: None, workspace: kit.ws.clone(), surface: crate::slash::Surface::Cli, sender: None, notify: None };
        let t = |a: &str| slash(&c, a).map(|r| r.text.unwrap_or_default());
        reset_overrides();
        assert_eq!(t("show").unwrap(), "Debug overrides: (none)");
        assert!(t("set runner.max_steps_per_turn=7").unwrap().contains("runner.max_steps_per_turn=7"));
        assert!(t("set runner.max_steps_per_turn=\"seven\"").is_err(), "a value that breaks the config is refused");
        assert!(t("set runner.__proto__.x=1").is_err());
        assert!(t("set nopath").is_err());
        assert_eq!(effective(&kit.k.cfg).unwrap().runner.max_steps_per_turn, 7);
        assert!(t("show").unwrap().contains("max_steps_per_turn = 7"));
        assert!(t("unset runner.max_steps_per_turn").unwrap().contains("removed"));
        assert!(t("unset runner.max_steps_per_turn").unwrap().contains("No debug override"));
        t("set model.default=\"a/b\"").unwrap();
        assert!(t("reset").unwrap().contains("cleared"));
        assert!(get_overrides().is_empty());
        assert!(t("local").unwrap().contains("--- seagent dump ---"));
        assert!(t("bogus").is_err());
        assert_eq!(parse_value("true").unwrap(), toml::Value::Boolean(true));
        assert_eq!(parse_value("hello world").unwrap(), toml::Value::String("hello world".into()));
        assert_eq!(parse_value("{\"a\": 1}").unwrap().get("a").and_then(|v| v.as_integer()), Some(1));
    }

    #[test]
    fn dispatch_claims_dump_and_debug_and_runs_them() {
        let kit = crate::testkit::kit();
        let a = |v: &[&str]| Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        let ws = kit.ws.display().to_string();
        // `seagent dump` — the support summary both §101 (dump.py) and `/debug` local mode print.
        assert_eq!(run(kit.paths.clone(), "dump", &a(&["--workspace", &ws, "--show-keys"])).unwrap(), 0);
        // `seagent debug share --local` prints the bundle instead of uploading (`--lines` honoured).
        assert_eq!(run(kit.paths.clone(), "debug", &a(&["--workspace", &ws, "share", "--local", "--lines", "5"])).unwrap(), 0);
        // `seagent debug list|sweep` and argument errors take the same dispatch path.
        assert_eq!(run(kit.paths.clone(), "debug", &a(&["--workspace", &ws, "list"])).unwrap(), 0);
        assert_eq!(run(kit.paths.clone(), "debug", &a(&["--workspace", &ws, "sweep"])).unwrap(), 0);
        assert!(run(kit.paths.clone(), "debug", &a(&["--workspace", &ws, "delete"])).unwrap_err().to_string().contains("usage: seagent debug delete"));
        assert!(run(kit.paths.clone(), "debug", &a(&["--workspace", &ws, "bogus"])).unwrap_err().to_string().contains("unknown `debug bogus`"));
        assert!(run(kit.paths.clone(), "debug", &a(&["--workspace", &ws, "share", "--nous"])).unwrap_err().to_string().contains("--nous"));
        // wiring: `dump`/`debug` are this module's names; anything else falls through.
        let me: fn(&str, &Args, &[String]) -> Option<R> = dispatch;
        assert!(crate::ops::modules().iter().any(|m| m.0 == COMMANDS && m.3 as usize == me as usize), "debugdump::dispatch is registered in ops::MODULES");
        assert!(dispatch("worktree", &a(&[]), &[]).is_none());
    }
}
