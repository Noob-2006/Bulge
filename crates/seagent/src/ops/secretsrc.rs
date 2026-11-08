//! External secret sources (Hermes `agent/secret_sources`, `hermes secrets bitwarden|onepassword`):
//! at process start, after `.env` loads, credentials are pulled from an external secret
//! manager into the environment so they need not live in `.env` / `secrets.toml`.
//!
//! Sources (configured in `<config>/secret_sources.toml`, one table per source):
//! - `bitwarden` (bulk): Bitwarden Secrets Manager via `bws secret list <project> --output json`,
//!   bootstrap token in `BWS_ACCESS_TOKEN` (or `access_token_env`), optional `server_url`.
//! - `onepassword` (mapped): `env = { NAME = "op://vault/item/field" }`, one
//!   `op read [--account A] -- <ref>` per binding with whatever auth `op` already has.
//! - `command` (bulk): a user helper run via `/bin/sh -c`, printing `KEY=VALUE` lines;
//!   3 s hard timeout, 1 MiB output cap, stderr discarded, key passed only as `SEAGENT_SECRET_KEY`.
//!
//! Orchestration (registry `apply_all`): mapped sources outrank bulk; within a shape the
//! top-level `sources = [...]` order, else built-in order; first claim wins (later sources get
//! a conflict warning); `override_existing` may beat `.env`/shell values but never another
//! source, never a name in `preserve_existing`, never a source's own bootstrap token var.
//! Fetches never block startup: each runs under a wall-clock timeout and failures become
//! warnings with a remediation hint. Values are cached in memory and under `<data>/cache`
//! (values only, keyed by a token fingerprint, 0600) for `cache_ttl_seconds`; Bitwarden can
//! instead keep an encrypted last-good cache (`[bitwarden.encrypted_cache]`) that is served
//! after network/timeout failures only.

use crate::args::Args;
use crate::R;
use seagent_kernel::config::Paths;
use seagent_net::crypto;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const COMMANDS: &[&str] = &[];
pub const VALUE_FLAGS: &[&str] = &["access-token", "project-id", "server-url", "op-account", "helper", "token-env"];
pub const BOOL_FLAGS: &[&str] = &["no-verify"];

pub const DEFAULT_FETCH_TIMEOUT: f64 = 120.0;
const CLI_TIMEOUT: Duration = Duration::from_secs(30);
const COMMAND_TIMEOUT: f64 = 3.0;
const MAX_OUTPUT: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    NotConfigured,
    BinaryMissing,
    AuthFailed,
    Network,
    EmptyValue,
    Timeout,
    Internal,
}

impl ErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorKind::NotConfigured => "not_configured",
            ErrorKind::BinaryMissing => "binary_missing",
            ErrorKind::AuthFailed => "auth_failed",
            ErrorKind::Network => "network",
            ErrorKind::EmptyValue => "empty_value",
            ErrorKind::Timeout => "timeout",
            ErrorKind::Internal => "internal",
        }
    }
}

type Rules = &'static [(ErrorKind, &'static [&'static str])];

const BWS_RULES: Rules = &[
    (ErrorKind::Timeout, &["timed out"]),
    (ErrorKind::BinaryMissing, &["binary not available", "failed to invoke"]),
    (ErrorKind::AuthFailed, &["unauthorized", "invalid token", "access token", "401", "403", "invalid_client", "invalid_grant", "400 bad request"]),
    (ErrorKind::Network, &["network", "connection", "resolve", "download", "dns"]),
];

const OP_RULES: Rules = &[
    (ErrorKind::Timeout, &["timed out"]),
    (ErrorKind::BinaryMissing, &["not found on path", "not an executable", "failed to invoke"]),
    (ErrorKind::AuthFailed, &["unauthorized", "not signed in", "session expired", "authentication", "401", "403"]),
    (ErrorKind::EmptyValue, &["empty value"]),
    (ErrorKind::Network, &["network", "connection", "resolve host", "dns"]),
];

/// First rule whose substring appears (case-insensitive) wins.
pub fn classify(msg: &str, rules: Rules) -> ErrorKind {
    let l = msg.to_lowercase();
    rules.iter().find(|(_, toks)| toks.iter().any(|t| l.contains(t))).map(|r| r.0).unwrap_or(ErrorKind::Internal)
}

#[derive(Debug, Clone, Default)]
pub struct Fetch {
    pub secrets: BTreeMap<String, String>,
    pub warnings: Vec<String>,
    pub error: Option<(String, ErrorKind)>,
    pub binary: Option<PathBuf>,
}

impl Fetch {
    fn fail(mut self, e: impl Into<String>, k: ErrorKind) -> Fetch {
        self.error = Some((e.into(), k));
        self
    }
}

pub fn valid_env_name(n: &str) -> bool {
    let mut c = n.chars();
    matches!(c.next(), Some(f) if f.is_ascii_alphabetic() || f == '_') && c.all(|x| x.is_ascii_alphanumeric() || x == '_')
}

/// Strip whole CSI/OSC escape sequences (also unterminated OSC from a killed CLI).
pub fn scrub_ansi(s: &str) -> String {
    let re = regex::Regex::new(r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)?)").unwrap();
    re.replace_all(s, "").replace('\x1b', "")
}

fn fingerprint(s: &str) -> String {
    crypto::hex(&crypto::sha256(s.as_bytes()))[..16].to_string()
}

// ---------------------------------------------------------------- config

pub fn config_path(paths: &Paths) -> PathBuf {
    paths.config_dir.join("secret_sources.toml")
}

pub fn load_config(paths: &Paths) -> toml::Table {
    std::fs::read_to_string(config_path(paths)).ok().and_then(|t| t.parse::<toml::Table>().ok()).unwrap_or_default()
}

pub fn save_config(paths: &Paths, t: &toml::Table) -> Result<(), String> {
    std::fs::create_dir_all(&paths.config_dir).map_err(|e| e.to_string())?;
    let body = format!("# External secret sources (`seagent secrets bitwarden|onepassword|command …`).\n{}", toml::to_string_pretty(t).map_err(|e| e.to_string())?);
    seagent_kernel::util::atomic_write(&config_path(paths), body.as_bytes()).map_err(|e| e.to_string())
}

fn section(t: &toml::Table, name: &str) -> toml::Table {
    t.get(name).and_then(|v| v.as_table()).cloned().unwrap_or_default()
}

fn s(c: &toml::Table, k: &str, d: &str) -> String {
    c.get(k).and_then(|v| v.as_str()).map(String::from).unwrap_or_else(|| d.to_string())
}

fn b(c: &toml::Table, k: &str, d: bool) -> bool {
    c.get(k).and_then(|v| v.as_bool()).unwrap_or(d)
}

fn f(c: &toml::Table, k: &str, d: f64) -> f64 {
    c.get(k).and_then(|v| v.as_float().or_else(|| v.as_integer().map(|i| i as f64))).unwrap_or(d)
}

// ---------------------------------------------------------------- sources

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    Mapped,
    Bulk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Bitwarden,
    OnePassword,
    Command,
    /// HashiCorp Vault KV v2 (ent-081, `secretsrc_cloud`).
    Vault,
    Aws,
    Gcp,
    Azure,
}

#[path = "secretsrc_cloud.rs"]
pub mod cloud;

pub const ALL: &[Source] = &[Source::Bitwarden, Source::OnePassword, Source::Command, Source::Vault, Source::Aws, Source::Gcp, Source::Azure];

impl Source {
    pub fn name(self) -> &'static str {
        match self {
            Source::Bitwarden => "bitwarden",
            Source::OnePassword => "onepassword",
            Source::Command => "command",
            Source::Vault => "vault",
            Source::Aws => "aws",
            Source::Gcp => "gcp",
            Source::Azure => "azure",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Source::Bitwarden => "Bitwarden Secrets Manager",
            Source::OnePassword => "1Password",
            Source::Command => "Command helper",
            Source::Vault => "HashiCorp Vault",
            Source::Aws => "AWS Secrets Manager",
            Source::Gcp => "GCP Secret Manager",
            Source::Azure => "Azure Key Vault",
        }
    }
    pub fn parse(s: &str) -> Option<Source> {
        Some(match s {
            "bitwarden" | "bw" | "bws" => Source::Bitwarden,
            "onepassword" | "op" | "1password" => Source::OnePassword,
            "command" | "cmd" => Source::Command,
            "vault" | "hashicorp" | "hashicorp-vault" => Source::Vault,
            "aws" | "aws-secrets-manager" => Source::Aws,
            "gcp" | "gcp-secret-manager" => Source::Gcp,
            "azure" | "azure-key-vault" | "keyvault" => Source::Azure,
            _ => return None,
        })
    }
    pub fn shape(self) -> Shape {
        if matches!(self, Source::Bitwarden | Source::Command) { Shape::Bulk } else { Shape::Mapped }
    }
    fn override_default(self) -> bool {
        self != Source::Command
    }
    /// Env var holding this source's bootstrap credential ("" = none).
    pub fn token_env(self, c: &toml::Table) -> String {
        match self {
            Source::Bitwarden => s(c, "access_token_env", "BWS_ACCESS_TOKEN"),
            Source::OnePassword => s(c, "service_account_token_env", "OP_SERVICE_ACCOUNT_TOKEN"),
            Source::Vault if s(c, "auth", "token") == "approle" => s(c, "secret_id_env", "VAULT_SECRET_ID"),
            Source::Vault => s(c, "token_env", "VAULT_TOKEN"),
            Source::Command | Source::Aws | Source::Gcp | Source::Azure => String::new(),
        }
    }
    pub fn remediation(self, k: ErrorKind, c: &toml::Table) -> String {
        let n = self.name();
        let te = self.token_env(c);
        match (self, k) {
            (Source::Bitwarden, ErrorKind::AuthFailed) => "Run `seagent secrets bitwarden token --access-token …` with a fresh access token (Bitwarden web app: Secrets Manager → Machine accounts → Access tokens). Wrong region? Re-run `seagent secrets bitwarden setup --server-url …`.".into(),
            (Source::OnePassword, ErrorKind::AuthFailed) => format!("Run `seagent secrets onepassword token --access-token …` with a fresh service-account token ({te}), or `op signin` for an interactive session."),
            (Source::OnePassword, ErrorKind::BinaryMissing) => "Install the 1Password CLI (https://developer.1password.com/docs/cli/get-started/) or set onepassword.binary_path.".into(),
            (Source::Command, ErrorKind::NotConfigured) => "Set command.command in secret_sources.toml to a fast, non-interactive helper that prints KEY=VALUE lines.".into(),
            (Source::Vault, ErrorKind::AuthFailed) => format!("Vault refused the credential — refresh ${te} (or the AppRole secret id) and check the policy grants read on the bound paths."),
            (Source::Aws | Source::Gcp | Source::Azure, ErrorKind::AuthFailed) => format!("The {n} CLI is not authorised — check its login / instance identity and the secret's access policy."),
            (Source::Command, ErrorKind::Internal) => "Run the helper manually in a shell to see its real error — seagent discards helper stderr so diagnostics can't leak secret material.".into(),
            (_, ErrorKind::NotConfigured) => format!("Run `seagent secrets {n} setup` to finish configuration."),
            (_, ErrorKind::BinaryMissing) => format!("Install the helper CLI (see `seagent secrets {n} status`)."),
            (_, ErrorKind::AuthFailed) => format!("Credentials rejected — run `seagent secrets {n} setup` to re-authenticate."),
            (_, ErrorKind::Network) => "Network problem reaching the secrets backend — check connectivity and retry.".into(),
            (_, ErrorKind::Timeout) => format!("Backend was slow — raise {n}.timeout_seconds if this recurs."),
            _ => String::new(),
        }
    }
    pub fn fetch(self, c: &toml::Table, env: &HashMap<String, String>, data: &Path, use_cache: bool) -> Fetch {
        match self {
            Source::Bitwarden => fetch_bitwarden(c, env, data, use_cache),
            Source::OnePassword => fetch_onepassword(c, env, data, use_cache),
            Source::Command => fetch_command(c, env),
            Source::Vault => cloud::fetch_vault(c, env, data, use_cache),
            Source::Aws | Source::Gcp | Source::Azure => cloud::fetch_cloud(self.name(), c, env, data, use_cache),
        }
    }
}

fn which(name: &str, env: &HashMap<String, String>) -> Option<PathBuf> {
    let path = env.get("PATH").cloned().or_else(|| std::env::var("PATH").ok()).unwrap_or_default();
    #[cfg(not(unix))]
    return seagent_core::platform::layout::which_in_pathext(name, Some(std::ffi::OsStr::new(&path)), std::env::var("PATHEXT").ok().as_deref()); // bw → bw.exe / op.exe
    #[cfg(unix)]
    std::env::split_paths(&path).map(|d| d.join(name)).find(|p| is_exec(p))
}

fn is_exec(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| crate::ops::hostos::is_executable(p, &m))
}

pub struct Out {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Run a helper CLI (argv, never a shell) with an allowlisted env, stdin = /dev/null.
fn run_cli(argv: &[String], env: &HashMap<String, String>, timeout: Duration, label: &str) -> Result<Out, String> {
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]).env_clear().envs(env).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("failed to invoke {label}: {e}"))?;
    let (mut so, mut se) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let ho = std::thread::spawn(move || {
        let mut v = vec![];
        let _ = so.by_ref().take(MAX_OUTPUT as u64 + 1).read_to_end(&mut v);
        v
    });
    let he = std::thread::spawn(move || {
        let mut v = vec![];
        let _ = se.by_ref().take(MAX_OUTPUT as u64).read_to_end(&mut v);
        v
    });
    let start = Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
            break st;
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{label} timed out after {}s", timeout.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = String::from_utf8_lossy(&ho.join().unwrap_or_default()).into_owned();
    let stderr = scrub_ansi(&String::from_utf8_lossy(&he.join().unwrap_or_default()));
    Ok(Out { code: status.code().unwrap_or(-1), stdout, stderr })
}

fn base_env(env: &HashMap<String, String>, keep: &[&str]) -> HashMap<String, String> {
    let mut out: HashMap<String, String> = ["PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR"].iter().chain(keep).filter_map(|k| env.get(*k).map(|v| (k.to_string(), v.clone()))).collect();
    out.insert("NO_COLOR".into(), "1".into());
    out
}

// ---------------------------------------------------------------- cache

/// One cached fetch: the secrets it produced and the unix time it was cached.
type Cached = (BTreeMap<String, String>, i64);

static MEM: Mutex<BTreeMap<String, Cached>> = Mutex::new(BTreeMap::new());

fn now() -> i64 {
    seagent_kernel::util::unix_now()
}

fn cache_file(data: &Path, name: &str) -> PathBuf {
    data.join("cache").join(name)
}

fn write_private(p: &Path, body: &[u8]) {
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    if seagent_kernel::util::atomic_write(p, body).is_ok() {
        let _ = crate::ops::hostos::set_mode(p, 0o600);
    }
}

/// In-memory entries are keyed by cache directory as well as file+key: two profiles
/// (`--profile`/`SEAGENT_PROFILE`) in one long-lived process must never see each other's
/// secrets, matching upstream's home-path component in the op L1 key.
fn mem_key(data: &Path, file: &str, key: &str) -> String {
    format!("{}|{file}|{key}", data.display())
}

fn cache_lookup(data: &Path, file: &str, key: &str, ttl: f64) -> Option<BTreeMap<String, String>> {
    if ttl <= 0.0 {
        return None;
    }
    // Timestamps have second resolution, so a sub-second TTL can never be honoured: treat
    // it as already expired rather than reusing an entry for a whole second.
    let fresh = |at: i64| ttl >= 1.0 && (now() - at) as f64 <= ttl && now() >= at;
    if let Some((v, at)) = MEM.lock().unwrap().get(&mem_key(data, file, key)) {
        if fresh(*at) {
            return Some(v.clone());
        }
    }
    let disk: Value = serde_json::from_str(&std::fs::read_to_string(cache_file(data, file)).ok()?).ok()?;
    let e = disk.get(key)?;
    let at = e.get("fetched_at")?.as_i64()?;
    if !fresh(at) {
        return None;
    }
    let v: BTreeMap<String, String> = serde_json::from_value(e.get("secrets")?.clone()).ok()?;
    MEM.lock().unwrap().insert(mem_key(data, file, key), (v.clone(), at));
    Some(v)
}

fn cache_read_any(data: &Path, file: &str, key: &str) -> Option<(BTreeMap<String, String>, i64)> {
    let disk: Value = serde_json::from_str(&std::fs::read_to_string(cache_file(data, file)).ok()?).ok()?;
    let e = disk.get(key)?;
    Some((serde_json::from_value(e.get("secrets")?.clone()).ok()?, e.get("fetched_at")?.as_i64()?))
}

fn cache_store(data: &Path, file: &str, key: &str, v: &BTreeMap<String, String>, ttl: f64) {
    if ttl <= 0.0 {
        return;
    }
    MEM.lock().unwrap().insert(mem_key(data, file, key), (v.clone(), now()));
    let p = cache_file(data, file);
    let mut disk: serde_json::Map<String, Value> = std::fs::read_to_string(&p).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    disk.insert(key.into(), json!({"secrets": v, "fetched_at": now()}));
    write_private(&p, serde_json::to_string(&disk).unwrap_or_default().as_bytes());
}

pub fn clear_caches(data: &Path) {
    MEM.lock().unwrap().clear();
    for f in ["bws_cache.json", "bws_cache.enc.json", "op_cache.json"] {
        let _ = std::fs::remove_file(cache_file(data, f));
    }
}

/// HKDF-SHA256 (RFC 5869), one 32-byte block.
fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = crypto::hmac_sha256(salt, ikm);
    let mut m = info.to_vec();
    m.push(1);
    crypto::hmac_sha256(&prk, &m)
}

const ENC_INFO: &[u8] = b"seagent-bws-encrypted-cache-v1";

/// Encrypted last-good Bitwarden cache: AES-256-CTR + HMAC-SHA256 (encrypt-then-MAC, the key
/// bound into the MAC), keys HKDF-derived from the access token; the token itself is never stored.
fn enc_write(data: &Path, key: &str, token: &str, v: &BTreeMap<String, String>) {
    let salt = crypto::random_bytes(16);
    let iv = crypto::random_bytes(16);
    let ek = hkdf(token.as_bytes(), &salt, &[ENC_INFO, b"|enc"].concat());
    let mk = hkdf(token.as_bytes(), &salt, &[ENC_INFO, b"|mac"].concat());
    let mut body = serde_json::to_vec(&json!({"secrets": v, "fetched_at": now()})).unwrap_or_default();
    let mut ivb = [0u8; 16];
    ivb.copy_from_slice(&iv);
    crypto::Aes::new(&ek).unwrap().ctr_apply(&ivb, &mut body);
    let mac = crypto::hmac_sha256(&mk, &[key.as_bytes(), &iv, &body].concat());
    let payload = json!({"version": 1, "key": key, "salt": crypto::b64(&salt), "nonce": crypto::b64(&iv), "ciphertext": crypto::b64(&body), "mac": crypto::b64(&mac)});
    write_private(&cache_file(data, "bws_cache.enc.json"), payload.to_string().as_bytes());
    let _ = std::fs::remove_file(cache_file(data, "bws_cache.json"));
}

fn enc_read(data: &Path, key: &str, token: &str, max_age: f64) -> Option<(BTreeMap<String, String>, i64)> {
    if max_age <= 0.0 {
        return None;
    }
    let p: Value = serde_json::from_str(&std::fs::read_to_string(cache_file(data, "bws_cache.enc.json")).ok()?).ok()?;
    if p.get("version")?.as_i64()? != 1 || p.get("key")?.as_str()? != key {
        return None;
    }
    let g = |k: &str| p.get(k).and_then(|v| v.as_str()).and_then(crypto::b64_decode);
    let (salt, iv, mut body, mac) = (g("salt")?, g("nonce")?, g("ciphertext")?, g("mac")?);
    let mk = hkdf(token.as_bytes(), &salt, &[ENC_INFO, b"|mac"].concat());
    if iv.len() != 16 || !crypto::ct_eq(&crypto::hmac_sha256(&mk, &[key.as_bytes(), &iv, &body].concat()), &mac) {
        return None;
    }
    let ek = hkdf(token.as_bytes(), &salt, &[ENC_INFO, b"|enc"].concat());
    let mut ivb = [0u8; 16];
    ivb.copy_from_slice(&iv);
    crypto::Aes::new(&ek)?.ctr_apply(&ivb, &mut body);
    let e: Value = serde_json::from_slice(&body).ok()?;
    let at = e.get("fetched_at")?.as_i64()?;
    let age = (now() - at) as f64;
    // Same second-resolution caveat as `cache_lookup`.
    if max_age < 1.0 || age < 0.0 || age > max_age {
        return None;
    }
    Some((serde_json::from_value(e.get("secrets")?.clone()).ok()?, at))
}

// ---------------------------------------------------------------- Bitwarden

/// Reduce a bws (color-eyre) error dump to its numbered cause lines joined with `; `.
pub fn summarize_bws_stderr(raw: &str) -> String {
    let text = raw.replace('\x1b', "");
    let text = text.trim();
    let mut causes = vec![];
    let numbered = regex::Regex::new(r"^\d+:\s*").unwrap();
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with("Location:") || l.starts_with("Backtrace omitted") || l.starts_with("Run with ") {
            break;
        }
        let c = numbered.replace(l, "").to_string();
        if !l.is_empty() && l != "Error:" && !c.is_empty() {
            causes.push(c);
        }
    }
    if causes.is_empty() { text.to_string() } else { causes.join("; ") }
}

pub fn bws_list(bws: &Path, token: &str, project: &str, server_url: &str, env: &HashMap<String, String>) -> Result<(BTreeMap<String, String>, Vec<String>), String> {
    let argv = vec![bws.display().to_string(), "secret".into(), "list".into(), project.into(), "--output".into(), "json".into()];
    let mut e = base_env(env, &["BWS_SERVER_URL"]);
    e.insert("BWS_ACCESS_TOKEN".into(), token.into());
    if !server_url.is_empty() {
        e.insert("BWS_SERVER_URL".into(), server_url.into());
    }
    let o = run_cli(&argv, &e, CLI_TIMEOUT, "bws").map_err(|m| if m.contains("timed out") { "bws timed out after 30s fetching secrets".to_string() } else { m })?;
    if o.code != 0 {
        let err = summarize_bws_stderr(if o.stderr.trim().is_empty() { &o.stdout } else { &o.stderr });
        return Err(format!("bws exited {}: {}", o.code, err.chars().take(200).collect::<String>()));
    }
    let raw = o.stdout.trim();
    if raw.is_empty() {
        return Ok((BTreeMap::new(), vec!["bws returned no output (empty project?)".into()]));
    }
    let v: Value = serde_json::from_str(raw).map_err(|e| format!("bws returned non-JSON output: {e}"))?;
    let arr = v.as_array().ok_or_else(|| format!("bws returned unexpected shape: {}", if v.is_object() { "dict" } else { "scalar" }))?;
    let (mut out, mut warn) = (BTreeMap::new(), vec![]);
    for it in arr {
        let (Some(k), Some(val)) = (it.get("key").and_then(|x| x.as_str()), it.get("value").and_then(|x| x.as_str())) else { continue };
        if valid_env_name(k) {
            out.insert(k.to_string(), val.to_string());
        } else {
            warn.push(format!("Skipping secret {k:?}: not a valid env-var name"));
        }
    }
    Ok((out, warn))
}

/// `bws project list --output json` → [(id, name)].
pub fn bws_projects(bws: &Path, token: &str, server_url: &str, env: &HashMap<String, String>) -> Result<Vec<(String, String)>, String> {
    let argv = vec![bws.display().to_string(), "project".into(), "list".into(), "--output".into(), "json".into()];
    let mut e = base_env(env, &[]);
    e.insert("BWS_ACCESS_TOKEN".into(), token.into());
    if !server_url.is_empty() {
        e.insert("BWS_SERVER_URL".into(), server_url.into());
    }
    let o = run_cli(&argv, &e, CLI_TIMEOUT, "bws")?;
    if o.code != 0 {
        return Err(format!("bws exited {}: {}", o.code, summarize_bws_stderr(&o.stderr)));
    }
    let v: Value = serde_json::from_str(o.stdout.trim()).map_err(|e| format!("bws returned non-JSON output: {e}"))?;
    Ok(v.as_array().map(|a| a.iter().filter_map(|p| Some((p.get("id")?.as_str()?.to_string(), p.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string()))).collect()).unwrap_or_default())
}

pub fn find_bws(c: &toml::Table, env: &HashMap<String, String>) -> Option<PathBuf> {
    let pinned = s(c, "binary_path", "");
    if !pinned.is_empty() {
        return Some(PathBuf::from(&pinned)).filter(|p| is_exec(p));
    }
    which("bws", env)
}

fn fetch_bitwarden(c: &toml::Table, env: &HashMap<String, String>, data: &Path, use_cache: bool) -> Fetch {
    let r = Fetch::default();
    let te = Source::Bitwarden.token_env(c);
    let token = env.get(&te).map(|s| s.trim().to_string()).unwrap_or_default();
    if token.is_empty() {
        return r.fail(format!("bitwarden.enabled is true but {te} is not set.  Run `seagent secrets bitwarden setup`."), ErrorKind::NotConfigured);
    }
    let project = s(c, "project_id", "");
    if project.is_empty() {
        return r.fail("bitwarden.project_id is empty.  Run `seagent secrets bitwarden setup`.", ErrorKind::NotConfigured);
    }
    let server = s(c, "server_url", "");
    let ttl = f(c, "cache_ttl_seconds", 300.0);
    let enc = c.get("encrypted_cache").and_then(|v| v.as_table()).cloned().unwrap_or_default();
    let (enc_on, max_stale) = (b(&enc, "enabled", false), f(&enc, "max_stale_seconds", 0.0));
    let key = format!("{}|{project}|{server}", fingerprint(&token));
    if use_cache && ttl > 0.0 {
        let hit = if enc_on { enc_read(data, &key, &token, ttl).map(|x| x.0) } else { cache_lookup(data, "bws_cache.json", &key, ttl) };
        if let Some(v) = hit {
            return Fetch { secrets: v, ..r };
        }
    }
    let Some(bws) = find_bws(c, env) else {
        return r.fail("bws binary not available — `bws` is not on PATH.  Install it from https://github.com/bitwarden/sdk-sm/releases or set bitwarden.binary_path.", ErrorKind::BinaryMissing);
    };
    match bws_list(&bws, &token, &project, &server, env) {
        Ok((v, w)) => {
            if use_cache {
                if enc_on {
                    enc_write(data, &key, &token, &v);
                } else {
                    cache_store(data, "bws_cache.json", &key, &v, ttl);
                }
            }
            Fetch { secrets: v, warnings: w, binary: Some(bws), error: None }
        }
        Err(e) => {
            let kind = classify(&e, BWS_RULES);
            // Stale fallback ONLY for transport failures — never auth/internal.
            if use_cache && matches!(kind, ErrorKind::Network | ErrorKind::Timeout) {
                let stale = if enc_on { enc_read(data, &key, &token, max_stale).map(|x| (x, "stale ENCRYPTED disk cache")) } else if ttl > 0.0 { cache_read_any(data, "bws_cache.json", &key).map(|x| (x, "stale disk cache")) } else { None };
                if let Some(((v, at), label)) = stale {
                    return Fetch { secrets: v, warnings: vec![format!("bws live fetch failed ({e}); falling back to {label} ({}s old)", (now() - at).max(0))], binary: Some(bws), error: None };
                }
            }
            Fetch { binary: Some(bws), ..r }.fail(e, kind)
        }
    }
}

// ---------------------------------------------------------------- 1Password

pub fn validate_refs(m: &toml::Table) -> (BTreeMap<String, String>, Vec<String>) {
    let (mut ok, mut warn) = (BTreeMap::new(), vec![]);
    for (n, r) in m {
        if !valid_env_name(n) {
            warn.push(format!("Skipping {n:?}: not a valid env-var name"));
        } else if let Some(r) = r.as_str() {
            if r.trim().starts_with("op://") {
                ok.insert(n.clone(), r.trim().to_string());
            } else {
                warn.push(format!("Skipping {n:?}: {r:?} is not an op:// secret reference"));
            }
        } else {
            warn.push(format!("Skipping {n:?}: reference is not a string"));
        }
    }
    (ok, warn)
}

pub fn find_op(c: &toml::Table, env: &HashMap<String, String>) -> Option<PathBuf> {
    let pinned = s(c, "binary_path", "");
    if !pinned.is_empty() {
        // Pinned-but-missing never falls back to PATH.
        return Some(PathBuf::from(&pinned)).filter(|p| is_exec(p));
    }
    which("op", env)
}

const OP_ENV: &[&str] = &["OP_CONFIG_DIR", "OP_ACCOUNT", "OP_CONNECT_HOST", "OP_CONNECT_TOKEN", "OP_LOAD_DESKTOP_APP_SETTINGS"];

pub fn op_read(op: &Path, reference: &str, account: &str, token: &str, env: &HashMap<String, String>) -> Result<String, String> {
    let mut argv = vec![op.display().to_string(), "read".into()];
    if !account.is_empty() {
        argv.extend(["--account".into(), account.into()]);
    }
    argv.extend(["--".into(), reference.into()]); // a reference can never parse as an op flag
    let mut e = base_env(env, OP_ENV);
    e.extend(env.iter().filter(|(k, _)| k.starts_with("OP_SESSION_")).map(|(k, v)| (k.clone(), v.clone())));
    if !token.is_empty() {
        e.insert("OP_SERVICE_ACCOUNT_TOKEN".into(), token.into());
    }
    let o = run_cli(&argv, &e, CLI_TIMEOUT, "op").map_err(|m| if m.contains("timed out") { format!("op read timed out after 30s for {reference:?}") } else { m })?;
    if o.code != 0 {
        let err: String = o.stderr.trim().chars().take(200).collect();
        return Err(if err.is_empty() { format!("op read exited {} for {reference:?}", o.code) } else { format!("op read failed for {reference:?}: {err}") });
    }
    let v = o.stdout.trim_end_matches(['\r', '\n']).to_string();
    if v.trim().is_empty() {
        return Err(format!("op read returned an empty value for {reference:?}"));
    }
    Ok(v)
}

/// `op whoami` — verify a 1Password credential before storing it (upstream `_op_whoami`).
/// The token is only ever visible to `op` as an env var, never on the argv.
pub fn op_whoami(op: &Path, account: &str, token: &str, env: &HashMap<String, String>) -> Result<String, String> {
    let mut argv = vec![op.display().to_string(), "whoami".into()];
    if !account.is_empty() {
        argv.extend(["--account".into(), account.into()]);
    }
    let mut e = base_env(env, OP_ENV);
    e.extend(env.iter().filter(|(k, _)| k.starts_with("OP_SESSION_")).map(|(k, v)| (k.clone(), v.clone())));
    if !token.is_empty() {
        e.insert("OP_SERVICE_ACCOUNT_TOKEN".into(), token.into());
    }
    let o = run_cli(&argv, &e, CLI_TIMEOUT, "op")?;
    if o.code != 0 {
        let err: String = o.stderr.trim().chars().take(200).collect();
        return Err(if err.is_empty() { format!("op whoami exited {}", o.code) } else { err });
    }
    Ok(o.stdout.trim().to_string())
}

fn op_auth_fp(te: &str, env: &HashMap<String, String>) -> String {
    let g = |k: &str| env.get(k).cloned().unwrap_or_default();
    let mut parts = vec![format!("token={}", g(te)), format!("account={}", g("OP_ACCOUNT")), format!("connect_host={}", g("OP_CONNECT_HOST")), format!("connect_token={}", g("OP_CONNECT_TOKEN"))];
    let mut sess: Vec<_> = env.iter().filter(|(k, _)| k.starts_with("OP_SESSION_")).map(|(k, v)| format!("{k}={v}")).collect();
    sess.sort();
    parts.extend(sess);
    fingerprint(&parts.join("\n"))
}

fn fetch_onepassword(c: &toml::Table, env: &HashMap<String, String>, data: &Path, use_cache: bool) -> Fetch {
    let mut r = Fetch::default();
    let m = c.get("env").and_then(|v| v.as_table()).cloned().unwrap_or_default();
    let (valid, warn) = validate_refs(&m);
    r.warnings = warn;
    if valid.is_empty() {
        return r.fail("onepassword.enabled is true but onepassword.env has no valid op:// bindings.  Add one with `seagent secrets onepassword set NAME op://vault/item/field`.", ErrorKind::NotConfigured);
    }
    let te = Source::OnePassword.token_env(c);
    let token = env.get(&te).map(|s| s.trim().to_string()).unwrap_or_default();
    let account = s(c, "account", "");
    let ttl = f(c, "cache_ttl_seconds", 300.0);
    let refs_fp = fingerprint(&valid.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("\n"));
    let key = format!("{}|{account}|{refs_fp}", op_auth_fp(&te, env));
    if use_cache {
        if let Some(v) = cache_lookup(data, "op_cache.json", &key, ttl) {
            r.secrets = v;
            return r;
        }
    }
    let pinned = s(c, "binary_path", "");
    let Some(op) = find_op(c, env) else {
        let msg = if pinned.is_empty() { "onepassword.enabled is true but the op CLI was not found on PATH.  Install it (https://developer.1password.com/docs/cli/get-started/) or set onepassword.binary_path.".to_string() } else { format!("onepassword.binary_path ({pinned:?}) is not an executable op binary.") };
        return r.fail(msg, ErrorKind::BinaryMissing);
    };
    r.binary = Some(op.clone());
    let mut errors = vec![];
    for (n, rf) in &valid {
        match op_read(&op, rf, &account, &token, env) {
            Ok(v) => {
                r.secrets.insert(n.clone(), v);
            }
            Err(e) => {
                r.warnings.push(e.clone());
                errors.push(e);
            }
        }
    }
    // Only a complete pull is cached, so a transient failure isn't frozen in for the TTL.
    if use_cache && errors.is_empty() && !r.secrets.is_empty() {
        cache_store(data, "op_cache.json", &key, &r.secrets, ttl);
    }
    if r.secrets.is_empty() {
        if let Some(e) = errors.first() {
            let k = classify(e, OP_RULES);
            return r.fail(format!("no 1Password reference resolved: {e}"), k);
        }
    }
    r
}

// ---------------------------------------------------------------- command helper

/// Strip one layer of matching surrounding quotes from a dotenv value.
pub fn unquote(raw: &str) -> String {
    let t = raw.trim();
    let bs = t.as_bytes();
    if bs.len() >= 2 && bs[0] == bs[bs.len() - 1] && (bs[0] == b'"' || bs[0] == b'\'') {
        return t[1..t.len() - 1].to_string();
    }
    t.to_string()
}

pub fn parse_kv(stdout: &str) -> BTreeMap<String, String> {
    let re = regex::Regex::new(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$").unwrap();
    stdout.replace("\r\n", "\n").lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).filter_map(|l| re.captures(l).map(|c| (c[1].to_string(), unquote(&c[2])))).collect()
}

/// Run the helper via `/bin/sh -c` in its own process group; the key travels only as data
/// in `SEAGENT_SECRET_KEY`. Failures log structured fields only (never the command, stderr or values).
pub fn run_helper(command: &str, key: &str, timeout: f64, env: &HashMap<String, String>) -> Result<String, String> {
    let mut e = env.clone();
    e.insert("SEAGENT_SECRET_KEY".into(), key.into());
    #[cfg(unix)]
    let mut child = {
        use std::os::unix::process::CommandExt;
        Command::new("/bin/sh").arg("-c").arg(command).env_clear().envs(&e).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).process_group(0).spawn().map_err(|e| format!("helper failed to spawn; resolving no value: errno={}", e.raw_os_error().unwrap_or(0)))?
    };
    // Windows: this machine's shell (Git Bash, else PowerShell) in a kill-on-close job object;
    // the shells need `SystemRoot` even with an otherwise cleared environment.
    #[cfg(not(unix))]
    let mut child = {
        if let Ok(v) = std::env::var("SystemRoot") {
            e.entry("SystemRoot".into()).or_insert(v);
        }
        let mut c = seagent_core::platform::shell::command(seagent_core::platform::shell::Style::BinSh, command);
        c.env_clear().envs(&e).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
        seagent_core::platform::proc::spawn_in_group(&mut c, false).map_err(|e| format!("helper failed to spawn; resolving no value: errno={}", e.raw_os_error().unwrap_or(0)))?
    };
    let mut so = child.stdout.take().unwrap();
    let h = std::thread::spawn(move || {
        let mut v = vec![];
        let _ = so.by_ref().take(MAX_OUTPUT as u64 + 1).read_to_end(&mut v);
        v
    });
    let start = Instant::now();
    let st = loop {
        if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
            break st;
        }
        if start.elapsed().as_secs_f64() > timeout {
            #[cfg(unix)]
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            #[cfg(not(unix))]
            seagent_core::platform::proc::kill_group(child.id() as i32, Duration::ZERO);
            let _ = child.wait();
            return Err(format!("helper timed out after {timeout}s; resolving no value"));
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let out = h.join().unwrap_or_default();
    if !st.success() {
        #[cfg(unix)]
        use std::os::unix::process::ExitStatusExt;
        #[cfg(unix)]
        let signal = st.signal();
        #[cfg(not(unix))]
        let signal: Option<i32> = None; // Windows has no signals: the exit code says it all
        return Err(match signal {
            Some(sig) => format!("helper failed; resolving no value: code=? signal={sig}"),
            None => format!("helper failed; resolving no value: code={} signal=none", st.code().unwrap_or(-1)),
        });
    }
    if out.len() > MAX_OUTPUT {
        return Err(format!("helper output exceeded the {MAX_OUTPUT}-byte cap; resolving no value"));
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

fn fetch_command(c: &toml::Table, env: &HashMap<String, String>) -> Fetch {
    let mut r = Fetch::default();
    let command = s(c, "command", "").trim().to_string();
    if command.is_empty() {
        return r.fail("command.enabled is true but command.command is empty.  Set the helper command in secret_sources.toml.", ErrorKind::NotConfigured);
    }
    let t = f(c, "helper_timeout_seconds", COMMAND_TIMEOUT);
    match run_helper(&command, "", if t > 0.0 { t } else { COMMAND_TIMEOUT }, env) {
        Err(e) => {
            eprintln!("[secrets:command] {e}");
            r.fail("helper command failed (see structured fields above); no secrets applied", ErrorKind::Internal)
        }
        Ok(out) => {
            r.secrets = parse_kv(&out);
            if r.secrets.is_empty() {
                r.warnings.push("helper output was not a KEY=VALUE map; nothing to apply".into());
            }
            r
        }
    }
}

// ---------------------------------------------------------------- orchestration

#[derive(Debug, Default)]
pub struct SourceReport {
    pub name: String,
    pub label: String,
    pub fetch: Fetch,
    pub remediation: String,
    pub applied: Vec<String>,
    pub skipped_existing: Vec<String>,
    pub skipped_claimed: Vec<String>,
    pub skipped_protected: Vec<String>,
    pub skipped_invalid: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Report {
    pub sources: Vec<SourceReport>,
    pub conflicts: Vec<String>,
    /// var → source that supplied it.
    pub provenance: BTreeMap<String, String>,
}

/// Enabled sources: `sources = [...]` order first, then built-in order; mapped before bulk.
pub fn ordered_enabled(t: &toml::Table) -> (Vec<Source>, Vec<String>) {
    let explicit: Vec<String> = t.get("sources").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    let unknown: Vec<String> = explicit.iter().filter(|n| Source::parse(n).is_none()).cloned().collect();
    let mut order: Vec<Source> = explicit.iter().filter_map(|n| Source::parse(n)).collect();
    for s in ALL {
        if !order.contains(s) {
            order.push(*s);
        }
    }
    let en: Vec<Source> = order.into_iter().filter(|s| b(&section(t, s.name()), "enabled", false)).collect();
    let mapped = en.iter().filter(|s| s.shape() == Shape::Mapped).copied();
    let bulk = en.iter().filter(|s| s.shape() == Shape::Bulk).copied();
    let warn = if unknown.is_empty() { vec![] } else { vec![format!("sources names unknown source(s): {} (known: bitwarden, onepassword, command, vault, aws, gcp, azure)", unknown.join(", "))] };
    (mapped.chain(bulk).collect(), warn)
}

fn fetch_with_timeout(src: Source, c: toml::Table, env: HashMap<String, String>, data: PathBuf, use_cache: bool) -> Fetch {
    let t = f(&c, "timeout_seconds", DEFAULT_FETCH_TIMEOUT);
    let t = if t > 0.0 { t } else { DEFAULT_FETCH_TIMEOUT };
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(src.fetch(&c, &env, &data, use_cache));
    });
    rx.recv_timeout(Duration::from_secs_f64(t)).unwrap_or_else(|_| Fetch::default().fail(format!("{} fetch exceeded {t:.0}s; skipped", src.name()), ErrorKind::Timeout))
}

/// Fetch every enabled source and apply the merged result to `env` (see module docs).
pub fn apply_all(t: &toml::Table, env: &mut HashMap<String, String>, data: &Path, use_cache: bool) -> Report {
    let mut rep = Report::default();
    let (en, warn) = ordered_enabled(t);
    rep.conflicts.extend(warn);
    if en.is_empty() {
        return rep;
    }
    let preserve: Vec<String> = t.get("preserve_existing").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect()).unwrap_or_default();
    let mut protected: BTreeMap<String, String> = BTreeMap::new();
    let mut fetched = vec![];
    for src in en {
        let c = section(t, src.name());
        let r = fetch_with_timeout(src, c.clone(), env.clone(), data.to_path_buf(), use_cache);
        let te = src.token_env(&c);
        if !te.is_empty() {
            protected.entry(te).or_insert_with(|| src.name().to_string());
        }
        fetched.push((src, c, r));
    }
    let mut claimed: BTreeMap<String, String> = BTreeMap::new();
    for (src, c, r) in fetched {
        let mut sr = SourceReport { name: src.name().into(), label: src.label().into(), ..Default::default() };
        if let Some((_, k)) = &r.error {
            sr.remediation = src.remediation(*k, &c);
        } else {
            let over = b(&c, "override_existing", src.override_default());
            for (var, val) in &r.secrets {
                if !valid_env_name(var) {
                    sr.skipped_invalid.push(var.clone());
                } else if protected.contains_key(var) {
                    sr.skipped_protected.push(var.clone());
                } else if let Some(w) = claimed.get(var) {
                    sr.skipped_claimed.push(var.clone());
                    rep.conflicts.push(format!("{var}: kept value from {w}; {} also supplies it (first source wins — remove one binding or reorder `sources`)", src.name()));
                } else if env.get(var).is_some_and(|v| !v.is_empty()) && (preserve.contains(var) || !over) {
                    sr.skipped_existing.push(var.clone());
                } else {
                    env.insert(var.clone(), val.clone());
                    claimed.insert(var.clone(), src.name().into());
                    rep.provenance.insert(var.clone(), src.name().into());
                    sr.applied.push(var.clone());
                }
            }
        }
        sr.fetch = r;
        rep.sources.push(sr);
    }
    rep
}

/// Startup hook (after `.env`): apply enabled sources to the process environment.
/// Runs single-threaded at the start of `main`; never fails, only warns.
pub fn early() {
    let paths = Paths::from_env();
    let t = load_config(&paths);
    if ordered_enabled(&t).0.is_empty() {
        return;
    }
    let before: HashMap<String, String> = std::env::vars().collect();
    let mut env = before.clone();
    let rep = apply_all(&t, &mut env, &paths.data, true);
    for (k, v) in &env {
        if before.get(k) != Some(v) {
            std::env::set_var(k, v);
        }
    }
    for sr in &rep.sources {
        if let Some((e, _)) = &sr.fetch.error {
            eprintln!("seagent: warning: secret source {}: {e}{}", sr.name, if sr.remediation.is_empty() { String::new() } else { format!(" — {}", sr.remediation) });
        }
        for w in &sr.fetch.warnings {
            eprintln!("seagent: warning: secret source {}: {w}", sr.name);
        }
    }
    for c in &rep.conflicts {
        eprintln!("seagent: warning: secret sources: {c}");
    }
}

// ---------------------------------------------------------------- CLI

/// Upsert `KEY=value` in `<config>/.env` (0600), keeping other lines.
pub fn save_env_value(paths: &Paths, key: &str, value: &str) -> Result<PathBuf, String> {
    let p = paths.config_dir.join(".env");
    let text = std::fs::read_to_string(&p).unwrap_or_default();
    let mut lines: Vec<String> = text.lines().filter(|l| {
        let l = l.trim_start().strip_prefix("export ").unwrap_or(l.trim_start());
        l.split_once('=').map(|(k, _)| k.trim() != key).unwrap_or(true)
    }).map(String::from).collect();
    lines.push(format!("{key}={value}"));
    std::fs::create_dir_all(&paths.config_dir).map_err(|e| e.to_string())?;
    write_private(&p, (lines.join("\n") + "\n").as_bytes());
    std::env::set_var(key, value);
    Ok(p)
}

fn yn(v: bool) -> &'static str {
    if v { "yes" } else { "no" }
}

fn proc_env() -> HashMap<String, String> {
    std::env::vars().collect()
}

pub fn status_text(paths: &Paths, src: Source) -> String {
    let t = load_config(paths);
    let c = section(&t, src.name());
    let env = proc_env();
    let te = src.token_env(&c);
    let mut o = format!("{}\n  enabled            {}\n", src.label(), yn(b(&c, "enabled", false)));
    match src {
        Source::Bitwarden => {
            let bin = find_bws(&c, &env);
            o += &format!("  token env var      {te}\n  token in env       {}\n  project id         {}\n  server url         {}\n  override existing  {}\n  cache ttl (s)      {}\n  bws binary         {}\n", yn(env.get(&te).is_some_and(|v| !v.trim().is_empty())), s(&c, "project_id", "(unset)"), { let u = s(&c, "server_url", ""); if u.is_empty() { "default (US Cloud, https://vault.bitwarden.com)".into() } else { u } }, yn(b(&c, "override_existing", true)), f(&c, "cache_ttl_seconds", 300.0), bin.map(|p| p.display().to_string()).unwrap_or_else(|| "not installed".into()));
        }
        Source::OnePassword => {
            let m = c.get("env").and_then(|v| v.as_table()).cloned().unwrap_or_default();
            o += &format!("  token env var      {te}\n  token in env       {}\n  account            {}\n  op binary          {}\n  bindings           {}\n", yn(env.get(&te).is_some_and(|v| !v.trim().is_empty())), s(&c, "account", "(default)"), find_op(&c, &env).map(|p| p.display().to_string()).unwrap_or_else(|| "not found".into()), m.len());
            for (k, v) in &m {
                o += &format!("    {k} → {}\n", v.as_str().unwrap_or("?"));
            }
        }
        Source::Vault | Source::Aws | Source::Gcp | Source::Azure => {
            let (refs, _) = cloud::bindings(&c);
            let wh = match src {
                Source::Vault => format!("  address            {}\n  auth               {}\n  mount              {}\n  credential env     {te} ({})\n", { let a = s(&c, "addr", ""); if a.is_empty() { env.get("VAULT_ADDR").cloned().unwrap_or_else(|| "(unset)".into()) } else { a } }, s(&c, "auth", "token"), s(&c, "mount", "secret"), if env.get(&te).is_some_and(|v| !v.trim().is_empty()) { "set" } else { "missing" }),
                Source::Aws => format!("  region             {}\n", s(&c, "region", "(CLI default)")),
                Source::Gcp => format!("  project            {}\n", s(&c, "project", "(CLI default)")),
                _ => format!("  vault name         {}\n", s(&c, "vault_name", "(unset)")),
            };
            o += &format!("{wh}  bindings           {}\n", refs.len());
            for (k, v) in &refs {
                o += &format!("    {k} → {v}\n");
            }
        }
        Source::Command => {
            o += &format!("  command            {}\n  timeout (s)        {}\n  override existing  {}\n", if s(&c, "command", "").is_empty() { "(unset)" } else { "(set)" }, f(&c, "helper_timeout_seconds", COMMAND_TIMEOUT), yn(b(&c, "override_existing", false)));
        }
    }
    if !b(&c, "enabled", false) {
        o += &format!("\n  Run `seagent secrets {} setup` to enable.\n", src.name());
    }
    o
}

/// Fetch live (no cache) and report what would happen to each variable.
pub fn sync_text(paths: &Paths, src: Source) -> Result<String, String> {
    let t = load_config(paths);
    let c = section(&t, src.name());
    if !b(&c, "enabled", false) {
        return Err(format!("{} is not enabled — run `seagent secrets {} setup`", src.label(), src.name()));
    }
    let env = proc_env();
    let r = src.fetch(&c, &env, &paths.data, false);
    if let Some((e, k)) = &r.error {
        return Err(format!("fetch failed: {e}\n{}", src.remediation(*k, &c)));
    }
    // Refresh the caches with the live values.
    let _ = src.fetch(&c, &env, &paths.data, true);
    let te = src.token_env(&c);
    let over = b(&c, "override_existing", src.override_default());
    let mut o = String::new();
    if r.secrets.is_empty() {
        o += "no secrets returned\n";
    }
    for k in r.secrets.keys() {
        let act = if *k == te { "skip (bootstrap token)" } else if env.get(k).is_some_and(|v| !v.is_empty()) { if over { "set (overrides env)" } else { "skip (already set)" } } else { "set" };
        o += &format!("  {k:<32} {act}\n");
    }
    for w in &r.warnings {
        o += &format!("warning: {w}\n");
    }
    o += "values are applied at the start of every seagent process (cache refreshed)";
    Ok(o)
}

fn set_enabled(paths: &Paths, src: Source, f: impl FnOnce(&mut toml::Table)) -> Result<(), String> {
    let mut t = load_config(paths);
    let mut c = section(&t, src.name());
    f(&mut c);
    t.insert(src.name().into(), toml::Value::Table(c));
    save_config(paths, &t)?;
    clear_caches(&paths.data);
    Ok(())
}

pub fn run(paths: &Paths, a: &Args) -> Result<String, String> {
    let which = a.pos(0).unwrap_or("");
    if which == "sources" {
        let t = load_config(paths);
        let mut env = proc_env();
        let rep = apply_all(&t, &mut env, &paths.data, true);
        if rep.sources.is_empty() {
            return Ok(format!("no external secret source enabled ({})", config_path(paths).display()));
        }
        let mut o = String::new();
        for sr in &rep.sources {
            o += &format!("{} ({}): ", sr.label, sr.name);
            match &sr.fetch.error {
                Some((e, k)) => o += &format!("error [{}] {e}\n  → {}\n", k.as_str(), sr.remediation),
                None => o += &format!("{} applied, {} kept from env, {} claimed by another source, {} protected\n", sr.applied.len(), sr.skipped_existing.len(), sr.skipped_claimed.len(), sr.skipped_protected.len()),
            }
        }
        for (v, s) in &rep.provenance {
            o += &format!("  {v:<32} ← {s}\n");
        }
        for c in &rep.conflicts {
            o += &format!("warning: {c}\n");
        }
        return Ok(o.trim_end().to_string());
    }
    let src = Source::parse(which).ok_or("usage: seagent secrets bitwarden|onepassword|command|vault|aws|gcp|azure|sources <status|setup|sync|token|set|remove|disable>")?;
    let env = proc_env();
    match a.pos(1).unwrap_or("status") {
        "status" => Ok(status_text(paths, src)),
        "sync" => sync_text(paths, src),
        "disable" => {
            set_enabled(paths, src, |c| {
                c.insert("enabled".into(), false.into());
            })?;
            Ok(format!("{} disabled", src.label()))
        }
        "token" => {
            let mut c = section(&load_config(paths), src.name());
            if let Some(te) = a.val("token-env") {
                c.insert(if src == Source::Bitwarden { "access_token_env" } else { "service_account_token_env" }.into(), te.into());
            }
            let te = src.token_env(&c);
            if te.is_empty() {
                return Err("the command source has no bootstrap token".into());
            }
            // `--token-env` must stick, otherwise the token lands in a var nothing reads.
            if a.val("token-env").is_some() {
                let mut t = load_config(paths);
                t.insert(src.name().into(), toml::Value::Table(c.clone()));
                save_config(paths, &t)?;
            }
            let tok = a.val("access-token").ok_or("usage: seagent secrets <source> token --access-token TOKEN [--no-verify]")?.trim().to_string();
            if !a.flag("no-verify") {
                match src {
                    Source::Bitwarden => {
                        let bin = find_bws(&c, &env).ok_or("bws binary not available — cannot verify. Re-run with --no-verify to store anyway.")?;
                        let ps = bws_projects(&bin, &tok, &s(&c, "server_url", ""), &env).map_err(|e| format!("✗ New token was rejected — nothing was changed. ({e})"))?;
                        let pid = s(&c, "project_id", "");
                        if !pid.is_empty() && !ps.iter().any(|p| p.0 == pid) {
                            eprintln!("warning: configured project {pid} is not visible to this machine account");
                        }
                    }
                    // Upstream verifies a 1Password token with `op whoami` before storing it.
                    Source::OnePassword => {
                        let bin = find_op(&c, &env).ok_or("the op CLI was not found — cannot verify. Re-run with --no-verify to store anyway.")?;
                        op_whoami(&bin, &s(&c, "account", ""), &tok, &env).map_err(|e| format!("✗ New token was rejected — nothing was changed. ({e})"))?;
                    }
                    _ => {}
                }
            }
            let p = save_env_value(paths, &te, &tok)?;
            clear_caches(&paths.data);
            Ok(format!("stored {te} in {}", p.display()))
        }
        "set" if src.shape() == Shape::Mapped => {
            let (n, r) = (a.need(2, "NAME")?.to_string(), a.need(3, "reference")?.to_string());
            let mut probe = toml::Table::new();
            probe.insert(n.clone(), r.clone().into());
            let (ok, warn) = if src == Source::OnePassword { validate_refs(&probe) } else { cloud::bindings(&toml::Table::from_iter([("env".to_string(), toml::Value::Table(probe))])) };
            if ok.is_empty() {
                return Err(warn.join("; "));
            }
            set_enabled(paths, src, |c| {
                let mut m = c.get("env").and_then(|v| v.as_table()).cloned().unwrap_or_default();
                m.insert(n.clone(), r.trim().into());
                c.insert("env".into(), toml::Value::Table(m));
            })?;
            Ok(format!("{n} → {}", r.trim()))
        }
        "remove" if src.shape() == Shape::Mapped => {
            let n = a.need(2, "NAME")?.to_string();
            let mut found = false;
            set_enabled(paths, src, |c| {
                if let Some(m) = c.get_mut("env").and_then(|v| v.as_table_mut()) {
                    found = m.remove(&n).is_some();
                }
            })?;
            if found { Ok(format!("removed {n}")) } else { Err(format!("{n} is not bound")) }
        }
        "setup" => setup(paths, src, a, &env),
        o => Err(format!("unknown `seagent secrets {} {o}`", src.name())),
    }
}

fn setup(paths: &Paths, src: Source, a: &Args, env: &HashMap<String, String>) -> Result<String, String> {
    let mut c = section(&load_config(paths), src.name());
    let mut env = env.clone();
    match src {
        Source::Bitwarden => {
            let bin = find_bws(&c, &env).ok_or("bws binary not available — install it from https://github.com/bitwarden/sdk-sm/releases (or set bitwarden.binary_path)")?;
            let te = a.val("token-env").map(String::from).unwrap_or_else(|| s(&c, "access_token_env", "BWS_ACCESS_TOKEN"));
            let token = match a.val("access-token") {
                Some(t) => t.trim().to_string(),
                None => env.get(&te).cloned().filter(|t| !t.is_empty()).ok_or(format!("non-interactive setup needs --access-token (or {te} in the environment)"))?,
            };
            if !token.starts_with("0.") {
                eprintln!("warning: this does not look like a Bitwarden Secrets Manager access token (they start with `0.`)");
            }
            let server = a.val("server-url").map(String::from).or_else(|| env.get("BWS_SERVER_URL").map(|s| s.trim().to_string()).filter(|s| !s.is_empty())).unwrap_or_else(|| s(&c, "server_url", ""));
            let project = match a.val("project-id") {
                Some(p) => p.to_string(),
                None => {
                    let ps = bws_projects(&bin, &token, &server, &env)?;
                    match ps.as_slice() {
                        [one] => one.0.clone(),
                        [] => return Err("this machine account sees no projects — grant it one in the Bitwarden web app".into()),
                        many => return Err(format!("several projects are visible; pass --project-id:\n{}", many.iter().map(|p| format!("  {}  {}", p.0, p.1)).collect::<Vec<_>>().join("\n"))),
                    }
                }
            };
            let (secrets, warns) = bws_list(&bin, &token, &project, &server, &env).map_err(|e| format!("✗ Fetch failed: {e}"))?;
            if a.val("access-token").is_some() {
                save_env_value(paths, &te, &token)?;
            }
            c.insert("enabled".into(), true.into());
            c.insert("project_id".into(), project.into());
            c.insert("server_url".into(), server.into());
            c.insert("access_token_env".into(), te.clone().into());
            for (k, v) in [("cache_ttl_seconds", 300.into()), ("override_existing", true.into())] {
                c.entry(k).or_insert(v);
            }
            let mut t = load_config(paths);
            t.insert("bitwarden".into(), toml::Value::Table(c));
            save_config(paths, &t)?;
            clear_caches(&paths.data);
            let mut o = format!("✓ Bitwarden Secrets Manager is enabled ({} secrets visible).\n", secrets.len());
            for k in secrets.keys() {
                o += &format!("  {k}{}\n", if *k == te { "  (bootstrap token — never overrides itself)" } else if env.contains_key(k) { "  (already set in env — will be overwritten)" } else { "" });
            }
            for w in warns {
                o += &format!("warning: {w}\n");
            }
            Ok(o + "Status: seagent secrets bitwarden status · Refresh: seagent secrets bitwarden sync · Disable: seagent secrets bitwarden disable")
        }
        Source::OnePassword => {
            if let Some(acct) = a.val("op-account") {
                c.insert("account".into(), acct.into());
            }
            let te = a.val("token-env").map(String::from).unwrap_or_else(|| s(&c, "service_account_token_env", "OP_SERVICE_ACCOUNT_TOKEN"));
            if a.val("token-env").is_some() {
                c.insert("service_account_token_env".into(), te.clone().into());
            }
            if let Some(t) = a.val("access-token") {
                save_env_value(paths, &te, t.trim())?;
                env.insert(te.clone(), t.trim().to_string());
            }
            let op = find_op(&c, &env).ok_or("the op CLI was not found on PATH. Install it (https://developer.1password.com/docs/cli/get-started/) or set onepassword.binary_path.")?;
            c.insert("enabled".into(), true.into());
            c.entry("env").or_insert(toml::Value::Table(toml::Table::new()));
            c.entry("cache_ttl_seconds").or_insert(300.into());
            let mut t = load_config(paths);
            t.insert("onepassword".into(), toml::Value::Table(c));
            save_config(paths, &t)?;
            clear_caches(&paths.data);
            Ok(format!("✓ 1Password enabled (op at {}). Bind variables with `seagent secrets onepassword set NAME op://vault/item/field`.", op.display()))
        }
        Source::Vault | Source::Aws | Source::Gcp | Source::Azure => {
            // Non-interactive: `--set key=value` style keys come from flags we already parse,
            // the rest from `seagent config`-like edits of secret_sources.toml; setup only enables.
            for (flag, key) in [("server-url", if src == Source::Vault { "addr" } else { "" }), ("token-env", "token_env")] {
                if let (Some(v), false) = (a.val(flag), key.is_empty()) {
                    c.insert(key.into(), v.into());
                }
            }
            c.insert("enabled".into(), true.into());
            c.entry("env").or_insert(toml::Value::Table(toml::Table::new()));
            c.entry("cache_ttl_seconds").or_insert(300.into());
            let mut t = load_config(paths);
            t.insert(src.name().into(), toml::Value::Table(c));
            save_config(paths, &t)?;
            clear_caches(&paths.data);
            Ok(format!("✓ {} enabled. Bind variables with `seagent secrets {} set NAME <reference>` (see docs/enterprise-network-secrets.md), then `seagent secrets {} sync`.", src.label(), src.name(), src.name()))
        }
        Source::Command => {
            let cmd = a.val("helper").map(String::from).unwrap_or_else(|| s(&c, "command", ""));
            if cmd.trim().is_empty() {
                return Err("usage: seagent secrets command setup --helper '<shell command printing KEY=VALUE lines>'".into());
            }
            c.insert("command".into(), cmd.clone().into());
            let out = run_helper(&cmd, "", f(&c, "helper_timeout_seconds", COMMAND_TIMEOUT), &env)?;
            let n = parse_kv(&out).len();
            c.insert("enabled".into(), true.into());
            let mut t = load_config(paths);
            t.insert("command".into(), toml::Value::Table(c));
            save_config(paths, &t)?;
            Ok(format!("✓ command helper enabled ({n} variables printed)"))
        }
    }
}

/// Which source `seagent secrets …` names, if this module owns the invocation at all.
/// `Some(None)` = the `sources` overview; `None` = not ours (falls through to the vault).
pub fn claims(cmd: &str, a: &Args) -> Option<Option<Source>> {
    if !matches!(cmd, "secrets" | "secret") {
        return None;
    }
    match a.pos(0) {
        Some("sources") => Some(None),
        Some(p) => Source::parse(p).map(Some),
        None => None,
    }
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    claims(cmd, a)?;
    let paths = Paths::from_env();
    Some(match run(&paths, a) {
        Ok(t) => {
            println!("{t}");
            Ok(0)
        }
        Err(e) => Err(e.into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn root() -> PathBuf {
        let d = seagent_core::tmp::scratch_path(format!("seagent-secsrc-{}", seagent_kernel::util::random_hex(6)));
        std::fs::create_dir_all(d.join("bin")).unwrap();
        d
    }

    #[cfg(unix)]
    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join("bin").join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn env_with(dir: &Path, extra: &[(&str, &str)]) -> HashMap<String, String> {
        let mut e: HashMap<String, String> = [("PATH".to_string(), format!("{}:/usr/bin:/bin", dir.join("bin").display()))].into();
        e.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        e
    }

    fn table(s: &str) -> toml::Table {
        s.parse().unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn bitwarden_fetch_cache_and_stale_fallback() {
        let d = root();
        // fake bws: checks argv + token, prints a project's secrets; FAIL file → network error
        script(&d, "bws", &format!(r#"if [ -f {0}/FAIL ]; then echo "Error: 0: connection refused" >&2; exit 1; fi
[ "$BWS_ACCESS_TOKEN" = "0.tok" ] || {{ echo "Error:\n 0: [400 Bad Request] {{\"error\":\"invalid_client\"}}\nLocation: x" >&2; exit 1; }}
[ "$1 $2 $3 $4 $5" = "secret list p1 --output json" ] || exit 3
echo "$BWS_SERVER_URL" > {0}/server
echo '[{{"key":"OPENAI_API_KEY","value":"sk-1"}},{{"key":"bad-name","value":"x"}},{{"key":"BWS_ACCESS_TOKEN","value":"evil"}}]'"#, d.display()));
        let c = table("enabled = true\nproject_id = \"p1\"\nserver_url = \"https://vault.bitwarden.eu\"\n");
        let env = env_with(&d, &[("BWS_ACCESS_TOKEN", "0.tok")]);
        let r = fetch_bitwarden(&c, &env, &d.join("data"), true);
        assert!(r.error.is_none(), "{:?}", r.error);
        assert_eq!(r.secrets.get("OPENAI_API_KEY").map(|s| s.as_str()), Some("sk-1"));
        assert!(r.warnings.iter().any(|w| w.contains("bad-name")));
        assert_eq!(std::fs::read_to_string(d.join("server")).unwrap().trim(), "https://vault.bitwarden.eu");
        // disk cache is values-only and private
        let cf = d.join("data/cache/bws_cache.json");
        let body = std::fs::read_to_string(&cf).unwrap();
        assert!(body.contains("sk-1") && !body.contains("0.tok"));
        assert_eq!(std::fs::metadata(&cf).unwrap().permissions().mode() & 0o777, 0o600);
        // network failure → stale disk cache
        MEM.lock().unwrap().clear();
        std::fs::write(d.join("FAIL"), "").unwrap();
        let r = fetch_bitwarden(&table("enabled = true\nproject_id = \"p1\"\nserver_url = \"https://vault.bitwarden.eu\"\ncache_ttl_seconds = 0.000001\n"), &env, &d.join("data"), true);
        assert!(r.error.is_none(), "{:?}", r.error);
        assert!(r.warnings[0].contains("stale disk cache"));
        // auth failure never falls back
        std::fs::remove_file(d.join("FAIL")).unwrap();
        let bad = env_with(&d, &[("BWS_ACCESS_TOKEN", "0.wrong")]);
        let r = fetch_bitwarden(&c, &bad, &d.join("data"), false);
        let (e, k) = r.error.unwrap();
        assert_eq!(k, ErrorKind::AuthFailed, "{e}");
        assert!(e.contains("invalid_client") && !e.contains("Location"));
        // not configured
        let r = fetch_bitwarden(&c, &env_with(&d, &[]), &d.join("data"), false);
        assert_eq!(r.error.unwrap().1, ErrorKind::NotConfigured);
    }

    #[test]
    fn bitwarden_encrypted_cache_roundtrip() {
        let d = root();
        let mut v = BTreeMap::new();
        v.insert("A_KEY".to_string(), "secret-value".to_string());
        enc_write(&d, "k1", "0.tok", &v);
        let raw = std::fs::read_to_string(d.join("cache/bws_cache.enc.json")).unwrap();
        assert!(!raw.contains("secret-value") && !raw.contains("0.tok"));
        assert_eq!(enc_read(&d, "k1", "0.tok", 60.0).unwrap().0, v);
        assert!(enc_read(&d, "k1", "0.other", 60.0).is_none());
        assert!(enc_read(&d, "k2", "0.tok", 60.0).is_none());
        assert!(enc_read(&d, "k1", "0.tok", 0.0).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn onepassword_reads_refs_with_terminator() {
        let d = root();
        script(&d, "op", &format!(r#"echo "$@" >> {0}/argv
[ "$OP_SERVICE_ACCOUNT_TOKEN" = "ops_x" ] || {{ echo "[ERROR] You are not signed in" >&2; exit 1; }}
for a in "$@"; do ref="$a"; done
case "$ref" in op://v/openai/key) echo sk-op;; op://v/empty/x) echo "";; *) echo "[ERROR] item not found" >&2; exit 1;; esac"#, d.display()));
        let c = table("enabled = true\naccount = \"me\"\n[env]\nOPENAI_API_KEY = \"op://v/openai/key\"\nEMPTY_TOKEN = \"op://v/empty/x\"\nNOT_REF = \"plain\"\n\"bad-name\" = \"op://v/a/b\"\n");
        let env = env_with(&d, &[("OP_SERVICE_ACCOUNT_TOKEN", "ops_x"), ("UNRELATED_SECRET", "leak")]);
        let r = fetch_onepassword(&c, &env, &d.join("data"), true);
        assert!(r.error.is_none(), "{:?}", r.error);
        assert_eq!(r.secrets.len(), 1);
        assert_eq!(r.secrets["OPENAI_API_KEY"], "sk-op");
        assert!(r.warnings.iter().any(|w| w.contains("empty value")));
        assert!(r.warnings.iter().any(|w| w.contains("not an op:// secret reference")));
        assert!(r.warnings.iter().any(|w| w.contains("not a valid env-var name")));
        assert!(std::fs::read_to_string(d.join("argv")).unwrap().contains("read --account me -- op://v/openai/key"));
        // partial pull is not cached
        assert!(!d.join("data/cache/op_cache.json").exists());
        // not signed in → auth_failed when nothing resolves
        let r = fetch_onepassword(&c, &env_with(&d, &[]), &d.join("data"), false);
        assert_eq!(r.error.unwrap().1, ErrorKind::AuthFailed);
        // pinned missing binary never falls back to PATH
        let r = fetch_onepassword(&table("enabled = true\nbinary_path = \"/nonexistent/op\"\n[env]\nA_KEY = \"op://v/openai/key\"\n"), &env, &d.join("data"), false);
        assert_eq!(r.error.unwrap().1, ErrorKind::BinaryMissing);
    }

    #[test]
    fn command_helper_limits() {
        let d = root();
        let env = env_with(&d, &[]);
        let r = fetch_command(&table("command = \"printf 'A_KEY=\\\"q v\\\"\\n# c\\nB=2\\nnot a line\\n'; echo oops >&2\""), &env);
        assert!(r.error.is_none());
        assert_eq!(r.secrets.get("A_KEY").map(|s| s.as_str()), Some("q v"));
        assert_eq!(r.secrets.len(), 2);
        // key only as data
        assert_eq!(run_helper("printf %s \"$SEAGENT_SECRET_KEY\"", "$(id)", 3.0, &env).unwrap(), "$(id)");
        assert!(run_helper("sleep 5", "", 0.2, &env).unwrap_err().contains("timed out"));
        assert!(run_helper("exit 7", "", 3.0, &env).unwrap_err().contains("code=7"));
        assert!(run_helper("head -c 1100000 /dev/zero", "", 3.0, &env).unwrap_err().contains("cap"));
        assert_eq!(fetch_command(&table(""), &env).error.unwrap().1, ErrorKind::NotConfigured);
    }

    #[cfg(unix)]
    #[test]
    fn apply_all_precedence() {
        let d = root();
        script(&d, "bws", "echo '[{\"key\":\"SHARED_KEY\",\"value\":\"from-bw\"},{\"key\":\"BW_ONLY\",\"value\":\"b\"},{\"key\":\"SHELL_KEY\",\"value\":\"bw-shell\"},{\"key\":\"KEEP_ME\",\"value\":\"x\"},{\"key\":\"OP_SERVICE_ACCOUNT_TOKEN\",\"value\":\"evil\"}]'");
        script(&d, "op", "echo from-op");
        let t = table("sources = [\"command\", \"bitwarden\", \"nope\"]\npreserve_existing = [\"KEEP_ME\"]\n[bitwarden]\nenabled = true\nproject_id = \"p\"\ncache_ttl_seconds = 0\n[onepassword]\nenabled = true\ncache_ttl_seconds = 0\n[onepassword.env]\nSHARED_KEY = \"op://v/i/f\"\n[command]\nenabled = true\ncommand = \"echo BW_ONLY=cmd; echo CMD_ONLY=c\"\n");
        let (order, warn) = ordered_enabled(&t);
        assert_eq!(order, vec![Source::OnePassword, Source::Command, Source::Bitwarden]);
        assert!(warn[0].contains("nope"));
        let mut env = env_with(&d, &[("BWS_ACCESS_TOKEN", "0.t"), ("OP_SERVICE_ACCOUNT_TOKEN", "real"), ("SHELL_KEY", "shell"), ("KEEP_ME", "mine")]);
        let rep = apply_all(&t, &mut env, &d.join("data"), true);
        assert_eq!(env["SHARED_KEY"], "from-op"); // mapped beats bulk
        assert_eq!(env["BW_ONLY"], "cmd"); // first bulk (configured order) wins
        assert_eq!(env["CMD_ONLY"], "c");
        assert_eq!(env["SHELL_KEY"], "bw-shell"); // bitwarden override_existing defaults true
        assert_eq!(env["KEEP_ME"], "mine"); // preserve_existing
        assert_eq!(env["OP_SERVICE_ACCOUNT_TOKEN"], "real"); // protected bootstrap token
        assert_eq!(rep.provenance["SHARED_KEY"], "onepassword");
        assert!(rep.conflicts.iter().any(|c| c.starts_with("BW_ONLY: kept value from command")));
        let bw = rep.sources.iter().find(|s| s.name == "bitwarden").unwrap();
        assert!(bw.skipped_protected.contains(&"OP_SERVICE_ACCOUNT_TOKEN".to_string()));
        assert!(bw.skipped_existing.contains(&"KEEP_ME".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn cli_setup_set_status_disable() {
        let d = root();
        script(&d, "op", "echo v");
        let paths = Paths { data: d.join("data"), config_dir: d.join("config"), runtime: d.join("run"), ..Default::default() };
        let p = |v: &[&str]| Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        let mut t = toml::Table::new();
        let mut c = toml::Table::new();
        c.insert("binary_path".into(), d.join("bin/op").display().to_string().into());
        t.insert("onepassword".into(), toml::Value::Table(c));
        save_config(&paths, &t).unwrap();
        assert!(run(&paths, &p(&["op", "setup", "--op-account", "me"])).unwrap().contains("1Password enabled"));
        assert!(run(&paths, &p(&["onepassword", "set", "X_KEY", "plain"])).is_err());
        assert!(run(&paths, &p(&["onepassword", "set", "X_KEY", "op://v/x/y"])).is_ok());
        let st = run(&paths, &p(&["1password", "status"])).unwrap();
        assert!(st.contains("X_KEY → op://v/x/y") && st.contains("enabled            yes"));
        assert!(run(&paths, &p(&["op", "sync"])).unwrap().contains("X_KEY"));
        assert!(run(&paths, &p(&["op", "remove", "X_KEY"])).is_ok());
        run(&paths, &p(&["op", "disable"])).unwrap();
        assert!(run(&paths, &p(&["op", "status"])).unwrap().contains("enabled            no"));
        let e = save_env_value(&paths, "SEAGENT_T_SECSRC_TOKEN", "abc").unwrap();
        save_env_value(&paths, "SEAGENT_T_SECSRC_TOKEN", "def").unwrap();
        assert_eq!(std::fs::read_to_string(e).unwrap().matches("SEAGENT_T_SECSRC_TOKEN").count(), 1);
        assert_eq!(classify("Error: dns lookup failed", BWS_RULES), ErrorKind::Network);
    }

    #[cfg(unix)]
    #[test]
    fn bitwarden_setup_honors_token_env_and_server_env() {
        let d = root();
        // `--token-env` names the bootstrap var, `BWS_SERVER_URL` substitutes for --server-url
        script(&d, "bws", &format!(r#"echo "$BWS_SERVER_URL" > {0}/server
echo "$BWS_ACCESS_TOKEN" > {0}/token
[ "$BWS_ACCESS_TOKEN" = "0.tok" ] || {{ echo "unauthorized" >&2; exit 1; }}
[ "$1 $2 $3 $4 $5" = "secret list p1 --output json" ] || exit 3
echo '[{{"key":"K","value":"v"}}]'"#, d.display()));
        let paths = Paths { data: d.join("data"), config_dir: d.join("config"), runtime: d.join("run"), ..Default::default() };
        let p = |v: &[&str]| Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        let env = env_with(&d, &[("BWS_T", "0.tok"), ("BWS_SERVER_URL", "https://vault.bitwarden.eu")]);
        let o = setup(&paths, Source::Bitwarden, &p(&["bitwarden", "setup", "--token-env", "BWS_T", "--project-id", "p1"]), &env).unwrap();
        assert!(o.contains("Bitwarden Secrets Manager is enabled (1 secrets visible)"), "{o}");
        let c = section(&load_config(&paths), "bitwarden");
        assert_eq!(s(&c, "access_token_env", ""), "BWS_T");
        assert_eq!(s(&c, "server_url", ""), "https://vault.bitwarden.eu");
        assert_eq!(s(&c, "project_id", ""), "p1");
        assert!(b(&c, "enabled", false));
        // the token came from BWS_T and travels to bws as BWS_ACCESS_TOKEN, never on argv
        assert_eq!(std::fs::read_to_string(d.join("token")).unwrap().trim(), "0.tok");
        assert_eq!(std::fs::read_to_string(d.join("server")).unwrap().trim(), "https://vault.bitwarden.eu");
        let st = run(&paths, &p(&["bw", "status"])).unwrap();
        assert!(st.contains("enabled            yes") && st.contains("BWS_T") && st.contains("p1"), "{st}");
        // an explicit flag still wins over the environment
        let env2 = env_with(&d, &[("BWS_T", "0.tok")]);
        setup(&paths, Source::Bitwarden, &p(&["bitwarden", "setup", "--token-env", "BWS_T", "--project-id", "p1", "--server-url", "https://vault.bitwarden.com"]), &env2).unwrap();
        assert_eq!(s(&section(&load_config(&paths), "bitwarden"), "server_url", ""), "https://vault.bitwarden.com");
    }

    #[cfg(unix)]
    #[test]
    fn onepassword_token_is_verified_with_whoami() {
        let d = root();
        script(&d, "op", &format!(r#"echo "$@" >> {0}/argv
if [ "$1" = whoami ]; then
  [ "$OP_SERVICE_ACCOUNT_TOKEN" = "ops_good" ] || {{ echo "[ERROR] 401: not signed in" >&2; exit 1; }}
  echo '{{"url":"my-team"}}'; exit 0
fi
exit 4"#, d.display()));
        let paths = Paths { data: d.join("data"), config_dir: d.join("config"), runtime: d.join("run"), ..Default::default() };
        let p = |v: &[&str]| Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        let mut c = toml::Table::new();
        c.insert("binary_path".into(), d.join("bin/op").display().to_string().into());
        let mut t = toml::Table::new();
        t.insert("onepassword".into(), toml::Value::Table(c));
        save_config(&paths, &t).unwrap();
        // a bad token is never stored
        let e = run(&paths, &p(&["op", "token", "--access-token", "ops_bad", "--token-env", "MY_OP_T"])).unwrap_err();
        assert!(e.contains("rejected") && e.contains("401"), "{e}");
        assert!(!paths.config_dir.join(".env").exists() || !std::fs::read_to_string(paths.config_dir.join(".env")).unwrap().contains("ops_bad"));
        // a good one is verified, then written to the configured var
        let o = run(&paths, &p(&["op", "token", "--access-token", "ops_good", "--token-env", "MY_OP_T"])).unwrap();
        assert!(o.contains("stored MY_OP_T"), "{o}");
        assert_eq!(s(&section(&load_config(&paths), "onepassword"), "service_account_token_env", ""), "MY_OP_T");
        assert!(std::fs::read_to_string(paths.config_dir.join(".env")).unwrap().contains("MY_OP_T=ops_good"));
        assert!(std::fs::read_to_string(d.join("argv")).unwrap().contains("whoami"));
        // --no-verify stores without calling op at all
        let before = std::fs::read_to_string(d.join("argv")).unwrap().lines().count();
        run(&paths, &p(&["op", "token", "--access-token", "ops_unverified", "--no-verify"])).unwrap();
        assert_eq!(std::fs::read_to_string(d.join("argv")).unwrap().lines().count(), before);
        assert!(std::fs::read_to_string(paths.config_dir.join(".env")).unwrap().contains("ops_unverified"));
    }

    #[test]
    fn cli_command_source_and_sources_listing() {
        let d = root();
        let paths = Paths { data: d.join("data"), config_dir: d.join("config"), runtime: d.join("run"), ..Default::default() };
        let p = |v: &[&str]| Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        assert!(run(&paths, &p(&["command", "setup"])).unwrap_err().contains("--helper"));
        let o = run(&paths, &p(&["cmd", "setup", "--helper", "echo CMD_TOK=1; echo SECOND=2"])).unwrap();
        assert!(o.contains("command helper enabled (2 variables printed)"), "{o}");
        assert!(run(&paths, &p(&["command", "status"])).unwrap().contains("enabled            yes"));
        let src = run(&paths, &p(&["sources"])).unwrap();
        assert!(src.contains("Command helper (command):"), "{src}");
        assert!(src.contains("CMD_TOK") && src.contains("← command"), "{src}");
        // nothing configured → says so instead of printing an empty report
        let fresh = Paths { data: d.join("data2"), config_dir: d.join("config2"), runtime: d.join("run2"), ..Default::default() };
        assert!(run(&fresh, &p(&["sources"])).unwrap().contains("no external secret source enabled"));
    }

    #[test]
    fn dispatch_claims_every_source_and_alias() {
        let p = |v: &[&str]| Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        // Args arrive without the command itself (as main.rs does), so pos(0) is the source
        for cmd in ["secrets", "secret"] {
            for s in ["bitwarden", "bw", "bws", "onepassword", "op", "1password", "command", "cmd"] {
                assert_eq!(claims(cmd, &p(&[s, "status"])), Some(Source::parse(s)), "{cmd} {s}");
            }
            assert_eq!(claims(cmd, &p(&["sources"])), Some(None), "{cmd} sources");
        }
        // the vault (`seagent secrets list|set|rm`) and other commands fall through to main.rs
        assert_eq!(claims("secrets", &p(&["list"])), None);
        assert_eq!(claims("secrets", &p(&["secrets"])), None);
        assert_eq!(claims("batch", &p(&["batch", "run", "x.jsonl"])), None);
        assert!(COMMANDS.is_empty(), "secrets owns subcommands, not a top-level command");
    }

    #[test]
    fn cache_is_scoped_per_profile_data_dir() {
        let d = root();
        let v: BTreeMap<String, String> = [("K".to_string(), "v".to_string())].into();
        cache_store(&d.join("a"), "op_cache.json", "k1", &v, 300.0);
        assert_eq!(cache_lookup(&d.join("a"), "op_cache.json", "k1", 300.0), Some(v.clone()));
        // a second profile (different data dir) must not see profile a's in-memory values
        assert!(cache_lookup(&d.join("b"), "op_cache.json", "k1", 300.0).is_none());
        assert!(cache_lookup(&d.join("a"), "bws_cache.json", "k1", 300.0).is_none());
    }
}
