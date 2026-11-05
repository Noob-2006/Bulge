//! Local egress proxy: the runtime enforcement layer behind the static egress gate
//! (Hermes `hermes_cli/proxy` + iron-proxy, OpenClaw `src/secrets/egress-proxy`).
//!
//! A forward proxy on `127.0.0.1:<port>` that every child ark spawns is pointed at
//! (`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`, see [`crate::envscrub::apply`]). It serves
//! absolute-URI HTTP requests and `CONNECT` tunnels and, per connection:
//!
//! 1. refuses hosts on `deny` / `gate.egress_deny` and the website blocklist;
//! 2. in `mode = "allowlist"` refuses every host not on `allow` / `gate.egress_allow`;
//! 3. resolves the host itself and refuses private / loopback / CGNAT targets (the SSRF
//!    floor; a host named explicitly in `allow` may be private) and cloud metadata
//!    (always), then dials exactly the vetted address (no DNS-rebinding window);
//! 4. for plain-HTTP requests only, sets the configured `inject` headers (credential
//!    injection: the child never sees the secret). `CONNECT` is filtered, never
//!    intercepted (no MITM, no CA), so HTTPS bodies cannot be injected or inspected.
//!
//! Every connection is logged (JSON lines + an in-memory ring for `recent()`).
//!
//! Limits: only clients that honour proxy env vars are covered. Raw sockets, programs
//! that ignore `*_PROXY`, `NO_PROXY` set by the code itself, DNS exfiltration and UDP
//! all bypass it — closing those needs the OS sandbox (network namespace / seccomp).
//! `NO_PROXY` is deliberately removed from children: exempting `localhost` would hand
//! interpreter code an unfiltered path to local services (SSRF); add local dev hosts
//! to `allow` instead. Lowercase `http_proxy`/`https_proxy`/`all_proxy` inherited from
//! the operator environment are removed too: curl and wget prefer them over the
//! uppercase names, so a stale value would silently bypass the proxy. One request per
//! connection (`Connection: close` upstream).
//!
//! Wiring: `[security.egress_proxy]` (`enabled` / `listen` / `mode` / `allow` / `deny` /
//! `inject`) is a field of `SecurityConfig`; [`crate::SecurityConfig::activate`] starts
//! the proxy when it is enabled (via [`crate::SecurityConfig::activate_egress`], which
//! appends the JSONL log to `<data>/egress/proxy.jsonl`) and
//! [`crate::envscrub::set_proxy`] then points every child that goes through
//! [`crate::envscrub::apply`] at it. `inject` values are expanded through `Secrets`;
//! [`env_secrets`] (the `activate` default) reads `{{secret:NAME}}` from the environment,
//! a vault-backed closure can be passed to `activate_egress` instead.
//! [`running_url`] / [`running_port`] expose the bound address for callers that need it
//! (e.g. `[exec.docker] proxy_port`).

use crate::url_safety::{self, UrlPolicy, WebsiteBlocklist};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

const MAX_HEAD: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const LOG_RING: usize = 256;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyMode {
    /// Everything not denied passes (deny lists, blocklist and SSRF floor still apply).
    #[default]
    Filter,
    /// Only `allow` + `gate.egress_allow` hosts pass.
    Allowlist,
}

/// One header the proxy sets on plain-HTTP requests to `host` (and its subdomains).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Inject {
    pub host: String,
    pub header: String,
    /// May reference vault secrets: `Bearer {{secret:SERVICE_TOKEN}}`.
    pub value: String,
}

/// `[security.egress_proxy]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EgressProxyConfig {
    /// Start the proxy and route every child through it. Default false.
    pub enabled: bool,
    /// Listen address; port 0 picks a free port. Default "127.0.0.1:0" (loopback only).
    pub listen: String,
    /// "filter" (default) or "allowlist".
    pub mode: ProxyMode,
    /// Hosts / `*.domain` always allowed (also: may resolve to private addresses).
    pub allow: Vec<String>,
    /// Hosts / `*.domain` always refused.
    pub deny: Vec<String>,
    /// Plain-HTTP credential injection rules. Default none.
    pub inject: Vec<Inject>,
    /// Pre-authorise the built-in development hosts (§0-3 A3): package mirrors, source
    /// hosts and documentation. New hosts still need the gate / a task envelope.
    pub dev_hosts: bool,
}

impl Default for EgressProxyConfig {
    fn default() -> Self {
        EgressProxyConfig { enabled: false, listen: "127.0.0.1:0".into(), mode: ProxyMode::Filter, allow: vec![], deny: vec![], inject: vec![], dev_hosts: true }
    }
}

pub type Resolver = Arc<dyn Fn(&str, u16) -> Result<Vec<IpAddr>, String> + Send + Sync>;

/// Capability gate (A5): `(host, port) → allowed`. Installed by the daemon when the exec plan
/// runs tools in a VM (`ark_security::capability::builtins()` declares the reachable set plus
/// `[security.egress_proxy]`/`gate.egress_allow`); `None` means only the host policy applies,
/// which is what every unit test and a host-only ark instance want.
pub type CapGate = Arc<dyn Fn(&str, u16) -> Result<(), String> + Send + Sync>;

fn gate() -> &'static Mutex<Option<CapGate>> {
    static G: std::sync::OnceLock<Mutex<Option<CapGate>>> = std::sync::OnceLock::new();
    G.get_or_init(Default::default)
}

/// Install (or clear) the capability gate. One daemon, one gate.
pub fn set_capability_gate(g: Option<CapGate>) {
    *gate().lock().unwrap_or_else(|p| p.into_inner()) = g;
}

/// The installed gate, or "no gate" when none is set.
pub fn capability_gate() -> CapGate {
    gate().lock().unwrap_or_else(|p| p.into_inner()).clone().unwrap_or_else(|| Arc::new(|_: &str, _: u16| Ok(())))
}
pub type Secrets = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// The effective runtime policy.
#[derive(Clone, Default)]
pub struct Policy {
    pub mode: ProxyMode,
    /// `allow` (may be private) — kept apart from `gate_allow` (public only).
    pub allow: Vec<String>,
    pub gate_allow: Vec<String>,
    /// `deny` + `gate.egress_deny`.
    pub deny: Vec<String>,
    pub url: UrlPolicy,
    pub blocklist: WebsiteBlocklist,
    pub config_dir: PathBuf,
    pub inject: Vec<Inject>,
    /// Hosts an active task envelope named (§0-2 #01). They pass the *name* check like an
    /// allowlisted host, but they are deliberately not part of [`Policy::allow`]: that list
    /// also switches `allow_private_urls` on, and an envelope must never open the host's
    /// private network (an envelope is a scope, not an SSRF exception).
    pub envelope_hosts: Vec<String>,
}

impl Policy {
    pub fn from_config(c: &EgressProxyConfig, url: UrlPolicy, blocklist: WebsiteBlocklist, config_dir: &Path, gate_allow: &[String], gate_deny: &[String]) -> Policy {
        let mut deny = c.deny.clone();
        deny.extend(gate_deny.iter().cloned());
        let mut allow = c.allow.clone();
        if c.dev_hosts {
            allow.extend(crate::risk::dev_hosts());
        }
        Policy { mode: c.mode, allow, gate_allow: gate_allow.to_vec(), deny, url, blocklist, config_dir: config_dir.to_path_buf(), inject: c.inject.clone(), envelope_hosts: vec![] }
    }

    /// Name-only verdict (no DNS): deny list, website blocklist, allowlist mode.
    pub fn check_host(&self, host: &str) -> Result<(), String> {
        let host = norm(host);
        if let Some(r) = self.deny.iter().find(|r| host_rule(&host, r)) {
            return Err(format!("host {host} is on the egress deny list ({r})"));
        }
        if let Some(m) = url_safety::check_website_access(&host, &self.blocklist, &self.config_dir) {
            return Err(m);
        }
        if self.mode == ProxyMode::Allowlist && !self.allow.iter().chain(&self.gate_allow).chain(&self.envelope_hosts).any(|r| host_rule(&host, r)) {
            return Err(format!("host {host} is not on the egress allowlist (security.egress_proxy.allow / gate.egress_allow)"));
        }
        Ok(())
    }

    /// Full verdict: name checks, then every resolved address. Returns what to dial.
    pub fn vet(&self, host: &str, port: u16, resolve: &Resolver) -> Result<Vec<SocketAddr>, String> {
        self.check_host(host)?;
        let host = norm(host);
        if host.is_empty() {
            return Err("empty host".into());
        }
        let ips = match host.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => match resolve(&host, port) {
                Ok(v) if !v.is_empty() => v,
                _ => return Err(format!("DNS resolution failed for {host}")),
            },
        };
        let explicit = self.allow.iter().any(|r| host_rule(&host, r));
        let policy = if explicit { UrlPolicy { allow_private_urls: true, ..self.url.clone() } } else { self.url.clone() };
        for ip in &ips {
            if let Some(r) = url_safety::block_reason(*ip, &host, if port == 443 { "https" } else { "http" }, &policy) {
                return Err(format!("{host} resolves to a {r} ({ip})"));
            }
        }
        Ok(ips.into_iter().take(8).map(|ip| SocketAddr::new(ip, port)).collect())
    }
}

fn norm(h: &str) -> String {
    h.trim().trim_start_matches('[').trim_end_matches(']').trim_end_matches('.').to_ascii_lowercase()
}

/// `example.com` matches itself and subdomains; `*.example.com` subdomains only.
pub fn host_rule(host: &str, rule: &str) -> bool {
    let r = norm(rule);
    if r.is_empty() {
        return false;
    }
    match r.strip_prefix("*.") {
        Some(base) => host.ends_with(&format!(".{base}")),
        None => host == r || host.ends_with(&format!(".{r}")),
    }
}

/// One logged connection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogEntry {
    pub ts: String,
    pub method: String,
    pub host: String,
    pub port: u16,
    pub allowed: bool,
    pub reason: String,
}

#[derive(Default)]
struct Log {
    ring: Mutex<VecDeque<LogEntry>>,
    file: Option<PathBuf>,
}

impl Log {
    fn push(&self, e: LogEntry) {
        if let Some(p) = &self.file {
            if let Some(d) = p.parent() {
                let _ = std::fs::create_dir_all(d);
            }
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
                let _ = writeln!(f, "{}", serde_json::to_string(&e).unwrap_or_default());
            }
        }
        let mut r = self.ring.lock().unwrap_or_else(|p| p.into_inner());
        if r.len() >= LOG_RING {
            r.pop_front();
        }
        r.push_back(e);
    }
}

/// A running proxy. Dropping the handle does not stop it; call [`Proxy::stop`].
pub struct Proxy {
    addr: SocketAddr,
    policy: Arc<RwLock<Policy>>,
    log: Arc<Log>,
    stop: Arc<AtomicBool>,
}

struct Shared {
    policy: Arc<RwLock<Policy>>,
    log: Arc<Log>,
    resolve: Resolver,
    secrets: Secrets,
}

impl Proxy {
    pub fn start(listen: &str, policy: Policy, resolve: Resolver, secrets: Secrets, log_file: Option<PathBuf>) -> Result<Proxy, String> {
        let l = TcpListener::bind(listen).map_err(|e| format!("egress proxy cannot listen on {listen}: {e}"))?;
        let addr = l.local_addr().map_err(|e| e.to_string())?;
        if !addr.ip().is_loopback() {
            eprintln!("ark: warning: egress proxy listens on non-loopback {addr}");
        }
        let policy = Arc::new(RwLock::new(policy));
        let log = Arc::new(Log { ring: Mutex::new(VecDeque::new()), file: log_file });
        let stop = Arc::new(AtomicBool::new(false));
        let sh = Arc::new(Shared { policy: policy.clone(), log: log.clone(), resolve, secrets });
        let st = stop.clone();
        std::thread::Builder::new()
            .name("ark-egress-proxy".into())
            .spawn(move || {
                for c in l.incoming() {
                    if st.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(c) = c else { continue };
                    let sh = sh.clone();
                    let _ = std::thread::Builder::new().name("ark-egress-conn".into()).spawn(move || handle(c, &sh));
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(Proxy { addr, policy, log, stop })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `http://127.0.0.1:<port>` for `*_PROXY`.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn set_policy(&self, p: Policy) {
        *self.policy.write().unwrap_or_else(|e| e.into_inner()) = p;
    }

    pub fn recent(&self) -> Vec<LogEntry> {
        self.log.ring.lock().unwrap_or_else(|p| p.into_inner()).iter().cloned().collect()
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(200));
    }
}

fn respond(s: &mut TcpStream, status: &str, body: &str) {
    let _ = write!(s, "HTTP/1.1 {status}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nx-ark-egress: {}\r\nconnection: close\r\n\r\n{body}", body.len(), if status.starts_with("403") { "blocked" } else { "error" });
    let _ = s.flush();
}

/// Read the request head (through the blank line); returns head text and any body bytes read past it.
fn read_head(r: &mut BufReader<TcpStream>) -> Option<(String, Vec<u8>)> {
    let mut head = String::new();
    loop {
        let mut line = String::new();
        let n = r.read_line(&mut line).ok()?;
        if n == 0 {
            return None;
        }
        head.push_str(&line);
        if head.len() > MAX_HEAD {
            return None;
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
    }
    let extra = r.buffer().to_vec();
    r.consume(extra.len());
    Some((head, extra))
}

fn split_hostport(hp: &str, default: u16) -> Option<(String, u16)> {
    if let Some(rest) = hp.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => default,
        };
        return Some((h.to_string(), port));
    }
    match hp.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Some((h.to_string(), p.parse().ok()?)),
        _ => Some((hp.to_string(), default)),
    }
}

fn dial(addrs: &[SocketAddr]) -> Result<TcpStream, String> {
    let mut last = String::from("no address");
    for a in addrs {
        match TcpStream::connect_timeout(a, CONNECT_TIMEOUT) {
            Ok(s) => return Ok(s),
            Err(e) => last = format!("{a}: {e}"),
        }
    }
    Err(last)
}

fn pump(mut from: TcpStream, mut to: TcpStream) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

fn splice(client: TcpStream, upstream: TcpStream) {
    let _ = client.set_read_timeout(Some(IDLE_TIMEOUT));
    let _ = upstream.set_read_timeout(Some(IDLE_TIMEOUT));
    let (Ok(c2), Ok(u2)) = (client.try_clone(), upstream.try_clone()) else { return };
    let t = std::thread::spawn(move || pump(c2, u2));
    pump(upstream, client);
    let _ = t.join();
}

fn handle(client: TcpStream, sh: &Shared) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
    let Ok(rc) = client.try_clone() else { return };
    let mut r = BufReader::new(rc);
    let mut client = client;
    let Some((head, extra)) = read_head(&mut r) else { return };
    let mut lines = head.split("\r\n").flat_map(|l| l.split('\n'));
    let first = lines.next().unwrap_or("").to_string();
    let mut parts = first.split_whitespace();
    let (method, target, version) = (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("HTTP/1.1").to_string());
    let headers: Vec<(String, String)> = lines.filter(|l| !l.is_empty()).filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect();

    let (host, port, path, connect) = if method.eq_ignore_ascii_case("CONNECT") {
        match split_hostport(&target, 443) {
            Some((h, p)) => (h, p, String::new(), true),
            None => return respond(&mut client, "400 Bad Request", "bad CONNECT target\n"),
        }
    } else {
        let Some(rest) = target.strip_prefix("http://").or_else(|| target.strip_prefix("HTTP://")) else {
            return respond(&mut client, "400 Bad Request", "ark egress proxy: only absolute http:// URIs and CONNECT are supported\n");
        };
        let (auth, path) = match rest.find(['/', '?']) {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };
        let auth = auth.rsplit('@').next().unwrap_or(auth);
        match split_hostport(auth, 80) {
            Some((h, p)) => (h, p, if path.starts_with('?') { format!("/{path}") } else { path }, false),
            None => return respond(&mut client, "400 Bad Request", "bad request target\n"),
        }
    };
    let host = norm(&host);
    let policy = sh.policy.read().unwrap_or_else(|p| p.into_inner()).clone();
    // A5, second layer: when the daemon enforces capability manifests, the host must also be
    // one some enabled component declared. The policy above is the *host list*; this is the
    // *who may reach it* question, and they fail independently on purpose.
    let verdict = match capability_gate()(&host, port) {
        Err(why) => Err(why),
        Ok(()) => policy.vet(&host, port, &sh.resolve),
    };
    sh.log.push(LogEntry { ts: crate::now_rfc3339(), method: method.clone(), host: host.clone(), port, allowed: verdict.is_ok(), reason: verdict.as_ref().err().cloned().unwrap_or_default() });
    let addrs = match verdict {
        Ok(a) => a,
        Err(e) => return respond(&mut client, "403 Forbidden", &format!("ark egress proxy: blocked {host}:{port}: {e}\n")),
    };
    let mut up = match dial(&addrs) {
        Ok(s) => s,
        Err(e) => return respond(&mut client, "502 Bad Gateway", &format!("ark egress proxy: cannot reach {host}:{port}: {e}\n")),
    };
    if connect {
        if client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").is_err() {
            return;
        }
        if !extra.is_empty() && up.write_all(&extra).is_err() {
            return;
        }
        return splice(client, up);
    }
    // Plain HTTP: origin-form request line, proxy headers dropped, injection applied.
    let inject: Vec<(String, String)> = policy.inject.iter().filter(|i| !i.header.trim().is_empty() && host_rule(&host, &i.host)).map(|i| (i.header.trim().to_string(), (sh.secrets)(&i.value))).collect();
    let mut out = format!("{method} {path} {version}\r\n");
    for (k, v) in &headers {
        let lk = k.to_ascii_lowercase();
        if matches!(lk.as_str(), "proxy-authorization" | "proxy-connection" | "connection" | "keep-alive") || inject.iter().any(|(h, _)| h.eq_ignore_ascii_case(k)) {
            continue;
        }
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    for (k, v) in &inject {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("Connection: close\r\n\r\n");
    if up.write_all(out.as_bytes()).is_err() || (!extra.is_empty() && up.write_all(&extra).is_err()) {
        return;
    }
    splice(client, up);
}

static RUNNING: Mutex<Option<Proxy>> = Mutex::new(None);

/// Start the process-wide proxy once (later calls update its policy) and point
/// children at it. Returns the proxy URL, or None when disabled. A disabled config
/// never stops an already running proxy (one daemon, one proxy).
pub fn ensure_started(cfg: &EgressProxyConfig, policy: Policy, secrets: Secrets, log_file: Option<PathBuf>) -> Result<Option<String>, String> {
    let mut g = RUNNING.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(p) = g.as_ref() {
        if cfg.enabled {
            p.set_policy(policy);
        }
        return Ok(Some(p.url()));
    }
    if !cfg.enabled {
        return Ok(None);
    }
    let p = Proxy::start(&cfg.listen, policy, Arc::new(url_safety::system_resolve), secrets, log_file)?;
    let url = p.url();
    crate::envscrub::set_proxy(Some(&url));
    *g = Some(p);
    Ok(Some(url))
}

/// Name-only verdict of the running proxy (None = no proxy running, or host allowed).
/// Lets the static gates refuse what the proxy would refuse anyway.
pub fn refusal(host: &str) -> Option<String> {
    let g = RUNNING.lock().unwrap_or_else(|p| p.into_inner());
    let p = g.as_ref()?;
    let pol = p.policy.read().unwrap_or_else(|e| e.into_inner());
    pol.check_host(host).err()
}

/// Recent connections of the running proxy.
pub fn recent() -> Vec<LogEntry> {
    RUNNING.lock().unwrap_or_else(|p| p.into_inner()).as_ref().map(Proxy::recent).unwrap_or_default()
}

/// `http://127.0.0.1:<port>` of the running proxy (what children get in `*_PROXY`),
/// or `None` when the proxy is not running. This is also what a sandbox backend hands
/// its container (`[exec.docker] proxy_port` must match [`running_port`]).
pub fn running_url() -> Option<String> {
    RUNNING.lock().unwrap_or_else(|p| p.into_inner()).as_ref().map(Proxy::url)
}

/// Bound port of the running proxy (`listen` may say `:0`), e.g. for
/// `[exec.docker] proxy_port`.
pub fn running_port() -> Option<u16> {
    RUNNING.lock().unwrap_or_else(|p| p.into_inner()).as_ref().map(|p| p.addr().port())
}

/// Expand `{{secret:NAME}}` references in an `inject` value from the process
/// environment. Unset names expand to "" and warn on stderr; a value without a
/// reference is returned unchanged. (`{`/`}` cannot appear in an env name, so a
/// plain scan is enough.)
pub fn expand_env_secrets(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(i) = rest.find("{{secret:") {
        out.push_str(&rest[..i]);
        let tail = &rest[i + "{{secret:".len()..];
        match tail.find("}}") {
            Some(j) => {
                let name = tail[..j].trim();
                match std::env::var(name) {
                    Ok(v) => out.push_str(&v),
                    Err(_) => eprintln!("ark: warning: egress_proxy inject references {{secret:{name}}} but {name} is not set"),
                }
                rest = &tail[j + 2..];
            }
            None => {
                // Unterminated: keep the text verbatim rather than guessing.
                out.push_str("{{secret:");
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out
}

/// [`Secrets`] backed by the process environment: the CLI/kernel fallback when no
/// vault is wired in. `SecurityConfig::activate` uses this.
pub fn env_secrets() -> Secrets {
    Arc::new(|v: &str| expand_env_secrets(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §0-3 A3: the built-in development hosts are pre-authorised, so a task does not
    /// stop on every package download; a new host still needs the gate or an envelope.
    #[test]
    fn builtin_dev_hosts_are_pre_authorised() {
        let dir = std::env::temp_dir().join(format!("ark-devhosts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let c = EgressProxyConfig { mode: ProxyMode::Allowlist, ..Default::default() };
        let p = Policy::from_config(&c, UrlPolicy::default(), WebsiteBlocklist::default(), &dir, &[], &[]);
        for h in ["crates.io", "static.crates.io", "api.github.com", "pypi.org", "deb.debian.org"] {
            assert!(p.check_host(h).is_ok(), "{h} should be pre-authorised: {:?}", p.check_host(h));
        }
        assert!(p.check_host("acme-internal.example").is_err(), "a new host still asks");
        let off = EgressProxyConfig { mode: ProxyMode::Allowlist, dev_hosts: false, ..Default::default() };
        let p2 = Policy::from_config(&off, UrlPolicy::default(), WebsiteBlocklist::default(), &dir, &[], &[]);
        assert!(p2.check_host("crates.io").is_err(), "dev_hosts = false restores a strict allowlist");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn resolver() -> Resolver {
        Arc::new(|h: &str, _| match h {
            "internal.test" => Ok(vec!["10.0.0.5".parse().unwrap()]),
            "meta.test" => Ok(vec!["169.254.169.254".parse().unwrap()]),
            "echo.test" | "api.test" | "other.test" => Ok(vec!["127.0.0.1".parse().unwrap()]),
            _ => Err("NXDOMAIN".into()),
        })
    }

    fn policy(mode: ProxyMode, allow: &[&str]) -> Policy {
        Policy { mode, allow: allow.iter().map(|s| s.to_string()).collect(), deny: vec!["evil.test".into()], inject: vec![Inject { host: "api.test".into(), header: "Authorization".into(), value: "Bearer {{secret:TOK}}".into() }], ..Default::default() }
    }

    fn start(p: Policy) -> Proxy {
        Proxy::start("127.0.0.1:0", p, resolver(), Arc::new(|s: &str| s.replace("{{secret:TOK}}", "real-token")), None).unwrap()
    }

    /// Echo server: replies with everything it received on the first read.
    fn echo() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                std::thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    let mut got = Vec::new();
                    let _ = s.set_read_timeout(Some(Duration::from_millis(300)));
                    while let Ok(n) = s.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        got.extend_from_slice(&buf[..n]);
                        if got.windows(4).any(|w| w == b"\r\n\r\n") || got.ends_with(b"ping") {
                            break;
                        }
                    }
                    let body = String::from_utf8_lossy(&got).to_string();
                    let _ = write!(s, "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                });
            }
        });
        port
    }

    fn send(proxy: &Proxy, req: &str) -> String {
        let mut s = TcpStream::connect(proxy.addr()).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }

    #[test]
    fn connect_tunnels_to_allowed_host_and_denies_others() {
        let port = echo();
        let p = start(policy(ProxyMode::Filter, &["echo.test"]));
        let out = send(&p, &format!("CONNECT echo.test:{port} HTTP/1.1\r\nHost: echo.test\r\n\r\nping"));
        assert!(out.starts_with("HTTP/1.1 200 Connection Established") && out.contains("ping"), "{out}");
        let out = send(&p, &format!("CONNECT evil.test:{port} HTTP/1.1\r\n\r\n"));
        assert!(out.starts_with("HTTP/1.1 403") && out.contains("deny list"), "{out}");
        let out = send(&p, "CONNECT sub.evil.test:443 HTTP/1.1\r\n\r\n");
        assert!(out.starts_with("HTTP/1.1 403"), "subdomains of denied hosts");
        let log = p.recent();
        assert!(log[0].allowed && log[0].host == "echo.test" && !log[1].allowed);
        p.stop();
    }

    #[test]
    fn ssrf_targets_are_refused_even_when_resolved() {
        let p = start(policy(ProxyMode::Filter, &[]));
        for (t, want) in [("internal.test:80", "private"), ("127.0.0.1:22", "private"), ("[::1]:22", "private"), ("meta.test:80", "metadata"), ("nx.test:443", "DNS")] {
            let out = send(&p, &format!("CONNECT {t} HTTP/1.1\r\n\r\n"));
            assert!(out.starts_with("HTTP/1.1 403") && out.contains(want), "{t}: {out}");
        }
        // Explicit allow may reach a private host, never metadata.
        p.set_policy(policy(ProxyMode::Filter, &["internal.test", "meta.test"]));
        assert!(policy(ProxyMode::Filter, &["internal.test"]).vet("internal.test", 80, &resolver()).is_ok());
        let out = send(&p, "GET http://meta.test/latest HTTP/1.1\r\n\r\n");
        assert!(out.starts_with("HTTP/1.1 403") && out.contains("metadata"), "{out}");
        p.stop();
    }

    #[test]
    fn absolute_uri_is_forwarded_with_injection() {
        let port = echo();
        let p = start(policy(ProxyMode::Allowlist, &["api.test", "other.test"]));
        let out = send(&p, &format!("GET http://api.test:{port}/v1/x?q=1 HTTP/1.1\r\nHost: api.test\r\nProxy-Authorization: Basic Zm9v\r\nAuthorization: Bearer placeholder\r\nProxy-Connection: keep-alive\r\n\r\n"));
        assert!(out.starts_with("HTTP/1.1 200"), "{out}");
        assert!(out.contains("GET /v1/x?q=1 HTTP/1.1") && out.contains("Authorization: Bearer real-token") && !out.contains("placeholder") && !out.contains("Proxy-") && out.contains("Connection: close"), "{out}");
        let out = send(&p, &format!("GET http://other.test:{port}/ HTTP/1.1\r\nAuthorization: mine\r\n\r\n"));
        assert!(out.contains("Authorization: mine") && !out.contains("real-token"), "injection is per host: {out}");
        let out = send(&p, "GET http://unlisted.test/ HTTP/1.1\r\n\r\n");
        assert!(out.starts_with("HTTP/1.1 403") && out.contains("allowlist"), "{out}");
        let out = send(&p, "GET /relative HTTP/1.1\r\n\r\n");
        assert!(out.starts_with("HTTP/1.1 400"));
        p.stop();
    }

    #[test]
    fn host_rules_and_config_shape() {
        assert!(host_rule("a.b.com", "b.com") && host_rule("b.com", "b.com") && !host_rule("xb.com", "b.com"));
        assert!(host_rule("a.b.com", "*.b.com") && !host_rule("b.com", "*.b.com"));
        let c: EgressProxyConfig = serde_json::from_value(serde_json::json!({"enabled": true, "mode": "allowlist", "allow": ["x.io"]})).unwrap();
        assert_eq!((c.listen.as_str(), c.mode), ("127.0.0.1:0", ProxyMode::Allowlist));
        assert!(serde_json::from_value::<EgressProxyConfig>(serde_json::json!({"mode": "open"})).is_err());
        assert!(serde_json::from_value::<EgressProxyConfig>(serde_json::json!({"typo": 1})).is_err());
        let pol = Policy::from_config(&c, UrlPolicy::default(), WebsiteBlocklist::default(), Path::new("/"), &["gh.io".into()], &["bad.io".into()]);
        assert!(pol.check_host("x.io").is_ok() && pol.check_host("api.gh.io").is_ok());
        assert!(pol.check_host("bad.io").unwrap_err().contains("deny") && pol.check_host("y.io").unwrap_err().contains("allowlist"));
    }
}
