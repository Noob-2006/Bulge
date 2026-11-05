//! Capability manifests (GAPS-next A5): every tool, skill, plugin and MCP server declares
//! what it needs, and anything undeclared is refused.
//!
//! §0's compromise is the whole point of this module. Built-in tools and official skills
//! ship their declarations ([`builtins`]), so an ordinary session configures nothing and
//! is never prompted; only a *third-party* component needs one installation-time look at
//! its manifest. The manifest is a boundary, not a prompt: protection must not cost
//! autonomy (§0: 保護不能吃掉自主性).
//!
//! The enforceable semantics, in the order they matter:
//!
//! 1. **Built-ins ship declarations.** [`builtins`] covers every tool name `ark-tools` can
//!    register, and the table below says what each one obviously needs: `shell` runs
//!    commands, `web_fetch` reaches the network, `write` writes files. The test keeps the
//!    name list checked in because `ark-security` may not gain an `ark-tools` dev-dependency
//!    (it would be a compile cycle); a new tool there means a new row here.
//! 2. **The common reversible actions are pre-allowed.** `shell` / `job` / `process`
//!    declare `exec: ["*"]`, and every file tool declares the whole tree: inside the VM the
//!    *isolation* is the protection (§0-1: 隔離或回復，不要詢問), so the manifest says *that*
//!    they touch the system, not which paths — `paths`, the workspace policy and the VM
//!    decide where, the risk tiers decide how loudly.
//! 3. **Undeclared third-party is denied.** [`check`] on an unknown name is an `Err`, never
//!    a default-allow: a component that did not say what it needs does not run.
//! 4. **Tier 3 is never authorised by a manifest.** A manifest can *let a component ask*
//!    (`destructive: true`), but every irreversible request goes to the operator (A6);
//!    `destructive: false` is stronger than any tier and can never do one at all.
//! 5. **A manifest can never widen a built-in.** [`register`] ignores a name [`builtin`]
//!    knows, and `check("shell", …)` only reads the built-in `shell` manifest, whatever a
//!    skill or MCP server claims about itself.
//!
//! # `net: ["*"]`
//!
//! `*` means **public hosts only**: never loopback, RFC 1918 / CGNAT / link-local / reserved
//! literal addresses, single-label LAN names (`fileserver`), local-only names (`localhost`,
//! `*.local`, `*.internal`) or cloud-metadata names. Those need an explicit entry such as
//! `"127.0.0.1"`. A declaration is a *name* grant: whether the name resolves to a private
//! address is [`crate::url_safety`]'s job (every DNS answer and every redirect hop), and the
//! egress proxy enforces the host list on the wire — two independent layers on purpose.
//!
//! An entry may pin a port (`"crates.io:443"`, `"[::1]:8080"`); without one it covers every
//! port. As in [`crate::egress_proxy::host_rule`], `"crates.io"` also covers its subdomains
//! and `"*.github.com"` covers subdomains only.

use crate::risk::{self, Candidate, Tier};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{OnceLock, RwLock};

// ───────────────────────────── vocabulary ─────────────────────────────

/// What kind of component a manifest describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Tool,
    Skill,
    Plugin,
    #[serde(alias = "mcp-server", alias = "mcp_server")]
    Mcp,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Tool => "tool",
            Kind::Skill => "skill",
            Kind::Plugin => "plugin",
            Kind::Mcp => "mcp",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "tool" => Some(Kind::Tool),
            "skill" => Some(Kind::Skill),
            "plugin" | "extension" => Some(Kind::Plugin),
            "mcp" | "mcp-server" | "mcpserver" => Some(Kind::Mcp),
            _ => None,
        }
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Who wrote the component — and therefore how much its declaration is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Source {
    /// Shipped with ark (the table in this module): trusted code, declares without asking.
    Builtin,
    /// The operator wrote it (their own skill or plugin): trusted, but a later widening is
    /// recorded by [`widenings`].
    Operator,
    /// Somebody else wrote it: one installation-time confirmation, then the manifest is the
    /// boundary (H3/H4).
    #[serde(rename = "third-party", alias = "third_party", alias = "thirdparty")]
    ThirdParty,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Builtin => "builtin",
            Source::Operator => "operator",
            Source::ThirdParty => "third-party",
        }
    }

    pub fn parse(s: &str) -> Option<Source> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "builtin" | "built-in" | "official" => Some(Source::Builtin),
            "operator" | "owner" | "local" => Some(Source::Operator),
            "third-party" | "thirdparty" | "vendor" | "marketplace" => Some(Source::ThirdParty),
            _ => None,
        }
    }
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What one component says it needs. An empty list means "not at all".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Manifest {
    pub name: String,
    pub kind: Kind,
    pub source: Source,
    /// Path globs the component may read (`"**"`, `"/home/me/proj/**"`).
    pub fs_read: Vec<String>,
    /// Path globs it may write.
    pub fs_write: Vec<String>,
    /// argv patterns it may run (`"apt-get install *"`, `"cargo build"`).
    pub exec: Vec<String>,
    /// Hosts it may contact (`"crates.io"`, `"*.github.com"`, `"*"` = public only).
    pub net: Vec<String>,
    /// Vault *names* it may have injected (never values).
    pub secrets: Vec<String>,
    /// Other tools it may call.
    pub tools: Vec<String>,
    /// May attempt tier-3 work at all — which still asks the operator, always (A6).
    pub destructive: bool,
}

impl Default for Manifest {
    fn default() -> Self {
        // Fail safe: a manifest that does not say who wrote it is treated as third-party,
        // so it needs the installation-time confirmation instead of being trusted.
        Manifest {
            name: String::new(),
            kind: Kind::Tool,
            source: Source::ThirdParty,
            fs_read: Vec::new(),
            fs_write: Vec::new(),
            exec: Vec::new(),
            net: Vec::new(),
            secrets: Vec::new(),
            tools: Vec::new(),
            destructive: false,
        }
    }
}

/// One thing a component wants to do. Every field is optional so an enforcement point
/// fills in only the effects it actually has (a broker call has `exec`, a fetcher has
/// `net`); `destructive` is the caller's own last-resort label.
#[derive(Debug, Clone, Copy, Default)]
pub struct Request<'a> {
    pub fs_read: Option<&'a str>,
    pub fs_write: Option<&'a str>,
    /// argv, already split. A caller that only holds a shell line may pass it as a single
    /// element; it is then matched word by word (see [`Manifest::allows`]).
    pub exec: Option<&'a [String]>,
    pub net: Option<(&'a str, u16)>,
    pub secret: Option<&'a str>,
    pub tool: Option<&'a str>,
    pub destructive: bool,
}

impl Manifest {
    /// Is this request inside the declaration? `Err` is the denial the operator sees: it
    /// names the missing capability and the manifest that lacked it.
    ///
    /// `destructive: false` refuses a destructive request here and now — no tier, task
    /// envelope or preset can talk this check into `Ok` (§0-2 #10). A `destructive: true`
    /// manifest merely *reaches* the operator gate; [`check`] still refuses tier 3.
    pub fn allows(&self, r: &Request<'_>) -> Result<(), String> {
        if r.destructive && !self.destructive {
            return Err(format!(
                "`{}` ({}, {}) does not declare the `destructive` capability: this request is irreversible, and a manifest that does not declare `destructive` can never be authorised to attempt one (A5)",
                self.name, self.kind, self.source
            ));
        }
        if let Some(p) = r.fs_read {
            if !matches(&self.fs_read, p) {
                return Err(self.denial(&format!("fs:read:{p}"), &format!("reading {p}")));
            }
        }
        if let Some(p) = r.fs_write {
            if !matches(&self.fs_write, p) {
                return Err(self.denial(&format!("fs:write:{p}"), &format!("writing {p}")));
            }
        }
        if let Some(argv) = r.exec {
            if argv.is_empty() {
                return Err(format!("`{}` was asked to run an empty command line; there is nothing to allow", self.name));
            }
            if !exec_allows(&self.exec, argv) {
                return Err(self.denial(&format!("exec:{}", argv.join(" ")), &format!("running `{}`", argv.join(" "))));
            }
        }
        if let Some((host, port)) = r.net {
            let host = crate::url_safety::normalize_host(host);
            if !net_allows(&self.net, &host, port) {
                let mut msg = self.denial(&format!("net:{host}:{port}"), &format!("connecting to {host}:{port}"));
                if !public_host(&host) && self.net.iter().any(|p| p.trim() == "*") {
                    msg.push_str("; `net: [\"*\"]` covers public hosts only — loopback, private, reserved and local names need an explicit entry (the address-level check is `url_safety`)");
                }
                return Err(msg);
            }
        }
        if let Some(s) = r.secret {
            if !matches(&self.secrets, s) {
                return Err(self.denial(&format!("secret:{s}"), &format!("having the secret {s} injected")));
            }
        }
        if let Some(t) = r.tool {
            if !matches(&self.tools, t) {
                return Err(self.denial(&format!("tool:{t}"), &format!("calling the tool {t}")));
            }
        }
        Ok(())
    }

    /// One line for `ark sandbox explain`: what this component is and what it may do.
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for (label, list) in [("fs:read", &self.fs_read), ("fs:write", &self.fs_write), ("exec", &self.exec), ("secret", &self.secrets), ("tool", &self.tools)] {
            parts.extend(list.iter().map(|v| format!("{label} {v}")));
        }
        // `*` is not "everything": say what it actually covers.
        parts.extend(self.net.iter().map(|v| if v.trim() == "*" { "net * (public hosts only)".to_string() } else { format!("net {v}") }));
        if self.destructive {
            parts.push("destructive (tier 3 still asks the operator)".to_string());
        }
        let caps = if parts.is_empty() { "no capabilities (no files, network, commands, secrets or tools)".to_string() } else { parts.join(", ") };
        // A glob may come from a TOML string; the summary is a single line by contract.
        format!("{} {} ({}): {caps}", self.kind, self.name, self.source).replace(['\n', '\r', '\t'], " ")
    }

    fn denial(&self, cap: &str, what: &str) -> String {
        format!(
            "`{}` ({}, {}) lacks the `{cap}` capability needed for {what}; undeclared capabilities are refused (A5), so add it to that component's manifest",
            self.name, self.kind, self.source
        )
    }

    /// The manifest as TOML, in the form [`from_toml`] reads back (round trip).
    pub fn to_toml(&self) -> String {
        let mut s = format!("name = {}\nkind = {}\nsource = {}\n", quote(&self.name), quote(self.kind.as_str()), quote(self.source.as_str()));
        for (key, list) in [("fs_read", &self.fs_read), ("fs_write", &self.fs_write), ("exec", &self.exec), ("net", &self.net), ("secrets", &self.secrets), ("tools", &self.tools)] {
            s.push_str(&format!("{key} = {}\n", toml_list(list)));
        }
        s.push_str(&format!("destructive = {}\n", self.destructive));
        s
    }
}

// ───────────────────────────── globs ─────────────────────────────

/// Does any pattern cover `value`?
///
/// - `"*"` — everything;
/// - a pattern with `/` — a path glob: `**` crosses directories, `*`/`?` stay inside one
///   segment, `~` is the home directory ([`crate::glob::path_glob`]);
/// - `"prefix*"` — prefix match (`"apt-get install *"`, `"mcp__github__*"`);
/// - any other pattern with `*` / `?` / `[...]` — [`crate::glob::fnmatch`] (`"*.host.tld"`);
/// - anything else — exact, case-sensitive.
///
/// Host semantics live in [`Manifest::allows`] (a `net` entry also covers subdomains);
/// this function is the plain glob the rest of the declaration vocabulary uses.
pub fn matches(patterns: &[String], value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    patterns.iter().any(|p| glob_match(p, value))
}

fn glob_match(pattern: &str, value: &str) -> bool {
    let p = pattern.trim();
    if p.is_empty() {
        return false;
    }
    if p == "*" {
        return true;
    }
    if p.contains('/') {
        return crate::glob::path_glob(p, value);
    }
    if let Some(prefix) = p.strip_suffix('*') {
        if !prefix.contains(['*', '?', '[']) {
            return value.starts_with(prefix);
        }
    }
    if p.contains(['*', '?', '[']) {
        return crate::glob::fnmatch(p, value);
    }
    p == value
}

// ───────────────────────────── exec, argv-first ─────────────────────────────

/// argv-prefix matching: the pattern's words must equal the first argv elements and may
/// stop there (`"cargo build"` allows `cargo build --release`); a trailing `*` element
/// covers the rest. Matching element by element — not by re-joining the line — keeps
/// `["sh","-c","rm -rf /"]` from being read as one loose string.
///
/// A single-element argv is split on whitespace, because a caller holding a shell string
/// has nothing better to give us. Grant narrowly: the pattern `"sh"` allows every `sh …`.
fn exec_allows(patterns: &[String], argv: &[String]) -> bool {
    let words: Vec<String> = if argv.len() == 1 { argv[0].split_whitespace().map(str::to_string).collect() } else { argv.to_vec() };
    if words.is_empty() {
        return false;
    }
    patterns.iter().any(|p| exec_matches(p, &words))
}

fn exec_matches(pattern: &str, words: &[String]) -> bool {
    let p = pattern.trim();
    if p.is_empty() {
        return false;
    }
    if p == "*" {
        return true;
    }
    let pat: Vec<&str> = p.split_whitespace().collect();
    let pat = match pat.split_last() {
        Some((last, init)) if last == &"*" => init,
        _ => &pat[..],
    };
    // Element-wise: an argv element carrying spaces stays one word.
    pat.len() <= words.len() && pat.iter().zip(words).all(|(p, w)| *p == "*" || if p.contains(['*', '?', '[']) { crate::glob::fnmatch(p, w) } else { p == w })
}

// ───────────────────────────── network ─────────────────────────────

/// Is this host one `net: ["*"]` may cover? A literal address only when it is not
/// loopback / private / reserved / metadata; a name only when it is not local-only, not a
/// single-label LAN name and not a metadata name.
fn public_host(host: &str) -> bool {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return !crate::url_safety::is_blocked_ip(ip) && !crate::url_safety::is_always_blocked_ip(ip);
    }
    if crate::url_safety::is_local_hostname(host) || crate::url_safety::BLOCKED_HOSTNAMES.iter().any(|h| h.eq_ignore_ascii_case(host)) || crate::url_safety::is_legacy_ipv4_literal(host) {
        return false;
    }
    // `fileserver`, `intranet`: resolved through a search domain, so not public.
    host.contains('.')
}

/// `"crates.io:443"` / `"[::1]:8080"` / `"crates.io"` → (host, optional port).
fn split_port(p: &str) -> (&str, Option<u16>) {
    if let Some(rest) = p.strip_prefix('[') {
        if let Some((h, tail)) = rest.split_once(']') {
            return (h, tail.strip_prefix(':').and_then(|x| x.parse::<u16>().ok()));
        }
    }
    match p.rsplit_once(':') {
        Some((h, port)) if !h.contains(':') => match port.parse::<u16>() {
            Ok(n) => (h, Some(n)),
            Err(_) => (p, None),
        },
        _ => (p, None),
    }
}

fn net_allows(patterns: &[String], host: &str, port: u16) -> bool {
    if host.is_empty() {
        return false;
    }
    patterns.iter().any(|raw| {
        let p = raw.trim();
        if p.is_empty() {
            return false;
        }
        let (pat, want_port) = split_port(p);
        if want_port.is_some_and(|w| w != port) {
            return false;
        }
        if pat == "*" {
            return public_host(host);
        }
        crate::egress_proxy::host_rule(host, pat)
    })
}

// ───────────────────────────── built-in declarations ─────────────────────────────

const NONE: &[&str] = &[];
const ALL_PATHS: &[&str] = &["**"];
const ANY_COMMAND: &[&str] = &["*"];
const PUBLIC_NET: &[&str] = &["*"];
const ANY_SECRET: &[&str] = &["*"];

/// One row of the shipped table: `&'static [&'static str]`, so the table is a `const` (no
/// allocation, no config section — nothing for an operator to maintain).
struct Row {
    name: &'static str,
    fs_read: &'static [&'static str],
    fs_write: &'static [&'static str],
    exec: &'static [&'static str],
    net: &'static [&'static str],
    secrets: &'static [&'static str],
    tools: &'static [&'static str],
    destructive: bool,
}

const fn row(name: &'static str) -> Row {
    Row { name, fs_read: NONE, fs_write: NONE, exec: NONE, net: NONE, secrets: NONE, tools: NONE, destructive: false }
}

/// Every `ToolSpec` name in `crates/ark-tools/src`, with what it obviously needs.
///
/// `ALL_PATHS` / `ANY_COMMAND` are deliberate (§0-1): the tools run inside the VM, the
/// workspace policy decides which paths are reachable, and the risk tiers decide how
/// loudly. The manifest's job is to say *that* a tool touches files or runs commands;
/// pretending to know the scope here would only produce prompts for ordinary work.
const BUILTIN_ROWS: &[Row] = &[
    // Filesystem. `write`/`edit`/`patch`/`apply_patch` can reach an irreversible write
    // (a backup or production path), so they may *ask*; tier 3 still asks a human.
    Row { fs_read: ALL_PATHS, ..row("read") },
    Row { fs_read: ALL_PATHS, fs_write: ALL_PATHS, destructive: true, ..row("write") },
    Row { fs_read: ALL_PATHS, fs_write: ALL_PATHS, destructive: true, ..row("edit") },
    Row { fs_read: ALL_PATHS, fs_write: ALL_PATHS, destructive: true, ..row("patch") },
    Row { fs_read: ALL_PATHS, fs_write: ALL_PATHS, destructive: true, ..row("apply_patch") },
    Row { fs_read: ALL_PATHS, ..row("glob") },
    Row { fs_read: ALL_PATHS, ..row("grep") },
    // Command execution: the VM is the boundary, so the declaration is `*` — including the
    // network, which a shell command reaches through the egress proxy (A3) and `*` still
    // keeps off the host's private space. `secrets: ["*"]` is what `shell` documents
    // (`{{secret:NAME}}` in a command line): the operator names the secret, so the set of
    // names cannot be known in advance.
    Row { fs_read: ALL_PATHS, fs_write: ALL_PATHS, exec: ANY_COMMAND, net: PUBLIC_NET, secrets: ANY_SECRET, destructive: true, ..row("shell") },
    // The guest agent asking on behalf of a session the host cannot attribute to a single
    // tool (a background job, a program started earlier). It may run commands and reach
    // public hosts, but it may not have a *named* secret injected: that needs a component
    // that declares the name (A4/A5). A program inside the VM cannot name itself.
    Row { fs_read: ALL_PATHS, fs_write: ALL_PATHS, exec: ANY_COMMAND, net: PUBLIC_NET, destructive: true, ..row("vm") },
    Row { fs_read: ALL_PATHS, fs_write: ALL_PATHS, exec: ANY_COMMAND, net: PUBLIC_NET, secrets: ANY_SECRET, tools: &["process", "read_terminal"], destructive: true, ..row("job") },
    Row { fs_read: ALL_PATHS, fs_write: ALL_PATHS, exec: ANY_COMMAND, net: PUBLIC_NET, secrets: ANY_SECRET, tools: &["read_terminal"], destructive: true, ..row("process") },
    Row { ..row("read_terminal") },
    Row { ..row("close_terminal") },
    // Agent-side tools.
    Row { fs_read: ALL_PATHS, fs_write: ALL_PATHS, ..row("memory") },
    // A spawned session's tools come from `toolpolicy`, not from this manifest: `spawn`
    // itself calls no tool, and a poisoned parent cannot hand it a wider set.
    Row { ..row("spawn") },
    Row { ..row("ask_user") },
    Row { fs_read: ALL_PATHS, fs_write: ALL_PATHS, ..row("todo") },
    Row { fs_read: ALL_PATHS, fs_write: ALL_PATHS, ..row("skill") },
    // Web. `net: ["*"]` = public hosts only (module docs); a fetcher that declared just
    // the dev hosts would refuse an ordinary documentation lookup, which is exactly the
    // prompt §0 forbids. Provider keys are read from the daemon's own config, never
    // injected into the call, so these tools declare no secret.
    Row { net: PUBLIC_NET, ..row("web_fetch") },
    Row { net: PUBLIC_NET, ..row("web_search") },
    Row { net: PUBLIC_NET, ..row("web_extract") },
    Row { net: PUBLIC_NET, ..row("x_search") },
    Row { net: PUBLIC_NET, ..row("code_execution") },
    // GitHub: the read tools only need the API and raw content.
    Row { net: &["api.github.com", "github.com", "*.github.com", "raw.githubusercontent.com"], ..row("github_read") },
    Row { net: &["api.github.com", "github.com", "*.github.com"], ..row("github_search") },
    Row { net: PUBLIC_NET, ..row("tavily_search") },
    Row { net: PUBLIC_NET, ..row("tavily_extract") },
    Row { net: PUBLIC_NET, ..row("firecrawl_search") },
    Row { net: PUBLIC_NET, ..row("firecrawl_scrape") },
];

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// The shipped declarations: every built-in tool, one manifest each.
pub fn builtins() -> &'static [Manifest] {
    static B: OnceLock<&'static [Manifest]> = OnceLock::new();
    B.get_or_init(|| {
        let v: Vec<Manifest> = BUILTIN_ROWS
            .iter()
            .map(|r| Manifest {
                name: r.name.to_string(),
                fs_read: strings(r.fs_read),
                fs_write: strings(r.fs_write),
                exec: strings(r.exec),
                net: strings(r.net),
                secrets: strings(r.secrets),
                tools: strings(r.tools),
                destructive: r.destructive,
                kind: Kind::Tool,
                source: Source::Builtin,
            })
            .collect();
        let leaked: &'static [Manifest] = Box::leak(v.into_boxed_slice());
        leaked
    })
}

/// The shipped manifest for `name`, if `name` is a built-in tool.
pub fn builtin(name: &str) -> Option<&'static Manifest> {
    let name = name.trim();
    builtins().iter().find(|m| m.name == name)
}

// ───────────────────────────── the registry ─────────────────────────────

/// A later registration that added capabilities to a name that was already known. This is
/// the rug pull (H3): the component the operator reviewed and the component running now are
/// not the same, so the host re-confirms (A13) and `ark sandbox explain` shows it.
#[derive(Debug, Clone, PartialEq)]
pub struct Widening {
    pub name: String,
    /// What the new manifest added (`net:example.com`, `fs:write:/x/**`, `destructive`).
    pub added: Vec<String>,
    pub previous: Manifest,
    pub current: Manifest,
}

struct Registry {
    manifests: BTreeMap<String, Manifest>,
    widenings: Vec<Widening>,
}

fn registry() -> &'static RwLock<Registry> {
    static R: OnceLock<RwLock<Registry>> = OnceLock::new();
    R.get_or_init(|| RwLock::new(Registry { manifests: BTreeMap::new(), widenings: Vec::new() }))
}

/// Record a skill / plugin / MCP server's declaration at load time.
///
/// - idempotent by name: registering the same capabilities twice changes nothing;
/// - a name [`builtin`] knows is **ignored** — a skill or MCP server can never widen or
///   shadow a built-in tool (rule 5);
/// - a later registration that adds capabilities replaces the old one *and* is recorded in
///   [`widenings`], but only for `Source::Operator` / `Source::ThirdParty`. A registration
///   that narrows keeps the reviewed scope (shrinking silently would make the log useless).
pub fn register(m: Manifest) {
    let name = m.name.trim().to_string();
    if name.is_empty() || builtin(&name).is_some() {
        return;
    }
    let mut reg = registry().write().unwrap_or_else(|e| e.into_inner());
    let Some(prev) = reg.manifests.get(&name).cloned() else {
        reg.manifests.insert(name, m);
        return;
    };
    let added = added_capabilities(&prev, &m);
    if added.is_empty() || !matches!(m.source, Source::Operator | Source::ThirdParty) {
        return;
    }
    reg.widenings.push(Widening { name: name.clone(), added, previous: prev, current: m.clone() });
    reg.manifests.insert(name, m);
}

/// The manifest enforcement must use: the shipped one for a built-in, the registered one
/// for everything else.
/// Every manifest in force: the built-ins plus whatever skills/plugins/MCP servers registered.
pub fn all() -> Vec<Manifest> {
    let mut v: Vec<Manifest> = builtins().to_vec();
    let reg = registry().read().unwrap_or_else(|e| e.into_inner());
    let mut extra: Vec<Manifest> = reg.manifests.values().cloned().collect();
    extra.sort_by(|a, b| a.name.cmp(&b.name));
    v.extend(extra);
    v
}

/// The egress proxy's capability gate (A5): a host is reachable when some component in force
/// declares it, or when the operator's own list (`security.egress_proxy.allow` /
/// `gate.egress_allow`, plus the built-in dev hosts) names it. Installed by the daemon when
/// tools run in a VM; see [`crate::egress_proxy::set_capability_gate`].
pub fn egress_gate(operator_allow: &[String]) -> crate::egress_proxy::CapGate {
    let extra: Vec<String> = operator_allow.to_vec();
    std::sync::Arc::new(move |host: &str, port: u16| {
        if extra.iter().any(|r| crate::egress_proxy::host_rule(host, r)) {
            return Ok(());
        }
        let mut declaring: Vec<String> = Vec::new();
        for m in all() {
            if net_allows(&m.net, host, port) {
                declaring.push(m.name);
            }
        }
        if declaring.is_empty() {
            return Err(format!("no component declares `{host}` (A5): name it in a skill/plugin manifest (`net:{host}`) or in `security.egress_proxy.allow`; `net: \"*\"` covers public hosts only"));
        }
        Ok(())
    })
}

pub fn lookup(name: &str) -> Option<Manifest> {
    let name = name.trim();
    if let Some(b) = builtin(name) {
        return Some(b.clone());
    }
    registry().read().unwrap_or_else(|e| e.into_inner()).manifests.get(name).cloned()
}

/// Every widening recorded so far, oldest first.
pub fn widenings() -> Vec<Widening> {
    registry().read().unwrap_or_else(|e| e.into_inner()).widenings.clone()
}

/// Widenings for one component.
pub fn widenings_for(name: &str) -> Vec<Widening> {
    let name = name.trim();
    registry().read().unwrap_or_else(|e| e.into_inner()).widenings.iter().filter(|w| w.name == name).cloned().collect()
}

/// Forget every registered manifest and the widening log (built-ins are unaffected). For a
/// host reloading its skills / plugins / MCP servers; not for use while other threads check.
pub fn reset() {
    let mut reg = registry().write().unwrap_or_else(|e| e.into_inner());
    reg.manifests.clear();
    reg.widenings.clear();
}

fn added_capabilities(prev: &Manifest, new: &Manifest) -> Vec<String> {
    let dims: [(&str, &[String], &[String]); 6] =
        [("fs:read", &prev.fs_read, &new.fs_read), ("fs:write", &prev.fs_write, &new.fs_write), ("exec", &prev.exec, &new.exec), ("net", &prev.net, &new.net), ("secret", &prev.secrets, &new.secrets), ("tool", &prev.tools, &new.tools)];
    let mut added: Vec<String> = Vec::new();
    for (label, before, after) in dims {
        for v in after {
            let cap = format!("{label}:{v}");
            if !before.contains(v) && !added.contains(&cap) {
                added.push(cap);
            }
        }
    }
    if new.destructive && !prev.destructive {
        added.push("destructive".into());
    }
    added
}

// ───────────────────────────── the check ─────────────────────────────

/// The manifest's verdict on one request.
///
/// - unknown name ⇒ `Err` ("no capability manifest for …"), never a default-allow;
/// - known ⇒ [`Manifest::allows`], then the A6 floor: a request the risk classifier calls
///   tier 3 is refused **by capability alone** — the caller must escalate to the operator
///   (call [`assess`] first to tell "denied" from "needs-operator").
pub fn check(name: &str, r: &Request<'_>) -> Result<Manifest, String> {
    let m = lookup(name).ok_or_else(|| format!("no capability manifest for `{name}`: third-party components must declare what they need before they run (A5)"))?;
    m.allows(r)?;
    let a = assess(name, r);
    if a.tier.is_irreversible() {
        let why = a.reasons.first().map(String::as_str).unwrap_or("no reason recorded");
        return Err(format!(
            "`{name}` ({}, {}): this request is tier 3 (irreversible) — {why}; a capability manifest can never authorise tier 3, it needs the operator (A6)",
            m.kind, m.source
        ));
    }
    Ok(m)
}

/// The risk classification of this request, for a caller that must send tier 3 to the
/// operator instead of refusing it (§0-1: tier 3 asks, it does not merely stop).
///
/// A [`Request`] carries no session workspace, so nothing here counts as "inside the
/// workspace": a write is tier 0 only when [`risk::sandboxed`] says so, and backup /
/// production paths are tier 3 whatever the sandbox says.
pub fn assess(name: &str, r: &Request<'_>) -> risk::Assessment {
    let c = Candidate {
        tool: name.to_string(),
        exec: r.exec.map(|argv| argv.join(" ")).into_iter().filter(|s| !s.trim().is_empty()).collect(),
        writes: r.fs_write.map(PathBuf::from).into_iter().collect(),
        reads: r.fs_read.map(PathBuf::from).into_iter().collect(),
        hosts: r.net.map(|(h, _)| h.to_string()).into_iter().collect(),
        sandboxed: risk::sandboxed(),
        // No workspace is known here; anything not provably inside one is judged as
        // outside (`inside()` is false for every path against this sentinel).
        workspace: PathBuf::from("\u{0}ark-capability-no-workspace"),
        ..Default::default()
    };
    let mut a = risk::assess(&c);
    if r.destructive && !a.tier.is_irreversible() {
        a.tier = Tier::Irreversible;
        a.hard_floor = true;
        a.reasons.insert(0, "the caller marked the request destructive".into());
    }
    a
}

// ───────────────────────────── declarations ─────────────────────────────

/// Build a manifest from the capability vocabulary `plugin_guard` / skill frontmatter
/// already use:
///
/// `fs:read:<glob>`, `fs:write:<glob>` (or `fs:rw:<glob>` for both), `exec:<pattern>`,
/// `net:<host>[:<port>]`, `secret:<NAME>`, `tool:<name>`, `destructive`.
///
/// Liberal in what it accepts: `fs.read:` / `network:` / `host:` / `env:` / `vault:` /
/// `tools:` / `call:` / `run:` are aliases, a token may carry a comma-separated list, and
/// `destructive:false` is a no-op. Strict in what it emits: [`Manifest::to_toml`] and
/// [`Manifest::summary`] only write the canonical spellings. A bad token is named in the
/// error, because the operator has to fix that line.
pub fn declared(name: &str, kind: Kind, source: Source, caps: &[String]) -> Result<Manifest, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("a capability declaration needs the component's name".into());
    }
    let mut m = Manifest { name: name.to_string(), kind, source, ..Default::default() };
    for raw in caps {
        for tok in raw.split(',') {
            let tok = tok.trim();
            if !tok.is_empty() {
                apply_cap(&mut m, tok)?;
            }
        }
    }
    Ok(m)
}

fn apply_cap(m: &mut Manifest, tok: &str) -> Result<(), String> {
    let (head, rest) = tok.split_once(':').unwrap_or((tok, ""));
    let head = head.trim().to_ascii_lowercase();
    let rest = rest.trim();
    let need = |what: &str| -> Result<&str, String> {
        if rest.is_empty() {
            Err(format!("capability `{tok}` is missing its {what} (expected `{}:{what}:<value>`) for `{}`", head, m.name))
        } else {
            Ok(rest)
        }
    };
    match head.as_str() {
        "destructive" => match rest.to_ascii_lowercase().as_str() {
            "" | "true" | "yes" | "1" => m.destructive = true,
            "false" | "no" | "0" => m.destructive = false,
            other => return Err(format!("capability `{tok}` for `{}`: `destructive` takes true or false, not `{other}`", m.name)),
        },
        "fs" => {
            let (mode, glob) = rest.split_once(':').map(|(a, b)| (a.trim().to_ascii_lowercase(), b.trim())).ok_or_else(|| format!("capability `{tok}` for `{}`: expected fs:read:<glob> or fs:write:<glob>", m.name))?;
            if glob.is_empty() {
                return Err(format!("capability `{tok}` for `{}` has no path glob", m.name));
            }
            match mode.as_str() {
                "read" | "r" => push_unique(&mut m.fs_read, glob),
                "write" | "w" => push_unique(&mut m.fs_write, glob),
                "readwrite" | "rw" => {
                    push_unique(&mut m.fs_read, glob);
                    push_unique(&mut m.fs_write, glob);
                }
                other => return Err(format!("capability `{tok}` for `{}`: unknown file mode `{other}` (expected read, write or rw)", m.name)),
            }
        }
        "exec" | "run" | "cmd" => push_unique(&mut m.exec, need("pattern")?),
        "net" | "network" | "host" => push_unique(&mut m.net, need("host")?),
        "secret" | "secrets" | "env" | "vault" => push_unique(&mut m.secrets, need("vault name")?),
        "tool" | "tools" | "call" => push_unique(&mut m.tools, need("tool name")?),
        other => {
            return Err(format!(
                "unrecognised capability `{tok}` for `{}`: expected `{other}` to be fs:read:<glob>, fs:write:<glob>, exec:<pattern>, net:<host>, secret:<NAME>, tool:<name> or destructive",
                m.name
            ))
        }
    }
    Ok(())
}

fn push_unique(v: &mut Vec<String>, s: &str) {
    let s = s.trim();
    if !s.is_empty() && !v.iter().any(|x| x == s) {
        v.push(s.to_string());
    }
}

/// Read a manifest file:
///
/// ```toml
/// name = "release-notes"
/// kind = "skill"              # tool | skill | plugin | mcp
/// source = "third-party"      # builtin | operator | third-party
/// fs_read = ["/home/me/proj/**"]
/// fs_write = []
/// exec = ["git log *"]
/// net = ["crates.io"]
/// secrets = ["CRATES_TOKEN"]
/// tools = ["read"]
/// destructive = false
/// capabilities = ["net:docs.rs"]   # optional, the same vocabulary as `declared`
/// ```
///
/// `name` is required. `kind` defaults to `tool` and `source` to `third-party` — a manifest
/// that does not say who wrote it does not get to be trusted. Unknown keys, section
/// headers, duplicate keys and values that are not strings / booleans / arrays of strings
/// are errors naming the line and key, because this is a boundary file edited by hand.
pub fn from_toml(text: &str) -> Result<Manifest, String> {
    let mut name = String::new();
    let mut kind = Kind::Tool;
    let mut source = Source::ThirdParty;
    let mut fields = Manifest::default();
    let mut caps: Vec<String> = Vec::new();

    for (key, value) in parse_lite(text)? {
        match key.as_str() {
            "name" => name = value.string(&key)?,
            "kind" => {
                let s = value.string(&key)?;
                kind = Kind::parse(&s).ok_or_else(|| format!("invalid kind `{s}` in the capability manifest: expected tool, skill, plugin or mcp"))?;
            }
            "source" => {
                let s = value.string(&key)?;
                source = Source::parse(&s).ok_or_else(|| format!("invalid source `{s}` in the capability manifest: expected builtin, operator or third-party"))?;
            }
            "fs_read" => fields.fs_read = value.list(&key)?,
            "fs_write" => fields.fs_write = value.list(&key)?,
            "exec" => fields.exec = value.list(&key)?,
            "net" => fields.net = value.list(&key)?,
            "secrets" => fields.secrets = value.list(&key)?,
            "tools" => fields.tools = value.list(&key)?,
            "destructive" => fields.destructive = value.bool(&key)?,
            "capabilities" => caps = value.list(&key)?,
            other => {
                return Err(format!(
                    "unknown key `{other}` in the capability manifest: expected name, kind, source, fs_read, fs_write, exec, net, secrets, tools, destructive or capabilities"
                ))
            }
        }
    }

    if name.trim().is_empty() {
        return Err("the capability manifest has no `name`".into());
    }
    let mut m = Manifest { name: name.trim().to_string(), kind, source, ..fields };
    if !caps.is_empty() {
        let extra = declared(&m.name, kind, source, &caps)?;
        for (mine, theirs) in [(&mut m.fs_read, &extra.fs_read), (&mut m.fs_write, &extra.fs_write), (&mut m.exec, &extra.exec), (&mut m.net, &extra.net), (&mut m.secrets, &extra.secrets), (&mut m.tools, &extra.tools)] {
            for v in theirs {
                push_unique(mine, v);
            }
        }
        m.destructive |= extra.destructive;
    }
    Ok(m)
}

// ── a deliberately small TOML reader (ark-security has no `toml` dependency) ──

#[derive(Debug, Clone, PartialEq)]
enum Lite {
    Str(String),
    Bool(bool),
    List(Vec<String>),
}

impl Lite {
    fn string(self, key: &str) -> Result<String, String> {
        if let Lite::Str(s) = self { Ok(s) } else { Err(wrong(key, "a string", &self)) }
    }

    fn list(self, key: &str) -> Result<Vec<String>, String> {
        if let Lite::List(v) = self { Ok(v) } else { Err(wrong(key, "an array of strings", &self)) }
    }

    fn bool(self, key: &str) -> Result<bool, String> {
        if let Lite::Bool(b) = self { Ok(b) } else { Err(wrong(key, "true or false", &self)) }
    }
}

fn wrong(key: &str, want: &str, got: &Lite) -> String {
    let got = match got {
        Lite::Str(_) => "a string",
        Lite::Bool(_) => "a boolean",
        Lite::List(_) => "an array",
    };
    format!("`{key}` must be {want}, not {got}")
}

fn parse_lite(text: &str) -> Result<BTreeMap<String, Lite>, String> {
    let mut out = BTreeMap::new();
    let mut lines = text.lines().enumerate();
    while let Some((i, raw)) = lines.next() {
        let no = i + 1;
        let mut line = strip_comment(raw);
        if line.trim().is_empty() {
            continue;
        }
        if line.trim_start().starts_with('[') {
            return Err(format!("line {no}: a capability manifest is a flat table; `{}` cannot open a section", line.trim()));
        }
        // Arrays may span lines; keep reading until the brackets close.
        let mut span = 0;
        while open_brackets(&line) > 0 {
            let Some((_, more)) = lines.next() else {
                return Err(format!("line {no}: an array is never closed"));
            };
            span += 1;
            if span > 500 {
                return Err(format!("line {no}: the value spans more than 500 lines"));
            }
            line.push('\n');
            line.push_str(&strip_comment(more));
        }
        let Some((key, rest)) = line.split_once('=') else {
            return Err(format!("line {no}: expected `key = value`, found `{}`", line.trim()));
        };
        let key = key.trim().to_string();
        if key.is_empty() {
            return Err(format!("line {no}: expected `key = value`, found `{}`", line.trim()));
        }
        if out.contains_key(&key) {
            return Err(format!("line {no}: `{key}` is set twice"));
        }
        let value = parse_value(rest.trim()).map_err(|e| format!("line {no}: `{key}`: {e}"))?;
        out.insert(key, value);
    }
    Ok(out)
}

/// Every character outside a quoted string, with its byte offset and the bracket depth
/// before it. One scanner for comments, arrays, values and balance.
fn unquoted(s: &str) -> Vec<(usize, char, i32)> {
    let mut out = Vec::new();
    let (mut quote, mut escaped, mut depth) = (None::<char>, false, 0i32);
    for (i, ch) in s.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' && q == '"' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => {
                quote = Some(ch);
                continue;
            }
            _ => {}
        }
        out.push((i, ch, depth));
        match ch {
            '[' => depth += 1,
            ']' => depth -= 1,
            _ => {}
        }
    }
    out
}

fn strip_comment(line: &str) -> String {
    match unquoted(line).iter().find(|(_, c, _)| *c == '#') {
        Some((i, _, _)) => line[..*i].to_string(),
        None => line.to_string(),
    }
}

fn open_brackets(s: &str) -> i32 {
    unquoted(s).iter().fold(0, |d, (_, c, _)| match c {
        '[' => d + 1,
        ']' => d - 1,
        _ => d,
    })
}

fn parse_value(s: &str) -> Result<Lite, String> {
    if s == "true" || s == "false" {
        return Ok(Lite::Bool(s == "true"));
    }
    if s.starts_with('"') || s.starts_with('\'') {
        return Ok(Lite::Str(unquote(s)?));
    }
    if s.starts_with('[') {
        let inner = s.strip_prefix('[').and_then(|x| x.strip_suffix(']')).ok_or_else(|| "an array must end with `]`".to_string())?;
        let mut items = Vec::new();
        for item in split_items(inner) {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            if !(item.starts_with('"') || item.starts_with('\'')) {
                return Err(format!("array items must be quoted strings; `{item}` is not"));
            }
            items.push(unquote(item)?);
        }
        return Ok(Lite::List(items));
    }
    Err(format!("expected a quoted string, true/false or an array of strings, found `{s}`"))
}

/// Split an array body on top-level commas (a comma inside a string is part of the item).
fn split_items(inner: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, c, depth) in unquoted(inner) {
        if c == ',' && depth == 0 {
            out.push(inner[start..i].to_string());
            start = i + 1;
        }
    }
    out.push(inner[start..].to_string());
    out
}

fn unquote(s: &str) -> Result<String, String> {
    let s = s.trim();
    let quote = s.chars().next().ok_or_else(|| "empty value".to_string())?;
    if quote != '"' && quote != '\'' {
        return Err(format!("expected a quoted string, found `{s}`"));
    }
    let body = s.strip_prefix(quote).and_then(|x| x.strip_suffix(quote)).ok_or_else(|| format!("`{s}` is not a closed {quote}…{quote} string"))?;
    if quote == '\'' {
        return Ok(body.to_string());
    }
    let mut out = String::with_capacity(body.len());
    let mut escaped = false;
    for ch in body.chars() {
        if escaped {
            out.push(match ch {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                other => other,
            });
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else {
            out.push(ch);
        }
    }
    Ok(out)
}

fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn toml_list(v: &[String]) -> String {
    let parts: Vec<String> = v.iter().map(|s| quote(s)).collect();
    format!("[{}]", parts.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_shipped_table_is_consistent() {
        let mut seen: Vec<&str> = Vec::new();
        for m in builtins() {
            assert!(!m.name.is_empty() && (m.kind, m.source) == (Kind::Tool, Source::Builtin), "{m:?}");
            assert!(!seen.contains(&m.name.as_str()), "duplicate row {}", m.name);
            seen.push(&m.name);
            let s = m.summary();
            assert!(!s.contains('\n') && s.contains(&m.name) && s.contains("builtin"), "{s}");
            // Every row either declares something or is a tool that genuinely touches nothing.
            if m.fs_read.is_empty() && m.fs_write.is_empty() && m.exec.is_empty() && m.net.is_empty() && m.secrets.is_empty() && m.tools.is_empty() {
                assert!(matches!(m.name.as_str(), "ask_user" | "spawn" | "read_terminal" | "close_terminal"), "{} declares nothing", m.name);
            }
        }
        assert!(builtins().len() >= 21, "every builtin tool needs a row");
        assert!(builtin("shell").is_some_and(|m| m.exec == ["*"] && m.destructive));
        assert!(builtin("web_fetch").is_some_and(|m| m.net == ["*"]));
        assert!(builtin("write").is_some_and(|m| m.fs_write == ["**"]));
        assert!(builtin("read").is_some_and(|m| m.fs_read == ["**"] && m.fs_write.is_empty()));
        assert!(builtin("nope").is_none() && builtin(" shell ").is_some(), "names are trimmed, not guessed");
    }

    #[test]
    fn globs_and_exec_and_net() {
        let pats = |v: &[&str]| strings(v);
        assert!(matches(&pats(&["*"]), "anything") && matches(&pats(&["apt-get install *"]), "apt-get install jq"));
        assert!(!matches(&pats(&["apt-get install *"]), "apt-get remove jq"));
        assert!(matches(&pats(&["*.github.com"]), "api.github.com") && !matches(&pats(&["*.github.com"]), "github.com"));
        assert!(matches(&pats(&["/home/me/proj/**"]), "/home/me/proj/src/main.rs") && !matches(&pats(&["/home/me/proj/**"]), "/home/me/other"));
        assert!(!matches(&pats(&["a/b/*"]), "a/b/c/d"), "* stays inside one segment");
        assert!(!matches(&pats(&[]), "x") && !matches(&pats(&["*"]), ""));

        let man = Manifest { exec: strings(&["apt-get install *", "cargo build"]), ..Default::default() };
        assert!(man.allows(&Request { exec: Some(&argv(&["apt-get", "install", "jq"])), ..Default::default() }).is_ok());
        assert!(man.allows(&Request { exec: Some(&argv(&["sh", "-c", "rm -rf /"])), ..Default::default() }).is_err());
        assert!(man.allows(&Request { exec: Some(&argv(&["cargo", "build", "--release"])), ..Default::default() }).is_ok(), "prefix");
        assert!(man.allows(&Request { exec: Some(&argv(&["cargo", "test"])), ..Default::default() }).is_err());
        assert!(man.allows(&Request { exec: Some(&argv(&["apt-get install jq"])), ..Default::default() }).is_ok(), "a shell line is split");
        assert!(man.allows(&Request { exec: Some(&argv(&["apt-get", "install jq"])), ..Default::default() }).is_err(), "element-wise");
        assert!(Manifest { exec: strings(&["*"]), ..Default::default() }.allows(&Request { exec: Some(&[]), ..Default::default() }).is_err());

        let public = Manifest { net: strings(&["*"]), ..Default::default() };
        let ok = |h: &str| public.allows(&Request { net: Some((h, 443)), ..Default::default() }).is_ok();
        assert!(ok("crates.io") && ok("93.184.216.34"));
        for h in ["127.0.0.1", "::1", "10.1.2.3", "169.254.169.254", "localhost", "box.local", "metadata.google.internal", "fileserver", "0x7f.1"] {
            assert!(!ok(h), "`*` must not cover {h}");
        }
        assert!(public.allows(&Request { net: Some(("127.0.0.1", 80)), ..Default::default() }).unwrap_err().contains("private"));
        let local = Manifest { net: strings(&["127.0.0.1:8080"]), ..Default::default() };
        assert!(local.allows(&Request { net: Some(("127.0.0.1", 8080)), ..Default::default() }).is_ok());
        assert!(local.allows(&Request { net: Some(("127.0.0.1", 80)), ..Default::default() }).is_err(), "the port is pinned");
        let gh = Manifest { net: strings(&["crates.io", "*.github.com"]), ..Default::default() };
        assert!(gh.allows(&Request { net: Some(("static.crates.io", 443)), ..Default::default() }).is_ok(), "subdomains follow host_rule");
        assert!(gh.allows(&Request { net: Some(("api.github.com", 443)), ..Default::default() }).is_ok());
        assert!(gh.allows(&Request { net: Some(("github.com", 443)), ..Default::default() }).is_err() && gh.allows(&Request { net: Some(("example.com", 443)), ..Default::default() }).is_err());
    }

    #[test]
    fn declarations_parse_liberally_and_name_bad_tokens() {
        let d = declared("notes", Kind::Skill, Source::ThirdParty, &strings(&["fs:read:/x/**", "fs:write:/x/out/**", "fs:rw:/y/**", "net:crates.io", "net:crates.io", "secret:TOKEN", "tool:read", "exec:git log *", "destructive:false", "destructive", " network:docs.rs , run:cargo test"])).unwrap();
        assert_eq!((d.fs_read.as_slice(), d.fs_write.as_slice()), (&["/x/**".to_string(), "/y/**".to_string()][..], &["/x/out/**".to_string(), "/y/**".to_string()][..]));
        assert_eq!((d.net.as_slice(), d.secrets.as_slice(), d.tools.as_slice(), d.exec.as_slice()), (&["crates.io".to_string(), "docs.rs".to_string()][..], &["TOKEN".to_string()][..], &["read".to_string()][..], &["git log *".to_string(), "cargo test".to_string()][..]));
        assert!(d.destructive, "the last `destructive` token wins");
        assert!(!declared("q", Kind::Tool, Source::Operator, &strings(&["destructive:false"])).unwrap().destructive);
        for (caps, needle) in [("net", "`net`"), ("glob:**", "glob:**"), ("fs:read", "fs:read"), ("fs:chmod:**", "chmod"), ("destructive:maybe", "maybe")] {
            let err = declared("bad", Kind::Tool, Source::Operator, &[caps.to_string()]).unwrap_err();
            assert!(err.contains(needle), "{err}");
        }
        assert!(declared(" ", Kind::Tool, Source::Operator, &[]).is_err());
        assert!(declared("q", Kind::Tool, Source::Operator, &strings(&["secret:TOKEN"])).unwrap().allows(&Request { secret: Some("TOKEN"), ..Default::default() }).is_ok());
        assert!(declared("q", Kind::Tool, Source::Operator, &strings(&["secret:TOKEN"])).unwrap().allows(&Request { secret: Some("OTHER"), ..Default::default() }).is_err());
    }

    #[test]
    fn toml_round_trip_and_errors() {
        let text = r#"
# a third-party skill
name = "release-notes"
kind = "skill"
source = "third-party"
fs_read = ["/home/me/proj/**",
           "**/*.md",  # multi-line arrays are fine
]
exec = []
net = ["crates.io", "docs.rs"]
capabilities = ["tool:read"]
"#;
        let m = from_toml(text).unwrap();
        assert_eq!((m.name.as_str(), m.kind, m.source), ("release-notes", Kind::Skill, Source::ThirdParty));
        assert_eq!(m.fs_read, ["/home/me/proj/**", "**/*.md"]);
        assert_eq!(m.tools, ["read"]);
        assert!(!m.destructive);
        assert_eq!(from_toml(&m.to_toml()).unwrap(), m, "to_toml/from_toml round trip");
        let d = from_toml("name = \"x\"\n").unwrap();
        assert_eq!((d.kind, d.source, d.destructive), (Kind::Tool, Source::ThirdParty, false), "an unlabelled file is a third-party tool");
        for (bad, needle) in [
            ("kind = \"skill\"\n", "no `name`"),
            ("name = 1\n", "`name`"),
            ("name = \"x\"\nkind = \"gadget\"\n", "gadget"),
            ("name = \"x\"\nsource = \"moon\"\n", "moon"),
            ("name = \"x\"\nextra = \"y\"\n", "extra"),
            ("name = \"x\"\n[table]\n", "flat table"),
            ("name = \"x\"\nname = \"y\"\n", "twice"),
            ("name = \"x\"\nnet = [1]\n", "quoted"),
            ("name = \"x\"\ndestructive = \"yes\"\n", "true or false"),
            ("name = \"x\"\nfs_read = [\"a\"\n", "never closed"),
        ] {
            let err = from_toml(bad).unwrap_err();
            assert!(err.contains(needle), "{bad:?} → {err}");
        }
    }

    #[test]
    fn builtins_cannot_be_shadowed_and_widening_is_recorded() {
        register(Manifest { name: "shell".into(), net: strings(&["*.example.com"]), fs_write: strings(&["**"]), exec: strings(&["*"]), source: Source::ThirdParty, ..Default::default() });
        assert_eq!(lookup("shell").as_ref(), builtin("shell"), "rule 5: the shipped row wins");
        assert!(widenings_for("shell").is_empty());

        let skill = "probe-skill-rugpull";
        register(declared(skill, Kind::Skill, Source::ThirdParty, &strings(&["net:crates.io"])).unwrap());
        assert_eq!(lookup(skill).unwrap().net, ["crates.io"]);
        register(declared(skill, Kind::Skill, Source::ThirdParty, &strings(&["net:crates.io"])).unwrap());
        assert!(widenings_for(skill).is_empty(), "idempotent");
        register(declared(skill, Kind::Skill, Source::ThirdParty, &strings(&["net:crates.io", "net:example.com"])).unwrap());
        let w = widenings_for(skill);
        assert_eq!(w.len(), 1, "{w:?}");
        assert_eq!(w[0].added, ["net:example.com"]);
        assert_eq!(lookup(skill).unwrap().net, ["crates.io", "example.com"]);
        register(declared(skill, Kind::Skill, Source::ThirdParty, &strings(&["net:crates.io"])).unwrap());
        assert_eq!(lookup(skill).unwrap().net, ["crates.io", "example.com"], "narrowing keeps the reviewed scope");
        assert!(lookup("probe-skill-never-registered").is_none());
    }

    #[test]
    fn a_capability_never_authorises_tier_three() {
        let quiet = Manifest { exec: strings(&["*"]), ..Default::default() };
        assert!(quiet.allows(&Request { destructive: true, ..Default::default() }).unwrap_err().contains("destructive"));
        let loud = Manifest { destructive: true, ..quiet.clone() };
        assert!(loud.allows(&Request { destructive: true, ..Default::default() }).is_ok(), "it may ask");
        register(Manifest { name: "probe-tier3".into(), source: Source::Operator, ..loud });
        let err = check("probe-tier3", &Request { destructive: true, ..Default::default() }).unwrap_err();
        assert!(err.contains("tier 3") && err.contains("operator"), "{err}");
        let tier3 = argv(&["aws", "s3", "rm", "s3://prod-backups", "--recursive"]);
        assert!(check("probe-tier3", &Request { exec: Some(&tier3), ..Default::default() }).unwrap_err().contains("tier 3"));
        assert!(assess("probe-tier3", &Request { fs_write: Some("/mnt/backups/db.dump"), ..Default::default() }).tier.is_irreversible(), "a backup path is tier 3");
        assert!(check("probe-tier3", &Request { fs_write: Some("/mnt/backups/db.dump"), ..Default::default() }).is_err());
        assert!(check("shell", &Request { exec: Some(&argv(&["cargo", "test"])), ..Default::default() }).is_ok(), "ordinary work is untouched");
        assert!(check("ask_user", &Request::default()).is_ok());
        let err = check("acme-repo-helper", &Request::default()).unwrap_err();
        assert!(err.starts_with("no capability manifest for `acme-repo-helper`") && err.contains("declare") && err.contains("A5"), "{err}");
    }
}
