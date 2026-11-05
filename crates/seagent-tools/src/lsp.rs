//! Language Server Protocol integration (Hermes `agent/lsp`). Real language servers run
//! as child processes speaking JSON-RPC over stdio; after `write` / `edit` / `patch` the
//! file's diagnostics are collected and the ones the edit *introduced* (pre-edit text is
//! the baseline) are appended to the tool output as a `<diagnostics>` block.
//!
//! Gated like upstream: only files inside a git worktree, servers that may load project
//! code only in trusted workspaces (the session workspace's worktree or
//! `lsp.trusted_workspaces`), a server that fails to start is not retried (unless
//! `broken_retry_seconds`), idle servers are reaped after `idle_timeout`.
//! Auto-installing servers is not done: seagent never downloads binaries on its own.

use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

pub const INITIALIZE_TIMEOUT: Duration = Duration::from_secs(45);
pub const DIAGNOSTICS_DOCUMENT_WAIT: f64 = 5.0;
pub const DIAGNOSTICS_FULL_WAIT: f64 = 10.0;
const DIAGNOSTICS_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const PUSH_DEBOUNCE: Duration = Duration::from_millis(150);
pub const DEFAULT_IDLE_TIMEOUT: f64 = 600.0;
pub const MIN_IDLE_TIMEOUT: f64 = 30.0;
const MAX_TRACKED_FILES: usize = 64;
const MAX_PER_FILE: usize = 20;
const MAX_TOTAL_CHARS: usize = 4000;
const MAX_MESSAGE_CHARS: usize = 300;
const MAX_FIELD_CHARS: usize = 80;
const MAX_WALK: usize = 64;

// ───────────────────────── config ─────────────────────────

/// `[lsp]` (defaults from Hermes `LSPService.create_from_config`).
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct LspConfig {
    /// Default true; still gated on a git worktree.
    pub enabled: bool,
    /// "document" (wait for this file's diagnostics) or "full" (longer settle window).
    pub wait_mode: String,
    /// Seconds to wait for diagnostics after an edit (default 5).
    pub wait_timeout: Option<f64>,
    /// "auto" | "manual" | "off". seagent never auto-installs; "off" disables PATH lookup too.
    pub install_strategy: String,
    /// Seconds before an idle server is shut down (0 = never, minimum 30).
    pub idle_timeout: f64,
    /// Retry a server that failed to start after this many seconds (0 = never).
    pub broken_retry_seconds: f64,
    /// Extra wait budget for a server's first (cold) diagnostics.
    pub warmup_timeout: f64,
    /// Glob patterns of project roots never served.
    pub exclude_roots: Vec<String>,
    /// Directories whose checkouts may load project code (interpreters, SDKs).
    pub trusted_workspaces: Vec<String>,
    /// Per-server overrides / custom servers.
    pub servers: BTreeMap<String, ServerOverride>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ServerOverride {
    pub command: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub initialization_options: Option<Value>,
    pub disabled: bool,
    /// With `command`, declares a custom server (claims these extensions first).
    pub extensions: Vec<String>,
    pub root_markers: Vec<String>,
    pub description: String,
    pub language_id: String,
}

impl Default for LspConfig {
    fn default() -> Self {
        LspConfig {
            enabled: true,
            wait_mode: "document".into(),
            wait_timeout: None,
            install_strategy: "auto".into(),
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            broken_retry_seconds: 0.0,
            warmup_timeout: 0.0,
            exclude_roots: vec![],
            trusted_workspaces: vec![],
            servers: BTreeMap::new(),
        }
    }
}

impl LspConfig {
    pub fn from_json(v: &Value) -> Result<LspConfig, String> {
        if v.is_null() || v.as_object().is_some_and(|o| o.is_empty()) {
            return Ok(LspConfig::default());
        }
        let mut c: LspConfig = serde_json::from_value(v.clone()).map_err(|e| format!("[lsp]: {e}"))?;
        if !matches!(c.wait_mode.as_str(), "document" | "full") {
            return Err(format!("lsp.wait_mode `{}`: use \"document\" or \"full\"", c.wait_mode));
        }
        if !matches!(c.install_strategy.as_str(), "auto" | "manual" | "off") {
            return Err(format!("lsp.install_strategy `{}`: use auto, manual or off", c.install_strategy));
        }
        if c.idle_timeout > 0.0 && c.idle_timeout < MIN_IDLE_TIMEOUT {
            c.idle_timeout = MIN_IDLE_TIMEOUT;
        }
        for (id, s) in &c.servers {
            if !s.extensions.is_empty() && s.command.is_empty() {
                return Err(format!("lsp.servers.{id}: a custom server needs command = [bin, args…] with extensions"));
            }
        }
        Ok(c)
    }
    pub fn wait(&self) -> f64 {
        self.wait_timeout.unwrap_or(if self.wait_mode == "full" { DIAGNOSTICS_FULL_WAIT } else { DIAGNOSTICS_DOCUMENT_WAIT })
    }
}

// ───────────────────────── server registry ─────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct ServerDef {
    pub id: String,
    pub extensions: Vec<String>,
    pub description: String,
    /// Binaries tried on PATH, in order.
    pub which: Vec<String>,
    pub args: Vec<String>,
    /// Root markers; empty = the workspace root.
    pub markers: Vec<String>,
    /// Marker files that disable the server for a file (deno for typescript).
    pub excludes: Vec<String>,
    pub base_init: Value,
    /// Safe in an untrusted checkout (loads no project code).
    pub untrusted_safe: bool,
    pub language_id: String,
}

const JS_MARKERS: &[&str] = &["package-lock.json", "bun.lockb", "bun.lock", "pnpm-lock.yaml", "yarn.lock", "package.json", "tsconfig.json"];

fn sv(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

#[allow(clippy::too_many_arguments)]
fn def(id: &str, exts: &[&str], desc: &str, which: &[&str], args: &[&str], markers: &[&str], init: Value, safe: bool) -> ServerDef {
    ServerDef { id: id.into(), extensions: sv(exts), description: desc.into(), which: if which.is_empty() { vec![id.into()] } else { sv(which) }, args: sv(args), markers: sv(markers), excludes: vec![], base_init: init, untrusted_safe: safe, language_id: String::new() }
}

/// The built-in registry (Hermes `agent/lsp/servers.py::SERVERS`, same order).
pub fn builtin_servers() -> Vec<ServerDef> {
    let n = Value::Null;
    let mut ts = def("typescript", &[".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"], "JavaScript/TypeScript — typescript-language-server", &["typescript-language-server"], &["--stdio"], JS_MARKERS, n.clone(), true);
    ts.excludes = sv(&["deno.json", "deno.jsonc"]);
    let mut v = vec![
        def("pyright", &[".py", ".pyi"], "Python — Microsoft pyright", &["pyright-langserver", "pyright"], &["--stdio"], &["pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "Pipfile", "pyrightconfig.json"], n.clone(), true),
        ts,
        def("vue-language-server", &[".vue"], "Vue.js — @vue/language-server", &[], &["--stdio"], JS_MARKERS, json!({"vue": {"hybridMode": false}}), false),
        def("svelte-language-server", &[".svelte"], "Svelte — svelte-language-server", &["svelteserver", "svelte-language-server"], &["--stdio"], JS_MARKERS, n.clone(), true),
        def("astro-language-server", &[".astro"], "Astro — @astrojs/language-server", &["astro-ls", "astro-language-server"], &["--stdio"], JS_MARKERS, n.clone(), false),
        def("gopls", &[".go"], "Go — gopls", &[], &[], &["go.work", "go.mod", "go.sum"], n.clone(), false),
        def("rust-analyzer", &[".rs"], "Rust — rust-analyzer", &[], &[], &["Cargo.toml", "Cargo.lock"], n.clone(), false),
        def("clangd", &[".c", ".cpp", ".cc", ".cxx", ".h", ".hh", ".hpp", ".hxx"], "C/C++ — clangd", &[], &["--background-index", "--clang-tidy"], &["compile_commands.json", "compile_flags.txt", ".clangd"], n.clone(), true),
        def("bash-language-server", &[".sh", ".bash", ".zsh", ".ksh"], "Bash — bash-language-server", &[], &["start"], &[], n.clone(), true),
        def("yaml-language-server", &[".yaml", ".yml"], "YAML — yaml-language-server", &[], &["--stdio"], &[], n.clone(), true),
        def("lua-language-server", &[".lua"], "Lua — lua-language-server", &[], &[], &[".luarc.json", ".luarc.jsonc", ".luacheckrc", ".stylua.toml", "stylua.toml", "selene.toml", "selene.yml"], n.clone(), false),
        def("laravel-lsp", &[".blade.php"], "Laravel Blade — laravel-lsp (manual: composer global require laravel/lsp)", &[], &["lsp"], &["artisan", "composer.json", "composer.lock"], n.clone(), false),
        def("intelephense", &[".php"], "PHP — intelephense", &[], &["--stdio"], &["composer.json", "composer.lock", ".php-version"], json!({"telemetry": {"enabled": false}}), true),
        def("ocaml-lsp", &[".ml", ".mli"], "OCaml — ocaml-lsp", &["ocamllsp"], &[], &["dune-project", "dune-workspace", ".merlin", "opam"], n.clone(), false),
        def("dockerfile-ls", &[".dockerfile", "Dockerfile"], "Dockerfile — dockerfile-language-server-nodejs", &["docker-langserver"], &["--stdio"], &[], n.clone(), true),
        def("terraform-ls", &[".tf", ".tfvars"], "Terraform — terraform-ls", &[], &["serve"], &[".terraform.lock.hcl", "terraform.tfstate"], json!({"experimentalFeatures": {"prefillRequiredFields": true, "validateOnSave": true}}), false),
        def("dart", &[".dart"], "Dart — built-in language server", &[], &["language-server", "--lsp"], &["pubspec.yaml", "analysis_options.yaml"], n.clone(), false),
        def("haskell-language-server", &[".hs", ".lhs"], "Haskell — haskell-language-server", &["haskell-language-server-wrapper", "haskell-language-server"], &["--lsp"], &["stack.yaml", "cabal.project", "hie.yaml"], n.clone(), false),
        def("julia", &[".jl"], "Julia — LanguageServer.jl", &[], &["--startup-file=no", "--history-file=no", "-e", "using LanguageServer; runserver()"], &["Project.toml", "Manifest.toml"], n.clone(), false),
        def("clojure-lsp", &[".clj", ".cljs", ".cljc", ".edn"], "Clojure — clojure-lsp", &[], &["listen"], &["deps.edn", "project.clj", "shadow-cljs.edn", "bb.edn", "build.boot"], n.clone(), false),
        def("nixd", &[".nix"], "Nix — nixd", &[], &[], &["flake.nix"], n.clone(), false),
        def("zls", &[".zig", ".zon"], "Zig — zls", &[], &[], &["build.zig"], n.clone(), false),
        def("gleam", &[".gleam"], "Gleam — built-in language server", &[], &["lsp"], &["gleam.toml"], n.clone(), false),
        def("elixir-ls", &[".ex", ".exs"], "Elixir — elixir-ls", &["elixir-ls", "language_server.sh"], &[], &["mix.exs", "mix.lock"], n.clone(), false),
        def("prisma", &[".prisma"], "Prisma — built-in language server", &[], &["language-server"], &["schema.prisma", "prisma/schema.prisma"], n.clone(), false),
        def("kotlin-language-server", &[".kt", ".kts"], "Kotlin — kotlin-language-server", &[], &[], &["settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts", "pom.xml"], n.clone(), false),
        def("jdtls", &[".java"], "Java — Eclipse JDT Language Server", &[], &[], &["pom.xml", "build.gradle", "build.gradle.kts", ".project", ".classpath", "settings.gradle"], n.clone(), false),
        def("powershell", &[".ps1", ".psm1", ".psd1"], "PowerShell — PowerShellEditorServices (manual bundle)", &["pwsh"], &[], &["PSScriptAnalyzerSettings.psd1"], n, false),
    ];
    // Hermes resolves nixd's root from flake.nix only (no workspace fallback difference here).
    v.iter_mut().for_each(|s| s.extensions.iter_mut().for_each(|e| *e = e.to_lowercase().replace("dockerfile", "Dockerfile").replace(".Dockerfile", ".dockerfile")));
    v
}

/// LSP languageId by extension (Hermes `LANGUAGE_BY_EXT`).
pub fn language_id(path: &Path) -> &'static str {
    let key = ext_key(path);
    const MAP: &[(&str, &[&str])] = &[
        ("python", &[".py", ".pyi"]), ("typescript", &[".ts", ".mts", ".cts"]), ("typescriptreact", &[".tsx"]),
        ("javascript", &[".js", ".mjs", ".cjs"]), ("javascriptreact", &[".jsx"]), ("vue", &[".vue"]), ("svelte", &[".svelte"]), ("astro", &[".astro"]),
        ("go", &[".go"]), ("rust", &[".rs"]), ("ruby", &[".rb", ".rake", ".gemspec", ".ru"]), ("c", &[".c", ".h"]),
        ("cpp", &[".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"]), ("csharp", &[".cs", ".csx"]), ("fsharp", &[".fs", ".fsi", ".fsx"]),
        ("swift", &[".swift"]), ("java", &[".java"]), ("kotlin", &[".kt", ".kts"]), ("yaml", &[".yaml", ".yml"]), ("json", &[".json"]),
        ("jsonc", &[".jsonc"]), ("lua", &[".lua"]), ("php", &[".php"]), ("blade", &[".blade.php"]), ("prisma", &[".prisma"]), ("dart", &[".dart"]),
        ("ocaml", &[".ml", ".mli"]), ("shellscript", &[".sh", ".bash", ".zsh"]), ("terraform", &[".tf", ".tfvars"]), ("latex", &[".tex"]),
        ("bibtex", &[".bib"]), ("gleam", &[".gleam"]), ("clojure", &[".clj", ".cljc", ".edn"]), ("clojurescript", &[".cljs"]), ("nix", &[".nix"]),
        ("typst", &[".typ", ".typc"]), ("haskell", &[".hs", ".lhs"]), ("julia", &[".jl"]), ("elixir", &[".ex", ".exs"]), ("zig", &[".zig", ".zon"]),
        ("dockerfile", &[".dockerfile", "Dockerfile"]), ("powershell", &[".ps1", ".psm1", ".psd1"]),
    ];
    MAP.iter().find(|(_, exts)| exts.contains(&key.as_str())).map(|(l, _)| *l).unwrap_or("plaintext")
}

/// Lower-cased extension (compound `.blade.php` first), or the basename for extensionless files.
fn ext_key(path: &Path) -> String {
    let base = path.file_name().map(|b| b.to_string_lossy().to_string()).unwrap_or_default();
    let lower = base.to_lowercase();
    if lower.ends_with(".blade.php") {
        return ".blade.php".into();
    }
    match lower.rfind('.') {
        Some(i) if i > 0 => lower[i..].to_string(),
        _ => base,
    }
}

/// Config-declared servers first (they may claim an extension), then the built-ins.
pub fn all_servers(cfg: &LspConfig) -> Vec<ServerDef> {
    let builtin = builtin_servers();
    let mut out: Vec<ServerDef> = cfg
        .servers
        .iter()
        .filter(|(id, s)| !s.extensions.is_empty() && !s.command.is_empty() && !builtin.iter().any(|b| &b.id == *id))
        .map(|(id, s)| ServerDef {
            id: id.clone(),
            extensions: s.extensions.iter().map(|e| if e.starts_with('.') { e.to_lowercase() } else { e.clone() }).collect(),
            description: if s.description.is_empty() { format!("{id} — custom (lsp.servers)") } else { s.description.clone() },
            which: vec![s.command[0].clone()],
            args: s.command[1..].to_vec(),
            markers: s.root_markers.clone(),
            excludes: vec![],
            base_init: Value::Null,
            untrusted_safe: false,
            language_id: s.language_id.clone(),
        })
        .collect();
    out.extend(builtin);
    out
}

pub fn server_for<'a>(servers: &'a [ServerDef], path: &Path) -> Option<&'a ServerDef> {
    let k = ext_key(path);
    servers.iter().find(|s| s.extensions.contains(&k))
}

/// First of `names` found on PATH (or an existing path).
pub fn which(names: &[String]) -> Option<PathBuf> {
    for n in names {
        let p = seagent_core::tool::expand_home(n);
        if p.components().count() > 1 {
            if p.is_file() {
                return Some(p);
            }
            continue;
        }
        for dir in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
            let c = dir.join(n);
            if c.is_file() && std::fs::metadata(&c).is_ok_and(|m| std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o111 != 0) {
                return Some(c);
            }
        }
    }
    None
}

/// Spawn command for `srv`: a config override → PATH lookup. None = binary not available.
pub fn command_for(cfg: &LspConfig, srv: &ServerDef) -> Option<Vec<String>> {
    if cfg.install_strategy == "off" {
        return None;
    }
    if let Some(o) = cfg.servers.get(&srv.id).filter(|o| !o.command.is_empty()) {
        let bin = which(&o.command[..1])?;
        let mut c = vec![bin.to_string_lossy().to_string()];
        c.extend(o.command[1..].iter().cloned());
        return Some(c);
    }
    let bin = which(&srv.which)?;
    let mut c = vec![bin.to_string_lossy().to_string()];
    c.extend(srv.args.iter().cloned());
    Some(c)
}

// ───────────────────────── workspace gate ─────────────────────────

/// Nearest ancestor holding `.git` (dir or file: worktrees count).
pub fn find_git_worktree(start: &Path) -> Option<PathBuf> {
    let mut cur = if start.is_file() || !start.exists() { start.parent()?.to_path_buf() } else { start.to_path_buf() };
    for _ in 0..MAX_WALK {
        if cur.join(".git").exists() {
            return Some(cur);
        }
        if !cur.pop() {
            return None;
        }
    }
    None
}

fn inside(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
}

/// Walk up from `start` to the first dir with a marker (stopping at `ceiling`); None when an
/// exclude marker is seen first. Directories with `__init__.py` are skipped (Python packages).
pub fn nearest_root(start: &Path, markers: &[String], excludes: &[String], ceiling: Option<&Path>) -> Option<PathBuf> {
    let mut cur = if start.is_file() || !start.exists() { start.parent()?.to_path_buf() } else { start.to_path_buf() };
    for _ in 0..MAX_WALK {
        if excludes.iter().any(|e| cur.join(e).exists()) {
            return None;
        }
        if !cur.join("__init__.py").exists() && markers.iter().any(|m| cur.join(m).exists()) {
            return Some(cur);
        }
        if ceiling.is_some_and(|c| c == cur) || !cur.pop() {
            return None;
        }
    }
    None
}

/// Project root for `file` under `srv`: marker walk bounded by the git worktree, falling
/// back to the worktree itself; None when an exclude marker disables the server.
pub fn project_root(srv: &ServerDef, file: &Path, worktree: &Path) -> Option<PathBuf> {
    if srv.markers.is_empty() {
        return Some(worktree.to_path_buf());
    }
    let ceiling = worktree.parent();
    match nearest_root(file, &srv.markers, &srv.excludes, ceiling) {
        Some(r) => Some(r),
        None if !srv.excludes.is_empty() && nearest_root(file, &srv.markers, &[], ceiling).is_some() => None,
        None => Some(worktree.to_path_buf()),
    }
}

fn glob_match(pat: &str, s: &str) -> bool {
    // `*` matches anything (including '/'), `?` one char — fnmatchcase semantics.
    fn rec(p: &[char], s: &[char]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some('*'), _) => rec(&p[1..], s) || (!s.is_empty() && rec(p, &s[1..])),
            (Some('?'), Some(_)) => rec(&p[1..], &s[1..]),
            (Some(a), Some(b)) if a == b => rec(&p[1..], &s[1..]),
            _ => false,
        }
    }
    let p: Vec<char> = pat.chars().collect();
    let s: Vec<char> = s.chars().collect();
    rec(&p, &s)
}

// ───────────────────────── JSON-RPC framing ─────────────────────────

pub fn encode(msg: &Value) -> Vec<u8> {
    let body = serde_json::to_vec(msg).unwrap_or_default();
    let mut out = format!("Content-Length: {}\r\n\r\n", body.len()).into_bytes();
    out.extend(body);
    out
}

/// Read one framed message; Ok(None) on EOF.
pub fn read_message(r: &mut impl BufRead) -> Result<Option<Value>, String> {
    let mut len: Option<usize> = None;
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            return Ok(None);
        }
        let l = line.trim_end();
        if l.is_empty() {
            if len.is_some() {
                break;
            }
            continue;
        }
        if let Some((k, v)) = l.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                len = Some(v.trim().parse().map_err(|_| format!("bad Content-Length `{}`", v.trim()))?);
            }
        }
    }
    let n = len.unwrap_or(0);
    if n > 64 * 1024 * 1024 {
        return Err("LSP message too large".into());
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).map_err(|e| e.to_string())?;
    serde_json::from_slice(&buf).map(Some).map_err(|e| format!("bad LSP JSON: {e}"))
}

pub fn file_uri(p: &Path) -> String {
    let mut s = String::from("file://");
    for b in p.to_string_lossy().bytes() {
        if b.is_ascii_alphanumeric() || b"/-._~".contains(&b) {
            s.push(b as char);
        } else {
            s.push_str(&format!("%{b:02X}"));
        }
    }
    s
}

// ───────────────────────── client ─────────────────────────

#[derive(Default)]
struct Shared {
    responses: HashMap<u64, Value>,
    /// uri → (diagnostics, version they were published for, arrival counter)
    pushes: HashMap<String, (Vec<Value>, Option<i64>, u64)>,
    push_seq: u64,
    closed: bool,
    stderr_tail: Vec<String>,
}

pub struct Client {
    pub server_id: String,
    pub root: PathBuf,
    child: Mutex<Child>,
    stdin: Arc<Mutex<ChildStdin>>,
    shared: Arc<(Mutex<Shared>, Condvar)>,
    next_id: AtomicU64,
    docs: Mutex<HashMap<String, (i64, Instant)>>,
    pull: bool,
    pub last_used: Mutex<Instant>,
}

impl Client {
    pub fn spawn(server_id: &str, command: &[String], root: &Path, env: &BTreeMap<String, String>, init: &Value) -> Result<Client, String> {
        let (bin, args) = command.split_first().ok_or("empty server command")?;
        let mut child = Command::new(bin)
            .args(args)
            .current_dir(root)
            .envs(env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("{server_id}: cannot start {bin}: {e}"))?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
        let stderr = child.stderr.take();
        let shared: Arc<(Mutex<Shared>, Condvar)> = Arc::new(Default::default());
        let stdin = Arc::new(Mutex::new(stdin));
        let client = Client { server_id: server_id.into(), root: root.to_path_buf(), child: Mutex::new(child), stdin, shared: shared.clone(), next_id: AtomicU64::new(1), docs: Mutex::new(HashMap::new()), pull: false, last_used: Mutex::new(Instant::now()) };
        if let Some(e) = stderr {
            let sh = shared.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(e).lines().map_while(Result::ok) {
                    let mut s = sh.0.lock().unwrap();
                    s.stderr_tail.push(line);
                    if s.stderr_tail.len() > 30 {
                        s.stderr_tail.remove(0);
                    }
                }
            });
        }
        // The reader answers server→client requests itself (same locked stdin as requests).
        let writer = client.stdin.clone();
        let sh = shared.clone();
        std::thread::spawn(move || {
            let mut r = BufReader::new(stdout);
            while let Ok(Some(msg)) = read_message(&mut r) {
                let method = msg.get("method").and_then(Value::as_str).map(str::to_string);
                match (method, msg.get("id")) {
                    (Some(m), Some(id)) => {
                        // Server request: answer what clients must, refuse the rest.
                        let reply = match m.as_str() {
                            "workspace/configuration" => {
                                let n = msg["params"]["items"].as_array().map(|a| a.len()).unwrap_or(1);
                                json!({"jsonrpc":"2.0","id":id,"result": vec![Value::Null; n]})
                            }
                            "window/workDoneProgress/create" | "client/registerCapability" | "client/unregisterCapability" | "window/showMessageRequest" | "workspace/diagnostic/refresh" => json!({"jsonrpc":"2.0","id":id,"result":null}),
                            "workspace/workspaceFolders" => json!({"jsonrpc":"2.0","id":id,"result":null}),
                            _ => json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":format!("method not found: {m}")}}),
                        };
                        let mut w = writer.lock().unwrap();
                        if w.write_all(&encode(&reply)).and_then(|_| w.flush()).is_err() {
                            break;
                        }
                    }
                    (Some(m), None) => {
                        if m == "textDocument/publishDiagnostics" {
                            let p = &msg["params"];
                            let uri = p["uri"].as_str().unwrap_or("").to_string();
                            let diags = p["diagnostics"].as_array().cloned().unwrap_or_default();
                            let mut s = sh.0.lock().unwrap();
                            s.push_seq += 1;
                            let seq = s.push_seq;
                            s.pushes.insert(uri, (diags, p["version"].as_i64(), seq));
                            sh.1.notify_all();
                        }
                    }
                    (None, Some(id)) => {
                        if let Some(id) = id.as_u64() {
                            let mut s = sh.0.lock().unwrap();
                            s.responses.insert(id, msg.clone());
                            sh.1.notify_all();
                        }
                    }
                    _ => {}
                }
            }
            let mut s = sh.0.lock().unwrap();
            s.closed = true;
            sh.1.notify_all();
        });
        let mut client = client;
        let deadline = Instant::now() + INITIALIZE_TIMEOUT;
        let folder = json!({"uri": file_uri(root), "name": root.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()});
        let params = json!({
            "processId": std::process::id(),
            "rootUri": file_uri(root),
            "rootPath": root.to_string_lossy(),
            "workspaceFolders": [folder],
            "initializationOptions": if init.is_null() { json!({}) } else { init.clone() },
            "capabilities": client_capabilities(),
            "clientInfo": {"name": "seagent", "version": env!("CARGO_PKG_VERSION")},
        });
        let result = client.request("initialize", params, deadline.saturating_duration_since(Instant::now())).map_err(|e| format!("{e}{}", client.stderr_hint()))?;
        client.pull = result["capabilities"].get("diagnosticProvider").is_some_and(|d| !d.is_null() && d != &json!(false));
        client.notify("initialized", json!({}))?;
        if !init.is_null() {
            client.notify("workspace/didChangeConfiguration", json!({"settings": init}))?;
        }
        Ok(client)
    }

    fn send(&self, msg: &Value) -> Result<(), String> {
        let mut w = self.stdin.lock().unwrap();
        w.write_all(&encode(msg)).and_then(|_| w.flush()).map_err(|e| format!("{}: write failed: {e}", self.server_id))
    }

    pub fn notify(&self, method: &str, params: Value) -> Result<(), String> {
        self.send(&json!({"jsonrpc":"2.0","method":method,"params":params}))
    }

    pub fn request(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, String> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))?;
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(v) = self.take_response(id, Duration::from_millis(100))? {
                return v;
            }
            if Instant::now() >= deadline {
                return Err(format!("{}: `{method}` timed out", self.server_id));
            }
        }
    }

    #[allow(clippy::type_complexity)]
    fn take_response(&self, id: u64, wait: Duration) -> Result<Option<Result<Value, String>>, String> {
        let (m, cv) = &*self.shared;
        let s = m.lock().unwrap();
        let (mut s, _) = cv.wait_timeout_while(s, wait, |s| !s.responses.contains_key(&id) && !s.closed).unwrap();
        if let Some(r) = s.responses.remove(&id) {
            return Ok(Some(match r.get("error") {
                Some(e) => Err(format!("{}: {}", self.server_id, e["message"].as_str().unwrap_or("error"))),
                None => Ok(r.get("result").cloned().unwrap_or(Value::Null)),
            }));
        }
        if s.closed {
            return Err(format!("{}: server exited{}", self.server_id, tail_hint(&s.stderr_tail)));
        }
        Ok(None)
    }

    fn stderr_hint(&self) -> String {
        tail_hint(&self.shared.0.lock().unwrap().stderr_tail)
    }

    pub fn is_running(&self) -> bool {
        !self.shared.0.lock().unwrap().closed
    }

    /// didOpen on first sight, didChange (full text) afterwards. Returns the new version.
    pub fn sync(&self, path: &Path, text: &str, lang: &str) -> Result<i64, String> {
        let uri = file_uri(path);
        let mut docs = self.docs.lock().unwrap();
        if docs.len() >= MAX_TRACKED_FILES && !docs.contains_key(&uri) {
            if let Some(old) = docs.iter().min_by_key(|(_, (_, t))| *t).map(|(u, _)| u.clone()) {
                docs.remove(&old);
                self.notify("textDocument/didClose", json!({"textDocument": {"uri": old}}))?;
            }
        }
        let version = match docs.get(&uri) {
            None => {
                self.notify("workspace/didChangeWatchedFiles", json!({"changes": [{"uri": uri, "type": 1}]}))?;
                self.notify("textDocument/didOpen", json!({"textDocument": {"uri": uri, "languageId": lang, "version": 0, "text": text}}))?;
                0
            }
            Some((v, _)) => {
                let v = v + 1;
                self.notify("workspace/didChangeWatchedFiles", json!({"changes": [{"uri": uri, "type": 2}]}))?;
                self.notify("textDocument/didChange", json!({"textDocument": {"uri": uri, "version": v}, "contentChanges": [{"text": text}]}))?;
                v
            }
        };
        docs.insert(uri.clone(), (version, Instant::now()));
        drop(docs);
        let _ = self.notify("textDocument/didSave", json!({"textDocument": {"uri": uri}}));
        *self.last_used.lock().unwrap() = Instant::now();
        Ok(version)
    }

    fn push_seq(&self) -> u64 {
        self.shared.0.lock().unwrap().push_seq
    }

    /// Diagnostics for `path` at `version`: pull when the server supports it, else wait for
    /// a publishDiagnostics newer than `after_seq` (version-tagged when the server sends one).
    pub fn diagnostics(&self, path: &Path, version: i64, after_seq: u64, wait: Duration, settle: bool) -> Option<Vec<Value>> {
        let uri = file_uri(path);
        if self.pull {
            if let Ok(r) = self.request("textDocument/diagnostic", json!({"textDocument": {"uri": uri}}), DIAGNOSTICS_REQUEST_TIMEOUT.min(wait.max(Duration::from_millis(200)))) {
                if let Some(items) = r.get("items").and_then(Value::as_array) {
                    return Some(items.clone());
                }
            }
        }
        let (m, cv) = &*self.shared;
        let deadline = Instant::now() + wait;
        let mut s = m.lock().unwrap();
        loop {
            let fresh = s.pushes.get(&uri).filter(|(_, v, seq)| *seq > after_seq && v.is_none_or(|v| v >= version)).map(|(d, _, seq)| (d.clone(), *seq));
            if let Some((d, seq)) = fresh {
                // Debounce: servers often publish twice (syntax, then semantic).
                let settle_for = if settle { Duration::from_millis(600) } else { PUSH_DEBOUNCE };
                let until = (Instant::now() + settle_for).min(deadline);
                let (s2, _) = cv.wait_timeout_while(s, until.saturating_duration_since(Instant::now()), |s| s.pushes.get(&uri).is_none_or(|(_, _, q)| *q == seq) && !s.closed).unwrap();
                return s2.pushes.get(&uri).map(|(d, _, _)| d.clone()).or(Some(d));
            }
            if s.closed {
                return None;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            s = cv.wait_timeout(s, left).unwrap().0;
        }
    }

    pub fn shutdown(&self) {
        if self.is_running() {
            let _ = self.request("shutdown", Value::Null, Duration::from_secs(2));
            let _ = self.notify("exit", Value::Null);
        }
        let mut c = self.child.lock().unwrap();
        let until = Instant::now() + Duration::from_secs(1);
        while Instant::now() < until {
            if let Ok(Some(_)) = c.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = c.kill();
        let _ = c.wait();
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let mut c = self.child.lock().unwrap();
        if let Ok(None) = c.try_wait() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn tail_hint(tail: &[String]) -> String {
    if tail.is_empty() {
        String::new()
    } else {
        format!(" (stderr: {})", tail.iter().rev().take(3).rev().cloned().collect::<Vec<_>>().join(" | "))
    }
}

fn client_capabilities() -> Value {
    json!({
        "window": {"workDoneProgress": true},
        "workspace": {"configuration": true, "workspaceFolders": true, "didChangeWatchedFiles": {"dynamicRegistration": true}, "diagnostics": {"refreshSupport": false}},
        "textDocument": {
            "synchronization": {"dynamicRegistration": false, "didOpen": true, "didChange": true, "didSave": true, "willSave": false, "willSaveWaitUntil": false},
            "publishDiagnostics": {"relatedInformation": true, "tagSupport": {"valueSet": [1, 2]}, "versionSupport": true, "codeDescriptionSupport": true, "dataSupport": false},
            "diagnostic": {"dynamicRegistration": false, "relatedDocumentSupport": false}
        }
    })
}

// ───────────────────────── reporting ─────────────────────────

fn sanitize(v: &Value, limit: usize) -> String {
    let raw = match v {
        Value::Null => return String::new(),
        Value::String(s) => s.clone(),
        o => o.to_string(),
    };
    let one: String = raw.replace(['\r', '\n'], " ").chars().filter(|c| *c == ' ' || !c.is_control()).collect();
    let cut: String = one.trim().chars().take(limit).collect();
    cut.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

pub fn format_diagnostic(d: &Value) -> String {
    let sev = match d["severity"].as_u64().unwrap_or(1) {
        2 => "WARN",
        3 => "INFO",
        4 => "HINT",
        _ => "ERROR",
    };
    let start = &d["range"]["start"];
    let line = start["line"].as_u64().unwrap_or(0) + 1;
    let col = start["character"].as_u64().unwrap_or(0) + 1;
    let msg = sanitize(&d["message"], MAX_MESSAGE_CHARS);
    let code = sanitize(&d["code"], MAX_FIELD_CHARS);
    let source = sanitize(&d["source"], MAX_FIELD_CHARS);
    format!("{sev} [{line}:{col}] {msg}{}{}", if code.is_empty() { String::new() } else { format!(" [{code}]") }, if source.is_empty() { String::new() } else { format!(" ({source})") })
}

/// `<diagnostics file=…>` block of errors (severity 1); "" when none.
pub fn report_for_file(file: &str, diags: &[Value]) -> String {
    let errs: Vec<&Value> = diags.iter().filter(|d| d["severity"].as_u64().unwrap_or(1) == 1).collect();
    if errs.is_empty() {
        return String::new();
    }
    let mut body = errs.iter().take(MAX_PER_FILE).map(|d| format_diagnostic(d)).collect::<Vec<_>>().join("\n");
    if errs.len() > MAX_PER_FILE {
        body.push_str(&format!("\n... and {} more", errs.len() - MAX_PER_FILE));
    }
    let safe = file.replace('&', "&amp;").replace('"', "&quot;").replace('<', "&lt;").replace('>', "&gt;");
    let mut out = format!("<diagnostics file=\"{safe}\">\n{body}\n</diagnostics>");
    if out.len() > MAX_TOTAL_CHARS {
        out = format!("{}\n[… diagnostics elided]\n</diagnostics>", crate::util::truncate_str(&out, MAX_TOTAL_CHARS - 40));
    }
    out
}

fn diag_key(d: &Value) -> String {
    format!("{}\u{1f}{}\u{1f}{}\u{1f}{}", d["severity"].as_u64().unwrap_or(1), d["message"].as_str().unwrap_or(""), d["code"], d["source"].as_str().unwrap_or(""))
}

/// Diagnostics in `post` not present in `pre` (multiset by severity/message/code/source; line moves ignored).
pub fn delta(pre: &[Value], post: &[Value]) -> Vec<Value> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for d in pre {
        *counts.entry(diag_key(d)).or_default() += 1;
    }
    post.iter()
        .filter(|d| match counts.get_mut(&diag_key(d)) {
            Some(n) if *n > 0 => {
                *n -= 1;
                false
            }
            _ => true,
        })
        .cloned()
        .collect()
}

// ───────────────────────── service ─────────────────────────

pub struct Service {
    pub cfg: LspConfig,
    servers: Vec<ServerDef>,
    clients: Mutex<HashMap<(String, PathBuf), Arc<Client>>>,
    broken: Mutex<HashMap<(String, PathBuf), (Instant, String)>>,
    untrusted_skipped: Mutex<HashSet<(String, PathBuf)>>,
    /// Session workspaces' worktrees: trusted (the operator opened them).
    operator_roots: Mutex<HashSet<PathBuf>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Skip {
    Disabled,
    NoServer,
    NotGit,
    Excluded,
    Untrusted(String),
    Broken(String),
    Missing(String),
}

impl Service {
    pub fn new(cfg: LspConfig) -> Service {
        let servers = all_servers(&cfg);
        Service { cfg, servers, clients: Default::default(), broken: Default::default(), untrusted_skipped: Default::default(), operator_roots: Default::default() }
    }

    pub fn servers(&self) -> &[ServerDef] {
        &self.servers
    }

    fn trusted(&self, root: &Path) -> bool {
        if self.cfg.trusted_workspaces.iter().any(|t| inside(root, &seagent_core::tool::expand_home(t))) {
            return true;
        }
        find_git_worktree(root).is_some_and(|w| self.operator_roots.lock().unwrap().contains(&w))
    }

    /// The server, project root and spawn command for a file, or why it is skipped.
    pub fn plan(&self, workspace: &Path, file: &Path) -> Result<(ServerDef, PathBuf, Vec<String>), Skip> {
        if !self.cfg.enabled {
            return Err(Skip::Disabled);
        }
        let srv = server_for(&self.servers, file).ok_or(Skip::NoServer)?;
        if self.cfg.servers.get(&srv.id).is_some_and(|o| o.disabled) {
            return Err(Skip::Disabled);
        }
        if let Some(w) = find_git_worktree(workspace) {
            self.operator_roots.lock().unwrap().insert(w);
        }
        let worktree = match find_git_worktree(workspace).filter(|w| inside(file, w)) {
            Some(w) => w,
            None => find_git_worktree(file).ok_or(Skip::NotGit)?,
        };
        let root = project_root(srv, file, &worktree).ok_or(Skip::NoServer)?;
        let rs = root.to_string_lossy();
        if self.cfg.exclude_roots.iter().any(|p| glob_match(p, &rs) || glob_match(&format!("{}/*", p.trim_end_matches('/')), &rs)) {
            return Err(Skip::Excluded);
        }
        if !srv.untrusted_safe && !self.trusted(&root) {
            self.untrusted_skipped.lock().unwrap().insert((srv.id.clone(), root.clone()));
            return Err(Skip::Untrusted(srv.id.clone()));
        }
        let key = (srv.id.clone(), root.clone());
        if let Some((at, why)) = self.broken.lock().unwrap().get(&key).cloned() {
            let retry = self.cfg.broken_retry_seconds;
            if retry <= 0.0 || at.elapsed().as_secs_f64() < retry {
                return Err(Skip::Broken(why));
            }
        }
        let cmd = command_for(&self.cfg, srv).ok_or_else(|| Skip::Missing(srv.id.clone()))?;
        Ok((srv.clone(), root, cmd))
    }

    fn client(&self, srv: &ServerDef, root: &Path, cmd: &[String]) -> Result<(Arc<Client>, bool), String> {
        let key = (srv.id.clone(), root.to_path_buf());
        if let Some(c) = self.clients.lock().unwrap().get(&key).filter(|c| c.is_running()).cloned() {
            return Ok((c, false));
        }
        let o = self.cfg.servers.get(&srv.id);
        let env = o.map(|o| o.env.clone()).unwrap_or_default();
        let mut init = srv.base_init.clone();
        if let Some(extra) = o.and_then(|o| o.initialization_options.clone()) {
            match (&mut init, extra) {
                (Value::Object(a), Value::Object(b)) => a.extend(b),
                (i, b) => *i = b,
            }
        }
        match Client::spawn(&srv.id, cmd, root, &env, &init) {
            Ok(c) => {
                let c = Arc::new(c);
                self.clients.lock().unwrap().insert(key.clone(), c.clone());
                self.broken.lock().unwrap().remove(&key);
                Ok((c, true))
            }
            Err(e) => {
                self.broken.lock().unwrap().insert(key, (Instant::now(), e.clone()));
                Err(e)
            }
        }
    }

    /// New errors `post` introduces over `pre` (None = new file), as a report block.
    /// Never fails the write: problems come back as "" (and are remembered as broken).
    pub fn check_edit(&self, workspace: &Path, file: &Path, pre: Option<&str>, post: &str) -> String {
        let Ok((srv, root, cmd)) = self.plan(workspace, file) else { return String::new() };
        let Ok((client, fresh)) = self.client(&srv, &root, &cmd) else { return String::new() };
        let lang = if srv.language_id.is_empty() { language_id(file) } else { &srv.language_id };
        let mut wait = Duration::from_secs_f64(self.cfg.wait().max(0.1));
        if fresh && self.cfg.warmup_timeout > self.cfg.wait() {
            wait = Duration::from_secs_f64(self.cfg.warmup_timeout);
        }
        let settle = self.cfg.wait_mode == "full";
        let baseline = match pre {
            Some(pre) => {
                let seq = client.push_seq();
                match client.sync(file, pre, lang) {
                    Ok(v) => client.diagnostics(file, v, seq, wait, settle).unwrap_or_default(),
                    Err(_) => vec![],
                }
            }
            None => vec![],
        };
        let seq = client.push_seq();
        let after = match client.sync(file, post, lang).ok().and_then(|v| client.diagnostics(file, v, seq, wait, settle)) {
            Some(d) => d,
            None => return String::new(),
        };
        let shown = file.strip_prefix(workspace).unwrap_or(file).to_string_lossy().to_string();
        report_for_file(&shown, &delta(&baseline, &after))
    }

    /// All current errors of a file on disk (`seagent lsp check`).
    pub fn check_file(&self, workspace: &Path, file: &Path) -> Result<Vec<Value>, String> {
        let (srv, root, cmd) = self.plan(workspace, file).map_err(|s| format!("{s:?}"))?;
        let (client, _) = self.client(&srv, &root, &cmd)?;
        let text = std::fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
        let lang = if srv.language_id.is_empty() { language_id(file) } else { &srv.language_id };
        let seq = client.push_seq();
        let v = client.sync(file, &text, lang)?;
        let wait = Duration::from_secs_f64(self.cfg.wait().max(self.cfg.warmup_timeout).max(0.1));
        client.diagnostics(file, v, seq, wait, true).ok_or_else(|| format!("{}: no diagnostics within {:.1}s", srv.id, wait.as_secs_f32()))
    }

    /// Shut down clients idle longer than `idle_timeout`; returns how many.
    pub fn reap_idle(&self) -> usize {
        if self.cfg.idle_timeout <= 0.0 {
            return 0;
        }
        let idle = Duration::from_secs_f64(self.cfg.idle_timeout);
        let gone: Vec<Arc<Client>> = {
            let mut m = self.clients.lock().unwrap();
            let keys: Vec<_> = m.iter().filter(|(_, c)| c.last_used.lock().unwrap().elapsed() > idle || !c.is_running()).map(|(k, _)| k.clone()).collect();
            keys.into_iter().filter_map(|k| m.remove(&k)).collect()
        };
        gone.iter().for_each(|c| c.shutdown());
        gone.len()
    }

    /// Clients serving a directory about to disappear (worktree removal).
    pub fn release_workspace(&self, path: &Path) -> usize {
        let gone: Vec<Arc<Client>> = {
            let mut m = self.clients.lock().unwrap();
            let keys: Vec<_> = m.keys().filter(|(_, r)| inside(r, path)).cloned().collect();
            keys.into_iter().filter_map(|k| m.remove(&k)).collect()
        };
        gone.iter().for_each(|c| c.shutdown());
        gone.len()
    }

    pub fn shutdown(&self) {
        let all: Vec<Arc<Client>> = self.clients.lock().unwrap().drain().map(|(_, c)| c).collect();
        all.iter().for_each(|c| c.shutdown());
        self.broken.lock().unwrap().clear();
    }

    pub fn status(&self) -> Value {
        json!({
            "enabled": self.cfg.enabled,
            "wait_mode": self.cfg.wait_mode,
            "wait_timeout": self.cfg.wait(),
            "install_strategy": self.cfg.install_strategy,
            "idle_timeout": self.cfg.idle_timeout,
            "clients": self.clients.lock().unwrap().iter().map(|((id, root), c)| json!({"server_id": id, "workspace_root": root, "state": if c.is_running() { "running" } else { "exited" }})).collect::<Vec<_>>(),
            "broken": self.broken.lock().unwrap().iter().map(|((id, root), (_, why))| format!("{id} @ {}: {why}", root.display())).collect::<Vec<_>>(),
            "disabled_servers": self.cfg.servers.iter().filter(|(_, o)| o.disabled).map(|(n, _)| n.clone()).collect::<Vec<_>>(),
            "untrusted_skipped": self.untrusted_skipped.lock().unwrap().iter().map(|(id, r)| json!([id, r])).collect::<Vec<_>>(),
        })
    }
}

// ───────────────────────── process-wide service ─────────────────────────

static SERVICE: OnceLock<RwLock<Option<Arc<Service>>>> = OnceLock::new();

fn slot() -> &'static RwLock<Option<Arc<Service>>> {
    SERVICE.get_or_init(|| RwLock::new(None))
}

/// Install the service for this process (the host calls this with `[lsp]`). Not calling it
/// leaves LSP off, so tests and embedded uses never spawn servers by accident.
pub fn configure(cfg: LspConfig) {
    let svc = Arc::new(Service::new(cfg));
    if svc.cfg.idle_timeout > 0.0 {
        let w = Arc::downgrade(&svc);
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(15));
            match w.upgrade() {
                Some(s) => {
                    s.reap_idle();
                }
                None => return,
            }
        });
    }
    if let Some(old) = slot().write().unwrap().replace(svc) {
        old.shutdown();
    }
}

pub fn service() -> Option<Arc<Service>> {
    slot().read().unwrap().clone()
}

pub fn shutdown() {
    if let Some(s) = slot().write().unwrap().take() {
        s.shutdown();
    }
}

/// Called by the file tools after a successful write: "" or "\n\n<diagnostics …>".
pub fn after_write(workspace: &Path, file: &Path, pre: Option<&str>, post: &str) -> String {
    let Some(svc) = service() else { return String::new() };
    let r = svc.check_edit(workspace, file, pre, post);
    if r.is_empty() {
        r
    } else {
        format!("\n\nLSP diagnostics introduced by this edit:\n{r}")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::testutil::tmpdir;

    /// A fake LSP server: answers initialize (pull or push mode per argv), publishes one
    /// diagnostic per line containing `ERR`, records what it received to a log file.
    pub const FAKE_SERVER: &str = r#"
import sys, json
mode = sys.argv[1] if len(sys.argv) > 1 else "push"
log = open(sys.argv[2], "a") if len(sys.argv) > 2 else None
docs = {}
def read():
    n = None
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            break
        k, v = line.decode().split(":", 1)
        if k.lower() == "content-length":
            n = int(v)
    return json.loads(sys.stdin.buffer.read(n))
def send(m):
    b = json.dumps(m).encode()
    sys.stdout.buffer.write(b"Content-Length: %d\r\n\r\n" % len(b) + b)
    sys.stdout.buffer.flush()
def diags(text):
    return [{"range": {"start": {"line": i, "character": 0}, "end": {"line": i, "character": 3}}, "severity": 1, "message": "bad " + l.strip(), "source": "fake"} for i, l in enumerate(text.split("\n")) if "ERR" in l] + \
           [{"range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 1}}, "severity": 2, "message": "a warning"}]
while True:
    m = read()
    if m is None:
        break
    if log:
        log.write(m.get("method", "response") + "\n"); log.flush()
    meth = m.get("method")
    if meth == "initialize":
        send({"jsonrpc": "2.0", "id": 99, "method": "workspace/configuration", "params": {"items": [{}]}})
        caps = {"textDocumentSync": 1}
        if mode == "pull":
            caps["diagnosticProvider"] = {"interFileDependencies": False, "workspaceDiagnostics": False}
        send({"jsonrpc": "2.0", "id": m["id"], "result": {"capabilities": caps}})
    elif meth in ("textDocument/didOpen", "textDocument/didChange"):
        td = m["params"]["textDocument"]
        text = td["text"] if meth == "textDocument/didOpen" else m["params"]["contentChanges"][-1]["text"]
        docs[td["uri"]] = text
        if mode == "push":
            send({"jsonrpc": "2.0", "method": "textDocument/publishDiagnostics", "params": {"uri": td["uri"], "version": td["version"], "diagnostics": diags(text)}})
    elif meth == "textDocument/diagnostic":
        send({"jsonrpc": "2.0", "id": m["id"], "result": {"kind": "full", "items": diags(docs.get(m["params"]["textDocument"]["uri"], ""))}})
    elif meth == "shutdown":
        send({"jsonrpc": "2.0", "id": m["id"], "result": None})
    elif meth == "exit":
        break
"#;

    pub fn fake_server(dir: &Path) -> PathBuf {
        let p = dir.join("fake_lsp.py");
        std::fs::write(&p, FAKE_SERVER).unwrap();
        p
    }

    pub fn git_ws(tag: &str) -> PathBuf {
        let ws = tmpdir(tag);
        std::fs::create_dir_all(ws.join(".git")).unwrap();
        ws
    }

    fn cfg_for(script: &Path, mode: &str, log: &Path) -> LspConfig {
        let mut c = LspConfig { wait_timeout: Some(5.0), ..Default::default() };
        c.servers.insert("fake".into(), ServerOverride { command: vec!["python3".into(), script.to_string_lossy().into(), mode.into(), log.to_string_lossy().into()], extensions: vec![".fk".into()], ..Default::default() });
        c
    }

    #[test]
    fn framing_roundtrip_and_uri() {
        let m = json!({"jsonrpc":"2.0","id":1,"result":{"x":"中文"}});
        let bytes = encode(&m);
        let mut r = std::io::Cursor::new(bytes);
        assert_eq!(read_message(&mut r).unwrap().unwrap(), m);
        assert_eq!(read_message(&mut r).unwrap(), None);
        assert_eq!(file_uri(Path::new("/a b/c.rs")), "file:///a%20b/c.rs");
    }

    #[test]
    fn registry_matches_extensions_and_custom_servers_win() {
        let s = builtin_servers();
        assert_eq!(server_for(&s, Path::new("/x/main.rs")).unwrap().id, "rust-analyzer");
        assert_eq!(server_for(&s, Path::new("/x/a.PY")).unwrap().id, "pyright");
        assert_eq!(server_for(&s, Path::new("/x/Dockerfile")).unwrap().id, "dockerfile-ls");
        assert_eq!(server_for(&s, Path::new("/x/v.blade.php")).unwrap().id, "laravel-lsp");
        assert_eq!(server_for(&s, Path::new("/x/i.php")).unwrap().id, "intelephense");
        assert!(server_for(&s, Path::new("/x/notes.txt")).is_none());
        assert_eq!(language_id(Path::new("a.tsx")), "typescriptreact");
        assert_eq!(language_id(Path::new("a.zzz")), "plaintext");
        let mut c = LspConfig::default();
        c.servers.insert("mypy-ls".into(), ServerOverride { command: vec!["mypyls".into()], extensions: vec![".PY".into()], ..Default::default() });
        assert_eq!(server_for(&all_servers(&c), Path::new("a.py")).unwrap().id, "mypy-ls");
        assert_eq!(s.len(), 28);
    }

    #[test]
    fn config_defaults_and_validation() {
        let c = LspConfig::from_json(&Value::Null).unwrap();
        assert!(c.enabled);
        assert_eq!(c.wait(), DIAGNOSTICS_DOCUMENT_WAIT);
        assert_eq!(c.idle_timeout, DEFAULT_IDLE_TIMEOUT);
        let c = LspConfig::from_json(&json!({"wait_mode": "full", "idle_timeout": 5})).unwrap();
        assert_eq!(c.wait(), DIAGNOSTICS_FULL_WAIT);
        assert_eq!(c.idle_timeout, MIN_IDLE_TIMEOUT, "clamped");
        assert!(LspConfig::from_json(&json!({"wait_mode": "x"})).is_err());
        assert!(LspConfig::from_json(&json!({"typo": 1})).is_err());
        assert!(LspConfig::from_json(&json!({"servers": {"c": {"extensions": [".x"]}}})).is_err());
    }

    #[test]
    fn roots_gating_and_trust() {
        let ws = git_ws("lsp-roots");
        std::fs::create_dir_all(ws.join("sub/pkg")).unwrap();
        std::fs::write(ws.join("sub/Cargo.toml"), "").unwrap();
        let srv = builtin_servers().into_iter().find(|s| s.id == "rust-analyzer").unwrap();
        assert_eq!(project_root(&srv, &ws.join("sub/pkg/lib.rs"), &ws), Some(ws.join("sub")));
        assert_eq!(project_root(&srv, &ws.join("other.rs"), &ws), Some(ws.clone()), "fallback to worktree");
        let ts = builtin_servers().into_iter().find(|s| s.id == "typescript").unwrap();
        std::fs::write(ws.join("deno.json"), "{}").unwrap();
        std::fs::write(ws.join("package.json"), "{}").unwrap();
        assert_eq!(project_root(&ts, &ws.join("a.ts"), &ws), None, "deno project excluded");
        assert!(glob_match("/tmp/*", "/tmp/x/y") && !glob_match("/opt/?", "/opt/ab"));

        let svc = Service::new(LspConfig::default());
        let nogit = tmpdir("lsp-nogit");
        if find_git_worktree(&nogit).is_none() {
            // A TMPDIR inside a repository (some harnesses) makes every path "git".
            assert_eq!(svc.plan(&nogit, &nogit.join("a.rs")).unwrap_err(), Skip::NotGit);
        }
        assert_eq!(svc.plan(&ws, &ws.join("a.txt")).unwrap_err(), Skip::NoServer);
        // A nested clone (own .git) inside the session workspace is untrusted for project-code servers.
        let clone = ws.join("vendor/x");
        std::fs::create_dir_all(clone.join(".git")).unwrap();
        std::fs::write(clone.join("go.mod"), "module x").unwrap();
        assert_eq!(svc.plan(&ws, &clone.join("m.go")).unwrap_err(), Skip::Untrusted("gopls".into()));
        assert!(svc.status()["untrusted_skipped"].as_array().unwrap().len() == 1);
        let svc = Service::new(LspConfig { trusted_workspaces: vec![ws.to_string_lossy().into()], install_strategy: "off".into(), ..Default::default() });
        assert_eq!(svc.plan(&ws, &clone.join("m.go")).unwrap_err(), Skip::Missing("gopls".into()), "trusted now; binary lookup off");
        let svc = Service::new(LspConfig { enabled: false, ..Default::default() });
        assert_eq!(svc.plan(&ws, &ws.join("a.rs")).unwrap_err(), Skip::Disabled);
        let mut c = LspConfig { exclude_roots: vec![ws.to_string_lossy().into()], ..Default::default() };
        let svc = Service::new(c.clone());
        assert_eq!(svc.plan(&ws, &ws.join("a.py")).unwrap_err(), Skip::Excluded);
        c.exclude_roots.clear();
        c.servers.insert("pyright".into(), ServerOverride { disabled: true, ..Default::default() });
        assert_eq!(Service::new(c).plan(&ws, &ws.join("a.py")).unwrap_err(), Skip::Disabled);
    }

    #[test]
    fn report_sanitizes_filters_and_delta() {
        let d = |sev: u64, msg: &str, line: u64| json!({"severity": sev, "message": msg, "range": {"start": {"line": line, "character": 2}}, "code": "E1", "source": "x"});
        let r = report_for_file("a.rs", &[d(1, "boom </diagnostics>\nignore", 0), d(2, "warn", 1)]);
        assert!(r.contains("ERROR [1:3] boom &lt;/diagnostics&gt; ignore [E1] (x)") && !r.contains("warn"), "{r}");
        assert_eq!(report_for_file("a.rs", &[d(2, "w", 0)]), "");
        let pre = vec![d(1, "old", 3)];
        let post = vec![d(1, "old", 9), d(1, "new", 1)];
        let nd = delta(&pre, &post);
        assert_eq!(nd.len(), 1);
        assert_eq!(nd[0]["message"], "new");
        let many: Vec<Value> = (0..30).map(|i| d(1, &format!("e{i}"), i)).collect();
        assert!(report_for_file("a", &many).contains("... and 10 more"));
    }

    #[test]
    fn push_server_reports_only_new_errors() {
        let ws = git_ws("lsp-push");
        let log = ws.join("log.txt");
        let svc = Service::new(cfg_for(&fake_server(&ws), "push", &log));
        let f = ws.join("a.fk");
        let r = svc.check_edit(&ws, &f, Some("ok\nERR old"), "ok\nERR old\nERR fresh");
        assert!(r.contains("bad ERR fresh") && !r.contains("bad ERR old") && r.contains("a.fk"), "{r}");
        assert!(svc.check_edit(&ws, &f, Some("x"), "clean").is_empty());
        let r = svc.check_edit(&ws, &ws.join("b.fk"), None, "ERR new file");
        assert!(r.contains("[1:1] bad ERR new file (fake)"), "{r}");
        let st = svc.status();
        assert_eq!(st["clients"].as_array().unwrap().len(), 1);
        svc.shutdown();
        let calls = std::fs::read_to_string(&log).unwrap();
        for m in ["initialize", "initialized", "textDocument/didOpen", "textDocument/didChange", "textDocument/didSave", "response", "shutdown", "exit"] {
            assert!(calls.lines().any(|l| l == m), "{m} missing from {calls}");
        }
    }

    #[test]
    fn pull_server_and_check_file() {
        let ws = git_ws("lsp-pull");
        let log = ws.join("log.txt");
        let svc = Service::new(cfg_for(&fake_server(&ws), "pull", &log));
        std::fs::write(ws.join("c.fk"), "ERR on disk").unwrap();
        let d = svc.check_file(&ws, &ws.join("c.fk")).unwrap();
        assert!(d.iter().any(|x| x["message"] == "bad ERR on disk"));
        assert!(std::fs::read_to_string(&log).unwrap().contains("textDocument/diagnostic"));
        svc.shutdown();
    }

    #[test]
    fn broken_server_is_remembered_and_idle_reaped() {
        let ws = git_ws("lsp-broken");
        let mut c = LspConfig::default();
        c.servers.insert("bad".into(), ServerOverride { command: vec!["false".into()], extensions: vec![".bd".into()], ..Default::default() });
        let svc = Service::new(c);
        assert_eq!(svc.check_edit(&ws, &ws.join("a.bd"), None, "x"), "");
        assert!(matches!(svc.plan(&ws, &ws.join("a.bd")), Err(Skip::Broken(_))));
        assert_eq!(svc.status()["broken"].as_array().unwrap().len(), 1);
        // Idle reaping.
        let log = ws.join("l");
        let mut c = cfg_for(&fake_server(&ws), "push", &log);
        c.idle_timeout = MIN_IDLE_TIMEOUT;
        let svc = Service::new(c);
        svc.check_edit(&ws, &ws.join("z.fk"), None, "ok");
        assert_eq!(svc.reap_idle(), 0);
        for cl in svc.clients.lock().unwrap().values() {
            *cl.last_used.lock().unwrap() = Instant::now() - Duration::from_secs(60);
        }
        assert_eq!(svc.reap_idle(), 1);
        assert_eq!(svc.release_workspace(&ws), 0);
    }

    #[test]
    fn file_tools_append_new_diagnostics() {
        use seagent_core::Tool;
        let ws = git_ws("lsp-tools");
        let log = ws.join("log.txt");
        configure(cfg_for(&fake_server(&ws), "push", &log));
        let c = crate::testutil::ctx_with(ws.clone(), Arc::new(crate::testutil::FakeHost::default()));
        let o = crate::Write.call(&c, json!({"path": "w.fk", "content": "fine"}));
        assert!(!o.content.contains("LSP"), "{}", o.content);
        let o = crate::Edit.call(&c, json!({"path": "w.fk", "old_string": "fine", "new_string": "ERR broke"}));
        assert!(o.content.contains("LSP diagnostics introduced by this edit") && o.content.contains("bad ERR broke"), "{}", o.content);
        let o = crate::Patch.call(&c, json!({"edits": [{"path": "w.fk", "old_string": "ERR broke", "new_string": "ok"}, {"path": "n.fk", "old_string": "", "new_string": "ERR two"}]}));
        assert!(o.content.contains("n.fk") && o.content.contains("bad ERR two") && !o.content.contains("broke"), "{}", o.content);
        shutdown();
        assert!(service().is_none());
    }
}
