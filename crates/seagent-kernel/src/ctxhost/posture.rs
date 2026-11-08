//! Coding posture and the local toolchain probe.
//!
//! * **Coding posture** (Hermes `agent/coding_context.py`): when the workspace looks like a code
//!   repository, a frozen `coding` segment tells the model the stack, the package manager and the
//!   exact verify commands, so "done" means "the project's own tests ran". Stack detection is not
//!   duplicated here — `crate::verify::{load_or_detect, detect_package_manager}` already infers the
//!   recipe (and honours a user-edited `.seagent/environment.json`).
//! * **Toolchain probe** (Hermes `tools/env_probe.py`, widened from Python-only to every common
//!   local toolchain): one line of `name version` for the compilers/runtimes found on `PATH`,
//!   bounded timeouts, cached per workspace for the session, omitted when nothing is found.
//!
//! Both are prompt-only: no tool is added or removed.

use super::Host;
use crate::config::Config;
use crate::ctxstate::ContextConfig;
use crate::lifecycle::Lifecycle;
use seagent_core::SystemSegment;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Filenames that mark a code workspace without git (Hermes `_PROJECT_MARKERS`).
pub const MARKERS: &[&str] = &[
    "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "package.json", "tsconfig.json", "deno.json", "Cargo.toml",
    "go.mod", "pom.xml", "build.gradle", "build.gradle.kts", "Gemfile", "composer.json", "mix.exs", "pubspec.yaml", "CMakeLists.txt",
    "Makefile", "Dockerfile", "AGENTS.md", "CLAUDE.md", ".cursorrules",
];
/// Extensions that make a manifest-less git repository a *code* workspace (a notes repo is not).
pub const CODE_EXTENSIONS: &[&str] = &[
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rs", ".java", ".kt", ".kts", ".scala", ".rb", ".php", ".c", ".h",
    ".cc", ".cpp", ".hpp", ".cs", ".swift", ".m", ".mm", ".dart", ".ex", ".exs", ".lua", ".sh", ".sql", ".vue", ".svelte", ".r", ".jl",
    ".hs", ".clj", ".erl", ".pl",
];
const SKIP_DIRS: &[&str] = &[".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "target", ".next", ".turbo", "vendor"];
/// A code workspace reveals itself in the first handful of entries (bounded sweep, never recursive).
const SCAN_MAX_ENTRIES: usize = 500;
/// Per-command ceiling for the probe: a wedged `--version` must not delay session start.
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(700);
/// Ceiling for the whole probe: a broken toolchain degrades the line, never the session start.
pub const PROBE_BUDGET: Duration = Duration::from_millis(3_000);

/// (program, args, reads stderr): `java -version` prints its version on stderr.
pub const PROBE_TOOLS: &[(&str, &[&str], bool)] = &[
    ("rustc", &["--version"], false),
    ("cargo", &["--version"], false),
    ("node", &["--version"], false),
    ("npm", &["--version"], false),
    ("pnpm", &["--version"], false),
    ("yarn", &["--version"], false),
    ("bun", &["--version"], false),
    ("python3", &["--version"], false),
    ("pip3", &["--version"], false),
    ("uv", &["--version"], false),
    ("go", &["version"], false),
    ("java", &["-version"], true),
    ("docker", &["--version"], false),
    ("git", &["--version"], false),
];

/// Operating brief for a code repository (condensed from Hermes `CODING_AGENT_GUIDANCE`).
pub const CODING_BRIEF: &str = "\
You are pairing with the user inside their codebase. Operate like a careful senior engineer.
- Gather context first: read the relevant files and trace a symbol to its definition and usages instead of guessing its shape.
- Make changes through the tools, not the chat: apply the edit, then summarise it. Match the existing style; no drive-by refactors or reformatting.
- AGENTS.md / CLAUDE.md / .cursorrules already in the prompt win over your defaults. Touch only what the task needs.
- If a patch fails to apply, re-read the file for the exact current text before retrying; after two failures on one region, rewrite the enclosing function or file.
- Verify before claiming the work is done: run the build/tests below and report what passed. Fix root causes, not symptoms.
- Don't commit, push or rewrite history unless asked, and never print secrets.";

fn is_code_ext(name: &str) -> bool {
    let lower = name.to_lowercase();
    CODE_EXTENSIONS.iter().any(|e| lower.ends_with(e))
}

/// Cheap, bounded "is this a code repository?" check: a project marker, or a git checkout holding
/// source files in its top two levels.
pub fn looks_like_code(root: &Path) -> bool {
    if MARKERS.iter().any(|m| root.join(m).exists()) {
        return true;
    }
    let entries: Vec<PathBuf> = match std::fs::read_dir(root) {
        Ok(rd) => rd.flatten().map(|e| e.path()).take(SCAN_MAX_ENTRIES).collect(),
        Err(_) => return false,
    };
    if !root.join(".git").exists() {
        return false;
    }
    for p in entries.iter().filter(|p| p.is_file()) {
        if p.file_name().and_then(|n| n.to_str()).is_some_and(is_code_ext) {
            return true;
        }
    }
    for dir in entries.iter().filter(|p| p.is_dir() && p.file_name().and_then(|n| n.to_str()).is_some_and(|n| !SKIP_DIRS.contains(&n))) {
        let Ok(rd) = std::fs::read_dir(dir) else { continue };
        for e in rd.flatten().take(SCAN_MAX_ENTRIES) {
            if e.file_name().to_str().is_some_and(is_code_ext) {
                return true;
            }
        }
    }
    false
}

/// `auto` | `on` | `focus` adopt the posture; `off` never does.
pub fn enabled(mode: &str) -> bool {
    !matches!(mode.trim().to_lowercase().as_str(), "off" | "false" | "no" | "0")
}

/// The package manager worth naming, from the manifest of the detected stack.
pub fn package_manager(root: &Path, kind: &str) -> Option<&'static str> {
    match kind {
        "rust" => Some("cargo"),
        "go" => Some("go"),
        "maven" => Some("mvn"),
        "gradle" => Some("gradle"),
        "make" => Some("make"),
        "compose" => Some("docker compose"),
        _ => crate::verify::detect_package_manager(root).or(match kind {
            "node" | "nextjs" | "sveltekit" | "astro" | "remix" | "cra" | "vite" => Some("npm"),
            "python" | "fastapi" | "flask" | "django" => Some("pip"),
            _ => None,
        }),
    }
}

/// The `coding` segment text for a workspace, or `None` when this is not a code repository or the
/// posture is off.
pub fn posture_text(root: &Path, cc: &ContextConfig) -> Option<String> {
    if !enabled(&cc.coding_context) || !looks_like_code(root) {
        return None;
    }
    let (recipe, source) = crate::verify::load_or_detect(root);
    let mut out = String::from("# Coding posture\nThis workspace is a code repository. ");
    match &recipe {
        Some(r) => {
            out.push_str(&format!("Detected stack: **{}** ({}).", r.name, r.kind));
            if let Some(pm) = package_manager(root, &r.kind) {
                out.push_str(&format!(" Package manager: `{pm}`."));
            }
            out.push_str(&format!(" Commands come from the {source} run recipe.\n"));
            let mut cmds: Vec<String> = Vec::new();
            for (label, list) in [("bootstrap", &r.bootstrap), ("build", &r.build), ("test", &r.test)] {
                if !list.is_empty() {
                    cmds.push(format!("- {label}: {}", list.iter().map(|c| format!("`{c}`")).collect::<Vec<_>>().join(", ")));
                }
            }
            if !cmds.is_empty() {
                out.push_str("Verify with:\n");
                out.push_str(&cmds.join("\n"));
                out.push('\n');
            }
        }
        None => out.push_str("No run recipe was detected; read the manifests before choosing a build or test command.\n"),
    }
    out.push('\n');
    out.push_str(CODING_BRIEF);
    let extra = cc.coding_instructions.trim();
    if !extra.is_empty() {
        out.push_str("\n\nProject instructions:\n");
        out.push_str(extra);
    }
    Some(out)
}

/// `name version` from a `--version` line: the first version-shaped token, else the trimmed line.
pub fn version_of(out: &str) -> Option<String> {
    let line = out.lines().map(str::trim).find(|l| !l.is_empty())?;
    let bytes: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            let mut j = i;
            while j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == '.') {
                j += 1;
            }
            let tok: String = bytes[start..j].iter().collect();
            if tok.matches('.').count() >= 1 || tok.len() >= 2 {
                return Some(tok.trim_end_matches('.').chars().take(24).collect());
            }
            i = j;
        } else {
            i += 1;
        }
    }
    Some(line.chars().take(40).collect())
}

/// The executable `name` in the first of `dirs` that holds an executable file of that name.
pub fn find_in(dirs: &[PathBuf], name: &str) -> Option<PathBuf> {
    // Windows: executables carry an extension (`cargo.exe`, `npm.cmd`), resolved by PATHEXT.
    #[cfg(windows)]
    {
        let joined = std::env::join_paths(dirs).ok()?;
        seagent_core::platform::layout::which_in_pathext(name, Some(joined.as_os_str()), std::env::var("PATHEXT").ok().as_deref())
    }
    #[cfg(not(windows))]
    find_in_unix(dirs, name)
}

#[cfg(not(windows))]
fn find_in_unix(dirs: &[PathBuf], name: &str) -> Option<PathBuf> {
    for d in dirs {
        let p = d.join(name);
        let Ok(md) = std::fs::metadata(&p) else { continue };
        if !md.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if md.permissions().mode() & 0o111 == 0 {
                continue;
            }
        }
        return Some(p);
    }
    None
}

fn run_version(bin: &Path, args: &[&str], stderr: bool) -> Option<String> {
    let mut cmd = Command::new(bin);
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().ok()?;
    let deadline = Instant::now() + PROBE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = if stderr { String::from_utf8_lossy(&out.stderr).to_string() } else { String::from_utf8_lossy(&out.stdout).to_string() };
    version_of(&text)
}

/// (name, version) for every toolchain found in `dirs`, in [`PROBE_TOOLS`] order. Stops at
/// [`PROBE_BUDGET`] so a hung binary can only shorten the line (Hermes fails open the same way).
pub fn probe_dirs(dirs: &[PathBuf]) -> Vec<(&'static str, String)> {
    let mut v = Vec::new();
    let started = Instant::now();
    for (name, args, stderr) in PROBE_TOOLS {
        if started.elapsed() >= PROBE_BUDGET {
            break;
        }
        let Some(bin) = find_in(dirs, name) else { continue };
        if let Some(version) = run_version(&bin, args, *stderr) {
            v.push((*name, version));
        }
    }
    v
}

pub fn path_dirs() -> Vec<PathBuf> {
    std::env::var_os("PATH").map(|p| std::env::split_paths(&p).collect()).unwrap_or_default()
}

/// `rustc 1.80.0, cargo 1.80.0, node 20.11.0` — `None` when nothing was found.
pub fn env_line(tools: &[(&'static str, String)]) -> Option<String> {
    (!tools.is_empty()).then(|| tools.iter().map(|(n, v)| format!("{n} {v}")).collect::<Vec<_>>().join(", "))
}

/// Probe cache: one line per workspace, computed once per process (a toolchain does not change
/// mid-session) and warmed in the background so session start pays nothing.
pub struct Probe {
    dirs: Option<Vec<PathBuf>>,
    cache: Arc<Mutex<HashMap<String, Arc<String>>>>,
}

impl Probe {
    pub fn new(path_override: Option<PathBuf>) -> Probe {
        Probe { dirs: path_override.map(|p| vec![p]), cache: Arc::new(Mutex::new(HashMap::new())) }
    }
    pub fn dirs(&self) -> Vec<PathBuf> {
        self.dirs.clone().unwrap_or_else(path_dirs)
    }
    /// The cached line for `ws` (computed synchronously on first use; "" when empty).
    pub fn line(&self, ws: &Path) -> String {
        let key = ws.to_string_lossy().to_string();
        if let Some(v) = self.cache.lock().unwrap().get(&key) {
            return v.to_string();
        }
        let line = env_line(&probe_dirs(&self.dirs())).unwrap_or_default();
        self.cache.lock().unwrap().insert(key, Arc::new(line.clone()));
        line
    }
    /// Compute `ws`'s line on a background thread (idempotent).
    pub fn warm(&self, ws: &Path) {
        let dirs = self.dirs();
        let cache = self.cache.clone();
        let key = ws.to_string_lossy().to_string();
        std::thread::spawn(move || {
            let line = env_line(&probe_dirs(&dirs)).unwrap_or_default();
            cache.lock().unwrap().entry(key).or_insert_with(|| Arc::new(line));
        });
    }
}

/// The `environment` segment: one line naming the local toolchains and their versions. Probing the
/// machine once is cheaper than the model discovering a missing/mismatched tool by hitting walls.
pub fn env_text(root: &Path, probe: &Probe) -> Option<String> {
    let line = probe.line(root);
    let line = line.trim();
    (!line.is_empty()).then(|| {
        format!("# Local toolchain\nInstalled here: {line}.\nChecked once at session start; a command's `--help` is still the source of truth for its flags.\n")
    })
}

/// `coding` system segment.
pub struct PostureSegment(pub Arc<Host>);

impl Lifecycle for PostureSegment {
    fn name(&self) -> String {
        "ctxhost:coding".into()
    }
    fn system_segment(&self, workspace: &str) -> Option<SystemSegment> {
        let cfg = self.0.cfg()?;
        posture_text(Path::new(workspace), &cfg.context).map(|text| SystemSegment { id: "coding".into(), text, cache: false })
    }
}

/// `environment` system segment.
pub struct EnvSegment(pub Arc<Host>);

impl Lifecycle for EnvSegment {
    fn name(&self) -> String {
        "ctxhost:environment".into()
    }
    fn system_segment(&self, workspace: &str) -> Option<SystemSegment> {
        let cfg: Config = self.0.cfg()?;
        if !cfg.context.environment_probe {
            return None;
        }
        env_text(Path::new(workspace), &self.0.probe).map(|text| SystemSegment { id: "environment".into(), text, cache: false })
    }
}
