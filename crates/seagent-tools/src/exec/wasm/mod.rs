//! `wasm` exec backend: the shell / VM substitute for iOS (no `fork`/`exec`, no JIT, no
//! hypervisor there). A command line is interpreted by the in-process POSIX-ish shell
//! ([`shell`]); every external command is a `wasm32-wasip1` module run by wasmi — a pure-Rust
//! WebAssembly *interpreter* (no JIT, so App Store policy allows it) — against the WASI
//! preview 1 layer in [`wasi`], which only sees the [`policy`] roots: the workspace (read-only
//! when the sandbox says so), the session's private `/tmp` and `[exec.sandbox] binds`.
//!
//! The tools are not built in. They are WASI modules in the *tools directory*
//! (`[exec.wasm] tools_dir`, `$SEAGENT_WASI_TOOLS`, else `<share>/wasi`): `<name>.wasm` is the
//! command `name`, and `tools.json` there maps more names onto multi-call modules (uutils
//! coreutils, busybox) and pins every module's SHA-256 — a module whose digest does not match is
//! refused. `apps/desktop/scripts/build-wasi-tools.sh` builds and pins the set the iOS app ships.
//!
//! Isolation is reported honestly as an OS-sandbox-level wall ([`WARNING`]): path policy and
//! memory/fuel limits are enforced by the interpreter in the agent's own process, not by a
//! kernel or a hypervisor.

mod policy;
pub mod shell;
mod wasi;

pub use policy::{Policy, Root};

use super::{BackendCtx, ExecConfig};
use seagent_core::exec::{ExecBackend, ExecChild, ExecRequest, ExitInfo};
use serde::Deserialize;
use serde_json::Value;
use shell::{In, Io, Live, Out, Shell, Tools};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};
use wasmi::{Config, Engine, Linker, Module, Store, TypedResumableCall};

/// What `seagent sandbox explain` and the system prompt say about this backend.
pub const WARNING: &str = super::WASM_WARNING;

/// `[exec.wasm]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WasmConfig {
    /// Directory of WASI tools (`<name>.wasm` + `tools.json`). Empty: `$SEAGENT_WASI_TOOLS`,
    /// else `<share>/wasi`.
    pub tools_dir: String,
    /// Linear-memory cap per tool, MiB.
    pub memory_mb: u64,
    /// Interpreter fuel between two checks for a kill / timeout.
    pub fuel_slice: u64,
}

impl Default for WasmConfig {
    fn default() -> Self {
        WasmConfig { tools_dir: String::new(), memory_mb: 512, fuel_slice: 20_000_000 }
    }
}

impl WasmConfig {
    pub fn parse(v: &Value) -> Result<WasmConfig, String> {
        if v.is_null() {
            return Ok(WasmConfig::default());
        }
        serde_json::from_value(v.clone()).map_err(|e| format!("[exec.wasm]: {e}"))
    }

    /// Where the tools are.
    pub fn tools_dir(&self) -> Option<PathBuf> {
        if !self.tools_dir.trim().is_empty() {
            return Some(PathBuf::from(self.tools_dir.trim()));
        }
        if let Some(d) = std::env::var_os("SEAGENT_WASI_TOOLS").filter(|v| !v.is_empty()) {
            return Some(PathBuf::from(d));
        }
        seagent_core::share::share_dir().map(|s| s.join("wasi"))
    }
}

// ───────────── tools ─────────────

#[derive(Debug, Default, Deserialize)]
struct Manifest {
    #[serde(default)]
    modules: BTreeMap<String, ModuleInfo>,
    #[serde(default)]
    tools: BTreeMap<String, ToolInfo>,
}

#[derive(Debug, Default, Deserialize)]
struct ModuleInfo {
    #[serde(default)]
    sha256: String,
}

#[derive(Debug, Default, Deserialize)]
struct ToolInfo {
    module: String,
    /// argv[0] the module wants (a multi-call binary picks the applet from it).
    #[serde(default)]
    argv0: Option<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    /// Extra read-only directories: guest path → path relative to the tools directory
    /// (the CPython standard library, for instance).
    #[serde(default)]
    dirs: BTreeMap<String, String>,
    /// Arguments put before the user's (`egrep` = `grep -E`).
    #[serde(default)]
    args: Vec<String>,
}

/// One resolved command.
#[derive(Debug, Clone)]
pub struct Tool {
    pub module: PathBuf,
    pub sha256: Option<String>,
    /// The tools directory pins its modules (`tools.json` lists any): an unpinned one is refused.
    pub must_pin: bool,
    pub argv0: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub dirs: Vec<(String, PathBuf)>,
}

/// The tools directory and its manifest.
#[derive(Debug, Default)]
pub struct Toolbox {
    dir: Option<PathBuf>,
    manifest: Manifest,
}

fn safe_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 64 && n.chars().all(|c| c.is_ascii_alphanumeric() || "._+-".contains(c)) && !n.starts_with('.')
}

impl Toolbox {
    pub fn load(dir: Option<PathBuf>) -> Result<Toolbox, String> {
        let manifest = match dir.as_ref().map(|d| d.join("tools.json")) {
            Some(p) if p.is_file() => {
                let s = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
                serde_json::from_str(&s).map_err(|e| format!("{}: {e}", p.display()))?
            }
            _ => Manifest::default(),
        };
        Ok(Toolbox { dir, manifest })
    }

    pub fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }

    /// Every command name this box offers.
    pub fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.manifest.tools.keys().cloned().collect();
        if let Some(rd) = self.dir.as_ref().and_then(|d| std::fs::read_dir(d).ok()) {
            v.extend(rd.flatten().filter_map(|e| e.file_name().to_str().and_then(|n| n.strip_suffix(".wasm")).map(String::from)));
        }
        v.sort();
        v.dedup();
        v
    }

    pub fn resolve(&self, name: &str) -> Option<Tool> {
        let dir = self.dir.as_ref()?;
        if !safe_name(name) {
            return None;
        }
        let sha = |file: &str| self.manifest.modules.get(file).map(|m| m.sha256.to_ascii_lowercase()).filter(|s| !s.is_empty());
        let must_pin = !self.manifest.modules.is_empty();
        if let Some(t) = self.manifest.tools.get(name) {
            if !safe_name(&t.module) {
                return None;
            }
            return Some(Tool {
                module: dir.join(&t.module),
                sha256: sha(&t.module),
                must_pin,
                argv0: t.argv0.clone().unwrap_or_else(|| name.to_string()),
                args: t.args.clone(),
                env: t.env.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                dirs: t.dirs.iter().filter(|(_, rel)| !rel.split('/').any(|c| c == "..")).map(|(g, rel)| (g.clone(), dir.join(rel))).collect(),
            });
        }
        let file = format!("{name}.wasm");
        let p = dir.join(&file);
        p.is_file().then(|| Tool { module: p, sha256: sha(&file), must_pin, argv0: name.to_string(), args: vec![], env: vec![], dirs: vec![] })
    }
}

// ───────────── the interpreter ─────────────

fn engine() -> &'static Engine {
    static E: OnceLock<Engine> = OnceLock::new();
    E.get_or_init(|| {
        let mut c = Config::default();
        c.consume_fuel(true);
        // Fuel is our kill / timeout clock, not a cost model: lazy translation of a large
        // function (CPython's eval loop) must not run out of fuel, because that is reported as
        // a non-resumable error. Charge only for execution and bulk copies.
        c.fuel_cost(wasmi::CustomFuelCosts { bytes_copied_per_fuel: 64, fuel_per_bytes_translated: 0, fuel_per_bytes_validated: 0 });
        Engine::new(&c)
    })
}

type Stamp = (u64, Option<SystemTime>);

/// Compiled modules, keyed by path and checked against size + mtime (a rebuilt tool reloads).
fn module_cache() -> &'static Mutex<HashMap<PathBuf, (Stamp, Module)>> {
    static C: OnceLock<Mutex<HashMap<PathBuf, (Stamp, Module)>>> = OnceLock::new();
    C.get_or_init(Default::default)
}

fn load_module(path: &Path, sha256: Option<&str>) -> Result<Module, String> {
    let md = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let stamp = (md.len(), md.modified().ok());
    if let Some((s, m)) = module_cache().lock().unwrap().get(path) {
        if *s == stamp {
            return Ok(m.clone());
        }
    }
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if let Some(want) = sha256 {
        let got: String = ring::digest::digest(&ring::digest::SHA256, &bytes).as_ref().iter().map(|b| format!("{b:02x}")).collect();
        if got != want {
            return Err(format!("{}: SHA-256 {got} does not match the pinned {want}; refusing to run it", path.display()));
        }
    }
    let m = Module::new(engine(), &bytes).map_err(|e| format!("{}: not a valid WebAssembly module: {e}", path.display()))?;
    module_cache().lock().unwrap().insert(path.to_path_buf(), (stamp, m.clone()));
    Ok(m)
}

/// Run one WASI command to completion; the exit status (137 = killed, 134 = trapped).
fn execute(module: &Module, proc: wasi::Proc, fuel: u64, err: &Out) -> i32 {
    let kill = proc.kill.clone();
    let mut store = Store::new(engine(), proc);
    store.limiter(|p| &mut p.limits);
    let _ = store.set_fuel(fuel);
    let mut linker = Linker::new(engine());
    if let Err(e) = wasi::add_to_linker(&mut linker) {
        err.put(format!("sh: wasi: {e}\n").as_bytes());
        return 126;
    }
    let inst = match linker.instantiate_and_start(&mut store, module) {
        Ok(i) => i,
        Err(e) => return trapped(&e, &kill, err, "cannot start"),
    };
    let Ok(start) = inst.get_typed_func::<(), ()>(&store, "_start") else {
        err.put(b"sh: not a WASI command (the module has no _start)\n");
        return 126;
    };
    let mut call = start.call_resumable(&mut store, ());
    loop {
        match call {
            Ok(TypedResumableCall::Finished(())) => return 0,
            Ok(TypedResumableCall::OutOfFuel(r)) => {
                if kill.load(Ordering::SeqCst) {
                    return 137;
                }
                let _ = store.set_fuel(fuel.max(r.required_fuel()));
                call = r.resume(&mut store);
            }
            Ok(TypedResumableCall::HostTrap(t)) => return trapped(t.host_error(), &kill, err, "trapped"),
            Err(e) => return trapped(&e, &kill, err, "trapped"),
        }
    }
}

fn trapped(e: &wasmi::Error, kill: &AtomicBool, err: &Out, what: &str) -> i32 {
    if let Some(code) = e.i32_exit_status() {
        return code;
    }
    if kill.load(Ordering::SeqCst) || e.downcast_ref::<wasi::Killed>().is_some() {
        return 137;
    }
    err.put(format!("sh: wasm {what}: {e}\n").as_bytes());
    134
}

/// The shell's way of running an external command.
struct Runner {
    toolbox: Arc<Toolbox>,
    policy: Arc<Policy>,
    kill: Arc<AtomicBool>,
    memory: usize,
    fuel: u64,
}

impl Runner {
    fn tool_for(&self, name: &str, cwd: &str) -> Option<Tool> {
        if name.contains('/') {
            // A module in the sandbox itself (`./build/app.wasm`), run like any other tool.
            let g = policy::join(cwd, name);
            let (host, _) = self.policy.host(&g, false, true).ok()?;
            return (host.is_file() && host.extension().is_some_and(|x| x == "wasm")).then(|| Tool { module: host, sha256: None, must_pin: false, argv0: name.to_string(), args: vec![], env: vec![], dirs: vec![] });
        }
        self.toolbox.resolve(name)
    }
}

impl Tools for Runner {
    fn find(&self, name: &str, cwd: &str) -> Option<String> {
        self.tool_for(name, cwd).map(|_| if name.contains('/') { name.to_string() } else { format!("/usr/bin/{name}") })
    }

    fn run(&self, argv: &[String], env: &[(String, String)], cwd: &str, io: &Io) -> Option<i32> {
        let tool = self.tool_for(&argv[0], cwd)?;
        if tool.must_pin && tool.sha256.is_none() {
            io.stderr.put(format!("sh: {}: {} has no SHA-256 in tools.json; refusing to run an unpinned tool\n", argv[0], tool.module.display()).as_bytes());
            return Some(126);
        }
        let module = match load_module(&tool.module, tool.sha256.as_deref()) {
            Ok(m) => m,
            Err(e) => {
                io.stderr.put(format!("sh: {}: {e}\n", argv[0]).as_bytes());
                return Some(126);
            }
        };
        let mut roots = self.policy.tool_roots();
        for (g, host) in &tool.dirs {
            if let Ok(h) = host.canonicalize() {
                roots.push(Root { guest: policy::normalize(g), host: h, write: false, tools: true });
            }
        }
        // `.` = the shell's cwd, so relative paths in the tool mean what they mean in the shell.
        let cwd_pre = self.policy.host(cwd, false, true).ok().and_then(|(h, i)| {
            let guest = &self.policy.roots[i].guest;
            roots.iter().position(|r| &r.guest == guest).map(|ri| (h, ri))
        });
        // wasi-libc resolves a relative path through the `.` preopen, and an absolute path no
        // other root claims lands there too (`/x` → `<cwd>/x`): odd, but never outside a root.
        let mut args = vec![tool.argv0.clone()];
        args.extend(tool.args.iter().cloned());
        args.extend(argv[1..].iter().cloned());
        let mut e: Vec<(String, String)> = env.to_vec();
        e.extend(tool.env.iter().cloned());
        e.retain(|(k, _)| k != "PWD");
        e.push(("PWD".into(), cwd.to_string()));
        let proc = wasi::Proc::new(args, e, Arc::new(roots), cwd_pre, (io.stdin.reader(), io.stdout.writer(), io.stderr.writer()), self.kill.clone(), self.memory);
        Some(execute(&module, proc, self.fuel, &io.stderr))
    }
}

// ───────────── the backend ─────────────

pub struct WasmBackend {
    policy: Arc<Policy>,
    toolbox: Arc<Toolbox>,
    cfg: WasmConfig,
    workspace_guest: String,
}

impl WasmBackend {
    pub fn new(cfg: &ExecConfig, ctx: &BackendCtx) -> Result<WasmBackend, String> {
        let wc = WasmConfig::parse(&cfg.wasm)?;
        let l = super::local::layout(&cfg.sandbox, ctx)?;
        Self::with_layout(wc, &l.workspace, l.writable, &l.tmp, &l.binds, &ctx.home)
    }

    /// The backend over explicit directories (tests, embedders).
    pub fn with_layout(wc: WasmConfig, workspace: &Path, writable: bool, tmp: &Path, binds: &[(PathBuf, String, bool)], home: &Path) -> Result<WasmBackend, String> {
        let mut p = Policy::default();
        let ws = workspace.canonicalize().map_err(|e| format!("workspace {}: {e}", workspace.display()))?;
        let ws_guest = ws.to_string_lossy().replace('\\', "/");
        let ws_guest = if ws_guest.starts_with('/') { ws_guest } else { format!("/{ws_guest}") };
        p.add(&ws_guest, &ws, writable, true)?;
        std::fs::create_dir_all(tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        p.add("/tmp", tmp, true, true)?;
        for (src, dst, ro) in binds {
            if src.exists() {
                p.add(dst, src, !ro, true)?;
            }
        }
        // The persistent-shell snapshots (`exec::session`): the shell itself writes them, the
        // tools never see them.
        let shell_dir = home.join("shell");
        std::fs::create_dir_all(&shell_dir).map_err(|e| format!("{}: {e}", shell_dir.display()))?;
        let sg = shell_dir.canonicalize().map_err(|e| e.to_string())?.to_string_lossy().replace('\\', "/");
        p.add(if sg.starts_with('/') { &sg } else { "/.seagent-shell" }, &shell_dir, true, false)?;
        let toolbox = Toolbox::load(wc.tools_dir())?;
        Ok(WasmBackend { policy: Arc::new(p), toolbox: Arc::new(toolbox), cfg: wc, workspace_guest: ws_guest })
    }

    pub fn toolbox(&self) -> &Toolbox {
        &self.toolbox
    }
}

static PIDS: AtomicU32 = AtomicU32::new(1000);

impl ExecBackend for WasmBackend {
    fn id(&self) -> &str {
        "wasm"
    }
    fn describe(&self) -> String {
        let tools = match self.toolbox.dir() {
            Some(d) => format!("{} WASI tools from {}", self.toolbox.names().len(), d.display()),
            None => "no WASI tools directory (shell builtins only)".into(),
        };
        format!("wasm: in-process WebAssembly interpreter (wasmi, no JIT) + built-in POSIX shell; {tools}; sees {}; no network, no native processes", self.policy.summary())
    }
    fn spawn(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>> {
        let kill = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let tx = Mutex::new(tx);
        let sink: shell::SinkFn = Arc::new(move |b: &[u8]| {
            let _ = tx.lock().unwrap().send(b.to_vec());
        });
        let (stdin_tx, stdin) = if req.stdin {
            let (stx, srx) = mpsc::channel::<Vec<u8>>();
            (Some(stx), In::Live(Arc::new(Live { rx: Mutex::new(srx), buf: Mutex::new(req.stdin_data.clone().unwrap_or_default()), kill: kill.clone() })))
        } else {
            (None, req.stdin_data.clone().map(In::bytes).unwrap_or(In::Null))
        };
        let cwd = req.cwd.as_ref().and_then(|c| self.policy.guest_of(c)).unwrap_or_else(|| self.workspace_guest.clone());
        let mut env: Vec<(String, String)> = vec![("PATH".into(), "/usr/bin:/bin".into()), ("SHELL".into(), "/bin/sh".into()), ("USER".into(), "agent".into()), ("LANG".into(), "C.UTF-8".into())];
        env.extend(req.env.iter().cloned());
        env.retain(|(k, _)| k != "HOME" && k != "TMPDIR");
        env.push(("HOME".into(), "/tmp".into()));
        env.push(("TMPDIR".into(), "/tmp".into()));
        let status: Arc<Mutex<Option<ExitInfo>>> = Arc::default();
        let (policy, toolbox, script, st, k2) = (self.policy.clone(), self.toolbox.clone(), req.script.clone(), status.clone(), kill.clone());
        let (memory, fuel) = ((self.cfg.memory_mb.clamp(16, 4096) as usize) << 20, self.cfg.fuel_slice.max(100_000));
        let pid = PIDS.fetch_add(1, Ordering::Relaxed);
        std::thread::Builder::new()
            .name("seagent-wasm".into())
            // The interpreter and the shell recurse; iOS gives secondary threads 512 KiB. 64 MiB:
            // wasmi translates CPython's largest functions on this stack (16 MiB overflowed).
            // Reserved address space, not resident memory.
            .stack_size(64 << 20)
            .spawn(move || {
                let runner = Runner { toolbox, policy: policy.clone(), kill: k2.clone(), memory, fuel };
                let io = Io { stdin, stdout: Out::Sink(sink.clone()), stderr: Out::Sink(sink) };
                let n = {
                    let mut sh = Shell::new(&policy, &runner, &env, &cwd, k2.clone(), pid);
                    sh.run_script(&script, &io)
                };
                *st.lock().unwrap() = Some(if k2.load(Ordering::SeqCst) { ExitInfo { code: None, signal: Some(9) } } else { ExitInfo::code(n) });
                drop(io);
            })?;
        Ok(Box::new(WasmChild { rx, pending: vec![], stdin: stdin_tx, status, kill }))
    }
    fn map_path(&self, host: &Path) -> String {
        self.policy.guest_of(host).unwrap_or_else(|| host.display().to_string())
    }
    fn shares_host_fs(&self) -> bool {
        true
    }
    fn supports_pty(&self) -> bool {
        false
    }
    fn temp_dir(&self) -> String {
        "/tmp".into()
    }
}

struct WasmChild {
    rx: mpsc::Receiver<Vec<u8>>,
    pending: Vec<u8>,
    stdin: Option<mpsc::Sender<Vec<u8>>>,
    status: Arc<Mutex<Option<ExitInfo>>>,
    kill: Arc<AtomicBool>,
}

impl ExecChild for WasmChild {
    fn pid(&self) -> Option<u32> {
        None
    }
    fn read(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        if self.pending.is_empty() {
            match self.rx.recv_timeout(timeout) {
                Ok(c) => self.pending = c,
                Err(mpsc::RecvTimeoutError::Timeout) => return Err(io::Error::new(io::ErrorKind::TimedOut, "no output yet")),
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(0),
            }
        }
        let n = buf.len().min(self.pending.len());
        buf[..n].copy_from_slice(&self.pending[..n]);
        self.pending.drain(..n);
        Ok(n)
    }
    fn write_stdin(&mut self, data: &[u8]) -> io::Result<()> {
        match &self.stdin {
            Some(t) => t.send(data.to_vec()).map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "command finished")),
            None => Err(io::Error::new(io::ErrorKind::BrokenPipe, "stdin is closed")),
        }
    }
    fn close_stdin(&mut self) {
        self.stdin = None;
    }
    fn try_wait(&mut self) -> io::Result<Option<ExitInfo>> {
        Ok(*self.status.lock().unwrap())
    }
    fn kill(&mut self, _force: bool) {
        self.kill.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests;
