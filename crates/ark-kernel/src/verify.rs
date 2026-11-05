//! Project verification (Hermes `agent/verify/*`, itself a port of grok-cli's verify flow):
//! static run-recipe detection, a user-editable manifest at `.ark/environment.json` that
//! wins over detection, and a smoke-test runner: bootstrap → build → test → start in the
//! background → poll readiness over HTTP → tear the process group down.
//! Commands are the project's own and run with `bash -c` in its checkout (the same trust
//! level as the shell tool).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const DEFAULT_PHASE_TIMEOUT: f64 = 600.0;
pub const DEFAULT_READY_TIMEOUT: f64 = 60.0;
pub const MANIFEST_VERSION: u32 = 1;
const TAIL_CHARS: usize = 2000;
pub const PHASES: &[&str] = &["bootstrap", "build", "test"];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Recipe {
    pub name: String,
    pub kind: String,
    pub bootstrap: Vec<String>,
    pub build: Vec<String>,
    pub test: Vec<String>,
    pub start: Option<String>,
    pub port: Option<u16>,
    pub readiness_path: String,
    pub evidence: Vec<String>,
}

impl Recipe {
    fn new(name: &str, kind: &str) -> Recipe {
        Recipe { name: name.into(), kind: kind.into(), bootstrap: vec![], build: vec![], test: vec![], start: None, port: None, readiness_path: "/".into(), evidence: vec![] }
    }

    /// Tolerant loader: this module's names and grok's camelCase aliases.
    pub fn from_value(raw: &Value) -> Option<Recipe> {
        let o = raw.as_object()?;
        let s = |keys: &[&str]| keys.iter().find_map(|k| o.get(*k).and_then(Value::as_str).map(str::trim).filter(|v| !v.is_empty()).map(String::from));
        let list = |keys: &[&str]| -> Vec<String> {
            keys.iter()
                .find_map(|k| o.get(*k).filter(|v| !v.is_null()))
                .map(|v| match v {
                    Value::String(x) => vec![x.clone()],
                    Value::Array(a) => a.iter().filter_map(Value::as_str).map(String::from).collect(),
                    _ => vec![],
                })
                .unwrap_or_default()
                .into_iter()
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        };
        let name = s(&["name", "appLabel"])?;
        let port = ["port", "startPort"].iter().find_map(|k| match o.get(*k) {
            Some(Value::Number(n)) => n.as_u64(),
            Some(Value::String(x)) => x.trim().parse().ok(),
            _ => None,
        });
        let readiness = s(&["readinessPath", "readiness_path"]).filter(|r| r.starts_with('/')).unwrap_or_else(|| "/".into());
        Some(Recipe {
            name,
            kind: s(&["kind", "appKind"]).unwrap_or_else(|| "unknown".into()),
            bootstrap: list(&["bootstrap", "installCommands"]),
            build: list(&["build", "buildCommands"]),
            test: list(&["test", "testCommands"]),
            start: s(&["start", "startCommand"]),
            port: port.filter(|p| *p > 0 && *p < 65536).map(|p| p as u16),
            readiness_path: readiness,
            evidence: list(&["evidence"]),
        })
    }
}

fn read(root: &Path, name: &str) -> Option<String> {
    std::fs::read_to_string(root.join(name)).ok().map(|s| s.trim_start_matches('\u{feff}').to_string())
}

const LOCKFILES: &[(&str, &str)] = &[("pnpm-lock.yaml", "pnpm"), ("bun.lock", "bun"), ("bun.lockb", "bun"), ("yarn.lock", "yarn"), ("package-lock.json", "npm"), ("uv.lock", "uv"), ("poetry.lock", "poetry"), ("Pipfile.lock", "pipenv")];

pub fn detect_package_manager(root: &Path) -> Option<&'static str> {
    LOCKFILES.iter().find(|(f, _)| root.join(f).exists()).map(|(_, m)| *m)
}

fn infer_port(cmd: &str) -> Option<u16> {
    let re = regex::Regex::new(r"(?:--port|-p)\s+(\d{2,5})|\bPORT=(\d{2,5})\b").ok()?;
    let c = re.captures(cmd)?;
    c.get(1).or(c.get(2))?.as_str().parse().ok()
}

fn dedupe(v: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for x in v.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        if !out.contains(&x) {
            out.push(x);
        }
    }
    out
}

fn node(root: &Path, pkg: &Value) -> Recipe {
    let scripts = pkg["scripts"].as_object().cloned().unwrap_or_default();
    let has = |n: &str| scripts.get(n).and_then(Value::as_str).is_some_and(|s| !s.is_empty());
    let dep = |n: &str| ["dependencies", "devDependencies"].iter().any(|s| pkg[*s].get(n).is_some());
    let pm = detect_package_manager(root);
    let frameworks: &[(&[&str], &str, &str, u16)] = &[
        (&["next"], "nextjs", "Next.js", 3000),
        (&["@sveltejs/kit"], "sveltekit", "SvelteKit", 5173),
        (&["astro"], "astro", "Astro", 4321),
        (&["@remix-run/dev", "@remix-run/react"], "remix", "Remix", 3000),
        (&["react-scripts"], "cra", "Create React App", 3000),
        (&["vite"], "vite", "Vite", 5173),
    ];
    let (kind, label, port) = frameworks.iter().find(|(n, ..)| n.iter().any(|x| dep(x))).map(|(_, k, l, p)| (*k, *l, Some(*p))).unwrap_or(("node", "Node.js app", None));
    let run = |s: &str| match pm {
        Some("pnpm") => format!("pnpm {s}"),
        Some("bun") => format!("bun run {s}"),
        Some("yarn") => format!("yarn {s}"),
        _ => format!("npm run {s}"),
    };
    let runners = |names: &[&str]| dedupe(names.iter().filter(|n| has(n)).map(|n| run(n)).collect());
    let start_script = ["dev", "start"].into_iter().find(|s| has(s));
    let mut r = Recipe::new(label, kind);
    r.start = start_script.map(run);
    r.port = start_script.and_then(|s| infer_port(scripts[s].as_str().unwrap_or("")).or(port));
    r.bootstrap = vec![match pm {
        Some("pnpm") => "pnpm install",
        Some("bun") => "bun install",
        Some("yarn") => "yarn install",
        _ => "npm install",
    }
    .into()];
    r.build = runners(&["build", "typecheck"]);
    r.test = runners(&["test", "check", "lint"]);
    let names: Vec<&str> = scripts.keys().map(String::as_str).collect();
    r.evidence = dedupe(vec!["Detected package.json".into(), pm.map(|p| format!("Package manager: {p}")).unwrap_or_default(), format!("Scripts: {}", if names.is_empty() { "(none)".into() } else { names.join(", ") })]);
    r
}

fn python(root: &Path) -> Option<Recipe> {
    let pyproject = read(root, "pyproject.toml");
    let reqs = read(root, "requirements.txt");
    let manage = root.join("manage.py").exists();
    if pyproject.is_none() && reqs.is_none() && !manage && !root.join("setup.py").exists() {
        return None;
    }
    let lower = format!("{}\n{}", pyproject.as_deref().unwrap_or(""), reqs.as_deref().unwrap_or("")).to_lowercase();
    let install = match detect_package_manager(root) {
        Some("uv") => "uv sync".to_string(),
        Some("poetry") => "poetry install".into(),
        Some("pipenv") => "pipenv install".into(),
        _ if pyproject.is_some() && reqs.is_none() => "pip install -e .".into(),
        _ => "pip install -r requirements.txt".into(),
    };
    let pytest: Vec<String> = if root.join("tests").exists() { vec!["pytest".into()] } else { vec![] };
    let first = |names: &[&str]| names.iter().find(|n| root.join(n).exists()).map(|s| s.to_string());
    if manage || lower.contains("django") {
        let mut r = Recipe::new("Django app", "django");
        r.bootstrap = vec![install];
        r.test = vec!["python manage.py test".into()];
        r.start = Some("python manage.py runserver 0.0.0.0:8000".into());
        r.port = Some(8000);
        r.evidence = vec![if manage { "Detected manage.py" } else { "Detected Django dependency" }.into()];
        if pyproject.is_some() {
            r.evidence.push("Detected pyproject.toml".into());
        }
        return Some(r);
    }
    if lower.contains("fastapi") || lower.contains("uvicorn") {
        let module = first(&["main.py", "app.py"]).unwrap_or_else(|| "main.py".into());
        let mut r = Recipe::new("FastAPI app", "fastapi");
        r.bootstrap = vec![install];
        r.test = pytest;
        r.start = Some(format!("uvicorn {}:app --host 0.0.0.0 --port 8000", module.trim_end_matches(".py")));
        r.port = Some(8000);
        r.evidence = vec!["Detected Python project".into(), "Detected FastAPI/Uvicorn dependency".into()];
        return Some(r);
    }
    if lower.contains("flask") {
        let module = first(&["app.py", "main.py"]).unwrap_or_else(|| "app.py".into());
        let mut r = Recipe::new("Flask app", "flask");
        r.bootstrap = vec![install];
        r.test = pytest;
        r.start = Some(format!("flask --app {module} run --host 0.0.0.0 --port 5000"));
        r.port = Some(5000);
        r.evidence = vec!["Detected Python project".into(), "Detected Flask dependency".into()];
        return Some(r);
    }
    let mut r = Recipe::new("Python project", "python");
    r.bootstrap = vec![install];
    r.test = if pytest.is_empty() { vec!["python -m unittest discover".into()] } else { pytest };
    r.evidence = vec!["Detected Python project".into()];
    Some(r)
}

fn simple(root: &Path) -> Option<Recipe> {
    let tools: &[(&str, &str, &str, &str, &str, &str, &str)] = &[
        ("go.mod", "Go project", "go", "go build ./...", "go test ./...", "go run .", "main.go"),
        ("Cargo.toml", "Rust project", "rust", "cargo build", "cargo test", "cargo run", "src/main.rs"),
    ];
    tools.iter().find(|t| root.join(t.0).exists()).map(|(m, label, kind, build, test, start, entry)| {
        let mut r = Recipe::new(label, kind);
        r.build = vec![build.to_string()];
        r.test = vec![test.to_string()];
        r.start = root.join(entry).exists().then(|| start.to_string());
        r.evidence = vec![format!("Detected {m}")];
        r
    })
}

fn java(root: &Path) -> Option<Recipe> {
    if root.join("pom.xml").exists() {
        let mut r = Recipe::new("Maven project", "maven");
        r.build = vec!["mvn package".into()];
        r.test = vec!["mvn test".into()];
        r.evidence = vec!["Detected pom.xml".into()];
        return Some(r);
    }
    if root.join("build.gradle").exists() || root.join("build.gradle.kts").exists() {
        let g = if root.join("gradlew").exists() { "./gradlew" } else { "gradle" };
        let mut r = Recipe::new("Gradle project", "gradle");
        r.build = vec![format!("{g} build")];
        r.test = vec![format!("{g} test")];
        r.evidence = vec!["Detected Gradle build file".into()];
        return Some(r);
    }
    None
}

fn make(root: &Path) -> Option<Recipe> {
    let mk = read(root, "Makefile")?;
    let re = regex::Regex::new(r"^([A-Za-z0-9_.-]+):(?:\s|$)").ok()?;
    let targets: Vec<String> = mk.lines().filter_map(|l| re.captures(l).map(|c| c[1].to_string())).collect();
    let pick = |names: &[&str]| names.iter().find(|n| targets.iter().any(|t| t == *n)).map(|n| vec![format!("make {n}")]).unwrap_or_default();
    let mut r = Recipe::new("Makefile-driven project", "make");
    r.bootstrap = pick(&["install", "setup", "bootstrap"]);
    r.build = pick(&["build", "compile"]);
    r.test = pick(&["test", "check"]);
    r.start = pick(&["run", "start", "serve", "dev"]).pop();
    r.evidence = vec!["Detected Makefile".into(), format!("Targets: {}", if targets.is_empty() { "(none)".into() } else { targets.join(", ") })];
    Some(r)
}

fn compose(root: &Path) -> Option<Recipe> {
    let f = ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"].into_iter().find(|f| root.join(f).exists())?;
    let mut r = Recipe::new("docker-compose project", "compose");
    r.build = vec!["docker compose build".into()];
    r.start = Some("docker compose up".into());
    r.evidence = vec![format!("Detected {f}")];
    Some(r)
}

/// grok-cli's `inferFallbackRecipe` order: package.json, Python, Go, Rust, Java, Makefile, compose.
pub fn detect_recipe(root: &Path) -> Option<Recipe> {
    if let Some(pkg) = read(root, "package.json").and_then(|s| serde_json::from_str::<Value>(&s).ok()).filter(Value::is_object) {
        return Some(node(root, &pkg));
    }
    python(root).or_else(|| simple(root)).or_else(|| java(root)).or_else(|| make(root)).or_else(|| compose(root))
}

pub fn manifest_path(root: &Path) -> PathBuf {
    root.join(".ark/environment.json")
}

/// A saved manifest (`{version, recipe}` or a bare recipe); anything unreadable → None.
pub fn load_manifest(root: &Path) -> Option<Recipe> {
    let v: Value = serde_json::from_str(&read(root, ".ark/environment.json")?).ok()?;
    Recipe::from_value(v.get("recipe").unwrap_or(&v))
}

pub fn save_manifest(root: &Path, r: &Recipe) -> Result<PathBuf, String> {
    let p = manifest_path(root);
    let payload = json!({"version": MANIFEST_VERSION, "recipe": r, "updatedAt": crate::util::fmt_time(crate::util::unix_now(), 0)});
    crate::util::atomic_write(&p, format!("{}\n", serde_json::to_string_pretty(&payload).unwrap_or_default()).as_bytes()).map_err(|e| format!("{}: {e}", p.display()))?;
    Ok(p)
}

/// (recipe, "manifest" | "detected").
pub fn load_or_detect(root: &Path) -> (Option<Recipe>, &'static str) {
    match load_manifest(root) {
        Some(r) => (Some(r), "manifest"),
        None => (detect_recipe(root), "detected"),
    }
}

// ───────────────────────── runner ─────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhaseResult {
    pub phase: String,
    pub command: String,
    pub exit_code: Option<i32>,
    pub duration: f64,
    pub ok: bool,
    pub timed_out: bool,
    pub output_tail: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Readiness {
    pub url: String,
    pub ready: bool,
    pub status_code: Option<u16>,
    pub duration: f64,
    pub error: Option<String>,
    pub output_tail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyResult {
    pub recipe: String,
    pub ok: bool,
    pub phases: Vec<PhaseResult>,
    pub readiness: Option<Readiness>,
}

#[derive(Debug, Clone)]
pub struct Opts {
    /// Empty = all of bootstrap, build, test, start.
    pub phases: Vec<String>,
    pub phase_timeout: Duration,
    pub ready_timeout: Duration,
    pub skip_start: bool,
    pub port: Option<u16>,
    pub stop_on_failure: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Opts { phases: vec![], phase_timeout: Duration::from_secs_f64(DEFAULT_PHASE_TIMEOUT), ready_timeout: Duration::from_secs_f64(DEFAULT_READY_TIMEOUT), skip_start: false, port: None, stop_on_failure: true }
    }
}

fn tail(s: &str) -> String {
    if s.len() <= TAIL_CHARS {
        return s.to_string();
    }
    let mut i = s.len() - TAIL_CHARS;
    while !s.is_char_boundary(i) {
        i += 1;
    }
    s[i..].to_string()
}

fn spawn_shell(cmd: &str, root: &Path) -> std::io::Result<std::process::Child> {
    use std::os::unix::process::CommandExt;
    let mut c = Command::new("bash");
    c.arg("-c").arg(cmd).current_dir(root).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    // Own process group so teardown reaches the whole tree.
    unsafe {
        c.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    c.spawn()
}

/// Collect stdout+stderr on threads (combined, arrival order per stream).
fn collect(child: &mut std::process::Child) -> std::sync::Arc<std::sync::Mutex<String>> {
    let buf = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    for r in [child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>), child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>)].into_iter().flatten() {
        let b = buf.clone();
        std::thread::spawn(move || {
            let mut r = r;
            let mut chunk = [0u8; 8192];
            while let Ok(n) = r.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                b.lock().unwrap().push_str(&String::from_utf8_lossy(&chunk[..n]));
            }
        });
    }
    buf
}

fn kill_group(child: &mut std::process::Child) {
    let pid = child.id() as i32;
    if let Ok(Some(_)) = child.try_wait() {
        return;
    }
    unsafe { libc::killpg(pid, libc::SIGTERM) };
    let until = Instant::now() + Duration::from_secs(10);
    while Instant::now() < until {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    unsafe { libc::killpg(pid, libc::SIGKILL) };
    let _ = child.wait();
}

pub fn run_phase(phase: &str, cmd: &str, root: &Path, timeout: Duration) -> PhaseResult {
    let started = Instant::now();
    let mut child = match spawn_shell(cmd, root) {
        Ok(c) => c,
        Err(e) => return PhaseResult { phase: phase.into(), command: cmd.into(), exit_code: None, duration: 0.0, ok: false, timed_out: false, output_tail: format!("cannot start bash: {e}") },
    };
    let out = collect(&mut child);
    let (code, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(s)) => break (s.code(), false),
            Ok(None) if started.elapsed() >= timeout => {
                kill_group(&mut child);
                break (None, true);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => break (None, false),
        }
    };
    std::thread::sleep(Duration::from_millis(30)); // let readers drain
    let output = out.lock().unwrap().clone();
    PhaseResult { phase: phase.into(), command: cmd.into(), exit_code: code, duration: started.elapsed().as_secs_f64(), ok: code == Some(0) && !timed_out, timed_out, output_tail: tail(&output) }
}

/// One HTTP GET to 127.0.0.1:port; any HTTP status counts as ready (like upstream's HTTPError).
fn http_status(port: u16, path: &str) -> Result<u16, String> {
    let mut s = std::net::TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_secs(5)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    write!(s, "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nUser-Agent: ark-verify\r\n\r\n").map_err(|e| e.to_string())?;
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).map_err(|e| e.to_string())?;
    let line = String::from_utf8_lossy(&buf[..n]);
    line.split_whitespace().nth(1).and_then(|c| c.parse().ok()).ok_or_else(|| format!("not an HTTP response: {}", line.trim()))
}

fn start_phase(r: &Recipe, root: &Path, ready_timeout: Duration, port: Option<u16>) -> Readiness {
    let port = port.or(r.port).unwrap_or(8000);
    let url = format!("http://127.0.0.1:{port}{}", r.readiness_path);
    let started = Instant::now();
    let mut child = match spawn_shell(r.start.as_deref().unwrap_or(""), root) {
        Ok(c) => c,
        Err(e) => return Readiness { url, ready: false, status_code: None, duration: 0.0, error: Some(e.to_string()), output_tail: String::new() },
    };
    let out = collect(&mut child);
    let mut last = None;
    let mut res = (false, None);
    while started.elapsed() < ready_timeout {
        match http_status(port, &r.readiness_path) {
            Ok(code) => {
                res = (true, Some(code));
                break;
            }
            Err(e) => last = Some(e),
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    kill_group(&mut child);
    std::thread::sleep(Duration::from_millis(30));
    let output = tail(&out.lock().unwrap());
    Readiness { url, ready: res.0, status_code: res.1, duration: started.elapsed().as_secs_f64(), error: if res.0 { None } else { last.or(Some("timeout".into())) }, output_tail: output }
}

/// Why `docker compose build/up` must not run here (live containers), or None.
fn compose_live_reason(root: &Path) -> Option<String> {
    let mut c = Command::new("docker");
    c.args(["compose", "ps", "--status", "running", "--format", "{{.Name}}"]).current_dir(root).stdin(Stdio::null());
    let out = match c.output() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => return Some(format!("docker compose ps failed: {e}")),
        Ok(o) => o,
    };
    if !out.status.success() {
        let d = String::from_utf8_lossy(if out.stderr.is_empty() { &out.stdout } else { &out.stderr }).trim().lines().last().unwrap_or("no output").to_string();
        return Some(format!("docker compose ps failed (exit {}): {d}", out.status.code().unwrap_or(-1)));
    }
    let names: Vec<String> = String::from_utf8_lossy(&out.stdout).lines().filter(|l| !l.trim().is_empty()).map(String::from).collect();
    (!names.is_empty()).then(|| format!("this compose project already has running container(s): {}", names.join(", ")))
}

pub fn run_verify(root: &Path, r: &Recipe, o: &Opts) -> VerifyResult {
    let all: Vec<String> = ["bootstrap", "build", "test", "start"].iter().map(|s| s.to_string()).collect();
    let selected = if o.phases.is_empty() { all } else { o.phases.clone() };
    let mut res = VerifyResult { recipe: r.name.clone(), ok: false, phases: vec![], readiness: None };
    let mutating = selected.iter().any(|p| p == "build") || (selected.iter().any(|p| p == "start") && !o.skip_start);
    if r.kind == "compose" && mutating {
        if let Some(reason) = compose_live_reason(root) {
            res.phases.push(PhaseResult {
                phase: "build".into(),
                command: r.build.first().cloned().unwrap_or_else(|| "docker compose build".into()),
                exit_code: Some(1),
                duration: 0.0,
                ok: false,
                timed_out: false,
                output_tail: format!("Refusing to run: {reason}. `docker compose build` + `up` would replace live containers on an image-hash change, destroying any container-local state they carry. If you intend to rebuild this live deployment, run `docker compose build`/`up` yourself."),
            });
            return res;
        }
    }
    for phase in PHASES {
        if !selected.iter().any(|p| p == phase) {
            continue;
        }
        let cmds = match *phase {
            "bootstrap" => &r.bootstrap,
            "build" => &r.build,
            _ => &r.test,
        };
        for c in cmds {
            let p = run_phase(phase, c, root, o.phase_timeout);
            let failed = !p.ok;
            res.phases.push(p);
            if failed && o.stop_on_failure {
                return res;
            }
        }
    }
    if !o.skip_start && selected.iter().any(|p| p == "start") && r.start.is_some() && res.phases.iter().all(|p| p.ok) {
        res.readiness = Some(start_phase(r, root, o.ready_timeout, o.port));
    }
    res.ok = res.phases.iter().all(|p| p.ok) && res.readiness.as_ref().is_none_or(|x| x.ready);
    res
}

/// `hermes verify`'s human report.
pub fn human_report(r: &Recipe, source: &str, res: &VerifyResult) -> String {
    let mut out = format!("Recipe: {} ({}) — source: {source}\n\n", r.name, r.kind);
    let w = res.phases.iter().map(|p| p.phase.len()).max().unwrap_or(5).max(5);
    if res.phases.is_empty() {
        out.push_str("  (no phases executed)\n");
    }
    for p in &res.phases {
        let st = if p.ok { "PASS" } else if p.timed_out { "TIMEOUT" } else { "FAIL" };
        out.push_str(&format!("  {:w$}  {st:<7}  {:6.1}s  {}\n", p.phase, p.duration, p.command));
    }
    let status = |x: &Readiness| if x.ready { format!("ready (HTTP {})", x.status_code.unwrap_or(0)) } else { format!("not ready ({})", x.error.as_deref().unwrap_or("timeout")) };
    if let Some(x) = &res.readiness {
        out.push_str(&format!("  {:w$}  {:<7}  {:6.1}s  {}\n\nReadiness: {} -> {}\n", "start", if x.ready { "PASS" } else { "FAIL" }, x.duration, r.start.as_deref().unwrap_or(""), x.url, status(x)));
    }
    out.push_str(&format!("\nResult: {}\n", if res.ok { "OK" } else { "FAILED" }));
    for p in res.phases.iter().filter(|p| !p.ok) {
        out.push_str(&format!("\n--- output tail: {} ({}) ---\n{}\n", p.phase, p.command, p.output_tail.trim_end()));
    }
    if let Some(x) = res.readiness.as_ref().filter(|x| !x.ready && !x.output_tail.is_empty()) {
        out.push_str(&format!("\n--- output tail: start ---\n{}\n", x.output_tail.trim_end()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let d = ark_core::tmp::scratch_path(format!("ark-verify-{}", crate::util::random_hex(8)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn detects_node_python_go_rust_java_make_compose() {
        let d = tmp();
        std::fs::write(d.join("package.json"), r#"{"scripts":{"dev":"vite --port 4000","build":"vite build","test":"vitest","lint":"eslint ."},"devDependencies":{"vite":"5"}}"#).unwrap();
        std::fs::write(d.join("pnpm-lock.yaml"), "").unwrap();
        let r = detect_recipe(&d).unwrap();
        assert_eq!((r.kind.as_str(), r.start.as_deref(), r.port), ("vite", Some("pnpm dev"), Some(4000)));
        assert_eq!(r.bootstrap, ["pnpm install"]);
        assert_eq!(r.build, ["pnpm build"]);
        assert_eq!(r.test, ["pnpm test", "pnpm lint"]);

        let d = tmp();
        std::fs::write(d.join("requirements.txt"), "fastapi\nuvicorn").unwrap();
        std::fs::write(d.join("app.py"), "").unwrap();
        let r = detect_recipe(&d).unwrap();
        assert_eq!(r.start.as_deref(), Some("uvicorn app:app --host 0.0.0.0 --port 8000"));
        assert_eq!(r.bootstrap, ["pip install -r requirements.txt"]);
        let d = tmp();
        std::fs::write(d.join("manage.py"), "").unwrap();
        assert_eq!(detect_recipe(&d).unwrap().kind, "django");
        let d = tmp();
        std::fs::write(d.join("pyproject.toml"), "[project]\nname='x'").unwrap();
        std::fs::write(d.join("uv.lock"), "").unwrap();
        let r = detect_recipe(&d).unwrap();
        assert_eq!((r.kind.as_str(), r.bootstrap[0].as_str(), r.test[0].as_str()), ("python", "uv sync", "python -m unittest discover"));

        let d = tmp();
        std::fs::write(d.join("Cargo.toml"), "").unwrap();
        let r = detect_recipe(&d).unwrap();
        assert_eq!((r.test[0].as_str(), r.start.as_deref()), ("cargo test", None));
        let d = tmp();
        std::fs::write(d.join("go.mod"), "").unwrap();
        std::fs::write(d.join("main.go"), "").unwrap();
        assert_eq!(detect_recipe(&d).unwrap().start.as_deref(), Some("go run ."));
        let d = tmp();
        std::fs::write(d.join("build.gradle.kts"), "").unwrap();
        std::fs::write(d.join("gradlew"), "").unwrap();
        assert_eq!(detect_recipe(&d).unwrap().test, ["./gradlew test"]);
        let d = tmp();
        std::fs::write(d.join("Makefile"), "build:\n\tcc x.c\ncheck: build\n\t./t\nserve:\n").unwrap();
        let r = detect_recipe(&d).unwrap();
        assert_eq!((r.build.clone(), r.test.clone(), r.start.clone()), (vec!["make build".to_string()], vec!["make check".to_string()], Some("make serve".to_string())));
        let d = tmp();
        std::fs::write(d.join("compose.yaml"), "").unwrap();
        assert_eq!(detect_recipe(&d).unwrap().kind, "compose");
        assert!(detect_recipe(&tmp()).is_none());
    }

    #[test]
    fn manifest_wins_and_tolerates_aliases() {
        let d = tmp();
        std::fs::write(d.join("Cargo.toml"), "").unwrap();
        assert_eq!(load_or_detect(&d).1, "detected");
        let mut r = detect_recipe(&d).unwrap();
        r.test = vec!["cargo test --lib".into()];
        save_manifest(&d, &r).unwrap();
        let (got, src) = load_or_detect(&d);
        assert_eq!((got.unwrap(), src), (r, "manifest"));
        std::fs::write(manifest_path(&d), r#"{"appLabel":"X","appKind":"k","testCommands":"make t","startPort":"3000","readinessPath":"health"}"#).unwrap();
        let r = load_manifest(&d).unwrap();
        assert_eq!((r.name.as_str(), r.kind.as_str(), r.test.clone(), r.port, r.readiness_path.as_str()), ("X", "k", vec!["make t".to_string()], Some(3000), "/"));
        std::fs::write(manifest_path(&d), "not json").unwrap();
        assert_eq!(load_or_detect(&d).1, "detected", "corrupt manifest degrades to detection");
    }

    #[test]
    fn runner_phases_stop_on_failure_timeout_and_readiness() {
        let d = tmp();
        let mut r = Recipe::new("t", "make");
        r.bootstrap = vec!["echo boot".into()];
        r.build = vec!["echo building; exit 3".into()];
        r.test = vec!["echo never".into()];
        let res = run_verify(&d, &r, &Opts::default());
        assert!(!res.ok);
        assert_eq!(res.phases.len(), 2);
        assert_eq!(res.phases[1].exit_code, Some(3));
        assert!(res.phases[1].output_tail.contains("building"));
        assert!(human_report(&r, "detected", &res).contains("--- output tail: build (echo building; exit 3) ---"));
        let res = run_verify(&d, &r, &Opts { phases: vec!["test".into()], ..Default::default() });
        assert!(res.ok && res.phases.len() == 1);
        let mut slow = Recipe::new("s", "x");
        slow.test = vec!["sleep 5".into()];
        let res = run_verify(&d, &slow, &Opts { phase_timeout: Duration::from_millis(300), ..Default::default() });
        assert!(res.phases[0].timed_out && !res.ok);
        assert!(human_report(&slow, "manifest", &res).contains("TIMEOUT"));

        // Start + readiness against a tiny HTTP server the recipe itself runs.
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let mut app = Recipe::new("app", "python");
        app.start = Some(format!("exec python3 -c \"import http.server as h; h.HTTPServer(('127.0.0.1', {port}), h.SimpleHTTPRequestHandler).serve_forever()\""));
        app.port = Some(port);
        let res = run_verify(&d, &app, &Opts { ready_timeout: Duration::from_secs(15), ..Default::default() });
        let rd = res.readiness.clone().unwrap();
        assert!(rd.ready && rd.status_code == Some(200) && res.ok, "{rd:?}");
        assert!(http_status(port, "/").is_err(), "process group torn down");
        let res = run_verify(&d, &app, &Opts { skip_start: true, ..Default::default() });
        assert!(res.readiness.is_none());
        app.start = Some("sleep 30".into());
        let res = run_verify(&d, &app, &Opts { ready_timeout: Duration::from_millis(500), port: Some(port), ..Default::default() });
        assert!(!res.ok && !res.readiness.unwrap().ready);
        let v = serde_json::to_value(&res.phases).unwrap();
        assert!(v.is_array());
    }
}
