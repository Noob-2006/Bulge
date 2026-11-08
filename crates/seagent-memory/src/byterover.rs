//! ByteRover memory provider (Hermes plugins/memory/byterover, MIT): the `brv` CLI's
//! hierarchical context tree. Prefetch = `brv query`, turn sync / memory mirror /
//! pre-compression flush = `brv curate`, tools brv_query / brv_curate / brv_status.

use crate::manager::Provider;
use crate::util::{clip, resolve_value};
use crate::Host;
use seagent_core::{Effect, Message, Role, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
pub const CURATE_TIMEOUT: Duration = Duration::from_secs(120);
const MIN_QUERY_LEN: usize = 10;
const MIN_OUTPUT_LEN: usize = 20;

pub struct Byterover {
    pub binary: Option<PathBuf>,
    pub cwd: PathBuf,
    pub auto_extract: bool,
    pub api_key: String,
}

fn find_brv() -> Option<PathBuf> {
    // Windows: npm installs `brv.cmd` (PATHEXT), under %APPDATA%\npm.
    #[cfg(windows)]
    if let Some(p) = seagent_core::platform::layout::which("brv") {
        return Some(p);
    }
    if let Some(p) = std::env::var_os("PATH") {
        for d in std::env::split_paths(&p) {
            let c = d.join("brv");
            if c.is_file() {
                return Some(c);
            }
        }
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    [home.join(".brv-cli/bin/brv"), PathBuf::from("/usr/local/bin/brv"), home.join(".npm-global/bin/brv")].into_iter().find(|c| c.is_file())
}

/// Run a command with a timeout; Ok(stdout) on exit 0, Err(stderr|stdout|exit) otherwise.
pub fn run_with_timeout(bin: &Path, args: &[&str], cwd: &Path, env: &[(&str, &str)], timeout: Duration) -> Result<String, String> {
    let _ = std::fs::create_dir_all(cwd);
    let mut cmd = Command::new(bin);
    cmd.args(args).current_dir(cwd).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().map_err(|e| if e.kind() == std::io::ErrorKind::NotFound { "brv CLI not found".to_string() } else { e.to_string() })?;
    let start = Instant::now();
    loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(status) => {
                let (mut out, mut err) = (String::new(), String::new());
                if let Some(mut o) = child.stdout.take() {
                    let _ = o.read_to_string(&mut out);
                }
                if let Some(mut e) = child.stderr.take() {
                    let _ = e.read_to_string(&mut err);
                }
                return if status.success() { Ok(out) } else { Err(if !err.trim().is_empty() { err.trim().to_string() } else if !out.trim().is_empty() { out.trim().to_string() } else { format!("brv exited {}", status.code().unwrap_or(-1)) }) };
            }
            None if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("brv timed out after {}s", timeout.as_secs()));
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

impl Byterover {
    pub fn new(h: &Host) -> Byterover {
        let s = &h.settings.byterover;
        let binary = if s.binary.is_empty() { find_brv() } else { Some(seagent_core::tool::expand_home(&s.binary)) };
        let cwd = if s.cwd.is_empty() { h.data.join("byterover") } else { seagent_core::tool::expand_home(&s.cwd) };
        Byterover { binary, cwd, auto_extract: s.auto_extract, api_key: resolve_value(&h.subst, &s.api_key, &["BRV_API_KEY"]) }
    }
    fn brv(&self, args: &[&str], timeout: Duration) -> Result<String, String> {
        let bin = self.binary.as_ref().ok_or("brv CLI not found. Install: npm install -g byterover-cli")?;
        let env: Vec<(&str, &str)> = if self.api_key.is_empty() { vec![] } else { vec![("BRV_API_KEY", self.api_key.as_str())] };
        run_with_timeout(bin, args, &self.cwd, &env, timeout)
    }
    pub fn query(&self, q: &str) -> Result<String, String> {
        let q = clip(q.trim(), 5000);
        self.brv(&["query", "--", &q], QUERY_TIMEOUT)
    }
    pub fn curate(&self, content: &str) -> Result<String, String> {
        self.brv(&["curate", "--", content], CURATE_TIMEOUT)
    }
}

impl Provider for Byterover {
    fn name(&self) -> String {
        "byterover".into()
    }
    fn prefetch(&self, _: &str, query: &str) -> Option<String> {
        if query.trim().chars().count() < MIN_QUERY_LEN {
            return None;
        }
        let out = self.query(query).ok()?;
        let out = out.trim();
        (out.chars().count() > MIN_OUTPUT_LEN).then(|| format!("## ByteRover Context\n{out}"))
    }
    fn sync_turn(&self, _: &str, user: &str, assistant: &str) {
        if self.auto_extract && user.trim().chars().count() >= MIN_QUERY_LEN {
            let _ = self.curate(&format!("User: {}\nAssistant: {}", clip(user, 2000), clip(assistant, 2000)));
        }
    }
    fn on_memory_write(&self, action: &str, target: &str, content: &str) {
        if self.auto_extract && (action == "add" || action == "replace" || action == "patch") && !content.is_empty() {
            let label = if target == "user" { "User profile" } else { "Agent memory" };
            let _ = self.curate(&format!("[{label}] {content}"));
        }
    }
    fn pre_compress(&self, _: &str, messages: &[Message]) -> Option<String> {
        if !self.auto_extract || messages.is_empty() {
            return None;
        }
        let parts: Vec<String> = messages.iter().rev().take(10).rev().map(|m| (m.role, m.text())).filter(|(_, t)| !t.trim().is_empty()).map(|(r, t)| format!("{}: {}", if r == Role::User { "user" } else { "assistant" }, clip(&t, 500))).collect();
        if !parts.is_empty() {
            let _ = self.curate(&format!("[Pre-compression context]\n{}", parts.join("\n")));
        }
        None
    }
}

pub fn tools(b: &Arc<Byterover>) -> Vec<Arc<dyn Tool>> {
    ["brv_query", "brv_curate", "brv_status"].iter().map(|n| Arc::new(BrvTool(b.clone(), n)) as Arc<dyn Tool>).collect()
}

pub struct BrvTool(pub Arc<Byterover>, pub &'static str);

impl Tool for BrvTool {
    fn spec(&self) -> ToolSpec {
        let (desc, arg, arg_desc) = match self.1 {
            "brv_query" => ("Search ByteRover's persistent knowledge tree for relevant context. Returns memories, project knowledge, architectural decisions, and patterns from previous sessions. Use for any question where past context would help.", "query", "What to search for."),
            "brv_curate" => ("Store important information in ByteRover's persistent knowledge tree. Use for architectural decisions, bug fixes, user preferences, project patterns — anything worth remembering across sessions. ByteRover's LLM automatically categorizes and organizes the memory.", "content", "The information to remember."),
            _ => ("Check ByteRover status — CLI version, context tree stats, cloud sync state.", "", ""),
        };
        let schema = if arg.is_empty() { json!({"type":"object","properties":{}}) } else { json!({"type":"object","properties":{arg:{"type":"string","description":arg_desc}},"required":[arg]}) };
        ToolSpec { name: self.1.into(), description: desc.into(), input_schema: schema, parallel_safe: self.1 != "brv_curate", idempotent: self.1 != "brv_curate", pinned: false }
    }
    fn effects(&self, _: &ToolCtx, input: &Value) -> Vec<Effect> {
        let cmd = match self.1 {
            "brv_query" => format!("brv query -- {}", input["query"].as_str().unwrap_or("")),
            "brv_curate" => format!("brv curate -- {}", input["content"].as_str().unwrap_or("")),
            _ => "brv status".into(),
        };
        vec![Effect::Exec { command: cmd }]
    }
    fn call(&self, _: &ToolCtx, input: Value) -> ToolOutput {
        let arg = |k: &str| input[k].as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
        let r = match self.1 {
            "brv_query" => match arg("query") {
                None => return ToolOutput::err("query is required"),
                Some(q) => self.0.query(&q).map(|o| {
                    let o = o.trim();
                    if o.chars().count() < MIN_OUTPUT_LEN {
                        json!({"result": "No relevant memories found."})
                    } else if o.chars().count() > 8000 {
                        json!({"result": format!("{}\n\n[... truncated]", clip(o, 8000))})
                    } else {
                        json!({"result": o})
                    }
                }),
            },
            "brv_curate" => match arg("content") {
                None => return ToolOutput::err("content is required"),
                Some(c) => self.0.curate(&c).map(|_| json!({"result": "Memory curated successfully."})),
            },
            _ => self.0.brv(&["status"], Duration::from_secs(15)).map(|o| json!({"status": o})),
        };
        match r {
            Ok(v) => ToolOutput::ok(v.to_string()),
            Err(e) => ToolOutput::err(json!({"error": e}).to_string()),
        }
    }
}

// Unix only: the fake `brv` CLI is a `#!/bin/sh` script.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn fake_brv_cli() {
        let h = crate::test_host("brv", |_| {});
        let bin = h.data.join("brv");
        std::fs::write(&bin, "#!/bin/sh\necho \"$@\" >> \"$PWD/calls.log\"\ncase \"$1\" in\n query) echo \"Found: user deploys with blue-green rollouts\";;\n curate) echo ok;;\n status) echo 'brv 1.2.3, 42 nodes';;\n fail) echo boom >&2; exit 3;;\nesac\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let b = Arc::new(Byterover { binary: Some(bin), cwd: h.data.join("byterover"), auto_extract: true, api_key: String::new() });
        assert_eq!(b.prefetch("s", "how do we deploy billing?").unwrap(), "## ByteRover Context\nFound: user deploys with blue-green rollouts");
        assert!(b.prefetch("s", "hi").is_none(), "short query");
        b.sync_turn("s", "we switched to postgres", "noted");
        b.on_memory_write("add", "user", "likes tea");
        b.pre_compress("s", &[Message::user("old context here")]);
        let log = std::fs::read_to_string(h.data.join("byterover/calls.log")).unwrap();
        assert!(log.contains("curate -- User: we switched to postgres") && log.contains("[User profile] likes tea") && log.contains("[Pre-compression context]"));
        let t = tools(&b);
        let c = crate::tools::tests_ctx(&h.data);
        assert!(t[0].call(&c, json!({"query":"deploy"})).content.contains("blue-green"));
        assert!(t[1].call(&c, json!({})).is_error);
        assert!(t[2].call(&c, json!({})).content.contains("42 nodes"));
        assert_eq!(b.brv(&["fail"], QUERY_TIMEOUT).unwrap_err(), "boom");
        let none = Byterover { binary: None, ..Byterover { binary: None, cwd: h.data.clone(), auto_extract: true, api_key: String::new() } };
        assert!(none.query("x").unwrap_err().contains("not found"));
    }
}
