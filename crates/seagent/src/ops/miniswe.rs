//! `seagent batch swe` (Hermes `mini_swe_runner.py`): a minimal tool-calling loop with a single
//! `terminal` tool, run in a local directory or a Docker container, that writes trajectories
//! in the Hermes ShareGPT format (compatible with `seagent batch compress`). A task is complete
//! when the model stops calling tools or a command prints `MINI_SWE_AGENT_FINAL_OUTPUT`.
//! Modal sandboxes are not offered (proprietary cloud service; use `--env docker`).

use crate::args::Args;
use crate::R;
use seagent_core::{Block, Cancel, Message, ModelRequest, Provider, Role, SystemSegment, ToolSchema};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const FINAL_MARKER: &str = "MINI_SWE_AGENT_FINAL_OUTPUT";

const TERMINAL_DESCRIPTION: &str = "Execute bash commands in a sandboxed environment.\n\n**Environment:**\n- Isolated execution environment (local, Docker, or Modal cloud)\n- Filesystem persists between tool calls within the same task\n- Internet access available\n\n**Command Execution:**\n- Provide the command to execute via the 'command' parameter\n- Optional 'timeout' parameter in seconds (default: 60)\n\n**Examples:**\n- Run command: `{\"command\": \"ls -la\"}`\n- With timeout: `{\"command\": \"long_task.sh\", \"timeout\": 300}`\n\n**Best Practices:**\n- Use non-interactive commands (avoid vim, nano, interactive python)\n- Pipe to cat if output might be large\n- Install tools with apt-get or pip as needed\n\n**Completion:**\n- When task is complete, output: echo \"MINI_SWE_AGENT_FINAL_OUTPUT\" followed by your result\n";

pub const SYSTEM_PROMPT: &str = "You are an AI agent that can execute bash commands to complete tasks.\n\nWhen you need to run commands, use the 'terminal' tool with your bash command.\n\n**Important:**\n- When you have completed the task successfully, run: echo \"MINI_SWE_AGENT_FINAL_OUTPUT\" followed by a summary\n- Be concise and efficient in your approach\n- Install any needed tools with apt-get or pip\n- Avoid interactive commands (no vim, nano, less, etc.)\n\nComplete the user's task step by step.";

fn terminal_schema() -> Value {
    json!({"type": "object", "properties": {"command": {"type": "string", "description": "The bash command to execute"}, "timeout": {"type": "integer", "description": "Command timeout in seconds (default: 60)"}}, "required": ["command"]})
}

/// Where commands run.
pub enum Env {
    Local { cwd: PathBuf },
    Docker { bin: String, id: String, cwd: String },
}

pub(crate) fn run_capture(mut cmd: Command, timeout: Duration) -> Result<(String, i32), String> {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| e.to_string())?;
    let (mut so, mut se) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let ho = std::thread::spawn(move || {
        let mut v = vec![];
        let _ = so.read_to_end(&mut v);
        v
    });
    let he = std::thread::spawn(move || {
        let mut v = vec![];
        let _ = se.read_to_end(&mut v);
        v
    });
    let start = Instant::now();
    let st = loop {
        if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
            break s;
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("Command timed out after {}s", timeout.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut out = String::from_utf8_lossy(&ho.join().unwrap_or_default()).into_owned();
    out.push_str(&String::from_utf8_lossy(&he.join().unwrap_or_default()));
    Ok((out, st.code().unwrap_or(-1)))
}

impl Env {
    #[cfg(test)]
    pub fn create(kind: &str, image: &str, cwd: Option<&Path>, docker_bin: &str) -> Result<Env, String> {
        Env::create_named(kind, image, cwd, docker_bin, None)
    }
    /// Like [`Env::create`]; a container gets `--name NAME` (evaluation runs name theirs
    /// `seagent-test-eval-*` so they are recognisable and never confused with the user's own).
    pub fn create_named(kind: &str, image: &str, cwd: Option<&Path>, docker_bin: &str, name: Option<&str>) -> Result<Env, String> {
        match kind {
            "local" => Ok(Env::Local { cwd: cwd.map(Path::to_path_buf).unwrap_or_else(std::env::temp_dir) }),
            "docker" => {
                let cwd = cwd.map(|p| p.display().to_string()).unwrap_or_else(|| "/tmp".into());
                let mut c = seagent_core::platform::proc::command(docker_bin);
                c.args(["run", "-d", "--rm"]);
                if let Some(n) = name {
                    c.args(["--name", n]);
                }
                c.args(["-w", &cwd, image, "sleep", "infinity"]);
                let (out, code) = run_capture(c, Duration::from_secs(600))?;
                if code != 0 {
                    return Err(format!("docker run failed: {}", out.trim()));
                }
                Ok(Env::Docker { bin: docker_bin.into(), id: out.trim().lines().last().unwrap_or("").to_string(), cwd })
            }
            "modal" => Err("the modal environment needs Modal's hosted sandboxes, which seagent does not drive; use --env docker".into()),
            o => Err(format!("Unknown environment type: {o}. Use 'local' or 'docker'")),
        }
    }
    /// The container id (docker env only).
    pub fn container_id(&self) -> Option<&str> {
        match self {
            Env::Docker { id, .. } => Some(id),
            Env::Local { .. } => None,
        }
    }
    /// The container CLI (docker env only).
    pub fn container_bin(&self) -> Option<&str> {
        match self {
            Env::Docker { bin, .. } => Some(bin),
            Env::Local { .. } => None,
        }
    }
    pub fn kind(&self) -> &'static str {
        match self {
            Env::Local { .. } => "local",
            Env::Docker { .. } => "docker",
        }
    }
    /// `{output, exit_code, error}` like upstream.
    pub fn execute(&self, command: &str, timeout: u64) -> Value {
        let mut c = match self {
            Env::Local { cwd } => {
                let mut c = seagent_core::platform::layout::program_command("bash");
                c.arg("-c").arg(command).current_dir(cwd);
                c
            }
            Env::Docker { bin, id, cwd } => {
                let mut c = seagent_core::platform::proc::command(bin);
                c.args(["exec", "-w", cwd, id, "bash", "-lc", command]);
                c
            }
        };
        c.env("TERM", "dumb");
        match run_capture(c, Duration::from_secs(timeout.max(1))) {
            Ok((output, code)) => json!({"output": output, "exit_code": code, "error": null}),
            Err(e) => json!({"output": "", "exit_code": -1, "error": e}),
        }
    }
    pub fn cleanup(&self) {
        if let Env::Docker { bin, id, .. } = self {
            let mut c = seagent_core::platform::proc::command(bin);
            c.args(["rm", "-f", id]);
            let _ = run_capture(c, Duration::from_secs(60));
        }
    }
}

pub struct Runner {
    pub provider: Arc<dyn Provider>,
    pub model: String,
    pub env_kind: String,
    pub image: String,
    pub cwd: Option<PathBuf>,
    pub docker_bin: String,
    pub max_iterations: u32,
    pub command_timeout: u64,
    /// `--name` for the docker env's container (None = runtime-chosen).
    pub container_name: Option<String>,
}

/// Removes the task container even when the loop or a caller's hook panics.
struct EnvGuard<'a>(&'a Env);

impl Drop for EnvGuard<'_> {
    fn drop(&mut self) {
        self.0.cleanup();
    }
}

fn tools_json() -> String {
    json!([{"name": "terminal", "description": TERMINAL_DESCRIPTION, "parameters": terminal_schema(), "required": null}]).to_string()
}

fn gpt_content(reasoning: &str, content: &str) -> String {
    (if reasoning.is_empty() { String::new() } else { format!("<think>{reasoning}</think>") }) + content
}

/// The Hermes trajectory for a mini-SWE conversation (`messages[0]` is the task).
pub fn to_hermes(messages: &[Message], task: &str) -> Vec<Value> {
    let sys = seagent_kernel::trajectory::TRAJECTORY_SYSTEM_PROMPT.replace("{tools}", &tools_json());
    let mut t = vec![json!({"from": "system", "value": sys}), json!({"from": "human", "value": task})];
    let mut i = 1;
    while i < messages.len() {
        let m = &messages[i];
        let text: String = m.content.iter().filter_map(|b| if let Block::Text { text } = b { Some(text.as_str()) } else { None }).collect::<Vec<_>>().join("\n");
        let reasoning: String = m.content.iter().filter_map(|b| if let Block::Thinking { text, .. } = b { Some(text.as_str()) } else { None }).collect::<Vec<_>>().join("\n");
        let calls: Vec<(&str, &Value)> = m.content.iter().filter_map(|b| if let Block::ToolUse { name, input, .. } = b { Some((name.as_str(), input)) } else { None }).collect();
        match m.role {
            Role::User => t.push(json!({"from": "human", "value": text})),
            Role::Assistant if calls.is_empty() => t.push(json!({"from": "gpt", "value": gpt_content(&reasoning, &text)})),
            Role::Assistant => {
                let mut c = if text.is_empty() { String::new() } else { text.clone() + "\n" };
                for (n, inp) in &calls {
                    c += &format!("<tool_call>\n{}\n</tool_call>\n", json!({"name": n, "arguments": inp}));
                }
                t.push(json!({"from": "gpt", "value": gpt_content(&reasoning, &c).trim_end()}));
                if let Some(next) = messages.get(i + 1).filter(|n| n.content.iter().any(|b| matches!(b, Block::ToolResult { .. }))) {
                    let resp: Vec<String> = next.content.iter().enumerate().filter_map(|(k, b)| match b {
                        Block::ToolResult { tool_use_id, content, .. } => {
                            let c: Value = if content.trim_start().starts_with(['{', '[']) { serde_json::from_str(content).unwrap_or(json!(content)) } else { json!(content) };
                            Some(format!("<tool_response>\n{}\n</tool_response>", json!({"tool_call_id": tool_use_id, "name": calls.get(k).map(|c| c.0).unwrap_or("unknown"), "content": c})))
                        }
                        _ => None,
                    }).collect();
                    t.push(json!({"from": "tool", "value": resp.join("\n")}));
                    i += 1;
                }
            }
        }
        i += 1;
    }
    t
}

impl Runner {
    pub fn run_task(&self, task: &str) -> Result<Value, String> {
        self.run_task_then(task, &mut |_| {})
    }

    /// Run the task, then call `after` with the still-live environment (graders, patch
    /// extraction) before it is torn down.
    pub fn run_task_then(&self, task: &str, after: &mut dyn FnMut(&Env)) -> Result<Value, String> {
        let env = Env::create_named(&self.env_kind, &self.image, self.cwd.as_deref(), &self.docker_bin, self.container_name.as_deref())?;
        let _guard = EnvGuard(&env);
        let mut messages = vec![Message::user(task)];
        let (mut calls, mut completed) = (0u32, false);
        let tool = ToolSchema { name: "terminal".into(), description: TERMINAL_DESCRIPTION.into(), input_schema: terminal_schema() };
        while calls < self.max_iterations {
            calls += 1;
            let req = ModelRequest { model: self.model.clone(), system: vec![SystemSegment { id: "mini-swe".into(), text: SYSTEM_PROMPT.into(), cache: false }], messages: messages.clone(), tools: vec![tool.clone()], max_tokens: 4096, ..Default::default() };
            let r = match self.provider.complete(&req, &mut |_| {}, &Cancel::new()) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("API call failed: {e}");
                    break;
                }
            };
            let uses: Vec<(String, Value)> = r.message.content.iter().filter_map(|b| if let Block::ToolUse { id, input, .. } = b { Some((id.clone(), input.clone())) } else { None }).collect();
            messages.push(Message { role: Role::Assistant, content: r.message.content.clone() });
            if uses.is_empty() {
                completed = true;
                break;
            }
            let mut results = vec![];
            let mut done = false;
            for (id, input) in uses {
                let cmd = input.get("command").and_then(|c| c.as_str()).unwrap_or("echo 'No command provided'");
                let to = input.get("timeout").and_then(|t| t.as_u64()).unwrap_or(self.command_timeout);
                let res = env.execute(cmd, to);
                if res["output"].as_str().unwrap_or("").contains(FINAL_MARKER) {
                    done = true;
                }
                results.push(Block::ToolResult { tool_use_id: id, content: json!({"content": res}).to_string(), is_error: false });
            }
            messages.push(Message { role: Role::User, content: results });
            if done {
                completed = true;
                break;
            }
        }
        after(&env);
        Ok(json!({"conversations": to_hermes(&messages, task), "completed": completed, "api_calls": calls, "metadata": {"model": self.model, "env_type": env.kind(), "timestamp": seagent_kernel::trajectory::iso_ms(seagent_kernel::event::now_ms()).trim_end_matches('Z')}}))
    }

    pub fn run_batch(&self, prompts: &[String], out: &Path) -> Result<Vec<Value>, String> {
        let mut f = std::fs::File::create(out).map_err(|e| format!("{}: {e}", out.display()))?;
        let mut v = vec![];
        for (i, p) in prompts.iter().enumerate() {
            eprintln!("task {}/{}", i + 1, prompts.len());
            let r = self.run_task(p).unwrap_or_else(|e| json!({"conversations": [], "completed": false, "api_calls": 0, "error": e, "metadata": {"timestamp": seagent_kernel::trajectory::iso_ms(seagent_kernel::event::now_ms())}}));
            writeln!(f, "{r}").map_err(|e| e.to_string())?;
            f.flush().map_err(|e| e.to_string())?;
            v.push(r);
        }
        Ok(v)
    }
}

/// One prompt per non-blank line: JSON `{"prompt"|"task": …}` or raw text.
pub fn load_prompts(text: &str) -> Vec<String> {
    text.lines().map(str::trim).filter(|l| !l.is_empty()).map(|l| match serde_json::from_str::<Value>(l) {
        Ok(Value::Object(o)) => o.get("prompt").or_else(|| o.get("task")).and_then(|v| v.as_str()).unwrap_or("").to_string(),
        _ => l.to_string(),
    }).collect()
}

pub fn cli(a: &Args) -> R {
    let mut args = vec![];
    if let Some(m) = a.val("model") {
        args.extend(["--model".to_string(), m.to_string()]);
    }
    let ba = Args::parse(&args).map_err(crate::Fail::Usage)?;
    let c = crate::build_agent(&ba, crate::approver_for(&ba, false), false)?;
    let model = a.val("model").map(String::from).unwrap_or_else(|| c.k.cfg.model.default.clone());
    let (pid, name) = seagent_kernel::context::split_model(&model);
    let r = Runner {
        provider: c.k.resolver.provider(pid)?,
        model: name.to_string(),
        env_kind: a.val("env").unwrap_or("local").into(),
        image: a.val("image").unwrap_or("python:3.11-slim").into(),
        cwd: a.val("cwd").map(PathBuf::from),
        docker_bin: "docker".into(),
        max_iterations: a.num::<u32>("max-iterations")?.unwrap_or(15),
        command_timeout: a.num::<u64>("command-timeout")?.unwrap_or(60),
        container_name: None,
    };
    match (a.val("task"), a.val("prompts")) {
        (Some(t), _) => {
            let res = r.run_task(t)?;
            let out = a.val("out").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("swe-runner-test1.jsonl"));
            std::fs::write(&out, format!("{res}\n")).map_err(|e| e.to_string())?;
            println!("completed={} api_calls={} → {}", res["completed"], res["api_calls"], out.display());
            Ok(0)
        }
        (None, Some(p)) => {
            let prompts = load_prompts(&std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))?);
            let out = a.val("out").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("swe-runner-test1.jsonl"));
            let v = r.run_batch(&prompts, &out)?;
            println!("batch complete: {} trajectories saved to {}", v.len(), out.display());
            Ok(0)
        }
        _ => crate::usage("usage: seagent batch swe (--task TEXT | --prompts FILE) [--out FILE] [--env local|docker] [--image IMG] [--cwd DIR] [--max-iterations 15] [--command-timeout 60] [-m MODEL]"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_core::*;
    use std::sync::Mutex;

    /// Calls `terminal` with the scripted commands, then answers.
    struct Script(Mutex<Vec<&'static str>>, Mutex<usize>);
    impl Provider for Script {
        fn id(&self) -> &str {
            "s"
        }
        fn caps(&self, _: &str) -> ModelCaps {
            ModelCaps { context_window: 1000, max_output: 100, tools: true, vision: false, explicit_cache: false }
        }
        fn complete(&self, req: &ModelRequest, _: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, ProviderError> {
            assert_eq!(req.tools[0].name, "terminal");
            assert!(req.system[0].text.contains(FINAL_MARKER));
            *self.1.lock().unwrap() += 1;
            let next = self.0.lock().unwrap().pop();
            let message = match next {
                Some(cmd) => Message { role: Role::Assistant, content: vec![Block::Thinking { text: "plan".into(), signature: None }, Block::text("running"), Block::ToolUse { id: format!("c{}", *self.1.lock().unwrap()), name: "terminal".into(), input: json!({"command": cmd}) }] },
                None => Message::assistant("all done"),
            };
            Ok(ModelResponse { message, stop: StopReason::EndTurn, usage: Usage::default(), model: "s/m".into() })
        }
    }

    fn runner(cmds: Vec<&'static str>, cwd: &Path, env: &str, bin: &str) -> Runner {
        Runner { provider: Arc::new(Script(Mutex::new(cmds), Mutex::new(0))), model: "m".into(), env_kind: env.into(), image: "python:3.11-slim".into(), cwd: Some(cwd.into()), docker_bin: bin.into(), max_iterations: 5, command_timeout: 5, container_name: None }
    }

    fn dir() -> PathBuf {
        seagent_core::tmp::scratch("seagent-swe")
    }

    #[test]
    fn local_task_stops_on_final_marker() {
        let d = dir();
        // popped from the end: first `echo hi > f.txt`, then the marker
        let r = runner(vec!["cat f.txt; echo MINI_SWE_AGENT_FINAL_OUTPUT ok", "echo hi > f.txt"], &d, "local", "docker");
        let v = r.run_task("make f.txt").unwrap();
        assert_eq!((v["completed"].as_bool(), v["api_calls"].as_u64()), (Some(true), Some(2)));
        assert_eq!(std::fs::read_to_string(d.join("f.txt")).unwrap(), "hi\n");
        let c = v["conversations"].as_array().unwrap();
        assert!(c[0]["value"].as_str().unwrap().contains("\"name\":\"terminal\""));
        assert_eq!(c[1]["value"], "make f.txt");
        assert!(c[2]["value"].as_str().unwrap().starts_with("<think>plan</think>running\n<tool_call>"));
        assert!(c[5]["value"].as_str().unwrap().contains("MINI_SWE_AGENT_FINAL_OUTPUT ok"));
        assert_eq!(c.len(), 6);
        // no tool call → completed on first answer
        let v = runner(vec![], &d, "local", "docker").run_task("hello").unwrap();
        assert_eq!(v["conversations"][2]["value"], "all done");
        assert!(Env::create("modal", "x", None, "docker").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn docker_env_and_batch_file() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        let d = dir();
        let fake = d.join("docker");
        std::fs::write(&fake, format!("#!/bin/sh\necho \"$@\" >> {0}/log\ncase \"$1\" in run) echo cid123;; exec) shift 4; sh -c \"$3\";; esac\n", d.display())).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let r = runner(vec!["echo MINI_SWE_AGENT_FINAL_OUTPUT"], &d, "docker", fake.to_str().unwrap());
        let out = d.join("t.jsonl");
        let v = r.run_batch(&load_prompts("{\"task\": \"t1\"}\nraw prompt\n\n"), &out).unwrap();
        assert_eq!(v.len(), 2);
        let log = std::fs::read_to_string(d.join("log")).unwrap();
        assert!(log.contains("run -d --rm -w") && log.contains("python:3.11-slim sleep infinity"));
        assert!(log.contains("exec -w") && log.contains("cid123 bash -lc echo MINI_SWE_AGENT_FINAL_OUTPUT"));
        assert!(log.contains("rm -f cid123"));
        assert_eq!(std::fs::read_to_string(out).unwrap().lines().count(), 2);
    }
}
