//! External agent CLIs as model backends (OpenClaw `src/agents/cli-backends.ts` with the
//! Claude/Gemini/Codex backend configs; Hermes `copilot-acp`): one process per request,
//! the conversation rendered as a prompt, the CLI's own tools and subscription login do
//! the work, and its stream-json / JSONL output is parsed back into text + usage.

use crate::{finalize_usage, ProviderConfig};
use seagent_core::*;
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub struct CliBackend {
    id: String,
    command: String,
    args: Vec<String>,
    dialect: String,
    timeout: Duration,
    env: Vec<(String, String)>,
}

/// Env vars removed for Claude Code so it runs on the subscription login, not a stray API key.
const CLAUDE_CLEAR_ENV: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
];

impl CliBackend {
    pub fn new(cfg: &ProviderConfig) -> Result<CliBackend, String> {
        let command = cfg
            .command
            .clone()
            .filter(|c| !c.is_empty())
            .ok_or_else(|| format!("provider `{}`: format \"cli\" needs `command`", cfg.id))?;
        let dialect = cfg.dialect.clone().unwrap_or_else(|| "text".into());
        if ![
            "text",
            "claude-stream-json",
            "gemini-stream-json",
            "codex-jsonl",
        ]
        .contains(&dialect.as_str())
        {
            return Err(format!(
                "provider `{}`: unknown CLI dialect `{dialect}`",
                cfg.id
            ));
        }
        Ok(CliBackend {
            id: cfg.id.clone(),
            command,
            args: cfg.args.clone(),
            dialect,
            timeout: Duration::from_secs(cfg.idle_timeout_secs.unwrap_or(1800).max(1)),
            env: cfg
                .headers
                .iter()
                .filter_map(|(k, v)| k.strip_prefix("env:").map(|k| (k.to_string(), v.clone())))
                .collect(),
        })
    }

    fn prompt(req: &ModelRequest) -> String {
        let sys = req.system_text();
        let convo = crate::transcript(req);
        let only_user = req.messages.len() == 1 && req.messages[0].role == Role::User;
        let mut p = String::new();
        if !sys.is_empty() {
            p.push_str("<instructions>\n");
            p.push_str(&sys);
            p.push_str("\n</instructions>\n\n");
        }
        if only_user {
            p.push_str(&req.messages[0].text());
        } else {
            p.push_str("<conversation>\n");
            p.push_str(&convo);
            p.push_str("</conversation>\n\nReply to the last User message.");
        }
        p
    }

    /// argv with `{model}` / `{prompt}` filled; `--model {model}` dropped for the CLI default.
    fn argv(&self, model: &str, prompt: &str) -> (Vec<String>, bool) {
        let mut out = Vec::new();
        let mut uses_arg = false;
        let mut i = 0;
        let default = model.is_empty() || model == "default";
        while i < self.args.len() {
            let a = &self.args[i];
            if default && i + 1 < self.args.len() && self.args[i + 1] == "{model}" {
                i += 2;
                continue;
            }
            if a.contains("{prompt}") {
                uses_arg = true;
            }
            out.push(a.replace("{model}", model).replace("{prompt}", prompt));
            i += 1;
        }
        (out, uses_arg)
    }
}

#[derive(Default)]
struct Parsed {
    text: String,
    final_text: Option<String>,
    usage: Option<Usage>,
    error: Option<String>,
}

/// Fold one output line of `dialect` into `p`; returns a text delta to stream.
fn parse_line(dialect: &str, line: &str, p: &mut Parsed) -> Option<String> {
    if dialect == "text" {
        let s = format!("{line}\n");
        p.text.push_str(&s);
        return Some(s);
    }
    let v: Value = serde_json::from_str(line.trim()).ok()?;
    match dialect {
        "claude-stream-json" => match v["type"].as_str()? {
            "assistant" => {
                let t: String = v["message"]["content"]
                    .as_array()?
                    .iter()
                    .filter(|b| b["type"] == "text")
                    .filter_map(|b| b["text"].as_str())
                    .collect();
                if t.is_empty() {
                    return None;
                }
                if !p.text.is_empty() {
                    p.text.push('\n');
                }
                p.text.push_str(&t);
                Some(t)
            }
            "result" => {
                if v["is_error"].as_bool() == Some(true) {
                    p.error = Some(
                        v["result"]
                            .as_str()
                            .or(v["error"].as_str())
                            .unwrap_or("Claude CLI reported an error")
                            .to_string(),
                    );
                }
                p.final_text = v["result"].as_str().map(String::from);
                let u = &v["usage"];
                if u.is_object() {
                    p.usage = Some(Usage {
                        input_tokens: u["input_tokens"].as_u64().unwrap_or(0),
                        output_tokens: u["output_tokens"].as_u64().unwrap_or(0),
                        cache_read_tokens: u["cache_read_input_tokens"].as_u64().unwrap_or(0),
                        cache_write_tokens: u["cache_creation_input_tokens"].as_u64().unwrap_or(0),
                        estimated: false,
                    });
                }
                None
            }
            _ => None,
        },
        "gemini-stream-json" => match v["type"].as_str()? {
            "message" if v["role"] == "assistant" => {
                let t = v["content"].as_str()?.to_string();
                p.text.push_str(&t);
                Some(t)
            }
            "result" => {
                if v["status"].as_str().is_some_and(|s| s != "success") {
                    p.error = Some(
                        v["error"]["message"]
                            .as_str()
                            .or(v["error"].as_str())
                            .unwrap_or("Gemini CLI failed")
                            .to_string(),
                    );
                }
                let s = &v["stats"];
                if s.is_object() {
                    p.usage = Some(Usage {
                        input_tokens: s["input_tokens"]
                            .as_u64()
                            .or(s["input"].as_u64())
                            .unwrap_or(0),
                        output_tokens: s["output_tokens"]
                            .as_u64()
                            .or(s["output"].as_u64())
                            .unwrap_or(0),
                        cache_read_tokens: s["cached"].as_u64().unwrap_or(0),
                        ..Default::default()
                    });
                }
                None
            }
            "error" => {
                p.error = v["message"].as_str().map(String::from);
                None
            }
            _ => None,
        },
        "codex-jsonl" => match v["type"].as_str()? {
            "item.completed" if v["item"]["type"] == "agent_message" => {
                let t = v["item"]["text"].as_str()?.to_string();
                if !p.text.is_empty() {
                    p.text.push('\n');
                }
                p.text.push_str(&t);
                Some(t)
            }
            "turn.completed" => {
                let u = &v["usage"];
                let cached = u["cached_input_tokens"].as_u64().unwrap_or(0);
                p.usage = Some(Usage {
                    input_tokens: u["input_tokens"]
                        .as_u64()
                        .unwrap_or(0)
                        .saturating_sub(cached),
                    output_tokens: u["output_tokens"].as_u64().unwrap_or(0),
                    cache_read_tokens: cached,
                    ..Default::default()
                });
                None
            }
            "turn.failed" | "error" => {
                p.error = v["error"]["message"]
                    .as_str()
                    .or(v["message"].as_str())
                    .map(String::from);
                None
            }
            _ => None,
        },
        _ => None,
    }
}

impl Provider for CliBackend {
    fn id(&self) -> &str {
        &self.id
    }
    fn caps(&self, model: &str) -> ModelCaps {
        // The CLI runs its own tools; seagent's tool schemas are not forwarded.
        ModelCaps {
            tools: false,
            ..crate::caps_for(model)
        }
    }
    fn complete(
        &self,
        req: &ModelRequest,
        on_event: &mut dyn FnMut(StreamEvent),
        cancel: &Cancel,
    ) -> Result<ModelResponse, ProviderError> {
        let prompt = Self::prompt(req);
        let (argv, prompt_in_args) = self.argv(&req.model, &prompt);
        let mut cmd = Command::new(&self.command);
        cmd.args(&argv)
            .stdin(if prompt_in_args {
                Stdio::null()
            } else {
                Stdio::piped()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // The CLI is third-party code: it gets the same scrub every other subprocess spawn
        // applies (`Surface::Server`, the surface documented for programs seagent does not own),
        // so seagent's provider keys, bot tokens and Tier-1 secrets are not visible to it.
        seagent_security::envscrub::apply(&mut cmd, seagent_security::envscrub::Surface::Server);
        if self.dialect == "claude-stream-json" {
            for k in CLAUDE_CLEAR_ENV {
                cmd.env_remove(k);
            }
        }
        // The CLI's own provider variables: `headers = { "env:NAME" = … }` in the provider
        // table. Applied after the scrub, so an explicitly configured value still arrives
        // (that is the deliberate allowlist: the scrub never re-adds a name itself).
        for (k, v) in &self.env {
            cmd.env(k, v);
        }
        // ETXTBSY: a just-written script can still be open in a concurrently forked child.
        let mut tries = 0;
        let spawned = loop {
            match cmd.spawn() {
                Err(e) if e.raw_os_error() == Some(26) && tries < 20 => {
                    tries += 1;
                    std::thread::sleep(Duration::from_millis(25));
                }
                r => break r,
            }
        };
        let mut child = spawned.map_err(|e| {
            ProviderError::new(
                ProviderErrorKind::Network,
                format!(
                    "{}: cannot start `{}`: {e} (is it installed and on PATH?)",
                    self.id, self.command
                ),
            )
        })?;
        if !prompt_in_args {
            if let Some(mut si) = child.stdin.take() {
                let p = prompt.clone();
                std::thread::spawn(move || {
                    let _ = si.write_all(p.as_bytes());
                });
            }
        }
        let (tx, rx) = mpsc::channel::<String>();
        let out = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for l in BufReader::new(out).lines().map_while(Result::ok) {
                if tx.send(l).is_err() {
                    break;
                }
            }
        });
        let err_pipe = child.stderr.take().unwrap();
        let err_h = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = std::io::Read::read_to_string(&mut BufReader::new(err_pipe), &mut s);
            s
        });
        let mut parsed = Parsed::default();
        let start = Instant::now();
        loop {
            if cancel.is_cancelled() {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ProviderError::new(
                    ProviderErrorKind::Cancelled,
                    "cancelled",
                ));
            }
            if start.elapsed() > self.timeout {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ProviderError::new(
                    ProviderErrorKind::Timeout,
                    format!(
                        "{} did not finish within {}s",
                        self.command,
                        self.timeout.as_secs()
                    ),
                ));
            }
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(line) => {
                    if let Some(d) = parse_line(&self.dialect, &line, &mut parsed) {
                        on_event(StreamEvent::TextDelta(d));
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        let status = child
            .wait()
            .map_err(|e| ProviderError::new(ProviderErrorKind::Network, e.to_string()))?;
        let stderr = err_h.join().unwrap_or_default();
        if let Some(e) = parsed.error.take() {
            let kind = if e.to_lowercase().contains("rate limit") || e.contains("429") {
                ProviderErrorKind::RateLimited { retry_after: None }
            } else if e.to_lowercase().contains("login") || e.to_lowercase().contains("auth") {
                ProviderErrorKind::Auth
            } else {
                ProviderErrorKind::Server
            };
            return Err(ProviderError::new(kind, format!("{}: {e}", self.id)));
        }
        if !status.success() && parsed.text.is_empty() {
            let tail: String = stderr
                .trim()
                .chars()
                .rev()
                .take(400)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            return Err(ProviderError::new(
                ProviderErrorKind::Server,
                format!("{} exited with {status}: {tail}", self.command),
            ));
        }
        let text = parsed
            .final_text
            .filter(|t| !t.is_empty())
            .unwrap_or(parsed.text)
            .trim_end()
            .to_string();
        let message = Message {
            role: Role::Assistant,
            content: vec![Block::Text { text }],
        };
        let usage = finalize_usage(parsed.usage, req, &message);
        Ok(ModelResponse {
            message,
            stop: StopReason::EndTurn,
            usage,
            model: format!(
                "{}/{}",
                self.id,
                if req.model.is_empty() {
                    "default"
                } else {
                    &req.model
                }
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(name: &str, body: &str) -> String {
        let d = seagent_core::tmp::scratch_path(format!("seagent-cli-{}-{}", std::process::id(), name));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p.to_string_lossy().into_owned()
    }

    fn cfg(cmd: &str, args: &[&str], dialect: &str) -> ProviderConfig {
        ProviderConfig {
            id: "c".into(),
            format: crate::WireFormat::Cli,
            command: Some(cmd.into()),
            args: args.iter().map(|s| s.to_string()).collect(),
            dialect: Some(dialect.into()),
            ..Default::default()
        }
    }

    fn req(model: &str) -> ModelRequest {
        ModelRequest {
            model: model.into(),
            system: vec![SystemSegment {
                id: "s".into(),
                text: "be brief".into(),
                cache: false,
            }],
            messages: vec![Message::user("say hi")],
            max_tokens: 100,
            ..Default::default()
        }
    }

    /// A provider CLI is third-party code: it sees the scrubbed environment, and only the
    /// variables its provider table declares (the `env:` allowlist) reach it.
    #[test]
    fn provider_cli_gets_the_scrubbed_environment() {
        let s = script("envdump", "cat >/dev/null; env");
        let mut c = cfg(&s, &[], "text");
        // The CLI's own credential, configured as the provider needs it.
        c.headers.insert("env:GEMINI_API_KEY".into(), "cli-own-key".into());
        let b = CliBackend::new(&c).unwrap();
        std::env::set_var("GITHUB_TOKEN", "ghp_tier1_must_not_leak");
        std::env::set_var("OPENAI_API_KEY", "sk-tier2-must-not-leak");
        let r = b.complete(&req("default"), &mut |_| {}, &Cancel::new());
        std::env::remove_var("GITHUB_TOKEN");
        std::env::remove_var("OPENAI_API_KEY");
        let text = r.unwrap().message.text();
        assert!(!text.contains("ghp_tier1_must_not_leak") && !text.contains("GITHUB_TOKEN="), "a Tier-1 credential reached the CLI: {text}");
        assert!(!text.contains("sk-tier2-must-not-leak"), "a provider key reached the CLI: {text}");
        assert!(text.contains("GEMINI_API_KEY=cli-own-key"), "the CLI's own variable must still arrive: {text}");
    }

    #[test]
    fn claude_stream_json_via_stdin() {
        let s = script(
            "claude",
            r#"read -r first; cat > /dev/null
echo "{\"type\":\"system\",\"subtype\":\"init\"}"
echo "{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"Hi there\"}]}}"
echo "{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"result\":\"Hi there\",\"usage\":{\"input_tokens\":12,\"output_tokens\":3,\"cache_read_input_tokens\":4}}"
echo "argv: $*" >&2"#,
        );
        let b = CliBackend::new(&cfg(
            &s,
            &["-p", "--output-format", "stream-json", "--model", "{model}"],
            "claude-stream-json",
        ))
        .unwrap();
        let mut deltas = vec![];
        let r = b
            .complete(&req("sonnet"), &mut |e| deltas.push(e), &Cancel::new())
            .unwrap();
        assert_eq!(r.message.text(), "Hi there");
        assert_eq!(
            (
                r.usage.input_tokens,
                r.usage.cache_read_tokens,
                r.usage.estimated
            ),
            (12, 4, false)
        );
        assert_eq!(deltas, vec![StreamEvent::TextDelta("Hi there".into())]);
        assert!(!b.caps("x").tools);
        let (argv, _) = b.argv("default", "p");
        assert_eq!(
            argv,
            vec!["-p", "--output-format", "stream-json"],
            "--model dropped for the CLI default"
        );
    }

    #[test]
    fn gemini_prompt_arg_and_codex_jsonl_and_errors() {
        let s = script(
            "gemini",
            r#"for a in "$@"; do last="$a"; done
printf '{"type":"message","role":"assistant","content":"Echo: %s","delta":true}\n' "$(echo "$last" | tail -c 7)"
echo '{"type":"result","status":"success","stats":{"input_tokens":5,"output_tokens":2}}'"#,
        );
        let b = CliBackend::new(&cfg(
            &s,
            &["--output-format", "stream-json", "--prompt", "{prompt}"],
            "gemini-stream-json",
        ))
        .unwrap();
        let r = b.complete(&req("g"), &mut |_| {}, &Cancel::new()).unwrap();
        assert_eq!(r.message.text(), "Echo: say hi");
        let s = script(
            "codex",
            r#"cat >/dev/null
echo '{"type":"thread.started"}'
echo '{"type":"item.completed","item":{"type":"agent_message","text":"done"}}'
echo '{"type":"turn.completed","usage":{"input_tokens":10,"cached_input_tokens":4,"output_tokens":1}}'"#,
        );
        let b = CliBackend::new(&cfg(&s, &["exec", "--json", "-"], "codex-jsonl")).unwrap();
        let r = b.complete(&req("m"), &mut |_| {}, &Cancel::new()).unwrap();
        assert_eq!(
            (
                r.message.text().as_str(),
                r.usage.input_tokens,
                r.usage.cache_read_tokens
            ),
            ("done", 6, 4)
        );
        let s = script(
            "bad",
            r#"cat >/dev/null; echo '{"type":"turn.failed","error":{"message":"rate limit reached"}}'"#,
        );
        let b = CliBackend::new(&cfg(&s, &[], "codex-jsonl")).unwrap();
        assert!(matches!(
            b.complete(&req("m"), &mut |_| {}, &Cancel::new())
                .unwrap_err()
                .kind,
            ProviderErrorKind::RateLimited { .. }
        ));
        let b = CliBackend::new(&cfg("/nonexistent/cli-xyz", &[], "text")).unwrap();
        assert!(b
            .complete(&req("m"), &mut |_| {}, &Cancel::new())
            .unwrap_err()
            .message
            .contains("cannot start"));
        assert!(CliBackend::new(&cfg("x", &[], "klingon")).is_err());
    }

    #[test]
    fn cancel_kills_the_process() {
        let s = script("slow", "sleep 30");
        let b = CliBackend::new(&cfg(&s, &[], "text")).unwrap();
        let c = Cancel::new();
        let c2 = c.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            c2.cancel();
        });
        let t = Instant::now();
        assert_eq!(
            b.complete(&req("m"), &mut |_| {}, &c).unwrap_err().kind,
            ProviderErrorKind::Cancelled
        );
        assert!(t.elapsed() < Duration::from_secs(5));
    }
}
