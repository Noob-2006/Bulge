//! AWS Bedrock Converse API (`/model/{id}/converse-stream`), SigV4-signed or with a
//! Bedrock API key (`$AWS_BEARER_TOKEN_BEDROCK`). Hermes `agent/bedrock_adapter.py`,
//! OpenClaw `extensions/amazon-bedrock` (guardrails, model discovery).

use crate::eventstream::Decoder;
use crate::http::truncated;
use crate::sigv4::{self, AwsCreds};
use crate::{
    caps_for, classify, finalize_usage, parse_args, thinking_budget, Conn, ProviderConfig,
};
use seagent_core::*;
use serde_json::{json, Value};

pub(crate) struct Bedrock {
    conn: Conn,
    region: String,
    guardrail: Option<(String, String)>,
}

/// Region from config, environment, or the endpoint host (`bedrock-runtime.<r>.amazonaws.com`).
pub(crate) fn region_of(cfg: &ProviderConfig, base: &str) -> String {
    cfg.region
        .clone()
        .or_else(|| crate::env_first(&["AWS_REGION", "AWS_DEFAULT_REGION"]))
        .unwrap_or_else(|| {
            let host = crate::net::host_port(base).0;
            host.split('.')
                .nth(1)
                .filter(|r| r.contains('-'))
                .unwrap_or("us-east-1")
                .to_string()
        })
}

fn bearer() -> Option<String> {
    crate::env_first(&["AWS_BEARER_TOKEN_BEDROCK"])
}

fn image_format(media: &str) -> &str {
    match media {
        "image/png" => "png",
        "image/gif" => "gif",
        "image/webp" => "webp",
        _ => "jpeg",
    }
}

impl Bedrock {
    pub fn new(conn: Conn, cfg: &ProviderConfig) -> Result<Self, String> {
        let region = region_of(cfg, &conn.base);
        let guardrail = cfg.guardrail.as_deref().map(|g| match g.split_once(':') {
            Some((id, v)) => (id.to_string(), v.to_string()),
            None => (g.to_string(), "DRAFT".to_string()),
        });
        Ok(Bedrock {
            conn,
            region,
            guardrail,
        })
    }

    pub(crate) fn body(&self, req: &ModelRequest) -> Value {
        let mut messages = Vec::new();
        for m in &req.messages {
            let mut content = Vec::new();
            for b in &m.content {
                match b {
                    Block::Text { text } if !text.is_empty() => content.push(json!({"text": text})),
                    Block::Image { media_type, data } => content.push(json!({"image": {"format": image_format(media_type), "source": {"bytes": data}}})),
                    Block::ToolUse { id, name, input } => content.push(json!({"toolUse": {"toolUseId": id, "name": name, "input": input}})),
                    Block::ToolResult { tool_use_id, content: c, is_error } => {
                        let mut r = json!({"toolUseId": tool_use_id, "content": [{"text": if c.is_empty() { "(empty)" } else { c }}]});
                        if *is_error {
                            r["status"] = "error".into();
                        }
                        content.push(json!({"toolResult": r}));
                    }
                    Block::Thinking { text, signature: Some(sig) } if m.role == Role::Assistant => content.push(json!({"reasoningContent": {"reasoningText": {"text": text, "signature": sig}}})),
                    _ => {}
                }
            }
            if content.is_empty() {
                content.push(json!({"text": "(empty)"}));
            }
            messages.push(json!({"role": if m.role == Role::User { "user" } else { "assistant" }, "content": content}));
        }
        let mut inf = json!({"maxTokens": req.max_tokens});
        let mut b = json!({"messages": messages});
        let mut system: Vec<Value> = req
            .system
            .iter()
            .filter(|s| !s.text.is_empty())
            .map(|s| json!({"text": s.text}))
            .collect();
        let claude = req.model.contains("anthropic") || req.model.contains("claude");
        if claude && req.system.iter().any(|s| s.cache) && !system.is_empty() {
            system.push(json!({"cachePoint": {"type": "default"}}));
        }
        if !system.is_empty() {
            b["system"] = system.into();
        }
        let level = self.conn.effort(crate::reasoning::BUDGET_WIRE, req);
        match thinking_budget(level.as_deref()) {
            Some(_) if claude && crate::reasoning::claude_adaptive(&req.model) => {
                if let Some(e) = self.conn.effort(crate::reasoning::ADAPTIVE_WIRE, req) {
                    b["additionalModelRequestFields"] =
                        json!({"thinking": {"type": "adaptive"}, "output_config": {"effort": e}});
                }
            }
            Some(budget) if claude => {
                b["additionalModelRequestFields"] =
                    json!({"thinking": {"type": "enabled", "budget_tokens": budget}});
                inf["maxTokens"] = req.max_tokens.max(budget + 4096).into();
            }
            Some(_) => {
                if let Some(e) = self.conn.effort(&["low", "medium", "high"], req) {
                    b["additionalModelRequestFields"] =
                        json!({"reasoning_config": {"type": "enabled", "reasoning_effort": e}});
                }
                if let Some(t) = req.temperature {
                    inf["temperature"] = t.into();
                }
            }
            None => {
                if let Some(t) = req.temperature {
                    inf["temperature"] = t.into();
                }
            }
        }
        b["inferenceConfig"] = inf;
        if !req.tools.is_empty() {
            let tools: Vec<Value> = req.tools.iter().map(|t| json!({"toolSpec": {"name": t.name, "description": t.description, "inputSchema": {"json": t.input_schema}}})).collect();
            b["toolConfig"] = json!({"tools": tools});
        }
        if let Some((id, v)) = &self.guardrail {
            b["guardrailConfig"] = json!({"guardrailIdentifier": id, "guardrailVersion": v, "streamProcessingMode": "async"});
        }
        b
    }

    fn headers_for(&self, url: &str, body: &[u8]) -> Result<Vec<(String, String)>, ProviderError> {
        let mut h = vec![
            ("content-type".to_string(), "application/json".to_string()),
            (
                "accept".to_string(),
                "application/vnd.amazon.eventstream".to_string(),
            ),
        ];
        let (_, extra, cred) = self.conn.prepare(crate::Style::None)?;
        if let Some(t) = cred.token.filter(|t| !t.is_empty()).or_else(bearer) {
            h.push(("authorization".into(), format!("Bearer {t}")));
        } else {
            let creds =
                AwsCreds::from_env().map_err(|e| ProviderError::new(ProviderErrorKind::Auth, e))?;
            let (host, port) = crate::net::host_port(url);
            let host = match port {
                Some(p) if !url.starts_with("https://") || p != 443 => format!("{host}:{p}"),
                _ => host,
            };
            let path = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
            let path = path.find('/').map(|i| &path[i..]).unwrap_or("/");
            let path = path.split('?').next().unwrap_or(path);
            let decoded = seagent_net::urldecode(path);
            let now = crate::ratelimit::now_ms() / 1000;
            h.extend(sigv4::sign(
                &creds,
                "POST",
                &host,
                &decoded,
                &[],
                &h,
                body,
                &self.region,
                "bedrock",
                now,
            ));
        }
        h.extend(extra);
        Ok(h)
    }
}

enum Part {
    Text(String),
    Reason(String, String),
    Tool {
        id: String,
        name: String,
        json: String,
    },
}

impl Provider for Bedrock {
    fn id(&self) -> &str {
        &self.conn.id
    }
    fn caps(&self, model: &str) -> ModelCaps {
        let mut c = caps_for(model);
        // Converse takes cachePoint blocks for Claude only.
        c.explicit_cache = model.contains("claude");
        c
    }
    fn complete(
        &self,
        req: &ModelRequest,
        on_event: &mut dyn FnMut(StreamEvent),
        cancel: &Cancel,
    ) -> Result<ModelResponse, ProviderError> {
        let url = self.conn.url(&format!(
            "model/{}/converse-stream",
            sigv4::uri_encode(&req.model, false)
        ));
        let body = serde_json::to_vec(&self.body(req)).expect("json");
        let headers = self.headers_for(&url, &body)?;
        let mut parts: Vec<Option<Part>> = Vec::new();
        let mut usage: Option<Usage> = None;
        let mut stop_raw: Option<String> = None;
        let mut dec = Decoder::new();
        let mut done = false;
        self.conn
            .http
            .post_stream(&url, &headers, body, cancel, |chunk| {
                let msgs = dec
                    .feed(chunk)
                    .map_err(|e| ProviderError::new(ProviderErrorKind::Protocol, e))?;
                for m in msgs {
                    let v: Value = serde_json::from_slice(&m.payload).unwrap_or(Value::Null);
                    if m.header(":message-type") == Some("exception")
                        || m.header(":message-type") == Some("error")
                    {
                        let ty = m
                            .header(":exception-type")
                            .or(m.header(":error-code"))
                            .unwrap_or("error")
                            .to_string();
                        let msg = v["message"]
                            .as_str()
                            .or(v["Message"].as_str())
                            .unwrap_or(&ty)
                            .to_string();
                        return Err(bedrock_error(&ty, &msg));
                    }
                    match m.header(":event-type").unwrap_or("") {
                        "contentBlockStart" => {
                            let i = v["contentBlockIndex"]
                                .as_u64()
                                .unwrap_or(parts.len() as u64)
                                as usize;
                            while parts.len() <= i {
                                parts.push(None);
                            }
                            if let Some(t) = v["start"].get("toolUse") {
                                let (id, name) = (
                                    t["toolUseId"].as_str().unwrap_or("").to_string(),
                                    t["name"].as_str().unwrap_or("").to_string(),
                                );
                                on_event(StreamEvent::ToolUseStart {
                                    id: id.clone(),
                                    name: name.clone(),
                                });
                                parts[i] = Some(Part::Tool {
                                    id,
                                    name,
                                    json: String::new(),
                                });
                            }
                        }
                        "contentBlockDelta" => {
                            let i = v["contentBlockIndex"].as_u64().unwrap_or(0) as usize;
                            while parts.len() <= i {
                                parts.push(None);
                            }
                            let d = &v["delta"];
                            if let Some(t) = d["text"].as_str() {
                                match &mut parts[i] {
                                    Some(Part::Text(s)) => s.push_str(t),
                                    p @ None => *p = Some(Part::Text(t.to_string())),
                                    _ => {}
                                }
                                on_event(StreamEvent::TextDelta(t.into()));
                            } else if let Some(tu) = d.get("toolUse") {
                                if let Some(Part::Tool { json, .. }) = &mut parts[i] {
                                    json.push_str(tu["input"].as_str().unwrap_or(""));
                                }
                            } else if let Some(r) = d.get("reasoningContent") {
                                if parts[i].is_none() {
                                    parts[i] = Some(Part::Reason(String::new(), String::new()));
                                }
                                if let Some(Part::Reason(t, s)) = &mut parts[i] {
                                    if let Some(x) = r["text"].as_str() {
                                        t.push_str(x);
                                        on_event(StreamEvent::ThinkingDelta(x.into()));
                                    }
                                    if let Some(x) = r["signature"].as_str() {
                                        s.push_str(x);
                                    }
                                }
                            }
                        }
                        "messageStop" => stop_raw = v["stopReason"].as_str().map(String::from),
                        "metadata" => {
                            let u = &v["usage"];
                            let cached = u["cacheReadInputTokens"].as_u64().unwrap_or(0);
                            usage = Some(Usage {
                                input_tokens: u["inputTokens"].as_u64().unwrap_or(0),
                                output_tokens: u["outputTokens"].as_u64().unwrap_or(0),
                                cache_read_tokens: cached,
                                cache_write_tokens: u["cacheWriteInputTokens"]
                                    .as_u64()
                                    .unwrap_or(0),
                                ..Default::default()
                            });
                            done = true;
                            return Ok(true);
                        }
                        _ => {}
                    }
                }
                Ok(false)
            })?;
        if stop_raw.is_none() && !done {
            return Err(truncated("messageStop"));
        }
        let content: Vec<Block> = parts
            .into_iter()
            .flatten()
            .map(|p| match p {
                Part::Text(text) => Block::Text { text },
                Part::Reason(text, sig) => Block::Thinking {
                    text,
                    signature: (!sig.is_empty()).then_some(sig),
                },
                Part::Tool { id, name, json } => Block::ToolUse {
                    id,
                    name,
                    input: parse_args(&json),
                },
            })
            .collect();
        let has_tools = content.iter().any(|b| matches!(b, Block::ToolUse { .. }));
        let stop = match stop_raw.as_deref() {
            _ if has_tools => StopReason::ToolUse,
            Some("max_tokens") => StopReason::MaxTokens,
            Some("guardrail_intervened") | Some("content_filtered") => StopReason::Refusal,
            Some("end_turn") | Some("stop_sequence") | None => StopReason::EndTurn,
            _ => StopReason::Other,
        };
        let message = Message {
            role: Role::Assistant,
            content,
        };
        let usage = finalize_usage(usage, req, &message);
        Ok(ModelResponse {
            message,
            stop,
            usage,
            model: req.model.clone(),
        })
    }
}

fn bedrock_error(ty: &str, msg: &str) -> ProviderError {
    use ProviderErrorKind as K;
    let t = ty.to_lowercase();
    let kind = if classify::mentions_overflow(msg) {
        K::ContextOverflow
    } else if t.contains("throttling") || t.contains("toomanyrequests") {
        K::RateLimited { retry_after: None }
    } else if t.contains("serviceunavailable") || t.contains("modelnotready") {
        K::Overloaded
    } else if t.contains("accessdenied")
        || t.contains("unrecognizedclient")
        || t.contains("expiredtoken")
    {
        K::Auth
    } else if t.contains("validation") || t.contains("resourcenotfound") {
        K::BadRequest
    } else if t.contains("timeout") {
        K::Timeout
    } else {
        K::Server
    };
    ProviderError::new(kind, format!("{ty}: {msg}"))
}

/// Foundation models with text output (`GET bedrock.<region>/foundation-models`).
pub(crate) fn list_models(cfg: &ProviderConfig) -> Result<Vec<String>, String> {
    use std::io::Read;
    let base = cfg.resolved_base()?;
    let region = region_of(cfg, &base);
    let url = std::env::var("SEAGENT_BEDROCK_CONTROL_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| format!("https://bedrock.{region}.amazonaws.com"));
    let full = format!(
        "{}/foundation-models?byOutputModality=TEXT",
        url.trim_end_matches('/')
    );
    let mut req = crate::net::agent(std::time::Duration::from_secs(20), &full)
        .get(&full)
        .header("accept", "application/json");
    if let Some(t) = bearer() {
        req = req.header("authorization", &format!("Bearer {t}"));
    } else {
        let creds = AwsCreds::from_env()?;
        let (host, port) = crate::net::host_port(&full);
        let host = port
            .filter(|p| *p != 443)
            .map(|p| format!("{host}:{p}"))
            .unwrap_or(host);
        for (k, v) in sigv4::sign(
            &creds,
            "GET",
            &host,
            "/foundation-models",
            &[("byOutputModality".into(), "TEXT".into())],
            &[],
            b"",
            &region,
            "bedrock",
            crate::ratelimit::now_ms() / 1000,
        ) {
            req = req.header(k.as_str(), v.as_str());
        }
    }
    let resp = req.call().map_err(|e| format!("GET {full}: {e}"))?;
    let status = resp.status().as_u16();
    let mut raw = String::new();
    resp.into_body()
        .into_reader()
        .take(4 << 20)
        .read_to_string(&mut raw)
        .map_err(|e| e.to_string())?;
    if !(200..300).contains(&status) {
        return Err(format!(
            "{}: {}",
            cfg.id,
            classify::from_status(status, None, &raw)
        ));
    }
    let v: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    Ok(v["modelSummaries"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| m["modelId"].as_str().map(String::from))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventstream::encode;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    fn serve(
        frames: Vec<u8>,
        status: u16,
    ) -> (
        String,
        Arc<Mutex<Vec<(String, Vec<(String, String)>, String)>>>,
    ) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let mut s = s.unwrap();
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                let mut len = 0;
                let mut hs = vec![];
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).unwrap();
                    if h.trim().is_empty() {
                        break;
                    }
                    let (k, v) = h.split_once(':').unwrap();
                    if k.eq_ignore_ascii_case("content-length") {
                        len = v.trim().parse().unwrap();
                    }
                    hs.push((k.trim().to_lowercase(), v.trim().to_string()));
                }
                let mut b = vec![0; len];
                r.read_exact(&mut b).unwrap();
                log2.lock().unwrap().push((
                    line.split_whitespace().nth(1).unwrap().to_string(),
                    hs,
                    String::from_utf8_lossy(&b).to_string(),
                ));
                let ct = if status == 200 {
                    "application/vnd.amazon.eventstream"
                } else {
                    "application/json"
                };
                let _ = write!(s, "HTTP/1.1 {status} X\r\ncontent-type: {ct}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", frames.len());
                let _ = s.write_all(&frames);
            }
        });
        (base, log)
    }

    static ENV: Mutex<()> = Mutex::new(());

    fn cfg(base: &str) -> ProviderConfig {
        ProviderConfig {
            id: "bedrock".into(),
            format: crate::WireFormat::Bedrock,
            base_url: base.into(),
            region: Some("us-west-2".into()),
            auth: "aws".into(),
            guardrail: Some("gr-1:3".into()),
            ..Default::default()
        }
    }

    #[test]
    fn converse_stream_text_tool_reasoning_usage_and_sigv4() {
        let ev = |t: &str, p: Value| {
            encode(
                &[
                    (":event-type", t),
                    (":message-type", "event"),
                    (":content-type", "application/json"),
                ],
                p.to_string().as_bytes(),
            )
        };
        let mut frames = Vec::new();
        frames.extend(ev("messageStart", json!({"role": "assistant"})));
        frames.extend(ev(
            "contentBlockDelta",
            json!({"contentBlockIndex": 0, "delta": {"reasoningContent": {"text": "hmm"}}}),
        ));
        frames.extend(ev(
            "contentBlockDelta",
            json!({"contentBlockIndex": 0, "delta": {"reasoningContent": {"signature": "SIG"}}}),
        ));
        frames.extend(ev(
            "contentBlockDelta",
            json!({"contentBlockIndex": 1, "delta": {"text": "Hel"}}),
        ));
        frames.extend(ev(
            "contentBlockDelta",
            json!({"contentBlockIndex": 1, "delta": {"text": "lo"}}),
        ));
        frames.extend(ev("contentBlockStart", json!({"contentBlockIndex": 2, "start": {"toolUse": {"toolUseId": "tu1", "name": "read"}}})));
        frames.extend(ev(
            "contentBlockDelta",
            json!({"contentBlockIndex": 2, "delta": {"toolUse": {"input": "{\"path\":"}}}),
        ));
        frames.extend(ev(
            "contentBlockDelta",
            json!({"contentBlockIndex": 2, "delta": {"toolUse": {"input": "\"a\"}"}}}),
        ));
        frames.extend(ev("messageStop", json!({"stopReason": "tool_use"})));
        frames.extend(ev(
            "metadata",
            json!({"usage": {"inputTokens": 50, "outputTokens": 7, "cacheReadInputTokens": 20}}),
        ));
        let (base, log) = serve(frames, 200);
        let _g = ENV.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("AWS_ACCESS_KEY_ID", "AKIDTEST");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "secret");
        std::env::remove_var("AWS_BEARER_TOKEN_BEDROCK");
        let p = crate::build(&cfg(&base)).unwrap();
        let req = ModelRequest {
            model: "anthropic.claude-sonnet-4-5:0".into(),
            system: vec![SystemSegment {
                id: "s".into(),
                text: "sys".into(),
                cache: true,
            }],
            messages: vec![Message::user("hi")],
            tools: vec![ToolSchema {
                name: "read".into(),
                description: "r".into(),
                input_schema: json!({"type": "object"}),
            }],
            max_tokens: 100,
            reasoning: Some("low".into()),
            ..Default::default()
        };
        let mut deltas = String::new();
        let r = p
            .complete(
                &req,
                &mut |e| {
                    if let StreamEvent::TextDelta(t) = e {
                        deltas.push_str(&t)
                    }
                },
                &Cancel::new(),
            )
            .unwrap();
        assert_eq!(deltas, "Hello");
        assert_eq!(r.stop, StopReason::ToolUse);
        assert_eq!(r.usage.input_tokens, 50);
        assert_eq!(r.usage.cache_read_tokens, 20);
        assert!(
            matches!(&r.message.content[0], Block::Thinking { text, signature: Some(s) } if text == "hmm" && s == "SIG")
        );
        assert!(
            matches!(&r.message.content[2], Block::ToolUse { input, .. } if input["path"] == "a")
        );
        let (path, hs, body) = log.lock().unwrap()[0].clone();
        assert_eq!(
            path,
            "/model/anthropic.claude-sonnet-4-5%3A0/converse-stream"
        );
        let auth = hs
            .iter()
            .find(|(k, _)| k == "authorization")
            .unwrap()
            .1
            .clone();
        assert!(
            auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDTEST/")
                && auth.contains("/us-west-2/bedrock/aws4_request"),
            "{auth}"
        );
        let b: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            b["additionalModelRequestFields"]["thinking"]["budget_tokens"],
            2048
        );
        assert_eq!(
            b["toolConfig"]["tools"][0]["toolSpec"]["inputSchema"]["json"]["type"],
            "object"
        );
        assert_eq!(b["guardrailConfig"]["guardrailIdentifier"], "gr-1");
        assert_eq!(b["system"][1]["cachePoint"]["type"], "default");
    }

    #[test]
    fn exceptions_are_classified_and_bearer_keys_skip_sigv4() {
        let frames = encode(
            &[
                (":message-type", "exception"),
                (":exception-type", "throttlingException"),
            ],
            br#"{"message":"Too many requests"}"#,
        );
        let (base, log) = serve(frames, 200);
        let _g = ENV.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("AWS_BEARER_TOKEN_BEDROCK", "bedrock-api-key-1");
        let p = crate::build(&cfg(&base)).unwrap();
        let req = ModelRequest {
            model: "amazon.nova-pro-v1:0".into(),
            messages: vec![Message::user("hi")],
            max_tokens: 10,
            ..Default::default()
        };
        let e = p.complete(&req, &mut |_| {}, &Cancel::new()).unwrap_err();
        std::env::remove_var("AWS_BEARER_TOKEN_BEDROCK");
        assert!(
            matches!(e.kind, ProviderErrorKind::RateLimited { .. }),
            "{e}"
        );
        let hs = log.lock().unwrap()[0].1.clone();
        assert!(hs.contains(&("authorization".into(), "Bearer bedrock-api-key-1".into())));
        assert_eq!(
            bedrock_error(
                "validationException",
                "Input is too long for requested model"
            )
            .kind,
            ProviderErrorKind::ContextOverflow
        );
        assert_eq!(
            bedrock_error("accessDeniedException", "no").kind,
            ProviderErrorKind::Auth
        );
    }

    #[test]
    fn region_resolution() {
        let c = ProviderConfig {
            id: "b".into(),
            ..Default::default()
        };
        let r = region_of(&c, "https://bedrock-runtime.ap-northeast-1.amazonaws.com");
        assert!(
            r == "ap-northeast-1"
                || std::env::var("AWS_REGION").is_ok()
                || std::env::var("AWS_DEFAULT_REGION").is_ok()
        );
    }
}
