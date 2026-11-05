//! `seagent infer` / `seagent capability` (OpenClaw `src/cli/capability-cli.ts`): a stable CLI
//! over the media capabilities. Domains: `list`, `inspect --name <id>`, `image
//! generate|edit|describe|describe-many|providers`, `audio transcribe|providers`,
//! `tts convert|voices|providers|personas|status`, `video generate|describe|providers`,
//! `music generate|providers`. Every command takes `--json`. (`model`, `web` and
//! `embedding` domains belong to the agent runtime and are dispatched by the binary.)

use crate::Media;
use seagent_core::{Cancel, Tool, ToolCtx, ToolHost};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// `(id, description, transports)` — OpenClaw `CAPABILITY_METADATA` (media subset + runtime domains).
pub const CAPABILITIES: &[(&str, &str, &[&str])] = &[
    ("model.run", "Run a one-shot inference turn through the selected model provider.", &["local", "gateway"]),
    ("model.list", "List known models from the model catalog.", &["local"]),
    ("image.generate", "Generate raster images with configured image providers.", &["local"]),
    ("image.edit", "Generate edited images from one or more input files.", &["local"]),
    ("image.describe", "Describe one image file through media-understanding providers.", &["local"]),
    ("image.describe-many", "Describe multiple image files independently.", &["local"]),
    ("image.providers", "List image generation providers.", &["local"]),
    ("audio.transcribe", "Transcribe one audio file.", &["local"]),
    ("audio.providers", "List audio transcription providers.", &["local"]),
    ("tts.convert", "Convert text to speech.", &["local", "gateway"]),
    ("tts.voices", "List voices for a speech provider.", &["local"]),
    ("tts.providers", "List speech providers.", &["local", "gateway"]),
    ("tts.personas", "List TTS personas.", &["local", "gateway"]),
    ("tts.status", "Show gateway-managed TTS state.", &["gateway"]),
    ("video.generate", "Generate video files with configured video providers.", &["local"]),
    ("video.describe", "Describe one video file through media-understanding providers.", &["local"]),
    ("video.providers", "List video generation and description providers.", &["local"]),
    ("music.generate", "Generate music with configured music providers.", &["local"]),
    ("music.providers", "List music generation providers.", &["local"]),
];

#[derive(Default)]
struct CliHost;

impl ToolHost for CliHost {
    fn spawn_agent(&self, _r: seagent_core::tool::SpawnRequest, _c: &Cancel) -> Result<String, String> {
        Err("sub-agents are not available from the CLI".into())
    }
    fn ask_user(&self, _q: &str) -> Result<String, String> {
        Err("non-interactive".into())
    }
    fn progress(&self, t: &str) {
        eprintln!("{t}");
    }
}

/// A tool context rooted at `cwd` for running media tools from the CLI.
pub fn cli_ctx(cwd: &Path) -> ToolCtx {
    let home = seagent_core::layout::data_dir();
    ToolCtx { workspace: cwd.to_path_buf(), session_id: "cli".into(), artifacts: cwd.join(".seagent").join("artifacts"), home, cancel: Cancel::new(), host: Arc::new(CliHost), secrets: Arc::new(|s: &str| s.to_string()) }
}

/// Parsed `--flag value` / `--flag` options (repeatable flags collect).
struct Opts {
    pos: Vec<String>,
    kv: Vec<(String, String)>,
    flags: Vec<String>,
}

const BOOL_FLAGS: &[&str] = &["json", "audio", "watermark", "instrumental", "local", "gateway", "background"];

impl Opts {
    fn parse(args: &[String]) -> Opts {
        let mut o = Opts { pos: vec![], kv: vec![], flags: vec![] };
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if let Some(name) = a.strip_prefix("--") {
                if let Some((k, v)) = name.split_once('=') {
                    o.kv.push((k.into(), v.into()));
                } else if BOOL_FLAGS.contains(&name) || i + 1 >= args.len() || args[i + 1].starts_with("--") {
                    o.flags.push(name.into());
                } else {
                    o.kv.push((name.into(), args[i + 1].clone()));
                    i += 1;
                }
            } else {
                o.pos.push(a.clone());
            }
            i += 1;
        }
        o
    }
    fn get(&self, k: &str) -> Option<&str> {
        self.kv.iter().rev().find(|(x, _)| x == k).map(|(_, v)| v.as_str())
    }
    fn all(&self, k: &str) -> Vec<String> {
        self.kv.iter().filter(|(x, _)| x == k).map(|(_, v)| v.clone()).collect()
    }
    fn flag(&self, k: &str) -> bool {
        self.flags.iter().any(|f| f == k)
    }
    fn req(&self, k: &str) -> Result<&str, String> {
        self.get(k).ok_or_else(|| format!("missing required option --{k}"))
    }
    fn int(&self, k: &str) -> Result<Option<i64>, String> {
        self.get(k).map(|v| v.parse().map_err(|_| format!("--{k} must be an integer"))).transpose()
    }
}

fn out(json_mode: bool, text: String, v: Value) -> String {
    if json_mode {
        serde_json::to_string_pretty(&v).unwrap_or_default()
    } else {
        text
    }
}

/// OpenClaw `formatEnvelopeForText` (`capability-cli/output.ts`).
pub fn format_envelope(e: &Value) -> String {
    let cap = e["capability"].as_str().unwrap_or("");
    if e["ok"] != true {
        return format!("{cap} failed: {}", e["error"].as_str().unwrap_or("unknown error"));
    }
    let mut lines = vec![format!("{cap} via {}", e["transport"].as_str().unwrap_or("local"))];
    if let Some(p) = e["provider"].as_str() {
        lines.push(format!("provider: {p}"));
    }
    if let Some(mo) = e["model"].as_str() {
        lines.push(format!("model: {mo}"));
    }
    if let Some(iv) = e["ignoredOverrides"].as_array().filter(|a| !a.is_empty()) {
        lines.push(format!("ignoredOverrides: {}", serde_json::to_string(iv).unwrap_or_default()));
    }
    let outputs = e["outputs"].as_array().cloned().unwrap_or_default();
    lines.push(format!("outputs: {}", outputs.len()));
    for o in &outputs {
        match (o["path"].as_str(), o["text"].as_str()) {
            (Some(p), Some(t)) => lines.extend([p.to_string(), t.to_string()]),
            (Some(p), None) => lines.push(p.to_string()),
            (None, Some(t)) => lines.push(t.to_string()),
            _ => lines.push(o.to_string()),
        }
    }
    lines.join("\n")
}

/// OpenClaw `ignoredOverrides`: `notes` such as `ignored unsupported lyrics` or
/// `ignored unsupported durationSeconds=60` become `{key, value?}` entries.
fn ignored_overrides(notes: Option<&Value>) -> Vec<Value> {
    notes
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|n| n.as_str())
        .filter_map(|n| {
            let rest = n.strip_prefix("ignored unsupported ")?.trim();
            let (key, value) = match rest.find(['=', ' ']) {
                Some(i) => (rest[..i].trim(), rest[i + 1..].trim()),
                None => (rest, ""),
            };
            if key.is_empty() {
                return None;
            }
            let mut o = json!({"key": key});
            if !value.is_empty() {
                o["value"] = if value == "true" {
                    json!(true)
                } else if value == "false" {
                    json!(false)
                } else if let Ok(i) = value.parse::<i64>() {
                    json!(i)
                } else {
                    json!(value)
                };
            }
            Some(o)
        })
        .collect()
}

/// A `CapabilityEnvelope` for one generation command (`image.generate`, …).
fn gen_envelope(capability: &str, body: &Value, outputs: Vec<Value>) -> Value {
    json!({
        "ok": true,
        "capability": capability,
        "transport": "local",
        "provider": body["provider"].clone(),
        "model": body["model"].clone(),
        "attempts": body["attempts"].as_array().cloned().unwrap_or_default(),
        "outputs": outputs,
        "ignoredOverrides": ignored_overrides(body.get("notes")),
        "result": body,
    })
}

/// A `CapabilityEnvelope` for a media-understanding command.
fn understanding_envelope(capability: &str, provider: Option<&str>, outputs: Vec<Value>) -> Value {
    json!({
        "ok": true,
        "capability": capability,
        "transport": "local",
        "provider": provider,
        "attempts": [],
        "outputs": outputs,
    })
}

/// `--local` / `--gateway` (OpenClaw `resolveTransport`); this CLI is the local transport.
fn check_transport(o: &Opts) -> Result<(), String> {
    if o.flag("local") && o.flag("gateway") {
        return Err("Pass only one of --local or --gateway.".into());
    }
    if o.flag("gateway") {
        return Err("--gateway needs the agent gateway: the media CLI runs locally, so drop --gateway (or run the command through the running gateway).".into());
    }
    Ok(())
}

/// `m` with a per-call HTTP timeout (`--timeout-ms`), when given.
fn with_timeout(m: &Media, o: &Opts) -> Result<Media, String> {
    let ms = match o.get("timeout-ms") {
        None => return Ok(Media { cfg: m.cfg.clone(), http: m.http.clone() }),
        Some(v) => v.parse::<i64>().map_err(|_| "--timeout-ms must be a positive integer".to_string())?,
    };
    if ms <= 0 {
        return Err("--timeout-ms must be a positive integer".into());
    }
    Ok(Media { cfg: m.cfg.clone(), http: crate::http::Http::new(std::time::Duration::from_millis(ms as u64)) })
}

/// Copy/replace generated files at `--output` (OpenClaw `writeOutputAsset`: one file keeps the
/// path, several get `<stem>-<n><ext>`).
fn move_outputs(ctx: &ToolCtx, files: &mut [String], output: Option<&str>) -> Result<(), String> {
    let Some(o) = output else { return Ok(()) };
    let dest = ctx.resolve(o);
    if let Some(p) = dest.parent() {
        std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let n = files.len();
    for (i, f) in files.iter_mut().enumerate() {
        let d = if n > 1 {
            let ext = std::path::Path::new(f.as_str()).extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
            let stem = dest.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "output".into());
            let dir = dest.parent().map(|p| p.to_path_buf()).unwrap_or_default();
            dir.join(format!("{stem}-{}{ext}", i + 1))
        } else {
            dest.clone()
        };
        std::fs::copy(f.as_str(), &d).map_err(|e| format!("could not write {}: {e}", d.display()))?;
        *f = d.display().to_string();
    }
    Ok(())
}

/// Run a generation tool, then copy its MEDIA files to `--output` when given.
fn run_tool(t: Arc<dyn Tool>, ctx: &ToolCtx, capability: &str, input: Value, output: Option<&str>, json_mode: bool) -> Result<String, String> {
    let r = t.call(ctx, input);
    if r.is_error {
        return Err(serde_json::from_str::<Value>(&r.content).ok().and_then(|v| v["error"].as_str().map(str::to_string)).unwrap_or(r.content));
    }
    let mut files: Vec<String> = r.content.lines().filter_map(|l| l.strip_prefix("MEDIA:")).map(str::to_string).collect();
    move_outputs(ctx, &mut files, output)?;
    let body: Value = serde_json::from_str(r.content.split("\nMEDIA:").next().unwrap_or("")).unwrap_or(Value::Null);
    let outputs = files.iter().map(|p| json!({"path": p})).collect();
    let e = gen_envelope(capability, &body, outputs);
    // No files (e.g. only remote URLs): keep the tool's own text.
    let text = if files.is_empty() { r.content.clone() } else { format_envelope(&e) };
    Ok(out(json_mode, text, e))
}

fn read_file(ctx: &ToolCtx, p: &str) -> Result<(Vec<u8>, String, PathBuf), String> {
    let path = ctx.resolve(p);
    let b = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mime = match crate::store::sniff(&b) {
        "application/octet-stream" => crate::store::mime_for_path(&path).to_string(),
        s => s.to_string(),
    };
    Ok((b, mime, path))
}

/// One described file: `(resolved path, provider id, text)`.
struct Described {
    path: String,
    provider: String,
    text: String,
}

fn describe_one(m: &Media, ctx: &ToolCtx, kind: &str, file: &str, o: &Opts) -> Result<Described, String> {
    let (bytes, mime, path) = read_file(ctx, file)?;
    let prompt = o.get("prompt").map(str::to_string).unwrap_or_else(|| if kind == "video" { "Describe the video.".into() } else { "Describe the image.".into() });
    let req = super::DescribeRequest { bytes, mime, prompt, model: o.get("model").map(str::to_string), max_tokens: 1024 };
    let mm = with_timeout(m, o)?;
    let (provider, text) = super::describe(&mm, kind, &req, &ctx.cancel)?;
    Ok(Described { path: path.display().to_string(), provider, text })
}

fn describe_output(d: &Described, kind: &str) -> Value {
    json!({"path": d.path, "text": d.text, "kind": format!("{kind}.description")})
}

/// Entry point: `args` are the words after `seagent infer` (or `seagent capability`).
pub fn cli(m: &Arc<Media>, args: &[String], cwd: &Path) -> Result<String, String> {
    let o = Opts::parse(args);
    let ctx = cli_ctx(cwd);
    let j = o.flag("json");
    let dom = o.pos.first().map(String::as_str).unwrap_or("");
    let sub = o.pos.get(1).map(String::as_str).unwrap_or("");
    match (dom, sub) {
        ("" | "help", _) => Ok(help()),
        ("list", _) => Ok(out(j, CAPABILITIES.iter().map(|(id, d, t)| format!("{id:<22} [{}] {d}", t.join(","))).collect::<Vec<_>>().join("\n"), json!(CAPABILITIES.iter().map(|(id, d, t)| json!({"id": id, "description": d, "transports": t})).collect::<Vec<_>>()))),
        ("inspect", _) => {
            let name = o.req("name")?;
            let (id, d, t) = CAPABILITIES.iter().find(|(id, _, _)| *id == name).ok_or_else(|| format!("Unknown capability: {name}"))?;
            Ok(out(j, format!("{id}\n  {d}\n  transports: {}", t.join(", ")), json!({"id": id, "description": d, "transports": t})))
        }
        ("image", "generate" | "edit") => {
            let mut input = json!({"prompt": o.req("prompt")?});
            if sub == "edit" {
                let files = o.all("file");
                if files.is_empty() {
                    return Err("missing required option --file".into());
                }
                input["images"] = json!(files);
            }
            for (flag, key) in [("model", "model"), ("size", "size"), ("aspect-ratio", "aspect_ratio"), ("resolution", "resolution"), ("output-format", "output_format"), ("background", "background"), ("quality", "quality")] {
                if let Some(v) = o.get(flag) {
                    input[key] = json!(v);
                }
            }
            if let Some(c) = o.int("count")? {
                input["count"] = json!(c);
            }
            if let Some(t) = o.int("timeout-ms")? {
                input["timeout_ms"] = json!(t);
            }
            let mut oa = json!({});
            if let Some(b) = o.get("openai-background") {
                oa["background"] = json!(b);
            }
            if let Some(mo) = o.get("openai-moderation") {
                oa["moderation"] = json!(mo);
            }
            if oa.as_object().is_some_and(|x| !x.is_empty()) {
                input["openai"] = oa;
            }
            let t = crate::image_gen::tools(m).into_iter().find(|t| t.spec().name == "image_generate").ok_or("image generation is disabled")?;
            run_tool(t, &ctx, if sub == "edit" { "image.edit" } else { "image.generate" }, input, o.get("output"), j)
        }
        ("image" | "video", "describe") => {
            let d = describe_one(m, &ctx, dom, o.req("file")?, &o)?;
            let e = understanding_envelope(if dom == "image" { "image.describe" } else { "video.describe" }, Some(&d.provider), vec![describe_output(&d, dom)]);
            Ok(out(j, format_envelope(&e), e))
        }
        ("image", "describe-many") => {
            let files = o.all("file");
            if files.is_empty() {
                return Err("missing required option --file".into());
            }
            let all: Vec<Result<Described, String>> = files.iter().map(|f| describe_one(m, &ctx, "image", f, &o)).collect();
            let first = all.iter().find_map(|r| r.as_ref().ok().map(|d| d.provider.clone()));
            let outputs: Vec<Value> = all
                .iter()
                .map(|r| match r {
                    Ok(d) => describe_output(d, "image"),
                    Err(e) => json!({"text": e, "kind": "image.description", "error": e}),
                })
                .collect();
            let e = understanding_envelope("image.describe-many", first.as_deref(), outputs);
            Ok(out(j, format_envelope(&e), e))
        }
        ("image", "providers") => {
            let ps: Vec<Value> = crate::image_gen::providers().iter().map(|p| json!({"id": p.id(), "label": p.label(), "configured": p.configured(m), "defaultModel": p.default_model(m), "env": p.env()})).collect();
            Ok(out(j, providers_text(&ps), json!(ps)))
        }
        ("audio", "transcribe") => {
            let (bytes, mime, path) = read_file(&ctx, o.req("file")?)?;
            let mut req = crate::stt::SttRequest::new(bytes, &mime);
            req.file_name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or(req.file_name);
            req.language = o.get("language").map(str::to_string);
            req.prompt = o.get("prompt").map(str::to_string);
            let mm = with_timeout(m, &o)?;
            let (provider, t) = match o.get("model") {
                Some(mo) => {
                    let (p, model) = mo.split_once('/').ok_or("--model must be a provider/model reference")?;
                    req.model = Some(model.to_string());
                    crate::stt::transcribe_with(&mm, p, &req, &ctx.cancel)?
                }
                None => crate::stt::transcribe(&mm, &req, &ctx.cancel).map_err(|e| if e.contains("no") && e.contains("provider") { "No audio transcription provider is configured or ready. Configure [media.stt] provider, or pass --model <provider/model> after configuring that provider's API key.".to_string() } else { e })?,
            };
            let e = understanding_envelope("audio.transcribe", Some(&provider), vec![json!({"path": path.display().to_string(), "text": t.text, "kind": "audio.transcription"})]);
            Ok(out(j, format_envelope(&e), e))
        }
        ("audio", "providers") => {
            let active = crate::stt::resolve_provider(m);
            let ps: Vec<Value> = crate::stt::providers().iter().map(|p| json!({"id": p.id(), "configured": p.available(m), "active": p.id() == active})).collect();
            Ok(out(j, providers_text(&ps), json!(ps)))
        }
        ("tts", "convert") => {
            let text = o.req("text")?;
            check_transport(&o)?;
            let mut req = crate::tts::TtsRequest::new(text);
            req.voice = o.get("voice").map(str::to_string);
            req.format = o.get("format").map(str::to_string);
            // `--channel` is a routing hint (OpenClaw `resolveTtsConfig(cfg, {channelId})`); this
            // crate has no per-channel TTS table, so the local runtime ignores it.
            let _channel = o.get("channel");
            // `--model` is a `<provider/model>` reference (OpenClaw tts convert).
            let model_ref = match o.get("model") {
                None => None,
                Some(mo) => Some(mo.split_once('/').filter(|(p, m)| !p.trim().is_empty() && !m.trim().is_empty()).ok_or("TTS model overrides must use the form <provider/model>.")?),
            };
            let provider_flag = o.get("provider").map(str::trim).filter(|p| !p.is_empty());
            if let (Some(a), Some((b, _))) = (provider_flag, model_ref) {
                if a != b {
                    return Err("TTS --provider must match the provider in --model.".into());
                }
            }
            req.model = model_ref.map(|(_, m)| m.to_string());
            let want = provider_flag.or_else(|| model_ref.map(|(p, _)| p)).map(str::to_string);
            let (provider, speech) = match want {
                Some(p) => crate::tts::find(m, &p).ok_or_else(|| format!("unknown TTS provider `{p}`"))?.synthesize(m, &req, &ctx.cancel).map(|s| (p.clone(), s))?,
                None => crate::tts::synthesize(m, &req, &ctx.cancel)?,
            };
            let (asset, _) = crate::tts::finalize(m, &provider, speech, req.voice_note(), &ctx.cancel);
            let dest = match o.get("output") {
                Some(p) => {
                    let d = ctx.resolve(p);
                    if let Some(par) = d.parent() {
                        std::fs::create_dir_all(par).map_err(|e| e.to_string())?;
                    }
                    std::fs::write(&d, &asset.bytes).map_err(|e| e.to_string())?;
                    d
                }
                None => crate::store::save(&m.out_dir(&ctx, "audio"), &crate::store::stem("tts"), &asset)?,
            };
            let e = json!({
                "ok": true,
                "capability": "tts.convert",
                "transport": "local",
                "provider": provider,
                "attempts": [],
                "outputs": [{"path": dest.display().to_string(), "mimeType": asset.mime}],
            });
            Ok(out(j, format_envelope(&e), e))
        }
        ("tts", "voices") => {
            let p = o.get("provider").map(str::to_string).unwrap_or_else(|| crate::tts::configured_provider(m));
            let v = crate::tts::find(m, &p).ok_or_else(|| format!("unknown TTS provider `{p}`"))?.voices(m, &ctx.cancel)?;
            Ok(out(j, v.join("\n"), json!({"provider": p, "voices": v})))
        }
        ("tts", "providers") => {
            let active = crate::tts::configured_provider(m);
            let ps: Vec<Value> = crate::tts::providers().iter().map(|p| json!({"id": p.id(), "configured": p.configured(m), "active": p.id() == active})).collect();
            Ok(out(j, providers_text(&ps), json!(ps)))
        }
        ("tts", "personas") => {
            let t = m.cfg.table("tts.personas");
            let v: Vec<Value> = t.iter().map(|(id, p)| json!({"id": id, "label": p.get("label").and_then(|x| x.as_str()), "provider": p.get("provider").and_then(|x| x.as_str()), "voice": p.get("voice").and_then(|x| x.as_str())})).collect();
            Ok(out(j, if v.is_empty() { "no personas configured ([media.tts.personas.<id>])".into() } else { v.iter().map(|p| format!("{} {}", p["id"].as_str().unwrap_or(""), p["label"].as_str().unwrap_or(""))).collect::<Vec<_>>().join("\n") }, json!(v)))
        }
        ("tts", "status") => {
            let chain = crate::tts::chain(m);
            let last = crate::tts::last_attempt().map(|a| json!({"at": a.at, "textLength": a.text_len, "attempts": a.attempts.iter().map(|x| json!({"provider": x.provider, "ok": x.ok, "error": x.error, "latencyMs": x.latency_ms})).collect::<Vec<_>>()}));
            Ok(out(j, format!("provider chain: {}\nauto: {}\nlast attempt: {}", chain.join(" → "), m.cfg.str_or("tts.auto", "off"), last.as_ref().map(|l| l.to_string()).unwrap_or_else(|| "none".into())), json!({"chain": chain, "auto": m.cfg.str_or("tts.auto", "off"), "last": last})))
        }
        ("video", "generate") => {
            let mut input = json!({"prompt": o.req("prompt")?});
            for (flag, key) in [("model", "model"), ("size", "size"), ("aspect-ratio", "aspect_ratio"), ("resolution", "resolution")] {
                if let Some(v) = o.get(flag) {
                    input[key] = json!(v);
                }
            }
            if let Some(d) = o.int("duration")? {
                input["durationSeconds"] = json!(d);
            }
            if let Some(t) = o.int("timeout-ms")? {
                input["timeoutMs"] = json!(t);
            }
            if o.flag("audio") {
                input["audio"] = json!(true);
            }
            if o.flag("watermark") {
                input["watermark"] = json!(true);
            }
            let files = o.all("file");
            if !files.is_empty() {
                input["images"] = json!(files);
            }
            if let Some(po) = o.get("provider-options") {
                input["providerOptions"] = serde_json::from_str(po).map_err(|e| format!("--provider-options must be JSON: {e}"))?;
            }
            run_tool(Arc::new(crate::video_gen::VideoGenerate { m: m.clone() }), &ctx, "video.generate", input, o.get("output"), j)
        }
        ("video", "providers") => {
            // OpenClaw `video.providers` = `{ generation, description }`.
            let gen: Vec<Value> = crate::video_gen::providers().iter().map(|p| json!({"id": p.id(), "label": p.label(), "configured": p.configured(m), "defaultModel": p.default_model(), "models": p.models()})).collect();
            let desc: Vec<Value> = super::describers_for(m).iter().filter(|d| d.video()).map(|d| json!({"id": d.id(), "configured": d.configured(m), "defaultModel": d.default_model("video")})).collect();
            let text = format!("generation:\n{}\ndescription:\n{}", providers_text(&gen), providers_text(&desc));
            Ok(out(j, text, json!({"generation": gen, "description": desc})))
        }
        ("music", "generate") => {
            let mut input = json!({"prompt": o.req("prompt")?});
            for (flag, key) in [("model", "model"), ("lyrics", "lyrics"), ("format", "format"), ("provider", "provider"), ("filename", "filename")] {
                if let Some(v) = o.get(flag) {
                    input[key] = json!(v);
                }
            }
            if let Some(d) = o.int("duration")? {
                input["durationSeconds"] = json!(d);
            }
            if let Some(t) = o.int("timeout-ms")? {
                input["timeoutMs"] = json!(t);
            }
            if o.flag("instrumental") {
                input["instrumental"] = json!(true);
            }
            if o.flag("background") {
                return Err("--background is for the agent runtime (a later turn delivers the track); the media CLI is a one-shot command, so drop it.".into());
            }
            run_tool(Arc::new(crate::music_gen::MusicGenerate { m: m.clone() }), &ctx, "music.generate", input, o.get("output"), j)
        }
        ("music", "providers") => {
            let ps: Vec<Value> = crate::music_gen::providers().iter().map(|p| json!({"id": p.id(), "label": p.label(), "configured": p.configured(m), "defaultModel": p.default_model()})).collect();
            Ok(out(j, providers_text(&ps), json!(ps)))
        }
        ("model" | "web" | "embedding", _) => Err(format!(
            "`{dom}` is not a media capability: the {dom} domain is served by the agent runtime, not `seagent infer` (`seagent capability`). \
             Run it through the agent host (`seagent capability {dom}` against the running gateway, or the equivalent {} tool), \
             and use `seagent infer list` for the media capabilities implemented here.",
            match dom {
                "model" => "model_*",
                "web" => "web_search / web_fetch",
                _ => "embedding",
            }
        )),
        _ => Err(format!("unknown command `{}`\n\n{}", o.pos.join(" "), help())),
    }
}

fn providers_text(ps: &[Value]) -> String {
    ps.iter().map(|p| format!("{} {}{}{}", if p["configured"] == true { "✓" } else { "✗" }, p["id"].as_str().unwrap_or(""), p["defaultModel"].as_str().map(|d| format!("  ({d})")).unwrap_or_default(), if p["active"] == true { "  [active]" } else { "" })).collect::<Vec<_>>().join("\n")
}

pub fn help() -> String {
    "seagent infer — provider-backed media capabilities (alias: seagent capability)\n\n  list | inspect --name <capability>\n  image generate --prompt <text> [--model p/m] [--count n] [--size WxH] [--aspect-ratio r] [--resolution 1K|2K|4K] [--output-format png|jpeg|webp] [--background transparent|opaque|auto] [--openai-background v] [--openai-moderation v] [--quality q] [--timeout-ms ms] [--output path]\n  image edit --file <path>... --prompt <text> [same options]\n  image describe --file <path> [--prompt t] [--model p/m] [--timeout-ms ms]\n  image describe-many --file <a> --file <b> …\n  image providers\n  audio transcribe --file <path> [--language code] [--prompt t] [--model p/m] [--timeout-ms ms]\n  audio providers\n  tts convert --text <t> [--provider id] [--model provider/model] [--voice v] [--channel id] [--format mp3|opus|wav] [--output path] [--local]\n  tts voices [--provider id] | tts providers | tts personas | tts status\n  video generate --prompt <t> [--file image] [--model p/m] [--size WxH] [--aspect-ratio r] [--resolution 720P] [--duration s] [--audio] [--watermark] [--provider-options JSON] [--timeout-ms ms] [--output path]\n  video describe --file <path> [--model p/m] [--timeout-ms ms]\n  video providers\n  music generate --prompt <t> [--lyrics t] [--instrumental] [--duration s] [--format mp3|wav] [--model p/m] [--provider id] [--filename f] [--timeout-ms ms] [--output path]\n  music providers\n\nEvery command accepts --json; file-producing commands accept --output <path>.".into()
}
