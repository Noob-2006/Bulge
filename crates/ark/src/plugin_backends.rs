//! Host side of the plugin capability backends ([`ark_plugin::backends`]): the crate that owns
//! each tool keeps its own provider table, so the `ark` binary — the only crate that links
//! `ark-media`, `ark-tools`, `ark-browser` and `ark-plugin` together — wraps a registered backend
//! in that table's trait and registers it there (Hermes does the same in-process:
//! `ctx.register_tts_provider(…)` and `tools.tts_tool` then resolves `tts.provider` through it).
//!
//! * `tts`        → [`ark_media::tts::register`]        (`text_to_speech`, `/tts`, voice replies)
//! * `stt`        → [`ark_media::stt::register`]        (`transcripts`, inbound voice)
//! * `web_search` → [`ark_tools::web::providers::register`] (`web_search`, `web_extract`)
//! * `browser`    → [`ark_browser::cloud::register`]     (cloud `browser_*` sessions)
//! * `image_gen` / `video_gen` → [`tools`], which replaces the media tool when
//!   `[media.image] provider` / `[media.video] provider` names the backend (the media provider
//!   traits return `&'static str` ids and have no runtime registry, so the backend serves the
//!   tool itself; the schema and the envelope stay the upstream ones).
//!
//! Nothing here auto-selects a backend: a backend is used only when its name is configured, and
//! a bundled provider with the same name always wins — the rules `ark_plugin::backends`
//! documents.

use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use ark_plugin::backends::{self, Backend, Kind};
use ark_plugin::PluginHost;
use serde_json::{json, Value};
use std::sync::Arc;

/// Register every backend the started plugins declared, then wire the kinds whose consumer has a
/// runtime registry. Called once, right after the plugins start (`ext::load`).
pub fn install(plugins: &[Arc<PluginHost>]) {
    for p in plugins {
        for b in p.backend_impls() {
            if let Err(e) = backends::register(b) {
                eprintln!("ark: warning: plugin `{}`: {e}", p.name);
            }
        }
        // Dashboard login providers (`[app.auth] provider = "<plugin id>"`).
        if let Some(a) = p.auth_impl() {
            if let Err(e) = ark_plugin::dashboard_auth::register(a) {
                eprintln!("ark: warning: plugin `{}`: {e}", p.name);
            }
        }
    }
    for b in backends::list(Kind::Tts) {
        ark_media::tts::register(Arc::new(TtsProvider(b)));
    }
    for b in backends::list(Kind::Stt) {
        if let Err(e) = ark_media::stt::register(Arc::new(SttProvider(b))) {
            eprintln!("ark: warning: {e}");
        }
    }
    for b in backends::list(Kind::WebSearch) {
        if let Err(e) = ark_tools::web::providers::register(Box::new(WebProvider(b))) {
            eprintln!("ark: warning: {e}");
        }
    }
    for b in backends::list(Kind::Browser) {
        if let Err(e) = ark_browser::cloud::register(Arc::new(CloudBrowser(b))) {
            eprintln!("ark: warning: {e}");
        }
    }
}

/// Tools that replace a media tool whose provider is a plugin backend (`cfg.media` is `[media]`).
pub fn tools(media: &toml::Table) -> Vec<Arc<dyn Tool>> {
    let mut v: Vec<Arc<dyn Tool>> = Vec::new();
    for (kind, section, tool) in [(Kind::ImageGen, "image", "image_generate"), (Kind::VideoGen, "video", "video_generate")] {
        let Some(name) = media.get(section).and_then(|t| t.get("provider")).and_then(toml::Value::as_str) else { continue };
        let Some(b) = backends::select(kind, name) else { continue };
        v.push(Arc::new(MediaTool { tool, kind, backend: b }));
    }
    v
}

// ─── text-to-speech ─────────────────────────────────────────────────────────

struct TtsProvider(Arc<dyn Backend>);

impl ark_media::tts::TtsProvider for TtsProvider {
    fn id(&self) -> &str {
        self.0.name()
    }
    fn env(&self) -> &[&str] {
        // The plugin holds its own credentials; `configured()` then only asks availability.
        &[]
    }
    fn synthesize(&self, _m: &ark_media::Media, req: &ark_media::tts::TtsRequest, _cancel: &ark_core::Cancel) -> Result<ark_media::tts::Speech, String> {
        let params = json!({
            "text": req.text,
            "voice": req.voice,
            "model": req.model,
            "speed": req.speed,
            "format": req.format,
            "language": req.language,
            "instructions": req.instructions,
        });
        let out = self.0.call("synthesize", params)?;
        let mime = out["mime"].as_str().filter(|m| !m.is_empty()).unwrap_or("audio/mpeg");
        let audio = match (out["url"].as_str(), out["audio_base64"].as_str()) {
            (Some(u), _) => ark_media::Asset::from_url(u, mime),
            (None, Some(b)) => ark_media::Asset::from_b64(b, mime).map_err(|e| format!("tts backend `{}`: {e}", self.0.name()))?,
            (None, None) => return Err(format!("tts backend `{}` returned no audio", self.0.name())),
        };
        Ok(ark_media::tts::Speech { audio, sample_rate: out["sample_rate"].as_u64().map(|r| r as u32) })
    }
    fn voices(&self, _m: &ark_media::Media, _cancel: &ark_core::Cancel) -> Result<Vec<String>, String> {
        Ok(self.0.caps()["voices"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default())
    }
    fn dest(&self, _m: &ark_media::Media) -> Option<String> {
        Some(format!("plugin:{}", self.0.name()))
    }
}

// ─── speech-to-text ─────────────────────────────────────────────────────────

struct SttProvider(Arc<dyn Backend>);

impl ark_media::stt::SttProvider for SttProvider {
    fn id(&self) -> &str {
        self.0.name()
    }
    fn env(&self) -> &[&str] {
        &[]
    }
    fn transcribe(&self, _m: &ark_media::Media, req: &ark_media::stt::SttRequest, _cancel: &ark_core::Cancel) -> Result<ark_media::stt::Transcript, String> {
        let params = json!({
            "audio_base64": ark_net::crypto::b64(&req.audio),
            "mime": req.mime,
            "file_name": req.file_name,
            "language": req.language,
            "prompt": req.prompt,
            "model": req.model,
        });
        let out = self.0.call("transcribe", params)?;
        let text = out["text"].as_str().ok_or_else(|| format!("stt backend `{}` returned no text", self.0.name()))?;
        Ok(ark_media::stt::Transcript { text: text.to_string(), language: out["language"].as_str().map(str::to_string), duration: out["duration"].as_f64(), segments: vec![] })
    }
}

// ─── web search / extract ───────────────────────────────────────────────────

/// `WebProvider` demands `&'static str` ids: the backend's name is leaked once, at wrap time.
struct WebProvider(Arc<dyn Backend>);

impl ark_tools::web::providers::WebProvider for WebProvider {
    fn id(&self) -> &'static str {
        static IDS: std::sync::Mutex<Vec<(&'static str, String)>> = std::sync::Mutex::new(Vec::new());
        let name = self.0.name().to_string();
        let mut ids = IDS.lock().unwrap();
        if let Some((s, _)) = ids.iter().find(|(_, n)| *n == name) {
            return s;
        }
        let leaked: &'static str = Box::leak(name.clone().into_boxed_str());
        ids.push((leaked, name));
        leaked
    }
    fn label(&self) -> &'static str {
        "Plugin backend"
    }
    fn configured(&self, _c: &ark_tools::web::http::WebCtx) -> bool {
        self.0.available()
    }
    /// Only ever selected by name: `auto` keeps walking the bundled order.
    fn auto_detect(&self) -> bool {
        false
    }
    fn endpoint(&self, _c: &ark_tools::web::http::WebCtx) -> String {
        // The plugin makes its own request; the egress gate sees the backend, not a URL.
        format!("plugin://{}/search", self.0.name())
    }
    fn search(&self, _c: &ark_tools::web::http::WebCtx, r: &ark_tools::web::providers::SearchRequest) -> Result<ark_tools::web::providers::SearchOutput, String> {
        let mut params = json!({"query": r.query, "count": r.count});
        for (k, v) in [("country", &r.country), ("language", &r.language), ("freshness", &r.freshness), ("date_after", &r.date_after), ("date_before", &r.date_before), ("search_lang", &r.search_lang), ("ui_lang", &r.ui_lang)] {
            if let Some(x) = v {
                params[k] = json!(x);
            }
        }
        if !r.domain_filter.is_empty() {
            params["domain_filter"] = json!(r.domain_filter);
        }
        if !r.extra.is_empty() {
            params["extra"] = Value::Object(r.extra.clone());
        }
        let out = self.0.call("search", params)?;
        if let Some(a) = out["answer"].as_str().filter(|a| !a.is_empty()) {
            let citations = out["citations"].as_array().map(|c| c.iter().filter_map(|x| x["url"].as_str().map(|u| ark_tools::web::providers::Citation { url: u.to_string(), title: x["title"].as_str().map(str::to_string) })).collect()).unwrap_or_default();
            return Ok(ark_tools::web::providers::SearchOutput::Answer { content: a.to_string(), citations });
        }
        let hits = out["results"].as_array().ok_or_else(|| format!("web backend `{}` returned no `results`", self.0.name()))?;
        let hits = hits.iter().map(|h| ark_tools::web::providers::Hit {
            title: h["title"].as_str().unwrap_or("").to_string(),
            url: h["url"].as_str().unwrap_or("").to_string(),
            snippet: h["snippet"].as_str().or_else(|| h["description"].as_str()).unwrap_or("").to_string(),
            published: h["published"].as_str().map(str::to_string),
            site_name: h["siteName"].as_str().map(str::to_string),
        }).collect();
        Ok(ark_tools::web::providers::SearchOutput::Results(hits))
    }
    fn supports_extract(&self) -> bool {
        self.0.caps()["extract"].as_bool().unwrap_or(true)
    }
    fn extract(&self, _c: &ark_tools::web::http::WebCtx, urls: &[String]) -> Result<Vec<ark_tools::web::providers::Page>, String> {
        let out = self.0.call("extract", json!({"urls": urls}))?;
        let pages = out["pages"].as_array().ok_or_else(|| format!("web backend `{}` returned no `pages`", self.0.name()))?;
        Ok(pages.iter().map(|p| ark_tools::web::providers::Page {
            url: p["url"].as_str().unwrap_or("").to_string(),
            title: p["title"].as_str().unwrap_or("").to_string(),
            content: p["content"].as_str().unwrap_or("").to_string(),
            error: p["error"].as_str().map(str::to_string),
            source_url: None,
        }).collect())
    }
}

// ─── cloud browser ──────────────────────────────────────────────────────────

struct CloudBrowser(Arc<dyn Backend>);

impl ark_browser::cloud::CloudProvider for CloudBrowser {
    fn id(&self) -> &str {
        self.0.name()
    }
    fn label(&self) -> String {
        self.0.label()
    }
    fn available(&self, _secrets: ark_browser::cloud::Secrets<'_>) -> bool {
        self.0.available()
    }
    fn create(&self, _secrets: ark_browser::cloud::Secrets<'_>, task: &str) -> Result<ark_browser::cloud::CloudSession, String> {
        let out = self.0.call("create_session", json!({"task": task}))?;
        let id = out["id"].as_str().ok_or_else(|| format!("browser backend `{}` returned no `id`", self.0.name()))?;
        let cdp = out["cdp_url"].as_str().ok_or_else(|| format!("browser backend `{}` returned no `cdp_url`", self.0.name()))?;
        let name = out["session_name"].as_str().filter(|s| !s.is_empty()).map(str::to_string).unwrap_or_else(|| ark_browser::cloud::session_name(task));
        Ok(ark_browser::cloud::CloudSession::new(self.0.name(), id, cdp, out["features"].clone(), out["expires_at"].as_str().map(str::to_string), &name))
    }
    fn close(&self, _secrets: ark_browser::cloud::Secrets<'_>, session: &str) -> bool {
        self.0.call("close_session", json!({"session": session})).is_ok_and(|r| r["ok"].as_bool() != Some(false))
    }
    fn cleanup(&self, _secrets: ark_browser::cloud::Secrets<'_>, session: &str) {
        let _ = self.0.call("cleanup", json!({"session": session}));
    }
}

// ─── image / video generation ───────────────────────────────────────────────

/// `image_generate` / `video_generate` served by a plugin backend (upstream tool names and
/// parameters; the provider picks whatever else it needs from `params`).
struct MediaTool {
    tool: &'static str,
    kind: Kind,
    backend: Arc<dyn Backend>,
}

impl Tool for MediaTool {
    fn spec(&self) -> ToolSpec {
        let (desc, extra) = if self.kind == Kind::ImageGen {
            ("Generate images from a text prompt, or edit existing images passed in `image`/`images`. Served by the configured image backend.", json!({"image": {"type": "string", "description": "Source image to edit (path, URL or data: URL)."}, "images": {"type": "array", "items": {"type": "string"}}, "size": {"type": "string"}, "quality": {"type": "string"}, "output_format": {"type": "string"}}))
        } else {
            ("Generate a video from a text prompt or an image. Served by the configured video backend.", json!({"image": {"type": "string", "description": "First frame (image-to-video)."}, "duration": {"type": "number"}, "resolution": {"type": "string"}, "audio": {"type": "boolean"}}))
        };
        let mut props = json!({
            "prompt": {"type": "string", "description": "What to generate. Be detailed and descriptive."},
            "aspect_ratio": {"type": "string"},
            "count": {"type": "integer", "minimum": 1},
            "model": {"type": "string"},
            "seed": {"type": "integer"},
            "filename": {"type": "string"},
        });
        if let (Some(p), Some(e)) = (props.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                p.insert(k.clone(), v.clone());
            }
        }
        ToolSpec {
            name: self.tool.to_string(),
            description: format!("{} Backend: {} ({}).", desc, self.backend.label(), self.backend.name()),
            input_schema: json!({"type": "object", "properties": props, "required": ["prompt"]}),
            parallel_safe: true,
            idempotent: false,
            pinned: false,
        }
    }

    fn effects(&self, _ctx: &ToolCtx, _input: &Value) -> Vec<Effect> {
        // The plugin process makes the call itself: no request leaves this process.
        vec![]
    }

    fn call(&self, _ctx: &ToolCtx, input: Value) -> ToolOutput {
        if input["prompt"].as_str().is_none_or(|p| p.trim().is_empty()) {
            return ToolOutput::err("missing string argument `prompt`");
        }
        match self.backend.call("generate", input) {
            Ok(v) => ToolOutput::ok(v.to_string()),
            Err(e) => ToolOutput::err(e),
        }
    }
}

/// Self-registration (`ark_core::registry`): `[media.image] provider` / `[media.video] provider`
/// naming a plugin backend — the plugin serves the media tool.
pub fn register() {
    ark_core::registry::register_tool_provider("media-plugin-backends", 600, |env| {
        let cfg = env.config::<ark_kernel::config::Config>()?;
        Ok(tools(&cfg.media))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_core::Cancel;
    use ark_plugin::backends::{clear, is_reserved, operations, Backend};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// One in-process backend per kind, recording what it was asked to do.
    struct Fake {
        kind: Kind,
        name: String,
        calls: Mutex<Vec<(String, Value)>>,
        hits: AtomicUsize,
    }

    impl Fake {
        fn arc(kind: Kind, name: &str) -> Arc<Fake> {
            Arc::new(Fake { kind, name: name.into(), calls: Mutex::new(vec![]), hits: AtomicUsize::new(0) })
        }
    }

    impl Backend for Fake {
        fn kind(&self) -> Kind {
            self.kind
        }
        fn name(&self) -> &str {
            &self.name
        }
        fn caps(&self) -> Value {
            json!({"voices": ["v1"], "extract": false})
        }
        fn call(&self, op: &str, params: Value) -> Result<Value, String> {
            self.hits.fetch_add(1, Ordering::SeqCst);
            self.calls.lock().unwrap().push((op.to_string(), params.clone()));
            match (self.kind, op) {
                (Kind::Tts, "synthesize") => Ok(json!({"audio_base64": ark_net::crypto::b64(b"ID3fakemp3"), "mime": "audio/mpeg", "sample_rate": 16000})),
                (Kind::Stt, "transcribe") => Ok(json!({"text": "hello from the plugin", "language": "en", "duration": 1.5})),
                (Kind::WebSearch, "search") => Ok(json!({"results": [{"title": "T", "url": "https://example.test/1", "description": "D"}]})),
                (Kind::WebSearch, "extract") => Ok(json!({"pages": [{"url": params["urls"][0], "title": "P", "content": "page body"}]})),
                (Kind::Browser, "create_session") => Ok(json!({"id": "sess-1", "cdp_url": "wss://fake.test/1", "features": {"proxies": true}})),
                (Kind::Browser, "close_session") => Ok(json!({"ok": true})),
                (Kind::Browser, "cleanup") => Ok(json!({})),
                (Kind::ImageGen | Kind::VideoGen, "generate") => Ok(json!({"success": true, "provider": self.name, "prompt": params["prompt"]})),
                (_, op) => Err(format!("unsupported {op}")),
            }
        }
    }

    /// The registries this test touches are process-global.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static L: Mutex<()> = Mutex::new(());
        L.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn media() -> Arc<ark_media::Media> {
        ark_media::Media::new(ark_media::config::MediaConfig::new(toml::Table::new(), Arc::new(|_: &str| None)))
    }

    #[test]
    fn tts_and_stt_backends_serve_the_media_traits() {
        let _g = serial();
        clear();
        let tts = Fake::arc(Kind::Tts, "acme-voice");
        let stt = Fake::arc(Kind::Stt, "acme-ears");
        backends::register(tts.clone()).unwrap();
        backends::register(stt.clone()).unwrap();
        install(&[]);
        let m = media();
        // `[media.tts] provider = "acme-voice"` resolves through the media registry…
        let p = ark_media::tts::find(&m, "acme-voice").expect("tts backend is selectable by name");
        let speech = p.synthesize(&m, &ark_media::tts::TtsRequest::new("hi"), &Cancel::new()).unwrap();
        assert_eq!(speech.audio.bytes, b"ID3fakemp3");
        assert_eq!(speech.sample_rate, Some(16000));
        assert_eq!(p.voices(&m, &Cancel::new()).unwrap(), ["v1"]);
        assert_eq!(p.dest(&m).as_deref(), Some("plugin:acme-voice"));
        assert_eq!(tts.calls.lock().unwrap()[0], ("synthesize".to_string(), json!({"text": "hi", "voice": null, "model": null, "speed": null, "format": null, "language": null, "instructions": null})));
        // …and `[media.stt] provider = "acme-ears"` through the STT registry.
        let t = ark_media::stt::command::find_plugin("acme-ears").expect("stt backend registered");
        let req = ark_media::stt::SttRequest::new(b"audio-bytes".to_vec(), "audio/ogg");
        let tr = t.transcribe(&m, &req, &Cancel::new()).unwrap();
        assert_eq!(tr.text, "hello from the plugin");
        assert_eq!((tr.language.as_deref(), tr.duration), (Some("en"), Some(1.5)));
        let (_, params) = stt.calls.lock().unwrap()[0].clone();
        assert_eq!(params["mime"], "audio/ogg");
        assert_eq!(ark_net::crypto::b64_decode(params["audio_base64"].as_str().unwrap()).unwrap(), b"audio-bytes");
        clear();
    }

    #[test]
    fn web_backend_serves_search_and_extract() {
        let _g = serial();
        clear();
        let b = Fake::arc(Kind::WebSearch, "acme-search");
        backends::register(b.clone()).unwrap();
        install(&[]);
        use ark_tools::web::providers::SearchOutput;
        let p = ark_tools::web::providers::get("acme-search").expect("web backend selectable by name");
        let c = ark_tools::web::http::WebCtx::new(Arc::new(ark_tools::web::config::WebConfig::default()), Arc::new(|_: &str| None));
        assert!(!p.auto_detect(), "a plugin backend is never auto-detected");
        assert!(p.configured(&c));
        assert_eq!(p.endpoint(&c), "plugin://acme-search/search");
        match p.search(&c, &ark_tools::web::providers::SearchRequest { query: "ark".into(), count: 2, ..Default::default() }).unwrap() {
            SearchOutput::Results(h) => assert_eq!((h[0].url.as_str(), h[0].snippet.as_str()), ("https://example.test/1", "D")),
            other => panic!("{other:?}"),
        }
        assert!(!p.supports_extract(), "caps.extract = false");
        assert_eq!(p.extract(&c, &["https://example.test/1".into()]).unwrap()[0].content, "page body");
        assert_eq!(b.calls.lock().unwrap()[0].1["count"], 2);
        clear();
    }

    #[test]
    fn browser_backend_serves_cloud_sessions() {
        let _g = serial();
        clear();
        let b = Fake::arc(Kind::Browser, "acme-browser");
        backends::register(b.clone()).unwrap();
        install(&[]);
        let p = ark_browser::cloud::registered().into_iter().find(|p| p.id() == "acme-browser").expect("browser backend registered");
        let none: ark_browser::cloud::Secrets = &|_: &str| String::new();
        assert!(p.available(none));
        let s = p.create(none, "look at the page").unwrap();
        assert_eq!((s.id.as_str(), s.cdp_url.as_str()), ("sess-1", "wss://fake.test/1"));
        assert!(s.session_name.starts_with("ark_lookatthepage_") || !s.session_name.is_empty());
        assert!(p.close(none, &s.id));
        p.cleanup(none, &s.id);
        let ops: Vec<String> = b.calls.lock().unwrap().iter().map(|(o, _)| o.clone()).collect();
        assert_eq!(ops, ["create_session", "close_session", "cleanup"]);
        // The bundled ids stay with the bundled providers.
        assert!(ark_browser::cloud::register(Arc::new(CloudBrowser(Fake::arc(Kind::Browser, "browserbase") as Arc<dyn Backend>))).is_err());
        clear();
    }

    #[test]
    fn image_and_video_backends_serve_the_media_tools_only_when_configured() {
        let _g = serial();
        clear();
        backends::register(Fake::arc(Kind::ImageGen, "acme-pix")).unwrap();
        backends::register(Fake::arc(Kind::VideoGen, "acme-reel")).unwrap();
        let mut media = toml::Table::new();
        assert!(tools(&media).is_empty(), "nothing is replaced until the provider is configured");
        media.insert("image".into(), toml::Value::Table(toml::from_str("provider = \"acme-pix\"").unwrap()));
        media.insert("video".into(), toml::Value::Table(toml::from_str("provider = \"acme-reel\"").unwrap()));
        let t = tools(&media);
        let names: Vec<String> = t.iter().map(|t| t.spec().name).collect();
        assert_eq!(names, ["image_generate", "video_generate"]);
        let ctx = ToolCtx {
            workspace: ark_core::tmp::scratch("ark-ws"),
            session_id: "t".into(),
            artifacts: ark_core::tmp::scratch("ark-ws"),
            home: ark_core::tmp::scratch("ark-ws"),
            cancel: Cancel::new(),
            host: Arc::new(NoHost),
            secrets: Arc::new(|s: &str| s.to_string()),
        };
        let o = t[0].call(&ctx, json!({"prompt": "a red fox", "aspect_ratio": "square", "count": 2}));
        assert!(!o.is_error, "{}", o.content);
        assert_eq!(serde_json::from_str::<Value>(&o.content).unwrap()["provider"], "acme-pix");
        assert!(t[0].call(&ctx, json!({})).is_error);
        assert!(!t[1].call(&ctx, json!({"prompt": "a fox running"})).is_error);
        clear();
    }

    struct NoHost;
    impl ark_core::ToolHost for NoHost {
        fn spawn_agent(&self, _: ark_core::tool::SpawnRequest, _: &Cancel) -> Result<String, String> {
            Err("no".into())
        }
        fn ask_user(&self, _: &str) -> Result<String, String> {
            Err("no".into())
        }
    }

    /// `ark_plugin::backends::RESERVED` must stay in step with the tables the consuming crates
    /// own: a plugin that took a bundled name would shadow a real provider.
    #[test]
    fn reserved_names_cover_every_bundled_provider() {
        for id in ark_media::tts::BUILTIN {
            assert!(is_reserved(Kind::Tts, id), "tts `{id}` must be reserved");
        }
        for id in ark_media::stt::BUILTIN {
            assert!(is_reserved(Kind::Stt, id), "stt `{id}` must be reserved");
        }
        for p in ark_media::image_gen::providers() {
            assert!(is_reserved(Kind::ImageGen, p.id()), "image `{}` must be reserved", p.id());
        }
        for p in ark_media::video_gen::providers() {
            assert!(is_reserved(Kind::VideoGen, p.id()), "video `{}` must be reserved", p.id());
        }
        for p in ark_tools::web::providers::all() {
            assert!(is_reserved(Kind::WebSearch, p.id()), "web `{}` must be reserved", p.id());
            for a in p.aliases() {
                assert!(is_reserved(Kind::WebSearch, a), "web alias `{a}` must be reserved");
            }
        }
        for id in ["browserbase", "browser-use", "firecrawl"] {
            assert!(is_reserved(Kind::Browser, id), "browser `{id}` must be reserved");
        }
        // Every operation a consumer can invoke is declared for its kind.
        assert_eq!(operations(Kind::Browser), ["create_session", "close_session", "cleanup"]);
        assert!(operations(Kind::WebSearch).contains(&"search"));
    }
}
