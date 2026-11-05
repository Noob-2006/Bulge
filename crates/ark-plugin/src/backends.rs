//! Backend providers a plugin contributes to a capability ark already ships a tool for:
//! text-to-speech, speech-to-text, image generation, video generation, cloud browsers and web
//! search / extraction.
//!
//! Hermes models each family as a pluggy ABC — `agent/tts_provider.py`,
//! `agent/transcription_provider.py`, `agent/image_gen_provider.py`,
//! `agent/video_gen_provider.py`, `agent/browser_provider.py`,
//! `agent/web_search_provider.py` — whose instances plugins register with
//! `PluginContext.register_*_provider()`; the tool then resolves one by config key
//! (`tts.provider`, `stt.provider`, `image_gen.provider`, `browser.cloud_provider`,
//! `web.search.provider`, …). ark keeps the upstream selection rules:
//!
//! * a built-in name is **reserved**: registering `openai`, `browserbase`, `brave`, … fails;
//! * a provider is only used when its name is configured — nothing plugin-supplied is ever
//!   auto-selected (`auto` keeps walking the bundled order);
//! * config wins over a plugin install, so a `[media.tts.providers.<name>] command` block or a
//!   bundled provider with the same name still wins inside the consuming crate.
//!
//! ark's plugins are MCP processes, so a backend crosses the process boundary as one JSON-RPC
//! request, declared in `initialize`:
//!
//! ```json
//! {"capabilities": {"experimental": {"ark": {"backends": [
//!   {"kind": "tts", "id": "acme", "label": "Acme Voice", "caps": {"voices": ["en-US-1"]}}
//! ]}}}}
//! ```
//!
//! and served by `ark/backend.call {kind, id, op, params}` → the answer object (an `error`
//! string is a failure). The operations are the upstream method names:
//!
//! | kind | `op` | `params` | answer |
//! |---|---|---|---|
//! | `tts` | `synthesize` | `{text, voice?, model?, speed?, format?, language?, instructions?}` | `{audio_base64, mime?, sample_rate?}` |
//! | `stt` | `transcribe` | `{audio_base64, mime, file_name, model?, language?, prompt?}` | `{text, language?, duration?}` |
//! | `image_gen` | `generate` | `{prompt, aspect_ratio?, image_url?, reference_image_urls?, count?, model?, size?, …}` | upstream envelope (`{success, image, model, prompt, provider}`, `error` on failure) |
//! | `video_gen` | `generate` | `{prompt, model?, image_url?, aspect_ratio?, duration?, …}` | upstream envelope (`{success, video, model, …}`) |
//! | `browser` | `create_session` / `close_session` / `cleanup` | `{task}` / `{session}` / `{session}` | `{id, cdp_url, session_name, features?, expires_at?}` / `{ok}` / anything |
//! | `web_search` | `search` / `extract` | `{query, count, …}` / `{urls}` | `{results: [{title, url, snippet?, published?, siteName?}]}` or `{answer, citations}` / `{pages: [{url, title?, content}]}` |
//!
//! In-process code (ark's built-in plugins, or the `ark` binary) registers the same [`Backend`]
//! with [`register`]; the host bridges this registry into the consuming crate — see
//! `crates/ark/src/plugin_backends.rs` (`ark_media::tts::register`, `ark_media::stt::register`,
//! `ark_tools::web::providers::register`, `ark_browser::cloud::register`).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::{Arc, OnceLock, RwLock};

/// The capability families a plugin can contribute a backend to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Tts,
    Stt,
    ImageGen,
    VideoGen,
    Browser,
    WebSearch,
}

impl Kind {
    pub const ALL: [Kind; 6] = [Kind::Tts, Kind::Stt, Kind::ImageGen, Kind::VideoGen, Kind::Browser, Kind::WebSearch];

    /// The wire name (`"tts"`, `"stt"`, `"image_gen"`, `"video_gen"`, `"browser"`, `"web_search"`).
    /// Also accepts the crate-internal spellings `image` / `video` / `websearch`.
    pub fn parse(s: &str) -> Option<Kind> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tts" | "text-to-speech" | "text_to_speech" => Some(Kind::Tts),
            "stt" | "transcription" | "speech-to-text" | "speech_to_text" => Some(Kind::Stt),
            "image_gen" | "image" | "image-generation" => Some(Kind::ImageGen),
            "video_gen" | "video" | "video-generation" => Some(Kind::VideoGen),
            "browser" | "browser_cloud" | "cloud_browser" => Some(Kind::Browser),
            "web_search" | "websearch" | "web" => Some(Kind::WebSearch),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Tts => "tts",
            Kind::Stt => "stt",
            Kind::ImageGen => "image_gen",
            Kind::VideoGen => "video_gen",
            Kind::Browser => "browser",
            Kind::WebSearch => "web_search",
        }
    }

    /// The config key that selects this kind's provider (shown in errors).
    pub fn config_key(self) -> &'static str {
        match self {
            Kind::Tts => "[media.tts] provider",
            Kind::Stt => "[media.stt] provider",
            Kind::ImageGen => "[media.image] provider",
            Kind::VideoGen => "[media.video] provider",
            Kind::Browser => "[browser] cloud_provider",
            Kind::WebSearch => "[web.search] provider",
        }
    }
}

/// The operations this kind serves (`Backend::call`).
pub fn operations(kind: Kind) -> &'static [&'static str] {
    match kind {
        Kind::Tts => &["synthesize"],
        Kind::Stt => &["transcribe"],
        Kind::ImageGen | Kind::VideoGen => &["generate"],
        Kind::Browser => &["create_session", "close_session", "cleanup"],
        Kind::WebSearch => &["search", "extract"],
    }
}

/// Built-in (bundled) names per kind. A plugin may never take one of these: the bundled provider
/// keeps the name, exactly like the upstream registries (`BUILTIN_TTS_PROVIDERS`, …). These
/// mirror the tables in `ark-media` (`tts::BUILTIN`, `image_gen`/`video_gen` provider ids),
/// `ark-tools` (`web::providers::all`) and `ark-browser` (`cloud::BUNDLED`); the host asserts the
/// three crates do not drift (`crates/ark/src/plugin_backends.rs` tests).
pub const RESERVED: &[(Kind, &[&str])] = &[
    (
        Kind::Tts,
        &[
            "edge", "microsoft", "openai", "deepinfra", "openrouter", "elevenlabs", "xai", "xai-oauth", "minimax", "mistral", "gemini", "google", "azure-speech", "azure", "inworld", "fish-audio", "fish", "gradium", "volcengine", "bytedance", "doubao", "xiaomi", "vydra", "neutts", "piper", "kittentts", "tts-local-cli", "cli", "auto",
        ],
    ),
    (Kind::Stt, &["local", "local_command", "groq", "openai", "mistral", "xai", "elevenlabs", "deepinfra", "deepgram", "auto", "none"]),
    (
        Kind::ImageGen,
        &["fal", "fal-ai", "falai", "openai", "openai-codex", "codex", "chatgpt", "google", "gemini", "imagen", "google-gemini", "xai", "grok", "x-ai", "openrouter", "krea", "deepinfra", "minimax", "meta-ai", "meta", "muse", "vydra", "microsoft-foundry", "foundry", "azure-foundry", "mai", "litellm", "comfy", "comfyui", "auto"],
    ),
    (
        Kind::VideoGen,
        &["fal", "xai", "grok", "openrouter", "deepinfra", "google", "gemini", "minimax", "runway", "byteplus", "dashscope", "alibaba", "qwen", "kie", "pixverse", "together", "zai", "novita", "vydra", "comfy", "comfyui", "auto"],
    ),
    (Kind::Browser, &["browserbase", "browser-use", "browser_use", "firecrawl", "auto", "local", "none"]),
    (
        Kind::WebSearch,
        &["brave", "brave-free", "minimax", "gemini", "google", "xai", "grok", "kimi", "moonshot", "perplexity", "firecrawl", "firecrawl-free", "exa", "tavily", "parallel", "parallel-free", "keenable", "deepseek", "duckduckgo", "ddgs", "ddg", "ollama", "searxng", "openai-native", "openai", "codex", "auto", "none", "keyless"],
    ),
];

/// Is `name` a bundled provider of `kind` (or a name consumers treat as "pick one for me")?
pub fn is_reserved(kind: Kind, name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    RESERVED.iter().any(|(k, names)| *k == kind && names.iter().any(|x| *x == n))
}

/// One backend. In-process implementations live in the binary (they wrap an external plugin or a
/// built-in service); process plugins get [`PluginBackend`](crate::plugin::PluginBackend).
pub trait Backend: Send + Sync {
    fn kind(&self) -> Kind;
    /// The name `config` selects it by (lowercase `[a-z0-9_-]`).
    fn name(&self) -> &str;
    fn label(&self) -> String {
        self.name().to_string()
    }
    /// Usable right now. Must be cheap: no network, no install (upstream `is_available`).
    fn available(&self) -> bool {
        true
    }
    /// Static description for pickers: `voices`/`models`/`capabilities` (upstream `list_voices`,
    /// `list_models`, `capabilities()`). Free-form JSON.
    fn caps(&self) -> Value {
        json!({})
    }
    /// Run one [`operations`] entry; `Err` is shown to the user as-is.
    fn call(&self, op: &str, params: Value) -> Result<Value, String>;
}

fn registry() -> &'static RwLock<Vec<Arc<dyn Backend>>> {
    static R: OnceLock<RwLock<Vec<Arc<dyn Backend>>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_'))
}

/// Register (or replace) the backend named `b.name()` for `b.kind()`.
pub fn register(b: Arc<dyn Backend>) -> Result<(), String> {
    let (kind, raw) = (b.kind(), b.name().trim());
    if !valid_name(raw) {
        return Err(format!("backend name `{raw}`: use lowercase letters, digits, `-` or `_` (1-64 chars)"));
    }
    let name = raw.to_ascii_lowercase();
    if is_reserved(kind, &name) {
        return Err(format!("backend name `{name}` is reserved for a bundled {} provider ({})", kind.as_str(), kind.config_key()));
    }
    let mut r = registry().write().unwrap();
    r.retain(|x| !(x.kind() == kind && x.name().eq_ignore_ascii_case(&name)));
    r.push(b);
    Ok(())
}

/// Every registered backend of `kind`, in registration order.
pub fn list(kind: Kind) -> Vec<Arc<dyn Backend>> {
    registry().read().unwrap().iter().filter(|b| b.kind() == kind).cloned().collect()
}

/// The backend `name` of `kind`. Bundled names are never returned: the consuming crate keeps
/// those (config and command providers beat a plugin install, upstream's precedence).
pub fn find(kind: Kind, name: &str) -> Option<Arc<dyn Backend>> {
    let n = name.trim().to_ascii_lowercase();
    if n.is_empty() || is_reserved(kind, &n) {
        return None;
    }
    registry().read().unwrap().iter().find(|b| b.kind() == kind && b.name().eq_ignore_ascii_case(&n)).cloned()
}

/// Resolve the configured provider `name` for `kind`: `Some` only when a plugin backend with that
/// name exists and is available (otherwise the bundled/built-in path serves the call).
pub fn select(kind: Kind, name: &str) -> Option<Arc<dyn Backend>> {
    find(kind, name).filter(|b| b.available())
}

/// Drop every registration (tests, and a host re-reading its plugin set).
#[doc(hidden)]
pub fn clear() {
    registry().write().unwrap().clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    struct Fake {
        kind: Kind,
        name: &'static str,
        calls: Arc<AtomicUsize>,
    }

    impl Backend for Fake {
        fn kind(&self) -> Kind {
            self.kind
        }
        fn name(&self) -> &str {
            self.name
        }
        fn label(&self) -> String {
            format!("{} (fake)", self.name)
        }
        fn caps(&self) -> Value {
            json!({"voices": ["v1"]})
        }
        fn call(&self, op: &str, params: Value) -> Result<Value, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match op {
                "synthesize" => Ok(json!({"audio_base64": "AAA=", "mime": "audio/mpeg"})),
                "generate" if params["prompt"] == "fail" => Err("provider said no".into()),
                other => Ok(json!({"op": other, "params": params})),
            }
        }
    }

    fn fake(kind: Kind, name: &'static str) -> (Arc<dyn Backend>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (Arc::new(Fake { kind, name, calls: calls.clone() }), calls)
    }

    /// The registry is process-global: the registration tests must not interleave.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static L: Mutex<()> = Mutex::new(());
        L.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn kinds_and_operations_round_trip() {
        for k in Kind::ALL {
            assert_eq!(Kind::parse(k.as_str()), Some(k), "{}", k.as_str());
            assert!(!operations(k).is_empty());
        }
        assert_eq!(Kind::parse("image"), Some(Kind::ImageGen));
        assert_eq!(Kind::parse("bogus"), None);
    }

    #[test]
    fn registration_validates_names_and_builtin_collisions() {
        let _g = serial();
        clear();
        let (b, _) = fake(Kind::Tts, "acme-voice");
        assert!(register(b).is_ok());
        let (b, _) = fake(Kind::Tts, "Acme");
        assert!(register(b).unwrap_err().contains("lowercase"));
        let (b, _) = fake(Kind::Tts, "openai");
        assert!(register(b).unwrap_err().contains("reserved"));
        let (b, _) = fake(Kind::WebSearch, "brave-free");
        assert!(register(b).unwrap_err().contains("reserved"));
        // Reserved names never resolve to a plugin, even if someone bypassed `register`.
        assert!(find(Kind::Tts, "openai").is_none());
        clear();
    }

    #[test]
    fn find_is_per_kind_and_replaces_the_same_name() {
        let _g = serial();
        clear();
        let (b, calls) = fake(Kind::Tts, "acme");
        register(b).unwrap();
        assert!(find(Kind::Stt, "acme").is_none(), "kinds do not share names");
        let found = find(Kind::Tts, "ACME").expect("case-insensitive");
        assert_eq!(found.label(), "acme (fake)");
        assert_eq!(found.caps()["voices"][0], "v1");
        assert_eq!(found.call("synthesize", json!({"text": "hi"})).unwrap()["mime"], "audio/mpeg");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let (b2, _) = fake(Kind::Tts, "acme");
        register(b2).unwrap();
        assert_eq!(list(Kind::Tts).len(), 1, "same name replaces");
        assert_eq!(selected("acme"), Some("acme".to_string()));
        assert_eq!(find(Kind::Tts, "acme").unwrap().call("generate", json!({"prompt": "fail"})).unwrap_err(), "provider said no");
        clear();
    }

    fn selected(name: &str) -> Option<String> {
        select(Kind::Tts, name).map(|b| b.name().to_string())
    }
}
