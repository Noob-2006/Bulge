//! ark-media: everything that is not text. Vision (load images for the model,
//! image prep, describe for text-only models), document extraction (PDF, OOXML,
//! ODF, ipynb, RTF), image/video/music generation, speech synthesis and
//! recognition (cloud, local, command), inbound channel media understanding,
//! realtime transcription and voice, CLI voice mode, meeting bots and phone calls.
//!
//! Providers talk to each vendor's documented HTTP/WebSocket API directly (no
//! SDKs). Configuration lives under `[media]` (see [`config`]).

pub mod audio;
pub mod config;
/// Generation runtime shared by image/video/music generation (model refs, fallback
/// candidates, geometry, background jobs).
pub mod genrt;
pub mod http;
pub mod proc;
pub mod store;
#[cfg(test)]
pub mod testutil;

pub mod docs;
pub mod image_gen;
pub mod inbound;
pub mod meeting;
pub mod music_gen;
pub mod phone;
pub mod realtime;
pub mod stt;
pub mod tts;
pub mod understand;
pub mod video_gen;
pub mod vision;
pub mod voice;

pub use config::{Creds, MediaConfig};
pub use store::Asset;

use ark_core::{Cancel, Message, Tool, ToolCtx};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

/// Calls the agent's own chat models (for vision fallbacks, summaries, voice turns).
/// Installed by the binary once the kernel exists.
pub trait Llm: Send + Sync {
    /// One completion; `model` = `provider/model` or `None` for the configured default.
    fn complete(&self, model: Option<&str>, system: &str, messages: Vec<Message>, max_tokens: u32, cancel: &Cancel) -> Result<String, String>;
    /// Whether `model` (or the default) accepts image input.
    fn vision(&self, model: Option<&str>) -> bool;
}

/// Runs one agent turn for voice front-ends (voice mode, talk, meetings, calls):
/// `session` (created when `None`), the user's words → the agent's reply text.
pub trait Agent: Send + Sync {
    fn turn(&self, session: Option<&str>, text: &str, source: &str, cancel: &Cancel) -> Result<(String, String), String>;
}

static LLM: OnceLock<Arc<dyn Llm>> = OnceLock::new();
static AGENT: OnceLock<Arc<dyn Agent>> = OnceLock::new();

pub fn set_llm(l: Arc<dyn Llm>) {
    let _ = LLM.set(l);
}
pub fn llm() -> Option<Arc<dyn Llm>> {
    LLM.get().cloned()
}
pub fn set_agent(a: Arc<dyn Agent>) {
    let _ = AGENT.set(a);
}
pub fn agent() -> Option<Arc<dyn Agent>> {
    AGENT.get().cloned()
}

/// Shared media services: config + HTTP client.
pub struct Media {
    pub cfg: MediaConfig,
    pub http: http::Http,
}

impl Media {
    pub fn new(cfg: MediaConfig) -> Arc<Media> {
        Arc::new(Media { cfg, http: http::Http::default() })
    }
    /// `<output_dir>/<kind>` for a tool call's workspace.
    pub fn out_dir(&self, ctx: &ToolCtx, kind: &str) -> PathBuf {
        self.cfg.output_dir(&ctx.workspace).join(kind)
    }
    pub fn creds(&self, id: &str, envs: &[&str], default_base: &str) -> Creds {
        self.cfg.creds(id, envs, default_base)
    }
    /// Fetch a provider-hosted result through the SSRF guard (see [`http::Http::download`]).
    pub fn download(&self, url: &str, headers: &http::Headers) -> Result<(Vec<u8>, String), String> {
        self.http.download(&self.cfg, url, headers)
    }
    /// `GET` a provider-supplied JSON URL under the same guard (fal `status_url`/`response_url`).
    pub fn get_json_checked(&self, url: &str, headers: &http::Headers) -> Result<serde_json::Value, String> {
        self.http.get_json_checked(&self.cfg, url, headers)
    }
}

/// Every media tool, given the `[media]` config.
pub fn tools(m: &Arc<Media>) -> Vec<Arc<dyn Tool>> {
    let mut v: Vec<Arc<dyn Tool>> = Vec::new();
    v.extend(vision::tools(m));
    v.extend(docs::tools(m));
    v.extend(image_gen::tools(m));
    v.extend(video_gen::tools(m));
    v.extend(music_gen::tools(m));
    v.extend(tts::tools(m));
    v.extend(stt::tools(m));
    v.extend(understand::tools(m));
    v.extend(meeting::tools(m));
    v.extend(phone::tools(m));
    v.extend(realtime::tools(m));
    v.extend(voice::tools(m));
    let disabled = m.cfg.list("disabled_tools");
    v.retain(|t| !disabled.contains(&t.spec().name));
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn tool_names_unique_and_schemas_are_objects() {
        let ts = tools(&Media::new(MediaConfig::default()));
        let names: HashSet<_> = ts.iter().map(|t| t.spec().name).collect();
        assert_eq!(names.len(), ts.len());
        for t in &ts {
            let s = t.spec();
            assert_eq!(s.input_schema["type"], "object", "{}", s.name);
            assert!(!s.description.is_empty(), "{}", s.name);
        }
    }
}
