//! Interface: tools. Every tool declares the concrete effects of a call so the two
//! gates can judge it without knowing the tool.

use crate::cancel::Cancel;
use crate::types::ToolSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Effect {
    Read { path: PathBuf },
    Write { path: PathBuf },
    /// A shell command line, judged by the privilege and egress gates.
    Exec { command: String },
    /// Data leaving the machine over the network.
    Net { dest: String, payload: String },
    /// Message to a human channel.
    Send { channel: String, payload: String },
    /// Spawning another agent (budget accounting only).
    Spawn,
    /// A call that always needs the egress gate's say-so (untrusted MCP server,
    /// spend limit reached): `reason` is shown when asking.
    Remote { dest: String, reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    /// May run concurrently with other parallel-safe calls in the same step.
    #[serde(default)]
    pub parallel_safe: bool,
    /// Safe to re-run after a crash between `called` and `settled`.
    #[serde(default)]
    pub idempotent: bool,
    /// Pinned tools ship their full schema every request; others are reached
    /// through `tool_describe` + `tool_call` (progressive disclosure).
    #[serde(default)]
    pub pinned: bool,
}

impl ToolSpec {
    pub fn schema(&self) -> ToolSchema {
        ToolSchema { name: self.name.clone(), description: self.description.clone(), input_schema: self.input_schema.clone() }
    }
    /// First sentence of the description for the tool index.
    pub fn summary(&self) -> &str {
        let d = self.description.trim();
        let end = d.find(['\n', '。']).or_else(|| d.find(". ").map(|i| i + 1)).unwrap_or(d.len());
        &d[..end]
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ToolOutput {
    pub content: String,
    #[serde(default)]
    pub is_error: bool,
    /// An interactive view for UIs (MCP Apps: `{server, tool, uri, html, csp, …}`).
    /// Never reaches the model; the kernel records it on `tool_settled`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ui_resource: Option<Value>,
}

impl ToolOutput {
    pub fn ok(s: impl Into<String>) -> Self {
        ToolOutput { content: s.into(), is_error: false, ui_resource: None }
    }
    pub fn err(s: impl Into<String>) -> Self {
        ToolOutput { content: s.into(), is_error: true, ui_resource: None }
    }
}

/// Services the kernel offers to a running tool.
pub trait ToolHost: Send + Sync {
    /// Run a sub-agent to completion and return its final answer.
    fn spawn_agent(&self, req: SpawnRequest, cancel: &Cancel) -> Result<String, String>;
    /// Ask the human a question (may fail in headless mode).
    fn ask_user(&self, question: &str) -> Result<String, String>;
    /// Ask with pickable choices. Hosts that can render native buttons use them; the
    /// default falls back to a numbered list in the question text. The reply may be a
    /// number, a label or free text ("Other").
    fn ask_user_choice(&self, question: &str, choices: &[String], multi: bool) -> Result<String, String> {
        let mut text = question.to_string();
        if !choices.is_empty() {
            text.push('\n');
            for (i, c) in choices.iter().enumerate() {
                text.push_str(&format!("  {}. {c}\n", i + 1));
            }
            text.push_str(&format!("  {}. Other (type your answer)\n", choices.len() + 1));
            text.push_str(if multi { "Reply with one or more numbers (e.g. 1,3), or type your own answer." } else { "Reply with a number, or type your own answer." });
        }
        self.ask_user(&text)
    }
    /// Live progress from a long-running tool, shown by attached UIs (not logged).
    fn progress(&self, _text: &str) {}
    /// The concrete host, for tools that live next to it (kernel session / sub-agent tools).
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        None
    }
    /// One plain completion with no tools and no conversation (deep research, summarizers).
    /// `model` empty = the host's default/aux model. The default is unavailable so foreign
    /// hosts (tests, MCP servers) do not accidentally reach a model.
    fn complete_text(&self, _model: &str, _system: &str, _prompt: &str, _max_tokens: u32) -> Result<String, String> {
        Err("no model is available to this tool host".into())
    }
    /// Answer `question` about an image (base64 `data` of `media_type`) with a vision-capable
    /// model; used by screenshot tools (browser_vision, computer_use capture).
    fn analyze_image(&self, _question: &str, _media_type: &str, _data: &str) -> Result<String, String> {
        Err("no vision model is available to this tool host".into())
    }
    /// Environment every process this session starts must carry (C9: a sub-agent never
    /// inherits the driver's `SEAGENT_HOME`). `key=value` pairs; default: nothing extra.
    fn sandbox_env(&self) -> Vec<(String, String)> {
        Vec::new()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SpawnRequest {
    pub task: String,
    #[serde(default)]
    pub model: Option<String>,
    /// Fork: seed the child with the parent's conversation.
    #[serde(default)]
    pub fork: bool,
    #[serde(default)]
    pub tools: Option<Vec<String>>,
    /// Run the child in its own git worktree (None = `delegation.worktree_isolation`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worktree: Option<bool>,
}

#[derive(Clone)]
pub struct ToolCtx {
    pub workspace: PathBuf,
    pub session_id: String,
    /// Where large outputs are spilled.
    pub artifacts: PathBuf,
    /// Arkhome (~/.local/share/seagent) for memory files etc.
    pub home: PathBuf,
    pub cancel: Cancel,
    pub host: Arc<dyn ToolHost>,
    /// Secret values substituted for `{{secret:NAME}}` at execution time.
    pub secrets: Arc<dyn Fn(&str) -> String + Send + Sync>,
}

impl ToolCtx {
    /// Resolve a model-supplied path against the workspace.
    pub fn resolve(&self, p: &str) -> PathBuf {
        let p = expand_home(p);
        if p.is_absolute() {
            p
        } else {
            self.workspace.join(p)
        }
    }
}

pub fn expand_home(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(h) = std::env::var_os("HOME") {
            return Path::new(&h).join(rest);
        }
    }
    PathBuf::from(p)
}

pub trait Tool: Send + Sync {
    fn spec(&self) -> ToolSpec;
    /// Concrete effects of this particular call (judged by the gates before running).
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect>;
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput;
}

/// Helpers for tool implementations.
pub fn arg_str<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v.get(k).and_then(|x| x.as_str()).ok_or_else(|| format!("missing string argument `{k}`"))
}
pub fn arg_opt_str<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(|x| x.as_str())
}
pub fn arg_opt_u64(v: &Value, k: &str) -> Option<u64> {
    v.get(k).and_then(|x| x.as_u64())
}
pub fn arg_opt_bool(v: &Value, k: &str) -> Option<bool> {
    v.get(k).and_then(|x| x.as_bool())
}

/// Tools whose output may attach an image file for the model (`read` of a PNG/JPEG…,
/// `vision_analyze`, `view_image`).
/// Markers in any other tool's output (e.g. a `cat` of an untrusted file) are left as text.
pub const IMAGE_TOOLS: &[&str] = &["read", "vision_analyze", "view_image"];
/// Largest image attached to a tool result (provider limits are ~5 MB).
pub const MAX_IMAGE_BYTES: u64 = 5 * 1024 * 1024;
const IMAGE_MARKER: &str = "[[seagent:image ";

/// Installed by the binary (`seagent_media::vision::post_tool_images`): shrink / re-encode the
/// images a tool attached before the model sees them (OpenClaw `image-sanitization`).
static IMAGE_POST: std::sync::OnceLock<fn(&mut Vec<crate::types::Block>) -> usize> = std::sync::OnceLock::new();

/// Install the image post-processor (first install wins; see [`post_process_images`]).
pub fn set_image_post(f: fn(&mut Vec<crate::types::Block>) -> usize) {
    let _ = IMAGE_POST.set(f);
}

/// Run the installed image post-processor over tool images; 0 when none is installed.
pub fn post_process_images(blocks: &mut Vec<crate::types::Block>) -> usize {
    IMAGE_POST.get().map(|f| f(blocks)).unwrap_or(0)
}

/// Whether a post-processor is installed (the binary's image sanitizer).
pub fn image_post_installed() -> bool {
    IMAGE_POST.get().is_some()
}

/// Line a tool appends to its output to attach `path` (an image of `media_type`).
pub fn image_marker(media_type: &str, path: &Path) -> String {
    format!("{IMAGE_MARKER}{media_type} {}]]", path.display())
}

/// Media type from an image's magic bytes (PNG, JPEG, GIF, WebP).
pub fn image_media_type(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if data.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if data.len() > 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

/// Split image markers out of a tool's output: (text without them, [(media_type, base64)]).
/// Only real image files of at most MAX_IMAGE_BYTES are attached.
pub fn take_images(content: &str) -> (String, Vec<(String, String)>) {
    if !content.contains(IMAGE_MARKER) {
        return (content.to_string(), vec![]);
    }
    let mut text = Vec::new();
    let mut imgs = Vec::new();
    for line in content.split('\n') {
        let Some(rest) = line.trim().strip_prefix(IMAGE_MARKER).and_then(|r| r.strip_suffix("]]")) else {
            text.push(line);
            continue;
        };
        let Some((_, path)) = rest.split_once(' ') else { continue };
        let ok = std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.len() <= MAX_IMAGE_BYTES);
        if let Some(data) = ok.then(|| std::fs::read(path).ok()).flatten() {
            if let Some(mt) = image_media_type(&data) {
                imgs.push((mt.to_string(), base64_encode(&data)));
            }
        }
    }
    (text.join("\n").trim_end().to_string(), imgs)
}

pub fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            out.push(if i <= c.len() { T[(n >> shift) as usize & 63] as char } else { '=' });
        }
    }
    out
}

#[cfg(test)]
mod image_tests {
    use super::*;

    #[test]
    fn markers_attach_only_real_images() {
        assert_eq!(base64_encode(b"Man"), "TWFu");
        assert_eq!(base64_encode(b"Ma"), "TWE=");
        assert_eq!(base64_encode(b"M"), "TQ==");
        let d = crate::tmp::scratch_path(format!("seagent-core-img-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let png = d.join("a.png");
        std::fs::write(&png, b"\x89PNG\r\n\x1a\nrest").unwrap();
        let fake = d.join("b.png");
        std::fs::write(&fake, b"not an image").unwrap();
        let out = format!("Read image a.png\n{}\n{}", image_marker("image/png", &png), image_marker("image/png", &fake));
        let (text, imgs) = take_images(&out);
        assert_eq!(text, "Read image a.png");
        assert_eq!(imgs, vec![("image/png".to_string(), base64_encode(b"\x89PNG\r\n\x1a\nrest"))]);
        assert_eq!(take_images("plain").0, "plain");
        let _ = std::fs::remove_dir_all(&d);
    }
}
