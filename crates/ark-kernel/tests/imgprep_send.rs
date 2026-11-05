//! The send path really prepares images per provider: non-vision models get text stand-ins,
//! vision models keep their images, and old tool-result images are retired once a request would
//! cross a provider image limit. Everything here goes through `Kernel::run`, so it pins the
//! wiring in `kernel.rs` (not just the pure `imgprep` functions).

use ark_core::*;
use ark_kernel::approver::{Approval, ApprovalRequest, Approver};
use ark_kernel::config::{Config, Paths};
use ark_kernel::imgprep;
use ark_kernel::kernel::{new_kernel, Resolver, RunOpts};
use ark_kernel::vault::Vault;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

// ───────────── a model that calls `read` once per turn, then answers ─────────────

struct Model {
    id: String,
    vision: bool,
    seen: Mutex<Vec<ModelRequest>>,
}

impl Model {
    fn new(id: &str, vision: bool) -> Arc<Self> {
        Arc::new(Model { id: id.into(), vision, seen: Mutex::new(vec![]) })
    }
    /// Kept for ad-hoc debugging of a multi-turn exchange (no test reads it today).
    #[allow(dead_code)]
    fn requests(&self) -> Vec<ModelRequest> {
        self.seen.lock().unwrap().clone()
    }
    fn last(&self) -> ModelRequest {
        self.seen.lock().unwrap().last().cloned().expect("a request")
    }
}

impl Provider for Model {
    fn id(&self) -> &str {
        &self.id
    }
    fn caps(&self, _: &str) -> ModelCaps {
        ModelCaps { context_window: 200_000, max_output: 8_192, tools: true, vision: self.vision, explicit_cache: false }
    }
    fn complete(&self, req: &ModelRequest, _: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, ProviderError> {
        self.seen.lock().unwrap().push(req.clone());
        static N: AtomicUsize = AtomicUsize::new(0);
        let answered = req.messages.last().is_some_and(|m| m.content.iter().any(|b| matches!(b, Block::ToolResult { .. })));
        let (content, stop) = if answered {
            (vec![Block::text("seen")], StopReason::EndTurn)
        } else {
            (vec![Block::ToolUse { id: format!("tu_{}", N.fetch_add(1, Ordering::SeqCst)), name: "read".into(), input: json!({"path": "pic.png"}) }], StopReason::ToolUse)
        };
        Ok(ModelResponse { message: Message { role: Role::Assistant, content }, stop, usage: Usage { input_tokens: 10, output_tokens: 5, ..Default::default() }, model: String::new() })
    }
}

struct Res(Arc<Model>);
impl Resolver for Res {
    fn provider(&self, id: &str) -> Result<Arc<dyn Provider>, String> {
        if id == self.0.id {
            Ok(self.0.clone())
        } else {
            Err(format!("no provider {id}"))
        }
    }
}

struct ReadTool(Arc<AtomicUsize>);
impl Tool for ReadTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec { name: "read".into(), description: "read a file.".into(), input_schema: json!({"type": "object"}), parallel_safe: false, idempotent: true, pinned: true }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![Effect::Read { path: "pic.png".into() }]
    }
    fn call(&self, ctx: &ToolCtx, _: Value) -> ToolOutput {
        self.0.fetch_add(1, Ordering::SeqCst);
        let path = ctx.workspace.join("pic.png");
        ToolOutput::ok(format!("pic.png (2400x1200)\n{}", ark_core::tool::image_marker("image/png", &path)))
    }
}

struct Yes;
impl Approver for Yes {
    fn approve(&self, _: &ApprovalRequest) -> Approval {
        Approval::Always
    }
    fn ask(&self, _: &str, q: &str) -> Result<String, String> {
        Ok(format!("answer to {q}"))
    }
}

fn rand_hex() -> String {
    use std::sync::atomic::AtomicUsize;
    static N: AtomicUsize = AtomicUsize::new(0);
    format!("{:x}{:x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(), N.fetch_add(1, Ordering::SeqCst))
}

/// A PNG of `w×h` (real header, so the send path measures it like any provider would).
fn png(w: u32, h: u32) -> Vec<u8> {
    let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
    v.extend_from_slice(&[0, 0, 0, 13]);
    v.extend_from_slice(b"IHDR");
    v.extend_from_slice(&w.to_be_bytes());
    v.extend_from_slice(&h.to_be_bytes());
    v.extend_from_slice(&[8, 6, 0, 0, 0]);
    v
}

struct Env {
    k: ark_kernel::kernel::Kernel,
    model: Arc<Model>,
    ws: std::path::PathBuf,
    reads: Arc<AtomicUsize>,
}

fn env(vision: bool) -> Env {
    let root = ark_core::tmp::scratch_path(format!("ark-imgprep-{}", rand_hex()));
    let ws = root.join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::write(ws.join("pic.png"), png(2400, 1200)).unwrap();
    let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run") };
    let mut cfg = Config::default();
    cfg.model.default = "main/m1".into();
    cfg.model.fallback = vec![];
    cfg.checkpoint.enabled = false;
    let model = Model::new("main", vision);
    let mut map = HashMap::new();
    map.insert("main".to_string(), model.clone());
    let reads = Arc::new(AtomicUsize::new(0));
    let tools: Vec<Arc<dyn Tool>> = vec![Arc::new(ReadTool(reads.clone()))];
    let k = new_kernel(cfg, paths, Arc::new(Res(model.clone())), tools, Arc::new(Vault::empty()), Arc::new(Yes));
    imgprep::clear_latch();
    Env { k, model, ws, reads }
}

fn run_turn(e: &Env, id: &str, prompt: &str) {
    e.k.submit(id, prompt, "cli").unwrap();
    assert!(e.k.run(id, RunOpts::default()).unwrap().reason.ok(), "turn failed");
}

fn images(req: &ModelRequest) -> usize {
    req.messages.iter().flat_map(|m| m.content.iter()).filter(|b| matches!(b, Block::Image { .. })).count()
}

#[test]
fn a_non_vision_model_never_receives_image_parts() {
    let e = env(false);
    let id = e.k.create_session(&e.ws, None, None, None).unwrap();
    e.k.submit_with(&id, "what is this?", vec![Block::Image { media_type: "image/png".into(), data: ark_core::tool::base64_encode(&png(64, 64)) }], "cli").unwrap();
    assert!(e.k.run(&id, RunOpts::default()).unwrap().reason.ok());
    let req = e.model.last();
    assert_eq!(images(&req), 0, "a text-only model must not get image parts");
    let text: String = req.messages.iter().flat_map(|m| m.content.iter()).filter_map(|b| match b { Block::Text { text } => Some(text.clone()), _ => None }).collect::<Vec<_>>().join("\n");
    assert!(text.contains("attached an image"), "{text}");
    // The transcript keeps the picture: only the request copy is degraded.
    let evs = e.k.store.read(&id).unwrap();
    assert!(evs.iter().any(|ev| matches!(&ev.kind, ark_kernel::event::EventKind::Message { message, .. } if message.content.iter().any(|b| matches!(b, Block::Image { .. })))));
}

#[test]
fn a_vision_model_still_gets_the_picture() {
    let e = env(true);
    let id = e.k.create_session(&e.ws, None, None, None).unwrap();
    let upload = Block::Image { media_type: "image/png".into(), data: ark_core::tool::base64_encode(&png(64, 64)) };
    e.k.submit_with(&id, "what is this?", vec![upload.clone()], "cli").unwrap();
    assert!(e.k.run(&id, RunOpts::default()).unwrap().reason.ok());
    let req = e.model.last();
    assert!(req.messages.iter().any(|m| m.content.contains(&upload)), "the user's picture reaches a vision model unchanged");
    assert!(!req.messages.iter().flat_map(|m| m.content.iter()).any(|b| matches!(b, Block::Text { text } if text.contains("attached an image"))), "no stand-ins for a vision model");
}

#[test]
fn tool_result_images_are_retired_once_the_request_crosses_the_strict_ceiling() {
    // 2400 px wide: over Anthropic's 2000 px many-image cap, so the strict 20-image ceiling is
    // live. Every turn reads the same oversized picture, one carrier per turn.
    let e = env(true);
    let id = e.k.create_session(&e.ws, None, None, None).unwrap();
    for i in 0..21 {
        run_turn(&e, &id, &format!("look {i}"));
    }
    assert_eq!(e.reads.load(Ordering::SeqCst), 21);
    let req = e.model.last();
    let retired = req.messages.iter().flat_map(|m| m.content.iter()).filter(|b| matches!(b, Block::Text { text } if text == imgprep::RETIRED_PLACEHOLDER)).count();
    assert_eq!(retired, 8, "one batch of the OLDEST carriers, not the exact overshoot");
    assert_eq!(images(&req), 13, "the newest 13 carriers keep their images");
    // The oldest tool result keeps its text; only the image block is rewritten.
    let oldest = req.messages.iter().find(|m| m.content.iter().any(|b| matches!(b, Block::ToolResult { .. }))).expect("a carrier");
    assert!(oldest.content.iter().any(|b| matches!(b, Block::ToolResult { content, .. } if content.contains("pic.png"))));
    assert!(oldest.content.iter().any(|b| matches!(b, Block::Text { text } if text == imgprep::RETIRED_PLACEHOLDER)));
    // Small pictures stay under the many-image cap: the hard ceiling applies, nothing is retired.
    let small = env(true);
    std::fs::write(small.ws.join("pic.png"), png(800, 600)).unwrap();
    let sid = small.k.create_session(&small.ws, None, None, None).unwrap();
    for i in 0..21 {
        run_turn(&small, &sid, &format!("look {i}"));
    }
    assert_eq!(images(&small.model.last()), 21, "within the many-image cap the hard limit is 100");
}
