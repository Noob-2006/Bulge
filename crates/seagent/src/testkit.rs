//! Test helpers: a kernel over a temp SEAGENT_HOME layout and an echoing provider.

use seagent_core::*;
use seagent_kernel::approver::Policy;
use seagent_kernel::config::{Config, Paths};
use seagent_kernel::kernel::{new_kernel, Kernel, Resolver};
use seagent_kernel::vault::Vault;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Replies `reply: <last user text>`; records every request.
pub struct Echo {
    pub seen: Mutex<Vec<ModelRequest>>,
}

impl Provider for Echo {
    fn id(&self) -> &str {
        "echo"
    }
    fn caps(&self, _: &str) -> ModelCaps {
        ModelCaps { context_window: 100_000, max_output: 4096, tools: true, vision: true, explicit_cache: false }
    }
    fn complete(&self, req: &ModelRequest, on: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, ProviderError> {
        self.seen.lock().unwrap().push(req.clone());
        let last = req.messages.last().map(|m| m.text()).unwrap_or_default();
        let text = format!("reply: {}", last.chars().take(200).collect::<String>());
        on(StreamEvent::TextDelta(text.clone()));
        Ok(ModelResponse { message: Message::assistant(text), stop: StopReason::EndTurn, usage: Usage { input_tokens: 50, output_tokens: 10, ..Default::default() }, model: "echo/m".into() })
    }
}

struct Res(Arc<Echo>);
impl Resolver for Res {
    fn provider(&self, _: &str) -> Result<Arc<dyn Provider>, String> {
        Ok(self.0.clone())
    }
}

pub struct Kit {
    pub k: Kernel,
    pub ws: PathBuf,
    pub paths: Paths,
    pub echo: Arc<Echo>,
}

/// Process environment (`SEAGENT_HOME`, `SEAGENT_PROFILE`, `XDG_*`) is global: every test that
/// changes it must hold this lock, or parallel tests read each other's home.
pub static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Lock [`ENV`] (poison-tolerant: a panicking test must not wedge the rest).
pub fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn kit() -> Kit {
    kit_with(|_| {})
}

pub fn kit_with(f: impl FnOnce(&mut Config)) -> Kit {
    // Removed when the test's thread ends (seagent_core::tmp::scratch): `kit()` hands back plain
    // paths, so the whole tree (ws/data/config/run) used to stay behind in $TMPDIR.
    let root = seagent_core::tmp::scratch("seagent-kit");
    let ws = root.join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let paths = Paths { data: root.join("data"), config_dir: root.join("config"), runtime: root.join("run"), ..Default::default() };
    std::fs::create_dir_all(&paths.config_dir).unwrap();
    let mut cfg = Config::default();
    cfg.model.default = "echo/m".into();
    cfg.checkpoint.enabled = false;
    f(&mut cfg);
    let echo = Arc::new(Echo { seen: Mutex::new(vec![]) });
    let k = new_kernel(cfg, paths.clone(), Arc::new(Res(echo.clone())), seagent_tools::builtin_tools(), Arc::new(Vault::empty()), Arc::new(Policy { allow_privilege: false, allow_egress: false }));
    // As the kernel stores session workspaces (`layout::canonicalize`: no `\\?\` on Windows).
    Kit { k, ws: seagent_core::platform::layout::canonicalize(&ws).unwrap(), paths, echo }
}
