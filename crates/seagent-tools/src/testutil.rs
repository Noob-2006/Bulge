use seagent_core::tool::SpawnRequest;
use seagent_core::{Cancel, ToolCtx, ToolHost};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// A scratch dir for one test: `seagent-tools-<tag>-*`, removed when the test's thread ends
/// (`seagent_core::tmp::scratch`), so the suite no longer leaves a tree behind per call.
pub fn tmpdir(tag: &str) -> PathBuf {
    seagent_core::tmp::scratch(&format!("seagent-tools-{tag}"))
}

#[derive(Default)]
pub struct FakeHost {
    pub spawned: Mutex<Vec<SpawnRequest>>,
    pub fail: bool,
}

impl ToolHost for FakeHost {
    fn spawn_agent(&self, req: SpawnRequest, _c: &Cancel) -> Result<String, String> {
        let task = req.task.clone();
        self.spawned.lock().unwrap().push(req);
        if self.fail {
            Err("child agent exceeded budget".into())
        } else {
            Ok(format!("done: {task}"))
        }
    }
    fn ask_user(&self, q: &str) -> Result<String, String> {
        if self.fail {
            Err("no human attached (headless)".into())
        } else {
            Ok(format!("answer to {q}"))
        }
    }
}

pub fn ctx_with(ws: PathBuf, host: Arc<dyn ToolHost>) -> ToolCtx {
    // Unique per context: file-tool read tracking is keyed by session.
    let session_id = format!("s-{}", ws.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
    ToolCtx {
        artifacts: ws.join(".artifacts"),
        home: ws.join(".home"),
        workspace: ws,
        session_id,
        cancel: Cancel::new(),
        host,
        secrets: Arc::new(|s: &str| s.replace("{{secret:TOKEN}}", "s3cr3t")),
    }
}

pub fn ctx(tag: &str) -> ToolCtx {
    ctx_with(tmpdir(tag), Arc::new(FakeHost::default()))
}
