use ark_core::tool::SpawnRequest;
use ark_core::{Cancel, ToolCtx, ToolHost};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

static SEQ: AtomicU64 = AtomicU64::new(0);

pub fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "ark-tools-{tag}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
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
    ToolCtx {
        artifacts: ws.join(".artifacts"),
        home: ws.join(".home"),
        workspace: ws,
        session_id: "s-test".into(),
        cancel: Cancel::new(),
        host,
        secrets: Arc::new(|s: &str| s.replace("{{secret:TOKEN}}", "s3cr3t")),
    }
}

pub fn ctx(tag: &str) -> ToolCtx {
    ctx_with(tmpdir(tag), Arc::new(FakeHost::default()))
}
