//! The main-daemon side: the helper client and the guest's slot commands.

use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use bulge_proto::msg::Outcome;
use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use crate::runtime::{HandlerError, InvocationContext};
use super::{CTL_DIR, HelperReply, HelperRequest, SlotError, SlotRequest, parse_helper_response, parse_slot_response, validate_rel_path, validate_slot, validate_stage_slots};

pub(crate) static HELPER: std::sync::OnceLock<Arc<HelperClient>> = std::sync::OnceLock::new();

pub struct HelperClient {
    pub(crate) inner: Mutex<HelperInner>,
}

pub(crate) struct HelperInner {
    pub(crate) child: Child,
    pub(crate) stdin: ChildStdin,
    pub(crate) stdout: BufReader<ChildStdout>,
    pub(crate) next_id: u64,
}

impl HelperClient {
    /// Spawn `/proc/self/exe --slot-helper`. Must be called as root, after
    /// `lock_down` and before `drop_privileges`.
    pub fn spawn(base_uid: u32, base_gid: u32, egress_proxy: Option<&str>) -> io::Result<Self> {
        let mut command = Command::new("/proc/self/exe");
        command
            .arg("--slot-helper")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .env("BULGE_BASE_UID", base_uid.to_string())
            .env("BULGE_BASE_GID", base_gid.to_string());
        if let Some(proxy) = egress_proxy {
            command.env("BULGE_EGRESS_PROXY", proxy);
        }
        let mut child = command.spawn()?;
        let stdin = child.stdin.take().ok_or_else(|| io::Error::other("helper has no stdin"))?;
        let stdout = child.stdout.take().ok_or_else(|| io::Error::other("helper has no stdout"))?;
        Ok(Self {
            inner: Mutex::new(HelperInner {
                child,
                stdin,
                stdout: BufReader::new(stdout),
                next_id: 1,
            }),
        })
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, HelperInner> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn call(&self, op: &str, slot: u8, from: u8, paths: Vec<String>) -> Result<Value, SlotError> {
        let mut inner = self.lock();
        let id = inner.next_id;
        inner.next_id += 1;
        let request = HelperRequest {
            id,
            op: op.to_owned(),
            slot,
            from,
            paths,
        };
        let mut line = serde_json::to_string(&request).map_err(SlotError::failed)?;
        line.push('\n');
        inner.stdin.write_all(line.as_bytes()).map_err(|e| SlotError::new("SLOT_UNAVAILABLE", e.to_string()))?;
        inner.stdin.flush().map_err(|e| SlotError::new("SLOT_UNAVAILABLE", e.to_string()))?;

        let mut response = String::new();
        let read = inner
            .stdout
            .read_line(&mut response)
            .map_err(|e| SlotError::new("SLOT_UNAVAILABLE", e.to_string()))?;
        if read == 0 {
            return Err(SlotError::new("SLOT_UNAVAILABLE", "slot helper exited"));
        }
        match parse_helper_response(&response).map_err(SlotError::failed)? {
            HelperReply::Ok { id: reply_id, value } if reply_id == id => Ok(value),
            HelperReply::Ok { id: reply_id, .. } => Err(SlotError::failed(format!("helper reply id {reply_id}, expected {id}"))),
            HelperReply::Err { id: reply_id, code, message } if reply_id == id || reply_id == 0 => Err(SlotError::new(code, message)),
            HelperReply::Err { id: reply_id, .. } => Err(SlotError::failed(format!("helper error id {reply_id}, expected {id}"))),
        }
    }

    pub fn open(&self, slot: u8) -> Result<Value, SlotError> {
        self.call("open", slot, 0, Vec::new())
    }

    pub fn changes(&self, slot: u8) -> Result<Value, SlotError> {
        self.call("changes", slot, 0, Vec::new())
    }

    pub fn export(&self, slot: u8, paths: Vec<String>) -> Result<Value, SlotError> {
        self.call("export", slot, 0, paths)
    }

    pub fn merge(&self, slot: u8, paths: Vec<String>) -> Result<Value, SlotError> {
        self.call("merge", slot, 0, paths)
    }

    pub fn stage(&self, slot: u8, from: u8, paths: Vec<String>) -> Result<Value, SlotError> {
        self.call("stage", slot, from, paths)
    }

    pub fn close(&self, slot: u8) -> Result<Value, SlotError> {
        self.call("close", slot, 0, Vec::new())
    }
}

impl Drop for HelperInner {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn install_helper(client: HelperClient) -> Result<(), String> {
    HELPER
        .set(Arc::new(client))
        .map_err(|_| "slot helper already installed".to_owned())
}

pub(crate) fn helper() -> Result<Arc<HelperClient>, HandlerError> {
    HELPER
        .get()
        .cloned()
        .ok_or_else(|| HandlerError::new("SLOT_UNAVAILABLE", "slot helper is not running"))
}

pub(crate) fn map_slot_error(error: SlotError) -> HandlerError {
    let code = match error.code.as_str() {
        "INVALID_PARAMS" | "SLOT_UNAVAILABLE" | "SLOT_FAILED" | "CONFLICT" => error.code,
        _ => "SLOT_FAILED".to_owned(),
    };
    HandlerError::new(code, error.message)
}

pub(crate) fn bad_params(error: impl std::fmt::Display) -> HandlerError {
    HandlerError::new("INVALID_PARAMS", error.to_string())
}

pub(crate) async fn block_on_helper<F>(call: F) -> Result<Value, HandlerError>
where
    F: FnOnce(&HelperClient) -> Result<Value, SlotError> + Send + 'static,
{
    let client = helper()?;
    tokio::task::spawn_blocking(move || call(&client))
        .await
        .map_err(|e| HandlerError::new("SLOT_FAILED", e.to_string()))?
        .map_err(map_slot_error)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SlotParams {
    pub(crate) slot: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SlotPathsParams {
    pub(crate) slot: u8,
    pub(crate) paths: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SlotStageParams {
    pub(crate) slot: u8,
    pub(crate) from: u8,
    pub(crate) paths: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SlotRunParams {
    pub(crate) slot: u8,
    pub(crate) command: String,
    #[serde(default)]
    pub(crate) params: Value,
    #[serde(default)]
    pub(crate) timeout_ms: Option<u64>,
}

pub(crate) fn valid_paths(paths: &[String]) -> Result<Vec<String>, HandlerError> {
    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        out.push(validate_rel_path(path).map_err(bad_params)?.to_string_lossy().into_owned());
    }
    Ok(out)
}

pub async fn slot_open(cx: InvocationContext) -> Result<Value, HandlerError> {
    let params: SlotParams = serde_json::from_value(cx.invocation.params.clone()).map_err(bad_params)?;
    let slot = validate_slot(params.slot).map_err(bad_params)?;
    block_on_helper(move |client| client.open(slot)).await
}

pub async fn slot_changes(cx: InvocationContext) -> Result<Value, HandlerError> {
    let params: SlotParams = serde_json::from_value(cx.invocation.params.clone()).map_err(bad_params)?;
    let slot = validate_slot(params.slot).map_err(bad_params)?;
    block_on_helper(move |client| client.changes(slot)).await
}

pub async fn slot_export(cx: InvocationContext) -> Result<Value, HandlerError> {
    let params: SlotPathsParams = serde_json::from_value(cx.invocation.params.clone()).map_err(bad_params)?;
    let slot = validate_slot(params.slot).map_err(bad_params)?;
    let paths = valid_paths(&params.paths)?;
    block_on_helper(move |client| client.export(slot, paths)).await
}

pub async fn slot_merge(cx: InvocationContext) -> Result<Value, HandlerError> {
    let params: SlotPathsParams = serde_json::from_value(cx.invocation.params.clone()).map_err(bad_params)?;
    let slot = validate_slot(params.slot).map_err(bad_params)?;
    let paths = valid_paths(&params.paths)?;
    block_on_helper(move |client| client.merge(slot, paths)).await
}

pub async fn slot_stage(cx: InvocationContext) -> Result<Value, HandlerError> {
    let params: SlotStageParams = serde_json::from_value(cx.invocation.params.clone()).map_err(bad_params)?;
    let (slot, from) = validate_stage_slots(params.slot, params.from).map_err(bad_params)?;
    let paths = valid_paths(&params.paths)?;
    block_on_helper(move |client| client.stage(slot, from, paths)).await
}

pub async fn slot_close(cx: InvocationContext) -> Result<Value, HandlerError> {
    let params: SlotParams = serde_json::from_value(cx.invocation.params.clone()).map_err(bad_params)?;
    let slot = validate_slot(params.slot).map_err(bad_params)?;
    block_on_helper(move |client| client.close(slot)).await
}

pub async fn slot_run(cx: InvocationContext) -> Result<Value, HandlerError> {
    let params: SlotRunParams = serde_json::from_value(cx.invocation.params.clone()).map_err(bad_params)?;
    let slot = validate_slot(params.slot).map_err(bad_params)?;
    let socket = Path::new(CTL_DIR).join(format!("slot{slot}.sock"));
    if !socket.exists() {
        return Err(HandlerError::new("SLOT_UNAVAILABLE", format!("slot {slot} is not open")));
    }
    let stream = tokio::net::UnixStream::connect(&socket)
        .await
        .map_err(|e| HandlerError::new("SLOT_UNAVAILABLE", e.to_string()))?;
    let (read_half, mut write_half) = stream.into_split();
    let request = SlotRequest {
        id: cx.invocation.id,
        command: params.command,
        params: params.params,
        timeout_ms: params.timeout_ms,
    };
    let mut line = serde_json::to_string(&request).map_err(bad_params)?;
    line.push('\n');
    write_half
        .write_all(line.as_bytes())
        .await
        .map_err(|e| HandlerError::new("SLOT_UNAVAILABLE", e.to_string()))?;
    write_half
        .flush()
        .await
        .map_err(|e| HandlerError::new("SLOT_UNAVAILABLE", e.to_string()))?;

    let mut reader = TokioBufReader::new(read_half);
    // The slot server enforces `timeout_ms` itself; leave a little room for its
    // structured HANDLER_TIMEOUT reply to travel back before we give up.
    let deadline = params.timeout_ms.map(|ms| Duration::from_millis(ms.saturating_add(1_000)));
    let read_response = async {
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                return Err(io::Error::other("slot server closed the connection"));
            }
            let response = parse_slot_response(&line).map_err(io::Error::other)?;
            if response.id == request.id {
                return Ok(response.outcome);
            }
        }
    };
    let outcome = if let Some(deadline) = deadline {
        tokio::select! {
            result = read_response => result.map_err(|e| HandlerError::new("SLOT_FAILED", e.to_string()))?,
            () = cx.cancellation.cancelled() => return Err(HandlerError::new("CANCELLED", "slot command cancelled")),
            () = tokio::time::sleep(deadline) => return Err(HandlerError::new("SLOT_FAILED", "slot command timed out")),
        }
    } else {
        tokio::select! {
            result = read_response => result.map_err(|e| HandlerError::new("SLOT_FAILED", e.to_string()))?,
            () = cx.cancellation.cancelled() => return Err(HandlerError::new("CANCELLED", "slot command cancelled")),
        }
    };
    match outcome {
        Outcome::Ok { value } => Ok(value),
        Outcome::Err { code, message } => Err(HandlerError::new(code, message)),
    }
}
