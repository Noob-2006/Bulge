//! Per-agent workspace slots.
//!
//! A slot is a private copy-on-write view of the main workspace: an overlay
//! whose lower layers are a snapshot of the main upper dir plus the read-only
//! host share, its own uid, mount namespace, home and `/tmp`. Everything that
//! needs root is done by the privileged `--slot-helper` process (started before
//! `sandboxd` drops privileges); tools inside a slot are served by a
//! `--slot-server` process that is this same binary re-executed inside the
//! slot's namespace as the slot uid.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io::{self, BufRead, BufReader, Write};
use std::os::fd::FromRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use base64::Engine;
use bulge_proto::msg::Outcome;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};

use crate::commands::{BaseEntry, walk_changes};
use crate::runtime::{CommandRuntime, HandlerError, Invocation, InvocationContext};
use crate::setup::{AGENT_HOME, WORKSPACE, WORKSPACE_LOWER, WORKSPACE_UPPER};

/// Matches `bulge-cli`'s `MAX_CONCURRENT_SUBAGENTS`.
pub const MAX_SLOTS: u8 = 8;
/// Root-owned 0700: `<n>/{snap,upper,work,merged,home,tmp}`.
pub const SLOTS_ROOT: &str = "/run/bulge/slots";
/// Owned by the base uid, 0700: `slot<n>.sock`.
pub const CTL_DIR: &str = "/run/bulge/ctl";
/// PATH for slot processes (the environment is cleared before exec).
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

pub fn validate_slot(slot: u8) -> Result<u8, String> {
    if slot < MAX_SLOTS {
        Ok(slot)
    } else {
        Err(format!("slot {slot} is out of range (must be < {MAX_SLOTS})"))
    }
}

/// Validate the two slots of a staging copy: both must be valid and distinct.
pub fn validate_stage_slots(slot: u8, from: u8) -> Result<(u8, u8), String> {
    let slot = validate_slot(slot)?;
    let from = validate_slot(from)?;
    if slot == from {
        return Err("stage source and destination must be different slots".into());
    }
    Ok((slot, from))
}

/// Validate a workspace-relative path used for export/merge. Returns the
/// normalised relative path.
pub fn validate_rel_path(path: &str) -> Result<PathBuf, String> {
    if path.is_empty() {
        return Err("path is empty".into());
    }
    if path.as_bytes().contains(&0) {
        return Err("path contains NUL".into());
    }
    let raw = Path::new(path);
    if raw.is_absolute() {
        return Err(format!("path must be relative: {path}"));
    }
    let mut normal = PathBuf::new();
    for component in raw.components() {
        match component {
            Component::Normal(part) => {
                if part.as_encoded_bytes().starts_with(b".overlay") {
                    return Err(format!("reserved overlay path component in {path}"));
                }
                normal.push(part);
            }
            Component::CurDir => return Err(format!("path must not contain '.' components: {path}")),
            Component::ParentDir => return Err(format!("path must not contain '..' components: {path}")),
            Component::RootDir | Component::Prefix(_) => return Err(format!("path must be relative: {path}")),
        }
    }
    if normal.as_os_str().is_empty() {
        return Err(format!("path does not name a file: {path}"));
    }
    Ok(normal)
}

// ---------------------------------------------------------------------------
// Slot paths
// ---------------------------------------------------------------------------

struct SlotPaths {
    root: PathBuf,
    snap: PathBuf,
    upper: PathBuf,
    work: PathBuf,
    merged: PathBuf,
    home: PathBuf,
    tmp: PathBuf,
    socket: PathBuf,
}

impl SlotPaths {
    fn new(slot: u8) -> Self {
        let root = Path::new(SLOTS_ROOT).join(slot.to_string());
        Self {
            snap: root.join("snap"),
            upper: root.join("upper"),
            work: root.join("work"),
            merged: root.join("merged"),
            home: root.join("home"),
            tmp: root.join("tmp"),
            socket: Path::new(CTL_DIR).join(format!("slot{slot}.sock")),
            root,
        }
    }

    fn prepare(&self, uid: u32, gid: u32) -> Result<(), SlotError> {
        std::fs::create_dir_all(SLOTS_ROOT).map_err(SlotError::failed)?;
        std::fs::set_permissions(SLOTS_ROOT, std::fs::Permissions::from_mode(0o700)).map_err(SlotError::failed)?;
        for dir in [&self.root, &self.snap, &self.upper, &self.work, &self.merged, &self.home, &self.tmp] {
            std::fs::create_dir_all(dir).map_err(SlotError::failed)?;
        }
        set_mode(&self.root, 0o700)?;
        set_mode(&self.snap, 0o755)?;
        set_mode(&self.upper, 0o700)?;
        set_mode(&self.work, 0o700)?;
        set_mode(&self.merged, 0o755)?;
        set_mode(&self.home, 0o700)?;
        set_mode(&self.tmp, 0o1777)?;
        for dir in [&self.upper, &self.home, &self.tmp] {
            std::os::unix::fs::chown(dir, Some(uid), Some(gid)).map_err(SlotError::failed)?;
        }
        Ok(())
    }
}

fn set_mode(path: &Path, mode: u32) -> Result<(), SlotError> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(SlotError::failed)
}

fn chown_path(path: &Path, uid: u32, gid: u32) -> Result<(), SlotError> {
    std::os::unix::fs::chown(path, Some(uid), Some(gid)).map_err(SlotError::failed)
}

fn cstring(path: &Path) -> Result<CString, SlotError> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes()).map_err(|_| SlotError::invalid(format!("path contains NUL: {}", path.display())))
}

// ---------------------------------------------------------------------------
// Errors and protocol
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotError {
    pub code: String,
    pub message: String,
}

impl SlotError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    fn invalid(message: impl std::fmt::Display) -> Self {
        Self::new("INVALID_PARAMS", message.to_string())
    }

    fn failed(error: impl std::fmt::Display) -> Self {
        Self::new("SLOT_FAILED", error.to_string())
    }
}

impl std::fmt::Display for SlotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for SlotError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperRequest {
    pub id: u64,
    pub op: String,
    pub slot: u8,
    /// Source slot for `stage`; ignored (and zero) for every other operation.
    #[serde(default)]
    pub from: u8,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperReply {
    Ok { id: u64, value: Value },
    Err { id: u64, code: String, message: String },
}

#[derive(Debug, Deserialize)]
struct HelperErrorBody {
    code: String,
    message: String,
}

pub fn parse_helper_request(line: &str) -> Result<HelperRequest, String> {
    serde_json::from_str(line).map_err(|e| e.to_string())
}

pub fn parse_helper_response(line: &str) -> Result<HelperReply, String> {
    let mut raw: Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
    let object = raw
        .as_object_mut()
        .ok_or_else(|| "helper reply is not an object".to_owned())?;
    let id = object
        .get("id")
        .and_then(Value::as_u64)
        .ok_or_else(|| "helper reply has no id".to_owned())?;
    let ok = object.remove("ok");
    let err = object.remove("err");
    // Only `id` may remain once the two mutually exclusive payloads are gone.
    let clean = object.len() == 1;
    match (clean, ok, err) {
        (true, Some(value), None) => Ok(HelperReply::Ok { id, value }),
        (true, None, Some(err)) => {
            let err: HelperErrorBody = serde_json::from_value(err).map_err(|e| e.to_string())?;
            Ok(HelperReply::Err {
                id,
                code: err.code,
                message: err.message,
            })
        }
        _ => Err("helper reply must contain exactly one of ok/err".into()),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotRequest {
    pub id: u64,
    pub command: String,
    #[serde(default)]
    pub params: Value,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotResponse {
    pub id: u64,
    pub outcome: Outcome,
}

pub fn parse_slot_request(line: &str) -> Result<SlotRequest, String> {
    serde_json::from_str(line).map_err(|e| e.to_string())
}

fn parse_slot_response(line: &str) -> Result<SlotResponse, String> {
    serde_json::from_str(line).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Main-daemon side: helper client and guest commands
// ---------------------------------------------------------------------------

static HELPER: std::sync::OnceLock<Arc<HelperClient>> = std::sync::OnceLock::new();

pub struct HelperClient {
    inner: Mutex<HelperInner>,
}

struct HelperInner {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
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

    fn lock(&self) -> MutexGuard<'_, HelperInner> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn call(&self, op: &str, slot: u8, from: u8, paths: Vec<String>) -> Result<Value, SlotError> {
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

fn helper() -> Result<Arc<HelperClient>, HandlerError> {
    HELPER
        .get()
        .cloned()
        .ok_or_else(|| HandlerError::new("SLOT_UNAVAILABLE", "slot helper is not running"))
}

fn map_slot_error(error: SlotError) -> HandlerError {
    let code = match error.code.as_str() {
        "INVALID_PARAMS" | "SLOT_UNAVAILABLE" | "SLOT_FAILED" | "CONFLICT" => error.code,
        _ => "SLOT_FAILED".to_owned(),
    };
    HandlerError::new(code, error.message)
}

fn bad_params(error: impl std::fmt::Display) -> HandlerError {
    HandlerError::new("INVALID_PARAMS", error.to_string())
}

async fn block_on_helper<F>(call: F) -> Result<Value, HandlerError>
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
struct SlotParams {
    slot: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SlotPathsParams {
    slot: u8,
    paths: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SlotStageParams {
    slot: u8,
    from: u8,
    paths: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SlotRunParams {
    slot: u8,
    command: String,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

fn valid_paths(paths: &[String]) -> Result<Vec<String>, HandlerError> {
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

// ---------------------------------------------------------------------------
// Privileged helper
// ---------------------------------------------------------------------------

struct HelperConfig {
    base_uid: u32,
    base_gid: u32,
    egress_proxy: Option<String>,
}

impl HelperConfig {
    fn from_env() -> Result<Self, SlotError> {
        let base_uid = env_id("BULGE_BASE_UID")?;
        let base_gid = env_id("BULGE_BASE_GID")?;
        Ok(Self {
            base_uid,
            base_gid,
            egress_proxy: std::env::var("BULGE_EGRESS_PROXY").ok().filter(|value| !value.is_empty()),
        })
    }
}

fn env_id(name: &str) -> Result<u32, SlotError> {
    std::env::var(name)
        .map_err(|_| SlotError::failed(format!("{name} is not set")))?
        .parse::<u32>()
        .map_err(|e| SlotError::failed(format!("{name}: {e}")))
}

struct OpenSlot {
    child: Child,
}

struct HelperState {
    config: HelperConfig,
    open: HashMap<u8, OpenSlot>,
}

impl HelperState {
    fn new(config: HelperConfig) -> Self {
        Self {
            config,
            open: HashMap::new(),
        }
    }

    fn handle(&mut self, request: HelperRequest) -> Result<Value, SlotError> {
        let slot = validate_slot(request.slot).map_err(SlotError::invalid)?;
        match request.op.as_str() {
            "open" => self.open(slot),
            "changes" => self.changes(slot),
            "export" => {
                let paths = self.validate_paths(&request.paths)?;
                self.export(slot, &paths)
            }
            "merge" => {
                let paths = self.validate_paths(&request.paths)?;
                self.merge(slot, &paths)
            }
            "stage" => {
                let (slot, from) = validate_stage_slots(request.slot, request.from).map_err(SlotError::invalid)?;
                let paths = self.validate_paths(&request.paths)?;
                self.stage(slot, from, &paths)
            }
            "close" => {
                self.close(slot)?;
                Ok(json!({ "slot": slot, "closed": true }))
            }
            other => Err(SlotError::invalid(format!("unknown slot helper operation: {other}"))),
        }
    }

    fn validate_paths(&self, paths: &[String]) -> Result<Vec<PathBuf>, SlotError> {
        paths.iter().map(|path| validate_rel_path(path).map_err(SlotError::invalid)).collect()
    }

    fn require_open(&self, slot: u8) -> Result<&OpenSlot, SlotError> {
        self.open
            .get(&slot)
            .ok_or_else(|| SlotError::new("SLOT_UNAVAILABLE", format!("slot {slot} is not open")))
    }

    fn open(&mut self, slot: u8) -> Result<Value, SlotError> {
        if self.open.contains_key(&slot) {
            self.close(slot)?;
        }
        let paths = SlotPaths::new(slot);
        // Slots run as the workspace owner so they can edit existing files (the
        // host share is owned by it); isolation comes from the slot's own mount,
        // PID and IPC namespaces, not from a different uid.
        let (uid, gid) = (self.config.base_uid, self.config.base_gid);
        let result = (|| -> Result<Child, SlotError> {
            paths.prepare(uid, gid)?;
            snapshot(&paths)?;
            mount_overlay(&paths)?;
            chown_path(&paths.merged, uid, gid)?;
            let listener = bind_control_socket(&paths, self.config.base_uid, self.config.base_gid)?;
            let child = spawn_server(slot, &paths, &self.config, uid, gid, &listener)?;
            drop(listener);
            Ok(child)
        })();
        match result {
            Ok(child) => {
                self.open.insert(slot, OpenSlot { child });
                Ok(json!({ "slot": slot, "uid": uid }))
            }
            Err(error) => {
                let _ = cleanup_slot(&paths);
                Err(error)
            }
        }
    }

    /// A process inside the slot's namespaces (the server's namespace holder),
    /// used to enter its mount namespace.
    fn namespace_pid(&self, slot: u8) -> Result<i32, SlotError> {
        self.open
            .get(&slot)
            .map(|open| open.child.id() as i32)
            .ok_or_else(|| SlotError::new("SLOT_UNAVAILABLE", format!("slot {slot} is not open")))
    }

    fn stage(&self, slot: u8, from: u8, paths_in: &[PathBuf]) -> Result<Value, SlotError> {
        self.require_open(slot)?;
        self.require_open(from)?;
        // SOURCE: read exactly like merge reads the slot side, inside the source
        // slot's mount namespace as the unprivileged owner, with symlink parents
        // refused.
        let rels = paths_in.to_vec();
        let ns = self.namespace_pid(from)?;
        let entries: Vec<(PathBuf, Option<Entry>)> = run_as(Some(ns), self.config.base_uid, self.config.base_gid, move || {
            let root = Path::new(WORKSPACE);
            rels.iter()
                .map(|rel| {
                    ensure_no_symlink_parents(root, rel).map_err(SlotError::failed)?;
                    Ok((rel.clone(), read_entry_opt(Some(&root.join(rel)))?))
                })
                .collect()
        })?;
        // DESTINATION: apply the source versions in the staging slot's namespace.
        // The staging slot was opened from the same main state, so there is no
        // conflict check: the worker's version simply wins.
        let rels = paths_in.to_vec();
        let ns = self.namespace_pid(slot)?;
        let (base_uid, base_gid) = (self.config.base_uid, self.config.base_gid);
        run_as(Some(ns), base_uid, base_gid, move || {
            let root = Path::new(WORKSPACE);
            for (rel, entry) in &entries {
                apply_entry(root, rel, entry.as_ref(), base_uid, base_gid).map_err(SlotError::failed)?;
            }
            let staged: Vec<String> = rels.iter().map(|rel| rel.to_string_lossy().into_owned()).collect();
            Ok(json!({ "staged": staged }))
        })
    }

    fn close(&mut self, slot: u8) -> Result<(), SlotError> {
        let paths = SlotPaths::new(slot);
        if let Some(mut open) = self.open.remove(&slot) {
            let pgid = open.child.id() as i32;
            let _ = nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pgid), nix::sys::signal::Signal::SIGKILL);
            let _ = open.child.wait();
        }
        cleanup_slot(&paths)
    }

    fn changes(&self, slot: u8) -> Result<Value, SlotError> {
        self.require_open(slot)?;
        let paths = SlotPaths::new(slot);
        let base = |rel: &Path| slot_base_entry(&paths.snap, Path::new(WORKSPACE_LOWER), rel, &is_overlay_whiteout);
        let mut out = walk_changes(&paths.upper, &base).map_err(SlotError::failed)?;
        out.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
        Ok(json!({ "changes": out }))
    }

    fn export(&self, slot: u8, paths_in: &[PathBuf]) -> Result<Value, SlotError> {
        self.require_open(slot)?;
        let paths = SlotPaths::new(slot);
        // Which paths existed in the base is decided here (root-only snapshot,
        // static while the slot is open); the slot's own files are read as the
        // slot's uid, so a symlink the agent planted can only reach what the
        // agent itself could read.
        let existed: Vec<bool> = paths_in.iter().map(|rel| base_entry_checked(&paths.snap, rel).exists()).collect();
        let rels = paths_in.to_vec();
        let ns = self.namespace_pid(slot)?;
        run_as(Some(ns), self.config.base_uid, self.config.base_gid, move || {
            let lookup: std::collections::HashMap<&Path, bool> = rels.iter().map(PathBuf::as_path).zip(existed.iter().copied()).collect();
            export_from(Path::new(WORKSPACE), &rels, &|rel| lookup.get(rel).copied().unwrap_or(false))
        })
    }

    fn merge(&self, slot: u8, paths_in: &[PathBuf]) -> Result<Value, SlotError> {
        self.require_open(slot)?;
        let paths = SlotPaths::new(slot);
        // BASE: the root-only snapshot over the read-only host share; static while
        // the slot is open, and symlink parents are refused.
        let mut bases = Vec::with_capacity(paths_in.len());
        for rel in paths_in {
            bases.push(read_entry_opt(base_entry_checked(&paths.snap, rel).path())?);
        }
        // SLOT: read inside the slot's own mount namespace as the unprivileged
        // owner (never root), with symlink parents refused.
        let rels = paths_in.to_vec();
        let ns = self.namespace_pid(slot)?;
        let slots: Vec<Option<Entry>> = run_as(Some(ns), self.config.base_uid, self.config.base_gid, move || {
            let root = Path::new(WORKSPACE);
            rels.iter()
                .map(|rel| {
                    ensure_no_symlink_parents(root, rel).map_err(SlotError::failed)?;
                    read_entry_opt(Some(&root.join(rel)))
                })
                .collect()
        })?;
        // MAIN: read, decide and apply as the main workspace's owner, so a symlink
        // swapped in by anything else in the guest can never redirect a write
        // beyond what that owner may already touch.
        let rels = paths_in.to_vec();
        let (base_uid, base_gid) = (self.config.base_uid, self.config.base_gid);
        run_as(None, base_uid, base_gid, move || {
            let root = Path::new(WORKSPACE);
            let mut merged = Vec::new();
            let mut conflicts = Vec::new();
            for ((rel, base), slot_entry) in rels.iter().zip(bases.iter()).zip(slots.iter()) {
                let display = rel.to_string_lossy().into_owned();
                if let Err(error) = ensure_no_symlink_parents(root, rel) {
                    conflicts.push(json!({ "path": display, "reason": error.to_string() }));
                    continue;
                }
                let main_entry = read_entry_opt(Some(&root.join(rel)))?;
                match merge_decision(base.as_ref(), slot_entry.as_ref(), main_entry.as_ref()) {
                    Decision::Nothing => {}
                    Decision::Conflict(reason) => conflicts.push(json!({ "path": display, "reason": reason })),
                    Decision::Apply => {
                        apply_entry(root, rel, slot_entry.as_ref(), base_uid, base_gid).map_err(SlotError::failed)?;
                        merged.push(display);
                    }
                }
            }
            Ok(json!({ "merged": merged, "conflicts": conflicts }))
        })
    }
}

pub fn helper_main() -> Result<(), String> {
    helper_run().map_err(|error| error.to_string())
}

fn helper_run() -> Result<(), SlotError> {
    let config = HelperConfig::from_env()?;
    let mut state = HelperState::new(config);
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    loop {
        let mut line = String::new();
        let read = input.read_line(&mut line).map_err(SlotError::failed)?;
        if read == 0 {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let response = match parse_helper_request(line) {
            Ok(request) => {
                let id = request.id;
                match state.handle(request) {
                    Ok(value) => HelperReply::Ok { id, value },
                    Err(error) => HelperReply::Err {
                        id,
                        code: error.code,
                        message: error.message,
                    },
                }
            }
            Err(message) => HelperReply::Err {
                id: 0,
                code: "INVALID_PARAMS".into(),
                message,
            },
        };
        write_helper_reply(&mut output, &response).map_err(SlotError::failed)?;
    }
    let slots: Vec<u8> = state.open.keys().copied().collect();
    for slot in slots {
        let _ = state.close(slot);
    }
    Ok(())
}

fn write_helper_reply(output: &mut impl Write, reply: &HelperReply) -> io::Result<()> {
    match reply {
        HelperReply::Ok { id, value } => serde_json::to_writer(&mut *output, &json!({ "id": id, "ok": value }))?,
        HelperReply::Err { id, code, message } => {
            serde_json::to_writer(&mut *output, &json!({ "id": id, "err": { "code": code, "message": message } }))?
        }
    }
    output.write_all(b"\n")?;
    output.flush()
}

fn snapshot(paths: &SlotPaths) -> Result<(), SlotError> {
    let source = format!("{WORKSPACE_UPPER}/.");
    let output = Command::new("/bin/cp")
        .args(["-a", "--preserve=all", &source])
        .arg(&paths.snap)
        .output()
        .map_err(SlotError::failed)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(SlotError::failed(format!(
            "snapshot failed: {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn mount_overlay(paths: &SlotPaths) -> Result<(), SlotError> {
    let target = cstring(&paths.merged)?;
    let fstype = CString::new("overlay").expect("static string");
    let source = CString::new("overlay").expect("static string");
    let data = CString::new(format!(
        "lowerdir={}:{},upperdir={},workdir={}",
        paths.snap.display(),
        WORKSPACE_LOWER,
        paths.upper.display(),
        paths.work.display()
    ))
    .map_err(|_| SlotError::failed("overlay path contains NUL"))?;
    nix::mount::mount(
        Some(source.as_c_str()),
        target.as_c_str(),
        Some(fstype.as_c_str()),
        nix::mount::MsFlags::empty(),
        Some(data.as_c_str()),
    )
    .map_err(|e| SlotError::failed(format!("mount overlay {}: {e}", paths.merged.display())))
}

fn bind_control_socket(paths: &SlotPaths, base_uid: u32, base_gid: u32) -> Result<std::os::unix::net::UnixListener, SlotError> {
    std::fs::create_dir_all(CTL_DIR).map_err(SlotError::failed)?;
    chown_path(Path::new(CTL_DIR), base_uid, base_gid)?;
    set_mode(Path::new(CTL_DIR), 0o700)?;
    match std::fs::remove_file(&paths.socket) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(SlotError::failed(error)),
    }
    let listener = std::os::unix::net::UnixListener::bind(&paths.socket).map_err(SlotError::failed)?;
    chown_path(&paths.socket, base_uid, base_gid)?;
    set_mode(&paths.socket, 0o600)?;
    Ok(listener)
}

#[allow(unsafe_code)] // pre_exec namespace/uid setup (see SAFETY below)
fn spawn_server(
    slot: u8,
    paths: &SlotPaths,
    config: &HelperConfig,
    uid: u32,
    gid: u32,
    listener: &std::os::unix::net::UnixListener,
) -> Result<Child, SlotError> {
    use std::os::fd::AsRawFd;

    let listener_fd = listener.as_raw_fd();
    let slot_name = slot.to_string();
    // Prepare everything that needs allocation before entering pre_exec.
    let merged = cstring(&paths.merged)?;
    let workspace = cstring(Path::new(WORKSPACE))?;
    let home = cstring(&paths.home)?;
    let agent_home = cstring(Path::new(AGENT_HOME))?;
    let tmp = cstring(&paths.tmp)?;
    let tmp_target = cstring(Path::new("/tmp"))?;
    let run_bulge = cstring(Path::new("/run/bulge"))?;
    let root = cstring(Path::new("/"))?;
    let tmpfs = CString::new("tmpfs").expect("static string");
    let tmpfs_data = CString::new("mode=0755").expect("static string");

    // Stage 1 (this pre_exec, still root): new mount/PID/IPC namespaces and the
    // slot's view of the filesystem, then exec the holder (stage 2, see
    // `holder_main`), which forks PID 1 of the new PID namespace (stage 3).
    let mut command = Command::new("/proc/self/exe");
    command
        .arg("--slot-holder")
        .arg(&slot_name)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .env_clear()
        .env("HOME", AGENT_HOME)
        .env("PATH", DEFAULT_PATH)
        .env("BULGE_SLOT", &slot_name)
        .env("BULGE_BASE_UID", uid.to_string())
        .env("BULGE_BASE_GID", gid.to_string());
    if let Some(proxy) = &config.egress_proxy {
        command.env("BULGE_EGRESS_PROXY", proxy);
    }
    command.current_dir("/");

    // SAFETY: pre_exec runs after fork and before exec. Every call below is an
    // async-signal-safe syscall wrapper; all CStrings were allocated before the
    // fork. fd 3 is the inherited listening socket (dup2 clears CLOEXEC).
    unsafe {
        command.pre_exec(move || {
            let sys = |result: nix::Result<()>| result.map_err(|error| io::Error::from_raw_os_error(error as i32));
            // Own process group so `close` can kill the holder and the slot at once.
            if nix::libc::setpgid(0, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            sys(nix::sched::unshare(
                nix::sched::CloneFlags::CLONE_NEWNS
                    | nix::sched::CloneFlags::CLONE_NEWPID
                    | nix::sched::CloneFlags::CLONE_NEWIPC
                    // Own network namespace: only a loopback, so one slot can never
                    // reach a service another slot (or the main agent) listens on.
                    // Egress goes through the bridge's unix socket (bridge::relay_to_unix).
                    | nix::sched::CloneFlags::CLONE_NEWNET,
            ))?;
            sys(nix::mount::mount::<CStr, CStr, CStr, CStr>(
                None,
                root.as_c_str(),
                None,
                nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
                None,
            ))?;
            for (source, target) in [(&merged, &workspace), (&home, &agent_home), (&tmp, &tmp_target)] {
                sys(nix::mount::mount::<CStr, CStr, CStr, CStr>(
                    Some(source.as_c_str()),
                    target.as_c_str(),
                    None,
                    nix::mount::MsFlags::MS_BIND,
                    None,
                ))?;
            }
            // Hide every slot, the main upper and the control sockets.
            sys(nix::mount::mount::<CStr, CStr, CStr, CStr>(
                Some(tmpfs.as_c_str()),
                run_bulge.as_c_str(),
                Some(tmpfs.as_c_str()),
                nix::mount::MsFlags::empty(),
                Some(tmpfs_data.as_c_str()),
            ))?;
            if listener_fd != 3 && nix::libc::dup2(listener_fd, 3) < 0 {
                return Err(io::Error::last_os_error());
            }
            if nix::libc::fcntl(3, nix::libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn().map_err(SlotError::failed)
}

/// `sandboxd --slot-holder <n>` (stage 2): runs as root inside the slot's mount
/// namespace but outside its PID namespace (`unshare(CLONE_NEWPID)` only moves
/// children). It forks PID 1 of the slot's PID namespace, which mounts a /proc
/// that shows only the slot's processes, applies limits, drops to the workspace
/// owner with `no_new_privs`, and execs the slot server (stage 3). The holder
/// just waits and mirrors the server's exit; when PID 1 dies the kernel kills
/// every process left in the slot. Synchronous and single-threaded.
#[allow(unsafe_code)] // fork + exec of the namespace's PID 1 (see SAFETY below)
pub fn holder_main(slot: u8) -> Result<(), String> {
    validate_slot(slot)?;
    let uid = env_number("BULGE_BASE_UID")?;
    let gid = env_number("BULGE_BASE_GID")?;
    let proc_fs = CString::new("proc").map_err(|e| e.to_string())?;
    let proc_target = CString::new("/proc").map_err(|e| e.to_string())?;
    // SAFETY: this process is single-threaded (no runtime has started).
    match unsafe { nix::unistd::fork() }.map_err(|e| format!("fork slot init: {e}"))? {
        nix::unistd::ForkResult::Parent { child } => loop {
            match nix::sys::wait::waitpid(child, None) {
                Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => std::process::exit(code),
                Ok(nix::sys::wait::WaitStatus::Signaled(..)) => std::process::exit(1),
                Ok(_) => continue,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(error) => return Err(format!("wait slot init: {error}")),
            }
        },
        nix::unistd::ForkResult::Child => {
            let result = (|| -> Result<std::convert::Infallible, String> {
                nix::mount::mount::<CStr, CStr, CStr, CStr>(
                    Some(proc_fs.as_c_str()),
                    proc_target.as_c_str(),
                    Some(proc_fs.as_c_str()),
                    nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NODEV | nix::mount::MsFlags::MS_NOEXEC,
                    None,
                )
                .map_err(|e| format!("mount slot /proc: {e}"))?;
                // The new network namespace starts with loopback down.
                let up = std::process::Command::new("/sbin/ip")
                    .args(["link", "set", "lo", "up"])
                    .status()
                    .map_err(|e| format!("bring up slot loopback: {e}"))?;
                if !up.success() {
                    return Err(format!("bring up slot loopback: {up}"));
                }
                nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_NPROC, 512, 512).map_err(|e| format!("rlimit: {e}"))?;
                nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE, 4096, 4096).map_err(|e| format!("rlimit: {e}"))?;
                let gid = nix::unistd::Gid::from_raw(gid);
                nix::unistd::setgroups(&[gid]).map_err(|e| format!("setgroups: {e}"))?;
                nix::unistd::setresgid(gid, gid, gid).map_err(|e| format!("setresgid: {e}"))?;
                let uid = nix::unistd::Uid::from_raw(uid);
                nix::unistd::setresuid(uid, uid, uid).map_err(|e| format!("setresuid: {e}"))?;
                nix::sys::prctl::set_no_new_privs().map_err(|e| format!("no_new_privs: {e}"))?;
                let exe = CString::new("/proc/self/exe").map_err(|e| e.to_string())?;
                let args = [exe.clone(), CString::new("--slot-server").map_err(|e| e.to_string())?, CString::new(slot.to_string()).map_err(|e| e.to_string())?];
                nix::unistd::execv(&exe, &args).map_err(|e| format!("exec slot server: {e}"))
            })();
            // execv only returns on failure.
            let Err(message) = result;
            eprintln!("sandboxd: slot {slot} init: {message}");
            std::process::exit(1);
        }
    }
}

fn env_number(name: &str) -> Result<u32, String> {
    std::env::var(name).map_err(|_| format!("{name} is not set"))?.parse().map_err(|e| format!("{name}: {e}"))
}

fn cleanup_slot(paths: &SlotPaths) -> Result<(), SlotError> {
    let merged = cstring(&paths.merged)?;
    match nix::mount::umount2(merged.as_c_str(), nix::mount::MntFlags::MNT_DETACH) {
        Ok(()) => {}
        Err(nix::errno::Errno::EINVAL | nix::errno::Errno::ENOENT) => {}
        Err(error) => return Err(SlotError::failed(format!("unmount {}: {error}", paths.merged.display()))),
    }
    match std::fs::remove_file(&paths.socket) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(SlotError::failed(error)),
    }
    match std::fs::remove_dir_all(&paths.root) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(SlotError::failed(error)),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Base lookup, export, and merge decision logic
// ---------------------------------------------------------------------------

/// A snapshot whiteout is a 0/0 character device.
pub fn is_overlay_whiteout(path: &Path) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    match std::fs::symlink_metadata(path) {
        Ok(meta) => meta.file_type().is_char_device() && meta.rdev() == 0,
        Err(_) => false,
    }
}

/// Base entry for a slot: the snapshot layer first, falling back to the
/// read-only host share. A whiteout in the snapshot means the path is absent.
pub fn slot_base_entry(snap: &Path, lower: &Path, rel: &Path, whiteout: &dyn Fn(&Path) -> bool) -> BaseEntry {
    let snap_path = snap.join(rel);
    if whiteout(&snap_path) {
        return BaseEntry::Absent;
    }
    if let Ok(meta) = std::fs::symlink_metadata(&snap_path) {
        return BaseEntry::from_metadata(snap_path, &meta);
    }
    let lower_path = lower.join(rel);
    match std::fs::metadata(&lower_path) {
        Ok(meta) => BaseEntry::from_metadata(lower_path, &meta),
        Err(_) => BaseEntry::Absent,
    }
}

/// [`slot_base_entry`] for the live helper, refusing a path whose parents in the
/// snapshot or the host share are symlinks (reported as absent from the base, so
/// any change to it conflicts or is added — never read through a link as root).
fn base_entry_checked(snap: &Path, rel: &Path) -> BaseEntry {
    let lower = Path::new(WORKSPACE_LOWER);
    if ensure_no_symlink_parents(snap, rel).is_err() || ensure_no_symlink_parents(lower, rel).is_err() {
        return BaseEntry::Absent;
    }
    slot_base_entry(snap, lower, rel, &is_overlay_whiteout)
}

/// Run `work` in a forked child that has (optionally) entered the mount namespace
/// of process `mount_ns_of` and then dropped to `uid`/`gid` (no supplementary
/// groups, `no_new_privs`), and return its result. The helper is single-threaded,
/// so forking is safe; the child reports back as one JSON value over a pipe and
/// exits without unwinding. Used so that the root helper never reads or writes a
/// path an unprivileged process could have redirected.
#[allow(unsafe_code)]
fn run_as<T, F>(mount_ns_of: Option<i32>, uid: u32, gid: u32, work: F) -> Result<T, SlotError>
where
    T: Serialize + serde::de::DeserializeOwned,
    F: FnOnce() -> Result<T, SlotError>,
{
    use std::io::Read;
    use std::os::fd::OwnedFd;

    let (read_end, write_end): (OwnedFd, OwnedFd) = nix::unistd::pipe().map_err(SlotError::failed)?;
    // SAFETY: the helper process is single-threaded (no tokio, no spawned
    // threads), so the child may run ordinary Rust code after fork.
    match unsafe { nix::unistd::fork() }.map_err(SlotError::failed)? {
        nix::unistd::ForkResult::Child => {
            drop(read_end);
            let result = (|| -> Result<T, SlotError> {
                if let Some(pid) = mount_ns_of {
                    let ns = std::fs::File::open(format!("/proc/{pid}/ns/mnt")).map_err(SlotError::failed)?;
                    nix::sched::setns(ns, nix::sched::CloneFlags::CLONE_NEWNS).map_err(SlotError::failed)?;
                    std::env::set_current_dir("/").map_err(SlotError::failed)?;
                }
                let gid = nix::unistd::Gid::from_raw(gid);
                nix::unistd::setgroups(&[gid]).map_err(SlotError::failed)?;
                nix::unistd::setresgid(gid, gid, gid).map_err(SlotError::failed)?;
                let uid = nix::unistd::Uid::from_raw(uid);
                nix::unistd::setresuid(uid, uid, uid).map_err(SlotError::failed)?;
                nix::sys::prctl::set_no_new_privs().map_err(SlotError::failed)?;
                work()
            })();
            let payload: Result<T, (String, String)> = result.map_err(|error| (error.code, error.message));
            let bytes = serde_json::to_vec(&payload).unwrap_or_default();
            let mut file = std::fs::File::from(write_end);
            let code = if file.write_all(&bytes).is_ok() { 0 } else { 1 };
            // SAFETY: terminate the forked child without running the parent's
            // destructors or flushing its buffers twice.
            unsafe { nix::libc::_exit(code) }
        }
        nix::unistd::ForkResult::Parent { child } => {
            drop(write_end);
            let mut bytes = Vec::new();
            let read = std::fs::File::from(read_end).read_to_end(&mut bytes);
            let status = nix::sys::wait::waitpid(child, None).map_err(SlotError::failed)?;
            read.map_err(SlotError::failed)?;
            if !matches!(status, nix::sys::wait::WaitStatus::Exited(_, 0)) {
                return Err(SlotError::failed(format!("unprivileged worker ended abnormally: {status:?}")));
            }
            let payload: Result<T, (String, String)> = serde_json::from_slice(&bytes).map_err(SlotError::failed)?;
            payload.map_err(|(code, message)| SlotError::new(code, message))
        }
    }
}

fn export_from(root: &Path, paths: &[PathBuf], base_exists: &dyn Fn(&Path) -> bool) -> Result<Value, SlotError> {
    let mut files = Vec::with_capacity(paths.len());
    for rel in paths {
        let display = rel.to_string_lossy().into_owned();
        ensure_no_symlink_parents(root, rel).map_err(SlotError::failed)?;
        let path = root.join(rel);
        let entry = match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                json!({ "path": display, "kind": "deleted" })
            }
            Err(error) => return Err(SlotError::failed(error)),
            Ok(meta) if meta.file_type().is_symlink() => json!({
                "path": display,
                "kind": "symlink",
                "target": std::fs::read_link(&path).map_err(SlotError::failed)?,
            }),
            Ok(meta) if meta.is_file() => {
                if meta.len() > crate::tools::handlers::MAX_EXPORT_FILE_BYTES {
                    json!({ "path": display, "kind": "too_large", "size": meta.len() })
                } else {
                    let data = std::fs::read(&path).map_err(SlotError::failed)?;
                    json!({
                        "path": display,
                        "kind": "file",
                        "executable": meta.permissions().mode() & 0o111 != 0,
                        "existed": base_exists(rel),
                        "data_b64": base64::engine::general_purpose::STANDARD.encode(&data),
                    })
                }
            }
            Ok(meta) if meta.is_dir() => json!({ "path": display, "kind": "dir" }),
            Ok(_) => json!({ "path": display, "kind": "deleted" }),
        };
        files.push(entry);
    }
    Ok(json!({ "files": files }))
}

/// A version of one workspace path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Entry {
    File { data: Vec<u8>, mode: u32 },
    Symlink { target: PathBuf },
    Dir,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Nothing to do (both sides absent, or both deleted).
    Nothing,
    /// Apply the slot version to the main workspace.
    Apply,
    /// The main workspace changed since the slot opened.
    Conflict(String),
}

/// Pure three-way merge decision. The main workspace may only be touched when
/// it still matches the slot's base version.
pub fn merge_decision(base: Option<&Entry>, slot: Option<&Entry>, main: Option<&Entry>) -> Decision {
    // Main already holds exactly what the slot has (both deleted it, or another
    // merge made the same change): the edits converged, nothing to do.
    if same_version(slot, main) {
        return Decision::Nothing;
    }
    if !same_version(base, main) {
        return Decision::Conflict("main workspace changed since the slot opened".into());
    }
    // Main still equals the base: apply the slot's version (or its deletion).
    Decision::Apply
}

fn same_version(a: Option<&Entry>, b: Option<&Entry>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(Entry::File { data: a, .. }), Some(Entry::File { data: b, .. })) => a == b,
        (Some(Entry::Symlink { target: a }), Some(Entry::Symlink { target: b })) => a == b,
        (Some(Entry::Dir), Some(Entry::Dir)) => true,
        (Some(Entry::Other), Some(Entry::Other)) => true,
        _ => false,
    }
}

fn read_entry_opt(path: Option<&Path>) -> Result<Option<Entry>, SlotError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(SlotError::failed(error)),
    };
    let file_type = meta.file_type();
    let entry = if file_type.is_symlink() {
        Entry::Symlink {
            target: std::fs::read_link(path).map_err(SlotError::failed)?,
        }
    } else if file_type.is_dir() {
        Entry::Dir
    } else if file_type.is_file() {
        Entry::File {
            data: std::fs::read(path).map_err(SlotError::failed)?,
            // Permission bits only: setuid/setgid/sticky never cross a merge.
            mode: meta.permissions().mode() & 0o777,
        }
    } else {
        Entry::Other
    };
    Ok(Some(entry))
}

fn apply_entry(root: &Path, rel: &Path, entry: Option<&Entry>, uid: u32, gid: u32) -> io::Result<()> {
    let target = root.join(rel);
    match entry {
        None => {
            ensure_no_symlink_parents(root, rel)?;
            remove_existing(&target)
        }
        Some(Entry::File { data, mode }) => {
            ensure_parent(root, rel, uid, gid)?;
            let name = target.file_name().unwrap_or_default().to_string_lossy();
            let temp = target.with_file_name(format!(
                ".{name}.bulge-slot-{}-{}",
                std::process::id(),
                next_temp_id()
            ));
            let write = (|| -> io::Result<()> {
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&temp)?;
                file.write_all(data)?;
                file.flush()?;
                drop(file);
                std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(*mode))?;
                std::os::unix::fs::chown(&temp, Some(uid), Some(gid))
            })();
            if let Err(error) = write {
                let _ = std::fs::remove_file(&temp);
                return Err(error);
            }
            if std::fs::symlink_metadata(&target).is_ok_and(|meta| meta.is_dir()) {
                std::fs::remove_dir_all(&target)?;
            }
            if let Err(error) = std::fs::rename(&temp, &target) {
                let _ = std::fs::remove_file(&temp);
                return Err(error);
            }
            Ok(())
        }
        Some(Entry::Symlink { target: link }) => {
            ensure_parent(root, rel, uid, gid)?;
            remove_existing(&target)?;
            std::os::unix::fs::symlink(link, &target)?;
            let _ = nix::unistd::fchownat(
                nix::fcntl::AT_FDCWD,
                &target,
                Some(nix::unistd::Uid::from_raw(uid)),
                Some(nix::unistd::Gid::from_raw(gid)),
                nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
            );
            Ok(())
        }
        Some(Entry::Dir) => {
            ensure_parent(root, rel, uid, gid)?;
            if let Ok(meta) = std::fs::symlink_metadata(&target)
                && !meta.is_dir()
            {
                remove_existing(&target)?;
            }
            std::fs::create_dir_all(&target)?;
            std::os::unix::fs::chown(&target, Some(uid), Some(gid))?;
            Ok(())
        }
        Some(Entry::Other) => Err(io::Error::other("cannot merge a special file")),
    }
}

fn next_temp_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn ensure_parent(root: &Path, rel: &Path, uid: u32, gid: u32) -> io::Result<()> {
    let Some(parent) = rel.parent() else {
        return Ok(());
    };
    let mut current = root.to_path_buf();
    for component in parent.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(io::Error::other(format!(
                    "refusing to traverse symlink parent {}",
                    current.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                std::fs::create_dir(&current)?;
                std::fs::set_permissions(&current, std::fs::Permissions::from_mode(0o755))?;
                std::os::unix::fs::chown(&current, Some(uid), Some(gid))?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Refuse to read/write through an existing symlink in any parent component.
fn ensure_no_symlink_parents(root: &Path, rel: &Path) -> io::Result<()> {
    let Some(parent) = rel.parent() else {
        return Ok(());
    };
    let mut current = root.to_path_buf();
    for component in parent.components() {
        current.push(component);
        if let Ok(meta) = std::fs::symlink_metadata(&current)
            && meta.file_type().is_symlink()
        {
            return Err(io::Error::other(format!(
                "refusing to traverse symlink parent {}",
                current.display()
            )));
        }
    }
    Ok(())
}

fn remove_existing(target: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(target) {
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(target),
        Ok(_) => std::fs::remove_file(target),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

// ---------------------------------------------------------------------------
// Slot server
// ---------------------------------------------------------------------------

static NEXT_INVOCATION_ID: AtomicU64 = AtomicU64::new(1);

#[allow(unsafe_code)] // adopting the inherited listener on fd 3 (see SAFETY below)
pub async fn slot_server_main(slot: u8) -> Result<(), String> {
    validate_slot(slot)?;
    if let Ok(proxy) = std::env::var("BULGE_EGRESS_PROXY")
        && !proxy.is_empty()
    {
        let _ = crate::EGRESS_PROXY.set(proxy);
        // This slot has its own network namespace: serve its loopback proxy
        // address by relaying to the main bridge's unix socket.
        tokio::spawn(async {
            if let Err(error) = crate::bridge::relay_to_unix().await {
                eprintln!("sandboxd: slot egress relay: {error}");
            }
        });
    }

    let runtime = CommandRuntime::builder()
        .command("exec", crate::commands::exec)
        .command("read", crate::tools::handlers::read)
        .command("write", crate::tools::handlers::write)
        .command("edit", crate::tools::handlers::edit)
        .command("glob", crate::tools::handlers::glob)
        .command("grep", crate::tools::handlers::grep)
        .max_timeout(Duration::from_secs(30 * 60))
        .build()
        .map_err(|e| format!("slot runtime: {e}"))?;

    // SAFETY: the privileged helper duped the already-bound listening socket to
    // fd 3 before exec and cleared CLOEXEC.
    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(3) };
    listener.set_nonblocking(true).map_err(|e| format!("slot listener: {e}"))?;
    let listener = tokio::net::UnixListener::from_std(listener).map_err(|e| format!("slot listener: {e}"))?;
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(error) => {
                eprintln!("sandboxd: slot {slot} accept: {error}");
                continue;
            }
        };
        let runtime = runtime.clone();
        tokio::spawn(async move {
            serve_connection(stream, runtime).await;
        });
    }
}

async fn serve_connection(stream: tokio::net::UnixStream, runtime: CommandRuntime) {
    let (read_half, write_half) = stream.into_split();
    let writer = Arc::new(tokio::sync::Mutex::new(write_half));
    let mut reader = TokioBufReader::new(read_half);
    let active: Arc<Mutex<std::collections::HashSet<u64>>> = Arc::new(Mutex::new(std::collections::HashSet::new()));

    loop {
        let mut line = String::new();
        let read = match reader.read_line(&mut line).await {
            Ok(read) => read,
            Err(_) => break,
        };
        if read == 0 {
            break;
        }
        if line.trim().is_empty() {
            continue;
        }
        let request = match parse_slot_request(&line) {
            Ok(request) => request,
            Err(message) => {
                let response = SlotResponse {
                    id: 0,
                    outcome: Outcome::Err {
                        code: "INVALID_PARAMS".into(),
                        message,
                    },
                };
                let _ = write_response(&writer, &response).await;
                continue;
            }
        };
        let internal_id = NEXT_INVOCATION_ID.fetch_add(1, Ordering::Relaxed);
        active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(internal_id);
        let runtime = runtime.clone();
        let writer = writer.clone();
        let active = active.clone();
        tokio::spawn(async move {
            let invocation = Invocation {
                id: internal_id,
                command: request.command,
                params: request.params,
                timeout: request.timeout_ms.map(Duration::from_millis),
            };
            let outcome = runtime.evaluate(invocation).await;
            active
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&internal_id);
            let response = SlotResponse {
                id: request.id,
                outcome,
            };
            let _ = write_response(&writer, &response).await;
        });
    }

    // A closed connection cancels every request still in flight on it.
    let in_flight: Vec<u64> = active
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .copied()
        .collect();
    for id in in_flight {
        runtime.cancel(id);
    }
}

async fn write_response(writer: &Arc<tokio::sync::Mutex<tokio::net::unix::OwnedWriteHalf>>, response: &SlotResponse) -> io::Result<()> {
    let mut line = serde_json::to_string(response).map_err(io::Error::other)?;
    line.push('\n');
    let mut writer = writer.lock().await;
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("bulge-slot-{}-{label}-{n}", std::process::id()));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn file(data: &[u8]) -> Entry {
        Entry::File {
            data: data.to_vec(),
            mode: 0o644,
        }
    }

    #[test]
    fn validate_slot_accepts_only_configured_indices() {
        for slot in 0..MAX_SLOTS {
            assert_eq!(validate_slot(slot), Ok(slot));
        }
        assert!(validate_slot(MAX_SLOTS).is_err());
        assert!(validate_slot(u8::MAX).is_err());
    }

    #[test]
    fn stage_slots_must_be_valid_and_different() {
        assert_eq!(validate_stage_slots(1, 2), Ok((1, 2)));
        assert!(validate_stage_slots(3, 3).is_err());
        assert!(validate_stage_slots(MAX_SLOTS, 0).is_err());
        assert!(validate_stage_slots(0, MAX_SLOTS).is_err());
    }

    #[test]
    fn parses_stage_params_and_helper_request() {
        let params: SlotStageParams = serde_json::from_str(r#"{"slot":2,"from":1,"paths":["a.txt","dir/b"]}"#)
            .expect("stage params");
        assert_eq!((params.slot, params.from), (2, 1));
        assert_eq!(params.paths, vec!["a.txt".to_owned(), "dir/b".to_owned()]);
        assert!(serde_json::from_str::<SlotStageParams>(r#"{"slot":2,"from":1,"paths":[],"extra":true}"#).is_err());

        let request = parse_helper_request(r#"{"id":11,"op":"stage","slot":2,"from":1,"paths":["a.txt"]}"#)
            .expect("helper stage request");
        assert_eq!(request.op, "stage");
        assert_eq!((request.slot, request.from), (2, 1));
        assert_eq!(request.paths, vec!["a.txt".to_owned()]);
        let legacy = parse_helper_request(r#"{"id":1,"op":"open","slot":0}"#).expect("legacy request");
        assert_eq!(legacy.from, 0);
    }


    #[test]
    fn validate_rel_path_accepts_and_normalises_safe_paths() {
        assert_eq!(validate_rel_path("a/b.txt").unwrap(), PathBuf::from("a/b.txt"));
        assert_eq!(validate_rel_path("a//b.txt").unwrap(), PathBuf::from("a/b.txt"));
        assert_eq!(validate_rel_path("a/").unwrap(), PathBuf::from("a"));
    }

    #[test]
    fn validate_rel_path_rejects_unsafe_paths() {
        for path in [
            "/etc/passwd",
            "../x",
            "a/../b",
            "./a",
            "",
            "a\0b",
            ".overlay-x/y",
            ".overlay",
            "a/.overlay-whiteout",
        ] {
            assert!(validate_rel_path(path).is_err(), "should reject {path:?}");
        }
    }

    #[test]
    fn identical_concurrent_changes_are_not_conflicts() {
        let base = file(b"VERSION = 1.0");
        let both = file(b"VERSION = 1.1");
        // Another slot already merged the same edit: converged.
        assert_eq!(merge_decision(Some(&base), Some(&both), Some(&both)), Decision::Nothing);
        // Both created the same directory.
        assert_eq!(merge_decision(None, Some(&Entry::Dir), Some(&Entry::Dir)), Decision::Nothing);
        // A different edit on top of someone else's change still conflicts.
        assert!(matches!(merge_decision(Some(&base), Some(&file(b"VERSION = 2.0")), Some(&both)), Decision::Conflict(_)));
    }

    #[test]
    fn merge_decision_table() {
        let base = file(b"base");
        let changed = file(b"slot");
        let main_changed = file(b"main");

        // unchanged main -> apply
        assert_eq!(merge_decision(Some(&base), Some(&changed), Some(&base)), Decision::Apply);
        // main changed -> conflict
        assert!(matches!(
            merge_decision(Some(&base), Some(&changed), Some(&main_changed)),
            Decision::Conflict(_)
        ));
        // both deleted -> nothing to do
        assert_eq!(merge_decision(Some(&base), None, None), Decision::Nothing);
        // added in slot, absent in main -> apply
        assert_eq!(merge_decision(None, Some(&changed), None), Decision::Apply);
        // added in both differently -> conflict
        assert!(matches!(
            merge_decision(None, Some(&changed), Some(&main_changed)),
            Decision::Conflict(_)
        ));
        // unchanged main and slot deleted -> delete
        assert_eq!(merge_decision(Some(&base), None, Some(&base)), Decision::Apply);
        // type change on main since the base -> conflict
        assert!(matches!(
            merge_decision(Some(&base), Some(&changed), Some(&Entry::Dir)),
            Decision::Conflict(_)
        ));
    }

    #[test]
    fn slot_base_prefers_snapshot_then_lower_and_honours_whiteouts() {
        let snap = TempDir::new("snap");
        let lower = TempDir::new("lower");
        std::fs::write(snap.path().join("in-snap.txt"), b"snap").unwrap();
        std::fs::write(lower.path().join("in-snap.txt"), b"lower").unwrap();
        std::fs::write(lower.path().join("only-lower.txt"), b"lower").unwrap();
        std::fs::write(snap.path().join("whited.txt"), b"whiteout placeholder").unwrap();
        std::fs::write(lower.path().join("whited.txt"), b"lower").unwrap();

        let no_whiteout = |_: &Path| false;
        let snap_entry = slot_base_entry(snap.path(), lower.path(), Path::new("in-snap.txt"), &no_whiteout);
        assert_eq!(snap_entry, BaseEntry::File(snap.path().join("in-snap.txt")));
        assert_eq!(std::fs::read(snap_entry.file_path().unwrap()).unwrap(), b"snap");

        let lower_entry = slot_base_entry(snap.path(), lower.path(), Path::new("only-lower.txt"), &no_whiteout);
        assert_eq!(lower_entry, BaseEntry::File(lower.path().join("only-lower.txt")));

        let whiteout = |path: &Path| path.file_name().is_some_and(|name| name == "whited.txt");
        assert_eq!(
            slot_base_entry(snap.path(), lower.path(), Path::new("whited.txt"), &whiteout),
            BaseEntry::Absent
        );
        assert_eq!(
            slot_base_entry(snap.path(), lower.path(), Path::new("missing.txt"), &no_whiteout),
            BaseEntry::Absent
        );
    }

    #[test]
    fn parses_helper_request_line() {
        let request = parse_helper_request(r#"{"id":9,"op":"merge","slot":2,"paths":["a/b"]}"#).unwrap();
        assert_eq!(request.id, 9);
        assert_eq!(request.op, "merge");
        assert_eq!(request.slot, 2);
        assert_eq!(request.paths, vec!["a/b".to_owned()]);
        // Unknown operation fields are rejected as malformed.
        assert!(parse_helper_request(r#"{"id":1,"op":"open","slot":0,"extra":1}"#).is_err());
        assert!(parse_helper_request(r#"{"id":1,"op":"open","slot":256}"#).is_err());
    }

    #[test]
    fn parses_slot_request_line() {
        let request = parse_slot_request(
            r#"{"id":7,"command":"read","params":{"path":"a"},"timeout_ms":250}"#,
        )
        .unwrap();
        assert_eq!(request.id, 7);
        assert_eq!(request.command, "read");
        assert_eq!(request.params, json!({"path": "a"}));
        assert_eq!(request.timeout_ms, Some(250));
        assert!(parse_slot_request(r#"{"id":1,"command":"read","extra":true}"#).is_err());
    }

    #[test]
    fn parses_helper_error_response() {
        let reply = parse_helper_response(
            r#"{"id":3,"err":{"code":"INVALID_PARAMS","message":"bad path"}}"#,
        )
        .unwrap();
        assert_eq!(
            reply,
            HelperReply::Err {
                id: 3,
                code: "INVALID_PARAMS".into(),
                message: "bad path".into(),
            }
        );
        let ok = parse_helper_response(r#"{"id":4,"ok":{"slot":4}}"#).unwrap();
        assert_eq!(ok, HelperReply::Ok { id: 4, value: json!({"slot": 4}) });
        let null = parse_helper_response(r#"{"id":5,"ok":null}"#).unwrap();
        assert_eq!(null, HelperReply::Ok { id: 5, value: Value::Null });
        assert!(parse_helper_response(r#"{"id":1,"ok":{"x":1},"err":{"code":"X","message":"y"}}"#).is_err());
    }
}
