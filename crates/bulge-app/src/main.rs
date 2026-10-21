//! Bulge desktop app.
//!
//! One window, no network ports: the webview talks to this process over Tauri's
//! in-process IPC (the roadmap's "Tauri 程序內 IPC"). A conversation runs as a
//! long-lived [`Session`] (one VM + the store job it serves) on its own thread;
//! follow-up turns are fed to that same session over a channel, so the VM — and
//! the files inside it — persist across turns. The VM can also be restarted on
//! its own (after a settings change) without disturbing the conversation.
//! Workspace changes stay in the VM overlay; nothing is written to the host until
//! the user reviews the diff and approves it here.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bulge_cli::backend::{BackendSpec, Protocol};
use bulge_cli::run::{RunConfig, Sampling, Session};
use bulge_store::{Autonomy, Budget, JobStore};
use bulge_vm::changes::{self, Change};
use bulge_vm::net::EgressApproval;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

/// At most this many live VMs at once; starting another evicts the least-recently
/// used conversation (its VM is shut down; the stored conversation can be resumed,
/// which launches a fresh VM).
const MAX_LIVE_SESSIONS: usize = 3;

/// A command sent to a running session's thread.
enum SessionCmd {
    /// Run another turn on this conversation (reuses the live VM).
    Turn { goal: String, cancel: CancellationToken },
    /// Restart just the VM with a new shape; the conversation is untouched.
    RestartVm { cpus: u8, ram_mib: u32, network: bool, reply: oneshot::Sender<Result<(), String>> },
}

/// Host-side bookkeeping for one live conversation (keyed by a session id).
struct SessionEntry {
    /// The real store job id (filled in once the session has launched).
    job_id: String,
    /// Feeds turns / restarts to the session thread. Dropping it ends the session
    /// (the thread shuts the VM down and exits).
    cmd_tx: mpsc::UnboundedSender<SessionCmd>,
    /// The current turn's cancel token (emergency stop targets this).
    current_cancel: Arc<Mutex<CancellationToken>>,
    /// The latest finished turn's changes, for the approval step.
    done: Option<DoneInfo>,
    last_used: Instant,
}

struct DoneInfo {
    workspace: PathBuf,
    changes: Vec<Change>,
}

#[derive(Default)]
struct AppState {
    sessions: Mutex<HashMap<String, SessionEntry>>,
    /// Egress approval prompts awaiting the user's answer, by request id. Each
    /// value is the gateway's reply channel; answering it unblocks the connection.
    pending_egress: Mutex<HashMap<String, oneshot::Sender<bool>>>,
}

/// Monotonic counter for unique egress-approval ids (ms alone can collide).
static EGRESS_SEQ: AtomicU64 = AtomicU64::new(1);

/// Defaults the UI pre-fills (mirrors the CLI's defaults).
#[derive(Serialize)]
struct Defaults {
    model: String,
    base_url: String,
    protocol: String,
    autonomy: String,
    cpus: u8,
    ram_mib: u32,
    context_window: u32,
    max_tokens: u32,
}

/// Everything the UI sends to start (or continue) a job. Fixed budgets/limits
/// match the CLI.
#[derive(Deserialize)]
struct StartArgs {
    /// Present and still live → feed this turn to that session's VM (full
    /// continuity). Absent or no longer live → start a fresh session.
    #[serde(default)]
    session: Option<String>,
    /// Present → resume this stored conversation when starting a fresh session
    /// (history is replayed; a new VM is launched). Absent → brand-new job.
    #[serde(default)]
    job_id: Option<String>,
    goal: String,
    workspace: String,
    model: String,
    base_url: String,
    protocol: String,
    autonomy: String,
    network: bool,
    cpus: u8,
    ram_mib: u32,
    /// Sampling / persona (all optional; absent means the provider/app default).
    #[serde(default)]
    temperature: Option<f32>,
    #[serde(default)]
    reasoning_effort: Option<String>,
    #[serde(default)]
    max_tokens: Option<u32>,
    #[serde(default)]
    context_window: Option<u32>,
    #[serde(default)]
    system_prompt: Option<String>,
}

/// One streamed log line, tagged with the session it belongs to.
#[derive(Clone, Serialize)]
struct LineEvent {
    handle: String,
    line: String,
}

/// An egress-approval prompt pushed to the UI: the agent inside this session's VM
/// is trying to reach `host:port` and (collaborative mode) needs the user's OK.
#[derive(Clone, Serialize)]
struct EgressAskEvent {
    handle: String,
    id: String,
    host: String,
    port: u16,
}

/// A single workspace change, for the review list. The full unified diff is sent
/// separately as text; this drives the per-file approval checkboxes.
#[derive(Clone, Serialize)]
struct ChangeDto {
    path: String,
    kind: String,
    detail: String,
}

impl ChangeDto {
    fn from_change(change: &Change) -> Self {
        let (kind, detail) = match change {
            Change::File { data, existed, executable, .. } => (
                "file",
                format!("{} · {} bytes{}", if *existed { "修改" } else { "新增" }, data.len(), if *executable { " · 可執行" } else { "" }),
            ),
            Change::Deleted { .. } => ("deleted", "刪除".to_string()),
            Change::Dir { .. } => ("dir", "新資料夾".to_string()),
            Change::Symlink { target, .. } => ("symlink", format!("符號連結 → {}", target.display())),
            Change::TooLarge { size, .. } => ("too_large", format!("過大,無法內嵌審閱 ({size} bytes)")),
        };
        Self { path: change.path().to_string(), kind: kind.to_string(), detail }
    }
}

#[derive(Clone, Serialize)]
struct DoneEvent {
    handle: String,
    /// The real store job id, so the UI can send a follow-up turn on this same
    /// conversation instead of starting a new one.
    job_id: String,
    status: String,
    outcome: String,
    diff: Option<String>,
    changes: Vec<ChangeDto>,
    job_dir: String,
    error: Option<String>,
}

#[derive(Serialize)]
struct ApplyReportDto {
    applied: Vec<String>,
    skipped: Vec<(String, String)>,
}

/// The host part of a base URL, used to locate its key file.
fn host_of(base_url: &str) -> String {
    base_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(base_url)
        .to_string()
}

fn parse_protocol(name: &str) -> Result<Protocol, String> {
    Protocol::parse(name)
}

fn parse_autonomy(value: &str) -> Result<Autonomy, String> {
    match value {
        "collaborative" => Ok(Autonomy::Collaborative),
        "autonomous" => Ok(Autonomy::Autonomous),
        "full-auto" | "full_auto" | "fullauto" => Ok(Autonomy::FullAuto),
        other => Err(format!("未知的自主模式 {other:?}")),
    }
}

#[tauri::command]
fn defaults() -> Defaults {
    Defaults {
        model: "deepseek-chat".into(),
        base_url: "https://api.deepseek.com".into(),
        protocol: "openai".into(),
        autonomy: "autonomous".into(),
        cpus: 2,
        ram_mib: 1024,
        context_window: 128_000,
        max_tokens: 8_192,
    }
}

/// Parse the optional reasoning-effort selector into the LLM enum.
fn parse_reasoning(value: Option<&str>) -> Option<bulge_llm::ReasoningEffort> {
    use bulge_llm::ReasoningEffort::{High, Low, Max, Off};
    match value {
        Some("off") => Some(Off),
        Some("low") => Some(Low),
        Some("high") => Some(High),
        Some("max") => Some(Max),
        _ => None,
    }
}

/// Whether a key file exists for this backend host. The app never reads or
/// returns the key's contents — only whether one is present.
#[tauri::command]
fn key_status(base_url: String) -> bool {
    bulge_cli::backend::key_path(&host_of(&base_url)).exists()
}

/// Write the user's API key to `~/.bulge/keys/<host>` with mode 600. The key is
/// taken straight from the UI to disk; it is never logged or echoed back.
#[tauri::command]
fn save_key(base_url: String, key: String) -> Result<(), String> {
    let key = key.trim();
    if key.is_empty() {
        return Err("金鑰是空的".into());
    }
    let path = bulge_cli::backend::key_path(&host_of(&base_url));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("建立金鑰目錄失敗:{e}"))?;
    }
    std::fs::write(&path, format!("{key}\n")).map_err(|e| format!("寫入金鑰失敗:{e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(|e| format!("設定權限失敗:{e}"))?;
    }
    Ok(())
}

/// Detect the models this provider currently offers, using the saved key. Replaces
/// a hardcoded list with what the endpoint+key can actually reach. The key is read
/// here only to make the request; it is never returned or logged.
#[tauri::command]
async fn detect_models(base_url: String, protocol: String) -> Result<Vec<String>, String> {
    use bulge_llm::protocol::WireProtocol;
    use bulge_llm::protocol::anthropic::AnthropicMessages;
    use bulge_llm::protocol::openai_chat::OpenAiChat;
    let proto = parse_protocol(&protocol)?;
    let key = bulge_cli::backend::load_api_key(&base_url)?;
    let wire: Box<dyn WireProtocol> = match proto {
        Protocol::OpenAiChat => Box::new(OpenAiChat),
        Protocol::Anthropic => Box::new(AnthropicMessages),
    };
    let mut models = bulge_llm::http::list_models(&base_url, &key, wire.as_ref()).await.map_err(|e| e.to_string())?;
    models.sort();
    Ok(models)
}

/// Native folder picker for choosing the workspace. Runs on the GTK main loop
/// (Linux requires it) via the dialog plugin's callback, awaited here.
#[tauri::command]
async fn pick_workspace(app: AppHandle) -> Option<String> {
    let (tx, rx) = oneshot::channel();
    app.dialog().file().pick_folder(move |picked| {
        let _ = tx.send(picked);
    });
    rx.await.ok().flatten().map(|p| p.to_string())
}

/// Build the per-run config from the UI args, resolving the workspace (an empty
/// path means an ephemeral scratch workspace inside the VM home).
fn build_config(args: &StartArgs) -> Result<RunConfig, String> {
    let home = PathBuf::from(std::env::var("HOME").map_err(|_| "HOME 未設定".to_string())?);
    let workspace = if args.workspace.trim().is_empty() {
        let dir = home.join(".bulge/scratch").join(format!("ws-{}", now_ms()));
        std::fs::create_dir_all(&dir).map_err(|e| format!("建立暫存工作區失敗:{e}"))?;
        dir
    } else {
        let w = PathBuf::from(&args.workspace);
        if !w.is_dir() {
            return Err(format!("工作區不是資料夾:{}", w.display()));
        }
        w
    };
    let protocol = parse_protocol(&args.protocol)?;
    let autonomy = parse_autonomy(&args.autonomy)?;

    // Fail early with a clear message if there is no key, rather than deep in the
    // run. This only checks presence; it does not read the key here.
    if !bulge_cli::backend::key_path(&host_of(&args.base_url)).exists() {
        return Err(format!("找不到 {} 的 API 金鑰。請先在「設定」裡填入並儲存。", host_of(&args.base_url)));
    }

    let title: String = args.goal.lines().next().unwrap_or("job").chars().take(80).collect();
    let host = host_of(&args.base_url);

    let reasoning_effort = parse_reasoning(args.reasoning_effort.as_deref());
    // A reasoning effort is only sent when the model is treated as a reasoning
    // model, so selecting low/high/max turns that on; "off"/unset leaves it off.
    let reasoning = matches!(reasoning_effort, Some(bulge_llm::ReasoningEffort::Low | bulge_llm::ReasoningEffort::High | bulge_llm::ReasoningEffort::Max));
    let context_window = args.context_window.unwrap_or(128_000).max(8_192);
    let out_cap = args.max_tokens.unwrap_or(8_192).clamp(256, 200_000);
    let system_prompt = args.system_prompt.as_ref().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());

    Ok(RunConfig {
        job_id: args.job_id.clone(),
        goal: args.goal.clone(),
        title,
        workspace,
        store_root: home.join(".bulge/jobs"),
        harness_dir: home.join(".bulge/harness"),
        autonomy,
        budget: Budget { max_steps: 200, max_tokens: 2_000_000, max_wall_secs: 14_400 },
        backend: BackendSpec {
            id: host,
            base_url: args.base_url.clone(),
            protocol,
            model: args.model.clone(),
            context_window,
            max_tokens: out_cap,
            reasoning,
        },
        network: args.network,
        cpus: args.cpus,
        ram_mib: args.ram_mib,
        sampling: Sampling { temperature: args.temperature, reasoning_effort, max_tokens: Some(out_cap) },
        system_prompt,
        // Filled in by start_job with the session's egress-approval channel.
        egress_approvals: None,
        skip_review: false,
        auto_review: false,
    })
}

/// Start a new job, or feed a follow-up turn to a live session. Returns the
/// session id the UI uses to stop it, continue it, and apply its diff. Events
/// stream back as `job-line`; each turn's completion arrives as `job-done`.
#[tauri::command]
async fn start_job(app: AppHandle, state: State<'_, AppState>, args: StartArgs) -> Result<String, String> {
    // Live follow-up: the named session is still running — hand it the next turn
    // so it reuses the same VM (in-VM files carry over).
    if let Some(sid) = args.session.clone() {
        let mut sessions = state.sessions.lock().unwrap();
        if let Some(entry) = sessions.get_mut(&sid) {
            let cancel = CancellationToken::new();
            *entry.current_cancel.lock().unwrap() = cancel.clone();
            entry.last_used = Instant::now();
            entry.done = None;
            entry
                .cmd_tx
                .send(SessionCmd::Turn { goal: args.goal.clone(), cancel })
                .map_err(|_| "工作階段已結束,請重試".to_string())?;
            return Ok(sid);
        }
        // Session gone (evicted) → fall through and start a fresh one (resuming the
        // stored conversation if a job_id was supplied).
    }

    let mut config = build_config(&args)?;

    // Egress approvals: in collaborative mode with network on, the gateway asks
    // before the agent reaches a host outside the package/dev allowlist. The
    // session drains these and surfaces them to the UI.
    let (egress_tx, egress_rx) = mpsc::unbounded_channel::<EgressApproval>();
    config.egress_approvals = Some(egress_tx);

    let sid = format!("s-{}", now_ms());
    let cancel = CancellationToken::new();
    let current_cancel = Arc::new(Mutex::new(cancel.clone()));
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    {
        let mut sessions = state.sessions.lock().unwrap();
        evict_if_needed(&mut sessions);
        sessions.insert(sid.clone(), SessionEntry { job_id: String::new(), cmd_tx, current_cancel, done: None, last_used: Instant::now() });
    }

    spawn_session(app, sid.clone(), config, cancel, cmd_rx, egress_rx).map_err(|e| {
        state.sessions.lock().unwrap().remove(&sid);
        format!("無法啟動工作執行緒:{e}")
    })?;

    Ok(sid)
}

/// Evict least-recently-used live sessions until there is room for one more.
fn evict_if_needed(sessions: &mut HashMap<String, SessionEntry>) {
    while sessions.len() >= MAX_LIVE_SESSIONS {
        let Some(oldest) = sessions.iter().min_by_key(|(_, e)| e.last_used).map(|(k, _)| k.clone()) else { break };
        // Dropping the entry drops its sender; the session thread then shuts its VM
        // down and exits.
        sessions.remove(&oldest);
    }
}

/// Spawn the session thread. The agent loop's scheduler is not `Send`, so the VM
/// and driver live entirely on this one thread with a current-thread runtime; the
/// app handle and channels cross the boundary fine.
fn spawn_session(
    app: AppHandle,
    sid: String,
    config: RunConfig,
    first_cancel: CancellationToken,
    cmd_rx: mpsc::UnboundedReceiver<SessionCmd>,
    egress_rx: mpsc::UnboundedReceiver<EgressApproval>,
) -> std::io::Result<()> {
    std::thread::Builder::new().name(format!("bulge-{sid}")).spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                emit_launch_error(&app, &sid, format!("無法建立執行緒 runtime:{e}"));
                app.state::<AppState>().sessions.lock().unwrap().remove(&sid);
                return;
            }
        };
        rt.block_on(session_loop(app, sid, config, first_cancel, cmd_rx, egress_rx));
    })?;
    Ok(())
}

/// The session's lifetime: launch the VM, run the first turn, then serve turns
/// and restarts until the channel closes, then shut the VM down.
async fn session_loop(
    app: AppHandle,
    sid: String,
    config: RunConfig,
    first_cancel: CancellationToken,
    mut cmd_rx: mpsc::UnboundedReceiver<SessionCmd>,
    egress_rx: mpsc::UnboundedReceiver<EgressApproval>,
) {
    let first_goal = config.goal.clone();
    let mut session = match Session::launch(config).await {
        Ok(session) => session,
        Err(error) => {
            emit_launch_error(&app, &sid, error);
            app.state::<AppState>().sessions.lock().unwrap().remove(&sid);
            return;
        }
    };

    // Record the real store job id now that the session exists.
    if let Some(entry) = app.state::<AppState>().sessions.lock().unwrap().get_mut(&sid) {
        entry.job_id = session.job_id().to_string();
    }

    // Drain egress-approval requests concurrently with the turns: a network call
    // the agent makes mid-turn blocks in the gateway until the user answers here.
    tokio::spawn(egress_drain(app.clone(), sid.clone(), egress_rx));

    run_turn_and_emit(&app, &sid, &mut session, first_goal, first_cancel).await;

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            SessionCmd::Turn { goal, cancel } => {
                run_turn_and_emit(&app, &sid, &mut session, goal, cancel).await;
            }
            SessionCmd::RestartVm { cpus, ram_mib, network, reply } => {
                let result = session.restart_vm(cpus, ram_mib, network).await;
                let _ = reply.send(result);
            }
        }
    }

    session.shutdown().await;
    app.state::<AppState>().sessions.lock().unwrap().remove(&sid);
}

/// Run one turn, streaming its log to the webview, then publish the result and
/// stash the changes for approval.
async fn run_turn_and_emit(app: &AppHandle, sid: &str, session: &mut Session, goal: String, cancel: CancellationToken) {
    let sink = {
        let app = app.clone();
        let sid = sid.to_string();
        Box::new(move |line: &str| {
            let _ = app.emit("job-line", LineEvent { handle: sid.clone(), line: line.to_string() });
        }) as bulge_cli::run::LineSink
    };

    let event = match session.run_turn(goal, cancel, sink).await {
        Ok(outcome) => {
            let changes_dto: Vec<ChangeDto> = outcome.changes.iter().map(ChangeDto::from_change).collect();
            if let Some(entry) = app.state::<AppState>().sessions.lock().unwrap().get_mut(sid) {
                entry.done = Some(DoneInfo { workspace: outcome.workspace.clone(), changes: outcome.changes });
            }
            DoneEvent {
                handle: sid.to_string(),
                job_id: outcome.job_id,
                status: format!("{:?}", outcome.status),
                outcome: format!("{:?}", outcome.outcome),
                diff: outcome.diff,
                changes: changes_dto,
                job_dir: outcome.job_dir.display().to_string(),
                error: None,
            }
        }
        Err(error) => DoneEvent {
            handle: sid.to_string(),
            job_id: session.job_id().to_string(),
            status: "Failed".into(),
            outcome: "Error".into(),
            diff: None,
            changes: Vec::new(),
            job_dir: String::new(),
            error: Some(error),
        },
    };
    let _ = app.emit("job-done", event);
}

/// Forward each egress-approval request to the UI and park its reply channel until
/// the user answers via `approve_egress`. Ends when the session's sender drops.
async fn egress_drain(app: AppHandle, sid: String, mut rx: mpsc::UnboundedReceiver<EgressApproval>) {
    while let Some(req) = rx.recv().await {
        let id = format!("eg-{}", EGRESS_SEQ.fetch_add(1, Ordering::Relaxed));
        app.state::<AppState>().pending_egress.lock().unwrap().insert(id.clone(), req.reply);
        let _ = app.emit("egress-ask", EgressAskEvent { handle: sid.clone(), id, host: req.host, port: req.port });
    }
}

fn emit_launch_error(app: &AppHandle, sid: &str, error: String) {
    let _ = app.emit(
        "job-done",
        DoneEvent {
            handle: sid.to_string(),
            job_id: String::new(),
            status: "Failed".into(),
            outcome: "Error".into(),
            diff: None,
            changes: Vec::new(),
            job_dir: String::new(),
            error: Some(error),
        },
    );
}

/// Emergency stop: cancel the running turn. The VM stays alive for another turn.
#[tauri::command]
fn stop_job(state: State<'_, AppState>, handle: String) -> Result<(), String> {
    let sessions = state.sessions.lock().unwrap();
    match sessions.get(&handle) {
        Some(entry) => {
            entry.current_cancel.lock().unwrap().cancel();
            Ok(())
        }
        None => Err("找不到這個工作".into()),
    }
}

/// Restart just this conversation's VM with a new shape (cpus / ram / network).
/// The conversation is untouched — only the machine is replaced, so in-VM files
/// reset but the agent's memory does not. Used by the settings "apply" button.
#[tauri::command]
async fn restart_vm(state: State<'_, AppState>, handle: String, cpus: u8, ram_mib: u32, network: bool) -> Result<(), String> {
    let (reply_tx, reply_rx) = oneshot::channel();
    {
        let sessions = state.sessions.lock().unwrap();
        let entry = sessions.get(&handle).ok_or("沒有執行中的工作階段可重啟")?;
        entry
            .cmd_tx
            .send(SessionCmd::RestartVm { cpus, ram_mib, network, reply: reply_tx })
            .map_err(|_| "工作階段已結束".to_string())?;
    }
    reply_rx.await.map_err(|_| "重啟無回應".to_string())?
}

/// Answer an egress-approval prompt: `true` opens the connection (and the host is
/// remembered for the rest of the session), `false` refuses it.
#[tauri::command]
fn approve_egress(state: State<'_, AppState>, id: String, allow: bool) -> Result<(), String> {
    let reply = state.pending_egress.lock().unwrap().remove(&id);
    match reply {
        Some(tx) => {
            let _ = tx.send(allow);
            Ok(())
        }
        None => Err("這個連線請求已處理或已過期".into()),
    }
}

/// End a conversation and shut its VM down (e.g. when the user starts a new task
/// or closes the window). Resuming it later from history launches a fresh VM.
#[tauri::command]
fn end_session(state: State<'_, AppState>, handle: String) -> Result<(), String> {
    // Dropping the entry drops its sender; the session thread shuts the VM down.
    state.sessions.lock().unwrap().remove(&handle);
    Ok(())
}

/// Apply the approved subset of a finished turn's changes to the host workspace.
/// Paths not in `approved` are left untouched; symlink and traversal defences
/// live in `bulge_vm::changes::apply`.
#[tauri::command]
fn apply_changes(state: State<'_, AppState>, handle: String, approved: Vec<String>) -> Result<ApplyReportDto, String> {
    let sessions = state.sessions.lock().unwrap();
    let entry = sessions.get(&handle).ok_or("找不到這個工作")?;
    let done = entry.done.as_ref().ok_or("這個工作還沒完成,沒有可套用的變更")?;
    let report = changes::apply(&done.workspace, &done.changes, &approved);
    Ok(ApplyReportDto { applied: report.applied, skipped: report.skipped })
}

#[derive(Serialize)]
struct McpServerDto {
    name: String,
    command: String,
    disabled: bool,
}

/// The MCP servers declared in `~/.bulge/mcp.json` (read-only view for settings).
/// bulge connects to the enabled ones at the start of each conversation.
#[tauri::command]
fn mcp_servers() -> Vec<McpServerDto> {
    let Ok(home) = std::env::var("HOME") else { return Vec::new() };
    let path = PathBuf::from(home).join(".bulge/mcp.json");
    match bulge_core::mcp::McpConfig::load(&path) {
        Ok(cfg) => cfg
            .servers
            .into_iter()
            .map(|(name, s)| McpServerDto { name, command: s.command, disabled: s.disabled })
            .collect(),
        Err(_) => Vec::new(),
    }
}

#[derive(Serialize)]
struct MemoryDto {
    cue: String,
    lesson: String,
    evidence: String,
    confidence: f32,
}

/// The durable lessons the agent has learned (read-only view for settings).
#[tauri::command]
fn list_memory() -> Vec<MemoryDto> {
    let Ok(home) = std::env::var("HOME") else { return Vec::new() };
    let root = PathBuf::from(home).join(".bulge/harness/memory");
    match bulge_harness::memory::load(&root) {
        Ok((lessons, _problems)) => lessons
            .into_iter()
            .map(|l| MemoryDto { cue: l.cue, lesson: l.lesson, evidence: l.evidence, confidence: l.confidence })
            .collect(),
        Err(_) => Vec::new(),
    }
}

#[derive(Serialize)]
struct SkillDto {
    name: String,
    description: String,
}

/// The reusable skills the agent has proposed (read-only view for settings). Reads
/// `~/.bulge/harness/skills/<name>/SKILL.md` frontmatter.
#[tauri::command]
fn list_skills() -> Vec<SkillDto> {
    let Ok(home) = std::env::var("HOME") else { return Vec::new() };
    let dir = PathBuf::from(home).join(".bulge/harness/skills");
    let Ok(entries) = std::fs::read_dir(&dir) else { return Vec::new() };
    let mut skills = Vec::new();
    for entry in entries.flatten() {
        let md = entry.path().join("SKILL.md");
        let Ok(text) = std::fs::read_to_string(&md) else { continue };
        let name = frontmatter_field(&text, "name").unwrap_or_else(|| entry.file_name().to_string_lossy().into_owned());
        let description = frontmatter_field(&text, "description").unwrap_or_default();
        skills.push(SkillDto { name, description });
    }
    skills.sort_by(|a, b| a.name.cmp(&b.name));
    skills
}

/// Pull one `key: value` line from a leading `---` frontmatter block.
fn frontmatter_field(text: &str, key: &str) -> Option<String> {
    let body = text.strip_prefix("---")?;
    let end = body.find("\n---")?;
    for line in body[..end].lines() {
        if let Some(rest) = line.strip_prefix(&format!("{key}:")) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

#[derive(Serialize)]
struct HookDto {
    event: String,
    matcher: String,
    actions: String,
}

/// The lifecycle hooks declared in `~/.bulge/hooks.json` (read-only settings view).
#[tauri::command]
fn list_hooks() -> Vec<HookDto> {
    use bulge_core::hooks::{HookAction, HookEvent};
    let Ok(home) = std::env::var("HOME") else { return Vec::new() };
    let cfg = bulge_core::hooks::HookConfig::load(&PathBuf::from(home).join(".bulge/hooks.json")).unwrap_or_default();
    let mut out = Vec::new();
    for (event, groups) in &cfg.hooks {
        let event = match event {
            HookEvent::PreToolUse => "PreToolUse",
            HookEvent::PostToolUse => "PostToolUse",
        };
        for group in groups {
            let actions: Vec<&str> = group
                .hooks
                .iter()
                .map(|a| match a {
                    HookAction::Deny { .. } => "deny",
                    HookAction::Allow { .. } => "allow",
                    HookAction::Command { .. } => "command",
                })
                .collect();
            let matcher = if group.matcher.trim().is_empty() { "*".to_string() } else { group.matcher.clone() };
            out.push(HookDto { event: event.to_string(), matcher, actions: actions.join(", ") });
        }
    }
    out
}

/// The saved scheduled tasks (read-only settings view).
#[tauri::command]
fn list_schedules() -> Vec<bulge_cli::cron::TaskSummary> {
    bulge_cli::cron::summaries()
}

/// Remove a scheduled task by id.
#[tauri::command]
fn remove_schedule(id: String) -> Result<bool, String> {
    bulge_cli::cron::remove_task(&id)
}

/// Enable or disable a scheduled task by id.
#[tauri::command]
fn set_schedule_enabled(id: String, enabled: bool) -> Result<bool, String> {
    bulge_cli::cron::set_enabled(&id, enabled)
}

#[derive(Serialize)]
struct ProfileEntryDto {
    file: String,
    key: String,
    body: String,
}

/// The durable profile surfaces USER.md / MEMORY.md (read-only settings view).
#[tauri::command]
fn list_profile() -> Vec<ProfileEntryDto> {
    let Ok(home) = std::env::var("HOME") else { return Vec::new() };
    let root = PathBuf::from(home).join(".bulge/harness/memory");
    let mut out = Vec::new();
    for (file, name) in [("USER", bulge_harness::profile::USER_FILE), ("MEMORY", bulge_harness::profile::MEMORY_FILE)] {
        let profile = bulge_harness::Profile::load(&root.join(name)).unwrap_or_default();
        for section in profile.sections {
            out.push(ProfileEntryDto { file: file.to_string(), key: section.key, body: section.body });
        }
    }
    out
}

#[derive(Serialize)]
struct UsageDto {
    name: String,
    created_by: String,
    uses: u32,
    patches: u32,
    state: String,
    pinned: bool,
}

/// The skill usage ledger (`.usage.json`): authorship and lifecycle per skill.
#[tauri::command]
fn list_usage() -> Vec<UsageDto> {
    use bulge_harness::{Author, Lifecycle};
    let Ok(home) = std::env::var("HOME") else { return Vec::new() };
    let path = PathBuf::from(home).join(".bulge/harness/skills").join(bulge_harness::usage::USAGE_FILE);
    let ledger = bulge_harness::UsageLedger::load(&path).unwrap_or_default();
    ledger
        .entries
        .into_iter()
        .map(|(name, u)| UsageDto {
            name,
            created_by: match u.created_by { Author::Agent => "agent", Author::User => "user" }.to_string(),
            uses: u.uses,
            patches: u.patches,
            state: match u.state { Lifecycle::Active => "active", Lifecycle::Stale => "stale", Lifecycle::Archived => "archived" }.to_string(),
            pinned: u.pinned,
        })
        .collect()
}

/// Keyword search over past job transcripts (for the sidebar history search).
#[tauri::command]
fn search_jobs(query: String) -> Vec<bulge_cli::recall::RecallHit> {
    bulge_cli::recall::search_default(&query, 20)
}

#[derive(Serialize)]
struct JobSummaryDto {
    id: String,
    title: String,
    status: String,
    created_ms: u64,
}

/// Recent jobs for the sidebar history, newest first.
#[tauri::command]
fn list_jobs() -> Vec<JobSummaryDto> {
    let Ok(home) = std::env::var("HOME") else { return Vec::new() };
    let store = JobStore::new(PathBuf::from(home).join(".bulge/jobs"));
    store
        .list()
        .unwrap_or_default()
        .into_iter()
        .map(|s| JobSummaryDto { id: s.id, title: s.title, status: format!("{:?}", s.status), created_ms: s.created_ms })
        .collect()
}

#[derive(Serialize)]
struct LoadedJobDto {
    jsonl: String,
    diff: Option<String>,
}

/// Read a past job's event log (and diff, if any) for read-only viewing. Changes
/// from an earlier run cannot be re-applied — the VM overlay is gone — so the
/// viewer shows the transcript and diff only. A follow-up turn resumes the
/// conversation in a fresh VM.
#[tauri::command]
fn load_job(id: String) -> Result<LoadedJobDto, String> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err("無效的任務 id".into());
    }
    let home = PathBuf::from(std::env::var("HOME").map_err(|_| "HOME 未設定".to_string())?);
    let dir = home.join(".bulge/jobs").join(&id);
    let jsonl = std::fs::read_to_string(dir.join("job.jsonl")).map_err(|e| format!("讀取任務失敗:{e}"))?;
    let diff = std::fs::read_to_string(dir.join("changes.diff")).ok();
    Ok(LoadedJobDto { jsonl, diff })
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            defaults,
            key_status,
            save_key,
            pick_workspace,
            start_job,
            stop_job,
            restart_vm,
            end_session,
            approve_egress,
            apply_changes,
            list_jobs,
            load_job,
            detect_models,
            mcp_servers,
            list_memory,
            list_skills,
            list_hooks,
            list_schedules,
            remove_schedule,
            set_schedule_enabled,
            list_profile,
            list_usage,
            search_jobs,
        ])
        .on_window_event(|window, event| {
            // Best-effort cleanup: when the window closes, end every live session so
            // their VMs are shut down rather than orphaned.
            if let tauri::WindowEvent::CloseRequested { .. } = event
                && let Some(state) = window.app_handle().try_state::<AppState>()
            {
                state.sessions.lock().unwrap().clear();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running bulge-app");
}
