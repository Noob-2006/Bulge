//! Conversations: building a run, the live sessions and their VMs, egress
//! approvals, and reviewing, applying and rolling back changes.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use bulge_runtime::backend::BackendSpec;
use bulge_runtime::run::{RunConfig, Sampling, Session};
use bulge_vm::net::EgressApproval;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use super::dto::{ApplyReportDto, ChangeDto, DoneEvent, EgressAskEvent, LineEvent, RollbackDto, WritebackDto};
use super::{AppState, DoneInfo, EGRESS_SEQ, MAX_LIVE_SESSIONS, SessionCmd, SessionEntry, StartArgs, now_ms};
use super::settings::{host_of, job_dir_for, parse_autonomy, parse_protocol, parse_reasoning};

/// Build the per-run config from the UI args, resolving the workspace (an empty
/// path means an ephemeral scratch workspace inside the VM home).
pub(crate) fn build_config(args: &StartArgs) -> Result<RunConfig, String> {
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
    if !bulge_runtime::backend::key_path(&host_of(&args.base_url))?.exists() {
        return Err(format!("找不到 {} 的 API 金鑰。請先在「設定」裡填入並儲存。", host_of(&args.base_url)));
    }

    let reasoning_effort = parse_reasoning(args.reasoning_effort.as_deref());
    // A reasoning effort is only sent when the model is treated as a reasoning
    // model, so choosing any effort — including "off", which must be sent to stop
    // a model that thinks by default — turns that on; unset sends nothing.
    let reasoning = reasoning_effort.is_some();
    let context_window = args.context_window.unwrap_or(bulge_runtime::backend::DEFAULT_CONTEXT_WINDOW).max(8_192);
    let out_cap = args.max_tokens.unwrap_or(bulge_runtime::backend::DEFAULT_MAX_TOKENS).clamp(256, 200_000);
    let system_prompt = args.system_prompt.as_ref().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());

    let backend = BackendSpec { context_window, max_tokens: out_cap, reasoning, ..BackendSpec::new(&args.base_url, protocol, &args.model) };
    Ok(RunConfig {
        job_id: args.job_id.clone(),
        autonomy,
        network: args.network,
        cpus: args.cpus,
        ram_mib: args.ram_mib,
        sampling: Sampling { temperature: args.temperature, reasoning_effort, max_tokens: Some(out_cap) },
        system_prompt,
        // egress_approvals is filled in by start_job with the session's channel.
        auto_review: args.auto_review,
        host_integrations: true,
        ..RunConfig::new(args.goal.clone(), workspace, backend)?
    })
}

/// Start a new job, or feed a follow-up turn to a live session. Returns the
/// session id the UI uses to stop it, continue it, and apply its diff. Events
/// stream back as `job-line`; each turn's completion arrives as `job-done`.
#[tauri::command]
pub(crate) async fn start_job(app: AppHandle, state: State<'_, AppState>, args: StartArgs) -> Result<String, String> {
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
pub(crate) fn evict_if_needed(sessions: &mut HashMap<String, SessionEntry>) {
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
pub(crate) fn spawn_session(
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
pub(crate) async fn session_loop(
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
pub(crate) async fn run_turn_and_emit(app: &AppHandle, sid: &str, session: &mut Session, goal: String, cancel: CancellationToken) {
    let sink = {
        let app = app.clone();
        let sid = sid.to_string();
        Box::new(move |line: &str| {
            let _ = app.emit("job-line", LineEvent { handle: sid.clone(), line: line.to_string() });
        }) as bulge_runtime::run::LineSink
    };

    let event = match session.run_turn(goal, cancel, sink).await {
        Ok(outcome) => {
            let auto_applied = outcome.auto_writeback.as_ref().map(|m| m.applied_paths()).unwrap_or_default();
            let changes_dto: Vec<ChangeDto> =
                outcome.changes.iter().map(|change| ChangeDto::from_change(change, &outcome.ignored, &auto_applied)).collect();
            if let Some(entry) = app.state::<AppState>().sessions.lock().unwrap().get_mut(sid) {
                entry.done = Some(DoneInfo { workspace: outcome.workspace.clone(), changes: outcome.changes, job_dir: outcome.job_dir.clone() });
            }
            DoneEvent {
                handle: sid.to_string(),
                job_id: outcome.job_id,
                status: format!("{:?}", outcome.status),
                outcome: format!("{:?}", outcome.outcome),
                diff: outcome.diff,
                changes: changes_dto,
                job_dir: outcome.job_dir.display().to_string(),
                error: outcome.changes_error,
                auto_writeback: outcome.auto_writeback.as_ref().map(WritebackDto::from_manifest),
            }
        }
        Err(error) => DoneEvent {
            auto_writeback: None,
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
pub(crate) async fn egress_drain(app: AppHandle, sid: String, mut rx: mpsc::UnboundedReceiver<EgressApproval>) {
    while let Some(req) = rx.recv().await {
        let id = format!("eg-{}", EGRESS_SEQ.fetch_add(1, Ordering::Relaxed));
        app.state::<AppState>().pending_egress.lock().unwrap().insert(id.clone(), req.reply);
        let _ = app.emit("egress-ask", EgressAskEvent { handle: sid.clone(), id, host: req.host, port: req.port });
    }
}

pub(crate) fn emit_launch_error(app: &AppHandle, sid: &str, error: String) {
    let _ = app.emit(
        "job-done",
        DoneEvent {
            auto_writeback: None,
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
pub(crate) fn stop_job(state: State<'_, AppState>, handle: String) -> Result<(), String> {
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
pub(crate) async fn restart_vm(state: State<'_, AppState>, handle: String, cpus: u8, ram_mib: u32, network: bool) -> Result<(), String> {
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
pub(crate) fn approve_egress(state: State<'_, AppState>, id: String, allow: bool) -> Result<(), String> {
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
pub(crate) fn end_session(state: State<'_, AppState>, handle: String) -> Result<(), String> {
    // Dropping the entry drops its sender; the session thread shuts the VM down.
    state.sessions.lock().unwrap().remove(&handle);
    Ok(())
}

/// Apply the approved subset of a finished turn's changes to the host workspace.
/// Paths not in `approved` are left untouched; symlink and traversal defences
/// live in `bulge_vm::changes::apply`.
#[tauri::command]
pub(crate) fn apply_changes(state: State<'_, AppState>, handle: String, approved: Vec<String>) -> Result<ApplyReportDto, String> {
    let sessions = state.sessions.lock().unwrap();
    let entry = sessions.get(&handle).ok_or("找不到這個工作")?;
    let done = entry.done.as_ref().ok_or("這個工作還沒完成,沒有可套用的變更")?;
    // Every approved write-back is snapshotted first, so it can be undone.
    let manifest = bulge_vm::writeback::apply(&done.workspace, &done.changes, &approved, &done.job_dir, false)
        .map_err(|e| format!("無法建立寫回前快照,工作區未變動:{e}"))?;
    Ok(ApplyReportDto { applied: manifest.applied_paths(), skipped: manifest.skipped, writeback_id: manifest.id })
}

/// The snapshotted write-backs of a job, oldest first (the audit trail).
#[tauri::command]
pub(crate) fn list_writebacks(job_id: String) -> Result<Vec<WritebackDto>, String> {
    let dir = job_dir_for(&job_id)?;
    Ok(bulge_vm::writeback::list(&dir).iter().map(WritebackDto::from_manifest).collect())
}

/// Undo one write-back. Paths changed since are left alone (reported as
/// conflicts) unless `force`.
#[tauri::command]
pub(crate) fn rollback_writeback(job_id: String, writeback_id: String, force: bool) -> Result<RollbackDto, String> {
    let dir = job_dir_for(&job_id)?;
    let report = bulge_vm::writeback::rollback(&dir, &writeback_id, force).map_err(|e| format!("回復失敗:{e}"))?;
    Ok(RollbackDto { restored: report.restored, conflicts: report.conflicts })
}
