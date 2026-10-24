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

mod dto;
mod panels;
mod sessions;
mod settings;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bulge_vm::changes::Change;
use serde::{Deserialize, Serialize};
use tauri::Manager;
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
    /// The job's store directory, where write-back snapshots are kept.
    job_dir: PathBuf,
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
    /// Enable the LLM review gate: a cheap reviewer vets each mutating tool call.
    #[serde(default)]
    auto_review: bool,
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn main() {
    // Keep ~/.bulge private (mode 700) before anything is written into it.
    if let Err(error) = bulge_util::fs::bulge_home() {
        eprintln!("warning: {error}");
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            settings::defaults,
            settings::key_status,
            settings::save_key,
            settings::pick_workspace,
            sessions::start_job,
            sessions::stop_job,
            sessions::restart_vm,
            sessions::end_session,
            sessions::approve_egress,
            sessions::apply_changes,
            sessions::list_writebacks,
            sessions::rollback_writeback,
            panels::list_jobs,
            panels::load_job,
            panels::org_chart,
            settings::detect_models,
            panels::mcp_servers,
            panels::list_memory,
            panels::remove_lesson,
            panels::list_skills,
            panels::list_hooks,
            panels::list_schedules,
            panels::add_schedule,
            panels::remove_schedule,
            panels::set_schedule_enabled,
            panels::list_profile,
            panels::save_profile_entry,
            panels::remove_profile_entry,
            panels::list_usage,
            panels::set_skill_pinned,
            panels::set_skill_state,
            panels::forget_skill,
            panels::search_jobs,
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
