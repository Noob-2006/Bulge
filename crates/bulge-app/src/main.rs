//! Bulge desktop app.
//!
//! One window, no network ports: the webview talks to this process over Tauri's
//! in-process IPC (the roadmap's "Tauri 程序內 IPC"). A job runs through the exact
//! same orchestration as the headless CLI (`bulge_cli::run::run_streaming`), so
//! there is one code path for an agent run. Workspace changes stay in the VM
//! overlay; nothing is written to the host until the user reviews the diff and
//! approves it here.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use bulge_cli::backend::{BackendSpec, Protocol};
use bulge_cli::run::{RunConfig, run_streaming};
use bulge_store::{Autonomy, Budget, JobStore};
use bulge_vm::changes::{self, Change};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

/// Per-run bookkeeping: its cancel handle (emergency stop) and, once finished,
/// the structured changes to apply on approval.
struct RunEntry {
    cancel: CancellationToken,
    done: Option<DoneInfo>,
}

struct DoneInfo {
    workspace: PathBuf,
    changes: Vec<Change>,
}

#[derive(Default)]
struct AppState {
    runs: Mutex<HashMap<String, RunEntry>>,
}

/// Defaults the UI pre-fills (mirrors the CLI's defaults).
#[derive(Serialize)]
struct Defaults {
    model: String,
    base_url: String,
    protocol: String,
    autonomy: String,
    cpus: u8,
    ram_mib: u32,
}

/// Everything the UI sends to start a job. Fixed budgets/limits match the CLI.
#[derive(Deserialize)]
struct StartArgs {
    /// Present → continue that conversation (a follow-up turn); absent → new job.
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
}

/// One streamed log line, tagged with the run it belongs to.
#[derive(Clone, Serialize)]
struct LineEvent {
    handle: String,
    line: String,
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

/// Start a job. Returns a handle the UI uses to stop it and later apply its
/// diff. Events stream back as `job-line`; completion arrives as `job-done`.
#[tauri::command]
async fn start_job(app: AppHandle, state: State<'_, AppState>, args: StartArgs) -> Result<String, String> {
    let home = PathBuf::from(std::env::var("HOME").map_err(|_| "HOME 未設定".to_string())?);
    // No folder chosen → use an ephemeral scratch workspace (the agent still works
    // in the VM; nothing lands on the user's real files unless they later pick one).
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
        return Err(format!(
            "找不到 {} 的 API 金鑰。請先在「設定」裡填入並儲存。",
            host_of(&args.base_url)
        ));
    }

    let title: String = args.goal.lines().next().unwrap_or("job").chars().take(80).collect();
    let host = host_of(&args.base_url);

    let config = RunConfig {
        job_id: args.job_id.clone(),
        goal: args.goal.clone(),
        title,
        workspace: workspace.clone(),
        store_root: home.join(".bulge/jobs"),
        harness_dir: home.join(".bulge/harness"),
        autonomy,
        budget: Budget { max_steps: 200, max_tokens: 2_000_000, max_wall_secs: 14_400 },
        backend: BackendSpec {
            id: host,
            base_url: args.base_url.clone(),
            protocol,
            model: args.model.clone(),
            context_window: 128_000,
            max_tokens: 8_192,
            reasoning: false,
        },
        network: args.network,
        cpus: args.cpus,
        ram_mib: args.ram_mib,
    };

    // A short, unique-enough handle for this run.
    let handle = format!("run-{}", now_ms());
    let cancel = CancellationToken::new();
    state.runs.lock().unwrap().insert(handle.clone(), RunEntry { cancel: cancel.clone(), done: None });

    // Stream each committed log line to the webview.
    let app_for_sink = app.clone();
    let sink_handle = handle.clone();
    let sink = Box::new(move |line: &str| {
        let _ = app_for_sink.emit("job-line", LineEvent { handle: sink_handle.clone(), line: line.to_string() });
    });

    // The agent loop's internal scheduler is not `Send`, so it cannot live on a
    // shared worker. Give it its own thread with a single-threaded runtime; the
    // sink and app handle are `Send + Sync` and cross the boundary fine.
    let app_for_done = app.clone();
    let done_handle = handle.clone();
    std::thread::Builder::new()
        .name(format!("bulge-{handle}"))
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = app_for_done.emit(
                        "job-done",
                        DoneEvent {
                            handle: done_handle.clone(),
                            job_id: String::new(),
                            status: "Failed".into(),
                            outcome: "Error".into(),
                            diff: None,
                            changes: Vec::new(),
                            job_dir: String::new(),
                            error: Some(format!("無法建立執行緒 runtime:{e}")),
                        },
                    );
                    return;
                }
            };
            rt.block_on(job_thread(config, cancel, sink, app_for_done, done_handle));
        })
        .map_err(|e| format!("無法啟動工作執行緒:{e}"))?;

    Ok(handle)
}

/// Run one job to completion on its own runtime, then publish the result.
async fn job_thread(config: RunConfig, cancel: CancellationToken, sink: bulge_cli::run::LineSink, app: AppHandle, handle: String) {
    {
        let result = run_streaming(config, cancel, sink).await;
        let event = match result {
            Ok(outcome) => {
                let changes_dto: Vec<ChangeDto> = outcome.changes.iter().map(ChangeDto::from_change).collect();
                // Keep the structured changes for the approval step.
                if let Some(entry) = app.state::<AppState>().runs.lock().unwrap().get_mut(&handle) {
                    entry.done = Some(DoneInfo { workspace: outcome.workspace.clone(), changes: outcome.changes });
                }
                DoneEvent {
                    handle: handle.clone(),
                    job_id: outcome.job_dir.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string(),
                    status: format!("{:?}", outcome.status),
                    outcome: format!("{:?}", outcome.outcome),
                    diff: outcome.diff,
                    changes: changes_dto,
                    job_dir: outcome.job_dir.display().to_string(),
                    error: None,
                }
            }
            Err(error) => DoneEvent {
                handle: handle.clone(),
                job_id: String::new(),
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
}

/// Emergency stop: cancel the running loop. The VM is torn down as the run unwinds.
#[tauri::command]
fn stop_job(state: State<'_, AppState>, handle: String) -> Result<(), String> {
    let runs = state.runs.lock().unwrap();
    match runs.get(&handle) {
        Some(entry) => {
            entry.cancel.cancel();
            Ok(())
        }
        None => Err("找不到這個工作".into()),
    }
}

/// Apply the approved subset of a finished run's changes to the host workspace.
/// Paths not in `approved` are left untouched; symlink and traversal defences
/// live in `bulge_vm::changes::apply`.
#[tauri::command]
fn apply_changes(state: State<'_, AppState>, handle: String, approved: Vec<String>) -> Result<ApplyReportDto, String> {
    let runs = state.runs.lock().unwrap();
    let entry = runs.get(&handle).ok_or("找不到這個工作")?;
    let done = entry.done.as_ref().ok_or("這個工作還沒完成,沒有可套用的變更")?;
    let report = changes::apply(&done.workspace, &done.changes, &approved);
    Ok(ApplyReportDto { applied: report.applied, skipped: report.skipped })
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
/// viewer shows the transcript and diff only.
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
            apply_changes,
            list_jobs,
            load_job,
            detect_models,
        ])
        .run(tauri::generate_context!())
        .expect("error while running bulge-app");
}
