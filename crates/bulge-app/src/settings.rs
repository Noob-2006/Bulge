//! Settings: defaults, the API key (only whether one is saved), the
//! provider's models, and picking a workspace.

use std::path::PathBuf;
use bulge_runtime::backend::Protocol;
use bulge_store::Autonomy;
use tauri::AppHandle;
use tauri_plugin_dialog::DialogExt;
use tokio::sync::oneshot;
use super::Defaults;

/// A job's store directory from its id (ids are generated, never paths).
pub(crate) fn job_dir_for(id: &str) -> Result<PathBuf, String> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err("無效的任務 id".into());
    }
    Ok(bulge_util::fs::jobs_dir()?.join(id))
}

/// The host part of a base URL, used to locate its key file.
pub(crate) fn host_of(base_url: &str) -> String {
    base_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(base_url)
        .to_string()
}

pub(crate) fn parse_protocol(name: &str) -> Result<Protocol, String> {
    Protocol::parse(name)
}

pub(crate) fn parse_autonomy(value: &str) -> Result<Autonomy, String> {
    match value {
        "collaborative" => Ok(Autonomy::Collaborative),
        "autonomous" => Ok(Autonomy::Autonomous),
        "full-auto" | "full_auto" | "fullauto" => Ok(Autonomy::FullAuto),
        other => Err(format!("未知的自主模式 {other:?}")),
    }
}

#[tauri::command]
pub(crate) fn defaults() -> Defaults {
    Defaults {
        model: bulge_runtime::backend::DEFAULT_MODEL.into(),
        base_url: bulge_runtime::backend::DEFAULT_BASE_URL.into(),
        protocol: "openai".into(),
        autonomy: "autonomous".into(),
        cpus: 2,
        ram_mib: 1024,
        context_window: bulge_runtime::backend::DEFAULT_CONTEXT_WINDOW,
        max_tokens: bulge_runtime::backend::DEFAULT_MAX_TOKENS,
    }
}

/// Parse the optional reasoning-effort selector into the LLM enum.
pub(crate) fn parse_reasoning(value: Option<&str>) -> Option<bulge_llm::ReasoningEffort> {
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
pub(crate) fn key_status(base_url: String) -> bool {
    bulge_runtime::backend::key_path(&host_of(&base_url)).is_ok_and(|path| path.exists())
}

/// Write the user's API key to `~/.bulge/keys/<host>` with mode 600. The key is
/// taken straight from the UI to disk; it is never logged or echoed back.
#[tauri::command]
pub(crate) fn save_key(base_url: String, key: String) -> Result<(), String> {
    let key = key.trim();
    if key.is_empty() {
        return Err("金鑰是空的".into());
    }
    // Mode 600 from the first byte (writing first and chmod-ing after left
    // the key readable for a moment).
    let path = bulge_runtime::backend::key_path(&host_of(&base_url))?;
    bulge_util::fs::write_private(&path, format!("{key}\n").as_bytes()).map_err(|e| format!("寫入金鑰失敗:{e}"))
}

/// Detect the models this provider currently offers, using the saved key. Replaces
/// a hardcoded list with what the endpoint+key can actually reach. The key is read
/// here only to make the request; it is never returned or logged.
#[tauri::command]
pub(crate) async fn detect_models(base_url: String, protocol: String) -> Result<Vec<String>, String> {
    use bulge_llm::protocol::WireProtocol;
    use bulge_llm::protocol::anthropic::AnthropicMessages;
    use bulge_llm::protocol::openai_chat::OpenAiChat;
    let proto = parse_protocol(&protocol)?;
    let key = bulge_runtime::backend::load_api_key(&base_url)?;
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
pub(crate) async fn pick_workspace(app: AppHandle) -> Option<String> {
    let (tx, rx) = oneshot::channel();
    app.dialog().file().pick_folder(move |picked| {
        let _ = tx.send(picked);
    });
    rx.await.ok().flatten().map(|p| p.to_string())
}
