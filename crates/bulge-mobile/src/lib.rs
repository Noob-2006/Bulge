//! Bulge Remote: the phone side of `bulge-remote`.
//!
//! Pair by scanning the QR code from `bulge remote pair` (or pasting the
//! link), then chat. Everything about the connection — relay tunnel pinned to
//! the relay key, the end-to-end Noise_IKpsk2 session, acknowledged replies,
//! the move to a direct path — is the same library the desktop client uses
//! ([`bulge_remote::conversation`]); this crate is only the screens.
//!
//! Keys and the paired-host list live in the app's private data directory.

use std::path::PathBuf;
use std::sync::Mutex;

use bulge_remote::conversation::{self, Event};
use bulge_remote::device::{self, KnownHost};
use bulge_remote::link::PairLink;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{mpsc, oneshot};

#[derive(Default)]
struct Chat {
    /// The open conversation: the sender for messages, and the stop signal
    /// of its event forwarding (dropping it ends that conversation).
    open: Mutex<Option<(mpsc::UnboundedSender<String>, oneshot::Sender<()>)>>,
}

#[derive(Serialize)]
struct HostView {
    name: String,
    device_name: String,
    relay: String,
}

impl From<&KnownHost> for HostView {
    fn from(host: &KnownHost) -> Self {
        Self { name: host.name.clone(), device_name: host.device_name.clone(), relay: host.relay.clone() }
    }
}

/// What the screen shows for one conversation event.
#[derive(Clone, Serialize)]
struct ChatEvent {
    host: String,
    kind: &'static str,
    text: String,
}

fn data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app.path().app_data_dir().map_err(|e| format!("app data dir: {e}"))?.join("remote"))
}

#[tauri::command]
fn hosts(app: AppHandle) -> Result<Vec<HostView>, String> {
    Ok(device::hosts(&data_dir(&app)?)?.iter().map(HostView::from).collect())
}

#[tauri::command]
async fn join(app: AppHandle, link: String, host_name: String, device_name: String) -> Result<HostView, String> {
    let link = PairLink::decode(&link)?;
    let host_name = if host_name.trim().is_empty() { "bulge".to_owned() } else { host_name.trim().to_owned() };
    let device_name = if device_name.trim().is_empty() { "phone".to_owned() } else { device_name.trim().to_owned() };
    let known = device::join(&data_dir(&app)?, &link, &host_name, &device_name).await?;
    Ok(HostView::from(&known))
}

#[tauri::command]
fn forget(app: AppHandle, name: String) -> Result<bool, String> {
    device::forget(&data_dir(&app)?, &name)
}

/// Open (or switch to) the conversation with `name`; events arrive as
/// `chat-event`.
#[tauri::command]
async fn open_chat(app: AppHandle, chat: State<'_, Chat>, name: String) -> Result<(), String> {
    let dir = data_dir(&app)?;
    let host = device::pick_host(&dir, Some(&name))?;
    let conversation::Conversation { send, mut events } = conversation::start(dir, host);
    let (stop_tx, mut stop) = oneshot::channel::<()>();
    // Replacing the entry drops the previous stop signal: its forwarding task
    // ends and drops its event receiver, which stops that conversation.
    *chat.open.lock().map_err(|_| "poisoned")? = Some((send, stop_tx));
    tauri::async_runtime::spawn(async move {
        loop {
            let event = tokio::select! {
                _ = &mut stop => return,
                event = events.recv() => match event {
                    Some(event) => event,
                    None => return,
                },
            };
            let (kind, text) = match event {
                Event::Connected { direct: false } => ("connected", "已連線（經中繼）".to_owned()),
                Event::Connected { direct: true } => ("connected", "已改為直連".to_owned()),
                Event::Reply(text) => ("reply", text),
                Event::NotSent(why) => ("notsent", why),
                Event::Typing => ("typing", String::new()),
                Event::Commands(list) => ("commands", serde_json::to_string(&list).unwrap_or_default()),
                Event::Disconnected(why) => ("disconnected", why),
                Event::Fatal(why) => ("fatal", why),
            };
            if app.emit("chat-event", ChatEvent { host: name.clone(), kind, text }).is_err() {
                return;
            }
        }
    });
    Ok(())
}

#[tauri::command]
fn send(chat: State<'_, Chat>, text: String) -> Result<(), String> {
    let open = chat.open.lock().map_err(|_| "poisoned")?;
    let (sender, _) = open.as_ref().ok_or("no conversation is open")?;
    sender.send(text).map_err(|_| "the conversation stopped".to_string())
}

#[tauri::command]
fn close_chat(chat: State<'_, Chat>) -> Result<(), String> {
    *chat.open.lock().map_err(|_| "poisoned")? = None;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();
    #[cfg(mobile)]
    let builder = builder.plugin(tauri_plugin_barcode_scanner::init());
    let result = builder
        .manage(Chat::default())
        .invoke_handler(tauri::generate_handler![hosts, join, forget, open_chat, send, close_chat])
        .run(tauri::generate_context!());
    if let Err(error) = result {
        eprintln!("bulge remote: {error}");
    }
}
